//! eBPF telemetry: attach programs, stream ring-buffer events, enrich from
//! /proc, apply kill/log rules.
//!
//! Enrichment races: by the time we read /proc/<pid> the process may have
//! exited or re-execed, so exe/cmdline/cwd are best-effort and may be
//! missing or (rarely) refer to a recycled pid. Lineage comes from the
//! ProcTable cache, which survives parent exit and detects pid reuse via
//! process start times.

use std::mem::size_of;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use aya::Ebpf;
use aya::maps::RingBuf;
use aya::programs::{KProbe, TracePoint};
use merlin_common::*;
use serde_json::Value;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::Sender;

use crate::fileless::{ExeClass, classify_exe, is_deleted_executable_path};
use crate::proctree::{ProcInfo, ProcTable};
use crate::rules::{Action, MatchCtx, Rules, RulesHandle};
use crate::spool;

/// Load and attach every program in the object. Used by `run` and `check`
/// (check drops the Ebpf right after, detaching everything).
pub fn attach_all(bpf: &mut Ebpf) -> Result<()> {
    for (prog_name, group, event) in [
        ("sched_process_exec", "sched", "sched_process_exec"),
        ("sched_process_fork", "sched", "sched_process_fork"),
        ("inet_sock_set_state", "sock", "inet_sock_set_state"),
        (
            "sys_enter_memfd_create",
            "syscalls",
            "sys_enter_memfd_create",
        ),
        ("sys_enter_setuid", "syscalls", "sys_enter_setuid"),
        ("sys_enter_setreuid", "syscalls", "sys_enter_setreuid"),
        ("sys_enter_setresuid", "syscalls", "sys_enter_setresuid"),
        (
            "sys_enter_io_uring_setup",
            "syscalls",
            "sys_enter_io_uring_setup",
        ),
        ("io_uring_submit_req", "io_uring", "io_uring_submit_req"),
        ("raw_syscalls_sys_enter", "raw_syscalls", "sys_enter"),
    ] {
        let prog: &mut TracePoint = bpf
            .program_mut(prog_name)
            .with_context(|| format!("program {prog_name} not in object"))?
            .try_into()?;
        prog.load()?;
        prog.attach(group, event)?;
        log::info!("attached tracepoint {group}/{event}");
    }
    let prog: &mut KProbe = bpf
        .program_mut("do_exit")
        .context("program do_exit not in object")?
        .try_into()?;
    prog.load()?;
    prog.attach("do_exit", 0)?;
    log::info!("attached kprobe do_exit");
    Ok(())
}

/// Hand the eBPF programs our pid namespace (dev, ino) so they can
/// translate pids with bpf_get_ns_current_pid_tgid — required when Merlin
/// itself runs inside a container, where init-namespace pids do not exist
/// in /proc.
fn set_pid_ns(bpf: &mut Ebpf) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata("/proc/self/ns/pid").context("stat pid ns")?;
    let mut arr = aya::maps::Array::<_, u64>::try_from(
        bpf.map_mut("PID_NS").context("PID_NS map not in object")?,
    )?;
    arr.set(0, md.dev(), 0)?;
    arr.set(1, md.ino(), 0)?;
    log::info!("pid namespace dev={} ino={}", md.dev(), md.ino());
    Ok(())
}

/// Spawn the ring-buffer consumer task. `bpf` is moved into the task so the
/// programs stay attached for the lifetime of the daemon. `table` is the
/// lineage cache shared with the file monitor. `security_rate_limit` caps
/// the `security` syscall stream (events/sec, 0 = unlimited) at the spool
/// dispatch point; event generation is unaffected.
pub async fn spawn(
    mut bpf: Ebpf,
    rules: RulesHandle,
    tx: Sender<Value>,
    table: Arc<Mutex<ProcTable>>,
    security_rate_limit: f64,
    alert: Option<crate::alert::AlertHook>,
) -> Result<()> {
    set_pid_ns(&mut bpf)?;
    attach_all(&mut bpf)?;
    let map = bpf.take_map("EVENTS").context("EVENTS map not in object")?;
    let rb = RingBuf::try_from(map)?;
    let mut afd = AsyncFd::new(rb)?;
    tokio::spawn(async move {
        let _bpf = bpf; // keep programs attached
        let mut throttle = TokenBucket::new(security_rate_limit, Instant::now());
        loop {
            match afd.readable_mut().await {
                Ok(mut guard) => {
                    while let Some(item) = guard.get_inner_mut().next() {
                        handle_event(&item, &rules.get(), &tx, &table, &mut throttle, &alert);
                    }
                    guard.clear_ready();
                }
                Err(e) => {
                    log::error!("ring buffer poll failed: {e}");
                    return;
                }
            }
        }
    });
    Ok(())
}

/// Token bucket for the `security` syscall stream (see --security-rate-limit).
/// Burst capacity is one second of rate; drops are counted and reported
/// periodically instead of per-event (a dropped-flood must not itself flood).
pub struct TokenBucket {
    rate: f64,
    tokens: f64,
    last_refill: Instant,
    dropped: u64,
    last_report: Instant,
}

impl TokenBucket {
    pub fn new(rate: f64, now: Instant) -> Self {
        TokenBucket {
            rate,
            tokens: rate.max(0.0),
            last_refill: now,
            dropped: 0,
            last_report: now,
        }
    }

    /// rate <= 0 means unlimited.
    pub fn allow(&mut self, now: Instant) -> bool {
        if self.rate <= 0.0 {
            return true;
        }
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.rate);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            self.dropped += 1;
            false
        }
    }

    /// Returns the drop count to report when a report is due (every 60s
    /// with nonzero drops), resetting the counter.
    pub fn report_due(&mut self, now: Instant) -> Option<u64> {
        if self.dropped > 0 && now.duration_since(self.last_report) >= Duration::from_secs(60) {
            let n = std::mem::take(&mut self.dropped);
            self.last_report = now;
            Some(n)
        } else {
            None
        }
    }
}

fn handle_event(
    bytes: &[u8],
    rules: &Rules,
    tx: &Sender<Value>,
    table: &Arc<Mutex<ProcTable>>,
    throttle: &mut TokenBucket,
    alert: &Option<crate::alert::AlertHook>,
) {
    if bytes.len() < size_of::<Event>() {
        log::warn!("short ring-buffer record ({} bytes)", bytes.len());
        return;
    }
    // Ring-buffer records are 8-byte aligned; read_unaligned is belt and
    // braces for the repr(C) payload union.
    let event: Event = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const Event) };
    match event.kind {
        KIND_EXEC => handle_exec(unsafe { event.payload.exec }, rules, tx, table, alert),
        KIND_FORK => handle_fork(unsafe { event.payload.fork }, tx, table),
        KIND_EXIT => handle_exit(unsafe { event.payload.exit }, tx, table),
        KIND_CONNECT => handle_connect(unsafe { event.payload.connect }, rules, tx),
        KIND_MEMFD => handle_memfd(unsafe { event.payload.memfd }, tx),
        KIND_SECURITY => handle_security(unsafe { event.payload.security }, tx, throttle),
        KIND_SOCKET => handle_socket(unsafe { event.payload.socket }, rules, tx),
        KIND_CRED => handle_cred(unsafe { event.payload.cred }, tx, alert),
        KIND_IOURING => handle_iouring(unsafe { event.payload.iouring }, tx),
        KIND_IOURING_OP => handle_iouring_op(unsafe { event.payload.iouring_op }, tx),
        other => log::warn!("unknown event kind {other}"),
    }
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn handle_exec(
    ev: ExecEvent,
    rules: &Rules,
    tx: &Sender<Value>,
    table: &Arc<Mutex<ProcTable>>,
    alert: &Option<crate::alert::AlertHook>,
) {
    let pid = (ev.pid_ns_valid != 0).then_some(ev.pid);
    let filename = cstr(&ev.filename);
    let comm = cstr(&ev.comm);

    // Best-effort /proc enrichment. Never read or act on a numeric pid when
    // the eBPF namespace translation was not valid; the init-namespace pid
    // could identify an unrelated process in this daemon's /proc.
    #[allow(clippy::type_complexity)]
    let (
        exe,
        fileless,
        exe_deleted,
        exe_missing,
        cmdline,
        cwd,
        uid,
        ppid,
        start_time,
        ancestors,
        parent_basename,
        ancestor_comms,
        script,
    ) = if let Some(pid) = pid {
        // exe keeps the readlink Result so fileless execution can be told
        // apart from a plain race.
        let exe_result = std::fs::read_link(format!("/proc/{pid}/exe"));
        let alive = std::path::Path::new(&format!("/proc/{pid}")).exists();
        let class = classify_exe(&exe_result, alive);
        let exe = match &class {
            ExeClass::Normal(s) | ExeClass::Fileless(s) => Some(s.clone()),
            _ => None,
        };
        let fileless = matches!(class, ExeClass::Fileless(_));
        let exe_deleted =
            matches!(&class, ExeClass::Normal(path) if is_deleted_executable_path(path));
        let exe_missing = matches!(class, ExeClass::MissingAlive);
        if let ExeClass::Fileless(path) = &class {
            log::warn!("FILELESS EXEC pid={pid} comm={comm} exe={path}");
        }
        if exe_missing {
            log::warn!("exe readlink ENOENT on live process pid={pid} comm={comm} (suspicious)");
        }

        let cmdline = proc_cmdline(pid);
        let cwd = std::fs::read_link(format!("/proc/{pid}/cwd"))
            .ok()
            .map(|p| p.display().to_string());
        let uid = proc_uid(pid).or(Some(ev.uid));

        // Feed the lineage cache; start_time in the entry guards pid
        // reuse.
        let parsed = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|s| crate::proctree::parse_stat(&s));
        let ppid = parsed.as_ref().map(|(_, ppid, _)| *ppid);
        let start_time = parsed
            .as_ref()
            .map(|(_, _, start_time)| *start_time)
            .or_else(|| proc_start_time(pid));
        let (ancestors, parent_basename, ancestor_comms) = {
            let mut t = table.lock().unwrap();
            if let Some((stat_comm, stat_ppid, start_time)) = parsed {
                t.upsert(
                    pid,
                    ProcInfo {
                        start_time,
                        ppid: Some(stat_ppid),
                        comm: Some(stat_comm),
                        exe: exe.clone(),
                        cmdline: cmdline.clone(),
                    },
                );
            }
            let lin = t.lineage(ppid);
            let comms = lin.comms();
            let json: Vec<Value> = lin
                .ancestors
                .iter()
                .map(|(pid, comm)| serde_json::json!({ "pid": pid, "comm": comm }))
                .collect();
            (json, lin.parent_basename, comms)
        };
        // Interpreter-run script? Code-mode invocations (-c/-e/-m) and
        // non-interpreters classify to None (see scripts.rs).
        let script = crate::scripts::proc_cmdline_args(pid)
            .and_then(|argv| crate::scripts::script_candidate(&comm, &argv).map(str::to_string))
            .and_then(|path| crate::scripts::inspect_script(&path).map(|i| (path, i.sha256)));
        (
            exe,
            fileless,
            exe_deleted,
            exe_missing,
            cmdline,
            cwd,
            uid,
            ppid,
            start_time,
            ancestors,
            parent_basename,
            ancestor_comms,
            script,
        )
    } else {
        log::warn!(
            "exec event pid namespace translation failed; recording telemetry without enrichment"
        );
        (
            None,
            false,
            false,
            false,
            None,
            None,
            Some(ev.uid),
            None,
            None,
            Vec::new(),
            None,
            Vec::new(),
            None,
        )
    };

    // taskstats backfill: remember processes we could not enrich, so a
    // later task_exit record can carry their accounting.
    if let Some(p) = pid {
        if exe.is_none() && cmdline.is_none() {
            crate::taskstats::failed_enrich().lock().unwrap().mark(p);
        }
    }

    let path = exe.as_deref().unwrap_or(filename.as_str());
    let basename = path.rsplit('/').next();
    let cgroup = pid.and_then(proc_cgroup);
    let container_id = cgroup.as_deref().and_then(container_id_from_cgroup);
    let ctx = MatchCtx {
        sha256: None,
        basename,
        path: Some(path),
        cmdline: cmdline.as_deref(),
        uid,
        comm: Some(comm.as_str()),
        parent_basename: parent_basename.as_deref(),
        ancestors: &ancestor_comms,
    };
    let mut logged = Vec::new();
    let mut killed = Vec::new();
    for rule in &rules.rules {
        if !rule.matches(&ctx) {
            continue;
        }
        match rule.action {
            Action::Log => logged.push(rule.name.clone()),
            Action::Kill => {
                // Race window: the exec already happened; the target may do
                // damage before SIGKILL lands. Never fall back to numeric
                // kill: an invalid namespace or recycled pid must fail safe.
                let Some(pid) = pid else {
                    log::warn!(
                        "kill rule {} matched an event with no valid pid namespace",
                        rule.name
                    );
                    continue;
                };
                let Some(start_time) = start_time else {
                    log::warn!(
                        "kill rule {} matched pid {pid} without a stable start time",
                        rule.name
                    );
                    continue;
                };
                match kill_pid_if_same(pid, start_time) {
                    Ok(()) => killed.push(rule.name.clone()),
                    Err(e) => log::warn!("kill({pid}) failed: {e}"),
                }
            }
            Action::Block => {} // handled synchronously by fanotify
        }
    }

    let mut event = serde_json::json!({
        "ts": spool::now_ts(),
        "source": "linux-ebpf",
        "source_seq": spool::next_sequence(),
        "kind": "exec",
        "pid": pid,
        "ppid": ppid,
        "uid": uid,
        "comm": comm,
        "filename": filename,
        "exe": exe,
        "cmdline": cmdline,
        "cwd": cwd,
        "cgroup": cgroup,
        "container_id": container_id,
        "ancestors": ancestors.clone(),
        "matched_rules": logged,
    });
    // Conditional keys: only present when flagged, to keep the common-case
    // line short (macOS parity: fixed key sets, so these are Linux-only).
    if fileless {
        event["fileless"] = Value::Bool(true);
    }
    if exe_deleted {
        event["exe_deleted"] = Value::Bool(true);
    }
    if exe_missing {
        event["exe_missing"] = Value::Bool(true);
    }
    spool::try_send(tx, event);

    if let Some((script_path, script_hash)) = script {
        log::info!("script exec pid={pid:?} interpreter={comm} script={script_path}");
        spool::try_send(
            tx,
            serde_json::json!({
                "ts": spool::now_ts(),
                "source": "linux-ebpf",
                "source_seq": spool::next_sequence(),
                "kind": "script",
                "pid": pid,
                "uid": uid,
                "comm": comm,
                "interpreter": exe,
                "script": script_path,
                "script_sha256": script_hash,
                "ancestors": ancestors,
            }),
        );
    }

    if !killed.is_empty() {
        log::info!("SIGKILL pid={pid:?} comm={comm} rules={killed:?}");
        if let Some(hook) = alert {
            hook.fire(crate::alert::AlertHook::alert(
                "kill",
                &killed,
                &comm,
                exe.as_deref(),
            ));
        }
        spool::try_send(
            tx,
            serde_json::json!({
                "ts": spool::now_ts(),
                "source": "linux-ebpf",
                "source_seq": spool::next_sequence(),
                "kind": "kill",
                "pid": pid,
                "uid": uid,
                "comm": comm,
                "exe": exe,
                "matched_rules": killed,
            }),
        );
    }
}

fn handle_fork(ev: ForkEvent, tx: &Sender<Value>, table: &Arc<Mutex<ProcTable>>) {
    let parent_pid = (ev.parent_pid_ns_valid != 0).then_some(ev.parent_pid);
    // The fork tracepoint's child pid is deliberately not marked action-safe:
    // the child has no current-task namespace translation yet. It is still
    // valuable as a lineage hint and is reconciled by the subsequent exec.
    let child_start = if ev.child_pid_ns_valid != 0 {
        proc_start_time(ev.child_pid)
    } else {
        None
    };
    if let (Some(start_time), Some(info)) = (child_start, crate::proctree::observe(ev.child_pid)) {
        table
            .lock()
            .unwrap()
            .upsert(ev.child_pid, ProcInfo { start_time, ..info });
    }
    spool::try_send(
        tx,
        serde_json::json!({
            "ts": spool::now_ts(),
            "source": "linux-ebpf",
            "source_seq": spool::next_sequence(),
            "kind": "fork",
            "pid": ev.child_pid,
            "ppid": parent_pid,
            "uid": ev.uid,
            "comm": cstr(&ev.child_comm),
            "parent_comm": cstr(&ev.parent_comm),
            "namespace_valid": ev.parent_pid_ns_valid != 0 && ev.child_pid_ns_valid != 0,
            "child_pid_namespace_valid": ev.child_pid_ns_valid != 0,
            "pid_start_time": child_start,
        }),
    );
}

fn handle_exit(ev: ExitEvent, tx: &Sender<Value>, table: &Arc<Mutex<ProcTable>>) {
    if ev.pid_ns_valid != 0 {
        table.lock().unwrap().remove(ev.pid);
        // taskstats backfill: this pid's exec enrichment failed; query its
        // final accounting.
        if crate::taskstats::failed_enrich()
            .lock()
            .unwrap()
            .take(ev.pid)
        {
            crate::taskstats::notify_exit(ev.pid);
        }
    }
    let raw = ev.exit_code;
    // do_exit's code encodes the wait(2) status: low byte signal info,
    // second byte the exit status for normal exits.
    spool::try_send(
        tx,
        serde_json::json!({
            "ts": spool::now_ts(),
            "source": "linux-ebpf",
            "source_seq": spool::next_sequence(),
            "kind": "exit",
            "pid": (ev.pid_ns_valid != 0).then_some(ev.pid),
            "uid": ev.uid,
            "comm": cstr(&ev.comm),
            "exit_code": raw,
            "exit_status": (raw >> 8) & 0xff,
        }),
    );
}

fn cred_syscall_name(id: u32) -> &'static str {
    match id {
        0 => "setuid",
        1 => "setreuid",
        2 => "setresuid",
        _ => "unknown",
    }
}

/// comms with a legitimate io_uring use (modern postgres, qemu, …).
/// Empty by default: telemetry is emitted for everyone, and when the list
/// IS empty every user is by definition "interesting" — alerting on
/// unexpected users is the rules engine's job via the comm selector.
pub const KNOWN_IOURING_USERS: [&str; 0] = [];

fn handle_iouring(ev: IouringEvent, tx: &Sender<Value>) {
    let pid = (ev.pid_ns_valid != 0).then_some(ev.pid);
    let comm = cstr(&ev.comm);
    if !KNOWN_IOURING_USERS.contains(&comm.as_str()) {
        log::warn!("io_uring_setup by unexpected process pid={pid:?} comm={comm}");
    }
    spool::try_send(
        tx,
        serde_json::json!({
            "ts": spool::now_ts(),
            "source": "linux-ebpf",
            "source_seq": spool::next_sequence(),
            "kind": "iouring",
            "pid": pid,
            "uid": ev.uid,
            "comm": comm,
            "entries": ev.entries,
        }),
    );
}

/// IORING_OP_* number → name. Unknown opcodes render as OP<n>.
pub fn iouring_op_name(opcode: u8) -> String {
    match opcode {
        13 => "accept".into(),
        16 => "connect".into(),
        18 => "openat".into(),
        19 => "close".into(),
        22 => "read".into(),
        23 => "write".into(),
        28 => "openat2".into(),
        45 => "socket".into(),
        other => format!("OP{other}"),
    }
}

fn handle_iouring_op(ev: IouringOpEvent, tx: &Sender<Value>) {
    let pid = (ev.pid_ns_valid != 0).then_some(ev.pid);
    spool::try_send(
        tx,
        serde_json::json!({
            "ts": spool::now_ts(),
            "source": "linux-ebpf",
            "source_seq": spool::next_sequence(),
            "kind": "iouring_op",
            "pid": pid,
            "uid": ev.uid,
            "comm": cstr(&ev.comm),
            "opcode": ev.opcode,
            "op": iouring_op_name(ev.opcode),
        }),
    );
}

fn handle_cred(ev: CredEvent, tx: &Sender<Value>, alert: &Option<crate::alert::AlertHook>) {
    let pid = (ev.pid_ns_valid != 0).then_some(ev.pid);
    let syscall = cred_syscall_name(ev.syscall);
    // 0xFFFF_FFFF encodes a -1 (unchanged) euid argument.
    let target = (ev.target_uid != u32::MAX).then_some(ev.target_uid);
    let to_root = target == Some(0) && ev.uid != 0;
    if to_root {
        log::warn!(
            "credential change to root pid={:?} comm={} uid={} via {}",
            pid,
            cstr(&ev.comm),
            ev.uid,
            syscall
        );
        if let Some(hook) = alert {
            hook.fire(crate::alert::AlertHook::alert(
                "cred",
                &[],
                &cstr(&ev.comm),
                None,
            ));
        }
    }
    let mut event = serde_json::json!({
        "ts": spool::now_ts(),
        "source": "linux-ebpf",
        "source_seq": spool::next_sequence(),
        "kind": "cred",
        "pid": pid,
        "uid": ev.uid,
        "comm": cstr(&ev.comm),
        "syscall": syscall,
        "target_uid": target,
    });
    if to_root {
        event["to_root"] = Value::Bool(true);
    }
    spool::try_send(tx, event);
}

/// Well-known public DoH resolver addresses (Do53 is also their business —
/// the tag is about port 443/853 traffic to them). Additive-extendable via
/// the rules-file `doh_resolvers:` list. Same list as the macOS port.
pub const BUILTIN_DOH_RESOLVERS: [&str; 11] = [
    "1.1.1.1",
    "1.0.0.1", // Cloudflare
    "8.8.8.8",
    "8.8.4.4", // Google
    "9.9.9.9", // Quad9
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
    "2620:fe::fe",
    "2620:fe::9",
];

/// A connect to a known DoH resolver on 443 (DoH) or 853 (DoT).
pub fn is_doh_suspect(daddr: &str, dport: u16, extra: &[String]) -> bool {
    if dport != 443 && dport != 853 {
        return false;
    }
    BUILTIN_DOH_RESOLVERS.contains(&daddr) || extra.iter().any(|r| r == daddr)
}

fn handle_connect(ev: ConnectEvent, rules: &Rules, tx: &Sender<Value>) {
    let saddr = std::net::Ipv4Addr::from(ev.saddr.to_le_bytes());
    let daddr = std::net::Ipv4Addr::from(ev.daddr.to_le_bytes());
    let doh = is_doh_suspect(&daddr.to_string(), ev.dport, &rules.doh_resolvers);
    if doh {
        log::info!(
            "DoH-suspect connect {} -> {}:{} comm={}",
            saddr,
            daddr,
            ev.dport,
            cstr(&ev.comm)
        );
    }
    let mut event = serde_json::json!({
        "ts": spool::now_ts(),
        "source": "linux-ebpf",
        "source_seq": spool::next_sequence(),
        "kind": "connect",
        "pid": (ev.pid_ns_valid != 0).then_some(ev.pid),
        "uid": ev.uid,
        "comm": cstr(&ev.comm),
        "saddr": saddr.to_string(),
        "daddr": daddr.to_string(),
        "dport": ev.dport,
    });
    if doh {
        event["doh_suspect"] = Value::Bool(true);
    }
    spool::try_send(tx, event);
}

fn handle_memfd(ev: MemfdEvent, tx: &Sender<Value>) {
    let name = cstr(&ev.name);
    let comm = cstr(&ev.comm);
    let pid = (ev.pid_ns_valid != 0).then_some(ev.pid);
    log::info!(
        "memfd_create pid={:?} comm={} name={:?} flags=0x{:x}",
        pid,
        comm,
        name,
        ev.flags
    );
    spool::try_send(
        tx,
        serde_json::json!({
            "ts": spool::now_ts(),
            "source": "linux-ebpf",
            "source_seq": spool::next_sequence(),
            "kind": "memfd",
            "pid": pid,
            "pid_start_time": pid.and_then(proc_start_time),
            "uid": ev.uid,
            "comm": comm,
            "name": name,
            "flags": ev.flags,
            "namespace_valid": ev.pid_ns_valid != 0,
        }),
    );
}

fn handle_security(ev: SecurityEvent, tx: &Sender<Value>, throttle: &mut TokenBucket) {
    let now = Instant::now();
    if !throttle.allow(now) {
        if let Some(n) = throttle.report_due(now) {
            log::warn!("security stream throttled: {n} events dropped in the last 60s");
        }
        return;
    }
    let pid = (ev.pid_ns_valid != 0).then_some(ev.pid);
    let cgroup = pid.and_then(proc_cgroup);
    let container_id = cgroup.as_deref().and_then(container_id_from_cgroup);
    let syscall = syscall_name(ev.syscall_nr);
    let w_x = matches!(ev.syscall_nr, 9 | 10) && (ev.args[2] & 0x6) == 0x6;
    if w_x {
        log::warn!(
            "W+X memory transition pid={:?} syscall={} comm={}",
            pid,
            syscall,
            cstr(&ev.comm)
        );
    }
    spool::try_send(
        tx,
        serde_json::json!({
            "ts": spool::now_ts(),
            "source": "linux-ebpf",
            "source_seq": spool::next_sequence(),
            "kind": "security",
            "pid": pid,
            "pid_start_time": pid.and_then(proc_start_time),
            "uid": ev.uid,
            "comm": cstr(&ev.comm),
            "cgroup": cgroup,
            "container_id": container_id,
            "namespace_valid": ev.pid_ns_valid != 0,
            "syscall": syscall,
            "syscall_nr": ev.syscall_nr,
            "args": ev.args,
            "w_x_transition": w_x,
            "action": "observe",
        }),
    );
}

fn handle_socket(ev: SocketEvent, rules: &Rules, tx: &Sender<Value>) {
    let pid = (ev.pid_ns_valid != 0).then_some(ev.pid);
    let cgroup = pid.and_then(proc_cgroup);
    let container_id = cgroup.as_deref().and_then(container_id_from_cgroup);
    let Some(saddr) = socket_addr(ev.family, &ev.saddr) else {
        log::warn!("socket event had unsupported address family {}", ev.family);
        return;
    };
    let Some(daddr) = socket_addr(ev.family, &ev.daddr) else {
        log::warn!("socket event had unsupported address family {}", ev.family);
        return;
    };
    let state = tcp_state_name(ev.new_state);
    let kind = if ev.new_state == 2 {
        "connect"
    } else {
        "socket"
    };
    let doh = kind == "connect" && is_doh_suspect(&daddr, ev.dport, &rules.doh_resolvers);
    if doh {
        log::info!(
            "DoH-suspect connect {saddr} -> {daddr}:{} comm={}",
            ev.dport,
            cstr(&ev.comm)
        );
    }
    let mut event = serde_json::json!({
        "ts": spool::now_ts(),
        "source": "linux-ebpf",
        "source_seq": spool::next_sequence(),
        "kind": kind,
        "pid": pid,
        "pid_start_time": pid.and_then(proc_start_time),
        "uid": ev.uid,
        "comm": cstr(&ev.comm),
        "cgroup": cgroup,
        "container_id": container_id,
        "saddr": saddr,
        "daddr": daddr,
        "sport": ev.sport,
        "dport": ev.dport,
        "family": ev.family,
        "protocol": ev.protocol,
        "old_state": tcp_state_name(ev.old_state),
        "state": state,
        "namespace_valid": ev.pid_ns_valid != 0,
    });
    if doh {
        event["doh_suspect"] = Value::Bool(true);
    }
    spool::try_send(tx, event);
}

fn socket_addr(family: u16, bytes: &[u8; 16]) -> Option<String> {
    match family {
        2 => Some(std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string()),
        10 => Some(std::net::Ipv6Addr::from(*bytes).to_string()),
        _ => None,
    }
}

fn tcp_state_name(state: u8) -> &'static str {
    match state {
        1 => "established",
        2 => "syn_sent",
        3 => "syn_recv",
        4 => "fin_wait1",
        5 => "fin_wait2",
        6 => "time_wait",
        7 => "close",
        8 => "close_wait",
        9 => "last_ack",
        10 => "listen",
        11 => "closing",
        _ => "unknown",
    }
}

fn syscall_name(nr: u32) -> &'static str {
    match nr {
        3 => "close",
        9 => "mmap",
        10 => "mprotect",
        41 => "socket",
        42 => "connect",
        43 => "accept",
        48 => "shutdown",
        49 => "bind",
        50 => "listen",
        59 => "execve",
        101 => "ptrace",
        105 => "setuid",
        106 => "setgid",
        113 => "setreuid",
        114 => "setregid",
        117 => "setresuid",
        119 => "setresgid",
        126 => "capset",
        155 => "pivot_root",
        165 => "mount",
        166 => "umount2",
        175 => "init_module",
        176 => "delete_module",
        272 => "unshare",
        308 => "setns",
        310 => "process_vm_writev",
        311 => "process_vm_readv",
        313 => "finit_module",
        317 => "seccomp",
        321 => "bpf",
        322 => "execveat",
        323 => "userfaultfd",
        435 => "clone3",
        _ => "unknown",
    }
}

pub(crate) fn proc_start_time(pid: u32) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = text.rsplit_once(") ")?.1;
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(target_os = "linux")]
pub(crate) fn kill_pid_if_same(pid: u32, expected_start: u64) -> Result<()> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) } as libc::c_int;
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("pidfd_open");
    }
    let current = proc_start_time(pid);
    if current != Some(expected_start) {
        unsafe { libc::close(fd) };
        anyhow::bail!("pid {pid} was recycled before pidfd signal");
    }
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd,
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    let error = if rc < 0 {
        Some(std::io::Error::last_os_error())
    } else {
        None
    };
    unsafe { libc::close(fd) };
    if let Some(error) = error {
        Err(error).context("pidfd_send_signal")
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn kill_pid_if_same(_pid: u32, _expected_start: u64) -> Result<()> {
    anyhow::bail!("pidfd signaling is only available on Linux")
}

// ---- /proc helpers (shared with the fanotify monitor) ----

pub struct ProcStatus {
    pub name: Option<String>,
    pub ppid: Option<u32>,
    pub uid: Option<u32>,
}

pub fn proc_status(pid: u32) -> Option<ProcStatus> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let mut st = ProcStatus {
        name: None,
        ppid: None,
        uid: None,
    };
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("Name:") {
            st.name = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("PPid:") {
            st.ppid = v.trim().parse().ok();
        } else if let Some(v) = line.strip_prefix("Uid:") {
            st.uid = v.split_whitespace().next().and_then(|u| u.parse().ok());
        }
    }
    Some(st)
}

pub fn proc_uid(pid: u32) -> Option<u32> {
    proc_status(pid).and_then(|s| s.uid)
}

pub fn proc_cmdline(pid: u32) -> Option<String> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let parts: Vec<&[u8]> = raw.split(|&b| b == 0).filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        return None;
    }
    Some(
        parts
            .iter()
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// Return the cgroup path for a process without dereferencing anything in the
/// cgroup hierarchy. This is context metadata, not payload collection.
pub fn proc_cgroup(pid: u32) -> Option<String> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    text.lines()
        .filter_map(|line| line.split_once("::").map(|(_, path)| path.to_string()))
        .next()
}

/// Best-effort container identity from a cgroup leaf. We only return a
/// hexadecimal leaf of a conventional runtime length, avoiding guesses from
/// arbitrary cgroup names.
fn container_id_from_cgroup(cgroup: &str) -> Option<String> {
    cgroup
        .split('/')
        .rev()
        .flat_map(|part| part.split(['-', '_', '.']))
        .find(|part| {
            matches!(part.len(), 32 | 64) && part.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
        })
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_addresses_render_both_families() {
        let mut v4 = [0u8; 16];
        v4[..4].copy_from_slice(&[192, 0, 2, 10]);
        assert_eq!(socket_addr(2, &v4).as_deref(), Some("192.0.2.10"));

        let v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(socket_addr(10, &v6).as_deref(), Some("2001:db8::1"));
        assert!(socket_addr(999, &v6).is_none());
    }

    #[test]
    fn security_names_and_w_x_marker_inputs_are_stable() {
        assert_eq!(syscall_name(321), "bpf");
        assert_eq!(syscall_name(322), "execveat");
        assert_eq!(syscall_name(u32::MAX), "unknown");
        assert_eq!(tcp_state_name(2), "syn_sent");
        assert_eq!(tcp_state_name(10), "listen");
    }

    #[test]
    fn token_bucket_limits_and_refills() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(5.0, t0);
        // Burst of one second of rate is allowed, then drops.
        for _ in 0..5 {
            assert!(b.allow(t0));
        }
        assert!(!b.allow(t0));
        assert!(!b.allow(t0));
        // Half a second later ~2.5 tokens refill (2 usable).
        let t1 = t0 + Duration::from_millis(500);
        assert!(b.allow(t1));
        assert!(b.allow(t1));
        assert!(!b.allow(t1));
        // Unlimited mode never drops.
        let mut open = TokenBucket::new(0.0, t0);
        for _ in 0..1000 {
            assert!(open.allow(t0));
        }
    }

    #[test]
    fn drop_reporting_is_periodic() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(1.0, t0);
        assert!(b.allow(t0));
        assert!(!b.allow(t0));
        assert!(!b.allow(t0));
        // No report before 60s even with drops.
        assert_eq!(b.report_due(t0 + Duration::from_secs(30)), None);
        let n = b.report_due(t0 + Duration::from_secs(61));
        assert_eq!(n, Some(2));
        // Counter reset: nothing to report now.
        assert_eq!(b.report_due(t0 + Duration::from_secs(122)), None);
    }

    #[test]
    fn iouring_opcode_names() {
        assert_eq!(iouring_op_name(18), "openat");
        assert_eq!(iouring_op_name(16), "connect");
        assert_eq!(iouring_op_name(22), "read");
        assert_eq!(iouring_op_name(23), "write");
        assert_eq!(iouring_op_name(45), "socket");
        assert_eq!(iouring_op_name(200), "OP200");
    }

    #[test]
    fn cred_syscall_names() {
        assert_eq!(cred_syscall_name(0), "setuid");
        assert_eq!(cred_syscall_name(1), "setreuid");
        assert_eq!(cred_syscall_name(2), "setresuid");
        assert_eq!(cred_syscall_name(99), "unknown");
    }
}
