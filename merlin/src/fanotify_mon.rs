//! fanotify enforcement monitor.
//!
//! Watches the whole `/` mount for FAN_OPEN_EXEC_PERM events. Every exec on
//! the system blocks in the kernel until we write an allow/deny response —
//! this is Merlin's synchronous prevention point (the analog of a process-
//! creation notify callback failing the create from kernel mode).
//!
//! Raw syscalls are used instead of libc wrappers so the exact flag values
//! are visible; constants are from linux/fanotify.h.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::FromRawFd;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc::Sender;

use crate::rules::{Action, MatchCtx, Rules, RulesHandle};
use crate::spool;

const FAN_CLOEXEC: u32 = 0x0000_0001;
const FAN_CLASS_CONTENT: u32 = 0x0000_0004;
const FAN_MARK_ADD: u32 = 0x0000_0001;
const FAN_MARK_MOUNT: u32 = 0x0000_0010;
const FAN_OPEN_EXEC_PERM: u64 = 0x0004_0000;
const FAN_ALLOW: u32 = 0x01;
const FAN_DENY: u32 = 0x02;
const FANOTIFY_METADATA_VERSION: u8 = 3;

#[repr(C)]
#[derive(Copy, Clone)]
struct Metadata {
    event_len: u32,
    vers: u8,
    _reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

const METADATA_LEN: usize = std::mem::size_of::<Metadata>();

#[repr(C)]
struct Response {
    fd: i32,
    response: u32,
}

/// fanotify_init + mark every mount visible in this mount namespace with
/// FAN_OPEN_EXEC_PERM. FAN_MARK_MOUNT is intentionally per-mount; marking
/// only `/` would leave executables on separate mounts unenforced.
/// Requires CAP_SYS_ADMIN. Exported for `merlin check`.
pub fn init_and_mark(mount: &str) -> Result<i32> {
    let fd = unsafe {
        libc::syscall(
            libc::SYS_fanotify_init,
            FAN_CLOEXEC | FAN_CLASS_CONTENT,
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    } as i32;
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("fanotify_init");
    }
    let mounts = mount_points().unwrap_or_else(|e| {
        log::warn!("could not enumerate mount points ({e}); marking {mount} only");
        vec![mount.to_string()]
    });
    let mut marked = 0usize;
    for mount_point in mounts {
        let path = std::ffi::CString::new(mount_point.as_str())?;
        let rc = unsafe {
            libc::syscall(
                libc::SYS_fanotify_mark,
                fd,
                FAN_MARK_ADD | FAN_MARK_MOUNT,
                FAN_OPEN_EXEC_PERM,
                libc::AT_FDCWD,
                path.as_ptr(),
            )
        } as i32;
        if rc < 0 {
            if mount_point == mount {
                let err = io::Error::last_os_error();
                unsafe { libc::close(fd) };
                return Err(err).context("fanotify_mark FAN_OPEN_EXEC_PERM");
            }
            log::warn!(
                "fanotify: skipping mount {mount_point}: {}",
                io::Error::last_os_error()
            );
        } else {
            marked += 1;
        }
    }
    if marked == 0 {
        unsafe { libc::close(fd) };
        anyhow::bail!("fanotify: no mount points could be marked");
    }
    Ok(fd)
}

fn mount_points() -> Result<Vec<String>> {
    let text =
        fs::read_to_string("/proc/self/mountinfo").context("reading /proc/self/mountinfo")?;
    let mut points = vec!["/".to_string()];
    for line in text.lines() {
        let Some(raw) = line.split_whitespace().nth(4) else {
            continue;
        };
        points.push(unescape_mountinfo(raw));
    }
    points.sort();
    points.dedup();
    Ok(points)
}

fn unescape_mountinfo(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let oct = &bytes[i + 1..i + 4];
            if oct.iter().all(|b| (b'0'..=b'7').contains(b)) {
                let value = (oct[0] - b'0') * 64 + (oct[1] - b'0') * 8 + oct[2] - b'0';
                out.push(value as char);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// How the AUTH point treats an executable it cannot hash within the
/// synchronous bound.
#[derive(Debug, Clone, Copy)]
pub struct HashPolicy {
    /// Wall-clock bound on one exec's hash. A byte cap would be worse on
    /// both ends: attacker-controllable (pad past it) and needlessly hostile
    /// to the large-but-legitimate binaries (Electron, ML runtimes) a size
    /// limit catches first. Time is what the enforcement thread actually
    /// has to protect — every exec on the box waits behind it.
    pub budget: Duration,
    /// Allow an exec whose hash blew the budget even when a hash-based block
    /// rule would otherwise have to be resolved against it. Restores the
    /// fail-open behaviour, at the cost of a bypass for anything an attacker
    /// can make slow to read.
    pub allow_unhashable: bool,
}

impl Default for HashPolicy {
    fn default() -> Self {
        Self {
            budget: Duration::from_secs(1),
            allow_unhashable: false,
        }
    }
}

/// Start the monitor thread. The fd is created before spawning so `run`
/// fails fast if fanotify is unavailable.
pub fn spawn(
    rules: RulesHandle,
    tx: Sender<Value>,
    policy: HashPolicy,
    alert: Option<crate::alert::AlertHook>,
) -> Result<std::thread::JoinHandle<()>> {
    let fd = init_and_mark("/")?;
    log::info!("fanotify: watching / for FAN_OPEN_EXEC_PERM");
    Ok(std::thread::Builder::new()
        .name("fanotify".into())
        .spawn(move || run_loop(fd, rules, tx, policy, alert))
        .context("spawning fanotify thread")?)
}

fn run_loop(
    fd: i32,
    rules: RulesHandle,
    tx: Sender<Value>,
    policy: HashPolicy,
    alert: Option<crate::alert::AlertHook>,
) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            log::error!("fanotify read failed: {err}; enforcement stopped");
            return;
        }
        let mut off = 0usize;
        let n = n as usize;
        while off + METADATA_LEN <= n {
            let meta: Metadata =
                unsafe { std::ptr::read_unaligned(buf[off..].as_ptr() as *const Metadata) };
            let len = meta.event_len as usize;
            if len < METADATA_LEN || off + len > n {
                break;
            }
            if meta.vers == FANOTIFY_METADATA_VERSION && meta.mask & FAN_OPEN_EXEC_PERM != 0 {
                handle_event(fd, &meta, &rules.get(), &tx, policy, &alert);
            }
            off += len;
        }
    }
}

fn handle_event(
    mon_fd: i32,
    meta: &Metadata,
    rules: &Rules,
    tx: &Sender<Value>,
    policy: HashPolicy,
    alert: &Option<crate::alert::AlertHook>,
) {
    if meta.fd < 0 {
        return;
    }
    let event_fd = meta.fd;
    let path = fs::read_link(format!("/proc/self/fd/{event_fd}")).ok();
    let basename = path
        .as_ref()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned());
    let status = crate::telemetry::proc_status(meta.pid as u32);
    let uid = status.as_ref().and_then(|s| s.uid);
    let comm = status.and_then(|s| s.name);
    let cmdline = crate::telemetry::proc_cmdline(meta.pid as u32);

    // Only hash when some block rule actually matches on sha256 — hashing
    // every executed binary on / would be wasted work otherwise.
    let needs_hash = rules
        .rules
        .iter()
        .any(|r| r.action == Action::Block && r.has_sha256_selector());
    let mut unhashable = false;
    let sha256 = if needs_hash {
        match sha256_fd(event_fd, policy.budget) {
            Ok(hash) => Some(hash),
            Err(HashError::Timeout(budget)) => {
                // Attacker-controllable: making the read slow (padding, a
                // hostile fuse/network mount) must not silently disable the
                // sha256 selector.
                unhashable = true;
                log::warn!("fanotify: hashing {path:?} blew the {budget:?} budget");
                None
            }
            Err(HashError::Io(e)) => {
                log::warn!(
                    "fanotify: bounded sha256 unavailable: {e}; allowing unless another selector matches"
                );
                None
            }
        }
    } else {
        None
    };

    let path_str = path.as_ref().map(|p| p.display().to_string());
    let ctx = MatchCtx {
        sha256: sha256.as_deref(),
        basename: basename.as_deref(),
        path: path_str.as_deref(),
        cmdline: cmdline.as_deref(),
        uid,
        // No lineage evidence at the fanotify decision point (the proctree
        // cache lives in the telemetry path); ancestor selectors simply
        // never match here — fail-safe. comm is resolved from /proc.
        comm: comm.as_deref(),
        parent_basename: None,
        ancestors: &[],
    };
    let mut matched: Vec<String> = rules
        .rules
        .iter()
        .filter(|r| r.action == Action::Block && r.matches(&ctx))
        .map(|r| r.name.clone())
        .collect();
    if unhashable && !policy.allow_unhashable {
        for name in unresolved_hash_rules(rules, &ctx) {
            log::warn!(
                "fanotify: denying unhashable exec {path:?}; block rule {name} cannot be evaluated (--allow-unhashable fails open instead)"
            );
            if !matched.contains(&name) {
                matched.push(name);
            }
        }
    }

    let verdict = if matched.is_empty() {
        FAN_ALLOW
    } else {
        FAN_DENY
    };
    respond(mon_fd, event_fd, verdict);
    unsafe { libc::close(event_fd) };

    if verdict == FAN_DENY {
        log::info!(
            "fanotify: DENY exec pid={} path={:?} rules={:?}",
            meta.pid,
            path,
            matched
        );
        if let Some(hook) = alert {
            hook.fire(crate::alert::AlertHook::alert(
                "deny",
                &matched,
                comm.as_deref().unwrap_or(""),
                path_str.as_deref(),
            ));
        }
        spool::try_send(
            tx,
            serde_json::json!({
                "ts": spool::now_ts(),
                "source": "linux-fanotify",
                "source_seq": spool::next_sequence(),
                "kind": "deny",
                "pid": meta.pid,
                "uid": uid,
                "path": path.map(|p| p.display().to_string()),
                "sha256": sha256,
                "cgroup": (meta.pid > 0)
                    .then_some(meta.pid as u32)
                    .and_then(crate::telemetry::proc_cgroup),
                "matched_rules": matched,
            }),
        );
    }
}

/// Block rules whose verdict hinges on a hash that could not be computed.
/// Their other selectors still have to hold, so a rule scoped to a path or
/// uid does not deny unrelated oversized executables.
fn unresolved_hash_rules(rules: &Rules, ctx: &MatchCtx) -> Vec<String> {
    rules
        .rules
        .iter()
        .filter(|r| r.action == Action::Block && r.matches_with_unresolved_sha256(ctx))
        .map(|r| r.name.clone())
        .collect()
}

fn respond(mon_fd: i32, event_fd: i32, verdict: u32) {
    let resp = Response {
        fd: event_fd,
        response: verdict,
    };
    unsafe {
        libc::write(
            mon_fd,
            &resp as *const Response as *const _,
            std::mem::size_of::<Response>(),
        )
    };
}

/// Why a synchronous hash is unavailable. `Timeout` is kept separate
/// because an attacker can force it deterministically (a payload that is
/// slow to read), unlike a transient I/O error.
#[derive(Debug)]
pub enum HashError {
    Timeout(Duration),
    Io(anyhow::Error),
}

impl std::fmt::Display for HashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout(budget) => {
                write!(f, "hashing did not finish within {budget:?}")
            }
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

/// sha256 of an already-open fd (the fanotify event fd). Reading via the
/// event fd itself avoids re-opening the path and racing the file.
pub fn sha256_fd(fd: i32, budget: Duration) -> std::result::Result<String, HashError> {
    let dup = unsafe { libc::dup(fd) };
    if dup < 0 {
        return Err(HashError::Io(
            anyhow::Error::from(io::Error::last_os_error()).context("dup event fd"),
        ));
    }
    let mut file = unsafe { File::from_raw_fd(dup) };
    file.seek(SeekFrom::Start(0)).map_err(HashError::from)?;
    let mut hasher = Sha256::new();
    // Chunked rather than io::copy so the budget is checked while reading:
    // the deadline is only enforced when there is more to read, so a file
    // that finishes right at the bound still hashes.
    let mut buf = vec![0u8; 256 * 1024];
    let start = Instant::now();
    loop {
        if start.elapsed() > budget {
            return Err(HashError::Timeout(budget));
        }
        let n = file.read(&mut buf).map_err(HashError::from)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

impl From<io::Error> for HashError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.into())
    }
}

/// sha256 of a path; used by `merlin gen-hash`.
pub fn sha256_path(path: &Path) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use super::*;

    #[test]
    fn a_budget_that_cannot_be_exhausted_hashes_the_whole_file() {
        let mut path = std::env::temp_dir();
        path.push(format!("merlin-hash-budget-{}", std::process::id()));
        std::fs::write(&path, vec![0u8; 1024 * 1024]).unwrap();
        let file = File::open(&path).unwrap();
        assert_eq!(
            sha256_fd(file.as_raw_fd(), Duration::from_secs(3600)).unwrap(),
            sha256_path(&path).unwrap(),
            "a size no byte cap would have allowed still hashes"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn an_exhausted_budget_is_reported_separately_from_io_errors() {
        let mut path = std::env::temp_dir();
        path.push(format!("merlin-hash-{}", std::process::id()));
        std::fs::write(&path, vec![0u8; 4096]).unwrap();
        let file = File::open(&path).unwrap();
        // Zero budget: the check runs before the first read.
        assert!(matches!(
            sha256_fd(file.as_raw_fd(), Duration::ZERO),
            Err(HashError::Timeout(_))
        ));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn unhashable_exec_resolves_only_rules_that_still_apply() {
        let rules = Rules::parse(concat!(
            "rules:\n",
            "  - name: hash-only\n    match:\n      sha256: abc\n    action: block\n",
            "  - name: scoped\n    match_all:\n      sha256: abc\n      path_prefix: /tmp/\n    action: block\n",
            "  - name: no-hash\n    match:\n      path_basename: ls\n    action: block\n",
        ))
        .unwrap();
        let ctx = MatchCtx {
            basename: Some("payload"),
            path: Some("/home/user/payload"),
            ..Default::default()
        };
        assert_eq!(unresolved_hash_rules(&rules, &ctx), vec!["hash-only"]);
        let in_tmp = MatchCtx {
            path: Some("/tmp/payload"),
            ..ctx
        };
        assert_eq!(
            unresolved_hash_rules(&rules, &in_tmp),
            vec!["hash-only", "scoped"]
        );
    }
}
