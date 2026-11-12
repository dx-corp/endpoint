//! BPF self-defense introspection: every 60s, enumerate loaded BPF
//! programs and maps via bpftool and diff against the previous snapshot.
//!
//! - New or removed programs/maps that are NOT ours → `bpfcheck` events
//!   (a BPF rootkit loading, or an unknown agent changing BPF state).
//! - Our own programs or maps disappearing → WARN-level `bpfcheck` event
//!   (tamper: someone detached or unloaded Merlin's probes).
//!
//! Enumeration uses aya's loaded_programs / loaded_maps (the
//! BPF_*_GET_NEXT_ID, *_GET_FD_BY_ID and OBJ_GET_INFO_BY_FD walk, with each
//! descriptor owned by aya) — bpftool on this host has no build matching the
//! pve kernel ("bpftool not found for kernel 7.0.14-8").

use std::collections::BTreeMap;
use std::thread;
use std::time::Duration;

use aya::maps::{MapError, MapType};
use aya::programs::{ProgramError, ProgramType};
use serde_json::Value;
use tokio::sync::mpsc::Sender;

use crate::spool;

const SCAN_INTERVAL: Duration = Duration::from_secs(60);

/// Program names loaded from our own eBPF object (see merlin-ebpf).
const OUR_PROGS: [&str; 11] = [
    "sched_process_exec",
    "sched_process_fork",
    "do_exit",
    "inet_sock_set_state",
    "raw_syscalls_sys_enter",
    "sys_enter_memfd_create",
    "sys_enter_setuid",
    "sys_enter_setreuid",
    "sys_enter_setresuid",
    "sys_enter_io_uring_setup",
    "io_uring_submit_req",
];

const OUR_MAPS: [&str; 2] = ["EVENTS", "PID_NS"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfObject {
    pub id: u64,
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BpfSnapshot {
    pub progs: BTreeMap<u64, BpfObject>,
    pub maps: BTreeMap<u64, BpfObject>,
}

pub fn is_our_prog(name: &str) -> bool {
    OUR_PROGS.contains(&name)
}

pub fn is_our_map(name: &str) -> bool {
    OUR_MAPS.contains(&name)
}

pub enum DiffEvent {
    ForeignLoaded(BpfObject),
    ForeignRemoved(BpfObject),
    OwnRemoved(BpfObject),
}

/// Ids (prog and map) that belonged to this daemon at baseline time:
/// name-matched from our eBPF object. Self-exclusion by id, not name —
/// another Merlin instance on the same host uses the same program names.
#[derive(Default, Clone)]
pub struct OwnIds {
    pub progs: std::collections::BTreeSet<u64>,
    pub maps: std::collections::BTreeSet<u64>,
}

impl OwnIds {
    pub fn from_snapshot(snap: &BpfSnapshot) -> Self {
        OwnIds {
            progs: snap
                .progs
                .values()
                .filter(|o| is_our_prog(&o.name))
                .map(|o| o.id)
                .collect(),
            maps: snap
                .maps
                .values()
                .filter(|o| is_our_map(&o.name))
                .map(|o| o.id)
                .collect(),
        }
    }
}

/// Diff two snapshots. Own objects (by id) are excluded from foreign
/// add/remove; a missing OWN object is the tamper signal.
pub fn diff(prev: &BpfSnapshot, cur: &BpfSnapshot, own: &OwnIds) -> Vec<DiffEvent> {
    let mut out = Vec::new();
    for (id, obj) in &cur.progs {
        if !prev.progs.contains_key(id) && !own.progs.contains(id) {
            out.push(DiffEvent::ForeignLoaded(obj.clone()));
        }
    }
    for (id, obj) in &prev.progs {
        if !cur.progs.contains_key(id) {
            if own.progs.contains(id) {
                out.push(DiffEvent::OwnRemoved(obj.clone()));
            } else {
                out.push(DiffEvent::ForeignRemoved(obj.clone()));
            }
        }
    }
    for (id, obj) in &cur.maps {
        if !prev.maps.contains_key(id) && !own.maps.contains(id) {
            out.push(DiffEvent::ForeignLoaded(obj.clone()));
        }
    }
    for (id, obj) in &prev.maps {
        if !cur.maps.contains_key(id) {
            if own.maps.contains(id) {
                out.push(DiffEvent::OwnRemoved(obj.clone()));
            } else {
                out.push(DiffEvent::ForeignRemoved(obj.clone()));
            }
        }
    }
    out
}

/// The kind label of a program type: the names earlier events used for the
/// common types, snake case of aya's name otherwise.
fn program_kind(program_type: Result<ProgramType, ProgramError>) -> String {
    match program_type {
        Ok(ProgramType::SocketFilter) => "socket_filter".into(),
        Ok(ProgramType::KProbe) => "kprobe".into(),
        Ok(ProgramType::SchedClassifier) => "sched_cls".into(),
        Ok(ProgramType::SchedAction) => "sched_act".into(),
        Ok(ProgramType::TracePoint) => "tracepoint".into(),
        Ok(ProgramType::Xdp) => "xdp".into(),
        Ok(ProgramType::PerfEvent) => "perf_event".into(),
        Ok(ProgramType::CgroupSkb) => "cgroup_skb".into(),
        Ok(other) => snake_case(&format!("{other:?}")),
        Err(_) => "unknown".into(),
    }
}

fn map_kind(map_type: Result<MapType, MapError>) -> String {
    match map_type {
        Ok(map_type) => snake_case(&format!("{map_type:?}")),
        Err(_) => "unknown".into(),
    }
}

fn snake_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    for (index, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if index > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Collect one id space. An object that unloads mid-walk yields an error for
/// its id and is skipped (expected races); a walk with errors and no object
/// at all (no privilege, no BPF) fails the snapshot.
fn collect<E: std::fmt::Display>(
    items: impl Iterator<Item = Result<BpfObject, E>>,
) -> Result<BTreeMap<u64, BpfObject>, String> {
    let mut out = BTreeMap::new();
    let mut first_error = None;
    for item in items {
        match item {
            Ok(object) => {
                out.insert(object.id, object);
            }
            Err(error) => {
                first_error.get_or_insert_with(|| error.to_string());
            }
        }
    }
    match first_error {
        Some(error) if out.is_empty() => Err(error),
        _ => Ok(out),
    }
}

/// Every loaded program and map, through aya's enumeration, which owns each
/// descriptor it opens. (A hand-rolled bpf(2) walk here used the wrong
/// command numbers: the "fd" it closed was a zero return code, so every scan
/// closed descriptor 0, whatever the process had open there.)
fn snapshot() -> Result<BpfSnapshot, String> {
    let progs = collect(aya::programs::loaded_programs().map(|program| {
        program.map(|program| BpfObject {
            id: u64::from(program.id()),
            name: program.name_as_str().unwrap_or_default().to_owned(),
            kind: program_kind(program.program_type()),
        })
    }))?;
    let maps = collect(aya::maps::loaded_maps().map(|map| {
        map.map(|map| BpfObject {
            id: u64::from(map.id()),
            name: map.name_as_str().unwrap_or_default().to_owned(),
            kind: map_kind(map.map_type()),
        })
    }))?;
    Ok(BpfSnapshot { progs, maps })
}

pub fn spawn(tx: Sender<Value>) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("bpfcheck".into())
        .spawn(move || {
            let mut prev = match snapshot() {
                Ok(s) => {
                    log::info!(
                        "bpfcheck: baseline {} progs, {} maps",
                        s.progs.len(),
                        s.maps.len()
                    );
                    s
                }
                Err(e) => {
                    log::warn!("bpfcheck: initial snapshot failed: {e}; monitor disabled");
                    return;
                }
            };
            loop {
                thread::sleep(SCAN_INTERVAL);
                let Ok(cur) = snapshot() else {
                    log::warn!("bpfcheck: snapshot failed");
                    continue;
                };
                let own = OwnIds::from_snapshot(&prev);
                for event in diff(&prev, &cur, &own) {
                    let (op, obj, tamper) = match &event {
                        DiffEvent::ForeignLoaded(o) => ("foreign_load", o, false),
                        DiffEvent::ForeignRemoved(o) => ("foreign_remove", o, false),
                        DiffEvent::OwnRemoved(o) => ("own_removed", o, true),
                    };
                    if tamper {
                        log::warn!(
                            "bpfcheck: MERLIN probe/map disappeared: {} ({})",
                            obj.name,
                            obj.kind
                        );
                    } else {
                        log::info!("bpfcheck: {op} {} ({})", obj.name, obj.kind);
                    }
                    spool::try_send(
                        &tx,
                        serde_json::json!({
                            "ts": spool::now_ts(),
                            "source": "linux-bpfcheck",
                            "source_seq": spool::next_sequence(),
                            "kind": "bpfcheck",
                            "op": op,
                            "prog_name": obj.name,
                            "prog_type": obj.kind,
                            "tamper": tamper,
                        }),
                    );
                }
                prev = cur;
            }
        })
        .expect("spawning bpfcheck thread")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_keep_the_established_names_and_snake_case_the_rest() {
        assert_eq!(program_kind(Ok(ProgramType::TracePoint)), "tracepoint");
        assert_eq!(program_kind(Ok(ProgramType::CgroupSkb)), "cgroup_skb");
        assert_eq!(
            program_kind(Ok(ProgramType::RawTracePoint)),
            "raw_trace_point"
        );
        assert_eq!(map_kind(Ok(MapType::RingBuf)), "ring_buf");
        assert_eq!(snake_case("PerCpuHash"), "per_cpu_hash");
    }

    #[test]
    fn a_walk_skips_racing_ids_but_fails_when_nothing_was_read() {
        let object = obj_id(7, "x", "kprobe");
        let mixed = collect(vec![Err("gone"), Ok(object.clone())].into_iter()).unwrap();
        assert_eq!(mixed.get(&7), Some(&object));
        assert!(collect(vec![Err::<BpfObject, _>("EPERM")].into_iter()).is_err());
        assert!(
            collect(std::iter::empty::<Result<BpfObject, &str>>())
                .unwrap()
                .is_empty()
        );
    }

    /// Root only (the bpf(2) walk needs CAP_SYS_ADMIN); skipped otherwise.
    /// The snapshot names the loaded programs and leaves every descriptor it
    /// did not open alone: stdin is still open afterwards.
    #[test]
    fn a_root_snapshot_names_programs_and_keeps_stdin_open() {
        // SAFETY: geteuid has no preconditions and cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        // SAFETY: F_GETFD only reads the descriptor flags of fd 0.
        let stdin_before = unsafe { libc::fcntl(0, libc::F_GETFD) } >= 0;
        let first = snapshot().expect("snapshot as root");
        for _ in 0..3 {
            snapshot().expect("repeated snapshot as root");
        }
        // SAFETY: as above.
        let stdin_after = unsafe { libc::fcntl(0, libc::F_GETFD) } >= 0;
        assert_eq!(stdin_before, stdin_after, "a snapshot closed descriptor 0");
        // A root test host runs systemd, whose cgroup programs are loaded.
        assert!(
            first.progs.values().any(|program| !program.name.is_empty()),
            "no named program was enumerated: {:?}",
            first.progs
        );
    }

    fn obj_id(id: u64, name: &str, kind: &str) -> BpfObject {
        BpfObject {
            id,
            name: name.into(),
            kind: kind.into(),
        }
    }

    #[test]
    fn diff_classifies_foreign_and_own() {
        let mut prev = BpfSnapshot::default();
        prev.progs
            .insert(1, obj_id(1, "sched_process_exec", "tracepoint"));
        prev.progs.insert(2, obj_id(2, "evil", "kprobe"));
        prev.maps.insert(10, obj_id(10, "EVENTS", "ringbuf"));
        let mut cur = BpfSnapshot::default();
        cur.progs
            .insert(1, obj_id(1, "sched_process_exec", "tracepoint"));
        cur.progs.insert(3, obj_id(3, "new_rootkit", "kprobe"));
        cur.maps.insert(10, obj_id(10, "EVENTS", "ringbuf"));

        let own = OwnIds {
            progs: [1u64].into_iter().collect(),
            maps: [10u64].into_iter().collect(),
        };
        let events = diff(&prev, &cur, &own);
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, DiffEvent::ForeignLoaded(o) if o.name == "new_rootkit"))
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, DiffEvent::ForeignRemoved(o) if o.name == "evil"))
        );
        // EVENTS map unchanged → no own_removed; prog 1 unchanged → none.
        assert!(!events.iter().any(|e| matches!(e, DiffEvent::OwnRemoved(_))));

        // Now our probe vanishes: tamper.
        let empty = BpfSnapshot::default();
        let own2 = OwnIds::from_snapshot(&cur);
        let events = diff(&cur, &empty, &own2);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, DiffEvent::OwnRemoved(o) if o.name == "sched_process_exec"))
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, DiffEvent::OwnRemoved(o) if o.name == "EVENTS"))
        );
    }
}
