//! BPF self-defense introspection: every 60s, enumerate loaded BPF
//! programs and maps via bpftool and diff against the previous snapshot.
//!
//! - New or removed programs/maps that are NOT ours → `bpfcheck` events
//!   (a BPF rootkit loading, or an unknown agent changing BPF state).
//! - Our own programs or maps disappearing → WARN-level `bpfcheck` event
//!   (tamper: someone detached or unloaded Merlin's probes).
//!
//! Enumeration uses raw BPF_PROG_GET_NEXT_ID / BPF_MAP_GET_NEXT_ID /
//! BPF_OBJ_GET_INFO_BY_FD syscalls — bpftool on this host has no build
//! matching the pve kernel ("bpftool not found for kernel 7.0.14-8"),
//! so the shell-out path was replaced before it ever ran.

use std::collections::BTreeMap;
use std::io;
use std::thread;
use std::time::Duration;

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

const BPF_PROG_GET_NEXT_ID: i64 = 11;
const BPF_MAP_GET_NEXT_ID: i64 = 12;
const BPF_PROG_GET_FD_BY_ID: i64 = 15;
const BPF_MAP_GET_FD_BY_ID: i64 = 16;
const BPF_OBJ_GET_INFO_BY_FD: i64 = 24;

// Field offsets of the name[16] member in bpf_prog_info / bpf_map_info.
const PROG_INFO_NAME_OFF: usize = 68;
const MAP_INFO_NAME_OFF: usize = 24;

fn prog_type_name(t: u32) -> String {
    match t {
        1 => "socket_filter".into(),
        2 => "kprobe".into(),
        3 => "sched_cls".into(),
        4 => "sched_act".into(),
        5 => "tracepoint".into(),
        6 => "xdp".into(),
        7 => "perf_event".into(),
        8 => "cgroup_skb".into(),
        other => format!("type{other}"),
    }
}

/// Walk one id space. Names read from the kernel via OBJ_GET_INFO_BY_FD;
/// unreadable entries are skipped (races with unload are expected).
fn enumerate(
    get_next: i64,
    get_fd: i64,
    name_off: usize,
    typed: bool,
) -> Result<BTreeMap<u64, BpfObject>, String> {
    let mut out = BTreeMap::new();
    let mut id: u32 = 0;
    loop {
        let mut attr = [0u8; 12];
        attr[..4].copy_from_slice(&id.to_ne_bytes());
        let rc = unsafe { libc::syscall(libc::SYS_bpf, get_next, attr.as_mut_ptr(), 12) } as i32;
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                break;
            }
            return Err(err.to_string());
        }
        let next = u32::from_ne_bytes(attr[4..8].try_into().unwrap());
        let mut fdattr = [0u8; 8];
        fdattr[..4].copy_from_slice(&next.to_ne_bytes());
        let fd = unsafe { libc::syscall(libc::SYS_bpf, get_fd, fdattr.as_mut_ptr(), 8) } as i32;
        id = next;
        if fd < 0 {
            continue;
        }
        let mut info = [0u8; 256];
        let mut iattr = [0u8; 16];
        iattr[..4].copy_from_slice(&(fd as u32).to_ne_bytes());
        iattr[4..8].copy_from_slice(&(256u32).to_ne_bytes());
        iattr[8..16].copy_from_slice(&(info.as_mut_ptr() as u64).to_ne_bytes());
        let irc = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_OBJ_GET_INFO_BY_FD,
                iattr.as_mut_ptr(),
                16,
            )
        } as i32;
        unsafe { libc::close(fd) };
        if irc == 0 {
            let ty = u32::from_ne_bytes(info[0..4].try_into().unwrap());
            let name_bytes = &info[name_off..name_off + 16];
            let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(16);
            out.insert(
                next as u64,
                BpfObject {
                    id: next as u64,
                    name: String::from_utf8_lossy(&name_bytes[..end]).into_owned(),
                    kind: if typed {
                        prog_type_name(ty)
                    } else {
                        format!("type{ty}")
                    },
                },
            );
        }
    }
    Ok(out)
}

fn snapshot() -> Result<BpfSnapshot, String> {
    Ok(BpfSnapshot {
        progs: enumerate(
            BPF_PROG_GET_NEXT_ID,
            BPF_PROG_GET_FD_BY_ID,
            PROG_INFO_NAME_OFF,
            true,
        )?,
        maps: enumerate(
            BPF_MAP_GET_NEXT_ID,
            BPF_MAP_GET_FD_BY_ID,
            MAP_INFO_NAME_OFF,
            false,
        )?,
    })
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

    fn obj(name: &str, kind: &str) -> BpfObject {
        BpfObject {
            id: 0,
            name: name.into(),
            kind: kind.into(),
        }
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
