//! One-shot posture report (`merlin posture`).
//!
//! (a) Processes holding AF_PACKET sockets (sniffers, including ourselves,
//! which is marked) — from /proc/net/packet inode + fd sweep.
//! (b) AF_UNIX peer graph via NETLINK_SOCK_DIAG: non-system processes
//! connected to container runtime sockets (/var/run/docker.sock,
//! containerd, crio) — a common container-escape surface.
//!
//! This is a point-in-time report, not a stream; it always exits 0 unless
//! the kernel interfaces themselves fail.

use std::collections::HashMap;
use std::io;

use anyhow::{Context, Result};

const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;
const UDIAG_SHOW_NAME: u32 = 1;
const UDIAG_SHOW_PEER: u32 = 4;
const UNIX_DIAG_NAME: u16 = 0;
const UNIX_DIAG_PEER: u16 = 2;

/// Container runtime sockets worth flagging peers of.
const GUARDED_SOCKET_PATHS: [&str; 4] = [
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/var/run/crio/crio.sock",
];

/// comms allowed to talk to runtime sockets without a flag.
const SYSTEM_OK_COMMS: [&str; 6] = [
    "containerd",
    "dockerd",
    "kubelet",
    "runc",
    "systemd",
    "podman",
];

/// One parsed unix_diag entry.
#[derive(Debug, PartialEq, Eq)]
pub struct UnixDiagEntry {
    pub ino: u32,
    pub name: Option<String>,
    pub peer: Option<u32>,
}

/// Parse a udiag_msg (16 bytes) + attributes.
pub fn parse_unix_diag(buf: &[u8]) -> Option<UnixDiagEntry> {
    if buf.len() < 16 {
        return None;
    }
    let ino = u32::from_ne_bytes(buf[4..8].try_into().ok()?);
    let mut entry = UnixDiagEntry {
        ino,
        name: None,
        peer: None,
    };
    let mut attrs = &buf[16..];
    while attrs.len() >= 4 {
        let len = u16::from_ne_bytes(attrs[0..2].try_into().ok()?) as usize;
        let ty = u16::from_ne_bytes(attrs[2..4].try_into().ok()?);
        if len < 4 || len > attrs.len() {
            break;
        }
        let data = &attrs[4..len];
        match ty {
            UNIX_DIAG_NAME => {
                entry.name = Some(
                    String::from_utf8_lossy(data)
                        .trim_start_matches('\0')
                        .trim_end_matches('\0')
                        .to_string(),
                );
            }
            UNIX_DIAG_PEER if data.len() >= 4 => {
                entry.peer = Some(u32::from_ne_bytes(data[..4].try_into().ok()?));
            }
            _ => {}
        }
        attrs = &attrs[(len + 3) & !3..];
    }
    Some(entry)
}

/// /proc/net/packet lines → socket inodes.
pub fn packet_socket_inodes(text: &str) -> Vec<u64> {
    text.lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().nth(8)?.parse().ok())
        .collect()
}

fn unix_diag_dump() -> Result<Vec<UnixDiagEntry>> {
    // ss(8) uses SOCK_RAW and an explicit bind here; SOCK_DGRAM unbound
    // is silently ignored by this kernel (verified 2026-08-02).
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW,
            4, /* NETLINK_SOCK_DIAG */
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("opening NETLINK_SOCK_DIAG");
    }
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error()).context("binding NETLINK_SOCK_DIAG");
    }
    let mut req = vec![0u8; 16 + 24];
    req[0..4].copy_from_slice(&(40u32.to_ne_bytes())); // len
    req[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    req[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    req[8..12].copy_from_slice(&1u32.to_ne_bytes()); // seq
    req[16] = 1; // AF_UNIX
    req[20..24].copy_from_slice(&0xFFFF_FFFFu32.to_ne_bytes()); // states
    req[28..32].copy_from_slice(&(UDIAG_SHOW_NAME | UDIAG_SHOW_PEER).to_ne_bytes());
    let rc = unsafe { libc::send(fd, req.as_ptr() as *const _, req.len(), 0) };
    if rc < 0 {
        return Err(io::Error::last_os_error()).context("unix_diag send");
    }

    let mut out = Vec::new();
    let mut buf = vec![0u8; 128 * 1024];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error()).context("unix_diag recv");
        }
        let mut off = 0usize;
        let n = n as usize;
        let mut done = false;
        while off + 16 <= n {
            let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
            let ty = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
            if len < 16 || off + len > n {
                done = true;
                break;
            }
            match ty {
                NLMSG_DONE => {
                    done = true;
                    break;
                }
                NLMSG_ERROR => {
                    anyhow::bail!("unix_diag returned NLMSG_ERROR");
                }
                _ => {
                    if let Some(entry) = parse_unix_diag(&buf[off + 16..off + len]) {
                        out.push(entry);
                    }
                }
            }
            off += (len + 3) & !3;
        }
        if done {
            break;
        }
    }
    unsafe { libc::close(fd) };
    Ok(out)
}

/// One pass over /proc/<pid>/fd: socket inode → (pid, comm). Posture
/// needs dozens of lookups; per-inode sweeps are O(peers × all fds).
fn socket_owners() -> HashMap<u64, (u32, String)> {
    let mut out = HashMap::new();
    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return out;
    };
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let s = target.as_os_str().as_encoded_bytes();
            if let Some(inner) = s
                .strip_prefix(b"socket:[")
                .and_then(|b| b.strip_suffix(b"]"))
                .and_then(|b| std::str::from_utf8(b).ok())
                .and_then(|t| t.parse::<u64>().ok())
            {
                let comm = crate::telemetry::proc_status(pid).and_then(|st| st.name);
                if let Some(comm) = comm {
                    out.insert(inner, (pid, comm));
                }
            }
        }
    }
    out
}

pub fn run() -> Result<()> {
    let self_pid = std::process::id();
    let owners = socket_owners();

    println!("== AF_PACKET socket holders (sniffers) ==");
    let text = std::fs::read_to_string("/proc/net/packet").unwrap_or_default();
    let mut sniffers = 0;
    for inode in packet_socket_inodes(&text) {
        match owners.get(&inode) {
            Some((pid, comm)) => {
                sniffers += 1;
                // The posture CLI is a separate process from the daemon;
                // our own AF_PACKET capture lives in the "merlin" daemon.
                let tag = if *pid == self_pid || comm == "merlin" {
                    " (self)"
                } else {
                    ""
                };
                println!("  pid {pid} comm {comm:?} inode {inode}{tag}");
            }
            None => println!("  inode {inode} (owner gone or not visible)"),
        }
    }
    if sniffers == 0 {
        println!("  (none)");
    }

    println!("== AF_UNIX peers of container runtime sockets ==");
    let entries = unix_diag_dump().unwrap_or_else(|e| {
        println!("  unix_diag unavailable: {e}");
        Vec::new()
    });
    let guarded: HashMap<u32, &str> = entries
        .iter()
        .filter(|e| {
            e.name
                .as_deref()
                .is_some_and(|n| GUARDED_SOCKET_PATHS.contains(&n) || n.contains("docker.sock"))
        })
        .map(|e| (e.ino, e.name.as_deref().unwrap()))
        .collect();
    if guarded.is_empty() {
        println!("  (no guarded sockets present)");
    }
    let mut flagged = 0;
    for (ino, path) in &guarded {
        println!("  {path} (inode {ino})");
        for entry in &entries {
            if entry.peer == Some(*ino) {
                match owners.get(&(entry.ino as u64)) {
                    Some((pid, comm)) => {
                        let system = SYSTEM_OK_COMMS.contains(&comm.as_str());
                        if !system {
                            flagged += 1;
                        }
                        println!(
                            "    pid {pid} comm {comm:?}{}",
                            if system {
                                " (system, ok)"
                            } else {
                                "  <-- NON-SYSTEM"
                            }
                        );
                    }
                    None => println!("    peer inode {} (owner gone)", entry.ino),
                }
            }
        }
    }

    println!("posture: {sniffers} sniffer(s), {flagged} non-system runtime-socket client(s)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unix_diag_entry_with_peer() {
        let mut buf = vec![1u8, 1, 11, 0];
        buf.extend_from_slice(&4242u32.to_ne_bytes()); // ino
        buf.extend_from_slice(&[0u8; 8]); // cookie
        // name attr
        let name = b"/var/run/docker.sock\0";
        buf.extend_from_slice(&((4 + name.len()) as u16).to_ne_bytes());
        buf.extend_from_slice(&UNIX_DIAG_NAME.to_ne_bytes());
        buf.extend_from_slice(name);
        while buf.len() % 4 != 0 {
            buf.push(0);
        }
        buf.extend_from_slice(&8u16.to_ne_bytes());
        buf.extend_from_slice(&UNIX_DIAG_PEER.to_ne_bytes());
        buf.extend_from_slice(&7777u32.to_ne_bytes());
        let entry = parse_unix_diag(&buf).unwrap();
        assert_eq!(entry.ino, 4242);
        assert_eq!(entry.name.as_deref(), Some("/var/run/docker.sock"));
        assert_eq!(entry.peer, Some(7777));
    }

    #[test]
    fn parses_packet_socket_lines() {
        let text = "sk       RefCnt Type Proto Iface R Rmem   User   Inode\n\
                    ffff0001 3      3    0003  2     1  0      1000   12345\n\
                    ffff0002 3      3    0003  2     1  0      0      12346\n";
        assert_eq!(packet_socket_inodes(text), vec![12345, 12346]);
    }
}
