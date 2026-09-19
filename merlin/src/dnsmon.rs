//! DNS telemetry via AF_PACKET (Linux parity with the macOS BPF provider).
//!
//! A SOCK_RAW socket on every interface captures IPv4/IPv6 UDP and TCP
//! traffic to or from port 53; messages are parsed with the same minimal
//! semantics as macOS's Dns.swift: header + first question only, qname
//! compression pointers rejected (safe by construction against pointer
//! loops), answers/authority/additional sections ignored. DNS over TCP is
//! parsed naively single-segment (2-byte length prefix, whole message in
//! this payload).
//!
//! Process attribution is best-effort: the local endpoint's port is looked
//! up in /proc/net/{udp,udp6,tcp,tcp6} for a socket inode, then
//! /proc/<pid>/fd is swept for that inode. Cached for 60s. Accuracy
//! caveats (documented in linux-sensor.md): short-lived sockets can be
//! gone before the sweep, the query goes to the stub resolver when one is
//! in use (attribution then lands on the stub — the true originator is
//! unknowable from packets, same limitation as macOS's mDNSResponder), and
//! shared sockets (forked children) attribute to the opener we find first.
//!
//! Conditional keys mirror macOS: `own_resolver` when the attributed comm
//! is NOT the system resolver (an app doing its own DNS), and
//! `via_system_resolver` when it is.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::Value;
use tokio::sync::mpsc::Sender;

use crate::spool;
use crate::telemetry;

const ETH_P_ALL: u16 = 0x0003;
const ATTRIBUTION_TTL: Duration = Duration::from_secs(60);

/// comms treated as "the system resolver" (kernel truncates comm to 15
/// chars, so systemd-resolved appears as "systemd-resolve").
const SYSTEM_RESOLVERS: [&str; 5] = [
    "systemd-resolve",
    "systemd-resolved",
    "dnsmasq",
    "named",
    "unbound",
];

#[derive(Debug, PartialEq, Eq)]
pub struct DnsMessage {
    pub id: u16,
    pub is_response: bool,
    pub rcode: Option<u8>,
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl DnsMessage {
    pub fn direction(&self) -> &'static str {
        if self.is_response {
            "response"
        } else {
            "query"
        }
    }

    /// RFC 3597-style rendering: well-known names, TYPE<n> for the rest.
    pub fn qtype_name(&self) -> String {
        match self.qtype {
            1 => "A".into(),
            2 => "NS".into(),
            5 => "CNAME".into(),
            6 => "SOA".into(),
            12 => "PTR".into(),
            15 => "MX".into(),
            16 => "TXT".into(),
            28 => "AAAA".into(),
            33 => "SRV".into(),
            64 => "SVCB".into(),
            65 => "HTTPS".into(),
            255 => "ANY".into(),
            other => format!("TYPE{other}"),
        }
    }
}

fn u16be(buf: &[u8], at: usize) -> u16 {
    (buf[at] as u16) << 8 | buf[at + 1] as u16
}

/// Parse one DNS message (UDP payload, or TCP payload with the 2-byte
/// length prefix already stripped). First question only; nil-equivalent
/// (None) for truncated or malformed input.
pub fn parse_dns(buf: &[u8]) -> Option<DnsMessage> {
    if buf.len() < 12 {
        return None;
    }
    let id = u16be(buf, 0);
    let flags = u16be(buf, 2);
    let qdcount = u16be(buf, 4);
    if qdcount < 1 {
        return None;
    }
    // Question name: length-prefixed labels, no compression pointers.
    let mut off = 12;
    let mut labels: Vec<String> = Vec::new();
    loop {
        if off >= buf.len() {
            return None;
        }
        let len = buf[off] as usize;
        if len == 0 {
            off += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return None; // compression pointer in qname: reject
        }
        if off + 1 + len > buf.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&buf[off + 1..off + 1 + len]).into_owned());
        off += 1 + len;
    }
    if off + 4 > buf.len() {
        return None;
    }
    let qtype = u16be(buf, off);
    let qclass = u16be(buf, off + 2);
    let is_response = flags & 0x8000 != 0;
    Some(DnsMessage {
        id,
        is_response,
        rcode: is_response.then_some((flags & 0x000F) as u8),
        qname: labels.join("."),
        qtype,
        qclass,
    })
}

/// DNS over TCP: 2-byte length prefix, then the message. Naive single
/// segment: parse only when the whole message is present in this payload.
pub fn parse_dns_tcp(buf: &[u8]) -> Option<DnsMessage> {
    if buf.len() < 2 {
        return None;
    }
    let len = u16be(buf, 0) as usize;
    if buf.len() < 2 + len {
        return None;
    }
    parse_dns(&buf[2..2 + len])
}

#[derive(Debug)]
struct Packet {
    sport: u16,
    dport: u16,
    is_udp: bool,
    is_v6: bool,
    payload_off: usize,
    payload_len: usize,
}

/// Ethernet (+IPv4/IPv6) frame decode, port-53 filter built in. IPv4
/// fragments and IPv6 extension headers are out of scope (dropped).
fn decode_frame(buf: &[u8]) -> Option<Packet> {
    if buf.len() < 14 {
        return None;
    }
    let ethertype = u16be(buf, 12);
    match ethertype {
        0x0800 => decode_ipv4(&buf[14..], 14),
        0x86DD => decode_ipv6(&buf[14..], 14),
        _ => None,
    }
}

fn decode_ipv4(buf: &[u8], base: usize) -> Option<Packet> {
    if buf.len() < 20 || buf[0] >> 4 != 4 {
        return None;
    }
    let ihl = (buf[0] & 0x0F) as usize * 4;
    if ihl < 20 || buf.len() < ihl {
        return None;
    }
    let proto = buf[9];
    let frag = u16be(buf, 6);
    if frag & 0x3FFF != 0 {
        return None; // fragmented: out of scope
    }
    decode_transport(proto, &buf[ihl..], base + ihl, false)
}

fn decode_ipv6(buf: &[u8], base: usize) -> Option<Packet> {
    if buf.len() < 40 || buf[0] >> 4 != 6 {
        return None;
    }
    let next = buf[6];
    decode_transport(next, &buf[40..], base + 40, true)
}

fn decode_transport(proto: u8, buf: &[u8], base: usize, is_v6: bool) -> Option<Packet> {
    match proto {
        17 => {
            if buf.len() < 8 {
                return None;
            }
            let sport = u16be(buf, 0);
            let dport = u16be(buf, 2);
            if sport != 53 && dport != 53 {
                return None;
            }
            Some(Packet {
                sport,
                dport,
                is_udp: true,
                is_v6,
                payload_off: base + 8,
                payload_len: buf.len().saturating_sub(8),
            })
        }
        6 => {
            if buf.len() < 20 {
                return None;
            }
            let sport = u16be(buf, 0);
            let dport = u16be(buf, 2);
            if sport != 53 && dport != 53 {
                return None;
            }
            let data_off = (buf[12] >> 4) as usize * 4;
            if data_off < 20 || buf.len() < data_off {
                return None;
            }
            Some(Packet {
                sport,
                dport,
                is_udp: false,
                is_v6,
                payload_off: base + data_off,
                payload_len: buf.len().saturating_sub(data_off),
            })
        }
        _ => None,
    }
}

/// /proc/net/{udp,udp6,tcp,tcp6} → (port, is_v6) → socket inode.
fn socket_inodes() -> HashMap<(u16, bool), u64> {
    let mut out = HashMap::new();
    for (path, v6) in [
        ("/proc/net/udp", false),
        ("/proc/net/udp6", true),
        ("/proc/net/tcp", false),
        ("/proc/net/tcp6", true),
    ] {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            let Some(port_hex) = fields[1].rsplit(':').next() else {
                continue;
            };
            let Ok(port) = u16::from_str_radix(port_hex, 16) else {
                continue;
            };
            let Ok(inode) = fields[9].parse::<u64>() else {
                continue;
            };
            out.insert((port, v6), inode);
        }
    }
    out
}

/// Sweep /proc/<pid>/fd for a socket inode → (pid, comm). First match wins.
pub(crate) fn pid_for_inode(inode: u64) -> Option<(u32, String)> {
    let needle = format!("socket:[{inode}]");
    for entry in fs::read_dir("/proc").ok()?.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let fd_dir = entry.path().join("fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue; // gone or not ours
        };
        for fd in fds.flatten() {
            if let Ok(target) = fs::read_link(fd.path()) {
                if target.as_os_str().as_encoded_bytes() == needle.as_bytes() {
                    let comm = telemetry::proc_status(pid).and_then(|s| s.name);
                    return Some((pid, comm?));
                }
            }
        }
    }
    None
}

struct Attribution {
    map: HashMap<u64, ((u32, String), Instant)>,
    last_sockets: Instant,
    sockets: HashMap<(u16, bool), u64>,
}

impl Attribution {
    fn new() -> Self {
        Attribution {
            map: HashMap::new(),
            last_sockets: Instant::now() - ATTRIBUTION_TTL,
            sockets: HashMap::new(),
        }
    }

    fn lookup(&mut self, port: u16, is_v6: bool) -> Option<(u32, String)> {
        if self.last_sockets.elapsed() >= Duration::from_secs(2) {
            self.sockets = socket_inodes();
            self.last_sockets = Instant::now();
        }
        let inode = *self.sockets.get(&(port, is_v6))?;
        if let Some((hit, at)) = self.map.get(&inode) {
            if at.elapsed() < ATTRIBUTION_TTL {
                return Some(hit.clone());
            }
        }
        let hit = pid_for_inode(inode)?;
        self.map.insert(inode, (hit.clone(), Instant::now()));
        Some(hit)
    }
}

fn open_socket() -> Result<i32> {
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (ETH_P_ALL as u16).to_be() as i32,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error())
            .context("opening AF_PACKET socket (needs CAP_NET_RAW)");
    }
    Ok(fd)
}

/// Start the capture thread.
pub fn spawn(tx: Sender<Value>) -> Result<thread::JoinHandle<()>> {
    let fd = open_socket()?;
    log::info!("dns: capturing port-53 traffic via AF_PACKET");
    Ok(thread::Builder::new()
        .name("dns".into())
        .spawn(move || capture_loop(fd, tx))
        .context("spawning dns thread")?)
}

fn capture_loop(fd: i32, tx: Sender<Value>) {
    let mut attr = Attribution::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            log::error!("dns: recv failed: {err}; capture stopped");
            return;
        }
        let buf = &buf[..n as usize];
        let Some(pkt) = decode_frame(buf) else {
            continue;
        };
        let payload = &buf[pkt.payload_off..pkt.payload_off + pkt.payload_len];
        let msg = if pkt.is_udp {
            parse_dns(payload)
        } else {
            parse_dns_tcp(payload)
        };
        let Some(msg) = msg else { continue };

        // Attribution: the LOCAL endpoint. A query's local side is the
        // source; a response's local side is the destination.
        let (local_port, is_v6) = if msg.is_response {
            (pkt.dport, pkt.is_v6)
        } else {
            (pkt.sport, pkt.is_v6)
        };
        let hit = attr.lookup(local_port, is_v6);
        let (pid, comm) = match &hit {
            Some((pid, comm)) => (Some(*pid), Some(comm.clone())),
            None => (None, None),
        };
        let uid = pid.and_then(telemetry::proc_uid);
        let via_system = comm
            .as_deref()
            .is_some_and(|c| SYSTEM_RESOLVERS.contains(&c));
        let own_resolver = comm.is_some() && !via_system;

        let mut event = serde_json::json!({
            "ts": spool::now_ts(),
            "source": "linux-afpacket",
            "source_seq": spool::next_sequence(),
            "kind": "dns",
            "pid": pid,
            "uid": uid,
            "comm": comm,
            "query": msg.qname,
            "qtype": msg.qtype_name(),
            "direction": msg.direction(),
            "rcode": msg.rcode,
        });
        if own_resolver {
            event["own_resolver"] = Value::Bool(true);
        }
        if via_system {
            event["via_system_resolver"] = Value::Bool(true);
        }
        spool::try_send(&tx, event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_example_com() -> Vec<u8> {
        let mut p = vec![
            0xAB, 0xCD, // id
            0x01, 0x00, // flags: standard query, RD
            0x00, 0x01, // qdcount
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in [b"example" as &[u8], b"com"] {
            p.push(label.len() as u8);
            p.extend_from_slice(label);
        }
        p.push(0);
        p.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
        p
    }

    fn response_nxdomain() -> Vec<u8> {
        let mut p = query_example_com();
        p[2] = 0x81;
        p[3] = 0x83; // response + rcode 3 (NXDOMAIN)
        p
    }

    #[test]
    fn parses_query() {
        let msg = parse_dns(&query_example_com()).unwrap();
        assert_eq!(msg.id, 0xABCD);
        assert!(!msg.is_response);
        assert_eq!(msg.direction(), "query");
        assert_eq!(msg.rcode, None);
        assert_eq!(msg.qname, "example.com");
        assert_eq!(msg.qtype, 1);
        assert_eq!(msg.qtype_name(), "A");
        assert_eq!(msg.qclass, 1);
    }

    #[test]
    fn parses_response_rcode() {
        let msg = parse_dns(&response_nxdomain()).unwrap();
        assert!(msg.is_response);
        assert_eq!(msg.direction(), "response");
        assert_eq!(msg.rcode, Some(3));
    }

    #[test]
    fn rejects_compression_pointer_in_qname() {
        let mut p = query_example_com();
        p[12] = 0xC0; // first label becomes a pointer
        assert_eq!(parse_dns(&p), None);
    }

    #[test]
    fn rejects_truncation_and_zero_questions() {
        assert_eq!(parse_dns(&query_example_com()[..14]), None);
        let mut p = query_example_com();
        p[5] = 0; // qdcount = 0
        assert_eq!(parse_dns(&p), None);
        assert_eq!(parse_dns(&[0u8; 5]), None);
    }

    #[test]
    fn parses_tcp_with_length_prefix() {
        let inner = query_example_com();
        let mut p = (inner.len() as u16).to_be_bytes().to_vec();
        p.extend_from_slice(&inner);
        let msg = parse_dns_tcp(&p).unwrap();
        assert_eq!(msg.qname, "example.com");
        // Length prefix longer than the payload → not parseable (naive
        // single segment).
        p.truncate(p.len() - 2);
        assert_eq!(parse_dns_tcp(&p), None);
    }

    #[test]
    fn qtype_names_cover_well_known_and_numeric() {
        assert_eq!(
            DnsMessage {
                qtype: 28,
                ..parse_dns(&query_example_com()).unwrap()
            }
            .qtype_name(),
            "AAAA"
        );
        assert_eq!(
            DnsMessage {
                qtype: 65,
                ..parse_dns(&query_example_com()).unwrap()
            }
            .qtype_name(),
            "HTTPS"
        );
        assert_eq!(
            DnsMessage {
                qtype: 99,
                ..parse_dns(&query_example_com()).unwrap()
            }
            .qtype_name(),
            "TYPE99"
        );
    }

    #[test]
    fn decodes_udp53_ipv4_frame() {
        // Minimal ethernet + IPv4 + UDP frame carrying the canned query.
        let payload = query_example_com();
        let mut frame = vec![0u8; 14];
        frame[12] = 0x08;
        frame[13] = 0x00;
        let udp_len = 8 + payload.len() as u16;
        let ip_len = 20 + udp_len;
        frame.extend_from_slice(&[
            0x45,
            0x00,
            (ip_len >> 8) as u8,
            ip_len as u8,
            0x00,
            0x00,
            0x00,
            0x00,
            64,
            17,
            0,
            0,
            192,
            168,
            1,
            5,
            8,
            8,
            8,
            8,
        ]);
        frame.extend_from_slice(&[0xC0, 0x00, 0x00, 0x35]);
        frame.extend_from_slice(&(udp_len.to_be_bytes()));
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(&payload);
        let pkt = decode_frame(&frame).unwrap();
        assert!(pkt.is_udp && !pkt.is_v6);
        assert_eq!(pkt.sport, 49152);
        assert_eq!(pkt.dport, 53);
        let msg = parse_dns(&frame[pkt.payload_off..pkt.payload_off + pkt.payload_len]).unwrap();
        assert_eq!(msg.qname, "example.com");
    }

    #[test]
    fn non_53_traffic_is_ignored() {
        let mut frame = vec![0u8; 14];
        frame[12] = 0x08;
        let mut ip = vec![
            0x45, 0x00, 0x00, 40, 0x00, 0x00, 0x00, 0x00, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        frame.append(&mut ip);
        frame.extend_from_slice(&[0x01, 0x01, 0x01, 0x02, 0x00, 12, 0, 0, 0, 0, 0, 0]);
        assert!(decode_frame(&frame).is_none());
    }
}
