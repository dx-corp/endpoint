//! Network-configuration telemetry via NETLINK_ROUTE.
//!
//! Subscribes to RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE and
//! emits `netif` events for interface up/down transitions, IFF_PROMISC
//! changes (sniffer signal), new tun/tap/wg interfaces, and address/route
//! changes. Fail-open: a dead monitor is telemetry loss, never an outage.

use std::io;
use std::thread;

use anyhow::{Context, Result};
use serde_json::Value;
use tokio::sync::mpsc::Sender;

use crate::spool;

const RTMGRP_LINK: u32 = 1;
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
const RTMGRP_IPV4_ROUTE: u32 = 0x40;

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;

const IFF_UP: u32 = 0x1;
const IFF_PROMISC: u32 = 0x100;

const IFLA_IFNAME: u16 = 3;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;

/// One parsed netlink attribute.
pub struct AttrIter<'a> {
    buf: &'a [u8],
}

impl<'a> AttrIter<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        AttrIter { buf }
    }
}

impl<'a> Iterator for AttrIter<'a> {
    type Item = (u16, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() < 4 {
            return None;
        }
        let len = u16::from_ne_bytes(self.buf[0..2].try_into().ok()?) as usize;
        let ty = u16::from_ne_bytes(self.buf[2..4].try_into().ok()?);
        if len < 4 || len > self.buf.len() {
            return None;
        }
        let payload = &self.buf[4..len];
        self.buf = &self.buf[(len + 3) & !3..]; // NLA_ALIGN(4)
        Some((ty, payload))
    }
}

pub struct LinkEvent {
    pub ifname: String,
    pub up: bool,
    pub promisc: bool,
    pub promisc_changed: bool,
    pub up_changed: bool,
    pub deleted: bool,
}

pub struct AddrEvent {
    pub ifname_hint: u32, // interface index; resolved to a name best-effort by the caller
    pub addr: String,
    pub prefix_len: u8,
    pub deleted: bool,
}

/// Parse one nlmsghdr payload for RTM_NEWLINK/RTM_DELLINK.
/// Layout: ifinfomsg(16B): family u8, pad u8, type u16, index u32,
/// flags u32, change u32; then attributes.
pub fn parse_link(payload: &[u8], deleted: bool) -> Option<LinkEvent> {
    if payload.len() < 16 {
        return None;
    }
    let flags = u32::from_ne_bytes(payload[8..12].try_into().ok()?);
    let change = u32::from_ne_bytes(payload[12..16].try_into().ok()?);
    let mut ifname = String::new();
    for (ty, data) in AttrIter::new(&payload[16..]) {
        if ty == IFLA_IFNAME {
            ifname = String::from_utf8_lossy(data)
                .trim_end_matches('\0')
                .to_string();
        }
    }
    if ifname.is_empty() {
        return None;
    }
    Some(LinkEvent {
        ifname,
        up: flags & IFF_UP != 0,
        promisc: flags & IFF_PROMISC != 0,
        promisc_changed: change & IFF_PROMISC != 0,
        up_changed: change & IFF_UP != 0,
        deleted,
    })
}

/// Parse one nlmsghdr payload for RTM_NEWADDR/RTM_DELADDR.
/// Layout: ifaddrmsg(8B): family u8, prefixlen u8, flags u8, scope u8,
/// index u32; then attributes.
pub fn parse_addr(payload: &[u8], deleted: bool, v6: bool) -> Option<AddrEvent> {
    if payload.len() < 8 {
        return None;
    }
    let prefix_len = payload[1];
    let index = u32::from_ne_bytes(payload[4..8].try_into().ok()?);
    let mut addr = String::new();
    for (ty, data) in AttrIter::new(&payload[8..]) {
        if ty == IFA_LOCAL || (ty == IFA_ADDRESS && addr.is_empty()) {
            addr = format_ip(data, v6);
        }
    }
    if addr.is_empty() {
        return None;
    }
    Some(AddrEvent {
        ifname_hint: index,
        addr,
        prefix_len,
        deleted,
    })
}

fn format_ip(data: &[u8], v6: bool) -> String {
    if v6 && data.len() == 16 {
        std::net::Ipv6Addr::from(<[u8; 16]>::try_from(data).unwrap()).to_string()
    } else if data.len() == 4 {
        std::net::Ipv4Addr::new(data[0], data[1], data[2], data[3]).to_string()
    } else {
        String::new()
    }
}

/// Parse one nlmsghdr payload for RTM_NEWROUTE/RTM_DELROUTE.
/// Layout: rtmsg(12B): family, dst_len, src_len, tos, table, protocol,
/// scope, type u8, flags u32; then attributes.
pub fn parse_route(payload: &[u8], deleted: bool) -> Option<String> {
    if payload.len() < 12 {
        return None;
    }
    let v6 = payload[0] == 10;
    let dst_len = payload[1];
    let mut dst = if dst_len == 0 {
        "default".to_string()
    } else {
        String::new()
    };
    let mut via = String::new();
    for (ty, data) in AttrIter::new(&payload[12..]) {
        match ty {
            RTA_DST if dst_len > 0 => dst = format!("{}/{}", format_ip(data, v6), dst_len),
            RTA_GATEWAY => via = format!(" via {}", format_ip(data, v6)),
            RTA_OIF if data.len() == 4 => {
                let idx = u32::from_ne_bytes(data.try_into().ok()?);
                via.push_str(&format!(" dev if{idx}"));
            }
            _ => {}
        }
    }
    if dst.is_empty() {
        return None;
    }
    Some(format!(
        "{}{} ({})",
        dst,
        via,
        if deleted { "del" } else { "add" }
    ))
}

/// Name prefixes that signal a new virtual interface worth an event.
pub fn is_virtual_iface(name: &str) -> bool {
    [
        "tun",
        "tap",
        "wg",
        "veth",
        "br-",
        "docker",
        "flannel",
        "cni",
        "tailscale",
    ]
    .iter()
    .any(|p| name.starts_with(p))
}

/// Resolve an interface index to a name (best effort).
fn ifname_of(index: u32) -> Option<String> {
    std::fs::read_dir("/sys/class/net").ok()?.find_map(|e| {
        let e = e.ok()?;
        let idx: u32 = std::fs::read_to_string(e.path().join("ifindex"))
            .ok()?
            .trim()
            .parse()
            .ok()?;
        (idx == index).then(|| e.file_name().to_string_lossy().into_owned())
    })
}

fn open_socket() -> Result<i32> {
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM, libc::NETLINK_ROUTE) };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("opening NETLINK_ROUTE socket");
    }
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error()).context("binding NETLINK_ROUTE groups");
    }
    Ok(fd)
}

pub fn spawn(tx: Sender<Value>) -> Result<thread::JoinHandle<()>> {
    let fd = open_socket()?;
    log::info!("netif: watching link/addr/route changes via NETLINK_ROUTE");
    Ok(thread::Builder::new()
        .name("netif".into())
        .spawn(move || run_loop(fd, tx))
        .context("spawning netif thread")?)
}

fn emit(tx: &Sender<Value>, op: &str, mut event: Value) {
    event["ts"] = Value::from(spool::now_ts());
    event["source"] = Value::from("linux-netlink");
    event["source_seq"] = Value::from(spool::next_sequence());
    event["kind"] = Value::from("netif");
    event["op"] = Value::from(op);
    spool::try_send(tx, event);
}

fn run_loop(fd: i32, tx: Sender<Value>) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            log::error!("netif: recv failed: {err}; monitor stopped");
            return;
        }
        let mut off = 0usize;
        let n = n as usize;
        while off + 16 <= n {
            let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
            let ty = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
            if len < 16 || off + len > n {
                break;
            }
            let payload = &buf[off + 16..off + len];
            match ty {
                RTM_NEWLINK | RTM_DELLINK => {
                    if let Some(link) = parse_link(payload, ty == RTM_DELLINK) {
                        let mut detail = Vec::new();
                        if link.deleted {
                            detail.push("deleted");
                        }
                        if link.up_changed {
                            detail.push(if link.up { "up" } else { "down" });
                        }
                        if link.promisc_changed {
                            detail.push(if link.promisc {
                                "promisc_on"
                            } else {
                                "promisc_off"
                            });
                        }
                        let virtual_new = !link.deleted && is_virtual_iface(&link.ifname);
                        if !detail.is_empty() || virtual_new {
                            if link.promisc_changed && link.promisc {
                                log::warn!(
                                    "netif: interface {} entered PROMISCUOUS mode",
                                    link.ifname
                                );
                            }
                            emit(
                                &tx,
                                "link",
                                serde_json::json!({
                                    "ifname": link.ifname,
                                    "up": link.up,
                                    "promisc": link.promisc,
                                    "changes": detail,
                                    "virtual": virtual_new,
                                }),
                            );
                        }
                    }
                }
                RTM_NEWADDR | RTM_DELADDR => {
                    if let Some(addr) = parse_addr(payload, ty == RTM_DELADDR, false) {
                        emit(
                            &tx,
                            if addr.deleted { "addr_del" } else { "addr_add" },
                            serde_json::json!({
                                "ifname": ifname_of(addr.ifname_hint),
                                "addr": format!("{}/{}", addr.addr, addr.prefix_len),
                            }),
                        );
                    }
                }
                RTM_NEWROUTE | RTM_DELROUTE => {
                    if let Some(summary) = parse_route(payload, ty == RTM_DELROUTE) {
                        emit(&tx, "route", serde_json::json!({ "route": summary }));
                    }
                }
                _ => {}
            }
            off += (len + 3) & !3;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nlattr(ty: u16, data: &[u8]) -> Vec<u8> {
        let len = 4 + data.len();
        let mut a = (len as u16).to_ne_bytes().to_vec();
        a.extend_from_slice(&ty.to_ne_bytes());
        a.extend_from_slice(data);
        while a.len() % 4 != 0 {
            a.push(0);
        }
        a
    }

    fn ifinfomsg(flags: u32, change: u32) -> Vec<u8> {
        let mut m = vec![0u8, 0, 0, 0];
        m.extend_from_slice(&1u32.to_ne_bytes());
        m.extend_from_slice(&flags.to_ne_bytes());
        m.extend_from_slice(&change.to_ne_bytes());
        m
    }

    #[test]
    fn parse_promisc_transition() {
        let mut payload = ifinfomsg(IFF_UP | IFF_PROMISC, IFF_PROMISC);
        payload.extend_from_slice(&nlattr(IFLA_IFNAME, b"eth0\0"));
        let link = parse_link(&payload, false).unwrap();
        assert_eq!(link.ifname, "eth0");
        assert!(link.promisc && link.promisc_changed && link.up && !link.up_changed);
    }

    #[test]
    fn parse_down_and_virtual_names() {
        let mut payload = ifinfomsg(0, IFF_UP);
        payload.extend_from_slice(&nlattr(IFLA_IFNAME, b"wg0\0"));
        let link = parse_link(&payload, false).unwrap();
        assert!(!link.up && link.up_changed);
        assert!(is_virtual_iface("wg0"));
        assert!(is_virtual_iface("tun0"));
        assert!(!is_virtual_iface("eth0"));
    }

    #[test]
    fn parse_addr_v4() {
        let mut payload = vec![2u8, 24, 0, 0];
        payload.extend_from_slice(&7u32.to_ne_bytes());
        payload.extend_from_slice(&nlattr(IFA_LOCAL, &[192, 168, 1, 5]));
        let addr = parse_addr(&payload, false, false).unwrap();
        assert_eq!(addr.addr, "192.168.1.5");
        assert_eq!(addr.prefix_len, 24);
        assert_eq!(addr.ifname_hint, 7);
    }

    #[test]
    fn parse_route_default_via() {
        let mut payload = vec![2u8, 0, 0, 0, 0, 3, 0, 0];
        payload.extend_from_slice(&0u32.to_ne_bytes());
        payload.extend_from_slice(&nlattr(RTA_GATEWAY, &[192, 168, 4, 1]));
        let summary = parse_route(&payload, false).unwrap();
        assert_eq!(summary, "default via 192.168.4.1 (add)");
    }

    #[test]
    fn rejects_truncated() {
        assert!(parse_link(&[0u8; 8], false).is_none());
        assert!(parse_addr(&[0u8; 4], false, false).is_none());
    }
}
