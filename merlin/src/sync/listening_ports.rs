//! Listening TCP and UDP ports.

use super::{DeviceListeningPort, bounded_read};

pub(super) fn collect_proc_ports(path: &str, protocol: &str, ports: &mut Vec<DeviceListeningPort>) {
    let Some(body) = bounded_read(path, 256 << 10) else {
        return;
    };
    for line in String::from_utf8_lossy(&body).lines().skip(1) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let Some(local) = fields.get(1) else { continue };
        let Some(port_hex) = local.rsplit(':').next() else {
            continue;
        };
        let Ok(port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };
        if port == 0 {
            continue;
        }
        let state_code = fields.get(3).copied().unwrap_or_default();
        if protocol == "tcp" && state_code != "0A" {
            continue;
        }
        ports.push(DeviceListeningPort {
            protocol: protocol.into(),
            port,
            state: if protocol == "tcp" {
                "listening"
            } else {
                "bound"
            }
            .into(),
            source: path.into(),
        });
        if ports.len() >= 256 {
            return;
        }
    }
}

pub(super) fn collect_listening_ports() -> Vec<DeviceListeningPort> {
    let mut ports = Vec::new();
    collect_proc_ports("/proc/net/tcp", "tcp", &mut ports);
    collect_proc_ports("/proc/net/tcp6", "tcp", &mut ports);
    collect_proc_ports("/proc/net/udp", "udp", &mut ports);
    collect_proc_ports("/proc/net/udp6", "udp", &mut ports);
    ports.sort_by(|left, right| {
        left.protocol
            .cmp(&right.protocol)
            .then(left.port.cmp(&right.port))
    });
    ports.dedup_by(|left, right| left.protocol == right.protocol && left.port == right.port);
    ports.truncate(256);
    ports
}
