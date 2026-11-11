//! Services from systemd unit files.

use std::collections::BTreeSet;
use std::fs;

use super::DeviceService;

pub(super) fn collect_services() -> Vec<DeviceService> {
    let mut names = BTreeSet::new();
    let mut services = Vec::new();
    for directory in [
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
    ] {
        let Ok(entries) = fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".service") && names.insert(name.clone()) {
                services.push(DeviceService {
                    name,
                    state: "installed".into(),
                    source: "systemd".into(),
                });
            }
            if services.len() >= 256 {
                return services;
            }
        }
    }
    services.sort_by(|left, right| left.name.cmp(&right.name));
    services
}
