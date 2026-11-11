//! Installed packages from dpkg, rpm or apk.

use super::{DevicePackage, bounded_read, inventory_text};

pub(super) fn collect_packages() -> (String, Vec<DevicePackage>) {
    let mut packages = Vec::new();
    let mut manager = String::new();
    if let Some(body) = bounded_read("/var/lib/dpkg/status", 8 << 20) {
        manager = "dpkg".into();
        let body = String::from_utf8_lossy(&body);
        for record in body.split("\n\n") {
            let mut name = String::new();
            let mut version = String::new();
            let mut architecture = String::new();
            let mut installed = false;
            for line in record.lines() {
                if let Some(value) = line.strip_prefix("Package:") {
                    name = inventory_text(value, 160);
                } else if let Some(value) = line.strip_prefix("Version:") {
                    version = inventory_text(value, 160);
                } else if let Some(value) = line.strip_prefix("Architecture:") {
                    architecture = inventory_text(value, 64);
                } else if line.starts_with("Status:") && line.contains("install ok installed") {
                    installed = true;
                }
            }
            if installed && !name.is_empty() {
                packages.push(DevicePackage {
                    name,
                    version,
                    architecture,
                    manager: manager.clone(),
                });
            }
            if packages.len() >= 512 {
                break;
            }
        }
    }
    if packages.is_empty() {
        if let Some(body) = bounded_read("/lib/apk/db/installed", 8 << 20) {
            manager = "apk".into();
            let body = String::from_utf8_lossy(&body);
            for record in body.split("\n\n") {
                let mut name = String::new();
                let mut version = String::new();
                for line in record.lines() {
                    if let Some(value) = line.strip_prefix("P:") {
                        name = inventory_text(value, 160);
                    } else if let Some(value) = line.strip_prefix("V:") {
                        version = inventory_text(value, 160);
                    }
                }
                if !name.is_empty() {
                    packages.push(DevicePackage {
                        name,
                        version,
                        architecture: String::new(),
                        manager: manager.clone(),
                    });
                }
                if packages.len() >= 512 {
                    break;
                }
            }
        }
    }
    packages.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.version.cmp(&right.version))
    });
    packages.truncate(512);
    (manager, packages)
}
