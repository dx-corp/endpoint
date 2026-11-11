//! Running processes.

use crate::ai_discovery::DeviceProcess;
use std::fs;

use super::{bounded_read_path, inventory_text};

pub(super) fn collect_processes() -> Vec<DeviceProcess> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut processes = entries
        .flatten()
        .filter_map(|entry| {
            let pid = entry.file_name().to_string_lossy().parse::<u32>().ok()?;
            let root = entry.path();
            let name = bounded_read_path(&root.join("comm"), 256)
                .map(|body| inventory_text(&String::from_utf8_lossy(&body), 256))
                .filter(|value| !value.is_empty())?;
            let executable = fs::read_link(root.join("exe"))
                .ok()
                .map(|path| inventory_text(&path.to_string_lossy(), 512))
                .unwrap_or_default();
            let mut user = String::new();
            let mut state = String::new();
            if let Some(body) = bounded_read_path(&root.join("status"), 16 << 10) {
                for line in String::from_utf8_lossy(&body).lines() {
                    if let Some(value) = line.strip_prefix("Uid:") {
                        user = format!(
                            "uid:{}",
                            value.split_whitespace().next().unwrap_or_default()
                        );
                    } else if let Some(value) = line.strip_prefix("State:") {
                        state =
                            inventory_text(value.split_whitespace().next().unwrap_or_default(), 32);
                    }
                }
            }
            Some(DeviceProcess {
                pid,
                name,
                executable,
                user,
                state,
            })
        })
        .take(512)
        .collect::<Vec<_>>();
    processes.sort_by_key(|left| left.pid);
    processes
}
