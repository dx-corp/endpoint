//! Running containers.

use std::collections::BTreeSet;
use std::fs;

use super::container_discovery;
use super::{DeviceContainer, bounded_read, bounded_read_path, inventory_text};

pub(super) fn collect_containers() -> Vec<DeviceContainer> {
    let mut ids = BTreeSet::new();
    if let Some(body) = bounded_read("/proc/1/cgroup", 64 << 10) {
        for line in String::from_utf8_lossy(&body).lines() {
            if let Some(candidate) = line.rsplit('/').next() {
                let candidate = candidate.trim();
                if candidate.len() >= 12
                    && candidate.len() <= 128
                    && candidate.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    ids.insert(candidate.to_string());
                }
            }
        }
    }
    if ids.is_empty() && fs::metadata("/.dockerenv").is_ok() {
        ids.insert(String::new());
    }
    let mut containers = ids
        .into_iter()
        .take(128)
        .map(|id| DeviceContainer {
            id,
            name: String::new(),
            image: String::new(),
            state: "running".into(),
            runtime: "container".into(),
            init_pid: 0,
        })
        .collect::<Vec<_>>();
    // Docker's metadata directory is readable by some root-installed agents
    // even when the Docker socket is not. Read only bounded JSON metadata; do
    // not invoke a runtime CLI or expose container environment variables.
    if let Ok(entries) = fs::read_dir("/var/lib/docker/containers") {
        for entry in entries.flatten() {
            if containers.len() >= 128 {
                break;
            }
            let id = entry
                .file_name()
                .to_string_lossy()
                .chars()
                .take(128)
                .collect::<String>();
            let path = entry.path().join("config.v2.json");
            let Some(body) = bounded_read_path(&path, 256 << 10) else {
                continue;
            };
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) else {
                continue;
            };
            let name = value
                .get("Name")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            let image = value
                .get("Config")
                .and_then(|value| value.get("Image"))
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            let state = value
                .get("State")
                .and_then(|value| value.get("Status"))
                .and_then(|value| value.as_str())
                .unwrap_or("unknown");
            let init_pid = docker_running_init_pid(&value);
            if let Some(container) = containers.iter_mut().find(|container| container.id == id) {
                container.name = inventory_text(name, 256);
                container.image = inventory_text(image, 256);
                container.state = inventory_text(state, 64);
                container.runtime = "docker".into();
                container.init_pid = init_pid;
            } else {
                containers.push(DeviceContainer {
                    id,
                    name: inventory_text(name, 256),
                    image: inventory_text(image, 256),
                    state: inventory_text(state, 64),
                    runtime: "docker".into(),
                    init_pid,
                });
            }
        }
    }
    container_discovery::add_running_process_containers(&mut containers);
    containers
}

/// Docker's `State.Pid` while `State.Running` is true; 0 otherwise.
pub(super) fn docker_running_init_pid(config: &serde_json::Value) -> u32 {
    let state = config.get("State");
    let running = state
        .and_then(|state| state.get("Running"))
        .and_then(serde_json::Value::as_bool)
        == Some(true);
    state
        .and_then(|state| state.get("Pid"))
        .and_then(serde_json::Value::as_u64)
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| running && *pid > 1)
        .unwrap_or(0)
}
