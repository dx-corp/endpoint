//! The files the plugin leaves for the Windows collector, under
//! `%ProgramData%\Deixic\Endpoint\wsl`: `plugin.json` says which WSL loaded
//! the plugin and whether it can scan, and one `<distribution id>.json` per
//! distribution holds its latest state. Each file is written to a temporary
//! name and renamed, so the collector never reads half a file. The folder
//! inherits the install's SYSTEM and Administrators ACL.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::ffi::{Guid, WslVersion};

pub(crate) const SCHEMA_VERSION: u64 = 1;
/// Largest scanner output accepted, as merlin caps its own child output.
pub(crate) const MAX_SCAN_BYTES: usize = 1 << 20;
const MAX_CLIS: usize = 32;
const MAX_FINDINGS: usize = 128;
const MAX_NAME_CHARS: usize = 64;

pub(crate) struct DistroState {
    name: String,
    state: &'static str,
    reason: Option<&'static str>,
    findings: Option<Value>,
}

impl DistroState {
    pub(crate) fn scanned(name: &str, findings: Value) -> Self {
        Self {
            name: bounded_name(name),
            state: "scanned",
            reason: None,
            findings: Some(findings),
        }
    }

    pub(crate) fn not_scanned(name: &str, reason: &'static str) -> Self {
        Self {
            name: bounded_name(name),
            state: "not_scanned",
            reason: Some(reason),
            findings: None,
        }
    }

    fn to_json(&self, id: &Guid) -> Value {
        json!({
            "schema_version": SCHEMA_VERSION,
            "distro_id": id.file_stem(),
            "distro": self.name,
            "state": self.state,
            "reason": self.reason,
            "observed_at": now(),
            "findings": self.findings,
        })
    }
}

fn bounded_name(name: &str) -> String {
    name.chars().take(MAX_NAME_CHARS).collect()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

pub(crate) struct StateDir {
    root: PathBuf,
}

impl StateDir {
    pub(crate) fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn path(&self, id: &Guid) -> PathBuf {
        self.root.join(format!("{}.json", id.file_stem()))
    }

    fn write_file(&self, file_name: &str, value: &Value) {
        if fs::create_dir_all(&self.root).is_err() {
            return;
        }
        let temporary = self.root.join(format!(".{file_name}.tmp"));
        let Ok(body) = serde_json::to_vec(value) else {
            return;
        };
        if fs::write(&temporary, body).is_ok()
            && fs::rename(&temporary, self.root.join(file_name)).is_err()
        {
            let _ = fs::remove_file(&temporary);
        }
    }

    pub(crate) fn write(&self, id: &Guid, state: &DistroState) {
        self.write_file(&format!("{}.json", id.file_stem()), &state.to_json(id));
    }

    /// A newly registered distribution is not scanned until it starts; an
    /// existing record, such as a scan that raced this event, is kept.
    pub(crate) fn record_registered(&self, id: &Guid, state: &DistroState) {
        if !self.path(id).exists() {
            self.write(id, state);
        }
    }

    pub(crate) fn remove(&self, id: &Guid) {
        let _ = fs::remove_file(self.path(id));
    }

    pub(crate) fn write_plugin_status(
        &self,
        version: &WslVersion,
        scans: bool,
        registrations: bool,
    ) {
        self.write_file(
            "plugin.json",
            &json!({
                "schema_version": SCHEMA_VERSION,
                "wsl_version": format!("{}.{}.{}", version.major, version.minor, version.revision),
                "scans": scans,
                "registrations": registrations,
                "loaded_at": now(),
            }),
        );
    }
}

/// Accept the scanner's JSON only when it is the shape merlin prints, within
/// its caps, and every finding carries the location the plugin asked for.
/// The Windows collector validates names and labels again before sending.
pub(crate) fn checked_scan(output: &[u8], location: &str) -> Option<Value> {
    if output.len() > MAX_SCAN_BYTES {
        return None;
    }
    let value: Value = serde_json::from_slice(output).ok()?;
    let object = value.as_object()?;
    let clis = object.get("clis")?.as_array()?;
    let servers = object.get("mcp_servers")?.as_array()?;
    let assets = object.get("agent_assets")?.as_array()?;
    if clis.len() > MAX_CLIS || servers.len() > MAX_FINDINGS || assets.len() > MAX_FINDINGS {
        return None;
    }
    let tagged = |item: &Value| item.get("location").and_then(Value::as_str) == Some(location);
    if !servers.iter().all(tagged) || !assets.iter().all(tagged) {
        return None;
    }
    Some(json!({ "clis": clis, "mcp_servers": servers, "agent_assets": assets }))
}
