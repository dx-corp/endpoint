//! What the Deixic Endpoint WSL plugin found. The plugin (`windows/wsl-plugin`),
//! which wslservice runs as distributions start, leaves its results in
//! `%ProgramData%\Deixic\Endpoint\wsl` under the file contract in its README.
//! The collector only reads those files, with the same handle-verified reads
//! as every other probe, and the distributions registered in loaded user
//! hives; it never starts WSL or runs anything. A registered distribution
//! with no scan is reported as not scanned, never as clean.

#[cfg(all(test, not(windows)))]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;

pub(crate) use crate::ai_discovery::DeviceAiLocationCoverage;
use crate::ai_discovery::{
    DeviceAgentAsset, DeviceMCPServer, keep_valid_content_facts, safe_agent_asset_name,
};
use crate::windows_discovery::ContainedFs;

const MAX_STATE_FILES: usize = 64;
const MAX_STATE_BYTES: u64 = 1 << 20;
const MAX_PLUGIN_STATUS_BYTES: u64 = 64 << 10;
const MAX_COVERAGE: usize = 32;
const MAX_FINDINGS: usize = 128;
const MAX_KIND_LEN: usize = 32;
const STATE_SCHEMA: u32 = 1;
const LOCATION_PREFIX: &str = "wsl:";
const NOT_STARTED: &str = "not_started";
const SCAN_FAILED: &str = "scan_failed";
const UNSUPPORTED: &str = "wsl_unsupported";
const PLUGIN_MISSING: &str = "plugin_not_loaded";
/// Reasons the server accepts for a not-scanned place.
const NOT_SCANNED_REASONS: &[&str] = &[
    NOT_STARTED,
    SCAN_FAILED,
    "scanner_missing",
    "no_init_pid",
    "scan_not_started",
    UNSUPPORTED,
    PLUGIN_MISSING,
];

/// A WSL distribution from a loaded user hive's Lxss key: its id in the
/// plugin's file-stem form (lowercase, no braces) and its name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RegisteredDistro {
    pub(crate) id: String,
    pub(crate) name: String,
}

#[derive(Debug, Default, PartialEq)]
pub(crate) struct WslInventory {
    pub(crate) mcp_servers: Vec<DeviceMCPServer>,
    pub(crate) agent_assets: Vec<DeviceAgentAsset>,
    pub(crate) coverage: Vec<DeviceAiLocationCoverage>,
}

#[derive(Deserialize)]
struct PluginStatus {
    schema_version: u32,
    #[serde(default)]
    scans: bool,
}

#[derive(Deserialize)]
struct StateFindings {
    #[serde(default)]
    mcp_servers: Vec<DeviceMCPServer>,
    #[serde(default)]
    agent_assets: Vec<DeviceAgentAsset>,
}

#[derive(Deserialize)]
struct State {
    schema_version: u32,
    distro_id: String,
    distro: String,
    state: String,
    reason: Option<String>,
    observed_at: i64,
    findings: Option<StateFindings>,
}

/// A distribution name that can be a `wsl:<name>` location:
/// `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`.
fn distro_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A lowercase GUID: 8-4-4-4-12 hex digits.
fn lowercase_guid(value: &str) -> bool {
    let groups: Vec<&str> = value.split('-').collect();
    groups.len() == 5
        && groups.iter().zip([8, 4, 4, 4, 12]).all(|(group, len)| {
            group.len() == len
                && group
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

/// A state file name: `<lowercase guid>.json`.
fn state_file(name: &str) -> bool {
    name.strip_suffix(".json").is_some_and(lowercase_guid)
}

/// An Lxss subkey name such as `{0123ABCD-4567-89AB-CDEF-000102030405}` as
/// the plugin's file stem.
pub(crate) fn lxss_distro_id(key: &str) -> Option<String> {
    if key.len() != 38 {
        return None;
    }
    let id = key
        .strip_prefix('{')?
        .strip_suffix('}')?
        .to_ascii_lowercase();
    lowercase_guid(&id).then_some(id)
}

/// The shape of a fixed user-relative source label. The scanner prints
/// labels from its compiled location table, never from the distribution,
/// and the server checks each against the same table.
fn source_label(source: &str) -> bool {
    !source.is_empty()
        && source.len() <= 128
        && !source.starts_with('/')
        && !source.contains(['\\', ':'])
        && source.split('/').all(|part| {
            !part.is_empty() && part != "." && part != ".." && !part.chars().any(char::is_control)
        })
}

/// A scan counts only when every finding carries the distribution's
/// location and fields the server accepts. Names come from the distribution's
/// own files, so one bad entry discards the whole scan rather than letting
/// the server refuse the device's check-in.
fn checked_findings(location: &str, findings: &StateFindings) -> bool {
    findings.mcp_servers.len() <= MAX_FINDINGS
        && findings.agent_assets.len() <= MAX_FINDINGS
        && findings.mcp_servers.iter().all(|server| {
            server.location == location
                && safe_agent_asset_name(&server.client)
                && safe_agent_asset_name(&server.name)
                && source_label(&server.source)
                && matches!(server.transport.as_str(), "stdio" | "remote" | "unknown")
        })
        && findings.agent_assets.iter().all(|asset| {
            asset.location == location
                && safe_agent_asset_name(&asset.client)
                && safe_agent_asset_name(&asset.kind)
                && asset.kind.len() <= MAX_KIND_LEN
                && safe_agent_asset_name(&asset.name)
                && source_label(&asset.source)
        })
}

fn not_scanned(location: String, reason: &str, observed_at: i64) -> DeviceAiLocationCoverage {
    DeviceAiLocationCoverage {
        location,
        source: String::new(),
        state: "not_scanned".into(),
        reason: reason.into(),
        observed_at,
    }
}

/// Read the plugin's files in `dir` and the registered distributions.
pub(crate) fn collect(
    fs: &impl ContainedFs,
    dir: &Path,
    registered: &[RegisteredDistro],
) -> WslInventory {
    let mut result = WslInventory::default();
    let mut coverage: BTreeMap<String, DeviceAiLocationCoverage> = BTreeMap::new();
    // One entry per location: a distribution of that name that was not
    // scanned makes the location not scanned.
    let mut record = |entry: DeviceAiLocationCoverage| match coverage.get(&entry.location) {
        Some(current) if !(current.state == "scanned" && entry.state == "not_scanned") => {}
        _ => {
            coverage.insert(entry.location.clone(), entry);
        }
    };

    let status = fs
        .read_within(dir, &dir.join("plugin.json"), MAX_PLUGIN_STATUS_BYTES)
        .and_then(|body| serde_json::from_slice::<PluginStatus>(&body).ok())
        .filter(|status| status.schema_version == STATE_SCHEMA);

    let mut seen_ids = BTreeSet::new();
    let names = fs.entries_within(dir, dir, 256);
    for name in names
        .iter()
        .filter(|name| state_file(name))
        .take(MAX_STATE_FILES)
    {
        let Some(body) = fs.read_within(dir, &dir.join(name), MAX_STATE_BYTES) else {
            continue;
        };
        let Ok(state) = serde_json::from_slice::<State>(&body) else {
            continue;
        };
        if state.schema_version != STATE_SCHEMA
            || format!("{}.json", state.distro_id) != *name
            || !distro_name(&state.distro)
            || state.observed_at < 0
        {
            continue;
        }
        seen_ids.insert(state.distro_id.clone());
        let location = format!("{LOCATION_PREFIX}{}", state.distro);
        match state.state.as_str() {
            "scanned" => {
                let Some(mut findings) = state.findings else {
                    continue;
                };
                if !checked_findings(&location, &findings) {
                    record(not_scanned(location, SCAN_FAILED, state.observed_at));
                    continue;
                }
                result.mcp_servers.extend(findings.mcp_servers);
                // The skill and plugin file hashes and matched rule ids the
                // scanner reported, kept only when they are well formed.
                findings
                    .agent_assets
                    .iter_mut()
                    .for_each(keep_valid_content_facts);
                result.agent_assets.extend(findings.agent_assets);
                record(DeviceAiLocationCoverage {
                    location,
                    source: String::new(),
                    state: "scanned".into(),
                    reason: String::new(),
                    observed_at: state.observed_at,
                });
            }
            "not_scanned" => {
                let reason = state
                    .reason
                    .as_deref()
                    .filter(|reason| NOT_SCANNED_REASONS.contains(reason))
                    .unwrap_or(SCAN_FAILED);
                record(not_scanned(location, reason, state.observed_at));
            }
            _ => {}
        }
    }

    // Registered distributions the plugin has no record of: never started
    // since it was installed, or the plugin cannot scan or is not loaded.
    let reason = match &status {
        None => PLUGIN_MISSING,
        Some(status) if !status.scans => UNSUPPORTED,
        Some(_) => NOT_STARTED,
    };
    for distro in registered {
        if seen_ids.contains(&distro.id) || !distro_name(&distro.name) {
            continue;
        }
        record(not_scanned(
            format!("{LOCATION_PREFIX}{}", distro.name),
            reason,
            0,
        ));
    }

    result.coverage = coverage.into_values().collect();
    // Not-scanned places first, so the cap never hides one.
    result.coverage.sort_by(|a, b| {
        (a.state != "not_scanned", &a.location).cmp(&(b.state != "not_scanned", &b.location))
    });
    result.coverage.truncate(MAX_COVERAGE);
    result
}
