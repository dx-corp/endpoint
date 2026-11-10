//! AI-tool discovery records and the parsers that read MCP servers and
//! enabled plugins out of config files. Shared by the Linux agent (`sync`)
//! and Windows discovery (`windows_discovery`): both report the same records
//! from the same `ai_locations` rows of the collection manifest.

use serde::{Deserialize, Serialize};

use crate::manifest::{AI_CONTENT_RULES, AiLocation, Format};

// The content check runs where its findings are collected: Linux so far.
#[cfg(target_os = "linux")]
mod content_scan;
mod extensions;
mod mcp_identity;

pub(crate) use extensions::{
    MAX_BROWSER_PROFILES, chromium_extension_id, chromium_profile, editor_extension_id,
};

#[cfg(target_os = "linux")]
pub(crate) use content_scan::{ContentFacts, ContentScan, MAX_CONTENT_BYTES};

use mcp_identity::{remote_host, stdio_package};

/// Keep only facts this agent could have produced: a lowercase hex SHA-256
/// and declared rule ids. For findings another process printed (a
/// container's or WSL distribution's scan), which are not taken on trust.
pub(crate) fn keep_valid_content_facts(asset: &mut DeviceAgentAsset) {
    let hex = asset.sha256.len() == 64
        && asset
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !hex {
        asset.sha256.clear();
        asset.matched_rules.clear();
    }
    asset
        .matched_rules
        .retain(|id| AI_CONTENT_RULES.iter().any(|rule| rule.id == id));
    asset.matched_rules.sort();
    asset.matched_rules.dedup();
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Ord, PartialOrd, Eq, Clone)]
pub(crate) struct DeviceAgentCLI {
    pub(crate) name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) location: String,
}

// `location` is empty on the device itself (the server reads absent as host)
// and container:<image> for a finding inside a running container.
#[derive(Serialize, Deserialize, Debug, PartialEq, Ord, PartialOrd, Eq, Clone)]
pub(crate) struct DeviceMCPServer {
    pub(crate) client: String,
    pub(crate) name: String,
    pub(crate) source: String,
    pub(crate) transport: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) location: String,
    /// For a local server, the package or image it runs, else its program
    /// name; never its arguments (see mcp_identity).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) package: String,
    /// For a remote server, its URL host name only.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) host: String,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Ord, PartialOrd, Eq, Clone)]
pub(crate) struct DeviceAgentAsset {
    pub(crate) client: String,
    pub(crate) kind: String,
    pub(crate) name: String,
    pub(crate) source: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) location: String,
    /// SHA-256 of a skill's SKILL.md, a custom agent file or a plugin
    /// manifest, present when its content was checked (content_scan).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) sha256: String,
    /// Ids of the declared `ai_content_rules` the content matched.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) matched_rules: Vec<String>,
}

/// Whether a place, or one declared file in it, had its AI tools read. A
/// not-scanned entry is unknown, never clean (server
/// `deviceAILocationCoverage`). `location` is empty for this computer and
/// `container:<image>` or `wsl:<distro>` off it; `source` is empty for the
/// whole place, or the manifest label of the one file that was not read.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub(crate) struct DeviceAiLocationCoverage {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) location: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) source: String,
    pub(crate) state: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) reason: String,
    /// Unix seconds of the scan or the not-scanned record.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) observed_at: i64,
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

/// Coverage entries a collector reports (the server's limit).
pub(crate) const MAX_COVERAGE: usize = 32;

impl DeviceAiLocationCoverage {
    /// `location`'s declared file, over its read limit and so not read.
    pub(crate) fn too_large(location: &AiLocation) -> Self {
        Self {
            location: String::new(),
            source: location.label(),
            state: "not_scanned".into(),
            reason: "too_large".into(),
            observed_at: 0,
        }
    }
}

/// Add `entry` unless an entry for the same place and file is there, keeping
/// at most `MAX_COVERAGE`.
pub(crate) fn add_coverage(
    coverage: &mut Vec<DeviceAiLocationCoverage>,
    entry: DeviceAiLocationCoverage,
) {
    let known = coverage
        .iter()
        .any(|known| known.location == entry.location && known.source == entry.source);
    if !known && coverage.len() < MAX_COVERAGE {
        coverage.push(entry);
    }
}

/// A declared config file as read: its body, or that it is larger than its
/// location's `max_bytes` and was not read.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ConfigRead {
    Body(String),
    TooLarge,
}

/// A running process: the Linux inventory lists every process; Windows
/// reports only AI agent processes. Never a command line, arguments or
/// environment.
#[derive(Serialize, Debug, PartialEq)]
pub(crate) struct DeviceProcess {
    pub(crate) pid: u32,
    pub(crate) name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) executable: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) user: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) state: String,
}

/// Names under a JSON object key whose value is `true`.
pub(crate) fn json_enabled_plugin_names(body: &str, key: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return Vec::new();
    };
    value
        .get(key)
        .and_then(|value| value.as_object())
        .into_iter()
        .flatten()
        .filter(|(name, enabled)| enabled.as_bool() == Some(true) && safe_agent_asset_name(name))
        .map(|(name, _)| name.clone())
        .collect()
}

pub(crate) fn codex_enabled_plugin_names(body: &str) -> Vec<String> {
    let Ok(value) = body.parse::<toml::Value>() else {
        return Vec::new();
    };
    value
        .get("plugins")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|plugins| plugins.iter())
        .filter(|&(name, config)| {
            safe_agent_asset_name(name)
                && config.get("enabled").and_then(toml::Value::as_bool) == Some(true)
        })
        .map(|(name, _)| name.clone())
        .take(128)
        .collect()
}

pub(crate) fn safe_agent_asset_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && !name.chars().any(char::is_control)
        && !name.contains('/')
        && !name.contains('\\')
}

/// One MCP server a config declares.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct McpEntry {
    pub(crate) name: String,
    pub(crate) transport: String,
    pub(crate) package: String,
    pub(crate) host: String,
}

impl McpEntry {
    fn new(name: &str, command: Option<&str>, args: &[&str], url: Option<&str>) -> Self {
        let transport = match (url.is_some(), command.is_some()) {
            (true, false) => "remote",
            (false, true) => "stdio",
            _ => "unknown",
        };
        McpEntry {
            name: name.to_string(),
            transport: transport.to_string(),
            package: match (transport, command) {
                ("stdio", Some(command)) => stdio_package(command, args),
                _ => String::new(),
            },
            host: match (transport, url) {
                ("remote", Some(url)) => remote_host(url),
                _ => String::new(),
            },
        }
    }

    /// The inventory row for this server, found by `client` at `source`.
    pub(crate) fn server(self, client: &str, source: String) -> DeviceMCPServer {
        DeviceMCPServer {
            client: client.to_string(),
            name: self.name,
            source,
            transport: self.transport,
            location: String::new(),
            package: self.package,
            host: self.host,
        }
    }
}

/// At most this many arguments are looked at for a package spec.
const MAX_ARGS: usize = 64;

/// MCP servers a config location declares: the entries under its `mcp_keys`
/// for JSON, its `[mcp_servers.<name>]` tables for TOML.
pub(crate) fn config_mcp_entries(location: &AiLocation, body: &str) -> Vec<McpEntry> {
    match location.format {
        Format::Toml | Format::CodexToml => codex_mcp_entries(body),
        _ => json_mcp_entries(body, location.mcp_keys),
    }
}

pub(crate) fn json_mcp_entries(body: &str, keys: &[&str]) -> Vec<McpEntry> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return Vec::new();
    };
    keys.iter()
        .filter_map(|key| value.get(key)?.as_object())
        .flat_map(|object| {
            object.iter().map(|(name, definition)| {
                let url = ["url", "httpUrl", "http_url"]
                    .iter()
                    .find_map(|key| definition.get(key)?.as_str());
                let command = definition
                    .get("command")
                    .and_then(serde_json::Value::as_str);
                let args: Vec<&str> = definition
                    .get("args")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                    .take(MAX_ARGS)
                    .filter_map(serde_json::Value::as_str)
                    .collect();
                McpEntry::new(name, command, &args, url)
            })
        })
        .collect()
}

/// `[mcp_servers.<name>]` tables. Names and transports come from a line scan,
/// so a file the TOML parser rejects still yields them; what each server runs
/// comes from the parsed table when the file parses.
pub(crate) fn codex_mcp_entries(body: &str) -> Vec<McpEntry> {
    let parsed = body.parse::<toml::Value>().ok();
    let table = |name: &str| {
        parsed
            .as_ref()
            .and_then(|value| value.get("mcp_servers")?.get(name))
    };
    codex_mcp_names(body)
        .into_iter()
        .map(|(name, has_url, has_command)| {
            let server = table(&name);
            let text = |key: &str| server.and_then(|s| s.get(key)?.as_str());
            let args: Vec<&str> = server
                .and_then(|s| s.get("args")?.as_array())
                .into_iter()
                .flatten()
                .take(MAX_ARGS)
                .filter_map(toml::Value::as_str)
                .collect();
            // The line scan decides the transport, as before; the table only
            // supplies values.
            let command = has_command.then(|| text("command").unwrap_or_default());
            let url = has_url.then(|| text("url").or_else(|| text("http_url")).unwrap_or_default());
            McpEntry::new(&name, command, &args, url)
        })
        .collect()
}

/// Each `[mcp_servers.<name>]` section with whether it sets a URL and a
/// command.
fn codex_mcp_names(body: &str) -> Vec<(String, bool, bool)> {
    let mut entries = Vec::new();
    let mut current: Option<String> = None;
    let mut has_url = false;
    let mut has_command = false;
    let mut finish = |current: &mut Option<String>, has_url: &mut bool, has_command: &mut bool| {
        if let Some(name) = current.take() {
            entries.push((name, *has_url, *has_command));
        }
        *has_url = false;
        *has_command = false;
    };
    for line in body.lines() {
        let text = line.trim();
        if text.starts_with('[') && text.ends_with(']') {
            finish(&mut current, &mut has_url, &mut has_command);
            let section = text
                .strip_prefix("[mcp_servers.")
                .and_then(|value| value.strip_suffix(']'));
            if let Some(section) = section {
                let quoted =
                    section.starts_with('"') && section.ends_with('"') && section.len() >= 2;
                let name = if quoted {
                    &section[1..section.len() - 1]
                } else {
                    section
                };
                if !name.is_empty()
                    && !name.chars().any(|ch| "[]".contains(ch))
                    && (quoted || !name.contains('.'))
                {
                    current = Some(name.to_string());
                }
            }
        } else if current.is_some() {
            if let Some((key, _)) = text.split_once('=') {
                match key.trim() {
                    "url" | "http_url" => has_url = true,
                    "command" => has_command = true,
                    _ => {}
                }
            }
        }
    }
    finish(&mut current, &mut has_url, &mut has_command);
    entries
}
