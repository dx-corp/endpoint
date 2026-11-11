//! Claude Code's plugin cache walker, for the `claude-plugin-cache` format
//! of `ai_locations`. Opens every directory with the same no-follow helpers
//! as the other Linux AI walkers in `sync`.

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use super::agent_discovery::{
    agent_regular_file_exists_at, checked_content, open_agent_child_dir, open_agent_directory,
    read_agent_dir_entries, read_agent_file_at,
};
use crate::ai_discovery::{
    ContentScan, DeviceAgentAsset, DeviceMCPServer, json_mcp_entries, safe_agent_asset_name,
};
use crate::manifest::AiLocation;

/// Directories opened in Claude Code plugin caches per scan, all homes
/// together.
pub(super) const MAX_CLAUDE_CACHE_DIRS: usize = 256;

/// Claude Code's plugin cache, `<marketplace>/<plugin>/<version>/`: each
/// plugin is an asset of the row's kind, the row's `mcp_files` in a version
/// and an inline `mcpServers` map in its `.claude-plugin/plugin.json` add MCP
/// servers, and each `skills/<name>` holding a regular `SKILL.md` is
/// a skill named `<plugin>:<name>`, as Claude Code namespaces it. A version
/// Claude Code marked `.orphaned_at` (replaced or uninstalled, deleted 14
/// days later) is skipped. Opened with no symlink anywhere below the home.
pub(super) fn collect_claude_plugin_cache(
    home: &Path,
    location: &AiLocation,
    (assets, servers): (
        &mut BTreeSet<DeviceAgentAsset>,
        &mut BTreeSet<DeviceMCPServer>,
    ),
    opened: &mut usize,
    content: &mut ContentScan,
) {
    let Some(cache) = open_agent_directory(&home.join(location.path)) else {
        return;
    };
    let label = location.label();
    let asset = |kind: &str, name: String, source: String| DeviceAgentAsset {
        location: String::new(),
        client: location.client.into(),
        kind: kind.into(),
        name,
        source,
        ..Default::default()
    };
    for marketplace in read_agent_dir_entries(&cache).unwrap_or_default() {
        let Some(marketplace) = open_claude_cache_dir(&cache, &marketplace, opened) else {
            continue;
        };
        for plugin in read_agent_dir_entries(&marketplace).unwrap_or_default() {
            let Some(plugin_dir) = open_claude_cache_dir(&marketplace, &plugin, opened) else {
                continue;
            };
            let plugin = plugin.to_string_lossy().into_owned();
            for version in read_agent_dir_entries(&plugin_dir).unwrap_or_default() {
                let Some(version) = open_claude_cache_dir(&plugin_dir, &version, opened) else {
                    continue;
                };
                if agent_regular_file_exists_at(&version, c".orphaned_at") {
                    continue;
                }
                // A full asset list still lets the version's MCP servers
                // through: they have their own cap.
                if assets.len() < 128 {
                    // The plugin manifest, .claude-plugin/plugin.json.
                    let manifest = open_agent_child_dir(&version, b".claude-plugin")
                        .and_then(|directory| checked_content(&directory, "plugin.json", content));
                    assets.insert(
                        asset(location.kind, plugin.clone(), label.clone()).with_content(manifest),
                    );
                }
                for config in location.mcp_files {
                    let Some(body) = read_agent_file_at(&version, config) else {
                        continue;
                    };
                    for entry in json_mcp_entries(&body, location.mcp_keys) {
                        if safe_agent_asset_name(&entry.name) {
                            servers.insert(
                                entry.server(location.client, format!("{label}/*/{config}")),
                            );
                        }
                    }
                }
                // The manifest's `mcpServers`, when it is an inline map; a
                // path, bundle or array of them names other files.
                let manifest = open_agent_child_dir(&version, b".claude-plugin")
                    .and_then(|directory| read_agent_file_at(&directory, "plugin.json"));
                for entry in manifest
                    .map(|body| json_mcp_entries(&body, &["mcpServers"]))
                    .unwrap_or_default()
                {
                    if safe_agent_asset_name(&entry.name) {
                        let source = format!("{label}/*/.claude-plugin/plugin.json");
                        servers.insert(entry.server(location.client, source));
                    }
                }
                let Some(skills) = open_agent_child_dir(&version, b"skills") else {
                    continue;
                };
                for skill in read_agent_dir_entries(&skills).unwrap_or_default() {
                    let skill_name = skill.to_string_lossy();
                    let name = format!("{plugin}:{skill_name}");
                    if assets.len() >= 128
                        || !safe_agent_asset_name(&skill_name)
                        || !safe_agent_asset_name(&name)
                    {
                        continue;
                    }
                    let Some(directory) = open_agent_child_dir(&skills, skill.as_bytes()) else {
                        continue;
                    };
                    if agent_regular_file_exists_at(&directory, c"SKILL.md") {
                        let checked = checked_content(&directory, "SKILL.md", content);
                        let skill = asset("skill", name, format!("{label}/*/skills"));
                        assets.insert(skill.with_content(checked));
                    }
                }
            }
        }
    }
}

/// One marketplace, plugin or version directory of a Claude Code plugin
/// cache: a safe name, opened without following a link, within the scan's
/// directory budget.
fn open_claude_cache_dir(
    parent: &fs::File,
    name: &std::ffi::OsStr,
    opened: &mut usize,
) -> Option<fs::File> {
    if *opened >= MAX_CLAUDE_CACHE_DIRS || !safe_agent_asset_name(&name.to_string_lossy()) {
        return None;
    }
    *opened += 1;
    open_agent_child_dir(parent, name.as_bytes())
}
