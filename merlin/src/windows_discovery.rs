//! Windows AI-tool discovery: the collection manifest's `ai_locations` rows
//! for Windows, read under each local profile and each admin-configured
//! workspace root. Findings carry names, fixed source labels and declared MCP
//! transport only: never usernames, absolute paths, config values, URLs,
//! commands or prompts. Every read goes through a `ContainedFs`, so a link or
//! junction never leads a probe outside the profile or workspace root.

mod contained;
#[cfg(windows)]
mod handle_fs;
// The discovery tests use Unix symlinks and `PortableFs`; `handle_fs` has
// the Windows handle tests.
#[cfg(all(test, not(windows)))]
mod tests;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::ai_discovery::{
    ConfigRead, DeviceAgentAsset, DeviceAgentCLI, DeviceAiLocationCoverage, DeviceMCPServer,
    DeviceProcess, MAX_BROWSER_PROFILES, McpEntry, add_coverage, chromium_extension_id,
    chromium_profile, codex_enabled_plugin_names, config_mcp_entries, editor_extension_id,
    json_enabled_plugin_names, json_mcp_entries, safe_agent_asset_name,
};
use crate::manifest::{AiLocation, Format, Scope};

#[cfg(all(test, not(windows)))]
pub(crate) use contained::PortableFs;
pub(crate) use contained::{ContainedFs, valid_workspace_root};
#[cfg(windows)]
pub(crate) use handle_fs::HandleFs;

use contained::join_relative;

/// Config and manifest files are read only when at most this large.
const MAX_CONFIG_BYTES: u64 = 64 << 10;
/// Any size counts for an executable or app binary.
const ANY_SIZE: u64 = 1 << 40;
/// Entries examined per directory.
const MAX_ENTRIES: usize = 256;
/// Profiles scanned, from the first `MAX_ENTRIES` entries of the profiles root.
const MAX_PROFILES: usize = 64;
/// Plugin and extension manifests read per collection.
const MAX_MANIFEST_READS: usize = 32;
/// Findings of each kind reported.
const MAX_FINDINGS: usize = 128;
/// Directories below a workspace root visited, and how deep.
const MAX_PROJECT_DESCENDANTS: usize = 32;
const MAX_PROJECT_DEPTH: usize = 2;
/// Project discovery is optional and must not hold up the check-in.
const PROJECT_DEADLINE: Duration = Duration::from_secs(10);

/// Per-profile directories where npm, pip/uv, cargo, bun and Codex install
/// CLI shims, checked for `<name>.exe` and `<name>.cmd`.
const PROFILE_BIN_DIRS: &[&str] = &[
    "AppData/Roaming/npm",
    ".local/bin",
    ".cargo/bin",
    ".bun/bin",
    ".codex/bin",
];
const CLI_EXTENSIONS: &[&str] = &[".exe", ".cmd"];
/// The desktop app probed under each app root (Program Files).
const CURSOR_APP: &str = "Cursor/Cursor.exe";

/// Where Windows discovery looks on this machine.
pub(crate) struct DiscoveryRoots {
    /// The directory holding local profiles (`%SystemDrive%\Users`).
    pub profiles: PathBuf,
    /// Machine-wide CLI directories (`%ProgramFiles%\nodejs`).
    pub system_bins: Vec<PathBuf>,
    /// Directories holding installed apps (`%ProgramFiles%`).
    pub app_roots: Vec<PathBuf>,
    /// Admin-configured workspace roots; none means no project scan.
    pub workspaces: Vec<PathBuf>,
}

impl DiscoveryRoots {
    /// This machine's roots, from `SystemDrive` and `ProgramFiles`.
    #[cfg(windows)]
    pub(crate) fn system(workspaces: Vec<PathBuf>) -> Self {
        let drive = std::env::var("SystemDrive")
            .ok()
            .filter(|drive| !drive.is_empty())
            .unwrap_or_else(|| "C:".into());
        let drive_root = PathBuf::from(format!("{drive}\\"));
        let program_files = std::env::var_os("ProgramFiles")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| drive_root.join("Program Files"));
        Self {
            profiles: drive_root.join("Users"),
            system_bins: vec![program_files.join("nodejs")],
            app_roots: vec![program_files],
            workspaces,
        }
    }
}

/// A desktop app found installed: Cursor under Program Files.
#[derive(Debug, PartialEq, serde::Serialize)]
pub(crate) struct DeviceAgentApp {
    pub name: String,
}

#[derive(Debug, Default, PartialEq, serde::Serialize)]
pub(crate) struct WindowsDiscovery {
    pub agent_clis: Vec<DeviceAgentCLI>,
    pub agent_apps: Vec<DeviceAgentApp>,
    pub mcp_servers: Vec<DeviceMCPServer>,
    pub agent_assets: Vec<DeviceAgentAsset>,
    /// Running AI agent processes (`windows_host::agent_processes`).
    pub processes: Vec<DeviceProcess>,
    /// Declared files that were not read (too large); the check-in sends
    /// them as `ai_location_coverage`.
    #[serde(skip)]
    pub coverage: Vec<DeviceAiLocationCoverage>,
}

/// The agent executables the process snapshot reports, matching the
/// process evidence the server's agent findings recognize for cursor,
/// claude and codex.
const AGENT_PROCESS_EXECUTABLES: &[&str] = &["cursor.exe", "claude.exe", "codex.exe"];

/// Processes reported per snapshot.
#[cfg_attr(not(windows), allow(dead_code, reason = "read by windows_host"))]
pub(crate) const MAX_AGENT_PROCESSES: usize = 32;

/// Whether a Windows image file name is one of the agent executables,
/// compared case-insensitively after trimming.
pub(crate) fn is_agent_process(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    AGENT_PROCESS_EXECUTABLES.contains(&name.as_str())
}

/// Add findings from places off the host (WSL) to `discovery`, deduplicated
/// and capped like the host's own.
pub(crate) fn merge_off_host(
    discovery: &mut WindowsDiscovery,
    servers: Vec<DeviceMCPServer>,
    assets: Vec<DeviceAgentAsset>,
) {
    let servers: BTreeSet<_> = discovery.mcp_servers.drain(..).chain(servers).collect();
    let assets: BTreeSet<_> = discovery.agent_assets.drain(..).chain(assets).collect();
    discovery.mcp_servers = servers.into_iter().take(MAX_FINDINGS).collect();
    discovery.agent_assets = assets.into_iter().take(MAX_FINDINGS).collect();
}

/// User-level discovery under every profile plus project discovery under the
/// workspace roots, merged, deduplicated and capped.
pub(crate) fn collect(fs: &impl ContainedFs, roots: &DiscoveryRoots) -> WindowsDiscovery {
    let mut found = Findings::default();
    let profiles = profiles(fs, &roots.profiles);
    let agent_clis = collect_clis(fs, &profiles, &roots.system_bins);
    let agent_apps = collect_apps(fs, &roots.app_roots);
    for profile in &profiles {
        collect_user_configs(fs, profile, &mut found);
        collect_user_asset_directories(fs, profile, &mut found);
    }
    let mut project = collect_projects(fs, &roots.workspaces);
    found.servers.append(&mut project.servers);
    found.assets.append(&mut project.assets);
    WindowsDiscovery {
        agent_clis,
        agent_apps,
        mcp_servers: found.servers.into_iter().take(MAX_FINDINGS).collect(),
        agent_assets: found.assets.into_iter().take(MAX_FINDINGS).collect(),
        processes: Vec::new(),
        coverage: found.coverage,
    }
}

#[derive(Default)]
struct Findings {
    servers: BTreeSet<DeviceMCPServer>,
    assets: BTreeSet<DeviceAgentAsset>,
    manifest_reads: usize,
    coverage: Vec<DeviceAiLocationCoverage>,
}

impl Findings {
    fn asset(&mut self, location: &AiLocation, kind: &str, name: &str, source: String) {
        self.assets.insert(DeviceAgentAsset {
            location: String::new(),
            client: location.client.into(),
            kind: kind.into(),
            name: name.into(),
            source,
            ..Default::default()
        });
    }

    fn servers(&mut self, location: &AiLocation, entries: Vec<McpEntry>, source: &str) {
        for entry in entries {
            if safe_agent_asset_name(&entry.name) {
                self.servers
                    .insert(entry.server(location.client, source.into()));
            }
        }
    }

    /// Read one plugin or extension manifest under the shared budget.
    fn read_manifest(&mut self, fs: &impl ContainedFs, root: &Path, path: &Path) -> Option<String> {
        if self.manifest_reads >= MAX_MANIFEST_READS {
            return None;
        }
        self.manifest_reads += 1;
        read_text(fs, root, path)
    }
}

fn read_text(fs: &impl ContainedFs, root: &Path, path: &Path) -> Option<String> {
    String::from_utf8(fs.read_within(root, path, MAX_CONFIG_BYTES)?).ok()
}

/// A declared config read up to `limit` bytes. A contained regular file over
/// the limit is `TooLarge`; one that cannot be read otherwise is `None`.
fn read_config(fs: &impl ContainedFs, root: &Path, path: &Path, limit: u64) -> Option<ConfigRead> {
    if let Some(body) = fs.read_within(root, path, limit) {
        return String::from_utf8(body).ok().map(ConfigRead::Body);
    }
    fs.regular_file_within(root, path, ANY_SIZE)
        .then_some(ConfigRead::TooLarge)
}

fn windows_locations(scope: Scope) -> impl Iterator<Item = &'static AiLocation> {
    AiLocation::on("windows", scope)
}

/// At most `MAX_PROFILES` plain directories among the first `MAX_ENTRIES`
/// entries of the profiles root.
fn profiles(fs: &impl ContainedFs, root: &Path) -> Vec<PathBuf> {
    fs.entries_within(root, root, MAX_ENTRIES)
        .into_iter()
        .map(|name| root.join(name))
        .filter(|path| fs.directory_within(root, path))
        .take(MAX_PROFILES)
        .collect()
}

/// A declared CLI counts when `<name>.exe` or `<name>.cmd` is a regular file
/// in a machine-wide bin directory or a profile's shim directory.
fn collect_clis(
    fs: &impl ContainedFs,
    profiles: &[PathBuf],
    system_bins: &[PathBuf],
) -> Vec<DeviceAgentCLI> {
    let mut bins: Vec<PathBuf> = system_bins.to_vec();
    for profile in profiles {
        for relative in PROFILE_BIN_DIRS {
            let path = join_relative(profile, relative);
            if fs.directory_within(profile, &path) {
                bins.push(path);
            }
        }
    }
    bins.retain(|bin| fs.directory_within(bin, bin));
    let mut clis = BTreeSet::new();
    for location in windows_locations(Scope::User).filter(|l| l.format == Format::Executable) {
        let name = location.path;
        let found = bins.iter().any(|bin| {
            CLI_EXTENSIONS.iter().any(|extension| {
                fs.regular_file_within(bin, &bin.join(format!("{name}{extension}")), ANY_SIZE)
            })
        });
        if found {
            clis.insert(DeviceAgentCLI {
                name: name.into(),
                location: String::new(),
            });
        }
    }
    clis.into_iter().collect()
}

fn collect_apps(fs: &impl ContainedFs, app_roots: &[PathBuf]) -> Vec<DeviceAgentApp> {
    app_roots
        .iter()
        .any(|root| fs.regular_file_within(root, &join_relative(root, CURSOR_APP), ANY_SIZE))
        .then(|| DeviceAgentApp {
            name: "cursor".into(),
        })
        .into_iter()
        .collect()
}

/// The declared user config files of one profile: each readable one is a
/// `config` asset, its enabled plugins are `plugin` assets and its MCP
/// entries are servers.
fn collect_user_configs(fs: &impl ContainedFs, profile: &Path, found: &mut Findings) {
    for location in windows_locations(Scope::User).filter(|l| l.kind == "config") {
        let path = join_relative(profile, location.path);
        let body = match read_config(fs, profile, &path, location.max_bytes) {
            Some(ConfigRead::Body(body)) => body,
            Some(ConfigRead::TooLarge) => {
                add_coverage(
                    &mut found.coverage,
                    DeviceAiLocationCoverage::too_large(location),
                );
                continue;
            }
            None => continue,
        };
        let source = location.label();
        found.asset(location, "config", "user", source.clone());
        if !location.plugins_key.is_empty() {
            for name in json_enabled_plugin_names(&body, location.plugins_key) {
                found.asset(location, "plugin", &name, source.clone());
            }
        }
        if location.format == Format::Json && location.mcp_keys.is_empty() {
            continue;
        }
        if location.format == Format::CodexToml {
            for name in codex_enabled_plugin_names(&body) {
                if found.assets.len() >= MAX_FINDINGS {
                    break;
                }
                found.asset(location, "plugin", &name, source.clone());
            }
        }
        found.servers(location, config_mcp_entries(location, &body), &source);
    }
}

/// The declared skill, agent, plugin and extension directories of one
/// profile, each entry checked against its location's format.
fn collect_user_asset_directories(fs: &impl ContainedFs, profile: &Path, found: &mut Findings) {
    for location in windows_locations(Scope::User).filter(|l| !matches!(l.kind, "cli" | "config")) {
        let directory = join_relative(profile, location.path);
        if location.format == Format::ChromiumExtensions {
            collect_chromium_extensions(fs, profile, &directory, location, found);
            continue;
        }
        for entry in fs.entries_within(profile, &directory, MAX_ENTRIES) {
            let path = directory.join(&entry);
            let name = match location.format {
                Format::SkillDir => skill_name(fs, profile, &path, &entry),
                Format::Md | Format::CursorAgent => file_stem(fs, profile, &path, &entry, &[".md"]),
                Format::JsTs => file_stem(fs, profile, &path, &entry, &[".js", ".ts"]),
                Format::GeminiExtension => (fs.directory_within(profile, &path)
                    && fs.regular_file_within(
                        profile,
                        &path.join("gemini-extension.json"),
                        MAX_CONFIG_BYTES,
                    ))
                .then_some(entry.as_str()),
                Format::PluginDir => fs
                    .directory_within(profile, &path)
                    .then_some(entry.as_str()),
                Format::CursorPlugin => cursor_plugin_name(fs, profile, &path, &entry, found),
                Format::EditorExtensions => {
                    editor_extension_id(&entry).filter(|_| fs.directory_within(profile, &path))
                }
                _ => None,
            };
            let Some(name) = name.filter(|name| safe_agent_asset_name(name)) else {
                continue;
            };
            found.asset(location, location.kind, name, location.label());
            match location.format {
                Format::GeminiExtension => {
                    let manifest = path.join("gemini-extension.json");
                    if let Some(body) = found.read_manifest(fs, profile, &manifest) {
                        let source = format!("{}/*/gemini-extension.json", location.label());
                        found.servers(
                            location,
                            json_mcp_entries(&body, location.mcp_keys),
                            &source,
                        );
                    }
                }
                Format::PluginDir => read_plugin_mcp_files(fs, profile, &path, location, found),
                _ => {}
            }
        }
    }
}

/// The declared extensions in each profile of a Chromium user data
/// directory, each an asset named by its id.
fn collect_chromium_extensions(
    fs: &impl ContainedFs,
    root: &Path,
    user_data: &Path,
    location: &AiLocation,
    found: &mut Findings,
) {
    let profiles = fs
        .entries_within(root, user_data, MAX_ENTRIES)
        .into_iter()
        .filter(|entry| chromium_profile(entry))
        .take(MAX_BROWSER_PROFILES);
    for profile in profiles {
        let extensions = user_data.join(&profile).join("Extensions");
        for entry in fs.entries_within(root, &extensions, MAX_ENTRIES) {
            if let Some(id) = chromium_extension_id(&entry)
                .filter(|_| fs.directory_within(root, &extensions.join(&entry)))
            {
                found.asset(location, location.kind, id, location.label());
            }
        }
    }
}

fn skill_name<'a>(
    fs: &impl ContainedFs,
    root: &Path,
    path: &Path,
    entry: &'a str,
) -> Option<&'a str> {
    (fs.directory_within(root, path)
        && fs.regular_file_within(root, &path.join("SKILL.md"), MAX_CONFIG_BYTES))
    .then_some(entry)
}

fn file_stem<'a>(
    fs: &impl ContainedFs,
    root: &Path,
    path: &Path,
    entry: &'a str,
    extensions: &[&str],
) -> Option<&'a str> {
    let stem = extensions
        .iter()
        .find_map(|extension| entry.strip_suffix(extension))?;
    fs.regular_file_within(root, path, MAX_CONFIG_BYTES)
        .then_some(stem)
}

/// A Cursor local plugin counts when its `plugin.json` or
/// `.cursor-plugin/plugin.json` is a bounded manifest naming a safe name.
fn cursor_plugin_name<'a>(
    fs: &impl ContainedFs,
    root: &Path,
    path: &Path,
    entry: &'a str,
    found: &mut Findings,
) -> Option<&'a str> {
    if !fs.directory_within(root, path) || !safe_agent_asset_name(entry) {
        return None;
    }
    for relative in ["plugin.json", ".cursor-plugin/plugin.json"] {
        if found.manifest_reads >= MAX_MANIFEST_READS {
            break;
        }
        let manifest = join_relative(path, relative);
        if !manifest
            .parent()
            .is_some_and(|parent| fs.directory_within(root, parent))
        {
            continue;
        }
        let Some(body) = found.read_manifest(fs, root, &manifest) else {
            continue;
        };
        let named = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|value| value.get("name")?.as_str().map(safe_agent_asset_name))
            .unwrap_or(false);
        if named {
            return Some(entry);
        }
    }
    None
}

/// MCP servers declared in a plugin directory's `mcp_files`.
fn read_plugin_mcp_files(
    fs: &impl ContainedFs,
    root: &Path,
    plugin: &Path,
    location: &AiLocation,
    found: &mut Findings,
) {
    for config in location.mcp_files {
        if found.manifest_reads >= MAX_MANIFEST_READS {
            break;
        }
        if let Some(body) = found.read_manifest(fs, root, &plugin.join(config)) {
            let source = format!("{}/*/{config}", location.label());
            found.servers(
                location,
                json_mcp_entries(&body, location.mcp_keys),
                &source,
            );
        }
    }
}

/// Each workspace root and at most `MAX_PROJECT_DESCENDANTS` directories
/// below it, breadth first and at most `MAX_PROJECT_DEPTH` levels down, all
/// within `PROJECT_DEADLINE`.
fn collect_projects(fs: &impl ContainedFs, roots: &[PathBuf]) -> Findings {
    let deadline = Instant::now() + PROJECT_DEADLINE;
    let mut found = Findings::default();
    for root in roots {
        if Instant::now() >= deadline {
            break;
        }
        let valid = root.to_str().is_some_and(valid_workspace_root);
        if !valid || !fs.directory_within(root, root) {
            continue;
        }
        for project in project_directories(fs, root, deadline) {
            if Instant::now() >= deadline {
                break;
            }
            collect_project(fs, root, &project, deadline, &mut found);
        }
    }
    found
}

fn project_directories(fs: &impl ContainedFs, root: &Path, deadline: Instant) -> Vec<PathBuf> {
    // Breadth first gives direct children priority over grandchildren.
    let mut projects = vec![(root.to_path_buf(), 0)];
    let mut index = 0;
    while index < projects.len()
        && projects.len() <= MAX_PROJECT_DESCENDANTS
        && Instant::now() < deadline
    {
        let (parent, depth) = projects[index].clone();
        index += 1;
        if depth >= MAX_PROJECT_DEPTH {
            continue;
        }
        for name in fs.entries_within(root, &parent, MAX_ENTRIES) {
            if projects.len() > MAX_PROJECT_DESCENDANTS || Instant::now() >= deadline {
                break;
            }
            let path = parent.join(name);
            if fs.directory_within(root, &path) {
                projects.push((path, depth + 1));
            }
        }
    }
    projects.into_iter().map(|(path, _)| path).collect()
}

fn collect_project(
    fs: &impl ContainedFs,
    root: &Path,
    project: &Path,
    deadline: Instant,
    found: &mut Findings,
) {
    for location in windows_locations(Scope::Project).filter(|l| l.kind == "config") {
        if Instant::now() >= deadline {
            return;
        }
        let Some(body) = read_text(fs, root, &join_relative(project, location.path)) else {
            continue;
        };
        let source = location.label();
        found.asset(location, "config", "project", source.clone());
        if !location.plugins_key.is_empty() {
            for name in json_enabled_plugin_names(&body, location.plugins_key) {
                found.asset(location, "plugin", &name, source.clone());
            }
        }
        found.servers(location, config_mcp_entries(location, &body), &source);
    }
    for location in windows_locations(Scope::Project).filter(|l| l.kind != "config") {
        if Instant::now() >= deadline {
            return;
        }
        let directory = join_relative(project, location.path);
        if !fs.directory_within(root, &directory) {
            continue;
        }
        for entry in fs.entries_within(root, &directory, MAX_ENTRIES) {
            let path = directory.join(&entry);
            let name = match location.format {
                Format::SkillDir => skill_name(fs, root, &path, &entry),
                Format::Md => file_stem(fs, root, &path, &entry, &[".md"]),
                Format::PluginDir => fs.directory_within(root, &path).then_some(entry.as_str()),
                _ => None,
            };
            let Some(name) = name.filter(|name| safe_agent_asset_name(name)) else {
                continue;
            };
            found.asset(location, location.kind, name, location.label());
            if location.format == Format::PluginDir {
                read_plugin_mcp_files(fs, root, &path, location, found);
            }
        }
    }
}
