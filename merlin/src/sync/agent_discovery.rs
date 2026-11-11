//! AI agent CLIs, MCP servers and assets.

use crate::ai_discovery::{
    ConfigRead, ContentScan, DeviceAgentAsset, DeviceAgentCLI, DeviceAiLocationCoverage,
    DeviceMCPServer, MAX_AGENT_FINDINGS, add_coverage, add_truncation, codex_enabled_plugin_names,
    config_mcp_entries, json_enabled_plugin_names, json_mcp_entries, json_project_mcp_entries,
    safe_agent_asset_name,
};
use crate::manifest::{AiLocation, Format, Scope};
use anyhow::Result;
use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::agent_read::{
    open_agent_regular_file_sized_at, read_agent_config_limited, read_agent_file_limited_at,
};
use super::ai_extensions::collect_ai_extensions;
use super::container_discovery::RootScan;
use super::plugin_cache::collect_claude_plugin_cache;
use super::{
    DeviceContainer, bounded_read, collect_container_agent_discovery,
    collect_project_agent_discovery, configured_agent_workspace_roots,
};

// Probe only fixed executable names and fixed configuration locations. Never
// execute a CLI or include configuration values in a managed heartbeat.
pub(super) fn collect_agent_discovery(containers: &[DeviceContainer]) -> RootScan {
    let mut discovery = collect_agent_discovery_from(&agent_homes(), AGENT_SYSTEM_BINS);
    let roots = configured_agent_workspace_roots();
    let (project_servers, project_assets) =
        collect_project_agent_discovery(&roots, &mut discovery.coverage);
    let containers = collect_container_agent_discovery(containers);
    let (system_servers, system_assets) = collect_system_agent_configs(Path::new("/"));
    discovery.mcp_servers.extend(system_servers);
    discovery.agent_assets.extend(system_assets);
    // Host CLIs first; the server accepts at most MAX_AGENT_CLIS.
    discovery.clis.extend(containers.clis);
    discovery.clis.truncate(MAX_AGENT_CLIS);
    discovery.mcp_servers.extend(project_servers);
    discovery.mcp_servers.extend(containers.mcp_servers);
    discovery.agent_assets.extend(containers.agent_assets);
    discovery.mcp_servers.sort();
    discovery.mcp_servers.dedup();
    discovery.mcp_servers.truncate(MAX_AGENT_FINDINGS);
    discovery.agent_assets.extend(project_assets);
    discovery.agent_assets.sort();
    discovery.agent_assets.dedup();
    discovery.agent_assets.truncate(MAX_AGENT_FINDINGS);
    for entry in containers.coverage {
        add_coverage(&mut discovery.coverage, entry);
    }
    add_truncation(
        &mut discovery.coverage,
        discovery.mcp_servers.len(),
        discovery.agent_assets.len(),
    );
    discovery
}

/// CLIs reported per inventory, host and containers together (the server's
/// limit).
pub(super) const MAX_AGENT_CLIS: usize = 32;

pub(super) const AGENT_SYSTEM_BINS: &[&str] = &[
    "/usr/local/bin",
    "/usr/bin",
    "/home/linuxbrew/.linuxbrew/bin",
];

/// The homes to scan, as this process sees `/`: `/root`, then the login
/// homes in `/etc/passwd`, then the directories in `/home` (which also
/// covers directory-service accounts that `/etc/passwd` does not list). At
/// most `MAX_AGENT_HOMES`.
pub(crate) fn agent_homes() -> Vec<PathBuf> {
    let passwd = bounded_read("/etc/passwd", 1 << 20)
        .map(|body| String::from_utf8_lossy(&body).into_owned())
        .unwrap_or_default();
    let mut listed = Vec::new();
    if let Ok(entries) = fs::read_dir("/home") {
        listed = entries
            .take(256)
            .flatten()
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
            .map(|entry| entry.path())
            .collect();
    }
    agent_homes_from(&passwd, listed)
}

/// Homes scanned per device (or per container root).
pub(super) const MAX_AGENT_HOMES: usize = 65;

pub(super) fn agent_homes_from(passwd: &str, mut listed: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut homes = vec![PathBuf::from("/root")];
    let mut from_passwd: Vec<PathBuf> = passwd
        .lines()
        .take(4096)
        .filter_map(passwd_login_home)
        // A home that is itself a symlink is not scanned: it would report
        // whatever directory it points at as this account's.
        .filter(|home| home.symlink_metadata().is_ok_and(|meta| meta.is_dir()))
        .collect();
    from_passwd.sort();
    listed.sort();
    for home in from_passwd.into_iter().chain(listed) {
        if homes.len() >= MAX_AGENT_HOMES {
            break;
        }
        if !homes.contains(&home) {
            homes.push(home);
        }
    }
    homes
}

/// The home of an `/etc/passwd` line for root or a person's account: uid 0
/// or at least 1000 (not `nobody`), an absolute home other than `/`, and a
/// shell that allows login.
pub(super) fn passwd_login_home(line: &str) -> Option<PathBuf> {
    let fields: Vec<&str> = line.split(':').collect();
    let [_, _, uid, _, _, home, shell] = fields[..] else {
        return None;
    };
    let uid: u32 = uid.parse().ok()?;
    let person = uid == 0 || (uid >= 1000 && uid != 65534);
    let login = !shell.ends_with("/nologin") && !shell.ends_with("/false");
    let home = Path::new(home);
    let plain = home.is_absolute()
        && home.parent().is_some()
        && home.components().all(|part| {
            matches!(
                part,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        });
    (person && login && plain).then(|| home.to_path_buf())
}

pub(super) fn collect_agent_discovery_from(homes: &[PathBuf], system_bins: &[&str]) -> RootScan {
    let mut coverage = Vec::new();
    let mut clis = BTreeSet::new();
    let mut servers = BTreeSet::new();
    let mut assets = BTreeSet::new();
    let mut plugin_config_reads = 0;
    let mut cursor_manifest_reads = 0;
    let mut claude_cache_dirs = 0;
    let mut content = ContentScan::new();
    for name in AiLocation::linux(Scope::User)
        .filter(|location| location.format == Format::Executable)
        .map(|location| location.path)
    {
        let found = system_bins
            .iter()
            .map(PathBuf::from)
            .chain(homes.iter().flat_map(|home| {
                [
                    home.join(".local/bin"),
                    home.join(".npm-global/bin"),
                    home.join(".bun/bin"),
                    home.join(".cargo/bin"),
                    home.join(".codex/bin"),
                ]
            }))
            .any(|dir| {
                fs::metadata(dir.join(name))
                    .is_ok_and(|meta| meta.is_file() && meta.mode() & 0o111 != 0)
            });
        if found {
            clis.insert(DeviceAgentCLI {
                name: name.into(),
                location: String::new(),
            });
        }
    }
    for home in homes.iter().take(MAX_AGENT_HOMES) {
        for location in AiLocation::linux(Scope::User)
            .filter(|location| !matches!(location.kind, "cli" | "config"))
        {
            match location.format {
                Format::CursorAgent => {
                    collect_cursor_agents(home, location, &mut assets, &mut content)
                }
                Format::CursorPlugin => collect_cursor_plugins(
                    home,
                    location,
                    &mut assets,
                    &mut cursor_manifest_reads,
                    &mut content,
                ),
                Format::ClaudePluginCache => collect_claude_plugin_cache(
                    home,
                    location,
                    (&mut assets, &mut servers),
                    &mut claude_cache_dirs,
                    &mut content,
                ),
                Format::EditorExtensions | Format::ChromiumExtensions => {
                    collect_ai_extensions(home, location, &mut assets)
                }
                // Each reader stops adding assets at the cap on its own; the
                // walk goes on so later locations still report MCP servers.
                _ => collect_user_asset_directory(
                    home,
                    location,
                    (&mut assets, &mut servers),
                    &mut plugin_config_reads,
                    &mut content,
                ),
            }
        }
        for location in AiLocation::linux(Scope::User).filter(|location| location.kind == "config")
        {
            let relative = location.path;
            let source = location.label();
            let body = match read_agent_config_limited(home, relative, location.max_bytes) {
                Some(ConfigRead::Body(body)) => body,
                Some(ConfigRead::TooLarge) => {
                    add_coverage(&mut coverage, DeviceAiLocationCoverage::too_large(location));
                    continue;
                }
                None => continue,
            };
            assets.insert(DeviceAgentAsset {
                location: String::new(),
                client: location.client.into(),
                kind: "config".into(),
                name: "user".into(),
                source: source.clone(),
                ..Default::default()
            });
            if !location.plugins_key.is_empty() {
                for name in json_enabled_plugin_names(&body, location.plugins_key) {
                    assets.insert(DeviceAgentAsset {
                        location: String::new(),
                        client: location.client.into(),
                        kind: "plugin".into(),
                        name,
                        source: source.clone(),
                        ..Default::default()
                    });
                }
            }
            if location.format == Format::Json && location.mcp_keys.is_empty() {
                continue;
            }
            if location.format == Format::CodexToml {
                for name in codex_enabled_plugin_names(&body) {
                    if assets.len() >= 128 {
                        break;
                    }
                    assets.insert(DeviceAgentAsset {
                        location: String::new(),
                        client: location.client.into(),
                        kind: "plugin".into(),
                        name,
                        source: source.clone(),
                        ..Default::default()
                    });
                }
            }
            let project_label = location.projects_label();
            let project_entries = if location.projects_key.is_empty() {
                Vec::new()
            } else {
                json_project_mcp_entries(&body, location.projects_key, location.mcp_keys)
            };
            let entries = config_mcp_entries(location, &body)
                .into_iter()
                .map(|entry| (entry, &source))
                .chain(
                    project_entries
                        .into_iter()
                        .map(|entry| (entry, &project_label)),
                );
            for (entry, source) in entries {
                if safe_agent_asset_name(&entry.name) {
                    servers.insert(entry.server(location.client, source.clone()));
                    if servers.len() >= 128 {
                        break;
                    }
                }
            }
            if servers.len() >= 128 {
                break;
            }
        }
        if servers.len() >= 128 {
            break;
        }
    }
    RootScan {
        clis: clis.into_iter().collect(),
        mcp_servers: servers.into_iter().take(128).collect(),
        agent_assets: assets.into_iter().take(128).collect(),
        coverage,
    }
}

/// The system-scope configs (an administrator's, such as Claude Code's
/// managed MCP file) beneath `root`: `/` on the host, or the scanned root
/// inside a container. Each is opened with no symlink anywhere on its path.
pub(crate) fn collect_system_agent_configs(
    root: &Path,
) -> (Vec<DeviceMCPServer>, Vec<DeviceAgentAsset>) {
    let mut servers = BTreeSet::new();
    let mut assets = BTreeSet::new();
    for location in AiLocation::linux(Scope::System) {
        let relative = location.path.trim_start_matches('/');
        let Some(body) = read_agent_config_beneath(root, relative) else {
            continue;
        };
        let source = location.label();
        assets.insert(DeviceAgentAsset {
            location: String::new(),
            client: location.client.into(),
            kind: location.kind.into(),
            name: "system".into(),
            source: source.clone(),
            ..Default::default()
        });
        for entry in config_mcp_entries(location, &body) {
            if safe_agent_asset_name(&entry.name) && servers.len() < 128 {
                servers.insert(entry.server(location.client, source.clone()));
            }
        }
    }
    (servers.into_iter().collect(), assets.into_iter().collect())
}

/// One user asset directory: each entry its format accepts becomes an asset,
/// and gemini extensions and plugin MCP files add their servers.
pub(super) fn collect_user_asset_directory(
    home: &Path,
    location: &AiLocation,
    (assets, servers): (
        &mut BTreeSet<DeviceAgentAsset>,
        &mut BTreeSet<DeviceMCPServer>,
    ),
    plugin_config_reads: &mut usize,
    content: &mut ContentScan,
) {
    // No symlink anywhere below the home: a linked `~/.claude` or
    // `~/.config` could otherwise report another account's files.
    let Some(directory) = open_agent_directory(&home.join(location.path)) else {
        return;
    };
    let Some(entries) = read_agent_dir_entries(&directory) else {
        return;
    };
    let regular_file_in = |child: &fs::File, manifest: &str| {
        agent_entry_type(child, std::ffi::OsStr::new(manifest)) == Some(libc::S_IFREG)
    };
    for entry in entries {
        let Some(kind_on_disk) = agent_entry_type(&directory, &entry) else {
            continue;
        };
        let is_file = kind_on_disk == libc::S_IFREG;
        let child = (kind_on_disk == libc::S_IFDIR)
            .then(|| open_agent_child_dir(&directory, entry.as_bytes()))
            .flatten();
        let file_name = entry.to_string_lossy().into_owned();
        let name = match location.format {
            Format::Md if is_file => file_name.strip_suffix(".md"),
            Format::JsTs if is_file => file_name
                .strip_suffix(".js")
                .or_else(|| file_name.strip_suffix(".ts")),
            Format::PluginDir if child.is_some() => Some(file_name.as_str()),
            Format::SkillDir
                if child
                    .as_ref()
                    .is_some_and(|child| regular_file_in(child, "SKILL.md")) =>
            {
                Some(file_name.as_str())
            }
            Format::GeminiExtension
                if child
                    .as_ref()
                    .is_some_and(|child| regular_file_in(child, "gemini-extension.json")) =>
            {
                Some(file_name.as_str())
            }
            _ => None,
        };
        let Some(name) = name.filter(|name| safe_agent_asset_name(name)) else {
            continue;
        };
        // At the asset cap the entry is still read for MCP servers.
        if assets.len() < 128 {
            // The skill's SKILL.md, the agent file or the extension manifest.
            let checked = match (location.format, child.as_ref()) {
                (Format::SkillDir, Some(child)) => checked_content(child, "SKILL.md", content),
                (Format::Md, _) => checked_content(&directory, &file_name, content),
                (Format::GeminiExtension, Some(child)) => {
                    checked_content(child, "gemini-extension.json", content)
                }
                _ => None,
            };
            let asset = DeviceAgentAsset {
                location: String::new(),
                client: location.client.into(),
                kind: location.kind.into(),
                name: name.into(),
                source: location.label(),
                ..Default::default()
            };
            assets.insert(asset.with_content(checked));
        }
        if location.format == Format::GeminiExtension {
            if let Some(body) = child
                .as_ref()
                .and_then(|child| read_agent_file_at(child, "gemini-extension.json"))
            {
                for entry in json_mcp_entries(&body, location.mcp_keys) {
                    if safe_agent_asset_name(&entry.name) {
                        let source = format!("{}/*/gemini-extension.json", location.label());
                        servers.insert(entry.server(location.client, source));
                    }
                }
            }
        }
        for config in location.mcp_files {
            if *plugin_config_reads >= 32 {
                break;
            }
            if let Some(body) = child
                .as_ref()
                .and_then(|child| read_agent_file_at(child, config))
            {
                *plugin_config_reads += 1;
                for entry in json_mcp_entries(&body, location.mcp_keys) {
                    if safe_agent_asset_name(&entry.name) {
                        let source = format!("{}/*/{config}", location.label());
                        servers.insert(entry.server(location.client, source));
                    }
                }
            }
        }
    }
}

/// Open each path component relative to the previous directory. A pathname
/// check followed by `read_dir` would let a user replace a parent with a link
/// while the root collector is traversing it.
pub(crate) fn open_agent_directory(path: &Path) -> Option<fs::File> {
    use std::path::Component;
    let mut directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .ok()?;
    for component in path.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(name) => {
                directory = open_agent_child_dir(&directory, name.as_bytes())?;
            }
            _ => return None,
        }
    }
    Some(directory)
}

pub(crate) fn open_agent_child_dir(parent: &fs::File, name: &[u8]) -> Option<fs::File> {
    let name = CString::new(name).ok()?;
    // SAFETY: `parent` is open during the call, the name is NUL terminated,
    // and ownership of a successful descriptor transfers to File.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    (fd >= 0).then(|| unsafe { fs::File::from_raw_fd(fd) })
}

/// Whether `name` in `parent` is a regular file itself (not a link to one),
/// without opening it.
pub(super) fn agent_regular_file_exists_at(parent: &fs::File, name: &CStr) -> bool {
    // SAFETY: `parent` is open, `name` is NUL terminated and `stat` is a
    // valid out pointer for the call.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    (unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    }) == 0
        && stat.st_mode & libc::S_IFMT == libc::S_IFREG
}

/// The default read limit of a declared file (a manifest row's `max_bytes`
/// when it sets none).
pub(super) const AGENT_FILE_LIMIT: u64 = 64 << 10;

pub(super) fn open_agent_regular_file_at(parent: &fs::File, name: &str) -> Option<fs::File> {
    open_agent_regular_file_within(parent, std::ffi::OsStr::new(name), AGENT_FILE_LIMIT)
}

/// The content check (ai_discovery::ContentScan) of the regular file `name`
/// in `parent`, opened the same way as every other agent file.
pub(super) fn checked_content(
    parent: &fs::File,
    name: &str,
    content: &mut ContentScan,
) -> Option<crate::ai_discovery::ContentFacts> {
    let file = open_agent_regular_file_within(
        parent,
        std::ffi::OsStr::new(name),
        crate::ai_discovery::MAX_CONTENT_BYTES,
    )?;
    content.check_file(file)
}

pub(super) fn open_agent_regular_file_within(
    parent: &fs::File,
    name: &std::ffi::OsStr,
    max_len: u64,
) -> Option<fs::File> {
    open_agent_regular_file_sized_at(parent, name)
        .and_then(|(file, size)| (size <= max_len).then_some(file))
}

pub(super) fn read_agent_file_at(parent: &fs::File, name: &str) -> Option<String> {
    match read_agent_file_limited_at(parent, name, AGENT_FILE_LIMIT)? {
        ConfigRead::Body(body) => Some(body),
        ConfigRead::TooLarge => None,
    }
}

/// Read `relative` beneath `home` with no symlink anywhere on the way: not
/// the home, not a parent directory, not the file.
pub(crate) fn read_agent_config_beneath(home: &Path, relative: &str) -> Option<String> {
    match read_agent_config_limited(home, relative, AGENT_FILE_LIMIT)? {
        ConfigRead::Body(body) => Some(body),
        ConfigRead::TooLarge => None,
    }
}

/// The file type of `name` in an open directory, not following a symlink.
pub(crate) fn agent_entry_type(
    directory: &fs::File,
    name: &std::ffi::OsStr,
) -> Option<libc::mode_t> {
    let name = CString::new(name.as_bytes()).ok()?;
    // SAFETY: `directory` is open, `name` is NUL terminated and `stat` is a
    // valid out pointer for the call.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let found = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0;
    found.then_some(stat.st_mode & libc::S_IFMT)
}

/// The first 256 entry names of an open directory. Reads the descriptor
/// itself, so it works without `/proc` (inside a container's root).
pub(crate) fn read_agent_dir_entries(directory: &fs::File) -> Option<Vec<std::ffi::OsString>> {
    let mut entries = nix::dir::Dir::openat(
        Some(directory.as_raw_fd()),
        ".",
        nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_DIRECTORY | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .ok()?;
    Some(
        entries
            .iter()
            .take(258)
            .filter_map(Result::ok)
            .map(|entry| std::ffi::OsStr::from_bytes(entry.file_name().to_bytes()).to_os_string())
            .filter(|name| name != "." && name != "..")
            .take(256)
            .collect(),
    )
}

/// Cursor agent files: regular `*.md` of at most 64 KiB, opened with no
/// symlink anywhere below the home.
pub(super) fn collect_cursor_agents(
    home: &Path,
    location: &AiLocation,
    assets: &mut BTreeSet<DeviceAgentAsset>,
    content: &mut ContentScan,
) {
    let Some(directory) = open_agent_directory(&home.join(location.path)) else {
        return;
    };
    let Some(entries) = read_agent_dir_entries(&directory) else {
        return;
    };
    for entry in entries {
        if assets.len() >= 128 {
            break;
        }
        let name = entry.to_string_lossy().into_owned();
        let Some(name) = name
            .strip_suffix(".md")
            .filter(|name| safe_agent_asset_name(name))
        else {
            continue;
        };
        if let Some(file) = open_agent_regular_file_at(&directory, &format!("{name}.md")) {
            let asset = DeviceAgentAsset {
                location: String::new(),
                client: location.client.into(),
                kind: location.kind.into(),
                name: name.into(),
                source: location.label(),
                ..Default::default()
            };
            assets.insert(asset.with_content(content.check_file(file)));
        }
    }
}

/// Cursor local plugins: a child directory counts when its `plugin.json` or
/// `.cursor-plugin/plugin.json` is a valid bounded manifest with a safe name.
pub(super) fn collect_cursor_plugins(
    home: &Path,
    location: &AiLocation,
    assets: &mut BTreeSet<DeviceAgentAsset>,
    manifest_reads: &mut usize,
    content: &mut ContentScan,
) {
    let Some(directory) = open_agent_directory(&home.join(location.path)) else {
        return;
    };
    let Some(entries) = read_agent_dir_entries(&directory) else {
        return;
    };
    for entry in entries {
        if assets.len() >= 128 || *manifest_reads >= 256 {
            break;
        }
        let name = entry.to_string_lossy().into_owned();
        if !safe_agent_asset_name(&name) {
            continue;
        }
        let Some(plugin_dir) = open_agent_child_dir(&directory, name.as_bytes()) else {
            continue;
        };
        *manifest_reads += 1;
        let manifest = read_agent_file_at(&plugin_dir, "plugin.json").or_else(|| {
            let cursor_dir = open_agent_child_dir(&plugin_dir, b".cursor-plugin")?;
            read_agent_file_at(&cursor_dir, "plugin.json")
        });
        let Some(manifest) = manifest else {
            continue;
        };
        let valid_name = serde_json::from_str::<serde_json::Value>(&manifest)
            .ok()
            .and_then(|value| value.get("name")?.as_str().map(str::to_string))
            .is_some_and(|manifest_name| safe_agent_asset_name(&manifest_name));
        if valid_name {
            let asset = DeviceAgentAsset {
                location: String::new(),
                client: location.client.into(),
                kind: location.kind.into(),
                name,
                source: location.label(),
                ..Default::default()
            };
            assets.insert(asset.with_content(content.check(manifest.as_bytes())));
        }
    }
}
