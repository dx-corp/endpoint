use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::dir::Dir;
use nix::fcntl::{self, OFlag};
use nix::sys::stat::Mode;

use super::{
    DeviceAgentAsset, DeviceMCPServer, codex_mcp_entries, json_mcp_entries, safe_agent_asset_name,
};

// MDM supplies a JSON array in the root-owned service configuration. No default
// workspace roots are scanned, and no configured path is sent in inventory.
pub(super) fn configured_agent_workspace_roots() -> Vec<PathBuf> {
    let Ok(raw) = std::env::var("MERLIN_AGENT_WORKSPACE_ROOTS") else {
        return Vec::new();
    };
    if raw.len() > 4096 {
        return Vec::new();
    }
    serde_json::from_str::<Vec<String>>(&raw)
        .unwrap_or_default()
        .into_iter()
        .filter(|path| path.len() <= 512 && path.starts_with('/'))
        .map(PathBuf::from)
        .filter(|path| {
            path.components().all(|component| {
                matches!(
                    component,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
        })
        .take(8)
        .collect()
}

const DIRECTORY_FLAGS: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_DIRECTORY)
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC);
const FILE_FLAGS: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC)
    .union(OFlag::O_NONBLOCK);

fn open_directory_at(parent: &Dir, name: &OsStr) -> Option<Dir> {
    Dir::openat(
        Some(parent.as_raw_fd()),
        name,
        DIRECTORY_FLAGS,
        Mode::empty(),
    )
    .ok()
}

fn open_project_root(path: &Path) -> Option<Dir> {
    let mut directory = Dir::open("/", DIRECTORY_FLAGS, Mode::empty()).ok()?;
    let mut absolute = false;
    for component in path.components() {
        match component {
            std::path::Component::RootDir => absolute = true,
            std::path::Component::Normal(name) if absolute => {
                directory = open_directory_at(&directory, name)?;
            }
            _ => return None,
        }
    }
    absolute.then_some(directory)
}

fn open_relative_directory(project: &Dir, relative: &str) -> Option<Dir> {
    let mut segments = relative.split('/');
    let first = segments.next()?;
    if first.is_empty() || first == "." || first == ".." {
        return None;
    }
    let mut directory = open_directory_at(project, OsStr::new(first))?;
    for segment in segments {
        if segment.is_empty() || segment == "." || segment == ".." {
            return None;
        }
        directory = open_directory_at(&directory, OsStr::new(segment))?;
    }
    Some(directory)
}

fn open_regular_file_at(directory: &Dir, name: &OsStr) -> Option<File> {
    let fd = fcntl::openat(Some(directory.as_raw_fd()), name, FILE_FLAGS, Mode::empty()).ok()?;
    let file = unsafe { File::from_raw_fd(fd) };
    file.metadata().ok().filter(|meta| meta.is_file())?;
    Some(file)
}

fn read_agent_config_at(project: &Dir, relative: &str) -> Option<String> {
    let (parent, filename) = relative.rsplit_once('/').unwrap_or(("", relative));
    let directory = if parent.is_empty() {
        None
    } else {
        Some(open_relative_directory(project, parent)?)
    };
    let base = if parent.is_empty() {
        project
    } else {
        directory.as_ref()?
    };
    let file = open_regular_file_at(base, OsStr::new(filename))?;
    if file.metadata().ok()?.len() > 64 << 10 {
        return None;
    }
    let mut body = String::new();
    file.take((64 << 10) + 1).read_to_string(&mut body).ok()?;
    (body.len() <= 64 << 10).then_some(body)
}

fn first_entries(directory: &mut Dir) -> Vec<OsString> {
    directory
        .iter()
        .take(258)
        .filter_map(Result::ok)
        .map(|entry| OsStr::from_bytes(entry.file_name().to_bytes()).to_os_string())
        .filter(|name| name != "." && name != "..")
        .take(256)
        .collect()
}

fn project_directories(root: Dir, deadline: Instant) -> Vec<Dir> {
    const MAX_DESCENDANTS: usize = 32;
    const MAX_DEPTH: usize = 2;

    let mut projects = vec![(root, 0)];
    let mut next = 0;
    // Breadth-first keeps the existing immediate-child coverage when a root
    // has 32 or more children. Each child is opened from its parent handle.
    while next < projects.len() && projects.len() <= MAX_DESCENDANTS && Instant::now() < deadline {
        let remaining = MAX_DESCENDANTS + 1 - projects.len();
        let children = {
            let (directory, depth) = &mut projects[next];
            if *depth >= MAX_DEPTH {
                Vec::new()
            } else {
                let mut names = first_entries(directory);
                names.sort();
                names
                    .into_iter()
                    .filter_map(|name| open_directory_at(directory, &name))
                    .take(remaining)
                    .map(|child| (child, *depth + 1))
                    .collect()
            }
        };
        projects.extend(children);
        next += 1;
    }
    projects
        .into_iter()
        .map(|(directory, _)| directory)
        .collect()
}

#[cfg(test)]
pub(super) fn project_directory_count(root: &Path, deadline: Instant) -> usize {
    open_project_root(root).map_or(0, |dir| project_directories(dir, deadline).len())
}

pub(super) fn collect_project_agent_discovery(
    roots: &[PathBuf],
) -> (Vec<DeviceMCPServer>, Vec<DeviceAgentAsset>) {
    const CONFIGS: &[(&str, &str, bool)] = &[
        ("claude", ".mcp.json", false),
        ("claude", ".claude/settings.json", false),
        ("cursor", ".cursor/mcp.json", false),
        ("codex", ".codex/config.toml", true),
        ("opencode", ".opencode/opencode.json", false),
        ("agents", ".agents/mcp.json", false),
    ];
    const ASSETS: &[(&str, &str, &str, &str)] = &[
        ("agents", "skill", ".agents/skills", "skill"),
        ("claude", "skill", ".claude/skills", "skill"),
        ("claude", "agent", ".claude/agents", "md"),
        ("claude", "plugin", ".claude/plugins", "plugin"),
        ("codex", "skill", ".codex/skills", "skill"),
        ("cursor", "skill", ".cursor/skills", "skill"),
        ("maestro", "plugin", ".maestro/plugins", "plugin"),
        ("maestro", "plugin", ".composer/plugins", "plugin"),
    ];
    let mut servers = BTreeSet::new();
    let mut assets = BTreeSet::new();
    let mut plugin_config_reads = 0;
    let deadline = Instant::now() + Duration::from_secs(5);
    for root in roots.iter().take(8) {
        if Instant::now() >= deadline {
            break;
        }
        let Some(root) = open_project_root(root) else {
            continue;
        };
        for project in project_directories(root, deadline) {
            if Instant::now() >= deadline {
                break;
            }
            for (client, relative, is_toml) in CONFIGS {
                if Instant::now() >= deadline {
                    break;
                }
                let Some(body) = read_agent_config_at(&project, relative) else {
                    continue;
                };
                assets.insert(DeviceAgentAsset {
                    client: (*client).into(),
                    kind: "config".into(),
                    name: "project".into(),
                    source: format!("project/{relative}"),
                });
                if *relative == ".claude/settings.json" {
                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) {
                        if let Some(plugins) =
                            value.get("enabledPlugins").and_then(|v| v.as_object())
                        {
                            for (name, enabled) in plugins {
                                if enabled.as_bool() == Some(true) && safe_agent_asset_name(name) {
                                    assets.insert(DeviceAgentAsset {
                                        client: "claude".into(),
                                        kind: "plugin".into(),
                                        name: name.clone(),
                                        source: "project/.claude/settings.json".into(),
                                    });
                                }
                            }
                        }
                    }
                }
                let entries = if *is_toml {
                    codex_mcp_entries(&body)
                } else if *client == "opencode" {
                    json_mcp_entries(&body, &["mcp"])
                } else {
                    json_mcp_entries(&body, &["mcpServers", "servers"])
                };
                for (name, transport) in entries
                    .into_iter()
                    .filter(|(name, _)| safe_agent_asset_name(name))
                {
                    servers.insert(DeviceMCPServer {
                        client: (*client).into(),
                        name,
                        source: format!("project/{relative}"),
                        transport,
                    });
                }
            }
            for (client, kind, relative, format) in ASSETS {
                if Instant::now() >= deadline {
                    break;
                }
                let Some(mut directory) = open_relative_directory(&project, relative) else {
                    continue;
                };
                for entry in first_entries(&mut directory) {
                    if Instant::now() >= deadline {
                        break;
                    }
                    let filename = entry.to_string_lossy().into_owned();
                    let child_directory = if *format == "skill" || *format == "plugin" {
                        open_directory_at(&directory, &entry)
                    } else {
                        None
                    };
                    let name = match *format {
                        "skill"
                            if child_directory.as_ref().is_some_and(|child| {
                                open_regular_file_at(child, OsStr::new("SKILL.md")).is_some()
                            }) =>
                        {
                            Some(filename.as_str())
                        }
                        "plugin" if child_directory.is_some() => Some(filename.as_str()),
                        "md" if open_regular_file_at(&directory, &entry).is_some() => {
                            filename.strip_suffix(".md")
                        }
                        _ => None,
                    };
                    if let Some(name) = name.filter(|name| safe_agent_asset_name(name)) {
                        assets.insert(DeviceAgentAsset {
                            client: (*client).into(),
                            kind: (*kind).into(),
                            name: name.into(),
                            source: format!("project/{relative}"),
                        });
                        if *client == "maestro" && *kind == "plugin" {
                            for config in ["mcp.json", ".mcp.json"] {
                                if plugin_config_reads >= 32 {
                                    break;
                                }
                                plugin_config_reads += 1;
                                if let Some(body) = child_directory
                                    .as_ref()
                                    .and_then(|child| read_agent_config_at(child, config))
                                {
                                    for (server, transport) in
                                        json_mcp_entries(&body, &["mcpServers", "servers"])
                                    {
                                        if safe_agent_asset_name(&server) {
                                            servers.insert(DeviceMCPServer {
                                                client: "maestro".into(),
                                                name: server,
                                                source: format!("project/{relative}/*/{config}"),
                                                transport,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    (
        servers.into_iter().take(128).collect(),
        assets.into_iter().take(128).collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    #[test]
    fn held_directory_handles_survive_parent_and_child_symlink_swaps() {
        let base =
            std::env::temp_dir().join(format!("merlin-project-handle-swap-{}", std::process::id()));
        let original = base.join("project");
        let outside = base.join("outside");
        fs::create_dir_all(original.join(".cursor")).unwrap();
        fs::create_dir_all(outside.join(".cursor")).unwrap();
        fs::write(original.join(".cursor/mcp.json"), "inside").unwrap();
        fs::write(outside.join(".cursor/mcp.json"), "outside").unwrap();

        let parent = open_project_root(&base).unwrap();
        let held_project = open_directory_at(&parent, OsStr::new("project")).unwrap();
        fs::rename(&original, base.join("project-original")).unwrap();
        symlink(&outside, &original).unwrap();
        assert!(open_project_root(&original).is_none());
        assert_eq!(
            read_agent_config_at(&held_project, ".cursor/mcp.json").as_deref(),
            Some("inside")
        );

        let held_cursor = open_relative_directory(&held_project, ".cursor").unwrap();
        let original_cursor = base.join("project-original/.cursor");
        fs::rename(
            &original_cursor,
            base.join("project-original/cursor-original"),
        )
        .unwrap();
        symlink(outside.join(".cursor"), &original_cursor).unwrap();
        assert!(read_agent_config_at(&held_project, ".cursor/mcp.json").is_none());
        assert_eq!(
            read_agent_config_at(&held_cursor, "mcp.json").as_deref(),
            Some("inside")
        );
        fs::remove_dir_all(base).unwrap();
    }
}
