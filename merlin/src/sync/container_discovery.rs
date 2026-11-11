//! AI tools inside running containers.
//!
//! A container's files are read by a one-shot child process,
//! `merlin scan-ai-locations --root /proc/<init pid>/root --location
//! container:<image>`. The child chroots into that root before it opens
//! anything, so an absolute symlink planted in the container resolves inside
//! the container and never on the host. It then runs the same walkers as the
//! host scan over the container's own homes and prints names and labels only.
//! The same command scans any root, such as a WSL distribution's.

use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use super::{
    AGENT_SYSTEM_BINS, DeviceAgentAsset, DeviceAgentCLI, DeviceAiLocationCoverage, DeviceContainer,
    DeviceMCPServer, agent_homes, collect_agent_discovery_from, collect_system_agent_configs,
};
use crate::ai_discovery::{MAX_COVERAGE, add_coverage};

/// Containers scanned per inventory, in collector order.
const MAX_CONTAINERS: usize = 16;
/// Wall-clock budget for one container, and for all of them.
const CHILD_TIMEOUT: Duration = Duration::from_secs(10);
const ALL_CONTAINERS_TIMEOUT: Duration = Duration::from_secs(60);
/// Largest result a child may print.
const MAX_CHILD_OUTPUT: u64 = 1 << 20;
/// MCP servers and assets kept from one root, as for the host scan.
const MAX_ROOT_FINDINGS: usize = crate::ai_discovery::MAX_AGENT_FINDINGS;

/// What one root holds, as the child prints it.
#[derive(Serialize, Deserialize, Default, Debug)]
pub(super) struct RootScan {
    pub(super) clis: Vec<DeviceAgentCLI>,
    pub(super) mcp_servers: Vec<DeviceMCPServer>,
    pub(super) agent_assets: Vec<DeviceAgentAsset>,
    /// Declared files in this root that were not read (too large).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) coverage: Vec<DeviceAiLocationCoverage>,
}

/// Containers from any runtime, found through their processes: podman
/// (rootful and rootless), containerd, CRI-O, and Docker without readable
/// metadata. Each container id in a process's cgroup is one container; its
/// init process is the lowest pid in it that has its own root. A container
/// Docker's metadata already listed gains its init pid if it had none.
pub(super) fn add_running_process_containers(containers: &mut Vec<DeviceContainer>) {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return;
    };
    let mut found: std::collections::BTreeMap<String, (u32, &'static str)> =
        std::collections::BTreeMap::new();
    for pid in entries
        .take(1 << 16)
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| *pid > 1)
    {
        let Some((id, runtime)) = crate::telemetry::proc_cgroup(pid)
            .as_deref()
            .and_then(container_from_cgroup)
        else {
            continue;
        };
        if found.get(&id).is_some_and(|(known, _)| *known < pid) || !has_own_root(pid) {
            continue;
        }
        found.insert(id, (pid, runtime));
    }
    for (id, (pid, runtime)) in found {
        if let Some(container) = containers.iter_mut().find(|container| container.id == id) {
            if container.init_pid == 0 {
                container.init_pid = pid;
            }
        } else if containers.len() < 128 {
            containers.push(DeviceContainer {
                id,
                name: String::new(),
                image: String::new(),
                state: "running".into(),
                runtime: runtime.into(),
                init_pid: pid,
            });
        }
    }
}

/// A container id and its runtime from a process's cgroup path, using the
/// telemetry collector's id rule. Podman's conmon monitor runs outside the
/// container and is not one.
pub(super) fn container_from_cgroup(cgroup: &str) -> Option<(String, &'static str)> {
    let leaf = cgroup
        .rsplit('/')
        .find(|part| !part.is_empty() && *part != "container")?;
    if leaf.starts_with("libpod-conmon-") {
        return None;
    }
    let id = crate::telemetry::container_id_from_cgroup(cgroup)?;
    let runtime = [
        ("docker", "docker"),
        ("libpod", "podman"),
        ("cri-containerd", "containerd"),
        ("crio", "cri-o"),
    ]
    .iter()
    .find(|(prefix, _)| {
        cgroup.contains(&format!("{prefix}-{id}")) || cgroup.contains(&format!("/{prefix}/{id}"))
    })
    .map_or("container", |(_, runtime)| runtime);
    Some((id, runtime))
}

fn has_own_root(pid: u32) -> bool {
    match (
        std::fs::metadata(format!("/proc/{pid}/root")),
        std::fs::metadata("/"),
    ) {
        (Ok(theirs), Ok(ours)) => theirs.dev() != ours.dev() || theirs.ino() != ours.ino(),
        _ => false,
    }
}

/// `container:<image>` with an image reference the server accepts, else
/// `container:unnamed`.
pub(super) fn container_location(image: &str) -> String {
    let valid = image.len() <= 255
        && image
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && image
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/:@+-".contains(&b));
    format!("container:{}", if valid { image } else { "unnamed" })
}

/// The location shapes the server accepts for a scanned root:
/// `container:<image>` or `wsl:<distribution>`.
fn valid_root_location(location: &str) -> bool {
    if let Some(image) = location.strip_prefix("container:") {
        return container_location(image) == location;
    }
    location.strip_prefix("wsl:").is_some_and(|distro| {
        distro.len() <= 64
            && distro
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_alphanumeric())
            && distro
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    })
}

pub(super) fn collect_container_agent_discovery(containers: &[DeviceContainer]) -> RootScan {
    let deadline = Instant::now() + ALL_CONTAINERS_TIMEOUT;
    let mut found = RootScan::default();
    for container in containers
        .iter()
        .filter(|container| container.init_pid > 1)
        .take(MAX_CONTAINERS)
    {
        if Instant::now() >= deadline {
            break;
        }
        let pid = container.init_pid;
        // A stale pid could now belong to a host process; scan only a
        // process that is still in this container and has its own root.
        if !in_container_cgroup(pid, &container.id) || shares_our_root(pid) {
            continue;
        }
        let root = format!("/proc/{pid}/root");
        match scan_root_in_child(Path::new(&root), &container_location(&container.image)) {
            Ok(scan) => {
                found.clis.extend(scan.clis);
                found.mcp_servers.extend(scan.mcp_servers);
                found.agent_assets.extend(scan.agent_assets);
                for entry in scan.coverage {
                    add_coverage(&mut found.coverage, entry);
                }
            }
            Err(error) => log::debug!("sync: container AI scan skipped: {error:#}"),
        }
    }
    found
}

fn in_container_cgroup(pid: u32, id: &str) -> bool {
    !id.is_empty()
        && super::bounded_read(&format!("/proc/{pid}/cgroup"), 64 << 10)
            .is_some_and(|body| body.windows(id.len()).any(|window| window == id.as_bytes()))
}

fn shares_our_root(pid: u32) -> bool {
    match (
        std::fs::metadata(format!("/proc/{pid}/root")),
        std::fs::metadata("/"),
    ) {
        (Ok(theirs), Ok(ours)) => theirs.dev() == ours.dev() && theirs.ino() == ours.ino(),
        _ => true,
    }
}

/// Run `merlin scan-ai-locations` on `root` and parse what it prints, within
/// the time and size budget.
fn scan_root_in_child(root: &Path, location: &str) -> Result<RootScan> {
    let mut child = Command::new("/proc/self/exe")
        .arg("scan-ai-locations")
        .arg("--root")
        .arg(root)
        .arg("--location")
        .arg(location)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("starting the AI location scan")?;
    let mut stdout = child.stdout.take().context("scan output")?;
    // Read on a thread so a stalled child cannot hold this one past the
    // timeout; the pipe closes when the child exits or is killed.
    let reader = std::thread::spawn(move || {
        let mut body = Vec::new();
        let _ = (&mut stdout)
            .take(MAX_CHILD_OUTPUT + 1)
            .read_to_end(&mut body);
        body
    });
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= CHILD_TIMEOUT {
            // The child is not yet reaped, so its pid cannot have been reused.
            let _ = child.kill();
            let _ = child.wait();
            bail!("AI location scan timed out");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let body = reader
        .join()
        .map_err(|_| anyhow!("AI location scan reader failed"))?;
    if !status.success() {
        bail!("AI location scan exited with {status}");
    }
    if body.len() as u64 > MAX_CHILD_OUTPUT {
        bail!("AI location scan printed too much");
    }
    let scan: RootScan = serde_json::from_slice(&body).context("parsing AI location scan")?;
    // Trust only what the parent asked for: every finding carries this
    // location and the usual caps.
    Ok(tagged(scan, location))
}

fn tagged(mut scan: RootScan, location: &str) -> RootScan {
    scan.clis.truncate(super::MAX_AGENT_CLIS);
    scan.mcp_servers.truncate(MAX_ROOT_FINDINGS);
    scan.agent_assets.truncate(MAX_ROOT_FINDINGS);
    scan.coverage.truncate(MAX_COVERAGE);
    for entry in &mut scan.coverage {
        entry.location = location.to_string();
    }
    for cli in &mut scan.clis {
        cli.location = location.to_string();
    }
    for server in &mut scan.mcp_servers {
        server.location = location.to_string();
        crate::ai_discovery::keep_valid_mcp_facts(server);
    }
    for asset in &mut scan.agent_assets {
        asset.location = location.to_string();
        crate::ai_discovery::keep_valid_content_facts(asset);
    }
    scan
}

/// The `merlin scan-ai-locations` command: chroot into `root`, scan its homes
/// with the host walkers, and print the findings tagged with `location` as
/// JSON. Names and labels only, as the host scan reports.
pub(crate) fn scan_ai_locations_in_root(root: &Path, location: &str) -> Result<()> {
    if !valid_root_location(location) {
        bail!("location must be container:<image> or wsl:<distribution>");
    }
    let root_c = std::ffi::CString::new(root.as_os_str().as_bytes())
        .context("root path holds a NUL byte")?;
    // SAFETY: `root_c` is a valid NUL-terminated path for the duration of the
    // call; chroot changes only this process's root directory.
    if unsafe { libc::chroot(root_c.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("chroot into the scanned root");
    }
    std::env::set_current_dir("/").context("entering the scanned root")?;
    let mut scan = collect_agent_discovery_from(&agent_homes(), AGENT_SYSTEM_BINS);
    let (system_servers, system_assets) = collect_system_agent_configs(Path::new("/"));
    scan.mcp_servers.extend(system_servers);
    scan.mcp_servers.truncate(MAX_ROOT_FINDINGS);
    scan.agent_assets.extend(system_assets);
    scan.agent_assets.truncate(MAX_ROOT_FINDINGS);
    crate::ai_discovery::add_truncation(
        &mut scan.coverage,
        scan.mcp_servers.len(),
        scan.agent_assets.len(),
    );
    let scan = tagged(scan, location);
    println!("{}", serde_json::to_string(&scan)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_locations_are_image_references_the_server_accepts() {
        assert_eq!(container_location("nginx"), "container:nginx");
        assert_eq!(
            container_location("ghcr.io/acme/dev:1.2@sha256:abc"),
            "container:ghcr.io/acme/dev:1.2@sha256:abc"
        );
        for unsafe_image in [
            "",
            "/home/alice/app",
            "app with space",
            "app\n",
            &"a".repeat(256),
        ] {
            assert_eq!(container_location(unsafe_image), "container:unnamed");
        }
        assert!(valid_root_location("container:nginx"));
        assert!(valid_root_location("wsl:Ubuntu-24.04"));
        for location in [
            "host",
            "container:",
            "container:/etc",
            "wsl:",
            "wsl:/mnt/c",
            "wsl:a b",
        ] {
            assert!(!valid_root_location(location), "{location}");
        }
    }

    #[test]
    fn only_a_running_docker_container_yields_an_init_pid() {
        use super::super::containers::docker_running_init_pid;
        let config = |running: bool, pid: u64| serde_json::json!({"State": {"Running": running, "Pid": pid, "Status": "running"}});
        assert_eq!(docker_running_init_pid(&config(true, 4242)), 4242);
        assert_eq!(docker_running_init_pid(&config(false, 4242)), 0);
        // Pid 0 (stopped) and 1 (this host's init) are never scanned.
        assert_eq!(docker_running_init_pid(&config(true, 0)), 0);
        assert_eq!(docker_running_init_pid(&config(true, 1)), 0);
        assert_eq!(docker_running_init_pid(&serde_json::json!({})), 0);
    }

    #[test]
    fn a_child_result_is_capped_and_carries_only_the_requested_location() {
        let server = DeviceMCPServer {
            package: String::new(),
            host: String::new(),
            matched_rules: Vec::new(),
            location: "host".into(),
            client: "claude".into(),
            name: "github".into(),
            source: ".claude.json".into(),
            transport: "stdio".into(),
        };
        let cli = DeviceAgentCLI {
            name: "claude".into(),
            location: "host".into(),
        };
        let scan = tagged(
            RootScan {
                clis: vec![cli],
                mcp_servers: vec![server; MAX_ROOT_FINDINGS + 1],
                agent_assets: Vec::new(),
                coverage: vec![DeviceAiLocationCoverage {
                    location: String::new(),
                    source: ".claude.json".into(),
                    state: "not_scanned".into(),
                    reason: "too_large".into(),
                    observed_at: 0,
                }],
            },
            "container:nginx",
        );
        assert!(scan.mcp_servers.len() <= MAX_ROOT_FINDINGS);
        assert!(
            scan.mcp_servers
                .iter()
                .all(|s| s.location == "container:nginx")
        );
        assert!(scan.clis.iter().all(|c| c.location == "container:nginx"));
        assert!(
            scan.coverage
                .iter()
                .all(|c| c.location == "container:nginx")
        );
    }

    #[test]
    fn containers_of_every_runtime_are_named_from_their_cgroup() {
        let id = "a".repeat(64);
        for (cgroup, runtime) in [
            (format!("/system.slice/docker-{id}.scope"), "docker"),
            (format!("/docker/{id}"), "docker"),
            (
                format!("/machine.slice/libpod-{id}.scope/container"),
                "podman",
            ),
            (
                format!(
                    "/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-{id}.scope/container"
                ),
                "podman",
            ),
            (
                format!(
                    "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1b2c3d4e_5f60_7182_93a4_b5c6d7e8f901.slice/cri-containerd-{id}.scope"
                ),
                "containerd",
            ),
            (
                format!("/kubepods.slice/kubepods-pod1.slice/crio-{id}.scope"),
                "cri-o",
            ),
            (
                format!("/kubepods/burstable/pod1b2c3d4e-5f60-7182-93a4-b5c6d7e8f901/{id}"),
                "container",
            ),
        ] {
            assert_eq!(
                container_from_cgroup(&cgroup),
                Some((id.clone(), runtime)),
                "{cgroup}"
            );
        }
        // Podman's monitor runs on the host, and host services are no container.
        for cgroup in [
            format!("/machine.slice/libpod-conmon-{id}.scope"),
            "/system.slice/sshd.service".to_string(),
            "/user.slice/user-1000.slice/session-3.scope".to_string(),
            "/".to_string(),
        ] {
            assert_eq!(container_from_cgroup(&cgroup), None, "{cgroup}");
        }
    }
}
