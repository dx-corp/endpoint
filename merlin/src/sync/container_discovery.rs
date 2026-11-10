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
    AGENT_SYSTEM_BINS, DeviceAgentAsset, DeviceAgentCLI, DeviceContainer, DeviceMCPServer,
    agent_homes, collect_agent_discovery_from,
};

/// Containers scanned per inventory, in collector order.
const MAX_CONTAINERS: usize = 16;
/// Wall-clock budget for one container, and for all of them.
const CHILD_TIMEOUT: Duration = Duration::from_secs(10);
const ALL_CONTAINERS_TIMEOUT: Duration = Duration::from_secs(60);
/// Largest result a child may print.
const MAX_CHILD_OUTPUT: u64 = 1 << 20;
/// MCP servers and assets kept from one root, as for the host scan.
const MAX_ROOT_FINDINGS: usize = 128;

/// What one root holds, as the child prints it.
#[derive(Serialize, Deserialize, Default, Debug)]
pub(super) struct RootScan {
    pub(super) clis: Vec<DeviceAgentCLI>,
    pub(super) mcp_servers: Vec<DeviceMCPServer>,
    pub(super) agent_assets: Vec<DeviceAgentAsset>,
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

pub(super) fn collect_container_agent_discovery(
    containers: &[DeviceContainer],
) -> (Vec<DeviceMCPServer>, Vec<DeviceAgentAsset>) {
    let deadline = Instant::now() + ALL_CONTAINERS_TIMEOUT;
    let mut servers = Vec::new();
    let mut assets = Vec::new();
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
                servers.extend(scan.mcp_servers);
                assets.extend(scan.agent_assets);
            }
            Err(error) => log::debug!("sync: container AI scan skipped: {error:#}"),
        }
    }
    (servers, assets)
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
    scan.clis.truncate(32);
    scan.mcp_servers.truncate(MAX_ROOT_FINDINGS);
    scan.agent_assets.truncate(MAX_ROOT_FINDINGS);
    for server in &mut scan.mcp_servers {
        server.location = location.to_string();
    }
    for asset in &mut scan.agent_assets {
        asset.location = location.to_string();
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
    let (clis, mcp_servers, agent_assets) =
        collect_agent_discovery_from(&agent_homes(), AGENT_SYSTEM_BINS);
    let scan = tagged(
        RootScan {
            clis,
            mcp_servers,
            agent_assets,
        },
        location,
    );
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
        use super::super::docker_running_init_pid;
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
            location: "host".into(),
            client: "claude".into(),
            name: "github".into(),
            source: ".claude.json".into(),
            transport: "stdio".into(),
        };
        let scan = tagged(
            RootScan {
                clis: Vec::new(),
                mcp_servers: vec![server; MAX_ROOT_FINDINGS + 1],
                agent_assets: Vec::new(),
            },
            "container:nginx",
        );
        assert!(scan.mcp_servers.len() <= MAX_ROOT_FINDINGS);
        assert!(
            scan.mcp_servers
                .iter()
                .all(|s| s.location == "container:nginx")
        );
    }
}
