//! Observed reach: the hosts each AI agent, and each MCP server it runs,
//! actually contacted on this computer.
//!
//! The DNS monitor and the connect stream note a host when the event is
//! attributed to an agent (agent_session.rs). A process is an MCP server when
//! it runs under an agent and its command line resolves, the way discovery
//! resolves a configured server (mcp_identity::stdio_package), to the package
//! of a server configured on this computer; its descendants count as that
//! server. The check-in sends the set as `contacted_hosts`: client, MCP
//! package (when the host was contacted by an MCP server), host, and the
//! first and last time it was seen. A host is a looked-up DNS name or a
//! connected IP address, never a URL, path, port or anything sent.
//!
//! Bounded: at most MAX_HOSTS entries; a host not seen for RETENTION is
//! dropped; a new host past the bound is not kept and the check-in says the
//! set is truncated. `last_seen` moves in whole hours, so a quiet hour
//! changes nothing. The set is kept in `<spool dir>/.merlin-contacted-hosts`
//! (0600, never through a symlink), written only when it changed, so first
//! sightings survive a restart.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

use serde::{Deserialize, Serialize};

use crate::ai_discovery::stdio_package;
use crate::proctree::{AgentProcess, ProcTable};

/// Entries kept per device.
pub(crate) const MAX_HOSTS: usize = 1024;
/// A host unseen this long is dropped (seconds).
const RETENTION: u64 = 30 * 24 * 3600;
/// `last_seen` resolution (seconds).
const LAST_SEEN_STEP: u64 = 3600;
/// Configured MCP server packages remembered for matching.
const MAX_PACKAGES: usize = 512;
/// The state file's size limit.
const MAX_FILE_BYTES: u64 = 512 << 10;
const FILE_NAME: &str = ".merlin-contacted-hosts";

/// One host an agent or MCP server contacted, as the check-in sends it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DeviceContactedHost {
    /// The AI agent's client, as ai_locations names it.
    pub(crate) client: String,
    /// The MCP server's package (as mcp_servers reports it) when one of the
    /// agent's MCP servers made the contact; empty for the agent itself.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) mcp_package: String,
    /// A DNS name looked up, or an IP address connected to.
    pub(crate) host: String,
    pub(crate) first_seen_unix: u64,
    pub(crate) last_seen_unix: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct Saved {
    hosts: Vec<DeviceContactedHost>,
    truncated: bool,
}

#[derive(Default)]
struct State {
    /// (client, mcp package, host) -> (first seen, last seen).
    hosts: BTreeMap<(String, String, String), (u64, u64)>,
    truncated: bool,
    packages: BTreeSet<String>,
    dirty: bool,
    path: Option<PathBuf>,
}

static STATE: LazyLock<Mutex<State>> = LazyLock::new(Mutex::default);

fn state() -> std::sync::MutexGuard<'static, State> {
    STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl State {
    fn note(&mut self, client: &str, mcp_package: &str, host: String, now: u64) {
        let key = (client.to_owned(), mcp_package.to_owned(), host);
        if let Some((_, last)) = self.hosts.get_mut(&key) {
            if now >= *last + LAST_SEEN_STEP {
                *last = now - now % LAST_SEEN_STEP;
                self.dirty = true;
            }
            return;
        }
        if self.hosts.len() >= MAX_HOSTS {
            if !self.truncated {
                self.truncated = true;
                self.dirty = true;
            }
            return;
        }
        self.hosts.insert(key, (now, now - now % LAST_SEEN_STEP));
        self.dirty = true;
    }

    /// Drop hosts unseen for RETENTION; a set back under the bound is no
    /// longer truncated.
    fn prune(&mut self, now: u64) {
        let before = self.hosts.len();
        self.hosts
            .retain(|_, (_, last)| now.saturating_sub(*last) < RETENTION);
        if self.hosts.len() != before {
            self.dirty = true;
            if self.truncated && self.hosts.len() < MAX_HOSTS {
                self.truncated = false;
            }
        }
    }

    fn list(&self) -> Vec<DeviceContactedHost> {
        self.hosts
            .iter()
            .map(
                |((client, mcp_package, host), (first, last))| DeviceContactedHost {
                    client: client.clone(),
                    mcp_package: mcp_package.clone(),
                    host: host.clone(),
                    first_seen_unix: *first,
                    last_seen_unix: *last,
                },
            )
            .collect()
    }

    fn restore(&mut self, saved: Saved) {
        for h in saved.hosts.into_iter().take(MAX_HOSTS) {
            let valid = dns_host(&h.host).or_else(|| address_host(&h.host)).as_ref()
                == Some(&h.host)
                && !h.client.is_empty()
                && h.client.len() <= 64
                && h.first_seen_unix <= h.last_seen_unix;
            if valid {
                self.hosts.insert(
                    (h.client, h.mcp_package, h.host),
                    (h.first_seen_unix, h.last_seen_unix),
                );
            }
        }
        self.truncated = saved.truncated;
    }
}

/// Load the kept set from `spool_dir` and remember where to keep it. Call
/// once at start, before any producer runs. A missing or unreadable file is
/// an empty set.
pub fn resume(spool_dir: &Path) {
    let path = spool_dir.join(FILE_NAME);
    let saved = read_file(&path).and_then(|bytes| serde_json::from_slice::<Saved>(&bytes).ok());
    let mut s = state();
    if let Some(saved) = saved {
        s.restore(saved);
    }
    s.path = Some(path);
}

fn read_file(path: &Path) -> Option<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() as u64 <= MAX_FILE_BYTES).then_some(bytes)
}

fn write_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// Note that `client` (or its MCP server `mcp_package`) contacted `host`.
fn note(client: &str, mcp_package: Option<&str>, host: String, now: u64) {
    state().note(client, mcp_package.unwrap_or(""), host, now);
}

/// Note `host` for an event attributed to `agent`, under the MCP server the
/// event's process belongs to, if any. Nothing without an agent or a host.
pub fn note_attributed(
    table: &Mutex<ProcTable>,
    agent: Option<AgentProcess>,
    pid: Option<u32>,
    host: Option<String>,
) {
    let (Some(agent), Some(host)) = (agent, host) else {
        return;
    };
    let package = pid.and_then(|p| {
        table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .mcp_package_of(p)
    });
    note(
        agent.client,
        package.as_deref(),
        host,
        crate::spool::now_ts() as u64,
    );
}

/// The set for the check-in, and whether it is truncated. Writes the kept
/// file first when the set changed since the last call.
pub(crate) fn snapshot(now: u64) -> (Vec<DeviceContactedHost>, bool) {
    let mut s = state();
    s.prune(now);
    let list = s.list();
    if s.dirty {
        if let Some(path) = s.path.clone() {
            let saved = Saved {
                hosts: list.clone(),
                truncated: s.truncated,
            };
            match serde_json::to_vec(&saved).map_err(std::io::Error::other) {
                Ok(bytes) => match write_file(&path, &bytes) {
                    Ok(()) => s.dirty = false,
                    Err(e) => log::warn!("contacted hosts: could not keep {}: {e}", path.display()),
                },
                Err(e) => log::warn!("contacted hosts: {e}"),
            }
        } else {
            s.dirty = false;
        }
    }
    (list, s.truncated)
}

/// The packages of the stdio MCP servers configured on this computer, from
/// the latest discovery. Replaces the previous set.
pub(crate) fn set_mcp_packages<'a>(packages: impl IntoIterator<Item = &'a str>) {
    let set: BTreeSet<String> = packages
        .into_iter()
        .filter(|p| !p.is_empty())
        .take(MAX_PACKAGES)
        .map(str::to_owned)
        .collect();
    state().packages = set;
}

/// The configured MCP server a command line runs, if any: the command line
/// read the way discovery reads a configured server, also past up to two
/// leading interpreter words (`env node /usr/bin/npx ...`, as a script
/// re-executes through its interpreter).
pub fn mcp_package(argv: &[String]) -> Option<Arc<str>> {
    let s = state();
    if s.packages.is_empty() {
        return None;
    }
    (0..argv.len().min(3)).find_map(|start| {
        let args: Vec<&str> = argv[start + 1..].iter().map(String::as_str).collect();
        let package = stdio_package(&argv[start], &args);
        s.packages.contains(&package).then(|| Arc::from(package))
    })
}

/// A looked-up name as a host: lowercase, without the root dot, a plain DNS
/// name of at least two labels.
pub fn dns_host(name: &str) -> Option<String> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let ok = name.len() <= 253
        && name.contains('.')
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        && name.parse::<IpAddr>().is_err();
    ok.then_some(name)
}

/// A connected address as a host: an IP address other than loopback,
/// unspecified or multicast, in its canonical text.
pub fn address_host(addr: &str) -> Option<String> {
    let ip: IpAddr = addr.parse().ok()?;
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    };
    (!ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast()).then(|| ip.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_is_kept_once_with_first_and_hourly_last_sightings() {
        let mut s = State::default();
        let t0 = 1_800_000_123;
        s.note("claude", "", "api.anthropic.com".into(), t0);
        s.dirty = false;
        // Within the hour: nothing changes.
        s.note("claude", "", "api.anthropic.com".into(), t0 + 600);
        assert!(!s.dirty);
        s.note("claude", "", "api.anthropic.com".into(), t0 + 7200);
        assert!(s.dirty);
        let list = s.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].first_seen_unix, t0);
        assert_eq!(list[0].last_seen_unix, (t0 + 7200) / 3600 * 3600);
        // The same host from an MCP server is its own entry.
        s.note(
            "claude",
            "@modelcontextprotocol/server-github",
            "api.github.com".into(),
            t0,
        );
        assert_eq!(s.list().len(), 2);
    }

    #[test]
    fn the_set_is_bounded_says_so_and_forgets_old_hosts() {
        let mut s = State::default();
        let t0 = 1_800_000_000;
        for i in 0..MAX_HOSTS + 5 {
            s.note("codex", "", format!("h{i}.example.com"), t0);
        }
        assert_eq!(s.hosts.len(), MAX_HOSTS);
        assert!(s.truncated);
        s.note("codex", "", "h0.example.com".into(), t0 + RETENTION);
        s.prune(t0 + RETENTION + 1);
        assert_eq!(s.hosts.len(), 1);
        assert!(!s.truncated);
    }

    #[test]
    fn hosts_are_names_or_addresses_never_urls_or_local_addresses() {
        assert_eq!(dns_host("API.OpenAI.com."), Some("api.openai.com".into()));
        for bad in [
            "localhost",
            "https://x.example.com/p",
            "a b.com",
            "-x.com",
            "10.0.0.1",
            "",
        ] {
            assert_eq!(dns_host(bad), None, "{bad}");
        }
        assert_eq!(address_host("140.82.112.3"), Some("140.82.112.3".into()));
        assert_eq!(
            address_host("::ffff:140.82.112.3"),
            Some("140.82.112.3".into())
        );
        assert_eq!(address_host("192.168.1.20"), Some("192.168.1.20".into()));
        for bad in [
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "224.0.0.251",
            "api.example.com",
        ] {
            assert_eq!(address_host(bad), None, "{bad}");
        }
    }

    #[test]
    fn an_mcp_server_is_recognized_by_its_configured_package_through_its_interpreter() {
        // Serialized with the other tests that touch the shared state.
        let _guard = SHARED.lock().unwrap_or_else(|p| p.into_inner());
        set_mcp_packages(["@modelcontextprotocol/server-github", "mcp-server-fetch"]);
        let argv = |words: &[&str]| words.iter().map(|w| w.to_string()).collect::<Vec<_>>();
        let github = Some(Arc::from("@modelcontextprotocol/server-github"));
        assert_eq!(
            mcp_package(&argv(&["npx", "-y", "@modelcontextprotocol/server-github"])),
            github
        );
        // The same process after the script re-executed through node.
        assert_eq!(
            mcp_package(&argv(&[
                "node",
                "/usr/lib/node_modules/npm/bin/npx-cli.js",
                "-y",
                "@modelcontextprotocol/server-github"
            ])),
            None,
            "npx-cli.js is not a runner name"
        );
        assert_eq!(
            mcp_package(&argv(&[
                "/usr/bin/env",
                "node",
                "/usr/bin/npx",
                "-y",
                "@modelcontextprotocol/server-github"
            ])),
            github
        );
        assert_eq!(
            mcp_package(&argv(&["uvx", "mcp-server-fetch"])),
            Some(Arc::from("mcp-server-fetch"))
        );
        // A server not configured here, or a plain tool, is not an MCP server.
        assert_eq!(mcp_package(&argv(&["npx", "-y", "left-pad"])), None);
        assert_eq!(mcp_package(&argv(&["git", "status"])), None);
        set_mcp_packages([]);
    }

    #[test]
    fn the_kept_file_restores_first_sightings_and_drops_forged_rows() {
        let _guard = SHARED.lock().unwrap_or_else(|p| p.into_inner());
        let dir = std::env::temp_dir().join(format!("merlin-reach-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(FILE_NAME);
        let saved = Saved {
            hosts: vec![
                DeviceContactedHost {
                    client: "claude".into(),
                    mcp_package: String::new(),
                    host: "api.anthropic.com".into(),
                    first_seen_unix: 100,
                    last_seen_unix: 3600,
                },
                DeviceContactedHost {
                    client: "claude".into(),
                    mcp_package: String::new(),
                    host: "https://evil.example.com/x".into(),
                    first_seen_unix: 100,
                    last_seen_unix: 3600,
                },
            ],
            truncated: false,
        };
        write_file(&path, &serde_json::to_vec(&saved).unwrap()).unwrap();
        let mut s = State::default();
        s.restore(serde_json::from_slice(&read_file(&path).unwrap()).unwrap());
        let list = s.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].host, "api.anthropic.com");
        assert_eq!(list[0].first_seen_unix, 100);
        // The file is the daemon's alone, and a linked file is never read.
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let link = dir.join("linked");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_file(&link).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    static SHARED: Mutex<()> = Mutex::new(());
}
