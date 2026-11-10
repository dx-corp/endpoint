//! The Windows device check-in: the restricted per-device configuration and
//! the `inventory-only` report posted to
//! `POST <sync_url>/v1/devices/<device_id>/check-in`, in the wire format the
//! Go collector sent. The server reply sets the next check-in, bounded to one
//! minute through one hour; a failed check-in retries after a minute.

#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::posture_report::DevicePosture;
use crate::windows_discovery::{WindowsDiscovery, valid_workspace_root};
use crate::windows_wsl::DeviceAiLocationCoverage;

/// The configuration file is refused above this size.
pub(crate) const MAX_CONFIG_BYTES: u64 = 16 << 10;
/// The check-in reply is read up to this size.
const MAX_REPLY_BYTES: u64 = 64 << 10;
const MAX_WORKSPACE_ROOTS: usize = 8;
const MIN_INTERVAL: Duration = Duration::from_secs(60);
const MAX_INTERVAL: Duration = Duration::from_secs(3600);
/// Wait after a failed check-in.
const RETRY_INTERVAL: Duration = MIN_INTERVAL;
const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The per-device configuration MDM delivers. Holds the device token, so it
/// is never serialized or printed (`Debug` redacts the token).
pub(crate) struct Config {
    /// Credential-free HTTPS origin, without a trailing slash.
    pub(crate) sync_url: String,
    pub(crate) device_id: String,
    pub(crate) device_token: String,
    pub(crate) workspace_roots: Vec<PathBuf>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("sync_url", &self.sync_url)
            .field("device_id", &self.device_id)
            .field("device_token", &"<redacted>")
            .field("workspace_roots", &self.workspace_roots)
            .finish()
    }
}

#[derive(Deserialize)]
struct RawConfig {
    sync_url: String,
    device_id: String,
    device_token: String,
    #[serde(default)]
    workspace_roots: Vec<String>,
}

fn valid_device_id(value: &str) -> bool {
    value.strip_prefix("dev_").is_some_and(|hex| {
        hex.len() == 24
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn valid_device_token(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `value` as a credential-free HTTPS origin (`https://host[:port]`), or an
/// error. A path other than `/`, a query, a fragment or user info is refused.
fn https_origin(value: &str) -> Result<String> {
    let invalid = || anyhow!("sync_url must be a credential-free HTTPS origin");
    let uri: ureq::http::Uri = value.parse().map_err(|_| invalid())?;
    let authority = uri.authority().ok_or_else(invalid)?;
    let path = uri.path();
    ensure!(
        uri.scheme_str() == Some("https")
            && !uri.host().unwrap_or("").is_empty()
            && !authority.as_str().contains('@')
            && uri.query().is_none()
            && (path.is_empty() || path == "/")
            && !value.contains('#'),
        invalid()
    );
    Ok(format!("https://{authority}"))
}

/// Parse and validate configuration bytes. Error messages never include a
/// value from the file.
pub(crate) fn parse_config(body: &[u8]) -> Result<Config> {
    ensure!(
        body.len() as u64 <= MAX_CONFIG_BYTES,
        "configuration exceeds 16 KiB"
    );
    let raw: RawConfig =
        serde_json::from_slice(body).map_err(|_| anyhow!("invalid configuration JSON"))?;
    let sync_url = https_origin(&raw.sync_url)?;
    ensure!(
        valid_device_id(&raw.device_id) && valid_device_token(&raw.device_token),
        "invalid device credentials"
    );
    ensure!(
        raw.workspace_roots.len() <= MAX_WORKSPACE_ROOTS,
        "too many workspace roots"
    );
    ensure!(
        raw.workspace_roots
            .iter()
            .all(|root| valid_workspace_root(root)),
        "workspace_roots must contain bounded local absolute paths without traversal"
    );
    Ok(Config {
        sync_url,
        device_id: raw.device_id,
        device_token: raw.device_token,
        workspace_roots: raw.workspace_roots.into_iter().map(PathBuf::from).collect(),
    })
}

/// The inventory section: discovery plus when and by what it was collected.
#[derive(Serialize)]
pub(crate) struct Inventory {
    pub(crate) collected_at: String,
    #[serde(flatten)]
    pub(crate) discovery: WindowsDiscovery,
    pub(crate) collection_source: &'static str,
    /// WSL distributions and whether their AI tools were read.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) ai_location_coverage: Vec<DeviceAiLocationCoverage>,
}

impl Inventory {
    pub(crate) fn new(mut discovery: WindowsDiscovery, now: std::time::SystemTime) -> Self {
        let millis = now
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let ai_location_coverage = std::mem::take(&mut discovery.coverage);
        Self {
            collected_at: format!("{:.3}", millis as f64 / 1000.0),
            discovery,
            collection_source: "windows-agent",
            ai_location_coverage,
        }
    }
}

#[derive(Serialize)]
struct Health {
    drop_rate: f64,
}

/// The check-in body. Field names and values are the Go collector's.
#[derive(Serialize)]
pub(crate) struct CheckIn<'a> {
    host: &'a str,
    platform: &'static str,
    agent_version: &'static str,
    os_version: &'static str,
    sensor_mode: &'static str,
    status: &'static str,
    capabilities: [&'static str; 2],
    health: Health,
    inventory: Inventory,
    posture: DevicePosture,
}

impl<'a> CheckIn<'a> {
    pub(crate) fn new(host: &'a str, inventory: Inventory, posture: DevicePosture) -> Self {
        Self {
            host,
            platform: "windows",
            agent_version: AGENT_VERSION,
            os_version: "",
            sensor_mode: "inventory-only",
            status: "healthy",
            capabilities: ["system_inventory", "agent_discovery"],
            health: Health { drop_rate: 0.0 },
            inventory,
            posture,
        }
    }
}

/// A trimmed hostname of 1 to 128 bytes, or an error.
pub(crate) fn valid_host(host: &str) -> Result<&str> {
    let host = host.trim();
    if host.is_empty() || host.len() > 128 {
        bail!("invalid hostname");
    }
    Ok(host)
}

/// The HTTP exchange, separated so the request and reply handling is tested
/// without a network: (url, bearer token, JSON body) -> (status, reply body
/// read up to `limit` bytes).
pub(crate) trait Transport {
    fn post(&self, url: &str, token: &str, body: Vec<u8>, limit: u64) -> Result<(u16, Vec<u8>)>;
}

/// Post one check-in and return the server's next interval.
pub(crate) fn post_check_in(
    transport: &impl Transport,
    config: &Config,
    check_in: &CheckIn<'_>,
) -> Result<Duration> {
    let body = serde_json::to_vec(check_in)?;
    let url = format!(
        "{}/v1/devices/{}/check-in",
        config.sync_url, config.device_id
    );
    let (status, reply) = transport.post(&url, &config.device_token, body, MAX_REPLY_BYTES)?;
    ensure!(status == 200, "check-in returned HTTP {status}");
    #[derive(Deserialize)]
    struct Reply {
        #[serde(default)]
        next_check_in_seconds: i64,
    }
    let reply: Reply =
        serde_json::from_slice(&reply).map_err(|_| anyhow!("invalid check-in reply"))?;
    let seconds = reply
        .next_check_in_seconds
        .clamp(MIN_INTERVAL.as_secs() as i64, MAX_INTERVAL.as_secs() as i64);
    Ok(Duration::from_secs(seconds as u64))
}

/// How long to wait before the next check-in: the server's interval, or a
/// minute after a failure (logged without the response body).
pub(crate) fn next_wait(result: Result<Duration>) -> Duration {
    result.unwrap_or_else(|error| {
        eprintln!("endpoint inventory check-in: {error:#}");
        RETRY_INTERVAL
    })
}

/// HTTPS through Windows' own TLS (schannel via native-tls) and the Windows
/// certificate store, with a 15-second timeout.
#[cfg(windows)]
pub(crate) struct SchannelTransport(ureq::Agent);

#[cfg(windows)]
impl SchannelTransport {
    pub(crate) fn new() -> Self {
        use ureq::tls::{RootCerts, TlsConfig, TlsProvider};
        let tls = TlsConfig::builder()
            .provider(TlsProvider::NativeTls)
            .root_certs(RootCerts::PlatformVerifier)
            .build();
        let config = ureq::Agent::config_builder()
            .tls_config(tls)
            .timeout_global(Some(Duration::from_secs(15)))
            .http_status_as_error(false)
            .https_only(true)
            .build();
        Self(config.into())
    }
}

#[cfg(windows)]
impl Transport for SchannelTransport {
    fn post(&self, url: &str, token: &str, body: Vec<u8>, limit: u64) -> Result<(u16, Vec<u8>)> {
        use std::io::Read;
        let mut response = self
            .0
            .post(url)
            .header("Authorization", &format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .send(&body[..])?;
        let status = response.status().as_u16();
        let mut reply = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(limit)
            .read_to_end(&mut reply)?;
        Ok((status, reply))
    }
}
