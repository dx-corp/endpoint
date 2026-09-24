//! Managed-mode sync client (Moroz-style): upload finished spool segments
//! to the sync server, and hot-reload the centrally-managed ruleset.
//!
//! Two loops on one thread, both fail-open — sync problems must never
//! affect collection or enforcement:
//! - Upload: scan the spool directory for finished `.jsonl.gz` segments
//!   and POST them, one at a time. Delete-after-ack: the segment on disk
//!   IS the buffer (Falcon MessageStore pattern), the server's 2xx is the
//!   release. Failures back off exponentially (capped) and keep segments.
//! - Rules: a managed check-in may assign one immutable policy version.
//!   The agent fetches only that SHA with its device credential and applies
//!   it only after Ed25519 verification and parsing. Failures preserve the
//!   last-known-good rules.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::desired_state::{self, AssertionReceipt};
use crate::linux_posture;
use crate::rules::{Rules, RulesHandle};
use crate::spool;

const UPLOAD_SCAN_INTERVAL: Duration = Duration::from_secs(2);
const CHECK_IN_INTERVAL: Duration = Duration::from_secs(60);
const BACKOFF_BASE_SECS: u64 = 2;
const BACKOFF_MAX_SECS: u64 = 60;
const MAX_SEGMENT_BYTES: usize = 64 << 20;
const MAX_RULES_BYTES: u64 = 1 << 20;
const MAX_POLICY_ENVELOPE_BYTES: u64 = 2 << 20;
const MAX_DEVICE_RESPONSE_BYTES: u64 = 64 << 10;
const POLICY_ENVELOPE_DOMAIN: &[u8] = b"merlin-policy-envelope-v1\0";
/// Segments younger than this may still be mid-compression; skip a cycle.
const MIN_SEGMENT_AGE: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub struct SyncConfig {
    pub base_url: String,
    pub key: Vec<u8>,
    pub device_id: Option<String>,
    pub device_token: Option<String>,
    pub policy_public_key: Vec<u8>,
    pub policy_public_keys: Vec<Vec<u8>>,
    pub sensor_mode: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedPolicyEnvelope {
    schema_version: u32,
    signed_payload: String,
    signatures: Vec<PolicyEnvelopeSignature>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyEnvelopeSignature {
    key_id: String,
    algorithm: String,
    value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyEnvelopePayload {
    schema_version: u32,
    artifact_sha256: String,
    source_policy_sha256: String,
    target_platform: String,
    #[serde(default)]
    target_agent_version: String,
    #[serde(default)]
    required_capabilities: Vec<String>,
    format: String,
    artifact: String,
}

struct VerifiedPolicy {
    artifact: Vec<u8>,
    artifact_sha256: String,
    format: String,
}

fn policy_public_key_id(key: &[u8]) -> String {
    let digest = Sha256::digest(key);
    hex_encode(&digest)
}

fn decode_policy_envelope(
    body: &[u8],
    target_sha: Option<&str>,
    configured_keys: impl Iterator<Item = Vec<u8>>,
) -> Result<VerifiedPolicy> {
    let envelope: SignedPolicyEnvelope =
        serde_json::from_slice(body).context("sync: invalid policy envelope")?;
    anyhow::ensure!(
        envelope.schema_version == 1,
        "sync: unsupported policy envelope schema {}",
        envelope.schema_version
    );
    anyhow::ensure!(
        !envelope.signatures.is_empty() && envelope.signatures.len() <= 8,
        "sync: policy envelope must contain 1-8 signatures"
    );
    let payload_bytes = base64::engine::general_purpose::STANDARD
        .decode(&envelope.signed_payload)
        .context("sync: invalid signed policy payload encoding")?;
    anyhow::ensure!(
        payload_bytes.len() <= MAX_POLICY_ENVELOPE_BYTES as usize,
        "sync: signed policy payload is too large"
    );

    let mut trusted = BTreeMap::new();
    for key in configured_keys {
        let bytes: [u8; 32] = key
            .as_slice()
            .try_into()
            .context("sync: policy public key must be 32 bytes")?;
        let verifying_key =
            VerifyingKey::from_bytes(&bytes).context("sync: invalid policy public key")?;
        trusted.insert(policy_public_key_id(&key), verifying_key);
    }
    anyhow::ensure!(
        !trusted.is_empty(),
        "sync: no trusted policy public keys configured"
    );
    let mut signed = Vec::with_capacity(POLICY_ENVELOPE_DOMAIN.len() + payload_bytes.len());
    signed.extend_from_slice(POLICY_ENVELOPE_DOMAIN);
    signed.extend_from_slice(&payload_bytes);
    let mut verified = false;
    for candidate in &envelope.signatures {
        if candidate.algorithm != "Ed25519" {
            continue;
        }
        let Some(key) = trusted.get(&candidate.key_id) else {
            continue;
        };
        let signature_bytes =
            match base64::engine::general_purpose::STANDARD.decode(&candidate.value) {
                Ok(value) => value,
                Err(_) => continue,
            };
        let Ok(signature) = Signature::from_slice(&signature_bytes) else {
            continue;
        };
        if key.verify(&signed, &signature).is_ok() {
            verified = true;
            break;
        }
    }
    anyhow::ensure!(
        verified,
        "sync: no policy envelope signature matched a trusted key"
    );

    // Only authenticated bytes cross into the policy parser.
    let payload: PolicyEnvelopePayload =
        serde_json::from_slice(&payload_bytes).context("sync: invalid signed policy payload")?;
    anyhow::ensure!(
        payload.schema_version == 1,
        "sync: unsupported signed policy payload schema"
    );
    anyhow::ensure!(
        payload.format == "application/yaml" || payload.format == desired_state::ARTIFACT_FORMAT,
        "sync: unsupported policy artifact format"
    );
    anyhow::ensure!(
        (payload.format == desired_state::ARTIFACT_FORMAT)
            == payload
                .required_capabilities
                .iter()
                .any(|capability| capability == "desired_state.v1"),
        "sync: desired-state format and capability do not agree"
    );
    anyhow::ensure!(
        payload.target_platform == "linux",
        "sync: policy artifact targets another platform"
    );
    anyhow::ensure!(
        payload.target_agent_version.is_empty()
            || payload.target_agent_version == env!("CARGO_PKG_VERSION"),
        "sync: policy artifact targets another agent version"
    );
    anyhow::ensure!(
        payload.required_capabilities.len() <= 64,
        "sync: policy artifact has too many capability requirements"
    );
    const SUPPORTED_CAPABILITIES: &[&str] = &[
        "segment_upload",
        "rules_sync",
        "system_inventory",
        "file_integrity",
        "security_configuration_assessment",
        "rootcheck",
        "container_inventory",
        "cloud_inventory",
        "desired_state.v1",
        "executor.apt",
        "executor.systemd",
        "executor.sysctl",
    ];
    anyhow::ensure!(
        payload
            .required_capabilities
            .iter()
            .all(
                |capability| SUPPORTED_CAPABILITIES.contains(&capability.as_str())
                    || desired_state::CAPABILITIES.contains(&capability.as_str())
            ),
        "sync: policy artifact requires an unsupported capability"
    );
    anyhow::ensure!(
        payload.source_policy_sha256.len() == 64
            && payload
                .source_policy_sha256
                .bytes()
                .all(|value| value.is_ascii_hexdigit()),
        "sync: signed source policy sha256 is invalid"
    );
    if let Some(target_sha) = target_sha {
        anyhow::ensure!(
            payload.artifact_sha256 == target_sha,
            "sync: server returned an unassigned policy version"
        );
    }
    let artifact = base64::engine::general_purpose::STANDARD
        .decode(&payload.artifact)
        .context("sync: invalid policy artifact encoding")?;
    anyhow::ensure!(
        artifact.len() <= MAX_RULES_BYTES as usize,
        "sync: policy artifact is too large"
    );
    anyhow::ensure!(
        sha256_hex(&artifact) == payload.artifact_sha256,
        "sync: signed policy artifact sha256 does not match its bytes"
    );
    Ok(VerifiedPolicy {
        artifact,
        artifact_sha256: payload.artifact_sha256,
        format: payload.format,
    })
}

fn configured_policy_keys(cfg: &SyncConfig) -> impl Iterator<Item = Vec<u8>> {
    std::iter::once(cfg.policy_public_key.clone())
        .filter(|key| !key.is_empty())
        .chain(cfg.policy_public_keys.clone())
}

fn read_cached_policy(path: &Path) -> Result<Vec<u8>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("opening cached managed policy {}", path.display()))?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file(),
        "cached managed policy is not a regular file"
    );
    anyhow::ensure!(
        metadata.uid() == unsafe { libc::geteuid() },
        "cached managed policy has the wrong owner"
    );
    anyhow::ensure!(
        metadata.mode() & 0o077 == 0,
        "cached managed policy is not private"
    );
    anyhow::ensure!(
        metadata.len() <= MAX_POLICY_ENVELOPE_BYTES,
        "cached managed policy is too large"
    );
    let mut body = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_POLICY_ENVELOPE_BYTES + 1)
        .read_to_end(&mut body)?;
    anyhow::ensure!(
        body.len() as u64 <= MAX_POLICY_ENVELOPE_BYTES,
        "cached managed policy is too large"
    );
    Ok(body)
}

pub fn load_cached_policy(cfg: &SyncConfig, rules_path: &Path) -> Result<Option<(Rules, String)>> {
    let path = PathBuf::from(format!("{}.synced", rules_path.display()));
    let body = match read_cached_policy(&path) {
        Ok(body) => body,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let verified = decode_policy_envelope(&body, None, configured_policy_keys(cfg))?;
    let text = String::from_utf8(verified.artifact).context("sync: cached rules are not UTF-8")?;
    let rules = if verified.format == desired_state::ARTIFACT_FORMAT {
        desired_state::parse_artifact(&text)
            .map(|(rules, _)| rules)
            .context("sync: cached desired-state artifact failed to parse")?
    } else {
        Rules::parse(&text).context("sync: cached rules failed to parse")?
    };
    Ok(Some((rules, verified.artifact_sha256)))
}

/// Bounded, read-only host inventory sent with managed device heartbeats.
/// Keep this machine posture data separate from event telemetry: no users,
/// paths, addresses, or process payloads are included here.
#[derive(Serialize, Debug, PartialEq)]
struct DeviceNetworkInterface {
    name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mtu: Option<u32>,
}

#[derive(Serialize, Debug, PartialEq)]
struct DeviceOSInfo {
    os_name: String,
    os_version: String,
    os_pretty_name: String,
    os_id: String,
    os_codename: String,
    os_build: String,
    kernel: String,
    kernel_build: String,
    architecture: String,
    cpu_model: String,
    uptime_seconds: u64,
    cpu_count: u32,
    load_average: [f64; 3],
    memory_total_bytes: u64,
    memory_available_bytes: u64,
    swap_total_bytes: u64,
    swap_free_bytes: u64,
    disk_total_bytes: u64,
    disk_free_bytes: u64,
    root_filesystem: String,
    virtualization: String,
    containerized: bool,
    network_interfaces: Vec<String>,
    network_interface_details: Vec<DeviceNetworkInterface>,
}

#[derive(Serialize, Debug, Default, PartialEq)]
struct DeviceInventory {
    collected_at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    package_manager: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    cloud_provider: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    cloud_instance_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    cloud_region: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    packages: Vec<DevicePackage>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    services: Vec<DeviceService>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    users: Vec<DeviceUser>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    groups: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    listening_ports: Vec<DeviceListeningPort>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    containers: Vec<DeviceContainer>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    processes: Vec<DeviceProcess>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fim: Vec<DeviceFIMEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sca: Vec<DeviceSCAResult>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    vulnerabilities: Vec<DeviceVulnerability>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    agent_clis: Vec<DeviceAgentCLI>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    mcp_servers: Vec<DeviceMCPServer>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    agent_assets: Vec<DeviceAgentAsset>,
    #[serde(skip_serializing_if = "String::is_empty")]
    collection_source: String,
}

#[derive(Serialize, Debug, PartialEq, Ord, PartialOrd, Eq, Clone)]
struct DeviceAgentCLI {
    name: String,
}

#[derive(Serialize, Debug, PartialEq, Ord, PartialOrd, Eq, Clone)]
struct DeviceMCPServer {
    client: String,
    name: String,
    source: String,
    transport: String,
}

#[derive(Serialize, Debug, PartialEq, Ord, PartialOrd, Eq, Clone)]
struct DeviceAgentAsset {
    client: String,
    kind: String,
    name: String,
    source: String,
}

#[derive(Serialize, Debug, PartialEq)]
struct DevicePackage {
    name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    version: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    architecture: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    manager: String,
}

#[derive(Serialize, Debug, PartialEq)]
struct DeviceService {
    name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    source: String,
}

#[derive(Serialize, Debug, PartialEq)]
struct DeviceUser {
    name: String,
    #[serde(skip_serializing_if = "is_zero")]
    uid: u64,
    #[serde(skip_serializing_if = "is_false")]
    admin: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    shell: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    source: String,
}

#[derive(Serialize, Debug, PartialEq)]
struct DeviceListeningPort {
    protocol: String,
    port: u16,
    #[serde(skip_serializing_if = "String::is_empty")]
    state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    source: String,
}

#[derive(Serialize, Debug, PartialEq)]
struct DeviceContainer {
    #[serde(skip_serializing_if = "String::is_empty")]
    id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    image: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    runtime: String,
}

#[derive(Serialize, Debug, PartialEq)]
struct DeviceProcess {
    pid: u32,
    name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    executable: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    user: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    state: String,
}

#[derive(Serialize, Debug, PartialEq)]
struct DeviceFIMEntry {
    path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    sha256: String,
    #[serde(skip_serializing_if = "is_zero")]
    size_bytes: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    mode: String,
    #[serde(skip_serializing_if = "is_zero_i64")]
    modified_unix: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    status: String,
}

#[derive(Serialize, Debug, PartialEq)]
struct DeviceSCAResult {
    id: String,
    title: String,
    status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    severity: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    detail: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    frameworks: Vec<String>,
}

#[derive(Serialize, Debug, PartialEq)]
struct DeviceVulnerability {
    id: String,
    package: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    installed: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    severity: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    fixed_version: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    summary: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    source: String,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Legacy key from --sync-key or MERLIN_LEGACY_SYNC_KEY: 64+ hex chars → hex, otherwise
/// try base64, otherwise use the raw string bytes (same rule as the server).
pub fn parse_key(s: &str) -> Vec<u8> {
    let s = s.trim();
    if s.len() >= 32 && s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        if let Ok(bytes) = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
        {
            return bytes;
        }
    }
    use base64::Engine;
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(s) {
        if !bytes.is_empty() {
            return bytes;
        }
    }
    s.as_bytes().to_vec()
}

pub fn sha256_hex(body: &[u8]) -> String {
    hex_encode(&Sha256::digest(body))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sync_auth_header(key: &[u8]) -> String {
    format!("Bearer {}", hex_encode(key))
}

/// Exponential backoff for sync failures, capped (seconds): 2,4,8,16,32,60.
pub fn backoff_secs(consecutive_failures: u32) -> u64 {
    BACKOFF_BASE_SECS
        .saturating_mul(1u64 << consecutive_failures.min(5))
        .min(BACKOFF_MAX_SECS)
}

pub struct SyncClient {
    cfg: SyncConfig,
    host: String,
    spool_path: PathBuf,
    synced_marker: PathBuf,
    handle: RulesHandle,
    current_sha: String,
    failures: u32,
    next_attempt: Instant,
    agent: ureq::Agent,
    pending_receipts: Vec<AssertionReceipt>,
}

#[derive(Serialize)]
struct DeviceCheckInRequest<'a> {
    host: &'a str,
    platform: &'static str,
    agent_version: &'static str,
    os_version: &'a str,
    kernel_version: &'a str,
    sensor_mode: &'a str,
    current_rules_sha256: &'a str,
    status: &'static str,
    capabilities: Vec<&'static str>,
    health: DeviceHealth,
    posture: linux_posture::DevicePosture,
    os_info: DeviceOSInfo,
    inventory: DeviceInventory,
}

#[derive(Serialize)]
struct DeviceHealth {
    drop_rate: f64,
    events_attempted: u64,
    events_accepted: u64,
    events_dropped: u64,
    events_written: u64,
    queue_dropped: u64,
    kernel_events_dropped: u64,
    write_failures: u64,
}

#[derive(Deserialize)]
struct DeviceCheckInResponse {
    pending_update: Option<PendingDeviceUpdate>,
}

#[derive(Deserialize)]
struct PendingDeviceUpdate {
    update_id: String,
    kind: String,
    target_rules_sha256: String,
}

#[derive(Serialize)]
struct DeviceUpdateAck<'a> {
    status: &'a str,
    rules_sha256: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
    #[serde(skip_serializing_if = "assertion_receipts_empty")]
    receipts: &'a [AssertionReceipt],
}

fn assertion_receipts_empty(receipts: &&[AssertionReceipt]) -> bool {
    receipts.is_empty()
}

impl SyncClient {
    pub fn new(
        cfg: SyncConfig,
        spool_path: PathBuf,
        rules_path: &Path,
        handle: RulesHandle,
        current_sha: String,
    ) -> Self {
        let host = hostname();
        let synced_marker = PathBuf::from(format!("{}.synced", rules_path.display()));
        SyncClient {
            cfg,
            host,
            spool_path,
            synced_marker,
            handle,
            current_sha,
            failures: 0,
            next_attempt: Instant::now(),
            agent: ureq::Agent::new_with_defaults(),
            pending_receipts: Vec::new(),
        }
    }

    /// Is `name` a finished, compressed segment of the live spool?
    fn is_uploadable_segment(name: &str, live_name: &str) -> bool {
        name.strip_suffix(".gz")
            .is_some_and(|bare| spool::is_segment_name(bare, live_name))
    }

    /// One upload pass: POST each finished segment, delete on 2xx.
    /// Fail-open: individual failures surface as Err for the backoff loop.
    pub fn upload_pending(&self) -> Result<()> {
        let dir = self.spool_path.parent().unwrap_or(Path::new("."));
        let live_name = self
            .spool_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut segments: Vec<(String, PathBuf)> = Vec::new();
        for entry in fs::read_dir(dir).with_context(|| format!("scanning {}", dir.display()))? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if Self::is_uploadable_segment(&name, &live_name) {
                segments.push((name, entry.path()));
            }
        }
        segments.sort();

        for (name, path) in segments {
            let segment = match spool::read_segment_no_follow(&path, MAX_SEGMENT_BYTES as u64) {
                Ok(segment) => segment,
                Err(error) => {
                    log::warn!("sync: refusing segment {name}: {error:#}");
                    continue;
                }
            };
            // Skip segments that may still be mid-compression.
            if segment
                .modified
                .elapsed()
                .ok()
                .is_some_and(|age| age < MIN_SEGMENT_AGE)
            {
                continue;
            }
            let body = segment.body;
            let (url, authorization) = match (
                self.cfg.device_id.as_deref(),
                self.cfg.device_token.as_deref(),
            ) {
                (Some(device_id), Some(device_token)) => (
                    format!("{}/v1/devices/{device_id}/events", self.cfg.base_url),
                    format!("Bearer {device_token}"),
                ),
                _ => (
                    format!("{}/v1/events", self.cfg.base_url),
                    sync_auth_header(&self.cfg.key),
                ),
            };
            let response = self
                .agent
                .post(&url)
                .header("X-Merlin-Segment", &name)
                .header("Authorization", &authorization)
                .send(&body);
            match response {
                Ok(resp) if resp.status() == 200 || resp.status() == 202 => {
                    // Delete-after-ack: the segment was the buffer.
                    fs::remove_file(&path)
                        .with_context(|| format!("deleting acked segment {name}"))?;
                    log::info!("sync: uploaded and acked {name}");
                }
                Ok(resp) => {
                    anyhow::bail!("sync: server rejected {name} with status {}", resp.status());
                }
                Err(ureq::Error::StatusCode(code)) => {
                    anyhow::bail!("sync: server rejected {name} with status {code}");
                }
                Err(e) => {
                    return Err(e).context("sync: upload transport error");
                }
            }
        }
        Ok(())
    }

    /// One rules check. Returns true when a new ruleset was applied.
    pub fn sync_rules(&mut self, target_sha: &str) -> Result<bool> {
        let (Some(device_id), Some(device_token)) = (
            self.cfg.device_id.as_deref(),
            self.cfg.device_token.as_deref(),
        ) else {
            anyhow::bail!("sync: managed policy delivery requires device credentials");
        };
        let device_id = device_id.to_string();
        let device_token = device_token.to_string();
        let url = format!(
            "{}/v1/devices/{device_id}/policies/{target_sha}",
            self.cfg.base_url
        );
        let authorization = format!("Bearer {device_token}");
        let mut response = self
            .agent
            .get(&url)
            .header("Authorization", &authorization)
            .call()
            .context("sync: rules request")?;
        if response.status() != 200 {
            anyhow::bail!("sync: rules endpoint returned {}", response.status());
        }
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_POLICY_ENVELOPE_BYTES)
            .read_to_vec()
            .context("sync: reading policy envelope")?;
        let verified =
            decode_policy_envelope(&body, Some(target_sha), configured_policy_keys(&self.cfg))?;
        let artifact_sha = verified.artifact_sha256.clone();
        let text = String::from_utf8(verified.artifact).context("sync: rules body is not UTF-8")?;
        self.pending_receipts.clear();
        let (parsed, desired) = if verified.format == desired_state::ARTIFACT_FORMAT {
            match desired_state::parse_artifact(&text) {
                Ok((rules, desired)) => (rules, Some(desired)),
                Err(error) => {
                    log::warn!(
                        "sync: desired-state artifact failed to parse ({error:#}); keeping current rules"
                    );
                    return Ok(false);
                }
            }
        } else {
            match Rules::parse(&text) {
                Ok(rules) => (rules, None),
                Err(e) => {
                    // Last-known-good: a bad push must not disarm the sensor.
                    log::warn!("sync: synced rules failed to parse ({e:#}); keeping current rules");
                    return Ok(false);
                }
            }
        };
        if let Some(desired) = desired {
            self.pending_receipts = desired.apply(&device_id, &artifact_sha)?;
            if self
                .pending_receipts
                .iter()
                .any(|receipt| receipt.result == "failed")
            {
                anyhow::bail!("sync: one or more desired-state assertions failed");
            }
        }
        write_synced_marker(&self.synced_marker, &body)?;
        let count = parsed.rules.len();
        self.handle.set(parsed);
        self.current_sha = target_sha.to_string();
        log::info!(
            "sync: applied {count} synced rules (sha256 {})",
            self.current_sha
        );
        Ok(true)
    }

    /// Send the device heartbeat. A queued signed-rules update is delivered
    /// through the existing rules endpoint and acknowledged only after the
    /// rules engine accepts the verified target version.
    pub fn check_in(&mut self) -> Result<()> {
        let (Some(device_id), Some(device_token)) = (
            self.cfg.device_id.as_deref(),
            self.cfg.device_token.as_deref(),
        ) else {
            return Ok(());
        };
        let metrics = spool::metrics_snapshot();
        let drop_rate = if metrics.events_attempted == 0 {
            0.0
        } else {
            metrics.events_dropped as f64 / metrics.events_attempted as f64
        };
        let os_version = std::env::var("MERLIN_OS_VERSION")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| std::env::consts::OS.to_string());
        let kernel_version = fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "unknown".to_string());
        let request_body = serde_json::to_vec(&DeviceCheckInRequest {
            host: &self.host,
            platform: "linux",
            agent_version: env!("CARGO_PKG_VERSION"),
            os_version: &os_version,
            kernel_version: &kernel_version,
            sensor_mode: &self.cfg.sensor_mode,
            current_rules_sha256: &self.current_sha,
            status: "healthy",
            capabilities: [
                "segment_upload",
                "rules_sync",
                "system_inventory",
                "file_integrity",
                "security_configuration_assessment",
                "rootcheck",
                "container_inventory",
                "cloud_inventory",
                "posture_reporting",
                "linux_boot_trust_posture",
            ]
            .into_iter()
            .chain(desired_state::CAPABILITIES.iter().copied())
            .collect(),
            health: DeviceHealth {
                drop_rate,
                events_attempted: metrics.events_attempted,
                events_accepted: metrics.events_accepted,
                events_dropped: metrics.events_dropped,
                events_written: metrics.events_written,
                queue_dropped: metrics.events_dropped,
                kernel_events_dropped: metrics.kernel_events_dropped,
                write_failures: metrics.write_failures,
            },
            posture: linux_posture::collect(),
            os_info: collect_os_info(),
            inventory: collect_inventory(),
        })
        .context("sync: encoding device check-in")?;
        let url = format!("{}/v1/devices/{device_id}/check-in", self.cfg.base_url);
        let authorization = format!("Bearer {device_token}");
        let mut response = match self
            .agent
            .post(&url)
            .header("Authorization", &authorization)
            .header("Content-Type", "application/json")
            .send(&request_body)
        {
            Ok(response) => response,
            Err(ureq::Error::StatusCode(code)) => {
                anyhow::bail!("sync: device check-in rejected with status {code}")
            }
            Err(error) => return Err(error).context("sync: device check-in transport error"),
        };
        if response.status() != 200 {
            anyhow::bail!("sync: device check-in returned {}", response.status());
        }
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_DEVICE_RESPONSE_BYTES)
            .read_to_vec()
            .context("sync: reading device check-in response")?;
        let result: DeviceCheckInResponse =
            serde_json::from_slice(&body).context("sync: decoding device check-in response")?;
        let Some(update) = result.pending_update else {
            return Ok(());
        };
        if update.kind != "rules" {
            anyhow::bail!("sync: unsupported device update kind {}", update.kind);
        }

        let target_sha = update.target_rules_sha256.clone();
        match self.sync_rules(&target_sha) {
            Ok(_) if self.current_sha == update.target_rules_sha256 => {
                self.ack_update(&update, "applied", &self.current_sha, None)?;
                Ok(())
            }
            Ok(_) => {
                let message = "verified rules did not reach the requested version";
                let _ = self.ack_update(&update, "failed", &self.current_sha, Some(message));
                anyhow::bail!("sync: {message}")
            }
            Err(error) => {
                let message = format!("{error:#}");
                let _ = self.ack_update(&update, "failed", &self.current_sha, Some(&message));
                Err(error).context("sync: applying queued device update")
            }
        }
    }

    fn ack_update(
        &self,
        update: &PendingDeviceUpdate,
        status: &str,
        rules_sha256: &str,
        error: Option<&str>,
    ) -> Result<()> {
        let (Some(device_id), Some(device_token)) = (
            self.cfg.device_id.as_deref(),
            self.cfg.device_token.as_deref(),
        ) else {
            anyhow::bail!("sync: cannot acknowledge update without device credentials");
        };
        let body = serde_json::to_vec(&DeviceUpdateAck {
            status,
            rules_sha256,
            error,
            receipts: &self.pending_receipts,
        })
        .context("sync: encoding update acknowledgement")?;
        let url = format!(
            "{}/v1/devices/{device_id}/updates/{}/ack",
            self.cfg.base_url, update.update_id
        );
        let authorization = format!("Bearer {device_token}");
        let response = match self
            .agent
            .post(&url)
            .header("Authorization", &authorization)
            .header("Content-Type", "application/json")
            .send(&body)
        {
            Ok(response) => response,
            Err(ureq::Error::StatusCode(code)) => {
                anyhow::bail!("sync: update acknowledgement rejected with status {code}")
            }
            Err(error) => {
                return Err(error).context("sync: update acknowledgement transport error");
            }
        };
        if response.status() != 200 {
            anyhow::bail!(
                "sync: update acknowledgement returned {}",
                response.status()
            );
        }
        Ok(())
    }
}

/// Write the verified ruleset next to the local rules file for operator
/// inspection. The engine runs the in-memory copy; this is evidence.
fn write_synced_marker(path: &Path, envelope: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    let file_name = path.file_name().unwrap_or_default().to_string_lossy();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = parent.join(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .mode(0o600)
        .open(&temp)
        .with_context(|| format!("creating {}", temp.display()))?;
    let result = (|| -> Result<()> {
        std::io::Write::write_all(&mut file, envelope)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.with_context(|| format!("writing {}", path.display()))
}

pub fn hostname() -> String {
    let mut buf = [0u8; 256];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc != 0 {
        return "unknown".to_string();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

fn bounded_read(path: &str, max_bytes: usize) -> Option<Vec<u8>> {
    let file = fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(max_bytes as u64).read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

fn bounded_read_path(path: &Path, max_bytes: usize) -> Option<Vec<u8>> {
    let file = fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(max_bytes as u64).read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

fn os_release_value(body: &str, key: &str) -> Option<String> {
    body.lines().find_map(|line| {
        let value = line.strip_prefix(key)?.strip_prefix('=')?.trim();
        let value = value.trim_matches('"').trim_matches('\'');
        if value.is_empty() {
            None
        } else {
            Some(value.chars().take(128).collect())
        }
    })
}

fn uname_release() -> String {
    let mut value = std::mem::MaybeUninit::<libc::utsname>::zeroed();
    if unsafe { libc::uname(value.as_mut_ptr()) } != 0 {
        return String::new();
    }
    let value = unsafe { value.assume_init() };
    unsafe { CStr::from_ptr(value.release.as_ptr()) }
        .to_string_lossy()
        .chars()
        .take(128)
        .collect()
}

fn uname_version() -> String {
    let mut value = std::mem::MaybeUninit::<libc::utsname>::zeroed();
    if unsafe { libc::uname(value.as_mut_ptr()) } != 0 {
        return String::new();
    }
    let value = unsafe { value.assume_init() };
    unsafe { CStr::from_ptr(value.version.as_ptr()) }
        .to_string_lossy()
        .chars()
        .take(128)
        .collect()
}

fn cpu_model() -> String {
    let Some(body) = bounded_read("/proc/cpuinfo", 64 << 10) else {
        return String::new();
    };
    let Ok(body) = std::str::from_utf8(&body) else {
        return String::new();
    };
    body.lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            if !matches!(key.trim(), "model name" | "Hardware" | "Processor") {
                return None;
            }
            let value = value.trim();
            if value.is_empty() {
                return None;
            }
            Some(value.chars().take(128).collect())
        })
        .unwrap_or_default()
}

fn load_average() -> [f64; 3] {
    let Some(body) = bounded_read("/proc/loadavg", 256) else {
        return [0.0; 3];
    };
    let mut values = body
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|part| !part.is_empty())
        .take(3)
        .filter_map(|part| std::str::from_utf8(part).ok()?.parse::<f64>().ok());
    [
        values.next().unwrap_or(0.0),
        values.next().unwrap_or(0.0),
        values.next().unwrap_or(0.0),
    ]
}

fn meminfo_bytes(label: &str) -> u64 {
    let Some(body) = bounded_read("/proc/meminfo", 64 << 10) else {
        return 0;
    };
    let Ok(body) = std::str::from_utf8(&body) else {
        return 0;
    };
    body.lines()
        .find_map(|line| {
            let value = line.strip_prefix(label)?.trim().strip_suffix(" kB")?;
            value.parse::<u64>().ok()?.checked_mul(1024)
        })
        .unwrap_or(0)
}

fn root_filesystem() -> String {
    bounded_read("/proc/mounts", 64 << 10)
        .and_then(|body| std::str::from_utf8(&body).ok().map(str::to_owned))
        .and_then(|body| {
            body.lines().find_map(|line| {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                if fields.get(1).copied() != Some("/") {
                    return None;
                }
                fields.get(2).map(|value| value.chars().take(64).collect())
            })
        })
        .unwrap_or_default()
}

fn virtualization(containerized: bool) -> String {
    if containerized {
        return "container".into();
    }
    let cpuinfo = bounded_read("/proc/cpuinfo", 64 << 10)
        .map(|body| String::from_utf8_lossy(&body).to_ascii_lowercase())
        .unwrap_or_default();
    if cpuinfo.lines().any(|line| line.contains(" hypervisor")) {
        return "virtual_machine".into();
    }
    let dmi = [
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
    ]
    .iter()
    .filter_map(|path| bounded_read(path, 256))
    .map(|body| String::from_utf8_lossy(&body).to_ascii_lowercase())
    .collect::<Vec<_>>()
    .join(" ");
    if [
        "kvm",
        "qemu",
        "vmware",
        "virtualbox",
        "xen",
        "microsoft corporation",
    ]
    .iter()
    .any(|marker| dmi.contains(marker))
    {
        return "virtual_machine".into();
    }
    "not_detected".into()
}

fn uptime_seconds() -> u64 {
    bounded_read("/proc/uptime", 128)
        .and_then(|body| {
            std::str::from_utf8(&body)
                .ok()?
                .split_whitespace()
                .next()?
                .parse::<f64>()
                .ok()
        })
        .filter(|value| value.is_finite() && *value >= 0.0)
        .map(|value| value as u64)
        .unwrap_or(0)
}

fn root_disk_bytes() -> (u64, u64) {
    let Ok(path) = CString::new("/") else {
        return (0, 0);
    };
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    if unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return (0, 0);
    }
    let stats = unsafe { stats.assume_init() };
    let block_size = if stats.f_frsize > 0 {
        stats.f_frsize as u64
    } else {
        stats.f_bsize as u64
    };
    (
        (stats.f_blocks as u64).saturating_mul(block_size),
        (stats.f_bavail as u64).saturating_mul(block_size),
    )
}

fn network_interface_details() -> Vec<DeviceNetworkInterface> {
    let mut interfaces = fs::read_dir("/sys/class/net")
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let name = entry
                .file_name()
                .to_string_lossy()
                .chars()
                .take(128)
                .collect::<String>();
            if name.is_empty() {
                return None;
            }
            let path = entry.path();
            let kind = if name == "lo" {
                "loopback"
            } else if path.join("wireless").exists() {
                "wireless"
            } else if path.join("bridge").exists() {
                "bridge"
            } else if path.join("device").exists() {
                "physical"
            } else {
                "virtual"
            };
            let state = bounded_read_path(&path.join("operstate"), 32)
                .map(|body| {
                    String::from_utf8_lossy(&body)
                        .trim()
                        .chars()
                        .take(32)
                        .collect()
                })
                .unwrap_or_default();
            let mtu = bounded_read_path(&path.join("mtu"), 32)
                .and_then(|body| String::from_utf8_lossy(&body).trim().parse::<u32>().ok());
            Some(DeviceNetworkInterface {
                name,
                kind: kind.into(),
                state,
                mtu,
            })
        })
        .collect::<Vec<_>>();
    interfaces.sort_by(|left, right| left.name.cmp(&right.name));
    interfaces.dedup_by(|left, right| left.name == right.name);
    interfaces.truncate(64);
    interfaces
}

fn is_containerized() -> bool {
    if fs::metadata("/.dockerenv").is_ok() {
        return true;
    }
    bounded_read("/proc/1/cgroup", 64 << 10)
        .map(|body| {
            let body = String::from_utf8_lossy(&body).to_ascii_lowercase();
            ["docker", "containerd", "kubepods", "podman"]
                .iter()
                .any(|marker| body.contains(marker))
        })
        .unwrap_or(false)
}

fn inventory_text(value: &str, max: usize) -> String {
    value.trim().chars().take(max).collect()
}

fn collect_packages() -> (String, Vec<DevicePackage>) {
    let mut packages = Vec::new();
    let mut manager = String::new();
    if let Some(body) = bounded_read("/var/lib/dpkg/status", 8 << 20) {
        manager = "dpkg".into();
        let body = String::from_utf8_lossy(&body);
        for record in body.split("\n\n") {
            let mut name = String::new();
            let mut version = String::new();
            let mut architecture = String::new();
            let mut installed = false;
            for line in record.lines() {
                if let Some(value) = line.strip_prefix("Package:") {
                    name = inventory_text(value, 160);
                } else if let Some(value) = line.strip_prefix("Version:") {
                    version = inventory_text(value, 160);
                } else if let Some(value) = line.strip_prefix("Architecture:") {
                    architecture = inventory_text(value, 64);
                } else if line.starts_with("Status:") && line.contains("install ok installed") {
                    installed = true;
                }
            }
            if installed && !name.is_empty() {
                packages.push(DevicePackage {
                    name,
                    version,
                    architecture,
                    manager: manager.clone(),
                });
            }
            if packages.len() >= 512 {
                break;
            }
        }
    }
    if packages.is_empty() {
        if let Some(body) = bounded_read("/lib/apk/db/installed", 8 << 20) {
            manager = "apk".into();
            let body = String::from_utf8_lossy(&body);
            for record in body.split("\n\n") {
                let mut name = String::new();
                let mut version = String::new();
                for line in record.lines() {
                    if let Some(value) = line.strip_prefix("P:") {
                        name = inventory_text(value, 160);
                    } else if let Some(value) = line.strip_prefix("V:") {
                        version = inventory_text(value, 160);
                    }
                }
                if !name.is_empty() {
                    packages.push(DevicePackage {
                        name,
                        version,
                        architecture: String::new(),
                        manager: manager.clone(),
                    });
                }
                if packages.len() >= 512 {
                    break;
                }
            }
        }
    }
    packages.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.version.cmp(&right.version))
    });
    packages.truncate(512);
    (manager, packages)
}

fn collect_services() -> Vec<DeviceService> {
    let mut names = BTreeSet::new();
    let mut services = Vec::new();
    for directory in [
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
    ] {
        let Ok(entries) = fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".service") && names.insert(name.clone()) {
                services.push(DeviceService {
                    name,
                    state: "installed".into(),
                    source: "systemd".into(),
                });
            }
            if services.len() >= 256 {
                return services;
            }
        }
    }
    services.sort_by(|left, right| left.name.cmp(&right.name));
    services
}

fn collect_users_groups() -> (Vec<DeviceUser>, Vec<String>) {
    let mut users = Vec::new();
    if let Some(body) = bounded_read("/etc/passwd", 256 << 10) {
        for line in String::from_utf8_lossy(&body).lines().take(256) {
            let fields = line.split(':').collect::<Vec<_>>();
            if fields.len() < 7 {
                continue;
            }
            let Some(uid) = fields[2].parse::<u64>().ok() else {
                continue;
            };
            let name = inventory_text(fields[0], 128);
            if name.is_empty() {
                continue;
            }
            users.push(DeviceUser {
                admin: uid == 0,
                name,
                uid,
                shell: inventory_text(fields[6], 256),
                source: "passwd".into(),
            });
        }
    }
    let mut groups = Vec::new();
    if let Some(body) = bounded_read("/etc/group", 256 << 10) {
        for line in String::from_utf8_lossy(&body).lines().take(256) {
            if let Some(name) = line
                .split(':')
                .next()
                .map(|value| inventory_text(value, 128))
            {
                if !name.is_empty() {
                    groups.push(name);
                }
            }
        }
    }
    users.sort_by(|left, right| left.uid.cmp(&right.uid).then(left.name.cmp(&right.name)));
    groups.sort();
    groups.dedup();
    (users, groups)
}

fn collect_proc_ports(path: &str, protocol: &str, ports: &mut Vec<DeviceListeningPort>) {
    let Some(body) = bounded_read(path, 256 << 10) else {
        return;
    };
    for line in String::from_utf8_lossy(&body).lines().skip(1) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let Some(local) = fields.get(1) else { continue };
        let Some(port_hex) = local.rsplit(':').next() else {
            continue;
        };
        let Ok(port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };
        if port == 0 {
            continue;
        }
        let state_code = fields.get(3).copied().unwrap_or_default();
        if protocol == "tcp" && state_code != "0A" {
            continue;
        }
        ports.push(DeviceListeningPort {
            protocol: protocol.into(),
            port,
            state: if protocol == "tcp" {
                "listening"
            } else {
                "bound"
            }
            .into(),
            source: path.into(),
        });
        if ports.len() >= 256 {
            return;
        }
    }
}

fn collect_listening_ports() -> Vec<DeviceListeningPort> {
    let mut ports = Vec::new();
    collect_proc_ports("/proc/net/tcp", "tcp", &mut ports);
    collect_proc_ports("/proc/net/tcp6", "tcp", &mut ports);
    collect_proc_ports("/proc/net/udp", "udp", &mut ports);
    collect_proc_ports("/proc/net/udp6", "udp", &mut ports);
    ports.sort_by(|left, right| {
        left.protocol
            .cmp(&right.protocol)
            .then(left.port.cmp(&right.port))
    });
    ports.dedup_by(|left, right| left.protocol == right.protocol && left.port == right.port);
    ports.truncate(256);
    ports
}

fn collect_containers() -> Vec<DeviceContainer> {
    let mut ids = BTreeSet::new();
    if let Some(body) = bounded_read("/proc/1/cgroup", 64 << 10) {
        for line in String::from_utf8_lossy(&body).lines() {
            if let Some(candidate) = line.rsplit('/').next() {
                let candidate = candidate.trim();
                if candidate.len() >= 12
                    && candidate.len() <= 128
                    && candidate.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    ids.insert(candidate.to_string());
                }
            }
        }
    }
    if ids.is_empty() && fs::metadata("/.dockerenv").is_ok() {
        ids.insert(String::new());
    }
    let mut containers = ids
        .into_iter()
        .take(128)
        .map(|id| DeviceContainer {
            id,
            name: String::new(),
            image: String::new(),
            state: "running".into(),
            runtime: "container".into(),
        })
        .collect::<Vec<_>>();
    // Docker's metadata directory is readable by some root-installed agents
    // even when the Docker socket is not. Read only bounded JSON metadata; do
    // not invoke a runtime CLI or expose container environment variables.
    if let Ok(entries) = fs::read_dir("/var/lib/docker/containers") {
        for entry in entries.flatten() {
            if containers.len() >= 128 {
                break;
            }
            let id = entry
                .file_name()
                .to_string_lossy()
                .chars()
                .take(128)
                .collect::<String>();
            let path = entry.path().join("config.v2.json");
            let Some(body) = bounded_read_path(&path, 256 << 10) else {
                continue;
            };
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) else {
                continue;
            };
            let name = value
                .get("Name")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            let image = value
                .get("Config")
                .and_then(|value| value.get("Image"))
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            let state = value
                .get("State")
                .and_then(|value| value.get("Status"))
                .and_then(|value| value.as_str())
                .unwrap_or("unknown");
            if let Some(container) = containers.iter_mut().find(|container| container.id == id) {
                container.name = inventory_text(name, 256);
                container.image = inventory_text(image, 256);
                container.state = inventory_text(state, 64);
                container.runtime = "docker".into();
            } else {
                containers.push(DeviceContainer {
                    id,
                    name: inventory_text(name, 256),
                    image: inventory_text(image, 256),
                    state: inventory_text(state, 64),
                    runtime: "docker".into(),
                });
            }
        }
    }
    containers
}

fn collect_processes() -> Vec<DeviceProcess> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut processes = entries
        .flatten()
        .filter_map(|entry| {
            let pid = entry.file_name().to_string_lossy().parse::<u32>().ok()?;
            let root = entry.path();
            let name = bounded_read_path(&root.join("comm"), 256)
                .map(|body| inventory_text(&String::from_utf8_lossy(&body), 256))
                .filter(|value| !value.is_empty())?;
            let executable = fs::read_link(root.join("exe"))
                .ok()
                .map(|path| inventory_text(&path.to_string_lossy(), 512))
                .unwrap_or_default();
            let mut user = String::new();
            let mut state = String::new();
            if let Some(body) = bounded_read_path(&root.join("status"), 16 << 10) {
                for line in String::from_utf8_lossy(&body).lines() {
                    if let Some(value) = line.strip_prefix("Uid:") {
                        user = format!(
                            "uid:{}",
                            value.split_whitespace().next().unwrap_or_default()
                        );
                    } else if let Some(value) = line.strip_prefix("State:") {
                        state =
                            inventory_text(value.split_whitespace().next().unwrap_or_default(), 32);
                    }
                }
            }
            Some(DeviceProcess {
                pid,
                name,
                executable,
                user,
                state,
            })
        })
        .take(512)
        .collect::<Vec<_>>();
    processes.sort_by(|left, right| left.pid.cmp(&right.pid));
    processes
}

fn cloud_metadata() -> (String, String, String) {
    (
        std::env::var("MERLIN_CLOUD_PROVIDER")
            .ok()
            .map(|value| inventory_text(&value, 128))
            .unwrap_or_default(),
        std::env::var("MERLIN_CLOUD_INSTANCE_ID")
            .ok()
            .map(|value| inventory_text(&value, 128))
            .unwrap_or_default(),
        std::env::var("MERLIN_CLOUD_REGION")
            .ok()
            .map(|value| inventory_text(&value, 128))
            .unwrap_or_default(),
    )
}

fn fim_paths() -> Vec<String> {
    let configured = std::env::var("MERLIN_FIM_PATHS").unwrap_or_default();
    let values = if configured.trim().is_empty() {
        vec![
            "/etc/passwd".to_string(),
            "/etc/group".to_string(),
            "/etc/ssh/sshd_config".to_string(),
            "/etc/sudoers".to_string(),
        ]
    } else {
        configured
            .split(',')
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .take(256)
            .collect()
    };
    values
}

fn collect_fim() -> Vec<DeviceFIMEntry> {
    fim_paths()
        .into_iter()
        .take(256)
        .map(|path| {
            let path_ref = Path::new(&path);
            let Ok(metadata) = fs::metadata(path_ref) else {
                return DeviceFIMEntry {
                    path,
                    sha256: String::new(),
                    size_bytes: 0,
                    mode: String::new(),
                    modified_unix: 0,
                    status: "missing".into(),
                };
            };
            let sha256 = bounded_read_path(path_ref, 2 << 20)
                .map(|body| hex_encode(&Sha256::digest(&body)))
                .unwrap_or_default();
            DeviceFIMEntry {
                path,
                sha256,
                size_bytes: metadata.len(),
                mode: format!("{:o}", metadata.mode() & 0o7777),
                modified_unix: metadata.mtime(),
                status: "present".into(),
            }
        })
        .collect()
}

fn config_setting(path: &str, key: &str) -> Option<String> {
    let body = bounded_read(path, 256 << 10)?;
    String::from_utf8_lossy(&body).lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || !line.starts_with(key) {
            return None;
        }
        let mut fields = line.split_whitespace();
        if fields.next()? != key {
            return None;
        }
        Some(inventory_text(fields.next().unwrap_or_default(), 64).to_ascii_lowercase())
    })
}

fn sca_result(
    id: &str,
    title: &str,
    status: &str,
    severity: &str,
    detail: &str,
) -> DeviceSCAResult {
    DeviceSCAResult {
        id: id.into(),
        title: title.into(),
        status: status.into(),
        severity: severity.into(),
        detail: detail.into(),
        frameworks: vec!["CIS".into(), "NIST 800-53".into()],
    }
}

fn collect_sca() -> Vec<DeviceSCAResult> {
    let mut results = Vec::new();
    let ssh_config = "/etc/ssh/sshd_config";
    match config_setting(ssh_config, "PermitRootLogin").as_deref() {
        Some("no") | Some("prohibit-password") => results.push(sca_result(
            "linux.ssh.root_login",
            "Root SSH login is restricted",
            "pass",
            "high",
            "PermitRootLogin disables password-based root login.",
        )),
        Some(value) => results.push(sca_result(
            "linux.ssh.root_login",
            "Root SSH login is restricted",
            "fail",
            "high",
            &format!("PermitRootLogin is configured as {value}."),
        )),
        None => results.push(sca_result(
            "linux.ssh.root_login",
            "Root SSH login is restricted",
            "unknown",
            "high",
            "sshd_config was not readable or did not specify the setting.",
        )),
    }
    match config_setting(ssh_config, "PasswordAuthentication").as_deref() {
        Some("no") => results.push(sca_result(
            "linux.ssh.password_auth",
            "SSH password authentication is disabled",
            "pass",
            "medium",
            "PasswordAuthentication is disabled.",
        )),
        Some(value) => results.push(sca_result(
            "linux.ssh.password_auth",
            "SSH password authentication is disabled",
            "fail",
            "medium",
            &format!("PasswordAuthentication is configured as {value}."),
        )),
        None => results.push(sca_result(
            "linux.ssh.password_auth",
            "SSH password authentication is disabled",
            "unknown",
            "medium",
            "sshd_config was not readable or did not specify the setting.",
        )),
    }
    let firewall_enabled = bounded_read("/proc/net/ip_tables_names", 4096)
        .is_some_and(|body| !body.is_empty())
        || fs::metadata("/run/ufw").is_ok();
    results.push(sca_result(
        "linux.firewall.present",
        "A host firewall is active",
        if firewall_enabled { "pass" } else { "unknown" },
        "high",
        if firewall_enabled {
            "The kernel firewall table or ufw runtime state is present."
        } else {
            "Firewall state could not be proven from the bounded collector."
        },
    ));
    let sensitive_paths = ["/etc/passwd", "/etc/group", "/etc/sudoers", "/etc/shadow"];
    let mut checked_sensitive = 0;
    let mut writable_sensitive = Vec::new();
    for path in sensitive_paths {
        let Ok(metadata) = fs::metadata(path) else {
            continue;
        };
        checked_sensitive += 1;
        if metadata.mode() & 0o022 != 0 || metadata.uid() != 0 {
            writable_sensitive.push(path);
        }
    }
    results.push(sca_result(
        "linux.rootcheck.sensitive_permissions",
        "Sensitive system files have safe ownership and permissions",
        if checked_sensitive == 0 {
            "unknown"
        } else if writable_sensitive.is_empty() {
            "pass"
        } else {
            "fail"
        },
        "high",
        if checked_sensitive == 0 {
            "No sensitive system files were readable by the bounded collector."
        } else if writable_sensitive.is_empty() {
            "Sensitive system files are root-owned and not group/world-writable."
        } else {
            "One or more sensitive system files are writable by a non-root group or user."
        },
    ));
    results
}

fn collect_inventory() -> DeviceInventory {
    let (package_manager, packages) = collect_packages();
    let (users, groups) = collect_users_groups();
    let (cloud_provider, cloud_instance_id, cloud_region) = cloud_metadata();
    let (agent_clis, mcp_servers, agent_assets) = collect_agent_discovery();
    DeviceInventory {
        collected_at: format!("{:.3}", spool::now_ts()),
        package_manager,
        cloud_provider,
        cloud_instance_id,
        cloud_region,
        packages,
        services: collect_services(),
        users,
        groups,
        listening_ports: collect_listening_ports(),
        containers: collect_containers(),
        processes: collect_processes(),
        fim: collect_fim(),
        sca: collect_sca(),
        vulnerabilities: Vec::new(),
        agent_clis,
        mcp_servers,
        agent_assets,
        collection_source: "linux-agent".into(),
    }
}

// Probe only fixed executable names and fixed configuration locations. Never
// execute a CLI or include configuration values in a managed heartbeat.
fn collect_agent_discovery() -> (
    Vec<DeviceAgentCLI>,
    Vec<DeviceMCPServer>,
    Vec<DeviceAgentAsset>,
) {
    let mut homes = vec![PathBuf::from("/root")];
    if let Ok(entries) = fs::read_dir("/home") {
        let mut candidates: Vec<_> = entries
            .take(256)
            .flatten()
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
            .map(|entry| entry.path())
            .collect();
        candidates.sort();
        homes.extend(candidates.into_iter().take(64));
    }
    let mut discovery = collect_agent_discovery_from(
        &homes,
        &[
            "/usr/local/bin",
            "/usr/bin",
            "/home/linuxbrew/.linuxbrew/bin",
        ],
    );
    let roots = configured_agent_workspace_roots();
    let (project_servers, project_assets) = collect_project_agent_discovery(&roots);
    discovery.1.extend(project_servers);
    discovery.1.sort();
    discovery.1.dedup();
    discovery.1.truncate(128);
    discovery.2.extend(project_assets);
    discovery.2.sort();
    discovery.2.dedup();
    discovery.2.truncate(128);
    discovery
}

// MDM supplies a JSON array in the root-owned service configuration. No default
// workspace roots are scanned, and no configured path is sent in inventory.
fn configured_agent_workspace_roots() -> Vec<PathBuf> {
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

fn project_directory(path: &std::path::Path) -> bool {
    path.symlink_metadata()
        .is_ok_and(|meta| meta.is_dir() && !meta.file_type().is_symlink())
}

fn collect_project_agent_discovery(
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
    for root in roots.iter().take(8).filter(|root| project_directory(root)) {
        let mut projects = vec![root.clone()];
        if let Ok(entries) = fs::read_dir(root) {
            let mut children: Vec<_> = entries
                .take(256)
                .flatten()
                .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
                .map(|entry| entry.path())
                .collect();
            children.sort();
            projects.extend(children.into_iter().take(32));
        }
        for project in projects {
            if !project_directory(&project) {
                continue;
            }
            for (client, relative, is_toml) in CONFIGS {
                let path = project.join(relative);
                if path
                    .parent()
                    .is_some_and(|parent| parent != project && !project_directory(parent))
                {
                    continue;
                }
                let Some(body) = read_agent_config(&path) else {
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
                let directory = project.join(relative);
                if !project_directory(directory.parent().unwrap_or(&project))
                    || !project_directory(&directory)
                {
                    continue;
                }
                let Ok(entries) = fs::read_dir(&directory) else {
                    continue;
                };
                for entry in entries.take(256).flatten() {
                    let Ok(file_type) = entry.file_type() else {
                        continue;
                    };
                    let filename = entry.file_name().to_string_lossy().into_owned();
                    let name = if *format == "skill"
                        && file_type.is_dir()
                        && entry
                            .path()
                            .join("SKILL.md")
                            .symlink_metadata()
                            .is_ok_and(|meta| meta.is_file() && !meta.file_type().is_symlink())
                    {
                        Some(filename.as_str())
                    } else if *format == "plugin" && file_type.is_dir() {
                        Some(filename.as_str())
                    } else if *format == "md" && file_type.is_file() {
                        filename.strip_suffix(".md")
                    } else {
                        None
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
                                if let Some(body) = read_agent_config(&entry.path().join(config)) {
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

fn collect_agent_discovery_from(
    homes: &[PathBuf],
    system_bins: &[&str],
) -> (
    Vec<DeviceAgentCLI>,
    Vec<DeviceMCPServer>,
    Vec<DeviceAgentAsset>,
) {
    const CLIS: &[&str] = &[
        "codex", "claude", "cursor", "gemini", "opencode", "aider", "maestro", "amp", "goose",
        "qwen", "pi",
    ];
    const CONFIGS: &[(&str, &str, bool)] = &[
        ("claude", ".config/Claude/claude_desktop_config.json", false),
        ("claude", ".claude.json", false),
        ("cursor", ".cursor/mcp.json", false),
        ("gemini", ".gemini/settings.json", false),
        ("vscode", ".config/Code/User/mcp.json", false),
        ("codex", ".codex/config.toml", true),
        ("opencode", ".config/opencode/opencode.json", false),
        ("claude", ".claude/settings.json", false),
        ("amp", ".config/amp/settings.json", false),
        ("qwen", ".qwen/settings.json", false),
        ("pi", ".pi/agent/settings.json", false),
        ("maestro", ".maestro/config.toml", true),
        ("maestro", ".composer/config.toml", true),
    ];
    let mut clis = BTreeSet::new();
    let mut servers = BTreeSet::new();
    let mut assets = BTreeSet::new();
    let mut plugin_config_reads = 0;
    for name in CLIS {
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
                name: (*name).into(),
            });
        }
    }
    for home in homes.iter().take(65) {
        for (client, kind, relative, extension) in [
            ("agents", "skill", ".agents/skills", ""),
            ("codex", "skill", ".codex/skills", ""),
            ("claude", "skill", ".claude/skills", ""),
            ("claude", "agent", ".claude/agents", "md"),
            ("gemini", "skill", ".gemini/skills", ""),
            ("gemini", "extension", ".gemini/extensions", ""),
            ("opencode", "skill", ".config/opencode/skills", ""),
            ("opencode", "plugin", ".config/opencode/plugins", "js-ts"),
            ("opencode", "agent", ".config/opencode/agents", "md"),
            ("amp", "skill", ".config/amp/skills", ""),
            ("qwen", "skill", ".qwen/skills", ""),
            ("pi", "skill", ".pi/agent/skills", ""),
            ("pi", "extension", ".pi/agent/extensions", "js-ts"),
            ("maestro", "skill", ".composer/skills", ""),
            ("maestro", "plugin", ".maestro/plugins", "plugin"),
            ("maestro", "plugin", ".composer/plugins", "plugin"),
        ] {
            let directory = home.join(relative);
            if !directory
                .symlink_metadata()
                .is_ok_and(|meta| meta.is_dir() && !meta.file_type().is_symlink())
            {
                continue;
            }
            let Ok(entries) = fs::read_dir(&directory) else {
                continue;
            };
            for entry in entries.take(256).flatten() {
                let Ok(kind_on_disk) = entry.file_type() else {
                    continue;
                };
                let file_name = entry.file_name().to_string_lossy().into_owned();
                let name = if extension == "md" && kind_on_disk.is_file() {
                    file_name.strip_suffix(".md")
                } else if extension == "js-ts" && kind_on_disk.is_file() {
                    file_name
                        .strip_suffix(".js")
                        .or_else(|| file_name.strip_suffix(".ts"))
                } else if extension.is_empty()
                    && kind == "skill"
                    && kind_on_disk.is_dir()
                    && directory
                        .join(&file_name)
                        .join("SKILL.md")
                        .symlink_metadata()
                        .is_ok_and(|meta| meta.is_file() && !meta.file_type().is_symlink())
                {
                    Some(file_name.as_str())
                } else if extension.is_empty()
                    && kind == "extension"
                    && kind_on_disk.is_dir()
                    && directory
                        .join(&file_name)
                        .join("gemini-extension.json")
                        .symlink_metadata()
                        .is_ok_and(|meta| meta.is_file() && !meta.file_type().is_symlink())
                {
                    Some(file_name.as_str())
                } else if extension == "plugin" && kind_on_disk.is_dir() {
                    Some(file_name.as_str())
                } else {
                    None
                };
                if let Some(name) = name.filter(|name| safe_agent_asset_name(name)) {
                    assets.insert(DeviceAgentAsset {
                        client: client.into(),
                        kind: kind.into(),
                        name: name.into(),
                        source: relative.into(),
                    });
                    if client == "gemini" && kind == "extension" {
                        if let Some(body) = read_agent_config(
                            &directory.join(&file_name).join("gemini-extension.json"),
                        ) {
                            for (server, transport) in
                                json_mcp_entries(&body, &["mcpServers", "servers"])
                            {
                                if safe_agent_asset_name(&server) {
                                    servers.insert(DeviceMCPServer {
                                        client: "gemini".into(),
                                        name: server,
                                        source: ".gemini/extensions/*/gemini-extension.json".into(),
                                        transport,
                                    });
                                }
                            }
                        }
                    }
                    if client == "maestro" && kind == "plugin" {
                        for config in ["mcp.json", ".mcp.json"] {
                            if plugin_config_reads >= 32 {
                                break;
                            }
                            if let Some(body) =
                                read_agent_config(&directory.join(&file_name).join(config))
                            {
                                plugin_config_reads += 1;
                                for (server, transport) in
                                    json_mcp_entries(&body, &["mcpServers", "servers"])
                                {
                                    if safe_agent_asset_name(&server) {
                                        servers.insert(DeviceMCPServer {
                                            client: "maestro".into(),
                                            name: server,
                                            source: format!("{relative}/*/{config}"),
                                            transport,
                                        });
                                    }
                                }
                            }
                        }
                    }
                    if assets.len() >= 128 {
                        break;
                    }
                }
            }
            if assets.len() >= 128 {
                break;
            }
        }
        for (client, relative, is_toml) in CONFIGS {
            let Some(body) = read_agent_config(&home.join(relative)) else {
                continue;
            };
            assets.insert(DeviceAgentAsset {
                client: (*client).into(),
                kind: "config".into(),
                name: "user".into(),
                source: (*relative).into(),
            });
            if *client == "claude" && *relative == ".claude/settings.json" {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(plugins) = value
                        .get("enabledPlugins")
                        .and_then(|value| value.as_object())
                    {
                        for (name, enabled) in plugins {
                            if enabled.as_bool() == Some(true) && safe_agent_asset_name(name) {
                                assets.insert(DeviceAgentAsset {
                                    client: "claude".into(),
                                    kind: "plugin".into(),
                                    name: name.clone(),
                                    source: ".claude/settings.json".into(),
                                });
                            }
                        }
                    }
                }
                continue;
            }
            let entries: Vec<(String, String)> = if *client == "amp" {
                json_mcp_entries(&body, &["amp.mcpServers"])
            } else if *client == "opencode" {
                json_mcp_entries(&body, &["mcp"])
            } else if *is_toml {
                codex_mcp_entries(&body)
            } else {
                json_mcp_entries(&body, &["mcpServers", "servers"])
            };
            for (name, transport) in entries {
                if safe_agent_asset_name(&name) {
                    servers.insert(DeviceMCPServer {
                        client: (*client).into(),
                        name,
                        source: (*relative).into(),
                        transport,
                    });
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
    (
        clis.into_iter().collect(),
        servers.into_iter().take(128).collect(),
        assets.into_iter().take(128).collect(),
    )
}

fn read_agent_config(path: &std::path::Path) -> Option<String> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    if !file
        .metadata()
        .ok()
        .is_some_and(|meta| meta.is_file() && meta.len() <= 64 << 10)
    {
        return None;
    }
    let mut body = String::new();
    file.take((64 << 10) + 1).read_to_string(&mut body).ok()?;
    (body.len() <= 64 << 10).then_some(body)
}

fn safe_agent_asset_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && !name.chars().any(char::is_control)
        && !name.contains('/')
        && !name.contains('\\')
}

fn json_mcp_entries(body: &str, keys: &[&str]) -> Vec<(String, String)> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return Vec::new();
    };
    keys.iter()
        .filter_map(|key| value.get(key)?.as_object())
        .flat_map(|object| {
            object.iter().map(|(name, definition)| {
                let has_url = ["url", "httpUrl", "http_url"].iter().any(|key| {
                    definition
                        .get(key)
                        .is_some_and(serde_json::Value::is_string)
                });
                let has_command = definition
                    .get("command")
                    .is_some_and(serde_json::Value::is_string);
                let transport = match (has_url, has_command) {
                    (true, false) => "remote",
                    (false, true) => "stdio",
                    _ => "unknown",
                };
                (name.clone(), transport.to_string())
            })
        })
        .collect()
}

fn codex_mcp_entries(body: &str) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    let mut current: Option<String> = None;
    let mut has_url = false;
    let mut has_command = false;
    let mut finish = |current: &mut Option<String>, has_url: &mut bool, has_command: &mut bool| {
        if let Some(name) = current.take() {
            let transport = match (*has_url, *has_command) {
                (true, false) => "remote",
                (false, true) => "stdio",
                _ => "unknown",
            };
            entries.push((name, transport.to_string()));
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

fn collect_os_info() -> DeviceOSInfo {
    let os_release = bounded_read("/etc/os-release", 64 << 10)
        .and_then(|body| String::from_utf8(body).ok())
        .unwrap_or_default();
    let os_name = os_release_value(&os_release, "NAME").unwrap_or_else(|| "Linux".into());
    let os_version = os_release_value(&os_release, "VERSION_ID")
        .or_else(|| os_release_value(&os_release, "VERSION"))
        .unwrap_or_default();
    let containerized = is_containerized();
    let network_interface_details = network_interface_details();
    let network_interfaces = network_interface_details
        .iter()
        .map(|interface| interface.name.clone())
        .collect();
    let (disk_total_bytes, disk_free_bytes) = root_disk_bytes();
    DeviceOSInfo {
        os_name,
        os_version,
        os_pretty_name: os_release_value(&os_release, "PRETTY_NAME").unwrap_or_default(),
        os_id: os_release_value(&os_release, "ID").unwrap_or_default(),
        os_codename: os_release_value(&os_release, "VERSION_CODENAME").unwrap_or_default(),
        os_build: os_release_value(&os_release, "BUILD_ID").unwrap_or_default(),
        kernel: uname_release(),
        kernel_build: uname_version(),
        architecture: std::env::consts::ARCH.to_string(),
        cpu_model: cpu_model(),
        uptime_seconds: uptime_seconds(),
        cpu_count: std::thread::available_parallelism()
            .map(|count| count.get() as u32)
            .unwrap_or(0),
        load_average: load_average(),
        memory_total_bytes: meminfo_bytes("MemTotal:"),
        memory_available_bytes: meminfo_bytes("MemAvailable:"),
        swap_total_bytes: meminfo_bytes("SwapTotal:"),
        swap_free_bytes: meminfo_bytes("SwapFree:"),
        disk_total_bytes,
        disk_free_bytes,
        root_filesystem: root_filesystem(),
        virtualization: virtualization(containerized),
        containerized,
        network_interfaces,
        network_interface_details,
    }
}

/// Run both loops on one thread. Fail-open: errors only drive backoff.
pub fn run_loop(mut client: SyncClient) {
    let mut last_check_in = Instant::now() - CHECK_IN_INTERVAL;
    loop {
        if Instant::now() >= client.next_attempt {
            let mut failed = false;
            if let Err(e) = client.upload_pending() {
                log::warn!("sync: upload pass failed: {e:#}");
                failed = true;
            }
            if last_check_in.elapsed() >= CHECK_IN_INTERVAL {
                last_check_in = Instant::now();
                if let Err(e) = client.check_in() {
                    log::warn!("sync: device check-in failed: {e:#}");
                    failed = true;
                }
            }
            if failed {
                client.failures = client.failures.saturating_add(1);
            } else {
                client.failures = 0;
            }
            let wait = if failed {
                backoff_secs(client.failures)
            } else {
                0
            };
            client.next_attempt = Instant::now() + Duration::from_secs(wait);
        }
        std::thread::sleep(UPLOAD_SCAN_INTERVAL);
    }
}

/// Start the sync thread.
pub fn spawn(client: SyncClient) -> Result<std::thread::JoinHandle<()>> {
    log::info!(
        "sync: uploading segments to {} as host {}",
        client.cfg.base_url,
        client.host
    );
    Ok(std::thread::Builder::new()
        .name("sync".into())
        .spawn(move || run_loop(client))
        .context("spawning sync thread")?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn agent_discovery_reports_names_without_config_values_or_symlinks() {
        let root = tmpdir("agent-discovery");
        let home = root.join("home");
        let bin = home.join(".local/bin");
        fs::create_dir_all(&bin).unwrap();
        let executable = bin.join("codex");
        fs::write(&executable, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let cursor = bin.join("cursor");
        fs::write(&cursor, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&cursor, fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir_all(home.join(".codex")).unwrap();
        fs::write(
            home.join(".codex/config.toml"),
            "[mcp_servers.github]\nurl = 'https://secret.example'\n[mcp_servers.\"/Users/private/work\"]\ncommand = 'secret'\n",
        )
        .unwrap();
        fs::create_dir_all(home.join(".cursor")).unwrap();
        fs::write(
            home.join(".cursor/mcp.json"),
            r#"{"mcpServers":{"docs":{"command":"secret"},"https://private.example/mcp":{"url":"secret"},"C:\\Users\\private":{"command":"secret"}}}"#,
        )
        .unwrap();
        fs::create_dir_all(home.join(".agents/skills/review")).unwrap();
        fs::write(
            home.join(".agents/skills/review/SKILL.md"),
            "secret instructions",
        )
        .unwrap();
        fs::create_dir_all(home.join(".pi/agent")).unwrap();
        std::os::unix::fs::symlink(home.join(".agents/skills"), home.join(".pi/agent/skills"))
            .unwrap();
        fs::create_dir_all(home.join(".gemini/extensions/workspace")).unwrap();
        fs::write(
            home.join(".gemini/extensions/workspace/gemini-extension.json"),
            r#"{"mcpServers":{"search":{"env":{"TOKEN":"secret"}}}}"#,
        )
        .unwrap();
        fs::create_dir_all(home.join(".gemini/extensions/not-extension")).unwrap();
        fs::write(
            home.join(".gemini/extensions/not-extension/SKILL.md"),
            "ignored",
        )
        .unwrap();
        fs::create_dir_all(home.join(".claude/agents")).unwrap();
        fs::write(home.join(".claude/agents/reviewer.md"), "secret prompt").unwrap();
        fs::write(
            home.join(".claude/settings.json"),
            r#"{"enabledPlugins":{"audit@marketplace":true,"off@marketplace":false}}"#,
        )
        .unwrap();
        fs::create_dir_all(home.join(".config/amp")).unwrap();
        fs::write(
            home.join(".config/amp/settings.json"),
            r#"{"amp.mcpServers":{"db":{"command":"secret"}}}"#,
        )
        .unwrap();
        fs::create_dir_all(home.join(".config/opencode/plugins")).unwrap();
        fs::write(
            home.join(".config/opencode/plugins/trace.ts"),
            "secret plugin",
        )
        .unwrap();
        fs::create_dir_all(home.join(".maestro/plugins/audit/.plugin")).unwrap();
        fs::write(
            home.join(".maestro/plugins/audit/.plugin/plugin.json"),
            "secret plugin",
        )
        .unwrap();
        fs::write(
            home.join(".maestro/plugins/audit/mcp.json"),
            r#"{"mcpServers":{"pluginsearch":{"command":"secret"}}}"#,
        )
        .unwrap();
        fs::create_dir_all(home.join(".maestro/plugins/convention")).unwrap();
        fs::create_dir_all(home.join(".composer/skills/review")).unwrap();
        fs::write(
            home.join(".composer/skills/review/SKILL.md"),
            "secret skill",
        )
        .unwrap();
        fs::write(
            home.join(".maestro/config.toml"),
            "[mcp_servers.managed]\nurl = 'https://secret.example'\n",
        )
        .unwrap();
        let (clis, servers, assets) = collect_agent_discovery_from(&[home.clone()], &[]);
        assert_eq!(
            clis,
            vec![
                DeviceAgentCLI {
                    name: "codex".into()
                },
                DeviceAgentCLI {
                    name: "cursor".into()
                },
            ]
        );
        assert_eq!(
            servers,
            vec![
                DeviceMCPServer {
                    client: "amp".into(),
                    name: "db".into(),
                    source: ".config/amp/settings.json".into(),
                    transport: "stdio".into()
                },
                DeviceMCPServer {
                    client: "codex".into(),
                    name: "github".into(),
                    source: ".codex/config.toml".into(),
                    transport: "remote".into()
                },
                DeviceMCPServer {
                    client: "cursor".into(),
                    name: "docs".into(),
                    source: ".cursor/mcp.json".into(),
                    transport: "stdio".into()
                },
                DeviceMCPServer {
                    client: "gemini".into(),
                    name: "search".into(),
                    source: ".gemini/extensions/*/gemini-extension.json".into(),
                    transport: "unknown".into()
                },
                DeviceMCPServer {
                    client: "maestro".into(),
                    name: "managed".into(),
                    source: ".maestro/config.toml".into(),
                    transport: "remote".into()
                },
                DeviceMCPServer {
                    client: "maestro".into(),
                    name: "pluginsearch".into(),
                    source: ".maestro/plugins/*/mcp.json".into(),
                    transport: "stdio".into()
                },
            ]
        );
        let serialized = serde_json::to_string(&servers).unwrap();
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("/Users/private/work"));
        assert!(!serialized.contains("https://private.example/mcp"));
        assert!(!serialized.contains("C:\\\\Users"));
        assert!(
            assets
                .iter()
                .any(|item| item.client == "codex" && item.kind == "config")
        );
        assert!(
            assets.iter().any(|item| item.client == "agents"
                && item.kind == "skill"
                && item.name == "review")
        );
        assert!(assets.iter().any(|item| item.client == "claude"
            && item.kind == "agent"
            && item.name == "reviewer"));
        assert!(assets.iter().any(|item| item.client == "claude"
            && item.kind == "plugin"
            && item.name == "audit@marketplace"));
        assert!(assets.iter().any(|item| item.client == "opencode"
            && item.kind == "plugin"
            && item.name == "trace"));
        assert!(
            assets.iter().any(|item| item.client == "maestro"
                && item.kind == "plugin"
                && item.name == "audit")
        );
        assert!(
            assets.iter().any(|item| item.client == "maestro"
                && item.kind == "skill"
                && item.name == "review")
        );
        assert!(assets.iter().any(|item| item.client == "maestro"
            && item.kind == "plugin"
            && item.name == "convention"));
        assert!(!assets.iter().any(|item| item.name == "off@marketplace"));
        assert!(!assets.iter().any(|item| item.name == "not-extension"));
        assert!(
            !assets
                .iter()
                .any(|item| item.client == "pi" && item.name == "review")
        );
        assert!(!serde_json::to_string(&assets).unwrap().contains("secret"));
        fs::remove_file(home.join(".cursor/mcp.json")).unwrap();
        std::os::unix::fs::symlink(
            home.join(".codex/config.toml"),
            home.join(".cursor/mcp.json"),
        )
        .unwrap();
        assert_eq!(collect_agent_discovery_from(&[home], &[]).1.len(), 5);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn project_discovery_is_bounded_and_hides_paths_and_values() {
        let root =
            std::env::temp_dir().join(format!("merlin-project-discovery-{}", std::process::id()));
        let project = root.join("customer-private");
        fs::create_dir_all(project.join(".cursor")).unwrap();
        fs::create_dir_all(project.join(".opencode")).unwrap();
        fs::create_dir_all(project.join(".agents")).unwrap();
        fs::create_dir_all(project.join(".claude/skills/review")).unwrap();
        fs::create_dir_all(project.join(".maestro/plugins/audit")).unwrap();
        fs::write(
            project.join(".maestro/plugins/audit/mcp.json"),
            r#"{"mcpServers":{"pluginsearch":{"url":"https://private.example/mcp"}}}"#,
        )
        .unwrap();
        fs::write(project.join(".claude/settings.json"), r#"{"enabledPlugins":{"audit@marketplace":true,"off@marketplace":false},"secret":"private-secret"}"#).unwrap();
        fs::write(
            project.join(".cursor/mcp.json"),
            r#"{"mcpServers":{"docs":{"command":"private-secret"}}}"#,
        )
        .unwrap();
        fs::write(
            project.join(".opencode/opencode.json"),
            r#"{"mcp":{"code-search":{"url":"https://private.example/mcp"}},"secret":"private-secret"}"#,
        )
        .unwrap();
        fs::write(
            project.join(".agents/mcp.json"),
            r#"{"mcpServers":{"agent-search":{"command":"private-secret"}}}"#,
        )
        .unwrap();
        fs::write(
            project.join(".claude/skills/review/SKILL.md"),
            "private-secret",
        )
        .unwrap();
        let (servers, assets) = collect_project_agent_discovery(std::slice::from_ref(&root));
        assert!(servers.iter().any(|item| item.name == "docs"
            && item.source == "project/.cursor/mcp.json"
            && item.transport == "stdio"));
        assert!(servers.iter().any(|item| item.name == "pluginsearch"
            && item.source == "project/.maestro/plugins/*/mcp.json"
            && item.transport == "remote"));
        assert!(servers.iter().any(|item| item.client == "opencode"
            && item.name == "code-search"
            && item.source == "project/.opencode/opencode.json"
            && item.transport == "remote"));
        assert!(servers.iter().any(|item| item.client == "agents"
            && item.name == "agent-search"
            && item.source == "project/.agents/mcp.json"
            && item.transport == "stdio"));
        assert!(assets.iter().any(|item| item.client == "opencode"
            && item.kind == "config"
            && item.source == "project/.opencode/opencode.json"));
        assert!(
            assets
                .iter()
                .any(|item| item.name == "review" && item.source == "project/.claude/skills")
        );
        assert!(assets.iter().any(|item| item.name == "audit@marketplace"
            && item.kind == "plugin"
            && item.source == "project/.claude/settings.json"));
        assert!(assets.iter().any(|item| item.name == "audit"
            && item.kind == "plugin"
            && item.source == "project/.maestro/plugins"));
        assert!(!assets.iter().any(|item| item.name == "off@marketplace"));
        let payload = serde_json::to_string(&(servers, assets)).unwrap();
        assert!(!payload.contains("customer-private"));
        assert!(!payload.contains("private-secret"));
        fs::remove_file(project.join(".cursor/mcp.json")).unwrap();
        std::os::unix::fs::symlink(
            project.join(".claude/skills/review/SKILL.md"),
            project.join(".cursor/mcp.json"),
        )
        .unwrap();
        assert!(
            !collect_project_agent_discovery(&[root.clone()])
                .0
                .iter()
                .any(|item| item.name == "docs")
        );
        fs::remove_dir_all(root).unwrap();
    }

    /// Minimal one-shot HTTP responder: reads one request (headers +
    /// content-length body), calls `respond` with (headers, body), writes
    /// back the returned raw response.
    fn mock_server(respond: impl Fn(Vec<u8>, Vec<u8>) -> String + Send + Sync + 'static) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut headers = Vec::new();
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    let trimmed = line.trim_end();
                    if trimmed.is_empty() {
                        break;
                    }
                    if let Some(v) = trimmed.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap();
                    }
                    headers.extend_from_slice(line.as_bytes());
                }
                let mut body = vec![0u8; content_length];
                reader.read_exact(&mut body).unwrap();
                // This fixture handles one request per accepted connection.
                // Tell HTTP/1.1 clients not to reuse a socket that the fixture
                // drops after writing the response.
                let response =
                    respond(headers, body).replacen("\r\n\r\n", "\r\nConnection: close\r\n\r\n", 1);
                stream.write_all(response.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    fn ok_response(status: &str) -> String {
        format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n")
    }

    fn signed_policy_envelope(
        sha: &str,
        body: &str,
        signing_seed: u8,
        required_capabilities: &[&str],
        format: &str,
    ) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let key = ed25519_dalek::SigningKey::from_bytes(&[signing_seed; 32]);
        let payload = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "artifact_sha256": sha,
            "source_policy_sha256": sha,
            "target_platform": "linux",
            "target_agent_version": env!("CARGO_PKG_VERSION"),
            "required_capabilities": required_capabilities,
            "format": format,
            "artifact": base64::engine::general_purpose::STANDARD.encode(body.as_bytes()),
        }))
        .unwrap();
        let mut signed = POLICY_ENVELOPE_DOMAIN.to_vec();
        signed.extend_from_slice(&payload);
        let envelope = serde_json::json!({
            "schema_version": 1,
            "signed_payload": base64::engine::general_purpose::STANDARD.encode(&payload),
            "signatures": [{
                "key_id": policy_public_key_id(&key.verifying_key().to_bytes()),
                "algorithm": "Ed25519",
                "value": base64::engine::general_purpose::STANDARD.encode(key.sign(&signed).to_bytes()),
            }],
        });
        serde_json::to_vec(&envelope).unwrap()
    }

    fn rules_response(sha: &str, body: &str, signing_seed: u8) -> String {
        let response_body =
            signed_policy_envelope(sha, body, signing_seed, &["rules_sync"], "application/yaml");
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.merlin.policy-envelope+json\r\nContent-Length: {}\r\n\r\n{}",
            response_body.len(),
            String::from_utf8(response_body).unwrap()
        )
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("merlin-sync-test-{}-{tag}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_client(base: &str, dir: &Path) -> SyncClient {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        SyncClient::new(
            SyncConfig {
                base_url: base.to_string(),
                key: b"test-key".to_vec(),
                device_id: Some("dev_0123456789abcdef01234567".to_string()),
                device_token: Some("enrollment-token".to_string()),
                policy_public_key: signing_key.verifying_key().to_bytes().to_vec(),
                policy_public_keys: vec![],
                sensor_mode: "test".to_string(),
            },
            dir.join("merlin-events.jsonl"),
            &dir.join("rules.yaml"),
            RulesHandle::new(Rules {
                schema_version: 1,
                rules: vec![],
                doh_resolvers: vec![],
            }),
            "deadbeef".to_string(),
        )
    }

    fn write_segment(dir: &Path, name: &str, lines: &str) -> PathBuf {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        let path = dir.join(name);
        let mut out = fs::File::create(&path).unwrap();
        {
            let mut enc = GzEncoder::new(&mut out, Compression::default());
            enc.write_all(lines.as_bytes()).unwrap();
            enc.finish().unwrap();
        }
        out.sync_all().unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        // Age it past the mid-compression guard.
        let cpath = std::ffi::CString::new(path.display().to_string()).unwrap();
        let past = libc::timespec {
            tv_sec: 1000,
            tv_nsec: 0,
        };
        let times = [past, past];
        unsafe { libc::utimensat(libc::AT_FDCWD, cpath.as_ptr(), times.as_ptr(), 0) };
        path
    }

    #[test]
    fn key_parsing_hex_base64_raw() {
        assert_eq!(parse_key(&"ab".repeat(32)), vec![0xab; 32]);
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"hello-key");
        assert_eq!(parse_key(&b64), b"hello-key");
        assert_eq!(parse_key("raw key with spaces"), b"raw key with spaces");
        assert_eq!(sync_auth_header(b"raw key"), "Bearer 726177206b6579");
    }

    #[test]
    fn signed_policy_accepts_every_advertised_desired_state_capability() {
        let body = "rules: []\ndesired_state:\n  schema: desired_state.v1\n  revision: 1\n  target: {platform: linux}\n  assertions:\n    - assertion_id: screen-lock\n      security.screen_lock: {enabled: true, idle_seconds: 300}\n";
        let sha = sha256_hex(body.as_bytes());
        let required_capabilities = std::iter::once("rules_sync")
            .chain(desired_state::CAPABILITIES.iter().copied())
            .collect::<Vec<_>>();
        let envelope = signed_policy_envelope(
            &sha,
            body,
            7,
            &required_capabilities,
            desired_state::ARTIFACT_FORMAT,
        );
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes()
            .to_vec();

        let verified = decode_policy_envelope(&envelope, Some(&sha), std::iter::once(key))
            .expect("the agent must accept every capability it advertises");

        assert_eq!(verified.artifact, body.as_bytes());
        assert_eq!(verified.format, desired_state::ARTIFACT_FORMAT);

        let unreviewed = signed_policy_envelope(
            &sha,
            body,
            7,
            &["rules_sync", "desired_state.v1", "executor.shell"],
            desired_state::ARTIFACT_FORMAT,
        );
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes()
            .to_vec();
        let error = decode_policy_envelope(&unreviewed, Some(&sha), std::iter::once(key))
            .err()
            .expect("unreviewed executors must stay outside the protocol");
        assert!(error.to_string().contains("unsupported capability"));
    }

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(backoff_secs(0), 2);
        assert!(backoff_secs(1) > backoff_secs(0));
        assert!(backoff_secs(2) > backoff_secs(1));
        assert_eq!(backoff_secs(30), 60);
    }

    #[test]
    fn upload_acks_and_deletes_after_2xx() {
        let dir = tmpdir("ack");
        let base = mock_server(&|headers: Vec<u8>, _| {
            let headers = String::from_utf8_lossy(&headers);
            assert!(headers.starts_with("POST /v1/devices/dev_0123456789abcdef01234567/events "));
            let has_auth = headers.lines().any(|line| {
                let Some((name, value)) = line.split_once(':') else {
                    return false;
                };
                name.eq_ignore_ascii_case("authorization")
                    && value.trim() == "Bearer enrollment-token"
            });
            assert!(
                has_auth,
                "upload request is missing its bearer authorization header"
            );
            ok_response("202 Accepted")
        });
        let client = test_client(&base, &dir);
        let seg = write_segment(
            &dir,
            "merlin-events.20260802-010203.jsonl.gz",
            "{\"kind\":\"exec\"}\n",
        );
        client.upload_pending().unwrap();
        assert!(!seg.exists(), "acked segment must be deleted");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn upload_failure_keeps_segment() {
        let dir = tmpdir("fail");
        let base = mock_server(&|_, _| ok_response("500 Internal Server Error"));
        let client = test_client(&base, &dir);
        let seg = write_segment(
            &dir,
            "merlin-events.20260802-010203.jsonl.gz",
            "{\"kind\":\"exec\"}\n",
        );
        assert!(client.upload_pending().is_err());
        assert!(seg.exists(), "failed upload keeps the segment");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_in_sends_device_identity_and_accepts_empty_queue() {
        let dir = tmpdir("check-in");
        let base = mock_server(|headers, body| {
            let headers = String::from_utf8_lossy(&headers);
            assert!(headers.lines().any(|line| {
                let Some((name, value)) = line.split_once(':') else {
                    return false;
                };
                name.eq_ignore_ascii_case("authorization")
                    && value.trim() == "Bearer enrollment-token"
            }));
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["host"].as_str(), Some("test-host"));
            assert_eq!(body["platform"].as_str(), Some("linux"));
            assert_eq!(body["current_rules_sha256"].as_str(), Some("deadbeef"));
            assert!(body["os_info"].is_object());
            assert_eq!(
                body["os_info"]["architecture"].as_str(),
                Some(std::env::consts::ARCH)
            );
            assert_eq!(
                body["os_info"]["load_average"].as_array().map(Vec::len),
                Some(3)
            );
            assert!(body["os_info"]["os_pretty_name"].is_string());
            assert!(body["os_info"]["cpu_model"].is_string());
            assert!(body["os_info"]["network_interface_details"].is_array());
            assert_eq!(body["posture"]["schema_version"].as_u64(), Some(2));
            assert_eq!(
                body["posture"]["coverage"]["checks_total"].as_u64(),
                Some(4)
            );
            assert!(body["posture"]["checks"]["secure_boot"].is_object());
            let response_body = br#"{"pending_update":null}"#;
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                response_body.len(),
                String::from_utf8_lossy(response_body)
            )
        });
        let mut client = test_client(&base, &dir);
        client.host = "test-host".to_string();
        client.cfg.device_id = Some("dev_0123456789abcdef01234567".to_string());
        client.cfg.device_token = Some("enrollment-token".to_string());
        client.check_in().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_in_applies_and_acknowledges_queued_rules_update() {
        let dir = tmpdir("check-in-update");
        let rules_body = "rules:\n  - name: queued-update\n    action: log\n";
        let target_sha = sha256_hex(rules_body.as_bytes());
        let response_sha = target_sha.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_server = Arc::clone(&calls);
        let base = mock_server(move |_, body| {
            match calls_for_server.fetch_add(1, Ordering::Relaxed) {
                0 => {
                    let response_body = format!(
                        "{{\"pending_update\":{{\"update_id\":\"upd_0123456789abcdef01234567\",\"kind\":\"rules\",\"target_rules_sha256\":\"{response_sha}\"}}}}"
                    );
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        response_body.len(),
                        response_body
                    )
                }
                1 => rules_response(&response_sha, rules_body, 7),
                2 => {
                    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(body["status"].as_str(), Some("applied"));
                    assert_eq!(body["rules_sha256"].as_str(), Some(response_sha.as_str()));
                    ok_response("200 OK")
                }
                call => panic!("unexpected sync request {call}"),
            }
        });
        let mut client = test_client(&base, &dir);
        client.cfg.device_id = Some("dev_0123456789abcdef01234567".to_string());
        client.cfg.device_token = Some("enrollment-token".to_string());
        client.check_in().unwrap();
        assert_eq!(client.current_sha, target_sha);
        assert_eq!(calls.load(Ordering::Relaxed), 3);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[ignore = "requires MERLIN_E2E_BASE_URL, device credentials, and a live server"]
    fn device_lifecycle_against_live_server_on_linux() {
        let base = std::env::var("MERLIN_E2E_BASE_URL").expect("MERLIN_E2E_BASE_URL");
        let device_id = std::env::var("MERLIN_E2E_DEVICE_ID").expect("MERLIN_E2E_DEVICE_ID");
        let device_token =
            std::env::var("MERLIN_E2E_DEVICE_TOKEN").expect("MERLIN_E2E_DEVICE_TOKEN");
        let admin_token = std::env::var("MERLIN_E2E_ADMIN_TOKEN").expect("MERLIN_E2E_ADMIN_TOKEN");
        let key = parse_key(&std::env::var("MERLIN_E2E_SYNC_KEY").expect("MERLIN_E2E_SYNC_KEY"));
        let dir = tmpdir("live-device-lifecycle");
        let ca_pem = fs::read(std::env::var("MERLIN_E2E_CA_CERT").expect("MERLIN_E2E_CA_CERT"))
            .expect("read E2E CA certificate");
        let ca = ureq::tls::Certificate::from_pem(&ca_pem).expect("parse E2E CA certificate");
        let e2e_agent: ureq::Agent = ureq::Agent::config_builder()
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .root_certs(ureq::tls::RootCerts::new_with_certs(&[ca]))
                    .build(),
            )
            .build()
            .into();
        let mut client = SyncClient::new(
            SyncConfig {
                base_url: base.trim_end_matches('/').to_string(),
                key,
                device_id: Some(device_id.clone()),
                device_token: Some(device_token),
                policy_public_key: parse_key(
                    &std::env::var("MERLIN_E2E_POLICY_PUBLIC_KEY")
                        .expect("MERLIN_E2E_POLICY_PUBLIC_KEY"),
                ),
                policy_public_keys: vec![],
                sensor_mode: "test".to_string(),
            },
            dir.join("merlin-events.jsonl"),
            &dir.join("rules.yaml"),
            RulesHandle::new(Rules {
                schema_version: 1,
                rules: vec![],
                doh_resolvers: vec![],
            }),
            "0".repeat(64),
        );
        client.agent = e2e_agent.clone();

        let expected_host = hostname();
        assert!(!expected_host.is_empty());
        let segment = write_segment(
            &dir,
            "merlin-events.20260817-000000.jsonl.gz",
            "{\"schema_version\":1,\"boot_id\":\"managed-e2e\",\"event_id\":\"managed-e2e:1\",\"source\":\"linux-e2e\",\"source_seq\":1,\"kind\":\"exec\"}\n",
        );
        client.upload_pending().expect("live HTTPS segment upload");
        assert!(
            !segment.exists(),
            "server acknowledgement must delete the uploaded segment"
        );
        client.check_in().expect("initial live check-in");

        let admin_auth = format!("Bearer {admin_token}");
        let mut queued = e2e_agent
            .post(&format!(
                "{}/v1/admin/devices/{device_id}/updates",
                base.trim_end_matches('/')
            ))
            .header("Authorization", &admin_auth)
            .send(&[])
            .expect("queue live device update");
        let queued_body = queued.body_mut().read_to_vec().expect("read queued update");
        let queued_json: serde_json::Value =
            serde_json::from_slice(&queued_body).expect("decode queued update");
        let target_sha = queued_json["update"]["target_rules_sha256"]
            .as_str()
            .expect("queued target sha")
            .to_string();
        assert_ne!(target_sha, "0".repeat(64));

        client
            .check_in()
            .expect("live check-in applies and acknowledges policy update");
        assert_eq!(client.current_sha, target_sha);
        assert!(client.synced_marker.exists());

        let mut detail = e2e_agent
            .get(&format!(
                "{}/v1/admin/devices/{device_id}",
                base.trim_end_matches('/')
            ))
            .header("Authorization", &admin_auth)
            .call()
            .expect("read live device detail");
        let detail_body = detail
            .body_mut()
            .read_to_vec()
            .expect("read live device detail");
        let detail_json: serde_json::Value =
            serde_json::from_slice(&detail_body).expect("decode live device detail");
        let device = &detail_json["device"];
        assert_eq!(device["host"].as_str(), Some(expected_host.as_str()));
        assert_eq!(device["platform"].as_str(), Some("linux"));
        assert_eq!(
            device["agent_version"].as_str(),
            Some(env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(device["status"].as_str(), Some("healthy"));
        assert_eq!(
            device["capabilities"].as_array(),
            Some(&vec![
                serde_json::Value::String("segment_upload".to_string()),
                serde_json::Value::String("rules_sync".to_string()),
                serde_json::Value::String("system_inventory".to_string()),
                serde_json::Value::String("file_integrity".to_string()),
                serde_json::Value::String("security_configuration_assessment".to_string()),
                serde_json::Value::String("rootcheck".to_string()),
                serde_json::Value::String("container_inventory".to_string()),
                serde_json::Value::String("cloud_inventory".to_string()),
                serde_json::Value::String("posture_reporting".to_string()),
                serde_json::Value::String("linux_boot_trust_posture".to_string()),
                serde_json::Value::String("desired_state.v1".to_string()),
                serde_json::Value::String("executor.apt".to_string()),
                serde_json::Value::String("executor.systemd".to_string()),
                serde_json::Value::String("executor.sysctl".to_string()),
            ])
        );
        assert!(detail_json["inventory"]["processes"].is_array());
        assert_eq!(
            device["current_rules_sha256"].as_str(),
            Some(target_sha.as_str())
        );
        assert_eq!(detail_json["updates"][0]["kind"].as_str(), Some("rules"));
        assert_eq!(
            detail_json["updates"][0]["status"].as_str(),
            Some("applied")
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rules_applied_only_with_valid_signature() {
        let dir = tmpdir("apply");
        let body = "rules:\n  - name: synced-marker\n    match:\n      path_basename: x\n    action: log\n";
        let sha = sha256_hex(body.as_bytes());
        let base = mock_server(move |_, _| rules_response(&sha, body, 7));
        let mut client = test_client(&base, &dir);
        assert!(client.sync_rules(&sha256_hex(body.as_bytes())).unwrap());
        assert_eq!(client.handle.get().rules.len(), 1);
        assert_eq!(client.handle.get().rules[0].name, "synced-marker");
        assert!(client.synced_marker.exists());
        let mode = fs::metadata(&client.synced_marker).unwrap().permissions();
        assert_eq!(mode.mode() & 0o777, 0o600);
        let (cached, cached_sha) = load_cached_policy(&client.cfg, &dir.join("rules.yaml"))
            .unwrap()
            .expect("verified cached policy");
        assert_eq!(cached_sha, sha256_hex(body.as_bytes()));
        assert_eq!(cached.rules[0].name, "synced-marker");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_cached_policy_keeps_bootstrap_rules() {
        let dir = tmpdir("cache-missing");
        let client = test_client("http://127.0.0.1:1", &dir);
        assert!(
            load_cached_policy(&client.cfg, &dir.join("rules.yaml"))
                .unwrap()
                .is_none()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_cached_policy_is_rejected_on_offline_restart() {
        let dir = tmpdir("cached-tamper");
        let body = "rules:\n  - name: cached\n    action: log\n";
        let sha = sha256_hex(body.as_bytes());
        let base = mock_server(move |_, _| rules_response(&sha, body, 7));
        let mut client = test_client(&base, &dir);
        assert!(client.sync_rules(&sha256_hex(body.as_bytes())).unwrap());
        let mut envelope = fs::read(&client.synced_marker).unwrap();
        let middle = envelope.len() / 2;
        envelope[middle] ^= 1;
        fs::write(&client.synced_marker, envelope).unwrap();
        fs::set_permissions(&client.synced_marker, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_cached_policy(&client.cfg, &dir.join("rules.yaml")).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_window_accepts_new_trusted_key() {
        let dir = tmpdir("key-rotation");
        let body = "rules:\n  - name: rotated-key\n    action: log\n";
        let sha = sha256_hex(body.as_bytes());
        let base = mock_server(move |_, _| rules_response(&sha, body, 8));
        let mut client = test_client(&base, &dir);
        client.cfg.policy_public_keys.push(
            ed25519_dalek::SigningKey::from_bytes(&[8; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        );
        assert!(client.sync_rules(&sha256_hex(body.as_bytes())).unwrap());
        assert_eq!(client.handle.get().rules[0].name, "rotated-key");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rules_rejected_on_bad_signature_and_bad_yaml() {
        let dir = tmpdir("reject");
        let good_body =
            "rules:\n  - name: keepme\n    match:\n      path_basename: x\n    action: log\n";
        let sha = sha256_hex(good_body.as_bytes());
        // Wrong key signs the response.
        let base = mock_server(move |_, _| rules_response(&sha, good_body, 8));
        let mut client = test_client(&base, &dir);
        assert!(
            client
                .sync_rules(&sha256_hex(good_body.as_bytes()))
                .is_err()
        );
        assert!(
            client.handle.get().rules.is_empty(),
            "unverified rules must not apply"
        );

        // Valid signature, unparsable YAML: last-known-good preserved.
        let garbage = "rules: [not, valid";
        let garbage_sha = sha256_hex(garbage.as_bytes());
        let base2 = mock_server(move |_, _| rules_response(&garbage_sha, garbage, 7));
        let mut client2 = test_client(&base2, &dir);
        assert!(!client2.sync_rules(&sha256_hex(garbage.as_bytes())).unwrap());
        assert!(client2.handle.get().rules.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }
}
