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
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

mod check_in_wire;
mod container_discovery;
use check_in_wire::DeviceCheckInRequest;

mod project_discovery;
use container_discovery::collect_container_agent_discovery;
pub(crate) use container_discovery::scan_ai_locations_in_root;
use project_discovery::{collect_project_agent_discovery, configured_agent_workspace_roots};

use anyhow::{Context, Result};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::desired_state::{self, AssertionReceipt};
use crate::manifest::{AiLocation, Format, Scope};
use crate::rules::{Rules, RulesHandle};
use crate::spool;
use crate::{linux_hardening, linux_posture};

const UPLOAD_SCAN_INTERVAL: Duration = Duration::from_secs(2);
/// The collection capabilities this build announces at check-in; every one
/// belongs to a manifest collector (the manifest tests check this).
pub(crate) const CHECK_IN_CAPABILITIES: &[&str] = &[
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
    "policy_dns",
];

/// Everything this build announces at check-in: the collection capabilities
/// and the desired-state ones. They select the manifest's active collectors
/// for the server and for the local screen alike.
pub(crate) fn check_in_capabilities() -> Vec<&'static str> {
    CHECK_IN_CAPABILITIES
        .iter()
        .chain(desired_state::CAPABILITIES)
        .copied()
        .collect()
}

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
/// Pending segments above this many bytes are evicted oldest first, so a
/// device that cannot upload never fills its disk (dev-desktop held 22 GB).
/// Overridden by MERLIN_SPOOL_MAX_BYTES.
const DEFAULT_SPOOL_MAX_BYTES: u64 = 2 << 30;
/// Rejected or pre-enrollment segments kept for inspection, oldest dropped
/// first past either bound.
const MAX_QUARANTINED_SEGMENTS: usize = 64;
const MAX_QUARANTINED_BYTES: u64 = 256 << 20;

/// A status no retry of the same bytes can change: the server read the
/// segment and refused it (malformed, too large, wrong type, unprocessable).
/// Everything else, including auth failures (401/403, e.g. a revoked token),
/// not found, rate limits and 5xx, keeps the segment for the backoff loop:
/// quarantining on those would throw away data a later attempt could send.
pub(crate) fn permanent_rejection(status: u16) -> bool {
    matches!(status, 400 | 413 | 415 | 422)
}
/// Records which device identity this spool belongs to and since when.
const DEVICE_MARKER: &str = ".merlin-device";

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
        "policy_dns",
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

#[derive(Serialize, Deserialize, Debug, PartialEq, Ord, PartialOrd, Eq, Clone)]
struct DeviceAgentCLI {
    name: String,
}

// `location` is empty on the device itself (the server reads absent as host)
// and container:<image> for a finding inside a running container.
#[derive(Serialize, Deserialize, Debug, PartialEq, Ord, PartialOrd, Eq, Clone)]
struct DeviceMCPServer {
    client: String,
    name: String,
    source: String,
    transport: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    location: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Ord, PartialOrd, Eq, Clone)]
struct DeviceAgentAsset {
    client: String,
    kind: String,
    name: String,
    source: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    location: String,
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
    /// The container's init process on this host while it runs; used to read
    /// its file system for AI tools, never sent.
    #[serde(skip)]
    init_pid: u32,
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
    if s.len() >= 32 && s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit()) {
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
    /// Unix seconds this spool's device identity started; segments named
    /// earlier were recorded before enrollment and are never uploaded.
    not_before: Option<i64>,
    spool_max_bytes: u64,
    /// Whether the last check-in succeeded (logs the first success and each
    /// recovery once).
    checked_in: bool,
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
            not_before: None,
            spool_max_bytes: std::env::var("MERLIN_SPOOL_MAX_BYTES")
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .filter(|v| *v > 0)
                .unwrap_or(DEFAULT_SPOOL_MAX_BYTES),
            checked_in: false,
        }
        .with_device_marker()
    }

    /// Load or create the spool's device marker. A spool first seen with this
    /// device identity starts now; a different identity than the one recorded
    /// (re-enrollment) starts over, so another identity's events never upload.
    fn with_device_marker(mut self) -> Self {
        let Some(device_id) = self.cfg.device_id.clone() else {
            return self;
        };
        let dir = self
            .spool_path
            .parent()
            .unwrap_or(Path::new("."))
            .to_path_buf();
        let marker = dir.join(DEVICE_MARKER);
        let recorded = fs::read_to_string(&marker).ok().and_then(|text| {
            let (id, since) = text.trim().split_once(' ')?;
            (id == device_id)
                .then(|| since.parse::<i64>().ok())
                .flatten()
        });
        let since = recorded.unwrap_or_else(|| {
            // Enrollment writes MERLIN_ENROLLED_AT next to the credential, so
            // a sensor that first runs later still uploads what it recorded
            // after enrolling. Without it, the identity starts now.
            let now = enrollment_start(
                std::env::var("MERLIN_ENROLLED_AT").ok().as_deref(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
            );
            if let Err(error) = fs::write(&marker, format!("{device_id} {now}\n")) {
                log::warn!(
                    "sync: could not record device marker {}: {error}",
                    marker.display()
                );
            } else {
                log::info!(
                    "sync: spool now belongs to {device_id}; earlier segments will not upload"
                );
            }
            now
        });
        self.not_before = Some(since);
        self
    }

    /// Move a segment aside under `quarantine/<why>/`, keeping only the newest
    /// MAX_QUARANTINED_SEGMENTS there. Never uploaded again.
    fn quarantine(dir: &Path, name: &str, path: &Path, why: &str) {
        let target = dir.join("quarantine").join(why);
        if let Err(error) =
            fs::create_dir_all(&target).and_then(|()| fs::rename(path, target.join(name)))
        {
            log::warn!("sync: could not quarantine {name}: {error}; deleting it");
            let _ = fs::remove_file(path);
            return;
        }
        if let Ok(entries) = fs::read_dir(&target) {
            let mut kept: Vec<(PathBuf, u64)> = entries
                .flatten()
                .map(|e| {
                    let len = e.metadata().map(|m| m.len()).unwrap_or(0);
                    (e.path(), len)
                })
                .collect();
            kept.sort();
            let mut bytes: u64 = kept.iter().map(|(_, len)| len).sum();
            let mut count = kept.len();
            for (old, len) in kept {
                if count <= MAX_QUARANTINED_SEGMENTS && bytes <= MAX_QUARANTINED_BYTES {
                    break;
                }
                let _ = fs::remove_file(old);
                count -= 1;
                bytes = bytes.saturating_sub(len);
            }
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

        // Never upload what was recorded before this device identity began.
        if let Some(not_before) = self.not_before {
            segments.retain(|(name, path)| {
                let recorded = segment_unix_secs(name);
                if recorded.is_some_and(|at| at < not_before) {
                    Self::quarantine(dir, name, path, "pre-enrollment");
                    log::info!(
                        "sync: {name} predates this device's enrollment; quarantined, not uploaded"
                    );
                    false
                } else {
                    true
                }
            });
        }

        // Bound what waits on disk: evict the oldest beyond the cap.
        let mut sizes: Vec<u64> = segments
            .iter()
            .map(|(_, path)| fs::metadata(path).map(|m| m.len()).unwrap_or(0))
            .collect();
        let mut total: u64 = sizes.iter().sum();
        let mut evicted = 0usize;
        while total > self.spool_max_bytes && !segments.is_empty() {
            let (name, path) = segments.remove(0);
            total -= sizes.remove(0);
            match fs::remove_file(&path) {
                Ok(()) => evicted += 1,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => evicted += 1,
                Err(error) => log::warn!("sync: could not evict {name}: {error}"),
            }
        }
        if evicted > 0 {
            log::warn!(
                "sync: evicted {evicted} oldest pending segment(s); pending spool was over {} bytes",
                self.spool_max_bytes
            );
        }

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
                .config()
                .http_status_as_error(false)
                .build()
                .header("X-Merlin-Segment", &name)
                .header("Authorization", &authorization)
                .send(&body);
            let (status, error_text) = match response {
                Ok(mut resp) => {
                    let status = resp.status().as_u16();
                    let text = if status == 409 {
                        resp.body_mut()
                            .with_config()
                            .limit(4096)
                            .read_to_string()
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };
                    (status, text)
                }
                Err(ureq::Error::StatusCode(code)) => (code, String::new()),
                Err(e) => return Err(e).context("sync: upload transport error"),
            };
            match status {
                200 | 202 => {
                    // Delete-after-ack: the segment was the buffer. Already
                    // gone is fine (someone moved it); never fail the pass.
                    match fs::remove_file(&path) {
                        Ok(()) => log::info!("sync: uploaded and acked {name}"),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            log::info!("sync: uploaded and acked {name} (already removed)")
                        }
                        Err(error) => {
                            return Err(error)
                                .with_context(|| format!("deleting acked segment {name}"));
                        }
                    }
                }
                // Permanent refusal: set it aside and keep going, so one bad
                // segment never blocks everything recorded after it.
                status if permanent_rejection(status) => {
                    Self::quarantine(dir, &name, &path, "rejected");
                    log::warn!(
                        "sync: server permanently rejected {name} ({status}); quarantined, continuing"
                    );
                }
                // The server already holds newer events for these streams, so
                // these bytes can never be accepted (dev-desktop, 2026-11-09:
                // segments restored after newer ones uploaded). Other 409s,
                // such as re-enrollment required, keep the data.
                409 if is_sequence_replay(&error_text) => {
                    Self::quarantine(dir, &name, &path, "replay");
                    log::warn!(
                        "sync: server already holds newer events than {name}; quarantined as replay, continuing"
                    );
                }
                // Retryable: stop this pass and back off; the segment stays.
                _ => anyhow::bail!("sync: server rejected {name} with status {status}"),
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
        let capabilities = check_in_capabilities();
        let active_collectors = crate::manifest::active_collector_ids(&capabilities);
        let request_body = serde_json::to_vec(&DeviceCheckInRequest {
            host: &self.host,
            platform: "linux",
            agent_version: env!("CARGO_PKG_VERSION"),
            os_version: &os_version,
            kernel_version: &kernel_version,
            sensor_mode: &self.cfg.sensor_mode,
            current_rules_sha256: &self.current_sha,
            status: "healthy",
            capabilities,
            manifest_version: crate::manifest::MANIFEST_VERSION,
            active_collectors,
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
            hardening: linux_hardening::collect(),
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
        stats.f_frsize
    } else {
        stats.f_bsize
    };
    (
        stats.f_blocks.saturating_mul(block_size),
        stats.f_bavail.saturating_mul(block_size),
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
            init_pid: 0,
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
            let init_pid = docker_running_init_pid(&value);
            if let Some(container) = containers.iter_mut().find(|container| container.id == id) {
                container.name = inventory_text(name, 256);
                container.image = inventory_text(image, 256);
                container.state = inventory_text(state, 64);
                container.runtime = "docker".into();
                container.init_pid = init_pid;
            } else {
                containers.push(DeviceContainer {
                    id,
                    name: inventory_text(name, 256),
                    image: inventory_text(image, 256),
                    state: inventory_text(state, 64),
                    runtime: "docker".into(),
                    init_pid,
                });
            }
        }
    }
    containers
}

/// Docker's `State.Pid` while `State.Running` is true; 0 otherwise.
fn docker_running_init_pid(config: &serde_json::Value) -> u32 {
    let state = config.get("State");
    let running = state
        .and_then(|state| state.get("Running"))
        .and_then(serde_json::Value::as_bool)
        == Some(true);
    state
        .and_then(|state| state.get("Pid"))
        .and_then(serde_json::Value::as_u64)
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| running && *pid > 1)
        .unwrap_or(0)
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
    processes.sort_by_key(|left| left.pid);
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
    let containers = collect_containers();
    let (agent_clis, mcp_servers, agent_assets) = collect_agent_discovery(&containers);
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
        containers,
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
fn collect_agent_discovery(
    containers: &[DeviceContainer],
) -> (
    Vec<DeviceAgentCLI>,
    Vec<DeviceMCPServer>,
    Vec<DeviceAgentAsset>,
) {
    let mut discovery = collect_agent_discovery_from(&agent_homes(), AGENT_SYSTEM_BINS);
    let roots = configured_agent_workspace_roots();
    let (project_servers, project_assets) = collect_project_agent_discovery(&roots);
    let (container_servers, container_assets) = collect_container_agent_discovery(containers);
    discovery.1.extend(project_servers);
    discovery.1.extend(container_servers);
    discovery.2.extend(container_assets);
    discovery.1.sort();
    discovery.1.dedup();
    discovery.1.truncate(128);
    discovery.2.extend(project_assets);
    discovery.2.sort();
    discovery.2.dedup();
    discovery.2.truncate(128);
    discovery
}

const AGENT_SYSTEM_BINS: &[&str] = &[
    "/usr/local/bin",
    "/usr/bin",
    "/home/linuxbrew/.linuxbrew/bin",
];

/// The homes to scan, as this process sees `/`: `/root`, then the login
/// homes in `/etc/passwd`, then the directories in `/home` (which also
/// covers directory-service accounts that `/etc/passwd` does not list). At
/// most `MAX_AGENT_HOMES`.
fn agent_homes() -> Vec<PathBuf> {
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
const MAX_AGENT_HOMES: usize = 65;

fn agent_homes_from(passwd: &str, mut listed: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut homes = vec![PathBuf::from("/root")];
    let mut from_passwd: Vec<PathBuf> = passwd
        .lines()
        .take(4096)
        .filter_map(passwd_login_home)
        .filter(|home| home.is_dir())
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
fn passwd_login_home(line: &str) -> Option<PathBuf> {
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

fn collect_agent_discovery_from(
    homes: &[PathBuf],
    system_bins: &[&str],
) -> (
    Vec<DeviceAgentCLI>,
    Vec<DeviceMCPServer>,
    Vec<DeviceAgentAsset>,
) {
    let mut clis = BTreeSet::new();
    let mut servers = BTreeSet::new();
    let mut assets = BTreeSet::new();
    let mut plugin_config_reads = 0;
    let mut cursor_manifest_reads = 0;
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
            clis.insert(DeviceAgentCLI { name: name.into() });
        }
    }
    for home in homes.iter().take(MAX_AGENT_HOMES) {
        for location in AiLocation::linux(Scope::User)
            .filter(|location| !matches!(location.kind, "cli" | "config"))
        {
            match location.format {
                Format::CursorAgent => collect_cursor_agents(home, location, &mut assets),
                Format::CursorPlugin => {
                    collect_cursor_plugins(home, location, &mut assets, &mut cursor_manifest_reads)
                }
                _ => {
                    collect_user_asset_directory(
                        home,
                        location,
                        &mut assets,
                        &mut servers,
                        &mut plugin_config_reads,
                    );
                    if assets.len() >= 128 {
                        break;
                    }
                }
            }
        }
        for location in AiLocation::linux(Scope::User).filter(|location| location.kind == "config")
        {
            let relative = location.path;
            let source = location.label();
            let body = if location.format == Format::CodexToml {
                read_agent_config_beneath(home, relative)
            } else {
                read_agent_config(&home.join(relative))
            };
            let Some(body) = body else {
                continue;
            };
            assets.insert(DeviceAgentAsset {
                location: String::new(),
                client: location.client.into(),
                kind: "config".into(),
                name: "user".into(),
                source: source.clone(),
            });
            if !location.plugins_key.is_empty() {
                for name in json_enabled_plugin_names(&body, location.plugins_key) {
                    assets.insert(DeviceAgentAsset {
                        location: String::new(),
                        client: location.client.into(),
                        kind: "plugin".into(),
                        name,
                        source: source.clone(),
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
                    });
                }
            }
            for (name, transport) in config_mcp_entries(location, &body) {
                if safe_agent_asset_name(&name) {
                    servers.insert(DeviceMCPServer {
                        location: String::new(),
                        client: location.client.into(),
                        name,
                        source: source.clone(),
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

/// MCP servers a config location declares: the entries under its `mcp_keys`
/// for JSON, its `[mcp_servers.<name>]` tables for TOML.
fn config_mcp_entries(location: &AiLocation, body: &str) -> Vec<(String, String)> {
    match location.format {
        Format::Toml | Format::CodexToml => codex_mcp_entries(body),
        _ => json_mcp_entries(body, location.mcp_keys),
    }
}

/// Names under a JSON object key whose value is `true`.
fn json_enabled_plugin_names(body: &str, key: &str) -> Vec<String> {
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

/// One user asset directory: each entry its format accepts becomes an asset,
/// and gemini extensions and plugin MCP files add their servers.
fn collect_user_asset_directory(
    home: &Path,
    location: &AiLocation,
    assets: &mut BTreeSet<DeviceAgentAsset>,
    servers: &mut BTreeSet<DeviceMCPServer>,
    plugin_config_reads: &mut usize,
) {
    let relative = location.path;
    let directory = home.join(relative);
    if !directory
        .symlink_metadata()
        .is_ok_and(|meta| meta.is_dir() && !meta.file_type().is_symlink())
    {
        return;
    }
    let Ok(entries) = fs::read_dir(&directory) else {
        return;
    };
    let regular_file_in = |child: &str, manifest: &str| {
        directory
            .join(child)
            .join(manifest)
            .symlink_metadata()
            .is_ok_and(|meta| meta.is_file() && !meta.file_type().is_symlink())
    };
    for entry in entries.take(256).flatten() {
        let Ok(kind_on_disk) = entry.file_type() else {
            continue;
        };
        let file_name = entry.file_name().to_string_lossy().into_owned();
        let name = match location.format {
            Format::Md if kind_on_disk.is_file() => file_name.strip_suffix(".md"),
            Format::JsTs if kind_on_disk.is_file() => file_name
                .strip_suffix(".js")
                .or_else(|| file_name.strip_suffix(".ts")),
            Format::PluginDir if kind_on_disk.is_dir() => Some(file_name.as_str()),
            Format::SkillDir
                if kind_on_disk.is_dir() && regular_file_in(&file_name, "SKILL.md") =>
            {
                Some(file_name.as_str())
            }
            Format::GeminiExtension
                if kind_on_disk.is_dir()
                    && regular_file_in(&file_name, "gemini-extension.json") =>
            {
                Some(file_name.as_str())
            }
            _ => None,
        };
        let Some(name) = name.filter(|name| safe_agent_asset_name(name)) else {
            continue;
        };
        assets.insert(DeviceAgentAsset {
            location: String::new(),
            client: location.client.into(),
            kind: location.kind.into(),
            name: name.into(),
            source: location.label(),
        });
        if location.format == Format::GeminiExtension {
            if let Some(body) =
                read_agent_config(&directory.join(&file_name).join("gemini-extension.json"))
            {
                for (server, transport) in json_mcp_entries(&body, location.mcp_keys) {
                    if safe_agent_asset_name(&server) {
                        servers.insert(DeviceMCPServer {
                            location: String::new(),
                            client: location.client.into(),
                            name: server,
                            source: format!("{}/*/gemini-extension.json", location.label()),
                            transport,
                        });
                    }
                }
            }
        }
        for config in location.mcp_files {
            if *plugin_config_reads >= 32 {
                break;
            }
            if let Some(body) = read_agent_config(&directory.join(&file_name).join(config)) {
                *plugin_config_reads += 1;
                for (server, transport) in json_mcp_entries(&body, location.mcp_keys) {
                    if safe_agent_asset_name(&server) {
                        servers.insert(DeviceMCPServer {
                            location: String::new(),
                            client: location.client.into(),
                            name: server,
                            source: format!("{}/*/{config}", location.label()),
                            transport,
                        });
                    }
                }
            }
        }
        if assets.len() >= 128 {
            break;
        }
    }
}

/// Open each path component relative to the previous directory. A pathname
/// check followed by `read_dir` would let a user replace a parent with a link
/// while the root collector is traversing it.
fn open_agent_directory(path: &Path) -> Option<fs::File> {
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

fn open_agent_child_dir(parent: &fs::File, name: &[u8]) -> Option<fs::File> {
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

fn open_agent_regular_file_at(parent: &fs::File, name: &str) -> Option<fs::File> {
    let name = CString::new(name).ok()?;
    // Refuse a device node before opening it: inside a container, its root
    // can create one, and opening some devices (a watchdog) has effects.
    // SAFETY: `parent` is open, `name` is NUL terminated and `stat` is a
    // valid out pointer for the call.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFREG
    {
        return None;
    }
    // O_NONBLOCK prevents an attacker from stalling a root collector with a FIFO.
    // SAFETY: `parent` is open during the call and `name` is NUL terminated.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }
    // SAFETY: the successful descriptor is owned solely by this File.
    let file = unsafe { fs::File::from_raw_fd(fd) };
    if !file
        .metadata()
        .ok()
        .is_some_and(|meta| meta.is_file() && meta.len() <= 64 << 10)
    {
        return None;
    }
    Some(file)
}

fn read_agent_file_at(parent: &fs::File, name: &str) -> Option<String> {
    let file = open_agent_regular_file_at(parent, name)?;
    let mut body = String::new();
    file.take((64 << 10) + 1).read_to_string(&mut body).ok()?;
    (body.len() <= 64 << 10).then_some(body)
}

fn read_agent_config_beneath(home: &Path, relative: &str) -> Option<String> {
    let (parent, file) = relative.rsplit_once('/')?;
    let directory = open_agent_directory(&home.join(parent))?;
    read_agent_file_at(&directory, file)
}

/// The first 256 entry names of an open directory. Reads the descriptor
/// itself, so it works without `/proc` (inside a container's root).
fn read_agent_dir_entries(directory: &fs::File) -> Option<Vec<std::ffi::OsString>> {
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
fn collect_cursor_agents(
    home: &Path,
    location: &AiLocation,
    assets: &mut BTreeSet<DeviceAgentAsset>,
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
        if open_agent_regular_file_at(&directory, &format!("{name}.md")).is_some() {
            assets.insert(DeviceAgentAsset {
                location: String::new(),
                client: location.client.into(),
                kind: location.kind.into(),
                name: name.into(),
                source: location.label(),
            });
        }
    }
}

/// Cursor local plugins: a child directory counts when its `plugin.json` or
/// `.cursor-plugin/plugin.json` is a valid bounded manifest with a safe name.
fn collect_cursor_plugins(
    home: &Path,
    location: &AiLocation,
    assets: &mut BTreeSet<DeviceAgentAsset>,
    manifest_reads: &mut usize,
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
            assets.insert(DeviceAgentAsset {
                location: String::new(),
                client: location.client.into(),
                kind: location.kind.into(),
                name,
                source: location.label(),
            });
        }
    }
}

fn codex_enabled_plugin_names(body: &str) -> Vec<String> {
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

fn read_agent_config(path: &std::path::Path) -> Option<String> {
    // Refuse a device node or FIFO before opening it (see
    // open_agent_regular_file_at).
    if !path.symlink_metadata().is_ok_and(|meta| meta.is_file()) {
        return None;
    }
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
                match client.check_in() {
                    Ok(()) => {
                        // One line a person can look for, on the first
                        // success and again after any failure.
                        if !client.checked_in {
                            log::info!(
                                "sync: checked in as {} to {}",
                                client.cfg.device_id.as_deref().unwrap_or(&client.host),
                                client.cfg.base_url
                            );
                            client.checked_in = true;
                        }
                    }
                    Err(e) => {
                        log::warn!("sync: device check-in failed: {e:#}");
                        client.checked_in = false;
                        failed = true;
                    }
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
    std::thread::Builder::new()
        .name("sync".into())
        .spawn(move || run_loop(client))
        .context("spawning sync thread")
}

/// Whether a 409 body is the sync server's "telemetry sequence replay"
/// refusal (`{"error":"telemetry sequence replay"}`).
fn is_sequence_replay(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned))
        .is_some_and(|e| e == "telemetry sequence replay")
}

/// When this spool's device identity began: the enrollment time the enroll
/// script recorded, else now. Never later than now.
fn enrollment_start(enrolled_at: Option<&str>, now: i64) -> i64 {
    enrolled_at
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|v| *v > 0 && *v <= now)
        .unwrap_or(now)
}

/// The local wall-clock time a segment's name records
/// (`<base>.yyyyMMdd-HHmmss.jsonl[.gz]`), as Unix seconds.
fn segment_unix_secs(name: &str) -> Option<i64> {
    let stamp = name
        .trim_end_matches(".gz")
        .trim_end_matches(".jsonl")
        .rsplit('.')
        .next()?;
    let (date, time) = stamp.split_once('-')?;
    if date.len() != 8
        || time.len() != 6
        || !date.bytes().chain(time.bytes()).all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let num = |s: &str| s.parse::<i32>().ok();
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_year = num(&date[0..4])? - 1900;
    tm.tm_mon = num(&date[4..6])? - 1;
    tm.tm_mday = num(&date[6..8])?;
    tm.tm_hour = num(&time[0..2])?;
    tm.tm_min = num(&time[2..4])?;
    tm.tm_sec = num(&time[4..6])?;
    tm.tm_isdst = -1;
    let secs = unsafe { libc::mktime(&mut tm) };
    (secs != -1).then_some(secs as i64)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "sync/posture_wire_tests.rs"]
mod posture_wire_tests;
