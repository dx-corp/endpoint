//! Bounded Linux boot-trust evidence for managed device check-ins.
//!
//! This collector is deliberately read-only. It reports normalized states and
//! hashes of the underlying kernel evidence; raw EFI variables, TPM event logs,
//! and kernel policy values never leave the device.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest, Sha256};

#[path = "linux_posture_host.rs"]
mod host;

const MAX_EFI_VARIABLE_BYTES: u64 = 64;
const MAX_TEXT_EVIDENCE_BYTES: u64 = 4 << 10;
const MAX_MEASURED_BOOT_BYTES: u64 = 8 << 20;
const MAX_MOUNTINFO_BYTES: u64 = 1 << 20;
const MAX_FIREWALL_OUTPUT_BYTES: u64 = 1 << 20;
const FIREWALL_COMMAND_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_DM_STACK_DEPTH: usize = 8;
const MAX_DM_SLAVES: usize = 16;

#[derive(Serialize, Debug, PartialEq)]
pub struct DevicePosture {
    schema_version: u8,
    collected_at: String,
    overall: &'static str,
    risk_score: u8,
    checks: BTreeMap<&'static str, PostureCheck>,
    findings: Vec<PostureFinding>,
    coverage: PostureCoverage,
}

#[derive(Serialize, Debug, PartialEq)]
struct PostureCheck {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<Cow<'static, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<&'static str>,
    detail: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<PostureEvidence>,
}

#[derive(Serialize, Debug, PartialEq)]
struct PostureEvidence {
    source: &'static str,
    privilege: &'static str,
    confidence: &'static str,
    observed_at: String,
    evidence_hash: String,
    redactions: [&'static str; 1],
}

#[derive(Serialize, Debug, PartialEq)]
struct PostureFinding {
    id: &'static str,
    check: &'static str,
    severity: &'static str,
    detail: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_hash: Option<String>,
}

#[derive(Serialize, Debug, PartialEq)]
struct PostureCoverage {
    provider: &'static str,
    root: bool,
    checks_total: u8,
    checks_available: u8,
    checks_unavailable: u8,
    checks_requires_root: u8,
    network_extension: &'static str,
    checks_with_evidence: u8,
    redacted_fields: u8,
    collection_duration_ms: u64,
    max_age_seconds: u16,
    capabilities: [&'static str; 5],
}

struct EvidencePaths {
    secure_boot_variables: PathBuf,
    tpm_version_major: PathBuf,
    measured_boot_log: PathBuf,
    kernel_lockdown: PathBuf,
    mountinfo: PathBuf,
    sys_dev_block: PathBuf,
    nft_binaries: Vec<PathBuf>,
    iptables_binaries: Vec<PathBuf>,
    host: host::HostPaths,
}

impl EvidencePaths {
    fn system() -> Self {
        Self {
            secure_boot_variables: PathBuf::from("/sys/firmware/efi/efivars"),
            tpm_version_major: PathBuf::from("/sys/class/tpm/tpm0/tpm_version_major"),
            measured_boot_log: PathBuf::from("/sys/kernel/security/tpm0/binary_bios_measurements"),
            kernel_lockdown: PathBuf::from("/sys/kernel/security/lockdown"),
            mountinfo: PathBuf::from("/proc/self/mountinfo"),
            sys_dev_block: PathBuf::from("/sys/dev/block"),
            nft_binaries: ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"]
                .map(PathBuf::from)
                .to_vec(),
            iptables_binaries: ["/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables"]
                .map(PathBuf::from)
                .to_vec(),
            host: host::HostPaths::system(),
        }
    }
}

enum EvidenceRead {
    Data(Vec<u8>),
    Missing,
    RequiresRoot,
    Unavailable,
}

pub fn collect() -> DevicePosture {
    collect_from(&EvidencePaths::system())
}

fn collect_from(paths: &EvidencePaths) -> DevicePosture {
    let started = Instant::now();
    let observed_at = format!("{:.3}", unix_timestamp());
    let privilege = if unsafe { libc::geteuid() } == 0 {
        "root"
    } else {
        "user"
    };
    let mut checks = BTreeMap::new();
    checks.insert(
        "secure_boot",
        secure_boot_check(paths, &observed_at, privilege),
    );
    checks.insert("tpm2", tpm2_check(paths, &observed_at, privilege));
    checks.insert(
        "measured_boot",
        measured_boot_check(paths, &observed_at, privilege),
    );
    checks.insert(
        "kernel_lockdown",
        kernel_lockdown_check(paths, &observed_at, privilege),
    );
    checks.insert(
        "disk_encryption",
        disk_encryption_check(paths, &observed_at, privilege),
    );
    checks.insert("firewall", firewall_check(paths, &observed_at, privilege));
    host::collect(&paths.host, &observed_at, privilege, &mut checks);

    let mut findings = Vec::new();
    let mut risk_score = 0u8;
    for (name, check) in &checks {
        if check.status != "finding" {
            continue;
        }
        let check_name = *name;
        risk_score = risk_score.saturating_add(risk_weight(check_name));
        findings.push(PostureFinding {
            id: check_name,
            check: check_name,
            severity: check.severity.unwrap_or("medium"),
            detail: check.detail,
            evidence_hash: check
                .evidence
                .as_ref()
                .map(|evidence| evidence.evidence_hash.clone()),
        });
    }

    let checks_requires_root = checks
        .values()
        .filter(|check| check.status == "requires_root")
        .count() as u8;
    let checks_unavailable = checks
        .values()
        .filter(|check| check.status == "unavailable")
        .count() as u8;
    let checks_available = checks.len() as u8 - checks_unavailable - checks_requires_root;
    let checks_with_evidence = checks
        .values()
        .filter(|check| check.evidence.is_some())
        .count() as u8;
    let has_high_finding = findings
        .iter()
        .any(|finding| matches!(finding.severity, "high" | "critical"));
    let overall = if checks_available == 0 {
        "unknown"
    } else if has_high_finding {
        "at_risk"
    } else if !findings.is_empty() || checks_available < checks.len() as u8 {
        "degraded"
    } else {
        "secure"
    };

    DevicePosture {
        schema_version: 2,
        collected_at: observed_at,
        overall,
        risk_score: risk_score.min(100),
        findings,
        coverage: PostureCoverage {
            provider: "merlin-linux-boot-trust",
            root: privilege == "root",
            checks_total: checks.len() as u8,
            checks_available,
            checks_unavailable,
            checks_requires_root,
            network_extension: "not_applicable",
            checks_with_evidence,
            redacted_fields: checks_with_evidence,
            collection_duration_ms: started.elapsed().as_millis().min(120_000) as u64,
            max_age_seconds: 300,
            capabilities: [
                "secure_boot",
                "tpm2",
                "measured_boot",
                "disk_encryption",
                "firewall",
            ],
        },
        checks,
    }
}

fn secure_boot_check(
    paths: &EvidencePaths,
    observed_at: &str,
    privilege: &'static str,
) -> PostureCheck {
    let entries = match fs::read_dir(&paths.secure_boot_variables) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            return unavailable_check("requires_root", "Secure Boot evidence requires root access");
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return unavailable_check("unavailable", "Secure Boot EFI evidence is unavailable");
        }
        Err(_) => {
            return unavailable_check("unavailable", "Secure Boot EFI evidence is unreadable");
        }
    };
    let variable = entries.filter_map(Result::ok).find(|entry| {
        entry
            .file_name()
            .to_str()
            .is_some_and(|name| name == "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
    });
    let Some(variable) = variable else {
        return unavailable_check("unavailable", "Secure Boot EFI evidence is unavailable");
    };
    match read_bounded_nofollow(&variable.path(), MAX_EFI_VARIABLE_BYTES) {
        EvidenceRead::Data(bytes) if bytes.len() >= 5 && bytes[4] == 1 => evidence_check(
            "pass",
            "enabled",
            None,
            "UEFI Secure Boot is enabled",
            "efivarfs.secure_boot",
            privilege,
            observed_at,
            &bytes,
        ),
        EvidenceRead::Data(bytes) if bytes.len() >= 5 && bytes[4] == 0 => evidence_check(
            "finding",
            "disabled",
            Some("high"),
            "UEFI Secure Boot is disabled",
            "efivarfs.secure_boot",
            privilege,
            observed_at,
            &bytes,
        ),
        EvidenceRead::Data(bytes) => evidence_check(
            "unknown",
            "unknown",
            None,
            "UEFI Secure Boot state is not recognized",
            "efivarfs.secure_boot",
            privilege,
            observed_at,
            &bytes,
        ),
        EvidenceRead::RequiresRoot => {
            unavailable_check("requires_root", "Secure Boot evidence requires root access")
        }
        EvidenceRead::Missing => {
            unavailable_check("unavailable", "Secure Boot EFI evidence is unavailable")
        }
        EvidenceRead::Unavailable => {
            unavailable_check("unavailable", "Secure Boot EFI evidence is unreadable")
        }
    }
}

fn tpm2_check(paths: &EvidencePaths, observed_at: &str, privilege: &'static str) -> PostureCheck {
    match read_bounded_nofollow(&paths.tpm_version_major, MAX_TEXT_EVIDENCE_BYTES) {
        EvidenceRead::Data(bytes) if normalized_text(&bytes) == "2" => evidence_check(
            "pass",
            "present",
            None,
            "TPM 2 is present",
            "sysfs.tpm_version_major",
            privilege,
            observed_at,
            &bytes,
        ),
        EvidenceRead::Data(bytes) => evidence_check(
            "finding",
            "not_tpm2",
            Some("high"),
            "TPM is present but is not TPM 2",
            "sysfs.tpm_version_major",
            privilege,
            observed_at,
            &bytes,
        ),
        EvidenceRead::RequiresRoot => {
            unavailable_check("requires_root", "TPM version evidence requires root access")
        }
        EvidenceRead::Missing => unavailable_check("unavailable", "TPM evidence is unavailable"),
        EvidenceRead::Unavailable => {
            unavailable_check("unavailable", "TPM version evidence is unreadable")
        }
    }
}

fn measured_boot_check(
    paths: &EvidencePaths,
    observed_at: &str,
    privilege: &'static str,
) -> PostureCheck {
    match read_bounded_nofollow(&paths.measured_boot_log, MAX_MEASURED_BOOT_BYTES) {
        EvidenceRead::Data(bytes) if !bytes.is_empty() => evidence_check(
            "pass",
            "available",
            None,
            "TPM measured-boot event log is available",
            "securityfs.measured_boot_log",
            privilege,
            observed_at,
            &bytes,
        ),
        EvidenceRead::Data(bytes) => evidence_check(
            "finding",
            "empty",
            Some("medium"),
            "TPM measured-boot event log is empty",
            "securityfs.measured_boot_log",
            privilege,
            observed_at,
            &bytes,
        ),
        EvidenceRead::RequiresRoot => unavailable_check(
            "requires_root",
            "Measured-boot evidence requires root access",
        ),
        EvidenceRead::Missing => {
            unavailable_check("unavailable", "Measured-boot evidence is unavailable")
        }
        EvidenceRead::Unavailable => {
            unavailable_check("unavailable", "Measured-boot evidence is unreadable")
        }
    }
}

fn kernel_lockdown_check(
    paths: &EvidencePaths,
    observed_at: &str,
    privilege: &'static str,
) -> PostureCheck {
    match read_bounded_nofollow(&paths.kernel_lockdown, MAX_TEXT_EVIDENCE_BYTES) {
        EvidenceRead::Data(bytes)
            if normalized_text(&bytes).contains("[integrity]")
                || normalized_text(&bytes).contains("[confidentiality]") =>
        {
            evidence_check(
                "pass",
                "enabled",
                None,
                "Kernel lockdown is enabled",
                "securityfs.kernel_lockdown",
                privilege,
                observed_at,
                &bytes,
            )
        }
        EvidenceRead::Data(bytes) if normalized_text(&bytes).contains("[none]") => evidence_check(
            "finding",
            "disabled",
            Some("medium"),
            "Kernel lockdown is disabled",
            "securityfs.kernel_lockdown",
            privilege,
            observed_at,
            &bytes,
        ),
        EvidenceRead::Data(bytes) => evidence_check(
            "unknown",
            "unknown",
            None,
            "Kernel lockdown state is not recognized",
            "securityfs.kernel_lockdown",
            privilege,
            observed_at,
            &bytes,
        ),
        EvidenceRead::RequiresRoot => unavailable_check(
            "requires_root",
            "Kernel lockdown evidence requires root access",
        ),
        EvidenceRead::Missing => {
            unavailable_check("unavailable", "Kernel lockdown evidence is unavailable")
        }
        EvidenceRead::Unavailable => {
            unavailable_check("unavailable", "Kernel lockdown evidence is unreadable")
        }
    }
}

/// Root filesystem encryption: the block device behind `/` (or any device it
/// stacks on, such as LVM on LUKS) is a dm-crypt target (`dm/uuid` starts with
/// `CRYPT-`). Only the fixed target type reaches the evidence hash; device
/// UUIDs and names do not.
fn disk_encryption_check(
    paths: &EvidencePaths,
    observed_at: &str,
    privilege: &'static str,
) -> PostureCheck {
    const SOURCE: &str = "procfs.mountinfo+sysfs.dm";
    let mountinfo = match read_bounded_nofollow(&paths.mountinfo, MAX_MOUNTINFO_BYTES) {
        EvidenceRead::Data(bytes) => bytes,
        EvidenceRead::RequiresRoot => {
            return unavailable_check(
                "requires_root",
                "Disk encryption evidence requires root access",
            );
        }
        _ => {
            return unavailable_check("unavailable", "Disk encryption evidence is unavailable");
        }
    };
    let Some(root_device) = root_device_from_mountinfo(&String::from_utf8_lossy(&mountinfo)) else {
        return unavailable_check("unavailable", "Root filesystem device is not identifiable");
    };
    let mut pending = vec![(root_device, 0usize)];
    let mut seen = BTreeSet::new();
    let mut chain = String::new();
    while let Some((device, depth)) = pending.pop() {
        if depth > MAX_DM_STACK_DEPTH || !seen.insert(device.clone()) {
            continue;
        }
        let dir = paths.sys_dev_block.join(&device);
        if !dir.is_dir() {
            return unavailable_check("unavailable", "Root block device is not visible in sysfs");
        }
        match read_bounded_nofollow(&dir.join("dm/uuid"), MAX_TEXT_EVIDENCE_BYTES) {
            EvidenceRead::Data(bytes) => {
                let uuid = String::from_utf8_lossy(&bytes);
                let kind = uuid.trim().split('-').take(2).collect::<Vec<_>>().join("-");
                chain.push_str(&kind);
                chain.push('\n');
                if uuid.trim().starts_with("CRYPT-") {
                    return evidence_check(
                        "pass",
                        "on",
                        None,
                        "Root filesystem is on an encrypted dm-crypt device",
                        SOURCE,
                        privilege,
                        observed_at,
                        chain.as_bytes(),
                    );
                }
            }
            EvidenceRead::Missing => chain.push_str("plain\n"),
            EvidenceRead::RequiresRoot => {
                return unavailable_check(
                    "requires_root",
                    "Disk encryption evidence requires root access",
                );
            }
            EvidenceRead::Unavailable => {
                return unavailable_check("unavailable", "Disk encryption evidence is unreadable");
            }
        }
        let Ok(slaves) = fs::read_dir(dir.join("slaves")) else {
            continue;
        };
        for slave in slaves.filter_map(Result::ok).take(MAX_DM_SLAVES) {
            if let EvidenceRead::Data(bytes) =
                read_bounded_nofollow(&slave.path().join("dev"), MAX_TEXT_EVIDENCE_BYTES)
            {
                let id = normalized_text(&bytes);
                if is_major_minor(&id) {
                    pending.push((id, depth + 1));
                }
            }
        }
    }
    evidence_check(
        "finding",
        "off",
        Some("critical"),
        "Root filesystem is not on an encrypted dm-crypt device",
        SOURCE,
        privilege,
        observed_at,
        chain.as_bytes(),
    )
}

fn is_major_minor(value: &str) -> bool {
    value.split_once(':').is_some_and(|(major, minor)| {
        [major, minor].iter().all(|part| {
            !part.is_empty() && part.len() <= 8 && part.bytes().all(|b| b.is_ascii_digit())
        })
    })
}

/// Returns the `major:minor` of the topmost mount at `/`.
fn root_device_from_mountinfo(mountinfo: &str) -> Option<String> {
    mountinfo
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let device = fields.nth(2)?;
            (fields.nth(1)? == "/" && is_major_minor(device)).then(|| device.to_string())
        })
        .last()
}

enum FirewallProbe {
    /// Tool ran and reported a filtering input path.
    Active(Vec<u8>),
    /// Tool ran and reported nothing filtering input.
    Inactive(Vec<u8>),
    Denied,
    Failed,
    NotInstalled,
}

/// Host firewall: an nftables input-hook chain with rules or a restrictive
/// policy, or an iptables INPUT chain with rules or a non-ACCEPT policy.
/// The kernel exposes no readable file for rules, so this runs `nft` and
/// `iptables` from fixed paths with a cleared environment, a timeout, and
/// capped output. Both need CAP_NET_ADMIN; without it the check reports
/// `requires_root`. IPv6-only rules (ip6tables) are not inspected.
fn firewall_check(
    paths: &EvidencePaths,
    observed_at: &str,
    privilege: &'static str,
) -> PostureCheck {
    const SOURCE: &str = "netfilter.nft_iptables";
    let probes = [
        probe_firewall(&paths.nft_binaries, &["list", "ruleset"], nft_input_active),
        probe_firewall(
            &paths.iptables_binaries,
            &["-S", "INPUT"],
            iptables_input_active,
        ),
    ];
    let mut inactive: Vec<u8> = Vec::new();
    let (mut saw_inactive, mut denied, mut failed) = (false, false, false);
    for probe in probes {
        match probe {
            FirewallProbe::Active(raw) => {
                return evidence_check(
                    "pass",
                    "enabled",
                    None,
                    "Host firewall has active input filtering",
                    SOURCE,
                    privilege,
                    observed_at,
                    &raw,
                );
            }
            FirewallProbe::Inactive(raw) => {
                saw_inactive = true;
                inactive.extend(raw);
            }
            FirewallProbe::Denied => denied = true,
            FirewallProbe::Failed => failed = true,
            FirewallProbe::NotInstalled => {}
        }
    }
    if denied {
        unavailable_check("requires_root", "Firewall evidence requires root access")
    } else if failed {
        unavailable_check("unavailable", "Firewall evidence is unreadable")
    } else if saw_inactive {
        evidence_check(
            "finding",
            "disabled",
            Some("medium"),
            "Host firewall has no active input filtering",
            SOURCE,
            privilege,
            observed_at,
            &inactive,
        )
    } else {
        unavailable_check("unavailable", "No supported firewall tool is installed")
    }
}

fn probe_firewall(binaries: &[PathBuf], args: &[&str], active: fn(&str) -> bool) -> FirewallProbe {
    let Some(binary) = binaries.iter().find(|path| path.is_file()) else {
        return FirewallProbe::NotInstalled;
    };
    let Ok(mut child) = Command::new(binary)
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return FirewallProbe::Failed;
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return FirewallProbe::Failed;
    };
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout
            .take(MAX_FIREWALL_OUTPUT_BYTES + 1)
            .read_to_end(&mut bytes);
        bytes
    });
    let deadline = Instant::now() + FIREWALL_COMMAND_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    // On timeout the reader is detached: a grandchild may still hold the pipe.
    let Some(status) = status else {
        return FirewallProbe::Failed;
    };
    let bytes = reader.join().unwrap_or_default();
    if !status.success() {
        // nft and iptables exit non-zero with an EPERM message when unprivileged.
        return if unsafe { libc::geteuid() } != 0 {
            FirewallProbe::Denied
        } else {
            FirewallProbe::Failed
        };
    }
    if bytes.len() as u64 > MAX_FIREWALL_OUTPUT_BYTES {
        return FirewallProbe::Failed;
    }
    if active(&String::from_utf8_lossy(&bytes)) {
        FirewallProbe::Active(bytes)
    } else {
        FirewallProbe::Inactive(bytes)
    }
}

fn nft_input_active(ruleset: &str) -> bool {
    let mut in_input_chain = false;
    for line in ruleset.lines().map(str::trim) {
        if in_input_chain {
            if line == "}" {
                in_input_chain = false;
            } else if !line.is_empty() && !line.starts_with("type ") {
                return true;
            }
        }
        if line.starts_with("type filter hook input ") {
            if line.contains("policy drop") || line.contains("policy reject") {
                return true;
            }
            in_input_chain = true;
        }
    }
    false
}

fn iptables_input_active(rules: &str) -> bool {
    rules.lines().any(|line| {
        let line = line.trim();
        line.starts_with("-A INPUT ")
            || (line.starts_with("-P INPUT ") && !line.ends_with(" ACCEPT"))
    })
}

fn evidence_check(
    status: &'static str,
    value: &'static str,
    severity: Option<&'static str>,
    detail: &'static str,
    source: &'static str,
    privilege: &'static str,
    observed_at: &str,
    raw: &[u8],
) -> PostureCheck {
    PostureCheck {
        status,
        value: Some(Cow::Borrowed(value)),
        severity,
        detail,
        evidence: Some(PostureEvidence {
            source,
            privilege,
            confidence: "kernel_reported",
            observed_at: observed_at.to_string(),
            evidence_hash: sha256_hex(raw),
            redactions: ["raw_evidence"],
        }),
    }
}

fn unavailable_check(status: &'static str, detail: &'static str) -> PostureCheck {
    PostureCheck {
        status,
        value: None,
        severity: None,
        detail,
        evidence: None,
    }
}

fn read_bounded_nofollow(path: &Path, max_bytes: u64) -> EvidenceRead {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return EvidenceRead::Missing,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            return EvidenceRead::RequiresRoot;
        }
        Err(_) => return EvidenceRead::Unavailable,
    };
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return EvidenceRead::Unavailable,
    };
    if !metadata.file_type().is_file() {
        return EvidenceRead::Unavailable;
    }
    let mut bytes = Vec::new();
    if file
        .by_ref()
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > max_bytes
    {
        return EvidenceRead::Unavailable;
    }
    EvidenceRead::Data(bytes)
}

fn normalized_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_ascii_lowercase()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn unix_timestamp() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn risk_weight(check: &str) -> u8 {
    match check {
        "secure_boot" => 45,
        "tpm2" => 35,
        "measured_boot" => 20,
        "disk_encryption" => 40,
        "kernel_lockdown" => 15,
        "firewall" => 15,
        "os_updates" => 15,
        "endpoint_protection" => 15,
        "remote_access" => 10,
        "auto_updates" => 5,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NONCE: AtomicU64 = AtomicU64::new(0);

    fn test_paths(name: &str) -> (PathBuf, EvidencePaths) {
        let root = std::env::temp_dir().join(format!(
            "merlin-linux-posture-{name}-{}-{}",
            std::process::id(),
            NONCE.fetch_add(1, Ordering::Relaxed)
        ));
        let efivars = root.join("efivars");
        fs::create_dir_all(&efivars).unwrap();
        let paths = EvidencePaths {
            secure_boot_variables: efivars,
            tpm_version_major: root.join("tpm_version_major"),
            measured_boot_log: root.join("binary_bios_measurements"),
            kernel_lockdown: root.join("lockdown"),
            mountinfo: root.join("mountinfo"),
            sys_dev_block: root.join("sys-dev-block"),
            nft_binaries: vec![root.join("bin/nft")],
            iptables_binaries: vec![root.join("bin/iptables")],
            host: host::HostPaths {
                proc_root: root.join("proc"),
                apt_conf_dir: root.join("apt.conf.d"),
                update_notifier: root.join("updates-available"),
                dnf_automatic_conf: root.join("automatic.conf"),
                timer_wants_dirs: vec![root.join("timers.target.wants")],
                application_dirs: vec![root.join("applications")],
                graphical_markers: vec![root.join("X11-unix")],
            },
        };
        fs::create_dir_all(root.join("bin")).unwrap();
        (root, paths)
    }

    #[test]
    fn passing_kernel_evidence_produces_secure_posture_with_hashed_receipts() {
        let (root, paths) = test_paths("secure");
        fs::write(
            paths
                .secure_boot_variables
                .join("SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"),
            [7, 0, 0, 0, 1],
        )
        .unwrap();
        fs::write(&paths.tpm_version_major, b"2\n").unwrap();
        fs::write(&paths.measured_boot_log, b"bounded event log").unwrap();
        fs::write(
            &paths.kernel_lockdown,
            b"none [integrity] confidentiality\n",
        )
        .unwrap();

        write_mountinfo(&paths, "253:0");
        add_block_device(&paths, "253:0", Some("CRYPT-LUKS2-1-x"), &[]);
        write_script(
            &paths.nft_binaries[0],
            "echo '\ttype filter hook input priority filter; policy drop;'",
        );

        fs::create_dir_all(&paths.host.apt_conf_dir).unwrap();
        fs::write(
            paths.host.apt_conf_dir.join("20auto-upgrades"),
            "APT::Periodic::Unattended-Upgrade \"1\";\n",
        )
        .unwrap();
        fs::write(
            &paths.host.update_notifier,
            "0 updates can be applied immediately.\n",
        )
        .unwrap();
        fs::create_dir_all(paths.host.proc_root.join("7")).unwrap();
        fs::write(paths.host.proc_root.join("7/comm"), "falcon-sensor\n").unwrap();

        let posture = collect_from(&paths);

        assert_eq!(posture.overall, "secure");
        assert_eq!(posture.risk_score, 0);
        assert!(posture.findings.is_empty());
        assert_eq!(posture.coverage.checks_available, 10);
        assert_eq!(posture.coverage.checks_with_evidence, 10);
        for check in posture.checks.values() {
            assert_eq!(check.status, "pass");
            assert_eq!(check.evidence.as_ref().unwrap().evidence_hash.len(), 64);
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn insecure_kernel_evidence_produces_typed_findings_and_bounded_risk() {
        let (root, paths) = test_paths("findings");
        fs::write(
            paths
                .secure_boot_variables
                .join("SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"),
            [7, 0, 0, 0, 0],
        )
        .unwrap();
        fs::write(&paths.tpm_version_major, b"1\n").unwrap();
        fs::write(&paths.measured_boot_log, b"").unwrap();
        fs::write(
            &paths.kernel_lockdown,
            b"[none] integrity confidentiality\n",
        )
        .unwrap();

        let posture = collect_from(&paths);

        assert_eq!(posture.overall, "at_risk");
        assert_eq!(posture.risk_score, 100);
        assert_eq!(posture.findings.len(), 4);
        assert_eq!(posture.checks["secure_boot"].severity, Some("high"));
        assert_eq!(posture.checks["kernel_lockdown"].severity, Some("medium"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn absent_evidence_is_unknown_without_fabricating_findings() {
        let (root, paths) = test_paths("missing");

        let posture = collect_from(&paths);

        assert_eq!(posture.overall, "unknown");
        assert_eq!(posture.risk_score, 0);
        assert!(posture.findings.is_empty());
        assert_eq!(posture.coverage.checks_available, 0);
        assert_eq!(posture.coverage.checks_unavailable, 10);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn symlinked_evidence_leaf_is_never_followed() {
        let (root, paths) = test_paths("nofollow");
        let target = root.join("attacker-controlled");
        fs::write(&target, b"[integrity]").unwrap();
        symlink(&target, &paths.kernel_lockdown).unwrap();

        let posture = collect_from(&paths);

        assert_eq!(posture.checks["kernel_lockdown"].status, "unavailable");
        assert!(posture.checks["kernel_lockdown"].evidence.is_none());
        let _ = fs::remove_dir_all(root);
    }

    fn write_script(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn add_block_device(paths: &EvidencePaths, id: &str, dm_uuid: Option<&str>, slaves: &[&str]) {
        let dir = paths.sys_dev_block.join(id);
        fs::create_dir_all(&dir).unwrap();
        if let Some(uuid) = dm_uuid {
            fs::create_dir_all(dir.join("dm")).unwrap();
            fs::write(dir.join("dm/uuid"), format!("{uuid}\n")).unwrap();
        }
        for slave in slaves {
            let slave_dir = dir.join("slaves").join(format!("dev-{slave}"));
            fs::create_dir_all(&slave_dir).unwrap();
            fs::write(slave_dir.join("dev"), format!("{slave}\n")).unwrap();
        }
    }

    fn write_mountinfo(paths: &EvidencePaths, device: &str) {
        fs::write(
            &paths.mountinfo,
            format!(
                "20 1 {device} / / rw,relatime shared:1 - ext4 /dev/mapper/root rw\n25 20 0:6 / /dev rw - devtmpfs udev rw\n"
            ),
        )
        .unwrap();
    }

    #[test]
    fn root_on_lvm_over_luks_is_encrypted() {
        let (root, paths) = test_paths("luks");
        write_mountinfo(&paths, "253:1");
        add_block_device(&paths, "253:1", Some("LVM-abcdef"), &["253:0"]);
        add_block_device(&paths, "253:0", Some("CRYPT-LUKS2-1234-luks"), &["8:2"]);
        add_block_device(&paths, "8:2", None, &[]);

        let check = disk_encryption_check(&paths, "1", "user");

        assert_eq!(check.status, "pass");
        assert_eq!(check.value.as_deref(), Some("on"));
        assert!(check.evidence.is_some());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn plain_root_device_is_a_critical_finding() {
        let (root, paths) = test_paths("plain-root");
        write_mountinfo(&paths, "8:1");
        add_block_device(&paths, "8:1", None, &[]);

        let check = disk_encryption_check(&paths, "1", "user");

        assert_eq!(check.status, "finding");
        assert_eq!(check.value.as_deref(), Some("off"));
        assert_eq!(check.severity, Some("critical"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn unidentifiable_root_device_is_unavailable_not_a_finding() {
        let (root, paths) = test_paths("anon-root");
        write_mountinfo(&paths, "0:42");

        assert_eq!(
            disk_encryption_check(&paths, "1", "user").status,
            "unavailable"
        );
        let _ = fs::remove_file(&paths.mountinfo);
        assert_eq!(
            disk_encryption_check(&paths, "1", "user").status,
            "unavailable"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn dm_cycle_terminates() {
        let (root, paths) = test_paths("dm-cycle");
        write_mountinfo(&paths, "253:1");
        add_block_device(&paths, "253:1", Some("LVM-a"), &["253:2"]);
        add_block_device(&paths, "253:2", Some("LVM-b"), &["253:1"]);

        assert_eq!(disk_encryption_check(&paths, "1", "user").status, "finding");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn nft_input_policy_and_rules_are_detected() {
        let drop = "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n}";
        let rules = "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t\ttcp dport 22 accept\n\t}\n}";
        let empty = "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n\t\tct state established accept\n\t}\n}";
        assert!(nft_input_active(drop));
        assert!(nft_input_active(rules));
        assert!(!nft_input_active(empty));
        assert!(!nft_input_active(""));
    }

    #[test]
    fn iptables_input_policy_and_rules_are_detected() {
        assert!(iptables_input_active("-P INPUT DROP"));
        assert!(iptables_input_active(
            "-P INPUT ACCEPT\n-A INPUT -p tcp -j DROP"
        ));
        assert!(!iptables_input_active("-P INPUT ACCEPT"));
    }

    #[test]
    fn firewall_check_reads_tool_output_and_reports_honestly() {
        let (root, paths) = test_paths("firewall");
        assert_eq!(firewall_check(&paths, "1", "root").status, "unavailable");

        write_script(&paths.iptables_binaries[0], "echo '-P INPUT ACCEPT'");
        let check = firewall_check(&paths, "1", "root");
        assert_eq!(check.status, "finding");
        assert_eq!(check.severity, Some("medium"));

        write_script(
            &paths.nft_binaries[0],
            "echo 'table inet f {'; echo '  chain input {'; echo '    type filter hook input priority filter; policy drop;'; echo '  }'; echo '}'",
        );
        let check = firewall_check(&paths, "1", "root");
        assert_eq!(check.status, "pass");
        assert_eq!(check.value.as_deref(), Some("enabled"));

        write_script(&paths.nft_binaries[0], "exit 1");
        write_script(&paths.iptables_binaries[0], "exit 1");
        let check = firewall_check(&paths, "1", "root");
        assert!(matches!(check.status, "unavailable" | "requires_root"));
        assert!(check.evidence.is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn firewall_command_timeout_does_not_hang() {
        let (root, paths) = test_paths("firewall-hang");
        write_script(&paths.nft_binaries[0], "sleep 30");
        let started = Instant::now();
        let check = firewall_check(&paths, "1", "root");
        assert_eq!(check.status, "unavailable");
        assert!(started.elapsed() < Duration::from_secs(10));
        let _ = fs::remove_dir_all(root);
    }
}
