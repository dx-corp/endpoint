//! Bounded Linux boot-trust evidence for managed device check-ins.
//!
//! This collector is deliberately read-only. It reports normalized states and
//! hashes of the underlying kernel evidence; raw EFI variables, TPM event logs,
//! and kernel policy values never leave the device.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest, Sha256};

const MAX_EFI_VARIABLE_BYTES: u64 = 64;
const MAX_TEXT_EVIDENCE_BYTES: u64 = 4 << 10;
const MAX_MEASURED_BOOT_BYTES: u64 = 8 << 20;

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
    value: Option<&'static str>,
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
    capabilities: [&'static str; 3],
}

struct EvidencePaths {
    secure_boot_variables: PathBuf,
    tpm_version_major: PathBuf,
    measured_boot_log: PathBuf,
    kernel_lockdown: PathBuf,
}

impl EvidencePaths {
    fn system() -> Self {
        Self {
            secure_boot_variables: PathBuf::from("/sys/firmware/efi/efivars"),
            tpm_version_major: PathBuf::from("/sys/class/tpm/tpm0/tpm_version_major"),
            measured_boot_log: PathBuf::from("/sys/kernel/security/tpm0/binary_bios_measurements"),
            kernel_lockdown: PathBuf::from("/sys/kernel/security/lockdown"),
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
            capabilities: ["secure_boot", "tpm2", "measured_boot"],
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
        value: Some(value),
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
        "kernel_lockdown" => 15,
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
        };
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

        let posture = collect_from(&paths);

        assert_eq!(posture.overall, "secure");
        assert_eq!(posture.risk_score, 0);
        assert!(posture.findings.is_empty());
        assert_eq!(posture.coverage.checks_available, 4);
        assert_eq!(posture.coverage.checks_with_evidence, 4);
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
        assert_eq!(posture.coverage.checks_unavailable, 4);
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
}
