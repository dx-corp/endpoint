//! The device posture report every Deixic Endpoint agent sends at check-in
//! (posture schema version 2): one check per key, each pass, finding,
//! unavailable or requires_root with a short reason and a hash of the
//! evidence read, then the findings, a capped risk score and coverage
//! counts. The Linux and Windows collectors build the checks; `summarize`
//! derives the rest the same way for both.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::time::Instant;

use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize, Debug, PartialEq)]
pub struct DevicePosture {
    pub(crate) schema_version: u8,
    pub(crate) collected_at: String,
    pub(crate) overall: &'static str,
    pub(crate) risk_score: u8,
    pub(crate) checks: BTreeMap<&'static str, PostureCheck>,
    pub(crate) findings: Vec<PostureFinding>,
    pub(crate) coverage: PostureCoverage,
}

#[derive(Serialize, Debug, PartialEq)]
pub(crate) struct PostureCheck {
    pub(crate) status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) value: Option<Cow<'static, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) severity: Option<&'static str>,
    pub(crate) detail: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) evidence: Option<PostureEvidence>,
}

#[derive(Serialize, Debug, PartialEq)]
pub(crate) struct PostureEvidence {
    pub(crate) source: &'static str,
    pub(crate) privilege: &'static str,
    pub(crate) confidence: &'static str,
    pub(crate) observed_at: String,
    pub(crate) evidence_hash: String,
    pub(crate) redactions: [&'static str; 1],
}

#[derive(Serialize, Debug, PartialEq)]
pub(crate) struct PostureFinding {
    pub(crate) id: &'static str,
    pub(crate) check: &'static str,
    pub(crate) severity: &'static str,
    pub(crate) detail: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) evidence_hash: Option<String>,
}

#[derive(Serialize, Debug, PartialEq)]
pub(crate) struct PostureCoverage {
    pub(crate) provider: &'static str,
    pub(crate) root: bool,
    pub(crate) checks_total: u8,
    pub(crate) checks_available: u8,
    pub(crate) checks_unavailable: u8,
    pub(crate) checks_requires_root: u8,
    pub(crate) network_extension: &'static str,
    pub(crate) checks_with_evidence: u8,
    pub(crate) redacted_fields: u8,
    pub(crate) collection_duration_ms: u64,
    pub(crate) max_age_seconds: u16,
    pub(crate) capabilities: Vec<&'static str>,
}

/// What a collector says about itself in the coverage section.
pub(crate) struct Collector {
    pub(crate) provider: &'static str,
    /// Whether the collector read with administrative rights.
    pub(crate) root: bool,
    pub(crate) max_age_seconds: u16,
    pub(crate) capabilities: Vec<&'static str>,
    /// When collection started, for `collection_duration_ms`.
    pub(crate) started: Instant,
}

/// A check whose source could not be read: `unavailable` or `requires_root`.
pub(crate) fn unavailable_check(status: &'static str, detail: &'static str) -> PostureCheck {
    PostureCheck {
        status,
        value: None,
        severity: None,
        detail,
        evidence: None,
    }
}

/// Evidence for a value read: its hash, never the value itself.
pub(crate) fn evidence(
    source: &'static str,
    privilege: &'static str,
    confidence: &'static str,
    observed_at: &str,
    raw: &[u8],
) -> PostureEvidence {
    PostureEvidence {
        source,
        privilege,
        confidence,
        observed_at: observed_at.to_string(),
        evidence_hash: sha256_hex(raw),
        redactions: ["raw_evidence"],
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The findings, risk score (each finding's weight, capped at 100), overall
/// state and coverage counts for `checks`.
pub(crate) fn summarize(
    checks: BTreeMap<&'static str, PostureCheck>,
    observed_at: String,
    collector: Collector,
    risk_weight: impl Fn(&str) -> u8,
) -> DevicePosture {
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
            provider: collector.provider,
            root: collector.root,
            checks_total: checks.len() as u8,
            checks_available,
            checks_unavailable,
            checks_requires_root,
            network_extension: "not_applicable",
            checks_with_evidence,
            redacted_fields: checks_with_evidence,
            collection_duration_ms: collector.started.elapsed().as_millis().min(120_000) as u64,
            max_age_seconds: collector.max_age_seconds,
            capabilities: collector.capabilities,
        },
        checks,
    }
}
