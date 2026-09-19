import CryptoKit
import Foundation

/// The bounded posture contract sent with a managed-device heartbeat. The
/// report intentionally contains summaries and finding identifiers rather
/// than raw command output or TCC/profile contents.
struct DevicePostureReport: Encodable, Sendable {
    let schemaVersion: Int
    let collectedAt: String
    let overall: String
    let riskScore: Int
    let checks: [String: DevicePostureCheck]
    let findings: [DevicePostureFinding]
    let coverage: DevicePostureCoverage

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case collectedAt = "collected_at"
        case overall
        case riskScore = "risk_score"
        case checks, findings, coverage
    }
}

struct DevicePostureCheck: Encodable, Sendable {
    let status: String
    let value: String
    let severity: String
    let detail: String
    let evidence: DevicePostureEvidence
}

struct DevicePostureEvidence: Encodable, Sendable {
    let source: String
    let privilege: String
    let confidence: String
    let observedAt: String
    let evidenceHash: String
    let redactions: [String]

    enum CodingKeys: String, CodingKey {
        case source, privilege, confidence
        case observedAt = "observed_at"
        case evidenceHash = "evidence_hash"
        case redactions
    }
}

struct DevicePostureFinding: Encodable, Sendable {
    let id: String
    let check: String
    let severity: String
    let detail: String
    let evidenceHash: String

    enum CodingKeys: String, CodingKey {
        case id, check, severity, detail
        case evidenceHash = "evidence_hash"
    }
}

struct DevicePostureCoverage: Encodable, Sendable {
    let provider: String
    let root: Bool
    let checksTotal: Int
    let checksAvailable: Int
    let checksUnavailable: Int
    let checksRequiresRoot: Int
    let networkExtension: String
    let checksWithEvidence: Int
    let redactedFields: Int
    let collectionDurationMs: Int
    let maxAgeSeconds: Int
    let capabilities: [String]

    enum CodingKeys: String, CodingKey {
        case provider, root
        case checksTotal = "checks_total"
        case checksAvailable = "checks_available"
        case checksUnavailable = "checks_unavailable"
        case checksRequiresRoot = "checks_requires_root"
        case networkExtension = "network_extension"
        case checksWithEvidence = "checks_with_evidence"
        case redactedFields = "redacted_fields"
        case collectionDurationMs = "collection_duration_ms"
        case maxAgeSeconds = "max_age_seconds"
        case capabilities
    }
}

private func postureSeverity(for check: String) -> String {
    switch check {
    case "filevault": return "critical"
    case "sip", "gatekeeper", "authenticated_root", "secure_boot", "boot_args": return "high"
    case "firewall", "software_updates", "mdm", "sysext", "eventtaps": return "medium"
    case "proxy", "profiles", "loginhooks", "tcc", "filevault_users": return "medium"
    default:
        if check.hasPrefix("launchd/") { return "high" }
        return "low"
    }
}

private func postureStatus(value: String, isFinding: Bool) -> String {
    if isFinding { return "finding" }
    let normalized = value.lowercased()
    if normalized == "unavailable" { return "unavailable" }
    if normalized == "requires root" || normalized == "requires_root" { return "requires_root" }
    if normalized == "unknown" { return "unknown" }
    return "pass"
}

private func postureRiskPoints(_ severity: String) -> Int {
    switch severity {
    case "critical": return 40
    case "high": return 25
    case "medium": return 12
    default: return 5
    }
}

private func postureEvidenceSource(for check: String) -> String {
    switch check {
    case "sip", "gatekeeper", "filevault", "authenticated_root", "secure_boot", "boot_args":
        return "security_tool"
    case "firewall", "firewall_rules":
        return "application_firewall"
    case "mdm", "profiles":
        return "device_management"
    case "tcc":
        return "tcc_metadata"
    case "software_updates":
        return "software_update"
    case "proxy", "dns", "router":
        return "system_configuration"
    case "sysext":
        return "system_extension_inventory"
    case "launchd":
        return "launchd_inventory"
    case "eventtaps":
        return "event_tap_api"
    default:
        if check.hasPrefix("launchd/") || check.hasPrefix("launchd@") {
            return "launchd_inventory"
        }
        if check == "filevault_users" {
            return "filevault_metadata"
        }
        return "posture_sweep"
    }
}

private func postureRedactions(for source: String) -> [String] {
    switch source {
    case "tcc_metadata":
        return ["tcc_database_rows", "account_names", "raw_identity"]
    case "device_management":
        return ["profile_payloads", "account_names"]
    case "software_update":
        return ["package_names", "download_urls"]
    case "launchd_inventory":
        return ["program_arguments", "plist_payloads"]
    default:
        return ["raw_command_output"]
    }
}

private func postureEvidence(
    check: String,
    value: String,
    detail: String,
    collectedAt: String,
    root: Bool
) -> DevicePostureEvidence {
    let source = postureEvidenceSource(for: check)
    let normalized = "merlin-posture-v2\n\(check)\n\(value)\n\(detail)"
    let hash = SHA256.hash(data: Data(normalized.utf8)).map { String(format: "%02x", $0) }.joined()
    let normalizedValue = value.lowercased()
    let privilege: String
    if normalizedValue == "requires root" || normalizedValue == "requires_root" {
        privilege = "root"
    } else if check == "tcc" {
        privilege = "full_disk_access_optional"
    } else {
        privilege = root ? "root" : "user"
    }
    let confidence: String
    if normalizedValue == "unavailable" || normalizedValue == "unknown" {
        confidence = "low"
    } else if privilege == "root" && !root {
        confidence = "medium"
    } else {
        confidence = "high"
    }
    return DevicePostureEvidence(
        source: source,
        privilege: privilege,
        confidence: confidence,
        observedAt: collectedAt,
        evidenceHash: hash,
        redactions: postureRedactions(for: source)
    )
}

/// Convert the legacy sweep snapshot into the versioned managed-heartbeat
/// report. Keeping this adapter separate lets existing JSONL posture events
/// remain unchanged while the server gets a point-in-time fleet signal.
func makeDevicePostureReport(
    snapshot: PostureSnapshot,
    provider: String = "posture-sweep",
    root: Bool = geteuid() == 0,
    networkExtension: String = networkExtensionCapability().state
) -> DevicePostureReport {
    let collectedAt = String(format: "%.3f", Date().timeIntervalSince1970)
    let keys = Set(snapshot.values.keys).union(snapshot.findings.keys).sorted()
    var checks: [String: DevicePostureCheck] = [:]
    var findings: [DevicePostureFinding] = []
    var riskScore = 0

    for key in keys {
        let value = snapshot.values[key] ?? snapshot.findings[key] ?? "unknown"
        let findingDetail = snapshot.findings[key]
        let severity = postureSeverity(for: key)
        let status = postureStatus(value: value, isFinding: findingDetail != nil)
        let evidence = postureEvidence(
            check: key, value: value, detail: findingDetail ?? "",
            collectedAt: collectedAt, root: root
        )
        checks[key] = DevicePostureCheck(
            status: status,
            value: String(value.prefix(512)),
            severity: findingDetail == nil ? "" : severity,
            detail: String((findingDetail ?? "").prefix(512)),
            evidence: evidence
        )
        if let findingDetail {
            riskScore = min(100, riskScore + postureRiskPoints(severity))
            findings.append(DevicePostureFinding(
                id: key,
                check: key.split(separator: "/", maxSplits: 1).first.map(String.init) ?? key,
                severity: severity,
                detail: String(findingDetail.prefix(512)),
                evidenceHash: evidence.evidenceHash
            ))
        }
    }

    let unavailable = checks.values.filter { $0.status == "unavailable" }.count
    let requiresRoot = checks.values.filter { $0.status == "requires_root" }.count
    let available = checks.count - unavailable - requiresRoot
    let overall: String
    if riskScore >= 50 {
        overall = "at_risk"
    } else if riskScore > 0 {
        overall = "degraded"
    } else if checks.isEmpty || unavailable + requiresRoot > 0 {
        overall = "unknown"
    } else {
        overall = "secure"
    }

    return DevicePostureReport(
        schemaVersion: 2,
        collectedAt: collectedAt,
        overall: overall,
        riskScore: riskScore,
        checks: checks,
        findings: findings.sorted { $0.id < $1.id },
        coverage: DevicePostureCoverage(
            provider: provider,
            root: root,
            checksTotal: checks.count,
            checksAvailable: max(0, available),
            checksUnavailable: unavailable,
            checksRequiresRoot: requiresRoot,
            networkExtension: networkExtension,
            checksWithEvidence: checks.count,
            redactedFields: checks.values.reduce(0) { $0 + $1.evidence.redactions.count },
            collectionDurationMs: snapshot.collectionDurationMs ?? 0,
            maxAgeSeconds: 300,
            capabilities: [
                "native_security_tools",
                "system_configuration",
                "device_management_metadata",
                "redacted_evidence_hashes",
                "persistence_inventory",
                "endpoint_security_optional",
                "network_extension_optional",
            ]
        )
    )
}
