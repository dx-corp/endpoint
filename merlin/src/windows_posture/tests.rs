//! Ported from the Go collector's posture_test.go, the spec for Windows
//! posture, with fixed registry, program, process and PowerShell values.

use super::*;
use std::collections::HashMap;
use std::time::UNIX_EPOCH;

#[derive(Clone, Default)]
struct FakeHost {
    values: HashMap<String, u32>,
    denied: Vec<String>,
    failed: Vec<String>,
    programs: Option<Vec<String>>,
    processes: Option<Vec<String>>,
    desktops: Option<Vec<BTreeMap<String, String>>>,
    shell: HashMap<&'static str, String>,
    not_elevated: bool,
}

impl PostureSources for FakeHost {
    fn dword(&self, key: &str, name: &str) -> RegRead {
        let path = format!(r"{key}\{name}");
        if self.denied.contains(&path) {
            return RegRead::Denied;
        }
        if self.failed.contains(&path) {
            return RegRead::Failed;
        }
        self.values
            .get(&path)
            .map_or(RegRead::Missing, |value| RegRead::Found(*value))
    }
    fn programs(&self) -> Option<Vec<String>> {
        self.programs.clone()
    }
    fn processes(&self) -> Option<Vec<String>> {
        self.processes.clone()
    }
    fn user_desktops(&self) -> Option<Vec<BTreeMap<String, String>>> {
        self.desktops.clone()
    }
    fn powershell(&self, expression: &str, _timeout: Duration) -> Option<String> {
        self.shell.get(expression).cloned()
    }
    fn elevated(&self) -> bool {
        !self.not_elevated
    }
}

fn key(prefix: &str, rest: &str) -> String {
    format!("{prefix}{rest}")
}

fn desktop(active: &str, secure: &str, timeout: &str) -> BTreeMap<String, String> {
    [
        ("ScreenSaveActive", active),
        ("ScreenSaverIsSecure", secure),
        ("ScreenSaveTimeOut", timeout),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_string(), value.to_string()))
    .collect()
}

fn hardened() -> FakeHost {
    FakeHost {
        values: [
            (key(FIREWALL_POLICY_KEY, r"DomainProfile\EnableFirewall"), 1),
            (
                key(FIREWALL_POLICY_KEY, r"StandardProfile\EnableFirewall"),
                1,
            ),
            (key(FIREWALL_POLICY_KEY, r"PublicProfile\EnableFirewall"), 1),
            (key(WUAUSERV_KEY, r"\Start"), 3),
            (key(TERMINAL_SERVER_KEY, r"\fDenyTSConnections"), 1),
        ]
        .into_iter()
        .collect(),
        programs: Some(vec!["Microsoft Edge".into(), "Bitwarden 2026.9.0".into()]),
        processes: Some(vec![
            "System".into(),
            "MsMpEng.exe".into(),
            "explorer.exe".into(),
        ]),
        desktops: Some(vec![desktop("1", "1", "600")]),
        shell: [
            (BITLOCKER_EXPRESSION, "On".to_string()),
            (PENDING_UPDATES_EXPRESSION, "0".to_string()),
        ]
        .into_iter()
        .collect(),
        ..FakeHost::default()
    }
}

fn at() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_760_400_000)
}

fn value(posture: &DevicePosture, check: &str) -> String {
    posture.checks[check]
        .value
        .as_deref()
        .unwrap_or_default()
        .to_string()
}

#[test]
fn a_hardened_host_passes_every_check_with_hashed_evidence() {
    let posture = collect(&hardened(), at());
    for check in CHECK_KEYS {
        let found = &posture.checks[check];
        assert_eq!(found.status, "pass", "{check}: {found:?}");
        let hash = &found.evidence.as_ref().unwrap().evidence_hash;
        assert_eq!(hash.len(), 64, "{check}");
    }
    assert_eq!(posture.overall, "secure");
    assert_eq!(posture.risk_score, 0);
    assert_eq!(posture.schema_version, 2);
    assert_eq!(value(&posture, "endpoint_protection"), "Microsoft Defender");
    assert_eq!(value(&posture, "password_manager"), "Bitwarden");
}

#[test]
fn an_exposed_host_reports_findings_with_product_names() {
    let mut host = hardened();
    // A policy value overrides the local "on".
    host.values
        .insert(key(FIREWALL_GPO_KEY, r"PublicProfile\EnableFirewall"), 0);
    host.values
        .insert(key(WINDOWS_UPDATE_GPO, r"\NoAutoUpdate"), 1);
    host.values
        .insert(key(TERMINAL_SERVER_KEY, r"\fDenyTSConnections"), 0);
    host.processes = Some(vec!["AnyDesk.exe".into(), "explorer.exe".into()]);
    host.programs = Some(vec!["Notepad++".into()]);
    host.shell.insert(BITLOCKER_EXPRESSION, "Off".into());
    host.shell.insert(PENDING_UPDATES_EXPRESSION, "7".into());
    host.desktops = Some(vec![desktop("1", "0", "300")]);
    let posture = collect(&host, at());
    for (check, expected) in [
        ("firewall", "disabled"),
        ("auto_updates", "off"),
        ("endpoint_protection", "none"),
        ("remote_access", "Remote Desktop,AnyDesk"),
        ("password_manager", "none"),
        ("disk_encryption", "off"),
        ("os_updates", "7 pending"),
        ("screen_lock", "disabled"),
    ] {
        assert_eq!(posture.checks[check].status, "finding", "{check}");
        assert_eq!(value(&posture, check), expected, "{check}");
    }
    assert_eq!(posture.overall, "at_risk");
    assert_eq!(posture.findings.len(), CHECK_KEYS.len());
    assert_eq!(posture.risk_score, 100);
}

#[test]
fn unreadable_sources_are_unavailable_never_pass() {
    let host = FakeHost {
        denied: vec![key(FIREWALL_GPO_KEY, r"DomainProfile\EnableFirewall")],
        ..FakeHost::default()
    };
    let posture = collect(&host, at());
    assert_eq!(posture.checks["firewall"].status, "requires_root");
    for check in CHECK_KEYS.iter().filter(|check| **check != "firewall") {
        assert_eq!(posture.checks[check].status, "unavailable", "{check}");
    }
    assert_eq!(posture.overall, "unknown");
    assert_eq!(posture.coverage.checks_available, 0);
}

#[test]
fn a_notify_only_update_policy_or_a_disabled_service_is_off() {
    for (path, setting) in [
        (key(WINDOWS_UPDATE_GPO, r"\AUOptions"), 2),
        (key(WUAUSERV_KEY, r"\Start"), 4),
    ] {
        let mut host = hardened();
        host.values.insert(path.clone(), setting);
        let posture = collect(&host, at());
        assert_eq!(posture.checks["auto_updates"].status, "finding", "{path}");
    }
}

#[test]
fn posture_serializes_to_the_server_schema() {
    let body = serde_json::to_value(collect(&hardened(), at())).unwrap();
    assert_eq!(body["schema_version"], 2);
    assert_eq!(body["collected_at"], "1760400000.000");
    let firewall = &body["checks"]["firewall"];
    assert_eq!(firewall["status"], "pass");
    assert_eq!(firewall["evidence"]["observed_at"], "1760400000.000");
    assert_eq!(
        firewall["evidence"]["redactions"],
        serde_json::json!(["raw_evidence"])
    );
    assert_eq!(firewall["evidence"]["privilege"], "system");
    assert_eq!(firewall["evidence"]["confidence"], "os_reported");
    let coverage = &body["coverage"];
    assert_eq!(coverage["provider"], "deixic-windows-collector");
    assert_eq!(coverage["max_age_seconds"], 3600);
    assert_eq!(coverage["capabilities"], serde_json::json!(CHECK_KEYS));
}

#[test]
fn screen_lock_prefers_machine_policy_then_every_user() {
    let policy = key(SYSTEM_POLICY_KEY, r"\InactivityTimeoutSecs");
    type Mutate<'a> = Box<dyn Fn(&mut FakeHost) + 'a>;
    let cases: Vec<(&str, Mutate, &str, &str)> = vec![
        (
            "machine policy within limit",
            Box::new(|host: &mut FakeHost| {
                host.values.insert(policy.clone(), MAX_SCREEN_LOCK_SECONDS);
            }),
            "pass",
            "timeout_seconds=900",
        ),
        (
            "machine policy too long",
            Box::new(|host: &mut FakeHost| {
                host.values
                    .insert(policy.clone(), 2 * MAX_SCREEN_LOCK_SECONDS);
            }),
            "finding",
            "timeout_seconds=1800",
        ),
        (
            "a user timeout too long",
            Box::new(|host: &mut FakeHost| {
                host.desktops
                    .as_mut()
                    .unwrap()
                    .push(desktop("1", "1", "1200"));
            }),
            "finding",
            "timeout_seconds=1200",
        ),
        (
            "no signed-in users",
            Box::new(|host: &mut FakeHost| host.desktops = None),
            "unavailable",
            "",
        ),
    ];
    for (name, mutate, status, expected) in cases {
        let mut host = hardened();
        mutate(&mut host);
        let posture = collect(&host, at());
        assert_eq!(posture.checks["screen_lock"].status, status, "{name}");
        assert_eq!(value(&posture, "screen_lock"), expected, "{name}");
    }
}

#[test]
fn bitlocker_needs_elevation_and_known_states() {
    let mut host = hardened();
    host.not_elevated = true;
    assert_eq!(
        collect(&host, at()).checks["disk_encryption"].status,
        "requires_root"
    );
    let mut host = hardened();
    host.shell.insert(BITLOCKER_EXPRESSION, "Unknown".into());
    assert_eq!(
        collect(&host, at()).checks["disk_encryption"].status,
        "unavailable"
    );
    host.shell
        .insert(PENDING_UPDATES_EXPRESSION, "not a number".into());
    assert_eq!(
        collect(&host, at()).checks["os_updates"].status,
        "unavailable"
    );
}

#[test]
fn evidence_is_a_hash_of_what_was_read_never_the_raw_value() {
    let posture = collect(&hardened(), at());
    let encoded = serde_json::to_string(&posture).unwrap();
    for raw in [
        "domain:local=1",
        "NoAutoUpdate=",
        "InactivityTimeoutSecs",
        "1/1/600",
    ] {
        assert!(!encoded.contains(raw), "raw evidence {raw:?} leaked");
    }
}

#[test]
fn a_failed_registry_read_is_unavailable_not_requires_root() {
    let mut host = hardened();
    host.failed = vec![
        key(FIREWALL_GPO_KEY, r"DomainProfile\EnableFirewall"),
        key(WINDOWS_UPDATE_GPO, r"\AUOptions"),
        key(TERMINAL_SERVER_KEY, r"\fDenyTSConnections"),
        key(SYSTEM_POLICY_KEY, r"\InactivityTimeoutSecs"),
    ];
    let posture = collect(&host, at());
    for check in ["firewall", "auto_updates", "remote_access", "screen_lock"] {
        assert_eq!(posture.checks[check].status, "unavailable", "{check}");
    }
}
