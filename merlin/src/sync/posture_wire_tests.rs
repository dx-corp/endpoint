pub(super) fn assert_linux_posture(posture: &serde_json::Value) {
    assert_eq!(posture["schema_version"].as_u64(), Some(2));
    let checks = posture["checks"].as_object().unwrap();
    for name in [
        "secure_boot",
        "tpm2",
        "measured_boot",
        "kernel_lockdown",
        "disk_encryption",
        "firewall",
        "os_updates",
        "auto_updates",
        "endpoint_protection",
        "remote_access",
    ] {
        assert!(checks.get(name).is_some_and(serde_json::Value::is_object));
    }
    // A graphical session adds the password-manager check; headless hosts omit it.
    assert_eq!(
        posture["coverage"]["checks_total"].as_u64(),
        Some(10 + u64::from(checks.contains_key("password_manager")))
    );
    assert!(
        checks
            .get("password_manager")
            .is_none_or(serde_json::Value::is_object)
    );
}

pub(super) fn assert_linux_hardening(hardening: &serde_json::Value) {
    assert_eq!(hardening["schema_version"].as_u64(), Some(1));
    let timestamp = hardening["collected_at"].as_str().unwrap();
    assert!(timestamp.contains('T') && timestamp.ends_with('Z'));
    let observations = hardening["observations"].as_array().unwrap();
    assert_eq!(observations.len(), 161);
    let mut ids = std::collections::BTreeSet::new();
    for row in observations {
        assert_eq!(row["os_family"], "linux");
        assert!(ids.insert(row["id"].as_str().unwrap()));
        assert_eq!(
            row["id"].as_str().unwrap(),
            format!(
                "{}:{}",
                row["kind"].as_str().unwrap(),
                row["target"].as_str().unwrap()
            )
        );
        assert!(row.get("status").is_none());
        assert!(row.get("compliant").is_none());
    }
}
