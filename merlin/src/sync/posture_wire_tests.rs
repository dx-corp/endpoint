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
