//! Configuration assessment results.

use std::fs;
use std::os::unix::fs::MetadataExt;

use super::{DeviceSCAResult, bounded_read, inventory_text};

pub(super) fn config_setting(path: &str, key: &str) -> Option<String> {
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

pub(super) fn sca_result(
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

pub(super) fn collect_sca() -> Vec<DeviceSCAResult> {
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
