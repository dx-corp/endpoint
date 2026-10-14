//! Linux host hygiene checks with platform-neutral keys: os_updates,
//! auto_updates, endpoint_protection, password_manager and remote_access.
//!
//! Every check reads bounded files only; nothing is executed. Product lists
//! are fixed and reviewed here. Values carry product names or counts, never
//! user names, home paths or raw file content. A check that does not apply
//! to the host is omitted (password_manager without a graphical session); a
//! check that applies but cannot be read is unavailable, never pass.
//! screen_lock is omitted: its settings live in per-user session stores this
//! root agent does not read.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::{EvidenceRead, PostureCheck, evidence_check, read_bounded_nofollow, unavailable_check};

const MAX_CONFIG_BYTES: u64 = 64 << 10;
const MAX_COMM_BYTES: u64 = 64;
const MAX_PROCESSES: usize = 8192;
const MAX_CONFIG_FILES: usize = 128;

/// AV/EDR agents by process name (`/proc/<pid>/comm`, 15 bytes max).
const ENDPOINT_PROTECTION: &[(&str, &str)] = &[
    ("falcon-sensor", "CrowdStrike Falcon"),
    ("wdavdaemon", "Microsoft Defender"),
    ("s1-agent", "SentinelOne"),
    ("sentinelone-age", "SentinelOne"),
    ("clamd", "ClamAV"),
    ("elastic-endpoi", "Elastic Endpoint"),
    ("wazuh-agentd", "Wazuh"),
    ("cbagentd", "Carbon Black"),
    ("ds_agent", "Trend Micro Deep Security"),
    ("sophos-spl", "Sophos"),
    ("SophosSPL", "Sophos"),
];

/// Remote-desktop and remote-control services by process name. SSH is not
/// listed: it is the administrative channel on servers, not screen sharing.
const REMOTE_ACCESS: &[(&str, &str)] = &[
    ("teamviewerd", "TeamViewer"),
    ("anydesk", "AnyDesk"),
    ("rustdesk", "RustDesk"),
    ("xrdp", "xrdp"),
    ("x11vnc", "x11vnc"),
    ("Xvnc", "VNC server"),
    ("vino-server", "Vino"),
    ("gnome-remote-de", "GNOME Remote Desktop"),
    ("krfb", "KDE Desktop Sharing"),
    ("chrome-remote-d", "Chrome Remote Desktop"),
];

/// Password managers by system-wide desktop entry.
const PASSWORD_MANAGERS: &[(&str, &str)] = &[
    ("1password.desktop", "1Password"),
    ("bitwarden.desktop", "Bitwarden"),
    ("com.bitwarden.desktop.desktop", "Bitwarden"),
    ("org.keepassxc.KeePassXC.desktop", "KeePassXC"),
    ("keepassxc.desktop", "KeePassXC"),
    ("com.dashlane.Dashlane.desktop", "Dashlane"),
    ("enpass.desktop", "Enpass"),
    ("proton-pass.desktop", "Proton Pass"),
];

pub(super) struct HostPaths {
    pub proc_root: PathBuf,
    pub apt_conf_dir: PathBuf,
    pub update_notifier: PathBuf,
    pub dnf_automatic_conf: PathBuf,
    pub timer_wants_dirs: Vec<PathBuf>,
    pub application_dirs: Vec<PathBuf>,
    pub graphical_markers: Vec<PathBuf>,
}

impl HostPaths {
    pub fn system() -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
            apt_conf_dir: PathBuf::from("/etc/apt/apt.conf.d"),
            update_notifier: PathBuf::from("/var/lib/update-notifier/updates-available"),
            dnf_automatic_conf: PathBuf::from("/etc/dnf/automatic.conf"),
            timer_wants_dirs: [
                "/etc/systemd/system/timers.target.wants",
                "/usr/lib/systemd/system/timers.target.wants",
            ]
            .map(PathBuf::from)
            .to_vec(),
            application_dirs: [
                "/usr/share/applications",
                "/var/lib/flatpak/exports/share/applications",
                "/var/lib/snapd/desktop/applications",
            ]
            .map(PathBuf::from)
            .to_vec(),
            graphical_markers: [
                "/tmp/.X11-unix",
                "/usr/share/xsessions",
                "/usr/share/wayland-sessions",
            ]
            .map(PathBuf::from)
            .to_vec(),
        }
    }
}

pub(super) fn collect(
    paths: &HostPaths,
    observed_at: &str,
    privilege: &'static str,
    checks: &mut BTreeMap<&'static str, PostureCheck>,
) {
    checks.insert("os_updates", os_updates(paths, observed_at, privilege));
    checks.insert("auto_updates", auto_updates(paths, observed_at, privilege));
    let processes = process_names(&paths.proc_root);
    checks.insert(
        "endpoint_protection",
        endpoint_protection(processes.as_deref(), observed_at, privilege),
    );
    checks.insert(
        "remote_access",
        remote_access(processes.as_deref(), observed_at, privilege),
    );
    if paths.graphical_markers.iter().any(|marker| marker.is_dir()) {
        checks.insert(
            "password_manager",
            password_manager(paths, observed_at, privilege),
        );
    }
}

/// A check whose value is computed (a count or product names).
fn valued(mut check: PostureCheck, value: String) -> PostureCheck {
    check.value = Some(Cow::Owned(value));
    check
}

/// Ubuntu's update-notifier summary: "N updates can be applied immediately."
/// (older releases: "N packages can be updated."). Other distributions keep
/// no readable pending count, so the check is unavailable there.
fn os_updates(paths: &HostPaths, observed_at: &str, privilege: &'static str) -> PostureCheck {
    const SOURCE: &str = "update-notifier.updates-available";
    let raw = match read_bounded_nofollow(&paths.update_notifier, MAX_CONFIG_BYTES) {
        EvidenceRead::Data(raw) => raw,
        EvidenceRead::RequiresRoot => {
            return unavailable_check("requires_root", "Pending update count requires root access");
        }
        _ => return unavailable_check("unavailable", "No readable pending update count"),
    };
    let text = String::from_utf8_lossy(&raw);
    let pending = text.lines().find_map(|line| {
        let line = line.trim();
        let (count, rest) = line.split_once(' ')?;
        (rest.starts_with("updates can be applied") || rest.starts_with("packages can be updated"))
            .then(|| count.parse::<u32>().ok())
            .flatten()
    });
    match pending {
        Some(0) => valued(
            evidence_check(
                "pass",
                "",
                None,
                "No pending OS updates",
                SOURCE,
                privilege,
                observed_at,
                &raw,
            ),
            "none".into(),
        ),
        Some(count) => valued(
            evidence_check(
                "finding",
                "",
                Some("high"),
                "OS updates are pending",
                SOURCE,
                privilege,
                observed_at,
                &raw,
            ),
            format!("{count} pending"),
        ),
        // A summary without a count line means nothing is pending on these releases.
        None if text.trim().is_empty() || !text.contains("can be") => valued(
            evidence_check(
                "pass",
                "",
                None,
                "No pending OS updates",
                SOURCE,
                privilege,
                observed_at,
                &raw,
            ),
            "none".into(),
        ),
        None => unavailable_check("unavailable", "Pending update count is unreadable"),
    }
}

/// apt: `APT::Periodic::Unattended-Upgrade "1"` in apt.conf.d (last file wins,
/// as apt reads them in lexical order). dnf: an enabled dnf-automatic install
/// timer, or `apply_updates = yes` with the plain timer enabled.
fn auto_updates(paths: &HostPaths, observed_at: &str, privilege: &'static str) -> PostureCheck {
    if paths.apt_conf_dir.is_dir() {
        const SOURCE: &str = "apt.conf.d";
        let mut setting = None;
        let mut evidence = Vec::new();
        for path in sorted_entries(&paths.apt_conf_dir) {
            let EvidenceRead::Data(raw) = read_bounded_nofollow(&path, MAX_CONFIG_BYTES) else {
                continue;
            };
            if let Some(value) = apt_unattended(&String::from_utf8_lossy(&raw)) {
                setting = Some(value);
                evidence.extend_from_slice(&raw);
            }
        }
        return match setting {
            Some(true) => evidence_check(
                "pass",
                "on",
                None,
                "Automatic security updates are enabled",
                SOURCE,
                privilege,
                observed_at,
                &evidence,
            ),
            _ => evidence_check(
                "finding",
                "off",
                Some("medium"),
                "Automatic updates are disabled",
                SOURCE,
                privilege,
                observed_at,
                &evidence,
            ),
        };
    }
    let timers: Vec<String> = paths
        .timer_wants_dirs
        .iter()
        .flat_map(|dir| sorted_entries(dir))
        .filter_map(|path| path.file_name()?.to_str().map(str::to_owned))
        .filter(|name| name.starts_with("dnf-automatic"))
        .collect();
    let applies = match read_bounded_nofollow(&paths.dnf_automatic_conf, MAX_CONFIG_BYTES) {
        EvidenceRead::Data(raw) => dnf_applies(&String::from_utf8_lossy(&raw)),
        _ => false,
    };
    if !timers.is_empty() || paths.dnf_automatic_conf.exists() {
        const SOURCE: &str = "dnf-automatic";
        let on = timers.iter().any(|t| t == "dnf-automatic-install.timer")
            || (applies && timers.iter().any(|t| t == "dnf-automatic.timer"));
        let raw = timers.join("\n");
        return if on {
            evidence_check(
                "pass",
                "on",
                None,
                "Automatic updates are enabled",
                SOURCE,
                privilege,
                observed_at,
                raw.as_bytes(),
            )
        } else {
            evidence_check(
                "finding",
                "off",
                Some("medium"),
                "Automatic updates are disabled",
                SOURCE,
                privilege,
                observed_at,
                raw.as_bytes(),
            )
        };
    }
    unavailable_check(
        "unavailable",
        "No supported automatic update service is configured",
    )
}

fn apt_unattended(config: &str) -> Option<bool> {
    config
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//") && !line.starts_with('#'))
        .filter_map(|line| line.strip_prefix("APT::Periodic::Unattended-Upgrade"))
        .filter_map(|rest| {
            rest.trim()
                .trim_end_matches(';')
                .trim()
                .trim_matches('"')
                .parse::<u32>()
                .ok()
        })
        .next_back()
        .map(|days| days > 0)
}

fn dnf_applies(config: &str) -> bool {
    config.lines().map(str::trim).any(|line| {
        line.split_once('=').is_some_and(|(key, value)| {
            key.trim() == "apply_updates" && matches!(value.trim(), "yes" | "true" | "1")
        })
    })
}

fn sorted_entries(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .take(MAX_CONFIG_FILES)
        .collect();
    paths.sort();
    paths
}

/// Running process names, or `None` when the process table is unreadable.
fn process_names(proc_root: &Path) -> Option<Vec<String>> {
    let entries = fs::read_dir(proc_root).ok()?;
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
        })
        .take(MAX_PROCESSES)
        .filter_map(|entry| {
            match read_bounded_nofollow(&entry.path().join("comm"), MAX_COMM_BYTES) {
                EvidenceRead::Data(raw) => Some(String::from_utf8_lossy(&raw).trim().to_owned()),
                _ => None,
            }
        })
        .collect();
    names.sort();
    names.dedup();
    Some(names)
}

/// Product names from `table` whose process is running, sorted and deduplicated.
fn running(processes: &[String], table: &[(&str, &'static str)]) -> Vec<&'static str> {
    let mut found: Vec<&'static str> = table
        .iter()
        .filter(|(process, _)| processes.iter().any(|name| name == process))
        .map(|(_, product)| *product)
        .collect();
    found.sort_unstable();
    found.dedup();
    found
}

fn endpoint_protection(
    processes: Option<&[String]>,
    observed_at: &str,
    privilege: &'static str,
) -> PostureCheck {
    const SOURCE: &str = "procfs.comm";
    let Some(processes) = processes else {
        return unavailable_check("unavailable", "Process table is unreadable");
    };
    let found = running(processes, ENDPOINT_PROTECTION);
    let raw = found.join(",");
    if found.is_empty() {
        evidence_check(
            "finding",
            "none",
            Some("high"),
            "No known endpoint protection agent is running",
            SOURCE,
            privilege,
            observed_at,
            b"none",
        )
    } else {
        valued(
            evidence_check(
                "pass",
                "",
                None,
                "An endpoint protection agent is running",
                SOURCE,
                privilege,
                observed_at,
                raw.as_bytes(),
            ),
            raw.clone(),
        )
    }
}

fn remote_access(
    processes: Option<&[String]>,
    observed_at: &str,
    privilege: &'static str,
) -> PostureCheck {
    const SOURCE: &str = "procfs.comm";
    let Some(processes) = processes else {
        return unavailable_check("unavailable", "Process table is unreadable");
    };
    let found = running(processes, REMOTE_ACCESS);
    let raw = found.join(",");
    if found.is_empty() {
        evidence_check(
            "pass",
            "none",
            None,
            "No remote desktop service is running",
            SOURCE,
            privilege,
            observed_at,
            b"none",
        )
    } else {
        valued(
            evidence_check(
                "finding",
                "",
                Some("medium"),
                "A remote desktop service is running",
                SOURCE,
                privilege,
                observed_at,
                raw.as_bytes(),
            ),
            raw.clone(),
        )
    }
}

fn password_manager(paths: &HostPaths, observed_at: &str, privilege: &'static str) -> PostureCheck {
    const SOURCE: &str = "xdg.applications";
    let mut found: Vec<&'static str> = PASSWORD_MANAGERS
        .iter()
        .filter(|(entry, _)| {
            paths
                .application_dirs
                .iter()
                .any(|dir| dir.join(entry).is_file())
        })
        .map(|(_, product)| *product)
        .collect();
    found.sort_unstable();
    found.dedup();
    let raw = found.join(",");
    if found.is_empty() {
        evidence_check(
            "finding",
            "none",
            Some("low"),
            "No known password manager is installed",
            SOURCE,
            privilege,
            observed_at,
            b"none",
        )
    } else {
        valued(
            evidence_check(
                "pass",
                "",
                None,
                "A password manager is installed",
                SOURCE,
                privilege,
                observed_at,
                raw.as_bytes(),
            ),
            raw.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NONCE: AtomicU64 = AtomicU64::new(0);

    fn host(name: &str) -> (PathBuf, HostPaths) {
        let root = std::env::temp_dir().join(format!(
            "merlin-linux-host-{name}-{}-{}",
            std::process::id(),
            NONCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("proc")).unwrap();
        let paths = HostPaths {
            proc_root: root.join("proc"),
            apt_conf_dir: root.join("apt.conf.d"),
            update_notifier: root.join("updates-available"),
            dnf_automatic_conf: root.join("automatic.conf"),
            timer_wants_dirs: vec![root.join("timers.target.wants")],
            application_dirs: vec![root.join("applications")],
            graphical_markers: vec![root.join("X11-unix")],
        };
        (root, paths)
    }

    fn process(paths: &HostPaths, pid: u32, comm: &str) {
        let dir = paths.proc_root.join(pid.to_string());
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("comm"), format!("{comm}\n")).unwrap();
    }

    fn run(paths: &HostPaths) -> BTreeMap<&'static str, PostureCheck> {
        let mut checks = BTreeMap::new();
        collect(paths, "1.000", "root", &mut checks);
        checks
    }

    #[test]
    fn hardened_desktop_passes_every_host_check() {
        let (root, paths) = host("hardened");
        fs::create_dir_all(&paths.apt_conf_dir).unwrap();
        fs::write(paths.apt_conf_dir.join("20auto-upgrades"), "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n").unwrap();
        fs::write(
            &paths.update_notifier,
            "\n0 updates can be applied immediately.\n\n",
        )
        .unwrap();
        process(&paths, 1, "systemd");
        process(&paths, 812, "falcon-sensor");
        fs::create_dir_all(&paths.graphical_markers[0]).unwrap();
        fs::create_dir_all(&paths.application_dirs[0]).unwrap();
        fs::write(paths.application_dirs[0].join("1password.desktop"), "").unwrap();

        let checks = run(&paths);

        for key in [
            "os_updates",
            "auto_updates",
            "endpoint_protection",
            "remote_access",
            "password_manager",
        ] {
            assert_eq!(checks[key].status, "pass", "{key}");
            assert_eq!(
                checks[key].evidence.as_ref().unwrap().evidence_hash.len(),
                64
            );
        }
        assert_eq!(
            checks["endpoint_protection"].value.as_deref(),
            Some("CrowdStrike Falcon")
        );
        assert_eq!(
            checks["password_manager"].value.as_deref(),
            Some("1Password")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn exposed_host_reports_findings_with_counts_and_product_names() {
        let (root, paths) = host("exposed");
        fs::create_dir_all(&paths.apt_conf_dir).unwrap();
        fs::write(
            paths.apt_conf_dir.join("20auto-upgrades"),
            "APT::Periodic::Unattended-Upgrade \"1\";\n",
        )
        .unwrap();
        // A later file turns it off again, as apt reads them in order.
        fs::write(
            paths.apt_conf_dir.join("99local"),
            "// local\nAPT::Periodic::Unattended-Upgrade \"0\";\n",
        )
        .unwrap();
        fs::write(&paths.update_notifier, "12 updates can be applied immediately.\n5 of these updates are standard security updates.\n").unwrap();
        process(&paths, 40, "anydesk");
        process(&paths, 41, "teamviewerd");
        fs::create_dir_all(&paths.graphical_markers[0]).unwrap();

        let checks = run(&paths);

        assert_eq!(checks["auto_updates"].status, "finding");
        assert_eq!(checks["os_updates"].value.as_deref(), Some("12 pending"));
        assert_eq!(checks["os_updates"].severity, Some("high"));
        assert_eq!(checks["endpoint_protection"].value.as_deref(), Some("none"));
        assert_eq!(
            checks["remote_access"].value.as_deref(),
            Some("AnyDesk,TeamViewer")
        );
        assert_eq!(checks["password_manager"].severity, Some("low"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn headless_dnf_host_omits_password_manager_and_reads_timers() {
        let (root, paths) = host("dnf");
        fs::create_dir_all(&paths.timer_wants_dirs[0]).unwrap();
        fs::write(paths.timer_wants_dirs[0].join("dnf-automatic.timer"), "").unwrap();
        fs::write(
            &paths.dnf_automatic_conf,
            "[commands]\napply_updates = yes\n",
        )
        .unwrap();

        let checks = run(&paths);

        assert!(!checks.contains_key("password_manager"));
        assert!(!checks.contains_key("screen_lock"));
        assert_eq!(checks["auto_updates"].status, "pass");
        // No readable pending count on this distribution: unavailable, never pass.
        assert_eq!(checks["os_updates"].status, "unavailable");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn unreadable_sources_are_unavailable_not_pass() {
        let (root, mut paths) = host("unreadable");
        paths.proc_root = root.join("missing-proc");

        let checks = run(&paths);

        assert_eq!(checks["endpoint_protection"].status, "unavailable");
        assert_eq!(checks["remote_access"].status, "unavailable");
        assert_eq!(checks["auto_updates"].status, "unavailable");
        assert_eq!(checks["os_updates"].status, "unavailable");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn apt_settings_parse_quoted_values_and_comments() {
        assert_eq!(
            apt_unattended("APT::Periodic::Unattended-Upgrade \"1\";"),
            Some(true)
        );
        assert_eq!(
            apt_unattended("APT::Periodic::Unattended-Upgrade \"0\";"),
            Some(false)
        );
        assert_eq!(
            apt_unattended("// APT::Periodic::Unattended-Upgrade \"1\";"),
            None
        );
        assert!(dnf_applies(
            "apply_updates=True".to_ascii_lowercase().as_str()
        ));
        assert!(!dnf_applies("apply_updates = no"));
    }
}
