//! Windows device posture: the platform-neutral checks `firewall`,
//! `auto_updates`, `endpoint_protection`, `remote_access`,
//! `password_manager`, `disk_encryption`, `os_updates` and `screen_lock`.
//! They read HKLM registry values, installed-program names, running process
//! image names, loaded user hives' screen saver settings and two fixed
//! read-only PowerShell expressions through `PostureSources`, so the
//! decisions are tested on any platform. Values are fixed product names or
//! on/off states: never user names, paths or raw registry content. A check
//! that applies but cannot be read is unavailable, never pass.

#[cfg(test)]
mod tests;

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant, SystemTime};

use crate::posture_report::{
    Collector, DevicePosture, PostureCheck, evidence, summarize, unavailable_check,
};

/// The outcome of one HKLM registry value read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RegRead {
    Found(u32),
    Missing,
    Denied,
    Failed,
}

/// The host reads posture needs. Windows uses the registry, a process
/// snapshot and PowerShell (`windows_host::WindowsHost`); tests use fixed
/// values.
pub(crate) trait PostureSources {
    /// An HKLM `REG_DWORD` value from the 64-bit view.
    fn dword(&self, key: &str, name: &str) -> RegRead;
    /// Installed-program display names, machine-wide and in loaded user hives.
    fn programs(&self) -> Option<Vec<String>>;
    /// Running process image names.
    fn processes(&self) -> Option<Vec<String>>;
    /// Per loaded interactive user hive, the effective screen saver values
    /// (policy over the user's own): ScreenSaveActive, ScreenSaverIsSecure and
    /// ScreenSaveTimeOut.
    fn user_desktops(&self) -> Option<Vec<BTreeMap<String, String>>>;
    /// The trimmed output of one fixed read-only expression; only the
    /// expressions below are ever passed.
    fn powershell(&self, expression: &str, timeout: Duration) -> Option<String>;
    /// Whether the collector reads with administrative rights.
    fn elevated(&self) -> bool;
}

/// Reviewed product lists, matched on the exact image name, case-insensitively.
const ENDPOINT_PROTECTION_PROCESSES: &[(&str, &str)] = &[
    ("msmpeng.exe", "Microsoft Defender"),
    ("mssense.exe", "Microsoft Defender for Endpoint"),
    ("csfalconservice.exe", "CrowdStrike Falcon"),
    ("sentinelagent.exe", "SentinelOne"),
    ("repmgr.exe", "Carbon Black"),
    ("sophoshealth.exe", "Sophos"),
    ("ekrn.exe", "ESET"),
    ("avp.exe", "Kaspersky"),
    ("ccsvchst.exe", "Symantec Endpoint Protection"),
    ("elastic-endpoint.exe", "Elastic Endpoint"),
];

const REMOTE_ACCESS_PROCESSES: &[(&str, &str)] = &[
    ("teamviewer_service.exe", "TeamViewer"),
    ("anydesk.exe", "AnyDesk"),
    ("rustdesk.exe", "RustDesk"),
    ("winvnc.exe", "VNC server"),
    ("tvnserver.exe", "VNC server"),
    ("vncserver.exe", "VNC server"),
    ("remoting_host.exe", "Chrome Remote Desktop"),
    ("splashtopstreamer.exe", "Splashtop"),
];

/// Matched as a display-name prefix, case-insensitively.
const PASSWORD_MANAGER_PROGRAMS: &[(&str, &str)] = &[
    ("1password", "1Password"),
    ("bitwarden", "Bitwarden"),
    ("keepassxc", "KeePassXC"),
    ("keepass password safe", "KeePass"),
    ("dashlane", "Dashlane"),
    ("lastpass", "LastPass"),
    ("keeper password manager", "Keeper"),
    ("enpass", "Enpass"),
    ("proton pass", "Proton Pass"),
];

pub(crate) const FIREWALL_POLICY_KEY: &str =
    r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\";
pub(crate) const FIREWALL_GPO_KEY: &str = r"SOFTWARE\Policies\Microsoft\WindowsFirewall\";
pub(crate) const WINDOWS_UPDATE_GPO: &str = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
pub(crate) const WUAUSERV_KEY: &str = r"SYSTEM\CurrentControlSet\Services\wuauserv";
pub(crate) const TERMINAL_SERVER_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Terminal Server";
pub(crate) const SYSTEM_POLICY_KEY: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

/// BitLocker's ProtectionStatus and the update count are enum names and
/// integers, so the output is not localized.
pub(crate) const BITLOCKER_EXPRESSION: &str =
    "(Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop).ProtectionStatus";
pub(crate) const PENDING_UPDATES_EXPRESSION: &str = "(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search(\"IsInstalled=0 and IsHidden=0 and Type='Software'\").Updates.Count";
const MAX_SCREEN_LOCK_SECONDS: u32 = 900;

const CHECK_KEYS: &[&str] = &[
    "auto_updates",
    "disk_encryption",
    "endpoint_protection",
    "firewall",
    "os_updates",
    "password_manager",
    "remote_access",
    "screen_lock",
];

fn risk_weight(check: &str) -> u8 {
    match check {
        "disk_encryption" => 40,
        "os_updates" | "firewall" | "endpoint_protection" => 15,
        "screen_lock" | "remote_access" => 10,
        "auto_updates" => 5,
        _ => 0,
    }
}

/// Evidence and values for one collection.
struct Reader<'a, S: PostureSources> {
    src: &'a S,
    observed_at: String,
    privilege: &'static str,
}

impl<S: PostureSources> Reader<'_, S> {
    fn check(
        &self,
        status: &'static str,
        value: impl Into<Cow<'static, str>>,
        severity: Option<&'static str>,
        detail: &'static str,
        source: &'static str,
        raw: &str,
    ) -> PostureCheck {
        PostureCheck {
            status,
            value: Some(value.into()),
            severity,
            detail,
            evidence: Some(evidence(
                source,
                self.privilege,
                "os_reported",
                &self.observed_at,
                raw.as_bytes(),
            )),
        }
    }
}

pub(crate) fn collect(src: &impl PostureSources, now: SystemTime) -> DevicePosture {
    let started = Instant::now();
    let seconds = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    let elevated = src.elevated();
    let reader = Reader {
        src,
        observed_at: format!("{seconds:.3}"),
        privilege: if elevated { "system" } else { "user" },
    };
    let processes = src.processes();
    let mut checks = BTreeMap::new();
    checks.insert("firewall", firewall(&reader));
    checks.insert("auto_updates", auto_updates(&reader));
    checks.insert(
        "endpoint_protection",
        endpoint_protection(&reader, processes.as_deref()),
    );
    checks.insert(
        "remote_access",
        remote_access(&reader, processes.as_deref()),
    );
    checks.insert("password_manager", password_manager(&reader));
    checks.insert("disk_encryption", disk_encryption(&reader));
    checks.insert("os_updates", os_updates(&reader));
    checks.insert("screen_lock", screen_lock(&reader));
    summarize(
        checks,
        reader.observed_at.clone(),
        Collector {
            provider: "deixic-windows-collector",
            root: elevated,
            max_age_seconds: 3600,
            capabilities: CHECK_KEYS.to_vec(),
            started,
        },
        risk_weight,
    )
}

fn read_failure(
    read: RegRead,
    unreadable: &'static str,
    needs_elevation: &'static str,
) -> PostureCheck {
    if read == RegRead::Denied {
        unavailable_check("requires_root", needs_elevation)
    } else {
        unavailable_check("unavailable", unreadable)
    }
}

/// Passes when every profile (domain, private, public) has the firewall on.
/// A Group Policy value overrides the local setting per profile.
fn firewall<S: PostureSources>(reader: &Reader<'_, S>) -> PostureCheck {
    let mut raw = Vec::new();
    let mut off = false;
    for (local, policy, name) in [
        ("DomainProfile", "DomainProfile", "domain"),
        ("StandardProfile", "PrivateProfile", "private"),
        ("PublicProfile", "PublicProfile", "public"),
    ] {
        let mut read = reader
            .src
            .dword(&format!("{FIREWALL_GPO_KEY}{policy}"), "EnableFirewall");
        let mut source = "policy";
        if read == RegRead::Missing {
            read = reader
                .src
                .dword(&format!("{FIREWALL_POLICY_KEY}{local}"), "EnableFirewall");
            source = "local";
        }
        let RegRead::Found(value) = read else {
            return read_failure(
                read,
                "Firewall setting is unreadable",
                "Firewall setting requires elevated access",
            );
        };
        raw.push(format!("{name}:{source}={value}"));
        off |= value == 0;
    }
    let raw = raw.join(";");
    if off {
        reader.check(
            "finding",
            "disabled",
            Some("medium"),
            "Windows Firewall is off for one or more network profiles",
            "registry.firewall_policy",
            &raw,
        )
    } else {
        reader.check(
            "pass",
            "enabled",
            None,
            "Windows Firewall is on for every network profile",
            "registry.firewall_policy",
            &raw,
        )
    }
}

fn reg_value_and_code(read: RegRead) -> (u32, u8) {
    // The codes match the Go collector's regRead order, so the evidence
    // string (and its hash) is the same for the same registry state.
    match read {
        RegRead::Found(value) => (value, 0),
        RegRead::Missing => (0, 1),
        RegRead::Denied => (0, 2),
        RegRead::Failed => (0, 3),
    }
}

/// Off when policy disables automatic updates, limits them to notification
/// (AUOptions 1 or 2), or the Windows Update service is disabled.
fn auto_updates<S: PostureSources>(reader: &Reader<'_, S>) -> PostureCheck {
    let no_auto = reader.src.dword(WINDOWS_UPDATE_GPO, "NoAutoUpdate");
    let options = reader.src.dword(WINDOWS_UPDATE_GPO, "AUOptions");
    let start = reader.src.dword(WUAUSERV_KEY, "Start");
    for read in [no_auto, options] {
        if matches!(read, RegRead::Denied | RegRead::Failed) {
            return read_failure(
                read,
                "Windows Update policy is unreadable",
                "Windows Update policy requires elevated access",
            );
        }
    }
    let RegRead::Found(start_value) = start else {
        return read_failure(
            start,
            "Windows Update service setting is unreadable",
            "Windows Update service setting requires elevated access",
        );
    };
    let (no_auto_value, no_auto_code) = reg_value_and_code(no_auto);
    let (options_value, options_code) = reg_value_and_code(options);
    let raw = format!(
        "NoAutoUpdate={no_auto_value}/{no_auto_code};AUOptions={options_value}/{options_code};Start={start_value}"
    );
    let off = no_auto == RegRead::Found(1)
        || matches!(options, RegRead::Found(1 | 2))
        || start_value == 4;
    if off {
        reader.check(
            "finding",
            "off",
            Some("medium"),
            "Automatic updates are disabled",
            "registry.windows_update",
            &raw,
        )
    } else {
        reader.check(
            "pass",
            "on",
            None,
            "Automatic updates are enabled",
            "registry.windows_update",
            &raw,
        )
    }
}

/// The sorted, deduplicated products whose process runs.
fn matched_products(processes: &[String], table: &[(&str, &'static str)]) -> Vec<&'static str> {
    let products: BTreeSet<&'static str> = processes
        .iter()
        .filter_map(|name| {
            let lower = name.to_ascii_lowercase();
            table
                .iter()
                .find(|(image, _)| *image == lower)
                .map(|(_, product)| *product)
        })
        .collect();
    products.into_iter().collect()
}

fn endpoint_protection<S: PostureSources>(
    reader: &Reader<'_, S>,
    processes: Option<&[String]>,
) -> PostureCheck {
    let Some(processes) = processes else {
        return unavailable_check("unavailable", "Process list is unreadable");
    };
    let products = matched_products(processes, ENDPOINT_PROTECTION_PROCESSES);
    let value = if products.is_empty() {
        "none".to_string()
    } else {
        products.join(",")
    };
    if products.is_empty() {
        reader.check(
            "finding",
            value.clone(),
            Some("high"),
            "No known endpoint protection agent is running",
            "process_snapshot",
            &value,
        )
    } else {
        reader.check(
            "pass",
            value.clone(),
            None,
            "An endpoint protection agent is running",
            "process_snapshot",
            &value,
        )
    }
}

/// A finding when Remote Desktop accepts connections or a known
/// remote-control service runs.
fn remote_access<S: PostureSources>(
    reader: &Reader<'_, S>,
    processes: Option<&[String]>,
) -> PostureCheck {
    let Some(processes) = processes else {
        return unavailable_check("unavailable", "Process list is unreadable");
    };
    let deny = reader.src.dword(TERMINAL_SERVER_KEY, "fDenyTSConnections");
    if matches!(deny, RegRead::Denied | RegRead::Failed) {
        return read_failure(
            deny,
            "Remote Desktop setting is unreadable",
            "Remote Desktop setting requires elevated access",
        );
    }
    let mut products = matched_products(processes, REMOTE_ACCESS_PROCESSES);
    // Remote Desktop is off unless the value is present and zero.
    if deny == RegRead::Found(0) {
        products.insert(0, "Remote Desktop");
    }
    if products.is_empty() {
        return reader.check(
            "pass",
            "none",
            None,
            "No remote access service is enabled",
            "registry+process_snapshot",
            "none",
        );
    }
    let value = products.join(",");
    reader.check(
        "finding",
        value.clone(),
        Some("medium"),
        "A remote access service is enabled",
        "registry+process_snapshot",
        &value,
    )
}

fn password_manager<S: PostureSources>(reader: &Reader<'_, S>) -> PostureCheck {
    let Some(programs) = reader.src.programs() else {
        return unavailable_check("unavailable", "Installed programs are unreadable");
    };
    let products: BTreeSet<&'static str> = programs
        .iter()
        .flat_map(|name| {
            let lower = name.trim().to_lowercase();
            PASSWORD_MANAGER_PROGRAMS
                .iter()
                .filter(move |(prefix, _)| lower.starts_with(prefix))
                .map(|(_, product)| *product)
        })
        .collect();
    if products.is_empty() {
        return reader.check(
            "finding",
            "none",
            Some("low"),
            "No known password manager is installed",
            "registry.uninstall",
            "none",
        );
    }
    let value = products.into_iter().collect::<Vec<_>>().join(",");
    reader.check(
        "pass",
        value.clone(),
        None,
        "A password manager is installed",
        "registry.uninstall",
        &value,
    )
}

/// BitLocker protection on the system drive.
fn disk_encryption<S: PostureSources>(reader: &Reader<'_, S>) -> PostureCheck {
    if !reader.src.elevated() {
        return unavailable_check("requires_root", "BitLocker status requires elevated access");
    }
    let output = reader
        .src
        .powershell(BITLOCKER_EXPRESSION, Duration::from_secs(20));
    match output.as_deref() {
        Some("On") => reader.check(
            "pass",
            "on",
            None,
            "The system drive is encrypted with BitLocker protection on",
            "bitlocker.protection_status",
            "On",
        ),
        Some("Off") => reader.check(
            "finding",
            "off",
            Some("critical"),
            "BitLocker protection is off for the system drive",
            "bitlocker.protection_status",
            "Off",
        ),
        _ => unavailable_check("unavailable", "BitLocker status is unreadable"),
    }
}

/// Applicable software updates not yet installed.
fn os_updates<S: PostureSources>(reader: &Reader<'_, S>) -> PostureCheck {
    let Some(output) = reader
        .src
        .powershell(PENDING_UPDATES_EXPRESSION, Duration::from_secs(120))
    else {
        return unavailable_check("unavailable", "Pending update count is unreadable");
    };
    let Ok(count) = output.parse::<u32>() else {
        return unavailable_check("unavailable", "Pending update count is unreadable");
    };
    if count == 0 {
        reader.check(
            "pass",
            "none",
            None,
            "No pending OS updates",
            "windows_update.search",
            &output,
        )
    } else {
        reader.check(
            "finding",
            format!("{count} pending"),
            Some("high"),
            "OS updates are pending",
            "windows_update.search",
            &output,
        )
    }
}

/// Passes when the machine inactivity limit is at most 15 minutes, or,
/// without that policy, when every signed-in user has a secure screen saver
/// that starts within 15 minutes.
fn screen_lock<S: PostureSources>(reader: &Reader<'_, S>) -> PostureCheck {
    let limit = reader.src.dword(SYSTEM_POLICY_KEY, "InactivityTimeoutSecs");
    match limit {
        RegRead::Found(seconds) => {
            let raw = format!("InactivityTimeoutSecs={seconds}");
            if seconds > 0 && seconds <= MAX_SCREEN_LOCK_SECONDS {
                return reader.check(
                    "pass",
                    format!("timeout_seconds={seconds}"),
                    None,
                    "The device locks after at most 15 minutes of inactivity",
                    "registry.inactivity_policy",
                    &raw,
                );
            }
            let value = if seconds > 0 {
                format!("timeout_seconds={seconds}")
            } else {
                "disabled".to_string()
            };
            return reader.check(
                "finding",
                value,
                Some("high"),
                "The device does not lock within 15 minutes of inactivity",
                "registry.inactivity_policy",
                &raw,
            );
        }
        RegRead::Denied | RegRead::Failed => {
            return read_failure(
                limit,
                "Inactivity lock policy is unreadable",
                "Inactivity lock policy requires elevated access",
            );
        }
        RegRead::Missing => {}
    }
    let users = reader.src.user_desktops().unwrap_or_default();
    if users.is_empty() {
        return unavailable_check(
            "unavailable",
            "No signed-in user screen lock settings to read",
        );
    }
    let mut worst = 0u32;
    let mut disabled = false;
    let mut raw = Vec::new();
    for desktop in &users {
        let get = |name: &str| desktop.get(name).map(String::as_str).unwrap_or("");
        raw.push(format!(
            "{}/{}/{}",
            get("ScreenSaveActive"),
            get("ScreenSaverIsSecure"),
            get("ScreenSaveTimeOut")
        ));
        let timeout = get("ScreenSaveTimeOut")
            .parse::<u32>()
            .ok()
            .filter(|t| *t > 0);
        match timeout {
            Some(timeout)
                if get("ScreenSaveActive") == "1" && get("ScreenSaverIsSecure") == "1" =>
            {
                worst = worst.max(timeout);
            }
            _ => disabled = true,
        }
    }
    let raw = raw.join(";");
    if disabled {
        reader.check(
            "finding",
            "disabled",
            Some("high"),
            "A signed-in user has no secure screen lock",
            "registry.user_desktop",
            &raw,
        )
    } else if worst > MAX_SCREEN_LOCK_SECONDS {
        reader.check(
            "finding",
            format!("timeout_seconds={worst}"),
            Some("high"),
            "The screen locks after more than 15 minutes",
            "registry.user_desktop",
            &raw,
        )
    } else {
        reader.check(
            "pass",
            format!("timeout_seconds={worst}"),
            None,
            "The screen locks within 15 minutes for every signed-in user",
            "registry.user_desktop",
            &raw,
        )
    }
}
