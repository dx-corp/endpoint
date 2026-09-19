//! Strict desired-state protocol and reviewed Linux executors.
//!
//! There is deliberately no generic command or shell operation here. Each
//! operation maps to one fixed native tool with validated, separately passed
//! arguments so a signed policy cannot become an authenticated RCE channel.

use std::collections::BTreeSet;
use std::ffi::{CString, OsStr};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};
use std::process::Stdio;
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::rules::{Rule, Rules};

pub const ARTIFACT_FORMAT: &str = "application/vnd.merlin.desired-state.v1+yaml";
pub const CAPABILITIES: &[&str] = &[
    "desired_state.v1",
    "executor.apt",
    "executor.browser_policy",
    "executor.dconf",
    "executor.file",
    "executor.screen_lock",
    "executor.systemd",
    "executor.sysctl",
];
const EXECUTOR_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_EXECUTOR_OUTPUT_BYTES: usize = 64 << 10;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointArtifact {
    #[serde(default)]
    schema_version: u32,
    #[serde(default)]
    rules: Vec<Rule>,
    #[serde(default)]
    doh_resolvers: Vec<String>,
    desired_state: DesiredState,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredState {
    schema: String,
    revision: u64,
    target: DesiredStateTarget,
    assertions: Vec<Assertion>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesiredStateTarget {
    platform: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Assertion {
    assertion_id: String,
    #[serde(rename = "system.package")]
    system_package: Option<PackageAssertion>,
    #[serde(rename = "system.service")]
    system_service: Option<ServiceAssertion>,
    #[serde(rename = "system.file")]
    system_file: Option<FileAssertion>,
    #[serde(rename = "system.sysctl")]
    system_sysctl: Option<SysctlAssertion>,
    #[serde(rename = "desktop.dconf")]
    desktop_dconf: Option<DconfAssertion>,
    #[serde(rename = "browser.policy")]
    browser_policy: Option<BrowserPolicyAssertion>,
    #[serde(rename = "security.screen_lock")]
    security_screen_lock: Option<ScreenLockAssertion>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageAssertion {
    name: String,
    state: PackageState,
    version: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum PackageState {
    Present,
    Absent,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceAssertion {
    name: String,
    enabled: Option<bool>,
    running: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileAssertion {
    path_class: String,
    path: String,
    state: FileState,
    content_base64: Option<String>,
    mode: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum FileState {
    Present,
    Absent,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SysctlAssertion {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DconfAssertion {
    key: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserPolicyAssertion {
    browser: Browser,
    name: String,
    value_json: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Browser {
    Chrome,
    Chromium,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScreenLockAssertion {
    enabled: bool,
    idle_seconds: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedAssertion {
    pub assertion_id: String,
    pub operations: Vec<NativeOperation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "executor", rename_all = "snake_case")]
pub enum NativeOperation {
    AptEnsurePresent {
        package: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        version: Option<String>,
    },
    AptEnsureAbsent {
        package: String,
    },
    SystemdSetEnabled {
        unit: String,
        enabled: bool,
    },
    SystemdSetRunning {
        unit: String,
        running: bool,
    },
    ManagedFileEnsurePresent {
        relative_path: String,
        content_base64: String,
        mode: String,
    },
    ManagedFileEnsureAbsent {
        relative_path: String,
    },
    SysctlSet {
        name: String,
        value: String,
    },
    DconfSet {
        key: String,
        value: String,
    },
    BrowserPolicySet {
        browser: Browser,
        name: String,
        value: Value,
    },
    ScreenLockSet {
        enabled: bool,
        idle_seconds: u32,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct AssertionReceipt {
    pub device_id: String,
    pub artifact_sha: String,
    pub assertion_id: String,
    pub observed_before: Value,
    pub action_taken: Value,
    pub observed_after: Value,
    pub result: &'static str,
    pub reboot_required: bool,
    pub timestamp: u64,
}

#[derive(Debug, PartialEq, Eq)]
struct OwnedFileSpec {
    root: &'static Path,
    relative_path: String,
    content: Vec<u8>,
    mode: u32,
    refresh: Option<(&'static str, &'static [&'static str])>,
}

struct ConfigurationExecutorContext<'a> {
    managed_config_root: &'a Path,
    dconf_root: &'a Path,
    chrome_policy_root: &'a Path,
    chromium_policy_root: &'a Path,
    refresh_dconf: bool,
}

fn production_configuration_context() -> ConfigurationExecutorContext<'static> {
    ConfigurationExecutorContext {
        managed_config_root: Path::new("/etc/merlin/managed-config"),
        dconf_root: Path::new("/etc/dconf/db/local.d"),
        chrome_policy_root: Path::new("/etc/opt/chrome/policies/managed"),
        chromium_policy_root: Path::new("/etc/chromium/policies/managed"),
        refresh_dconf: true,
    }
}

impl DesiredState {
    pub fn parse(source: &str) -> Result<Self> {
        let document: Self = serde_yaml::from_str(source).context("decoding desired_state.v1")?;
        document.validate()?;
        Ok(document)
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.schema == "desired_state.v1",
            "unsupported desired-state schema"
        );
        anyhow::ensure!(self.revision > 0, "desired-state revision must be positive");
        anyhow::ensure!(
            self.target.platform == "linux",
            "desired state targets another platform"
        );
        anyhow::ensure!(
            !self.assertions.is_empty() && self.assertions.len() <= 256,
            "desired state must contain 1-256 assertions"
        );
        let mut ids = BTreeSet::new();
        for assertion in &self.assertions {
            anyhow::ensure!(
                valid_token(&assertion.assertion_id, 128),
                "invalid assertion id"
            );
            anyhow::ensure!(
                ids.insert(&assertion.assertion_id),
                "duplicate assertion id"
            );
            let selected = usize::from(assertion.system_package.is_some())
                + usize::from(assertion.system_service.is_some())
                + usize::from(assertion.system_file.is_some())
                + usize::from(assertion.system_sysctl.is_some())
                + usize::from(assertion.desktop_dconf.is_some())
                + usize::from(assertion.browser_policy.is_some())
                + usize::from(assertion.security_screen_lock.is_some());
            anyhow::ensure!(
                selected == 1,
                "assertion must select exactly one reviewed executor"
            );
            if let Some(value) = &assertion.system_package {
                anyhow::ensure!(valid_package(&value.name), "invalid package name");
                anyhow::ensure!(
                    value.version.as_deref().map_or(true, valid_package_version),
                    "invalid package version"
                );
                anyhow::ensure!(
                    !matches!(value.state, PackageState::Absent) || value.version.is_none(),
                    "absent packages cannot select a version"
                );
            }
            if let Some(value) = &assertion.system_service {
                anyhow::ensure!(valid_service(&value.name), "invalid systemd unit");
                anyhow::ensure!(
                    value.enabled.is_some() || value.running.is_some(),
                    "service assertion must select enabled or running state"
                );
            }
            if let Some(value) = &assertion.system_file {
                anyhow::ensure!(
                    value.path_class == "managed_config" && valid_relative_path(&value.path),
                    "invalid managed file path"
                );
                anyhow::ensure!(
                    value.mode.as_deref().map_or(true, valid_file_mode),
                    "invalid managed file mode"
                );
                match value.state {
                    FileState::Present => {
                        let encoded = value
                            .content_base64
                            .as_deref()
                            .context("present managed file requires content")?;
                        let decoded = base64::engine::general_purpose::STANDARD
                            .decode(encoded)
                            .context("invalid managed file content")?;
                        anyhow::ensure!(
                            !encoded.is_empty() && decoded.len() <= 256 << 10,
                            "invalid managed file content"
                        );
                    }
                    FileState::Absent => anyhow::ensure!(
                        value.content_base64.is_none(),
                        "absent managed file cannot contain content"
                    ),
                }
            }
            if let Some(value) = &assertion.system_sysctl {
                anyhow::ensure!(valid_sysctl(&value.name), "invalid sysctl name");
                anyhow::ensure!(valid_text(&value.value, 256), "invalid sysctl value");
            }
            if let Some(value) = &assertion.desktop_dconf {
                anyhow::ensure!(
                    valid_dconf_key(&value.key) && valid_text(&value.value, 4096),
                    "invalid dconf key or value"
                );
            }
            if let Some(value) = &assertion.browser_policy {
                anyhow::ensure!(
                    valid_browser_policy_name(&value.name)
                        && value.value_json.len() <= 16 << 10
                        && serde_json::from_str::<Value>(&value.value_json).is_ok(),
                    "invalid browser policy name or value"
                );
            }
            if let Some(value) = &assertion.security_screen_lock {
                let idle_seconds = value.idle_seconds.unwrap_or_default();
                anyhow::ensure!(
                    value.enabled && (1..=86_400).contains(&idle_seconds)
                        || !value.enabled && idle_seconds == 0,
                    "invalid screen-lock idle seconds"
                );
            }
        }
        Ok(())
    }

    pub fn plan(&self) -> Result<Vec<PlannedAssertion>> {
        self.validate()?;
        self.assertions
            .iter()
            .map(|assertion| {
                let operations = if let Some(value) = &assertion.system_package {
                    match value.state {
                        PackageState::Present => vec![NativeOperation::AptEnsurePresent {
                            package: value.name.clone(),
                            version: value.version.clone(),
                        }],
                        PackageState::Absent => vec![NativeOperation::AptEnsureAbsent {
                            package: value.name.clone(),
                        }],
                    }
                } else if let Some(value) = &assertion.system_service {
                    let mut operations = Vec::with_capacity(2);
                    if let Some(enabled) = value.enabled {
                        operations.push(NativeOperation::SystemdSetEnabled {
                            unit: value.name.clone(),
                            enabled,
                        });
                    }
                    if let Some(running) = value.running {
                        operations.push(NativeOperation::SystemdSetRunning {
                            unit: value.name.clone(),
                            running,
                        });
                    }
                    operations
                } else if let Some(value) = &assertion.system_file {
                    match value.state {
                        FileState::Present => vec![NativeOperation::ManagedFileEnsurePresent {
                            relative_path: value.path.clone(),
                            content_base64: value.content_base64.clone().unwrap_or_default(),
                            mode: value.mode.clone().unwrap_or_else(|| "0600".into()),
                        }],
                        FileState::Absent => vec![NativeOperation::ManagedFileEnsureAbsent {
                            relative_path: value.path.clone(),
                        }],
                    }
                } else if let Some(value) = &assertion.system_sysctl {
                    vec![NativeOperation::SysctlSet {
                        name: value.name.clone(),
                        value: value.value.clone(),
                    }]
                } else if let Some(value) = &assertion.desktop_dconf {
                    vec![NativeOperation::DconfSet {
                        key: value.key.clone(),
                        value: value.value.clone(),
                    }]
                } else if let Some(value) = &assertion.browser_policy {
                    vec![NativeOperation::BrowserPolicySet {
                        browser: value.browser,
                        name: value.name.clone(),
                        value: serde_json::from_str(&value.value_json)
                            .context("decoding browser policy value")?,
                    }]
                } else if let Some(value) = &assertion.security_screen_lock {
                    vec![NativeOperation::ScreenLockSet {
                        enabled: value.enabled,
                        idle_seconds: value.idle_seconds.unwrap_or_default(),
                    }]
                } else {
                    unreachable!("validated assertion has one operation")
                };
                Ok(PlannedAssertion {
                    assertion_id: assertion.assertion_id.clone(),
                    operations,
                })
            })
            .collect()
    }

    pub fn apply(&self, device_id: &str, artifact_sha: &str) -> Result<Vec<AssertionReceipt>> {
        let mut receipts = Vec::with_capacity(self.assertions.len());
        for assertion in self.plan()? {
            receipts.push(apply_assertion(device_id, artifact_sha, assertion));
        }
        Ok(receipts)
    }
}

pub fn parse_artifact(source: &str) -> Result<(Rules, DesiredState)> {
    let artifact: EndpointArtifact =
        serde_yaml::from_str(source).context("decoding desired-state policy artifact")?;
    artifact.desired_state.validate()?;
    Ok((
        Rules {
            schema_version: artifact.schema_version,
            rules: artifact.rules,
            doh_resolvers: artifact.doh_resolvers,
        },
        artifact.desired_state,
    ))
}

fn apply_assertion(
    device_id: &str,
    artifact_sha: &str,
    assertion: PlannedAssertion,
) -> AssertionReceipt {
    let before = observe_all(&assertion.operations);
    let mut actions = Vec::new();
    let mut failure = None;
    for operation in &assertion.operations {
        match operation_satisfied(operation) {
            Ok(true) => {}
            Ok(false) => {
                actions.push(serde_json::to_value(operation).unwrap_or_else(|_| json!({})));
                if let Err(error) = execute_operation(operation) {
                    failure = Some(error.to_string());
                    break;
                }
            }
            Err(error) => {
                failure = Some(error.to_string());
                break;
            }
        }
    }
    let after = observe_all(&assertion.operations);
    let satisfied = assertion
        .operations
        .iter()
        .all(|operation| operation_satisfied(operation).unwrap_or(false));
    let result = if failure.is_some() || !satisfied {
        "failed"
    } else if actions.is_empty() {
        "compliant"
    } else {
        "applied"
    };
    AssertionReceipt {
        device_id: device_id.to_string(),
        artifact_sha: artifact_sha.to_string(),
        assertion_id: assertion.assertion_id,
        observed_before: before,
        action_taken: json!({"operations": actions, "error": failure}),
        observed_after: after,
        result,
        reboot_required: false,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    }
}

fn observe_all(operations: &[NativeOperation]) -> Value {
    Value::Array(
        operations
            .iter()
            .map(|operation| match observe_operation(operation) {
                Ok(value) => value,
                Err(error) => json!({"error": error.to_string()}),
            })
            .collect(),
    )
}

fn operation_satisfied(operation: &NativeOperation) -> Result<bool> {
    match (operation, observe_operation(operation)?) {
        (NativeOperation::AptEnsurePresent { version, .. }, observed) => {
            Ok(observed["present"].as_bool() == Some(true)
                && version
                    .as_ref()
                    .map_or(true, |wanted| observed["version"].as_str() == Some(wanted)))
        }
        (NativeOperation::AptEnsureAbsent { .. }, observed) => {
            Ok(observed["present"].as_bool() == Some(false))
        }
        (NativeOperation::SystemdSetEnabled { enabled, .. }, observed) => {
            Ok(observed["enabled"].as_bool() == Some(*enabled))
        }
        (NativeOperation::SystemdSetRunning { running, .. }, observed) => {
            Ok(observed["running"].as_bool() == Some(*running))
        }
        (NativeOperation::ManagedFileEnsurePresent { .. }, observed)
        | (NativeOperation::DconfSet { .. }, observed)
        | (NativeOperation::BrowserPolicySet { .. }, observed)
        | (NativeOperation::ScreenLockSet { .. }, observed) => {
            Ok(observed["compliant"].as_bool() == Some(true))
        }
        (NativeOperation::ManagedFileEnsureAbsent { .. }, observed) => {
            Ok(observed["absent"].as_bool() == Some(true))
        }
        (NativeOperation::SysctlSet { value, .. }, observed) => {
            Ok(observed["value"].as_str() == Some(value))
        }
    }
}

fn observe_operation(operation: &NativeOperation) -> Result<Value> {
    match operation {
        NativeOperation::AptEnsurePresent { package, .. }
        | NativeOperation::AptEnsureAbsent { package } => {
            let output = run(
                "/usr/bin/dpkg-query",
                &["-W", "-f=${Status}\t${Version}", package],
            )?;
            if !output.status.success() {
                return Ok(json!({"present": false}));
            }
            let text = String::from_utf8_lossy(&output.stdout);
            let (status, version) = text.trim().split_once('\t').unwrap_or((text.trim(), ""));
            Ok(json!({"present": status == "install ok installed", "version": version}))
        }
        NativeOperation::SystemdSetEnabled { unit, .. } => {
            let output = run("/usr/bin/systemctl", &["is-enabled", unit])?;
            Ok(json!({"enabled": output.status.success()}))
        }
        NativeOperation::SystemdSetRunning { unit, .. } => {
            let output = run("/usr/bin/systemctl", &["is-active", "--quiet", unit])?;
            Ok(json!({"running": output.status.success()}))
        }
        NativeOperation::SysctlSet { name, .. } => {
            let output = run("/usr/sbin/sysctl", &["-n", name])?;
            anyhow::ensure!(output.status.success(), "sysctl observation failed");
            Ok(json!({"value": String::from_utf8_lossy(&output.stdout).trim()}))
        }
        NativeOperation::ManagedFileEnsurePresent {
            relative_path,
            mode,
            ..
        } => Ok(json!({
            "path_class": "managed_config",
            "path": relative_path,
            "mode": mode,
            "compliant": configuration_operation_satisfied(
                operation,
                &production_configuration_context(),
            )?,
        })),
        NativeOperation::ManagedFileEnsureAbsent { relative_path } => Ok(json!({
            "path_class": "managed_config",
            "path": relative_path,
            "absent": configuration_operation_satisfied(
                operation,
                &production_configuration_context(),
            )?,
        })),
        NativeOperation::DconfSet { key, .. } => Ok(json!({
            "key": key,
            "compliant": configuration_operation_satisfied(
                operation,
                &production_configuration_context(),
            )?,
        })),
        NativeOperation::BrowserPolicySet { browser, name, .. } => Ok(json!({
            "browser": browser,
            "name": name,
            "compliant": configuration_operation_satisfied(
                operation,
                &production_configuration_context(),
            )?,
        })),
        NativeOperation::ScreenLockSet {
            enabled,
            idle_seconds,
        } => Ok(json!({
            "enabled": enabled,
            "idle_seconds": idle_seconds,
            "compliant": configuration_operation_satisfied(
                operation,
                &production_configuration_context(),
            )?,
        })),
    }
}

fn execute_operation(operation: &NativeOperation) -> Result<()> {
    if matches!(
        operation,
        NativeOperation::ManagedFileEnsurePresent { .. }
            | NativeOperation::ManagedFileEnsureAbsent { .. }
            | NativeOperation::DconfSet { .. }
            | NativeOperation::BrowserPolicySet { .. }
            | NativeOperation::ScreenLockSet { .. }
    ) {
        return execute_configuration_operation(operation, &production_configuration_context());
    }
    let (program, arguments): (&str, Vec<String>) = match operation {
        NativeOperation::AptEnsurePresent { package, version } => (
            "/usr/bin/apt-get",
            vec![
                "install".into(),
                "--yes".into(),
                "--no-install-recommends".into(),
                version
                    .as_ref()
                    .map_or_else(|| package.clone(), |version| format!("{package}={version}")),
            ],
        ),
        NativeOperation::AptEnsureAbsent { package } => (
            "/usr/bin/apt-get",
            vec!["remove".into(), "--yes".into(), package.clone()],
        ),
        NativeOperation::SystemdSetEnabled { unit, enabled } => (
            "/usr/bin/systemctl",
            vec![
                if *enabled { "enable" } else { "disable" }.into(),
                unit.clone(),
            ],
        ),
        NativeOperation::SystemdSetRunning { unit, running } => (
            "/usr/bin/systemctl",
            vec![if *running { "start" } else { "stop" }.into(), unit.clone()],
        ),
        NativeOperation::SysctlSet { name, value } => (
            "/usr/sbin/sysctl",
            vec!["-w".into(), format!("{name}={value}")],
        ),
        NativeOperation::ManagedFileEnsurePresent { .. }
        | NativeOperation::ManagedFileEnsureAbsent { .. }
        | NativeOperation::DconfSet { .. }
        | NativeOperation::BrowserPolicySet { .. }
        | NativeOperation::ScreenLockSet { .. } => {
            unreachable!("configuration operations return before command planning")
        }
    };
    let refs: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let output = run(program, &refs)?;
    anyhow::ensure!(
        output.status.success(),
        "{} executor failed: {}",
        operation_name(operation),
        String::from_utf8_lossy(&output.stderr)
            .trim()
            .chars()
            .take(512)
            .collect::<String>()
    );
    Ok(())
}

fn run(program: &str, arguments: &[&str]) -> Result<Output> {
    let mut child = Command::new(program)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("DEBIAN_FRONTEND", "noninteractive")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting reviewed executor {program}"))?;
    let stdout = child.stdout.take().context("capturing executor stdout")?;
    let stderr = child.stderr.take().context("capturing executor stderr")?;
    let stdout_reader = thread::spawn(move || read_bounded(stdout));
    let stderr_reader = thread::spawn(move || read_bounded(stderr));
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(error).context("polling reviewed executor");
            }
        }
        if started.elapsed() >= EXECUTOR_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            anyhow::bail!("reviewed executor {program} exceeded its 120 second limit");
        }
        thread::sleep(Duration::from_millis(50));
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| anyhow::anyhow!("executor stdout reader panicked"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow::anyhow!("executor stderr reader panicked"))??;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn read_bounded(mut reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut retained = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(retained);
        }
        let remaining = MAX_EXECUTOR_OUTPUT_BYTES.saturating_sub(retained.len());
        retained.extend_from_slice(&buffer[..read.min(remaining)]);
    }
}

fn reconcile_owned_file(
    root: &Path,
    relative_path: &str,
    desired: Option<(&[u8], u32)>,
) -> Result<()> {
    anyhow::ensure!(
        valid_relative_path(relative_path),
        "invalid owned relative path"
    );
    let components = Path::new(relative_path)
        .components()
        .map(|component| match component {
            Component::Normal(value) => Ok(value),
            _ => anyhow::bail!("invalid owned path component"),
        })
        .collect::<Result<Vec<_>>>()?;
    let (file_name, parents) = components
        .split_last()
        .context("owned path requires a file name")?;

    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)
        .with_context(|| format!("opening owned directory {}", root.display()))?;
    for component in parents {
        directory = open_or_create_owned_directory(&directory, component, 0o700)?;
    }

    let file_name = c_string(file_name)?;
    match desired {
        Some((content, mode)) => {
            anyhow::ensure!(mode <= 0o777, "invalid owned file mode");
            write_owned_file(&directory, &file_name, content, mode)
        }
        None => {
            let result = unsafe { libc::unlinkat(directory.as_raw_fd(), file_name.as_ptr(), 0) };
            if result == 0 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) {
                Ok(())
            } else {
                Err(error).context("removing owned file")
            }
        }
    }
}

fn ensure_owned_directory(path: &Path, mode: u32) -> Result<()> {
    anyhow::ensure!(path.is_absolute(), "owned directory must be absolute");
    anyhow::ensure!(mode <= 0o777, "invalid owned directory mode");
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .context("opening owned directory root")?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) => {
                directory = open_or_create_owned_directory(&directory, value, mode)?;
            }
            _ => anyhow::bail!("invalid absolute owned directory component"),
        }
    }
    Ok(())
}

fn owned_file_matches(root: &Path, relative_path: &str, content: &[u8], mode: u32) -> Result<bool> {
    let Some(file) = open_owned_file(root, relative_path)? else {
        return Ok(false);
    };
    let metadata = file.metadata().context("inspecting owned file")?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o777 != mode {
        return Ok(false);
    }
    let mut observed = Vec::with_capacity(content.len().saturating_add(1));
    file.take(content.len().saturating_add(1) as u64)
        .read_to_end(&mut observed)
        .context("reading owned file")?;
    Ok(observed == content)
}

fn open_owned_file(root: &Path, relative_path: &str) -> Result<Option<File>> {
    anyhow::ensure!(
        valid_relative_path(relative_path),
        "invalid owned relative path"
    );
    let components = Path::new(relative_path)
        .components()
        .map(|component| match component {
            Component::Normal(value) => Ok(value),
            _ => anyhow::bail!("invalid owned path component"),
        })
        .collect::<Result<Vec<_>>>()?;
    let (file_name, parents) = components
        .split_last()
        .context("owned path requires a file name")?;
    let mut directory = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)
    {
        Ok(directory) => directory,
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("opening owned directory {}", root.display()));
        }
    };
    for component in parents {
        match open_owned_directory_at(&directory, &c_string(component)?) {
            Ok(next) => directory = next,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
            Err(error) => return Err(error).context("opening owned directory component"),
        }
    }
    let file_name = c_string(file_name)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            file_name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(error).context("opening owned file");
    }
    Ok(Some(unsafe { File::from_raw_fd(fd) }))
}

fn configuration_operation_satisfied(
    operation: &NativeOperation,
    context: &ConfigurationExecutorContext<'_>,
) -> Result<bool> {
    if let NativeOperation::ManagedFileEnsureAbsent { relative_path } = operation {
        return Ok(open_owned_file(context.managed_config_root, relative_path)?.is_none());
    }
    let root = configuration_root(operation, context)?;
    for spec in owned_file_specs(operation)? {
        if !owned_file_matches(root, &spec.relative_path, &spec.content, spec.mode)? {
            return Ok(false);
        }
        if context.refresh_dconf
            && spec.refresh.is_some()
            && !dconf_database_is_current(context.dconf_root, &spec.relative_path)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn dconf_database_is_current(root: &Path, relative_path: &str) -> Result<bool> {
    let Some(fragment) = open_owned_file(root, relative_path)? else {
        return Ok(false);
    };
    let parent = root.parent().context("dconf root requires a parent")?;
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)
        .context("opening dconf database directory")?;
    let database_name = CString::new("local").unwrap();
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            database_name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(false);
        }
        return Err(error).context("opening compiled dconf database");
    }
    let database = unsafe { File::from_raw_fd(fd) };
    let fragment = fragment.metadata().context("inspecting dconf fragment")?;
    let database = database
        .metadata()
        .context("inspecting compiled dconf database")?;
    anyhow::ensure!(database.is_file(), "compiled dconf database is not a file");
    Ok((database.mtime(), database.mtime_nsec()) >= (fragment.mtime(), fragment.mtime_nsec()))
}

fn execute_configuration_operation(
    operation: &NativeOperation,
    context: &ConfigurationExecutorContext<'_>,
) -> Result<()> {
    let root = configuration_root(operation, context)?;
    let root_mode = if matches!(
        operation,
        NativeOperation::ManagedFileEnsurePresent { .. }
            | NativeOperation::ManagedFileEnsureAbsent { .. }
    ) {
        0o700
    } else {
        0o755
    };
    ensure_owned_directory(root, root_mode)?;
    if let NativeOperation::ManagedFileEnsureAbsent { relative_path } = operation {
        return reconcile_owned_file(root, relative_path, None);
    }
    let specs = owned_file_specs(operation)?;
    for spec in &specs {
        reconcile_owned_file(root, &spec.relative_path, Some((&spec.content, spec.mode)))?;
    }
    if context.refresh_dconf {
        if let Some((program, arguments)) = specs.iter().find_map(|spec| spec.refresh) {
            let output = run(program, arguments)?;
            anyhow::ensure!(
                output.status.success(),
                "dconf executor failed: {}",
                String::from_utf8_lossy(&output.stderr)
                    .trim()
                    .chars()
                    .take(512)
                    .collect::<String>()
            );
        }
    }
    Ok(())
}

fn configuration_root<'a>(
    operation: &NativeOperation,
    context: &'a ConfigurationExecutorContext<'_>,
) -> Result<&'a Path> {
    match operation {
        NativeOperation::ManagedFileEnsurePresent { .. }
        | NativeOperation::ManagedFileEnsureAbsent { .. } => Ok(context.managed_config_root),
        NativeOperation::DconfSet { .. } | NativeOperation::ScreenLockSet { .. } => {
            Ok(context.dconf_root)
        }
        NativeOperation::BrowserPolicySet { browser, .. } => match browser {
            Browser::Chrome => Ok(context.chrome_policy_root),
            Browser::Chromium => Ok(context.chromium_policy_root),
        },
        _ => anyhow::bail!("operation is not a configuration executor"),
    }
}

fn owned_file_specs(operation: &NativeOperation) -> Result<Vec<OwnedFileSpec>> {
    match operation {
        NativeOperation::ManagedFileEnsurePresent {
            relative_path,
            content_base64,
            mode,
        } => Ok(vec![OwnedFileSpec {
            root: Path::new("/etc/merlin/managed-config"),
            relative_path: relative_path.clone(),
            content: base64::engine::general_purpose::STANDARD
                .decode(content_base64)
                .context("decoding managed file content")?,
            mode: u32::from_str_radix(mode, 8)
                .context("decoding managed file mode")?,
            refresh: None,
        }]),
        NativeOperation::DconfSet { key, value } => {
            let (group, name) = key
                .rsplit_once('/')
                .filter(|(group, name)| !group.is_empty() && !name.is_empty())
                .context("invalid dconf key")?;
            let digest = Sha256::digest(key.as_bytes());
            Ok(vec![OwnedFileSpec {
                root: Path::new("/etc/dconf/db/local.d"),
                relative_path: format!("90-deixic-{digest:x}")[..26].to_string(),
                content: format!("[{}]\n{name}={value}\n", group.trim_start_matches('/'))
                    .into_bytes(),
                mode: 0o644,
                refresh: Some(("/usr/bin/dconf", &["update"])),
            }])
        }
        NativeOperation::BrowserPolicySet {
            browser,
            name,
            value,
        } => {
            let root = match browser {
                Browser::Chrome => Path::new("/etc/opt/chrome/policies/managed"),
                Browser::Chromium => Path::new("/etc/chromium/policies/managed"),
            };
            let mut policy = serde_json::Map::new();
            policy.insert(name.clone(), value.clone());
            let mut content = serde_json::to_vec(&Value::Object(policy))
                .context("encoding browser policy")?;
            content.push(b'\n');
            Ok(vec![OwnedFileSpec {
                root,
                relative_path: format!("deixic-{name}.json"),
                content,
                mode: 0o644,
                refresh: None,
            }])
        }
        NativeOperation::ScreenLockSet {
            enabled,
            idle_seconds,
        } => Ok(vec![
            OwnedFileSpec {
                root: Path::new("/etc/dconf/db/local.d"),
                relative_path: "90-deixic-screen-lock".into(),
                content: format!(
                    "[org/gnome/desktop/session]\nidle-delay=uint32 {idle_seconds}\n[org/gnome/desktop/screensaver]\nlock-enabled={enabled}\nlock-delay=uint32 0\n"
                )
                .into_bytes(),
                mode: 0o644,
                refresh: Some(("/usr/bin/dconf", &["update"])),
            },
            OwnedFileSpec {
                root: Path::new("/etc/dconf/db/local.d"),
                relative_path: "locks/90-deixic-screen-lock".into(),
                content: b"/org/gnome/desktop/session/idle-delay\n/org/gnome/desktop/screensaver/lock-enabled\n/org/gnome/desktop/screensaver/lock-delay\n".to_vec(),
                mode: 0o644,
                refresh: Some(("/usr/bin/dconf", &["update"])),
            },
        ]),
        _ => anyhow::bail!("operation does not own a configuration file"),
    }
}

fn open_or_create_owned_directory(parent: &File, component: &OsStr, mode: u32) -> Result<File> {
    let component = c_string(component)?;
    match open_owned_directory_at(parent, &component) {
        Ok(directory) => Ok(directory),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
            let created = unsafe { libc::mkdirat(parent.as_raw_fd(), component.as_ptr(), mode) };
            if created != 0 {
                let create_error = std::io::Error::last_os_error();
                if create_error.raw_os_error() != Some(libc::EEXIST) {
                    return Err(create_error).context("creating owned directory");
                }
            }
            open_owned_directory_at(parent, &component)
                .context("opening owned directory after creation")
        }
        Err(error) => Err(error).context("opening owned directory component"),
    }
}

fn open_owned_directory_at(parent: &File, component: &CString) -> std::io::Result<File> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            component.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn write_owned_file(parent: &File, file_name: &CString, content: &[u8], mode: u32) -> Result<()> {
    let temp_name = CString::new(format!(
        ".deixic-{}-{}.tmp",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ))
    .context("building owned temporary file name")?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            temp_name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("creating owned temporary file");
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let result = (|| -> Result<()> {
        file.write_all(content).context("writing owned file")?;
        let changed = unsafe { libc::fchmod(file.as_raw_fd(), mode) };
        if changed != 0 {
            return Err(std::io::Error::last_os_error()).context("setting owned file mode");
        }
        file.sync_all().context("syncing owned file")?;
        let renamed = unsafe {
            libc::renameat(
                parent.as_raw_fd(),
                temp_name.as_ptr(),
                parent.as_raw_fd(),
                file_name.as_ptr(),
            )
        };
        if renamed != 0 {
            return Err(std::io::Error::last_os_error()).context("installing owned file");
        }
        parent.sync_all().context("syncing owned file directory")?;
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(parent.as_raw_fd(), temp_name.as_ptr(), 0);
        }
    }
    result
}

fn c_string(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes()).context("owned path contains NUL")
}

fn operation_name(operation: &NativeOperation) -> &'static str {
    match operation {
        NativeOperation::AptEnsurePresent { .. } | NativeOperation::AptEnsureAbsent { .. } => "apt",
        NativeOperation::SystemdSetEnabled { .. } | NativeOperation::SystemdSetRunning { .. } => {
            "systemd"
        }
        NativeOperation::SysctlSet { .. } => "sysctl",
        NativeOperation::ManagedFileEnsurePresent { .. }
        | NativeOperation::ManagedFileEnsureAbsent { .. } => "file",
        NativeOperation::DconfSet { .. } => "dconf",
        NativeOperation::BrowserPolicySet { .. } => "browser_policy",
        NativeOperation::ScreenLockSet { .. } => "screen_lock",
    }
}

fn valid_token(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
}

fn valid_package(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"+.-".contains(&byte)
        })
}

fn valid_package_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".+:~_-".contains(&byte))
}

fn valid_service(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"@_.:-".contains(&byte))
}

fn valid_sysctl(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && (value.as_bytes()[0].is_ascii_lowercase()
            || value.as_bytes()[0].is_ascii_digit()
            || value.as_bytes()[0] == b'_')
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_.-".contains(&byte)
        })
}

fn valid_text(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && !value.bytes().any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
}

fn valid_dconf_key(value: &str) -> bool {
    value.starts_with('/')
        && valid_text(value, 256)
        && value.split('/').skip(1).all(|component| {
            !component.is_empty()
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
}

fn valid_relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && Path::new(value)
            .components()
            .all(|component| matches!(component, Component::Normal(name) if !name.is_empty()))
}

fn valid_file_mode(value: &str) -> bool {
    value.len() == 4
        && value.starts_with('0')
        && value
            .bytes()
            .skip(1)
            .all(|byte| matches!(byte, b'0'..=b'7'))
}

fn valid_browser_policy_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn unique_test_dir(name: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "merlin-desired-state-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn typed_assertions_plan_only_reviewed_native_operations() {
        let document = DesiredState::parse(
            r#"
schema: desired_state.v1
revision: 42
target:
  platform: linux
assertions:
  - assertion_id: package.openssh
    system.package: {name: openssh-server, state: present}
  - assertion_id: service.ssh
    system.service: {name: ssh, enabled: true, running: true}
  - assertion_id: sysctl.kptr
    system.sysctl: {name: kernel.kptr_restrict, value: "2"}
"#,
        )
        .unwrap();

        assert_eq!(
            document.plan().unwrap(),
            vec![
                PlannedAssertion {
                    assertion_id: "package.openssh".into(),
                    operations: vec![NativeOperation::AptEnsurePresent {
                        package: "openssh-server".into(),
                        version: None,
                    }],
                },
                PlannedAssertion {
                    assertion_id: "service.ssh".into(),
                    operations: vec![
                        NativeOperation::SystemdSetEnabled {
                            unit: "ssh".into(),
                            enabled: true,
                        },
                        NativeOperation::SystemdSetRunning {
                            unit: "ssh".into(),
                            running: true,
                        },
                    ],
                },
                PlannedAssertion {
                    assertion_id: "sysctl.kptr".into(),
                    operations: vec![NativeOperation::SysctlSet {
                        name: "kernel.kptr_restrict".into(),
                        value: "2".into(),
                    }],
                },
            ]
        );
    }

    #[test]
    fn configuration_assertions_plan_fixed_native_operations() {
        let document = DesiredState::parse(
            r#"
schema: desired_state.v1
revision: 43
target:
  platform: linux
assertions:
  - assertion_id: file.banner
    system.file:
      path_class: managed_config
      path: ssh/banner.txt
      state: present
      content_base64: b2sK
      mode: "0640"
  - assertion_id: desktop.idle
    desktop.dconf:
      key: /org/gnome/desktop/session/idle-delay
      value: uint32 900
  - assertion_id: browser.home
    browser.policy:
      browser: chrome
      name: HomepageLocation
      value_json: '"https://example.com/"'
  - assertion_id: screen.lock
    security.screen_lock:
      enabled: true
      idle_seconds: 900
"#,
        )
        .unwrap();

        let planned = document
            .plan()
            .unwrap()
            .into_iter()
            .map(|assertion| {
                json!({
                    "assertion_id": assertion.assertion_id,
                    "operations": assertion.operations,
                })
            })
            .collect::<Vec<_>>();

        assert_eq!(
            planned,
            vec![
                json!({
                    "assertion_id": "file.banner",
                    "operations": [{
                        "executor": "managed_file_ensure_present",
                        "relative_path": "ssh/banner.txt",
                        "content_base64": "b2sK",
                        "mode": "0640"
                    }]
                }),
                json!({
                    "assertion_id": "desktop.idle",
                    "operations": [{
                        "executor": "dconf_set",
                        "key": "/org/gnome/desktop/session/idle-delay",
                        "value": "uint32 900"
                    }]
                }),
                json!({
                    "assertion_id": "browser.home",
                    "operations": [{
                        "executor": "browser_policy_set",
                        "browser": "chrome",
                        "name": "HomepageLocation",
                        "value": "https://example.com/"
                    }]
                }),
                json!({
                    "assertion_id": "screen.lock",
                    "operations": [{
                        "executor": "screen_lock_set",
                        "enabled": true,
                        "idle_seconds": 900
                    }]
                }),
            ]
        );
    }

    #[test]
    fn owned_file_reconciliation_writes_mode_and_removes_the_file() {
        let root = unique_test_dir("owned-file");
        reconcile_owned_file(&root, "ssh/banner.txt", Some((b"ok\n", 0o640))).unwrap();

        let path = root.join("ssh/banner.txt");
        assert_eq!(fs::read(&path).unwrap(), b"ok\n");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );

        reconcile_owned_file(&root, "ssh/banner.txt", None).unwrap();
        assert!(!path.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn owned_file_reconciliation_rejects_a_symlinked_parent() {
        let root = unique_test_dir("owned-file-link");
        let outside = unique_test_dir("owned-file-outside");
        symlink(&outside, root.join("escape")).unwrap();

        let error =
            reconcile_owned_file(&root, "escape/owned", Some((b"nope", 0o600))).unwrap_err();

        assert!(
            format!("{error:#}").contains("opening owned directory"),
            "{error:#}"
        );
        assert!(!outside.join("owned").exists());
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn configuration_operations_render_only_owned_canonical_files() {
        let cases = [
            (
                NativeOperation::ManagedFileEnsurePresent {
                    relative_path: "ssh/banner.txt".into(),
                    content_base64: "b2sK".into(),
                    mode: "0640".into(),
                },
                vec![OwnedFileSpec {
                    root: Path::new("/etc/merlin/managed-config"),
                    relative_path: "ssh/banner.txt".into(),
                    content: b"ok\n".to_vec(),
                    mode: 0o640,
                    refresh: None,
                }],
            ),
            (
                NativeOperation::DconfSet {
                    key: "/org/gnome/desktop/session/idle-delay".into(),
                    value: "uint32 900".into(),
                },
                vec![OwnedFileSpec {
                    root: Path::new("/etc/dconf/db/local.d"),
                    relative_path: "90-deixic-4b9df683c181b203".into(),
                    content: b"[org/gnome/desktop/session]\nidle-delay=uint32 900\n".to_vec(),
                    mode: 0o644,
                    refresh: Some(("/usr/bin/dconf", &["update"])),
                }],
            ),
            (
                NativeOperation::BrowserPolicySet {
                    browser: Browser::Chrome,
                    name: "HomepageLocation".into(),
                    value: json!("https://example.com/"),
                },
                vec![OwnedFileSpec {
                    root: Path::new("/etc/opt/chrome/policies/managed"),
                    relative_path: "deixic-HomepageLocation.json".into(),
                    content: b"{\"HomepageLocation\":\"https://example.com/\"}\n".to_vec(),
                    mode: 0o644,
                    refresh: None,
                }],
            ),
            (
                NativeOperation::ScreenLockSet {
                    enabled: true,
                    idle_seconds: 900,
                },
                vec![
                    OwnedFileSpec {
                        root: Path::new("/etc/dconf/db/local.d"),
                        relative_path: "90-deixic-screen-lock".into(),
                        content: b"[org/gnome/desktop/session]\nidle-delay=uint32 900\n[org/gnome/desktop/screensaver]\nlock-enabled=true\nlock-delay=uint32 0\n".to_vec(),
                        mode: 0o644,
                        refresh: Some(("/usr/bin/dconf", &["update"])),
                    },
                    OwnedFileSpec {
                        root: Path::new("/etc/dconf/db/local.d"),
                        relative_path: "locks/90-deixic-screen-lock".into(),
                        content: b"/org/gnome/desktop/session/idle-delay\n/org/gnome/desktop/screensaver/lock-enabled\n/org/gnome/desktop/screensaver/lock-delay\n".to_vec(),
                        mode: 0o644,
                        refresh: Some(("/usr/bin/dconf", &["update"])),
                    },
                ],
            ),
        ];

        for (operation, expected) in cases {
            assert_eq!(owned_file_specs(&operation).unwrap(), expected);
        }
    }

    #[test]
    fn owned_file_observation_compares_content_and_mode_without_following_links() {
        let root = unique_test_dir("owned-file-observe");
        reconcile_owned_file(&root, "policy.json", Some((b"{}\n", 0o644))).unwrap();
        assert!(owned_file_matches(&root, "policy.json", b"{}\n", 0o644).unwrap());
        assert!(!owned_file_matches(&root, "policy.json", b"[]\n", 0o644).unwrap());
        assert!(!owned_file_matches(&root, "policy.json", b"{}\n", 0o600).unwrap());

        let outside = unique_test_dir("owned-file-observe-outside").join("target");
        fs::write(&outside, b"{}\n").unwrap();
        symlink(&outside, root.join("linked.json")).unwrap();
        let error = owned_file_matches(&root, "linked.json", b"{}\n", 0o644).unwrap_err();
        assert!(
            format!("{error:#}").contains("opening owned file"),
            "{error:#}"
        );

        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside.parent().unwrap()).unwrap();
    }

    #[test]
    fn owned_directory_creation_rejects_a_symlinked_intermediate() {
        let base = unique_test_dir("owned-root");
        let created = base.join("one/two");
        ensure_owned_directory(&created, 0o755).unwrap();
        assert!(created.is_dir());

        let outside = unique_test_dir("owned-root-outside");
        symlink(&outside, base.join("escape")).unwrap();
        let error = ensure_owned_directory(&base.join("escape/child"), 0o755).unwrap_err();
        assert!(
            format!("{error:#}").contains("opening owned directory"),
            "{error:#}"
        );
        assert!(!outside.join("child").exists());

        fs::remove_dir_all(base).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn configuration_executor_transitions_owned_policy_to_compliant() {
        let root = unique_test_dir("configuration-executor");
        let context = ConfigurationExecutorContext {
            managed_config_root: &root,
            dconf_root: &root,
            chrome_policy_root: &root,
            chromium_policy_root: &root,
            refresh_dconf: false,
        };
        let operations = [
            NativeOperation::ManagedFileEnsurePresent {
                relative_path: "ssh/banner.txt".into(),
                content_base64: "b2sK".into(),
                mode: "0640".into(),
            },
            NativeOperation::DconfSet {
                key: "/org/gnome/desktop/session/idle-delay".into(),
                value: "uint32 900".into(),
            },
            NativeOperation::BrowserPolicySet {
                browser: Browser::Chrome,
                name: "HomepageLocation".into(),
                value: json!("https://example.com/"),
            },
            NativeOperation::ScreenLockSet {
                enabled: true,
                idle_seconds: 900,
            },
        ];

        for operation in &operations {
            assert!(!configuration_operation_satisfied(operation, &context).unwrap());
            execute_configuration_operation(operation, &context).unwrap();
            assert!(configuration_operation_satisfied(operation, &context).unwrap());
        }

        let absent = NativeOperation::ManagedFileEnsureAbsent {
            relative_path: "ssh/banner.txt".into(),
        };
        assert!(!configuration_operation_satisfied(&absent, &context).unwrap());
        execute_configuration_operation(&absent, &context).unwrap();
        assert!(configuration_operation_satisfied(&absent, &context).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dconf_compliance_requires_a_fresh_compiled_database() {
        let parent = unique_test_dir("dconf-freshness");
        let root = parent.join("local.d");
        fs::create_dir(&root).unwrap();
        fs::write(parent.join("local"), b"old database").unwrap();
        thread::sleep(Duration::from_millis(10));
        fs::write(root.join("90-deixic-test"), b"[group]\nkey=true\n").unwrap();

        assert!(!dconf_database_is_current(&root, "90-deixic-test").unwrap());

        thread::sleep(Duration::from_millis(10));
        fs::write(parent.join("local"), b"new database").unwrap();
        assert!(dconf_database_is_current(&root, "90-deixic-test").unwrap());
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn arbitrary_shell_is_not_part_of_the_protocol() {
        let error = DesiredState::parse(
            r#"
schema: desired_state.v1
revision: 1
target: {platform: linux}
assertions:
  - assertion_id: nope
    shell: {command: id}
"#,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("unknown field `shell`"),
            "{error:#}"
        );
    }
}
