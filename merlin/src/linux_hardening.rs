//! Read-only native Linux hardening facts. Rules remain server-owned; this
//! module never decides compliance. Missing, truncated or ambiguous evidence
//! omits the relevant fact, while retaining its target row.
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_FILE: u64 = 1 << 20;
const MAX_PACKAGES: u64 = 32 << 20;
const MAX_FILES: usize = 256;
const MAX_OUTPUT: usize = 4 << 20;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
const COLLECTION_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Serialize)]
pub struct HardeningSnapshot {
    schema_version: u8,
    collected_at: String,
    observations: Vec<Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u8,
    targets: Vec<Target>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    kind: String,
    target: String,
    fields: Vec<String>,
    rules: Vec<String>,
}
fn manifest() -> Option<Manifest> {
    let result: Manifest = toml::from_str(include_str!("linux_hardening_targets.toml")).ok()?;
    (result.schema_version == 1
        && result.targets.len() <= 200
        && result
            .targets
            .iter()
            .all(|t| !t.rules.is_empty() && t.rules.len() <= 200 && !t.fields.is_empty())
        && result
            .targets
            .iter()
            .map(|t| (&t.kind, &t.target))
            .collect::<BTreeSet<_>>()
            .len()
            == result.targets.len())
    .then_some(result)
}

pub fn collect() -> HardeningSnapshot {
    let started = Instant::now();
    let collected_at = rfc3339_now();
    let mut host = Host::new(started + COLLECTION_TIMEOUT);
    let observations = manifest()
        .map(|m| {
            m.targets
                .into_iter()
                .map(|target| {
                    let mut row = Map::from_iter([
                        (
                            "id".into(),
                            Value::String(format!("{}:{}", target.kind, target.target)),
                        ),
                        ("kind".into(), Value::String(target.kind.clone())),
                        ("os_family".into(), Value::String("linux".into())),
                        ("target".into(), Value::String(target.target.clone())),
                    ]);
                    if Instant::now() < host.deadline {
                        host.collect(&target, &mut row);
                    }
                    Value::Object(row)
                })
                .collect()
        })
        .unwrap_or_default();
    HardeningSnapshot {
        schema_version: 1,
        collected_at,
        observations,
    }
}

struct Host {
    deadline: Instant,
    packages: Option<Option<BTreeSet<String>>>,
    systemd: Option<Option<BTreeMap<String, BTreeMap<String, String>>>>,
    sockets: Option<Option<BTreeMap<String, BTreeMap<String, String>>>>,
    modprobe: Option<Option<String>>,
    modules: Option<String>,
    mounts: Option<String>,
    fstab: Option<String>,
    sysctl: Option<Option<String>>,
    sshd: Option<Option<String>>,
    audit: Option<Option<String>>,
    persistent_audit: Option<Option<String>>,
    next_boot: Option<Option<String>>,
}
impl Host {
    fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            packages: None,
            systemd: None,
            sockets: None,
            modprobe: None,
            modules: read_text(Path::new("/proc/modules"), MAX_FILE),
            mounts: read_text(
                &PathBuf::from(format!("/proc/{}/mountinfo", std::process::id())),
                MAX_FILE,
            ),
            fstab: read_text(Path::new("/etc/fstab"), MAX_FILE),
            sysctl: None,
            sshd: None,
            audit: None,
            persistent_audit: None,
            next_boot: None,
        }
    }
    fn command(&self, names: &[&str], args: &[&str]) -> Option<String> {
        probe(names, args, self.deadline)
    }
    fn collect(&mut self, t: &Target, row: &mut Map<String, Value>) {
        // Only collector kinds select behavior. No rule identifier is consulted.
        match t.kind.as_str() {
            "file" => {
                if let Some(file) = open_nofollow(Path::new(&t.target), true) {
                    if let Ok(meta) = file.metadata() {
                        row.insert("uid".into(), meta.uid().into());
                        row.insert("gid".into(), meta.gid().into());
                        row.insert(
                            "mode".into(),
                            format!("{:04o}", meta.mode() & 0o7777).into(),
                        );
                    }
                }
            }
            "package" => {
                if self.packages.is_none() {
                    self.packages = Some(self.package_inventory());
                }
                if let Some(Some(packages)) = &self.packages {
                    row.insert(
                        "state".into(),
                        if packages.contains(&t.target) {
                            "installed"
                        } else {
                            "absent"
                        }
                        .into(),
                    );
                }
            }
            "systemd_unit" => self.systemd(t, row),
            "mount" => {
                put(
                    row,
                    "runtime_options",
                    self.mounts
                        .as_deref()
                        .and_then(|raw| mount_options(raw, &t.target)),
                );
                put(
                    row,
                    "persistent_options",
                    self.fstab
                        .as_deref()
                        .filter(|_| !native_mount_override(&t.target))
                        .and_then(|raw| fstab_options(raw, &t.target)),
                );
            }
            "sysctl" => {
                let path = PathBuf::from("/proc/sys").join(t.target.replace('.', "/"));
                if let Some(value) =
                    read_text(&path, 4096).and_then(|v| v.trim().parse::<i64>().ok())
                {
                    row.insert("runtime_value".into(), value.into());
                }
                if self.sysctl.is_none() {
                    self.sysctl = Some(self.sysctl_persistent());
                }
                if let Some(value) = self
                    .sysctl
                    .as_ref()
                    .and_then(Option::as_deref)
                    .and_then(|raw| sysctl_value(raw, &t.target))
                {
                    row.insert("persistent_value".into(), value.into());
                }
            }
            "kernel_module" => self.module(t, row),
            "sshd_setting" => {
                const CONTEXT: &str =
                    "user=root,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=22";
                row.insert("context".into(), CONTEXT.into());
                if self.sshd.is_none() {
                    self.sshd = Some((|| {
                        let (binary, mut args) = running_sshd_invocation()?;
                        args.extend(["-T".to_string(), "-C".into(), CONTEXT.into()]);
                        self.command(
                            &[&binary],
                            &args.iter().map(String::as_str).collect::<Vec<_>>(),
                        )
                    })());
                }
                put(
                    row,
                    "effective_value",
                    self.sshd
                        .as_ref()
                        .and_then(Option::as_deref)
                        .and_then(|raw| sshd_value(raw, &t.target)),
                );
            }
            "sudo_setting" => {
                row.insert(
                    "context".into(),
                    "user=root,runas=ALL,host=local,command=ALL".into(),
                );
                if sudo_policy_unscoped() {
                    if let Some(raw) = self.command(
                        &["/usr/bin/sudo", "/usr/local/bin/sudo"],
                        &["-n", "-ll", "-U", "root"],
                    ) {
                        put(row, "effective_state", sudo_pty(&raw));
                    }
                }
            }
            "boot_argument" => {
                put(
                    row,
                    "runtime_value",
                    read_text(Path::new("/proc/cmdline"), 65536)
                        .and_then(|raw| boot_value(&raw, &t.target)),
                );
                if self.next_boot.is_none() {
                    self.next_boot = Some(resolved_grub_arguments());
                }
                put(
                    row,
                    "persistent_value",
                    self.next_boot
                        .as_ref()
                        .and_then(Option::as_deref)
                        .and_then(|raw| boot_value(raw, &t.target)),
                );
            }
            "audit_watch" => {
                if self.audit.is_none() {
                    self.audit =
                        Some(self.command(&["/usr/sbin/auditctl", "/usr/bin/auditctl"], &["-l"]));
                }
                if self.persistent_audit.is_none() {
                    self.persistent_audit = Some(self.audit_persistent());
                }
                if let Some((abis, certain)) = applicable_abis() {
                    put(
                        row,
                        "runtime_permissions",
                        self.audit
                            .as_ref()
                            .and_then(Option::as_deref)
                            .and_then(|raw| {
                                audit_permissions_scoped(raw, &t.target, &abis, certain)
                            }),
                    );
                    put(
                        row,
                        "persistent_permissions",
                        self.persistent_audit
                            .as_ref()
                            .and_then(Option::as_deref)
                            .and_then(|raw| {
                                audit_permissions_scoped(raw, &t.target, &abis, certain)
                            }),
                    );
                }
            }
            _ => {}
        }
        // Manifest declares exactly which deciding facts each target demands.
        // Context accompanies effective settings; unneeded facts never escape.
        row.retain(|key, _| {
            ["id", "kind", "target", "os_family", "context"].contains(&key.as_str())
                || t.fields.contains(key)
        });
    }
    fn package_inventory(&self) -> Option<BTreeSet<String>> {
        // Read the native database completely. A missing or malformed database
        // cannot establish package absence. Never mix different package owners.
        if Path::new("/var/lib/dpkg/status").try_exists().ok()? {
            return parse_dpkg(&read_text(Path::new("/var/lib/dpkg/status"), MAX_PACKAGES)?);
        }
        if Path::new("/lib/apk/db/installed").try_exists().ok()? {
            return parse_apk(&read_text(
                Path::new("/lib/apk/db/installed"),
                MAX_PACKAGES,
            )?);
        }
        self.command(&["/usr/bin/rpm"], &["-qa", "--qf", "%{NAME}\n"])
            .and_then(|raw| parse_package_lines(&raw))
    }
    fn systemd(&mut self, t: &Target, row: &mut Map<String, Value>) {
        if self.systemd.is_none() {
            self.systemd = Some((|| {
                let manifest = manifest()?;
                let mut args = vec![
                    "show".to_string(),
                    "--no-pager".into(),
                    "--property=Id,Names,LoadState,UnitFileState,ActiveState".into(),
                ];
                for target in manifest.targets.iter().filter(|t| t.kind == "systemd_unit") {
                    args.push(target.target.clone());
                }
                let raw = self.command(
                    &["/usr/bin/systemctl"],
                    &args.iter().map(String::as_str).collect::<Vec<_>>(),
                )?;
                parse_systemd(&raw)
            })());
        }
        let Some(Some(units)) = &self.systemd else {
            return;
        };
        for (name, prefix) in [(t.target.clone(), "")] {
            let Some(unit) = units.get(&name) else {
                continue;
            };
            if unit.get("LoadState").map(String::as_str) == Some("not-found") {
                row.insert(format!("{prefix}unit_file_state"), "not-found".into());
                row.insert(format!("{prefix}active_state"), "not-found".into());
            } else {
                put(
                    row,
                    &format!("{prefix}unit_file_state"),
                    unit.get("UnitFileState").filter(|v| !v.is_empty()).cloned(),
                );
                put(
                    row,
                    &format!("{prefix}active_state"),
                    unit.get("ActiveState").filter(|v| !v.is_empty()).cloned(),
                );
            }
        }
        if t.fields.iter().any(|field| field.starts_with("socket_")) {
            self.socket_states(t, row);
        }
    }
    fn module(&mut self, t: &Target, row: &mut Map<String, Value>) {
        if let Some(raw) = &self.modules {
            let valid = raw.lines().all(|l| l.split_whitespace().count() >= 6);
            if valid {
                let builtin_or_loaded = open_nofollow(
                    &PathBuf::from("/sys/module").join(module_name(&t.target)),
                    true,
                )
                .is_some();
                let loaded = builtin_or_loaded
                    || raw.lines().any(|l| {
                        l.split_whitespace()
                            .next()
                            .is_some_and(|name| module_name(name) == module_name(&t.target))
                    });
                row.insert(
                    "load_state".into(),
                    if loaded { "loaded" } else { "not-loaded" }.into(),
                );
            }
        }
        if self.modprobe.is_none() {
            self.modprobe = Some(self.command(
                &["/usr/sbin/modprobe", "/usr/bin/modprobe"],
                &["--showconfig"],
            ));
        }
        if let Some(Some(raw)) = &self.modprobe {
            let mut install = None;
            let mut install_count = 0;
            let mut blacklist = false;
            for line in raw.lines() {
                let mut words = line.split_whitespace();
                let (Some(kind), Some(name)) = (words.next(), words.next()) else {
                    continue;
                };
                if module_name(name) != module_name(&t.target) {
                    continue;
                }
                match kind {
                    "install" => {
                        install_count += 1;
                        let command = words.collect::<Vec<_>>().join(" ");
                        if install.is_some() {
                            install = Some(String::new());
                        } else {
                            install = Some(command);
                        }
                    }
                    "blacklist" => blacklist = true,
                    _ => {}
                }
            }
            put(
                row,
                "effective_install_command",
                if install_count == 0 {
                    Some(String::new())
                } else if install_count == 1 {
                    install
                } else {
                    None
                },
            );
            row.insert(
                "blacklist_state".into(),
                if blacklist {
                    "blacklisted"
                } else {
                    "not-blacklisted"
                }
                .into(),
            );
        }
    }
    fn audit_persistent(&self) -> Option<String> {
        // Ask the service manager which loader is actually configured. A rules.d
        // directory alone cannot establish which persistent rules boot loads.
        let loader = self.command(
            &["/usr/bin/systemctl"],
            &[
                "show",
                "auditd.service",
                "--no-pager",
                "--property=ExecStartPost",
            ],
        )?;
        if loader.contains("augenrules")
            && loader.contains("--load")
            && !loader.contains("auditctl")
        {
            let entries = config_entries(Path::new("/etc/audit/rules.d"), ".rules")?;
            if entries.is_empty() {
                return None;
            }
            let mut raw = String::new();
            let mut delete = None;
            let mut backlog = None;
            let mut failure = None;
            let mut enabled = None;
            for path in entries {
                for line in read_text(&path, MAX_FILE)?
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                {
                    match line.split_whitespace().next()? {
                        "-D" if line == "-D" => delete = Some(line.to_string()),
                        "-b" => backlog = Some(line.to_string()),
                        "-f" => failure = Some(line.to_string()),
                        "-e" => enabled = Some(line.to_string()),
                        _ => {
                            raw.push_str(line);
                            raw.push('\n');
                        }
                    }
                }
                if raw.len() as u64 > MAX_FILE * 4 {
                    return None;
                }
            }
            let mut result = [delete, backlog, failure]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join("\n");
            result.push('\n');
            result.push_str(&raw);
            if let Some(enabled) = enabled {
                result.push_str(&enabled);
                result.push('\n');
            }
            Some(result)
        } else if loader.contains("auditctl")
            && loader.contains("-R /etc/audit/audit.rules")
            && !loader.contains("augenrules")
        {
            read_text(Path::new("/etc/audit/audit.rules"), MAX_FILE)
        } else {
            None
        }
    }
}
fn put(row: &mut Map<String, Value>, key: &str, value: Option<String>) {
    if let Some(value) = value.filter(|v| v.len() <= 1024 && !v.chars().any(char::is_control)) {
        row.insert(key.into(), value.into());
    }
}
fn module_name(name: &str) -> String {
    name.replace('-', "_")
}

// Every path component is opened relative to its already-open parent. Symlinks
// and special files are rejected. O_PATH permits stat of unreadable secrets and
// directories without ever reading their content.
fn open_nofollow(path: &Path, stat_only: bool) -> Option<File> {
    if !path.is_absolute() {
        return None;
    }
    let mut dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open("/")
        .ok()?;
    let parts = path
        .components()
        .filter_map(|c| match c {
            Component::RootDir => None,
            Component::Normal(v) => Some(Some(v)),
            _ => Some(None),
        })
        .collect::<Option<Vec<_>>>()?;
    for (i, part) in parts.iter().enumerate() {
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(part.as_bytes()).ok()?;
        let last = i + 1 == parts.len();
        let flags = libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | if last {
                if stat_only {
                    libc::O_PATH
                } else {
                    libc::O_RDONLY | libc::O_NONBLOCK
                }
            } else {
                libc::O_RDONLY | libc::O_DIRECTORY
            };
        let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return None;
        }
        dir = unsafe { File::from_raw_fd(fd) };
    }
    let meta = dir.metadata().ok()?;
    if meta.file_type().is_symlink() || (!meta.is_file() && !(stat_only && meta.is_dir())) {
        return None;
    }
    Some(dir)
}
fn read_text(path: &Path, cap: u64) -> Option<String> {
    let file = open_nofollow(path, false)?;
    if file.metadata().ok()?.len() > cap {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(cap + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > cap || bytes.contains(&0) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

// Commands receive only fixed arguments or packaged manifest targets, never a
// shell. Both pipes are nonblocking and bounded; neither a descendant retaining
// a pipe nor a full stderr can extend the deadline. Execution is descriptor-bound
// to a root-owned, non-writable ELF binary opened without following symlinks.
fn probe(names: &[&str], args: &[&str], collection_deadline: Instant) -> Option<String> {
    let deadline = (Instant::now() + COMMAND_TIMEOUT).min(collection_deadline);
    if Instant::now() >= deadline {
        return None;
    }
    let (name, executable) = names.iter().find_map(|name| {
        let resolved = fs::canonicalize(name).ok()?;
        let mut file = open_nofollow(&resolved, false)?;
        let meta = file.metadata().ok()?;
        let source_meta = fs::metadata(name).ok()?;
        if meta.dev() != source_meta.dev() || meta.ino() != source_meta.ino() {
            return None;
        }
        let mut magic = [0; 4];
        file.read_exact(&mut magic).ok()?;
        (meta.uid() == 0
            && meta.mode() & 0o022 == 0
            && meta.mode() & 0o111 != 0
            && magic == *b"\x7fELF")
            .then_some((*name, file))
    })?;
    let mut child = Command::new(format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        executable.as_raw_fd()
    ))
    .arg0(name)
    .args(args)
    .env_clear()
    .env("LC_ALL", "C")
    .env("PATH", "/usr/sbin:/usr/bin")
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .ok()?;
    let mut stdout = child.stdout.take()?;
    let mut stderr = child.stderr.take()?;
    for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
    }
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut out_eof = false;
    let mut err_eof = false;
    loop {
        for (pipe, bytes, eof) in [
            (&mut stdout as &mut dyn Read, &mut out, &mut out_eof),
            (&mut stderr as &mut dyn Read, &mut err, &mut err_eof),
        ] {
            let mut buf = [0; 8192];
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) => {
                        *eof = true;
                        break;
                    }
                    Ok(n) => {
                        bytes.extend_from_slice(&buf[..n]);
                        if bytes.len() > MAX_OUTPUT {
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return None;
                    }
                }
                if Instant::now() >= deadline {
                    break;
                }
            }
        }
        if out.len() > MAX_OUTPUT || err.len() > MAX_OUTPUT || Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        match child.try_wait() {
            Ok(Some(status)) if out_eof && err_eof => {
                return status
                    .success()
                    .then(|| String::from_utf8(out).ok())
                    .flatten();
            }
            Ok(_) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}
fn package_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"+.-_".contains(&c))
}
fn parse_dpkg(raw: &str) -> Option<BTreeSet<String>> {
    if !raw.ends_with("\n\n") || raw.is_empty() {
        return None;
    }
    let mut installed = BTreeSet::new();
    let mut count = 0;
    for stanza in raw.split("\n\n").filter(|s| !s.trim().is_empty()) {
        count += 1;
        if count > 100_000 {
            return None;
        }
        let names = stanza
            .lines()
            .filter_map(|l| l.strip_prefix("Package: "))
            .collect::<Vec<_>>();
        let states = stanza
            .lines()
            .filter_map(|l| l.strip_prefix("Status: "))
            .collect::<Vec<_>>();
        if names.len() != 1 || states.len() != 1 || !package_name(names[0]) {
            return None;
        }
        let state = states[0].split_whitespace().collect::<Vec<_>>();
        if state.len() != 3
            || ![
                "not-installed",
                "config-files",
                "half-installed",
                "unpacked",
                "half-configured",
                "triggers-awaited",
                "triggers-pending",
                "installed",
            ]
            .contains(&state[2])
        {
            return None;
        }
        if !["installed", "not-installed", "config-files"].contains(&state[2]) {
            return None;
        }
        // Desired state can be hold/deinstall while files remain installed.
        if state[2] == "installed" {
            installed.insert(names[0].into());
        }
    }
    Some(installed)
}
fn parse_apk(raw: &str) -> Option<BTreeSet<String>> {
    if raw.is_empty() || !raw.ends_with("\n\n") {
        return None;
    }
    let mut installed = BTreeSet::new();
    for stanza in raw.split("\n\n").filter(|s| !s.is_empty()) {
        let names = stanza
            .lines()
            .filter_map(|l| l.strip_prefix("P:"))
            .collect::<Vec<_>>();
        if names.len() != 1
            || !package_name(names[0])
            || !stanza.lines().any(|l| l.starts_with("V:"))
        {
            return None;
        }
        installed.insert(names[0].into());
        if installed.len() > 100_000 {
            return None;
        }
    }
    Some(installed)
}
fn parse_package_lines(raw: &str) -> Option<BTreeSet<String>> {
    if !raw.ends_with('\n') || raw.lines().count() > 100_000 {
        return None;
    }
    raw.lines()
        .map(|name| package_name(name).then(|| name.to_string()))
        .collect()
}
fn parse_systemd(raw: &str) -> Option<BTreeMap<String, BTreeMap<String, String>>> {
    let mut units = BTreeMap::new();
    for block in raw.split("\n\n").filter(|s| !s.trim().is_empty()) {
        let mut values: BTreeMap<String, String> = BTreeMap::new();
        for line in block.lines() {
            let (key, value) = line.split_once('=')?;
            if ![
                "Id",
                "Names",
                "LoadState",
                "UnitFileState",
                "ActiveState",
                "Triggers",
                "ExecStart",
                "ExecStartPre",
                "ExecStartPost",
                "DropInPaths",
                "FragmentPath",
            ]
            .contains(&key)
                || values.insert(key.into(), value.into()).is_some()
            {
                return None;
            }
        }
        let id: String = values.get("Id")?.clone();
        let mut names = values
            .get("Names")
            .map(|names| {
                names
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if !names.contains(&id) {
            names.push(id);
        }
        for name in names {
            if units.get(&name).is_some_and(|old| old != &values) {
                return None;
            }
            units.insert(name, values.clone());
        }
    }
    (!units.is_empty()).then_some(units)
}
fn unescape_mount(raw: &str) -> Option<String> {
    let mut out = String::new();
    let mut i = 0;
    let bytes = raw.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            let code = raw.get(i + 1..i + 4)?;
            out.push(match code {
                "040" => ' ',
                "011" => '\t',
                "012" => '\n',
                "134" => '\\',
                _ => return None,
            });
            i += 4;
        } else {
            out.push(char::from(bytes[i]));
            i += 1;
        }
    }
    Some(out)
}
fn mount_options(raw: &str, target: &str) -> Option<String> {
    let mut found = None;
    for line in raw.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let sep = fields.iter().position(|v| *v == "-")?;
        if sep < 6 || fields.len() < sep + 4 {
            return None;
        }
        if unescape_mount(fields[4])? != target {
            continue;
        }
        if found.is_some() {
            return None;
        }
        let mut tokens = Vec::new();
        for token in fields[5].split(',').chain(fields[sep + 3].split(',')) {
            if !tokens.contains(&token) {
                tokens.push(token);
            }
        }
        found = Some(tokens.join(","));
    }
    found
}
fn fstab_options(raw: &str, target: &str) -> Option<String> {
    let mut found = None;
    for line in raw
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
    {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 4 || fields.len() > 6 {
            return None;
        }
        if unescape_mount(fields[1])? != target {
            continue;
        }
        if found.is_some() {
            return None;
        }
        // A native mount unit can override fstab. The caller suppresses this
        // value when native unit configuration is present/ambiguous.
        found = Some(fields[3].into());
    }
    found
}
fn native_mount_override(target: &str) -> bool {
    // Mount-unit escaping follows systemd.unit(5): separator '/' becomes '-',
    // literal hyphens and other special bytes use hexadecimal escapes.
    let mut unit = String::new();
    for byte in target.trim_start_matches('/').bytes() {
        if byte == b'/' {
            unit.push('-');
        } else if byte.is_ascii_alphanumeric() || b"_.".contains(&byte) {
            unit.push(char::from(byte));
        } else {
            unit.push_str(&format!("\\x{byte:02x}"));
        }
    }
    unit.push_str(".mount");
    for base in [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/usr/local/lib/systemd/system",
        "/usr/lib/systemd/system",
    ] {
        for path in [
            Path::new(base).join(&unit),
            Path::new(base).join(format!("{unit}.d")),
            Path::new(base).join("mount.d"),
        ] {
            match fs::symlink_metadata(path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                _ => return true,
            }
        }
    }
    false
}
fn config_entries(dir: &Path, suffix: &str) -> Option<Vec<PathBuf>> {
    match fs::symlink_metadata(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(Vec::new()),
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {}
        _ => return None,
    }
    let resolved_dir = fs::canonicalize(dir).ok()?;
    let descriptor = open_nofollow(&resolved_dir, true)?;
    let bound = format!("/proc/{}/fd/{}", std::process::id(), descriptor.as_raw_fd());
    let mut entries = Vec::new();
    for (index, entry) in fs::read_dir(bound).ok()?.enumerate() {
        if index >= MAX_FILES {
            return None;
        }
        let entry = entry.ok()?;
        if entry.file_name().to_str()?.ends_with(suffix) {
            entries.push(resolved_dir.join(entry.file_name()));
        }
    }
    entries.sort();
    Some(entries)
}
fn resolved_config(dirs: &[&str], suffix: &str) -> Option<String> {
    let mut selected = BTreeMap::new();
    for dir in dirs {
        for path in config_entries(Path::new(dir), suffix)? {
            selected
                .entry(path.file_name()?.to_os_string())
                .or_insert(path);
        }
    }
    let mut raw = String::new();
    for path in selected.values() {
        if fs::symlink_metadata(path).ok()?.file_type().is_symlink() {
            // systemd uses /dev/null masks. Other links are resolved only after
            // checking the actual opened descriptor matches the source stat.
            let dest = fs::canonicalize(path).ok()?;
            if dest == Path::new("/dev/null") {
                continue;
            }
            let file = open_nofollow(&dest, false)?;
            let meta = file.metadata().ok()?;
            let source_meta = fs::metadata(path).ok()?;
            if meta.dev() != source_meta.dev()
                || meta.ino() != source_meta.ino()
                || meta.uid() != 0
                || meta.mode() & 0o022 != 0
            {
                return None;
            }
            let mut bytes = Vec::new();
            file.take(MAX_FILE + 1).read_to_end(&mut bytes).ok()?;
            if bytes.len() as u64 > MAX_FILE {
                return None;
            }
            raw.push_str(&String::from_utf8(bytes).ok()?);
        } else {
            raw.push_str(&read_text(path, MAX_FILE)?);
        }
        raw.push('\n');
        if raw.len() as u64 > MAX_FILE * 4 {
            return None;
        }
    }
    Some(raw)
}
fn sysctl_value(raw: &str, target: &str) -> Option<i64> {
    let mut value = None;
    for line in raw.lines() {
        let line = line.split(['#', ';']).next()?.trim();
        if line.is_empty() {
            continue;
        }
        let (key, raw_value) = match line.split_once('=') {
            Some(pair) => pair,
            None => {
                if line.contains(target) || line.contains('*') {
                    return None;
                } else {
                    continue;
                }
            }
        };
        let key = key.trim().trim_start_matches('-').replace('/', ".");
        if key.contains(['*', '?', '[']) {
            let prefix = key.split(['*', '?', '[']).next()?;
            if target.starts_with(prefix) {
                return None;
            }
            continue;
        }
        if key == target {
            value = Some(raw_value.trim().parse().ok()?);
        }
    }
    value
}
fn sshd_value(raw: &str, target: &str) -> Option<String> {
    let mut found = None;
    for line in raw.lines() {
        let (key, value) = line.split_once(' ')?;
        if key.eq_ignore_ascii_case(target) {
            if found.is_some() || value.len() > 1024 || value.is_empty() {
                return None;
            }
            found = Some(value.to_string());
        }
    }
    found
}
fn sudo_pty(raw: &str) -> Option<String> {
    // -ll emits a localized header followed by the Defaults applicable to the
    // named user and host. Command-specific or runas Defaults are not described
    // by that header, so a listing containing such scope remains unknown.
    if !raw.starts_with("Matching Defaults entries for root on ") {
        return None;
    }
    let defaults = raw.split_once('\n')?.1.split("\n\n").next()?;
    if defaults.contains("Defaults!") || defaults.contains("Defaults>") {
        return None;
    }
    if raw
        .lines()
        .any(|line| line.trim_start().starts_with("Options:"))
    {
        return None;
    }
    let mut state = None;
    for token in defaults.split([',', '\n']).map(str::trim) {
        if token == "use_pty" {
            state = Some("enabled".to_string());
        }
        if token == "!use_pty" {
            state = Some("disabled".to_string());
        }
    }
    state
}
fn boot_value(raw: &str, target: &str) -> Option<String> {
    let values = raw
        .split_whitespace()
        .filter_map(|w| w.split_once('='))
        .filter(|(key, _)| *key == target)
        .map(|(_, v)| v)
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Some(String::new());
    }
    if values.len() != 1 || values[0].contains(['$', '"', '\\', '\'']) {
        return None;
    }
    Some(values[0].into())
}
fn applicable_abis() -> Option<(Vec<&'static str>, bool)> {
    let arch = std::env::consts::ARCH;
    if ["x86", "arm"].contains(&arch) {
        return Some((vec!["b32"], true));
    }
    if !["x86_64", "aarch64", "s390x", "powerpc64"].contains(&arch) {
        return None;
    }
    // Only the running kernel's embedded config can exclude a possible ABI.
    // A /boot/config filename alone does not bind its contents to that kernel.
    let embedded = (|| {
        let bytes = read_bytes(Path::new("/proc/config.gz"), MAX_FILE)?;
        let decoder = flate2::read::GzDecoder::new(bytes.as_slice());
        let mut plain = Vec::new();
        decoder
            .take(MAX_FILE * 4 + 1)
            .read_to_end(&mut plain)
            .ok()?;
        if plain.len() as u64 > MAX_FILE * 4 {
            return None;
        }
        abis_for_config(arch, &String::from_utf8(plain).ok()?)
    })();
    Some(
        embedded
            .map(|abis| (abis, true))
            .unwrap_or((vec!["b64", "b32"], false)),
    )
}
fn audit_permissions_scoped(
    raw: &str,
    target: &str,
    abis: &[&str],
    certain: bool,
) -> Option<String> {
    if certain {
        return audit_permissions(raw, target, abis);
    }
    let observed = abis
        .iter()
        .map(|abi| audit_permissions(raw, target, &[*abi]))
        .collect::<Option<Vec<_>>>()?;
    let first = observed.first()?;
    observed
        .iter()
        .all(|value| value == first)
        .then(|| first.clone())
}

fn abis_for_config(arch: &str, config: &str) -> Option<Vec<&'static str>> {
    let option = match arch {
        "x86_64" => "CONFIG_IA32_EMULATION",
        "aarch64" | "s390x" | "powerpc64" => "CONFIG_COMPAT",
        "x86" | "arm" => return Some(vec!["b32"]),
        _ => return None,
    };
    let yes = format!("{option}=y");
    let no = format!("# {option} is not set");
    let values = config
        .lines()
        .filter_map(|line| {
            if line == yes {
                Some(true)
            } else if line == no {
                Some(false)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    match values.as_slice() {
        [true] => Some(vec!["b64", "b32"]),
        [false] => Some(vec!["b64"]),
        _ => None,
    }
}

fn audit_permissions(raw: &str, target: &str, abis: &[&str]) -> Option<String> {
    let mut per_abi: BTreeMap<&str, BTreeSet<char>> =
        abis.iter().map(|abi| (*abi, BTreeSet::new())).collect();
    for line in raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        if line == "No rules" {
            continue;
        }
        let words = line.split_whitespace().collect::<Vec<_>>();
        if words.windows(2).any(|pair| {
            ["-a", "-A", "-d"].contains(&pair[0])
                && pair[1]
                    .split(',')
                    .any(|part| ["never", "exclude"].contains(&part))
        }) || words[0] == "-d"
        {
            return None;
        }

        if words[0] == "-D" {
            for perms in per_abi.values_mut() {
                perms.clear();
            }
            continue;
        }
        if words[0] == "-W" {
            return None;
        }
        if [
            "-b",
            "-f",
            "-e",
            "--backlog_wait_time",
            "--loginuid-immutable",
            "-r",
        ]
        .contains(&words[0])
        {
            continue;
        }
        // Ordinary audit rules for unrelated paths do not constrain this watch.
        // Directory-based ancestors could overlap the target and remain unknown.
        let watch_path = words
            .windows(2)
            .find_map(|pair| (pair[0] == "-w").then_some(pair[1]));
        let field_path = words.iter().find_map(|word| word.strip_prefix("path="));
        if words.iter().any(|word| {
            word.strip_prefix("dir=")
                .is_some_and(|dir| target.starts_with(dir))
        }) {
            return None;
        }
        if watch_path.or(field_path) != Some(target) {
            continue;
        }
        let mut path = None;
        let mut perms = None;
        let mut arch = None;
        let mut i = 0;
        while i < words.len() {
            match words[i] {
                "-w" => {
                    path = words.get(i + 1).copied();
                    i += 2;
                }
                "-p" => {
                    perms = words.get(i + 1).copied();
                    i += 2;
                }
                "-F" => {
                    let field = *words.get(i + 1)?;
                    if let Some(v) = field.strip_prefix("path=") {
                        path = Some(v);
                    } else if let Some(v) = field.strip_prefix("perm=") {
                        perms = Some(v);
                    } else if let Some(v) = field.strip_prefix("arch=") {
                        arch = Some(match v {
                            "c000003e" | "c00000b7" => "b64",
                            "40000003" | "40000028" => "b32",
                            v => v,
                        });
                    } else if !field.starts_with("key=") {
                        return None;
                    }
                    i += 2;
                }
                "-a" | "-A"
                    if matches!(words.get(i + 1), Some(&"always,exit" | &"exit,always")) =>
                {
                    i += 2;
                }
                "-S" if words.get(i + 1) == Some(&"all") => {
                    i += 2;
                }
                "-k" => {
                    i += 2;
                }
                _ => return None,
            }
        }
        if path != Some(target) {
            continue;
        }
        let perms = perms?;
        if !perms.chars().all(|p| "rwxa".contains(p)) {
            return None;
        }
        for (abi, values) in &mut per_abi {
            if arch.is_none() || arch == Some(*abi) {
                values.extend(perms.chars());
            }
        }
    }
    Some(
        "rwxa"
            .chars()
            .filter(|p| per_abi.values().all(|set| set.contains(p)))
            .collect(),
    )
}
fn rfc3339_now() -> String {
    // libc's UTC conversion avoids a dependency or locale-sensitive command.
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as libc::time_t;
    let mut tm = unsafe { std::mem::zeroed::<libc::tm>() };
    if unsafe { libc::gmtime_r(&seconds, &mut tm) }.is_null() {
        return "1970-01-01T00:00:00Z".into();
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

impl Host {
    fn sysctl_persistent(&self) -> Option<String> {
        if fs::symlink_metadata("/etc/rc.local").is_ok() {
            return None;
        }
        let raw = self.command(&["/usr/bin/systemctl"], &["show", "systemd-sysctl.service", "procps.service", "sysctl.service", "--no-pager", "--property=Id,Names,LoadState,ExecStart,ExecStartPre,ExecStartPost,DropInPaths,FragmentPath"])?;
        let units = parse_systemd(&raw).or_else(|| {
            log::debug!("hardening sysctl unit response ambiguous");
            None
        })?;
        let mut loaders = BTreeSet::new();
        for unit in units.values() {
            if unit.get("LoadState").map(String::as_str) == Some("not-found") {
                continue;
            }
            let loader = sysctl_loader(unit).or_else(|| {
                log::debug!("hardening sysctl loader unsupported");
                None
            })?;
            if !sysctl_disk_chain(unit) {
                log::debug!("hardening sysctl disk chain ambiguous");
                return None;
            }
            loaders.insert(loader);
        }
        if loaders.len() != 1 {
            return None;
        }
        let mut config = resolved_config(
            &[
                "/etc/sysctl.d",
                "/run/sysctl.d",
                "/usr/local/lib/sysctl.d",
                "/usr/lib/sysctl.d",
            ],
            ".conf",
        )
        .or_else(|| {
            log::debug!("hardening sysctl config resolution unavailable");
            None
        })?;
        if loaders.contains("procps") {
            config.push_str(&read_text(Path::new("/etc/sysctl.conf"), MAX_FILE)?);
            config.push('\n');
        }
        Some(config)
    }
    fn socket_states(&mut self, target: &Target, row: &mut Map<String, Value>) {
        if self.sockets.is_none() {
            self.sockets = Some((|| {
                let files = self.command(
                    &["/usr/bin/systemctl"],
                    &[
                        "list-unit-files",
                        "--type=socket",
                        "--no-legend",
                        "--no-pager",
                        "--full",
                    ],
                )?;
                let runtime = self.command(
                    &["/usr/bin/systemctl"],
                    &[
                        "list-units",
                        "--type=socket",
                        "--all",
                        "--no-legend",
                        "--no-pager",
                        "--plain",
                        "--full",
                    ],
                )?;
                let mut names = socket_listing(&files)?;
                names.extend(socket_listing(&runtime)?);
                if names.len() > MAX_FILES {
                    return None;
                }
                if names.is_empty() {
                    return Some(BTreeMap::new());
                }
                let mut args = vec![
                    "show",
                    "--no-pager",
                    "--property=Id,Names,LoadState,UnitFileState,ActiveState,Triggers",
                ];
                args.extend(names.iter().map(String::as_str));
                let units = parse_systemd(&self.command(&["/usr/bin/systemctl"], &args)?)?;
                if names.iter().any(|name| !units.contains_key(name)) {
                    return None;
                }
                Some(units)
            })());
        }
        let Some(Some(sockets)) = &self.sockets else {
            return;
        };
        let Some(Some(services)) = &self.systemd else {
            return;
        };
        let Some(service) = services.get(&target.target) else {
            return;
        };
        let mut aliases = service
            .get("Names")
            .map(|names| {
                names
                    .split_whitespace()
                    .map(str::to_string)
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        aliases.insert(target.target.clone());
        if let Some((boot, runtime)) = socket_aggregate(sockets, &aliases) {
            put(row, "socket_unit_file_state", Some(boot));
            put(row, "socket_active_state", Some(runtime));
        }
    }
}
fn sysctl_loader(unit: &BTreeMap<String, String>) -> Option<&'static str> {
    if ["ExecStartPre", "ExecStartPost", "DropInPaths"]
        .iter()
        .any(|key| unit.get(*key).is_some_and(|v| !v.is_empty()))
    {
        return None;
    }
    let args = native_exec_argv(unit.get("ExecStart")?)?;
    let fragment = unit.get("FragmentPath")?;
    if !["/usr/lib/systemd/system/", "/lib/systemd/system/"]
        .iter()
        .any(|prefix| fragment.starts_with(prefix))
    {
        return None;
    }
    match args.as_slice() {
        [binary] if binary.ends_with("/systemd-sysctl") => Some("systemd"),
        [binary, strict] if binary.ends_with("/systemd-sysctl") && strict == "--strict" => {
            Some("systemd")
        }
        [binary, flag] if binary.ends_with("/sysctl") && flag == "--system" => Some("procps"),
        _ => None,
    }
}
fn sysctl_disk_chain(unit: &BTreeMap<String, String>) -> bool {
    (|| -> Option<()> {
        let id = unit.get("Id")?;
        for base in [
            "/etc/systemd/system",
            "/run/systemd/system",
            "/usr/local/lib/systemd/system",
            "/usr/lib/systemd/system",
        ] {
            for dropin in [format!("{id}.d"), "service.d".to_string()] {
                match fs::symlink_metadata(Path::new(base).join(dropin)) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    _ => return None,
                }
            }
        }
        let raw = read_text(Path::new(unit.get("FragmentPath")?), MAX_FILE)?;
        let mut service = false;
        let mut starts = Vec::new();
        for line in raw
            .lines()
            .map(|line| line.split('#').next().unwrap_or("").trim())
            .filter(|line| !line.is_empty())
        {
            if line.starts_with('[') {
                service = line == "[Service]";
                continue;
            }
            if !service {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if ["ExecStartPre", "ExecStartPost", "ExecCondition"].contains(&key.trim()) {
                return None;
            }
            if key.trim() == "ExecStart" {
                if value.contains(['$', '%', '\\', '"', '\'']) {
                    return None;
                }
                starts.push(
                    value
                        .split_whitespace()
                        .map(str::to_string)
                        .collect::<Vec<_>>(),
                );
            }
        }
        if starts.len() != 1 || starts[0] != native_exec_argv(unit.get("ExecStart")?)? {
            return None;
        }
        Some(())
    })()
    .is_some()
}
fn native_exec_argv(raw: &str) -> Option<Vec<String>> {
    if raw.matches("argv[]=").count() != 1 {
        return None;
    }
    let args = raw.split_once("argv[]=")?.1.split_once(" ;")?.0;
    if args.contains(['$', '%', '\\', '"', '\'']) {
        return None;
    }
    let args = args
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    (!args.is_empty()).then_some(args)
}
fn socket_listing(raw: &str) -> Option<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for (index, line) in raw.lines().enumerate() {
        if index >= MAX_FILES {
            return None;
        }
        let name = line.split_whitespace().next()?;
        if !name.ends_with(".socket")
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.@-\\:".contains(&c))
        {
            return None;
        }
        names.insert(if name.ends_with("@.socket") {
            name.replace("@.socket", "@merlin-hardening-probe.socket")
        } else {
            name.into()
        });
    }
    Some(names)
}
fn socket_aggregate(
    sockets: &BTreeMap<String, BTreeMap<String, String>>,
    services: &BTreeSet<String>,
) -> Option<(String, String)> {
    let mut boot = Vec::new();
    let mut active = Vec::new();
    for unit in sockets.values() {
        if unit.get("LoadState").map(String::as_str) == Some("not-found") {
            continue;
        }
        let triggers = unit.get("Triggers")?;
        if !triggers
            .split_whitespace()
            .any(|name| services.contains(name))
        {
            continue;
        }
        boot.push(unit.get("UnitFileState")?.as_str());
        active.push(unit.get("ActiveState")?.as_str());
    }
    if boot.is_empty() {
        return Some(("not-found".into(), "not-found".into()));
    }
    let boot = boot
        .iter()
        .find(|state| !["disabled", "masked", "not-found"].contains(state))
        .copied()
        .unwrap_or("disabled");
    let active = active
        .iter()
        .find(|state| !["inactive", "failed", "not-found"].contains(state))
        .copied()
        .unwrap_or("inactive");
    Some((boot.into(), active.into()))
}

fn read_bytes(path: &Path, cap: u64) -> Option<Vec<u8>> {
    let file = open_nofollow(path, false)?;
    let mut bytes = Vec::new();
    file.take(cap + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() as u64 <= cap).then_some(bytes)
}
fn running_sshd_invocation() -> Option<(String, Vec<String>)> {
    let mut listeners = Vec::new();
    for (index, entry) in fs::read_dir("/proc").ok()?.enumerate() {
        if index > 16384 {
            return None;
        }
        let entry = entry.ok()?;
        if !entry
            .file_name()
            .to_str()?
            .bytes()
            .all(|c| c.is_ascii_digit())
        {
            continue;
        }
        let path = entry.path();
        let Some(comm) = read_text(&path.join("comm"), 256) else {
            continue;
        };
        if comm.trim() != "sshd" {
            continue;
        }
        let before = read_text(&path.join("stat"), 8192)?;
        let raw = read_bytes(&path.join("cmdline"), 65536)?;
        let Some(args) = sshd_probe_args(&raw) else {
            // Privilege-separated sessions have a recognizable non-listener
            // process title. Unrecognized sshd processes remain ambiguous.
            let title = String::from_utf8(raw).ok()?;
            if title.starts_with("sshd: ")
                && !title.contains("[listener]")
                && !title.contains("/sshd ")
            {
                continue;
            }
            return None;
        };
        let exe = fs::canonicalize(path.join("exe")).ok()?;
        let binary = args.0;
        let expected = fs::canonicalize(&binary).ok()?;
        if exe != expected
            || process_start(&before)? != process_start(&read_text(&path.join("stat"), 8192)?)?
        {
            return None;
        }
        listeners.push((binary, args.1));
        if listeners.len() > 1 {
            return None;
        }
    }
    (listeners.len() == 1).then(|| listeners.remove(0))
}
fn process_start(raw: &str) -> Option<&str> {
    raw.rsplit_once(')')?.1.split_whitespace().nth(19)
}
fn sshd_probe_args(raw: &[u8]) -> Option<(String, Vec<String>)> {
    let raw = std::str::from_utf8(raw).ok()?;
    let words = if let Some(title) = raw.strip_prefix("sshd: ") {
        title
            .split_once(" [listener]")?
            .0
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>()
    } else {
        raw.trim_end_matches('\0')
            .split('\0')
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    let binary = words.first()?.clone();
    if !binary.starts_with('/')
        || !binary.ends_with("/sshd")
        || words
            .iter()
            .any(|w| w.chars().any(char::is_whitespace) || w.contains(['$', '\\', '"', '\'']))
    {
        return None;
    }
    let mut args = Vec::new();
    let mut i = 1;
    while i < words.len() {
        match words[i].as_str() {
            "-D" | "-e" | "-d" | "-dd" | "-ddd" => i += 1,
            "-f" | "-o" | "-p" | "-h" | "-c" | "-E" | "-u" => {
                let flag = &words[i];
                let value = words.get(i + 1)?;
                // Logging destination is irrelevant to policy and must not be
                // replayed by a read-only configuration probe.
                if flag != "-E" {
                    args.extend([flag.clone(), value.clone()]);
                }
                i += 2;
            }
            _ => return None,
        }
    }
    Some((binary, args))
}

fn sudo_policy_unscoped() -> bool {
    (|| -> Option<()> {
        if let Some(nss) = Some(read_text(Path::new("/etc/nsswitch.conf"), MAX_FILE)?) {
            for line in nss
                .lines()
                .map(|l| l.split('#').next().unwrap_or("").trim())
            {
                if let Some(backends) = line.strip_prefix("sudoers:") {
                    if backends.split_whitespace().collect::<Vec<_>>() != ["files"] {
                        return None;
                    }
                }
            }
        }
        // Custom policy plugins or alternate policy paths are unsupported.
        if !sudo_plugin_configuration_supported(Path::new("/etc/sudo.conf")) {
            return None;
        }
        let mut seen = BTreeSet::new();
        sudo_policy_file(Path::new("/etc/sudoers"), &mut seen, 0)?;
        Some(())
    })()
    .is_some()
}
fn sudo_plugin_configuration_supported(path: &Path) -> bool {
    (|| -> Option<()> {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return None,
            Ok(metadata) => {
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return None;
                }
                let config = read_text(path, MAX_FILE)?;
                for line in config
                    .lines()
                    .map(|line| line.split('#').next().unwrap_or("").trim())
                {
                    if line.starts_with("Plugin") || line.starts_with("Path sudoers") {
                        return None;
                    }
                }
            }
        }
        Some(())
    })()
    .is_some()
}
fn sudo_policy_file(path: &Path, seen: &mut BTreeSet<PathBuf>, depth: usize) -> Option<()> {
    if depth > 8 || seen.len() >= MAX_FILES || !seen.insert(path.to_path_buf()) {
        return None;
    }
    let raw = read_text(path, MAX_FILE)?;
    let raw = raw.replace("\\\n", "");
    for line in raw.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if line.starts_with("Defaults!") || line.starts_with("Defaults>") {
            return None;
        }
        if let Some(rest) = ["@include ", "@include\t", "#include ", "#include\t"]
            .iter()
            .find_map(|p| line.strip_prefix(p))
        {
            let path = sudo_include_path(rest)?;
            sudo_policy_file(&path, seen, depth + 1)?;
        } else if let Some(rest) = [
            "@includedir ",
            "@includedir\t",
            "#includedir ",
            "#includedir\t",
        ]
        .iter()
        .find_map(|p| line.strip_prefix(p))
        {
            for path in config_entries(&sudo_include_path(rest)?, "")? {
                let name = path.file_name()?.to_str()?;
                if name.contains('.') || name.ends_with('~') {
                    continue;
                }
                sudo_policy_file(&path, seen, depth + 1)?;
            }
        } else if line.starts_with('@') || line.starts_with("#include") {
            return None;
        }
    }
    Some(())
}
fn sudo_include_path(raw: &str) -> Option<PathBuf> {
    let raw = raw.trim();
    if !raw.starts_with('/') || raw.contains([' ', '\t', '"', '\'', '\\', '%', '#']) {
        return None;
    }
    Some(PathBuf::from(raw))
}

#[path = "linux_hardening_grub.rs"]
mod grub;
#[cfg(test)]
use grub::grub_arguments;
use grub::resolved_grub_arguments;

#[cfg(test)]
#[path = "linux_hardening_tests.rs"]
mod tests;
