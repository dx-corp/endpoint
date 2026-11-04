//! Safe Kubernetes facts over the existing Linux hardening check-in. No
//! credentials, kubeconfig bodies, key bodies, environment or arbitrary argv
//! cross the boundary. Unsupported effective configuration remains absent.
use super::*;

const COMPONENTS: &[(&str, &str)] = &[
    ("kube-apiserver", "apiserver"),
    ("kube-controller-manager", "controller_manager"),
    ("kube-scheduler", "scheduler"),
    ("etcd", "etcd"),
    ("kubelet", "kubelet"),
    ("kube-proxy", "kube_proxy"),
];
const API_FLAGS: &[&str] = &[
    "anonymous-auth",
    "token-auth-file",
    "kubelet-client-certificate",
    "kubelet-client-key",
    "kubelet-certificate-authority",
    "authorization-mode",
    "profiling",
    "audit-log-path",
    "audit-log-maxage",
    "audit-log-maxbackup",
    "audit-log-maxsize",
    "service-account-lookup",
    "service-account-key-file",
    "etcd-certfile",
    "etcd-keyfile",
    "tls-cert-file",
    "tls-private-key-file",
    "client-ca-file",
    "etcd-cafile",
    "encryption-provider-config",
    "tls-cipher-suites",
    "service-account-extend-token-expiration",
    "audit-policy-file",
];
const CONTROLLER_FLAGS: &[&str] = &[
    "profiling",
    "use-service-account-credentials",
    "service-account-private-key-file",
    "root-ca-file",
    "bind-address",
];
const ETCD_FLAGS: &[&str] = &[
    "cert-file",
    "key-file",
    "client-cert-auth",
    "auto-tls",
    "peer-cert-file",
    "peer-key-file",
    "peer-client-cert-auth",
    "peer-auto-tls",
];
const KUBELET_CONFIG: &[(&str, &str)] = &[
    ("authentication.anonymous.enabled", "bool"),
    ("authorization.mode", "text"),
    ("authentication.x509.clientCAFile", "text"),
    ("readOnlyPort", "number"),
    ("streamingConnectionIdleTimeout", "text"),
    ("makeIPTablesUtilChains", "bool"),
    ("eventRecordQPS", "number"),
    ("tlsCertFile", "text"),
    ("tlsPrivateKeyFile", "text"),
    ("rotateCertificates", "bool"),
    ("featureGates.RotateKubeletServerCertificate", "bool"),
    ("podPidsLimit", "number"),
    ("seccompDefault", "bool"),
];

pub(super) fn collect(deadline: Instant) -> Vec<Value> {
    let mut cluster = identity("kubernetes_cluster");
    let mut node = identity("kubernetes_node");
    let Some(processes) = running_components(deadline) else {
        return Vec::new();
    };
    let mut cluster_applicable = false;
    let mut node_applicable = false;
    for (name, section) in COMPONENTS {
        if Instant::now() >= deadline {
            break;
        }
        let Some(process) = processes.get(*name) else {
            continue;
        };
        // etcd is also a standalone non-Kubernetes product. Collect it only
        // after a stable Kubernetes control-plane component established scope.
        if *name == "etcd" && !cluster_applicable {
            continue;
        }
        let row = if matches!(*name, "kubelet" | "kube-proxy") {
            &mut node
        } else {
            &mut cluster
        };
        if !process.valid() {
            continue;
        }
        let previous = row.clone();
        collect_component(
            section,
            &process.args,
            row,
            &|path| process.text(path),
            &|path| process.metadata(path),
        );
        if !process.valid() {
            *row = previous;
        } else if matches!(*name, "kubelet" | "kube-proxy") {
            node_applicable = true;
        } else if kubernetes_control_plane(name) {
            cluster_applicable = true;
        }
    }
    // These are kubeadm's published manifest locations, not assumed effective
    // config files. Their own permissions are independent of runtime flags.
    if processes.contains_key("kube-apiserver") {
        for (key, path) in [
            (
                "apiserver_manifest",
                "/etc/kubernetes/manifests/kube-apiserver.yaml",
            ),
            (
                "controller_manager_manifest",
                "/etc/kubernetes/manifests/kube-controller-manager.yaml",
            ),
            (
                "scheduler_manifest",
                "/etc/kubernetes/manifests/kube-scheduler.yaml",
            ),
            ("etcd_manifest", "/etc/kubernetes/manifests/etcd.yaml"),
        ] {
            if let Some(value) = metadata(Path::new(path)) {
                set(&mut cluster, &format!("files.{key}"), value);
            }
        }
    }
    if processes.contains_key("kube-apiserver") {
        for (key, directory, suffixes, recursive) in [
            ("cni_configuration_files", "/etc/cni/net.d", &[][..], false),
            (
                "pki_directory_and_files",
                "/etc/kubernetes/pki",
                &[][..],
                true,
            ),
            (
                "pki_certificates",
                "/etc/kubernetes/pki",
                &[".crt"][..],
                true,
            ),
            (
                "pki_private_keys",
                "/etc/kubernetes/pki",
                &[".key"][..],
                true,
            ),
        ] {
            if let Some(mut rows) = metadata_group(Path::new(directory), suffixes, recursive) {
                if key == "pki_directory_and_files" {
                    let Some(root) = metadata(Path::new(directory)) else {
                        continue;
                    };
                    rows.push(root);
                }
                set(&mut cluster, &format!("files.{key}"), rows.into());
            }
        }
        // Enumerate all operator kubeconfigs in kubeadm's config directory;
        // bodies are never opened. Unknown extensions/layouts remain unknown.
        let admin_paths = [
            "/etc/kubernetes/admin.conf",
            "/etc/kubernetes/super-admin.conf",
        ];
        if let Some(admins) = optional_metadata_paths(&admin_paths.map(Path::new)) {
            set(&mut cluster, "files.admin_kubeconfigs", admins.into());
        }
    }
    if processes.contains_key("kubelet") {
        // systemd reports the effective fragment, including overridden units.
        if let Some(raw) = probe(
            &["/usr/bin/systemctl"],
            &[
                "show",
                "kubelet.service",
                "--property=FragmentPath",
                "--value",
            ],
            deadline,
        ) {
            if let Some(value) = metadata(Path::new(raw.trim())) {
                set(&mut node, "files.kubelet_service", value);
            }
        }
    }
    if let Some(value) = cluster
        .get_mut("files")
        .and_then(|v| v.get_mut("etcd_data_directory"))
        .and_then(Value::as_object_mut)
    {
        for (id, field, file, column) in [
            ("uid", "owner", "/etc/passwd", 2),
            ("gid", "group", "/etc/group", 2),
        ] {
            if let Some(name) = value.get(id).and_then(Value::as_u64).and_then(|id| {
                read_text(Path::new(file), MAX_FILE).and_then(|s| owner_name(&s, id, column))
            }) {
                value.insert(field.into(), name.into());
            }
        }
    }
    applicable_rows(cluster, node, cluster_applicable, node_applicable)
}
fn identity(kind: &str) -> Map<String, Value> {
    Map::from_iter([
        ("id".into(), format!("{kind}:local").into()),
        ("kind".into(), kind.into()),
        ("target".into(), "local".into()),
        ("os_family".into(), "linux".into()),
    ])
}
fn metadata(path: &Path) -> Option<Value> {
    let m = open_nofollow(path, true)?.metadata().ok()?;
    Some(
        serde_json::json!({"mode": format!("{:04o}", m.mode() & 0o7777), "uid": m.uid(), "gid": m.gid()}),
    )
}
fn set(row: &mut Map<String, Value>, path: &str, value: Value) {
    let mut parts = path.splitn(2, '.');
    let key = parts.next().unwrap();
    if let Some(rest) = parts.next() {
        let child = row.entry(key).or_insert_with(|| Value::Object(Map::new()));
        if let Some(child) = child.as_object_mut() {
            set(child, rest, value);
        }
    } else {
        row.insert(key.into(), value);
    }
}
fn leaf<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(value, |v, k| v.get(k))
}
fn safe_text(value: &str) -> bool {
    value.len() <= 1024 && !value.chars().any(char::is_control)
}
fn parse_args(words: &[String]) -> Option<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    let mut i = 1;
    while i < words.len() {
        let arg = words[i].strip_prefix("--")?;
        let (key, value) = if let Some((key, value)) = arg.split_once('=') {
            (key, value.to_owned())
        } else {
            i += 1;
            (arg, words.get(i)?.clone())
        };
        if key.is_empty() || !safe_text(&value) || result.insert(key.into(), value).is_some() {
            return None;
        }
        i += 1;
    }
    Some(result)
}
fn running_components(deadline: Instant) -> Option<BTreeMap<String, Process>> {
    let mut result = BTreeMap::new();
    let mut duplicates = BTreeSet::new();
    let mut count = 0;
    for entry in fs::read_dir("/proc").ok()? {
        if Instant::now() >= deadline {
            return None;
        }
        let entry = entry.ok()?;
        let name = entry.file_name();
        if !name.to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        count += 1;
        if count > 4096 {
            return None;
        }
        let path = entry.path();
        let before = read_text(&path.join("stat"), 65536);
        let Some(file) = open_nofollow(&path.join("cmdline"), false) else {
            continue;
        };
        let mut bytes = Vec::new();
        if file.take(65537).read_to_end(&mut bytes).is_err() || bytes.len() > 65536 {
            continue;
        }
        if bytes.last() != Some(&0) {
            continue;
        }
        let Ok(raw) = String::from_utf8(bytes) else {
            continue;
        };
        let words = raw
            .trim_end_matches('\0')
            .split('\0')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let Some(binary) = words
            .first()
            .and_then(|s| Path::new(s).file_name())
            .and_then(|s| s.to_str())
        else {
            continue;
        };
        if !COMPONENTS.iter().any(|(name, _)| *name == binary) {
            continue;
        }
        if result.contains_key(binary) {
            duplicates.insert(binary.to_string());
        }
        if let Some(args) = parse_args(&words) {
            if let Some(process) = Process::open(path.clone(), args, before?, raw.clone()) {
                result.insert(binary.to_string(), process);
            } else {
                duplicates.insert(binary.to_string());
            }
        } else {
            duplicates.insert(binary.to_string());
        }
    }
    for duplicate in duplicates {
        result.remove(&duplicate);
    }
    Some(result)
}
fn document(raw: &str) -> Option<Value> {
    // serde_yaml rejects duplicate mapping keys. Bound size before parsing;
    // reject aliases to avoid expansion and YAML merge semantics.
    if raw.len() as u64 > MAX_FILE || yaml_reference_token(raw) {
        return None;
    }
    serde_yaml::from_str::<UniqueValue>(raw).ok().map(|v| v.0)
}
fn collect_component(
    section: &str,
    args: &BTreeMap<String, String>,
    row: &mut Map<String, Value>,
    read: &impl Fn(&str) -> Option<String>,
    stat: &impl Fn(&str) -> Option<Value>,
) {
    let flags: &[&str] = match section {
        "apiserver" => API_FLAGS,
        "controller_manager" => CONTROLLER_FLAGS,
        "scheduler" => &["profiling", "bind-address"],
        "etcd" => ETCD_FLAGS,
        "kubelet" => &["hostname-override", "tls-cipher-suites"],
        _ => &[],
    };
    // Component config changes CLI precedence. For control-plane components
    // whose structured config is unsupported, omit flags rather than guess.
    if !args.contains_key("config") || matches!(section, "kubelet" | "kube_proxy") {
        for key in flags {
            if let Some(value) = args.get(*key).and_then(|value| flag_value(key, value)) {
                set(row, &format!("{section}.flags.{key}"), value.clone());
            }
        }
    }
    if section == "apiserver" {
        if let Some(plugins) = explicit_admission(args) {
            set(
                row,
                "apiserver.admission_plugins",
                plugins
                    .into_iter()
                    .map(Value::from)
                    .collect::<Vec<_>>()
                    .into(),
            );
        }
        if let Some(plugins) = args.get("admission-control").filter(|_| {
            !args.contains_key("enable-admission-plugins")
                && !args.contains_key("disable-admission-plugins")
        }) {
            if plugins
                .split(',')
                .all(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric()))
            {
                set(
                    row,
                    "apiserver.admission_plugins",
                    plugins
                        .split(',')
                        .map(Value::from)
                        .collect::<Vec<_>>()
                        .into(),
                );
            }
        }
        if let Some(policy) = args
            .get("audit-policy-file")
            .and_then(|p| read(p))
            .and_then(|s| document(&s))
        {
            if let Some(cases) = audit_security_cases(&policy) {
                set(row, "apiserver.audit_security_cases", cases);
            }
            for key in ["apiVersion", "kind"] {
                if let Some(value) = policy
                    .get(key)
                    .and_then(Value::as_str)
                    .filter(|s| safe_text(s))
                {
                    set(row, &format!("apiserver.audit_policy.{key}"), value.into());
                }
            }
            if let Some(rules) = policy
                .get("rules")
                .and_then(Value::as_array)
                .filter(|v| v.len() <= 256 && v.iter().all(valid_audit_rule))
            {
                set(
                    row,
                    "apiserver.audit_policy.rules",
                    rules
                        .iter()
                        .map(|_| Value::Object(Map::new()))
                        .collect::<Vec<_>>()
                        .into(),
                );
            }
        }
        if let Some(config) = args
            .get("encryption-provider-config")
            .and_then(|path| read(path))
            .and_then(|raw| document(&raw))
            .and_then(|config| secrets_encryption(&config))
        {
            set(row, "apiserver.secrets_encryption", config);
        }
    }
    if section == "controller_manager" {
        if let Some(gates) = args.get("feature-gates") {
            if let Some(value) = feature_gate(gates, "RotateKubeletServerCertificate") {
                set(
                    row,
                    "controller_manager.featureGates.RotateKubeletServerCertificate",
                    value.into(),
                );
            }
        }
    }
    for (flag, target) in match section {
        "controller_manager" => vec![("kubeconfig", "controller_manager_kubeconfig")],
        "scheduler" => vec![("kubeconfig", "scheduler_kubeconfig")],
        "etcd" => vec![("data-dir", "etcd_data_directory")],
        "kubelet" => vec![
            ("config", "kubelet_config"),
            ("kubeconfig", "kubelet_kubeconfig"),
            ("client-ca-file", "kubelet_client_ca"),
        ],
        "kube_proxy" => vec![("kubeconfig", "kube_proxy_kubeconfig")],
        _ => vec![],
    } {
        if let Some(value) = args.get(flag).and_then(|p| stat(p)) {
            set(row, &format!("files.{target}"), value);
        }
    }
    if matches!(section, "kubelet" | "kube_proxy") {
        if let Some(config) = args
            .get("config")
            .and_then(|p| read(p))
            .and_then(|s| document(&s))
        {
            let fields = if section == "kubelet" {
                KUBELET_CONFIG
            } else {
                &[("metricsBindAddress", "text")][..]
            };
            // Reject CLI overrides of structured config deciding fields, until
            // exact precedence conversion for that option is implemented.
            for (path, kind) in fields {
                let flag = config_flag(path);
                if args.contains_key(flag.as_str()) || args.contains_key("config-dir") {
                    continue;
                }
                if let Some(value) = leaf(&config, path).filter(|v| match *kind {
                    "bool" => v.is_boolean(),
                    "number" => v.is_i64() || v.is_u64(),
                    _ => v.as_str().is_some_and(safe_text),
                }) {
                    set(row, &format!("{section}.config.{path}"), value.clone());
                }
            }
            if section == "kubelet" {
                if let Some(path) = leaf(&config, "authentication.x509.clientCAFile")
                    .and_then(Value::as_str)
                    .filter(|_| {
                        !args.contains_key("client-ca-file") && !args.contains_key("config-dir")
                    })
                {
                    if let Some(value) = stat(path) {
                        set(row, "files.kubelet_client_ca", value);
                    }
                }
            } else if let Some(value) = config
                .get("clientConnection")
                .filter(|_| !args.contains_key("kubeconfig"))
                .and_then(|v| v.get("kubeconfig"))
                .and_then(Value::as_str)
                .and_then(stat)
            {
                set(row, "files.kube_proxy_kubeconfig", value);
            }
        }
    }
}
fn feature_gate(raw: &str, key: &str) -> Option<bool> {
    let mut seen = BTreeSet::new();
    let mut found = None;
    for item in raw.split(',') {
        let (name, value) = item.split_once('=')?;
        if !seen.insert(name) {
            return None;
        }
        let value = value.parse::<bool>().ok()?;
        if name == key {
            found = Some(value);
        }
    }
    found
}
fn config_flag(path: &str) -> String {
    match path {
        "authentication.anonymous.enabled" => "anonymous-auth".into(),
        "authorization.mode" => "authorization-mode".into(),
        "authentication.x509.clientCAFile" => "client-ca-file".into(),
        "featureGates.RotateKubeletServerCertificate" => "feature-gates".into(),
        _ => {
            let mut out = String::new();
            for c in path.chars() {
                if c.is_ascii_uppercase() {
                    out.push('-');
                    out.push(c.to_ascii_lowercase());
                } else {
                    out.push(c);
                }
            }
            out
        }
    }
}

fn metadata_group(path: &Path, suffixes: &[&str], recursive: bool) -> Option<Vec<Value>> {
    fn walk(
        path: &Path,
        suffixes: &[&str],
        recursive: bool,
        rows: &mut Vec<Value>,
        depth: usize,
    ) -> Option<()> {
        if depth > 8 || rows.len() >= MAX_FILES {
            return None;
        }
        let dir = open_nofollow(path, true)?;
        if !dir.metadata().ok()?.is_dir() {
            return None;
        }
        // Linux procfd pins the opened directory across rename; entries are
        // opened again by the component-walking nofollow metadata reader.
        for entry in fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd())).ok()? {
            let entry = entry.ok()?;
            let name = entry.file_name();
            let child = path.join(&name);
            let m = open_nofollow(&child, true)?.metadata().ok()?;
            if m.is_dir() && recursive {
                if suffixes.is_empty() {
                    rows.push(metadata(&child)?);
                }
                walk(&child, suffixes, recursive, rows, depth + 1)?;
            } else if m.is_file()
                && (suffixes.is_empty()
                    || suffixes.iter().any(|s| name.to_string_lossy().ends_with(s)))
            {
                rows.push(metadata(&child)?);
            }
            if rows.len() >= MAX_FILES {
                return None;
            }
        }
        Some(())
    }
    let mut rows = Vec::new();
    walk(path, suffixes, recursive, &mut rows, 0)?;
    (!rows.is_empty()).then_some(rows)
}
fn owner_name(raw: &str, id: u64, column: usize) -> Option<String> {
    let mut names = raw.lines().filter_map(|line| {
        let cells = line.split(':').collect::<Vec<_>>();
        (cells.get(column)?.parse::<u64>().ok()? == id).then(|| cells[0].to_owned())
    });
    let name = names.next()?;
    (names.next().is_none() && safe_text(&name)).then_some(name)
}

// /proc/PID/root is the one intentional kernel-owned magic-link boundary.
// It is opened only for a numerically enumerated live process, pinned by start
// time plus root inode and mount namespace before and after every operation.
// Every descendant component is opened relative to that FD with O_NOFOLLOW.
struct Process {
    path: PathBuf,
    root: File,
    start: String,
    namespace: PathBuf,
    args: BTreeMap<String, String>,
    command_line: String,
}
impl Process {
    fn open(
        path: PathBuf,
        args: BTreeMap<String, String>,
        start: String,
        command_line: String,
    ) -> Option<Self> {
        let namespace = fs::read_link(path.join("ns/mnt")).ok()?;
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(path.join("root"))
            .ok()?;
        let result = Self {
            path,
            root,
            start,
            namespace,
            args,
            command_line,
        };
        result.valid().then_some(result)
    }
    fn valid(&self) -> bool {
        // stat's CPU counters change; only pid start time binds identity.
        let start = |s: &str| {
            s.rsplit_once(')')
                .and_then(|(_, tail)| tail.split_whitespace().nth(19))
                .map(str::to_owned)
        };
        let command_matches = (|| -> Option<bool> {
            let file = open_nofollow(&self.path.join("cmdline"), false)?;
            let mut bytes = Vec::new();
            file.take(65537).read_to_end(&mut bytes).ok()?;
            Some(bytes == self.command_line.as_bytes())
        })() == Some(true);
        command_matches
            && start(&self.start).is_some()
            && read_text(&self.path.join("stat"), 65536)
                .as_deref()
                .and_then(start)
                == start(&self.start)
            && fs::read_link(self.path.join("ns/mnt")).ok().as_ref() == Some(&self.namespace)
            && self
                .root
                .metadata()
                .ok()
                .zip(fs::metadata(self.path.join("root")).ok())
                .is_some_and(|(a, b)| a.dev() == b.dev() && a.ino() == b.ino())
    }
    fn open_file(&self, path: &str, stat_only: bool) -> Option<File> {
        if !self.valid() || !Path::new(path).is_absolute() {
            return None;
        }
        let mut dir = self.root.try_clone().ok()?;
        let parts = Path::new(path)
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
        if meta.file_type().is_symlink()
            || !(meta.is_file() || stat_only && meta.is_dir())
            || !self.valid()
        {
            return None;
        }
        Some(dir)
    }
    fn text(&self, path: &str) -> Option<String> {
        let file = self.open_file(path, false)?;
        if file.metadata().ok()?.len() > MAX_FILE {
            return None;
        }
        let mut bytes = Vec::new();
        file.take(MAX_FILE + 1).read_to_end(&mut bytes).ok()?;
        if bytes.len() as u64 > MAX_FILE || bytes.contains(&0) || !self.valid() {
            return None;
        }
        String::from_utf8(bytes).ok()
    }
    fn metadata(&self, path: &str) -> Option<Value> {
        let m = self.open_file(path, true)?.metadata().ok()?;
        Some(
            serde_json::json!({"mode":format!("{:04o}",m.mode()&0o7777),"uid":m.uid(),"gid":m.gid()}),
        )
    }
}

// When every plugin used by this benchmark has explicit enable/disable
// authority, defaults cannot affect any deciding predicate. Do not infer a
// default plugin set from an unverified image tag or binary filename.
fn explicit_admission(args: &BTreeMap<String, String>) -> Option<Vec<String>> {
    const DECIDING: &[&str] = &[
        "DenyServiceExternalIPs",
        "EventRateLimit",
        "AlwaysAdmit",
        "AlwaysPullImages",
        "ServiceAccount",
        "NamespaceLifecycle",
        "NodeRestriction",
    ];
    let parse = |key: &str| -> Option<BTreeSet<String>> {
        let mut out = BTreeSet::new();
        if let Some(raw) = args.get(key) {
            for plugin in raw.split(',') {
                if plugin.is_empty()
                    || !plugin.bytes().all(|b| b.is_ascii_alphanumeric())
                    || !out.insert(plugin.into())
                {
                    return None;
                }
            }
        }
        Some(out)
    };
    let enabled = parse("enable-admission-plugins")?;
    let disabled = parse("disable-admission-plugins")?;
    if !enabled.is_disjoint(&disabled)
        || !DECIDING
            .iter()
            .all(|p| enabled.contains(*p) || disabled.contains(*p))
    {
        return None;
    }
    Some(enabled.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_flags_configs_and_unknowns() {
        let words = vec![
            "kubelet",
            "--config=/safe/config",
            "--hostname-override=worker",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let args = parse_args(&words).unwrap();
        let mut row = identity("kubernetes_node");
        let config="authentication:\n  anonymous:\n    enabled: false\n  x509:\n    clientCAFile: /safe/ca\nreadOnlyPort: 0\nrotateCertificates: true\nseccompDefault: true\nclientKeyData: DO_NOT_EXPORT\n".to_owned();
        collect_component(
            "kubelet",
            &args,
            &mut row,
            &|_| Some(config.clone()),
            &|_| Some(serde_json::json!({"uid":0,"gid":0,"mode":"0600"})),
        );
        assert_eq!(
            leaf(&Value::Object(row.clone()), "kubelet.config.readOnlyPort"),
            Some(&Value::from(0))
        );
        assert!(
            !serde_json::to_string(&row)
                .unwrap()
                .contains("DO_NOT_EXPORT")
        );
        let mut overridden = args.clone();
        overridden.insert("read-only-port".into(), "10255".into());
        let mut row = identity("kubernetes_node");
        collect_component(
            "kubelet",
            &overridden,
            &mut row,
            &|_| Some(config.clone()),
            &|_| None,
        );
        assert!(leaf(&row.into(), "kubelet.config.readOnlyPort").is_none());
        assert!(
            parse_args(&["kubelet".into(), "--config=a".into(), "--config=b".into()]).is_none()
        );
        assert!(
            document("authentication: {anonymous: {enabled: false}}\nauthentication: {}").is_none()
        );
    }
    #[test]
    fn admission_requires_explicit_effective_authority() {
        let mut args=BTreeMap::from([("enable-admission-plugins".into(),"DenyServiceExternalIPs,EventRateLimit,AlwaysPullImages,ServiceAccount,NamespaceLifecycle,NodeRestriction".into()),("disable-admission-plugins".into(),"AlwaysAdmit".into())]);
        assert_eq!(explicit_admission(&args).unwrap().len(), 6);
        args.remove("disable-admission-plugins");
        assert!(explicit_admission(&args).is_none());
    }
    #[test]
    fn file_metadata_never_follows_symlinks() {
        let path = std::env::temp_dir().join(format!("cis-k8s-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        fs::write(path.join("key"), "SECRET").unwrap();
        std::os::unix::fs::symlink(path.join("key"), path.join("link")).unwrap();
        assert!(metadata(&path.join("link")).is_none());
        assert!(metadata(&path.join("key")).is_some());
        fs::remove_dir_all(path).unwrap();
    }
}

// JSON Value silently overwrites duplicate YAML keys. Reject them before
// selecting fields, otherwise a malformed document can manufacture a pass.
struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "bounded unique-key configuration")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<UniqueValue, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<UniqueValue, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<UniqueValue, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<UniqueValue, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| UniqueValue(n.into()))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<UniqueValue, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<UniqueValue, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<UniqueValue, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<UniqueValue, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<UniqueValue, A::Error> {
                let mut out = Vec::new();
                while let Some(value) = seq.next_element::<UniqueValue>()? {
                    if out.len() >= 256 {
                        return Err(serde::de::Error::custom("sequence too long"));
                    }
                    out.push(value.0)
                }
                Ok(UniqueValue(out.into()))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<UniqueValue, A::Error> {
                let mut out = Map::new();
                while let Some((key, value)) = map.next_entry::<String, UniqueValue>()? {
                    if out.len() >= 256 || out.insert(key, value.0).is_some() {
                        return Err(serde::de::Error::custom(
                            "duplicate key or mapping too long",
                        ));
                    }
                }
                Ok(UniqueValue(out.into()))
            }
        }
        d.deserialize_any(Visitor)
    }
}

#[cfg(test)]
mod replay {
    use super::*;
    #[test]
    fn parsed_product_replay() {
        let Some(output) = std::env::var_os("CIS_ENDPOINT_REPLAY") else {
            return;
        };
        let mut rows = Vec::new();
        for (name, anonymous, port) in [("passing", "false", 0), ("finding", "true", 10255)] {
            let mut cluster = identity("kubernetes_cluster");
            let args=parse_args(&["kube-apiserver".into(),format!("--anonymous-auth={anonymous}"),"--authorization-mode=Node,RBAC".into(),"--audit-log-maxage=30".into(),"--audit-log-maxbackup=10".into(),"--audit-log-maxsize=100".into(),"--enable-admission-plugins=DenyServiceExternalIPs,EventRateLimit,AlwaysPullImages,ServiceAccount,NamespaceLifecycle,NodeRestriction".into(),"--disable-admission-plugins=AlwaysAdmit".into()]).unwrap();
            collect_component("apiserver", &args, &mut cluster, &|_| None, &|_| None);
            let mut node = identity("kubernetes_node");
            let args = parse_args(&[
                "kubelet".into(),
                "--config=/etc/kubernetes/kubelet.yaml".into(),
            ])
            .unwrap();
            let config = format!(
                "authentication:\n  anonymous:\n    enabled: {anonymous}\nauthorization:\n  mode: Webhook\nreadOnlyPort: {port}\nrotateCertificates: true\nseccompDefault: true\n"
            );
            collect_component(
                "kubelet",
                &args,
                &mut node,
                &|_| Some(config.clone()),
                &|_| Some(serde_json::json!({"uid":0,"gid":0,"mode":"0600"})),
            );
            rows.push(serde_json::json!({"name":name,"observations":[cluster,node]}));
        }
        fs::write(output, serde_json::to_vec_pretty(&rows).unwrap()).unwrap();
    }
}

fn flag_value(key: &str, value: &str) -> Option<Value> {
    match key {
        "anonymous-auth"
        | "profiling"
        | "service-account-lookup"
        | "service-account-extend-token-expiration"
        | "use-service-account-credentials"
        | "client-cert-auth"
        | "auto-tls"
        | "peer-client-cert-auth"
        | "peer-auto-tls" => value.parse::<bool>().ok().map(Value::from),
        "audit-log-maxage" | "audit-log-maxbackup" | "audit-log-maxsize" => {
            value.parse::<i64>().ok().map(Value::from)
        }
        _ => Some(value.into()),
    }
}

fn valid_audit_rule(rule: &Value) -> bool {
    let Some(object) = rule.as_object() else {
        return false;
    };
    if !matches!(
        object.get("level").and_then(Value::as_str),
        Some("None" | "Metadata" | "Request" | "RequestResponse")
    ) {
        return false;
    }
    if object
        .get("nonResourceURLs")
        .and_then(Value::as_array)
        .is_some_and(|v| !v.is_empty())
        && ["resources", "namespaces"].iter().any(|key| {
            object
                .get(*key)
                .and_then(Value::as_array)
                .is_some_and(|v| !v.is_empty())
        })
    {
        return false;
    }
    let strings = |v: &Value| {
        v.as_array()
            .is_some_and(|a| a.len() <= 256 && a.iter().all(|v| v.as_str().is_some_and(safe_text)))
    };
    object.iter().all(|(key, value)| match key.as_str() {
        "level" => true,
        "omitManagedFields" => value.is_boolean(),
        "users" | "userGroups" | "verbs" | "namespaces" | "nonResourceURLs" => strings(value),
        "omitStages" => value.as_array().is_some_and(|a| {
            a.iter().all(|v| {
                matches!(
                    v.as_str(),
                    Some("RequestReceived" | "ResponseStarted" | "ResponseComplete" | "Panic")
                )
            })
        }),
        "resources" => value.as_array().is_some_and(|a| {
            a.len() <= 256
                && a.iter().all(|v| {
                    v.as_object().is_some_and(|o| {
                        o.iter().all(|(key, v)| match key.as_str() {
                            "group" => v.as_str().is_some_and(safe_text),
                            "resources" | "resourceNames" => strings(v),
                            _ => false,
                        })
                    })
                })
        }),
        _ => false,
    })
}

fn applicable_rows(
    cluster: Map<String, Value>,
    node: Map<String, Value>,
    cluster_applicable: bool,
    node_applicable: bool,
) -> Vec<Value> {
    let mut rows = Vec::new();
    if cluster_applicable {
        rows.push(cluster.into())
    }
    if node_applicable {
        rows.push(node.into())
    }
    rows
}
fn optional_metadata_paths(paths: &[&Path]) -> Option<Vec<Value>> {
    let mut rows = Vec::new();
    let parent_path = paths.first()?.parent()?;
    let parent = open_nofollow(parent_path, true)?;
    if !parent.metadata().ok()?.is_dir() {
        return None;
    }
    for path in paths {
        if path.parent()? != parent_path {
            return None;
        }
        // A missing optional file is safe to omit only below a real nofollow
        // directory. A present symlink, denied lookup or failed stat invalidates
        // the whole universal-quantification group.
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(path.file_name()?.as_bytes()).ok()?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                continue;
            }
            return None;
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let m = file.metadata().ok()?;
        if !m.is_file() || m.file_type().is_symlink() {
            return None;
        }
        rows.push(serde_json::json!({"mode":format!("{:04o}",m.mode() & 0o7777), "uid":m.uid(), "gid":m.gid()}));
    }
    (!rows.is_empty()).then_some(rows)
}
#[cfg(test)]
mod fix_round_one {
    use super::*;
    #[test]
    fn applicability_requires_positive_component_discovery() {
        assert!(
            applicable_rows(
                identity("kubernetes_cluster"),
                identity("kubernetes_node"),
                false,
                false
            )
            .is_empty()
        );
        assert_eq!(
            applicable_rows(
                identity("kubernetes_cluster"),
                identity("kubernetes_node"),
                true,
                false
            )[0]["kind"],
            "kubernetes_cluster"
        );
        assert_eq!(
            applicable_rows(
                identity("kubernetes_cluster"),
                identity("kubernetes_node"),
                false,
                true
            )[0]["kind"],
            "kubernetes_node"
        );
        assert!(collect(Instant::now()).is_empty());
    }
    #[test]
    fn optional_admin_group_rejects_present_unsafe_member() {
        let dir = std::env::temp_dir().join(format!("cis-admin-group-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        let admin = dir.join("admin.conf");
        let optional = dir.join("super-admin.conf");
        fs::write(&admin, "SECRET").unwrap();
        assert_eq!(
            optional_metadata_paths(&[&admin, &optional]).unwrap().len(),
            1
        );
        std::os::unix::fs::symlink(dir.join("missing"), &optional).unwrap();
        assert!(optional_metadata_paths(&[&admin, &optional]).is_none());
        fs::remove_file(&optional).unwrap();
        fs::write(&optional, "SECRET").unwrap();
        assert_eq!(
            optional_metadata_paths(&[&admin, &optional]).unwrap().len(),
            2
        );
        fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
mod effective_path_fix {
    use super::*;
    #[test]
    fn kubelet_dropins_never_authorize_base_client_ca_metadata() {
        let mut args = BTreeMap::from([
            ("config".into(), "/base".into()),
            ("config-dir".into(), "/dropins".into()),
        ]);
        let read = |_: &str| Some("authentication: {x509: {clientCAFile: /old-ca}}".into());
        let stat =
            |path: &str| Some(serde_json::json!({"path":path,"mode":"0600","uid":0,"gid":0}));
        let mut row = identity("kubernetes_node");
        collect_component("kubelet", &args, &mut row, &read, &stat);
        assert!(leaf(&row.into(), "files.kubelet_client_ca").is_none());
        args.insert("client-ca-file".into(), "/effective-ca".into());
        let mut row = identity("kubernetes_node");
        collect_component("kubelet", &args, &mut row, &read, &stat);
        assert_eq!(
            leaf(&row.into(), "files.kubelet_client_ca.path"),
            Some(&Value::from("/effective-ca"))
        );
    }
    #[test]
    fn proxy_explicit_kubeconfig_metadata_cannot_be_replaced_by_base_config() {
        let args = BTreeMap::from([
            ("config".into(), "/base".into()),
            ("kubeconfig".into(), "/effective".into()),
        ]);
        let mut row = identity("kubernetes_node");
        collect_component(
            "kube_proxy",
            &args,
            &mut row,
            &|_| Some("clientConnection: {kubeconfig: /old}".into()),
            &|path| Some(serde_json::json!({"path":path})),
        );
        assert_eq!(
            leaf(&row.into(), "files.kube_proxy_kubeconfig.path"),
            Some(&Value::from("/effective"))
        );
    }
}

fn yaml_reference_token(raw: &str) -> bool {
    let mut quote = None;
    let mut escaped = false;
    let mut comment = false;
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if comment {
            if c == '\n' {
                comment = false
            }
            continue;
        }
        match quote {
            Some('"') => {
                if escaped {
                    escaped = false
                } else if c == '\\' {
                    escaped = true
                } else if c == '"' {
                    quote = None
                }
            }
            Some('\'') => {
                if c == '\'' {
                    if chars.peek() == Some(&'\'') {
                        chars.next();
                    } else {
                        quote = None
                    }
                }
            }
            _ => match c {
                '"' | '\'' => quote = Some(c),
                '#' => comment = true,
                '&' | '*' => return true,
                _ => {}
            },
        }
    }
    false
}
#[cfg(test)]
mod audit_wildcards {
    use super::*;
    #[test]
    fn quoted_wildcards_are_values_but_yaml_references_are_rejected() {
        let raw = "apiVersion: audit.k8s.io/v1\nkind: Policy\nrules:\n- level: Metadata\n  resources:\n  - group: \"\"\n    resources: ['*']\n";
        let policy = document(raw).unwrap();
        assert!(
            policy["rules"]
                .as_array()
                .unwrap()
                .iter()
                .all(valid_audit_rule)
        );
        assert!(document("x: &anchor [Metadata]\ny: *anchor").is_none());
        assert!(document("x: \"literal *wildcard &text\"").is_some());
    }
}

fn kubernetes_control_plane(name: &str) -> bool {
    matches!(
        name,
        "kube-apiserver" | "kube-controller-manager" | "kube-scheduler"
    )
}
#[cfg(test)]
mod fix_round_two {
    use super::*;
    #[test]
    fn standalone_etcd_never_establishes_kubernetes_cluster_applicability() {
        for names in [vec!["etcd"], vec!["etcd", "unrelated-process"]] {
            let cluster_applicable = names.iter().any(|name| kubernetes_control_plane(name));
            assert!(
                applicable_rows(
                    identity("kubernetes_cluster"),
                    identity("kubernetes_node"),
                    cluster_applicable,
                    false
                )
                .is_empty()
            );
        }
        for name in [
            "kube-apiserver",
            "kube-controller-manager",
            "kube-scheduler",
        ] {
            assert!(kubernetes_control_plane(name));
        }
    }
    #[test]
    fn descriptor_relative_optional_group_rejects_leaf_symlink() {
        let root = std::env::temp_dir().join(format!("cis-group-fd-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let good = root.join("admin.conf");
        let unsafe_file = root.join("super-admin.conf");
        fs::write(&good, "private").unwrap();
        std::os::unix::fs::symlink(&good, &unsafe_file).unwrap();
        assert!(optional_metadata_paths(&[&good, &unsafe_file]).is_none());
        fs::remove_file(&unsafe_file).unwrap();
        assert_eq!(
            optional_metadata_paths(&[&good, &unsafe_file])
                .unwrap()
                .len(),
            1
        );
        fs::remove_dir_all(root).unwrap();
    }
}

// Match the first encryption resource stanza and first write provider. Reading
// key lengths validates the configured cipher without disclosing key material.
fn secrets_encryption(config: &Value) -> Option<Value> {
    use base64::Engine;
    if config.get("apiVersion")?.as_str()? != "apiserver.config.k8s.io/v1"
        || config.get("kind")?.as_str()? != "EncryptionConfiguration"
    {
        return None;
    }
    let resources = config.get("resources")?.as_array()?;
    if resources.len() > 128 {
        return None;
    }
    // A malformed later stanza invalidates the configured file too. Validate
    // its bounded shape and keys before selecting a write provider.
    for stanza in resources {
        let object = stanza.as_object()?;
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "resources" | "providers"))
        {
            return None;
        }
        let selectors = stanza.get("resources")?.as_array()?;
        if selectors.is_empty()
            || selectors.len() > 128
            || selectors
                .iter()
                .any(|v| !v.as_str().is_some_and(|s| !s.is_empty() && safe_text(s)))
        {
            return None;
        }
        let providers = stanza.get("providers")?.as_array()?;
        if providers.is_empty() || providers.len() > 32 {
            return None;
        }
        for provider in providers {
            let provider = provider.as_object()?;
            if provider.len() != 1 {
                return None;
            }
            let (name, options) = provider.iter().next()?;
            let options = options.as_object()?;
            match name.as_str() {
                "identity" if options.is_empty() => (),
                "kms" => {
                    if options.keys().any(|k| {
                        !matches!(
                            k.as_str(),
                            "name" | "apiVersion" | "endpoint" | "timeout" | "cachesize"
                        )
                    }) || options.get("name")?.as_str().is_none_or(|s| s.is_empty())
                        || !options
                            .get("endpoint")?
                            .as_str()
                            .is_some_and(|s| s.starts_with("unix://") && s.len() > 7)
                        || options
                            .get("apiVersion")
                            .is_some_and(|v| !matches!(v.as_str(), Some("v1" | "v2")))
                        || options
                            .get("cachesize")
                            .is_some_and(|v| v.as_i64().is_none_or(|n| n < 0))
                        || options.get("timeout").is_some_and(|v| {
                            !v.as_str().is_some_and(|s| {
                                s.bytes().all(|b| {
                                    b.is_ascii_digit() || matches!(b, b'.' | b'm' | b's' | b'h')
                                })
                            })
                        })
                    {
                        return None;
                    }
                }
                "aescbc" | "aesgcm" | "secretbox" => {
                    if options.len() != 1 {
                        return None;
                    }
                    let keys = options.get("keys")?.as_array()?;
                    if keys.is_empty() || keys.len() > 32 {
                        return None;
                    }
                    for key in keys {
                        let key = key.as_object()?;
                        if key.len() != 2 || key.get("name")?.as_str()?.is_empty() {
                            return None;
                        }
                        let text = key.get("secret")?.as_str()?;
                        if text.len() > 128 {
                            return None;
                        }
                        let bytes = base64::engine::general_purpose::STANDARD
                            .decode(text)
                            .ok()?
                            .len();
                        if (name != "secretbox" && !matches!(bytes, 16 | 24 | 32))
                            || (name == "secretbox" && bytes != 32)
                        {
                            return None;
                        }
                    }
                }
                _ => return None,
            }
        }
    }
    for (index, stanza) in resources.iter().enumerate() {
        let selectors = stanza.get("resources")?.as_array()?;
        let selectors: Vec<&str> = selectors.iter().map(Value::as_str).collect::<Option<_>>()?;
        // The core Secrets resource matches these documented selector forms.
        // An unknown wildcard must not let a later encrypted stanza win.
        let mut selected = None;
        for selector in &selectors {
            if matches!(*selector, "secrets" | "secrets." | "*." | "*.*") {
                selected = Some(*selector);
                break;
            }
            if selector.contains('*') {
                // A wildcard for an explicitly different API group cannot
                // select the core Secrets resource.
                if !selector.starts_with("*.") || selector.len() <= 2 {
                    return None;
                }
            }
        }
        let Some(selector) = selected else {
            continue;
        };
        let providers = stanza.get("providers")?.as_array()?;
        if providers.is_empty() || providers.len() > 32 {
            return None;
        }
        let mut order = Vec::new();
        let mut key_bytes = None;
        for (i, provider) in providers.iter().enumerate() {
            let provider = provider.as_object()?;
            if provider.len() != 1 {
                return None;
            }
            let (name, options) = provider.iter().next()?;
            if !matches!(
                name.as_str(),
                "identity" | "aescbc" | "aesgcm" | "secretbox" | "kms"
            ) {
                return None;
            }
            order.push(name.clone());
            if i != 0 {
                continue;
            }
            if name == "identity" {
                if !options.as_object()?.is_empty() {
                    return None;
                }
            } else if name == "kms" {
                let version = options
                    .get("apiVersion")
                    .and_then(Value::as_str)
                    .unwrap_or("v1");
                if !matches!(version, "v1" | "v2")
                    || options.get("name")?.as_str().is_none_or(|s| s.is_empty())
                    || !options
                        .get("endpoint")?
                        .as_str()
                        .is_some_and(|s| s.starts_with("unix://") && s.len() > 7)
                {
                    return None;
                }
            } else {
                let keys = options.get("keys")?.as_array()?;
                if keys.is_empty() || keys.len() > 32 {
                    return None;
                }
                let key = &keys[0];
                if key.get("name")?.as_str()?.is_empty() {
                    return None;
                }
                let encoded = key.get("secret")?.as_str()?;
                if encoded.len() > 128 {
                    return None;
                }
                key_bytes = Some(
                    base64::engine::general_purpose::STANDARD
                        .decode(encoded)
                        .ok()?
                        .len(),
                );
            }
        }
        let mut fact = serde_json::json!({"selected_rule":index,"selector":selector,"provider_order":order,"write_provider":order[0]});
        if let Some(bytes) = key_bytes {
            fact["write_key_bytes"] = bytes.into();
        }
        return Some(fact);
    }
    Some(serde_json::json!({"write_provider":"none","provider_order":[]}))
}

// Synthetic request tuples exercise configuration only. No customer requests,
// user identities or audit request/response bodies leave this host.
const AUDIT_CASES: &[(&str, &str, &str, &str)] = &[
    ("secrets-get", "", "secrets", "get"),
    ("secrets-list", "", "secrets", "list"),
    ("configmaps-get", "", "configmaps", "get"),
    (
        "roles-create",
        "rbac.authorization.k8s.io",
        "roles",
        "create",
    ),
    (
        "rolebindings-create",
        "rbac.authorization.k8s.io",
        "rolebindings",
        "create",
    ),
    (
        "clusterroles-update",
        "rbac.authorization.k8s.io",
        "clusterroles",
        "update",
    ),
    (
        "clusterrolebindings-delete",
        "rbac.authorization.k8s.io",
        "clusterrolebindings",
        "delete",
    ),
    ("pods-create", "", "pods", "create"),
    ("pods-delete", "", "pods", "delete"),
    ("deployments-patch", "apps", "deployments", "patch"),
    ("nodes-patch", "", "nodes", "patch"),
    ("serviceaccounts-create", "", "serviceaccounts", "create"),
];

fn audit_security_cases(policy: &Value) -> Option<Value> {
    if policy.get("apiVersion")?.as_str()? != "audit.k8s.io/v1"
        || policy.get("kind")?.as_str()? != "Policy"
    {
        return None;
    }
    let rules = policy.get("rules")?.as_array()?;
    if rules.len() > 256 || !rules.iter().all(valid_audit_rule) {
        return None;
    }
    let stages = |value: Option<&Value>| -> Option<Vec<String>> {
        value.map_or(Some(Vec::new()), |v| {
            v.as_array()?
                .iter()
                .map(|v| {
                    let text = v.as_str()?;
                    matches!(
                        text,
                        "RequestReceived" | "ResponseStarted" | "ResponseComplete" | "Panic"
                    )
                    .then(|| text.to_owned())
                })
                .collect()
        })
    };
    let global_stages = stages(policy.get("omitStages"))?;
    let matches_list = |rule: &Value, key: &str, candidate: &str| {
        rule.get(key)
            .and_then(Value::as_array)
            .is_none_or(|a| a.is_empty() || a.iter().any(|v| v.as_str() == Some(candidate)))
    };
    let mut output = Vec::new();
    for (id, group, resource, verb) in AUDIT_CASES {
        let namespace = if matches!(*resource, "nodes" | "clusterroles" | "clusterrolebindings") {
            ""
        } else {
            "cis-audit-probe"
        };
        let resource_name = if matches!(*verb, "create" | "list" | "watch" | "deletecollection") {
            ""
        } else {
            "cis-audit-probe"
        };
        let mut fact =
            serde_json::json!({"case_id":id,"level":"None","effective_omit_stages":global_stages});
        for (index, rule) in rules.iter().enumerate() {
            if rule
                .get("nonResourceURLs")
                .and_then(Value::as_array)
                .is_some_and(|a| !a.is_empty())
            {
                continue;
            }
            if !matches_list(rule, "users", "cis-audit-probe")
                || !matches_list(rule, "userGroups", "system:authenticated")
                || !matches_list(rule, "namespaces", namespace)
                || !matches_list(rule, "verbs", verb)
            {
                continue;
            }
            let matches_resource =
                rule.get("resources")
                    .and_then(Value::as_array)
                    .is_none_or(|entries| {
                        entries.is_empty()
                            || entries.iter().any(|entry| {
                                let actual_group =
                                    entry.get("group").and_then(Value::as_str).unwrap_or("");
                                if actual_group != *group {
                                    return false;
                                }
                                if entry
                                    .get("resources")
                                    .and_then(Value::as_array)
                                    .is_none_or(Vec::is_empty)
                                {
                                    return true;
                                }
                                if !matches_list(entry, "resourceNames", resource_name) {
                                    return false;
                                }
                                entry.get("resources").and_then(Value::as_array).is_none_or(
                                    |names| {
                                        names.is_empty()
                                            || names.iter().any(|name| {
                                                matches!(name.as_str(), Some("*"))
                                                    || name.as_str() == Some(*resource)
                                                    || name
                                                        .as_str()
                                                        .and_then(|s| s.strip_suffix("/*"))
                                                        == Some(*resource)
                                            })
                                    },
                                )
                            })
                    });
            if !matches_resource {
                continue;
            }
            let mut omitted = global_stages.clone();
            omitted.extend(stages(rule.get("omitStages"))?);
            omitted.sort();
            omitted.dedup();
            fact = serde_json::json!({"case_id":id,"first_match_rule_index":index,"level":rule.get("level")?,"effective_omit_stages":omitted});
            break;
        }
        output.push(fact);
    }
    Some(output.into())
}

#[cfg(test)]
mod ordered_policy_tests {
    use super::*;
    #[test]
    fn encryption_first_match_and_first_provider_control_new_secret_writes() {
        let identity = serde_json::json!({"identity":{}});
        let cipher = serde_json::json!({"aescbc":{"keys":[{"name":"fixture","secret":"MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="}]}});
        let config = |rows: Vec<Value>| serde_json::json!({"apiVersion":"apiserver.config.k8s.io/v1","kind":"EncryptionConfiguration","resources":rows});
        let plaintext = config(vec![
            serde_json::json!({"resources":["secrets"],"providers":[identity.clone(),cipher.clone()]}),
        ]);
        assert_eq!(
            secrets_encryption(&plaintext).unwrap()["write_provider"],
            "identity"
        );
        let encrypted = config(vec![
            serde_json::json!({"resources":["secrets"],"providers":[cipher.clone(),identity.clone()]}),
        ]);
        let fact = secrets_encryption(&encrypted).unwrap();
        assert_eq!(fact["write_provider"], "aescbc");
        assert_eq!(fact["write_key_bytes"], 32);
        assert!(!fact.to_string().contains("MDAw"));
        let exemption = config(vec![
            serde_json::json!({"resources":["secrets"],"providers":[identity.clone()]}),
            serde_json::json!({"resources":["*.*"],"providers":[cipher.clone()]}),
        ]);
        assert_eq!(
            secrets_encryption(&exemption).unwrap()["write_provider"],
            "identity"
        );
        let unsupported = config(vec![
            serde_json::json!({"resources":["secret*"],"providers":[cipher]}),
        ]);
        assert!(secrets_encryption(&unsupported).is_none());
    }
    #[test]
    fn core_secret_selector_accepts_sixteen_byte_aes_key() {
        let config = serde_json::json!({"apiVersion":"apiserver.config.k8s.io/v1","kind":"EncryptionConfiguration","resources":[{"resources":["secrets."],"providers":[{"aescbc":{"keys":[{"name":"fixture","secret":"MDAwMDAwMDAwMDAwMDAwMA=="}]}}]}]});
        let fact = secrets_encryption(&config).unwrap();
        assert_eq!(fact["write_key_bytes"], 16);
        assert_eq!(fact["write_provider"], "aescbc");
    }
    #[test]
    fn audit_group_namespace_and_object_name_match_kubernetes_request_shape() {
        let config = serde_json::json!({"apiVersion":"audit.k8s.io/v1","kind":"Policy","rules":[
            {"level":"None","resources":[{"group":"*","resources":["*"]}]},
            {"level":"None","resources":[{"group":"","resources":["pods"],"resourceNames":["cis-audit-probe"]}],"verbs":["create"]},
            {"level":"Request","resources":[{"group":"","resources":["nodes"]}],"namespaces":[""]},
            {"level":"Metadata"}
        ]});
        let facts = audit_security_cases(&config).unwrap();
        assert_eq!(facts[0]["level"], "Metadata");
        assert_eq!(facts[6]["level"], "Metadata");
        assert_eq!(facts[10]["level"], "Request");
    }
    #[test]
    fn audit_first_match_and_all_selector_dimensions_control_security_case_levels() {
        let policy = |rules: Vec<Value>| serde_json::json!({"apiVersion":"audit.k8s.io/v1","kind":"Policy","rules":rules});
        let metadata = serde_json::json!({"level":"Metadata"});
        let none = serde_json::json!({"level":"None"});
        let facts = audit_security_cases(&policy(vec![none, metadata.clone()])).unwrap();
        assert!(
            facts
                .as_array()
                .unwrap()
                .iter()
                .all(|f| f["level"] == "None" && f["first_match_rule_index"] == 0)
        );
        let facts = audit_security_cases(&policy(vec![serde_json::json!({"level":"None","users":["another-user"],"resources":[{"group":"","resources":["secrets"]}]}),metadata.clone()])).unwrap();
        assert_eq!(facts[0]["level"], "Metadata");
        assert_eq!(facts[0]["first_match_rule_index"], 1);
        let facts = audit_security_cases(&policy(vec![
            serde_json::json!({"level":"None","resources":[{"group":"","resources":["pods/*"]}]}),
            metadata.clone(),
        ]))
        .unwrap();
        assert_eq!(facts[7]["level"], "None");
        let mut p = policy(vec![metadata]);
        p["omitStages"] = serde_json::json!(["RequestReceived", "ResponseComplete"]);
        assert_eq!(
            audit_security_cases(&p).unwrap()[0]["effective_omit_stages"],
            p["omitStages"]
        );
        assert!(
            audit_security_cases(&policy(vec![serde_json::json!({"level":"Bogus"})])).is_none()
        );
        assert_eq!(
            audit_security_cases(&policy(vec![])).unwrap()[0]["level"],
            "None"
        );
    }
}
