//! AI agents running without approval: one posture check per AI client,
//! evaluated from the declaration in `../../ai-agent-approval.toml`.
//!
//! For each declared client the agent reads the client's own settings files
//! (user files under each home directory, managed files at fixed system
//! paths) through the same bounded, no-follow reader the AI tool inventory
//! uses. A declared rule that matches and is not neutralized by an
//! admin-managed lock is a finding. Only declared text, rule and lock ids and a
//! hash of the per-file observation leave the device: never config values,
//! paths or account names. A client with none of its files present is omitted.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::Deserialize;

use super::{PostureCheck, evidence_check};

const DECLARATION: &str = include_str!("../../ai-agent-approval.toml");
const SOURCE: &str = "ai_agent_settings";
const UNREADABLE: &str =
    "Not checked: an AI agent settings file exists but could not be read or parsed";
const ASKS: &str = "No declared setting lets this AI agent act without asking";

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(super) struct Declaration {
    version: u32,
    risk_weight: u8,
    clients: Vec<Client>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Client {
    id: String,
    check: String,
    name: String,
    docs: Vec<String>,
    sources: Vec<Source>,
    #[serde(default)]
    rules: Vec<Rule>,
    #[serde(default)]
    locks: Vec<Lock>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Source {
    scope: Scope,
    format: Format,
    linux: Option<String>,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Scope {
    User,
    Managed,
}

#[derive(Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum Format {
    Json,
    Toml,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Rule {
    id: String,
    severity: Severity,
    reason: String,
    when: Vec<Condition>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Lock {
    id: String,
    reason: String,
    when: Vec<Condition>,
    neutralizes: Vec<String>,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Condition {
    key: String,
    #[serde(default)]
    any_of: Vec<Scalar>,
    #[serde(default)]
    lacks: Vec<String>,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum Scalar {
    Bool(bool),
    Text(String),
}

impl Scalar {
    fn matches(&self, value: &serde_json::Value) -> bool {
        match (self, value) {
            (Self::Bool(want), serde_json::Value::Bool(got)) => want == got,
            (Self::Text(want), serde_json::Value::String(got)) => want == got,
            _ => false,
        }
    }
}

impl Condition {
    fn holds(&self, document: &serde_json::Value) -> bool {
        let Some(value) = self
            .key
            .split('.')
            .try_fold(document, |node, part| node.get(part))
        else {
            return false;
        };
        if !self.any_of.is_empty() {
            let matches = |item: &serde_json::Value| self.any_of.iter().any(|s| s.matches(item));
            return match value {
                serde_json::Value::Array(items) => items.iter().any(matches),
                scalar => matches(scalar),
            };
        }
        value.as_array().is_some_and(|items| {
            items.iter().all(|item| {
                item.as_str()
                    .is_some_and(|text| !self.lacks.iter().any(|lacked| lacked == text))
            })
        })
    }
}

fn all_hold(conditions: &[Condition], document: &serde_json::Value) -> bool {
    conditions.iter().all(|condition| condition.holds(document))
}

/// The compiled-in declaration, parsed and validated once. `None` only if the
/// declaration is invalid, which the tests rule out.
pub(super) fn declaration() -> Option<&'static Declaration> {
    static PARSED: OnceLock<Option<Declaration>> = OnceLock::new();
    PARSED
        .get_or_init(|| {
            let parsed: Declaration = toml::from_str(DECLARATION).ok()?;
            validate(&parsed).ok()?;
            Some(parsed)
        })
        .as_ref()
}

fn validate(declaration: &Declaration) -> Result<(), String> {
    if declaration.version != 1 {
        return Err("version must be 1".into());
    }
    let mut checks = std::collections::BTreeSet::new();
    for client in &declaration.clients {
        let id = &client.id;
        if !client.check.starts_with("ai_agent_approval_") || !checks.insert(&client.check) {
            return Err(format!(
                "{id}: check must be unique and start with ai_agent_approval_"
            ));
        }
        if client.name.is_empty() || client.docs.is_empty() || client.sources.is_empty() {
            return Err(format!("{id}: name, docs and sources are required"));
        }
        if client.docs.iter().any(|url| !url.starts_with("https://")) {
            return Err(format!("{id}: docs must be https URLs"));
        }
        for source in &client.sources {
            if let Some(path) = &source.linux {
                let absolute = path.starts_with('/');
                let valid = !path.contains("..")
                    && path.contains('/')
                    && absolute == (source.scope == Scope::Managed);
                if !valid {
                    return Err(format!(
                        "{id}: user paths are home-relative, managed paths absolute"
                    ));
                }
            }
        }
        let conditions = client
            .rules
            .iter()
            .flat_map(|rule| &rule.when)
            .chain(client.locks.iter().flat_map(|lock| &lock.when));
        for condition in conditions {
            if condition.key.is_empty() || condition.any_of.is_empty() == condition.lacks.is_empty()
            {
                return Err(format!(
                    "{id}: each condition names a key and exactly one of any_of or lacks"
                ));
            }
        }
        if client
            .rules
            .iter()
            .any(|rule| rule.when.is_empty() || rule.reason.is_empty())
            || client
                .locks
                .iter()
                .any(|lock| lock.when.is_empty() || lock.reason.is_empty())
        {
            return Err(format!(
                "{id}: rules and locks need a reason and conditions"
            ));
        }
        for lock in &client.locks {
            for rule in &lock.neutralizes {
                if !client.rules.iter().any(|known| &known.id == rule) {
                    return Err(format!(
                        "{id}: lock {} neutralizes unknown rule {rule}",
                        lock.id
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Risk added to the posture score by a failing AI agent check.
pub(super) fn risk_weight(check: &str) -> u8 {
    declaration()
        .filter(|declared| declared.clients.iter().any(|client| client.check == check))
        .map_or(0, |declared| declared.risk_weight)
}

pub(super) struct AgentPaths {
    /// Home directories whose user settings are read.
    pub homes: Vec<PathBuf>,
    /// Where managed (absolute) paths are resolved; `/` on a real host.
    pub root: PathBuf,
}

impl AgentPaths {
    pub fn system() -> Self {
        Self {
            homes: crate::sync::agent_homes(),
            root: PathBuf::from("/"),
        }
    }
}

enum Observation {
    Missing,
    Unreadable,
    Parsed(serde_json::Value),
}

fn observe(base: &Path, relative: &str, format: Format) -> Observation {
    let path = base.join(relative);
    match path.symlink_metadata() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Observation::Missing,
        _ => {}
    }
    let Some(body) = crate::sync::read_agent_config_beneath(base, relative) else {
        return Observation::Unreadable;
    };
    let parsed = match format {
        Format::Json => serde_json::from_str(&body).ok(),
        Format::Toml => toml::from_str(&body).ok(),
    };
    parsed.map_or(Observation::Unreadable, Observation::Parsed)
}

pub(super) fn collect(
    paths: &AgentPaths,
    observed_at: &str,
    privilege: &'static str,
    checks: &mut BTreeMap<&'static str, PostureCheck>,
) {
    let Some(declared) = declaration() else {
        return;
    };
    for client in &declared.clients {
        let mut files = Vec::new();
        for (index, source) in client.sources.iter().enumerate() {
            let Some(path) = source.linux.as_deref() else {
                continue;
            };
            match source.scope {
                Scope::User => {
                    for home in &paths.homes {
                        files.push((index, source.scope, observe(home, path, source.format)));
                    }
                }
                Scope::Managed => {
                    let relative = path.trim_start_matches('/');
                    files.push((
                        index,
                        source.scope,
                        observe(&paths.root, relative, source.format),
                    ));
                }
            }
        }
        if let Some(check) = evaluate(client, &files, observed_at, privilege) {
            checks.insert(client.check.as_str(), check);
        }
    }
}

fn evaluate(
    client: &'static Client,
    files: &[(usize, Scope, Observation)],
    observed_at: &str,
    privilege: &'static str,
) -> Option<PostureCheck> {
    let mut receipt = String::new();
    let (mut any_present, mut any_parsed, mut any_unreadable) = (false, false, false);
    let mut matched: Vec<&'static Rule> = Vec::new();
    let mut locks: Vec<&'static Lock> = Vec::new();
    for (index, scope, observation) in files {
        receipt.push_str(&format!("{index}:"));
        let document = match observation {
            Observation::Missing => {
                receipt.push_str("missing\n");
                continue;
            }
            Observation::Unreadable => {
                any_present = true;
                any_unreadable = true;
                receipt.push_str("unreadable\n");
                continue;
            }
            Observation::Parsed(document) => document,
        };
        any_present = true;
        any_parsed = true;
        receipt.push_str("parsed");
        for rule in &client.rules {
            if all_hold(&rule.when, document) {
                receipt.push_str(&format!(" rule={}", rule.id));
                if !matched.iter().any(|seen| seen.id == rule.id) {
                    matched.push(rule);
                }
            }
        }
        if *scope == Scope::Managed {
            for lock in &client.locks {
                if all_hold(&lock.when, document) {
                    receipt.push_str(&format!(" lock={}", lock.id));
                    locks.push(lock);
                }
            }
        }
        receipt.push('\n');
    }
    if !any_present {
        return None;
    }
    matched.retain(|rule| !locks.iter().any(|lock| lock.neutralizes.contains(&rule.id)));
    // Declaration order, so the reason is stable across runs.
    matched.sort_by_key(|rule| client.rules.iter().position(|known| known.id == rule.id));
    let raw = receipt.as_bytes();
    let (status, value, severity, detail): (_, Cow<'static, str>, _, _) =
        if let Some(first) = matched.first() {
            let severity = matched.iter().map(|rule| rule.severity).max();
            let ids: Vec<&str> = matched.iter().map(|rule| rule.id.as_str()).collect();
            (
                "finding",
                Cow::Owned(ids.join(",")),
                severity.map(Severity::as_str),
                first.reason.as_str(),
            )
        } else if any_unreadable {
            ("unknown", Cow::Borrowed("not_checked"), None, UNREADABLE)
        } else if let Some(lock) = locks.first() {
            ("pass", Cow::Borrowed("managed"), None, lock.reason.as_str())
        } else if any_parsed {
            ("pass", Cow::Borrowed("asks"), None, ASKS)
        } else {
            return None;
        };
    let mut check = evidence_check(
        status,
        "",
        severity,
        detail,
        SOURCE,
        privilege,
        observed_at,
        raw,
    );
    check.value = Some(value);
    Some(check)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NONCE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        paths: AgentPaths,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "merlin-ai-posture-{name}-{}-{}",
                std::process::id(),
                NONCE.fetch_add(1, Ordering::Relaxed)
            ));
            let homes = vec![root.join("home/alice"), root.join("home/bob")];
            for home in &homes {
                fs::create_dir_all(home).unwrap();
            }
            let system = root.join("system");
            fs::create_dir_all(&system).unwrap();
            Self {
                paths: AgentPaths {
                    homes,
                    root: system,
                },
                root,
            }
        }

        fn user(&self, home: usize, relative: &str, body: &str) {
            let path = self.paths.homes[home].join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, body).unwrap();
        }

        fn managed(&self, absolute: &str, body: &str) {
            let path = self.paths.root.join(absolute.trim_start_matches('/'));
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, body).unwrap();
        }

        fn checks(&self) -> BTreeMap<&'static str, PostureCheck> {
            let mut checks = BTreeMap::new();
            collect(&self.paths, "1700000000.000", "root", &mut checks);
            checks
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn declaration_parses_validates_and_covers_every_client_on_linux() {
        let declared = declaration().expect("ai-agent-approval.toml is valid");
        assert!(!declared.clients.is_empty());
        for client in &declared.clients {
            assert!(
                client.sources.iter().any(|source| source.linux.is_some()),
                "{} has a Linux source",
                client.id
            );
            assert!(risk_weight(&client.check) > 0);
        }
        assert_eq!(risk_weight("secure_boot"), 0);
    }

    #[test]
    fn validation_rejects_ambiguous_conditions_and_unknown_neutralized_rules() {
        let bad_condition = r#"
version = 1
risk_weight = 1
[[clients]]
id = "x"
check = "ai_agent_approval_x"
name = "X"
docs = ["https://example.com"]
sources = [{ scope = "user", format = "json", linux = ".x/settings.json" }]
rules = [{ id = "r", severity = "high", reason = "r", when = [{ key = "k" }] }]
"#;
        let parsed: Declaration = toml::from_str(bad_condition).unwrap();
        assert!(validate(&parsed).is_err());
        let bad_lock = bad_condition.replace(
            r#"when = [{ key = "k" }] }]"#,
            r#"when = [{ key = "k", any_of = ["v"] }] }]
locks = [{ id = "l", reason = "l", when = [{ key = "k", any_of = ["v"] }], neutralizes = ["nope"] }]"#,
        );
        let parsed: Declaration = toml::from_str(&bad_lock).unwrap();
        assert!(validate(&parsed).is_err());
        let typo = bad_condition.replace("severity", "sevrity");
        assert!(toml::from_str::<Declaration>(&typo).is_err());
    }

    #[test]
    fn absent_clients_are_omitted() {
        let fixture = Fixture::new("absent");
        assert!(fixture.checks().is_empty());
    }

    #[test]
    fn claude_code_bypass_mode_and_allow_all_shell_are_findings() {
        let fixture = Fixture::new("claude");
        fixture.user(
            0,
            ".claude/settings.json",
            r#"{"permissions":{"defaultMode":"default","allow":["Bash(npm test *)"]}}"#,
        );
        let checks = fixture.checks();
        let check = &checks["ai_agent_approval_claude_code"];
        assert_eq!(check.status, "pass");
        assert_eq!(check.value.as_deref(), Some("asks"));

        fixture.user(
            1,
            ".claude/settings.json",
            r#"{"permissions":{"defaultMode":"bypassPermissions","allow":["Bash(*)"]},"env":{"API_KEY":"sk-secret"}}"#,
        );
        let checks = fixture.checks();
        let check = &checks["ai_agent_approval_claude_code"];
        assert_eq!(check.status, "finding");
        assert_eq!(check.severity, Some("high"));
        assert_eq!(
            check.value.as_deref(),
            Some("bypass_permissions,allow_all_shell")
        );
        assert!(check.detail.contains("permissions.defaultMode"));
        let wire = serde_json::to_string(check).unwrap();
        for leaked in [
            "sk-secret",
            "API_KEY",
            "alice",
            "bob",
            "/home",
            "settings.json",
        ] {
            assert!(!wire.contains(leaked), "{leaked} must not leave the device");
        }
        assert_eq!(check.evidence.as_ref().unwrap().evidence_hash.len(), 64);
    }

    #[test]
    fn claude_code_managed_lock_neutralizes_bypass_but_not_allow_rules() {
        let fixture = Fixture::new("claude-managed");
        fixture.user(
            0,
            ".claude/settings.json",
            r#"{"permissions":{"defaultMode":"bypassPermissions"}}"#,
        );
        fixture.managed(
            "/etc/claude-code/managed-settings.json",
            r#"{"permissions":{"disableBypassPermissionsMode":"disable"}}"#,
        );
        let check = &fixture.checks()["ai_agent_approval_claude_code"];
        assert_eq!(check.status, "pass");
        assert_eq!(check.value.as_deref(), Some("managed"));
        assert!(check.detail.contains("disableBypassPermissionsMode"));

        fixture.user(
            1,
            ".claude/settings.json",
            r#"{"permissions":{"allow":["Bash"]}}"#,
        );
        let check = &fixture.checks()["ai_agent_approval_claude_code"];
        assert_eq!(check.status, "finding");
        assert_eq!(check.value.as_deref(), Some("allow_all_shell"));
    }

    #[test]
    fn codex_needs_never_and_full_access_together() {
        let fixture = Fixture::new("codex");
        fixture.user(
            0,
            ".codex/config.toml",
            "approval_policy = \"never\"\nsandbox_mode = \"workspace-write\"\n",
        );
        assert_eq!(fixture.checks()["ai_agent_approval_codex"].status, "pass");

        fixture.user(
            1,
            ".codex/config.toml",
            "approval_policy = \"never\"\nsandbox_mode = \"danger-full-access\"\n",
        );
        let check = &fixture.checks()["ai_agent_approval_codex"];
        assert_eq!(check.status, "finding");
        assert_eq!(check.value.as_deref(), Some("never_ask_full_access"));

        fixture.managed(
            "/etc/codex/requirements.toml",
            "allowed_approval_policies = [\"untrusted\", \"on-request\"]\n",
        );
        let check = &fixture.checks()["ai_agent_approval_codex"];
        assert_eq!(check.status, "pass");
        assert!(check.detail.contains("allowed_approval_policies"));
    }

    #[test]
    fn codex_requirements_that_still_allow_never_are_not_a_lock() {
        let fixture = Fixture::new("codex-weak-lock");
        fixture.user(
            0,
            ".codex/config.toml",
            "approval_policy = \"never\"\ndefault_permissions = \":danger-full-access\"\n",
        );
        fixture.managed(
            "/etc/codex/requirements.toml",
            "allowed_approval_policies = [\"on-request\", \"never\"]\n",
        );
        let check = &fixture.checks()["ai_agent_approval_codex"];
        assert_eq!(check.status, "finding");
        assert_eq!(
            check.value.as_deref(),
            Some("never_ask_full_access_profile")
        );
    }

    #[test]
    fn gemini_bare_shell_tool_is_a_finding_and_a_scoped_one_is_not() {
        let fixture = Fixture::new("gemini");
        fixture.user(
            0,
            ".gemini/settings.json",
            r#"{"tools":{"allowed":["run_shell_command(git)"]}}"#,
        );
        assert_eq!(
            fixture.checks()["ai_agent_approval_gemini_cli"].status,
            "pass"
        );
        fixture.user(
            1,
            ".gemini/settings.json",
            r#"{"tools":{"allowed":["run_shell_command"]}}"#,
        );
        assert_eq!(
            fixture.checks()["ai_agent_approval_gemini_cli"].status,
            "finding"
        );
    }

    #[test]
    fn gemini_managed_secure_mode_alone_is_a_managed_pass() {
        let fixture = Fixture::new("gemini-managed");
        fixture.managed(
            "/etc/gemini-cli/settings.json",
            r#"{"admin":{"secureModeEnabled":true}}"#,
        );
        let check = &fixture.checks()["ai_agent_approval_gemini_cli"];
        assert_eq!(check.status, "pass");
        assert_eq!(check.value.as_deref(), Some("managed"));
        fixture.managed(
            "/etc/gemini-cli/settings.json",
            r#"{"admin":{"secureModeEnabled":"true"}}"#,
        );
        assert_eq!(
            fixture.checks()["ai_agent_approval_gemini_cli"]
                .value
                .as_deref(),
            Some("asks"),
            "a string is not the boolean the setting takes"
        );
    }

    #[test]
    fn cursor_cli_unrestricted_and_shell_wildcard_are_findings() {
        let fixture = Fixture::new("cursor");
        fixture.user(
            0,
            ".cursor/cli-config.json",
            r#"{"approvalMode":"allowlist","permissions":{"allow":["Shell(ls)"],"deny":[]}}"#,
        );
        assert_eq!(
            fixture.checks()["ai_agent_approval_cursor_cli"].status,
            "pass"
        );
        fixture.user(
            0,
            ".cursor/cli-config.json",
            r#"{"approvalMode":"unrestricted","permissions":{"allow":["Shell(*)"],"deny":[]}}"#,
        );
        let check = &fixture.checks()["ai_agent_approval_cursor_cli"];
        assert_eq!(check.status, "finding");
        assert_eq!(check.value.as_deref(), Some("unrestricted,allow_all_shell"));
    }

    #[test]
    fn unparseable_or_symlinked_settings_are_unknown_never_pass() {
        let fixture = Fixture::new("unknown");
        fixture.user(0, ".claude/settings.json", "{ not json");
        let check = &fixture.checks()["ai_agent_approval_claude_code"];
        assert_eq!(check.status, "unknown");
        assert_eq!(check.value.as_deref(), Some("not_checked"));
        assert!(check.detail.starts_with("Not checked:"));
        assert!(check.evidence.is_some());

        let target = fixture.root.join("elsewhere.json");
        fs::write(&target, r#"{"permissions":{"defaultMode":"default"}}"#).unwrap();
        fs::create_dir_all(fixture.paths.homes[1].join(".cursor")).unwrap();
        std::os::unix::fs::symlink(
            &target,
            fixture.paths.homes[1].join(".cursor/cli-config.json"),
        )
        .unwrap();
        assert_eq!(
            fixture.checks()["ai_agent_approval_cursor_cli"].status,
            "unknown"
        );
    }

    #[test]
    fn a_finding_outranks_an_unreadable_file_and_hash_tracks_the_observation() {
        let fixture = Fixture::new("ranking");
        fixture.user(0, ".claude/settings.json", "{ not json");
        fixture.user(
            1,
            ".claude/settings.json",
            r#"{"permissions":{"defaultMode":"bypassPermissions"}}"#,
        );
        let first = fixture.checks()["ai_agent_approval_claude_code"]
            .evidence
            .as_ref()
            .unwrap()
            .evidence_hash
            .clone();
        assert_eq!(
            fixture.checks()["ai_agent_approval_claude_code"].status,
            "finding"
        );
        fixture.user(0, ".claude/settings.json", "{}");
        let second = fixture.checks()["ai_agent_approval_claude_code"]
            .evidence
            .as_ref()
            .unwrap()
            .evidence_hash
            .clone();
        assert_ne!(first, second);
    }

    #[test]
    fn bare_bash_and_powershell_allow_rules_are_findings() {
        for rule in ["Bash", "PowerShell", "PowerShell(*)"] {
            let fixture = Fixture::new("claude-bare-shell");
            fixture.user(
                0,
                ".claude/settings.json",
                &format!(r#"{{"permissions":{{"allow":["{rule}"]}}}}"#),
            );
            let check = &fixture.checks()["ai_agent_approval_claude_code"];
            assert_eq!(check.status, "finding", "{rule}");
            assert_eq!(check.value.as_deref(), Some("allow_all_shell"), "{rule}");
        }
    }

    #[test]
    fn claude_managed_rules_only_neutralizes_allow_rules_but_not_bypass() {
        let fixture = Fixture::new("claude-rules-only");
        fixture.user(
            0,
            ".claude/settings.json",
            r#"{"permissions":{"allow":["Bash"]}}"#,
        );
        fixture.managed(
            "/etc/claude-code/managed-settings.json",
            r#"{"allowManagedPermissionRulesOnly":true}"#,
        );
        let check = &fixture.checks()["ai_agent_approval_claude_code"];
        assert_eq!(check.status, "pass");
        assert_eq!(check.value.as_deref(), Some("managed"));
        assert!(check.detail.contains("allowManagedPermissionRulesOnly"));

        fixture.user(
            1,
            ".claude/settings.json",
            r#"{"permissions":{"defaultMode":"bypassPermissions"}}"#,
        );
        let check = &fixture.checks()["ai_agent_approval_claude_code"];
        assert_eq!(check.status, "finding");
        assert_eq!(check.value.as_deref(), Some("bypass_permissions"));
    }

    #[test]
    fn codex_managed_sandbox_lock_neutralizes_only_the_sandbox_mode_rule() {
        let fixture = Fixture::new("codex-sandbox-lock");
        fixture.user(
            0,
            ".codex/config.toml",
            "approval_policy = \"never\"\nsandbox_mode = \"danger-full-access\"\n",
        );
        fixture.managed(
            "/etc/codex/requirements.toml",
            "allowed_sandbox_modes = [\"read-only\", \"workspace-write\"]\n",
        );
        let check = &fixture.checks()["ai_agent_approval_codex"];
        assert_eq!(check.status, "pass");
        assert!(check.detail.contains("allowed_sandbox_modes"));

        fixture.user(
            1,
            ".codex/config.toml",
            "approval_policy = \"never\"\ndefault_permissions = \":danger-full-access\"\n",
        );
        let check = &fixture.checks()["ai_agent_approval_codex"];
        assert_eq!(check.status, "finding");
        assert_eq!(
            check.value.as_deref(),
            Some("never_ask_full_access_profile")
        );
    }

    #[test]
    fn codex_managed_config_is_read_and_its_rules_apply() {
        let fixture = Fixture::new("codex-managed-config");
        fixture.managed(
            "/etc/codex/managed_config.toml",
            "approval_policy = \"never\"\nsandbox_mode = \"danger-full-access\"\n",
        );
        let check = &fixture.checks()["ai_agent_approval_codex"];
        assert_eq!(check.status, "finding");
        assert_eq!(check.value.as_deref(), Some("never_ask_full_access"));

        fixture.managed(
            "/etc/codex/managed_config.toml",
            "approval_policy = \"on-request\"\n",
        );
        let check = &fixture.checks()["ai_agent_approval_codex"];
        assert_eq!(check.status, "pass");
        assert_eq!(check.value.as_deref(), Some("asks"));
    }

    #[test]
    fn gemini_managed_yolo_disabled_is_a_managed_pass() {
        let fixture = Fixture::new("gemini-yolo-lock");
        fixture.user(
            0,
            ".gemini/settings.json",
            r#"{"tools":{"allowed":["run_shell_command(git)"]}}"#,
        );
        fixture.managed(
            "/etc/gemini-cli/settings.json",
            r#"{"security":{"disableYoloMode":true}}"#,
        );
        let check = &fixture.checks()["ai_agent_approval_gemini_cli"];
        assert_eq!(check.status, "pass");
        assert_eq!(check.value.as_deref(), Some("managed"));
        assert!(check.detail.contains("disableYoloMode"));
    }
}
