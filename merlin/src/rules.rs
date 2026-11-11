//! YAML rules engine.
//!
//! A rule may carry `match:` (OR semantics: at least one listed selector
//! must match), `match_all:` (AND semantics: every listed selector must
//! match), or both — in which case the rule fires when all of `match_all`
//! holds AND at least one `match` selector matches. A `not:` block
//! suppresses the rule when ANY of its selectors matches; it is evaluated
//! first (order: not → match_all → match). `uid` is a constraint (AND) in
//! `match`/`match_all`; inside `not` every field acts as a plain selector.
//! A rule with only a `uid` fires on uid alone. This gives hash-primary,
//! basename-fallback semantics for `block` rules naturally: list both in
//! `match` and either one triggers the deny.
//!
//! `dns_contains` and `dns_suffix` match the queried name of a `dns` event
//! (ASCII case-insensitive, like DNS itself); no other event carries a
//! name, so they never match exec, file or fanotify decisions.
//!
//! `agent` and `has_agent` match the AI agent an event is attributed to
//! (agent_session.rs: the event's process or its nearest ancestor runs under
//! a declared agent name); `credential` and `has_credential` match the
//! declared credential file an `open` file event touched. They take only
//! `true`: evidence a decision point lacks (the fanotify exec decision has no
//! lineage) must never read as "no agent".
//! `path_contains` is a substring of the path (a file event's file, an
//! exec's executable).

use std::path::Path;
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Additional DoH resolver addresses for `doh_suspect` tagging on
    /// connect events (additive to the built-in list in telemetry.rs).
    #[serde(default)]
    pub doh_resolvers: Vec<String>,
}

/// A hot-swappable ruleset. Producers take a cheap snapshot (an Arc clone)
/// per event; the sync client swaps the set when a verified ruleset
/// arrives. Read-heavy, write-once-a-minute: a plain RwLock is fine.
#[derive(Clone)]
pub struct RulesHandle {
    inner: Arc<RwLock<Arc<Rules>>>,
}

impl RulesHandle {
    pub fn new(rules: Rules) -> Self {
        RulesHandle {
            inner: Arc::new(RwLock::new(Arc::new(rules))),
        }
    }

    pub fn get(&self) -> Arc<Rules> {
        self.inner.read().unwrap().clone()
    }

    pub fn set(&self, rules: Rules) {
        *self.inner.write().unwrap() = Arc::new(rules);
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    #[serde(rename = "match", default)]
    pub match_: Match,
    #[serde(default)]
    pub match_all: Option<Match>,
    #[serde(default)]
    pub not: Option<Match>,
    pub action: Action,
    /// Free-form documentation for the pack author; not used by the engine.
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub approved_alternative: Option<ApprovedAlternative>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedAlternative {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Match {
    pub sha256: Option<String>,
    pub path_basename: Option<String>,
    pub path_prefix: Option<String>,
    pub cmdline_contains: Option<String>,
    /// Exact match on the kernel comm (the exec'd name, max 15 chars).
    /// Unlike path_basename this follows the name the program was invoked
    /// as: /bin/sh execs have comm "sh" even though the exe is dash.
    pub comm: Option<String>,
    /// Exact basename of the parent process's exe (or comm as fallback).
    pub parent_basename: Option<String>,
    /// Substring match against any ancestor's comm (nearest-first chain).
    pub ancestor_comm_contains: Option<String>,
    /// Substring of a `dns` event's queried name (parity with macOS).
    pub dns_contains: Option<String>,
    /// A domain and its subdomains, matched at a label boundary:
    /// `openrouter.ai` matches `openrouter.ai` and `x.openrouter.ai`, never
    /// `notopenrouter.ai`; a leading dot (`.openai.azure.com`) matches
    /// subdomains only.
    pub dns_suffix: Option<String>,
    /// Substring of the path (`path_prefix`'s path).
    pub path_contains: Option<String>,
    /// The client of the AI agent the event is attributed to, exactly.
    pub agent: Option<String>,
    /// Whether the event is attributed to any AI agent.
    pub has_agent: Option<bool>,
    /// The declared name of the credential file an `open` touched, exactly.
    pub credential: Option<String>,
    /// Whether the event is an open of any declared credential file.
    pub has_credential: Option<bool>,
    pub uid: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Log,
    Kill,
    Block,
}

/// Evidence available at a decision point. Fields that cannot be obtained
/// (e.g. sha256 on a racy /proc read, lineage on a fanotify decision) are
/// simply absent — a selector with absent evidence never matches, which is
/// the fail-safe direction.
#[derive(Debug, Default, Clone, Copy)]
pub struct MatchCtx<'a> {
    pub sha256: Option<&'a str>,
    pub basename: Option<&'a str>,
    /// Full executable path (readlink of /proc/<pid>/exe, else the
    /// tracepoint filename) — what `path_prefix` matches against. For
    /// `file` events this is the touched file's path.
    pub path: Option<&'a str>,
    pub cmdline: Option<&'a str>,
    pub uid: Option<u32>,
    /// Kernel comm of the event's process (exec/file events).
    pub comm: Option<&'a str>,
    /// Basename of the parent process's exe (comm fallback), from the
    /// proctree cache.
    pub parent_basename: Option<&'a str>,
    /// Ancestor comms, nearest parent first, from the proctree cache.
    pub ancestors: &'a [String],
    /// The queried name of a `dns` event; absent for every other kind.
    pub dns: Option<&'a str>,
    /// The client of the AI agent the event is attributed to.
    pub agent: Option<&'a str>,
    /// The declared credential file a file `open` touched.
    pub credential: Option<&'a str>,
}

/// ASCII case-insensitive substring test. An empty needle never matches
/// (`Rules::parse` rejects one; this keeps the engine fail-safe anyway).
fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    !needle.is_empty()
        && haystack
            .as_bytes()
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

/// ASCII case-insensitive domain-suffix test at a label boundary: the name
/// equals `suffix`, the suffix starts with a dot, or the byte before it in
/// the name is a dot. An empty suffix never matches.
fn ends_with_domain(name: &str, suffix: &str) -> bool {
    let (name, suffix) = (name.as_bytes(), suffix.as_bytes());
    let Some(start) = name.len().checked_sub(suffix.len()) else {
        return false;
    };
    !suffix.is_empty()
        && name[start..].eq_ignore_ascii_case(suffix)
        && (start == 0 || suffix[0] == b'.' || name[start - 1] == b'.')
}

impl Match {
    fn has_selectors(&self) -> bool {
        self.sha256.is_some()
            || self.path_basename.is_some()
            || self.path_prefix.is_some()
            || self.cmdline_contains.is_some()
            || self.comm.is_some()
            || self.parent_basename.is_some()
            || self.ancestor_comm_contains.is_some()
            || self.dns_contains.is_some()
            || self.dns_suffix.is_some()
            || self.path_contains.is_some()
            || self.agent.is_some()
            || self.has_agent.is_some()
            || self.credential.is_some()
            || self.has_credential.is_some()
    }

    fn uid_ok(&self, ctx: &MatchCtx) -> bool {
        self.uid.is_none_or(|want| ctx.uid == Some(want))
    }

    fn uid_hit(&self, ctx: &MatchCtx) -> bool {
        self.uid.is_some_and(|want| ctx.uid == Some(want))
    }

    fn sha256_hit(&self, ctx: &MatchCtx) -> bool {
        self.sha256
            .as_deref()
            .is_some_and(|h| Some(h) == ctx.sha256)
    }

    fn basename_hit(&self, ctx: &MatchCtx) -> bool {
        self.path_basename
            .as_deref()
            .is_some_and(|b| Some(b) == ctx.basename)
    }

    fn prefix_hit(&self, ctx: &MatchCtx) -> bool {
        self.path_prefix
            .as_deref()
            .is_some_and(|p| ctx.path.is_some_and(|s| s.starts_with(p)))
    }

    fn cmdline_hit(&self, ctx: &MatchCtx) -> bool {
        self.cmdline_contains
            .as_deref()
            .is_some_and(|c| ctx.cmdline.is_some_and(|s| s.contains(c)))
    }

    fn comm_hit(&self, ctx: &MatchCtx) -> bool {
        self.comm.as_deref().is_some_and(|c| Some(c) == ctx.comm)
    }

    fn parent_hit(&self, ctx: &MatchCtx) -> bool {
        self.parent_basename
            .as_deref()
            .is_some_and(|b| Some(b) == ctx.parent_basename)
    }

    fn ancestor_hit(&self, ctx: &MatchCtx) -> bool {
        self.ancestor_comm_contains
            .as_deref()
            .is_some_and(|sub| ctx.ancestors.iter().any(|c| c.contains(sub)))
    }

    fn dns_contains_hit(&self, ctx: &MatchCtx) -> bool {
        self.dns_contains
            .as_deref()
            .is_some_and(|c| ctx.dns.is_some_and(|q| contains_ignore_ascii_case(q, c)))
    }

    fn dns_suffix_hit(&self, ctx: &MatchCtx) -> bool {
        self.dns_suffix
            .as_deref()
            .is_some_and(|s| ctx.dns.is_some_and(|q| ends_with_domain(q, s)))
    }

    fn path_contains_hit(&self, ctx: &MatchCtx) -> bool {
        self.path_contains
            .as_deref()
            .is_some_and(|c| ctx.path.is_some_and(|p| !c.is_empty() && p.contains(c)))
    }

    fn agent_hit(&self, ctx: &MatchCtx) -> bool {
        self.agent.as_deref().is_some_and(|a| Some(a) == ctx.agent)
    }

    fn has_agent_hit(&self, ctx: &MatchCtx) -> bool {
        self.has_agent == Some(true) && ctx.agent.is_some()
    }

    fn credential_hit(&self, ctx: &MatchCtx) -> bool {
        self.credential
            .as_deref()
            .is_some_and(|c| Some(c) == ctx.credential)
    }

    fn has_credential_hit(&self, ctx: &MatchCtx) -> bool {
        self.has_credential == Some(true) && ctx.credential.is_some()
    }

    /// OR semantics (`match:`): at least one listed selector must hit.
    fn any_hit(&self, ctx: &MatchCtx) -> bool {
        self.sha256_hit(ctx)
            || self.basename_hit(ctx)
            || self.prefix_hit(ctx)
            || self.cmdline_hit(ctx)
            || self.comm_hit(ctx)
            || self.parent_hit(ctx)
            || self.ancestor_hit(ctx)
            || self.dns_contains_hit(ctx)
            || self.dns_suffix_hit(ctx)
            || self.path_contains_hit(ctx)
            || self.agent_hit(ctx)
            || self.has_agent_hit(ctx)
            || self.credential_hit(ctx)
            || self.has_credential_hit(ctx)
    }

    /// AND semantics (`match_all:`): every listed selector must hit.
    fn all_hit(&self, ctx: &MatchCtx) -> bool {
        if self.sha256.is_some() && !self.sha256_hit(ctx) {
            return false;
        }
        if self.path_basename.is_some() && !self.basename_hit(ctx) {
            return false;
        }
        if self.path_prefix.is_some() && !self.prefix_hit(ctx) {
            return false;
        }
        if self.cmdline_contains.is_some() && !self.cmdline_hit(ctx) {
            return false;
        }
        if self.comm.is_some() && !self.comm_hit(ctx) {
            return false;
        }
        if self.parent_basename.is_some() && !self.parent_hit(ctx) {
            return false;
        }
        if self.ancestor_comm_contains.is_some() && !self.ancestor_hit(ctx) {
            return false;
        }
        if self.dns_contains.is_some() && !self.dns_contains_hit(ctx) {
            return false;
        }
        if self.dns_suffix.is_some() && !self.dns_suffix_hit(ctx) {
            return false;
        }
        if self.path_contains.is_some() && !self.path_contains_hit(ctx) {
            return false;
        }
        if self.agent.is_some() && !self.agent_hit(ctx) {
            return false;
        }
        if self.has_agent.is_some() && !self.has_agent_hit(ctx) {
            return false;
        }
        if self.credential.is_some() && !self.credential_hit(ctx) {
            return false;
        }
        if self.has_credential.is_some() && !self.has_credential_hit(ctx) {
            return false;
        }
        true
    }

    /// `not:` semantics: any listed field (uid included) matching
    /// suppresses the rule.
    fn suppresses(&self, ctx: &MatchCtx) -> bool {
        self.uid_hit(ctx) || self.any_hit(ctx)
    }
}

impl Rule {
    pub fn matches(&self, ctx: &MatchCtx) -> bool {
        if let Some(not) = &self.not {
            if not.suppresses(ctx) {
                return false;
            }
        }
        if !self.match_.uid_ok(ctx) {
            return false;
        }
        if let Some(all) = &self.match_all {
            if !all.uid_ok(ctx) || !all.all_hit(ctx) {
                return false;
            }
        }
        if self.match_.has_selectors() {
            return self.match_.any_hit(ctx);
        }
        // No OR selectors: fire on uid-only rules (unchanged legacy
        // behavior), or when a non-empty match_all carried the rule.
        self.match_.uid.is_some()
            || self
                .match_all
                .as_ref()
                .is_some_and(|all| all.has_selectors() || all.uid.is_some())
    }

    /// Does this rule name `dns_contains` or `dns_suffix` in `match` or
    /// `match_all`? Only such rules apply to `dns` events, so a plain
    /// program rule never tags every lookup that program makes.
    pub fn has_dns_selector(&self) -> bool {
        [Some(&self.match_), self.match_all.as_ref()]
            .into_iter()
            .flatten()
            .any(|m| m.dns_contains.is_some() || m.dns_suffix.is_some())
    }

    pub fn has_sha256_selector(&self) -> bool {
        self.match_.sha256.is_some()
            || self
                .match_all
                .as_ref()
                .is_some_and(|all| all.sha256.is_some())
    }

    /// Would this rule fire if its `sha256` selector were satisfied? The
    /// enforcement path uses this when the hash could not be computed: a
    /// missing hash is attacker-controllable (pad the binary past the
    /// synchronous limit), so an unresolved hash selector must not read as
    /// a clean miss.
    pub fn matches_with_unresolved_sha256(&self, ctx: &MatchCtx) -> bool {
        if !self.has_sha256_selector() {
            return false;
        }
        // A rule may name a hash in either block (or a different one in
        // each): try every candidate, since any of them could have been
        // the real hash of the file that could not be read.
        [
            self.match_.sha256.as_deref(),
            self.match_all
                .as_ref()
                .and_then(|all| all.sha256.as_deref()),
        ]
        .into_iter()
        .flatten()
        .any(|assumed| {
            self.matches(&MatchCtx {
                sha256: Some(assumed),
                ..*ctx
            })
        })
    }
}

impl Rules {
    const MAX_SOURCE_BYTES: u64 = 1 << 20;

    pub fn parse(text: &str) -> Result<Self> {
        let rules: Rules = serde_yaml::from_str(text).context("parsing rules YAML")?;
        anyhow::ensure!(
            rules.schema_version <= 1,
            "unsupported policy schema_version {}",
            rules.schema_version
        );
        for rule in &rules.rules {
            if let Some(alternative) = &rule.approved_alternative {
                let authority = alternative
                    .url
                    .strip_prefix("https://")
                    .and_then(|rest| rest.split('/').next());
                anyhow::ensure!(
                    rule.action != Action::Log
                        && !alternative.name.is_empty()
                        && alternative.name.trim() == alternative.name
                        && alternative.name.len() <= 80
                        && !alternative.name.chars().any(char::is_control)
                        && alternative.url.len() <= 2048
                        && !alternative.url.contains('?')
                        && !alternative.url.contains('#')
                        && !alternative.url.contains('\\')
                        && !alternative.url.chars().any(char::is_control)
                        && authority.is_some_and(|host| !host.is_empty() && !host.contains('@')),
                    "rule '{}': invalid approved_alternative",
                    rule.name
                );
            }
            for block in [
                Some(&rule.match_),
                rule.match_all.as_ref(),
                rule.not.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                for (key, value) in [
                    ("dns_contains", &block.dns_contains),
                    ("dns_suffix", &block.dns_suffix),
                    ("path_contains", &block.path_contains),
                    ("agent", &block.agent),
                    ("credential", &block.credential),
                ] {
                    if value.as_deref().is_some_and(|v| v.trim().is_empty()) {
                        bail!("rule '{}': {} must not be empty", rule.name, key);
                    }
                }
                for (key, value) in [
                    ("has_agent", block.has_agent),
                    ("has_credential", block.has_credential),
                ] {
                    if value == Some(false) {
                        bail!(
                            "rule '{}': {} takes only true (a decision point that lacks the evidence must not read as its absence)",
                            rule.name,
                            key
                        );
                    }
                }
            }
            for (key, block) in [("match_all", &rule.match_all), ("not", &rule.not)] {
                if let Some(m) = block {
                    if !m.has_selectors() && m.uid.is_none() {
                        bail!(
                            "rule '{}': {} must list at least one selector or uid",
                            rule.name,
                            key
                        );
                    }
                }
            }
        }
        Ok(rules)
    }

    #[cfg(test)]
    pub fn load(path: &Path) -> Result<Self> {
        Self::load_with_source(path).map(|(rules, _)| rules)
    }

    pub fn load_with_source(path: &Path) -> Result<(Self, Vec<u8>)> {
        // The daemon runs as root and the rules path may be user-controlled:
        // never follow a symlink into an attacker-chosen file. O_NOFOLLOW
        // makes open(2) fail with ELOOP; fstat then proves a regular file
        // (fifos/devices are rejected too). Group/other-writable only warns
        // — dev machines are full of 0644 dotfiles.
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .with_context(|| format!("opening rules {} (symlinks are rejected)", path.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("statting rules {}", path.display()))?;
        if !metadata.is_file() {
            anyhow::bail!("rules {} is not a regular file", path.display());
        }
        if metadata.mode() & 0o022 != 0 {
            log::warn!("rules {} is group/other writable", path.display());
        }
        if metadata.len() > Self::MAX_SOURCE_BYTES {
            anyhow::bail!("rules {} exceeds the 1 MiB limit", path.display());
        }
        let mut source = Vec::new();
        file.take(Self::MAX_SOURCE_BYTES + 1)
            .read_to_end(&mut source)
            .with_context(|| format!("reading {}", path.display()))?;
        if source.len() as u64 > Self::MAX_SOURCE_BYTES {
            anyhow::bail!("rules {} exceeds the 1 MiB limit", path.display());
        }
        let text = std::str::from_utf8(&source)
            .with_context(|| format!("rules {} is not UTF-8", path.display()))?;
        let rules = Self::parse(text).with_context(|| format!("parsing {}", path.display()))?;
        Ok((rules, source))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approved_alternative_is_bounded_and_requires_enforcement() {
        let base = "rules:\n  - name: block-cursor\n    match:\n      path_basename: Cursor\n    action: block\n    approved_alternative:\n      name: Approved editor\n      url: https://tools.example.com/editor\n";
        let parsed = Rules::parse(base).unwrap();
        assert_eq!(
            parsed.rules[0].approved_alternative.as_ref().unwrap().name,
            "Approved editor"
        );
        assert!(Rules::parse(&base.replace("action: block", "action: log")).is_err());
        assert!(
            Rules::parse(&base.replace(
                "https://tools.example.com/editor",
                "http://tools.example.com/editor"
            ))
            .is_err()
        );
    }

    fn rule(yaml: &str) -> Rule {
        serde_yaml::from_str(yaml).unwrap()
    }

    fn lookup(name: &str) -> MatchCtx<'_> {
        MatchCtx {
            dns: Some(name),
            ..Default::default()
        }
    }

    #[test]
    fn dns_suffix_matches_the_end_of_the_queried_name_only() {
        let r = rule("name: t\nmatch:\n  dns_suffix: .openai.azure.com\naction: log\n");
        assert!(r.matches(&lookup("contoso.openai.azure.com")));
        assert!(r.matches(&lookup("Contoso.OpenAI.Azure.COM")));
        // Near-misses: the suffix appears but is not the end, or the
        // name lacks the leading label boundary.
        assert!(!r.matches(&lookup("contoso.openai.azure.com.evil.example")));
        assert!(!r.matches(&lookup("openai.azure.com")));
        assert!(!r.matches(&lookup("notopenai.azure.com")));
        // Without a leading dot: the domain itself and its subdomains, cut
        // at a label boundary.
        let apex = rule("name: t\nmatch:\n  dns_suffix: openrouter.ai\naction: log\n");
        assert!(apex.matches(&lookup("openrouter.ai")));
        assert!(apex.matches(&lookup("eu.OpenRouter.ai")));
        assert!(!apex.matches(&lookup("notopenrouter.ai")));
        assert!(!apex.matches(&lookup("openrouter.ai.example.net")));
        assert!(!apex.matches(&lookup("ai")));
        // Events with no queried name (exec, file, fanotify) never match.
        assert!(!r.matches(&MatchCtx {
            basename: Some("contoso.openai.azure.com"),
            ..Default::default()
        }));
    }

    #[test]
    fn dns_contains_is_a_case_insensitive_substring_like_macos() {
        let r = rule("name: t\nmatch:\n  dns_contains: Bedrock-Runtime\naction: log\n");
        assert!(r.matches(&lookup("bedrock-runtime.us-east-1.amazonaws.com")));
        assert!(!r.matches(&lookup("bedrock.us-east-1.amazonaws.com")));
        assert!(!r.matches(&MatchCtx::default()));
    }

    #[test]
    fn dns_selectors_and_together_in_match_all() {
        let r = rule(
            "name: t\nmatch_all:\n  dns_contains: bedrock-runtime\n  dns_suffix: .amazonaws.com\naction: log\n",
        );
        assert!(r.matches(&lookup("bedrock-runtime.eu-west-1.amazonaws.com")));
        assert!(r.matches(&lookup("bedrock-runtime-fips.us-east-1.amazonaws.com")));
        assert!(!r.matches(&lookup("bedrock-runtime.evil.example")));
        assert!(!r.matches(&lookup("s3.us-east-1.amazonaws.com")));
    }

    #[test]
    fn empty_dns_selectors_are_rejected_at_load() {
        for key in ["dns_contains", "dns_suffix"] {
            for block in ["match", "match_all", "not"] {
                let yaml = format!(
                    "rules:\n  - name: t\n    {block}:\n      {key}: \" \"\n    action: log\n"
                );
                assert!(Rules::parse(&yaml).is_err(), "{block}.{key}");
            }
        }
    }

    #[test]
    fn sha256_or_basename_block() {
        let r = rule("name: t\nmatch:\n  sha256: abc\n  path_basename: evil\naction: block\n");
        assert!(r.matches(&MatchCtx {
            sha256: Some("abc"),
            ..Default::default()
        }));
        assert!(r.matches(&MatchCtx {
            basename: Some("evil"),
            ..Default::default()
        }));
        assert!(!r.matches(&MatchCtx {
            basename: Some("good"),
            sha256: Some("def"),
            ..Default::default()
        }));
    }

    #[test]
    fn uid_constrains_selectors() {
        let r = rule("name: t\nmatch:\n  path_basename: sh\n  uid: 0\naction: kill\n");
        assert!(r.matches(&MatchCtx {
            basename: Some("sh"),
            uid: Some(0),
            ..Default::default()
        }));
        assert!(!r.matches(&MatchCtx {
            basename: Some("sh"),
            uid: Some(1000),
            ..Default::default()
        }));
    }

    #[test]
    fn cmdline_contains() {
        let r = rule("name: t\nmatch:\n  cmdline_contains: --evil-flag\naction: log\n");
        assert!(r.matches(&MatchCtx {
            cmdline: Some("/bin/tool --evil-flag -x"),
            ..Default::default()
        }));
        assert!(!r.matches(&MatchCtx {
            cmdline: Some("/bin/tool -x"),
            ..Default::default()
        }));
    }

    #[test]
    fn path_prefix_matches_full_path() {
        let r = rule("name: t\nmatch:\n  path_prefix: /tmp/\naction: log\n");
        assert!(r.matches(&MatchCtx {
            path: Some("/tmp/evil"),
            ..Default::default()
        }));
        assert!(!r.matches(&MatchCtx {
            path: Some("/usr/bin/tmp-tool"),
            ..Default::default()
        }));
        // No path evidence (racy /proc) → no match.
        assert!(!r.matches(&MatchCtx::default()));
    }

    #[test]
    fn match_all_requires_every_selector() {
        let r = rule(
            "name: t\nmatch_all:\n  path_basename: crontab\n  cmdline_contains: \"-e\"\naction: log\n",
        );
        let crontab = |cmdline: &'static str| MatchCtx {
            basename: Some("crontab"),
            path: Some("/usr/bin/crontab"),
            cmdline: Some(cmdline),
            ..Default::default()
        };
        assert!(r.matches(&crontab("crontab -e")));
        assert!(!r.matches(&crontab("crontab -l"))); // selector missing
        // Right cmdline, wrong binary:
        assert!(!r.matches(&MatchCtx {
            basename: Some("vi"),
            path: Some("/usr/bin/vi"),
            cmdline: Some("vi -e"),
            ..Default::default()
        }));
    }

    #[test]
    fn match_and_match_all_combine() {
        // uid constraint in match + OR selector in match + AND block.
        let r = rule(
            "name: t\nmatch:\n  cmdline_contains: \"| sh\"\n  uid: 0\nmatch_all:\n  path_basename: bash\naction: log\n",
        );
        let ctx = |cmdline: &'static str, uid: u32| MatchCtx {
            basename: Some("bash"),
            path: Some("/usr/bin/bash"),
            cmdline: Some(cmdline),
            uid: Some(uid),
            ..Default::default()
        };
        assert!(r.matches(&ctx("bash -c curl x | sh", 0)));
        assert!(!r.matches(&ctx("bash -c curl x | sh", 1000))); // uid constraint
        assert!(!r.matches(&ctx("bash -c echo hi", 0))); // OR selector missing
        // match_all fails even when the OR selector hits:
        let not_bash = MatchCtx {
            basename: Some("zsh"),
            path: Some("/usr/bin/zsh"),
            cmdline: Some("zsh -c curl x | sh"),
            uid: Some(0),
            ..Default::default()
        };
        assert!(!r.matches(&not_bash));
    }

    #[test]
    fn unresolved_hash_keeps_other_selectors_honest() {
        let hash_only = rule("name: t\nmatch:\n  sha256: abc\naction: block\n");
        assert!(hash_only.matches_with_unresolved_sha256(&MatchCtx::default()));
        // A rule without a hash selector is unaffected by a missing hash.
        let no_hash = rule("name: t\nmatch:\n  path_basename: evil\naction: block\n");
        assert!(!no_hash.matches_with_unresolved_sha256(&MatchCtx {
            basename: Some("evil"),
            ..Default::default()
        }));
        // Constraints outside the hash still have to hold.
        let constrained =
            rule("name: t\nmatch_all:\n  sha256: abc\n  path_prefix: /tmp/\naction: block\n");
        assert!(constrained.matches_with_unresolved_sha256(&MatchCtx {
            path: Some("/tmp/evil"),
            ..Default::default()
        }));
        assert!(!constrained.matches_with_unresolved_sha256(&MatchCtx {
            path: Some("/usr/bin/ls"),
            ..Default::default()
        }));
    }

    #[test]
    fn empty_match_all_rejected() {
        let err = Rules::parse("rules:\n  - name: bad\n    match_all: {}\n    action: log\n")
            .unwrap_err();
        assert!(err.to_string().contains("match_all"), "{err}");
    }

    #[test]
    fn unknown_keys_rejected() {
        assert!(
            Rules::parse(
                "rules:\n  - name: bad\n    match:\n      bogus_key: 1\n    action: log\n",
            )
            .is_err()
        );
        assert!(
            Rules::parse(
                "rules:\n  - name: bad\n    match_all:\n      bogus_key: 1\n    action: log\n",
            )
            .is_err()
        );
    }

    #[test]
    fn existing_packs_unchanged() {
        // Backward compat: every shipped pack loads and keeps OR semantics.
        let demo = Rules::load(Path::new("../rules/block-demo.yaml")).unwrap();
        let block = demo
            .rules
            .iter()
            .find(|r| r.name == "block-merlin-evil")
            .unwrap();
        // OR: basename alone (hash unavailable) still triggers the block.
        assert!(block.matches(&MatchCtx {
            basename: Some("merlin-evil"),
            ..Default::default()
        }));
        let pack = Rules::load(Path::new("../rules/content/linux-lolbins.yaml")).unwrap();
        let crontab = pack
            .rules
            .iter()
            .find(|r| r.name == "lolbin-crontab-edit")
            .unwrap();
        let crontab_ctx = |cmdline: &'static str| MatchCtx {
            basename: Some("crontab"),
            path: Some("/usr/bin/crontab"),
            cmdline: Some(cmdline),
            uid: Some(1000),
            ..Default::default()
        };
        assert!(!crontab.matches(&crontab_ctx("crontab -l")));
        assert!(crontab.matches(&crontab_ctx("crontab -e")));
    }

    /// Every local model server rule in the Sigma pack fires when its server
    /// starts, and not on the same program's client commands.
    #[test]
    fn local_model_server_pack_rules_fire_on_server_starts_only() {
        let pack = Rules::load(Path::new("../packs/sigma-linux.yaml")).unwrap();
        let local: Vec<&Rule> = pack
            .rules
            .iter()
            .filter(|r| r.name.starts_with("sigma-local-model-server-"))
            .collect();
        // (rule, exe path, command line that starts the server, a near-miss
        // command line by the same program)
        let cases = [
            (
                "sigma-local-model-server-ollama",
                "/usr/bin/ollama",
                "/usr/bin/ollama serve",
                "/usr/bin/ollama list",
            ),
            (
                "sigma-local-model-server-llama-cpp-server",
                "/usr/local/bin/llama-server",
                "llama-server -m model.gguf",
                "",
            ),
            (
                "sigma-local-model-server-localai",
                "/usr/local/bin/local-ai",
                "local-ai run",
                "",
            ),
            (
                "sigma-local-model-server-vllm",
                "/home/u/.venv/bin/vllm",
                "/home/u/.venv/bin/vllm serve Qwen/Qwen3-8B",
                "/home/u/.venv/bin/vllm --version",
            ),
            (
                "sigma-local-model-server-vllm-2",
                "/usr/bin/python3",
                "python3 -m vllm.entrypoints.openai.api_server --model m",
                "python3 -m pip install vllm",
            ),
            (
                "sigma-local-model-server-lm-studio",
                "/home/u/.lmstudio/bin/lms",
                "lms server start",
                "lms ls",
            ),
        ];
        let rules: std::collections::BTreeSet<&str> =
            local.iter().map(|r| r.name.as_str()).collect();
        let covered: std::collections::BTreeSet<&str> = cases.iter().map(|c| c.0).collect();
        assert_eq!(rules, covered, "every local model server rule needs a case");
        let hits = |exe: &str, cmdline: &str| -> Vec<String> {
            let ctx = MatchCtx {
                basename: exe.rsplit('/').next(),
                path: Some(exe),
                cmdline: Some(cmdline),
                ..Default::default()
            };
            local
                .iter()
                .filter(|r| r.matches(&ctx))
                .map(|r| r.name.clone())
                .collect()
        };
        for (rule, exe, start, near_miss) in cases {
            assert_eq!(hits(exe, start), vec![rule.to_string()], "{start}");
            // Basename-only rules have no command-line near-miss ("").
            if !near_miss.is_empty() {
                assert!(hits(exe, near_miss).is_empty(), "{near_miss}");
            }
            // A program with a similar name is not the server (for rules that
            // select the program by name; the vLLM module rule runs under any
            // Python).
            let by_name = local.iter().any(|r| {
                r.name == rule
                    && [Some(&r.match_), r.match_all.as_ref()]
                        .into_iter()
                        .flatten()
                        .any(|m| m.path_basename.is_some())
            });
            if by_name {
                assert!(
                    hits(&format!("{exe}-helper"), start).is_empty(),
                    "{exe}-helper"
                );
            }
        }
        assert!(local.iter().all(|r| r.action == Action::Log));
    }

    #[test]
    fn agent_and_credential_selectors_need_the_evidence_and_take_only_true() {
        let exact = rule(
            "name: r\nmatch_all:\n  agent: codex\n  path_contains: /.config/systemd/user/\naction: log\n",
        );
        let unit = "/home/u/.config/systemd/user/x.service";
        let ctx = |agent| MatchCtx {
            path: Some(unit),
            agent,
            ..Default::default()
        };
        assert!(exact.matches(&ctx(Some("codex"))));
        assert!(!exact.matches(&ctx(Some("claude"))));
        assert!(!exact.matches(&ctx(None)));
        let any = rule("name: r\nmatch:\n  has_credential: true\naction: log\n");
        assert!(any.matches(&MatchCtx {
            credential: Some("aws"),
            ..Default::default()
        }));
        assert!(!any.matches(&MatchCtx::default()));
        // `false` would read a decision point's missing evidence as absence.
        for key in ["has_agent", "has_credential"] {
            let text =
                format!("rules:\n  - name: r\n    match:\n      {key}: false\n    action: log\n");
            assert!(Rules::parse(&text).is_err(), "{key}: false");
        }
        for key in ["agent", "credential", "path_contains"] {
            let text =
                format!("rules:\n  - name: r\n    match:\n      {key}: \" \"\n    action: log\n");
            assert!(Rules::parse(&text).is_err(), "empty {key}");
        }
    }

    /// Every AI agent rule in the Sigma pack fires on a sample event under an
    /// agent and on none of the near misses: the same event outside any
    /// agent, or a similar command or file under one.
    #[test]
    fn ai_agent_pack_rules_fire_on_agent_samples_and_not_near_misses() {
        let pack = Rules::load(Path::new("../packs/sigma-linux.yaml")).unwrap();
        let agent_rules: Vec<&Rule> = pack
            .rules
            .iter()
            .filter(|r| r.name.starts_with("sigma-ai-agent-"))
            .collect();
        assert!(!agent_rules.is_empty());
        assert!(agent_rules.iter().all(|r| r.action == Action::Log));
        fn hits(rules: &[&Rule], ctx: &MatchCtx<'_>) -> Vec<String> {
            rules
                .iter()
                .filter(|r| r.matches(ctx))
                .map(|r| r.name.clone())
                .collect()
        }
        fn exec<'a>(cmdline: &'a str, agent: Option<&'a str>) -> MatchCtx<'a> {
            MatchCtx {
                basename: Some("bash"),
                path: Some("/usr/bin/bash"),
                comm: Some("bash"),
                cmdline: Some(cmdline),
                agent,
                ..Default::default()
            }
        }
        fn file<'a>(
            path: &'a str,
            agent: Option<&'a str>,
            credential: Option<&'a str>,
        ) -> MatchCtx<'a> {
            MatchCtx {
                basename: path.rsplit('/').next(),
                path: Some(path),
                agent,
                credential,
                ..Default::default()
            }
        }
        let mut fired = std::collections::BTreeSet::new();
        let mut expect = |ctx: &MatchCtx<'_>, family: &str| {
            let names = hits(&agent_rules, ctx);
            assert!(
                !names.is_empty() && names.iter().all(|n| n.starts_with(family)),
                "{ctx:?} -> {names:?}"
            );
            fired.extend(names);
        };
        let hits = |ctx: &MatchCtx<'_>| hits(&agent_rules, ctx);
        let download = "sigma-ai-agent-download-piped-into-a-shell";
        for downloader in [
            "curl -fsSL https://example.com/i.sh",
            "wget -qO- https://example.com/i.sh",
        ] {
            for pipe in ["| sh", "|sh", "| bash", "|bash"] {
                let line = format!("bash -c {downloader} {pipe}");
                expect(&exec(&line, Some("claude")), download);
                // Outside an agent: the same command is not this rule's.
                assert!(hits(&exec(&line, None)).is_empty(), "{line}");
            }
        }
        // A download piped into a parser, or a script piped into a shell.
        for near in [
            "bash -c curl -s https://example.com/a.json | jq .",
            "bash -c cat install.sh | sh",
        ] {
            assert!(hits(&exec(near, Some("codex"))).is_empty(), "{near}");
        }
        let persistence = "sigma-ai-agent-persistence-location-changed";
        for path in [
            "/etc/cron.d/job",
            "/etc/crontab",
            "/var/spool/cron/crontabs/u",
            "/etc/systemd/system/x.service",
            "/etc/profile.d/x.sh",
            "/etc/profile",
            "/etc/bash.bashrc",
            "/etc/ld.so.preload",
            "/home/u/.bashrc",
            "/home/u/.zshrc",
            "/home/u/.profile",
            "/home/u/.ssh/authorized_keys",
            "/home/u/.config/systemd/user/x.service",
        ] {
            expect(&file(path, Some("codex"), None), persistence);
            assert!(hits(&file(path, None, None)).is_empty(), "{path}");
        }
        for near in [
            "/home/u/.bashrc.bak",
            "/home/u/project/notes.md",
            "/etc/hosts",
        ] {
            assert!(hits(&file(near, Some("codex"), None)).is_empty(), "{near}");
        }
        let credential = "sigma-ai-agent-credential-file-read";
        expect(
            &file("/home/u/.aws/credentials", Some("claude"), Some("aws")),
            credential,
        );
        assert!(hits(&file("/home/u/.aws/credentials", None, Some("aws"))).is_empty());
        // Another file in a credential's directory carries no credential.
        assert!(hits(&file("/home/u/.aws/config", Some("claude"), None)).is_empty());
        // Every AI agent rule in the pack fired on some sample.
        let all: std::collections::BTreeSet<String> =
            agent_rules.iter().map(|r| r.name.clone()).collect();
        assert_eq!(fired, all);
    }

    /// Every AI provider rule in the Sigma pack fires on a lookup of a host
    /// its provider's API reference names, and on none of the near-misses.
    #[test]
    fn ai_api_pack_rules_fire_on_their_provider_and_not_on_near_misses() {
        let pack = Rules::load(Path::new("../packs/sigma-linux.yaml")).unwrap();
        let ai: Vec<&Rule> = pack
            .rules
            .iter()
            .filter(|r| r.name.starts_with("sigma-ai-api-"))
            .collect();
        // (rule, a lookup of the provider's API host, a near-miss)
        let cases = [
            ("sigma-ai-api-openai", "api.openai.com", "openai.com"),
            (
                "sigma-ai-api-anthropic",
                "api.anthropic.com",
                "anthropic.com",
            ),
            (
                "sigma-ai-api-google-gemini",
                "generativelanguage.googleapis.com",
                "language.googleapis.com",
            ),
            (
                "sigma-ai-api-google-vertex-ai",
                "aiplatform.googleapis.com",
                "storage.googleapis.com",
            ),
            (
                "sigma-ai-api-google-vertex-ai-2",
                "us-central1-aiplatform.googleapis.com",
                "us-central1-aiplatform.example.net",
            ),
            (
                "sigma-ai-api-azure-openai",
                "contoso.openai.azure.com",
                "contoso.cognitiveservices.azure.com",
            ),
            (
                "sigma-ai-api-aws-bedrock",
                "bedrock-runtime.us-east-1.amazonaws.com",
                "bedrock.us-east-1.amazonaws.com",
            ),
            (
                "sigma-ai-api-aws-bedrock",
                "bedrock-runtime-fips.us-west-2.amazonaws.com",
                "s3.us-west-2.amazonaws.com",
            ),
            ("sigma-ai-api-mistral", "api.mistral.ai", "mistral.ai"),
            ("sigma-ai-api-cohere", "api.cohere.com", "cohere.com"),
            ("sigma-ai-api-groq", "api.groq.com", "groq.com"),
            ("sigma-ai-api-together-ai", "api.together.ai", "together.ai"),
            (
                "sigma-ai-api-together-ai-2",
                "api-inference.together.ai",
                "inference.together.ai",
            ),
            (
                "sigma-ai-api-fireworks-ai",
                "api.fireworks.ai",
                "app.fireworks.ai",
            ),
            (
                "sigma-ai-api-deepseek",
                "api.deepseek.com",
                "chat.deepseek.com",
            ),
            ("sigma-ai-api-xai", "api.x.ai", "x.ai"),
            (
                "sigma-ai-api-perplexity",
                "api.perplexity.ai",
                "www.perplexity.ai",
            ),
            (
                "sigma-ai-api-openrouter",
                "openrouter.ai",
                "notopenrouter.ai",
            ),
            (
                "sigma-ai-api-hugging-face-inference-providers",
                "router.huggingface.co",
                "huggingface.co",
            ),
            (
                "sigma-ai-api-replicate",
                "api.replicate.com",
                "replicate.com",
            ),
        ];
        let rules: std::collections::BTreeSet<&str> = ai.iter().map(|r| r.name.as_str()).collect();
        let covered: std::collections::BTreeSet<&str> = cases.iter().map(|c| c.0).collect();
        assert_eq!(rules, covered, "every AI provider rule needs a case");
        let hits = |name: &str| -> Vec<&str> {
            ai.iter()
                .filter(|r| r.matches(&lookup(name)))
                .map(|r| r.name.as_str())
                .collect()
        };
        for (rule, host, near_miss) in cases {
            assert_eq!(hits(host), vec![rule], "{host}");
            assert!(hits(near_miss).is_empty(), "{near_miss}");
            assert!(
                hits(&format!("{host}.example.net")).is_empty(),
                "{host}.example.net"
            );
            // Rules name DNS selectors only, so program events never match.
            assert!(
                ai.iter().all(|r| !r.matches(&MatchCtx {
                    basename: Some(host),
                    comm: Some(host),
                    ..Default::default()
                })),
                "{host}"
            );
        }
        assert!(ai.iter().all(|r| r.action == Action::Log));
    }

    #[test]
    fn note_is_optional_documentation() {
        let r: Rule = serde_yaml::from_str(
            "name: t\nmatch:\n  path_basename: x\naction: log\nnote: \"why this rule exists\"\n",
        )
        .unwrap();
        assert_eq!(r.note.as_deref(), Some("why this rule exists"));
        let bare = rule("name: t\nmatch:\n  path_basename: x\naction: log\n");
        assert_eq!(bare.note, None);
    }

    #[test]
    fn content_pack_loads_and_every_rule_has_a_note() {
        let rules = Rules::load(Path::new("../rules/content/linux-lolbins.yaml"))
            .expect("content pack must parse");
        assert!(!rules.rules.is_empty());
        for r in &rules.rules {
            assert!(r.note.is_some(), "rule {} is missing a note", r.name);
            assert_eq!(r.action, Action::Log, "content pack is log-only");
        }
    }

    #[test]
    fn persistence_pack_loads() {
        let rules = Rules::load(Path::new("../rules/content/linux-persistence.yaml"))
            .expect("persistence pack must parse");
        assert!(!rules.rules.is_empty());
        for r in &rules.rules {
            assert!(r.note.is_some(), "rule {} is missing a note", r.name);
            assert_eq!(r.action, Action::Log, "content pack is log-only");
        }
    }

    #[test]
    fn not_suppresses_match_all() {
        // "crontab edit, but not read-only -l": match_all/not combo.
        let r = rule(
            "name: t\nmatch_all:\n  path_basename: crontab\nnot:\n  cmdline_contains: \" -l\"\naction: log\n",
        );
        let ctx = |cmdline: &'static str| MatchCtx {
            basename: Some("crontab"),
            cmdline: Some(cmdline),
            ..Default::default()
        };
        assert!(r.matches(&ctx("crontab -e")));
        assert!(!r.matches(&ctx("crontab -l")));
    }

    #[test]
    fn not_blocks_before_any_match() {
        let r = rule(
            "name: t\nmatch:\n  path_basename: curl\nnot:\n  path_prefix: /usr/bin/\naction: log\n",
        );
        assert!(!r.matches(&MatchCtx {
            basename: Some("curl"),
            path: Some("/usr/bin/curl"),
            ..Default::default()
        }));
        assert!(r.matches(&MatchCtx {
            basename: Some("curl"),
            path: Some("/tmp/curl"),
            ..Default::default()
        }));
    }

    #[test]
    fn empty_not_rejected() {
        let err =
            Rules::parse("rules:\n  - name: bad\n    not: {}\n    action: log\n").unwrap_err();
        assert!(err.to_string().contains("not"), "{err}");
    }

    #[test]
    fn parent_and_ancestor_selectors() {
        let r = rule(
            "name: t\nmatch_all:\n  path_basename: sh\n  ancestor_comm_contains: curl\naction: log\n",
        );
        let lineage = MatchCtx {
            basename: Some("sh"),
            parent_basename: Some("curl"),
            ancestors: &["curl".to_string(), "bash".to_string()],
            ..Default::default()
        };
        assert!(r.matches(&lineage));
        let no_curl = MatchCtx {
            basename: Some("sh"),
            parent_basename: Some("bash"),
            ancestors: &["bash".to_string()],
            ..Default::default()
        };
        assert!(!r.matches(&no_curl));
        // Absent lineage evidence → no match (fail-safe).
        assert!(!r.matches(&MatchCtx {
            basename: Some("sh"),
            ..Default::default()
        }));

        let p = rule("name: p\nmatch:\n  parent_basename: curl\naction: log\n");
        assert!(p.matches(&lineage));
        assert!(!p.matches(&no_curl));
    }

    #[test]
    fn comm_selector_matches_invoked_name() {
        // /bin/sh → dash on Ubuntu: path basename is "dash", comm is "sh".
        let r =
            rule("name: t\nmatch_all:\n  comm: sh\n  ancestor_comm_contains: curl\naction: log\n");
        assert!(r.matches(&MatchCtx {
            basename: Some("dash"),
            comm: Some("sh"),
            ancestors: &["curl".to_string()],
            ..Default::default()
        }));
        assert!(!r.matches(&MatchCtx {
            basename: Some("dash"),
            comm: Some("sh"),
            ancestors: &["bash".to_string()],
            ..Default::default()
        }));
    }

    #[test]
    fn rules_file_symlink_rejected() {
        let dir =
            std::env::temp_dir().join(format!("merlin-rules-test-{}-symlink", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("real.yaml");
        let link = dir.join("linked.yaml");
        std::fs::write(&target, "rules: []\n").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = Rules::load(&link).unwrap_err();
        assert!(
            format!("{err:#}").contains("symlinks are rejected"),
            "{err:#}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rules_file_group_writable_warns_but_loads() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("merlin-rules-test-{}-writable", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("writable.yaml");
        std::fs::write(&file, "rules: []\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o664)).unwrap();
        let rules = Rules::load(&file).expect("writable mode must warn, not fail");
        assert!(rules.rules.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rules_file_fifo_is_rejected_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let dir =
            std::env::temp_dir().join(format!("merlin-rules-test-{}-fifo", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("rules.yaml");
        let path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let err = Rules::load(&fifo).unwrap_err();
        assert!(format!("{err:#}").contains("not a regular file"), "{err:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rules_file_over_one_mib_is_rejected() {
        let dir =
            std::env::temp_dir().join(format!("merlin-rules-test-{}-large", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("rules.yaml");
        std::fs::write(&file, vec![b' '; (1 << 20) + 1]).unwrap();
        let err = Rules::load(&file).unwrap_err();
        assert!(format!("{err:#}").contains("1 MiB limit"), "{err:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
