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

    /// OR semantics (`match:`): at least one listed selector must hit.
    fn any_hit(&self, ctx: &MatchCtx) -> bool {
        self.sha256_hit(ctx)
            || self.basename_hit(ctx)
            || self.prefix_hit(ctx)
            || self.cmdline_hit(ctx)
            || self.comm_hit(ctx)
            || self.parent_hit(ctx)
            || self.ancestor_hit(ctx)
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
