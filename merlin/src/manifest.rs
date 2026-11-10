//! The collection manifest: what this agent collects, what it never
//! collects, where it keeps things locally, and how long the server keeps
//! them. `merlin manifest` prints it; the transparency page, the TUI and the
//! menu bar app render from it, so what people read is what the binary does.
//!
//! The manifest is declared once, in `../collection-manifest.toml`; `build.rs`
//! compiles it into the constants below, and the tests in this module tie it
//! to the code: every inventory field the check-in serialises, every
//! telemetry event kind any monitor emits, and every check-in capability must
//! be named by a collector, and every "never" claim names the source fact or
//! test that proves it. A collector added
//! without a manifest entry fails `cargo test`.

use serde::Serialize;

/// Where the server keeps a collector's output.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Retention {
    /// Current device state, replaced on check-in. Retirement or disposal
    /// leaves a device-record tombstone.
    WhileEnrolled,
    /// Raw events, kept for the server's telemetry window (default 30 days
    /// and 10 GiB per device; the server reports its actual values).
    TelemetryWindow,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Group {
    /// Security settings the compliance checks grade.
    Checks,
    /// Facts about the machine and what is installed.
    Inventory,
    /// AI coding tools and MCP servers present (names only).
    AiTools,
    /// Raw security events from the kernel sensors.
    SecurityEvents,
    /// Agent health and enforcement outcomes.
    Agent,
}

#[derive(Serialize, Clone, Copy, Debug)]
pub struct Collector {
    /// Stable id the web page, TUI and menu bar key on.
    pub id: &'static str,
    pub group: Group,
    /// Plain-language name.
    pub title: &'static str,
    /// Plain-language description of what is recorded.
    pub what: &'static str,
    /// Why it is collected, in terms of the requirement it serves.
    pub why: &'static str,
    /// The check-in section or event kinds this collector produces, so a
    /// reader can map a stored record back to its source here.
    pub records: &'static [&'static str],
    /// The check-in capability strings that announce this collector, if any.
    pub capabilities: &'static [&'static str],
    pub retention: Retention,
}

#[derive(Serialize, Clone, Copy, Debug)]
pub struct Never {
    pub claim: &'static str,
    /// The source fact or test name that keeps the claim true.
    pub proof: &'static str,
}

#[derive(Serialize, Clone, Copy, Debug)]
pub struct LocalStore {
    pub path: &'static str,
    pub holds: &'static str,
}

/// How an AI location is read; see the `ai_locations` comment in the TOML.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    Executable,
    Json,
    Toml,
    CodexToml,
    SkillDir,
    Md,
    JsTs,
    PluginDir,
    GeminiExtension,
    CursorAgent,
    CursorPlugin,
    ClaudePluginCache,
    /// Hugging Face's hub cache, read by the model-file posture check.
    HfHub,
    /// A model directory (Ollama, LM Studio), read by the model-file posture
    /// check.
    ModelDir,
    EditorExtensions,
    ChromiumExtensions,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Relative to each user's home.
    User,
    /// Relative to each visited project directory.
    Project,
    /// An absolute path on the computer (or container root), read once.
    System,
}

/// One place the `ai_tools` collector looks, from `ai_locations`.
#[derive(Serialize, Clone, Copy, Debug)]
pub struct AiLocation {
    pub client: &'static str,
    /// cli, config, skill, agent, plugin, extension or model.
    pub kind: &'static str,
    /// Relative to the home or project; a bare executable name for a cli.
    pub path: &'static str,
    pub format: Format,
    pub scope: Scope,
    /// linux, macos and/or windows.
    pub platforms: &'static [&'static str],
    /// JSON object keys whose entries are MCP servers.
    pub mcp_keys: &'static [&'static str],
    /// JSON object key whose `name: true` entries are enabled plugins; empty
    /// when the file has none.
    pub plugins_key: &'static str,
    /// Files inside each plugin directory read for MCP servers.
    pub mcp_files: &'static [&'static str],
    /// The most bytes of this file read; a larger file is reported as not
    /// scanned (`too_large`) instead.
    pub max_bytes: u64,
}

impl AiLocation {
    /// The fixed source label findings from this location carry.
    pub fn label(&self) -> String {
        match self.scope {
            Scope::User => self.path.to_string(),
            Scope::Project => format!("project/{}", self.path),
            Scope::System => format!("system{}", self.path),
        }
    }

    /// The locations the Linux agent reads in `scope`, in declared order.
    pub fn linux(scope: Scope) -> impl Iterator<Item = &'static AiLocation> {
        Self::on("linux", scope)
    }

    /// The AI tool inventory locations that apply on `platform` (linux, macos
    /// or windows) in `scope`, in declared order. Model caches (kind model)
    /// are not inventory; see `models`.
    pub fn on(platform: &'static str, scope: Scope) -> impl Iterator<Item = &'static AiLocation> {
        AI_LOCATIONS.iter().filter(move |l| {
            l.scope == scope && l.platforms.contains(&platform) && l.kind != "model"
        })
    }

    /// The model caches the model-file posture check reads on `platform`,
    /// in declared order.
    pub fn models(platform: &'static str) -> impl Iterator<Item = &'static AiLocation> {
        AI_LOCATIONS
            .iter()
            .filter(move |l| l.kind == "model" && l.platforms.contains(&platform))
    }
}

/// Where an AI extension is published; its id has that store's shape.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ExtensionStore {
    VscodeMarketplace,
    ChromeWebStore,
}

/// One AI editor or browser extension reported by id, from
/// `ai_extensions`.
#[derive(Serialize, Clone, Copy, Debug)]
pub struct AiExtension {
    pub store: ExtensionStore,
    pub id: &'static str,
    pub name: &'static str,
    pub publisher: &'static str,
}

/// A name an AI agent's process runs under, from `ai_agent_processes`.
#[derive(Serialize, Clone, Copy, Debug)]
pub struct AiAgentProcess {
    /// The client, as ai_locations names it.
    pub client: &'static str,
    /// The process name: the kernel's process name or the executable's file
    /// name.
    pub name: &'static str,
}

impl AiAgentProcess {
    /// Every name an AI agent runs under: each `cli` row of ai_locations
    /// (its path is the command name), then the `ai_agent_processes` rows.
    pub fn all() -> impl Iterator<Item = AiAgentProcess> {
        AI_LOCATIONS
            .iter()
            .filter(|l| l.kind == "cli")
            .map(|l| AiAgentProcess {
                client: l.client,
                name: l.path,
            })
            .chain(AI_AGENT_PROCESSES.iter().copied())
    }
}

/// One rule run on the content of AI skill, agent and plugin files, from
/// `ai_content_rules`.
#[derive(Serialize, Clone, Copy, Debug)]
pub struct AiContentRule {
    /// The rule name findings report.
    pub id: &'static str,
    /// yara.
    pub engine: &'static str,
    /// The rule file under `rules/ai/`.
    pub file: &'static str,
}

#[derive(Serialize, Clone, Debug)]
pub struct Manifest {
    pub manifest_version: u32,
    pub agent: &'static str,
    pub agent_version: &'static str,
    pub platform: &'static str,
    pub collectors: Vec<Collector>,
    /// The check-in inventory record kinds and the telemetry event kinds the
    /// collectors above account for, so a reader can map any stored record
    /// back to its collector.
    pub inventory_fields: Vec<&'static str>,
    pub event_kinds: Vec<&'static str>,
    pub never_collected: Vec<Never>,
    pub local: Vec<LocalStore>,
    /// Journald carries health and errors only; per-event details are debug
    /// level and off by default.
    pub journal: &'static str,
    /// Every place this agent looks for AI tools, from `ai_locations`, so the
    /// transparency page lists them all.
    pub ai_locations: Vec<AiLocation>,
    /// The names AI agents run under (cli rows and `ai_agent_processes`):
    /// telemetry from their process trees carries the agent and its session.
    pub ai_agent_processes: Vec<AiAgentProcess>,
    /// The rules run on the content of the AI skill, agent and plugin files
    /// found there, from `ai_content_rules`.
    pub ai_content_rules: Vec<AiContentRule>,
    /// The AI editor and browser extensions reported by id, from
    /// `ai_extensions`; no other extension is named.
    pub ai_extensions: Vec<AiExtension>,
}

// MANIFEST_VERSION (set by the release, 0 in a development build), JOURNAL,
// INVENTORY_FIELDS (the check-in's inventory record kinds), EVENT_KINDS
// (every telemetry event kind a monitor writes),
// COLLECTORS, NEVER_COLLECTED, LOCAL and AI_LOCATIONS (where the ai_tools
// collector looks), from the TOML.
include!(concat!(env!("OUT_DIR"), "/manifest_data.rs"));

pub fn manifest() -> Manifest {
    Manifest {
        manifest_version: MANIFEST_VERSION,
        agent: "merlin",
        agent_version: env!("CARGO_PKG_VERSION"),
        platform: "linux",
        collectors: COLLECTORS.to_vec(),
        inventory_fields: INVENTORY_FIELDS.to_vec(),
        event_kinds: EVENT_KINDS.to_vec(),
        never_collected: NEVER_COLLECTED.to_vec(),
        local: LOCAL.to_vec(),
        journal: JOURNAL,
        ai_locations: AI_LOCATIONS
            .iter()
            .filter(|l| l.platforms.contains(&"linux"))
            .copied()
            .collect(),
        ai_agent_processes: AiAgentProcess::all().collect(),
        ai_content_rules: AI_CONTENT_RULES.to_vec(),
        ai_extensions: AI_EXTENSIONS.to_vec(),
    }
}

/// The collectors declared as supported by this build, derived from its
/// static check-in capabilities. A collector whose manifest lists no
/// capability is always declared; the others are declared when any capability
/// they name is present. This does not observe runtime collector state.
pub fn active_collector_ids(capabilities: &[&str]) -> Vec<&'static str> {
    COLLECTORS
        .iter()
        .filter(|c| {
            c.capabilities.is_empty()
                || c.capabilities
                    .iter()
                    .any(|capability| capabilities.contains(capability))
        })
        .map(|c| c.id)
        .collect()
}

/// How people read a manifest version: `v103` for a release, `(development
/// build)` for 0, which main carries until the release sets the number.
pub fn version_label(version: u32) -> String {
    if version == 0 {
        "(development build)".to_owned()
    } else {
        format!("v{version}")
    }
}

/// Plain text for a terminal: one line per collector, then the never list.
pub fn render_text() -> String {
    let m = manifest();
    let mut out = format!(
        "Deixic Endpoint ({} {}) collection manifest {}\n\nWhat it collects\n",
        m.agent,
        m.agent_version,
        version_label(m.manifest_version)
    );
    for c in &m.collectors {
        let retention = match c.retention {
            Retention::WhileEnrolled => {
                "current device state, replaced on check-in; a tombstone remains after retirement/disposal"
            }
            Retention::TelemetryWindow => "raw events, kept for the server's telemetry window",
        };
        out.push_str(&format!(
            "  {}\n    {}\n    Why: {}\n    Kept: {}\n",
            c.title, c.what, c.why, retention
        ));
    }
    out.push_str("\nWhat it never collects\n");
    for n in &m.never_collected {
        out.push_str(&format!("  - {}\n", n.claim));
    }
    out.push_str("\nWhere it looks for AI tools\n");
    for (scope, heading) in [
        (Scope::User, "In each home directory"),
        (Scope::Project, "In each configured project directory"),
        (Scope::System, "On the computer"),
    ] {
        out.push_str(&format!("  {heading}:\n"));
        for l in m.ai_locations.iter().filter(|l| l.scope == scope) {
            let place = if l.kind == "cli" {
                format!("{} in the fixed bin directories", l.path)
            } else {
                l.path.to_string()
            };
            out.push_str(&format!("    {} {}: {place}\n", l.client, l.kind));
        }
    }
    out.push_str(
        "\nAI agents whose programs, connections, lookups and file changes are attributed to them\n",
    );
    for p in &m.ai_agent_processes {
        out.push_str(&format!("  {} (process {})\n", p.client, p.name));
    }
    out.push_str("\nRules run on AI skill, agent and plugin files (ids reported, never content)\n");
    for r in &m.ai_content_rules {
        out.push_str(&format!("  {} ({})\n", r.id, r.file));
    }
    out.push_str("\nOn this computer\n");
    for l in &m.local {
        out.push_str(&format!("  {}: {}\n", l.path, l.holds));
    }
    out.push_str(&format!("  Journal: {}\n", m.journal));
    out
}

// The tests tie the manifest to the Linux agent's modules.
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const SYNC: &str = include_str!("sync.rs");
    const AI_DISCOVERY: &str = include_str!("ai_discovery.rs");
    const SOURCES: &[(&str, &str)] = &[
        ("telemetry.rs", include_str!("telemetry.rs")),
        ("filemon.rs", include_str!("filemon.rs")),
        ("fanotify_mon.rs", include_str!("fanotify_mon.rs")),
        ("dnsmon.rs", include_str!("dnsmon.rs")),
        ("netifmon.rs", include_str!("netifmon.rs")),
        ("persistence_mon.rs", include_str!("persistence_mon.rs")),
        ("taskstats.rs", include_str!("taskstats.rs")),
        ("bpfcheck.rs", include_str!("bpfcheck.rs")),
        ("spool.rs", include_str!("spool.rs")),
        ("fileless.rs", include_str!("fileless.rs")),
        ("proctree.rs", include_str!("proctree.rs")),
        ("agent_session.rs", include_str!("agent_session.rs")),
        ("linux_posture.rs", include_str!("linux_posture.rs")),
        ("linux_hardening.rs", include_str!("linux_hardening.rs")),
        ("sync.rs", SYNC),
    ];

    /// Field names of `struct <name> {` in `source` (one per line, `name: Type,`).
    fn struct_fields(source: &str, name: &str) -> Vec<String> {
        let start = source
            .find(&format!("struct {name} {{"))
            .unwrap_or_else(|| panic!("struct {name} not found"));
        let body = &source[start..];
        let end = body.find("\n}").expect("struct end");
        body[..end]
            .lines()
            .skip(1)
            .filter_map(|line| {
                let line = line.trim();
                if line.starts_with('#') || line.starts_with("//") || line.starts_with("pub struct")
                {
                    return None;
                }
                let name = line
                    .strip_prefix("pub(crate) ")
                    .or_else(|| line.strip_prefix("pub "))
                    .unwrap_or(line);
                let (name, _) = name.split_once(':')?;
                Some(name.trim().to_owned())
            })
            .collect()
    }

    /// Every `"kind": "<x>"` literal in the sources, outside their test modules.
    fn literal_kinds() -> BTreeSet<String> {
        let mut kinds = BTreeSet::new();
        for (_, source) in SOURCES {
            let production = source.split("#[cfg(test)]").next().unwrap_or("");
            for line in production.lines() {
                if let Some(rest) = line.split("\"kind\": \"").nth(1) {
                    if let Some((kind, _)) = rest.split_once('"') {
                        kinds.insert(kind.to_owned());
                    }
                }
            }
        }
        kinds
    }

    #[test]
    fn every_inventory_field_the_check_in_sends_is_declared() {
        let fields = struct_fields(SYNC, "DeviceInventory");
        assert!(!fields.is_empty());
        let declared: BTreeSet<&str> = INVENTORY_FIELDS.iter().copied().collect();
        for field in &fields {
            assert!(
                declared.contains(field.as_str()),
                "DeviceInventory.{field} is not in INVENTORY_FIELDS"
            );
        }
        let named: BTreeSet<String> = COLLECTORS
            .iter()
            .flat_map(|c| c.records.iter())
            .filter_map(|r| r.strip_prefix("inventory."))
            .map(str::to_owned)
            .collect();
        for field in INVENTORY_FIELDS {
            assert!(
                named.contains(*field),
                "no collector records inventory.{field}"
            );
            assert!(
                fields.iter().any(|f| f == field),
                "INVENTORY_FIELDS names {field}, which DeviceInventory no longer has"
            );
        }
    }

    #[test]
    fn every_event_kind_a_monitor_emits_is_declared_by_a_collector() {
        let declared: BTreeSet<&str> = EVENT_KINDS.iter().copied().collect();
        for kind in literal_kinds() {
            assert!(
                declared.contains(kind.as_str()),
                "event kind {kind:?} is emitted but not in EVENT_KINDS"
            );
        }
        // Kinds chosen at run time rather than written as literals.
        for kind in ["socket", "netif"] {
            assert!(declared.contains(kind));
        }
        let recorded: BTreeSet<&str> = COLLECTORS
            .iter()
            .flat_map(|c| c.records.iter().copied())
            .collect();
        for kind in EVENT_KINDS {
            assert!(
                recorded.contains(kind),
                "no collector records event kind {kind}"
            );
        }
    }

    #[test]
    fn every_check_in_capability_belongs_to_a_collector() {
        let announced = crate::sync::CHECK_IN_CAPABILITIES;
        assert!(!announced.is_empty());
        let declared: BTreeSet<&str> = COLLECTORS
            .iter()
            .flat_map(|c| c.capabilities.iter().copied())
            .collect();
        for capability in announced {
            assert!(
                declared.contains(capability),
                "check-in capability {capability:?} has no collector"
            );
        }
        // desired_state capabilities announce the enforcement executors.
        assert!(declared.contains("rules_sync"));
    }

    #[test]
    fn declared_collectors_follow_the_static_build_capabilities() {
        let all: Vec<&str> = COLLECTORS
            .iter()
            .flat_map(|c| c.capabilities.iter().copied())
            .collect();
        let every: Vec<&str> = COLLECTORS.iter().map(|c| c.id).collect();
        assert_eq!(active_collector_ids(&all), every);
        // Nothing announced: only the discovery that needs no sensor.
        assert_eq!(active_collector_ids(&[]), vec!["ai_tools"]);
        // A segment uploader without inventory declares the event collectors only.
        let events = active_collector_ids(&["segment_upload"]);
        assert!(events.contains(&"process_events") && events.contains(&"health"));
        assert!(!events.contains(&"software") && !events.contains(&"posture_checks"));
    }

    #[test]
    fn the_never_claims_are_backed_by_the_code_they_name() {
        // Inventory processes carry no command line.
        let process = struct_fields(AI_DISCOVERY, "DeviceProcess");
        assert_eq!(process, ["pid", "name", "executable", "user", "state"]);
        // MCP servers and agent assets: names and places only.
        assert_eq!(
            struct_fields(AI_DISCOVERY, "DeviceMCPServer"),
            [
                "client",
                "name",
                "source",
                "transport",
                "location",
                "package",
                "host"
            ]
        );
        assert_eq!(
            struct_fields(AI_DISCOVERY, "DeviceAgentAsset"),
            [
                "client",
                "kind",
                "name",
                "source",
                "location",
                "sha256",
                "matched_rules"
            ]
        );
        // Accounts: no secrets.
        assert_eq!(
            struct_fields(SYNC, "DeviceUser"),
            ["name", "uid", "admin", "shell", "source"]
        );
        // Every claim names its proof.
        for never in NEVER_COLLECTED {
            assert!(!never.proof.is_empty(), "{}", never.claim);
        }
    }

    #[test]
    fn every_ai_location_parses_and_its_label_is_unique() {
        assert!(!AI_LOCATIONS.is_empty());
        for platform in ["linux", "macos", "windows"] {
            let mut labels = BTreeSet::new();
            for location in AI_LOCATIONS
                .iter()
                .filter(|l| l.platforms.contains(&platform))
            {
                let key = (location.kind == "cli", location.label());
                assert!(
                    labels.insert(key),
                    "{platform}: {} is declared twice",
                    location.label()
                );
            }
        }
        for location in AI_LOCATIONS {
            // A label is a fixed probe: no home, account or absolute path.
            // Only a system row's path is absolute, and its label is not.
            assert!(!location.label().starts_with('/') && !location.path.contains(".."));
            assert_eq!(
                location.path.starts_with('/'),
                location.scope == Scope::System
            );
            assert!(!location.client.is_empty() && !location.kind.is_empty());
            // The project walker reads these formats only.
            if location.scope == Scope::Project {
                assert!(
                    matches!(
                        location.format,
                        Format::Json
                            | Format::Toml
                            | Format::SkillDir
                            | Format::Md
                            | Format::PluginDir
                    ),
                    "project/{} uses a format the project walker does not read",
                    location.path
                );
            }
        }
    }

    #[test]
    fn the_ai_tools_collector_reads_the_declared_locations() {
        // The Linux walkers take every location from AI_LOCATIONS: no
        // hand-kept list of clients, configs or asset directories remains.
        let sync = SYNC.split("#[cfg(test)]").next().unwrap_or("");
        let project = include_str!("sync/project_discovery.rs");
        for (name, source) in [("sync.rs", sync), ("project_discovery.rs", project)] {
            for needle in [
                "const CLIS",
                "const CONFIGS",
                "const ASSETS",
                "\".claude/skills\"",
            ] {
                assert!(!source.contains(needle), "{name} still hand-lists {needle}");
            }
        }
        assert!(sync.contains("AiLocation::linux(Scope::User)"));
        assert!(project.contains("AiLocation::linux(Scope::Project)"));
    }

    #[test]
    fn no_collector_touches_input_display_or_media_devices() {
        for (name, source) in SOURCES {
            // Display servers are named by the screen-lock check; device
            // nodes and capture words would mean a collector reads them.
            for needle in [
                "/dev/input",
                "evdev",
                "/dev/video",
                "/dev/snd",
                "screenshot",
                "keylog",
            ] {
                assert!(
                    !source
                        .to_ascii_lowercase()
                        .contains(&needle.to_ascii_lowercase()),
                    "{name} mentions {needle}"
                );
            }
        }
    }

    /// The product directory: collection-manifest.toml, macos/ and packaging/.
    fn product_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
    }

    // Pull requests never set the manifest version; the release does
    // (packaging/stamp-manifest-version.sh). A number on main is what made
    // every endpoint pull request conflict with every other.
    #[test]
    fn main_carries_the_development_manifest_version() {
        assert_eq!(
            MANIFEST_VERSION, 0,
            "manifest_version in collection-manifest.toml is set by the release; keep it 0"
        );
        let swift =
            std::fs::read_to_string(product_dir().join("macos/Sources/MerlinMacOS/Manifest.swift"))
                .unwrap();
        assert!(
            swift
                .lines()
                .any(|line| line == "    static let version = 0"),
            "CollectionManifest.version in Manifest.swift is set by the release; keep it 0"
        );
        assert_eq!(version_label(0), "(development build)");
        assert_eq!(version_label(103), "v103");
    }

    #[cfg(unix)]
    #[test]
    fn the_release_stamp_sets_the_rust_and_swift_versions_together() {
        let product = product_dir();
        let scratch = std::env::temp_dir().join(format!(
            "merlin-manifest-stamp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let swift = "macos/Sources/MerlinMacOS/Manifest.swift";
        let fresh = || {
            let _ = std::fs::remove_dir_all(&scratch);
            std::fs::create_dir_all(scratch.join("macos/Sources/MerlinMacOS")).unwrap();
            for file in ["collection-manifest.toml", swift] {
                std::fs::copy(product.join(file), scratch.join(file)).unwrap();
            }
        };
        let stamp = |release: &str| {
            std::process::Command::new("sh")
                .arg(product.join("packaging/stamp-manifest-version.sh"))
                .arg(release)
                .arg(&scratch)
                .output()
                .unwrap()
        };
        let versions = || {
            let toml: toml::Table =
                std::fs::read_to_string(scratch.join("collection-manifest.toml"))
                    .unwrap()
                    .parse()
                    .unwrap();
            let swift = std::fs::read_to_string(scratch.join(swift)).unwrap();
            let swift = swift
                .lines()
                .find_map(|line| line.strip_prefix("    static let version = "))
                .map(|value| value.parse::<i64>().unwrap());
            (toml["manifest_version"].as_integer(), swift)
        };
        for (release, want) in [
            ("merlin-v0.1.3", 103),
            ("v1.2.3", 10203),
            ("0.2.0-rc.1", 200),
            ("99.99.99", 999_999),
        ] {
            fresh();
            let out = stamp(release);
            assert!(out.status.success(), "{release}: {out:?}");
            assert_eq!(versions(), (Some(want), Some(want)), "{release}");
            // A stamped checkout is refused, not stamped twice.
            assert!(!stamp(release).status.success(), "{release} stamped twice");
            assert_eq!(versions(), (Some(want), Some(want)), "{release}");
        }
        for release in ["0.0.0", "0.1", "1.2.3.4", "100.0.0", "0.1.x", "nightly", ""] {
            fresh();
            assert!(!stamp(release).status.success(), "{release:?} accepted");
            assert_eq!(versions(), (Some(0), Some(0)), "{release:?}");
        }
        std::fs::remove_dir_all(&scratch).unwrap();
    }

    #[test]
    fn the_manifest_serialises_and_renders() {
        let value = serde_json::to_value(manifest()).unwrap();
        assert_eq!(value["manifest_version"], MANIFEST_VERSION);
        assert_eq!(
            value["collectors"].as_array().unwrap().len(),
            COLLECTORS.len()
        );
        let ids: BTreeSet<&str> = COLLECTORS.iter().map(|c| c.id).collect();
        assert_eq!(ids.len(), COLLECTORS.len(), "collector ids are unique");
        let text = render_text();
        assert!(text.contains("What it never collects"));
        assert!(text.contains("a tombstone remains after retirement/disposal"));
        // Every Linux AI location is printed, in JSON and text.
        let linux: Vec<&AiLocation> = AI_LOCATIONS
            .iter()
            .filter(|l| l.platforms.contains(&"linux"))
            .collect();
        assert_eq!(value["ai_locations"].as_array().unwrap().len(), linux.len());
        for l in linux {
            assert!(text.contains(l.path), "{} is not printed", l.path);
        }
        assert!(!value["ai_locations"].as_array().unwrap().iter().any(|l| {
            !l["platforms"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p == "linux")
        }));
        assert!(text.contains("/var/lib/merlin"));
    }
}
