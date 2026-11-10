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
    /// Current state, replaced on every check-in and deleted with the device.
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
}

// MANIFEST_VERSION (bumped when a collector is added, removed or changes
// what it records), JOURNAL, INVENTORY_FIELDS (the check-in's inventory
// record kinds), EVENT_KINDS (every telemetry event kind a monitor writes),
// COLLECTORS, NEVER_COLLECTED and LOCAL, from the TOML.
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
    }
}

/// The collectors this agent runs, derived from the capabilities it announces
/// at check-in: a collector whose manifest lists no capability is always on
/// (discovery that needs no sensor); the others are on when any capability
/// they name is announced. The health section says whether the sensors behind
/// them attached.
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

/// Plain text for a terminal: one line per collector, then the never list.
pub fn render_text() -> String {
    let m = manifest();
    let mut out = format!(
        "Deixic Endpoint ({} {}) collection manifest v{}\n\nWhat it collects\n",
        m.agent, m.agent_version, m.manifest_version
    );
    for c in &m.collectors {
        let retention = match c.retention {
            Retention::WhileEnrolled => "current state, kept while enrolled",
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
    out.push_str("\nOn this computer\n");
    for l in &m.local {
        out.push_str(&format!("  {}: {}\n", l.path, l.holds));
    }
    out.push_str(&format!("  Journal: {}\n", m.journal));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const SYNC: &str = include_str!("sync.rs");
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
                let name = line.strip_prefix("pub ").unwrap_or(line);
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
    fn active_collectors_follow_the_announced_capabilities() {
        let all: Vec<&str> = COLLECTORS
            .iter()
            .flat_map(|c| c.capabilities.iter().copied())
            .collect();
        let every: Vec<&str> = COLLECTORS.iter().map(|c| c.id).collect();
        assert_eq!(active_collector_ids(&all), every);
        // Nothing announced: only the discovery that needs no sensor.
        assert_eq!(active_collector_ids(&[]), vec!["ai_tools"]);
        // A segment uploader without inventory runs the event collectors only.
        let events = active_collector_ids(&["segment_upload"]);
        assert!(events.contains(&"process_events") && events.contains(&"health"));
        assert!(!events.contains(&"software") && !events.contains(&"posture_checks"));
    }

    #[test]
    fn the_never_claims_are_backed_by_the_code_they_name() {
        // Inventory processes carry no command line.
        let process = struct_fields(SYNC, "DeviceProcess");
        assert_eq!(process, ["pid", "name", "executable", "user", "state"]);
        // MCP servers and agent assets: names and places only.
        assert_eq!(
            struct_fields(SYNC, "DeviceMCPServer"),
            ["client", "name", "source", "transport"]
        );
        assert_eq!(
            struct_fields(SYNC, "DeviceAgentAsset"),
            ["client", "kind", "name", "source"]
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
        assert!(text.contains("/var/lib/merlin"));
    }
}
