//! The collection manifest: what this agent collects, what it never
//! collects, where it keeps things locally, and how long the server keeps
//! them. `merlin manifest` prints it; the transparency page, the TUI and the
//! menu bar app render from it, so what people read is what the binary does.
//!
//! The manifest is declared here, next to the collectors, and the tests in
//! this module tie it to the code: every inventory field the check-in
//! serialises, every telemetry event kind any monitor emits, and every
//! check-in capability must be named by a collector, and every "never"
//! claim names the source fact or test that proves it. A collector added
//! without a manifest entry fails `cargo test`.

use serde::Serialize;

/// Bumped when a collector is added, removed or changes what it records.
pub const MANIFEST_VERSION: u32 = 1;

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

/// Inventory record kinds, as the check-in's `inventory` object names them
/// (field names of `DeviceInventory` in `sync.rs`; the test below checks
/// this list against that struct).
pub const INVENTORY_FIELDS: &[&str] = &[
    "collected_at",
    "package_manager",
    "cloud_provider",
    "cloud_instance_id",
    "cloud_region",
    "packages",
    "services",
    "users",
    "groups",
    "listening_ports",
    "containers",
    "processes",
    "fim",
    "sca",
    "vulnerabilities",
    "agent_clis",
    "mcp_servers",
    "agent_assets",
    "collection_source",
];

/// Every telemetry event kind a Linux monitor writes to the spool (checked
/// against the sources below).
pub const EVENT_KINDS: &[&str] = &[
    "exec",
    "script",
    "fork",
    "exit",
    "task_exit",
    "kill",
    "deny",
    "connect",
    "socket",
    "dns",
    "netif",
    "file",
    "memfd",
    "iouring",
    "iouring_op",
    "cred",
    "security",
    "bpfcheck",
    "health",
];

pub const COLLECTORS: &[Collector] = &[
    Collector {
        id: "posture_checks",
        group: Group::Checks,
        title: "Security settings",
        what: "Whether disk encryption, screen lock, OS and automatic updates, firewall, remote access, endpoint protection and a password manager are in place, each as pass, fail or unknown with a short reason and a hash of the evidence read. Settings are read; their contents are not copied.",
        why: "Workstation controls in SOC 2 and ISO 27001 ask that company computers are encrypted, locked, patched and protected.",
        records: &["posture.checks", "posture.findings", "posture.coverage"],
        capabilities: &["posture_reporting"],
        retention: Retention::WhileEnrolled,
    },
    Collector {
        id: "hardening",
        group: Group::Checks,
        title: "System hardening facts",
        what: "Read-only facts about kernel parameters, boot settings, service configuration and Kubernetes components, taken from a fixed list of targets, reported as normalized states and hashes.",
        why: "Configuration benchmarks (CIS-style) that controls reference.",
        records: &["hardening.observations"],
        capabilities: &[
            "security_configuration_assessment",
            "linux_boot_trust_posture",
        ],
        retention: Retention::WhileEnrolled,
    },
    Collector {
        id: "os_and_hardware",
        group: Group::Inventory,
        title: "Operating system and hardware",
        what: "OS name and version, kernel, architecture, CPU model and count, memory and disk totals, uptime, virtualization and network interface names and states. No addresses.",
        why: "The device record every control refers to.",
        records: &["os_info"],
        capabilities: &["system_inventory"],
        retention: Retention::WhileEnrolled,
    },
    Collector {
        id: "software",
        group: Group::Inventory,
        title: "Installed software and services",
        what: "Package names, versions and architectures from the system package manager; service names and states; known vulnerability matches by package and version.",
        why: "Patch management and vulnerability controls.",
        records: &[
            "inventory.package_manager",
            "inventory.packages",
            "inventory.services",
            "inventory.vulnerabilities",
            "inventory.collected_at",
            "inventory.collection_source",
        ],
        capabilities: &["system_inventory", "rootcheck"],
        retention: Retention::WhileEnrolled,
    },
    Collector {
        id: "accounts",
        group: Group::Inventory,
        title: "User accounts and groups",
        what: "Account names, numeric ids, whether an account is an administrator, and its login shell; group names. No passwords or password hashes.",
        why: "Access control: who can sign in to the computer and with what rights.",
        records: &["inventory.users", "inventory.groups"],
        capabilities: &["system_inventory"],
        retention: Retention::WhileEnrolled,
    },
    Collector {
        id: "network_exposure",
        group: Group::Inventory,
        title: "Listening ports and containers",
        what: "Protocol, port and state of listening sockets; container ids, names, images, states and runtimes; cloud provider, instance id and region when the machine runs in a cloud.",
        why: "Exposure and asset inventory controls.",
        records: &[
            "inventory.listening_ports",
            "inventory.containers",
            "inventory.cloud_provider",
            "inventory.cloud_instance_id",
            "inventory.cloud_region",
        ],
        capabilities: &["container_inventory", "cloud_inventory"],
        retention: Retention::WhileEnrolled,
    },
    Collector {
        id: "running_programs",
        group: Group::Inventory,
        title: "Running programs",
        what: "For each process: id, program name, executable path, owning user id and state. Not the command line or arguments.",
        why: "Endpoint protection and unauthorized software controls.",
        records: &["inventory.processes"],
        capabilities: &["system_inventory"],
        retention: Retention::WhileEnrolled,
    },
    Collector {
        id: "file_integrity",
        group: Group::Inventory,
        title: "File integrity baselines",
        what: "For files in a fixed list of system locations: path, size, permissions, modification time and whether the baseline changed. File contents are never read.",
        why: "Change detection on system configuration.",
        records: &["inventory.fim", "inventory.sca"],
        capabilities: &["file_integrity"],
        retention: Retention::WhileEnrolled,
    },
    Collector {
        id: "ai_tools",
        group: Group::AiTools,
        title: "AI coding tools and MCP servers",
        what: "Which AI coding tools are installed (names), which MCP servers each client has configured (client, server name, where it is configured, transport), and which agent skills or instructions exist (client, kind, name, source). Commands, arguments, URLs, environment variables and file bodies are never read.",
        why: "AI tool governance: knowing which agents and servers run on company machines.",
        records: &[
            "inventory.agent_clis",
            "inventory.mcp_servers",
            "inventory.agent_assets",
        ],
        capabilities: &[],
        retention: Retention::WhileEnrolled,
    },
    Collector {
        id: "process_events",
        group: Group::SecurityEvents,
        title: "Program starts, scripts and exits",
        what: "When a program starts or ends: program name, executable path, parent programs, working directory, container, and the rules it matched. The command line is read on this computer to evaluate rules and is included only when a rule matched. Scripts record the interpreter and script path.",
        why: "Detecting and investigating attacks (endpoint detection).",
        records: &["exec", "script", "fork", "exit", "task_exit"],
        capabilities: &["segment_upload"],
        retention: Retention::TelemetryWindow,
    },
    Collector {
        id: "network_events",
        group: Group::SecurityEvents,
        title: "Network connections and DNS lookups",
        what: "Outbound connections (program, source and destination address and port), socket state changes, network interface changes, and the domain names programs look up with the program that asked. Not page contents, messages or what was sent.",
        why: "Detecting command-and-control, data exfiltration and DNS tunnelling.",
        records: &["connect", "socket", "netif", "dns"],
        capabilities: &["segment_upload"],
        retention: Retention::TelemetryWindow,
    },
    Collector {
        id: "file_events",
        group: Group::SecurityEvents,
        title: "Changes in watched system locations",
        what: "The path, operation and program for changes under a fixed list of persistence and configuration locations. File contents are never read.",
        why: "Detecting persistence (startup items, cron, shell profiles) and tampering.",
        records: &["file"],
        capabilities: &["segment_upload"],
        retention: Retention::TelemetryWindow,
    },
    Collector {
        id: "memory_and_privilege_events",
        group: Group::SecurityEvents,
        title: "Memory, privilege and kernel signals",
        what: "Anonymous memory files, io_uring use, credential changes to root, selected system calls with their numeric arguments and memory-protection transitions, and eBPF program changes. Program name and id only; no file contents or command lines.",
        why: "Detecting in-memory attacks, privilege escalation and sensor tampering.",
        records: &[
            "memfd",
            "iouring",
            "iouring_op",
            "cred",
            "security",
            "bpfcheck",
        ],
        capabilities: &["segment_upload"],
        retention: Retention::TelemetryWindow,
    },
    Collector {
        id: "enforcement",
        group: Group::Agent,
        title: "What the agent blocked or stopped",
        what: "When a signed rule blocks a program from starting or stops a running one: the program, the rule name and the outcome. Nothing is blocked unless the workspace assigned a rule that blocks.",
        why: "Evidence that endpoint protection acted, and a record of every action taken on this computer.",
        records: &["deny", "kill"],
        capabilities: &["rules_sync"],
        retention: Retention::TelemetryWindow,
    },
    Collector {
        id: "health",
        group: Group::Agent,
        title: "Agent health",
        what: "Whether the sensors are attached, how many events were kept or dropped, upload backlog and errors, and the agent version.",
        why: "Knowing the evidence stream is complete; a device that stopped reporting is a finding, not a pass.",
        records: &["health", "check_in.health", "check_in.capabilities"],
        capabilities: &["segment_upload"],
        retention: Retention::WhileEnrolled,
    },
];

pub const NEVER_COLLECTED: &[Never] = &[
    Never {
        claim: "Command lines and arguments of programs you run, unless a security rule matched that program",
        proof: "telemetry::recorded_cmdline (test the_command_line_leaves_the_device_only_with_a_matched_rule); inventory DeviceProcess has no cmdline or args field",
    },
    Never {
        claim: "Contents of your files, documents or messages",
        proof: "file events carry path, op, pid, comm and matched rules only; FIM records path, size, mode, mtime and status; no monitor opens file bodies",
    },
    Never {
        claim: "MCP server commands, arguments, URLs, environment variables, skill or instruction bodies",
        proof: "DeviceMCPServer is client, name, source, transport; DeviceAgentAsset is client, kind, name, source; collect_agent_discovery never executes a CLI or reads configuration values",
    },
    Never {
        claim: "Passwords, password hashes, tokens or keys",
        proof: "DeviceUser is name, uid, admin, shell, source; posture evidence is a hash of what was read, with redactions declared",
    },
    Never {
        claim: "Keystrokes, screen contents, camera or microphone",
        proof: "no collector opens input, display, video or audio devices (test no_collector_touches_input_display_or_media_devices)",
    },
    Never {
        claim: "Web pages, chats or what you typed into them (domain names looked up are recorded; page contents are not)",
        proof: "dns events carry pid, uid, comm and the queried name; connect events carry addresses and ports",
    },
];

pub const LOCAL: &[LocalStore] = &[
    LocalStore {
        path: "/var/lib/merlin",
        holds: "The event spool: finished segments wait here until the server accepts them, then they are deleted; segments the server refuses for good move to quarantine/ and are never uploaded.",
    },
    LocalStore {
        path: "/etc/merlin",
        holds: "The device credential (0600, root) and the signed rules the workspace assigned.",
    },
];

pub const JOURNAL: &str = "The system journal (journalctl -u merlin) carries health and errors only: starts, sensor attach, upload results, enforcement actions by rule name. Per-event details are debug level and off by default.";

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
        let start = SYNC.find("capabilities: [").expect("check-in capabilities");
        let body = &SYNC[start..];
        let end = body.find(']').expect("capabilities end");
        let announced: Vec<&str> = body[..end].split('"').skip(1).step_by(2).collect();
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
    fn the_never_claims_are_backed_by_the_code_they_name() {
        // Command lines: only with a match (the helper and its test exist).
        let telemetry = SOURCES
            .iter()
            .find(|(n, _)| *n == "telemetry.rs")
            .unwrap()
            .1;
        assert!(telemetry.contains("fn recorded_cmdline("));
        assert!(
            telemetry.contains("fn the_command_line_leaves_the_device_only_with_a_matched_rule()")
        );
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
