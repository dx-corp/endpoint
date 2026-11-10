import Foundation

// The collection manifest, macOS port. Same collector ids, groups, retention
// classes and never-claims as the declared manifest (`collection-manifest.toml`,
// which the Linux port compiles in), so the transparency page, the TUI and the menu bar app make one claim for both
// operating systems; the `what` text names the macOS sources where they differ.
// `ManifestTests` reads that file and fails when the id sets or the number
// of never-claims drift apart.

enum ManifestRetention: String, Encodable, Sendable {
    /// Current device state, replaced on check-in. Retirement or disposal
    /// leaves a device-record tombstone.
    case whileEnrolled = "while_enrolled"
    /// Raw events, kept for the server's telemetry window (default 30 days and
    /// 10 GiB per device; the server reports its actual values).
    case telemetryWindow = "telemetry_window"
}

enum ManifestGroup: String, Encodable, Sendable {
    case checks, inventory
    case aiTools = "ai_tools"
    case securityEvents = "security_events"
    case agent
}

struct ManifestCollector: Encodable, Sendable {
    let id: String
    let group: ManifestGroup
    let title: String
    let what: String
    let why: String
    let records: [String]
    let capabilities: [String]
    let retention: ManifestRetention
}

struct ManifestNever: Encodable, Sendable {
    let claim: String
    let proof: String
}

struct ManifestLocalStore: Encodable, Sendable {
    let path: String
    let holds: String
}

struct CollectionManifest: Encodable, Sendable {
    let manifestVersion: Int
    let agent: String
    let agentVersion: String
    let platform: String
    let collectors: [ManifestCollector]
    let neverCollected: [ManifestNever]
    let local: [ManifestLocalStore]
    let journal: String

    enum CodingKeys: String, CodingKey {
        case manifestVersion = "manifest_version"
        case agent
        case agentVersion = "agent_version"
        case platform
        case collectors
        case neverCollected = "never_collected"
        case local
        case journal
    }

    /// Set by the release; pull requests never change it. 0 is a development
    /// build; `packaging/stamp-manifest-version.sh` writes the release's number
    /// here and into `collection-manifest.toml` before a release build.
    static let version = 0

    /// `v103` for a release, `(development build)` for 0 (merlin's
    /// `manifest::version_label`).
    static func versionLabel(_ version: Int) -> String {
        version == 0 ? "(development build)" : "v\(version)"
    }

    static let collectors: [ManifestCollector] = [
        ManifestCollector(
            id: "posture_checks", group: .checks, title: "Security settings",
            what: "Whether FileVault, screen lock, macOS and automatic updates, the firewall, remote access, endpoint protection and a password manager are in place, each as pass, fail or unknown with a short reason and a hash of the evidence read. Settings are read; their contents are not copied.",
            why: "Workstation controls in SOC 2 and ISO 27001 ask that company computers are encrypted, locked, patched and protected.",
            records: ["posture.checks", "posture.findings", "posture.coverage"],
            capabilities: ["posture_reporting"], retention: .whileEnrolled),
        ManifestCollector(
            id: "hardening", group: .checks, title: "System hardening facts",
            what: "Read-only facts from the posture sweep: system integrity protection, configuration profiles, system extensions, proxy and DNS settings, launch items and event taps, reported as normalized states and hashes.",
            why: "Configuration benchmarks (CIS-style) that controls reference.",
            records: ["posture.sweep"],
            capabilities: ["security_configuration_assessment"], retention: .whileEnrolled),
        ManifestCollector(
            id: "os_and_hardware", group: .inventory, title: "Operating system and hardware",
            what: "macOS version and build, kernel, architecture, CPU model and count, memory and disk totals, uptime, virtualization and network interface names and states. No addresses.",
            why: "The device record every control refers to.",
            records: ["os_info"], capabilities: ["system_inventory"], retention: .whileEnrolled),
        ManifestCollector(
            id: "software", group: .inventory, title: "Installed software and services",
            what: "Application and package names and versions; launch daemons and agents and their states; known vulnerability matches by package and version.",
            why: "Patch management and vulnerability controls.",
            records: ["inventory.package_manager", "inventory.packages", "inventory.services", "inventory.vulnerabilities", "inventory.collected_at", "inventory.collection_source"],
            capabilities: ["system_inventory", "rootcheck"], retention: .whileEnrolled),
        ManifestCollector(
            id: "accounts", group: .inventory, title: "User accounts and groups",
            what: "Account names, numeric ids, whether an account is an administrator, and its login shell; group names. No passwords or password hashes.",
            why: "Access control: who can sign in to the computer and with what rights.",
            records: ["inventory.users", "inventory.groups"], capabilities: ["system_inventory"], retention: .whileEnrolled),
        ManifestCollector(
            id: "network_exposure", group: .inventory, title: "Listening ports and containers",
            what: "Protocol, port and state of listening sockets; container ids, names, images, states and runtimes; cloud provider, instance id and region when the machine runs in a cloud.",
            why: "Exposure and asset inventory controls.",
            records: ["inventory.listening_ports", "inventory.containers", "inventory.cloud_provider", "inventory.cloud_instance_id", "inventory.cloud_region"],
            // The Mac ships these inside the inventory section and announces no
            // separate container or cloud capability.
            capabilities: ["system_inventory"], retention: .whileEnrolled),
        ManifestCollector(
            id: "running_programs", group: .inventory, title: "Running programs",
            what: "For each process: id, program name, executable path, owning user id and state. Not the command line or arguments.",
            why: "Endpoint protection and unauthorized software controls.",
            records: ["inventory.processes"], capabilities: ["system_inventory"], retention: .whileEnrolled),
        ManifestCollector(
            id: "file_integrity", group: .inventory, title: "File integrity baselines",
            what: "For files in selected system locations: path, SHA-256 when readable within the size limit, size, permissions, modification time and status. File bodies are read locally for hashes and selected configuration values; raw bodies are not uploaded.",
            why: "Change detection on system configuration.",
            records: ["inventory.fim", "inventory.sca"], capabilities: ["file_integrity"], retention: .whileEnrolled),
        ManifestCollector(
            id: "ai_tools", group: .aiTools, title: "AI coding tools and MCP servers",
            what: "Which AI coding tools are installed (names), which MCP servers each client has configured (client, server name, where it is configured, transport), and which agent skills or instructions exist (client, kind, name, source). A declared config file over its read limit is reported as not scanned, by its fixed label. For each MCP server, what it runs: for a local server the package or image a known runner starts (npx, bunx, pnpm dlx, npm exec, uvx, pipx run, docker run) or else the program's file name; for a remote server only the URL's host name. Configuration files are read locally to derive these fields; argument values beyond that package name, environment variable values, headers, URL paths, query strings, tokens and skill or instruction bodies are not recorded.",
            why: "AI tool governance: knowing which agents and servers run on company machines.",
            records: ["inventory.agent_clis", "inventory.mcp_servers", "inventory.agent_assets", "inventory.ai_location_coverage"],
            capabilities: [], retention: .whileEnrolled),
        ManifestCollector(
            id: "process_events", group: .securityEvents, title: "Program starts and exits",
            what: "When a program starts or ends: program name, executable path, executable SHA-256 when computed, code signature identity, parent programs, and the rules it matched. The command line is read locally to evaluate rules and is omitted from recorded events.",
            why: "Detecting and investigating attacks (endpoint detection).",
            records: ["exec", "fork", "exit"], capabilities: ["segment_upload"], retention: .telemetryWindow),
        ManifestCollector(
            id: "network_events", group: .securityEvents, title: "Network connections and DNS lookups",
            what: "Outbound connections (program, source and destination address and port) and the domain names programs look up with the program that asked, from the system resolver's log, and the names of any assigned rules the lookup matched. Not page contents, messages or what was sent.",
            why: "Detecting command-and-control, data exfiltration and DNS tunnelling.",
            records: ["connect", "dns"], capabilities: ["segment_upload", "policy_dns"], retention: .telemetryWindow),
        ManifestCollector(
            id: "file_events", group: .securityEvents, title: "Changes in watched system locations",
            what: "The path, operation and program for changes under a fixed list of persistence and configuration locations (launch items, login items, profiles). Selected plist bodies are read locally for labels, programs and login-item details; raw bodies are not uploaded.",
            why: "Detecting persistence and tampering.",
            records: ["file"], capabilities: ["segment_upload"], retention: .telemetryWindow),
        ManifestCollector(
            id: "memory_and_privilege_events", group: .securityEvents, title: "Memory, privilege and system signals",
            what: "Memory-protection transitions and selected system calls with their numeric arguments, privacy-permission (TCC) changes and the operating system's own security verdicts. Program name and id only; no file contents or command lines.",
            why: "Detecting in-memory attacks, privilege escalation and sensor tampering.",
            records: ["security", "verdict"], capabilities: ["segment_upload"], retention: .telemetryWindow),
        ManifestCollector(
            id: "enforcement", group: .agent, title: "What the agent blocked or stopped",
            what: "When a signed rule blocks a program from starting, suspends or stops a running one: the program, the rule name and the outcome. Nothing is blocked unless the workspace assigned a rule that blocks.",
            why: "Evidence that endpoint protection acted, and a record of every action taken on this Mac.",
            records: ["deny", "kill"], capabilities: ["rules_sync"], retention: .telemetryWindow),
        ManifestCollector(
            id: "health", group: .agent, title: "Agent health",
            what: "How many events were kept or dropped, upload backlog and errors, and the agent version.",
            why: "Knowing the evidence stream is complete; a device that stopped reporting is a finding, not a pass.",
            records: ["health", "snapshot", "config", "check_in.health", "check_in.capabilities"],
            capabilities: ["segment_upload"], retention: .whileEnrolled),
    ]

    static let neverCollected: [ManifestNever] = [
        ManifestNever(
            claim: "Command lines and arguments in recorded process events",
            proof: "SpoolEvent.encode omits cmdline (EventEncodingTests.commandLinesStayLocal); inventory processes carry no command line"),
        ManifestNever(
            claim: "Raw file, document, message, skill or instruction bodies in uploaded records",
            proof: "file events contain metadata and selected plist fields; FIM, process and persistence providers read file bodies locally for hashes and selected fields; raw bodies are not encoded"),
        ManifestNever(
            claim: "MCP server arguments beyond the package name, environment variable values, headers, URL paths, query strings or tokens in uploaded records",
            proof: "bounded local config reads derive MCP client, name, source, transport, package and host; package is a package spec, image reference or program file name and host a URL host name (MCPIdentity.swift mcpStdioPackage and mcpRemoteHost; test discoveryCarriesIdentityWithoutSecrets); discovery never executes a CLI"),
        ManifestNever(
            claim: "Password and password-hash fields from account records",
            proof: "accounts are name, uid, admin, shell; posture evidence is a hash of what was read"),
        ManifestNever(
            claim: "Keystrokes, screen contents, camera or microphone",
            proof: "no provider opens input, display, video or audio devices; event taps are reported as a posture fact, never read"),
        ManifestNever(
            claim: "Web pages, chats or what you typed into them (domain names looked up are recorded; page contents are not)",
            proof: "dns events carry pid, uid, comm, the queried name and matched rule names; connect events carry addresses and ports"),
    ]

    static let local: [ManifestLocalStore] = [
        ManifestLocalStore(
            path: "/Library/Application Support/Merlin/spool",
            holds: "The event spool (merlin-events.jsonl and its finished segments): segments wait here until the server accepts them, then they are deleted."),
        ManifestLocalStore(
            path: "/Library/Application Support/Merlin",
            holds: "The device configuration merlin-configure installed (sync URL, device id, device credential, policy keys) and the signed rules the workspace assigned."),
        ManifestLocalStore(
            path: "/Library/Logs/Merlin/merlin.log",
            holds: "The daemon's log: health and errors only."),
    ]

    static let journal = "launchd keeps the daemon's standard output and error in /Library/Logs/Merlin/merlin.log: starts, provider attach, upload results, enforcement actions by rule name. Per-event details stay in the spool."

    /// The collectors declared as supported by this build, derived from its
    /// static check-in capabilities. A collector that lists no capability is
    /// always declared; the others are declared when any capability they name
    /// is present. This does not observe runtime collector state. Same rule as
    /// the Linux port's `manifest::active_collector_ids`.
    static func activeCollectorIds(capabilities: [String]) -> [String] {
        let announced = Set(capabilities)
        return collectors
            .filter { $0.capabilities.isEmpty || $0.capabilities.contains(where: announced.contains) }
            .map(\.id)
    }

    static func current() -> CollectionManifest {
        CollectionManifest(
            manifestVersion: version,
            agent: "merlin-macos",
            agentVersion: merlinAgentVersion,
            platform: "macos",
            collectors: collectors,
            neverCollected: neverCollected,
            local: local,
            journal: journal
        )
    }

    func renderText() -> String {
        var out = "Deixic Endpoint (\(agent) \(agentVersion)) collection manifest \(Self.versionLabel(manifestVersion))\n\nWhat it collects\n"
        for c in collectors {
            let kept = c.retention == .whileEnrolled
                ? "current device state, replaced on check-in; a tombstone remains after retirement/disposal"
                : "raw events, kept for the server's telemetry window"
            out += "  \(c.title)\n    \(c.what)\n    Why: \(c.why)\n    Kept: \(kept)\n"
        }
        out += "\nWhat it never collects\n"
        for n in neverCollected { out += "  - \(n.claim)\n" }
        out += "\nOn this Mac\n"
        for l in local { out += "  \(l.path): \(l.holds)\n" }
        out += "  Journal: \(journal)\n"
        return out
    }

    func renderJSON() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return String(decoding: try encoder.encode(self), as: UTF8.self)
    }
}
