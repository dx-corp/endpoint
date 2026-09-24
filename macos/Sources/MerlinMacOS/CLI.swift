// Deixic Endpoint telemetry and policy enforcement for macOS.
//
// Endpoint Security collects exec/exit/fork telemetry and provides
// synchronous AUTH_EXEC enforcement; a kqueue (EVFILT_PROC) provider
// provides entitlement-free telemetry when the ES entitlement is
// unavailable; an OpenBSM provider covers older macOS as a last resort; a
// YAML policy source compiles to platform-targeted artifacts; the macOS
// engine supports selectors and actions that are not available on Linux.
// Everything lands in an append-only JSONL spool.

import ArgumentParser
import Foundation

@main
struct Merlin: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "merlin-macos",
        abstract: "Deixic Endpoint: endpoint telemetry and policy enforcement for macOS",
        subcommands: [RunCommand.self, CheckCommand.self, PostureCommand.self, GenHashCommand.self,
                      MCPHookCommand.self]
    )
}

enum ProviderChoice: String, ExpressibleByArgument {
    case es, kqueue, bsm, auto
}

enum NetworkChoice: String, ExpressibleByArgument {
    case pktap, bpf, ne, none
}

struct RunCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "run",
        abstract: "Start the sensor: subscribe to exec/exit/fork events, enforce rules, spool JSONL."
    )

    @Option(help: "YAML rules file.")
    var rules: String = "rules/block-demo.yaml"

    @Option(help: "Append-only JSONL event spool.")
    var spool: String = "./merlin-events.jsonl"

    @Option(help: "Event provider: es, kqueue, bsm, or auto (try ES, then kqueue, then BSM).")
    var provider: ProviderChoice = .auto

    @Option(help: "Network telemetry: pktap, bpf, ne (optional packaged NetworkExtension), or none. Default: pktap when root, none otherwise.")
    var network: NetworkChoice?

    @Option(help: "Rotate the spool into compressed segments every N seconds (0 = off).")
    var segmentInterval: Int = 0

    @Option(help: "Rotate the spool when the live file exceeds N bytes (0 = off).")
    var segmentBytes: Int = 0

    @Option(help: "Emit a periodic health event with capability and loss counters (0 = off).")
    var healthInterval: Int = 10

    @Option(help: "Snapshot-diff interval in seconds (launchd items, listening ports, logged-in users; 0 = off).")
    var snapshotInterval: Int = 60

    @Option(help: "Posture sweep interval in seconds (full host-posture drift detection; 0 = off, suggest 3600).")
    var postureInterval: Int = 0

    @Option(help: "Team IDs of expected active system extensions — the posture sweep won't flag these. Repeatable.")
    var postureExpectedSysexTeams: [String] = []

    @Option(help: "Sync server base URL (e.g. https://sync.example.com). Off by default.")
    var sync: String?

	@Option(help: "Legacy unmanaged telemetry key (or env MERLIN_LEGACY_SYNC_KEY); managed devices do not use it.")
    var syncKey: String?

    @Option(help: "Registered device ID for managed check-ins (or env MERLIN_DEVICE_ID).")
    var deviceId: String?

    @Option(help: "Enrollment token for managed check-ins (or env MERLIN_DEVICE_TOKEN).")
    var deviceToken: String?

	@Option(help: "Trusted Ed25519 policy public key in hex (or env MERLIN_POLICY_PUBLIC_KEY).")
	var policyPublicKey: String?

	@Option(help: "Comma-separated trusted Ed25519 public keys for rotation (or env MERLIN_POLICY_PUBLIC_KEYS).")
	var policyPublicKeys: String?

    @Flag(help: "Disable the persistence-path watcher (LaunchAgents/LaunchDaemons/periodic file telemetry; on by default).")
    var noPersistenceWatch = false

    func run() throws {
        guard healthInterval >= 0 else {
            throw MerlinError.plain("--health-interval must be zero or a positive number of seconds")
        }
        // Only the kqueue provider works unprivileged; ES clients and
        // /dev/auditpipe require root.
        if geteuid() != 0 {
            switch provider {
            case .es:
                throw MerlinError.plain("the ES provider needs root; use sudo (or --provider kqueue)")
            case .bsm:
                throw MerlinError.plain("the BSM provider needs root for /dev/auditpipe; use sudo (or --provider kqueue)")
            case .kqueue, .auto:
                merlinLog("warn", "not running as root: cross-user enrichment and kill enforcement are limited to your own processes")
            }
        }
        let loaded = try Rules.load(path: rules)
        merlinLog("info", "loaded \(loaded.rules.count) rules from \(rules)")
        // One shared ruleset for every provider — the sync client
        // hot-reloads into it (last-known-good on any failure).
        let rulesBox = RulesBox(loaded)
        let spoolWriter = try SpoolWriter(path: spool)
        spoolWriter.startHealth(
            interval: TimeInterval(healthInterval),
            capabilities: [
                "endpoint_security_optional",
                "kqueue_fallback",
                "openbsm_legacy",
                "bpf_network_optional",
                "persistence_metadata",
                "bounded_spool",
            ]
        )
        if segmentInterval > 0 || segmentBytes > 0 {
            spoolWriter.segmentation = SegmentConfig(
                interval: TimeInterval(segmentInterval),
                maxBytes: Int64(segmentBytes)
            )
            merlinLog("info", "spool segmentation: interval=\(segmentInterval)s bytes=\(segmentBytes)")
        }

        // Network telemetry is orthogonal to the process provider; it runs
        // alongside whichever one started.
        let bpf = try startNetwork(rulesBox: rulesBox, spool: spoolWriter)
        defer { bpf?.stop() }

        // Unified-log providers (fail-open, work unprivileged on this host):
        // per-process DNS attribution and the OS's own security verdicts.
        var mdnsEngine = Engine(rulesBox: rulesBox, spool: spoolWriter, canBlock: false)
        mdnsEngine.source = "mdnsresponder-log"
        let mdns = MdnsLogProvider(engine: mdnsEngine)
        let verdicts = VerdictsProvider(spool: spoolWriter)
        let configWatcher = ConfigWatcher(spool: spoolWriter)
        do {
            try mdns.start()
        } catch {
            merlinLog("warn", "mDNSResponder log provider unavailable: \(error)")
        }
        do {
            try verdicts.start()
        } catch {
            merlinLog("warn", "verdicts provider unavailable: \(error)")
        }
        do {
            try configWatcher.start()
        } catch {
            merlinLog("warn", "config watch unavailable: \(error)")
        }
        defer {
            mdns.stop()
            verdicts.stop()
            configWatcher.stop()
        }

        // Sync client (off unless --sync is given): segment upload +
        // assigned policy delivery. Managed uploads use the device credential.
        let localStatus = LocalStatusStore()
        var syncClient: SyncClient?
        if let sync {
            guard let baseURL = URL(string: sync) else {
                throw MerlinError.plain("--sync: invalid base URL '\(sync)'")
            }
            let configuredDeviceId = deviceId ?? ProcessInfo.processInfo.environment["MERLIN_DEVICE_ID"]
            let configuredDeviceToken = deviceToken ?? ProcessInfo.processInfo.environment["MERLIN_DEVICE_TOKEN"]
			let key = syncKey ?? ProcessInfo.processInfo.environment["MERLIN_LEGACY_SYNC_KEY"]
			let configuredPolicyPublicKey = policyPublicKey ?? ProcessInfo.processInfo.environment["MERLIN_POLICY_PUBLIC_KEY"]
			let configuredPolicyPublicKeys = (policyPublicKeys ?? ProcessInfo.processInfo.environment["MERLIN_POLICY_PUBLIC_KEYS"])?
				.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty } ?? []
            guard (configuredDeviceId == nil) == (configuredDeviceToken == nil) else {
                throw MerlinError.plain("managed check-ins require both --device-id and --device-token (or both environment variables)")
            }
			if configuredDeviceId != nil && configuredPolicyPublicKey == nil && configuredPolicyPublicKeys.isEmpty {
				throw MerlinError.plain("managed policy delivery requires --policy-public-key or --policy-public-keys")
			}
			if configuredPolicyPublicKey.map({ Data(hexString: $0)?.count != 32 }) == true ||
				configuredPolicyPublicKeys.contains(where: { Data(hexString: $0)?.count != 32 }) {
				throw MerlinError.plain("every managed policy public key must be 32-byte hex")
			}
			if configuredDeviceId == nil && key == nil {
				throw MerlinError.plain("--sync requires managed device credentials or --sync-key/MERLIN_LEGACY_SYNC_KEY")
			}
            let initialHash = readFileNoFollow(path: rules, maxBytes: 4 << 20).map { sha256Hex($0) } ?? ""
            let client = SyncClient(
                config: SyncConfig(
                    baseURL: baseURL,
                    keyHex: key ?? "",
                    hostId: syncHostId(),
					deviceId: configuredDeviceId,
					deviceToken: configuredDeviceToken,
					policyPublicKeyHex: configuredPolicyPublicKey,
					policyPublicKeyHexes: configuredPolicyPublicKeys
                ),
                spoolPath: spool, rulesPath: rules, rulesBox: rulesBox,
                initialRulesHash: initialHash, localStatus: localStatus
            )
            client.start()
            syncClient = client
        }

        // Optional read-only GUI status. Unsigned/development collectors do not
        // expose privileged IPC; telemetry continues independently.
        let statusService: LocalStatusService?
        do {
            let service = try LocalStatusService(store: localStatus)
            service.start()
            statusService = service
        } catch {
            statusService = nil
            merlinLog("warn", "local device status unavailable: signed root collector required")
        }
        defer { statusService?.stop() }

        // Persistence-path watcher (file telemetry), on by default.
        var watcher: PersistenceWatcher?
        if !noPersistenceWatch {
            let targets = persistenceWatchTargets(root: geteuid() == 0)
            watcher = PersistenceWatcher(dirs: targets.dirs, files: targets.files, onEvent: spoolFileEvent(spoolWriter))
            merlinLog("info", "persistence watch: \(targets.dirs.count) dirs + \(targets.files.count) files (pid attribution unavailable)")
        }
        // Snapshot-diff inventory (telemetry only), default 60s.
        var snapshotter: Snapshotter?
        if snapshotInterval > 0 {
            let s = Snapshotter(spool: spoolWriter, interval: TimeInterval(snapshotInterval))
            s.start()
            snapshotter = s
        }
        // Posture sweep (telemetry only), opt-in via --posture-interval.
        var postureWatcher: PostureWatcher?
        if postureInterval > 0 {
            let w = PostureWatcher(spool: spoolWriter, interval: TimeInterval(postureInterval), expectedSysexTeams: postureExpectedSysexTeams)
            w.start()
            postureWatcher = w
        }
        // The provider stays alive in this frame: parkUntilSignal() never
        // returns. Keep the persistence watcher alive for the same lifetime;
        // an empty withExtendedLifetime closure would allow ARC to release it
        // before the provider enters its event loop in optimized builds.
        try withExtendedLifetime(postureWatcher) {
        try withExtendedLifetime(snapshotter) {
            try withExtendedLifetime(watcher) {
            try withExtendedLifetime(syncClient) {
            switch provider {
        case .es:
            let p = try makeES(rulesBox: rulesBox, spool: spoolWriter, localStatus: localStatus)
            merlinLog("info", "merlin is running; ctrl-c to stop")
            withExtendedLifetime(p) { parkUntilSignal() }
        case .kqueue:
            let p = try makeKqueue(rulesBox: rulesBox, spool: spoolWriter, localStatus: localStatus)
            merlinLog("info", "merlin is running; ctrl-c to stop")
            withExtendedLifetime(p) { parkUntilSignal() }
        case .bsm:
            let p = try makeBSM(rulesBox: rulesBox, spool: spoolWriter, localStatus: localStatus)
            merlinLog("info", "merlin is running; ctrl-c to stop")
            withExtendedLifetime(p) { parkUntilSignal() }
        case .auto:
            do {
                let p = try makeES(rulesBox: rulesBox, spool: spoolWriter, localStatus: localStatus)
                merlinLog("info", "merlin is running; ctrl-c to stop")
                withExtendedLifetime(p) { parkUntilSignal() }
            } catch {
                merlinLog("warn", "ES provider unavailable: \(error)")
                merlinLog("warn", "falling back to kqueue provider (telemetry only)")
                do {
                    let p = try makeKqueue(rulesBox: rulesBox, spool: spoolWriter, localStatus: localStatus)
                    merlinLog("info", "merlin is running; ctrl-c to stop")
                    withExtendedLifetime(p) { parkUntilSignal() }
                } catch {
                    // BSM is LAST: OpenBSM is deprecated since macOS 11,
                    // disabled since macOS 14 and emits zero exec records on
                    // macOS 27 (auditd runs but the trail is inert). Kept
                    // only for older systems where it still works.
                    merlinLog("warn", "kqueue provider unavailable: \(error)")
                    merlinLog("warn", "falling back to OpenBSM provider (telemetry only; dead on macOS 14+)")
                    let p = try makeBSM(rulesBox: rulesBox, spool: spoolWriter, localStatus: localStatus)
                    merlinLog("info", "merlin is running; ctrl-c to stop")
                    withExtendedLifetime(p) { parkUntilSignal() }
                }
            }
            }
        }
        }
        }
        }
    }

    private func makeES(rulesBox: RulesBox, spool: SpoolWriter, localStatus: LocalStatusStore) throws -> ESProvider {
        var engine = Engine(rulesBox: rulesBox, spool: spool, canBlock: true)
        engine.onEnforcement = { action, alternative in
            localStatus.recordEnforcement(action: action, approvedName: alternative?.name, approvedURL: alternative?.url)
        }
        let provider = ESProvider(engine: engine)
        try provider.start()
        merlinLog("info", "provider: Endpoint Security (AUTH_EXEC enforcement active)")
        return provider
    }

    /// Start network telemetry per --network (default: pktap when root,
    /// falling back to bpf). Explicit choice without root is a hard
    /// error; auto mode degrades to a warning (process telemetry still
    /// runs).
    private func startNetwork(rulesBox: RulesBox, spool: SpoolWriter) throws -> (any NetworkProviding)? {
        let choice: NetworkChoice = network ?? (geteuid() == 0 ? .pktap : .none)
        switch choice {
        case .none:
            if network == nil {
                merlinLog("info", "network telemetry disabled: --network pktap|bpf needs root for /dev/bpf")
            }
            return nil
        case .pktap:
            let engine = Engine(rulesBox: rulesBox, spool: spool, canBlock: false)
            let provider = PktapProvider(engine: engine)
            do {
                try provider.start()
                return provider
            } catch {
                if network != nil { throw error } // explicit request
                merlinLog("warn", "pktap unavailable (\(error)); falling back to /dev/bpf interface capture")
                let bpfProvider = BpfProvider(engine: engine)
                try? bpfProvider.start()
                return bpfProvider
            }
        case .bpf:
            let engine = Engine(rulesBox: rulesBox, spool: spool, canBlock: false)
            let provider = BpfProvider(engine: engine)
            do {
                try provider.start()
                return provider
            } catch {
                if network != nil { throw error } // explicit request
                merlinLog("warn", "network telemetry unavailable: \(error)")
                return nil
            }
        case .ne:
            let capability = networkExtensionCapability()
            throw MerlinError.plain("NetworkExtension is \(capability.state): \(capability.reason). Use --network pktap or --network bpf until the signed extension is installed.")
        }
    }

    private func makeKqueue(rulesBox: RulesBox, spool: SpoolWriter, localStatus: LocalStatusStore) throws -> KqueueProvider {
        var engine = Engine(rulesBox: rulesBox, spool: spool, canBlock: false)
        engine.onEnforcement = { action, alternative in
            localStatus.recordEnforcement(action: action, approvedName: alternative?.name, approvedURL: alternative?.url)
        }
        let degraded = engine.degradedBlockRuleNames()
        if !degraded.isEmpty {
            merlinLog("warn", "block rules \(degraded) cannot deny execs under the kqueue provider; degrading to kill+log")
        }
        let provider = KqueueProvider(engine: engine)
        try provider.start()
        merlinLog("info", "provider: kqueue EVFILT_PROC (telemetry only)")
        return provider
    }

    private func makeBSM(rulesBox: RulesBox, spool: SpoolWriter, localStatus: LocalStatusStore) throws -> BSMProvider {
        var engine = Engine(rulesBox: rulesBox, spool: spool, canBlock: false)
        engine.onEnforcement = { action, alternative in
            localStatus.recordEnforcement(action: action, approvedName: alternative?.name, approvedURL: alternative?.url)
        }
        let degraded = engine.degradedBlockRuleNames()
        if !degraded.isEmpty {
            merlinLog("warn", "block rules \(degraded) cannot deny execs under the BSM provider; degrading to kill+log")
        }
        let provider = BSMProvider(engine: engine)
        try provider.start()
        return provider
    }
}

struct CheckCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "check",
        abstract: "Probe ES entitlement, BSM auditpipe, and root status; print readiness."
    )

    @Flag(help: "Emit one machine-readable JSON capability report.")
    var json = false

    func run() throws {
        Foundation.exit(runCheck(json: json))
    }
}

struct PostureCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "posture",
        abstract: "Full host-posture sweep: integrity, proxy/DNS, sysext, profiles, hooks, launchd, event taps."
    )

    @Flag(help: "Emit the sweep as JSON.")
    var json = false

    @Flag(help: "Include top-5 CPU processes and disk usage.")
    var verbose = false

    @Option(help: "Team IDs of expected active system extensions — the sweep won't flag these. Repeatable.")
    var expectedSysexTeams: [String] = []

    func run() throws {
        Foundation.exit(runPosture(json: json, verbose: verbose, expectedSysexTeams: expectedSysexTeams))
    }
}

struct GenHashCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "gen-hash",
        abstract: "Print the sha256 (and cdhash, if signed) of a file, ready to paste into a rules file."
    )

    @Argument(help: "File to hash.")
    var path: String

    func run() throws {
        let hash = try sha256File(path: path)
        print("\(hash)  \(path)")
        if let cd = cdhashForFile(path: path) {
            print("cdhash: \(cd)")
        } else {
            print("cdhash: <unsigned or unavailable>")
        }
    }
}

/// Park the main thread until SIGINT/SIGTERM.
func parkUntilSignal() -> Never {
    signal(SIGINT, SIG_IGN)
    signal(SIGTERM, SIG_IGN)
    let int = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
    int.setEventHandler {
        SuspendedPids.shared.releaseAll()
        merlinLog("info", "shutting down")
        Foundation.exit(0)
    }
    int.resume()
    let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
    term.setEventHandler {
        SuspendedPids.shared.releaseAll()
        merlinLog("info", "shutting down")
        Foundation.exit(0)
    }
    term.resume()
    dispatchMain()
}
