// Shared sensor core: rules + spool + rule application, provider-agnostic.
// Mirrors the Linux daemon's telemetry/fanotify split:
//   authVerdict  ≈ fanotify_mon handle_event (synchronous allow/deny)
//   handleExec   ≈ telemetry handle_exec (log/kill rules + spool)

import Foundation
import MerlinClientCore

/// Hot-swappable rules container: the sync client replaces the ruleset
/// atomically; readers see a consistent snapshot (AGENTS.md — a half-
/// parsed policy must never take effect).
final class RulesBox: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Rules

    init(_ rules: Rules) {
        stored = rules
    }

    var current: Rules {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }

    func update(_ rules: Rules) {
        lock.lock()
        stored = rules
        lock.unlock()
    }
}

struct Engine: Sendable {
    let rulesBox: RulesBox
    var rules: Rules { rulesBox.current }
    let spool: SpoolWriter
    /// false under the BSM provider, which is telemetry-only: `block` rules
    /// degrade to kill (with a startup warning), like a kill rule.
    let canBlock: Bool
    /// `source` stamped on spooled events (e.g. "mdnsresponder-log").
    var source: String = "macos"
    /// Indirection for tests; production is Darwin.kill(pid, SIGKILL).
    var killImpl: @Sendable (Int32) -> Int32 = { Darwin.kill($0, SIGKILL) }
    var selfPID: Int32 = getpid()
    /// The daemon's own signing team, for the own-team failsafe.
    var ownTeamId: String? = Engine.detectOwnTeamId()
    /// Indirection for tests; production re-reads the pid's start time before
    /// every kill decision.
    var processIdentity: @Sendable (Int32) -> ProcessIdentity? = { procInfo($0)?.identity }
    /// Signals (SIGSTOP/SIGCONT) for the suspend path; injectable for tests.
    var signalImpl: @Sendable (Int32, Int32) -> Int32 = { Darwin.kill($0, $1) }
    /// Freeze budget for the suspend cycle: enrichment+evaluation beyond
    /// this resumes the process immediately (AGENTS.md: a wedged sensor
    /// must never leave frozen processes around).
    var suspendBudget: TimeInterval = 2.0
    /// sha256 files larger than this are not hashed at the suspend
    /// enrichment point (bounded work per event).
    var suspendHashMaxBytes: Int64 = 64 << 20
    let signingCache = SigningInfoCache()
    var onEnforcement: @Sendable (LocalEnforcementAction, ApprovedAlternative?) -> Void = { _, _ in }

    /// Convenience for existing call sites/tests: wraps a static ruleset
    /// (no hot-reload needed).
    init(
        rules: Rules, spool: SpoolWriter, canBlock: Bool,
        killImpl: @escaping @Sendable (Int32) -> Int32 = { Darwin.kill($0, SIGKILL) },
        selfPID: Int32 = getpid(),
        ownTeamId: String? = Engine.detectOwnTeamId(),
        processIdentity: @escaping @Sendable (Int32) -> ProcessIdentity? = { procInfo($0)?.identity }
    ) {
        rulesBox = RulesBox(rules)
        self.spool = spool
        self.canBlock = canBlock
        self.killImpl = killImpl
        self.selfPID = selfPID
        self.ownTeamId = ownTeamId
        self.processIdentity = processIdentity
    }

    init(rulesBox: RulesBox, spool: SpoolWriter, canBlock: Bool) {
        self.rulesBox = rulesBox
        self.spool = spool
        self.canBlock = canBlock
    }

    /// Team id of the running daemon binary (nil when unsigned/adhoc).
    static func detectOwnTeamId() -> String? {
        var buf = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard proc_pidpath(getpid(), &buf, UInt32(buf.count)) > 0 else { return nil }
        let path = String(decoding: buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
        return signingInfo(path: path)?.teamId
    }

    struct Verdict {
        let allow: Bool
        let matched: [String]
    }

    /// Santa-style failsafes: the engine must NEVER kill or block pid 1,
    /// itself, or — when the team is known — a process signed by the
    /// daemon's own team (that would let a rule brick the sensor).
    func isFailsafe(pid: Int32, teamId: String?) -> Bool {
        if pid == 1 || pid == selfPID { return true }
        if let ownTeamId, let teamId, teamId == ownTeamId { return true }
        return false
    }

    /// `block` rules that cannot be enforced by this provider.
    func degradedBlockRuleNames() -> [String] {
        guard !canBlock else { return [] }
        return rules.rules.filter { $0.action == .block }.map(\.name)
    }

    private func effective(_ action: Action) -> Action {
        action == .block && !canBlock ? .kill : action
    }

    /// A tied enforcing rule with no guidance must not hide another rule's
    /// configured alternative. Resolve conflicting guidance independently of
    /// policy file order, without changing which rules enforce or get logged.
    private func approvedAlternative(from enforcedRules: [Rule]) -> ApprovedAlternative? {
        let candidates = enforcedRules.compactMap { rule -> (name: String, alternative: ApprovedAlternative)? in
            guard let alternative = rule.approvedAlternative else { return nil }
            return (rule.name, alternative)
        }
        return candidates.min { lhs, rhs in
            if lhs.name != rhs.name { return lhs.name < rhs.name }
            if lhs.alternative.name != rhs.alternative.name {
                return lhs.alternative.name < rhs.alternative.name
            }
            return lhs.alternative.url.absoluteString < rhs.alternative.url.absoluteString
        }?.alternative
    }

    /// Only hash at the AUTH point when some block rule selects on sha256 —
    /// hashing every executed binary system-wide would be wasted work
    /// otherwise (same policy as the Linux fanotify monitor).
    var needsSHA256ForAuth: Bool {
        canBlock && rules.rules.contains { $0.action == .block && $0.hasSHA256Selector }
    }

    var needsSHA256ForNotify: Bool {
        rules.rules.contains { effective($0.action) != .block && $0.hasSHA256Selector }
    }

    /// Cached network attribution must be re-confirmed against the live fd
    /// table before it is handed out when a kill rule is active.
    var needsFreshNetworkAttribution: Bool {
        rules.rules.contains { effective($0.action) == .kill }
    }

    /// Signing selectors (team_id/signing_id/is_platform_binary) at the
    /// AUTH point — the ES auth handler only pays for SecStaticCode when
    /// some block rule actually selects on them.
    var needsSigningForAuth: Bool {
        canBlock && rules.rules.contains { $0.action == .block && $0.hasSigningSelector }
    }

    /// Synchronous AUTH_EXEC decision (ES provider only). Spools a `deny`
    /// event on a deny verdict.
    func authVerdict(pid: Int32, uid: UInt32?, path: String, sha256: String?, cdhash: String?, teamId: String? = nil) -> Verdict {
        let ctx = MatchCtx(
            sha256: sha256,
            basename: (path as NSString).lastPathComponent,
            path: path,
            uid: uid,
            cdhash: cdhash,
            teamId: teamId
        )
        let matchedRules = mostSpecific(rules.rules.filter { $0.action == .block && $0.matches(ctx) })
        let matched = matchedRules.map(\.name)
        if matched.isEmpty { return Verdict(allow: true, matched: []) }
        if isFailsafe(pid: pid, teamId: teamId) {
            merlinLog("warn", "failsafe: block rules \(matched) matched pid \(pid) (\(path)) but it is protected (launchd/self/own team)")
            return Verdict(allow: true, matched: [])
        }
        let identity = processIdentity(pid)
        spool.write(SpoolEvent(
            kind: .deny, pid: pid, uid: uid, path: path,
            sha256: sha256, cdhash: cdhash, matchedRules: matched,
            pidStartSec: identity?.startSec, pidStartUsec: identity?.startUsec
        ))
        onEnforcement(.blocked, approvedAlternative(from: matchedRules))
        return Verdict(allow: false, matched: matched)
    }

    /// NOTIFY_EXEC handling (both providers): apply log/kill rules, spool
    /// the exec event (and a `kill` event per SIGKILLed process). Kill has
    /// the same race window as the Linux port: the exec already happened.
    /// `signing`/`quarantined`/`platformBinary` are the SecStaticCode/
    /// xattr/csops enrichment (nil when undetermined).
    func handleExec(
        pid: Int32, ppid: Int32?, uid: UInt32?, comm: String, exe: String,
        cmdline: String?, sha256: String?, cdhash: String?,
        signing: SigningInfo? = nil, quarantined: Bool? = nil,
        platformBinary: Bool? = nil, identity: ProcessIdentity? = nil
    ) {
        let platform = platformBinary ?? signing?.platformBinary
        let chain = ancestorChain(fromPPID: ppid)
        let ctx = MatchCtx(
            sha256: sha256,
            basename: (exe as NSString).lastPathComponent,
            path: exe,
            cmdline: cmdline,
            uid: uid,
            cdhash: cdhash ?? signing?.cdhash,
            teamId: signing?.teamId,
            signingId: signing?.signingId,
            isPlatformBinary: platform,
            unsigned: signing?.unsigned,
            parentBasename: chain.first?.comm,
            ancestorComms: chain.compactMap(\.comm),
            comm: comm
        )
        var logged: [String] = []
        var killed: [String] = []
        var killedViaSuspend = false
        var releasedBySuspend = false
        // A fired suspend rule owns the kill decision for this event:
        // plain kill rules are deferred to the frozen second stage. If
        // the suspend cycle couldn't run (failsafe, SIGSTOP failure, or
        // a budget/identity error that resumed the process), the plain
        // reactive kill path proceeds as a fallback.
        var killsDeferred = false
        var suspendRan = false
        let matched = mostSpecific(rules.rules.filter { effective($0.action) != .block && $0.matches(ctx) })
        for rule in matched where effective(rule.action) == .suspend {
            guard !suspendRan else { continue } // one cycle per event
            suspendRan = true
            if isFailsafe(pid: pid, teamId: ctx.teamId) {
                merlinLog("warn", "failsafe: suspend rule \(rule.name) matched pid \(pid) (\(exe)) but it is protected (launchd/self/own team)")
                continue
            }
            switch suspendCycle(pid: pid, exe: exe, uid: uid, comm: comm, baseCtx: ctx, identity: identity) {
            case .killed(let names):
                killed += names
                killedViaSuspend = true
                killsDeferred = true
            case .released:
                releasedBySuspend = true
                killsDeferred = true
            case .resumedAfterError:
                killsDeferred = true
            case .notSuspended:
                break
            }
        }
        for rule in matched where effective(rule.action) != .suspend {
            switch effective(rule.action) {
            case .log:
                logged.append(rule.name)
            case .kill:
                guard !killsDeferred else { continue }
                guard let identity, processIdentity(pid) == identity else {
                    merlinLog("warn", "kill(\(pid)) skipped: process identity changed or is unavailable")
                    continue
                }
                if isFailsafe(pid: pid, teamId: ctx.teamId) {
                    merlinLog("warn", "failsafe: kill rule \(rule.name) matched pid \(pid) (\(exe)) but it is protected (launchd/self/own team)")
                    continue
                }
                if killImpl(pid) == 0 {
                    killed.append(rule.name)
                } else {
                    merlinLog("warn", "kill(\(pid)) failed: errno \(errno)")
                }
            case .block, .suspend:
                break
            }
        }
        var execSignals: [String] = []
        if exe.hasPrefix("/memfd:") || exe.contains("/memfd:") {
            execSignals.append("fileless_execution")
        }
        if exe.contains(" (deleted)") {
            execSignals.append("deleted_executable")
        }
        spool.write(SpoolEvent(
            kind: .exec, pid: pid, ppid: ppid, uid: uid, comm: comm, exe: exe,
            cmdline: cmdline, sha256: sha256, cdhash: cdhash ?? signing?.cdhash,
            matchedRules: logged, ancestors: chain,
            pidStartSec: identity?.startSec, pidStartUsec: identity?.startUsec,
            signals: execSignals.isEmpty ? nil : execSignals,
            quarantined: quarantined, unsigned: signing?.unsigned,
            isPlatformBinary: platform,
            suspendReleased: releasedBySuspend ? true : nil
        ))
        if !killed.isEmpty {
            merlinLog("info", "SIGKILL pid=\(pid) comm=\(comm) rules=\(killed)\(killedViaSuspend ? " (via suspend)" : "")")
            spool.write(SpoolEvent(
                kind: .kill, pid: pid, uid: uid, comm: comm, exe: exe,
                matchedRules: killed,
                pidStartSec: identity?.startSec, pidStartUsec: identity?.startUsec,
                viaSuspend: killedViaSuspend ? true : nil
            ))
            let enforcingRules = matched.filter { effective($0.action) == .kill && killed.contains($0.name) }
            if !enforcingRules.isEmpty {
                onEnforcement(.stopped, approvedAlternative(from: enforcingRules))
            }
        }
    }

    enum SuspendOutcome {
        case killed([String])
        case released
        case resumedAfterError
        case notSuspended
    }

    /// Stop → enrich (frozen) → re-evaluate → kill or continue. Every
    /// guardrail in Suspend.swift's header applies here; any deviation
    /// from the happy path resumes the process.
    private func suspendCycle(
        pid: Int32, exe: String, uid: UInt32?, comm: String,
        baseCtx: MatchCtx, identity: ProcessIdentity?
    ) -> SuspendOutcome {
        let started = nowTs()
        func overBudget() -> Bool { nowTs() - started > suspendBudget }
        func resume(_ why: String) -> SuspendOutcome {
            guard processIdentity(pid) == identity else {
                merlinLog("warn", "suspend: SIGCONT \(pid) skipped because process identity changed or is unavailable (\(why))")
                return .resumedAfterError
            }
            _ = signalImpl(pid, SIGCONT)
            merlinLog("warn", "suspend: resumed pid \(pid) (\(why))")
            return .resumedAfterError
        }

        guard let identity, processIdentity(pid) == identity else {
            merlinLog("warn", "suspend: SIGSTOP \(pid) skipped because process identity changed or is unavailable")
            return .notSuspended
        }
        guard signalImpl(pid, SIGSTOP) == 0 else {
            merlinLog("warn", "suspend: SIGSTOP \(pid) failed: errno \(errno)")
            return .notSuspended
        }
        SuspendedPids.shared.hold(pid, identity: identity)
        defer { SuspendedPids.shared.release(pid) }

        // Full enrichment on the frozen process (bounded).
        if overBudget() { return resume("freeze budget exceeded before enrichment") }
        var frozenSha256 = baseCtx.sha256
        if frozenSha256 == nil {
            var st = stat()
            if stat(exe, &st) == 0, st.st_size <= suspendHashMaxBytes {
                frozenSha256 = try? sha256File(path: exe)
            } else if stat(exe, &st) == 0 {
                merlinLog("warn", "suspend: \(exe) exceeds hash bound; skipping sha256")
            }
        }
        if overBudget() { return resume("freeze budget exceeded during enrichment") }
        let signing = signingCache.info(path: exe)
        let ctx2 = MatchCtx(
            sha256: frozenSha256,
            basename: baseCtx.basename,
            path: baseCtx.path,
            cmdline: baseCtx.cmdline,
            uid: baseCtx.uid,
            cdhash: signing?.cdhash ?? baseCtx.cdhash,
            daddr: baseCtx.daddr,
            dport: baseCtx.dport,
            dns: baseCtx.dns,
            teamId: signing?.teamId ?? baseCtx.teamId,
            signingId: signing?.signingId ?? baseCtx.signingId,
            isPlatformBinary: signing?.platformBinary ?? baseCtx.isPlatformBinary,
            unsigned: signing?.unsigned ?? baseCtx.unsigned,
            parentBasename: baseCtx.parentBasename,
            ancestorComms: baseCtx.ancestorComms,
            comm: baseCtx.comm
        )
        if overBudget() { return resume("freeze budget exceeded during evaluation") }

        // Second stage: the decision is made by KILL rules only. The
        // triggering suspend rule always re-matches the enriched ctx —
        // counting it would kill every inspected process, contradicting
        // "stop and inspect" (guardrail: no kill-rule match = resume).
        let matched = mostSpecific(rules.rules.filter {
            effective($0.action) == .kill && $0.matches(ctx2)
        })
        if matched.isEmpty {
            guard processIdentity(pid) == identity else {
                return resume("process identity changed or unavailable before release")
            }
            guard signalImpl(pid, SIGCONT) == 0 else {
                merlinLog("warn", "suspend: SIGCONT \(pid) failed: errno \(errno)")
                return .resumedAfterError
            }
            return .released
        }
        // Identity re-validation before the kill, same as the kill path.
        guard processIdentity(pid) == identity else {
            return resume("process identity changed or unavailable after enrichment")
        }
        if isFailsafe(pid: pid, teamId: ctx2.teamId) {
            return resume("failsafe after enrichment (launchd/self/own team)")
        }
        guard killImpl(pid) == 0 else {
            merlinLog("warn", "suspend: kill(\(pid)) failed: errno \(errno); resuming")
            return resume("SIGKILL failed")
        }
        return .killed(matched.map(\.name))
    }

    /// NOTIFY_EXIT. `status` is the raw wait(2)-style status; exit_status is
    /// (status >> 8) & 0xff, same formula as the Linux port's do_exit code.
    func handleExit(pid: Int32, uid: UInt32?, comm: String?, status: Int32?, identity: ProcessIdentity? = nil) {
        spool.write(SpoolEvent(
            kind: .exit, pid: pid, uid: uid, comm: comm,
            exitCode: status, exitStatus: status.map { ($0 >> 8) & 0xff },
            pidStartSec: identity?.startSec, pidStartUsec: identity?.startUsec
        ))
    }

    func handleFork(pid: Int32, ppid: Int32, comm: String?, exe: String?, identity: ProcessIdentity? = nil) {
        let parentIdentity = processIdentity(ppid)
        spool.write(SpoolEvent(
            kind: .fork, pid: pid, ppid: ppid, comm: comm, exe: exe,
            pidStartSec: identity?.startSec, pidStartUsec: identity?.startUsec,
            parentPidStartSec: parentIdentity?.startSec,
            parentPidStartUsec: parentIdentity?.startUsec
        ))
    }

    /// Well-known public DoH resolver addresses (Do53 is also their
    /// business — the tag is about port 443/853 traffic to them).
    /// Additive-extendable via the rules-file `doh_resolvers:` list.
    static let builtinDohResolvers: Set<String> = [
        "1.1.1.1", "1.0.0.1", // Cloudflare
        "8.8.8.8", "8.8.4.4", // Google
        "9.9.9.9", // Quad9
        "2606:4700:4700::1111", "2606:4700:4700::1001",
        "2001:4860:4860::8888", "2001:4860:4860::8844",
        "2620:fe::fe", "2620:fe::9",
    ]

    /// A connect to a known DoH resolver on 443 (DoH) or 853 (DoT).
    func isDohSuspect(daddr: String, dport: UInt16) -> Bool {
        guard dport == 443 || dport == 853 else { return false }
        return Engine.builtinDohResolvers.contains(daddr) || rules.dohResolvers.contains(daddr)
    }

    /// New outbound flow (BPF provider). Spools a `connect` event in the
    /// Linux schema (no matched_rules key there); log/kill rules still
    /// apply on comm/uid, with kills spooled as separate `kill` events —
    /// the same post-fact enforcement window as kill-on-exec.
    func handleConnect(
        pid: Int32?, uid: UInt32?, comm: String?, identity: ProcessIdentity?,
        saddr: String, daddr: String, sport: UInt16? = nil, dport: UInt16,
        family: UInt16? = nil, protocolNumber: UInt8? = nil,
        oldState: String? = nil, state: String? = nil, viaPid: Int32? = nil
    ) {
        let ctx = MatchCtx(basename: comm, uid: uid, daddr: daddr, dport: dport, comm: comm)
        let killed = applyNetworkRules(ctx: ctx, pid: pid, uid: uid, comm: comm, identity: identity, via: "connect \(saddr) -> \(daddr):\(dport)")
        let doh = isDohSuspect(daddr: daddr, dport: dport)
        if doh {
            merlinLog("info", "DoH-suspect connect \(saddr) -> \(daddr):\(dport) comm=\(comm ?? "?")")
        }
        spool.write(SpoolEvent(
            kind: .connect, source: source, pid: pid, uid: uid, comm: comm,
            saddr: saddr, daddr: daddr, sport: sport, dport: dport,
            family: family, protocolNumber: protocolNumber,
            oldState: oldState, state: state,
            pidStartSec: identity?.startSec, pidStartUsec: identity?.startUsec,
            dohSuspect: doh ? true : nil,
            viaSystemResolver: comm == "mDNSResponder" ? true : nil,
            viaPid: viaPid
        ))
        spoolKills(killed, pid: pid, uid: uid, comm: comm, identity: identity)
    }

    /// DNS query or response (BPF provider, UDP/53 and TCP/53). log/kill
    /// rules apply on comm/uid (and the dns_contains selector); a kill
    /// rule without attribution spools the event and logs why it can't
    /// fire. own_resolver: the attributed process is NOT the system
    /// resolver (an app doing its own DNS — a detection signal).
    /// via_system_resolver: attribution IS mDNSResponder, whose cache and
    /// proxying make the true originator unknowable from bpf.
    func handleDns(pid: Int32?, uid: UInt32?, comm: String?, identity: ProcessIdentity?, msg: DnsMessage, viaPid: Int32? = nil) {
        let ctx = MatchCtx(basename: comm, uid: uid, dns: msg.qname, comm: comm)
        let via = "dns \(msg.direction) \(msg.qname)"
        let killed = applyNetworkRules(ctx: ctx, pid: pid, uid: uid, comm: comm, identity: identity, via: via)
        spool.write(SpoolEvent(
            kind: .dns, source: source, pid: pid, uid: uid, comm: comm,
            query: msg.qname, qtype: msg.qtypeName,
            direction: msg.direction, rcode: msg.rcode,
            pidStartSec: identity?.startSec, pidStartUsec: identity?.startUsec,
            ownResolver: comm != nil && comm != "mDNSResponder" ? true : nil,
            viaSystemResolver: comm == "mDNSResponder" ? true : nil,
            viaPid: viaPid
        ))
        spoolKills(killed, pid: pid, uid: uid, comm: comm, identity: identity)
    }

    /// Security-transition telemetry from Endpoint Security. These events
    /// are intentionally observe-only: the provider's fail-open boundary is
    /// preserved, while the evidence records the exact transition and the
    /// process identity that produced it.
    func handleSecurity(
        pid: Int32?, uid: UInt32?, comm: String?, syscall: String,
        syscallNumber: UInt32?, args: [UInt64]?, wXTransition: Bool?,
        namespaceValid: Bool? = nil, identity: ProcessIdentity? = nil
    ) {
        spool.write(SpoolEvent(
            kind: .security, pid: pid, uid: uid, comm: comm,
            syscall: syscall, syscallNumber: syscallNumber, args: args,
            wXTransition: wXTransition, namespaceValid: namespaceValid,
            pidStartSec: identity?.startSec, pidStartUsec: identity?.startUsec,
            signals: securitySignals(syscall: syscall, wXTransition: wXTransition)
        ))
    }

    /// TCC changes are high-value security telemetry, but the identity is
    /// pseudonymized before it reaches the spool. The service and decision
    /// metadata remain available for correlation without uploading TCC rows,
    /// account names, or executable paths.
    func handleTCCModify(
        pid: Int32?, uid: UInt32?, comm: String?, service: String,
        identityHash: String, identityType: String, updateType: String,
        right: String, reason: String, identity: ProcessIdentity? = nil
    ) {
        spool.write(SpoolEvent(
            kind: .security, pid: pid, uid: uid, comm: comm,
            syscall: "tcc_modify", tccService: service,
            tccIdentityHash: identityHash, tccIdentityType: identityType,
            tccUpdateType: updateType, tccRight: right, tccReason: reason,
            pidStartSec: identity?.startSec, pidStartUsec: identity?.startUsec,
            signals: ["tcc_change", "tcc_" + updateType]
        ))
    }

    /// File mutation telemetry from Endpoint Security. The file identity is
    /// captured from the kernel-provided stat tuple; file contents are never
    /// read by this path.
    func handleFile(
        pid: Int32?, uid: UInt32?, path: String?, op: String,
        label: String? = nil, program: String? = nil,
        device: UInt64? = nil, inode: UInt64? = nil,
        size: UInt64? = nil, mode: String? = nil,
        contentCollected: Bool = false
    ) {
        let identity = pid.flatMap(processIdentity)
        spool.write(SpoolEvent(
            kind: .file, pid: pid, uid: uid, path: path, op: op,
            label: label, program: program, fileDevice: device,
            fileInode: inode, fileSize: size, fileMode: mode,
            contentCollected: contentCollected,
            pidStartSec: identity?.startSec, pidStartUsec: identity?.startUsec,
            signals: ["persistence_change"]
        ))
    }

    /// Background Task Management notifications use the existing `file`
    /// event shape so the macOS and Linux spools stay interchangeable. The
    /// URL/executable are the persistence evidence; signals distinguish the
    /// BTM add/remove and managed/legacy variants for downstream detection.
    func handleBackgroundTask(
        pid: Int32?, path: String?, op: String, label: String?, program: String?,
        signals: [String]
    ) {
        let identity = pid.flatMap(processIdentity)
        spool.write(SpoolEvent(
            kind: .file, pid: pid, path: path, op: op, label: label, program: program,
            contentCollected: false,
            pidStartSec: identity?.startSec, pidStartUsec: identity?.startUsec,
            signals: signals.isEmpty ? nil : signals
        ))
    }

    /// Apply log/kill rules to a network event context. Returns the rules
    /// that killed (for the caller's kill-event spool).
    private func applyNetworkRules(ctx: MatchCtx, pid: Int32?, uid: UInt32?, comm: String?, identity: ProcessIdentity?, via: String) -> [String] {
        var killed: [String] = []
        for rule in mostSpecific(rules.rules.filter { effective($0.action) == .kill && $0.matches(ctx) }) {
            guard let pid else {
                merlinLog("warn", "rule \(rule.name) matched \(via) but there is no attribution — cannot kill")
                continue
            }
            guard let identity, processIdentity(pid) == identity else {
                merlinLog("warn", "rule \(rule.name) matched \(via) but process identity changed or is unavailable — cannot kill")
                continue
            }
            if isFailsafe(pid: pid, teamId: ctx.teamId) {
                merlinLog("warn", "failsafe: kill rule \(rule.name) matched pid \(pid) (\(via)) but it is protected")
                continue
            }
            if killImpl(pid) == 0 {
                killed.append(rule.name)
                merlinLog("info", "SIGKILL pid=\(pid) comm=\(comm ?? "?") on \(via) rules=[\(rule.name)]")
            } else {
                merlinLog("warn", "kill(\(pid)) failed: errno \(errno)")
            }
        }
        return killed
    }

    private func spoolKills(_ killed: [String], pid: Int32?, uid: UInt32?, comm: String?, identity: ProcessIdentity?) {
        guard !killed.isEmpty, let pid else { return }
        spool.write(SpoolEvent(
            kind: .kill, pid: pid, uid: uid, comm: comm,
            matchedRules: killed,
            pidStartSec: identity?.startSec, pidStartUsec: identity?.startUsec
        ))
    }

    private func securitySignals(syscall: String, wXTransition: Bool?) -> [String] {
        var signals: [String] = []
        if wXTransition == true { signals.append("w_x_transition") }
        switch syscall {
        case "ptrace", "task_for_pid", "process_vm_readv", "process_vm_writev":
            signals.append("process_injection")
        case "setuid", "setgid", "seteuid", "setegid", "setreuid", "setregid":
            signals.append("privilege_change")
        case "mount", "unmount", "pivot_root":
            signals.append("mount_or_root_change")
        case "kextload":
            signals.append("kernel_module_change")
        case "bpf":
            signals.append("bpf_program")
        case "cs_invalidated":
            signals.append("code_signing_change")
        default:
            break
        }
        return signals
    }
}
