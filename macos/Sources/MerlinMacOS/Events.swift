// JSONL spool events. Field names and null-when-absent encoding match the
// Linux daemon's serde_json::json! output (merlin/src/telemetry.rs,
// merlin/src/fanotify_mon.rs) so both ports' spools are interchangeable.

import Foundation

enum EventKind: String, Codable, Sendable {
    case exec, exit, fork, deny, kill, connect, dns, file, security, health, snapshot, verdict, config, posture
}

/// Stable host boot identity for correlating events across providers without
/// collecting process payloads. A boot timestamp is sufficient here because
/// it is paired with a per-boot event sequence and is never presented as a
/// globally unique machine identifier.
enum HostIdentity {
    static let bootID: String = {
        var boot = timeval()
        var size = MemoryLayout<timeval>.size
        guard sysctlbyname("kern.boottime", &boot, &size, nil, 0) == 0 else {
            return "unknown"
        }
        return "macos:\(boot.tv_sec):\(boot.tv_usec)"
    }()
}

/// Process-local ordering is evidence correlation, not a completeness claim.
/// Providers remain fail-open and may drop telemetry under pressure.
private final class EventSequence: @unchecked Sendable {
    static let shared = EventSequence()
    private let lock = NSLock()
    private var value: UInt64 = 1

    func next() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        defer { value &+= 1 }
        return value
    }
}

struct Ancestor: Codable, Sendable, Equatable {
    let pid: Int32
    let comm: String?
}

/// One JSONL spool event. Per-kind key sets mirror the Linux port:
///   exec: ts kind pid ppid uid comm exe cmdline sha256 cdhash ancestors matched_rules
///         quarantined unsigned is_platform_binary
///   exit: ts kind pid uid comm exit_code exit_status
///   fork: ts kind pid ppid comm exe
///   deny: ts kind pid uid path sha256 cdhash matched_rules
///   kill: ts kind pid uid comm exe matched_rules
///   connect: ts kind pid uid comm saddr daddr dport
///   dns: ts kind pid uid comm query qtype direction rcode
///   file: ts kind pid path op label program
struct SpoolEvent: Encodable, Sendable {
    let kind: EventKind
    var ts: Double = nowTs()
    var source: String? = "macos"
    var sourceSeq: UInt64? = EventSequence.shared.next()
    var spooledTs: Double? = nil
    var schemaVersion: UInt32 = 1
    var bootId: String? = HostIdentity.bootID
    var eventId: String? = nil
    var pid: Int32? = nil
    var ppid: Int32? = nil
    var uid: UInt32? = nil
    var comm: String? = nil
    var exe: String? = nil
    var path: String? = nil
    var cmdline: String? = nil
    var sha256: String? = nil
    var cdhash: String? = nil
    var matchedRules: [String]? = nil
    var ancestors: [Ancestor]? = nil
    var exitCode: Int32? = nil
    var exitStatus: Int32? = nil
    var saddr: String? = nil
    var daddr: String? = nil
    var sport: UInt16? = nil
    var dport: UInt16? = nil
    var family: UInt16? = nil
    var protocolNumber: UInt8? = nil
    var oldState: String? = nil
    var state: String? = nil
    var query: String? = nil
    var qtype: String? = nil
    var direction: String? = nil
    var rcode: Int? = nil
    var op: String? = nil
    var label: String? = nil
    var program: String? = nil
    var fileDevice: UInt64? = nil
    var fileInode: UInt64? = nil
    var fileSize: UInt64? = nil
    var fileMode: String? = nil
    var contentCollected: Bool? = nil
    var syscall: String? = nil
    var syscallNumber: UInt32? = nil
    var args: [UInt64]? = nil
    var tccService: String? = nil
    var tccIdentityHash: String? = nil
    var tccIdentityType: String? = nil
    var tccUpdateType: String? = nil
    var tccRight: String? = nil
    var tccReason: String? = nil
    var wXTransition: Bool? = nil
    var namespaceValid: Bool? = nil
    var pidStartSec: UInt64? = nil
    var pidStartUsec: UInt64? = nil
    var parentPidStartSec: UInt64? = nil
    var parentPidStartUsec: UInt64? = nil
    var signals: [String]? = nil
    var quarantined: Bool? = nil
    var unsigned: Bool? = nil
    var isPlatformBinary: Bool? = nil
    var healthStatus: String? = nil
    var healthCapabilities: [String]? = nil
    var healthEventsAttempted: UInt64? = nil
    var healthEventsAccepted: UInt64? = nil
    var healthEventsDropped: UInt64? = nil
    var healthDropRate: Double? = nil
    var healthEventsWritten: UInt64? = nil
    var healthWriteFailures: UInt64? = nil
    var healthIntervalSeconds: Double? = nil

    // Conditional keys: encoded only when true, never as nulls (like the
    // Linux port's `fileless`).
    var dohSuspect: Bool? = nil
    var ownResolver: Bool? = nil
    var viaSystemResolver: Bool? = nil
    var viaSuspend: Bool? = nil
    var suspendReleased: Bool? = nil
    var viaPid: Int32? = nil
    // verdict/config events (unified-log verdicts, SCDynamicStore changes)
    var subsystem: String? = nil
    var message: String? = nil
    var key: String? = nil
    var summary: String? = nil
    var check: String? = nil
    // snapshot events (periodic state diff, telemetry only)
    var category: String? = nil
    var change: String? = nil
    var detail: [String: String]? = nil

    enum CodingKeys: String, CodingKey {
        case kind, ts, source, pid, ppid, uid, comm, exe, path, cmdline, sha256, cdhash
        case sourceSeq = "source_seq"
        case spooledTs = "spooled_ts"
        case schemaVersion = "schema_version"
        case bootId = "boot_id"
        case eventId = "event_id"
        case processKey = "process_key"
        case signals
        case matchedRules = "matched_rules"
        case ancestors
        case exitCode = "exit_code"
        case exitStatus = "exit_status"
        case saddr, daddr, sport, dport, family
        case protocolNumber = "protocol"
        case oldState = "old_state"
        case state
        case query, qtype, direction, rcode
        case op, label, program
        case fileDevice = "device"
        case fileInode = "inode"
        case fileSize = "size"
        case fileMode = "mode"
        case contentCollected = "content_collected"
        case syscall
        case syscallNumber = "syscall_nr"
        case args
        case tccService = "tcc_service"
        case tccIdentityHash = "tcc_identity_hash"
        case tccIdentityType = "tcc_identity_type"
        case tccUpdateType = "tcc_update_type"
        case tccRight = "tcc_right"
        case tccReason = "tcc_reason"
        case wXTransition = "w_x_transition"
        case namespaceValid = "namespace_valid"
        case pidStartSec = "pid_start_sec"
        case pidStartUsec = "pid_start_usec"
        case parentPidStartSec = "parent_pid_start_sec"
        case parentPidStartUsec = "parent_pid_start_usec"
        case quarantined, unsigned
        case isPlatformBinary = "is_platform_binary"
        case healthStatus = "status"
        case healthCapabilities = "capabilities"
        case healthEventsAttempted = "events_attempted"
        case healthEventsAccepted = "events_accepted"
        case healthEventsDropped = "events_dropped"
        case healthDropRate = "drop_rate"
        case healthEventsWritten = "events_written"
        case healthWriteFailures = "write_failures"
        case healthIntervalSeconds = "interval_seconds"

        case dohSuspect = "doh_suspect"
        case ownResolver = "own_resolver"
        case viaSystemResolver = "via_system_resolver"
        case viaSuspend = "via_suspend"
        case suspendReleased = "suspend_released"
        case viaPid = "via_pid"
        case category, change, detail
        case subsystem, message, key, summary, check
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(ts, forKey: .ts)
        try c.encode(kind.rawValue, forKey: .kind)
        try opt(source, .source)
        try opt(sourceSeq, .sourceSeq)
        // Explicit nulls, like serde_json::json! with Option fields.
        func opt<T: Encodable>(_ v: T?, _ k: CodingKeys) throws {
            if let v { try c.encode(v, forKey: k) } else { try c.encodeNil(forKey: k) }
        }
        let resolvedBootId = bootId ?? "unknown"
        let resolvedEventId = eventId ?? sourceSeq.map { "\(resolvedBootId):\($0)" }
        let processKey: String? = if let pid, let startSec = pidStartSec, let startUsec = pidStartUsec {
            "\(resolvedBootId):\(pid):\(startSec):\(startUsec)"
        } else {
            nil
        }
        try opt(spooledTs, .spooledTs)
        try c.encode(schemaVersion, forKey: .schemaVersion)
        try opt(bootId, .bootId)
        try opt(resolvedEventId, .eventId)
        try opt(processKey, .processKey)
        try opt(signals, .signals)
        switch kind {
        case .exec:
            try opt(pid, .pid)
            try opt(ppid, .ppid)
            try opt(uid, .uid)
            try opt(comm, .comm)
            try opt(exe, .exe)
            try opt(cmdline, .cmdline)
            try opt(sha256, .sha256)
            try opt(cdhash, .cdhash)
            try opt(ancestors, .ancestors)
            try opt(matchedRules, .matchedRules)
            try opt(quarantined, .quarantined)
            try opt(unsigned, .unsigned)
            try opt(isPlatformBinary, .isPlatformBinary)
            try opt(pidStartSec, .pidStartSec)
            try opt(pidStartUsec, .pidStartUsec)
            if suspendReleased == true { try c.encode(true, forKey: .suspendReleased) }
        case .exit:
            try opt(pid, .pid)
            try opt(uid, .uid)
            try opt(comm, .comm)
            try opt(exitCode, .exitCode)
            try opt(exitStatus, .exitStatus)
            try opt(pidStartSec, .pidStartSec)
            try opt(pidStartUsec, .pidStartUsec)
        case .fork:
            try opt(pid, .pid)
            try opt(ppid, .ppid)
            try opt(comm, .comm)
            try opt(exe, .exe)
            try opt(pidStartSec, .pidStartSec)
            try opt(pidStartUsec, .pidStartUsec)
            try opt(parentPidStartSec, .parentPidStartSec)
            try opt(parentPidStartUsec, .parentPidStartUsec)
        case .deny:
            try opt(pid, .pid)
            try opt(uid, .uid)
            try opt(path, .path)
            try opt(sha256, .sha256)
            try opt(cdhash, .cdhash)
            try opt(matchedRules, .matchedRules)
        case .kill:
            try opt(pid, .pid)
            try opt(uid, .uid)
            try opt(comm, .comm)
            try opt(exe, .exe)
            try opt(matchedRules, .matchedRules)
            if viaSuspend == true { try c.encode(true, forKey: .viaSuspend) }
        case .connect:
            try opt(pid, .pid)
            try opt(uid, .uid)
            try opt(comm, .comm)
            try opt(saddr, .saddr)
            try opt(daddr, .daddr)
            try opt(sport, .sport)
            try opt(dport, .dport)
            try opt(family, .family)
            try opt(protocolNumber, .protocolNumber)
            try opt(oldState, .oldState)
            try opt(state, .state)
            try opt(pidStartSec, .pidStartSec)
            try opt(pidStartUsec, .pidStartUsec)
            if dohSuspect == true { try c.encode(true, forKey: .dohSuspect) }
            if viaSystemResolver == true { try c.encode(true, forKey: .viaSystemResolver) }
            if let viaPid { try c.encode(viaPid, forKey: .viaPid) }
        case .dns:
            try opt(pid, .pid)
            try opt(uid, .uid)
            try opt(comm, .comm)
            try opt(query, .query)
            try opt(qtype, .qtype)
            try opt(direction, .direction)
            try opt(rcode, .rcode)
            try opt(pidStartSec, .pidStartSec)
            try opt(pidStartUsec, .pidStartUsec)
            if ownResolver == true { try c.encode(true, forKey: .ownResolver) }
            if viaSystemResolver == true { try c.encode(true, forKey: .viaSystemResolver) }
            if let viaPid { try c.encode(viaPid, forKey: .viaPid) }
        case .file:
            try opt(pid, .pid)
            try opt(path, .path)
            try opt(op, .op)
            try opt(label, .label)
            try opt(program, .program)
            try opt(fileDevice, .fileDevice)
            try opt(fileInode, .fileInode)
            try opt(fileSize, .fileSize)
            try opt(fileMode, .fileMode)
            try opt(contentCollected, .contentCollected)
        case .security:
            try opt(pid, .pid)
            try opt(uid, .uid)
            try opt(comm, .comm)
            try opt(syscall, .syscall)
            try opt(syscallNumber, .syscallNumber)
            try opt(args, .args)
            if let tccService { try c.encode(tccService, forKey: .tccService) }
            if let tccIdentityHash { try c.encode(tccIdentityHash, forKey: .tccIdentityHash) }
            if let tccIdentityType { try c.encode(tccIdentityType, forKey: .tccIdentityType) }
            if let tccUpdateType { try c.encode(tccUpdateType, forKey: .tccUpdateType) }
            if let tccRight { try c.encode(tccRight, forKey: .tccRight) }
            if let tccReason { try c.encode(tccReason, forKey: .tccReason) }
            try opt(wXTransition, .wXTransition)
            try opt(namespaceValid, .namespaceValid)
            try opt(pidStartSec, .pidStartSec)
            try opt(pidStartUsec, .pidStartUsec)
        case .health:
            try opt(healthStatus, .healthStatus)
            try opt(healthCapabilities, .healthCapabilities)
            try opt(healthEventsAttempted, .healthEventsAttempted)
            try opt(healthEventsAccepted, .healthEventsAccepted)
            try opt(healthEventsDropped, .healthEventsDropped)
            try opt(healthDropRate, .healthDropRate)
            try opt(healthEventsWritten, .healthEventsWritten)
            try opt(healthWriteFailures, .healthWriteFailures)
            try opt(healthIntervalSeconds, .healthIntervalSeconds)

        case .snapshot:
            try opt(category, .category)
            try opt(change, .change)
            try opt(detail, .detail)
        case .verdict:
            try opt(subsystem, .subsystem)
            try opt(message, .message)
            try opt(pid, .pid)
            try opt(comm, .comm)
        case .config:
            try opt(key, .key)
            try opt(summary, .summary)
        case .posture:
            try opt(check, .check)
            try opt(change, .change)
            try opt(detail, .detail)
        }
    }
}
