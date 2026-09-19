// Unified-log providers: mDNSResponder DNS attribution and the OS's own
// security verdicts, both via `log stream --style ndjson` subprocesses
// (same pattern as the BSM provider's praudit pipe).
//
// MdnsLogProvider closes the via_system_resolver blindspot: mDNSResponder
// logs each query with the REQUESTING process's pid and comm
// ("DNSServiceQueryRecord START ... client pid: N (comm)"). Verified on
// this host (macOS 27): qnames are REDACTED without the
// Enable-Private-Data logging profile (MDM-deliverable) — events carry
// the redaction-stable <dn:HASH> string as `query` (still useful for
// frequency/correlation), marked partial in the docs. dns events from
// this provider spool with source "mdnsresponder-log".
//
// VerdictsProvider consumes the OS's own security decisions:
// com.apple.syspolicy (Gatekeeper/notarization/first-launch),
// com.apple.TCC (consent grants/denials),
// com.apple.XProtectFramework.PluginAPI (XProtect Remediator results).
// Rate-capped with a token bucket (10/s, burst 20; drops counted and
// logged), matching the Linux security-throttle pattern.
//
// Verified on macOS 27: both predicates are readable WITHOUT root here;
// the providers still fail open (stream errors only log).

import Foundation

// MARK: - Token bucket rate limiter

/// Simple token bucket: `rate` tokens/sec, `burst` capacity.
struct TokenBucket: Sendable {
    let rate: Double
    let burst: Double
    private var tokens: Double
    private var last: TimeInterval

    init(rate: Double, burst: Double) {
        self.rate = rate
        self.burst = burst
        tokens = burst
        last = nowTs()
    }

    mutating func take() -> Bool {
        let now = nowTs()
        tokens = min(burst, tokens + (now - last) * rate)
        last = now
        guard tokens >= 1 else { return false }
        tokens -= 1
        return true
    }
}

// MARK: - mDNSResponder query lines

struct MdnsQuery: Equatable {
    var pid: Int32
    var comm: String
    /// The qname as logged: "<private> <dn:HASH>" without the
    /// Enable-Private-Data profile — a stable per-qname token, not the
    /// name itself.
    var qname: String
    var qtype: String
}

/// Parse one ndjson `log stream` line for the query-start format. Pure.
/// Real line (macOS 27): {"formatString":"[R%u] DNSServiceQueryRecord
/// START -- qname: %{sensitive,...}, ...", "eventMessage":"[R636276]
/// DNSServiceQueryRecord START -- qname: <private> <dn:I/vUYw>, qtype: A,
/// flags: 0x1D000, interface index: 0, client pid: 46484 (codex), ..."}
func parseMdnsLogLine(_ line: String) -> MdnsQuery? {
    guard line.hasPrefix("{"),
          let data = line.data(using: .utf8),
          let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let format = obj["formatString"] as? String,
          format.contains("DNSServiceQueryRecord START"),
          let msg = obj["eventMessage"] as? String
    else { return nil }
    // qname: <…>, qtype: X — qname may itself contain ", " inside <…>.
    guard let qRange = msg.range(of: "qname: "),
          let tRange = msg.range(of: ", qtype: ", range: qRange.upperBound..<msg.endIndex)
    else { return nil }
    let qname = String(msg[qRange.upperBound ..< tRange.lowerBound])
    let typeStart = tRange.upperBound
    let typeEnd = msg[typeStart...].firstIndex(of: ",") ?? msg.endIndex
    let qtype = String(msg[typeStart ..< typeEnd])
    guard let pRange = msg.range(of: "client pid: "),
          let openRange = msg.range(of: "(", range: pRange.upperBound ..< msg.endIndex),
          let closeRange = msg.range(of: ")", range: openRange.upperBound ..< msg.endIndex),
          let pid = Int32(msg[pRange.upperBound ..< openRange.lowerBound].trimmingCharacters(in: .whitespaces))
    else { return nil }
    let comm = String(msg[openRange.upperBound ..< closeRange.lowerBound])
    return MdnsQuery(pid: pid, comm: comm, qname: qname, qtype: qtype)
}

/// qtype word → wire number (for DnsMessage rendering).
func qtypeNumber(_ word: String) -> UInt16 {
    switch word {
    case "A": return 1
    case "NS": return 2
    case "CNAME": return 5
    case "SOA": return 6
    case "PTR": return 12
    case "MX": return 15
    case "TXT": return 16
    case "AAAA": return 28
    case "SRV": return 33
    case "SVCB": return 64
    case "HTTPS": return 65
    case "ANY": return 255
    default: return 0
    }
}

// MARK: - Verdict lines

struct VerdictLine: Equatable {
    var subsystem: String
    var message: String
    var pid: Int32?
    var comm: String?
}

/// Parse one ndjson unified-log line into a verdict event. Pure.
func parseVerdictLine(_ line: String) -> VerdictLine? {
    guard line.hasPrefix("{"),
          let data = line.data(using: .utf8),
          let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let subsystem = obj["subsystem"] as? String,
          let message = obj["eventMessage"] as? String
    else { return nil }
    var comm: String?
    if let image = (obj["processImagePath"] as? String) ?? (obj["senderImagePath"] as? String) {
        comm = (image as NSString).lastPathComponent
    }
    return VerdictLine(
        subsystem: subsystem, message: message,
        pid: (obj["processID"] as? NSNumber)?.int32Value, comm: comm
    )
}

// MARK: - Shared subprocess plumbing

private final class LogStreamProcess: @unchecked Sendable {
    private var process: Process?
    private var partial = Data()
    private let lock = NSLock()
    private let onLine: (String) -> Void

    init(predicate: String, label: String, onLine: @escaping (String) -> Void) {
        self.onLine = onLine
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/log")
        p.arguments = ["stream", "--style", "ndjson", "--predicate", predicate]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.standardError
        p.terminationHandler = { proc in
            merlinLog("error", "log stream (\(label)) exited (status \(proc.terminationStatus)); telemetry stopped")
        }
        out.fileHandleForReading.readabilityHandler = { [weak self] fh in
            self?.consume(fh.availableData)
        }
        process = p
    }

    func start() throws {
        guard let process else { return }
        try process.run()
    }

    func stop() {
        process?.terminate()
        process = nil
    }

    private func consume(_ data: Data) {
        lock.lock()
        partial.append(data)
        var lines: [Data] = []
        while let nl = partial.firstIndex(of: 0x0a) {
            lines.append(partial.prefix(upTo: nl))
            partial = partial.subdata(in: partial.index(after: nl) ..< partial.endIndex)
        }
        lock.unlock()
        for line in lines {
            guard let s = String(data: line, encoding: .utf8), !s.isEmpty else { continue }
            onLine(s)
        }
    }
}

// MARK: - Providers

final class MdnsLogProvider: @unchecked Sendable {
    private let engine: Engine
    private var stream: LogStreamProcess?

    init(engine: Engine) {
        self.engine = engine
    }

    func start() throws {
        let engine = self.engine
        let stream = LogStreamProcess(
            predicate: "subsystem == \"com.apple.mDNSResponder\"",
            label: "mdns"
        ) { line in
            guard let q = parseMdnsLogLine(line) else { return }
            let info = procInfo(q.pid)
            engine.handleDns(
                pid: q.pid, uid: info?.uid, comm: q.comm,
                identity: info?.identity,
                msg: DnsMessage(
                    id: 0, isResponse: false, rcode: nil,
                    qname: q.qname, qtype: qtypeNumber(q.qtype), qclass: 1
                )
            )
        }
        try stream.start()
        self.stream = stream
        merlinLog("info", "mDNSResponder log provider: per-process DNS attribution (qnames redacted without Enable-Private-Data)")
    }

    func stop() {
        stream?.stop()
        stream = nil
    }
}

final class VerdictsProvider: @unchecked Sendable {
    private let spool: SpoolWriter
    private var stream: LogStreamProcess?
    private var bucket = TokenBucket(rate: 10, burst: 20)
    private var dropped = 0
    private let lock = NSLock()

    init(spool: SpoolWriter) {
        self.spool = spool
    }

    func start() throws {
        let spool = self.spool
        let stream = LogStreamProcess(
            predicate: "subsystem IN {\"com.apple.syspolicy\", \"com.apple.TCC\", \"com.apple.XProtectFramework.PluginAPI\"}",
            label: "verdicts"
        ) { [weak self] line in
            guard let self, let v = parseVerdictLine(line) else { return }
            lock.lock()
            let allowed = bucket.take()
            if !allowed { dropped += 1 }
            let droppedNow = dropped
            lock.unlock()
            guard allowed else {
                if droppedNow % 100 == 1 {
                    merlinLog("warn", "verdicts: rate cap dropping events (\(droppedNow) dropped so far)")
                }
                return
            }
            spool.write(SpoolEvent(
                kind: .verdict, pid: v.pid, comm: v.comm,
                subsystem: v.subsystem, message: v.message
            ))
        }
        try stream.start()
        self.stream = stream
        merlinLog("info", "verdicts provider: syspolicy/TCC/XProtect unified-log verdicts (10/s cap)")
    }

    func stop() {
        stream?.stop()
        stream = nil
    }
}
