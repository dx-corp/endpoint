// OpenBSM fallback provider for machines (or signing identities) where the
// Endpoint Security entitlement is not granted.
//
// Spawns `/usr/sbin/praudit -l /dev/auditpipe` and parses execve/exit audit
// records into the same events as the ES provider. TELEMETRY ONLY: OpenBSM
// has no synchronous hook, so `block` rules cannot deny an exec here — the
// engine degrades them to kill (same race window as any kill rule). Root is
// required at runtime to open /dev/auditpipe; that's expected, the daemon
// runs under sudo.

import Foundation

/// Parsed subset of one praudit -l record (a single comma-separated line).
enum BSMRecord {
    struct Exec {
        var pid: Int32?
        var euid: String?
        var path: String?
        var args: [String]
        var retval: String?
    }
    struct Exit {
        var pid: Int32?
        var euid: String?
        var retval: String?
    }
    case exec(Exec)
    case exit(Exit)
}

/// Token names praudit -l can print; used to delimit tokens on a line.
private let bsmTokenNames: Set<String> = [
    "header", "path", "attribute", "subject", "subject_ex", "return", "trailer",
    "exec_args", "argument", "text", "process", "process_ex", "ipc", "socket",
    "groups", "acl", "attr", "zonename", "cmd",
]

private func bsmTokens(_ line: String) -> [(name: String, fields: [String])] {
    let fields = line.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
    var out: [(String, [String])] = []
    var cur: (String, [String])?
    for f in fields {
        if bsmTokenNames.contains(f) {
            if let c = cur { out.append(c) }
            cur = (f, [])
        } else {
            cur?.1.append(f)
        }
    }
    if let c = cur { out.append(c) }
    return out
}

/// Best-effort parser for praudit -l lines. Audit paths with commas in them
/// confuse the split; acceptable for a teaching sensor (documented).
func parseBSMLine(_ line: String) -> BSMRecord? {
    let toks = bsmTokens(line)
    guard let header = toks.first(where: { $0.name == "header" }),
          header.fields.count >= 3 else { return nil }
    let eventName = header.fields[2]
    let subject = toks.first(where: { $0.name.hasPrefix("subject") })
    // subject token: auid, euid, egid, ruid, rgid, pid, session, terminal...
    let pid = subject?.fields.dropFirst(5).first.flatMap { Int32($0) }
    let euid = subject?.fields.dropFirst(1).first
    let retval = toks.first(where: { $0.name == "return" })?.fields.dropFirst(1).first

    if eventName.hasPrefix("execve") || eventName.hasPrefix("posix_spawn") {
        let path = toks.first(where: { $0.name == "path" })?.fields.first
        var args: [String] = []
        if let ea = toks.first(where: { $0.name == "exec_args" }), ea.fields.count > 1 {
            args = Array(ea.fields.dropFirst()) // first field is the count
        }
        return .exec(BSMRecord.Exec(pid: pid, euid: euid, path: path, args: args, retval: retval))
    }
    if eventName.hasPrefix("exit") {
        return .exit(BSMRecord.Exit(pid: pid, euid: euid, retval: retval))
    }
    return nil
}

func parseAuditInt(_ s: String) -> Int32? {
    if let v = Int32(s) { return v }
    if s.hasPrefix("0x"), let v = Int32(s.dropFirst(2), radix: 16) { return v }
    return nil
}

/// praudit prints user/group fields as names; resolve via proc info first
/// (the process is usually still alive right after exec), then getpwnam.
func resolveAuditUID(_ name: String?) -> UInt32? {
    guard let name else { return nil }
    if let v = UInt32(name) { return v }
    if let pw = getpwnam(name) { return pw.pointee.pw_uid }
    return nil
}

final class BSMProvider: @unchecked Sendable {
    private let engine: Engine
    private var process: Process?
    private let lock = NSLock()
    private var partial = Data()
    private let selfPID = getpid()

    init(engine: Engine) {
        self.engine = engine
    }

    func start() throws {
        guard FileManager.default.isExecutableFile(atPath: "/usr/sbin/praudit") else {
            throw MerlinError.plain("/usr/sbin/praudit not found")
        }
        guard FileManager.default.isReadableFile(atPath: "/dev/auditpipe") else {
            throw MerlinError.plain("/dev/auditpipe not readable — BSM provider needs root and a running auditd")
        }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/sbin/praudit")
        p.arguments = ["-l", "/dev/auditpipe"]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.standardError
        p.terminationHandler = { proc in
            merlinLog("error", "praudit exited (status \(proc.terminationStatus)); BSM telemetry stopped")
        }
        out.fileHandleForReading.readabilityHandler = { [weak self] fh in
            self?.consume(fh.availableData)
        }
        try p.run()
        process = p
        merlinLog("info", "OpenBSM provider: streaming praudit -l /dev/auditpipe (telemetry only — exec blocking unavailable)")
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
            guard let s = String(data: line, encoding: .utf8) else { continue }
            handleLine(s)
        }
    }

    func handleLine(_ line: String) {
        guard let rec = parseBSMLine(line) else { return }
        switch rec {
        case .exec(let e):
            guard let pid = e.pid, pid != selfPID, pid != process?.processIdentifier else { return }
            let info = procInfo(pid)
            let uid = info?.uid ?? resolveAuditUID(e.euid)
            guard let exe = e.path ?? e.args.first else { return }
            let cmdline = e.args.isEmpty ? nil : e.args.joined(separator: " ")
            var sha256: String?
            if engine.needsSHA256ForNotify {
                sha256 = try? sha256File(path: exe, maxBytes: 64 * 1024 * 1024)
            }
            engine.handleExec(
                pid: pid, ppid: info?.ppid, uid: uid,
                comm: (exe as NSString).lastPathComponent, exe: exe,
                cmdline: cmdline, sha256: sha256, cdhash: nil, identity: info?.identity
            )
        case .exit(let x):
            guard let pid = x.pid, pid != selfPID else { return }
            let info = procInfo(pid) // usually already gone; subject fields are the fallback
            engine.handleExit(
                pid: pid, uid: info?.uid ?? resolveAuditUID(x.euid),
                comm: info?.comm, status: x.retval.flatMap(parseAuditInt), identity: info?.identity
            )
        }
    }
}
