// Enrichment helpers: libproc process info (the macOS analog of the Linux
// port's /proc reads) and file hashing/signing evidence.
//
// Enrichment races: by the time we read proc info the process may have
// exited or re-execed, so fields are best-effort and may be missing or
// (rarely) refer to a recycled pid — same caveat as the Linux port.

import CryptoKit
import Foundation

struct ProcessIdentity: Equatable, Hashable, Sendable {
    let startSec: UInt64
    let startUsec: UInt64
}

struct FileIdentity: Equatable, Hashable, Sendable {
    let device: UInt64
    let inode: UInt64
}

func fileIdentityNoFollow(_ path: String) -> FileIdentity? {
    var st = stat()
    guard lstat(path, &st) == 0, st.st_mode & S_IFMT == S_IFREG else { return nil }
    return FileIdentity(device: UInt64(st.st_dev), inode: UInt64(st.st_ino))
}

struct ProcInfo {
    let pid: Int32
    let ppid: Int32
    let uid: UInt32
    let comm: String
    /// Process start time (pbi_start_tvsec/usec) — the pid-reuse guard:
    /// two different processes occupying the same pid have different
    /// start times.
    let startSec: UInt64
    let startUsec: UInt64

    var identity: ProcessIdentity {
        ProcessIdentity(startSec: startSec, startUsec: startUsec)
    }
}

func procInfo(_ pid: Int32) -> ProcInfo? {
    var info = proc_bsdinfo()
    let size = Int32(MemoryLayout<proc_bsdinfo>.size)
    guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
    let comm = withUnsafeBytes(of: info.pbi_comm) { raw in
        String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
    }
    return ProcInfo(
        pid: Int32(info.pbi_pid), ppid: Int32(info.pbi_ppid), uid: info.pbi_uid,
        comm: comm, startSec: info.pbi_start_tvsec, startUsec: info.pbi_start_tvusec
    )
}

/// Walk the parent chain from `ppid` up to launchd (depth-capped at 8,
/// same as the Linux port's parent_chain).
func ancestorChain(fromPPID ppid: Int32?, depth: Int = 8) -> [Ancestor] {
    var chain: [Ancestor] = []
    var cur = ppid
    for _ in 0 ..< depth {
        guard let pid = cur, pid > 0, let info = procInfo(pid) else { break }
        chain.append(Ancestor(pid: pid, comm: info.comm))
        cur = info.ppid
    }
    return chain
}

/// sha256 of a file, streamed (CryptoKit). Used by AUTH_EXEC enforcement,
//  rule matching, and `merlin-macos gen-hash`.
///
/// `budget` is a wall-clock bound for callers that answer against a
/// deadline. It is preferred over `maxBytes` at the AUTH point: a fixed
/// byte cap is attacker-controllable (pad the payload past it and the
/// sha256 selector is deterministically skipped), whereas the time bound
/// tracks the deadline that actually constrains the decision.
func sha256File(
    path: String,
    maxBytes: UInt64? = nil,
    budget: TimeInterval? = nil,
    expectedIdentity: FileIdentity? = nil
) throws -> String {
    let fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    guard fd >= 0 else {
        throw MerlinError.plain("opening \(path): errno \(errno)")
    }
    var st = stat()
    guard fstat(fd, &st) == 0 else {
        close(fd)
        throw MerlinError.plain("stating \(path): errno \(errno)")
    }
    let actualIdentity = FileIdentity(device: UInt64(st.st_dev), inode: UInt64(st.st_ino))
    if let expectedIdentity, actualIdentity != expectedIdentity {
        close(fd)
        throw MerlinError.plain("\(path) changed while opening for hashing")
    }
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    var hasher = SHA256()
    var total: UInt64 = 0
    let start = Date()
    while let data = try handle.read(upToCount: 64 * 1024), !data.isEmpty {
        total += UInt64(data.count)
        if let maxBytes, total > maxBytes {
            throw MerlinError.plain("\(path) exceeds the synchronous hash limit of \(maxBytes) bytes")
        }
        if let budget, Date().timeIntervalSince(start) > budget {
            throw MerlinError.plain("\(path) exceeded the synchronous hash budget of \(budget)s after \(total) bytes")
        }
        hasher.update(data: data)
    }
    return hasher.finalize().map { String(format: "%02x", $0) }.joined()
}

/// cdhash of a signed binary via `codesign -dvvv`. The ES provider reads
/// cdhashes straight from the event; this is for `gen-hash` only, where
/// shelling out once is fine.
func cdhashForFile(path: String) -> String? {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
    p.arguments = ["-dvvv", path]
    let pipe = Pipe()
    p.standardOutput = pipe
    p.standardError = pipe
    do { try p.run() } catch { return nil }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    guard p.terminationStatus == 0, let out = String(data: data, encoding: .utf8) else { return nil }
    for line in out.split(separator: "\n") where line.hasPrefix("CDHash=") {
        return String(line.dropFirst("CDHash=".count)).trimmingCharacters(in: .whitespaces)
    }
    return nil
}
