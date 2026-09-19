// Snapshot-diff layer (idea survey #8): a periodic capture+diff
// inventory next to the real-time watchers — snapshots catch
// pre-existing items and changes made while the daemon was down, which
// event-driven watches cannot see.
//
// Three categories per tick:
//   launchd: label → {path, program, sha256-of-plist} from
//     /Library/LaunchAgents, /Library/LaunchDaemons, and
//     /Users/*/Library/LaunchAgents (own home when unprivileged)
//   listen: listening sockets (proto, port, pid) via the libproc sweep
//   user: logged-in sessions (user, tty, host) via utmpx
//
// Diffs spool `snapshot` events {category, change: added|removed|
// changed, detail}. The first capture is a baseline: it emits no
// events, only a daemon-log summary line with counts (documented in
// reference.md). TELEMETRY ONLY: rules are not applied to snapshot
// events (same contract as the Linux layer) — correlation happens at
// analysis time via the other event kinds.
//
// Two layers, deliberately: the PersistenceWatcher is the real-time
// detector on persistence locations; the Snapshotter is the bounded,
// race-proof inventory over a broader state set. Overlapping coverage
// produces two events by design — dedupe is an analysis-time concern.
//
// Invariants (AGENTS.md): every file opened is O_NOFOLLOW + fstat
// regular-file; enumeration and plist reads are capped; a failed tick
// logs a warning and retries next interval — never crashes the daemon.

import CryptoKit
import Foundation

struct SnapshotChange: Equatable {
    enum Category: String {
        case launchd, listen, user
    }

    enum Change: String {
        case added, removed, changed
    }

    var category: Category
    var change: Change
    var detail: [String: String]
}

struct LaunchdItem: Equatable {
    var label: String
    var path: String
    var program: String?
    var plistHash: String

    var detail: [String: String] {
        var d = ["label": label, "path": path, "sha256": plistHash]
        if let program { d["program"] = program }
        return d
    }
}

struct ListenSocket: Hashable {
    var proto: String // "tcp" | "udp"
    var port: UInt16
    var pid: Int32

    var detail: [String: String] {
        ["proto": proto, "port": String(port), "pid": String(pid)]
    }
}

struct UserSession: Hashable {
    var user: String
    var tty: String
    var host: String

    var detail: [String: String] {
        ["user": user, "tty": tty, "host": host]
    }
}

struct SnapshotState {
    var launchd: [String: LaunchdItem] = [:]
    var listen: Set<ListenSocket> = []
    var users: Set<UserSession> = []
}

// MARK: - Pure diff

func diffLaunchd(old: [String: LaunchdItem], new: [String: LaunchdItem]) -> [SnapshotChange] {
    var out: [SnapshotChange] = []
    for (label, item) in new {
        guard let prev = old[label] else {
            out.append(SnapshotChange(category: .launchd, change: .added, detail: item.detail))
            continue
        }
        if prev != item {
            var d = item.detail
            d["previous_sha256"] = prev.plistHash
            if prev.program != item.program, let p = prev.program { d["previous_program"] = p }
            out.append(SnapshotChange(category: .launchd, change: .changed, detail: d))
        }
    }
    for (label, item) in old where new[label] == nil {
        out.append(SnapshotChange(category: .launchd, change: .removed, detail: item.detail))
    }
    return out.sorted { $0.detail["label"] ?? "" < $1.detail["label"] ?? "" }
}

private func diffSet<T: Hashable>(
    old: Set<T>, new: Set<T>,
    category: SnapshotChange.Category,
    detail: (T) -> [String: String]
) -> [SnapshotChange] {
    var out: [SnapshotChange] = []
    for item in new.subtracting(old) {
        out.append(SnapshotChange(category: category, change: .added, detail: detail(item)))
    }
    for item in old.subtracting(new) {
        out.append(SnapshotChange(category: category, change: .removed, detail: detail(item)))
    }
    return out.sorted { ($0.detail["pid"] ?? "") + ($0.detail["user"] ?? "") < ($1.detail["pid"] ?? "") + ($1.detail["user"] ?? "") }
}

func diffSnapshotStates(old: SnapshotState, new: SnapshotState) -> [SnapshotChange] {
    diffLaunchd(old: old.launchd, new: new.launchd)
        + diffSet(old: old.listen, new: new.listen, category: .listen) { $0.detail }
        + diffSet(old: old.users, new: new.users, category: .user) { $0.detail }
}

// MARK: - Capture helpers

/// Read a file with O_NOFOLLOW + regular-file check, size-capped
/// (AGENTS.md invariants). Returns nil on any failure — callers treat
/// capture pieces as best-effort and log once per tick, not per file.
func readFileNoFollow(path: String, maxBytes: Int) -> Data? {
    let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
    guard fd >= 0 else { return nil }
    defer { close(fd) }
    var st = stat()
    guard fstat(fd, &st) == 0, st.st_mode & S_IFMT == S_IFREG else { return nil }
    var data = Data()
    var buf = [UInt8](repeating: 0, count: 65536)
    while data.count <= maxBytes {
        let want = min(buf.count, maxBytes + 1 - data.count)
        let n = buf.withUnsafeMutableBytes { read(fd, $0.baseAddress, want) }
        if n < 0 { return nil }
        if n == 0 { break }
        data.append(contentsOf: buf.prefix(n))
        if data.count > maxBytes { return nil }
    }
    return data
}

/// Launchd inventory: label → item. Enumeration is capped per directory
/// and plist hashing is size-capped (bounded work per tick).
func scanLaunchd(roots: [String], maxFilesPerDir: Int = 512, maxPlistBytes: Int = 1 << 20) -> [String: LaunchdItem] {
    var out: [String: LaunchdItem] = [:]
    let fm = FileManager.default
    for root in roots {
        let names = ((try? fm.contentsOfDirectory(atPath: root)) ?? []).sorted()
        for name in names.prefix(maxFilesPerDir) where name.hasSuffix(".plist") {
            let path = root + "/" + name
            guard let data = readFileNoFollow(path: path, maxBytes: maxPlistBytes) else { continue }
            let info = extractLaunchItemInfo(path: path)
            let label = info.label ?? (name as NSString).deletingPathExtension
            let hash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            out[label] = LaunchdItem(label: label, path: path, program: info.program, plistHash: hash)
        }
    }
    return out
}

/// Logged-in sessions from utmpx records (USER_PROCESS only).
/// NB: the ON-DISK record is 628 bytes (legacy 32-bit timeval layout:
/// ut_user[256] ut_id[4] ut_line[32] ut_pid(4) ut_type(2) ut_tv(8)
/// ut_host[256] pad) — NOT the 640-byte in-memory struct getutxent
/// returns. Verified against /var/run/utmpx (8164 = 13 × 628).
func parseUtmpx(_ data: Data) -> Set<UserSession> {
    let recordSize = 628
    var out: Set<UserSession> = []
    data.withUnsafeBytes { raw in
        var off = 0
        while off + recordSize <= raw.count {
            let type = Int16(bitPattern: raw.loadUnaligned(fromByteOffset: off + 296, as: UInt16.self))
            if type == Int16(USER_PROCESS) {
                out.insert(UserSession(
                    user: cString(from: raw, at: off, max: 256),
                    tty: cString(from: raw, at: off + 260, max: 32),
                    host: cString(from: raw, at: off + 306, max: 256)
                ))
            }
            off += recordSize
        }
    }
    return out
}

private func cString(from raw: UnsafeRawBufferPointer, at offset: Int, max: Int) -> String {
    String(decoding: raw[offset ..< offset + max].prefix { $0 != 0 }, as: UTF8.self)
}

func readUserSessions(path: String = "/var/run/utmpx") -> Set<UserSession> {
    guard let data = readFileNoFollow(path: path, maxBytes: 4 << 20) else { return [] }
    return parseUtmpx(data)
}

// MARK: - Snapshotter

final class Snapshotter: @unchecked Sendable {
    private let spool: SpoolWriter
    private let interval: TimeInterval
    private let launchdRoots: [String]
    private let utmpxPath: String
    private let sweeper: LibprocSweeper
    private let queue = DispatchQueue(label: "merlin.snapshots", qos: .utility)
    private var timer: DispatchSourceTimer?
    private var state: SnapshotState?

    init(
        spool: SpoolWriter,
        interval: TimeInterval,
        launchdRoots: [String]? = nil,
        utmpxPath: String = "/var/run/utmpx",
        sweeper: LibprocSweeper = LibprocSweeper()
    ) {
        self.spool = spool
        self.interval = interval
        self.launchdRoots = launchdRoots ?? Snapshotter.defaultRoots(root: geteuid() == 0)
        self.utmpxPath = utmpxPath
        self.sweeper = sweeper
    }

    static func defaultRoots(root: Bool) -> [String] {
        var roots = ["/Library/LaunchAgents", "/Library/LaunchDaemons"]
        if root {
            for home in (try? FileManager.default.contentsOfDirectory(atPath: "/Users")) ?? [] {
                roots.append("/Users/\(home)/Library/LaunchAgents")
            }
        } else {
            roots.append(NSHomeDirectory() + "/Library/LaunchAgents")
        }
        return roots
    }

    func start() {
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now(), repeating: interval)
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        timer = t
        merlinLog("info", "snapshotter: launchd+listen+users every \(Int(interval))s (telemetry only)")
    }

    func stop() {
        timer?.cancel()
        timer = nil
    }

    /// One capture+diff cycle. Fail-open: any failure logs and the next
    /// tick retries with the previous state intact.
    func tick() {
        let new = SnapshotState(
            launchd: scanLaunchd(roots: launchdRoots),
            listen: sweeper.listeningSockets(),
            users: readUserSessions(path: utmpxPath)
        )
        guard let prev = state else {
            state = new
            merlinLog("info", "snapshot baseline: \(new.launchd.count) launchd items, \(new.listen.count) listeners, \(new.users.count) user sessions")
            return
        }
        for change in diffSnapshotStates(old: prev, new: new) {
            spool.write(SpoolEvent(
                kind: .snapshot,
                category: change.category.rawValue,
                change: change.change.rawValue,
                detail: change.detail
            ))
        }
        state = new
    }
}
