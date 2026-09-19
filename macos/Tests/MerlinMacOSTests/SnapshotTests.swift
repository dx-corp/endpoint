import Foundation
import Testing
@testable import MerlinMacOS

// Snapshot-diff layer: pure diff logic, utmpx fixture parsing, launchd
// scan on fixture dirs, end-to-end tick through a temp spool.

@Suite("snapshot diff logic")
struct SnapshotLayerDiffTests {
    private let itemA = LaunchdItem(label: "com.a", path: "/L/a.plist", program: "/bin/a", plistHash: "aa")
    private let itemB = LaunchdItem(label: "com.b", path: "/L/b.plist", program: "/bin/b", plistHash: "bb")

    @Test("launchd: added, removed, unchanged-no-op")
    func launchdBasic() {
        let added = diffLaunchd(old: [:], new: ["com.a": itemA])
        #expect(added == [SnapshotChange(category: .launchd, change: .added, detail: itemA.detail)])
        let removed = diffLaunchd(old: ["com.a": itemA], new: [:])
        #expect(removed == [SnapshotChange(category: .launchd, change: .removed, detail: itemA.detail)])
        #expect(diffLaunchd(old: ["com.a": itemA], new: ["com.a": itemA]).isEmpty)
    }

    @Test("launchd: hash change and program change both fire 'changed' with previous evidence")
    func launchdChanged() {
        let hashChanged = LaunchdItem(label: "com.a", path: "/L/a.plist", program: "/bin/a", plistHash: "cc")
        let events = diffLaunchd(old: ["com.a": itemA], new: ["com.a": hashChanged])
        #expect(events.count == 1)
        #expect(events[0].change == .changed)
        #expect(events[0].detail["sha256"] == "cc")
        #expect(events[0].detail["previous_sha256"] == "aa")
        let progChanged = LaunchdItem(label: "com.a", path: "/L/a.plist", program: "/bin/evil", plistHash: "aa")
        let e2 = diffLaunchd(old: ["com.a": itemA], new: ["com.a": progChanged])
        #expect(e2.count == 1)
        #expect(e2[0].detail["previous_program"] == "/bin/a")
    }

    @Test("listen/user sets: added and removed, no changed variant")
    func setDiffs() {
        let s1 = ListenSocket(proto: "tcp", port: 22, pid: 100)
        let s2 = ListenSocket(proto: "udp", port: 53, pid: 200)
        let u1 = UserSession(user: "jon", tty: "console", host: "")
        let old = SnapshotState(launchd: [:], listen: [s1], users: [u1])
        let new = SnapshotState(launchd: [:], listen: [s2], users: [])
        let events = diffSnapshotStates(old: old, new: new)
        #expect(events.contains(SnapshotChange(category: .listen, change: .added, detail: s2.detail)))
        #expect(events.contains(SnapshotChange(category: .listen, change: .removed, detail: s1.detail)))
        #expect(events.contains(SnapshotChange(category: .user, change: .removed, detail: u1.detail)))
        #expect(events.count == 3)
        #expect(diffSnapshotStates(old: new, new: new).isEmpty)
    }
}

@Suite("utmpx parsing")
struct UtmpxTests {
    @Test("USER_PROCESS records parse; other types skipped")
    func fixture() {
        // On-disk 628-byte record layout (see parseUtmpx).
        func record(user: String, tty: String, host: String, type: Int16) -> Data {
            var rec = [UInt8](repeating: 0, count: 628)
            for (i, b) in user.utf8.enumerated() { rec[i] = b }
            for (i, b) in tty.utf8.enumerated() { rec[260 + i] = b }
            rec[296] = UInt8(bitPattern: Int8(truncatingIfNeeded: type))
            rec[297] = UInt8(truncatingIfNeeded: Int(type) >> 8)
            for (i, b) in host.utf8.enumerated() { rec[306 + i] = b }
            return Data(rec)
        }
        var data = record(user: "jon", tty: "console", host: "", type: Int16(USER_PROCESS))
        data.append(record(user: "root", tty: "ttys000", host: "", type: Int16(USER_PROCESS)))
        data.append(record(user: "reboot", tty: "~", host: "", type: 2 /* BOOT_TIME */))
        data.append(Data([0, 1, 2])) // trailing garbage shorter than a record
        let sessions = parseUtmpx(data)
        #expect(sessions.count == 2)
        #expect(sessions.contains(UserSession(user: "jon", tty: "console", host: "")))
        #expect(sessions.contains(UserSession(user: "root", tty: "ttys000", host: "")))
        #expect(parseUtmpx(Data()).isEmpty)
    }
}

@Suite("launchd scan on fixture dirs")
struct LaunchdScanTests {
    private func plist(_ label: String, _ program: String) -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
          <key>Label</key><string>\(label)</string>
          <key>ProgramArguments</key><array><string>\(program)</string></array>
        </dict></plist>
        """
    }

    @Test("scan finds items with label/program/hash; symlinked plists skipped")
    func scan() throws {
        let dir = NSTemporaryDirectory() + "merlin-snap-\(UUID().uuidString)"
        let outside = NSTemporaryDirectory() + "merlin-snap-out-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: outside, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(atPath: dir)
            try? FileManager.default.removeItem(atPath: outside)
        }
        try plist("com.test.agent", "/usr/local/bin/agent").write(
            toFile: dir + "/com.test.agent.plist", atomically: true, encoding: .utf8
        )
        // A symlink pointing OUTSIDE the scanned root must NOT be followed
        // (no-follow invariant) — its label must never appear.
        try plist("com.test.external", "/bin/external").write(
            toFile: outside + "/external.plist", atomically: true, encoding: .utf8
        )
        try FileManager.default.createSymbolicLink(
            atPath: dir + "/link.plist", withDestinationPath: outside + "/external.plist"
        )

        let first = scanLaunchd(roots: [dir])
        #expect(first["com.test.agent"]?.program == "/usr/local/bin/agent")
        #expect(first["com.test.agent"]?.plistHash.isEmpty == false)
        #expect(first["com.test.external"] == nil) // symlink not followed

        // Content change → different hash → 'changed' on next diff.
        try plist("com.test.agent", "/usr/local/bin/evil").write(
            toFile: dir + "/com.test.agent.plist", atomically: true, encoding: .utf8
        )
        let second = scanLaunchd(roots: [dir])
        #expect(second["com.test.agent"]?.plistHash != first["com.test.agent"]?.plistHash)
        let events = diffLaunchd(old: first, new: second)
        #expect(events.count == 1)
        #expect(events[0].change == .changed)
        #expect(events[0].detail["label"] == "com.test.agent")
    }

    @Test("snapshotter tick: baseline emits nothing, drop+remove plist emits added then removed")
    func tick() throws {
        let dir = NSTemporaryDirectory() + "merlin-snap-tick-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let spoolPath = dir + "/events.jsonl"
        let spool = try SpoolWriter(path: spoolPath)
        let snap = Snapshotter(
            spool: spool, interval: 3600,
            launchdRoots: [dir + "/agents"],
            utmpxPath: dir + "/no-utmpx-here"
        )
        try FileManager.default.createDirectory(atPath: dir + "/agents", withIntermediateDirectories: true)
        snap.tick() // baseline
        #expect(spoolEvents(spoolPath).isEmpty)

        try plist("com.test.dropped", "/opt/dropped").write(
            toFile: dir + "/agents/com.test.dropped.plist", atomically: true, encoding: .utf8
        )
        snap.tick()
        var kinds = spoolEvents(spoolPath).compactMap { $0["change"] as? String }
        #expect(kinds == ["added"])
        var detail = spoolEvents(spoolPath).first?["detail"] as? [String: String]
        #expect(detail?["label"] == "com.test.dropped")
        #expect(detail?["program"] == "/opt/dropped")

        try FileManager.default.removeItem(atPath: dir + "/agents/com.test.dropped.plist")
        snap.tick()
        kinds = spoolEvents(spoolPath).compactMap { $0["change"] as? String }
        #expect(kinds == ["added", "removed"])
        detail = spoolEvents(spoolPath).last?["detail"] as? [String: String]
        #expect(detail?["label"] == "com.test.dropped")
    }

    private func spoolEvents(_ path: String) -> [[String: Any]] {
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return [] }
        return text.split(separator: "\n").compactMap {
            try? JSONSerialization.jsonObject(with: Data($0.utf8)) as? [String: Any]
        }
    }
}

@Suite("snapshot event encoding")
struct SnapshotEventEncodingTests {
    @Test("snapshot event key set")
    func encoding() throws {
        let e = SpoolEvent(
            kind: .snapshot, category: "launchd", change: "added",
            detail: ["label": "com.x", "path": "/L/x.plist"]
        )
        let d = try JSONSerialization.jsonObject(with: JSONEncoder().encode(e)) as? [String: Any]
        #expect(Set(d?.keys ?? Dictionary<String, Any>().keys) == [
            "ts", "kind", "source", "source_seq", "schema_version", "boot_id",
            "event_id", "spooled_ts", "process_key", "signals", "category", "change", "detail"
        ])
        #expect(d?["kind"] as? String == "snapshot")
        #expect((d?["detail"] as? [String: String])?["label"] == "com.x")
    }
}

@Suite("background task telemetry")
struct BackgroundTaskTelemetryTests {
    @Test("BTM changes use file events with explicit persistence signals")
    func encoding() throws {
        let path = NSTemporaryDirectory() + "merlin-btm-\(UUID().uuidString).jsonl"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let spool = try SpoolWriter(path: path)
        let engine = Engine(
            rules: try Rules.parse("rules: []"), spool: spool, canBlock: false,
            processIdentity: { _ in nil }
        )
        engine.handleBackgroundTask(
            pid: 4242, path: "/Users/jon/Library/LaunchAgents/com.example.agent.plist",
            op: "create", label: "background_task/agent", program: "/Users/jon/bin/agent",
            signals: ["persistence_change", "background_task_add", "background_task_managed"]
        )
        engine.handleBackgroundTask(
            pid: 4242, path: "/Users/jon/Library/LaunchAgents/com.example.agent.plist",
            op: "delete", label: "background_task/agent", program: nil,
            signals: ["persistence_change", "background_task_remove"]
        )
        let text = try String(contentsOfFile: path, encoding: .utf8)
        let events = text.split(separator: "\n").compactMap {
            try? JSONSerialization.jsonObject(with: Data($0.utf8)) as? [String: Any]
        }
        #expect(events.count == 2)
        guard events.count == 2 else { return }
        #expect(events[0]["kind"] as? String == "file")
        #expect(events[0]["op"] as? String == "create")
        #expect(events[0]["path"] as? String == "/Users/jon/Library/LaunchAgents/com.example.agent.plist")
        #expect(events[0]["program"] as? String == "/Users/jon/bin/agent")
        #expect((events[0]["signals"] as? [String])?.contains("background_task_add") == true)
        #expect(events[1]["op"] as? String == "delete")
        #expect((events[1]["signals"] as? [String])?.contains("background_task_remove") == true)
    }
}
