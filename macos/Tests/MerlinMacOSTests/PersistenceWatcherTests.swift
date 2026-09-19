import Foundation
import Testing
@testable import MerlinMacOS

// Persistence watcher tests — temp-directory watches (create/modify/
// delete/rename), the pure snapshot diff, plist extraction, malformed
// plist tolerance. All unprivileged.

@Suite("persistence snapshot diff")
struct SnapshotDiffTests {
    private let a = FileMeta(inode: 1, mtime: 100, size: 10)
    private let b = FileMeta(inode: 2, mtime: 100, size: 20)

    @Test("create, modify, delete, rename are classified")
    func classification() {
        let old = ["/d/keep": a, "/d/gone": b, "/d/changed": a]
        let new = [
            "/d/keep": a,
            "/d/changed": FileMeta(inode: 1, mtime: 200, size: 10), // mtime bump
            "/d/moved": b, // same inode as /d/gone → rename
            "/d/fresh": FileMeta(inode: 3, mtime: 100, size: 5),
        ]
        let events = diffSnapshots(old: old, new: new)
        let byPath = Dictionary(uniqueKeysWithValues: events.map { ($0.path, $0.op) })
        #expect(byPath["/d/fresh"] == .create)
        #expect(byPath["/d/changed"] == .modify)
        #expect(byPath["/d/moved"] == .rename)
        #expect(byPath["/d/keep"] == nil)
        #expect(byPath["/d/gone"] == nil) // renamed away, not deleted
        // A real delete (inode nowhere in new) is reported.
        let del = diffSnapshots(old: ["/d/x": a], new: [:])
        #expect(del == [FileWatchEvent(path: "/d/x", op: .delete)])
    }
}

@Suite("launch item plist extraction")
struct PlistExtractionTests {
    private func withTempPlist(_ content: String, ext: String = "plist", _ body: (String) -> Void) {
        let path = NSTemporaryDirectory() + "merlin-pw-test-\(UUID().uuidString).\(ext)"
        try? content.write(toFile: path, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: path) }
        body(path)
    }

    @Test("Label and ProgramArguments[0] are extracted")
    func validPlist() {
        withTempPlist("""
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
          <key>Label</key><string>com.example.agent</string>
          <key>ProgramArguments</key><array><string>/usr/local/bin/agent</string><string>--flag</string></array>
          <key>RunAtLoad</key><true/>
        </dict></plist>
        """) { path in
            let info = extractLaunchItemInfo(path: path)
            #expect(info.label == "com.example.agent")
            #expect(info.program == "/usr/local/bin/agent")
        }
    }

    @Test("Program key is used when ProgramArguments is absent")
    func programKey() {
        withTempPlist("""
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
          <key>Label</key><string>com.example.other</string>
          <key>Program</key><string>/opt/evil.sh</string>
        </dict></plist>
        """) { path in
            let info = extractLaunchItemInfo(path: path)
            #expect(info.label == "com.example.other")
            #expect(info.program == "/opt/evil.sh")
        }
    }

    @Test("malformed plist yields nils, never a crash")
    func malformedPlist() {
        withTempPlist("this is not a plist \u{0}\u{1}\u{2} <<<") { path in
            let info = extractLaunchItemInfo(path: path)
            #expect(info.label == nil)
            #expect(info.program == nil)
        }
        // Missing file is also tolerated.
        let info = extractLaunchItemInfo(path: "/nonexistent/\(UUID().uuidString).plist")
        #expect(info.label == nil)
    }
}

@Suite("persistence watcher (temp dir)")
struct PersistenceWatcherTests {
    /// Collect events from a watcher on a fresh temp dir while `body`
    /// mutates it; waits for events asynchronously.
    private func collect(
        _ body: (String) throws -> Void,
        until predicate: @escaping ([FileWatchEvent]) -> Bool
    ) throws -> [FileWatchEvent] {
        let dir = NSTemporaryDirectory() + "merlin-pw-watch-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let state = NSLock()
        var events: [FileWatchEvent] = []
        let watcher = PersistenceWatcher(dirs: [dir]) { ev in
            state.lock()
            events.append(ev)
            state.unlock()
        }
        defer { watcher.stop() }
        try body(dir)
        let deadline = Date().addingTimeInterval(8)
        while Date() < deadline {
            state.lock()
            let snapshot = events
            state.unlock()
            if predicate(snapshot) { return snapshot }
            usleep(100_000)
        }
        state.lock()
        defer { state.unlock() }
        return events
    }

    @Test("create, modify, delete of a file are all observed")
    func createModifyDelete() throws {
        var file = ""
        let events = try collect({ dir in
            file = dir + "/com.test.agent.plist"
            // Non-atomic writes: an atomic save is create-temp + rename,
            // which the watcher correctly reports as rename (inode match).
            try "v1".write(toFile: file, atomically: false, encoding: .utf8)
            usleep(400_000)
            try "v2-longer".write(toFile: file, atomically: false, encoding: .utf8)
            usleep(400_000)
            try FileManager.default.removeItem(atPath: file)
        }, until: { evs in
            let ops = evs.filter { $0.path == file }.map(\.op)
            return ops.contains(.create) && ops.contains(.modify) && ops.contains(.delete)
        })
        let ops = events.filter { $0.path == file }.map(\.op)
        #expect(ops.contains(.create), "no create event; got \(events)")
        #expect(ops.contains(.modify), "no modify event; got \(events)")
        #expect(ops.contains(.delete), "no delete event; got \(events)")
    }

    @Test("rename is observed as rename (inode match)")
    func rename() throws {
        var from = ""
        var to = ""
        let events = try collect({ dir in
            from = dir + "/before.plist"
            to = dir + "/after.plist"
            try "x".write(toFile: from, atomically: true, encoding: .utf8)
            usleep(400_000)
            try FileManager.default.moveItem(atPath: from, toPath: to)
        }, until: { evs in
            evs.contains { $0.path == to && $0.op == .rename }
        })
        #expect(events.contains { $0.path == to && $0.op == .rename },
                "no rename event for \(to); got \(events)")
    }

    @Test("symlinked directories are not traversed")
    func symlinkDirectoryIsNotWatched() throws {
        let root = NSTemporaryDirectory() + "merlin-pw-root-\(UUID().uuidString)"
        let target = NSTemporaryDirectory() + "merlin-pw-target-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: target, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(atPath: root)
            try? FileManager.default.removeItem(atPath: target)
        }
        let link = root + "/linked"
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: target)
        let state = NSLock()
        var events: [FileWatchEvent] = []
        let watcher = PersistenceWatcher(dirs: [root]) { event in
            state.lock()
            events.append(event)
            state.unlock()
        }
        defer { watcher.stop() }
        try "outside-root".write(toFile: target + "/agent.plist", atomically: false, encoding: .utf8)
        usleep(600_000)
        state.lock()
        let snapshot = events
        state.unlock()
        #expect(!snapshot.contains { $0.path == target + "/agent.plist" })
    }
}

@Suite("knockknock expansion")
struct KnockKnockTests {
    @Test("standalone file target: create-via-retry, modify, delete")
    func fileTargetLifecycle() throws {
        let dir = NSTemporaryDirectory() + "merlin-kk-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let rc = dir + "/.zshrc"
        let lock = NSLock()
        var events: [FileWatchEvent] = []
        let watcher = PersistenceWatcher(dirs: [], files: [rc]) { ev in
            lock.lock()
            events.append(ev)
            lock.unlock()
        }
        defer { watcher.stop() }
        // File doesn't exist at watch start — the retry must pick it up.
        let deadline = Date().addingTimeInterval(12)
        var seenCreate = false
        while Date() < deadline {
            if !seenCreate {
                try "export X=1".write(toFile: rc, atomically: false, encoding: .utf8)
                usleep(200_000)
                try "export X=2".write(toFile: rc, atomically: false, encoding: .utf8)
            }
            lock.lock()
            let ops = events.map(\.op)
            lock.unlock()
            if ops.contains(.modify) { seenCreate = true; break }
            usleep(200_000)
        }
        // The file target emits modify on content change (create comes via
        // the retry re-arm; first seen change is a modify against the
        // re-stat baseline or a create from the parent — accept either
        // event present for the path, but require a modify for v2).
        lock.lock()
        let ops = events.map(\.op)
        lock.unlock()
        #expect(ops.contains(.modify), "no modify for \(rc); got \(events)")
        // Delete is reported and the retry re-arms.
        try FileManager.default.removeItem(atPath: rc)
        let delDeadline = Date().addingTimeInterval(8)
        while Date() < delDeadline {
            lock.lock()
            let hasDelete = events.contains { $0.op == .delete }
            lock.unlock()
            if hasDelete { return }
            usleep(100_000)
        }
        lock.lock()
        defer { lock.unlock() }
        #expect(events.contains { $0.op == .delete }, "no delete for \(rc); got \(events)")
    }

    @Test("loginwindow.plist hooks are extracted into the event")
    func loginHooks() throws {
        let dir = NSTemporaryDirectory() + "merlin-kk-lw-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let path = dir + "/com.apple.loginwindow.plist"
        let dict: [String: Any] = ["LoginHook": "/opt/evil/login.sh", "LogoutHook": "/opt/evil/logout.sh", "other": 1]
        try? PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0).write(to: URL(fileURLWithPath: path))
        let hooks = extractLoginHooks(path: path)
        #expect(hooks.login == "/opt/evil/login.sh")
        #expect(hooks.logout == "/opt/evil/logout.sh")
        // Enrichment wires them into label/program.
        var ev = FileWatchEvent(path: path, op: .modify)
        enrichFileEvent(&ev)
        #expect(ev.label == "loginwindow")
        #expect(ev.program == "/opt/evil/login.sh | /opt/evil/logout.sh")
        // Missing file: nils, no crash.
        let none = extractLoginHooks(path: "/nonexistent/\(UUID().uuidString)")
        #expect(none.login == nil && none.logout == nil)
    }

    @Test("loginitems summary: names when present, count otherwise, nil on garbage")
    func loginItems() throws {
        let dir = NSTemporaryDirectory() + "merlin-kk-li-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let path = dir + "/com.apple.loginitems.plist"
        let withItems: [String: Any] = ["customlistitems": [["Name": "Dropbox"], ["Name": "Evil Helper"]]]
        try? PropertyListSerialization.data(fromPropertyList: withItems, format: .xml, options: 0).write(to: URL(fileURLWithPath: path))
        #expect(loginItemsSummary(path: path) == "Dropbox, Evil Helper")
        let noItems: [String: Any] = ["foo": "bar"]
        try? PropertyListSerialization.data(fromPropertyList: noItems, format: .xml, options: 0).write(to: URL(fileURLWithPath: path))
        #expect(loginItemsSummary(path: path) == nil)
        try? "garbage".write(toFile: path, atomically: true, encoding: .utf8)
        #expect(loginItemsSummary(path: path) == nil)
        // Enrichment label.
        var ev = FileWatchEvent(path: path, op: .create)
        enrichFileEvent(&ev)
        #expect(ev.label == "loginitems")
    }

    @Test("watch targets: non-root lists own-home paths, root iterates /Users")
    func targetList() {
        let t = persistenceWatchTargets(root: false)
        #expect(t.dirs.contains("/Library/LaunchAgents"))
        #expect(t.dirs.contains("/usr/lib/cron/tabs"))
        #expect(t.dirs.contains("/var/at/tabs"))
        #expect(t.dirs.contains("/Library/StartupItems"))
        #expect(t.dirs.contains(NSHomeDirectory() + "/Library/LaunchAgents"))
        #expect(t.files.contains("/private/etc/rc.common"))
        #expect(t.files.contains(NSHomeDirectory() + "/.zshrc"))
        #expect(t.files.contains(NSHomeDirectory() + "/Library/Preferences/com.apple.loginitems.plist"))
        #expect(t.files.contains("/Library/Preferences/com.apple.loginwindow.plist"))
        let root = persistenceWatchTargets(root: true)
        #expect(root.dirs.contains { $0.hasPrefix("/Users/") && $0.hasSuffix("/Library/LaunchAgents") })
        #expect(root.files.contains { $0.hasPrefix("/Users/") && $0.hasSuffix(".zshrc") })
    }
}

@Suite("file event encoding")
struct FileEventEncodingTests {
    @Test("file event key set, pid always null")
    func fileEvent() throws {
        let e = SpoolEvent(kind: .file, pid: nil, path: "/Library/LaunchDaemons/x.plist", op: "create", label: "com.x", program: "/bin/x")
        let d = try JSONSerialization.jsonObject(with: JSONEncoder().encode(e)) as? [String: Any]
        #expect(Set(d?.keys ?? Dictionary<String, Any>().keys) == ["ts", "kind", "source", "source_seq", "pid", "path", "op", "label", "program", "device", "inode", "size", "mode", "content_collected", "schema_version", "boot_id", "event_id", "process_key", "signals", "spooled_ts"])
        #expect(d?["pid"] is NSNull) // no attribution from vnode watches
        #expect(d?["op"] as? String == "create")
        #expect(d?["label"] as? String == "com.x")
        #expect(d?["program"] as? String == "/bin/x")
        let bare = SpoolEvent(kind: .file, path: "/private/etc/periodic/daily/x", op: "delete")
        let db = try JSONSerialization.jsonObject(with: JSONEncoder().encode(bare)) as? [String: Any]
        #expect(db?["label"] is NSNull)
        #expect(db?["program"] is NSNull)
    }
}
