import Foundation
import Testing
@testable import MerlinMacOS

// KqueueProvider end-to-end tests. No root needed: EVFILT_PROC covers the
// user's own processes unprivileged, which is exactly what these tests
// exercise. The suite is serialized because each test seeds ~2000 proc
// filters and spawns real children.
//
// Children are spawned with raw fork()+execl (NOT Foundation Process /
// posix_spawn): posix_spawn fuses fork+exec, so the exec usually lands
// before the provider's NOTE_FORK handling has registered the child and
// the exec event is lost — an inherent race of EVFILT_PROC, documented in
// the README. A 100 ms pre-exec sleep in the child makes registration
// deterministic.

@_silgen_name("fork")
private func c_fork() -> pid_t

/// fork a child that pauses (so the provider's NOTE_FORK handling registers
/// it) and then execs `path` with `args`. Returns the child pid.
@discardableResult
private func forkExec(_ path: String, _ args: [String]) -> pid_t {
    let child = c_fork()
    if child == 0 {
        usleep(100_000)
        let cargs = ([path] + args).map { strdup($0) } + [nil]
        var va: [UnsafeMutablePointer<CChar>?] = cargs
        execve(path, &va, nil)
        _exit(127)
    }
    return child
}

private func makeProvider(rulesYAML: String, spoolPath: String) throws -> KqueueProvider {
    let rule = try Rules.decodeOne(rulesYAML)
    let engine = Engine(rules: Rules(rules: [rule]), spool: try SpoolWriter(path: spoolPath), canBlock: false)
    let provider = KqueueProvider(engine: engine)
    try provider.start()
    return provider
}

private func spoolEvents(_ path: String) -> [[String: Any]] {
    guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return [] }
    return text.split(separator: "\n").compactMap {
        try? JSONSerialization.jsonObject(with: Data($0.utf8)) as? [String: Any]
    }
}

/// Poll the spool until `predicate` matches an event or the deadline passes.
private func awaitEvent(
    in path: String,
    timeout: TimeInterval = 8,
    matching predicate: ([String: Any]) -> Bool
) -> [String: Any]? {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if let hit = spoolEvents(path).first(where: predicate) { return hit }
        usleep(100_000)
    }
    return nil
}

@Suite("kqueue provider", .serialized)
struct KqueueProviderTests {
    @Test("sees exec and exit of an own-process child")
    func execAndExitObserved() throws {
        let spool = NSTemporaryDirectory() + "merlin-kq-test-\(UUID().uuidString).jsonl"
        defer { try? FileManager.default.removeItem(atPath: spool) }
        let provider = try makeProvider(rulesYAML: """
        name: log-all-sleep
        match: {path_basename: sleep}
        action: log
        """, spoolPath: spool)
        defer { provider.stop() }

        // Distinctive duration doubles as a unique marker in the cmdline.
        let marker = "0.313"
        let pid = forkExec("/bin/sleep", [marker])

        let exec = awaitEvent(in: spool) {
            $0["kind"] as? String == "exec"
                && $0["pid"] as? Int32 == pid
                && ($0["exe"] as? String)?.hasSuffix("/sleep") == true
        }
        #expect(exec != nil, "no NOTE_EXEC-derived exec event for /bin/sleep child within timeout")
        #expect((exec?["cmdline"] as? String)?.contains(marker) == true)
        #expect(exec?["uid"] as? Int == Int(getuid()))
        #expect(exec?["matched_rules"] as? [String] == ["log-all-sleep"])

        var status: Int32 = 0
        waitpid(pid, &status, 0)
        let exit = awaitEvent(in: spool) {
            $0["kind"] as? String == "exit" && $0["pid"] as? Int32 == pid
        }
        #expect(exit != nil, "no NOTE_EXIT-derived exit event for /bin/sleep child within timeout")
        // Own children get NOTE_EXITSTATUS (wait(2)-style status in kevent
        // data); /bin/sleep exits 0. Cross-user/unreadable exits still
        // spool null here — that path can't be tested unprivileged.
        #expect(exit?["exit_code"] as? Int == 0)
        #expect(exit?["exit_status"] as? Int == 0)
        #expect(exit?["comm"] as? String == "sleep")
    }

    @Test("exit status propagates for own children (NOTE_EXITSTATUS)")
    func exitStatusPropagated() throws {
        let spool = NSTemporaryDirectory() + "merlin-kq-test-\(UUID().uuidString).jsonl"
        defer { try? FileManager.default.removeItem(atPath: spool) }
        let provider = try makeProvider(rulesYAML: """
        name: log-all
        match: {uid: \(getuid())}
        action: log
        """, spoolPath: spool)
        defer { provider.stop() }

        // Raw fork child: pause for registration, then exit(42).
        let pid = forkExec("/bin/sh", ["-c", "exit 42"])
        var status: Int32 = 0
        waitpid(pid, &status, 0)

        let exit = awaitEvent(in: spool) {
            $0["kind"] as? String == "exit" && $0["pid"] as? Int32 == pid
        }
        #expect(exit != nil, "no exit event for exit(42) child within timeout")
        // 42 << 8 = 10752, wait(2)-style; exit_status applies (code>>8)&0xff.
        #expect(exit?["exit_code"] as? Int == 10752)
        #expect(exit?["exit_status"] as? Int == 42)
    }

    @Test("fused posix_spawn child is covered end-to-end (rescan/fork path)")
    func posixSpawnCoverage() throws {
        let spool = NSTemporaryDirectory() + "merlin-kq-test-\(UUID().uuidString).jsonl"
        defer { try? FileManager.default.removeItem(atPath: spool) }
        let provider = try makeProvider(rulesYAML: """
        name: log-all
        match: {uid: \(getuid())}
        action: log
        """, spoolPath: spool)
        defer { provider.stop() }

        // Foundation Process uses posix_spawn: fork+exec are fused, so the
        // exec event itself may be lost to the registration race — but the
        // child must still be tracked (NOTE_FORK path or the 1s rescan) and
        // its exit must be seen.
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/sleep")
        proc.arguments = ["1.5"]
        try proc.run()
        let pid = proc.processIdentifier

        let seen = awaitEvent(in: spool) {
            $0["pid"] as? Int32 == pid && ["fork", "exec"].contains($0["kind"] as? String ?? "")
        }
        #expect(seen != nil, "posix_spawn'd child never tracked (no fork/exec event)")
        proc.waitUntilExit()
        let exit = awaitEvent(in: spool) {
            $0["kind"] as? String == "exit" && $0["pid"] as? Int32 == pid
        }
        #expect(exit != nil, "no exit event for posix_spawn'd child within timeout")
    }

    @Test("kill rule SIGKILLs a matching exec (no root needed for own processes)")
    func killRuleEnforced() throws {
        let marker = "merlin-kq-test-\(UUID().uuidString)"
        let spool = NSTemporaryDirectory() + "merlin-kq-test-\(UUID().uuidString).jsonl"
        defer { try? FileManager.default.removeItem(atPath: spool) }
        let provider = try makeProvider(rulesYAML: """
        name: kill-marked
        match: {cmdline_contains: "\(marker)"}
        action: kill
        """, spoolPath: spool)
        defer { provider.stop() }

        let pid = forkExec("/bin/bash", ["-c", "sleep 30 # \(marker)"])

        let kill = awaitEvent(in: spool) {
            $0["kind"] as? String == "kill"
                && $0["pid"] as? Int32 == pid
                && $0["matched_rules"] as? [String] == ["kill-marked"]
        }
        #expect(kill != nil, "no kill event for marked child within timeout")
        var status: Int32 = 0
        waitpid(pid, &status, 0)
        #expect(kill != nil ? (status & 0x7f) == 9 : false) // died of SIGKILL
    }

    @Test("childPids lists live children; procArgs reads own argv")
    func libprocHelpers() throws {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/sleep")
        proc.arguments = ["2"]
        try proc.run()
        defer { proc.terminate(); proc.waitUntilExit() }

        var found = false
        for _ in 0 ..< 20 {
            if childPids(of: getpid()).contains(proc.processIdentifier) { found = true; break }
            usleep(50_000)
        }
        #expect(found, "childPids(of: self) did not list the spawned child")
        #expect(pidPath(proc.processIdentifier)?.hasSuffix("/sleep") == true)
        #expect(procArgs(proc.processIdentifier)?.contains("/bin/sleep") == true)
        // Own argv is always readable.
        #expect(procArgs(getpid())?.isEmpty == false)
    }
}
