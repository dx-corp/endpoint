import Foundation
import Testing
@testable import MerlinMacOS

// Suspend (SIGSTOP quasi-blocking) guardrail tests — the point of the
// feature. Real child processes where signals matter (own user, no
// root), mock signal recording where only the decision logic matters.

@_silgen_name("fork")
private func c_fork() -> pid_t

/// fork a child that pauses (so a watcher can register it) then execs.
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

/// Records (pid, sig) pairs; can deliver the signal for real.
private final class SignalRecorder: @unchecked Sendable {
    let forReal: Bool
    private let lock = NSLock()
    private(set) var calls: [(Int32, Int32)] = []

    init(forReal: Bool) {
        self.forReal = forReal
    }

    func signal(_ pid: Int32, _ sig: Int32) -> Int32 {
        lock.lock()
        calls.append((pid, sig))
        lock.unlock()
        return forReal ? Darwin.kill(pid, sig) : 0
    }

    func contains(_ sig: Int32) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return calls.contains { $0.1 == sig }
    }

    func contains(_ pid: Int32, _ sig: Int32) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return calls.contains { $0.0 == pid && $0.1 == sig }
    }
}

private func spoolEvents(_ path: String) -> [[String: Any]] {
    guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return [] }
    return text.split(separator: "\n").compactMap {
        try? JSONSerialization.jsonObject(with: Data($0.utf8)) as? [String: Any]
    }
}

private func waitForSleep(_ pid: pid_t) throws -> ProcessIdentity {
    let deadline = Date().addingTimeInterval(3)
    while Date() < deadline {
        if let process = procInfo(pid), process.comm == "sleep" {
            return process.identity
        }
        usleep(10_000)
    }
    throw MerlinError.plain("child did not exec /bin/sleep before suspend test deadline")
}

@Suite("suspend guardrails", .serialized)
struct SuspendGuardrailTests {
    private func makeEngine(
        rulesYaml: String,
        signals: SignalRecorder,
        budget: TimeInterval = 2.0
    ) throws -> (Engine, String) {
        let parsed = try Rules.parse(rulesYaml)
        let spoolPath = NSTemporaryDirectory() + "merlin-susp-\(UUID().uuidString).jsonl"
        var engine = Engine(rules: parsed, spool: try SpoolWriter(path: spoolPath), canBlock: false)
        engine.signalImpl = { signals.signal($0, $1) }
        engine.killImpl = { signals.signal($0, SIGKILL) }
        engine.suspendBudget = budget
        return (engine, spoolPath)
    }

    private func reap(_ pid: pid_t) {
        var status: Int32 = 0
        waitpid(pid, &status, 0)
    }

    @Test("failsafe: pid 1 and own pid are never SIGSTOPped")
    func noSuspendOnFailsafe() throws {
        let signals = SignalRecorder(forReal: false)
        let (engine, _) = try makeEngine(rulesYaml: """
        rules:
          - name: susp
            match: {path_basename: sleep}
            action: suspend
        """, signals: signals)
        engine.handleExec(pid: 1, ppid: nil, uid: 0, comm: "sleep", exe: "/bin/sleep", cmdline: "sleep 30", sha256: nil, cdhash: nil)
        engine.handleExec(pid: getpid(), ppid: nil, uid: getuid(), comm: "sleep", exe: "/bin/sleep", cmdline: "sleep 30", sha256: nil, cdhash: nil)
        #expect(!signals.contains(SIGSTOP))
        #expect(!signals.contains(SIGKILL))
    }

    @Test("no second-stage match: child is stopped, inspected, and resumed (suspend_released)")
    func resumeOnMismatch() throws {
        let signals = SignalRecorder(forReal: true)
        var (engine, spoolPath) = try makeEngine(rulesYaml: """
        rules:
          - name: susp-sleep
            match: {path_basename: sleep}
            action: suspend
        """, signals: signals)
        defer { try? FileManager.default.removeItem(atPath: spoolPath) }
        let child = forkExec("/bin/sleep", ["30"])
        defer { Darwin.kill(child, SIGKILL); reap(child) }
        let identity = try waitForSleep(child)
        engine.processIdentity = { pid in pid == child ? identity : procInfo(pid)?.identity }
        engine.handleExec(
            pid: child, ppid: getpid(), uid: getuid(), comm: "sleep", exe: "/bin/sleep",
            cmdline: "sleep 30", sha256: nil, cdhash: nil, identity: identity
        )
        #expect(signals.contains(child, SIGSTOP))
        #expect(signals.contains(child, SIGCONT))
        #expect(!signals.contains(child, SIGKILL))
        let events = spoolEvents(spoolPath)
        let exec = events.first { $0["kind"] as? String == "exec" }
        #expect(exec?["suspend_released"] as? Bool == true)
        #expect(events.allSatisfy { $0["kind"] as? String != "kill" })
    }

    @Test("second-stage kill rule matches: frozen child is killed (via_suspend)")
    func killOnMatch() throws {
        let signals = SignalRecorder(forReal: true)
        var (engine, spoolPath) = try makeEngine(rulesYaml: """
        rules:
          - name: susp-sleep
            match: {path_basename: sleep}
            action: suspend
          - name: kill-sleepers
            match_all:
              path_basename: sleep
              uid: \(getuid())
            action: kill
        """, signals: signals)
        defer { try? FileManager.default.removeItem(atPath: spoolPath) }
        let child = forkExec("/bin/sleep", ["30"])
        defer { Darwin.kill(child, SIGKILL); reap(child) }
        let identity = try waitForSleep(child)
        engine.processIdentity = { pid in pid == child ? identity : procInfo(pid)?.identity }
        engine.handleExec(
            pid: child, ppid: getpid(), uid: getuid(), comm: "sleep", exe: "/bin/sleep",
            cmdline: "sleep 30", sha256: nil, cdhash: nil, identity: identity
        )
        #expect(signals.contains(child, SIGSTOP))
        #expect(signals.contains(child, SIGKILL))
        let events = spoolEvents(spoolPath)
        let kill = events.first { $0["kind"] as? String == "kill" }
        #expect(kill?["via_suspend"] as? Bool == true)
        #expect(kill?["matched_rules"] as? [String] == ["kill-sleepers"])
        var status: Int32 = 0
        waitpid(child, &status, 0)
        #expect(status & 0x7f == 9) // died of SIGKILL
    }

    @Test("freeze budget: expired budget resumes immediately, never kills")
    func freezeBudget() throws {
        let signals = SignalRecorder(forReal: false)
        var (engine, _) = try makeEngine(rulesYaml: """
        rules:
          - name: susp
            match: {path_basename: sleep}
            action: suspend
          - name: kill-anything
            match: {path_basename: sleep}
            action: kill
        """, signals: signals, budget: 0)
        let identity = ProcessIdentity(startSec: 1, startUsec: 0)
        engine.processIdentity = { _ in identity }
        engine.handleExec(
            pid: 999_999, ppid: nil, uid: getuid(), comm: "sleep", exe: "/bin/sleep",
            cmdline: nil, sha256: nil, cdhash: nil,
            identity: identity
        )
        #expect(signals.contains(SIGSTOP))
        #expect(signals.contains(SIGCONT))
        #expect(!signals.contains(SIGKILL))
    }

    @Test("missing identity before suspension: no process is signaled")
    func missingIdentitySkipsSuspension() throws {
        let signals = SignalRecorder(forReal: false)
        let (engine, _) = try makeEngine(rulesYaml: """
        rules:
          - name: susp
            match: {path_basename: sleep}
            action: suspend
          - name: kill-sleep
            match: {path_basename: sleep}
            action: kill
        """, signals: signals)
        engine.handleExec(
            pid: 888_888, ppid: nil, uid: getuid(), comm: "sleep", exe: "/bin/sleep",
            cmdline: nil, sha256: nil, cdhash: nil, identity: nil
        )
        #expect(!signals.contains(SIGSTOP))
        #expect(!signals.contains(SIGCONT))
        #expect(!signals.contains(SIGKILL))
    }

    @Test("shutdown release: only identity-matched pids get SIGCONT")
    func shutdownRelease() throws {
        let recorder = SignalRecorder(forReal: false)
        let first = ProcessIdentity(startSec: 1, startUsec: 1)
        let second = ProcessIdentity(startSec: 2, startUsec: 2)
        SuspendedPids.shared.hold(111, identity: first)
        SuspendedPids.shared.hold(222, identity: second)
        #expect(SuspendedPids.shared.count == 2)
        let released = SuspendedPids.shared.releaseAll(
            processIdentity: { $0 == 111 ? first : ProcessIdentity(startSec: 9, startUsec: 9) },
            signal: { recorder.signal($0, $1) }
        )
        #expect(released == [111])
        #expect(SuspendedPids.shared.count == 0)
        #expect(recorder.contains(111, SIGCONT))
        #expect(!recorder.contains(222, SIGCONT))
    }
}

@Suite("suspend event encoding")
struct SuspendEncodingTests {
    @Test("via_suspend on kill, suspend_released on exec — conditional keys")
    func encoding() throws {
        let kill = SpoolEvent(kind: .kill, pid: 1, comm: "x", exe: "/x", matchedRules: ["r"], viaSuspend: true)
        let dk = try JSONSerialization.jsonObject(with: JSONEncoder().encode(kill)) as? [String: Any]
        #expect(dk?["via_suspend"] as? Bool == true)
        let killPlain = SpoolEvent(kind: .kill, pid: 1, matchedRules: ["r"])
        let dp = try JSONSerialization.jsonObject(with: JSONEncoder().encode(killPlain)) as? [String: Any]
        #expect(dp?["via_suspend"] == nil)
        let exec = SpoolEvent(kind: .exec, pid: 1, comm: "x", exe: "/x", matchedRules: [], suspendReleased: true)
        let de = try JSONSerialization.jsonObject(with: JSONEncoder().encode(exec)) as? [String: Any]
        #expect(de?["suspend_released"] as? Bool == true)
        let execPlain = SpoolEvent(kind: .exec, pid: 1, matchedRules: [])
        let dx = try JSONSerialization.jsonObject(with: JSONEncoder().encode(execPlain)) as? [String: Any]
        #expect(dx?["suspend_released"] == nil)
    }
}
