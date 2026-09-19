import Foundation
import Testing
@testable import MerlinMacOS

// Santa rules model: team_id/signing_id selectors, specificity
// precedence, and the hard-coded failsafes. Plus the SecStaticCode /
// csops / xattr enrichment helpers.

private func rule(_ yaml: String) throws -> Rule {
    try Rules.decodeOne(yaml)
}

@Suite("signing selectors")
struct SigningSelectorTests {
    @Test("team_id matches exactly")
    func teamId() throws {
        let r = try rule("name: t\nmatch:\n  team_id: ABCDEFG123\naction: log\n")
        #expect(r.matches(MatchCtx(teamId: "ABCDEFG123")))
        #expect(!r.matches(MatchCtx(teamId: "ABCDEFG1234")))
        #expect(!r.matches(MatchCtx(basename: "zsh")))
    }

    @Test("signing_id matches exactly (not prefix)")
    func signingId() throws {
        let r = try rule("name: t\nmatch:\n  signing_id: com.apple.curl\naction: log\n")
        #expect(r.matches(MatchCtx(signingId: "com.apple.curl")))
        #expect(!r.matches(MatchCtx(signingId: "com.apple.curling")))
    }

    @Test("is_platform_binary selector")
    func platformBinary() throws {
        let r = try rule("name: t\nmatch:\n  is_platform_binary: true\naction: log\n")
        #expect(r.matches(MatchCtx(isPlatformBinary: true)))
        #expect(!r.matches(MatchCtx(isPlatformBinary: false)))
        #expect(!r.matches(MatchCtx())) // unknown is not a match
    }
}

@Suite("rule precedence (Santa specificity)")
struct PrecedenceTests {
    private func rules(_ yamls: [String]) throws -> [Rule] {
        try yamls.map { try Rules.decodeOne($0) }
    }

    @Test("cdhash > sha256 > signing_id > team_id > basename")
    func tierOrder() throws {
        let rs = try rules([
            "name: by-basename\nmatch:\n  path_basename: x\naction: log\n",
            "name: by-team\nmatch:\n  team_id: T\naction: log\n",
            "name: by-signing\nmatch:\n  signing_id: com.x\naction: log\n",
            "name: by-sha\nmatch:\n  sha256: aa\naction: log\n",
            "name: by-cdhash\nmatch:\n  cdhash: bb\naction: log\n",
        ])
        // All match the same ctx; only the top tier survives.
        let ctx = MatchCtx(sha256: "aa", basename: "x", cdhash: "bb", teamId: "T", signingId: "com.x")
        let matched = rs.filter { $0.matches(ctx) }
        #expect(matched.count == 5)
        #expect(mostSpecific(matched).map(\.name) == ["by-cdhash"])
        let noCd = matched.filter { $0.name != "by-cdhash" }
        #expect(mostSpecific(noCd).map(\.name) == ["by-sha"])
        let noHash = noCd.filter { $0.name != "by-sha" }
        #expect(mostSpecific(noHash).map(\.name) == ["by-signing"])
        let noSigning = noHash.filter { $0.name != "by-signing" }
        #expect(mostSpecific(noSigning).map(\.name) == ["by-team"])
        let noTeam = noSigning.filter { $0.name != "by-team" }
        #expect(mostSpecific(noTeam).map(\.name) == ["by-basename"])
    }

    @Test("ties within a tier all apply")
    func tierTies() throws {
        let rs = try rules([
            "name: a\nmatch:\n  path_basename: x\naction: log\n",
            "name: b\nmatch:\n  cmdline_contains: x\naction: log\n",
            "name: c\nmatch:\n  sha256: aa\naction: log\n",
        ])
        let ctx = MatchCtx(sha256: nil, basename: "x", cmdline: "x")
        let matched = rs.filter { $0.matches(ctx) }
        #expect(Set(mostSpecific(matched).map(\.name)) == ["a", "b"])
    }

    @Test("single match is unchanged (backward compat)")
    func singleMatch() throws {
        let rs = try rules(["name: only\nmatch:\n  path_basename: nc\naction: kill\n"])
        let matched = rs.filter { $0.matches(MatchCtx(basename: "nc")) }
        #expect(mostSpecific(matched).map(\.name) == ["only"])
    }
}

@Suite("engine failsafes")
struct FailsafeTests {
    private let spoolPath = NSTemporaryDirectory() + "merlin-failsafe-\(UUID().uuidString).jsonl"

    /// Thread-safe record of kill() invocations.
    final class KillRecorder: @unchecked Sendable {
        private let lock = NSLock()
        private var pids: [Int32] = []

        func record(_ pid: Int32) {
            lock.lock()
            pids.append(pid)
            lock.unlock()
        }

        var calls: [Int32] {
            lock.lock()
            defer { lock.unlock() }
            return pids
        }
    }

    private func makeEngine() throws -> (Engine, KillRecorder) {
        let r = try Rules.decodeOne("name: kill-all\nmatch:\n  path_basename: evil\naction: kill\n")
        let spool = try SpoolWriter(path: spoolPath)
        let recorder = KillRecorder()
        let engine = Engine(
            rules: Rules(rules: [r]), spool: spool, canBlock: true,
            killImpl: { pid in recorder.record(pid); return 0 },
            selfPID: 42_424,
            ownTeamId: "OWNTEAM42",
            processIdentity: { _ in ProcessIdentity(startSec: 1, startUsec: 1) }
        )
        return (engine, recorder)
    }

    @Test("pid 1 is never killed or blocked")
    func launchdProtected() throws {
        let (engine, recorder) = try makeEngine()
        engine.handleExec(pid: 1, ppid: nil, uid: 0, comm: "evil", exe: "/tmp/evil", cmdline: nil, sha256: nil, cdhash: nil)
        #expect(recorder.calls.isEmpty)
        let v = engine.authVerdict(pid: 1, uid: 0, path: "/tmp/evil", sha256: nil, cdhash: nil)
        #expect(v.allow)
    }

    @Test("the sensor's own pid is never killed or blocked")
    func selfProtected() throws {
        let (engine, recorder) = try makeEngine()
        engine.handleExec(pid: 42_424, ppid: nil, uid: 501, comm: "evil", exe: "/tmp/evil", cmdline: nil, sha256: nil, cdhash: nil)
        #expect(recorder.calls.isEmpty)
        #expect(engine.authVerdict(pid: 42_424, uid: 501, path: "/tmp/evil", sha256: nil, cdhash: nil).allow)
    }

    @Test("a process signed by the daemon's own team is never killed")
    func ownTeamProtected() throws {
        let (engine, recorder) = try makeEngine()
        let signing = SigningInfo(teamId: "OWNTEAM42", signingId: "com.merlin.other", cdhash: nil, adhoc: false, platformBinary: false)
        engine.handleExec(
            pid: 777, ppid: nil, uid: 501, comm: "evil", exe: "/tmp/evil",
            cmdline: nil, sha256: nil, cdhash: nil, signing: signing
        )
        #expect(recorder.calls.isEmpty)
        // A different team's process is fair game.
        let other = SigningInfo(teamId: "OTHERTEAM", signingId: "com.x", cdhash: nil, adhoc: false, platformBinary: false)
        engine.handleExec(
            pid: 778, ppid: nil, uid: 501, comm: "evil", exe: "/tmp/evil",
            cmdline: nil, sha256: nil, cdhash: nil, signing: other,
            identity: ProcessIdentity(startSec: 1, startUsec: 1)
        )
        #expect(recorder.calls == [778])
    }

    @Test("failsafe check itself: launchd/self/own-team true, others false")
    func isFailsafeMatrix() throws {
        let (engine, _) = try makeEngine()
        #expect(engine.isFailsafe(pid: 1, teamId: nil))
        #expect(engine.isFailsafe(pid: 42_424, teamId: nil))
        #expect(engine.isFailsafe(pid: 5, teamId: "OWNTEAM42"))
        #expect(!engine.isFailsafe(pid: 5, teamId: "OTHER"))
        #expect(!engine.isFailsafe(pid: 5, teamId: nil))
    }
}

@Suite("signing enrichment helpers")
struct SigningEnrichmentTests {
    @Test("static info: Apple binary identified; unsigned file has no identity")
    func staticInfo() {
        let zsh = signingInfo(path: "/bin/zsh")
        #expect(zsh != nil)
        #expect(zsh?.signingId == "com.apple.zsh")
        #expect(zsh?.cdhash?.isEmpty == false)
        // A plain text file yields an identity-less result, not a crash.
        let text = signingInfo(path: "/etc/passwd")
        #expect(text?.signingId == nil)
        #expect(text?.cdhash == nil)
        #expect(text?.unsigned == true)
    }

    @Test("runtime platform-binary flag via csops")
    func runtimePlatformBinary() {
        // Xcode may sign the test runner as either a platform or non-platform
        // binary; a live process must still yield a definite csops result.
        #expect(isPlatformBinary(pid: getpid()) != nil)
        // A dead pid yields nil, not a crash.
        #expect(isPlatformBinary(pid: 0x7FFF_FFFE) == nil)
    }

    @Test("quarantine xattr: present, absent, unreadable")
    func quarantine() throws {
        let path = NSTemporaryDirectory() + "merlin-quar-\(UUID().uuidString)"
        try "x".write(toFile: path, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: path) }
        #expect(isQuarantined(path: path) == false) // no xattr
        var value: UInt8 = 0x01
        #expect(setxattr(path, "com.apple.quarantine", &value, 1, 0, XATTR_NOFOLLOW) == 0)
        #expect(isQuarantined(path: path) == true)
        #expect(isQuarantined(path: "/nonexistent/\(UUID().uuidString)") == nil)
    }
}
