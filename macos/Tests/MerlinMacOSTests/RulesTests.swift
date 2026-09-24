import Foundation
import MerlinClientCore
import Testing
@testable import MerlinMacOS

// Rules engine tests — semantics mirror merlin/src/rules.rs tests, plus the
// macOS cdhash selector and a cross-load of the Linux repo's example file.

private func rule(_ yaml: String) throws -> Rule {
    try Rules.decodeOne(yaml)
}

@Suite("rules")
struct RulesTests {
    /// repo root = macos/Tests/MerlinMacOSTests/this file, four levels up.
    static let repoRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()

    @Test("approved alternative is decoded only for enforcement")
    func approvedAlternative() throws {
        let base = "name: block-cursor\nmatch:\n  path_basename: Cursor\naction: block\napproved_alternative:\n  name: Approved editor\n  url: https://tools.example.com/editor\n"
        let parsed = try rule(base)
        #expect(parsed.approvedAlternative?.name == "Approved editor")
        #expect(parsed.approvedAlternative?.url.absoluteString == "https://tools.example.com/editor")
        #expect(throws: Error.self) { try rule(base.replacingOccurrences(of: "action: block", with: "action: log")) }
        #expect(throws: Error.self) { try rule(base.replacingOccurrences(of: "https://tools.example.com/editor", with: "http://tools.example.com/editor")) }
    }

    @Test("an actual deny publishes the mapped alternative, and a failsafe does not")
    func deniedExecutionGuidance() throws {
        let parsed = try rule("name: block-cursor\nmatch:\n  path_basename: Cursor\naction: block\napproved_alternative:\n  name: Approved editor\n  url: https://tools.example.com/editor\n")
        let store = LocalStatusStore()
        var engine = Engine(rules: Rules(rules: [parsed]),
                            spool: try SpoolWriter(path: NSTemporaryDirectory() + "merlin-guidance-\(UUID().uuidString).jsonl"),
                            canBlock: true)
        engine.onEnforcement = { action, alternative in
            store.recordEnforcement(action: action, approvedName: alternative?.name, approvedURL: alternative?.url)
        }
        #expect(engine.authVerdict(pid: 1, uid: 0, path: "/tmp/Cursor", sha256: nil, cdhash: nil).allow)
        #expect(store.snapshot().enforcement == nil)
        #expect(!engine.authVerdict(pid: 42_424, uid: 501, path: "/tmp/Cursor", sha256: nil, cdhash: nil).allow)
        #expect(store.snapshot().enforcement?.action == .blocked)
        #expect(store.snapshot().enforcement?.approvedName == "Approved editor")
    }

    @Test("reactive kill guidance appears only after a successful kill")
    func stoppedExecutionGuidance() throws {
        let parsed = try rule("name: stop-claude\nmatch:\n  path_basename: claude\naction: kill\napproved_alternative:\n  name: Approved agent\n  url: https://tools.example.com/agent\n")
        let store = LocalStatusStore()
        let identity = ProcessIdentity(startSec: 1, startUsec: 1)
        var engine = Engine(rules: Rules(rules: [parsed]),
                            spool: try SpoolWriter(path: NSTemporaryDirectory() + "merlin-guidance-\(UUID().uuidString).jsonl"),
                            canBlock: false, killImpl: { _ in 0 }, selfPID: 42_424,
                            processIdentity: { _ in identity })
        engine.onEnforcement = { action, alternative in
            store.recordEnforcement(action: action, approvedName: alternative?.name, approvedURL: alternative?.url)
        }
        engine.handleExec(pid: 1, ppid: nil, uid: 0, comm: "claude", exe: "/tmp/claude",
                          cmdline: nil, sha256: nil, cdhash: nil, identity: identity)
        #expect(store.snapshot().enforcement == nil)
        engine.handleExec(pid: 123, ppid: nil, uid: 501, comm: "claude", exe: "/tmp/claude",
                          cmdline: nil, sha256: nil, cdhash: nil, identity: identity)
        #expect(store.snapshot().enforcement?.action == .stopped)
        #expect(store.snapshot().enforcement?.approvedName == "Approved agent")
    }
    @Test("cross-loads the Linux repo's rules/block-demo.yaml")
    func blockDemoYaml() throws {
        let path = Self.repoRoot.appendingPathComponent("rules/block-demo.yaml").path
        let rules = try Rules.load(path: path)
        #expect(rules.rules.count == 1)
        let r = rules.rules[0]
        #expect(r.name == "block-merlin-evil")
        #expect(r.action == .block)
        #expect(r.match.sha256 == "9f2e8d80e1c357b889e1b827566e882411ddc6ff45a70196e808f00e62a6c7c5")
        #expect(r.match.pathBasename == "merlin-evil")
        // Fires on the basename fallback even without a hash (hash-primary,
        // basename-fallback semantics).
        #expect(r.matches(MatchCtx(basename: "merlin-evil")))
        #expect(r.matches(MatchCtx(sha256: "9f2e8d80e1c357b889e1b827566e882411ddc6ff45a70196e808f00e62a6c7c5")))
        #expect(!r.matches(MatchCtx(sha256: "deadbeef", basename: "id")))
    }

    @Test("cross-loads the Linux LOLBin pack (match_all and all its selectors)")
    func linuxLolbinPack() throws {
        let path = Self.repoRoot.appendingPathComponent("rules/content/linux-lolbins.yaml").path
        let rules = try Rules.load(path: path)
        #expect(!rules.rules.isEmpty)
        #expect(rules.rules.contains { $0.matchAll != nil })
    }

    @Test("a hash under match_all still asks the AUTH path for a hash")
    func matchAllHashIsGated() throws {
        let r = try rule(
            "name: t\nmatch_all:\n  sha256: abc\n  path_prefix: /private/tmp/\naction: block\n")
        #expect(r.hasSHA256Selector)
        let engine = Engine(
            rules: Rules(rules: [r]),
            spool: try SpoolWriter(path: NSTemporaryDirectory() + "merlin-gate-\(UUID().uuidString).jsonl"),
            canBlock: true
        )
        // Without this the executable is never hashed and the rule can
        // never deny — the gap the Linux port closed with
        // Rule::has_sha256_selector.
        #expect(engine.needsSHA256ForAuth)
    }

    @Test("sha256 or basename triggers a block")
    func sha256OrBasenameBlock() throws {
        let r = try rule("name: t\nmatch:\n  sha256: abc\n  path_basename: evil\naction: block\n")
        #expect(r.matches(MatchCtx(sha256: "abc")))
        #expect(r.matches(MatchCtx(basename: "evil")))
        #expect(!r.matches(MatchCtx(sha256: "def", basename: "good")))
    }

    @Test("uid constrains selectors")
    func uidConstrainsSelectors() throws {
        let r = try rule("name: t\nmatch:\n  path_basename: sh\n  uid: 0\naction: kill\n")
        #expect(r.matches(MatchCtx(basename: "sh", uid: 0)))
        #expect(!r.matches(MatchCtx(basename: "sh", uid: 1000)))
    }

    @Test("cmdline_contains selector")
    func cmdlineContains() throws {
        let r = try rule("name: t\nmatch:\n  cmdline_contains: --evil-flag\naction: log\n")
        #expect(r.matches(MatchCtx(cmdline: "/bin/tool --evil-flag -x")))
        #expect(!r.matches(MatchCtx(cmdline: "/bin/tool -x")))
    }

    @Test("cdhash selector (macOS addition)")
    func cdhashSelector() throws {
        let r = try rule("name: t\nmatch:\n  cdhash: \"0123abcdef\"\naction: block\n")
        #expect(r.matches(MatchCtx(cdhash: "0123abcdef")))
        #expect(!r.matches(MatchCtx(cdhash: "ffff")))
    }

    @Test("uid-only rule fires on uid alone")
    func uidOnly() throws {
        let r = try rule("name: t\nmatch:\n  uid: 0\naction: log\n")
        #expect(r.matches(MatchCtx(uid: 0)))
        #expect(!r.matches(MatchCtx(uid: 501)))
    }

    @Test("unknown policy fields are rejected")
    func unknownFieldsRejected() {
        do {
            _ = try rule("name: t\nmatch:\n  daddr_typo: 8.8.8.8\naction: log\n")
            Issue.record("unsupported policy fields must not become no-ops")
        } catch {
            // Expected: policy schema errors are fail-closed at load time.
        }
    }

    @Test("daddr selector (exact string, v4 or v6)")
    func daddrSelector() throws {
        let r = try rule("name: t\nmatch:\n  daddr: 8.8.8.8\naction: log\n")
        #expect(r.matches(MatchCtx(daddr: "8.8.8.8")))
        #expect(!r.matches(MatchCtx(daddr: "1.1.1.1")))
        #expect(!r.matches(MatchCtx(basename: "curl"))) // absent daddr ≠ match
        let r6 = try rule("name: t\nmatch:\n  daddr: \"2606:4700:4700::1111\"\naction: log\n")
        #expect(r6.matches(MatchCtx(daddr: "2606:4700:4700::1111")))
        #expect(!r6.matches(MatchCtx(daddr: "2606:4700:4700::1001")))
    }

    @Test("dport selector")
    func dportSelector() throws {
        let r = try rule("name: t\nmatch:\n  dport: 53\naction: log\n")
        #expect(r.matches(MatchCtx(dport: 53)))
        #expect(!r.matches(MatchCtx(dport: 443)))
    }

    @Test("dns_contains selector (case-insensitive substring on qname)")
    func dnsContainsSelector() throws {
        let r = try rule("name: t\nmatch:\n  dns_contains: ExFil\naction: log\n")
        #expect(r.matches(MatchCtx(dns: "data.exfil.example.com")))
        #expect(!r.matches(MatchCtx(dns: "example.com")))
        #expect(!r.matches(MatchCtx(daddr: "8.8.8.8"))) // no qname in ctx
    }

    @Test("combined network selectors: uid constraint + daddr + dport")
    func combinedNetworkSelectors() throws {
        let r = try rule("name: t\nmatch:\n  daddr: 8.8.8.8\n  dport: 53\n  uid: 501\naction: log\n")
        #expect(r.matches(MatchCtx(uid: 501, daddr: "8.8.8.8", dport: 53)))
        #expect(!r.matches(MatchCtx(uid: 0, daddr: "8.8.8.8", dport: 53)))
        // Selectors are OR'd (same as sha256+path_basename): dport alone fires.
        #expect(r.matches(MatchCtx(uid: 501, daddr: "8.8.4.4", dport: 53)))
        #expect(!r.matches(MatchCtx(uid: 501, daddr: "8.8.4.4", dport: 853)))
    }

    @Test("path_prefix selector")
    func pathPrefix() throws {
        let r = try rule("name: t\nmatch:\n  path_prefix: /private/tmp/\naction: log\n")
        #expect(r.matches(MatchCtx(path: "/private/tmp/evil")))
        #expect(!r.matches(MatchCtx(path: "/usr/bin/evil")))
        #expect(!r.matches(MatchCtx(basename: "evil"))) // basename alone doesn't feed path_prefix
    }

    @Test("cmdline_regex selector (case-insensitive, invalid pattern never matches)")
    func cmdlineRegex() throws {
        let r = try rule("name: t\nmatch:\n  cmdline_regex: \"nc(at)?\\\\s+[^|]*-l\"\naction: log\n")
        #expect(r.matches(MatchCtx(cmdline: "nc -l 4444")))
        #expect(r.matches(MatchCtx(cmdline: "ncat -v -lp 4444")))
        #expect(r.matches(MatchCtx(cmdline: "NC -L 4444"))) // case-insensitive
        #expect(!r.matches(MatchCtx(cmdline: "nc example.com 80")))
        let bad = try rule("name: t\nmatch:\n  cmdline_regex: \"[unclosed\"\naction: log\n")
        #expect(!bad.matches(MatchCtx(cmdline: "anything")))
    }

    @Test("note field decodes, absent by default")
    func noteField() throws {
        let with = try rule("name: t\nmatch:\n  path_basename: x\naction: log\nnote: \"why this exists\"\n")
        #expect(with.note == "why this exists")
        let without = try rule("name: t\nmatch:\n  path_basename: x\naction: log\n")
        #expect(without.note == nil)
    }

    // MARK: match_all / not / validation (Linux rules.rs parity)

    @Test("match_all requires every selector")
    func matchAllRequiresEvery() throws {
        let r = try rule("name: t\nmatch_all:\n  path_basename: crontab\n  cmdline_contains: \"-e\"\naction: log\n")
        #expect(r.matches(MatchCtx(basename: "crontab", path: "/usr/bin/crontab", cmdline: "crontab -e")))
        #expect(!r.matches(MatchCtx(basename: "crontab", path: "/usr/bin/crontab", cmdline: "crontab -l")))
        // Right cmdline, wrong binary:
        #expect(!r.matches(MatchCtx(basename: "vi", path: "/usr/bin/vi", cmdline: "vi -e")))
    }

    @Test("match + match_all combine (uid constrains both)")
    func matchAndMatchAllCombine() throws {
        let r = try rule("name: t\nmatch:\n  cmdline_contains: \"| sh\"\n  uid: 0\nmatch_all:\n  path_basename: bash\naction: log\n")
        #expect(r.matches(MatchCtx(basename: "bash", path: "/usr/bin/bash", cmdline: "bash -c curl x | sh", uid: 0)))
        #expect(!r.matches(MatchCtx(basename: "bash", path: "/usr/bin/bash", cmdline: "bash -c curl x | sh", uid: 1000)))
        #expect(!r.matches(MatchCtx(basename: "bash", path: "/usr/bin/bash", cmdline: "bash -c echo hi", uid: 0)))
        // match_all fails even when the OR selector hits:
        #expect(!r.matches(MatchCtx(basename: "zsh", path: "/usr/bin/zsh", cmdline: "zsh -c curl x | sh", uid: 0)))
    }

    @Test("empty match_all is rejected at load")
    func emptyMatchAllRejected() {
        #expect(throws: MerlinError.self) {
            try Rules.parse("rules:\n  - name: t\n    match_all: {}\n    action: log\n")
        }
    }

    @Test("unknown keys are rejected at load (rule, selector, top level)")
    func unknownKeysRejected() {
        // Decoder-level rejection (DecodingError) like serde's
        // deny_unknown_fields on the Linux side.
        #expect(throws: (any Error).self) {
            try Rules.parse("rules:\n  - name: t\n    match:\n      bogus_selector: x\n    action: log\n")
        }
        #expect(throws: (any Error).self) {
            try Rules.parse("rules:\n  - name: t\n    match_all:\n      bogus: x\n    action: log\n")
        }
        #expect(throws: (any Error).self) {
            try Rules.parse("rules:\n  - name: t\n    matc: {}\n    action: log\n") // typo'd rule key
        }
        #expect(throws: (any Error).self) {
            try Rules.parse("rules: []\nbogus_top: 1\n")
        }
    }

    @Test("not vetoes a rule (not → match_all → match order)")
    func notVeto() throws {
        let r = try rule("""
        name: t
        match:
          cmdline_contains: crontab
        not:
          cmdline_contains: "-l"
        action: log
        """)
        #expect(r.matches(MatchCtx(cmdline: "crontab -e")))
        #expect(!r.matches(MatchCtx(cmdline: "crontab -l")))
        // not hits even when match_all would pass:
        let r2 = try rule("""
        name: t
        match_all:
          path_basename: osascript
        not:
          cmdline_contains: "display dialog"
        action: log
        """)
        #expect(r2.matches(MatchCtx(basename: "osascript", cmdline: "osascript -e 'beep'")))
        #expect(!r2.matches(MatchCtx(basename: "osascript", cmdline: "osascript -e 'display dialog \"hi\"'")))
        // not with no selectors never vetoes.
        let r3 = try rule("name: t\nmatch:\n  path_basename: x\nnot:\n  uid: 0\naction: log\n")
        #expect(r3.matches(MatchCtx(basename: "x", uid: 0)))
    }

    // MARK: lineage selectors

    @Test("parent_basename matches the immediate parent")
    func parentBasename() throws {
        let r = try rule("name: t\nmatch:\n  parent_basename: bash\naction: log\n")
        #expect(r.matches(MatchCtx(parentBasename: "bash")))
        #expect(!r.matches(MatchCtx(parentBasename: "zsh")))
        #expect(!r.matches(MatchCtx())) // missing lineage → no match, no crash
    }

    @Test("ancestor_comm_contains matches any ancestor")
    func ancestorCommContains() throws {
        let r = try rule("name: t\nmatch:\n  ancestor_comm_contains: curl\naction: log\n")
        #expect(r.matches(MatchCtx(ancestorComms: ["sh", "curl", "zsh"])))
        #expect(!r.matches(MatchCtx(ancestorComms: ["sh", "wget"])))
        #expect(!r.matches(MatchCtx(ancestorComms: [])))
        #expect(!r.matches(MatchCtx())) // nil lineage fails safe
        // Usable inside match_all too:
        let r2 = try rule("name: t\nmatch_all:\n  path_basename: sh\n  ancestor_comm_contains: curl\naction: log\n")
        #expect(r2.matches(MatchCtx(basename: "sh", ancestorComms: ["sh", "curl"])))
        #expect(!r2.matches(MatchCtx(basename: "sh", ancestorComms: ["sh"])))
        #expect(!r2.matches(MatchCtx(basename: "sh"))) // no lineage → match_all fails
    }

    @Test("shipped packs still load (validation is not stricter than the packs)")
    func packsLoadUnchanged() throws {
        for rel in ["rules/block-demo.yaml", "rules/network-demo.yaml", "rules/content/macos-lolbins.yaml"] {
            let p = Self.repoRoot.appendingPathComponent(rel).path
            _ = try Rules.load(path: p)
        }
    }

    @Test("rules file is opened no-follow: symlinks rejected, regular files load, world-writable loads with a warning")
    func rulesNoFollow() throws {
        let dir = NSTemporaryDirectory() + "merlin-rules-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let real = dir + "/real.yaml"
        try "rules: []\n".write(toFile: real, atomically: true, encoding: .utf8)

        // Regular file loads.
        _ = try Rules.load(path: real)

        // Symlinked rules file is rejected with a clear error.
        let link = dir + "/link.yaml"
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: real)
        #expect(throws: (any Error).self) {
            try Rules.load(path: link)
        }
        // And the error says why.
        do {
            _ = try Rules.load(path: link)
            Issue.record("symlinked rules file loaded")
        } catch {
            #expect(String(describing: error).contains("not followed") || String(describing: error).contains("62"))
        }

        // World-writable still loads (warn-only per the invariants).
        try FileManager.default.setAttributes([.posixPermissions: 0o666], ofItemAtPath: real)
        _ = try Rules.load(path: real)

        // A fifo is not a regular file.
        let fifo = dir + "/fifo"
        #expect(mkfifo(fifo, 0o600) == 0)
        #expect(throws: (any Error).self) {
            try Rules.load(path: fifo)
        }
    }

    @Test("macOS LOLBin content pack loads and matches")
    func macosLolbinsPack() throws {
        let path = Self.repoRoot.appendingPathComponent("rules/content/macos-lolbins.yaml").path
        let rules = try Rules.load(path: path)
        #expect(rules.rules.count == 12)
        // 10 log rules + the suspend/kill demo pair.
        #expect(rules.rules.filter { $0.action == .log }.count == 10)
        #expect(rules.rules.first { $0.name == "susp-inspect-tmp-exec" }?.action == .suspend)
        #expect(rules.rules.first { $0.name == "kill-unsigned-tmp-exec" }?.action == .kill)
        #expect(rules.rules.allSatisfy { $0.note != nil })
        func anyMatch(_ ctx: MatchCtx) -> [String] {
            rules.rules.filter { $0.matches(ctx) }.map(\.name)
        }
        #expect(anyMatch(MatchCtx(cmdline: "sh -c 'curl https://e.com/x.sh | sh'"))
            .contains("lolbin-download-pipe-sh"))
        #expect(anyMatch(MatchCtx(cmdline: "nc -l 4444")).contains("lolbin-nc-listener"))
        #expect(anyMatch(MatchCtx(cmdline: "osascript -e 'tell app X' -e 'beep'"))
            .contains("lolbin-osascript-eval"))
        #expect(anyMatch(MatchCtx(path: "/private/tmp/evil", cmdline: "/private/tmp/evil"))
            .contains("lolbin-exec-tmp"))
        #expect(anyMatch(MatchCtx(cmdline: "nc example.com 80")).isEmpty)
        #expect(anyMatch(MatchCtx(path: "/usr/bin/safari", cmdline: "safari")).isEmpty)
        // Lineage demo rule: sh with curl in the ancestry fires; same
        // cmdline without lineage does not.
        let lineage = MatchCtx(basename: "sh", path: "/bin/sh", cmdline: "sh", ancestorComms: ["sh", "curl", "zsh"])
        #expect(anyMatch(lineage).contains("lolbin-sh-spawned-by-curl"))
        #expect(!anyMatch(MatchCtx(basename: "sh", path: "/bin/sh", cmdline: "sh", ancestorComms: ["sh", "zsh"]))
            .contains("lolbin-sh-spawned-by-curl"))
        // not: demo — crontab -e fires, crontab --help is vetoed.
        #expect(anyMatch(MatchCtx(basename: "crontab", path: "/usr/bin/crontab", cmdline: "crontab -e"))
            .contains("lolbin-crontab-edit"))
        #expect(anyMatch(MatchCtx(basename: "crontab", path: "/usr/bin/crontab", cmdline: "crontab --help")).isEmpty)
    }

    @Test("BSM praudit exec line parses")
    func bsmExecParse() {
        let line = "header,124,11,execve(2),0,Sun Feb  1 00:00:00 2026, + 12 msec,exec_args,2,/tmp/merlin-evil,-f,path,/tmp/merlin-evil,attribute,100755,root,wheel,subject,-1,root,wheel,root,wheel,4242,100005,0x00000000,return,success,0,trailer,124"
        guard case .exec(let e)? = parseBSMLine(line) else {
            Issue.record("expected exec record")
            return
        }
        #expect(e.pid == 4242)
        #expect(e.euid == "root")
        #expect(e.path == "/tmp/merlin-evil")
        #expect(e.args == ["/tmp/merlin-evil", "-f"])
        #expect(e.retval == "0")
    }

    @Test("BSM praudit exit line parses")
    func bsmExitParse() {
        let line = "header,59,11,exit(2),0,Sun Feb  1 00:00:01 2026, + 3 msec,subject,-1,jonathanhaas,staff,jonathanhaas,staff,4243,100005,0x00000000,return,success,256,trailer,59"
        guard case .exit(let x)? = parseBSMLine(line) else {
            Issue.record("expected exit record")
            return
        }
        #expect(x.pid == 4243)
        #expect(x.retval == "256")
        #expect(parseAuditInt("256").map { ($0 >> 8) & 0xff } == 1)
    }
}
