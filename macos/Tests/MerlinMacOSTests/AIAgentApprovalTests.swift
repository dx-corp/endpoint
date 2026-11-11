import Foundation
import Testing
@testable import MerlinMacOS

/// Homes and a system root under a fresh temporary directory.
private final class AIApprovalFixture {
    let root: URL
    let homes: [String]
    let system: String

    init() throws {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("merlin-ai-approval-\(UUID().uuidString)")
        root = base
        homes = ["alice", "bob"].map { base.appendingPathComponent("home/\($0)").path }
        system = base.appendingPathComponent("system").path
        for directory in homes + [system] {
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        }
    }

    deinit { try? FileManager.default.removeItem(at: root) }

    func write(_ base: String, _ relative: String, _ body: String) throws {
        let url = URL(fileURLWithPath: base).appendingPathComponent(relative)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(body.utf8).write(to: url)
    }

    func user(_ home: Int, _ relative: String, _ body: String) throws {
        try write(homes[home], relative, body)
    }

    /// A managed file at its declared absolute path, under the system root.
    func managed(_ absolute: String, _ body: String) throws {
        try write(system, String(aiApprovalSystemPath(absolute).drop { $0 == "/" }), body)
    }

    func results() -> [String: AIApprovalResult] {
        Dictionary(uniqueKeysWithValues: collectAIApproval(homes: homes, root: system).map { ($0.check, $0) })
    }
}

@Suite("AI agent approval")
struct AIAgentApprovalTests {
    @Test("the declared table covers every client with a macOS source")
    func table() {
        #expect(aiApprovalClients.map(\.check) == [
            "ai_agent_approval_claude_code", "ai_agent_approval_codex",
            "ai_agent_approval_gemini_cli", "ai_agent_approval_cursor_cli",
        ])
        for client in aiApprovalClients {
            #expect(!client.sources.isEmpty, "\(client.id) has a macOS source")
            for lock in client.locks {
                for rule in lock.neutralizes {
                    #expect(client.rules.contains { $0.id == rule })
                }
            }
        }
    }

    @Test("absent clients are omitted")
    func absent() throws {
        let fixture = try AIApprovalFixture()
        #expect(fixture.results().isEmpty)
    }

    @Test("Claude Code bypass mode and an allow-all shell rule are findings that name nothing")
    func claudeFindings() throws {
        let fixture = try AIApprovalFixture()
        try fixture.user(0, ".claude/settings.json", #"{"permissions":{"defaultMode":"default","allow":["Bash(npm test *)"]}}"#)
        var result = try #require(fixture.results()["ai_agent_approval_claude_code"])
        #expect(result.status == "pass")
        #expect(result.value == "asks")

        try fixture.user(1, ".claude/settings.json", #"{"permissions":{"defaultMode":"bypassPermissions","allow":["Bash(*)"]},"env":{"API_KEY":"sk-secret"}}"#)
        result = try #require(fixture.results()["ai_agent_approval_claude_code"])
        #expect(result.status == "finding")
        #expect(result.severity == "high")
        #expect(result.value == "bypass_permissions,allow_all_shell")
        #expect(result.reason.contains("permissions.defaultMode"))

        var snapshot = PostureSnapshot()
        addAIApprovalChecks([result], to: &snapshot)
        let report = makeDevicePostureReport(snapshot: snapshot, root: false, networkExtension: "not_configured")
        let check = try #require(report.checks["ai_agent_approval_claude_code"])
        #expect(check.status == "finding")
        #expect(check.severity == "high")
        #expect(check.evidence.source == "ai_agent_settings")
        let wire = String(decoding: try JSONEncoder().encode(report), as: UTF8.self)
        for leaked in ["sk-secret", "API_KEY", "alice", "bob", "/home", "settings.json"] {
            #expect(!wire.contains(leaked), "\(leaked) must not leave the device")
        }
    }

    @Test("a managed lock neutralizes the rule it names")
    func claudeManagedLock() throws {
        let fixture = try AIApprovalFixture()
        try fixture.user(0, ".claude/settings.json", #"{"permissions":{"defaultMode":"bypassPermissions"}}"#)
        try fixture.managed(
            "/Library/Application Support/ClaudeCode/managed-settings.json",
            #"{"permissions":{"disableBypassPermissionsMode":"disable"}}"#
        )
        let result = try #require(fixture.results()["ai_agent_approval_claude_code"])
        #expect(result.status == "pass")
        #expect(result.value == "managed")
        #expect(result.reason.contains("disableBypassPermissionsMode"))
    }

    @Test("a user file cannot lock its own rules")
    func userLocksDoNotCount() throws {
        let fixture = try AIApprovalFixture()
        try fixture.user(0, ".claude/settings.json", #"{"permissions":{"defaultMode":"bypassPermissions","disableBypassPermissionsMode":"disable"}}"#)
        #expect(fixture.results()["ai_agent_approval_claude_code"]?.status == "finding")
    }

    @Test("Codex TOML: never asking with full access is a finding; managed requirements lock it")
    func codex() throws {
        let fixture = try AIApprovalFixture()
        try fixture.user(0, ".codex/config.toml", "approval_policy = \"never\"\nsandbox_mode = 'danger-full-access'\n[mcp_servers.x]\ncommand = \"node\"\n")
        var result = try #require(fixture.results()["ai_agent_approval_codex"])
        #expect(result.status == "finding")
        #expect(result.value == "never_ask_full_access")

        // /etc/codex is read through /private/etc, the real directory.
        try fixture.managed("/etc/codex/requirements.toml", "allowed_approval_policies = [\"untrusted\", \"on-request\"]\n")
        result = try #require(fixture.results()["ai_agent_approval_codex"])
        #expect(result.status == "pass")
        #expect(result.value == "managed")
    }

    @Test("Codex requirements that still allow never do not lock")
    func codexLockLacks() throws {
        let fixture = try AIApprovalFixture()
        try fixture.user(0, ".codex/config.toml", "approval_policy = \"never\"\ndefault_permissions = \":danger-full-access\"\n")
        try fixture.managed("/etc/codex/requirements.toml", "allowed_approval_policies = [\"never\", \"on-request\"]\n")
        let result = try #require(fixture.results()["ai_agent_approval_codex"])
        #expect(result.status == "finding")
        #expect(result.value == "never_ask_full_access_profile")
    }

    @Test("Gemini and Cursor rules match array entries and booleans exactly")
    func geminiAndCursor() throws {
        let fixture = try AIApprovalFixture()
        try fixture.user(0, ".gemini/settings.json", #"{"tools":{"allowed":["run_shell_command(git status)"]}}"#)
        try fixture.user(0, ".cursor/cli-config.json", #"{"approvalMode":"unrestricted","permissions":{"allow":["Shell(*)"]}}"#)
        var results = fixture.results()
        #expect(results["ai_agent_approval_gemini_cli"]?.value == "asks")
        #expect(results["ai_agent_approval_cursor_cli"]?.value == "unrestricted,allow_all_shell")

        try fixture.user(1, ".gemini/settings.json", #"{"tools":{"allowed":["run_shell_command"]}}"#)
        results = fixture.results()
        #expect(results["ai_agent_approval_gemini_cli"]?.status == "finding")
        #expect(results["ai_agent_approval_gemini_cli"]?.severity == "medium")
    }

    @Test("a number 1 is not the boolean true a lock names")
    func booleansAreNotNumbers() throws {
        let fixture = try AIApprovalFixture()
        try fixture.user(0, ".claude/settings.json", #"{"permissions":{"allow":["Bash"]}}"#)
        try fixture.managed("/Library/Application Support/ClaudeCode/managed-settings.json", #"{"allowManagedPermissionRulesOnly":1}"#)
        #expect(fixture.results()["ai_agent_approval_claude_code"]?.status == "finding")
        try fixture.managed("/Library/Application Support/ClaudeCode/managed-settings.json", #"{"allowManagedPermissionRulesOnly":true}"#)
        #expect(fixture.results()["ai_agent_approval_claude_code"]?.value == "managed")
    }

    @Test("unreadable, unparseable and symlinked files are not checked")
    func unreadable() throws {
        let fixture = try AIApprovalFixture()
        try fixture.user(0, ".cursor/cli-config.json", "{not json")
        var result = try #require(fixture.results()["ai_agent_approval_cursor_cli"])
        #expect(result.status == "unknown")
        #expect(result.value == "not_checked")

        let fixture2 = try AIApprovalFixture()
        let elsewhere = fixture2.root.appendingPathComponent("elsewhere.json")
        try Data(#"{"approvalMode":"unrestricted"}"#.utf8).write(to: elsewhere)
        let cursor = URL(fileURLWithPath: fixture2.homes[0]).appendingPathComponent(".cursor")
        try FileManager.default.createDirectory(at: cursor, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: cursor.appendingPathComponent("cli-config.json"), withDestinationURL: elsewhere)
        result = try #require(fixture2.results()["ai_agent_approval_cursor_cli"])
        #expect(result.value == "not_checked", "a symlinked settings file is never followed")

        var snapshot = PostureSnapshot()
        addAIApprovalChecks([result], to: &snapshot)
        let report = makeDevicePostureReport(snapshot: snapshot, root: false, networkExtension: "not_configured")
        #expect(report.checks["ai_agent_approval_cursor_cli"]?.status == "unknown")
        #expect(report.checks["ai_agent_approval_cursor_cli"]?.detail == aiApprovalUnreadable)
        #expect(report.findings.isEmpty)
    }

    @Test("a finding wins over an unreadable file")
    func findingWins() throws {
        let fixture = try AIApprovalFixture()
        try fixture.user(0, ".cursor/cli-config.json", "{not json")
        try fixture.user(1, ".cursor/cli-config.json", #"{"approvalMode":"unrestricted"}"#)
        #expect(fixture.results()["ai_agent_approval_cursor_cli"]?.status == "finding")
    }

    @Test("the TOML scanner keeps booleans, strings and string arrays")
    func tomlValues() throws {
        let body = "a = true\nb = false\nc = \"text\"\nd = ['x', \"y\"]\ne = [1, 2]\nf = 3\n[t]\ng = \"\"\"\nmulti\n\"\"\"\n"
        let leaves = try #require(TOMLLeafScanner.parse(Array(body.utf8)))
        let values = Dictionary(uniqueKeysWithValues: leaves.map { ($0.path.joined(separator: "."), $0.value) })
        #expect(values["a"] == .bool(true))
        #expect(values["b"] == .bool(false))
        #expect(values["c"] == .string("text"))
        #expect(values["d"] == .strings(["x", "y"]))
        #expect(values["e"] == .other)
        #expect(values["f"] == .other)
        #expect(values["t.g"] == .other)
    }
}
