import Foundation
import Testing
@testable import MerlinMacOS

@Suite("MCP hook coverage observations")
struct MCPHookCoverageTests {
    @Test("only exact managed Cursor and Claude hook entries count")
    func jsonRegistrations() {
        let cursor = Data(#"{"version":1,"hooks":{"beforeMCPExecution":[{"command":"/Library/Application Support/Merlin/bin/merlin-macos mcp-hook --client cursor"}]}}"#.utf8)
        #expect(cursorHookRegistered(cursor))
        #expect(!cursorHookRegistered(Data(#"{"version":1,"hooks":{"afterMCPExecution":[{"command":"/Library/Application Support/Merlin/bin/merlin-macos mcp-hook --client cursor"}]}}"#.utf8)))
        #expect(!cursorHookRegistered(Data(#"{"version":1,"hooks":{"beforeMCPExecution":[{"command":"echo /Library/Application Support/Merlin/bin/merlin-macos mcp-hook --client cursor"}]}}"#.utf8)))
        let claude = Data(#"{"hooks":{"PreToolUse":[{"matcher":"mcp__.*","hooks":[{"type":"command","command":"'/Library/Application Support/Merlin/bin/merlin-macos' mcp-hook --client claude"}]}]}}"#.utf8)
        #expect(claudeHookRegistered(claude))
        #expect(!claudeHookRegistered(Data(#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"'/Library/Application Support/Merlin/bin/merlin-macos' mcp-hook --client claude"}]}]}}"#.utf8)))
        #expect(!claudeHookRegistered(Data("{malformed".utf8)))
    }

    @Test("Codex requires hook enablement and the managed MCP matcher")
    func tomlRegistration() {
        let valid = """
        [features]
        hooks = true
        [hooks]
        managed_dir = "/Library/Application Support/Merlin/bin"
        [[hooks.PreToolUse]]
        matcher = "^mcp__.*"
        [[hooks.PreToolUse.hooks]]
        type = "command"
        command = "'/Library/Application Support/Merlin/bin/merlin-macos' mcp-hook --client codex"
        """
        #expect(codexHookRegistered(Data(valid.utf8)))
        #expect(!codexHookRegistered(Data(valid.replacingOccurrences(of: "hooks = true", with: "hooks = false").utf8)))
        #expect(!codexHookRegistered(Data(valid.replacingOccurrences(of: "matcher = \"^mcp__.*\"", with: "matcher = \"^Bash$\"").utf8)))
        #expect(!codexHookRegistered(Data(("# " + valid.replacingOccurrences(of: "\n", with: "\n# ")).utf8)))
    }

    @Test("managed file observation rejects writable and symlinked ancestors")
    func unsafeAncestors() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("managed-settings.json")
        try Data(#"{"hooks":{}}"#.utf8).write(to: file)
        if case .unreadable = observeManagedHookFile(file.path) {
        } else {
            Issue.record("accepted a user-writable managed file ancestor")
        }
        let alias = directory.deletingLastPathComponent().appendingPathComponent(UUID().uuidString)
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: directory)
        defer { try? FileManager.default.removeItem(at: alias) }
        if case .unreadable = observeManagedHookFile(alias.appendingPathComponent("managed-settings.json").path) {
        } else {
            Issue.record("accepted a symlinked managed file ancestor")
        }
    }

    @Test("audit would-deny records append, bound, and count without exposing arguments")
    func auditRecordAppendAndCount() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }

        appendMCPHookAuditRecord(
            client: "claude",
            record: MCPHookAuditRecord(server: "shadow", tool: "search", rule: "unapproved_server", observedAt: 1),
            home: home.path)
        appendMCPHookAuditRecord(
            client: "claude",
            record: MCPHookAuditRecord(server: "shadow", tool: "write", rule: "unapproved_server", observedAt: 2),
            home: home.path)
        appendMCPHookAuditRecord(
            client: "codex",
            record: MCPHookAuditRecord(server: "other", tool: "search", rule: "unapproved_server", observedAt: 3),
            home: home.path)

        let storePath = home.appendingPathComponent("Library/Application Support/Merlin/mcp-hook-audit-claude.jsonl").path
        let contents = try #require(FileManager.default.contents(atPath: storePath))
        let text = try #require(String(data: contents, encoding: .utf8))
        #expect(text.contains("\"server\":\"shadow\""))
        #expect(!text.contains("secret"))
        #expect(text.split(separator: "\n").count == 2)

        let coverage = collectMCPHookCoverage(homes: [home.path])
        let claude = try #require(coverage.clients.first { $0.client == "claude" })
        #expect(claude.wouldDenyCount == 2)
        let codex = try #require(coverage.clients.first { $0.client == "codex" })
        #expect(codex.wouldDenyCount == 1)
        let cursor = try #require(coverage.clients.first { $0.client == "cursor" })
        #expect(cursor.wouldDenyCount == 0)
    }

    @Test("the audit store resets instead of growing without bound")
    func auditStoreBounded() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }

        for index in 0..<4096 {
            appendMCPHookAuditRecord(
                client: "cursor",
                record: MCPHookAuditRecord(server: "shadow-\(index)", tool: "search", rule: "unapproved_server", observedAt: Double(index)),
                home: home.path)
        }
        let storePath = home.appendingPathComponent("Library/Application Support/Merlin/mcp-hook-audit-cursor.jsonl").path
        let attributes = try FileManager.default.attributesOfItem(atPath: storePath)
        let size = (attributes[.size] as? NSNumber)?.intValue ?? Int.max
        #expect(size <= 16 * 1024)

        let coverage = collectMCPHookCoverage(homes: [home.path])
        let cursor = try #require(coverage.clients.first { $0.client == "cursor" })
        #expect(cursor.wouldDenyCount <= 128)
    }
}
