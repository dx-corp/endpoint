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
}
