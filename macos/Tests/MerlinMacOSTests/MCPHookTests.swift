import Foundation
import Testing
@testable import MerlinMacOS

@Suite("managed MCP hooks")
struct MCPHookTests {
    private let policy = """
    {"schema_version":1,"mode":"enforce",
     "approved_servers":[{"client":"cursor","server":"deixic-gateway"},
                         {"client":"claude","server":"deixic-gateway"},
                         {"client":"codex","server":"deixic-gateway"}],
     "approved_alternative":{"name":"Approved agent","url":"https://tools.example.com/agent"}}
    """

    @Test("blocks unapproved Cursor, Claude, and Codex MCP calls")
    func blockedClients() throws {
        let parsed = try MCPHookPolicy.parse(Data(policy.utf8))
        let inputs: [(String, [String: Any])] = [
            ("cursor", ["mcp_server_name": "shadow", "tool_name": "search", "tool_input": ["secret": "do not emit"]]),
            ("claude", ["tool_name": "mcp__shadow__search", "tool_input": ["secret": "do not emit"]]),
            ("codex", ["tool_name": "mcp__shadow__search", "tool_input": ["secret": "do not emit"]]),
        ]
        for (client, input) in inputs {
            let verdict = try parsed.verdict(client: client, input: input)
            guard case .deny(let reason) = verdict else {
                Issue.record("\(client) did not deny an unapproved server")
                continue
            }
            #expect(reason.contains("Approved agent"))
            #expect(reason.contains("https://tools.example.com/agent"))
            let output = mcpHookOutput(client: client, verdict: verdict)
            let encoded = String(data: try JSONSerialization.data(withJSONObject: output), encoding: .utf8) ?? ""
            #expect(!encoded.contains("do not emit"))
            if client == "cursor" {
                #expect(output["permission"] as? String == "deny")
            } else {
                let specific = output["hookSpecificOutput"] as? [String: String]
                #expect(specific?["permissionDecision"] == "deny")
            }
        }
    }

    @Test("allows approved servers and unrelated tools")
    func approvedAndUnrelated() throws {
        let parsed = try MCPHookPolicy.parse(Data(policy.utf8))
        #expect(try parsed.verdict(client: "cursor", input: ["mcp_server_name": "deixic-gateway", "tool_name": "search"]) == .allow)
        #expect(try parsed.verdict(client: "claude", input: ["tool_name": "mcp__deixic-gateway__search"]) == .allow)
        #expect(try parsed.verdict(client: "codex", input: ["tool_name": "Bash"]) == .allow)
        #expect(try parsed.verdict(client: "codex", input: ["tool_name": "mcp__plugin_my-plugin_db__search"]) != .allow)
    }

    @Test("rejects unknown policy fields, unsafe links, and oversized policy")
    func invalidPolicy() throws {
        for invalid in [
            policy.replacingOccurrences(of: "\"mode\":\"enforce\"", with: "\"mode\":\"enforce\",\"surprise\":true"),
            policy.replacingOccurrences(of: "https://tools.example.com/agent", with: "http://tools.example.com/agent"),
            policy.replacingOccurrences(of: "\"server\":\"deixic-gateway\"", with: "\"server\":\"*\""),
            String(repeating: "x", count: 65_537),
        ] {
            #expect(throws: Error.self) { try MCPHookPolicy.parse(Data(invalid.utf8)) }
        }
    }

    @Test("audit policy never denies")
    func audit() throws {
        let parsed = try MCPHookPolicy.parse(Data(policy.replacingOccurrences(of: "enforce", with: "audit").utf8))
        #expect(try parsed.verdict(client: "cursor", input: ["mcp_server_name": "shadow", "tool_name": "search"]) == .allow)
    }

    @Test("refuses user-owned and symlinked policy files")
    func unsafeFiles() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let plain = directory.appendingPathComponent("policy.json")
        try Data(policy.utf8).write(to: plain)
        #expect(throws: Error.self) { try readMCPHookPolicy(path: plain.path) }
        let link = directory.appendingPathComponent("link.json")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: plain)
        #expect(throws: Error.self) { try readMCPHookPolicy(path: link.path) }
    }
}
