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
        // A user-owned file cannot be told apart from a missing one: both
        // report unavailablePolicy, not malformedPolicy, so a call still
        // allows rather than denying on the strength of an attacker-writable
        // file.
        do {
            _ = try readMCPHookPolicy(path: plain.path)
            Issue.record("expected readMCPHookPolicy to throw")
        } catch MCPHookError.unavailablePolicy {
        } catch {
            Issue.record("expected unavailablePolicy, got \(error)")
        }
    }

    @Test("a tool name with an extra __ segment still resolves to its server")
    func extraSegments() throws {
        let parsed = try MCPHookPolicy.parse(Data(policy.utf8))
        // "mcp__shadow__search__preview" previously split into 3 "__" parts
        // and was treated as unrecognized (and so allowed) instead of being
        // read as server "shadow", tool "search__preview".
        for client in ["claude", "codex"] {
            let verdict = try parsed.verdict(client: client, input: ["tool_name": "mcp__shadow__search__preview"])
            guard case .deny(let reason) = verdict else {
                Issue.record("\(client) allowed an unapproved server behind an extra __ segment")
                continue
            }
            #expect(reason.contains("shadow"))
        }
        // The same shape resolves to an approved server and allows.
        #expect(try parsed.verdict(client: "claude", input: ["tool_name": "mcp__deixic-gateway__search__preview"]) == .allow)
    }

    @Test("audit mode records a would-deny without denying")
    func auditRecordsWouldDeny() throws {
        let audit = try MCPHookPolicy.parse(Data(policy.replacingOccurrences(of: "enforce", with: "audit").utf8))
        let denied = try audit.verdict(client: "claude", input: ["tool_name": "mcp__shadow__search"])
        #expect(denied == .allow)
        let record = audit.auditWouldDenyRecord(client: "claude", input: ["tool_name": "mcp__shadow__search"])
        #expect(record?.server == "shadow")
        #expect(record?.tool == "search")
        #expect(record?.rule == "unapproved_server")
        // Never records an approved call or one that never resolves to a server.
        #expect(audit.auditWouldDenyRecord(client: "claude", input: ["tool_name": "mcp__deixic-gateway__search"]) == nil)
        #expect(audit.auditWouldDenyRecord(client: "claude", input: ["tool_name": "Bash"]) == nil)
        // Enforce mode never records: it denies directly instead.
        let enforce = try MCPHookPolicy.parse(Data(policy.utf8))
        #expect(enforce.auditWouldDenyRecord(client: "claude", input: ["tool_name": "mcp__shadow__search"]) == nil)
    }

    @Test("a malformed policy denies only when it declares enforce mode")
    func malformedPolicyMode() {
        let input: [String: Any] = ["tool_name": "mcp__shadow__search"]
        let enforceVerdict = mcpHookErrorVerdict(MCPHookError.malformedPolicy(mode: "enforce"), client: "claude", input: input)
        guard case .deny(let reason) = enforceVerdict else {
            Issue.record("a malformed policy declaring enforce mode did not deny")
            return
        }
        #expect(reason.contains("shadow"))
        #expect(reason.contains("Contact your administrator"))
        #expect(mcpHookErrorVerdict(MCPHookError.malformedPolicy(mode: "audit"), client: "claude", input: input) == .allow)
        #expect(mcpHookErrorVerdict(MCPHookError.malformedPolicy(mode: nil), client: "claude", input: input) == .allow)
        #expect(mcpHookErrorVerdict(MCPHookError.unavailablePolicy, client: "claude", input: input) == .allow)
        #expect(mcpHookErrorVerdict(MCPHookError.invalidInput, client: "claude", input: input) == .allow)
        // No input recovered (e.g. stdin failed before the policy did) still allows.
        #expect(mcpHookErrorVerdict(MCPHookError.malformedPolicy(mode: "enforce"), client: "claude", input: nil) == .allow)
        // A malformed enforce-mode policy on a call that never resolves to a server still allows.
        #expect(mcpHookErrorVerdict(MCPHookError.malformedPolicy(mode: "enforce"), client: "claude", input: ["tool_name": "Bash"]) == .allow)
    }

    @Test("peekMCPHookPolicyMode reads a mode from an otherwise malformed policy")
    func peekMode() {
        #expect(peekMCPHookPolicyMode(Data(#"{"schema_version":1,"mode":"enforce","approved_servers":"not an array"}"#.utf8)) == "enforce")
        #expect(peekMCPHookPolicyMode(Data(#"{"mode":"audit","surprise":true}"#.utf8)) == "audit")
        #expect(peekMCPHookPolicyMode(Data(#"{"mode":"disabled"}"#.utf8)) == nil)
        #expect(peekMCPHookPolicyMode(Data(#"{"schema_version":1}"#.utf8)) == nil)
        #expect(peekMCPHookPolicyMode(Data("not json".utf8)) == nil)
        #expect(peekMCPHookPolicyMode(Data("[]".utf8)) == nil)
        #expect(peekMCPHookPolicyMode(Data(String(repeating: "x", count: 65_537).utf8)) == nil)
    }
}
