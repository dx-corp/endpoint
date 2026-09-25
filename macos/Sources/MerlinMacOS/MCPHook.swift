// Managed MCP tool-call hook for Cursor, Claude Code, and Codex.
// The hook reads only server and tool names. Arguments never leave the client.
import ArgumentParser
import Darwin
import Foundation

private let mcpHookPolicyPath = "/Library/Application Support/Merlin/mcp-hook-policy.json"
private let mcpHookMaximumBytes = 64 * 1024

private enum MCPHookClient: String, ExpressibleByArgument {
    case cursor, claude, codex
}

struct MCPHookCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "mcp-hook",
        abstract: "Apply an administrator-installed MCP server allowlist to a client tool call."
    )

    @Option(help: "Client emitting the hook: cursor, claude, or codex.")
    private var client: MCPHookClient

    func run() throws {
        let output: [String: Any]
        var input: [String: Any]?
        do {
            input = try readMCPHookInput()
            let policy = try readMCPHookPolicy(path: mcpHookPolicyPath)
            let verdict = try policy.verdict(client: client.rawValue, input: input!)
            if let record = policy.auditWouldDenyRecord(client: client.rawValue, input: input!) {
                appendMCPHookAuditRecord(client: client.rawValue, record: record)
            }
            output = mcpHookOutput(client: client.rawValue, verdict: verdict)
        } catch {
            // Every enforcement point allows on internal errors, with one
            // exception handled by mcpHookErrorVerdict: a policy that is
            // present, safely owned, and declares enforce mode, but fails
            // schema validation, still denies. An administrator who pushed
            // enforcement does not get a silent fail-open because the pushed
            // file happened to be broken. Every other error (a missing or
            // unsafe policy file, a malformed policy that is absent or
            // declares audit mode, oversized or invalid input) allows.
            fputs("deixic endpoint mcp hook: \(error)\n", stderr)
            output = mcpHookOutput(client: client.rawValue, verdict: mcpHookErrorVerdict(error, client: client.rawValue, input: input))
        }
        let data = try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys])
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data([0x0a]))
    }
}

enum MCPHookError: Error, Equatable {
    case invalidInput, invalidPolicy, unavailablePolicy, oversizedInput
    case malformedPolicy(mode: String?)
}

// Pulled out of run()'s catch block so the one case that is not a plain
// fail-open (a malformed policy that declares enforce mode) is testable
// without a root-owned policy file on disk.
func mcpHookErrorVerdict(_ error: Error, client: String, input: [String: Any]?) -> MCPHookVerdict {
    guard case MCPHookError.malformedPolicy(let mode) = error, mode == "enforce" else { return .allow }
    guard let input, let server = mcpHookServer(client: client, input: input) else { return .allow }
    return .deny(mcpHookBlockedMessage(server: server, approvedName: nil, approvedURL: nil))
}

enum MCPHookVerdict: Equatable {
    case allow
    case deny(String)
}

// Local, bounded evidence that an audit-mode call would have been denied
// under enforce mode. Only fixed identifiers and a timestamp; never the tool
// call's arguments.
struct MCPHookAuditRecord: Codable, Equatable, Sendable {
    let server: String
    let tool: String
    let rule: String
    let observedAt: Double

    enum CodingKeys: String, CodingKey {
        case server, tool, rule
        case observedAt = "observed_at"
    }
}

private func mcpHookBlockedMessage(server: String, approvedName: String?, approvedURL: String?) -> String {
    var message = "Deixic Endpoint blocked an unapproved MCP server (\(server))."
    if let approvedName, let approvedURL {
        message += " Use the administrator-approved tool \(approvedName): \(approvedURL)"
    } else {
        message += " Contact your administrator for an approved tool."
    }
    return message
}

struct MCPHookPolicy {
    let enforced: Bool
    let approvedServers: [String: Set<String>]
    let approvedName: String?
    let approvedURL: String?

    static func parse(_ data: Data) throws -> MCPHookPolicy {
        guard data.count <= mcpHookMaximumBytes,
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(root.keys).isSubset(of: ["schema_version", "mode", "approved_servers", "approved_alternative"]),
              root["schema_version"] as? Int == 1,
              let mode = root["mode"] as? String, ["audit", "enforce"].contains(mode),
              let entries = root["approved_servers"] as? [[String: Any]], entries.count <= 128 else {
            throw MCPHookError.invalidPolicy
        }
        var approved: [String: Set<String>] = [:]
        for entry in entries {
            guard Set(entry.keys) == Set(["client", "server"]),
                  let client = entry["client"] as? String,
                  ["cursor", "claude", "codex"].contains(client),
                  let server = entry["server"] as? String,
                  validMCPHookName(server) else {
                throw MCPHookError.invalidPolicy
            }
            approved[client, default: []].insert(server)
        }
        var name: String?
        var url: String?
        if let alternative = root["approved_alternative"] {
            guard let value = alternative as? [String: String],
                  Set(value.keys) == Set(["name", "url"]),
                  let candidateName = value["name"],
                  !candidateName.isEmpty, candidateName.utf8.count <= 80,
                  candidateName == candidateName.trimmingCharacters(in: .whitespacesAndNewlines),
                  !candidateName.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
                  let candidateURL = value["url"], candidateURL.utf8.count <= 2048,
                  let parsed = URLComponents(string: candidateURL), parsed.scheme == "https",
                  parsed.host != nil, parsed.user == nil, parsed.password == nil,
                  parsed.query == nil, parsed.fragment == nil else {
                throw MCPHookError.invalidPolicy
            }
            name = candidateName
            url = candidateURL
        }
        return MCPHookPolicy(enforced: mode == "enforce", approvedServers: approved,
                             approvedName: name, approvedURL: url)
    }

    func verdict(client: String, input: [String: Any]) throws -> MCPHookVerdict {
        guard let call = evaluateCall(client: client, input: input) else {
            // Unrecognized hook events and malformed names do not become an
            // implicit block. Managed client matchers limit calls to MCP.
            return .allow
        }
        guard enforced, !call.approved else {
            return .allow
        }
        return .deny(mcpHookBlockedMessage(server: call.server, approvedName: approvedName, approvedURL: approvedURL))
    }

    // A call that would have been denied had this policy been in enforce
    // mode. Enforce mode itself never audits: it denies outright through
    // `verdict(client:input:)` instead.
    func auditWouldDenyRecord(client: String, input: [String: Any]) -> MCPHookAuditRecord? {
        guard !enforced, let call = evaluateCall(client: client, input: input), !call.approved else { return nil }
        return MCPHookAuditRecord(server: call.server, tool: call.tool, rule: "unapproved_server", observedAt: Date().timeIntervalSince1970)
    }

    private func evaluateCall(client: String, input: [String: Any]) -> (server: String, tool: String, approved: Bool)? {
        guard let (server, tool) = mcpHookServerAndTool(client: client, input: input) else { return nil }
        return (server, tool, approvedServers[client, default: []].contains(server))
    }
}

private func validMCPHookName(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.count <= 128 && value.unicodeScalars.allSatisfy {
        CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-").contains($0)
    }
}

private func mcpHookServer(client: String, input: [String: Any]) -> String? {
    mcpHookServerAndTool(client: client, input: input)?.server
}

// Claude Code and Codex encode a tool call as "mcp__<server>__<tool>". The
// tool name itself may contain "__" (for example a plugin-qualified tool),
// so only the first "__"-separated segment is the server; everything after
// it, rejoined with "__", is the tool.
private func mcpHookServerAndTool(client: String, input: [String: Any]) -> (server: String, tool: String)? {
    if client == "cursor" {
        guard let server = input["mcp_server_name"] as? String, validMCPHookName(server),
              let tool = input["tool_name"] as? String, validMCPHookName(tool) else { return nil }
        return (server, tool)
    }
    guard let raw = input["tool_name"] as? String, raw.hasPrefix("mcp__") else { return nil }
    let parts = raw.dropFirst(5).components(separatedBy: "__")
    guard parts.count >= 2, validMCPHookName(parts[0]) else { return nil }
    let tool = parts.dropFirst().joined(separator: "__")
    guard validMCPHookName(tool) else { return nil }
    return (parts[0], tool)
}

func mcpHookOutput(client: String, verdict: MCPHookVerdict) -> [String: Any] {
    switch (client, verdict) {
    case ("cursor", .allow):
        return ["permission": "allow"]
    case ("cursor", .deny(let message)):
        return ["permission": "deny", "user_message": message, "agent_message": message]
    case (_, .allow):
        return [:]
    case (_, .deny(let message)):
        return ["hookSpecificOutput": [
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": message,
        ]]
    }
}

private func readMCPHookInput() throws -> [String: Any] {
    let data = FileHandle.standardInput.readData(ofLength: mcpHookMaximumBytes + 1)
    guard data.count <= mcpHookMaximumBytes else { throw MCPHookError.oversizedInput }
    guard let input = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw MCPHookError.invalidInput
    }
    return input
}

// Best-effort extraction of a raw policy's declared mode, tolerant of a file
// that otherwise fails MCPHookPolicy.parse's strict schema validation. It
// grants no server approvals by itself; it exists only so a policy that
// safely passed the file-ownership checks below but is malformed can still
// signal that it intended enforce mode.
func peekMCPHookPolicyMode(_ data: Data) -> String? {
    guard data.count <= mcpHookMaximumBytes,
          let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
          let mode = root["mode"] as? String, ["audit", "enforce"].contains(mode) else { return nil }
    return mode
}

func readMCPHookPolicy(path: String) throws -> MCPHookPolicy {
    let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
    guard fd >= 0 else { throw MCPHookError.unavailablePolicy }
    defer { close(fd) }
    var metadata = stat()
    guard fstat(fd, &metadata) == 0,
          metadata.st_mode & S_IFMT == S_IFREG,
          metadata.st_uid == 0,
          metadata.st_mode & 0o022 == 0,
          metadata.st_size >= 0,
          metadata.st_size <= mcpHookMaximumBytes else {
        throw MCPHookError.unavailablePolicy
    }
    let data = FileHandle(fileDescriptor: fd, closeOnDealloc: false).readData(ofLength: mcpHookMaximumBytes + 1)
    guard data.count <= mcpHookMaximumBytes else { throw MCPHookError.unavailablePolicy }
    do {
        return try MCPHookPolicy.parse(data)
    } catch {
        // The file passed every ownership and size check above, so its bytes
        // are trustworthy enough to peek at for a mode, even though the full
        // schema failed to validate.
        throw MCPHookError.malformedPolicy(mode: peekMCPHookPolicyMode(data))
    }
}
