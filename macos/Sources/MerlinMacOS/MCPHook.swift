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
        do {
            let input = try readMCPHookInput()
            let policy = try readMCPHookPolicy(path: mcpHookPolicyPath)
            let verdict = try policy.verdict(client: client.rawValue, input: input)
            output = mcpHookOutput(client: client.rawValue, verdict: verdict)
        } catch {
            // Endpoint enforcement points allow on internal errors. Client
            // hooks must never turn a missing or malformed policy into a deny.
            fputs("deixic endpoint mcp hook: \(error)\n", stderr)
            output = mcpHookOutput(client: client.rawValue, verdict: .allow)
        }
        let data = try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys])
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data([0x0a]))
    }
}

private enum MCPHookError: Error {
    case invalidInput, invalidPolicy, unsafePolicyFile, oversizedInput
}

enum MCPHookVerdict: Equatable {
    case allow
    case deny(String)
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
        guard let server = mcpHookServer(client: client, input: input) else {
            // Unrecognized hook events and malformed names do not become an
            // implicit block. Managed client matchers limit calls to MCP.
            return .allow
        }
        guard enforced, !approvedServers[client, default: []].contains(server) else {
            return .allow
        }
        var message = "Deixic Endpoint blocked an unapproved MCP server (\(server))."
        if let approvedName, let approvedURL {
            message += " Use the administrator-approved tool \(approvedName): \(approvedURL)"
        } else {
            message += " Contact your administrator for an approved tool."
        }
        return .deny(message)
    }
}

private func validMCPHookName(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.count <= 128 && value.unicodeScalars.allSatisfy {
        CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-").contains($0)
    }
}

private func mcpHookServer(client: String, input: [String: Any]) -> String? {
    if client == "cursor" {
        guard let server = input["mcp_server_name"] as? String, validMCPHookName(server),
              let tool = input["tool_name"] as? String, validMCPHookName(tool) else { return nil }
        return server
    }
    guard let tool = input["tool_name"] as? String, tool.hasPrefix("mcp__") else { return nil }
    let parts = tool.dropFirst(5).components(separatedBy: "__")
    guard parts.count == 2, validMCPHookName(parts[0]), validMCPHookName(parts[1]) else { return nil }
    return parts[0]
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

func readMCPHookPolicy(path: String) throws -> MCPHookPolicy {
    let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
    guard fd >= 0 else { throw MCPHookError.unsafePolicyFile }
    defer { close(fd) }
    var metadata = stat()
    guard fstat(fd, &metadata) == 0,
          metadata.st_mode & S_IFMT == S_IFREG,
          metadata.st_uid == 0,
          metadata.st_mode & 0o022 == 0,
          metadata.st_size >= 0,
          metadata.st_size <= mcpHookMaximumBytes else {
        throw MCPHookError.unsafePolicyFile
    }
    let data = FileHandle(fileDescriptor: fd, closeOnDealloc: false).readData(ofLength: mcpHookMaximumBytes + 1)
    guard data.count <= mcpHookMaximumBytes else { throw MCPHookError.unsafePolicyFile }
    return try MCPHookPolicy.parse(data)
}
