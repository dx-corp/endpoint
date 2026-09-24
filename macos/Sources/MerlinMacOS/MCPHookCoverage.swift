import CryptoKit
import Darwin
import Foundation

// A local file observation. It cannot establish that a client loaded the hook,
// that an MDM delivered it, or that any tool call passed through it.
struct DeviceMCPHookCoverage: Encodable, Sendable {
    let policy: String
    let policySHA256: String?
    let clients: [DeviceMCPHookClientCoverage]

    enum CodingKeys: String, CodingKey {
        case policy, clients
        case policySHA256 = "policy_sha256"
    }
}

struct DeviceMCPHookClientCoverage: Encodable, Sendable {
    let client: String
    let registration: String
}

private let hookBinary = "/Library/Application Support/Merlin/bin/merlin-macos"
private let hookReadLimit = 64 * 1024
private let hookPolicyFile = "/Library/Application Support/Merlin/mcp-hook-policy.json"

enum HookFileObservation {
    case absent
    case unreadable
    case data(Data)
}

// The daemon is privileged. Never follow a symlink or accept writable or
// non-root-owned client settings as evidence of an administrator registration.
func observeManagedHookFile(_ path: String) -> HookFileObservation {
    guard path.hasPrefix("/"), !path.hasSuffix("/") else { return .unreadable }
    let segments = path.split(separator: "/")
    guard segments.count >= 2, !segments.contains(where: { $0 == "." || $0 == ".." }) else { return .unreadable }
    var directory = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard directory >= 0 else { return .unreadable }
    defer { close(directory) }
    var root = stat()
    guard fstat(directory, &root) == 0,
          root.st_mode & S_IFMT == S_IFDIR,
          root.st_uid == 0,
          root.st_mode & 0o022 == 0 else { return .unreadable }
    for segment in segments.dropLast() {
        let next = openat(directory, String(segment), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        if next < 0 { return errno == ENOENT ? .absent : .unreadable }
        var parent = stat()
        guard fstat(next, &parent) == 0,
              parent.st_mode & S_IFMT == S_IFDIR,
              parent.st_uid == 0,
              parent.st_mode & 0o022 == 0 else {
            close(next)
            return .unreadable
        }
        close(directory)
        directory = next
    }
    let descriptor = openat(directory, String(segments.last!), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
    if descriptor < 0 { return errno == ENOENT ? .absent : .unreadable }
    defer { close(descriptor) }
    var info = stat()
    guard fstat(descriptor, &info) == 0,
          info.st_mode & S_IFMT == S_IFREG,
          info.st_uid == 0,
          info.st_mode & 0o022 == 0,
          info.st_size >= 0,
          info.st_size <= hookReadLimit else { return .unreadable }
    let data = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false).readData(ofLength: hookReadLimit + 1)
    return data.count <= hookReadLimit ? .data(data) : .unreadable
}

func collectMCPHookCoverage() -> DeviceMCPHookCoverage {
    let policy: String
    let digest: String?
    switch observeManagedHookFile(hookPolicyFile) {
    case .absent:
        policy = "absent"
        digest = nil
    case .unreadable:
        policy = "invalid"
        digest = nil
    case .data(let data):
        if let parsed = try? MCPHookPolicy.parse(data) {
            policy = parsed.enforced ? "enforce" : "audit"
            digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        } else {
            policy = "invalid"
            digest = nil
        }
    }

    let definitions: [(String, String, (Data) -> Bool)] = [
        ("cursor", "/Library/Application Support/Cursor/hooks.json", { cursorHookRegistered($0) }),
        ("claude", "/Library/Application Support/ClaudeCode/managed-settings.json", { claudeHookRegistered($0) }),
        // macOS /etc is a symlink to /private/etc; use its canonical path so
        // every ancestor can be checked without following a symlink.
        ("codex", "/private/etc/codex/requirements.toml", { codexHookRegistered($0) }),
    ]
    let clients = definitions.map { client, path, matches -> DeviceMCPHookClientCoverage in
        let registration: String
        switch observeManagedHookFile(path) {
        case .absent: registration = "absent"
        case .unreadable: registration = "unreadable"
        case .data(let data): registration = matches(data) ? "observed" : "not_observed"
        }
        return DeviceMCPHookClientCoverage(client: client, registration: registration)
    }
    return DeviceMCPHookCoverage(policy: policy, policySHA256: digest, clients: clients)
}

private func hookCommandMatches(_ value: Any?, client: String) -> Bool {
    guard let command = value as? String else { return false }
    // The two supported spellings in the managed deployment guide. Do not
    // treat a substring in an arbitrary command as a managed hook.
    return command == "\(hookBinary) mcp-hook --client \(client)" ||
        command == "'\(hookBinary)' mcp-hook --client \(client)"
}

private func hookJSON(_ data: Data) -> [String: Any]? {
    (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
}

func cursorHookRegistered(_ data: Data) -> Bool {
    guard let root = hookJSON(data), root["version"] as? Int == 1,
          let hooks = root["hooks"] as? [String: Any],
          let entries = hooks["beforeMCPExecution"] as? [[String: Any]],
          entries.count <= 128 else { return false }
    return entries.contains { hookCommandMatches($0["command"], client: "cursor") }
}

func claudeHookRegistered(_ data: Data) -> Bool {
    guard let hooks = hookJSON(data)?["hooks"] as? [String: Any],
          let entries = hooks["PreToolUse"] as? [[String: Any]],
          entries.count <= 128 else { return false }
    return entries.contains { entry in
        guard entry["matcher"] as? String == "mcp__.*",
              let commands = entry["hooks"] as? [[String: Any]], commands.count <= 128 else { return false }
        return commands.contains { $0["type"] as? String == "command" && hookCommandMatches($0["command"], client: "claude") }
    }
}

// Conservative TOML subset for the exact managed sample. A matching line in
// a comment or another table is insufficient. Unsupported syntax is reported
// as not observed instead of claiming coverage.
func codexHookRegistered(_ data: Data) -> Bool {
    guard let source = String(data: data, encoding: .utf8) else { return false }
    var table = ""
    var featureEnabled = false
    var managedDirectory = false
    var matcher = false
    var command = false
    var commandType = false
    var foundHandler = false
    func matchesHandler() -> Bool { matcher && command && commandType }
    for rawLine in source.split(separator: "\n", omittingEmptySubsequences: false) {
        let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
        if line.isEmpty || line.hasPrefix("#") { continue }
        if line.hasPrefix("[") {
            foundHandler = foundHandler || matchesHandler()
            if line == "[features]" || line == "[hooks]" || line == "[[hooks.PreToolUse]]" || line == "[[hooks.PreToolUse.hooks]]" {
                table = line
            } else {
                table = ""
            }
            if line == "[[hooks.PreToolUse]]" {
                matcher = false
                command = false
                commandType = false
            } else if line == "[[hooks.PreToolUse.hooks]]" {
                command = false
                commandType = false
            } else {
                matcher = false
                command = false
                commandType = false
            }
            continue
        }
        let parts = line.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        guard parts.count == 2 else { return false }
        switch (table, parts[0], parts[1]) {
        case ("[features]", "hooks", _): featureEnabled = parts[1] == "true"
        case ("[hooks]", "managed_dir", _): managedDirectory = parts[1] == "\"/Library/Application Support/Merlin/bin\""
        case ("[[hooks.PreToolUse]]", "matcher", _): matcher = parts[1] == "\"^mcp__.*\""
        case ("[[hooks.PreToolUse.hooks]]", "type", _): commandType = parts[1] == "\"command\""
        case ("[[hooks.PreToolUse.hooks]]", "command", _): command = parts[1] == "\"'\(hookBinary)' mcp-hook --client codex\""
        default: break
        }
    }
    return featureEnabled && managedDirectory && (foundHandler || matchesHandler())
}
