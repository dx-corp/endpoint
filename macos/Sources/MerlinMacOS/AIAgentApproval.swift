// AI agents running without approval: one posture check per AI client,
// evaluated from the rules declared in ai-agent-approval.toml, the one
// declaration every port evaluates (the Linux agent compiles it in).
//
// The table between the BEGIN and END markers is that declaration with its
// macOS paths. It is not edited by hand: merlin's Rust test
// `swift_table_matches_the_declaration` renders it from the TOML and fails,
// printing the expected block, when this copy drifts.
//
// Each client's user files (under each home) and managed files (fixed system
// paths) are read with no symlink anywhere below the home or the system root,
// at most 64 KiB each, through the same readers the AI tool inventory uses.
// Only the declared reason and rule ids leave the device: never setting
// values, paths or account names. A client with none of its files is omitted.

import Darwin
import Foundation

enum AIApprovalScope: Sendable { case user, managed }
enum AIApprovalFormat: Sendable { case json, toml }
enum AIApprovalScalar: Sendable, Equatable { case bool(Bool), text(String) }

/// Every condition of a rule or lock must hold in the same file. `key` is a
/// dotted path; `anyOf` matches a value equal to one scalar or an array
/// holding one; `lacks` matches an array of strings holding none of them.
struct AIApprovalCondition: Sendable {
    let key: String
    let anyOf: [AIApprovalScalar]
    let lacks: [String]
}

struct AIApprovalSource: Sendable {
    let scope: AIApprovalScope
    let format: AIApprovalFormat
    /// Relative to each home (user) or absolute (managed).
    let path: String
}

struct AIApprovalRule: Sendable {
    let id: String
    let severity: String
    let reason: String
    let when: [AIApprovalCondition]
}

struct AIApprovalLock: Sendable {
    let id: String
    let reason: String
    let when: [AIApprovalCondition]
    let neutralizes: [String]
}

struct AIApprovalClient: Sendable {
    let id: String
    let check: String
    let name: String
    let sources: [AIApprovalSource]
    let rules: [AIApprovalRule]
    let locks: [AIApprovalLock]
}

// BEGIN ai-agent-approval.toml
let aiApprovalUnreadable = "Not checked: an AI agent settings file exists but could not be read or parsed"
let aiApprovalAsks = "No declared setting lets this AI agent act without asking"

let aiApprovalClients: [AIApprovalClient] = [
    AIApprovalClient(
        id: "claude_code", check: "ai_agent_approval_claude_code", name: "Claude Code",
        sources: [
            AIApprovalSource(scope: .user, format: .json, path: ".claude/settings.json"),
            AIApprovalSource(scope: .managed, format: .json, path: "/Library/Application Support/ClaudeCode/managed-settings.json"),
        ],
        rules: [
            AIApprovalRule(id: "bypass_permissions", severity: "high", reason: "Claude Code permissions.defaultMode skips every permission prompt (bypassPermissions)", when: [AIApprovalCondition(key: "permissions.defaultMode", anyOf: [.text("bypassPermissions")], lacks: [])]),
            AIApprovalRule(id: "allow_all_shell", severity: "medium", reason: "Claude Code permissions.allow approves every shell command without asking", when: [AIApprovalCondition(key: "permissions.allow", anyOf: [.text("Bash"), .text("Bash(*)"), .text("PowerShell"), .text("PowerShell(*)")], lacks: [])]),
        ],
        locks: [
            AIApprovalLock(id: "managed_bypass_disabled", reason: "Admin-managed Claude Code settings turn off bypass mode (permissions.disableBypassPermissionsMode)", when: [AIApprovalCondition(key: "permissions.disableBypassPermissionsMode", anyOf: [.text("disable")], lacks: [])], neutralizes: ["bypass_permissions"]),
            AIApprovalLock(id: "managed_rules_only", reason: "Admin-managed Claude Code settings ignore user permission rules (allowManagedPermissionRulesOnly)", when: [AIApprovalCondition(key: "allowManagedPermissionRulesOnly", anyOf: [.bool(true)], lacks: [])], neutralizes: ["allow_all_shell"]),
        ]
    ),
    AIApprovalClient(
        id: "codex", check: "ai_agent_approval_codex", name: "Codex",
        sources: [
            AIApprovalSource(scope: .user, format: .toml, path: ".codex/config.toml"),
            AIApprovalSource(scope: .managed, format: .toml, path: "/etc/codex/requirements.toml"),
            AIApprovalSource(scope: .managed, format: .toml, path: "/etc/codex/managed_config.toml"),
        ],
        rules: [
            AIApprovalRule(id: "never_ask_full_access", severity: "high", reason: "Codex approval_policy never asks and sandbox_mode gives full access", when: [AIApprovalCondition(key: "approval_policy", anyOf: [.text("never")], lacks: []), AIApprovalCondition(key: "sandbox_mode", anyOf: [.text("danger-full-access")], lacks: [])]),
            AIApprovalRule(id: "never_ask_full_access_profile", severity: "high", reason: "Codex approval_policy never asks and default_permissions gives full access", when: [AIApprovalCondition(key: "approval_policy", anyOf: [.text("never")], lacks: []), AIApprovalCondition(key: "default_permissions", anyOf: [.text(":danger-full-access")], lacks: [])]),
        ],
        locks: [
            AIApprovalLock(id: "managed_approval_required", reason: "Admin-managed Codex requirements forbid approval_policy never (allowed_approval_policies)", when: [AIApprovalCondition(key: "allowed_approval_policies", anyOf: [], lacks: ["never"])], neutralizes: ["never_ask_full_access", "never_ask_full_access_profile"]),
            AIApprovalLock(id: "managed_sandbox_required", reason: "Admin-managed Codex requirements forbid danger-full-access (allowed_sandbox_modes)", when: [AIApprovalCondition(key: "allowed_sandbox_modes", anyOf: [], lacks: ["danger-full-access"])], neutralizes: ["never_ask_full_access"]),
        ]
    ),
    AIApprovalClient(
        id: "gemini_cli", check: "ai_agent_approval_gemini_cli", name: "Gemini CLI",
        sources: [
            AIApprovalSource(scope: .user, format: .json, path: ".gemini/settings.json"),
            AIApprovalSource(scope: .managed, format: .json, path: "/Library/Application Support/GeminiCli/settings.json"),
        ],
        rules: [
            AIApprovalRule(id: "allow_all_shell", severity: "medium", reason: "Gemini CLI tools.allowed lets every shell command skip confirmation (run_shell_command)", when: [AIApprovalCondition(key: "tools.allowed", anyOf: [.text("run_shell_command")], lacks: [])]),
        ],
        locks: [
            AIApprovalLock(id: "managed_yolo_disabled", reason: "Admin-managed Gemini CLI settings turn off YOLO mode (security.disableYoloMode)", when: [AIApprovalCondition(key: "security.disableYoloMode", anyOf: [.bool(true)], lacks: [])], neutralizes: []),
            AIApprovalLock(id: "managed_secure_mode", reason: "Admin-managed Gemini CLI settings turn on secure mode (admin.secureModeEnabled)", when: [AIApprovalCondition(key: "admin.secureModeEnabled", anyOf: [.bool(true)], lacks: [])], neutralizes: []),
        ]
    ),
    AIApprovalClient(
        id: "cursor_cli", check: "ai_agent_approval_cursor_cli", name: "Cursor CLI",
        sources: [
            AIApprovalSource(scope: .user, format: .json, path: ".cursor/cli-config.json"),
        ],
        rules: [
            AIApprovalRule(id: "unrestricted", severity: "high", reason: "Cursor CLI approvalMode runs agent actions without approval (unrestricted)", when: [AIApprovalCondition(key: "approvalMode", anyOf: [.text("unrestricted")], lacks: [])]),
            AIApprovalRule(id: "allow_all_shell", severity: "medium", reason: "Cursor CLI permissions.allow approves every shell command (Shell(*))", when: [AIApprovalCondition(key: "permissions.allow", anyOf: [.text("Shell(*)")], lacks: [])]),
        ],
        locks: [
        ]
    ),
]
// END ai-agent-approval.toml

/// A settings value as the rules see it.
enum AIApprovalValue: Equatable, Sendable {
    case bool(Bool)
    case text(String)
    case array([AIApprovalValue])
    case other
}

/// A parsed settings file.
enum AIApprovalDocument {
    case json(Any)
    case toml([[String]: TOMLLeafScanner.Value])

    /// The value at a dotted key, or nil when the key is absent.
    func value(at key: String) -> AIApprovalValue? {
        let path = key.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        switch self {
        case .json(let root):
            var node = root
            for part in path {
                guard let object = node as? [String: Any], let next = object[part] else { return nil }
                node = next
            }
            return aiApprovalValue(json: node)
        case .toml(let leaves):
            switch leaves[path] {
            case nil: return nil
            case .bool(let flag)?: return .bool(flag)
            case .string(let text)?: return .text(text)
            case .strings(let items)?: return .array(items.map { .text($0) })
            case .other?: return .other
            }
        }
    }
}

/// A JSON value from JSONSerialization. A boolean is told from a number by
/// its CoreFoundation type, as `as? Bool` also accepts 0 and 1.
func aiApprovalValue(json: Any) -> AIApprovalValue {
    if let number = json as? NSNumber {
        return CFGetTypeID(number) == CFBooleanGetTypeID() ? .bool(number.boolValue) : .other
    }
    if let text = json as? String { return .text(text) }
    if let items = json as? [Any] { return .array(items.map { aiApprovalValue(json: $0) }) }
    return .other
}

extension AIApprovalScalar {
    func matches(_ value: AIApprovalValue) -> Bool {
        switch (self, value) {
        case let (.bool(want), .bool(got)): return want == got
        case let (.text(want), .text(got)): return want == got
        default: return false
        }
    }
}

extension AIApprovalCondition {
    func holds(in document: AIApprovalDocument) -> Bool {
        guard let value = document.value(at: key) else { return false }
        if !anyOf.isEmpty {
            let wanted = anyOf
            let matches = { (item: AIApprovalValue) in wanted.contains { $0.matches(item) } }
            if case .array(let items) = value { return items.contains(where: matches) }
            return matches(value)
        }
        guard case .array(let items) = value else { return false }
        let lacked = lacks
        return items.allSatisfy { item in
            if case .text(let text) = item { return !lacked.contains(text) }
            return false
        }
    }
}

enum AIApprovalObservation {
    case missing
    case unreadable
    case parsed(AIApprovalDocument)
}

/// macOS keeps /etc as a link to /private/etc. A managed path under /etc is
/// read through the real directory, so no link is followed on the way.
func aiApprovalSystemPath(_ path: String) -> String {
    path.hasPrefix("/etc/") ? "/private" + path : path
}

/// Reads `relative` beneath `base` with no symlink below `base`: a missing
/// file is `missing`; one that exists but is a link, sits under a link, is
/// over 64 KiB or does not parse is `unreadable`.
func observeAIApprovalFile(base: String, relative: String, format: AIApprovalFormat) -> AIApprovalObservation {
    let full = base.hasSuffix("/") ? base + relative : base + "/" + relative
    var info = stat()
    if lstat(full, &info) != 0 {
        return errno == ENOENT ? .missing : .unreadable
    }
    let parts = relative.split(separator: "/").map(String.init)
    guard let name = parts.last,
          let directory = openAgentDirectoryNoFollow(home: base, relative: parts.dropLast().joined(separator: "/"))
    else { return .unreadable }
    defer { close(directory) }
    guard let data = readAgentConfigNoFollow(descriptor: directory, name: name) else { return .unreadable }
    switch format {
    case .json:
        guard let object = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) else {
            return .unreadable
        }
        return .parsed(.json(object))
    case .toml:
        guard let leaves = TOMLLeafScanner.parse([UInt8](data)) else { return .unreadable }
        var values: [[String]: TOMLLeafScanner.Value] = [:]
        for leaf in leaves { values[leaf.path] = leaf.value }
        return .parsed(.toml(values))
    }
}

/// One client's check: finding, unknown (not checked) or pass, with the
/// declared reason; the value is the matched rule ids, `not_checked`,
/// `managed` or `asks`.
struct AIApprovalResult: Equatable, Sendable {
    let check: String
    let status: String
    let value: String
    let severity: String?
    let reason: String
}

/// Evaluates one client over its observed files, as the Linux agent does: a
/// rule that matches in any file and that no managed lock neutralizes is a
/// finding; otherwise an unreadable file is not checked, a managed lock is a
/// pass naming it, and files read with nothing matched are a pass. Nil when
/// none of the client's files exists.
func evaluateAIApproval(
    _ client: AIApprovalClient,
    files: [(scope: AIApprovalScope, observation: AIApprovalObservation)]
) -> AIApprovalResult? {
    var anyPresent = false
    var anyParsed = false
    var anyUnreadable = false
    var matched: [AIApprovalRule] = []
    var locks: [AIApprovalLock] = []
    for file in files {
        switch file.observation {
        case .missing:
            continue
        case .unreadable:
            anyPresent = true
            anyUnreadable = true
        case .parsed(let document):
            anyPresent = true
            anyParsed = true
            for rule in client.rules where rule.when.allSatisfy({ $0.holds(in: document) }) {
                if !matched.contains(where: { $0.id == rule.id }) { matched.append(rule) }
            }
            if file.scope == .managed {
                for lock in client.locks where lock.when.allSatisfy({ $0.holds(in: document) }) {
                    locks.append(lock)
                }
            }
        }
    }
    guard anyPresent else { return nil }
    matched.removeAll { rule in locks.contains { $0.neutralizes.contains(rule.id) } }
    // Declaration order, so the reason is stable across runs.
    let order = client.rules.map(\.id)
    matched.sort { (order.firstIndex(of: $0.id) ?? 0) < (order.firstIndex(of: $1.id) ?? 0) }
    if let first = matched.first {
        let ranks = ["low", "medium", "high", "critical"]
        let severity = matched.map(\.severity).max { (ranks.firstIndex(of: $0) ?? 0) < (ranks.firstIndex(of: $1) ?? 0) }
        return AIApprovalResult(
            check: client.check, status: "finding", value: matched.map(\.id).joined(separator: ","),
            severity: severity, reason: first.reason
        )
    }
    if anyUnreadable {
        return AIApprovalResult(check: client.check, status: "unknown", value: "not_checked", severity: nil, reason: aiApprovalUnreadable)
    }
    if let lock = locks.first {
        return AIApprovalResult(check: client.check, status: "pass", value: "managed", severity: nil, reason: lock.reason)
    }
    if anyParsed {
        return AIApprovalResult(check: client.check, status: "pass", value: "asks", severity: nil, reason: aiApprovalAsks)
    }
    return nil
}

/// Reads every declared client's files. `root` is where managed (absolute)
/// paths are resolved; empty means `/`.
func collectAIApproval(homes: [String], root: String = "", clients: [AIApprovalClient] = aiApprovalClients) -> [AIApprovalResult] {
    let systemRoot = root.isEmpty ? "/" : root
    return clients.compactMap { client in
        var files: [(scope: AIApprovalScope, observation: AIApprovalObservation)] = []
        for source in client.sources {
            switch source.scope {
            case .user:
                for home in homes {
                    files.append((.user, observeAIApprovalFile(base: home, relative: source.path, format: source.format)))
                }
            case .managed:
                let relative = String(aiApprovalSystemPath(source.path).drop { $0 == "/" })
                files.append((.managed, observeAIApprovalFile(base: systemRoot, relative: relative, format: source.format)))
            }
        }
        return evaluateAIApproval(client, files: files)
    }
}

/// Adds each client's result to a posture snapshot: the value, and the
/// reason as the finding detail or, for a pass or not checked, as its
/// reason.
func addAIApprovalChecks(_ results: [AIApprovalResult], to snapshot: inout PostureSnapshot) {
    for result in results {
        snapshot.values[result.check] = result.value
        if result.status == "finding" {
            snapshot.findings[result.check] = result.reason
            if let severity = result.severity { snapshot.severities[result.check] = severity }
        } else {
            snapshot.reasons[result.check] = result.reason
        }
    }
}
