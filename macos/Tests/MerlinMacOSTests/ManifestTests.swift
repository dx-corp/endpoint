import Foundation
import Testing
@testable import MerlinMacOS

// The macOS manifest and the declared one (collection-manifest.toml, which the
// Linux port compiles in) describe one product: same collector ids, same
// number of never-claims, same version.
// A collector added to one port without the other fails here.

private func declaredManifestSource() throws -> String {
    let here = URL(fileURLWithPath: #filePath)
    let rust = here
        .deletingLastPathComponent() // ManifestTests.swift -> MerlinMacOSTests
        .deletingLastPathComponent() // -> Tests
        .deletingLastPathComponent() // -> macos
        .deletingLastPathComponent() // -> deixic-endpoint
        .appendingPathComponent("collection-manifest.toml")
    return try String(contentsOf: rust, encoding: .utf8)
}

private func declaredCollectorIds(_ source: String) -> Set<String> {
    var ids = Set<String>()
    for line in source.split(separator: "\n") {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("id = \"") {
            let rest = trimmed.dropFirst("id = \"".count)
            if let end = rest.firstIndex(of: "\"") { ids.insert(String(rest[..<end])) }
        }
    }
    return ids
}

/// The ai_locations rows declared for macOS, as "scope client kind path".
/// Each row is one inline table on one line of collection-manifest.toml.
private func declaredMacAILocations(_ source: String) -> Set<String> {
    var rows = Set<String>()
    var inside = false
    for line in source.split(separator: "\n").map({ $0.trimmingCharacters(in: .whitespaces) }) {
        if line == "ai_locations = [" { inside = true; continue }
        if inside && line == "]" { inside = false; continue }
        guard inside, line.hasPrefix("{") else { continue }
        var fields: [String: String] = [:]
        for key in ["client", "kind", "path", "scope"] {
            guard let start = line.range(of: "\(key) = \"") else { continue }
            let rest = line[start.upperBound...]
            if let end = rest.firstIndex(of: "\"") { fields[key] = String(rest[..<end]) }
        }
        if let platforms = line.range(of: "platforms = [") {
            let list = line[platforms.upperBound...].prefix { $0 != "]" }
            if !list.contains("\"macos\"") { continue }
        }
        if let scope = fields["scope"], let client = fields["client"], let kind = fields["kind"], let path = fields["path"] {
            rows.insert("\(scope) \(client) \(kind) \(path)")
        }
    }
    return rows
}

/// The `max_bytes` of each user ai_locations row that sets one, by path.
private func declaredReadLimits(_ source: String, scope: String) -> [String: Int] {
    var limits: [String: Int] = [:]
    for line in source.split(separator: "\n").map({ $0.trimmingCharacters(in: .whitespaces) }) where line.hasPrefix("{") && line.contains("scope = \"\(scope)\"") {
        guard let path = line.range(of: "path = \""), let bytes = line.range(of: "max_bytes = ") else { continue }
        let name = line[path.upperBound...].prefix { $0 != "\"" }
        limits[String(name)] = Int(line[bytes.upperBound...].prefix { $0.isNumber })
    }
    return limits
}

/// The `projects_key` of each user ai_locations row that sets one, by path.
private func declaredUserProjectKeys(_ source: String) -> [String: String] {
    var keys: [String: String] = [:]
    for line in source.split(separator: "\n").map({ $0.trimmingCharacters(in: .whitespaces) }) where line.hasPrefix("{") && line.contains("scope = \"user\"") {
        guard let path = line.range(of: "path = \""), let key = line.range(of: "projects_key = \"") else { continue }
        keys[String(line[path.upperBound...].prefix { $0 != "\"" })] = String(line[key.upperBound...].prefix { $0 != "\"" })
    }
    return keys
}

@Suite("collection manifest")
struct ManifestTests {
    @Test("collector ids match the Linux port")
    func collectorIdsMatchLinux() throws {
        let rust = try declaredManifestSource()
        let linux = declaredCollectorIds(rust)
        let mac = Set(CollectionManifest.collectors.map(\.id))
        #expect(!linux.isEmpty)
        #expect(mac == linux, "macOS \(mac.symmetricDifference(linux)) differs from Linux")
        #expect(CollectionManifest.collectors.count == mac.count, "ids are unique")
        // Same version and the same number of never-claims.
        #expect(rust.contains("\nmanifest_version = \(CollectionManifest.version)\n"))
        // The release sets the version (packaging/stamp-manifest-version.sh);
        // main and pull requests keep the development placeholder.
        #expect(CollectionManifest.version == 0, "set by the release; keep it 0")
        #expect(CollectionManifest.versionLabel(0) == "(development build)")
        #expect(CollectionManifest.versionLabel(103) == "v103")
        let rustNever = rust.components(separatedBy: "[[never_collected]]").count - 1
        #expect(rustNever == CollectionManifest.neverCollected.count)
    }

    @Test("AI extension ids match the declared manifest")
    func aiExtensionsMatchManifest() throws {
        var declared: [String: Set<String>] = [:]
        var inside = false
        for line in try declaredManifestSource().split(separator: "\n").map({ $0.trimmingCharacters(in: .whitespaces) }) {
            if line == "ai_extensions = [" { inside = true; continue }
            if inside && line == "]" { break }
            guard inside, line.hasPrefix("{") else { continue }
            func value(_ key: String) -> String? {
                guard let start = line.range(of: "\(key) = \"") else { return nil }
                let rest = line[start.upperBound...]
                return rest.firstIndex(of: "\"").map { String(rest[..<$0]) }
            }
            if let store = value("store"), let id = value("id") { declared[store, default: []].insert(id) }
        }
        #expect(declared["vscode-marketplace"] == Set(macEditorAIExtensions))
        #expect(declared["chrome-web-store"] == Set(macChromeAIExtensions))
    }

    @Test("AI locations match the declared manifest")
    func aiLocationsMatchManifest() throws {
        let declared = declaredMacAILocations(try declaredManifestSource())
        #expect(!declared.isEmpty)
        var probed = Set(macAgentCLINames.map { "user \($0) cli \($0)" })
        probed.insert("user cursor agent \(macCursorAgentsDirectory)")
        probed.insert("user cursor plugin \(macCursorLocalPluginsDirectory)")
        probed.insert("user claude plugin \(macClaudePluginCacheDirectory)")
        probed.insert("user vscode extension \(macEditorExtensionsDirectory)")
        probed.insert("user chrome extension \(macChromeUserDataDirectory)")
        for (client, relative, _) in macUserAgentConfigs { probed.insert("user \(client) config \(relative)") }
        for (client, kind, relative, _) in macUserAgentAssetDirs { probed.insert("user \(client) \(kind) \(relative)") }
        for (client, relative, _) in macProjectAgentConfigs { probed.insert("project \(client) config \(relative)") }
        for (client, path) in macSystemAgentConfigs { probed.insert("system \(client) config \(path)") }
        for (client, kind, relative, _) in macProjectAgentAssetDirs { probed.insert("project \(client) \(kind) \(relative)") }
        #expect(probed == declared, "not probed: \(declared.subtracting(probed).sorted()); not declared: \(probed.subtracting(declared).sorted())")
    }

    @Test("config read limits match the declared max_bytes")
    func readLimitsMatchManifest() throws {
        let source = try declaredManifestSource()
        #expect(!declaredReadLimits(source, scope: "user").isEmpty)
        #expect(declaredReadLimits(source, scope: "user") == macUserAgentConfigReadLimits)
        #expect(declaredReadLimits(source, scope: "project") == macProjectAgentConfigReadLimits)
    }

    @Test("project MCP keys match the declared projects_key")
    func projectKeysMatchManifest() throws {
        let declared = declaredUserProjectKeys(try declaredManifestSource())
        #expect(!declared.isEmpty)
        #expect(declared == macUserAgentConfigProjectKeys)
    }

    @Test("declared collectors follow the static build capabilities")
    func declaredCollectorsFollowCapabilities() {
        let every = CollectionManifest.collectors.map(\.id)
        #expect(CollectionManifest.activeCollectorIds(capabilities: checkInCapabilities) == every,
                "this build announces every collector it declares")
        #expect(CollectionManifest.activeCollectorIds(capabilities: []) == ["ai_tools"])
        let events = CollectionManifest.activeCollectorIds(capabilities: ["segment_upload"])
        #expect(events.contains("process_events") && events.contains("health"))
        #expect(!events.contains("software") && !events.contains("posture_checks"))
    }

    @Test("serialized records contain hashes and identifiers without raw values")
    func serializedRecordFields() throws {
        let fim = DeviceFIMEntry(
            path: "/etc/example", sha256: "abc123", sizeBytes: 42,
            mode: "600", modifiedUnix: 1_700_000_000, status: "present")
        let fimObject = try JSONSerialization.jsonObject(with: JSONEncoder().encode(fim)) as? [String: Any]
        #expect(fimObject.map { Set($0.keys) } == ["path", "sha256", "size_bytes", "mode", "modified_unix", "status"])
        #expect(fimObject?["sha256"] as? String == "abc123")
        #expect(fimObject?["size_bytes"] as? Int == 42)

        let mcp = DeviceMCPServer(client: "codex", name: "docs", source: ".codex/config.toml", transport: "stdio")
        let mcpObject = try JSONSerialization.jsonObject(with: JSONEncoder().encode(mcp)) as? [String: Any]
        #expect(mcpObject.map { Set($0.keys) } == ["client", "name", "source", "transport"])
        #expect(mcpObject?["name"] as? String == "docs")
        #expect(mcpObject?["transport"] as? String == "stdio")
    }

    @Test("renders text and JSON with the public shape")
    func renders() throws {
        let manifest = CollectionManifest.current()
        let text = manifest.renderText()
        #expect(text.contains("What it never collects"))
        #expect(text.contains("a tombstone remains after retirement/disposal"))
        let data = Data(try manifest.renderJSON().utf8)
        let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        #expect(object?["manifest_version"] as? Int == CollectionManifest.version)
        #expect((object?["collectors"] as? [Any])?.count == CollectionManifest.collectors.count)
        #expect(object?["platform"] as? String == "macos")
    }
}
