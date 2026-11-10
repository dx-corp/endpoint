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
        let rustNever = rust.components(separatedBy: "[[never_collected]]").count - 1
        #expect(rustNever == CollectionManifest.neverCollected.count)
    }

    @Test("AI locations match the declared manifest")
    func aiLocationsMatchManifest() throws {
        let declared = declaredMacAILocations(try declaredManifestSource())
        #expect(!declared.isEmpty)
        var probed = Set(macAgentCLINames.map { "user \($0) cli \($0)" })
        probed.insert("user cursor agent \(macCursorAgentsDirectory)")
        probed.insert("user cursor plugin \(macCursorLocalPluginsDirectory)")
        for (client, relative, _) in macUserAgentConfigs { probed.insert("user \(client) config \(relative)") }
        for (client, kind, relative, _) in macUserAgentAssetDirs { probed.insert("user \(client) \(kind) \(relative)") }
        for (client, relative, _) in macProjectAgentConfigs { probed.insert("project \(client) config \(relative)") }
        for (client, kind, relative, _) in macProjectAgentAssetDirs { probed.insert("project \(client) \(kind) \(relative)") }
        #expect(probed == declared, "not probed: \(declared.subtracting(probed).sorted()); not declared: \(probed.subtracting(declared).sorted())")
    }

    @Test("active collectors follow the announced capabilities")
    func activeCollectorsFollowCapabilities() {
        let every = CollectionManifest.collectors.map(\.id)
        #expect(CollectionManifest.activeCollectorIds(capabilities: checkInCapabilities) == every,
                "this build announces every collector it declares")
        #expect(CollectionManifest.activeCollectorIds(capabilities: []) == ["ai_tools"])
        let events = CollectionManifest.activeCollectorIds(capabilities: ["segment_upload"])
        #expect(events.contains("process_events") && events.contains("health"))
        #expect(!events.contains("software") && !events.contains("posture_checks"))
    }

    @Test("renders text and JSON with the public shape")
    func renders() throws {
        let manifest = CollectionManifest.current()
        let text = manifest.renderText()
        #expect(text.contains("What it never collects"))
        let data = Data(try manifest.renderJSON().utf8)
        let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        #expect(object?["manifest_version"] as? Int == CollectionManifest.version)
        #expect((object?["collectors"] as? [Any])?.count == CollectionManifest.collectors.count)
        #expect(object?["platform"] as? String == "macos")
    }
}
