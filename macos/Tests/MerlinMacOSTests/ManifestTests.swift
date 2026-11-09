import Foundation
import Testing
@testable import MerlinMacOS

// The macOS manifest and the Linux one (merlin/src/manifest.rs) describe one
// product: same collector ids, same number of never-claims, same version.
// A collector added to one port without the other fails here.

private func rustManifestSource() throws -> String {
    let here = URL(fileURLWithPath: #filePath)
    let rust = here
        .deletingLastPathComponent() // ManifestTests.swift -> MerlinMacOSTests
        .deletingLastPathComponent() // -> Tests
        .deletingLastPathComponent() // -> macos
        .deletingLastPathComponent() // -> deixic-endpoint
        .appendingPathComponent("merlin/src/manifest.rs")
    return try String(contentsOf: rust, encoding: .utf8)
}

private func rustCollectorIds(_ source: String) -> Set<String> {
    var ids = Set<String>()
    for line in source.split(separator: "\n") {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("id: \"") {
            let rest = trimmed.dropFirst("id: \"".count)
            if let end = rest.firstIndex(of: "\"") { ids.insert(String(rest[..<end])) }
        }
    }
    return ids
}

@Suite("collection manifest")
struct ManifestTests {
    @Test("collector ids match the Linux port")
    func collectorIdsMatchLinux() throws {
        let rust = try rustManifestSource()
        let linux = rustCollectorIds(rust)
        let mac = Set(CollectionManifest.collectors.map(\.id))
        #expect(!linux.isEmpty)
        #expect(mac == linux, "macOS \(mac.symmetricDifference(linux)) differs from Linux")
        #expect(CollectionManifest.collectors.count == mac.count, "ids are unique")
        // Same version and the same number of never-claims.
        #expect(rust.contains("pub const MANIFEST_VERSION: u32 = \(CollectionManifest.version);"))
        let rustNever = rust.components(separatedBy: "Never {").count - 1 - 1 // minus the struct declaration
        #expect(rustNever == CollectionManifest.neverCollected.count)
    }

    @Test("command line leaves the device only with a matched rule")
    func commandLineOnlyWithAMatch() {
        #expect(SpoolEvent.recordedCmdline("zsh -c 'curl -H token'", matchedRules: []) == nil)
        #expect(SpoolEvent.recordedCmdline(nil, matchedRules: ["rule"]) == nil)
        #expect(SpoolEvent.recordedCmdline("zsh -c id", matchedRules: ["rule"]) == "zsh -c id")
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
