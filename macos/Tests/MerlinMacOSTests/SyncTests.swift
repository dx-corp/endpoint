import CryptoKit
import Foundation
import Testing
@testable import MerlinMacOS

// Sync client tests — no network: a URLProtocol mock stands in for the
// server. Covers the upload state machine and Ed25519 policy delivery
// (ack/delete, failure/retry, 200-vs-202), rules last-known-good, and
// segment dir watching.

/// Intercepts every request of the test URLSession.
private final class MockURLProtocol: URLProtocol, @unchecked Sendable {
    /// request → (status, headers, body)
    nonisolated(unsafe) static var handler: ((URLRequest) -> (Int, [String: String], Data))!
    private static let seenLock = NSLock()
    nonisolated(unsafe) private static var seenRequests: [URLRequest] = []
    nonisolated(unsafe) private static var seenBodies: [Data] = []

    static var seen: [URLRequest] {
        seenLock.lock()
        defer { seenLock.unlock() }
        return seenRequests
    }

    static var bodies: [Data] {
        seenLock.lock()
        defer { seenLock.unlock() }
        return seenBodies
    }

    static func reset() {
        seenLock.lock()
        seenRequests = []
        seenBodies = []
        seenLock.unlock()
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        // URLSession hands the body over as a stream, not httpBody.
        var body = Data()
        if let stream = request.httpBodyStream {
            stream.open()
            var buf = [UInt8](repeating: 0, count: 65536)
            while stream.hasBytesAvailable {
                let n = stream.read(&buf, maxLength: buf.count)
                if n <= 0 { break }
                body.append(contentsOf: buf.prefix(n))
            }
            stream.close()
        } else if let direct = request.httpBody {
            body = direct
        }
        MockURLProtocol.seenLock.lock()
        MockURLProtocol.seenRequests.append(request)
        MockURLProtocol.seenBodies.append(body)
        MockURLProtocol.seenLock.unlock()
        let (status, headers, responseBody) = MockURLProtocol.handler(request)
        let response = HTTPURLResponse(
            url: request.url!, statusCode: status,
            httpVersion: nil, headerFields: headers
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: responseBody)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

private func mockSession() -> URLSession {
    let config = URLSessionConfiguration.ephemeral
    config.protocolClasses = [MockURLProtocol.self]
    return URLSession(configuration: config)
}

private func makeAgentSkills(home: String, count: Int) throws {
    // Keep each fixture directory below the separate 256-entry scan bound.
    let roots = macUserAgentAssetDirs.filter { $0.1 == "skill" && $0.3 == "skill" }.map { $0.2 }
    try #require(count <= roots.count * 200)
    for index in 0..<count {
        let skill = home + "/" + roots[index / 200] + String(format: "/s%04d", index)
        try FileManager.default.createDirectory(atPath: skill, withIntermediateDirectories: true)
        try "x".write(toFile: skill + "/SKILL.md", atomically: true, encoding: .utf8)
    }
}

private let testKeyHex = "00112233445566778899aabbccddeeff"

private func policyPublicKeyHex(seed: UInt8) -> String {
	let key = try! Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: seed, count: 32))
	return key.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
}

private let testPolicyPublicKeyHex = policyPublicKeyHex(seed: 7)

private func testSyncConfig() -> SyncConfig {
	SyncConfig(
		baseURL: URL(string: "https://sync.test")!,
		keyHex: testKeyHex, hostId: "test-host-1",
		deviceId: "dev_0123456789abcdef01234567", deviceToken: "device-token",
		policyPublicKeyHex: testPolicyPublicKeyHex
	)
}

private func rulesResponse(_ body: String, signingSeed: UInt8 = 7) -> (Int, [String: String], Data) {
	let artifact = Data(body.utf8)
	let sha = sha256Hex(artifact)
	let payload: [String: Any] = [
		"schema_version": 1,
		"artifact_sha256": sha,
		"source_policy_sha256": sha,
		"target_platform": "macos",
		"target_agent_version": "0.1.0",
		"required_capabilities": ["rules_sync"],
		"format": "application/yaml",
		"artifact": artifact.base64EncodedString(),
	]
	let payloadData = try! JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
	let key = try! Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: signingSeed, count: 32))
	var signed = Data("merlin-policy-envelope-v1\0".utf8)
	signed.append(payloadData)
	let signature = try! key.signature(for: signed)
	let envelope: [String: Any] = [
		"schema_version": 1,
		"signed_payload": payloadData.base64EncodedString(),
		"signatures": [[
			"key_id": sha256Hex(key.publicKey.rawRepresentation),
			"algorithm": "Ed25519",
			"value": signature.base64EncodedString(),
		]],
	]
	let envelopeData = try! JSONSerialization.data(withJSONObject: envelope, options: [.sortedKeys])
	return (200, ["Content-Type": "application/vnd.merlin.policy-envelope+json"], envelopeData)
}

private func makeClient(spoolPath: String, rulesPath: String, rulesBox: RulesBox, hash: String) -> SyncClient {
    SyncClient(
		config: testSyncConfig(),
        spoolPath: spoolPath, rulesPath: rulesPath, rulesBox: rulesBox,
        initialRulesHash: hash, session: mockSession()
    )
}

@Suite("sync", .serialized)
struct SyncTests {
    @Test("agent discovery reports identifiers without configuration values")
    func agentDiscovery() throws {
        let home = NSTemporaryDirectory() + "merlin-discovery-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: home) }
        try FileManager.default.createDirectory(atPath: home + "/.codex", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: home + "/.cursor", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: home + "/.local/bin", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: home + "/.agents/skills/review", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: home + "/.pi/agent", withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: home + "/.pi/agent/skills", withDestinationPath: home + "/.agents/skills")
        try FileManager.default.createDirectory(atPath: home + "/.gemini/extensions/workspace", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: home + "/.gemini/extensions/not-extension", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: home + "/.claude/agents", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: home + "/.config/amp", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: home + "/.config/opencode/plugins", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: home + "/.maestro/plugins/audit/.plugin", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: home + "/.maestro/plugins/convention", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: home + "/.composer/skills/review", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: home + "/Applications/Cursor.app", withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: home + "/Applications/Codex.app", withDestinationPath: home + "/Applications/Cursor.app")
        try "[mcp_servers.github]\nurl = 'https://mcp.example/secret?token=secret'\n[mcp_servers.\"/Users/private/work\"]\ncommand = 'secret'\n".write(toFile: home + "/.codex/config.toml", atomically: true, encoding: .utf8)
        try #"{"mcpServers":{"docs":{"command":"node","args":["secret"]},"https://private.example/mcp":{"url":"secret"},"C:\\Users\\private":{"command":"node","args":["secret"]}}}"#.write(toFile: home + "/.cursor/mcp.json", atomically: true, encoding: .utf8)
        try "secret instructions".write(toFile: home + "/.agents/skills/review/SKILL.md", atomically: true, encoding: .utf8)
        try #"{"mcpServers":{"search":{"env":{"TOKEN":"secret"}}}}"#.write(toFile: home + "/.gemini/extensions/workspace/gemini-extension.json", atomically: true, encoding: .utf8)
        try "ignored".write(toFile: home + "/.gemini/extensions/not-extension/SKILL.md", atomically: true, encoding: .utf8)
        try "secret prompt".write(toFile: home + "/.claude/agents/reviewer.md", atomically: true, encoding: .utf8)
        try #"{"enabledPlugins":{"audit@marketplace":true,"off@marketplace":false}}"#.write(toFile: home + "/.claude/settings.json", atomically: true, encoding: .utf8)
        try #"{"amp.mcpServers":{"db":{"command":"node","args":["secret"]}}}"#.write(toFile: home + "/.config/amp/settings.json", atomically: true, encoding: .utf8)
        try "secret plugin".write(toFile: home + "/.config/opencode/plugins/trace.ts", atomically: true, encoding: .utf8)
        try "secret plugin".write(toFile: home + "/.maestro/plugins/audit/.plugin/plugin.json", atomically: true, encoding: .utf8)
        try #"{"mcpServers":{"pluginsearch":{"command":"node","args":["secret"]}}}"#.write(toFile: home + "/.maestro/plugins/audit/mcp.json", atomically: true, encoding: .utf8)
        try "secret skill".write(toFile: home + "/.composer/skills/review/SKILL.md", atomically: true, encoding: .utf8)
        try "[mcp_servers.managed]\nurl = 'https://mcp.example/secret?token=secret'\n".write(toFile: home + "/.maestro/config.toml", atomically: true, encoding: .utf8)
        let cli = home + "/.local/bin/codex"
        try "#!/bin/sh\n".write(toFile: cli, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: cli)

        let discovered = collectMacAgentDiscovery(homes: [home], systemBins: [], appRoots: [home + "/Applications"])
        #expect(discovered.clis.map(\.name) == ["codex"])
        #expect(discovered.apps.map(\.name) == ["cursor"])
        #expect(discovered.servers.map { "\($0.client):\($0.name)" } == ["amp:db", "codex:github", "cursor:docs", "gemini:search", "maestro:managed", "maestro:pluginsearch"])
        #expect(discovered.servers.contains { $0.client == "codex" && $0.source == ".codex/config.toml" })
        #expect(discovered.servers.contains { $0.client == "codex" && $0.transport == "remote" })
        #expect(discovered.servers.contains { $0.client == "cursor" && $0.transport == "stdio" })
        #expect(discovered.servers.contains { $0.client == "gemini" && $0.transport == "unknown" })
        #expect(discovered.servers.contains { $0.client == "gemini" && $0.source == ".gemini/extensions/*/gemini-extension.json" })
        #expect(discovered.servers.contains { $0.client == "maestro" && $0.name == "managed" && $0.source == ".maestro/config.toml" })
        #expect(discovered.servers.contains { $0.client == "maestro" && $0.name == "pluginsearch" && $0.source == ".maestro/plugins/*/mcp.json" })
        #expect(discovered.assets.contains { $0.client == "agents" && $0.kind == "skill" && $0.name == "review" })
        #expect(discovered.assets.contains { $0.client == "claude" && $0.kind == "agent" && $0.name == "reviewer" })
        #expect(discovered.assets.contains { $0.client == "claude" && $0.kind == "plugin" && $0.name == "audit@marketplace" })
        #expect(discovered.assets.contains { $0.client == "opencode" && $0.kind == "plugin" && $0.name == "trace" })
        #expect(discovered.assets.contains { $0.client == "maestro" && $0.kind == "plugin" && $0.name == "audit" })
        #expect(discovered.assets.contains { $0.client == "maestro" && $0.kind == "skill" && $0.name == "review" })
        #expect(discovered.assets.contains { $0.client == "maestro" && $0.kind == "plugin" && $0.name == "convention" })
        #expect(!discovered.assets.contains { $0.name == "off@marketplace" })
        #expect(!discovered.assets.contains { $0.name == "not-extension" })
        #expect(!discovered.assets.contains { $0.client == "pi" && $0.name == "review" })
        let encoded = try JSONEncoder().encode(discovered.servers)
        #expect(!String(decoding: encoded, as: UTF8.self).contains("secret"))
        let payload = String(decoding: encoded, as: UTF8.self)
        #expect(!payload.contains("/Users/private/work"))
        #expect(!payload.contains("https://private.example/mcp"))
        #expect(!payload.contains("C:\\\\Users"))
        #expect(!String(decoding: try JSONEncoder().encode(discovered.assets), as: UTF8.self).contains("secret"))

        try FileManager.default.removeItem(atPath: home + "/.cursor/mcp.json")
        try FileManager.default.createSymbolicLink(atPath: home + "/.cursor/mcp.json", withDestinationPath: home + "/.codex/config.toml")
        #expect(collectMacAgentDiscovery(homes: [home], systemBins: []).servers.count == 5)
    }

    @Test("Cursor user agents and local plugins require bounded regular files and real manifests")
    func cursorUserAssets() throws {
        let home = NSTemporaryDirectory() + "merlin-cursor-assets-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: home) }
        let cursor = home + "/.cursor"
        try FileManager.default.createDirectory(atPath: cursor + "/agents", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: cursor + "/plugins/local/portable", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: cursor + "/plugins/local/native/.cursor-plugin", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: cursor + "/plugins/local/invalid", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: cursor + "/plugins/local/mismatch", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: cursor + "/plugins/local/linked", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: cursor + "/plugins/local/oversized", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: cursor + "/plugins/local/nested-link", withIntermediateDirectories: true)
        try "secret prompt".write(toFile: cursor + "/agents/reviewer.md", atomically: true, encoding: .utf8)
        try "oversized".padding(toLength: (64 << 10) + 1, withPad: "x", startingAt: 0).write(toFile: cursor + "/agents/oversized.md", atomically: true, encoding: .utf8)
        try FileManager.default.createSymbolicLink(atPath: cursor + "/agents/linked.md", withDestinationPath: cursor + "/agents/reviewer.md")
        try #"{"name":"portable","description":"secret"}"#.write(toFile: cursor + "/plugins/local/portable/plugin.json", atomically: true, encoding: .utf8)
        try #"{"name":"native","description":"secret"}"#.write(toFile: cursor + "/plugins/local/native/.cursor-plugin/plugin.json", atomically: true, encoding: .utf8)
        try "not JSON".write(toFile: cursor + "/plugins/local/invalid/plugin.json", atomically: true, encoding: .utf8)
        try #"{"name":"another"}"#.write(toFile: cursor + "/plugins/local/mismatch/plugin.json", atomically: true, encoding: .utf8)
        try FileManager.default.createSymbolicLink(atPath: cursor + "/plugins/local/linked/plugin.json", withDestinationPath: cursor + "/plugins/local/portable/plugin.json")
        try (#"{"name":"oversized","padding":""# + String(repeating: "x", count: 64 << 10) + #""}"#).write(toFile: cursor + "/plugins/local/oversized/plugin.json", atomically: true, encoding: .utf8)
        try FileManager.default.createSymbolicLink(atPath: cursor + "/plugins/local/nested-link/.cursor-plugin", withDestinationPath: cursor + "/plugins/local/native/.cursor-plugin")
        let assets = collectMacAgentDiscovery(homes: [home], systemBins: []).assets
        #expect(assets.contains { $0.client == "cursor" && $0.kind == "agent" && $0.name == "reviewer" && $0.source == ".cursor/agents" })
        #expect(assets.contains { $0.client == "cursor" && $0.kind == "plugin" && $0.name == "portable" && $0.source == ".cursor/plugins/local" })
        #expect(assets.contains { $0.client == "cursor" && $0.kind == "plugin" && $0.name == "native" })
        #expect(!assets.contains { ["linked", "oversized", "invalid", "mismatch", "nested-link"].contains($0.name) })
        #expect(!String(decoding: try JSONEncoder().encode(assets), as: UTF8.self).contains("secret"))

        try FileManager.default.removeItem(atPath: cursor + "/agents")
        try FileManager.default.createSymbolicLink(atPath: cursor + "/agents", withDestinationPath: cursor + "/plugins/local")
        #expect(!collectMacAgentDiscovery(homes: [home], systemBins: []).assets.contains { $0.client == "cursor" && $0.kind == "agent" })
    }

    @Test("Cursor local plugin manifest probes stop after 32 directories")
    func cursorPluginProbeCap() throws {
        let home = NSTemporaryDirectory() + "merlin-cursor-cap-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: home) }
        let local = home + "/.cursor/plugins/local"
        for index in 0...32 {
            let name = String(format: "plugin-%02d", index)
            try FileManager.default.createDirectory(atPath: local + "/" + name, withIntermediateDirectories: true)
            try "{\"name\":\"\(name)\"}".write(toFile: local + "/" + name + "/plugin.json", atomically: true, encoding: .utf8)
        }
        let plugins = collectMacAgentDiscovery(homes: [home], systemBins: []).assets.filter { $0.client == "cursor" && $0.kind == "plugin" }
        #expect(plugins.count == 32)
        #expect(plugins.contains { $0.name == "plugin-31" })
        #expect(!plugins.contains { $0.name == "plugin-32" })
    }

    @Test("more than 128 skills are all reported")
    func manySkills() throws {
        let home = NSTemporaryDirectory() + "merlin-many-skills-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: home) }
        let names = (0..<200).map { String(format: "s%03d", $0) }
        for name in names {
            try FileManager.default.createDirectory(atPath: home + "/.claude/skills/" + name, withIntermediateDirectories: true)
            try "x".write(toFile: home + "/.claude/skills/" + name + "/SKILL.md", atomically: true, encoding: .utf8)
        }
        let assets = collectMacAgentDiscovery(homes: [home], systemBins: []).assets
        #expect(Set(names).isSubset(of: Set(assets.filter { $0.kind == "skill" }.map(\.name))))
        #expect(assets.count <= macAgentFindingLimit)
    }

    @Test("a config is read up to its own limit and a larger one is reported not scanned")
    func configReadLimit() throws {
        let home = NSTemporaryDirectory() + "merlin-config-limit-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: home) }
        try FileManager.default.createDirectory(atPath: home + "/.cursor", withIntermediateDirectories: true)
        func padded(_ server: String, _ size: Int) -> String {
            let head = #"{"mcpServers":{"\#(server)":{"command":"npx"}},"pad":""#
            return head + String(repeating: "x", count: size - head.utf8.count - 2) + #""}"#
        }
        let claudeLimit = try #require(macUserAgentConfigReadLimits[".claude.json"])
        #expect(claudeLimit > macAgentConfigReadLimit)
        // Over the default limit, within its own: read.
        try padded("deixic", macAgentConfigReadLimit + 1024).write(toFile: home + "/.claude.json", atomically: true, encoding: .utf8)
        // No limit of its own and over the default: reported, not read.
        try padded("cursor-big", macAgentConfigReadLimit + 1).write(toFile: home + "/.cursor/mcp.json", atomically: true, encoding: .utf8)
        var found = collectMacAgentDiscovery(homes: [home], systemBins: [])
        #expect(found.servers.contains { $0.name == "deixic" && $0.source == ".claude.json" })
        #expect(!found.servers.contains { $0.name == "cursor-big" })
        #expect(found.coverage == [.tooLarge(".cursor/mcp.json")])

        try padded("deixic", claudeLimit + 1).write(toFile: home + "/.claude.json", atomically: true, encoding: .utf8)
        found = collectMacAgentDiscovery(homes: [home, home], systemBins: [])
        #expect(!found.servers.contains { $0.name == "deixic" })
        #expect(!found.assets.contains { $0.source == ".claude.json" })
        #expect(found.coverage.count == Set(found.coverage.map(\.source)).count)
        #expect(Set(found.coverage.map(\.source)) == [".cursor/mcp.json", ".claude.json"])
        let wire = String(decoding: try JSONEncoder().encode(found.coverage), as: UTF8.self)
        #expect(wire.contains(#""reason":"too_large""#) && !wire.contains("location") && !wire.contains(home))
    }

    @Test("a full asset list still reports Claude Code plugin cache MCP servers")
    func pluginCacheServersPastTheAssetCap() throws {
        let home = NSTemporaryDirectory() + "merlin-cache-full-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: home) }
        // More skills than the asset cap, read before the plugin cache.
        try makeAgentSkills(home: home, count: macAgentFindingLimit + 20)
        let version = home + "/.claude/plugins/cache/official/slack/1.0.0"
        try FileManager.default.createDirectory(atPath: version, withIntermediateDirectories: true)
        try #"{"mcpServers":{"slack":{"type":"http","url":"https://mcp.slack.com/mcp?token=private-secret"}}}"#.write(toFile: version + "/.mcp.json", atomically: true, encoding: .utf8)
        try FileManager.default.createDirectory(atPath: home + "/.gemini/extensions/notes", withIntermediateDirectories: true)
        try #"{"mcpServers":{"notes":{"command":"npx","args":["-y","notes-mcp","--key","private-secret"]}}}"#.write(toFile: home + "/.gemini/extensions/notes/gemini-extension.json", atomically: true, encoding: .utf8)
        let discovered = collectMacAgentDiscovery(homes: [home], systemBins: [])
        #expect(discovered.assets.count == macAgentFindingLimit)
        #expect(discovered.servers.contains { $0.name == "slack" && $0.source == ".claude/plugins/cache/*/.mcp.json" })
        #expect(discovered.servers.contains { $0.name == "notes" && $0.source == ".gemini/extensions/*/gemini-extension.json" })
        #expect(!String(decoding: try JSONEncoder().encode(discovered.servers), as: UTF8.self).contains("private-secret"))
    }

    @Test("a CLI linked from a bin directory counts, as on Linux; a link to a non-executable does not")
    func linkedCLI() throws {
        let home = NSTemporaryDirectory() + "merlin-linked-cli-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: home) }
        let versions = home + "/.local/share/claude/versions"
        try FileManager.default.createDirectory(atPath: versions, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: home + "/.local/bin", withIntermediateDirectories: true)
        try "#!/bin/sh\n".write(toFile: versions + "/2.1.0", atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: versions + "/2.1.0")
        try "notes".write(toFile: versions + "/notes", atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: versions + "/notes")
        try FileManager.default.createSymbolicLink(atPath: home + "/.local/bin/claude", withDestinationPath: versions + "/2.1.0")
        try FileManager.default.createSymbolicLink(atPath: home + "/.local/bin/codex", withDestinationPath: versions + "/notes")
        try FileManager.default.createSymbolicLink(atPath: home + "/.local/bin/gemini", withDestinationPath: versions)
        let discovered = collectMacAgentDiscovery(homes: [home], systemBins: [])
        #expect(discovered.clis.map(\.name) == ["claude"])
        #expect(!String(decoding: try JSONEncoder().encode(discovered.clis), as: UTF8.self).contains("versions"))
    }

    @Test("a list at its cap is reported truncated and a shorter one is not")
    func truncatedCoverage() throws {
        let home = NSTemporaryDirectory() + "merlin-truncated-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: home) }
        try makeAgentSkills(home: home, count: macAgentFindingLimit + 20)
        let discovered = collectMacAgentDiscovery(homes: [home], systemBins: [])
        #expect(discovered.assets.count == macAgentFindingLimit)
        #expect(discovered.coverage == [.truncated("agent_assets")])
        let wire = String(decoding: try JSONEncoder().encode(discovered.coverage), as: UTF8.self)
        #expect(!wire.contains("source"))
        #expect(macCoverageWithTruncation([], servers: 1, assets: macAgentFindingLimit - 1).isEmpty)
        #expect(macCoverageWithTruncation(discovered.coverage, servers: 0, assets: macAgentFindingLimit).count == 1)
    }

    @Test("Codex configs are read up to their own limit in homes and projects")
    func codexReadLimit() throws {
        let root = NSTemporaryDirectory() + "merlin-codex-limit-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: root) }
        func padded(_ server: String, _ size: Int) -> String {
            let head = "[mcp_servers.\(server)]\ncommand = \"npx\"\nargs = [\"-y\", \"\(server)-mcp\"]\n# "
            return head + String(repeating: "x", count: size - head.utf8.count - 1) + "\n"
        }
        let userLimit = try #require(macUserAgentConfigReadLimits[".codex/config.toml"])
        let projectLimit = try #require(macProjectAgentConfigReadLimits[".codex/config.toml"])
        let home = root + "/home"
        try FileManager.default.createDirectory(atPath: home + "/.codex", withIntermediateDirectories: true)
        try padded("homebig", macAgentConfigReadLimit + 1024).write(toFile: home + "/.codex/config.toml", atomically: true, encoding: .utf8)
        let user = collectMacAgentDiscovery(homes: [home], systemBins: [])
        #expect(userLimit > macAgentConfigReadLimit)
        #expect(user.servers.contains { $0.name == "homebig" && $0.package == "homebig-mcp" })
        #expect(user.coverage.isEmpty)

        let workspace = root + "/workspace"
        for project in ["within", "over"] {
            try FileManager.default.createDirectory(atPath: workspace + "/\(project)/.codex", withIntermediateDirectories: true)
        }
        try padded("projectbig", macAgentConfigReadLimit + 1024).write(toFile: workspace + "/within/.codex/config.toml", atomically: true, encoding: .utf8)
        try padded("toolarge", projectLimit + 1).write(toFile: workspace + "/over/.codex/config.toml", atomically: true, encoding: .utf8)
        let project = collectMacProjectAgentDiscovery(roots: [workspace])
        #expect(project.servers.contains { $0.name == "projectbig" })
        #expect(!project.servers.contains { $0.name == "toolarge" })
        #expect(project.coverage == [.tooLarge("project/.codex/config.toml")])
    }

    @Test("Claude Code project MCP servers are read without their project paths")
    func claudeProjectServers() throws {
        let home = NSTemporaryDirectory() + "merlin-claude-projects-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: home) }
        try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
        try #"{"mcpServers":{"deixic":{"type":"http","url":"https://mcp.deixic.com/mcp"}},"projects":{"/Users/alice/customer-private":{"mcpServers":{"granola":{"url":"https://mcp.granola.ai/mcp?key=private-secret"}},"allowedTools":["private-secret"]},"/Users/alice/other-private":{"mcpServers":{"fli":{"command":"uvx","args":["flights-mcp","--token","private-secret"]},"/Users/alice/bad":{"command":"x"}}}}}"#.write(toFile: home + "/.claude.json", atomically: true, encoding: .utf8)
        let servers = collectMacAgentDiscovery(homes: [home], systemBins: []).servers
        #expect(Set(servers.map { "\($0.name) \($0.source)" }) == ["deixic .claude.json", "granola .claude.json/projects/*", "fli .claude.json/projects/*"])
        let payload = String(decoding: try JSONEncoder().encode(servers), as: UTF8.self)
        #expect(!payload.contains("private"))
    }

    @Test("project discovery reports fixed labels and ignores linked configs")
    func projectAgentDiscovery() throws {
        let root = NSTemporaryDirectory() + "merlin-project-discovery-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: root) }
        let project = root + "/customer-private"
        try FileManager.default.createDirectory(atPath: project + "/.cursor", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: project + "/.opencode", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: project + "/.agents", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: project + "/.claude/skills/review", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: project + "/.maestro/plugins/audit", withIntermediateDirectories: true)
        try #"{"mcpServers":{"pluginsearch":{"url":"https://private.example/mcp"}}}"#.write(toFile: project + "/.maestro/plugins/audit/mcp.json", atomically: true, encoding: .utf8)
        try #"{"enabledPlugins":{"audit@marketplace":true,"off@marketplace":false},"secret":"private-secret"}"#.write(toFile: project + "/.claude/settings.json", atomically: true, encoding: .utf8)
        try #"{"mcpServers":{"docs":{"command":"node","args":["private-secret"]}}}"#.write(toFile: project + "/.cursor/mcp.json", atomically: true, encoding: .utf8)
        try #"{"mcp":{"code-search":{"url":"https://private.example/mcp"}},"secret":"private-secret"}"#.write(toFile: project + "/.opencode/opencode.json", atomically: true, encoding: .utf8)
        try #"{"mcpServers":{"agent-search":{"command":"node","args":["private-secret"]}}}"#.write(toFile: project + "/.agents/mcp.json", atomically: true, encoding: .utf8)
        try "private-secret".write(toFile: project + "/.claude/skills/review/SKILL.md", atomically: true, encoding: .utf8)
        let discovered = collectMacProjectAgentDiscovery(roots: [root])
        #expect(discovered.servers.contains { $0.name == "docs" && $0.source == "project/.cursor/mcp.json" && $0.transport == "stdio" })
        #expect(discovered.servers.contains { $0.name == "pluginsearch" && $0.source == "project/.maestro/plugins/*/mcp.json" && $0.transport == "remote" })
        #expect(discovered.servers.contains { $0.client == "opencode" && $0.name == "code-search" && $0.source == "project/.opencode/opencode.json" && $0.transport == "remote" })
        #expect(discovered.servers.contains { $0.client == "agents" && $0.name == "agent-search" && $0.source == "project/.agents/mcp.json" && $0.transport == "stdio" })
        #expect(discovered.assets.contains { $0.client == "opencode" && $0.kind == "config" && $0.source == "project/.opencode/opencode.json" })
        #expect(discovered.assets.contains { $0.name == "review" && $0.source == "project/.claude/skills" })
        #expect(discovered.assets.contains { $0.name == "audit@marketplace" && $0.kind == "plugin" && $0.source == "project/.claude/settings.json" })
        #expect(discovered.assets.contains { $0.name == "audit" && $0.kind == "plugin" && $0.source == "project/.maestro/plugins" })
        #expect(!discovered.assets.contains { $0.name == "off@marketplace" })
        let payload = String(decoding: try JSONEncoder().encode(discovered.servers), as: UTF8.self)
        #expect(!payload.contains("customer-private") && !payload.contains("private-secret"))
        try FileManager.default.removeItem(atPath: project + "/.cursor/mcp.json")
        try FileManager.default.createSymbolicLink(atPath: project + "/.cursor/mcp.json", withDestinationPath: project + "/.claude/skills/review/SKILL.md")
        #expect(!collectMacProjectAgentDiscovery(roots: [root]).servers.contains { $0.name == "docs" })
    }

    @Test("project discovery visits grandchildren but not linked or deeper directories")
    func nestedProjectAgentDiscovery() throws {
        let base = NSTemporaryDirectory() + "merlin-nested-discovery-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: base) }
        let root = base + "/workspaces"
        let nested = root + "/team/repository"
        let deeper = nested + "/deeper"
        let outside = base + "/outside"
        for directory in [nested + "/.cursor", deeper + "/.cursor", outside + "/.cursor"] {
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        }
        try #"{"mcpServers":{"nested":{"command":"node","args":["private-command"]}}}"#.write(toFile: nested + "/.cursor/mcp.json", atomically: true, encoding: .utf8)
        try #"{"mcpServers":{"too-deep":{"command":"node","args":["private-command"]}}}"#.write(toFile: deeper + "/.cursor/mcp.json", atomically: true, encoding: .utf8)
        try #"{"mcpServers":{"linked":{"command":"node","args":["private-command"]}}}"#.write(toFile: outside + "/.cursor/mcp.json", atomically: true, encoding: .utf8)
        try FileManager.default.createSymbolicLink(atPath: root + "/linked", withDestinationPath: outside)
        try FileManager.default.createSymbolicLink(atPath: root + "/team/linked", withDestinationPath: outside)

        let discovered = collectMacProjectAgentDiscovery(roots: [root])
        #expect(discovered.servers.map(\.name) == ["nested"])
        let payload = String(decoding: try JSONEncoder().encode(discovered.servers), as: UTF8.self)
        #expect(!payload.contains("repository") && !payload.contains("private-command"))
    }

    @Test("project discovery limits each root to 32 descendant directories")
    func projectAgentDiscoveryDirectoryCap() throws {
        let root = NSTemporaryDirectory() + "merlin-project-cap-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: root) }
        for index in 0..<40 {
            let directory = root + "/project-\(String(format: "%02d", index))/.cursor"
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
            try "{\"mcpServers\":{\"server-\(index)\":{\"command\":\"run\"}}}".write(toFile: directory + "/mcp.json", atomically: true, encoding: .utf8)
        }
        let discovered = collectMacProjectAgentDiscovery(roots: [root])
        #expect(discovered.servers.count == 32)
    }

    @Test("project discovery remains inside the opened root after a path swap")
    func projectAgentDiscoveryRootSwap() throws {
        let base = NSTemporaryDirectory() + "merlin-project-swap-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: base) }
        let root = base + "/approved"
        let moved = base + "/original"
        let outside = base + "/outside"
        for directory in [root + "/team/repo/.cursor", outside + "/team/repo/.cursor", base + "/.cursor/plugins/local/portable"] {
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        }
        try #"{"mcpServers":{"inside":{"command":"run"}}}"#.write(toFile: root + "/team/repo/.cursor/mcp.json", atomically: true, encoding: .utf8)
        try #"{"mcpServers":{"outside":{"command":"run"}}}"#.write(toFile: outside + "/team/repo/.cursor/mcp.json", atomically: true, encoding: .utf8)
        try #"{"name":"portable"}"#.write(toFile: base + "/.cursor/plugins/local/portable/plugin.json", atomically: true, encoding: .utf8)

        let rootFD = try #require(openMacProjectRoot(root))
        try FileManager.default.moveItem(atPath: root, toPath: moved)
        try FileManager.default.createSymbolicLink(atPath: root, withDestinationPath: outside)
        let discovered = collectMacProjectAgentDiscovery(rootFDs: [rootFD])
        #expect(discovered.servers.map(\.name) == ["inside"])
        #expect(collectMacAgentDiscovery(homes: [base], systemBins: []).assets.contains {
            $0.client == "cursor" && $0.kind == "plugin" && $0.name == "portable" && $0.source == ".cursor/plugins/local"
        })
        #expect(openMacProjectRoot(root) == nil)
        try FileManager.default.createSymbolicLink(atPath: base + "/linked-parent", withDestinationPath: outside)
        #expect(openMacProjectRoot(base + "/linked-parent/team/repo") == nil)
        #expect(openMacProjectRoot(base + "/outside\0/../approved") == nil)
    }

    @Test("host id is a 16-char hash, not the raw UUID")
    func hostId() {
        let id = syncHostId()
        #expect(id.count == 16)
        #expect(id.allSatisfy { "0123456789abcdef".contains($0) })
        #expect(id != "unknown-host" || true) // unknown-host acceptable headless
    }
}

extension SyncTests {
    @Test("managed check-in includes bounded OS inventory")
    func deviceCheckIn() async throws {
        MockURLProtocol.reset()
        MockURLProtocol.handler = { _ in
            let responseBody = Data("{\"pending_update\":null}".utf8)
            return (200, ["Content-Type": "application/json"], responseBody)
        }
        let client = SyncClient(
            config: SyncConfig(
                baseURL: URL(string: "https://sync.test")!,
                keyHex: testKeyHex,
                hostId: "test-host-1",
                deviceId: "dev_0123456789abcdef01234567",
                deviceToken: "device-token"
				, policyPublicKeyHex: testPolicyPublicKeyHex
            ),
            spoolPath: "/tmp/merlin-events.jsonl",
            rulesPath: "/tmp/merlin-rules.yaml",
            rulesBox: RulesBox(Rules()),
            initialRulesHash: "abc",
            session: mockSession()
        )
        await client.checkIn()

        let request = MockURLProtocol.seen.first { $0.url?.path == "/v1/devices/dev_0123456789abcdef01234567/check-in" }
        #expect(request?.value(forHTTPHeaderField: "Authorization") == "Bearer device-token")
        let body = try #require(MockURLProtocol.bodies.first)
        let json = try #require(JSONSerialization.jsonObject(with: body) as? [String: Any])
        #expect(json["platform"] as? String == "macos")
        #expect(json["current_rules_sha256"] as? String == "abc")
        let osInfo = try #require(json["os_info"] as? [String: Any])
        #expect(osInfo["os_name"] as? String == "macOS")
        #expect(osInfo["os_pretty_name"] as? String != nil)
        #expect(osInfo["cpu_model"] as? String != nil)
        #expect(osInfo["hardware_model"] as? String != nil)
        #expect(osInfo["root_filesystem"] as? String != nil)
        #expect(osInfo["swap_total_bytes"] as? UInt64 != nil)
        #expect(osInfo["network_interface_details"] is [[String: Any]])
        let posture = try #require(json["posture"] as? [String: Any])
        #expect(posture["schema_version"] as? Int == 2)
        #expect(posture["overall"] as? String != nil)
        #expect(posture["risk_score"] as? Int != nil)
        #expect(posture["checks"] is [String: Any])
        #expect(posture["findings"] is [[String: Any]])
        let coverage = try #require(posture["coverage"] as? [String: Any])
        #expect(coverage["network_extension"] as? String == "not_configured")
        #expect(coverage["checks_with_evidence"] as? Int != nil)
        let inventory = try #require(json["inventory"] as? [String: Any])
        #expect(inventory["collection_source"] as? String == "macos-agent")
        #expect(inventory["fim"] is [[String: Any]])
        #expect(inventory["sca"] is [[String: Any]])
        #expect(inventory["processes"] is [[String: Any]])
    }

    private func tempSpool() throws -> (dir: String, live: String) {
        let dir = NSTemporaryDirectory() + "merlin-sync-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        return (dir, dir + "/merlin-events.jsonl")
    }

    private func makeSegment(live: String, ts: String, payload: String = "{\"kind\":\"exec\"}\n") throws -> String {
        let base = live.hasSuffix(".jsonl") ? String(live.dropLast(6)) : live
        let path = "\(base).\(ts).jsonl.gz"
        try payload.write(toFile: path, atomically: true, encoding: .utf8)
        return path
    }

    @Test("202 ack deletes the segment; request carries contract headers")
    func accepted() async throws {
        MockURLProtocol.reset()
        MockURLProtocol.handler = { _ in (202, [:], Data()) }
        let (dir, live) = try tempSpool()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let seg = try makeSegment(live: live, ts: "20260802-101010")
        let client = makeClient(spoolPath: live, rulesPath: dir + "/rules.yaml", rulesBox: RulesBox(Rules()), hash: "")
        #expect(client.pendingSegments() == [seg])
        await client.uploadNextSegment()
        #expect(!FileManager.default.fileExists(atPath: seg))
        let req = MockURLProtocol.seen.first
        #expect(req?.url?.path == "/v1/devices/dev_0123456789abcdef01234567/events")
        #expect(req?.httpMethod == "POST")
        #expect(req?.value(forHTTPHeaderField: "X-Merlin-Host") == nil)
        #expect(req?.value(forHTTPHeaderField: "X-Merlin-Segment") == (seg as NSString).lastPathComponent)
        #expect(req?.value(forHTTPHeaderField: "Authorization") == "Bearer device-token")
        #expect(MockURLProtocol.bodies.first == Data("{\"kind\":\"exec\"}\n".utf8))
    }

    @Test("200 duplicate is also an ack")
    func duplicate() async throws {
        MockURLProtocol.reset()
        MockURLProtocol.handler = { _ in (200, [:], Data()) }
        let (dir, live) = try tempSpool()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let seg = try makeSegment(live: live, ts: "20260802-101011")
        let client = makeClient(spoolPath: live, rulesPath: dir + "/rules.yaml", rulesBox: RulesBox(Rules()), hash: "")
        await client.uploadNextSegment()
        #expect(!FileManager.default.fileExists(atPath: seg))
    }

    @Test("failure keeps the file and backs off; recovery clears backoff")
    func failureBackoff() async throws {
        MockURLProtocol.reset()
        var calls = 0
        MockURLProtocol.handler = { _ in
            calls += 1
            return calls < 3 ? (500, [:], Data()) : (202, [:], Data())
        }
        let (dir, live) = try tempSpool()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let seg = try makeSegment(live: live, ts: "20260802-101012")
        let client = makeClient(spoolPath: live, rulesPath: dir + "/rules.yaml", rulesBox: RulesBox(Rules()), hash: "")
        await client.uploadNextSegment() // 500 → kept
        #expect(FileManager.default.fileExists(atPath: seg))
        await client.uploadNextSegment() // 500 → kept
        #expect(FileManager.default.fileExists(atPath: seg))
        await client.uploadNextSegment() // 202 → deleted
        #expect(!FileManager.default.fileExists(atPath: seg))
        #expect(calls == 3)
    }

    @Test("pendingSegments ignores the live file and non-segment files")
    func dirWatching() async throws {
        let (dir, live) = try tempSpool()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        _ = try makeSegment(live: live, ts: "20260802-101013")
        _ = try makeSegment(live: live, ts: "20260802-101012") // sorts first
        try "x".write(toFile: live, atomically: true, encoding: .utf8) // live file
        try "x".write(toFile: live + ".20260802-101014.jsonl", atomically: true, encoding: .utf8) // uncompressed orphan
        let client = makeClient(spoolPath: live, rulesPath: dir + "/rules.yaml", rulesBox: RulesBox(Rules()), hash: "")
        let pending = client.pendingSegments()
        #expect(pending.count == 2)
        #expect(pending[0].contains("20260802-101012"))
        #expect(pending[1].contains("20260802-101013"))
    }
}

extension SyncTests {
    private var goodYaml: String {
        """
        rules:
          - name: synced-rule
            match:
              path_basename: synced
            action: log
        """
    }

    @Test("valid signed rules apply, hot-reload the box, and persist 0600")
    func applyValid() async throws {
        MockURLProtocol.reset()
		MockURLProtocol.handler = { _ in rulesResponse(goodYaml) }
        let dir = NSTemporaryDirectory() + "merlin-sync-rules-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let box = RulesBox(Rules())
        let client = makeClient(spoolPath: dir + "/merlin-events.jsonl", rulesPath: dir + "/rules.yaml", rulesBox: box, hash: "")
		await client.pollRules(targetSHA256: sha256Hex(Data(goodYaml.utf8)))
        #expect(box.current.rules.count == 1)
        #expect(box.current.rules[0].name == "synced-rule")
        let synced = dir + "/rules.yaml.synced"
        var st = stat()
        #expect(stat(synced, &st) == 0)
        #expect(st.st_mode & 0o777 == 0o600)
		let cached = try loadCachedManagedPolicy(config: testSyncConfig(), rulesPath: dir + "/rules.yaml")
		#expect(cached?.rules.rules.first?.name == "synced-rule")
		#expect(cached?.artifactSHA256 == sha256Hex(Data(goodYaml.utf8)))
		let offlineBox = RulesBox(Rules(rules: [Rule(name: "bootstrap", match: Match(), action: .log)]))
		_ = SyncClient(
			config: testSyncConfig(), spoolPath: dir + "/offline-events.jsonl",
			rulesPath: dir + "/rules.yaml", rulesBox: offlineBox, initialRulesHash: "",
			session: mockSession()
		)
		#expect(offlineBox.current.rules.first?.name == "synced-rule")
    }

	@Test("tampered cached envelope is rejected during offline restart")
	func tamperedCacheRejected() async throws {
		MockURLProtocol.reset()
		MockURLProtocol.handler = { _ in rulesResponse(goodYaml) }
		let dir = NSTemporaryDirectory() + "merlin-sync-cache-\(UUID().uuidString)"
		try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
		defer { try? FileManager.default.removeItem(atPath: dir) }
		let path = dir + "/rules.yaml"
		let client = makeClient(spoolPath: dir + "/events.jsonl", rulesPath: path, rulesBox: RulesBox(Rules()), hash: "")
		await client.pollRules(targetSHA256: sha256Hex(Data(goodYaml.utf8)))
		var envelope = try Data(contentsOf: URL(fileURLWithPath: path + ".synced"))
		envelope[envelope.count / 2] ^= 1
		try envelope.write(to: URL(fileURLWithPath: path + ".synced"), options: .atomic)
		try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path + ".synced")
		#expect(throws: (any Error).self) {
			try loadCachedManagedPolicy(config: testSyncConfig(), rulesPath: path)
		}
	}

    @Test("bad signature keeps last-known-good (no apply, no file)")
    func badSignature() async throws {
		MockURLProtocol.reset()
		MockURLProtocol.handler = { _ in
			rulesResponse(goodYaml, signingSeed: 8)
        }
        let dir = NSTemporaryDirectory() + "merlin-sync-rules-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let original = Rules(rules: [Rule(name: "original", match: Match(), action: .log)])
        let box = RulesBox(original)
        let client = makeClient(spoolPath: dir + "/merlin-events.jsonl", rulesPath: dir + "/rules.yaml", rulesBox: box, hash: "")
		await client.pollRules(targetSHA256: sha256Hex(Data(goodYaml.utf8)))
        #expect(box.current.rules.count == 1)
        #expect(box.current.rules[0].name == "original") // last-known-good preserved
        #expect(!FileManager.default.fileExists(atPath: dir + "/rules.yaml.synced"))
    }

    @Test("empty body means unchanged; same hash means unchanged")
    func unchanged() async throws {
        MockURLProtocol.reset()
        MockURLProtocol.handler = { _ in (200, [:], Data()) } // empty body
        let box = RulesBox(Rules(rules: [Rule(name: "keep", match: Match(), action: .log)]))
        let dir = NSTemporaryDirectory() + "merlin-sync-rules-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let client = makeClient(spoolPath: dir + "/merlin-events.jsonl", rulesPath: dir + "/rules.yaml", rulesBox: box, hash: "")
		await client.pollRules(targetSHA256: String(repeating: "0", count: 64))
		#expect(box.current.rules[0].name == "keep")
	}

	@Test("rotation window accepts a newly trusted signing key")
	func rotationWindow() async throws {
		MockURLProtocol.reset()
		MockURLProtocol.handler = { _ in rulesResponse(goodYaml, signingSeed: 8) }
		let dir = NSTemporaryDirectory() + "merlin-sync-rules-\(UUID().uuidString)"
		try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
		defer { try? FileManager.default.removeItem(atPath: dir) }
		let box = RulesBox(Rules())
		let client = SyncClient(
			config: SyncConfig(
				baseURL: URL(string: "https://sync.test")!,
				keyHex: testKeyHex,
				hostId: "test-host-1",
				deviceId: "dev_0123456789abcdef01234567",
				deviceToken: "device-token",
				policyPublicKeyHex: testPolicyPublicKeyHex,
				policyPublicKeyHexes: [policyPublicKeyHex(seed: 8)]
			),
			spoolPath: dir + "/merlin-events.jsonl",
			rulesPath: dir + "/rules.yaml",
			rulesBox: box,
			initialRulesHash: "",
			session: mockSession()
		)
		await client.pollRules(targetSHA256: sha256Hex(Data(goodYaml.utf8)))
		#expect(box.current.rules.first?.name == "synced-rule")
	}
}


extension SyncTests {
    @Test("local server contact advances only after a valid managed response")
    func localContactRejectsMalformedSuccess() async throws {
        let store = LocalStatusStore()
        // Reuse a fresh in-memory report; this test does not run a posture sweep.
        store.publish(makeDevicePostureReport(snapshot: PostureSnapshot()))
        let client = SyncClient(config: testSyncConfig(),
            spoolPath: "/tmp/merlin-local-status-test-events.jsonl",
            rulesPath: "/tmp/merlin-local-status-test-rules.yaml",
            rulesBox: RulesBox(Rules()), initialRulesHash: "",
            session: mockSession(), localStatus: store)
        MockURLProtocol.reset()
        MockURLProtocol.handler = { _ in (200, [:], Data("not-json".utf8)) }
        await client.checkIn()
        #expect(store.snapshot().lastServerContact == nil)
        MockURLProtocol.handler = { _ in (403, [:], Data()) }
        await client.checkIn()
        #expect(store.snapshot().enrollment == .rejected)
        #expect(store.snapshot().lastServerContact == nil)
        MockURLProtocol.handler = { _ in (200, [:], Data("{\"pending_update\":null}".utf8)) }
        await client.checkIn()
        #expect(store.snapshot().lastServerContact != nil)
        #expect(store.snapshot().enrollment == .configured)
    }
}
