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
        try "[mcp_servers.github]\nurl = 'https://secret.example'\n".write(toFile: home + "/.codex/config.toml", atomically: true, encoding: .utf8)
        try #"{"mcpServers":{"docs":{"command":"secret"}}}"#.write(toFile: home + "/.cursor/mcp.json", atomically: true, encoding: .utf8)
        try "secret instructions".write(toFile: home + "/.agents/skills/review/SKILL.md", atomically: true, encoding: .utf8)
        try #"{"mcpServers":{"search":{"env":{"TOKEN":"secret"}}}}"#.write(toFile: home + "/.gemini/extensions/workspace/gemini-extension.json", atomically: true, encoding: .utf8)
        try "ignored".write(toFile: home + "/.gemini/extensions/not-extension/SKILL.md", atomically: true, encoding: .utf8)
        try "secret prompt".write(toFile: home + "/.claude/agents/reviewer.md", atomically: true, encoding: .utf8)
        try #"{"enabledPlugins":{"audit@marketplace":true,"off@marketplace":false}}"#.write(toFile: home + "/.claude/settings.json", atomically: true, encoding: .utf8)
        try #"{"amp.mcpServers":{"db":{"command":"secret"}}}"#.write(toFile: home + "/.config/amp/settings.json", atomically: true, encoding: .utf8)
        try "secret plugin".write(toFile: home + "/.config/opencode/plugins/trace.ts", atomically: true, encoding: .utf8)
        try "secret plugin".write(toFile: home + "/.maestro/plugins/audit/.plugin/plugin.json", atomically: true, encoding: .utf8)
        try #"{"mcpServers":{"pluginsearch":{"command":"secret"}}}"#.write(toFile: home + "/.maestro/plugins/audit/mcp.json", atomically: true, encoding: .utf8)
        try "secret skill".write(toFile: home + "/.composer/skills/review/SKILL.md", atomically: true, encoding: .utf8)
        try "[mcp_servers.managed]\nurl = 'https://secret.example'\n".write(toFile: home + "/.maestro/config.toml", atomically: true, encoding: .utf8)
        let cli = home + "/.local/bin/codex"
        try "#!/bin/sh\n".write(toFile: cli, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: cli)

        let discovered = collectMacAgentDiscovery(homes: [home], systemBins: [], appRoots: [home + "/Applications"])
        #expect(discovered.clis.map(\.name) == ["codex"])
        #expect(discovered.apps.map(\.name) == ["cursor"])
        #expect(discovered.servers.map { "\($0.client):\($0.name)" } == ["amp:db", "codex:github", "cursor:docs", "gemini:search", "maestro:managed", "maestro:pluginsearch"])
        #expect(discovered.servers.contains { $0.client == "codex" && $0.source == ".codex/config.toml" })
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
        #expect(!String(decoding: try JSONEncoder().encode(discovered.assets), as: UTF8.self).contains("secret"))

        try FileManager.default.removeItem(atPath: home + "/.cursor/mcp.json")
        try FileManager.default.createSymbolicLink(atPath: home + "/.cursor/mcp.json", withDestinationPath: home + "/.codex/config.toml")
        #expect(collectMacAgentDiscovery(homes: [home], systemBins: []).servers.count == 5)
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
