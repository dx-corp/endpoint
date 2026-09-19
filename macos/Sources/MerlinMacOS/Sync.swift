// Sync client — segment upload and rules polling against the fixed
// API contract:
//
//   POST /v1/devices/<id>/events
//                      body: finished .jsonl.gz segment
//                      header: X-Merlin-Segment
//                      Authorization: Bearer <device token>
//                      202 = accepted, 200 = duplicate no-op (both = ack)
//   GET  /v1/devices/<id>/policies/<sha256>
//                      Authorization: Bearer <device token>
//                      immutable YAML assigned by a managed check-in,
//                      signed with the configured Ed25519 policy key
//   GET  /v1/health
//
// Fail-open everywhere (AGENTS.md): sync errors only ever produce log
// lines — collection, the live spool, and the current ruleset are never
// affected by the network.
//
// Host id: SHA-256 of IOPlatformUUID, truncated — a stable pseudonymous
// id; the raw hardware UUID never leaves the machine (documented in
// docs/reference.md).

import CryptoKit
import Foundation
import IOKit

struct SyncConfig: Sendable {
    var baseURL: URL
    var keyHex: String
    var hostId: String
    var deviceId: String? = nil
    var deviceToken: String? = nil
	var policyPublicKeyHex: String? = nil
	var policyPublicKeyHexes: [String] = []

    var keyData: Data? {
        var out = Data()
        var hex = keyHex[...]
        while hex.count >= 2 {
            guard let byte = UInt8(hex.prefix(2), radix: 16) else { return nil }
            out.append(byte)
            hex = hex.dropFirst(2)
        }
        return out.isEmpty ? nil : out
    }

	private func policyKeyData(_ value: String) -> Data? {
		guard value.count == 64 else { return nil }
		var out = Data()
		var hex = value[...]
		while hex.count >= 2 {
			guard let byte = UInt8(hex.prefix(2), radix: 16) else { return nil }
			out.append(byte)
			hex = hex.dropFirst(2)
		}
		return out.count == 32 ? out : nil
	}

	var policyPublicKeyData: Data? {
		guard let value = policyPublicKeyHex else { return nil }
		return policyKeyData(value)
	}

	var policyPublicKeysData: [Data] {
		var keys = policyPublicKeyHexes.compactMap { policyKeyData($0) }
		if let single = policyPublicKeyData { keys.insert(single, at: 0) }
		return keys
	}
}

private let merlinAgentVersion = "0.1.0"
private let policyEnvelopeDomain = Data("merlin-policy-envelope-v1\0".utf8)
private let maxPolicyEnvelopeBytes = 2 << 20

private struct DeviceCheckInRequest: Encodable, Sendable {
    let host: String
    let platform: String
    let agentVersion: String
    let currentRulesSHA256: String
    let status: String
    let capabilities: [String]
    let osInfo: DeviceOSInfo
    let inventory: DeviceInventory
    let posture: DevicePostureReport

    enum CodingKeys: String, CodingKey {
        case host
        case platform
        case agentVersion = "agent_version"
        case currentRulesSHA256 = "current_rules_sha256"
        case status
        case capabilities
        case osInfo = "os_info"
        case inventory
        case posture
    }
}

private struct DeviceCheckInResponse: Decodable, Sendable {
    let pendingUpdate: PendingDeviceUpdate?

    enum CodingKeys: String, CodingKey {
        case pendingUpdate = "pending_update"
    }
}

private struct PendingDeviceUpdate: Decodable, Sendable {
    let updateId: String
    let kind: String
    let targetRulesSHA256: String

    enum CodingKeys: String, CodingKey {
        case updateId = "update_id"
        case kind
        case targetRulesSHA256 = "target_rules_sha256"
    }
}

private struct SignedPolicyEnvelope: Decodable, Sendable {
	let schemaVersion: Int
	let signedPayload: String
	let signatures: [PolicyEnvelopeSignature]

	enum CodingKeys: String, CodingKey {
		case schemaVersion = "schema_version"
		case signedPayload = "signed_payload"
		case signatures
	}
}

private struct PolicyEnvelopeSignature: Decodable, Sendable {
	let keyId: String
	let algorithm: String
	let value: String

	enum CodingKeys: String, CodingKey {
		case keyId = "key_id"
		case algorithm, value
	}
}

private struct PolicyEnvelopePayload: Decodable, Sendable {
	let schemaVersion: Int
	let artifactSHA256: String
	let sourcePolicySHA256: String
	let targetPlatform: String
	let targetAgentVersion: String?
	let requiredCapabilities: [String]?
	let format: String
	let artifact: String

	enum CodingKeys: String, CodingKey {
		case schemaVersion = "schema_version"
		case artifactSHA256 = "artifact_sha256"
		case sourcePolicySHA256 = "source_policy_sha256"
		case targetPlatform = "target_platform"
		case targetAgentVersion = "target_agent_version"
		case requiredCapabilities = "required_capabilities"
		case format, artifact
	}
}

struct VerifiedManagedPolicy: Sendable {
	let rules: Rules
	let artifactSHA256: String
}

private struct DeviceUpdateAck: Encodable, Sendable {
    let status: String
    let rulesSHA256: String

    enum CodingKeys: String, CodingKey {
        case status
        case rulesSHA256 = "rules_sha256"
    }
}

/// sha256(IOPlatformUUID)[:16] — stable across reboots, pseudonymous.
func syncHostId() -> String {
    let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
    defer { IOObjectRelease(service) }
    guard let uuid = IORegistryEntryCreateCFProperty(service, kIOPlatformUUIDKey as CFString, kCFAllocatorDefault, 0)?
        .takeRetainedValue() as? String
    else { return "unknown-host" }
    return SHA256.hash(data: Data(uuid.utf8)).map { String(format: "%02x", $0) }.joined().prefix(16).description
}

func sha256Hex(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

private let supportedPolicyCapabilities: Set<String> = [
	"segment_upload", "rules_sync", "policy_cmdline_regex", "policy_network",
	"policy_signing", "policy_suspend", "endpoint_security_optional", "kqueue_fallback",
	"openbsm_legacy", "persistence_metadata", "bounded_spool", "os_inventory",
	"system_inventory", "file_integrity", "security_configuration_assessment", "rootcheck",
	"posture_reporting", "macos_security_posture", "network_extension_optional",
]

private func policyPublicKeyId(_ data: Data) -> String {
	sha256Hex(data)
}

private func validPolicySHA256(_ value: String) -> Bool {
	value.count == 64 && value.allSatisfy { "0123456789abcdef".contains($0) }
}

private func decodePolicyEnvelope(_ data: Data, targetSHA256: String?, trustedKeyData: [Data]) throws -> (artifact: Data, sha256: String) {
	guard data.count <= maxPolicyEnvelopeBytes else {
		throw MerlinError.plain("policy envelope exceeds the 2 MiB limit")
	}
	let envelope = try JSONDecoder().decode(SignedPolicyEnvelope.self, from: data)
	guard envelope.schemaVersion == 1 else {
		throw MerlinError.plain("unsupported policy envelope schema \(envelope.schemaVersion)")
	}
	guard !envelope.signatures.isEmpty, envelope.signatures.count <= 8,
		  let payloadData = Data(base64Encoded: envelope.signedPayload),
		  payloadData.count <= maxPolicyEnvelopeBytes else {
		throw MerlinError.plain("invalid signed policy envelope")
	}
	var trusted: [String: Curve25519.Signing.PublicKey] = [:]
	for keyData in trustedKeyData {
		guard keyData.count == 32,
			  let key = try? Curve25519.Signing.PublicKey(rawRepresentation: keyData) else {
			throw MerlinError.plain("invalid policy public key")
		}
		trusted[policyPublicKeyId(keyData)] = key
	}
	guard !trusted.isEmpty else { throw MerlinError.plain("no trusted policy public keys configured") }
	var signed = policyEnvelopeDomain
	signed.append(payloadData)
	let verified = envelope.signatures.contains { candidate in
		guard candidate.algorithm == "Ed25519",
			  let key = trusted[candidate.keyId],
			  let signature = Data(base64Encoded: candidate.value) else { return false }
		return key.isValidSignature(signature, for: signed)
	}
	guard verified else { throw MerlinError.plain("no policy envelope signature matched a trusted key") }

	// Decode policy metadata only after the exact payload bytes authenticate.
	let payload = try JSONDecoder().decode(PolicyEnvelopePayload.self, from: payloadData)
	guard payload.schemaVersion == 1,
		  (targetSHA256 == nil || payload.artifactSHA256 == targetSHA256),
		  validPolicySHA256(payload.sourcePolicySHA256),
		  payload.targetPlatform == "macos",
		  payload.targetAgentVersion == nil || payload.targetAgentVersion == merlinAgentVersion,
		  (payload.requiredCapabilities?.count ?? 0) <= 64,
		  (payload.requiredCapabilities ?? []).allSatisfy({ supportedPolicyCapabilities.contains($0) }),
		  payload.format == "application/yaml",
		  let artifact = Data(base64Encoded: payload.artifact),
		  artifact.count <= 1 << 20,
		  sha256Hex(artifact) == payload.artifactSHA256 else {
		throw MerlinError.plain("signed policy payload does not match this assignment")
	}
	return (artifact, payload.artifactSHA256)
}

func loadCachedManagedPolicy(config: SyncConfig, rulesPath: String) throws -> VerifiedManagedPolicy? {
	let path = rulesPath + ".synced"
	guard FileManager.default.fileExists(atPath: path) else { return nil }
	let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
	guard fd >= 0 else { throw MerlinError.plain("opening cached managed policy: errno \(errno)") }
	defer { close(fd) }
	var st = stat()
	guard fstat(fd, &st) == 0,
		  st.st_mode & S_IFMT == S_IFREG,
		  st.st_uid == geteuid(),
		  st.st_mode & 0o077 == 0,
		  st.st_size >= 0,
		  st.st_size <= maxPolicyEnvelopeBytes else {
		throw MerlinError.plain("cached managed policy is not a private bounded regular file")
	}
	var data = Data()
	var buffer = [UInt8](repeating: 0, count: 65_536)
	while data.count <= maxPolicyEnvelopeBytes {
		let count = buffer.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
		if count < 0 { throw MerlinError.plain("reading cached managed policy: errno \(errno)") }
		if count == 0 { break }
		data.append(contentsOf: buffer.prefix(count))
		if data.count > maxPolicyEnvelopeBytes { throw MerlinError.plain("cached managed policy exceeds the 2 MiB limit") }
	}
	let verified = try decodePolicyEnvelope(data, targetSHA256: nil, trustedKeyData: config.policyPublicKeysData)
	guard let text = String(data: verified.artifact, encoding: .utf8) else {
		throw MerlinError.plain("cached managed rules are not UTF-8")
	}
	return VerifiedManagedPolicy(rules: try Rules.parse(text), artifactSHA256: verified.sha256)
}

extension Data {
	init?(hexString: String) {
		guard hexString.count.isMultiple(of: 2) else { return nil }
		var result = Data()
		var rest = hexString[...]
		while !rest.isEmpty {
			guard let byte = UInt8(rest.prefix(2), radix: 16) else { return nil }
			result.append(byte)
			rest = rest.dropFirst(2)
		}
		self = result
	}
}

func syncAuthorizationHeader(keyHex: String) -> String {
    "Bearer " + keyHex.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
}

/// Persist the verified signed envelope before publishing its in-memory rules.
func writeRulesSynced(path: String, contents: Data) throws {
	let directory = (path as NSString).deletingLastPathComponent
	let temporary = (directory as NSString).appendingPathComponent(".\((path as NSString).lastPathComponent).\(UUID().uuidString).tmp")
	let fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
	guard fd >= 0 else {
		throw MerlinError.plain("creating \(temporary): errno \(errno)")
	}
	var published = false
	defer {
		close(fd)
		if !published { unlink(temporary) }
	}
    var st = stat()
    guard fstat(fd, &st) == 0, st.st_mode & S_IFMT == S_IFREG else {
		throw MerlinError.plain("\(temporary) is not a regular file")
    }
    try contents.withUnsafeBytes { raw in
        var written = 0
        while written < raw.count {
            let n = write(fd, raw.baseAddress!.advanced(by: written), raw.count - written)
            guard n > 0 else { throw MerlinError.plain("writing \(path): errno \(errno)") }
            written += n
        }
    }
	guard fsync(fd) == 0, rename(temporary, path) == 0 else {
		throw MerlinError.plain("publishing \(path): errno \(errno)")
	}
	let directoryFD = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
	if directoryFD >= 0 {
		_ = fsync(directoryFD)
		close(directoryFD)
	}
	published = true
}

/// A finished segment awaiting upload: "<base>.<ts>.jsonl.gz".
func isSegmentGzFile(_ name: String, liveName: String) -> Bool {
    let base = liveName.hasSuffix(".jsonl") ? String(liveName.dropLast(6)) : liveName
    guard name.hasPrefix(base + "."), name.hasSuffix(".jsonl.gz") else { return false }
    let mid = name.dropFirst(base.count + 1).dropLast(9)
    guard mid.count == 15, mid[mid.index(mid.startIndex, offsetBy: 8)] == "-" else { return false }
    return mid.allSatisfy { $0.isNumber || $0 == "-" }
}

final class SyncClient: @unchecked Sendable {
    private let config: SyncConfig
    private let spoolPath: String
    private let rulesPath: String
    private let rulesBox: RulesBox
    private let session: URLSession
    private let queue = DispatchQueue(label: "merlin.sync", qos: .utility)
    private var uploadTimer: DispatchSourceTimer?
    private var checkInTimer: DispatchSourceTimer?
    private let lock = NSLock()
    private var currentRulesHash: String
    private var uploadBackoffUntil = Date.distantPast
    private var uploadBackoff: TimeInterval = 1
    private var uploadInFlight = false
    private let postureLock = NSLock()
    private var postureCache: (at: Date, report: DevicePostureReport)?
    private let localStatus: LocalStatusStore?

    init(
        config: SyncConfig,
        spoolPath: String,
        rulesPath: String,
        rulesBox: RulesBox,
        initialRulesHash: String,
        session: URLSession = .shared,
        localStatus: LocalStatusStore? = nil
    ) {
        self.config = config
        self.spoolPath = spoolPath
        self.rulesPath = rulesPath
        self.rulesBox = rulesBox
        currentRulesHash = initialRulesHash
        self.session = session
        self.localStatus = localStatus
        localStatus?.configure(deviceID: config.deviceId)
		do {
			if let cached = try loadCachedManagedPolicy(config: config, rulesPath: rulesPath) {
				rulesBox.update(cached.rules)
				currentRulesHash = cached.artifactSHA256
				merlinLog("info", "sync: loaded verified cached managed policy \(cached.artifactSHA256.prefix(12))…")
			}
		} catch {
			merlinLog("warn", "sync: cached managed policy rejected (\(error)); using bootstrap rules")
		}
    }

    func start() {
        let up = DispatchSource.makeTimerSource(queue: queue)
        up.schedule(deadline: .now() + 2, repeating: 5)
        up.setEventHandler { [weak self] in self?.uploadTick() }
        up.resume()
        uploadTimer = up
        if config.deviceId != nil, config.deviceToken != nil {
            let ci = DispatchSource.makeTimerSource(queue: queue)
            ci.schedule(deadline: .now() + 2, repeating: 60)
            ci.setEventHandler { [weak self] in
                Task { [weak self] in await self?.checkIn() }
            }
            ci.resume()
            checkInTimer = ci
            Task { [weak self] in await self?.checkIn() }
        }
        Task { [weak self] in await self?.healthCheck() }
		merlinLog("info", "sync: uploading segments and accepting assigned policy updates from \(config.baseURL) as \(config.hostId)")
    }

    func stop() {
        uploadTimer?.cancel()
        checkInTimer?.cancel()
        uploadTimer = nil
        checkInTimer = nil
    }

    // MARK: health

    func healthCheck() async {
        guard let url = URL(string: "/v1/health", relativeTo: config.baseURL) else { return }
        do {
            let (_, response) = try await session.data(from: url)
            if let http = response as? HTTPURLResponse, http.statusCode == 200 {
                merlinLog("info", "sync: server health OK")
            } else {
                merlinLog("warn", "sync: /v1/health returned \((response as? HTTPURLResponse)?.statusCode ?? -1)")
            }
        } catch {
            merlinLog("warn", "sync: /v1/health failed (continuing anyway): \(error.localizedDescription)")
        }
    }

    // MARK: segment upload

    /// Finished segments awaiting upload, oldest first.
    func pendingSegments() -> [String] {
        let dir = (spoolPath as NSString).deletingLastPathComponent
        let liveName = (spoolPath as NSString).lastPathComponent
        let names = (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []
        return names
            .filter { isSegmentGzFile($0, liveName: liveName) }
            .sorted()
            .map { (dir as NSString).appendingPathComponent($0) }
    }

    private func uploadTick() {
        let shouldStart = lock.withLock { () -> Bool in
            let busy = uploadInFlight
            let backoffActive = Date() < uploadBackoffUntil
            if !busy, !backoffActive {
                uploadInFlight = true
                return true
            }
            return false
        }
        guard shouldStart else { return }
        Task { [weak self] in
            await self?.uploadNextSegment()
            self?.lock.withLock { self?.uploadInFlight = false }
        }
    }

    /// Upload the oldest pending segment. One at a time; on success
    /// (202 or 200) the local file is deleted; on failure the backoff
    /// doubles up to 60s and the same file is retried next tick.
    func uploadNextSegment() async {
        guard let path = pendingSegments().first else { return }
        guard let body = readFileNoFollow(path: path, maxBytes: 64 << 20) else {
            merlinLog("warn", "sync: cannot read segment \(path); skipping this tick")
            return
        }
        let name = (path as NSString).lastPathComponent
        let endpointPath: String
        let authorization: String
        if let deviceId = config.deviceId, let deviceToken = config.deviceToken {
            endpointPath = "/v1/devices/\(deviceId)/events"
            authorization = "Bearer \(deviceToken)"
        } else {
            endpointPath = "/v1/events"
            authorization = syncAuthorizationHeader(keyHex: config.keyHex)
        }
        guard let url = URL(string: endpointPath, relativeTo: config.baseURL) else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue(name, forHTTPHeaderField: "X-Merlin-Segment")
        request.setValue(authorization, forHTTPHeaderField: "Authorization")
        request.setValue("application/gzip", forHTTPHeaderField: "Content-Type")
        request.httpBody = body
        do {
            let (_, response) = try await session.data(for: request)
            let status = (response as? HTTPURLResponse)?.statusCode ?? -1
            if status == 202 || status == 200 {
                try? FileManager.default.removeItem(atPath: path)
                lock.withLock { uploadBackoff = 1 }
                merlinLog("info", "sync: uploaded \(name) (\(body.count) bytes, status \(status))")
            } else {
                throw MerlinError.plain("server returned \(status)")
            }
        } catch {
            lock.withLock {
                uploadBackoffUntil = Date().addingTimeInterval(uploadBackoff)
                uploadBackoff = min(uploadBackoff * 2, 60)
            }
            merlinLog("warn", "sync: upload of \(name) failed (retry with backoff): \(error.localizedDescription)")
        }
    }

    // MARK: rules polling

    // MARK: managed device heartbeat

    /// The posture sweep includes bounded system commands and should not run
    /// on every 60-second heartbeat. Keep the latest report for five minutes;
    /// a failed/limited sweep is still sent and never blocks telemetry.
    private func currentPostureReport() -> DevicePostureReport {
        if let localStatus { return localStatus.currentPostureReport() }
        postureLock.lock()
        if let cached = postureCache, Date().timeIntervalSince(cached.at) < 300 {
            postureLock.unlock()
            return cached.report
        }
        postureLock.unlock()

        let report = makeDevicePostureReport(snapshot: capturePosture())
        postureLock.lock()
        postureCache = (Date(), report)
        postureLock.unlock()
        return report
    }

    func checkIn() async {
        guard let deviceId = config.deviceId, let deviceToken = config.deviceToken else { return }
        guard let url = URL(string: "/v1/devices/\(deviceId)/check-in", relativeTo: config.baseURL) else { return }
        let requestBody = DeviceCheckInRequest(
            host: syncHostName(),
            platform: "macos",
            agentVersion: merlinAgentVersion,
            currentRulesSHA256: currentRulesHashSnapshot(),
            status: "healthy",
            capabilities: [
                "segment_upload",
                "rules_sync",
                "policy_cmdline_regex",
                "policy_network",
                "policy_signing",
                "policy_suspend",
                "endpoint_security_optional",
                "kqueue_fallback",
                "openbsm_legacy",
                "persistence_metadata",
                "bounded_spool",
                "os_inventory",
                "system_inventory",
                "file_integrity",
                "security_configuration_assessment",
                "rootcheck",
                "posture_reporting",
                "macos_security_posture",
                "network_extension_optional",
            ],
            osInfo: collectDeviceOSInfo(),
            inventory: collectDeviceInventory(),
            posture: currentPostureReport()
        )
        do {
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("Bearer \(deviceToken)", forHTTPHeaderField: "Authorization")
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONEncoder().encode(requestBody)
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                localStatus?.recordServerResponse(status: (response as? HTTPURLResponse)?.statusCode ?? -1)
                merlinLog("warn", "sync: device check-in returned \((response as? HTTPURLResponse)?.statusCode ?? -1)")
                return
            }
            let result = try JSONDecoder().decode(DeviceCheckInResponse.self, from: data)
            localStatus?.recordServerResponse(status: 200)
            guard let pending = result.pendingUpdate, pending.kind == "rules" else { return }
			await pollRules(targetSHA256: pending.targetRulesSHA256)
            guard currentRulesHashSnapshot() == pending.targetRulesSHA256 else {
                merlinLog("warn", "sync: queued policy \(pending.updateId) was not applied; keeping it pending")
                return
            }
            await acknowledgeDeviceUpdate(pending, token: deviceToken)
        } catch {
            merlinLog("warn", "sync: device check-in failed (continuing anyway): \(error.localizedDescription)")
        }
    }

    private func acknowledgeDeviceUpdate(_ update: PendingDeviceUpdate, token: String) async {
        guard let deviceId = config.deviceId,
              let url = URL(string: "/v1/devices/\(deviceId)/updates/\(update.updateId)/ack", relativeTo: config.baseURL)
        else { return }
        do {
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONEncoder().encode(DeviceUpdateAck(status: "applied", rulesSHA256: update.targetRulesSHA256))
            let (_, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                merlinLog("warn", "sync: device update acknowledgement returned \((response as? HTTPURLResponse)?.statusCode ?? -1)")
                return
            }
            merlinLog("info", "sync: applied and acknowledged policy \(update.targetRulesSHA256.prefix(12))…")
        } catch {
            merlinLog("warn", "sync: device update acknowledgement failed: \(error.localizedDescription)")
        }
    }

    /// Poll for a new ruleset. Applies ONLY when the server's hash
    /// differs from the current one AND the body is non-empty AND the
	/// Ed25519 signature verifies AND the YAML parses. Any failure keeps the
    /// last-known-good ruleset.
	func pollRules(targetSHA256: String) async {
		guard let deviceId = config.deviceId, let deviceToken = config.deviceToken,
			  !config.policyPublicKeysData.isEmpty else {
			merlinLog("warn", "sync: managed policy credentials or public key missing; update skipped")
            return
        }
        let hash = currentRulesHashSnapshot()
		guard let url = URL(string: "/v1/devices/\(deviceId)/policies/\(targetSHA256)", relativeTo: config.baseURL) else { return }
        do {
            var request = URLRequest(url: url)
			request.setValue("Bearer \(deviceToken)", forHTTPHeaderField: "Authorization")
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse else { return }
			if data.isEmpty { return }
            guard http.statusCode == 200 else {
				merlinLog("warn", "sync: assigned policy endpoint returned \(http.statusCode)")
                return
            }
			guard targetSHA256 != hash else { return }
			let verified: (artifact: Data, sha256: String)
			do {
				verified = try decodePolicyEnvelope(data, targetSHA256: targetSHA256, trustedKeyData: config.policyPublicKeysData)
			} catch {
				merlinLog("warn", "sync: policy envelope rejected (\(error)); keeping last-known-good")
				return
			}
			guard let text = String(data: verified.artifact, encoding: .utf8) else {
                merlinLog("warn", "sync: rules body is not UTF-8; keeping last-known-good")
                return
            }
            let newRules: Rules
            do {
                newRules = try Rules.parse(text)
            } catch {
                merlinLog("warn", "sync: rules parse failed (\(error)); keeping last-known-good")
                return
            }
            do {
				try writeRulesSynced(path: rulesPath + ".synced", contents: data)
            } catch {
				merlinLog("warn", "sync: persisting verified managed policy failed (\(error)); keeping last-known-good")
				return
            }
            rulesBox.update(newRules)
			lock.withLock { currentRulesHash = verified.sha256 }
			merlinLog("info", "sync: applied new ruleset (\(newRules.rules.count) rules, sha256 \(targetSHA256.prefix(12))…)")
        } catch {
            merlinLog("warn", "sync: rules poll failed (keeping last-known-good): \(error.localizedDescription)")
        }
    }

    private func currentRulesHashSnapshot() -> String {
        lock.withLock { currentRulesHash }
    }
}
