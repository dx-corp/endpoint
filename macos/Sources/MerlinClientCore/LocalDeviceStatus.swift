import Foundation

public enum LocalEnrollmentState: String, Codable, Sendable {
    /// Local configuration only; this is not server acceptance or device proof.
    case unconfigured, configured, rejected
}

public enum LocalPostureSummary: String, Codable, Sendable {
    case unknown, secure, degraded, atRisk
}

public enum LocalPostureCheckState: String, Codable, Sendable {
    case pass, finding, unknown, unavailable, requiresRoot
}

public struct LocalPostureCheck: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    public let status: LocalPostureCheckState

    public init(id: String, status: LocalPostureCheckState) {
        self.id = id
        self.status = status
    }
}

public enum LocalEnforcementAction: String, Codable, Sendable {
    case blocked, stopped
}

/// Display-only guidance for the most recent local enforcement decision.
/// The collector sends no process path, command line, or rule payload across IPC.
public struct LocalEnforcementNotice: Codable, Sendable, Equatable {
    public let action: LocalEnforcementAction
    public let occurredAt: Date
    public let approvedName: String?
    public let approvedURL: URL?

    public init(action: LocalEnforcementAction, occurredAt: Date, approvedName: String?, approvedURL: URL?) {
        self.action = action
        self.occurredAt = occurredAt
        self.approvedName = approvedName
        self.approvedURL = approvedURL
    }

    public func isRecent(at now: Date = Date()) -> Bool {
        (0..<3600).contains(now.timeIntervalSince(occurredAt))
    }

    fileprivate var isValid: Bool {
        guard occurredAt.timeIntervalSince1970.isFinite,
              (approvedName == nil) == (approvedURL == nil) else { return false }
        guard let approvedName, let approvedURL else { return true }
        return !approvedName.isEmpty && approvedName.utf8.count <= 80 &&
            !approvedName.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) &&
            approvedURL.absoluteString.utf8.count <= 2048 && approvedURL.scheme == "https" &&
            approvedURL.host != nil && approvedURL.user == nil && approvedURL.password == nil &&
            approvedURL.query == nil && approvedURL.fragment == nil
    }
}

/// Non-authoritative local display data. Never use this snapshot for authorization.
/// No credentials, raw command output, spool records, or user inventory cross IPC.
public struct LocalDeviceStatus: Codable, Sendable, Equatable {
    public static let maxEncodedBytes = 32 * 1024
    public static let maxAge: TimeInterval = 300
    public static let checkIDs = ["filevault", "sip", "gatekeeper", "firewall", "authenticated_root", "secure_boot", "software_updates"]

    public let schemaVersion: Int
    public let observedAt: Date
    public let deviceID: String?
    public let collectorRunning: Bool
    public let enrollment: LocalEnrollmentState
    public let posture: LocalPostureSummary
    public let checks: [LocalPostureCheck]
    /// Latest accepted authenticated heartbeat, not proof the server accepted posture.
    public let lastServerContact: Date?
    public let enforcement: LocalEnforcementNotice?

    public init(observedAt: Date, deviceID: String?, collectorRunning: Bool,
                enrollment: LocalEnrollmentState, posture: LocalPostureSummary,
                checks: [LocalPostureCheck], lastServerContact: Date?, enforcement: LocalEnforcementNotice? = nil) {
        self.schemaVersion = 1
        self.observedAt = observedAt
        self.deviceID = deviceID
        self.collectorRunning = collectorRunning
        self.enrollment = enrollment
        self.posture = posture
        self.checks = checks
        self.lastServerContact = lastServerContact
        self.enforcement = enforcement
    }

    public func isStale(at now: Date = Date()) -> Bool {
        let age = now.timeIntervalSince(observedAt)
        return age < 0 || age > Self.maxAge
    }

    public static func decode(_ data: Data) throws -> LocalDeviceStatus {
        guard data.count <= maxEncodedBytes else { throw LocalStatusError.invalidResponse }
        let result = try JSONDecoder().decode(Self.self, from: data)
        guard result.schemaVersion == 1,
              result.deviceID.map({ $0.utf8.count <= 128 && $0.unicodeScalars.allSatisfy { CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_")).contains($0) } }) ?? true,
              result.checks.count == checkIDs.count,
              Set(result.checks.map(\.id)) == Set(checkIDs),
              result.observedAt.timeIntervalSince1970.isFinite,
              result.lastServerContact?.timeIntervalSince1970.isFinite ?? true,
              result.enforcement?.isValid ?? true else {
            throw LocalStatusError.invalidResponse
        }
        return result
    }
}
