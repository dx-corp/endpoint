import Foundation
import Security

@objc public protocol MerlinLocalStatusProtocol {
    func readStatus(withReply reply: @escaping (Data?) -> Void)
}

public enum LocalStatusError: Error, Sendable {
    case unavailable, untrustedSignature, invalidResponse, timedOut
}

/// Both sides pin the peer to their own actual signing team and its fixed identifier.
/// NSXPC enforces this requirement on the live peer/message; no PID lookup or
/// user-supplied assertion participates. Ad-hoc signatures have no trusted team.
public enum LocalStatusPeerPolicy {
    public static let serviceName = "com.evalops.merlin.status"
    public static let appIdentifier = "com.merlin.agent"
    public static let collectorIdentifier = "com.evalops.merlin.collector"

    public static func requirement(teamID: String, identifier: String) throws -> String {
        guard teamID.count == 10, teamID.utf8.allSatisfy({ (65...90).contains($0) || (48...57).contains($0) }),
              [appIdentifier, collectorIdentifier].contains(identifier) else {
            throw LocalStatusError.untrustedSignature
        }
        return "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\" and identifier \"\(identifier)\""
    }

    public static func ownTeamID() throws -> String {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { throw LocalStatusError.untrustedSignature }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
            throw LocalStatusError.untrustedSignature
        }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let values = information as? [String: Any],
              let team = values[kSecCodeInfoTeamIdentifier as String] as? String else {
            throw LocalStatusError.untrustedSignature
        }
        return team
    }
}

/// One bounded request/connection. Timeout and invalidation cannot resume twice.
private final class LocalStatusRequest: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<LocalDeviceStatus, any Error>?
    private var connection: NSXPCConnection?

    init(_ continuation: CheckedContinuation<LocalDeviceStatus, any Error>, connection: NSXPCConnection) {
        self.continuation = continuation
        self.connection = connection
    }

    func finish(_ result: Result<LocalDeviceStatus, any Error>) {
        let pending = lock.withLock { () -> (CheckedContinuation<LocalDeviceStatus, any Error>?, NSXPCConnection?) in
            let pending = (continuation, connection)
            continuation = nil
            connection = nil
            return pending
        }
        pending.1?.invalidate()
        pending.0?.resume(with: result)
    }
}

public struct LocalStatusClient: Sendable {
    public init() {}

    public func readStatus() async throws -> LocalDeviceStatus {
        let requirement = try LocalStatusPeerPolicy.requirement(
            teamID: LocalStatusPeerPolicy.ownTeamID(), identifier: LocalStatusPeerPolicy.collectorIdentifier)
        let connection = NSXPCConnection(machServiceName: LocalStatusPeerPolicy.serviceName, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: MerlinLocalStatusProtocol.self)
        // Available since macOS 13.0; never fall back to unauthenticated IPC.
        connection.setCodeSigningRequirement(requirement)
        return try await withCheckedThrowingContinuation { continuation in
            let request = LocalStatusRequest(continuation, connection: connection)
            connection.interruptionHandler = { request.finish(.failure(LocalStatusError.unavailable)) }
            connection.invalidationHandler = { request.finish(.failure(LocalStatusError.unavailable)) }
            connection.resume()
            DispatchQueue.global().asyncAfter(deadline: .now() + 5) {
                request.finish(.failure(LocalStatusError.timedOut))
            }
            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
                request.finish(.failure(LocalStatusError.unavailable))
            }) as? MerlinLocalStatusProtocol else {
                request.finish(.failure(LocalStatusError.unavailable))
                return
            }
            proxy.readStatus { data in
                guard let data else { request.finish(.failure(LocalStatusError.unavailable)); return }
                do { request.finish(.success(try LocalDeviceStatus.decode(data))) }
                catch { request.finish(.failure(LocalStatusError.invalidResponse)) }
            }
        }
    }
}
