import Foundation
import Network
import Testing
import MerlinAppAuthCompat
@preconcurrency import AppAuth
@testable import MerlinEndpointApp

/// Loopback-only transport fixture. It never opens SSO or uses credentials.
private final class IdentityRedirectFixture: @unchecked Sendable {
    private let listener: NWListener
    private let queue = DispatchQueue(label: "merlin.tests.identity-redirect")
    private let lock = NSLock()
    private var requests = 0

    init() throws {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
    }
    var requestCount: Int { lock.withLock { requests } }

    func start() async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            listener.stateUpdateHandler = { [self] state in
                if case .ready = state, let port = listener.port {
                    listener.stateUpdateHandler = nil
                    continuation.resume(returning: URL(string: "http://127.0.0.1:\(port.rawValue)/token")!)
                } else if case .failed(let error) = state {
                    listener.stateUpdateHandler = nil
                    continuation.resume(throwing: error)
                }
            }
            listener.newConnectionHandler = { [self] connection in
                connection.start(queue: queue)
                connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [self] data, _, _, _ in
                    guard let data, !data.isEmpty, let port = listener.port else { connection.cancel(); return }
                    let count = lock.withLock { requests += 1; return requests }
                    let response = count == 1
                        ? "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:\(port.rawValue)/unexpected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        : "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    connection.send(content: Data(response.utf8), completion: .contentProcessed { _ in connection.cancel() })
                }
            }
            listener.start(queue: queue)
        }
    }

    func stop() { listener.cancel() }
}

@Suite("native session transport", .serialized)
struct NativeSessionTransportTests {
    @MainActor @Test("an occupied callback port returns nil instead of trapping in Swift URL bridging")
    func occupiedCallbackPortFailsSafely() throws {
        let first = OIDRedirectHTTPHandler(successURL: nil)
        let second = OIDRedirectHTTPHandler(successURL: nil)
        defer { second.cancelHTTPListener(); first.cancelHTTPListener() }
        let firstURL = try #require(MerlinStartLoopbackListener(first, 49177))
        #expect(firstURL.port == 49177)
        #expect(MerlinStartLoopbackListener(second, 49177) == nil)
    }

    @MainActor @Test("AppAuth uses the nonpersistent transport and refuses token POST redirects")
    func tokenTransportRejectsRedirect() async throws {
        // No native sign-in bundle configuration: init cannot load credentials or start auth.
        let model = EndpointSessionModel(bundle: Bundle(for: NativeTransportBundleAnchor.self))
        _ = model
        let transport = OIDURLSessionProvider.session()
        #expect(transport !== URLSession.shared)
        #expect(transport.configuration.httpCookieStorage !== HTTPCookieStorage.shared)
        #expect((transport.configuration.urlCache?.diskCapacity ?? 0) == 0)
        let server = try IdentityRedirectFixture()
        let endpoint = try await server.start()
        defer { server.stop() }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.httpBody = Data("fixture-without-credentials".utf8)
        request.timeoutInterval = 5
        let (_, response) = try await transport.data(for: request)
        #expect((response as? HTTPURLResponse)?.statusCode == 307)
        #expect(server.requestCount == 1)
    }
}

private final class NativeTransportBundleAnchor: NSObject {}
