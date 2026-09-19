import AppKit
@preconcurrency import AppAuth
import Combine
import Foundation
import MerlinClientCore
import MerlinAppAuthCompat
import Security

// Native credentials belong to the signed-in user, never the root collector.
enum EndpointSessionState: Equatable {
    case signedOut
    case signingIn
    case signedIn(EndpointIdentitySession)
    case unavailable(String)
}

@MainActor
final class EndpointSessionModel: ObservableObject {
    @Published private(set) var state: EndpointSessionState = .signedOut
    private var authState: OIDAuthState?
    private var redirectHandler: OIDRedirectHTTPHandler?
    private var activeFlow: StrictAuthorizationFlow?
    private var timeout: Task<Void, Never>?
    private var isRefreshing = false
    private var generation = 0
    private let configuration: NativeIdentityConfiguration?
    private let network = URLSession(configuration: .ephemeral, delegate: NoIdentityRedirects(), delegateQueue: nil)

    init(bundle: Bundle = .main) {
        OIDURLSessionProvider.setSession(network)
        if bundle.object(forInfoDictionaryKey: "MerlinNativeSignInEnabled") as? Bool == true,
           let organization = bundle.object(forInfoDictionaryKey: "MerlinOrganizationID") as? String,
           let workspace = bundle.object(forInfoDictionaryKey: "MerlinWorkspaceID") as? String,
           let resource = bundle.object(forInfoDictionaryKey: "MerlinOAuthResource") as? String {
            configuration = try? NativeIdentityConfiguration(organizationID: organization, workspaceID: workspace, resource: resource)
        } else { configuration = nil }
        if configuration != nil {
            do {
                if let data = try SessionKeychain.load() {
                    authState = try NSKeyedUnarchiver.unarchivedObject(ofClass: OIDAuthState.self, from: data)
                }
            } catch { state = .unavailable("The saved sign-in could not be opened. Sign in again.") }
        }
    }

    func signIn() async {
        guard let configuration else {
            state = .unavailable("Organization sign-in is awaiting native client registration.")
            return
        }
        guard activeFlow == nil else { return }
        generation += 1
        let attempt = generation
        state = .signingIn
        do {
            let listener = OIDRedirectHTTPHandler(successURL: nil)
            guard let redirect = MerlinStartLoopbackListener(listener, 49177) else {
                throw IdentitySessionError.unavailable
            }
            guard redirect == NativeIdentityConfiguration.redirectURL else {
                listener.cancelHTTPListener()
                throw IdentitySessionError.configuration
            }
            redirectHandler = listener
            let service = OIDServiceConfiguration(
                authorizationEndpoint: NativeIdentityConfiguration.issuer.appendingPathComponent("authorize"),
                tokenEndpoint: NativeIdentityConfiguration.issuer.appendingPathComponent("token"))
            let request = OIDAuthorizationRequest(configuration: service,
                clientId: NativeIdentityConfiguration.clientID, clientSecret: nil,
                scopes: NativeIdentityConfiguration.scopes, redirectURL: redirect,
                responseType: OIDResponseTypeCode,
                additionalParameters: ["organization_id": configuration.organizationID,
                                       "workspace_id": configuration.workspaceID, "resource": configuration.resource])
            guard let window = NSApp.keyWindow ?? NSApp.windows.first else {
                listener.cancelHTTPListener()
                throw IdentitySessionError.unavailable
            }
            // AppAuth generates cryptographically random state/nonce and S256 PKCE.
            let result: OIDAuthState = try await withCheckedThrowingContinuation { continuation in
                let flow = OIDAuthState.authState(byPresenting: request, presenting: window) { [weak self] result, _ in
                    Task { @MainActor in
                        self?.timeout?.cancel()
                        self?.timeout = nil
                        self?.activeFlow = nil
                        self?.redirectHandler = nil
                        if let result { continuation.resume(returning: result) }
                        else { continuation.resume(throwing: IdentitySessionError.denied) }
                    }
                }
                let strict = StrictAuthorizationFlow(flow: flow)
                activeFlow = strict
                listener.currentAuthorizationFlow = strict
                timeout = Task { [weak self] in
                    try? await Task.sleep(for: .seconds(120))
                    guard !Task.isCancelled else { return }
                    self?.redirectHandler?.cancelHTTPListener()
                }
            }
            guard generation == attempt else { return }
            authState = result
            await refresh()
        } catch {
            guard generation == attempt else { return }
            state = .unavailable("Sign-in did not complete. Try again.")
            redirectHandler?.cancelHTTPListener()
            redirectHandler = nil
            activeFlow = nil
        }
    }

    func refresh() async {
        guard !isRefreshing, activeFlow == nil else { return }
        guard let configuration, let authState else {
            if case .unavailable = state { return }
            state = .signedOut
            return
        }
        isRefreshing = true
        let attempt = generation
        defer { isRefreshing = false }
        do {
            let token: String = try await withCheckedThrowingContinuation { continuation in
                authState.performAction { accessToken, _, _ in
                    if let accessToken { continuation.resume(returning: accessToken) }
                    else { continuation.resume(throwing: IdentitySessionError.denied) }
                }
            }
            guard generation == attempt else { return }
            let requestID = "req_" + UUID().uuidString.lowercased()
            var request = URLRequest(url: NativeIdentityConfiguration.issuer.appendingPathComponent("v1/tokens/authorize"))
            request.httpMethod = "POST"
            request.timeoutInterval = 15
            request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization")
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONSerialization.data(withJSONObject: [
                "organization_id": configuration.organizationID, "workspace_id": configuration.workspaceID,
                "required_scopes": ["merlin:fleet:read"], "request_id": requestID, "authorization_lineage_id": requestID])
            let (bytes, response) = try await network.bytes(for: request)
            guard let http = response as? HTTPURLResponse else { throw IdentitySessionError.unavailable }
            guard http.statusCode == 200 else {
                if http.statusCode == 401 || http.statusCode == 403 { throw IdentitySessionError.denied }
                throw IdentitySessionError.unavailable
            }
            var data = Data()
            for try await byte in bytes {
                guard data.count < 65_536 else { throw IdentitySessionError.invalidDecision }
                data.append(byte)
            }
            let session = try IdentitySessionDecoder.decode(data, requestID: requestID, configuration: configuration)
            guard generation == attempt else { return }
            try saveState()
            state = .signedIn(session)
        } catch {
            guard generation == attempt else { return }
            if (error as? IdentitySessionError) == .denied || (error as? IdentitySessionError) == .expired {
                self.authState = nil
                try? SessionKeychain.delete()
                state = .signedOut
            } else {
                // Previously cached claims never remain a live-session success during failure.
                state = .unavailable("Session verification is unavailable. Connect to the internet and refresh.")
            }
        }
    }

    func monitor() async {
        while !Task.isCancelled {
            await refresh()
            do { try await Task.sleep(for: .seconds(60)) } catch { return }
        }
    }

    func signOut() async {
        generation += 1
        timeout?.cancel()
        redirectHandler?.cancelHTTPListener()
        let refreshToken = authState?.refreshToken
        authState = nil
        do { try SessionKeychain.delete(); state = .signedOut }
        catch { state = .unavailable("The saved sign-in could not be removed from Keychain.") }
        // Revoke this app's refresh credential; device enrollment and other sessions remain separate.
        if let refreshToken {
            var request = URLRequest(url: NativeIdentityConfiguration.issuer.appendingPathComponent("revoke"))
            request.httpMethod = "POST"
            request.timeoutInterval = 10
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            var form = URLComponents()
            form.queryItems = [URLQueryItem(name: "token", value: refreshToken), URLQueryItem(name: "token_type_hint", value: "refresh_token"),
                               URLQueryItem(name: "client_id", value: NativeIdentityConfiguration.clientID)]
            request.httpBody = form.percentEncodedQuery?.data(using: .utf8)
            _ = try? await network.data(for: request)
        }
    }

    private func saveState() throws {
        guard let authState else { return }
        try SessionKeychain.save(NSKeyedArchiver.archivedData(withRootObject: authState, requiringSecureCoding: true))
    }
}

private final class NoIdentityRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

private final class StrictAuthorizationFlow: NSObject, OIDExternalUserAgentSession {
    private let flow: any OIDExternalUserAgentSession
    init(flow: any OIDExternalUserAgentSession) { self.flow = flow }
    func resumeExternalUserAgentFlow(with url: URL) -> Bool {
        do { try resumeExternalUserAgentFlow(url); return true } catch { return false }
    }
    func resumeExternalUserAgentFlow(_ url: URL) throws {
        guard NativeCallbackValidation.accepts(url) else { throw IdentitySessionError.invalidDecision }
        try flow.resumeExternalUserAgentFlow(url)
    }
    func failExternalUserAgentFlowWithError(_ error: Error) { flow.failExternalUserAgentFlowWithError(error) }
    func cancel() { flow.cancel() }
    func cancel(completion: (@Sendable () -> Void)?) { flow.cancel(completion: completion) }
}

private enum SessionKeychain {
    static var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.merlin.agent.identity",
         kSecAttrAccount as String: NativeIdentityConfiguration.clientID, kSecAttrSynchronizable as String: false]
    }
    static func load() throws -> Data? {
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data, data.count <= 131_072 else { throw IdentitySessionError.unavailable }
        return data
    }
    static func save(_ data: Data) throws {
        let values = [kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly] as [String: Any]
        let updated = SecItemUpdate(query as CFDictionary, values as CFDictionary)
        if updated == errSecItemNotFound {
            guard SecItemAdd(query.merging(values) { _, new in new } as CFDictionary, nil) == errSecSuccess else { throw IdentitySessionError.unavailable }
        } else if updated != errSecSuccess { throw IdentitySessionError.unavailable }
    }
    static func delete() throws {
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw IdentitySessionError.unavailable }
    }
}
