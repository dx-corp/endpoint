import Foundation

public struct EndpointIdentitySession: Equatable, Sendable {
    public let subject: String
    public let displayName: String?
    public let email: String?
    public let expiresAt: Date
    public let lastVerifiedAt: Date
    public let sessionID: String
}

public struct NativeIdentityConfiguration: Equatable, Sendable {
    public static let issuer = URL(string: "https://identity.evalops.dev")!
    public static let clientID = "merlin-macos"
    public static let redirectURL = URL(string: "http://127.0.0.1:49177/")!
    public static let scopes = ["openid", "profile", "email", "merlin:fleet:read"]
    public let organizationID: String
    public let workspaceID: String
    public let resource: String

    // Settings come from the signed app bundle. Presence is not a registration receipt.
    public init(organizationID: String, workspaceID: String, resource: String) throws {
        guard Self.identifier(organizationID), Self.identifier(workspaceID),
              resource == "https://merlin.dx-corp.net" else { throw IdentitySessionError.configuration }
        self.organizationID = organizationID
        self.workspaceID = workspaceID
        self.resource = resource
    }

    private static func identifier(_ value: String) -> Bool {
        !value.isEmpty && value.count <= 128 && value.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_" || $0 == "-") }
    }
}

public enum IdentitySessionError: Error, Equatable {
    case configuration, invalidDecision, expired, denied, unavailable
}

// This adapter consumes the existing Identity JSON authorization boundary.
// It never projects session authority from an unverified ID-token payload.
public enum IdentitySessionDecoder {
    public static func decode(_ data: Data, requestID: String, configuration: NativeIdentityConfiguration,
                              now: Date = Date()) throws -> EndpointIdentitySession {
        guard data.count <= 65_536 else { throw IdentitySessionError.invalidDecision }
        let result = try JSONDecoder().decode(Decision.self, from: data)
        guard result.allowed else { throw IdentitySessionError.denied }
        let identity = result.identity
        let context = identity.identityContext
        guard result.requestID == requestID, result.authorizationLineageID == requestID,
              validText(result.decisionID), validText(result.policyID), validText(result.policyVersion),
              validDigest(result.policyDigest), result.authorizationFingerprint.hasPrefix("authz_fingerprint_v1_"),
              validDigest(String(result.authorizationFingerprint.dropFirst("authz_fingerprint_v1_".count))),
              Set(["record_actor", "enforce_tenant_boundary", "revalidate_policy_version"]) == Set(result.obligations),
              result.obligations.count <= 32, result.obligations.allSatisfy(validText),
              validText(identity.subject), identity.organizationID == configuration.organizationID,
              identity.workspaceID == configuration.workspaceID, identity.scopes.contains("merlin:fleet:read"),
              context.schemaVersion == "identity.context.v1", context.principal.subject == identity.subject,
              context.principal.principalKind == "human", context.tenant.organizationID == configuration.organizationID,
              context.tenant.workspaceID == configuration.workspaceID, context.tenant.membershipState == "active",
              context.tenant.organizationAccessState == "approved", validText(context.session.sessionID),
              context.session.tokenType == "access", let expiry = parseDate(context.session.expiresAt)
        else { throw IdentitySessionError.invalidDecision }
        guard expiry > now else { throw IdentitySessionError.expired }
        return EndpointIdentitySession(subject: identity.subject, displayName: nil, email: nil,
                                       expiresAt: expiry, lastVerifiedAt: now, sessionID: context.session.sessionID)
    }

    private static func validText(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 512 && !value.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }
    private static func validDigest(_ value: String) -> Bool {
        value.count == 64 && value.allSatisfy { "0123456789abcdef".contains($0) }
    }
    private static func parseDate(_ value: String) -> Date? {
        let parser = ISO8601DateFormatter()
        parser.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = parser.date(from: value) { return date }
        parser.formatOptions = [.withInternetDateTime]
        return parser.date(from: value)
    }

    private struct Decision: Decodable {
        let allowed: Bool
        let requestID, authorizationLineageID, decisionID, policyID, policyVersion, policyDigest, authorizationFingerprint: String
        let obligations: [String]
        let identity: Identity
        enum CodingKeys: String, CodingKey {
            case allowed, obligations, identity
            case requestID = "request_id", authorizationLineageID = "authorization_lineage_id", decisionID = "decision_id"
            case policyID = "policy_id", policyVersion = "policy_version", policyDigest = "policy_digest", authorizationFingerprint = "authorization_fingerprint"
        }
    }
    private struct Identity: Decodable {
        let subject, organizationID, workspaceID: String
        let scopes: [String]
        let identityContext: Context
        enum CodingKeys: String, CodingKey {
            case subject, scopes
            case organizationID = "organization_id", workspaceID = "workspace_id", identityContext = "identity_context"
        }
    }
    private struct Context: Decodable {
        let schemaVersion: String
        let principal: Principal
        let tenant: Tenant
        let session: Session
        enum CodingKeys: String, CodingKey { case schemaVersion = "schema_version", principal, tenant, session }
    }
    private struct Principal: Decodable {
        let subject, principalKind: String
        enum CodingKeys: String, CodingKey { case subject, principalKind = "principal_kind" }
    }
    private struct Tenant: Decodable {
        let organizationID, workspaceID, membershipState, organizationAccessState: String
        enum CodingKeys: String, CodingKey {
            case organizationID = "organization_id", workspaceID = "workspace_id", membershipState = "membership_state", organizationAccessState = "organization_access_state"
        }
    }
    private struct Session: Decodable {
        let sessionID, tokenType, expiresAt: String
        enum CodingKeys: String, CodingKey { case sessionID = "session_id", tokenType = "token_type", expiresAt = "expires_at" }
    }
}
