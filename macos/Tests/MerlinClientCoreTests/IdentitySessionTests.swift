import Foundation
import Testing
@testable import MerlinClientCore

@Suite("Native Identity boundary")
struct IdentitySessionTests {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    var config: NativeIdentityConfiguration {
        get throws { try NativeIdentityConfiguration(organizationID: "org_test", workspaceID: "workspace_test", resource: "https://merlin.dx-corp.net") }
    }
    func fixture() -> [String: Any] {
        let digest = String(repeating: "a", count: 64)
        return ["allowed": true, "request_id": "req_test", "authorization_lineage_id": "req_test", "decision_id": "decision_test",
                "policy_id": "policy_test", "policy_version": "v1", "policy_digest": digest, "authorization_fingerprint": "authz_fingerprint_v1_" + digest,
                "obligations": ["record_actor", "enforce_tenant_boundary", "revalidate_policy_version"],
                "identity": ["subject": "user_test", "organization_id": "org_test", "workspace_id": "workspace_test", "scopes": ["merlin:fleet:read"],
                    "identity_context": ["schema_version": "identity.context.v1", "principal": ["subject": "user_test", "principal_kind": "human"],
                        "tenant": ["organization_id": "org_test", "workspace_id": "workspace_test", "membership_state": "active", "organization_access_state": "approved"],
                        "session": ["session_id": "session_test", "token_type": "access", "expires_at": ISO8601DateFormatter().string(from: now.addingTimeInterval(60))]]]]
    }
    func decode(_ fixture: [String: Any]) throws -> EndpointIdentitySession {
        try IdentitySessionDecoder.decode(JSONSerialization.data(withJSONObject: fixture), requestID: "req_test", configuration: config, now: now)
    }
    @Test func acceptsAuthoritativeSession() throws {
        let session = try decode(fixture())
        #expect(session.subject == "user_test")
        #expect(session.sessionID == "session_test")
        #expect(session.lastVerifiedAt == now)
    }
    @Test func rejectsMismatchedAndMissingAuthority() throws {
        for key in ["allowed", "request_id", "authorization_lineage_id", "policy_digest", "authorization_fingerprint", "obligations"] {
            var value = fixture()
            value[key] = key == "allowed" ? false : (key == "obligations" ? ["new_unimplemented_obligation"] : "wrong")
            #expect(throws: (any Error).self) { try decode(value) }
        }
        for key in ["subject", "organization_id", "workspace_id", "scopes"] {
            var value = fixture()
            var identity = value["identity"] as! [String: Any]
            identity[key] = key == "scopes" ? [] : "other"
            value["identity"] = identity
            #expect(throws: (any Error).self) { try decode(value) }
        }
        for field in ["session_id", "token_type", "expires_at"] {
            var value = fixture()
            var identity = value["identity"] as! [String: Any]
            var context = identity["identity_context"] as! [String: Any]
            var session = context["session"] as! [String: Any]
            session[field] = field == "expires_at" ? "2000-01-01T00:00:00Z" : ""
            context["session"] = session; identity["identity_context"] = context; value["identity"] = identity
            #expect(throws: (any Error).self) { try decode(value) }
        }
    }
    @Test func rejectsForeignCallbackAndDuplicates() {
        #expect(NativeCallbackValidation.accepts(URL(string: "http://127.0.0.1:49177/?code=test&state=test")!))
        for callback in ["http://127.0.0.1:49177/?code=test&state=test&state=other", "http://127.0.0.1:49177/?code=test&error=denied&state=test",
                         "http://127.0.0.1:49178/?code=test&state=test", "http://localhost:49177/?code=test&state=test",
                         "https://example.com/?code=test&state=test", "http://127.0.0.1:49177/other?code=test&state=test",
                         "http://127.0.0.1:49177/?code=test", "http://127.0.0.1:49177/?code=test&state=test#fragment"] {
            #expect(!NativeCallbackValidation.accepts(URL(string: callback)!))
        }
    }
    @Test func refusesArbitraryResourceAndEmptyTenant() {
        #expect(throws: IdentitySessionError.configuration) {
            try NativeIdentityConfiguration(organizationID: "", workspaceID: "workspace", resource: "https://merlin.dx-corp.net")
        }
        #expect(throws: IdentitySessionError.configuration) {
            try NativeIdentityConfiguration(organizationID: "org", workspaceID: "workspace", resource: "https://attacker.invalid")
        }
    }
}
