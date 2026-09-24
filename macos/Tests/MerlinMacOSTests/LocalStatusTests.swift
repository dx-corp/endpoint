import Foundation
import MerlinClientCore
import Security
import Testing
@testable import MerlinMacOS

@Suite struct LocalStatusTests {
    @Test func absentObservationRemainsUnknownAndStale() {
        let status = LocalStatusStore().snapshot()
        #expect(status.posture == .unknown)
        #expect(status.enrollment == .unconfigured)
        #expect(status.lastServerContact == nil)
        #expect(status.isStale())
        #expect(status.checks.allSatisfy { $0.status == .unknown })
    }

    @Test func configurationIsNotAuthenticatedServerContact() {
        let store = LocalStatusStore()
        store.configure(deviceID: "device-fixture")
        #expect(store.snapshot().enrollment == .configured)
        #expect(store.snapshot().lastServerContact == nil)
        store.recordServerResponse(status: 503)
        #expect(store.snapshot().lastServerContact == nil)
        store.recordServerResponse(status: 403)
        #expect(store.snapshot().enrollment == .rejected)
        let accepted = Date(timeIntervalSince1970: 123)
        store.recordServerResponse(status: 200, at: accepted)
        #expect(store.snapshot().lastServerContact == accepted)
        #expect(store.snapshot().enrollment == .configured)
        store.recordServerResponse(status: 401)
        #expect(store.snapshot().enrollment == .rejected)
        #expect(store.snapshot().lastServerContact == accepted)
    }

    @Test func projectionNeverSerializesRawPostureOrCredentials() throws {
        let store = LocalStatusStore()
        let snapshot = PostureSnapshot(values: ["filevault": "raw-private-value", "tcc": "raw-private-account"], findings: ["filevault": "raw-private-detail"])
        store.publish(makeDevicePostureReport(snapshot: snapshot))
        let encoded = try JSONEncoder().encode(store.snapshot())
        let text = String(decoding: encoded, as: UTF8.self)
        #expect(!text.contains("raw-private"))
        #expect(!text.contains("tcc"))
        #expect(!text.contains("token"))
        #expect(!text.contains("evidence"))
        #expect(try LocalDeviceStatus.decode(encoded).checks.first?.status == .finding)
    }

    @Test func enforcementGuidanceIsRecentAndContainsOnlyApprovedMapping() throws {
        let store = LocalStatusStore()
        let approvedURL = try #require(URL(string: "https://approved.example.com/editor"))
        store.recordEnforcement(action: .blocked, approvedName: "Approved editor", approvedURL: approvedURL)
        let data = try JSONEncoder().encode(store.snapshot())
        let text = String(decoding: data, as: UTF8.self)
        #expect(text.contains("Approved editor"))
        #expect(!text.contains("process"))
        #expect(try LocalDeviceStatus.decode(data).enforcement?.approvedURL == approvedURL)

        store.recordEnforcement(action: .stopped, approvedName: nil, approvedURL: nil,
                                at: Date().addingTimeInterval(-3601))
        #expect(store.snapshot().enforcement == nil)
    }

    @Test func malformedGuidanceIsRejectedAtIPCBoundary() throws {
        let status = LocalDeviceStatus(observedAt: Date(), deviceID: nil, collectorRunning: true,
                                       enrollment: .configured, posture: .unknown,
                                       checks: LocalStatusStore().snapshot().checks, lastServerContact: nil,
                                       enforcement: LocalEnforcementNotice(action: .blocked, occurredAt: Date(),
                                           approvedName: "Injected", approvedURL: URL(string: "https://user:secret@example.com")))
        #expect(throws: (any Error).self) { try LocalDeviceStatus.decode(JSONEncoder().encode(status)) }
    }

    @Test func unknownChecksDoNotBecomeSecure() {
        let store = LocalStatusStore()
        store.publish(makeDevicePostureReport(snapshot: PostureSnapshot(values: ["filevault": "unknown"], findings: [:])))
        #expect(store.snapshot().posture == .unknown)
        #expect(store.snapshot().checks.first?.status == .unknown)
    }

    @Test func staleAndFutureObservationsAreExplicit() {
        let now = Date()
        for observed in [now.addingTimeInterval(-301), now.addingTimeInterval(1)] {
            let status = LocalDeviceStatus(observedAt: observed, deviceID: nil, collectorRunning: true,
                                           enrollment: .unconfigured, posture: .unknown, checks: [], lastServerContact: nil)
            #expect(status.isStale(at: now))
        }
    }

    @Test func signingRequirementRejectsInjectionAndUnexpectedPeers() throws {
        #expect(throws: LocalStatusError.self) {
            try LocalStatusPeerPolicy.requirement(teamID: "", identifier: LocalStatusPeerPolicy.appIdentifier)
        }
        #expect(throws: LocalStatusError.self) {
            try LocalStatusPeerPolicy.requirement(teamID: "TEST123456", identifier: "com.unrelated.application")
        }
        #expect(throws: LocalStatusError.self) {
            try LocalStatusPeerPolicy.requirement(teamID: "\" or true ", identifier: LocalStatusPeerPolicy.appIdentifier)
        }
        for identifier in [LocalStatusPeerPolicy.appIdentifier, LocalStatusPeerPolicy.collectorIdentifier] {
            let source = try LocalStatusPeerPolicy.requirement(teamID: "TEST123456", identifier: identifier)
            var requirement: SecRequirement?
            #expect(SecRequirementCreateWithString(source as CFString, [], &requirement) == errSecSuccess)
            var executable: SecStaticCode?
            #expect(SecStaticCodeCreateWithPath(URL(fileURLWithPath: "/usr/bin/true") as CFURL, [], &executable) == errSecSuccess)
            if let executable, let requirement {
                #expect(SecStaticCodeCheckValidity(executable, [], requirement) != errSecSuccess)
            }
        }
    }

    @Test func malformedAndOversizedRepliesAreRejected() throws {
        #expect(throws: (any Error).self) { try LocalDeviceStatus.decode(Data(repeating: 32, count: LocalDeviceStatus.maxEncodedBytes + 1)) }
        let data = try JSONEncoder().encode(LocalStatusStore().snapshot())
        var object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        object["schemaVersion"] = 2
        #expect(throws: (any Error).self) { try LocalDeviceStatus.decode(JSONSerialization.data(withJSONObject: object)) }
    }
}
