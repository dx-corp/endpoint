import Foundation
import MerlinClientCore
import Testing
@testable import MerlinEndpointApp

@MainActor
struct EndpointAppModelTests {
    @Test func sessionVerificationExpiresIndependentlyOfTokenExpiry() {
        let verifiedAt = Date(timeIntervalSince1970: 1_000)
        #expect(EndpointSessionFreshness.isCurrent(lastVerifiedAt: verifiedAt, now: verifiedAt))
        #expect(EndpointSessionFreshness.isCurrent(lastVerifiedAt: verifiedAt, now: verifiedAt.addingTimeInterval(120)))
        #expect(!EndpointSessionFreshness.isCurrent(lastVerifiedAt: verifiedAt, now: verifiedAt.addingTimeInterval(121)))
        #expect(!EndpointSessionFreshness.isCurrent(lastVerifiedAt: verifiedAt, now: verifiedAt.addingTimeInterval(-1)))
    }

    @Test func unavailableCollectorDiscardsPreviouslySuccessfulStatus() async {
        let reader = StatusReader()
        let model = EndpointAppModel(readStatus: { try await reader.read() })
        await model.refresh()
        #expect(model.status != nil)
        #expect(!model.readFailed)

        await reader.failNextRead()
        await model.refresh()
        #expect(model.status == nil)
        #expect(model.readFailed)
        #expect(!model.isRefreshing)

        await model.refresh()
        #expect(model.status != nil)
        #expect(!model.readFailed)
    }

    @Test func concurrentRefreshDoesNotCreateAnotherIPCRequest() async {
        let reader = SuspendedReader()
        let model = EndpointAppModel(readStatus: { await reader.read() })
        let firstRead = Task { await model.refresh() }
        await reader.waitUntilStarted()
        #expect(model.isRefreshing)
        await model.refresh()
        #expect(await reader.callCount == 1)
        await reader.finish()
        await firstRead.value
        #expect(!model.isRefreshing)
        #expect(model.status != nil)
    }
}

private func observedStatus() -> LocalDeviceStatus {
    LocalDeviceStatus(observedAt: Date(), deviceID: nil, collectorRunning: true,
                      enrollment: .unconfigured, posture: .unknown, checks: [], lastServerContact: nil)
}

private actor StatusReader {
    private var shouldFail = false

    func failNextRead() { shouldFail = true }

    func read() throws -> LocalDeviceStatus {
        if shouldFail {
            shouldFail = false
            throw LocalStatusError.untrustedSignature
        }
        return observedStatus()
    }
}

private actor SuspendedReader {
    private(set) var callCount = 0
    private var reply: CheckedContinuation<LocalDeviceStatus, Never>?
    private var startedWaiter: CheckedContinuation<Void, Never>?

    func waitUntilStarted() async {
        if callCount > 0 { return }
        await withCheckedContinuation { startedWaiter = $0 }
    }

    func read() async -> LocalDeviceStatus {
        callCount += 1
        return await withCheckedContinuation { continuation in
            reply = continuation
            startedWaiter?.resume()
            startedWaiter = nil
        }
    }

    func finish() {
        reply?.resume(returning: observedStatus())
        reply = nil
    }
}
