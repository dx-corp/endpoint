import Foundation
import MerlinClientCore
import Testing
import UserNotifications
@testable import MerlinEndpointApp

@MainActor
struct EndpointAppModelTests {
    @Test func applicationDelegateOwnsExactlyOneStatusMonitor() async {
        let reader = SuspendedReader()
        let model = EndpointAppModel(readStatus: { await reader.read() })
        var notificationInstalls = 0
        let delegate = EndpointAppDelegate(model: model, installNotifications: { notificationInstalls += 1 })
        let launch = Notification(name: Notification.Name("test-launch"))
        delegate.applicationDidFinishLaunching(launch)
        await reader.waitUntilStarted()
        delegate.applicationDidFinishLaunching(launch)
        #expect(notificationInstalls == 1)
        #expect(await reader.callCount == 1)
        await reader.finish()
        delegate.applicationWillTerminate(Notification(name: Notification.Name("test-terminate")))
    }

    @Test func enforcementNotificationIsRecentDeduplicatedAndRateLimited() async {
        let suite = "endpoint-notification-tests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let sent = NoticeCounter()
        let start = Date(timeIntervalSince1970: 1_000)
        let first = LocalEnforcementNotice(action: .blocked, occurredAt: start,
                                           approvedName: "Approved Tool", approvedURL: URL(string: "https://example.com/approved"))
        let notifier = EnforcementNotifications(defaults: defaults, now: { start.addingTimeInterval(10) },
                                                 deliver: { _ in await sent.record() })
        await notifier.presentIfNeeded(first)
        await notifier.presentIfNeeded(first)
        #expect(await sent.count == 1)

        // A new instance still knows about the delivered event after app restart.
        let restarted = EnforcementNotifications(defaults: defaults, now: { start.addingTimeInterval(11) },
                                                  deliver: { _ in await sent.record() })
        await restarted.presentIfNeeded(first)
        #expect(await sent.count == 1)
        let second = LocalEnforcementNotice(action: .stopped, occurredAt: start.addingTimeInterval(20),
                                            approvedName: nil, approvedURL: nil)
        await restarted.presentIfNeeded(second)
        #expect(await sent.count == 1)
        let later = EnforcementNotifications(defaults: defaults, now: { start.addingTimeInterval(72) },
                                              deliver: { _ in await sent.record() })
        await later.presentIfNeeded(second)
        #expect(await sent.count == 2)
    }

    @Test func staleNoticeIsNeverPresentedAsARecentBlock() async {
        let suite = "endpoint-notification-tests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let sent = NoticeCounter()
        let now = Date(timeIntervalSince1970: 1_000)
        let notifier = EnforcementNotifications(defaults: defaults, now: { now },
                                                 deliver: { _ in await sent.record() })
        await notifier.presentIfNeeded(LocalEnforcementNotice(action: .blocked,
            occurredAt: now.addingTimeInterval(-121), approvedName: nil, approvedURL: nil))
        #expect(await sent.count == 0)
    }

    @Test func notificationOnlyCarriesApprovedAlternative() {
        let notice = LocalEnforcementNotice(action: .blocked, occurredAt: Date(),
            approvedName: "Approved Tool", approvedURL: URL(string: "https://example.com/approved"))
        let content = EnforcementNotifications.content(for: notice)
        #expect(content.title == "App blocked by policy")
        #expect(content.body.contains("Approved Tool"))
        #expect(content.userInfo[EnforcementNotificationRouter.approvedURLKey] as? String == "https://example.com/approved")
        #expect(EnforcementNotificationRouter.safeApprovedURL("https://example.com/approved") != nil)
        #expect(EnforcementNotificationRouter.safeApprovedURL("https://user:password@example.com/") == nil)
        #expect(EnforcementNotificationRouter.safeApprovedURL("file:///tmp/bad") == nil)
        let unconfigured = EnforcementNotifications.content(for: LocalEnforcementNotice(
            action: .stopped, occurredAt: Date(), approvedName: nil, approvedURL: nil))
        #expect(unconfigured.body == "Contact your administrator for an approved alternative.")
        #expect(unconfigured.userInfo.isEmpty)
    }

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

private actor NoticeCounter {
    private(set) var count = 0
    func record() { count += 1 }
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
