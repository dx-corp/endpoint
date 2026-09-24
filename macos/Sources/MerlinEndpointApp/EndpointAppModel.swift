import Combine
import Foundation
import MerlinClientCore

/// Holds a read-only snapshot from the authenticated collector connection.
@MainActor
final class EndpointAppModel: ObservableObject {
    @Published private(set) var status: LocalDeviceStatus?
    @Published private(set) var isRefreshing = false
    @Published private(set) var readFailed = false

    private let readStatus: @Sendable () async throws -> LocalDeviceStatus
    private let notifications: EnforcementNotifications

    init(readStatus: @escaping @Sendable () async throws -> LocalDeviceStatus = {
        try await LocalStatusClient().readStatus()
    }, notifications: EnforcementNotifications = EnforcementNotifications()) {
        self.readStatus = readStatus
        self.notifications = notifications
    }

    func refresh() async {
        guard !isRefreshing else { return }
        isRefreshing = true
        defer { isRefreshing = false }
        do {
            let current = try await readStatus()
            status = current
            readFailed = false
            if let notice = current.enforcement {
                Task { [notifications] in await notifications.presentIfNeeded(notice) }
            }
        } catch {
            // A previously successful read cannot establish current collector health.
            status = nil
            readFailed = true
        }
    }

    func monitor() async {
        while !Task.isCancelled {
            await refresh()
            do {
                try await Task.sleep(for: .seconds(30))
            } catch {
                return
            }
        }
    }
}
