import AppKit
import Foundation
import MerlinClientCore
import UserNotifications

/// Local best-effort guidance from the authenticated status snapshot. Notification
/// authorization and delivery remain under the signed-in user's macOS settings.
@MainActor
final class EnforcementNotifications {
    private static let lastEventKey = "endpoint.lastEnforcementNotificationEvent"
    private static let lastAttemptKey = "endpoint.lastEnforcementNotificationAttempt"
    private let defaults: UserDefaults
    private let now: @Sendable () -> Date
    private let deliver: @MainActor @Sendable (LocalEnforcementNotice) async -> Void

    init(defaults: UserDefaults = .standard, now: @escaping @Sendable () -> Date = Date.init,
         deliver: @escaping @MainActor @Sendable (LocalEnforcementNotice) async -> Void = EnforcementNotifications.deliverToSystem) {
        self.defaults = defaults
        self.now = now
        self.deliver = deliver
    }

    func presentIfNeeded(_ notice: LocalEnforcementNotice) async {
        let current = now()
        let age = current.timeIntervalSince(notice.occurredAt)
        // A cached collector notice can remain visible for an hour. A banner
        // should only describe an event that just happened.
        guard (0...120).contains(age) else { return }
        let event = "\(notice.action.rawValue):\(notice.occurredAt.timeIntervalSince1970)"
        guard defaults.string(forKey: Self.lastEventKey) != event else { return }
        if let last = defaults.object(forKey: Self.lastAttemptKey) as? Date,
           (0..<60).contains(current.timeIntervalSince(last)) { return }
        // Record before awaiting macOS authorization so concurrent refreshes,
        // app restarts, and denied notification permission do not prompt again.
        defaults.set(event, forKey: Self.lastEventKey)
        defaults.set(current, forKey: Self.lastAttemptKey)
        await deliver(notice)
    }

    private static func deliverToSystem(_ notice: LocalEnforcementNotice) async {
        let center = UNUserNotificationCenter.current()
        let settings = await center.notificationSettings()
        if settings.authorizationStatus == .notDetermined {
            guard (try? await center.requestAuthorization(options: [.alert])) == true else { return }
        } else {
            guard settings.authorizationStatus == .authorized ||
                    settings.authorizationStatus == .provisional else { return }
        }

        let content = content(for: notice)
        // The request contains no process path, command line, rule, or source app.
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        try? await center.add(request)
    }

    static func content(for notice: LocalEnforcementNotice) -> UNMutableNotificationContent {
        let content = UNMutableNotificationContent()
        content.title = notice.action == .blocked ? "App blocked by policy" : "App stopped by policy"
        if let name = notice.approvedName, let url = notice.approvedURL {
            content.body = "Your organization approved \(name) as an alternative."
            content.categoryIdentifier = EnforcementNotificationRouter.categoryID
            content.userInfo = [EnforcementNotificationRouter.approvedURLKey: url.absoluteString]
        } else {
            content.body = "Contact your administrator for an approved alternative."
        }
        return content
    }
}

final class EnforcementNotificationRouter: NSObject, UNUserNotificationCenterDelegate {
    @MainActor static let shared = EnforcementNotificationRouter()
    static let categoryID = "endpoint.approvedAlternative"
    static let actionID = "endpoint.openApprovedAlternative"
    static let approvedURLKey = "approvedURL"

    func install() {
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        let action = UNNotificationAction(identifier: Self.actionID, title: "Open approved tool")
        center.setNotificationCategories([
            UNNotificationCategory(identifier: Self.categoryID, actions: [action], intentIdentifiers: [])
        ])
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner])
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        defer { completionHandler() }
        guard response.actionIdentifier == Self.actionID,
              let raw = response.notification.request.content.userInfo[Self.approvedURLKey] as? String,
              let url = Self.safeApprovedURL(raw) else { return }
        Task { @MainActor in NSWorkspace.shared.open(url) }
    }

    static func safeApprovedURL(_ raw: String) -> URL? {
        guard raw.utf8.count <= 2048, let url = URL(string: raw),
              url.scheme == "https", url.host != nil,
              url.user == nil, url.password == nil,
              url.query == nil, url.fragment == nil else { return nil }
        return url
    }
}
