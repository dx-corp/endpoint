import AppKit
import SwiftUI

@main
struct MerlinEndpointApp: App {
    @NSApplicationDelegateAdaptor(EndpointAppDelegate.self) private var appDelegate
    @StateObject private var session = EndpointSessionModel()
    @StateObject private var updater = EndpointUpdaterModel()

    var body: some Scene {
        // The primary scene presents device details on launch, including a fresh install.
        Window("Deixic Endpoint", id: "device-details") {
            EndpointDetailView(model: appDelegate.model, session: session, updater: updater)
        }
        .defaultSize(width: 700, height: 680)
        .windowResizability(.contentMinSize)

        MenuBarExtra {
            EndpointPopover(model: appDelegate.model, session: session, updater: updater)
        } label: {
            EndpointMenuBarLabel(model: appDelegate.model)
        }
        .menuBarExtraStyle(.window)

    }
}

private struct EndpointMenuBarLabel: View {
    @ObservedObject var model: EndpointAppModel

    var body: some View {
        Label("Deixic Endpoint", systemImage: model.status?.enforcement == nil
            ? "shield.lefthalf.filled" : "exclamationmark.shield.fill")
    }
}

@MainActor
final class EndpointAppDelegate: NSObject, NSApplicationDelegate {
    let model: EndpointAppModel
    private let installNotifications: () -> Void
    private var monitorTask: Task<Void, Never>?

    override convenience init() {
        self.init(model: EndpointAppModel(),
                  installNotifications: { EnforcementNotificationRouter.shared.install() })
    }

    init(model: EndpointAppModel, installNotifications: @escaping () -> Void) {
        self.model = model
        self.installNotifications = installNotifications
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        guard monitorTask == nil else { return }
        installNotifications()
        monitorTask = Task { [model] in await model.monitor() }
    }

    func applicationWillTerminate(_ notification: Notification) {
        monitorTask?.cancel()
        monitorTask = nil
    }
}

struct EndpointPopover: View {
    @ObservedObject var model: EndpointAppModel
    @ObservedObject var session: EndpointSessionModel
    @ObservedObject var updater: EndpointUpdaterModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.title2)
                    .foregroundStyle(.tint)
                Text("Deixic Endpoint").font(.headline)
                Spacer()
                if model.isRefreshing { ProgressView().controlSize(.small) }
            }
            TimelineView(.periodic(from: .now, by: 15)) { context in
                LocalStatusSummary(model: model, now: context.date, compact: true)
            }
            if let notice = model.status?.enforcement {
                Divider()
                EnforcementNoticeView(notice: notice)
            }
            Divider()
            EndpointSessionView(session: session, compact: true)
            Divider()
            HStack {
                Button("Device details") {
                    openWindow(id: "device-details")
                    NSApp.activate(ignoringOtherApps: true)
                }
                .keyboardShortcut("d")
                Spacer()
                Button {
                    Task { await model.refresh(); await session.refresh() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .accessibilityLabel("Refresh device and session status")
                .help("Refresh device and session status")
                .disabled(model.isRefreshing)
            }
            Button("Check for updates…") { updater.checkForUpdates() }
                .disabled(!updater.isAvailable)
            Button("Quit Deixic Endpoint") { NSApp.terminate(nil) }
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(20)
        .frame(width: 360)
        .task { await session.monitor() }
    }
}
