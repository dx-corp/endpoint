import AppKit
import MerlinClientCore
import SwiftUI

struct EndpointDetailView: View {
    @ObservedObject var model: EndpointAppModel
    @ObservedObject var session: EndpointSessionModel
    @ObservedObject var updater: EndpointUpdaterModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Device health").font(.largeTitle.bold())
                        Text("Deixic Endpoint").foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button {
                        Task { await model.refresh(); await session.refresh() }
                    } label: {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                    .disabled(model.isRefreshing)
                }
                GroupBox {
                    TimelineView(.periodic(from: .now, by: 15)) { context in
                        LocalStatusSummary(model: model, now: context.date).padding(12)
                    }
                }
                GroupBox {
                    EndpointSessionView(session: session).padding(12)
                }
                if let status = model.status {
                    if let notice = status.enforcement {
                        GroupBox { EnforcementNoticeView(notice: notice).padding(12) }
                    }
                    reportingSection(status)
                    TimelineView(.periodic(from: .now, by: 15)) { context in
                        checksSection(status, stale: status.isStale(at: context.date) || !status.collectorRunning)
                    }
                }
                Link(destination: URL(string: "https://merlin.dx-corp.net/")!) {
                    Label("Open fleet administration", systemImage: "arrow.up.right.square")
                }
                Text("Fleet access is checked by your organization when you open the web app.")
                    .font(.caption).foregroundStyle(.secondary)
                Divider()
                HStack {
                    Text(updater.status).font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button("Check for updates…") { updater.checkForUpdates() }
                        .disabled(!updater.isAvailable)
                }
            }
            .padding(28)
            .frame(maxWidth: 860)
            .frame(maxWidth: .infinity)
        }
        .frame(minWidth: 560, minHeight: 480)
        .task { await session.monitor() }
        .task { await model.monitor() }
    }

    private func reportingSection(_ status: LocalDeviceStatus) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                Text("ENROLLMENT & REPORTING").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                switch status.enrollment {
                case .unconfigured:
                    Label("Enrollment not configured", systemImage: "desktopcomputer.badge.exclamationmark")
                    Text("Contact IT to enroll this Mac and enable device reporting.")
                case .configured:
                    Label("Device reporting configured", systemImage: "desktopcomputer")
                    Text("Configuration alone does not confirm this Mac’s enrollment or current server health.")
                case .rejected:
                    Label("Device credentials rejected", systemImage: "exclamationmark.triangle")
                    Text("Contact IT to restore this Mac’s enrollment.")
                }
                if let lastContact = status.lastServerContact {
                    LabeledContent("Last server contact", value: lastContact.formatted(date: .abbreviated, time: .shortened))
                } else {
                    LabeledContent("Last server contact", value: "No successful contact recorded")
                }
                Text("Local checks describe this Mac’s last observation. Server contact records a successful check-in; server posture freshness is unavailable here.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .font(.callout)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(12)
        }
    }

    private func checksSection(_ status: LocalDeviceStatus, stale: Bool) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Local posture checks").font(.title3.weight(.semibold))
            if stale {
                Text("These checks are from the last observation and may have changed.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            if status.checks.isEmpty {
                Text("No posture checks are available.").foregroundStyle(.secondary)
            } else {
                ForEach(status.checks.sorted { $0.id < $1.id }, id: \.id) { check in
                    PostureCheckRow(check: check, stale: stale)
                    Divider()
                }
            }
        }
    }
}

struct EnforcementNoticeView: View {
    let notice: LocalEnforcementNotice

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(notice.action == .blocked ? "App blocked by policy" : "App stopped by policy",
                  systemImage: "exclamationmark.shield.fill")
                .font(.headline)
            Text("Deixic Endpoint applied your organization's device policy at \(notice.occurredAt.formatted(date: .abbreviated, time: .shortened)).")
                .font(.callout)
            if let name = notice.approvedName, let url = notice.approvedURL {
                Link("Use approved tool: \(name)", destination: url)
                    .font(.callout)
                Text("Your administrator configured this alternative.")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                Text("Contact your administrator for an approved alternative.")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct PostureCheckRow: View {
    let check: LocalPostureCheck
    let stale: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(title).font(.body.weight(.medium))
                Spacer()
                Label(stale ? "Last: \(stateLabel)" : stateLabel, systemImage: stale ? "clock" : stateIcon)
                    .foregroundStyle(stale ? .secondary : stateColor)
            }
            if check.status != .pass {
                Text(remediation).font(.callout).foregroundStyle(.secondary)
                if settingsCheck {
                    Button("Open System Settings") {
                        NSWorkspace.shared.open(URL(fileURLWithPath: "/System/Applications/System Settings.app"))
                    }
                    .font(.callout)
                }
            }
        }
        .padding(.vertical, 6)
        .accessibilityElement(children: .contain)
    }

    private var title: String {
        ["filevault": "FileVault", "sip": "System Integrity Protection", "gatekeeper": "Gatekeeper",
         "firewall": "Firewall", "software_updates": "Software updates", "mdm": "Device management",
         "authenticated_root": "Signed system volume", "secure_boot": "Secure Boot",
         "tcc": "Privacy permissions", "sysext": "System extensions"][check.id]
            ?? check.id.replacingOccurrences(of: "_", with: " ").capitalized
    }

    private var stateLabel: String {
        switch check.status {
        case .pass: return "Passing"
        case .finding: return "Needs attention"
        case .unknown: return "Unknown"
        case .unavailable: return "Unavailable"
        case .requiresRoot: return "Collector access required"
        }
    }

    private var stateIcon: String {
        switch check.status {
        case .pass: return "checkmark.circle"
        case .finding: return "exclamationmark.circle"
        case .unknown, .unavailable, .requiresRoot: return "questionmark.circle"
        }
    }

    private var stateColor: Color {
        switch check.status {
        case .pass: return .green
        case .finding: return .orange
        case .unknown, .unavailable, .requiresRoot: return .secondary
        }
    }

    private var settingsCheck: Bool {
        check.status == .finding && ["filevault", "firewall", "software_updates", "gatekeeper"].contains(check.id)
    }

    private var remediation: String {
        guard check.status == .finding else {
            return "The collector could not determine this check. Refresh, or contact IT if it remains unavailable."
        }
        switch check.id {
        case "filevault": return "Review FileVault in System Settings → Privacy & Security. Follow your organization’s recovery-key policy."
        case "firewall": return "Review Firewall in System Settings → Network. Follow your organization’s firewall policy."
        case "software_updates": return "Check System Settings → General → Software Update for available updates."
        case "gatekeeper": return "Review app security in System Settings → Privacy & Security."
        default: return "Contact IT to review this finding and the required remediation."
        }
    }
}
