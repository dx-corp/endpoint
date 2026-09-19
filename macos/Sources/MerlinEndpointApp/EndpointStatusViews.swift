import MerlinClientCore
import SwiftUI

enum EndpointSessionFreshness {
    static func isCurrent(lastVerifiedAt: Date, now: Date) -> Bool {
        let age = now.timeIntervalSince(lastVerifiedAt)
        return age >= 0 && age <= 120
    }
}

struct LocalStatusSummary: View {
    @ObservedObject var model: EndpointAppModel
    let now: Date
    var compact = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("THIS MAC").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            if let status = model.status {
                Label(postureTitle(status), systemImage: postureIcon(status))
                    .font(compact ? .headline : .title2.weight(.semibold))
                    .foregroundStyle(postureColor(status))
                Text("Local observation · \(status.observedAt.formatted(date: .abbreviated, time: .shortened))")
                    .font(.caption).foregroundStyle(.secondary)
                if status.isStale(at: now) {
                    Text("The last observation is out of date. Refresh to check the collector.")
                        .font(.callout)
                }
                if !status.collectorRunning {
                    Text("The collector is stopped. Contact IT to restore collection.").font(.callout)
                }
            } else if model.readFailed {
                Label("Collector unavailable", systemImage: "questionmark.circle")
                    .font(.headline)
                Text("Check that Deixic Endpoint is installed and running, then refresh.")
                    .font(.callout).foregroundStyle(.secondary)
            } else {
                Label("Reading device status…", systemImage: "clock")
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func postureTitle(_ status: LocalDeviceStatus) -> String {
        if !status.collectorRunning { return "Collector stopped" }
        if status.isStale(at: now) { return "Posture stale" }
        switch status.posture {
        case .secure: return "Local checks passing"
        case .degraded: return "Needs attention"
        case .atRisk: return "Device at risk"
        case .unknown: return "Posture unknown"
        }
    }

    private func postureIcon(_ status: LocalDeviceStatus) -> String {
        if !status.collectorRunning { return "pause.circle" }
        if status.isStale(at: now) { return "clock.badge.exclamationmark" }
        switch status.posture {
        case .secure: return "checkmark.shield"
        case .degraded, .atRisk: return "exclamationmark.shield"
        case .unknown: return "questionmark.circle"
        }
    }

    private func postureColor(_ status: LocalDeviceStatus) -> Color {
        if !status.collectorRunning || status.isStale(at: now) { return .orange }
        switch status.posture {
        case .secure: return .green
        case .degraded: return .orange
        case .atRisk: return .red
        case .unknown: return .secondary
        }
    }
}

struct EndpointSessionView: View {
    @ObservedObject var session: EndpointSessionModel
    var compact = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("IDENTITY SESSION").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            switch session.state {
            case .signedOut:
                Text("Signed out").font(.headline)
                Text("Sign in with your organization account.").font(.callout).foregroundStyle(.secondary)
                signInButton
            case .signingIn:
                HStack { ProgressView().controlSize(.small); Text("Waiting for sign-in…") }
            case .signedIn(let identity):
                TimelineView(.periodic(from: .now, by: 15)) { context in
                    VStack(alignment: .leading, spacing: 6) {
                        if identity.expiresAt <= context.date {
                            Label("Session expired", systemImage: "clock.badge.exclamationmark")
                            signInButton
                        } else if !EndpointSessionFreshness.isCurrent(lastVerifiedAt: identity.lastVerifiedAt, now: context.date) {
                            Label("Session verification is stale", systemImage: "clock")
                                .font(.headline).foregroundStyle(.secondary)
                            Text("Last verified \(identity.lastVerifiedAt.formatted(date: .abbreviated, time: .shortened))")
                                .foregroundStyle(.secondary)
                            Button("Verify session") { Task { await session.refresh() } }
                        } else {
                            Label(identity.displayName ?? identity.email ?? "Signed in", systemImage: "person.crop.circle")
                                .font(.headline)
                            if let email = identity.email, email != identity.displayName {
                                Text(email).font(.callout).textSelection(.enabled)
                            }
                            if !compact {
                                LabeledContent("Account ID", value: identity.subject)
                                    .textSelection(.enabled)
                                Text("Expires \(identity.expiresAt.formatted(date: .abbreviated, time: .shortened))")
                                Text("Verified \(identity.lastVerifiedAt.formatted(date: .abbreviated, time: .shortened))")
                            }
                        }
                    }
                    .font(.caption)
                }
                Button("Sign out") { Task { await session.signOut() } }
            case .unavailable(let message):
                Label("Sign-in unavailable", systemImage: "person.crop.circle.badge.exclamationmark")
                    .font(.headline)
                Text(message).font(.callout).foregroundStyle(.secondary)
                signInButton
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var signInButton: some View {
        Button("Sign in with SSO") { Task { await session.signIn() } }
    }
}
