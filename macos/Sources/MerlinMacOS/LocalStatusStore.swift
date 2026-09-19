import Foundation
import MerlinClientCore

/// An in-memory projection of the existing collector report; never a new posture
/// authority. The same cached report feeds heartbeat and GUI, avoiding extra sweeps.
final class LocalStatusStore: @unchecked Sendable {
    private let lock = NSLock()
    private let collectionLock = NSLock()
    private var report: DevicePostureReport?
    private var deviceID: String?
    private var enrollment: LocalEnrollmentState = .unconfigured
    private var lastServerContact: Date?

    func configure(deviceID: String?) {
        lock.withLock {
            self.deviceID = deviceID
            enrollment = deviceID == nil ? .unconfigured : .configured
        }
    }

    func recordServerResponse(status: Int, at now: Date = Date()) {
        lock.withLock {
            if status == 200 {
                lastServerContact = now
                enrollment = deviceID == nil ? .unconfigured : .configured
            } else if status == 401 || status == 403 {
                enrollment = .rejected
            }
        }
    }

    func publish(_ report: DevicePostureReport) {
        lock.withLock { self.report = report }
    }

    func currentPostureReport() -> DevicePostureReport {
        collectionLock.withLock {
            if let existing = lock.withLock({ report }),
               let seconds = Double(existing.collectedAt),
               (0..<LocalDeviceStatus.maxAge).contains(Date().timeIntervalSince1970 - seconds) {
                return existing
            }
            let next = makeDevicePostureReport(snapshot: capturePosture())
            publish(next)
            return next
        }
    }

    func snapshot() -> LocalDeviceStatus {
        lock.withLock {
            let checks = LocalDeviceStatus.checkIDs.map { id -> LocalPostureCheck in
                let state: LocalPostureCheckState
                switch report?.checks[id]?.status {
                case "pass": state = .pass
                case "finding": state = .finding
                case "unavailable": state = .unavailable
                case "requires_root": state = .requiresRoot
                default: state = .unknown
                }
                return LocalPostureCheck(id: id, status: state)
            }
            // Missing/unknown checks must not turn into a reassuring green result.
            let summary: LocalPostureSummary
            if report?.overall == "at_risk" { summary = .atRisk }
            else if report?.overall == "degraded" || checks.contains(where: { $0.status == .finding }) { summary = .degraded }
            else if report?.overall == "secure" && checks.allSatisfy({ $0.status == .pass }) { summary = .secure }
            else { summary = .unknown }
            let safeID = deviceID.flatMap { value -> String? in
                guard value.utf8.count <= 128,
                      value.unicodeScalars.allSatisfy({ CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_")).contains($0) }) else { return nil }
                return value
            }
            return LocalDeviceStatus(
                observedAt: report.flatMap { Double($0.collectedAt) }.map(Date.init(timeIntervalSince1970:)) ?? .distantPast,
                deviceID: safeID, collectorRunning: true, enrollment: enrollment,
                posture: summary, checks: checks, lastServerContact: lastServerContact)
        }
    }
}
