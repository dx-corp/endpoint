import Foundation

/// NetworkExtension is an optional packaged system-extension path. The
/// SwiftPM sensor can report the boundary and advertise the capability, but
/// it cannot install or impersonate an NEFilterDataProvider without an
/// app-extension bundle, entitlement, provisioning profile, and user approval.
struct NetworkExtensionCapability: Sendable {
    let state: String
    let flowAttribution: Bool
    let blocking: Bool
    let reason: String
}

func networkExtensionCapability() -> NetworkExtensionCapability {
    NetworkExtensionCapability(
        state: "not_configured",
        flowAttribution: true,
        blocking: true,
        reason: "optional NEFilterDataProvider system extension requires a separately signed and approved app-extension bundle"
    )
}
