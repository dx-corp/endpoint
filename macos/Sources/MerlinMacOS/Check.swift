// `merlin-macos check` — readiness probe, same role as the Linux port's
// check subcommand: report privilege/provider problems plainly rather than
// failing obscurely at run time.

import Foundation

@preconcurrency import EndpointSecurity

func runCheck(json: Bool = false) -> Int32 {
    if !json { print("merlin-macos check") }
    let root = geteuid() == 0
    var capabilities: [[String: String]] = []
    func record(_ capability: String, _ pass: Bool, _ reason: String, status: String? = nil) {
        let state = status ?? (pass ? "pass" : "fail")
        capabilities.append(["capability": capability, "status": state, "reason": reason])
        if !json { print("\(capability): \(state) (\(reason))") }
    }
    if !json {
        print("root: \(root ? "yes" : "no — ES and BSM providers need root; the kqueue provider works unprivileged (cross-user enrichment limited)")")
    }
    record("privileged_runtime", root, root ? "root available for ES/BSM and cross-user enrichment" : "kqueue remains available; ES/BSM and cross-user enrichment are limited")

    var anyProvider = false

    // Endpoint Security: creating a client is the definitive entitlement
    // probe — without a granted com.apple.developer.endpoint-security.client
    // entitlement this returns ERR_NOT_ENTITLED.
    var client: OpaquePointer?
    let result = es_new_client(&client) { _, _ in }
    if result == ES_NEW_CLIENT_RESULT_SUCCESS {
        record("endpoint_security", true, "client entitlement honored; ES provider available")
        if let c = client { es_delete_client(c) }
        anyProvider = true
    } else {
        record("endpoint_security", false, describeNewClientResult(result), status: "warn")
        if !root, result != ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED {
            if !json { print("  note: unprivileged probe may be inconclusive; re-run with sudo") }
        }
    }

    // kqueue: EVFILT_PROC needs no entitlement and no root — it is always
    // viable. Root only widens visibility: without it, cross-user
    // enrichment (proc_pidpath, KERN_PROCARGS2) and kill enforcement fail.
    let kq = Darwin.kqueue()
    if kq >= 0 {
        close(kq)
        record("kqueue", true, "EVFILT_PROC available (\(root ? "full cross-user visibility" : "own-process visibility; other users may be bare pid events"))")
        anyProvider = true
    } else {
        record("kqueue", false, "kqueue() failed (errno \(errno))")
    }

    // OpenBSM: praudit + a readable /dev/auditpipe. Deprecated since macOS
    // 11, disabled since macOS 14 (man audit) — the daemon runs on macOS 27
    // but emits zero exec records; last-resort provider for older systems.
    let fm = FileManager.default
    let praudit = fm.isExecutableFile(atPath: "/usr/sbin/praudit")
    let pipeExists = fm.fileExists(atPath: "/dev/auditpipe")
    let pipeReadable = fm.isReadableFile(atPath: "/dev/auditpipe")
    record("openbsm_binary", praudit, praudit ? "praudit present" : "praudit missing", status: praudit ? "pass" : "warn")
    if pipeExists {
        record("openbsm_auditpipe", pipeReadable, pipeReadable ? "readable; BSM telemetry available (legacy/inert on newer macOS)" : "present but not readable (needs root)", status: pipeReadable ? "warn" : "warn")
    } else {
        record("openbsm_auditpipe", false, "auditpipe absent; auditd may not be running", status: "warn")
    }
    if praudit, pipeReadable { anyProvider = true }

    // Network telemetry (orthogonal to process providers): /dev/bpf.
    let bpfReadable = fm.isReadableFile(atPath: "/dev/bpf0")
    record("bpf_network", bpfReadable, bpfReadable ? "network telemetry available (--network pktap|bpf)" : "not readable; network telemetry is optional", status: bpfReadable ? "pass" : "warn")

    // Cheap detectors: installed event taps (keylogger surface).
    let taps = currentEventTaps()
    record("event_taps", true, "\(taps.count) event tap(s) installed in this session (merlin-macos posture for detail)", status: taps.count > 12 ? "warn" : "pass")
    let networkExtension = networkExtensionCapability()
    record(
        "network_extension",
        false,
        networkExtension.reason,
        status: networkExtension.state == "installed" ? "pass" : "warn"
    )
    record("fleet_health", true, "periodic health events expose provider capabilities and spool loss counters")

    if json {
        let object: [String: Any] = [
            "ready": anyProvider,
            "platform": "macos",
            "capabilities": capabilities,
        ]
        if let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]),
           let output = String(data: data, encoding: .utf8) {
            print(output)
        }
    } else {
        print("verdict: \(anyProvider ? "at least one provider available" : "no provider available — see above")")
    }
    return anyProvider ? 0 : 1
}
