// Posture: one-shot cheap detectors (event taps, proxy/DNS config) plus
// the SCDynamicStore config watcher.
//
// CGGetEventTapList is single-call keylogger surface: every installed
// CGEvent tap with owning pid, listener-vs-modifier, and enable state.
// It needs a GUI session context — verified on this host it works for
// our unprivileged user (6 taps visible); as a root daemon without a
// session it may see nothing or a restricted set (documented).
//
// SCDynamicStore requires no entitlement: proxy and DNS resolver
// changes are high-signal config telemetry ("attacker configured a
// system proxy" is otherwise nearly invisible).

import CoreGraphics
import Foundation
import SystemConfiguration

struct EventTapInfo: Equatable {
    var tappingPid: Int32
    var targetPid: Int32
    var listenOnly: Bool
    var enabled: Bool
    var eventsMask: UInt64
}

/// Installed event taps (empty without a GUI session).
func currentEventTaps() -> [EventTapInfo] {
    var taps = [CGEventTapInformation](repeating: CGEventTapInformation(), count: 64)
    var count: UInt32 = 0
    guard CGGetEventTapList(64, &taps, &count) == .success else { return [] }
    return (0 ..< Int(count)).map { i in
        let t = taps[i]
        return EventTapInfo(
            tappingPid: t.tappingProcess,
            targetPid: t.processBeingTapped,
            listenOnly: t.options == .listenOnly,
            enabled: t.enabled,
            eventsMask: t.eventsOfInterest
        )
    }
}

func summarizeProxies(_ dict: [String: Any]?) -> String {
    guard let dict else { return "no proxy configuration" }
    var parts: [String] = []
    if (dict["HTTPEnable"] as? NSNumber)?.boolValue == true {
        parts.append("http=\(dict["HTTPProxy"] ?? "?"):\(dict["HTTPPort"] ?? "?")")
    }
    if (dict["HTTPSEnable"] as? NSNumber)?.boolValue == true {
        parts.append("https=\(dict["HTTPSProxy"] ?? "?"):\(dict["HTTPSPort"] ?? "?")")
    }
    if (dict["SOCKSEnable"] as? NSNumber)?.boolValue == true {
        parts.append("socks=\(dict["SOCKSProxy"] ?? "?"):\(dict["SOCKSPort"] ?? "?")")
    }
    if let pac = dict["ProxyAutoConfigURLString"] as? String, !pac.isEmpty {
        parts.append("pac=\(pac)")
    }
    return parts.isEmpty ? "no proxies enabled" : parts.joined(separator: " ")
}

func summarizeDNS(_ dict: [String: Any]?) -> String {
    guard let servers = dict?["ServerAddresses"] as? [String], !servers.isEmpty else {
        return "no resolver addresses"
    }
    return "resolvers=\(servers.joined(separator: ","))"
}

/// Watched keys and their summaries.
let configWatchKeys = [
    "State:/Network/Global/Proxies",
    "State:/Network/Global/DNS",
    "State:/Network/Global/IPv4",
]

func configSummary(key: String, store: SCDynamicStore) -> String {
    let value = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any]
    if key.hasSuffix("Proxies") { return summarizeProxies(value) }
    if key.hasSuffix("DNS") { return summarizeDNS(value) }
    if let dict = value, let router = dict["Router"] as? String { return "router=\(router)" }
    return value.map { "\($0.keys.sorted().prefix(6).joined(separator: ","))" } ?? "key absent"
}

/// SCDynamicStore watcher: emits a `config` event when a watched key
/// changes (dispatch queue — no runloop needed).
final class ConfigWatcher: @unchecked Sendable {
    private let spool: SpoolWriter
    private var store: SCDynamicStore?
    private let queue = DispatchQueue(label: "merlin.config", qos: .utility)

    init(spool: SpoolWriter) {
        self.spool = spool
    }

    func start() throws {
        var context = SCDynamicStoreContext()
        context.info = Unmanaged.passUnretained(self).toOpaque()
        let callback: SCDynamicStoreCallBack = { _, keys, info in
            guard let info, let keys = keys as? [String] else { return }
            Unmanaged<ConfigWatcher>.fromOpaque(info).takeUnretainedValue().changed(keys: keys)
        }
        guard let store = SCDynamicStoreCreate(nil, "merlin-macos" as CFString, callback, &context) else {
            throw MerlinError.plain("SCDynamicStoreCreate failed")
        }
        guard SCDynamicStoreSetNotificationKeys(store, configWatchKeys as CFArray, nil) else {
            throw MerlinError.plain("SCDynamicStoreSetNotificationKeys failed")
        }
        guard SCDynamicStoreSetDispatchQueue(store, queue) else {
            throw MerlinError.plain("SCDynamicStoreSetDispatchQueue failed")
        }
        self.store = store
        merlinLog("info", "config watch: proxy/DNS/IPv4 via SCDynamicStore")
    }

    private func changed(keys: [String]) {
        guard let store else { return }
        for key in keys where configWatchKeys.contains(key) {
            let summary = configSummary(key: key, store: store)
            merlinLog("info", "config change: \(key) → \(summary)")
            spool.write(SpoolEvent(kind: .config, key: key, summary: summary))
        }
    }

    func stop() {
        if let store { SCDynamicStoreSetDispatchQueue(store, nil) }
        store = nil
    }
}

/// One-shot posture report lives in PostureSweep.swift (runPosture
/// with json/verbose); event-tap and SCDynamicStore helpers stay here.
