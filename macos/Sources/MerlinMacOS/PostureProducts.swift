// Product-presence checks (endpoint_protection, password_manager,
// remote_access). Product lists are fixed and reviewed in code; reports
// carry product names only, never paths, user names or raw output.
// Matching is pure over already-collected inventories so tests need no root.

import Foundation

struct ProductSignature: Equatable {
    var name: String
    /// Exact CFBundleIdentifier values of /Applications bundles.
    var bundleIds: [String] = []
    /// App bundle file names (without .app) for vendors that vary bundle ids.
    var appNames: [String] = []
    /// System extension bundle id prefixes (active ones count as running).
    var sysextPrefixes: [String] = []
    /// Loaded launchd label prefixes (count as running / enabled).
    var labelPrefixes: [String] = []
}

struct InstalledApp: Equatable {
    var bundleId: String?
    var name: String
}

let endpointProtectionCatalog: [ProductSignature] = [
    ProductSignature(name: "CrowdStrike Falcon", bundleIds: ["com.crowdstrike.falcon.App"],
                     sysextPrefixes: ["com.crowdstrike.falcon"], labelPrefixes: ["com.crowdstrike.falcon"]),
    ProductSignature(name: "SentinelOne", bundleIds: ["com.sentinelone.sentinel-agent"],
                     sysextPrefixes: ["com.sentinelone"], labelPrefixes: ["com.sentinelone"]),
    ProductSignature(name: "Microsoft Defender", bundleIds: ["com.microsoft.wdav"],
                     sysextPrefixes: ["com.microsoft.wdav"], labelPrefixes: ["com.microsoft.fresno", "com.microsoft.wdav"]),
    ProductSignature(name: "Jamf Protect", bundleIds: ["com.jamf.protect"],
                     sysextPrefixes: ["com.jamf.protect"], labelPrefixes: ["com.jamf.protect"]),
    ProductSignature(name: "Sophos", appNames: ["Sophos Endpoint"],
                     sysextPrefixes: ["com.sophos"], labelPrefixes: ["com.sophos"]),
    ProductSignature(name: "Carbon Black", bundleIds: ["com.vmware.carbonblack.cloud.se-agent"],
                     sysextPrefixes: ["com.vmware.carbonblack", "com.carbonblack"],
                     labelPrefixes: ["com.vmware.carbonblack", "com.carbonblack"]),
    ProductSignature(name: "Elastic Endpoint", sysextPrefixes: ["co.elastic"], labelPrefixes: ["co.elastic.endpoint"]),
    ProductSignature(name: "Malwarebytes", bundleIds: ["com.malwarebytes.mbam.frontend.application"],
                     sysextPrefixes: ["com.malwarebytes"], labelPrefixes: ["com.malwarebytes"]),
]

let passwordManagerCatalog: [ProductSignature] = [
    ProductSignature(name: "1Password", bundleIds: ["com.1password.1password", "com.agilebits.onepassword7", "com.agilebits.onepassword-osx"], appNames: ["1Password"]),
    ProductSignature(name: "Bitwarden", bundleIds: ["com.bitwarden.desktop"], appNames: ["Bitwarden"]),
    ProductSignature(name: "Dashlane", bundleIds: ["com.dashlane.dashlanephonefinal", "com.dashlane.Dashlane"], appNames: ["Dashlane"]),
    ProductSignature(name: "Keeper", bundleIds: ["com.callpod.keepermac.lite", "com.keepersecurity.desktop"], appNames: ["Keeper Password Manager"]),
    ProductSignature(name: "LastPass", bundleIds: ["com.lastpass.lastpassmacdesktop"], appNames: ["LastPass"]),
    ProductSignature(name: "Proton Pass", bundleIds: ["me.proton.pass.electron"], appNames: ["Proton Pass"]),
    ProductSignature(name: "Enpass", bundleIds: ["in.sinew.Enpass-Desktop"], appNames: ["Enpass"]),
    ProductSignature(name: "NordPass", bundleIds: ["com.nordsec.nordpass"], appNames: ["NordPass"]),
]

/// Third-party remote access tools. Built-in macOS services are handled
/// separately by `builtinRemoteAccess`.
let remoteAccessCatalog: [ProductSignature] = [
    ProductSignature(name: "TeamViewer", bundleIds: ["com.teamviewer.TeamViewer"], appNames: ["TeamViewer"],
                     labelPrefixes: ["com.teamviewer"]),
    ProductSignature(name: "AnyDesk", bundleIds: ["com.philandro.anydesk"], appNames: ["AnyDesk"],
                     labelPrefixes: ["com.philandro.anydesk"]),
    ProductSignature(name: "Splashtop", appNames: ["Splashtop Streamer", "Splashtop Business"],
                     labelPrefixes: ["com.splashtop"]),
    ProductSignature(name: "LogMeIn", appNames: ["LogMeIn Client", "LogMeIn Host"], labelPrefixes: ["com.logmein"]),
    ProductSignature(name: "RealVNC", appNames: ["VNC Server", "VNC Viewer"], labelPrefixes: ["com.realvnc"]),
    ProductSignature(name: "Chrome Remote Desktop", appNames: ["Chrome Remote Desktop Host Uninstaller"],
                     labelPrefixes: ["org.chromium.chromoting"]),
]

/// Built-in macOS remote access services: display name → loaded launchd label.
let builtinRemoteServices: [(name: String, label: String)] = [
    ("Screen Sharing", "com.apple.screensharing"),
    ("Remote Management", "com.apple.RemoteDesktop.agent"),
    ("Remote Login", "com.openssh.sshd"),
]

/// Labels from `launchctl list` (PID, status, label columns; header first).
func parseLaunchctlListLabels(_ out: String) -> [String] {
    out.split(separator: "\n").dropFirst().compactMap { line in
        let cols = line.split(separator: "\t", omittingEmptySubsequences: true)
        return cols.count >= 3 ? String(cols[2]) : nil
    }
}

func installedMatches(_ catalog: [ProductSignature], apps: [InstalledApp]) -> [String] {
    catalog.filter { sig in
        apps.contains { app in
            (app.bundleId.map(sig.bundleIds.contains) ?? false) || sig.appNames.contains(app.name)
        }
    }.map(\.name).sorted()
}

/// Products with an active system extension or a loaded launchd label.
func runningMatches(_ catalog: [ProductSignature], sysext: [SysexEntry], labels: [String]) -> [String] {
    catalog.filter { sig in
        sysext.contains { e in
            e.state.contains("activated enabled") && sig.sysextPrefixes.contains { e.bundleId.hasPrefix($0) }
        } || labels.contains { l in sig.labelPrefixes.contains { l.hasPrefix($0) } }
    }.map(\.name).sorted()
}

func builtinRemoteAccess(labels: [String]) -> [String] {
    builtinRemoteServices.filter { labels.contains($0.label) }.map(\.name)
}

/// Value for list-style checks: comma-separated names or "none".
func productListValue(_ names: [String]) -> String {
    names.isEmpty ? "none" : names.joined(separator: ", ")
}

/// One level of `*.app` bundles in the given directories; bounded.
func listInstalledApps(dirs: [String] = ["/Applications", "/Applications/Utilities"], limit: Int = 2000) -> [InstalledApp] {
    var out: [InstalledApp] = []
    for dir in dirs {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: dir) else { continue }
        for n in names where n.hasSuffix(".app") {
            if out.count >= limit { return out }
            let plist = "\(dir)/\(n)/Contents/Info.plist"
            var id: String?
            if let data = FileManager.default.contents(atPath: plist),
               let obj = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] {
                id = obj["CFBundleIdentifier"] as? String
            }
            out.append(InstalledApp(bundleId: id, name: String(n.dropLast(4))))
        }
    }
    return out
}

/// Fills the three product checks. Unreadable sources report "unavailable".
func capturePostureProducts(into snap: inout PostureSnapshot) {
    let apps = listInstalledApps()
    let labelsOut = shellOut("/bin/launchctl", ["list"], timeout: 3)
    let labels = labelsOut.map { parseLaunchctlListLabels($0.stdout) }
    let sysext = shellOut("/usr/bin/systemextensionsctl", ["list"], timeout: 3).map { parseSysextList($0.stdout) }

    if labels == nil && sysext == nil {
        snap.values["endpoint_protection"] = "unavailable"
    } else {
        let names = runningMatches(endpointProtectionCatalog, sysext: sysext ?? [], labels: labels ?? [])
        snap.values["endpoint_protection"] = productListValue(names)
        if names.isEmpty { snap.findings["endpoint_protection"] = "No known endpoint protection product is running" }
    }

    let managers = installedMatches(passwordManagerCatalog, apps: apps)
    snap.values["password_manager"] = productListValue(managers)
    if managers.isEmpty { snap.findings["password_manager"] = "No known password manager is installed" }

    if let labels {
        let names = (builtinRemoteAccess(labels: labels)
            + Set(installedMatches(remoteAccessCatalog, apps: apps))
                .union(runningMatches(remoteAccessCatalog, sysext: [], labels: labels)).sorted())
        snap.values["remote_access"] = productListValue(names)
        if !names.isEmpty { snap.findings["remote_access"] = "Remote access enabled or installed: \(names.joined(separator: ", "))" }
    } else {
        snap.values["remote_access"] = "unavailable"
    }
}
