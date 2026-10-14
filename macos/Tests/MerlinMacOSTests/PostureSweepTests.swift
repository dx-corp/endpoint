import Foundation
import Testing
@testable import MerlinMacOS

// Posture sweep tests — parsers on fixtures, hook extraction, unsigned
// launchd flagging, drift diff. Shell-outs themselves are not tested
// (pure functions over fixture strings).

@Suite("posture parsers")
struct PostureParserTests {
    @Test("integrity parsers")
    func integrity() {
        #expect(parseCsrutil("System Integrity Protection status: enabled.") == "enabled")
        #expect(parseCsrutil("System Integrity Protection status: disabled.") == "disabled")
        #expect(parseCsrutil("System Integrity Protection Status: ENABLED.") == "enabled")
        #expect(parseCsrutil("garbage") == "unknown")
        #expect(parseSpctl("assessments enabled") == "enabled")
        #expect(parseSpctl("assessments disabled") == "disabled")
        #expect(parseSpctl("Assessments ENABLED") == "enabled")
        #expect(parseFdesetup("FileVault is On.") == "on")
        #expect(parseFdesetup("FileVault is Off.") == "off")
        #expect(parseFdesetup("FILEVAULT IS OFF.") == "off")
        #expect(parseFirewall("Firewall is enabled") == "enabled")
        #expect(parseFirewall("Firewall is disabled") == "disabled")
        #expect(parseFirewallRuleCount("ALF: /Applications/A\nAllow /Applications/B") == "2 application rule(s)")
        #expect(parseSecureBoot("Secure Boot: Full Security") == "full")
        #expect(parseSecureBoot("Secure Boot: Reduced Security") == "reduced")
        #expect(parseMDMEnrollment("MDM enrollment: Yes") == "enrolled")
        #expect(parseMDMEnrollment("MDM enrollment: No") == "not enrolled")
        #expect(parseSoftwareUpdate("No new software available.") == "none available")
        #expect(parseSoftwareUpdate("* Label: macOS Security Update\n") == "1 update(s) available")
        #expect(parseBootArgs("boot-args\tamfi_get_out_of_my_way debug=0x144").risky.contains("amfi_get_out_of_my_way"))
        #expect(parseTCCAccess(exists: true, readable: false) == "protected")
    }

    @Test("sysext list parses real tailscale-style rows")
    func sysext() {
        let fixture = """
        3 extension(s)
        --- com.apple.system_extension.network_extension (Go to 'System Settings' to modify)
        enabled\tactive\tteamID\tbundleID (version)\tname\t[state]
        *\t*\tW5364U7YZB\tio.tailscale.ipn.macsys.network-extension (1.103.9/101.103.9)\tTailscale Network Extension\t[activated enabled]
        \t\tW5364U7YZB\tio.tailscale.ipn.macsys.network-extension (1.101.284/101.101.284)\tTailscale Network Extension\t[terminated waiting to uninstall on reboot]
        """
        let entries = parseSysextList(fixture)
        #expect(entries.count == 2)
        #expect(entries[0].teamId == "W5364U7YZB")
        #expect(entries[0].bundleId == "io.tailscale.ipn.macsys.network-extension")
        #expect(entries[0].name == "Tailscale Network Extension")
        #expect(entries[0].state == "[activated enabled]")
        #expect(entries[1].state == "[terminated waiting to uninstall on reboot]")
        #expect(parseSysextList("0 extension(s)").isEmpty)
    }

    @Test("profiles count and requires-root")
    func profiles() {
        #expect(parseProfiles("There are 2 configuration profiles installed", "").count == 2)
        #expect(parseProfiles("There are 0 configuration profiles installed", "").count == 0)
        let r = parseProfiles("", "profiles: this command requires root privileges")
        #expect(r.count == nil)
        #expect(r.requiresRoot)
    }

    @Test("sysext findings: active non-expected flagged, expected/terminated not")
    func sysextFindingsTest() {
        let entries = [
            SysexEntry(teamId: "W5364U7YZB", bundleId: "io.tailscale.ipn.macsys.network-extension", name: "Tailscale", state: "[activated enabled]"),
            SysexEntry(teamId: "W5364U7YZB", bundleId: "io.tailscale.ipn.macsys.network-extension", name: "Tailscale", state: "[terminated waiting to uninstall on reboot]"),
            SysexEntry(teamId: "TEAMOTHER0", bundleId: "com.evil.ext", name: "Evil", state: "[activated enabled]"),
        ]
        let none = sysextFindings(entries: entries, expectedTeams: ["W5364U7YZB", "TEAMOTHER0"])
        #expect(none.isEmpty)
        let flagged = sysextFindings(entries: entries, expectedTeams: ["W5364U7YZB"])
        #expect(flagged.count == 1)
        #expect(flagged["sysext/com.evil.ext"]?.contains("Evil") == true)
    }
}

@Suite("posture report contract")
struct PostureReportTests {
    @Test("legacy snapshot becomes bounded risk-scored report")
    func report() throws {
        var snapshot = PostureSnapshot()
        snapshot.values = ["sip": "disabled", "filevault": "on", "firewall": "enabled"]
        snapshot.findings = ["sip": "SIP disabled"]
        snapshot.collectionDurationMs = 42
        let report = makeDevicePostureReport(snapshot: snapshot, root: false, networkExtension: "not_configured")
        #expect(report.schemaVersion == 2)
        #expect(report.overall == "degraded")
        #expect(report.riskScore == 25)
        #expect(report.findings.count == 1)
        #expect(report.checks["sip"]?.evidence.source == "security_tool")
        #expect(report.checks["sip"]?.evidence.evidenceHash.count == 64)
        #expect(report.checks["sip"]?.evidence.redactions.contains("raw_command_output") == true)
        #expect(report.coverage.root == false)
        #expect(report.coverage.checksWithEvidence == 3)
        #expect(report.coverage.collectionDurationMs == 42)
        let json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(report)) as? [String: Any]
        #expect(json?["schema_version"] as? Int == 2)
        #expect(json?["risk_score"] as? Int == 25)
        #expect(json?["findings"] is [[String: Any]])
    }
}

@Suite("launchd findings")
struct LaunchdFindingTests {
    private func plist(_ label: String, _ program: String) -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
          <key>Label</key><string>\(label)</string>
          <key>ProgramArguments</key><array><string>\(program)</string></array>
        </dict></plist>
        """
    }

    @Test("temp-path and unsigned programs flagged; signed system binaries clean")
    func findings() throws {
        let dir = NSTemporaryDirectory() + "merlin-posture-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        try plist("com.ok.zsh", "/bin/zsh").write(toFile: dir + "/ok.plist", atomically: true, encoding: .utf8)
        try plist("com.bad.tmp", "/private/tmp/evil").write(toFile: dir + "/tmp.plist", atomically: true, encoding: .utf8)
        try plist("com.bad.unsigned", "/etc/hosts").write(toFile: dir + "/unsigned.plist", atomically: true, encoding: .utf8)

        let findings = launchdFindings(items: scanLaunchd(roots: [dir]))
        #expect(findings["launchd/com.bad.tmp"]?.contains("temp path") == true)
        #expect(findings["launchd/com.bad.unsigned"]?.contains("unsigned") == true)
        #expect(findings["launchd/com.ok.zsh"] == nil)
    }

    @Test("per-dir item counts")
    func perDirCounts() {
        let items: [String: LaunchdItem] = [
            "a": LaunchdItem(label: "a", path: "/Library/LaunchAgents/a.plist", program: nil, plistHash: "x"),
            "b": LaunchdItem(label: "b", path: "/Library/LaunchAgents/b.plist", program: nil, plistHash: "x"),
            "c": LaunchdItem(label: "c", path: "/Library/LaunchDaemons/c.plist", program: nil, plistHash: "x"),
        ]
        let counts = launchdPerDirCounts(items: items)
        #expect(counts["/Library/LaunchAgents"] == 2)
        #expect(counts["/Library/LaunchDaemons"] == 1)
    }
}

@Suite("posture drift")
struct PostureDriftTests {
    @Test("added, removed, changed, finding")
    func drift() {
        var old = PostureSnapshot()
        old.values = ["sip": "enabled", "proxy": "no proxies enabled", "dns": "resolvers=1.1.1.1"]
        var new = PostureSnapshot()
        new.values = ["sip": "enabled", "proxy": "http=10.0.0.1:8080", "sysext": "1 extension(s)"]
        new.findings = ["proxy": "proxy configured: http=10.0.0.1:8080"]
        let drifts = diffPosture(old: old, new: new)
        #expect(drifts.contains(PostureDrift(check: "proxy", change: "changed", detail: "no proxies enabled → http=10.0.0.1:8080")))
        #expect(drifts.contains(PostureDrift(check: "dns", change: "removed", detail: "resolvers=1.1.1.1")))
        #expect(drifts.contains(PostureDrift(check: "sysext", change: "added", detail: "1 extension(s)")))
        #expect(drifts.contains(PostureDrift(check: "proxy", change: "finding", detail: "proxy configured: http=10.0.0.1:8080")))
        // No drift between identical sweeps.
        #expect(diffPosture(old: new, new: new).isEmpty)
    }
}

@Suite("login hook extraction")
struct LoginHookTests {
    @Test("hooks extracted from a fixture loginwindow plist")
    func hooks() throws {
        let path = NSTemporaryDirectory() + "com.apple.loginwindow.\(UUID().uuidString).plist"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let dict: [String: Any] = ["LoginHook": "/opt/evil/hook.sh"]
        try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
            .write(to: URL(fileURLWithPath: path))
        let hooks = extractLoginHooks(path: path)
        #expect(hooks.login == "/opt/evil/hook.sh")
        #expect(hooks.logout == nil)
    }
}

@Suite("posture event encoding")
struct PostureEncodingTests {
    @Test("posture event key set")
    func encoding() throws {
        let e = SpoolEvent(kind: .posture, check: "proxy", change: "finding", detail: ["value": "proxy configured"])
        let d = try JSONSerialization.jsonObject(with: JSONEncoder().encode(e)) as? [String: Any]
        let keys = Set(d?.keys ?? Dictionary<String, Any>().keys)
        #expect(keys.contains("ts") && keys.contains("kind") && keys.contains("check") && keys.contains("change") && keys.contains("detail"))
        #expect(d?["kind"] as? String == "posture")
        #expect(d?["check"] as? String == "proxy")
        #expect((d?["detail"] as? [String: String])?["value"] == "proxy configured")
    }
}

@Suite("product presence checks")
struct ProductCheckTests {
    @Test("launchctl list labels")
    func labels() {
        let out = "PID\tStatus\tLabel\n123\t0\tcom.crowdstrike.falcond\n-\t0\tcom.apple.screensharing\n"
        #expect(parseLaunchctlListLabels(out) == ["com.crowdstrike.falcond", "com.apple.screensharing"])
    }

    @Test("endpoint protection needs a running signal; XProtect never counts")
    func endpointProtection() {
        let active = SysexEntry(teamId: "X123456789", bundleId: "com.crowdstrike.falcon.Agent", name: "Falcon", state: "[activated enabled]")
        let stale = SysexEntry(teamId: "X123456789", bundleId: "com.sentinelone.extension", name: "S1", state: "[terminated waiting to uninstall on reboot]")
        let names = runningMatches(endpointProtectionCatalog, sysext: [active, stale], labels: ["com.microsoft.fresno", "com.apple.XProtect.daemon.scan"])
        #expect(names == ["CrowdStrike Falcon", "Microsoft Defender"])
        #expect(runningMatches(endpointProtectionCatalog, sysext: [], labels: ["com.apple.XProtect.daemon.scan"]).isEmpty)
        #expect(productListValue([]) == "none")
    }

    @Test("password managers match bundle id or app name only")
    func passwordManagers() {
        let apps = [InstalledApp(bundleId: "com.bitwarden.desktop", name: "Bitwarden"),
                    InstalledApp(bundleId: nil, name: "1Password"),
                    InstalledApp(bundleId: "com.example.notes", name: "Notes")]
        #expect(installedMatches(passwordManagerCatalog, apps: apps) == ["1Password", "Bitwarden"])
        #expect(installedMatches(passwordManagerCatalog, apps: []).isEmpty)
    }

    @Test("remote access: built-in services and third-party tools")
    func remoteAccess() {
        #expect(builtinRemoteAccess(labels: ["com.apple.screensharing", "com.openssh.sshd"]) == ["Screen Sharing", "Remote Login"])
        #expect(builtinRemoteAccess(labels: ["com.apple.other"]).isEmpty)
        let apps = [InstalledApp(bundleId: "com.teamviewer.TeamViewer", name: "TeamViewer")]
        #expect(installedMatches(remoteAccessCatalog, apps: apps) == ["TeamViewer"])
        #expect(runningMatches(remoteAccessCatalog, sysext: [], labels: ["com.philandro.anydesk.service"]) == ["AnyDesk"])
    }

    @Test("severity, status and source for product keys")
    func report() {
        var snap = PostureSnapshot()
        snap.values = ["endpoint_protection": "none", "password_manager": "Bitwarden", "remote_access": "unavailable"]
        snap.findings = ["endpoint_protection": "none"]
        let r = makeDevicePostureReport(snapshot: snap, root: false, networkExtension: "not_configured")
        #expect(r.checks["endpoint_protection"]?.severity == "high")
        #expect(r.checks["endpoint_protection"]?.status == "finding")
        #expect(r.checks["password_manager"]?.status == "pass")
        #expect(r.checks["remote_access"]?.status == "unavailable")
        #expect(r.checks["password_manager"]?.evidence.source == "product_inventory")
        #expect(r.checks["password_manager"]?.evidence.redactions.contains("app_paths") == true)
    }
}

@Suite("neutral compliance checks")
struct NeutralCheckTests {
    @Test("os_updates maps softwareupdate summary")
    func osUpdates() {
        #expect(osUpdatesValue(fromSoftwareUpdate: "none available") == "none")
        #expect(osUpdatesValue(fromSoftwareUpdate: "2 update(s) available") == "2 pending")
        #expect(osUpdatesValue(fromSoftwareUpdate: "updates available") == "pending")
        #expect(osUpdatesValue(fromSoftwareUpdate: "unavailable") == "unavailable")
    }

    @Test("auto_updates parses defaults output")
    func autoUpdates() {
        let on = "{\n    AutomaticDownload = 1;\n    AutomaticallyInstallMacOSUpdates = 1;\n    CriticalUpdateInstall = 1;\n}"
        let off = "{\n    AutomaticDownload = 1;\n    AutomaticallyInstallMacOSUpdates = 0;\n}"
        let missing = "{\n    LastFullSuccessfulDate = \"2026-10-01\";\n}"
        #expect(parseAutoUpdates(on) == "on")
        #expect(parseAutoUpdates(off) == "off")
        #expect(parseAutoUpdates(missing) == "off")
        #expect(parseAutoUpdates("") == "unknown")
    }

    @Test("sysadminctl screenLock output")
    func sysadminctl() {
        #expect(parseSysadminctlScreenLock("sysadminctl[1:2] screenLock delay is immediate").delay == 0)
        let five = parseSysadminctlScreenLock("screenLock delay is 300 seconds")
        #expect(five.ask == true && five.delay == 300)
        #expect(parseSysadminctlScreenLock("screenLock is off").ask == false)
        #expect(parseSysadminctlScreenLock("garbage").ask == nil)
    }

    @Test("screen_lock policy never passes on unreadable input")
    func screenLockPolicy() {
        #expect(evaluateScreenLock(ScreenLockSettings()).value == "unavailable")
        #expect(evaluateScreenLock(ScreenLockSettings(idleSeconds: 300, askForPassword: nil)).value == "unavailable")
        #expect(evaluateScreenLock(ScreenLockSettings(idleSeconds: nil, askForPassword: true)).value == "unavailable")
        let ok = evaluateScreenLock(ScreenLockSettings(idleSeconds: 300, askForPassword: true, passwordDelaySeconds: 0))
        #expect(ok.value == "timeout_seconds=300" && ok.finding == nil)
        let slow = evaluateScreenLock(ScreenLockSettings(idleSeconds: 600, askForPassword: true, passwordDelaySeconds: 600))
        #expect(slow.value == "timeout_seconds=1200" && slow.finding != nil)
        #expect(evaluateScreenLock(ScreenLockSettings(idleSeconds: 0, askForPassword: true)).value == "disabled")
        #expect(evaluateScreenLock(ScreenLockSettings(askForPassword: false)).finding != nil)
    }

    @Test("severity and evidence for neutral keys")
    func report() {
        var snap = PostureSnapshot()
        snap.values = ["disk_encryption": "off", "screen_lock": "unavailable", "auto_updates": "off", "os_updates": "1 pending"]
        snap.findings = ["disk_encryption": "x", "auto_updates": "y", "os_updates": "z"]
        let r = makeDevicePostureReport(snapshot: snap, root: false, networkExtension: "not_configured")
        #expect(r.checks["disk_encryption"]?.severity == "critical")
        #expect(r.checks["os_updates"]?.severity == "high")
        #expect(r.checks["auto_updates"]?.severity == "medium")
        #expect(r.checks["screen_lock"]?.status == "unavailable")
        #expect(r.checks["screen_lock"]?.evidence.confidence == "low")
        #expect(r.checks["os_updates"]?.evidence.source == "software_update")
    }
}
