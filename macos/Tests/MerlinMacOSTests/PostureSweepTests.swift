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
