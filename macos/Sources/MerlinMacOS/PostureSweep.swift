// Full host-posture sweep: integrity, proxy/DNS, system extensions,
// configuration profiles, login hooks, launchd inventory, event taps —
// one-shot (`posture`) and scheduled drift detection (--posture-interval).
//
// Design rationale (docs/telemetry-sources-claude.md, macOS item 23):
// every serious persistence technique changes one of these first.
// Scheduled mode diffs each sweep against the previous one and spools
// `posture` events {check, change: added|removed|changed|finding,
// detail}. First sweep is a baseline (summary log, no events).
// Telemetry only (no rules), bounded, fail-open: a failed check is
// reported as "unavailable"/"requires root" and never kills the sweep.

import Darwin
import Foundation
import SystemConfiguration

struct PostureDrift: Equatable {
    var check: String
    var change: String // added | removed | changed | finding
    var detail: String
}

/// Point-in-time posture: values for drift comparison, findings to flag.
struct PostureSnapshot: Equatable {
    /// check → value ("requires root"/"unavailable" included as values).
    var values: [String: String] = [:]
    /// check → finding detail (only entries that ARE findings).
    var findings: [String: String] = [:]
    /// Duration is a local collection-health signal; raw command output is
    /// never retained in the report.
    var collectionDurationMs: Int? = nil
}

// MARK: - Shell-outs (5s timeout, graceful degradation)

/// Run a system tool with a timeout. nil = timeout/failure to launch.
/// Pipes are drained concurrently with the wait: a child that writes
/// more than the 64KB pipe buffer (e.g. `ps -A`) would otherwise
/// deadlock against a full pipe until the timeout.
func shellOut(_ path: String, _ args: [String], timeout: TimeInterval = 5) -> (status: Int32, stdout: String, stderr: String)? {
    final class Box: @unchecked Sendable { var data = Data() }
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = args
    let outPipe = Pipe()
    let errPipe = Pipe()
    p.standardOutput = outPipe
    p.standardError = errPipe
    do {
        try p.run()
    } catch {
        return nil
    }
    let outBox = Box()
    let errBox = Box()
    let drained = DispatchGroup()
    drained.enter()
    DispatchQueue.global(qos: .utility).async {
        outBox.data = outPipe.fileHandleForReading.readDataToEndOfFile()
        drained.leave()
    }
    drained.enter()
    DispatchQueue.global(qos: .utility).async {
        errBox.data = errPipe.fileHandleForReading.readDataToEndOfFile()
        drained.leave()
    }
    let done = DispatchSemaphore(value: 0)
    p.terminationHandler = { _ in done.signal() }
    if done.wait(timeout: .now() + timeout) == .timedOut {
        p.terminate()
        return nil
    }
    drained.wait() // process exited → pipes at EOF → drains finish
    return (p.terminationStatus, String(decoding: outBox.data, as: UTF8.self), String(decoding: errBox.data, as: UTF8.self))
}

// MARK: - Parsers (pure)

func parseCsrutil(_ out: String) -> String {
    let lower = out.lowercased()
    if lower.contains("status: enabled") { return "enabled" }
    if lower.contains("status: disabled") { return "disabled" }
    return "unknown"
}

func parseSpctl(_ out: String) -> String {
    let lower = out.lowercased()
    if lower.contains("assessments enabled") { return "enabled" }
    if lower.contains("assessments disabled") { return "disabled" }
    return "unknown"
}

func parseFdesetup(_ out: String) -> String {
    let lower = out.lowercased()
    if lower.contains("filevault is on") { return "on" }
    if lower.contains("filevault is off") { return "off" }
    return "unknown"
}

func parseFirewall(_ out: String) -> String {
    let lower = out.lowercased()
    if lower.contains("state = 1") || lower.contains("enabled") { return "enabled" }
    if lower.contains("state = 0") || lower.contains("disabled") { return "disabled" }
    return "unknown"
}

func parseFirewallRuleCount(_ out: String) -> String {
    let lines = out.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
    let rules = lines.filter { line in
        line.contains("ALF") || line.contains("Block") || line.contains("Allow") || line.contains("/Contents/MacOS/")
    }
    return "\(rules.count) application rule(s)"
}

func parseSecureBoot(_ out: String) -> String {
    let lower = out.lowercased()
    if lower.contains("full security") { return "full" }
    if lower.contains("reduced security") { return "reduced" }
    if lower.contains("permissive security") { return "permissive" }
    if lower.contains("security enabled") { return "full" }
    return "unknown"
}

func parseMDMEnrollment(_ out: String) -> String {
    let lower = out.lowercased()
    if lower.contains("mdm enrollment: yes") || lower.contains("enrolled: yes") || lower.contains("enrollment: yes") {
        return "enrolled"
    }
    if lower.contains("mdm enrollment: no") || lower.contains("enrolled: no") || lower.contains("enrollment: no") {
        return "not enrolled"
    }
    return "unknown"
}

func parseSoftwareUpdate(_ out: String) -> String {
    let lower = out.lowercased()
    if lower.contains("no new software available") || lower.contains("no updates available") {
        return "none available"
    }
    let candidates = out.split(separator: "\n").filter { line in
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        return trimmed.hasPrefix("*") || trimmed.hasPrefix("Label:")
    }
    if candidates.isEmpty {
        return lower.contains("update") ? "updates available" : "none available"
    }
    return "\(candidates.count) update(s) available"
}

func parseBootArgs(_ out: String) -> (summary: String, risky: [String]) {
    let lower = out.lowercased()
    let riskyTokens = ["amfi_get_out_of_my_way", "amfi_allow_any_signature", "-no_", "cs_enforcement_disable", "debug=0x"]
    let risky = riskyTokens.filter { lower.contains($0) }
    return (risky.isEmpty ? "none" : "restricted flags present", risky)
}

func parseTCCAccess(exists: Bool, readable: Bool) -> String {
    if !exists { return "unavailable" }
    return readable ? "metadata readable" : "protected"
}

struct SysexEntry: Equatable {
    var teamId: String
    var bundleId: String
    var name: String
    var state: String
}

/// Parse `systemextensionsctl list` table rows.
/// Row shape: "[*]\t[*]\tteamID\tbundleID (version)\tname\t[state]"
func parseSysextList(_ out: String) -> [SysexEntry] {
    var entries: [SysexEntry] = []
    for line in out.split(separator: "\n") {
        // teamID: 10 uppercase alnum chars followed by whitespace.
        guard let range = line.range(of: #"[A-Z0-9]{10}\s+"#, options: .regularExpression) else { continue }
        let teamId = String(line[range]).trimmingCharacters(in: .whitespaces)
        let rest = line[range.upperBound...]
        // bundleID (version) name [state]
        guard let paren = rest.range(of: #"\s+\([^)]*\)\s+"#, options: .regularExpression),
              let bracket = rest.range(of: #"\s+\[[^]]*\]\s*$"#, options: .regularExpression)
        else { continue }
        let bundleId = String(rest[..<paren.lowerBound]).trimmingCharacters(in: .whitespaces)
        let name = String(rest[paren.upperBound ..< bracket.lowerBound])
        let state = String(rest[bracket]).trimmingCharacters(in: .whitespaces)
        entries.append(SysexEntry(teamId: teamId, bundleId: bundleId, name: name, state: state))
    }
    return entries
}

/// `profiles show -all`: count from "There are N configuration
/// profiles installed", or nil when the tool says root is required.
func parseProfiles(_ stdout: String, _ stderr: String) -> (count: Int?, requiresRoot: Bool) {
    let combined = stdout + stderr
    if combined.contains("requires root") || combined.contains("requires admin") {
        return (nil, true)
    }
    if let m = combined.range(of: #"There are (\d+) configuration profiles"#, options: .regularExpression) {
        let digits = combined[m].filter(\.isNumber)
        return (Int(digits), false)
    }
    if combined.contains("configuration profiles installed") {
        return (0, false)
    }
    return (0, false)
}

/// Active system extensions outside the expected team set are findings.
func sysextFindings(entries: [SysexEntry], expectedTeams: [String]) -> [String: String] {
    var findings: [String: String] = [:]
    for e in entries where e.state.contains("activated enabled") && !expectedTeams.contains(e.teamId) {
        findings["sysext/\(e.bundleId)"] = "active system extension: \(e.name) (team \(e.teamId), \(e.state))"
    }
    return findings
}

/// Launchd item counts grouped by containing directory.
func launchdPerDirCounts(items: [String: LaunchdItem]) -> [String: Int] {
    var perDir: [String: Int] = [:]
    for item in items.values {
        perDir[(item.path as NSString).deletingLastPathComponent, default: 0] += 1
    }
    return perDir
}

/// Launchd items worth flagging: program under temp paths, or unsigned.
func launchdFindings(items: [String: LaunchdItem], signing: SigningInfoCache = SigningInfoCache()) -> [String: String] {
    let tempPrefixes = ["/tmp", "/var/tmp", "/private/tmp", "/private/var/tmp", "~"]
    var findings: [String: String] = [:]
    for (label, item) in items {
        guard let program = item.program else { continue }
        let path = program.trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
        if tempPrefixes.contains(where: { path.hasPrefix($0) }) {
            findings["launchd/\(label)"] = "program in temp path: \(path)"
            continue
        }
        let sig = signing.info(path: path)
        if sig == nil || sig?.adhoc == true || sig?.signingId == nil {
            // "Unsigned" for posture purposes: adhoc-signed or no signing
            // identifier at all. Static flags lack the runtime platform
            // bit, so Apple system binaries (com.apple.* signing ids,
            // no team id) are NOT flagged.
            findings["launchd/\(label)"] = "unsigned, adhoc, or unverifiable program: \(path)"
        }
    }
    return findings
}

// MARK: - Sweep capture

func capturePosture(expectedSysexTeams: [String] = []) -> PostureSnapshot {
    let startedAt = Date()
    var snap = PostureSnapshot()

    // Integrity.
    if let r = shellOut("/usr/bin/csrutil", ["status"]) {
        let v = parseCsrutil(r.stdout)
        snap.values["sip"] = v
        if v == "disabled" { snap.findings["sip"] = "SIP disabled" }
    } else {
        snap.values["sip"] = "unavailable"
    }
    if let r = shellOut("/usr/sbin/spctl", ["--status"]) {
        let v = parseSpctl(r.stdout + r.stderr)
        snap.values["gatekeeper"] = v
        if v == "disabled" { snap.findings["gatekeeper"] = "Gatekeeper disabled" }
    } else {
        snap.values["gatekeeper"] = "unavailable"
    }
    if let r = shellOut("/usr/bin/fdesetup", ["status"]) {
        let v = parseFdesetup(r.stdout)
        snap.values["filevault"] = v
        if v == "off" { snap.findings["filevault"] = "FileVault off" }
    } else {
        snap.values["filevault"] = "unavailable"
    }

    // The authenticated system volume is a separate integrity signal from
    // SIP. It is unavailable on Intel/older systems where the command is not
    // supported, which is represented explicitly rather than treated as a
    // pass.
    if let r = shellOut("/usr/bin/csrutil", ["authenticated-root", "status"], timeout: 2) {
        let v = parseCsrutil(r.stdout + r.stderr)
        snap.values["authenticated_root"] = v
        if v == "disabled" { snap.findings["authenticated_root"] = "Authenticated System Volume is disabled" }
    } else {
        snap.values["authenticated_root"] = "unavailable"
    }

    // FileVault user/secure-token coverage is intentionally a boolean
    // capability. The fdesetup output contains account names, so never put
    // that output into the posture report or JSONL spool.
    if let r = shellOut("/usr/bin/fdesetup", ["list"], timeout: 2), r.status == 0 {
        snap.values["filevault_users"] = "available"
    } else if snap.values["filevault"] == "on" {
        snap.values["filevault_users"] = "requires root"
    } else {
        snap.values["filevault_users"] = "unavailable"
    }

    // Apple Silicon/T2 secure-boot policy. `bputil` may be unavailable or
    // may require RecoveryOS; both cases are useful coverage metadata.
    if let r = shellOut("/usr/bin/bputil", ["-s"], timeout: 2) {
        let v = parseSecureBoot(r.stdout + r.stderr)
        snap.values["secure_boot"] = v
        if v == "reduced" || v == "permissive" {
            snap.findings["secure_boot"] = "Secure Boot policy is \(v)"
        }
    } else {
        snap.values["secure_boot"] = "unavailable"
    }

    // Application firewall state is a system configuration fact, not a
    // replacement for packet telemetry.
    if let r = shellOut("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"], timeout: 2) {
        let v = parseFirewall(r.stdout + r.stderr)
        snap.values["firewall"] = v
        if v == "disabled" { snap.findings["firewall"] = "Application firewall disabled" }
    } else {
        snap.values["firewall"] = "unavailable"
    }
    if let r = shellOut("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--listapps"], timeout: 2) {
        snap.values["firewall_rules"] = parseFirewallRuleCount(r.stdout + r.stderr)
    } else {
        snap.values["firewall_rules"] = "unavailable"
    }

    // Enrollment metadata is parsed into booleans only. Profiles themselves
    // are not uploaded; MDM is optional, so lack of enrollment is reported as
    // a value but is not a finding by default.
    if let r = shellOut("/usr/bin/profiles", ["status", "-type", "enrollment"], timeout: 2) {
        snap.values["mdm"] = parseMDMEnrollment(r.stdout + r.stderr)
    } else {
        snap.values["mdm"] = "unavailable"
    }

    // TCC database contents are private and commonly protected by Full Disk
    // Access. Report only whether the database exists and is readable.
    let tccPath = "/Library/Application Support/com.apple.TCC/TCC.db"
    var tccStat = stat()
    let tccExists = lstat(tccPath, &tccStat) == 0 && tccStat.st_mode & S_IFMT == S_IFREG
    snap.values["tcc"] = parseTCCAccess(exists: tccExists, readable: tccExists && FileManager.default.isReadableFile(atPath: tccPath))

    // A bounded update probe gives operators a useful “update available”
    // signal without retaining package names or download URLs.
    if let r = shellOut("/usr/sbin/softwareupdate", ["--list"], timeout: 3) {
        let v = parseSoftwareUpdate(r.stdout + r.stderr)
        snap.values["software_updates"] = v
        if v != "none available" { snap.findings["software_updates"] = "Software updates available: \(v)" }
    } else {
        snap.values["software_updates"] = "unavailable"
    }

    if let r = shellOut("/usr/sbin/nvram", ["boot-args"], timeout: 2) {
        let parsed = parseBootArgs(r.stdout + r.stderr)
        snap.values["boot_args"] = parsed.summary
        if !parsed.risky.isEmpty {
            snap.findings["boot_args"] = "Risky boot arguments present: \(parsed.risky.joined(separator: ", "))"
        }
    } else {
        snap.values["boot_args"] = "unavailable"
    }

    // Proxy/DNS/router (SCDynamicStore, no root).
    if let store = SCDynamicStoreCreate(nil, "merlin-macos" as CFString, nil, nil) {
        let proxySummary = configSummary(key: "State:/Network/Global/Proxies", store: store)
        snap.values["proxy"] = proxySummary
        if proxySummary != "no proxies enabled", proxySummary != "no proxy configuration" {
            snap.findings["proxy"] = "proxy configured: \(proxySummary)"
        }
        snap.values["dns"] = configSummary(key: "State:/Network/Global/DNS", store: store)
        snap.values["router"] = configSummary(key: "State:/Network/Global/IPv4", store: store)
    } else {
        snap.values["proxy"] = "unavailable"
        snap.values["dns"] = "unavailable"
        snap.values["router"] = "unavailable"
    }

    // System extensions.
    if let r = shellOut("/usr/bin/systemextensionsctl", ["list"]) {
        let entries = parseSysextList(r.stdout)
        snap.values["sysext"] = "\(entries.count) extension(s)"
        for (key, detail) in sysextFindings(entries: entries, expectedTeams: expectedSysexTeams) {
            snap.findings[key] = detail
        }
    } else {
        snap.values["sysext"] = "unavailable"
    }

    // Configuration profiles (root required on macOS 27).
    if let r = shellOut("/usr/bin/profiles", ["show", "-all"]) {
        let (count, requiresRoot) = parseProfiles(r.stdout, r.stderr)
        if requiresRoot {
            snap.values["profiles"] = "requires root"
        } else {
            snap.values["profiles"] = "\(count ?? 0) installed"
            if (count ?? 0) > 0 {
                snap.findings["profiles"] = "\(count ?? 0) configuration profile(s) installed"
            }
        }
    } else {
        snap.values["profiles"] = "unavailable"
    }

    // Login hooks (should be none).
    let hooks = extractLoginHooks(path: "/Library/Preferences/com.apple.loginwindow.plist")
    snap.values["loginhooks"] = [hooks.login, hooks.logout].compactMap { $0 }.joined(separator: " | ")
    if hooks.login != nil { snap.findings["loginhooks/login"] = "LoginHook: \(hooks.login!)" }
    if hooks.logout != nil { snap.findings["loginhooks/logout"] = "LogoutHook: \(hooks.logout!)" }

    // Launchd inventory: total + per-dir counts, unsigned/temp-path
    // flagging. Per-dir counts are separate drift keys so an item
    // added/removed in one directory shows up as a "changed" value.
    let roots = Snapshotter.defaultRoots(root: geteuid() == 0)
    let items = scanLaunchd(roots: roots)
    snap.values["launchd"] = "\(items.count) items"
    for (dir, count) in launchdPerDirCounts(items: items).sorted(by: { $0.key < $1.key }) {
        snap.values["launchd@\(dir)"] = "\(count) items"
    }
    for (key, detail) in launchdFindings(items: items) {
        snap.findings[key] = detail
    }

    // Event taps.
    let taps = currentEventTaps()
    snap.values["eventtaps"] = "\(taps.count) installed"
    for tap in taps where !tap.listenOnly && tap.enabled {
        let comm = procInfo(tap.tappingPid)?.comm ?? "?"
        snap.findings["eventtaps/\(tap.tappingPid)"] = "modifying event tap: \(comm) (pid \(tap.tappingPid), mask 0x\(String(tap.eventsMask, radix: 16)))"
    }

    snap.collectionDurationMs = max(0, Int(Date().timeIntervalSince(startedAt) * 1000))
    return snap
}

/// Diff two sweeps. Findings are compared by key: a finding present in
/// `new` but not `old` is reported (change "finding").
func diffPosture(old: PostureSnapshot, new: PostureSnapshot) -> [PostureDrift] {
    var out: [PostureDrift] = []
    let keys = Set(old.values.keys).union(new.values.keys).sorted()
    for key in keys {
        switch (old.values[key], new.values[key]) {
        case (nil, let nv?): out.append(PostureDrift(check: key, change: "added", detail: nv))
        case (let ov?, nil): out.append(PostureDrift(check: key, change: "removed", detail: ov))
        case (let ov?, let nv?) where ov != nv:
            out.append(PostureDrift(check: key, change: "changed", detail: "\(ov) → \(nv)"))
        default: break
        }
    }
    let newFindings = Set(new.findings.keys).subtracting(old.findings.keys).sorted()
    for key in newFindings {
        out.append(PostureDrift(check: key, change: "finding", detail: new.findings[key]!))
    }
    return out
}

// MARK: - Scheduled watcher

final class PostureWatcher: @unchecked Sendable {
    private let spool: SpoolWriter
    private let interval: TimeInterval
    private let expectedSysexTeams: [String]
    private let queue = DispatchQueue(label: "merlin.posture", qos: .utility)
    private var timer: DispatchSourceTimer?
    private var baseline: PostureSnapshot?

    init(spool: SpoolWriter, interval: TimeInterval, expectedSysexTeams: [String] = []) {
        self.spool = spool
        self.interval = interval
        self.expectedSysexTeams = expectedSysexTeams
    }

    func start() {
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now(), repeating: interval)
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        timer = t
        merlinLog("info", "posture watch: full sweep every \(Int(interval))s (telemetry only)")
    }

    func stop() {
        timer?.cancel()
        timer = nil
    }

    func tick() {
        let snap = capturePosture(expectedSysexTeams: expectedSysexTeams)
        guard let prev = baseline else {
            baseline = snap
            merlinLog("info", "posture baseline: \(snap.values.count) checks, \(snap.findings.count) finding(s)\(snap.findings.isEmpty ? "" : ": " + snap.findings.sorted(by: { $0.key < $1.key }).map { "\($0.key)=\($0.value)" }.joined(separator: "; "))")
            for (key, detail) in snap.findings.sorted(by: { $0.key < $1.key }) {
                // Baseline findings are events too — they exist now, not
                // just as drift. change "finding" marks them.
                spool.write(SpoolEvent(kind: .posture, check: key, change: "finding", detail: ["value": detail]))
            }
            return
        }
        for drift in diffPosture(old: prev, new: snap) {
            merlinLog("info", "posture \(drift.change): \(drift.check) — \(drift.detail)")
            spool.write(SpoolEvent(kind: .posture, check: drift.check, change: drift.change, detail: ["value": drift.detail]))
        }
        baseline = snap
    }
}

// MARK: - One-shot report

func runPosture(json: Bool, verbose: Bool, expectedSysexTeams: [String] = []) -> Int32 {
    let snap = capturePosture(expectedSysexTeams: expectedSysexTeams)
    if json {
        var obj: [String: Any] = ["values": snap.values, "findings": snap.findings]
        if let reportData = try? JSONEncoder().encode(makeDevicePostureReport(snapshot: snap)),
           let report = try? JSONSerialization.jsonObject(with: reportData) {
            obj["report"] = report
        }
        if let data = try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys, .prettyPrinted]) {
            print(String(decoding: data, as: UTF8.self))
        }
    } else {
        let order = ["sip", "gatekeeper", "filevault", "authenticated_root", "filevault_users", "secure_boot", "firewall", "mdm", "tcc", "software_updates", "boot_args", "proxy", "dns", "router", "sysext", "profiles", "loginhooks", "launchd", "eventtaps"]
        for key in order {
            print("\(key): \(snap.values[key] ?? "n/a")")
        }
        // Dynamic keys (per-dir launchd counts) after the fixed ones.
        for key in snap.values.keys.sorted() where !order.contains(key) {
            print("\(key): \(snap.values[key]!)")
        }
        for (key, detail) in snap.findings.sorted(by: { $0.key < $1.key }) {
            print("FINDING \(key): \(detail)")
        }
        if verbose {
            print("-- top-5 cpu --")
            if let r = shellOut("/bin/ps", ["-Ao", "pcpu,pid,comm", "-r"]) {
                print(r.stdout.split(separator: "\n").prefix(6).joined(separator: "\n"))
            }
            print("-- disk --")
            if let r = shellOut("/bin/df", ["-h", "/"]) {
                print(r.stdout.trimmingCharacters(in: .whitespacesAndNewlines))
            }
        }
    }
    return 0
}
