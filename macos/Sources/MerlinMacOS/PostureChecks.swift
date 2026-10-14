// Platform-neutral compliance checks (disk_encryption, screen_lock,
// os_updates, auto_updates). Keys and rules follow the shared endpoint
// check-key contract: a check that applies but cannot be read reports
// "unavailable" and is never a pass. Parsers are pure; command execution
// stays in `capturePosture` / `captureScreenLock` via `shellOut`.

import Darwin
import Foundation
import SystemConfiguration

/// Maximum idle time (screen saver start + password delay) that passes.
let screenLockMaxSeconds = 900

/// `os_updates` value: "none" or "<n> pending", from `parseSoftwareUpdate`.
func osUpdatesValue(fromSoftwareUpdate v: String) -> String {
    if v == "none available" { return "none" }
    if v == "unavailable" { return "unavailable" }
    if let n = v.split(separator: " ").first.flatMap({ Int($0) }) { return "\(n) pending" }
    return "pending"
}

/// Reads `defaults read /Library/Preferences/com.apple.SoftwareUpdate`.
/// "on" needs automatic download and automatic macOS update install.
/// A missing key is the macOS default (off).
func parseAutoUpdates(_ out: String) -> String {
    func flag(_ key: String) -> Bool? {
        for line in out.split(separator: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            guard t.hasPrefix(key), let eq = t.firstIndex(of: "=") else { continue }
            if String(t[..<eq]).trimmingCharacters(in: .whitespaces) != key { continue }
            let rhs = t[t.index(after: eq)...].trimmingCharacters(in: CharacterSet(charactersIn: " ;\""))
            return rhs == "1" || rhs.lowercased() == "true"
        }
        return nil
    }
    if !out.contains("=") { return "unknown" }
    let download = flag("AutomaticDownload") ?? false
    let install = flag("AutomaticallyInstallMacOSUpdates") ?? false
    return download && install ? "on" : "off"
}

/// Combined idle/password settings for the console user.
struct ScreenLockSettings: Equatable {
    var idleSeconds: Int?          // screen saver idle time; 0 = never
    var askForPassword: Bool?      // nil = not readable
    var passwordDelaySeconds: Int? // delay between screen saver and lock
}

/// `defaults read com.apple.screensaver` style integer value, nil if unreadable.
func parseDefaultsInt(_ out: String) -> Int? {
    Int(out.trimmingCharacters(in: .whitespacesAndNewlines))
}

/// `sysadminctl -screenLock status` writes to stderr, e.g.
/// "screenLock delay is 300 seconds", "screenLock delay is immediate",
/// "screenLock is off". Returns (askForPassword, delaySeconds).
func parseSysadminctlScreenLock(_ out: String) -> (ask: Bool?, delay: Int?) {
    let lower = out.lowercased()
    guard lower.contains("screenlock") else { return (nil, nil) }
    if lower.contains("screenlock is off") || lower.contains("screenlock is disabled") { return (false, nil) }
    if lower.contains("delay is immediate") { return (true, 0) }
    if let r = lower.range(of: #"delay is (\d+) second"#, options: .regularExpression) {
        let digits = lower[r].filter(\.isNumber)
        if let n = Int(digits) { return (true, n) }
    }
    return (nil, nil)
}

/// Returns (value, finding detail). `unavailable` when the settings that
/// decide the outcome cannot be read; never a pass in that case.
func evaluateScreenLock(_ s: ScreenLockSettings) -> (value: String, finding: String?) {
    if s.askForPassword == false {
        return ("disabled", "Screen lock does not require a password")
    }
    guard let idle = s.idleSeconds, s.askForPassword == true else { return ("unavailable", nil) }
    if idle == 0 { return ("disabled", "Screen saver never starts") }
    let total = idle + (s.passwordDelaySeconds ?? 0)
    if total > screenLockMaxSeconds {
        return ("timeout_seconds=\(total)", "Screen lock timeout \(total)s exceeds \(screenLockMaxSeconds)s")
    }
    return ("timeout_seconds=\(total)", nil)
}

/// Console user's settings. The daemon runs as root without the user's
/// defaults domain, so tools run in the console user's launchd session.
/// The user name is never recorded.
func captureScreenLock() -> (value: String, finding: String?) {
    var uid: uid_t = 0
    guard let user = SCDynamicStoreCopyConsoleUser(nil, &uid, nil) as String?,
          user != "loginwindow", uid != 0
    else { return ("unavailable", nil) }

    func run(_ tool: String, _ args: [String]) -> (status: Int32, stdout: String, stderr: String)? {
        if geteuid() == 0 {
            return shellOut("/bin/launchctl", ["asuser", String(uid), tool] + args, timeout: 3)
        }
        return uid == getuid() ? shellOut(tool, args, timeout: 3) : nil
    }

    var s = ScreenLockSettings()
    if let r = run("/usr/bin/defaults", ["-currentHost", "read", "com.apple.screensaver", "idleTime"]), r.status == 0 {
        s.idleSeconds = parseDefaultsInt(r.stdout)
    }
    if let r = run("/usr/sbin/sysadminctl", ["-screenLock", "status"]) {
        let p = parseSysadminctlScreenLock(r.stdout + r.stderr)
        s.askForPassword = p.ask
        s.passwordDelaySeconds = p.delay
    }
    if s.askForPassword == nil,
       let r = run("/usr/bin/defaults", ["read", "com.apple.screensaver", "askForPassword"]), r.status == 0 {
        s.askForPassword = parseDefaultsInt(r.stdout).map { $0 != 0 }
        if let d = run("/usr/bin/defaults", ["read", "com.apple.screensaver", "askForPasswordDelay"]), d.status == 0 {
            s.passwordDelaySeconds = parseDefaultsInt(d.stdout)
        }
    }
    return evaluateScreenLock(s)
}
