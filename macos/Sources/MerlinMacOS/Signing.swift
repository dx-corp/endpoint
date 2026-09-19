// Signing metadata for exec telemetry and the Santa-style rule selectors
// (team_id / signing_id): SecStaticCode signing information needs no
// entitlement. team id, signing identifier, cdhash, and the adhoc /
// platform-binary flags come from one SecStaticCodeCopySigningInformation
// call; quarantine comes from the com.apple.quarantine xattr. Results are
// cached briefly per path — exec storms (builds, test suites) would
// otherwise re-validate the same binaries thousands of times.

import Foundation
import Security

struct SigningInfo: Equatable, Sendable {
    var teamId: String? // kSecCodeInfoTeamIdentifier, e.g. "7BPHA88333"
    var signingId: String? // kSecCodeInfoIdentifier, e.g. "com.apple.curl"
    var cdhash: String? // kSecCodeInfoUnique, hex
    var adhoc: Bool // CS_ADHOC (0x2)
    var platformBinary: Bool // CS_PLATFORM_BINARY (0x04000000)

    /// No identity-backed signature: unsigned outright, or adhoc-signed
    /// (locally compiled binaries are adhoc on arm64). Platform binaries
    /// count as signed even without a team id.
    var unsigned: Bool { teamId == nil && !platformBinary }
}

/// Static signing info for a path, or nil when the file has no code
/// signature at all (unsigned scripts, most text files).
func signingInfo(path: String) -> SigningInfo? {
    var code: SecStaticCode?
    guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
          let code
    else { return nil }
    var infoRef: CFDictionary?
    guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &infoRef) == errSecSuccess,
          let info = infoRef as? [String: Any]
    else { return nil }
    let flags = (info[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
    let cdhash = (info[kSecCodeInfoUnique as String] as? Data)
        .map { $0.map { String(format: "%02x", $0) }.joined() }
    return SigningInfo(
        teamId: info[kSecCodeInfoTeamIdentifier as String] as? String,
        signingId: info[kSecCodeInfoIdentifier as String] as? String,
        cdhash: cdhash,
        adhoc: flags & 0x2 != 0, // CS_ADHOC
        platformBinary: flags & 0x0400_0000 != 0 // CS_PLATFORM_BINARY
    )
}

/// Brief cache keyed by path and descriptor identity. Replacing a binary at
/// the same path must force a fresh signing lookup before policy evaluation.
final class SigningInfoCache: @unchecked Sendable {
    private struct Key: Hashable {
        let path: String
        let identity: FileIdentity
    }

    private var cache: [Key: (info: SigningInfo?, at: TimeInterval)] = [:]
    private let lock = NSLock()
    let ttl: TimeInterval
    private let loader: @Sendable (String) -> SigningInfo?

    init(
        ttl: TimeInterval = 5,
        loader: @escaping @Sendable (String) -> SigningInfo? = signingInfo
    ) {
        self.ttl = ttl
        self.loader = loader
    }

    func info(path: String) -> SigningInfo? {
        guard let before = fileIdentityNoFollow(path) else { return nil }
        let key = Key(path: path, identity: before)
        let now = nowTs()
        lock.lock()
        if let hit = cache[key], now - hit.at < ttl {
            lock.unlock()
            return hit.info
        }
        lock.unlock()
        let value = loader(path)
        guard fileIdentityNoFollow(path) == before else { return nil }
        lock.lock()
        cache[key] = (value, now)
        lock.unlock()
        return value
    }
}

/// com.apple.quarantine xattr presence: true = quarantined (browser/
/// mail-downloaded), false = definitively absent, nil = couldn't tell
/// (unreadable file, exotic error).
func isQuarantined(path: String) -> Bool? {
    let rc = getxattr(path, "com.apple.quarantine", nil, 0, 0, XATTR_NOFOLLOW)
    if rc >= 0 { return true }
    if errno == ENOATTR { return false }
    return nil
}

@_silgen_name("csops")
private func c_csops(_ pid: pid_t, _ ops: UInt32, _ useraddr: UnsafeMutableRawPointer, _ usersize: Int) -> Int32

/// Runtime platform-binary state via csops CS_OPS_STATUS: the kernel sets
/// CS_PLATFORM_BINARY (0x04000000) when it loads a system binary — this
/// is per-process runtime state, NOT available from the on-disk static
/// flags (verified empirically: /bin/zsh's static flags are 0). nil when
/// the process is gone or the call fails.
func isPlatformBinary(pid: pid_t) -> Bool? {
    var flags: UInt32 = 0
    guard c_csops(pid, 0, &flags, MemoryLayout<UInt32>.size) == 0 else { return nil }
    return flags & 0x0400_0000 != 0
}
