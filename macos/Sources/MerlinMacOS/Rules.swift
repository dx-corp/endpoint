// YAML rules engine — schema and matching semantics at parity with the
// Linux port (merlin/src/rules.rs), plus macOS-specific selectors
// (cdhash, network, signing, lineage).
//
// A rule may carry `match:` (OR: at least one listed selector must hit),
// `match_all:` (AND: every listed selector must hit), or both — then the
// rule fires when all of `match_all` holds AND at least one `match`
// selector hits. `not:` vetoes: any selector hit in `not` and the rule
// does not fire. Evaluation order: not → match_all → match. `uid` is an
// AND-constraint inside `match`/`match_all`, not a selector. A rule with
// only a `uid` fires on uid alone. Hash selectors, `dns_contains` and
// `cmdline_regex` compare case-insensitively.
//
// Validation (parity with Linux): unknown keys are rejected at load
// (rules/rule/match levels), and an empty `match_all` (no selector and
// no uid) is rejected. Yams has no deny_unknown_fields, so validation
// runs over the composed YAML node tree before decoding.

import Foundation
import Yams

private struct AnyCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}

private func rejectUnknownKeys(_ decoder: Decoder, allowed: Set<String>, type: String) throws {
    let container = try decoder.container(keyedBy: AnyCodingKey.self)
    guard let unknown = container.allKeys.first(where: { !allowed.contains($0.stringValue) }) else { return }
    throw DecodingError.dataCorrupted(.init(
        codingPath: decoder.codingPath + [unknown],
        debugDescription: "unknown \(type) field '\(unknown.stringValue)'"
    ))
}

struct Rules: Sendable {
	var schemaVersion: Int = 1
    var rules: [Rule] = []
    /// Extra DoH resolver addresses (additive to the built-in set), used
    /// for `doh_suspect` tagging on connect events.
    var dohResolvers: [String] = []

    static func load(path: String) throws -> Rules {
        let text = try readRulesFile(path: path)
        do {
            return try parse(text)
        } catch {
            throw MerlinError.context("parsing \(path)", error)
        }
    }

    /// Read a rules file without following symlinks (AGENTS.md security
    /// invariants: the daemon may be root while the path is
    /// user-controlled). O_NOFOLLOW + fstat regular-file check; a
    /// group/world-writable policy file warns but still loads.
    /// O_NONBLOCK at open keeps the fifo case from blocking before fstat
    /// can reject it (cleared afterwards — regular files ignore it).
    private static func readRulesFile(path: String) throws -> String {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else {
            let why = errno == ELOOP ? " (symlinks are not followed)" : ""
            throw MerlinError.plain("opening rules \(path): errno \(errno)\(why)")
        }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0 else {
            throw MerlinError.plain("stating rules \(path): errno \(errno)")
        }
        guard st.st_mode & S_IFMT == S_IFREG else {
            throw MerlinError.plain("rules \(path) is not a regular file")
        }
        _ = fcntl(fd, F_SETFL, 0)
        if st.st_mode & 0o022 != 0 {
            merlinLog("warn", "rules file \(path) is group/world-writable — policy should not be editable by others")
        }
        var data = Data()
        var buf = [UInt8](repeating: 0, count: 65536)
        while true {
            let n = buf.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
            if n < 0 {
                throw MerlinError.plain("reading rules \(path): errno \(errno)")
            }
            if n == 0 { break }
            data.append(contentsOf: buf.prefix(n))
        }
        guard let text = String(data: data, encoding: .utf8) else {
            throw MerlinError.plain("rules \(path) is not valid UTF-8")
        }
        return text
    }

    /// Validate + decode (Linux parity: Rules::parse).
    static func parse(_ text: String) throws -> Rules {
        let rules = try YAMLDecoder().decode(Rules.self, from: text)
        for rule in rules.rules {
            if let all = rule.matchAll, !all.hasSelectors, all.uid == nil {
                throw MerlinError.plain("rule '\(rule.name)': match_all must list at least one selector or uid")
            }
        }
        return rules
    }
}

extension Rules: Decodable {
    init(from decoder: Decoder) throws {
		try rejectUnknownKeys(decoder, allowed: ["schema_version", "rules", "doh_resolvers"], type: "rules")
        let c = try decoder.container(keyedBy: CodingKeys.self)
		schemaVersion = try c.decodeIfPresent(Int.self, forKey: .schemaVersion) ?? 1
		guard schemaVersion == 1 else { throw MerlinError.plain("unsupported policy schema_version \(schemaVersion)") }
		rules = try c.decodeIfPresent([Rule].self, forKey: .rules) ?? []
        dohResolvers = try c.decodeIfPresent([String].self, forKey: .dohResolvers) ?? []
    }
    private enum CodingKeys: String, CodingKey {
		case schemaVersion = "schema_version"
        case rules
        case dohResolvers = "doh_resolvers"
    }

    /// Decode a single rule from a YAML fragment (used by tests; no
    /// unknown-key validation there — load/parse paths have it).
    static func decodeOne(_ yaml: String) throws -> Rule {
        try YAMLDecoder().decode(Rule.self, from: yaml)
    }
}

struct Rule: Decodable, Sendable {
    let name: String
    let match: Match
    let matchAll: Match?
    let not: Match?
    let action: Action
    /// Free-text detection rationale (content packs); ignored by matching.
    let note: String?
    let approvedAlternative: ApprovedAlternative?

    init(from decoder: Decoder) throws {
        try rejectUnknownKeys(decoder, allowed: ["name", "match", "match_all", "not", "action", "note", "approved_alternative"], type: "rule")
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try c.decode(String.self, forKey: .name)
        match = try c.decodeIfPresent(Match.self, forKey: .match) ?? Match()
        matchAll = try c.decodeIfPresent(Match.self, forKey: .matchAll)
        not = try c.decodeIfPresent(Match.self, forKey: .not)
        action = try c.decode(Action.self, forKey: .action)
        note = try c.decodeIfPresent(String.self, forKey: .note)
        approvedAlternative = try c.decodeIfPresent(ApprovedAlternative.self, forKey: .approvedAlternative)
        if approvedAlternative != nil && action == .log {
            throw DecodingError.dataCorruptedError(forKey: .approvedAlternative, in: c, debugDescription: "approved_alternative requires an enforcement action")
        }
    }
    private enum CodingKeys: String, CodingKey {
        case name, match, action, note, not
        case matchAll = "match_all"
        case approvedAlternative = "approved_alternative"
    }

    /// Both blocks count: a hash under `match_all` needs the executable
    /// hashed just as much as one under `match` (mirrors
    /// `Rule::has_sha256_selector` on Linux).
    var hasSHA256Selector: Bool {
        match.sha256 != nil || matchAll?.sha256 != nil
    }

    var hasSigningSelector: Bool {
        let blocks: [Match?] = [match, matchAll]
        return blocks.contains {
            $0?.teamId != nil || $0?.signingId != nil || $0?.isPlatformBinary != nil
        }
    }

    init(name: String, match: Match, action: Action) {
        self.name = name
        self.match = match
        matchAll = nil
        not = nil
        self.action = action
        note = nil
        approvedAlternative = nil
    }
}

struct ApprovedAlternative: Decodable, Sendable {
    let name: String
    let url: URL

    init(from decoder: Decoder) throws {
        try rejectUnknownKeys(decoder, allowed: ["name", "url"], type: "approved_alternative")
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let name = try c.decode(String.self, forKey: .name)
        let rawURL = try c.decode(String.self, forKey: .url)
        guard !name.isEmpty, name == name.trimmingCharacters(in: .whitespacesAndNewlines), name.utf8.count <= 80,
              !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              rawURL.utf8.count <= 2048, let url = URL(string: rawURL), url.scheme == "https",
              url.host != nil, url.user == nil, url.password == nil, url.query == nil, url.fragment == nil else {
            throw DecodingError.dataCorruptedError(forKey: .url, in: c, debugDescription: "approved_alternative requires a name and credential-free HTTPS URL")
        }
        self.name = name
        self.url = url
    }

    private enum CodingKeys: String, CodingKey { case name, url }
}

struct Match: Decodable, Sendable {
    var sha256: String? = nil
    var pathBasename: String? = nil
    var pathPrefix: String? = nil
    var cmdlineContains: String? = nil
    var cmdlineRegex: String? = nil
    var uid: UInt32? = nil
    var cdhash: String? = nil
    var daddr: String? = nil
    var dport: UInt16? = nil
    var dnsContains: String? = nil
    var teamId: String? = nil
    var signingId: String? = nil
    var isPlatformBinary: Bool? = nil
    var unsigned: Bool? = nil
    var parentBasename: String? = nil
    var ancestorCommContains: String? = nil
    var comm: String? = nil

    init() {}

    enum CodingKeys: String, CodingKey {
        case sha256
        case pathBasename = "path_basename"
        case pathPrefix = "path_prefix"
        case cmdlineContains = "cmdline_contains"
        case cmdlineRegex = "cmdline_regex"
        case uid
        case cdhash
        case daddr
        case dport
        case dnsContains = "dns_contains"
        case teamId = "team_id"
        case signingId = "signing_id"
        case isPlatformBinary = "is_platform_binary"
        case unsigned
        case parentBasename = "parent_basename"
        case ancestorCommContains = "ancestor_comm_contains"
        case comm
    }

    init(from decoder: Decoder) throws {
        try rejectUnknownKeys(decoder, allowed: [
            "sha256", "path_basename", "path_prefix", "cmdline_contains", "cmdline_regex", "uid",
            "cdhash", "daddr", "dport", "dns_contains", "team_id", "signing_id",
            "is_platform_binary", "unsigned", "parent_basename", "ancestor_comm_contains", "comm"
        ], type: "match")
        let c = try decoder.container(keyedBy: CodingKeys.self)
        sha256 = try c.decodeIfPresent(String.self, forKey: .sha256)
        pathBasename = try c.decodeIfPresent(String.self, forKey: .pathBasename)
        pathPrefix = try c.decodeIfPresent(String.self, forKey: .pathPrefix)
        cmdlineContains = try c.decodeIfPresent(String.self, forKey: .cmdlineContains)
        cmdlineRegex = try c.decodeIfPresent(String.self, forKey: .cmdlineRegex)
        uid = try c.decodeIfPresent(UInt32.self, forKey: .uid)
        cdhash = try c.decodeIfPresent(String.self, forKey: .cdhash)
        daddr = try c.decodeIfPresent(String.self, forKey: .daddr)
        dport = try c.decodeIfPresent(UInt16.self, forKey: .dport)
        dnsContains = try c.decodeIfPresent(String.self, forKey: .dnsContains)
        teamId = try c.decodeIfPresent(String.self, forKey: .teamId)
        signingId = try c.decodeIfPresent(String.self, forKey: .signingId)
        isPlatformBinary = try c.decodeIfPresent(Bool.self, forKey: .isPlatformBinary)
        unsigned = try c.decodeIfPresent(Bool.self, forKey: .unsigned)
        parentBasename = try c.decodeIfPresent(String.self, forKey: .parentBasename)
        ancestorCommContains = try c.decodeIfPresent(String.self, forKey: .ancestorCommContains)
        comm = try c.decodeIfPresent(String.self, forKey: .comm)
    }
}

enum Action: String, Decodable, Sendable {
    /// `suspend` = SIGSTOP quasi-blocking (macOS-only; the Linux parser
    /// would reject it as an unknown action).
    case log, kill, block, suspend
}

/// Evidence available at a decision point. Fields that cannot be obtained
/// (e.g. sha256 of an unreadable executable) are simply absent — and a
/// selector whose evidence is absent never hits (failsafe for lineage:
/// missing ancestors → parent/ancestor selectors don't match).
struct MatchCtx {
    var sha256: String? = nil
    var basename: String? = nil
    var path: String? = nil
    var cmdline: String? = nil
    var uid: UInt32? = nil
    var cdhash: String? = nil
    var daddr: String? = nil
    var dport: UInt16? = nil
    var dns: String? = nil
    var teamId: String? = nil
    var signingId: String? = nil
    var isPlatformBinary: Bool? = nil
    var unsigned: Bool? = nil
    var parentBasename: String? = nil
    var ancestorComms: [String]? = nil
    var comm: String? = nil
}

/// NSRegularExpression is thread-safe for matching but not marked
/// Sendable; box it. Patterns are compiled once and cached (the match
/// path runs per exec system-wide).
private final class RegexCache: @unchecked Sendable {
    static let shared = RegexCache()

    private let lock = NSLock()
    private var cache: [String: NSRegularExpression?] = [:]

    func get(_ pattern: String) -> NSRegularExpression? {
        lock.lock()
        defer { lock.unlock() }
        if let hit = cache[pattern] { return hit ?? nil }
        let compiled = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive])
        cache[pattern] = .some(compiled)
        return compiled
    }
}

extension Match {
    /// Any non-uid selector present (uid is a constraint, not a selector).
    var hasSelectors: Bool {
        sha256 != nil || pathBasename != nil || pathPrefix != nil
            || cmdlineContains != nil || cmdlineRegex != nil || cdhash != nil
            || daddr != nil || dport != nil || dnsContains != nil
            || teamId != nil || signingId != nil || isPlatformBinary != nil
            || parentBasename != nil || ancestorCommContains != nil || comm != nil || unsigned != nil
    }

    func uidOk(_ ctx: MatchCtx) -> Bool {
        uid == nil || ctx.uid == uid
    }

    // Per-selector hits; absent evidence never hits.
    private func sha256Hit(_ c: MatchCtx) -> Bool {
        sha256.map { $0.caseInsensitiveCompare(c.sha256 ?? "") == .orderedSame } ?? false
    }

    private func basenameHit(_ c: MatchCtx) -> Bool {
        pathBasename.map { $0 == c.basename } ?? false
    }

    private func prefixHit(_ c: MatchCtx) -> Bool {
        pathPrefix.map { c.path?.hasPrefix($0) == true } ?? false
    }

    private func cmdlineHit(_ c: MatchCtx) -> Bool {
        cmdlineContains.map { c.cmdline?.contains($0) == true } ?? false
    }

    private func regexHit(_ c: MatchCtx) -> Bool {
        guard let pattern = cmdlineRegex, let cmdline = c.cmdline,
              let re = RegexCache.shared.get(pattern)
        else { return false }
        return re.firstMatch(in: cmdline, range: NSRange(cmdline.startIndex..., in: cmdline)) != nil
    }

    private func cdhashHit(_ c: MatchCtx) -> Bool {
        cdhash.map { $0.caseInsensitiveCompare(c.cdhash ?? "") == .orderedSame } ?? false
    }

    private func daddrHit(_ c: MatchCtx) -> Bool {
        daddr.map { $0 == c.daddr } ?? false
    }

    private func dportHit(_ c: MatchCtx) -> Bool {
        dport.map { $0 == c.dport } ?? false
    }

    private func dnsHit(_ c: MatchCtx) -> Bool {
        dnsContains.map { c.dns?.range(of: $0, options: .caseInsensitive) != nil } ?? false
    }

    private func teamIdHit(_ c: MatchCtx) -> Bool {
        teamId.map { $0 == c.teamId } ?? false
    }

    private func signingIdHit(_ c: MatchCtx) -> Bool {
        signingId.map { $0 == c.signingId } ?? false
    }

    private func platformHit(_ c: MatchCtx) -> Bool {
        isPlatformBinary.map { $0 == c.isPlatformBinary } ?? false
    }

    private func unsignedHit(_ c: MatchCtx) -> Bool {
        unsigned.map { $0 == c.unsigned } ?? false
    }

    private func parentHit(_ c: MatchCtx) -> Bool {
        parentBasename.map { $0 == c.parentBasename } ?? false
    }

    private func ancestorHit(_ c: MatchCtx) -> Bool {
        ancestorCommContains.map { sub in
            c.ancestorComms?.contains { $0.contains(sub) } == true
        } ?? false
    }

    private func commHit(_ c: MatchCtx) -> Bool {
        comm.map { $0 == c.comm } ?? false
    }

    /// OR semantics (`match:`): at least one listed selector must hit.
    func anyHit(_ c: MatchCtx) -> Bool {
        sha256Hit(c) || basenameHit(c) || prefixHit(c) || cmdlineHit(c)
            || regexHit(c) || cdhashHit(c) || daddrHit(c) || dportHit(c)
            || dnsHit(c) || teamIdHit(c) || signingIdHit(c) || platformHit(c)
            || parentHit(c) || ancestorHit(c) || commHit(c) || unsignedHit(c)
    }

    /// AND semantics (`match_all:`): every listed selector must hit.
    func allHit(_ c: MatchCtx) -> Bool {
        if sha256 != nil, !sha256Hit(c) { return false }
        if pathBasename != nil, !basenameHit(c) { return false }
        if pathPrefix != nil, !prefixHit(c) { return false }
        if cmdlineContains != nil, !cmdlineHit(c) { return false }
        if cmdlineRegex != nil, !regexHit(c) { return false }
        if cdhash != nil, !cdhashHit(c) { return false }
        if daddr != nil, !daddrHit(c) { return false }
        if dport != nil, !dportHit(c) { return false }
        if dnsContains != nil, !dnsHit(c) { return false }
        if teamId != nil, !teamIdHit(c) { return false }
        if signingId != nil, !signingIdHit(c) { return false }
        if isPlatformBinary != nil, !platformHit(c) { return false }
        if parentBasename != nil, !parentHit(c) { return false }
        if ancestorCommContains != nil, !ancestorHit(c) { return false }
        if comm != nil, !commHit(c) { return false }
        if unsigned != nil, !unsignedHit(c) { return false }
        return true
    }
}

extension Rule {
    func matches(_ ctx: MatchCtx) -> Bool {
        // not → match_all → match.
        if let not, not.hasSelectors, not.anyHit(ctx) { return false }
        guard match.uidOk(ctx) else { return false }
        if let all = matchAll {
            guard all.uidOk(ctx), all.allHit(ctx) else { return false }
        }
        if match.hasSelectors {
            return match.anyHit(ctx)
        }
        // No OR selectors: fire on uid-only rules (legacy behavior), or
        // when a non-empty match_all carried the rule.
        return match.uid != nil || (matchAll.map { $0.hasSelectors || $0.uid != nil } ?? false)
    }
}

extension Rule {
    /// Santa-style specificity tier: the highest-ranked selector the rule
    /// carries (cdhash > sha256 > signing_id > team_id > everything else).
    var specificityTier: Int {
        if match.cdhash != nil { return 4 }
        if match.sha256 != nil { return 3 }
        if match.signingId != nil { return 2 }
        if match.teamId != nil { return 1 }
        return 0
    }
}

/// Santa's precedence: among the rules that match one event, only the
/// most specific tier applies; ties within a tier all apply. Single-match
/// behavior is unchanged.
func mostSpecific(_ matched: [Rule]) -> [Rule] {
    guard let top = matched.map(\.specificityTier).max() else { return [] }
    return matched.filter { $0.specificityTier == top }
}

enum MerlinError: Error, CustomStringConvertible {
    case context(String, Error)
    case plain(String)

    var description: String {
        switch self {
        case .context(let what, let e): return "\(what): \(e)"
        case .plain(let msg): return msg
        }
    }
}
