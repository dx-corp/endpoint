import Foundation

/// Names of Codex plugins that `~/.codex/config.toml` explicitly enables.
/// Matches the Linux collector: a key under the top-level `plugins` table is
/// reported only when its `enabled` value is the boolean true and the key is
/// a safe asset name. A document that fails to parse yields no names. No other
/// configuration value is returned.
func codexEnabledPluginNames(_ data: Data) -> [String] {
    guard let leaves = TOMLLeafScanner.parse([UInt8](data)) else { return [] }
    let names = leaves.compactMap { leaf -> String? in
        leaf.path.count == 3 && leaf.path[0] == "plugins" && leaf.path[2] == "enabled" && leaf.isTrue
            && safeAgentAssetName(leaf.path[1]) ? leaf.path[1] : nil
    }
    return Array(names.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }.prefix(128))
}

/// Walks a TOML 1.0 document and records the full key path of every value
/// assignment outside arrays of tables. Only boolean true is retained as a
/// value; strings, numbers, dates, and arrays are skipped. The Windows
/// collector's `windows/codex_plugins.go` implements the same rules.
private struct TOMLLeafScanner {
    struct Leaf { let path: [String]; let isTrue: Bool }
    struct Invalid: Error {}

    /// TOML 1.0 rejects a document that defines one path twice or reopens a
    /// value, an inline table, or a dotted-key table with a header.
    enum Kind { case implicit, dotted, header, array, value }

    let bytes: [UInt8]
    var pos = 0
    var leaves: [Leaf] = []
    var kinds: [[String]: Kind] = [:]

    static func parse(_ bytes: [UInt8]) -> [Leaf]? {
        guard String(bytes: bytes, encoding: .utf8) != nil else { return nil }
        var scanner = TOMLLeafScanner(bytes: bytes)
        do {
            try scanner.document()
            return scanner.leaves
        } catch {
            return nil
        }
    }

    private var current: UInt8? { pos < bytes.count ? bytes[pos] : nil }

    private func has(_ prefix: String) -> Bool {
        let utf8 = Array(prefix.utf8)
        return pos + utf8.count <= bytes.count && Array(bytes[pos..<pos + utf8.count]) == utf8
    }

    private mutating func document() throws {
        if has("\u{FEFF}") { pos += 3 }
        var table: [String]? = []
        while true {
            skipBlank(newlines: true)
            guard let byte = current else { return }
            if byte == UInt8(ascii: "[") {
                let array = has("[[")
                pos += array ? 2 : 1
                skipSpace()
                let path = try key()
                skipSpace()
                guard has(array ? "]]" : "]") else { throw Invalid() }
                pos += array ? 2 : 1
                table = try header(path, array: array) ? path : nil
            } else {
                let path = try key()
                skipSpace()
                guard has("=") else { throw Invalid() }
                pos += 1
                skipSpace()
                try value(try assign(table, path))
            }
            skipBlank(newlines: false)
            guard current == nil || current == UInt8(ascii: "\n") || has("\r\n") else { throw Invalid() }
        }
    }

    /// Resolves key relative to base and rejects a redefinition. A nil base
    /// means the assignment is inside an array of tables and is not tracked.
    private mutating func assign(_ base: [String]?, _ key: [String]) throws -> [String]? {
        guard let base else { return nil }
        let full = base + key
        for end in (base.count + 1)..<full.count {
            let prefix = Array(full[..<end])
            switch kinds[prefix] {
            case nil: kinds[prefix] = .dotted
            case .dotted: break
            default: throw Invalid()
            }
        }
        guard kinds[full] == nil else { throw Invalid() }
        return full
    }

    /// Records a [table] or [[array]] header. Returns false when keys under
    /// the header belong to an array of tables and are not tracked.
    private mutating func header(_ path: [String], array: Bool) throws -> Bool {
        for end in 1..<max(path.count, 1) {
            switch kinds[Array(path[..<end])] {
            case .array: return false
            case .value: throw Invalid()
            default: break
            }
        }
        for end in 1..<max(path.count, 1) where kinds[Array(path[..<end])] == nil {
            kinds[Array(path[..<end])] = .implicit
        }
        let kind = kinds[path]
        if array && (kind == nil || kind == .array) {
            kinds[path] = .array
            return false
        }
        if !array && (kind == nil || kind == .implicit) {
            kinds[path] = .header
            return true
        }
        throw Invalid()
    }

    private mutating func skipSpace() {
        while let byte = current, byte == UInt8(ascii: " ") || byte == UInt8(ascii: "\t") { pos += 1 }
    }

    private mutating func skipBlank(newlines: Bool) {
        while let byte = current {
            if byte == UInt8(ascii: " ") || byte == UInt8(ascii: "\t") {
                pos += 1
            } else if byte == UInt8(ascii: "#") {
                while let next = current, next != UInt8(ascii: "\n") { pos += 1 }
            } else if newlines && (byte == UInt8(ascii: "\n") || has("\r\n")) {
                pos += 1
            } else {
                return
            }
        }
    }

    private mutating func key() throws -> [String] {
        var path: [String] = []
        while true {
            skipSpace()
            guard let byte = current else { throw Invalid() }
            if byte == UInt8(ascii: "\"") {
                path.append(try basicString())
            } else if byte == UInt8(ascii: "'") {
                path.append(try literalString())
            } else {
                let start = pos
                while let next = current, Self.isBareKey(next) { pos += 1 }
                guard pos > start else { throw Invalid() }
                path.append(String(decoding: bytes[start..<pos], as: UTF8.self))
            }
            skipSpace()
            guard has(".") else { return path }
            pos += 1
        }
    }

    private static func isBareKey(_ byte: UInt8) -> Bool {
        (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "Z")) || (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "z")) ||
            (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9")) || byte == UInt8(ascii: "_") || byte == UInt8(ascii: "-")
    }

    /// Control characters that TOML forbids inside a single-line string. Tab
    /// is allowed.
    private static func isControl(_ byte: UInt8) -> Bool {
        (byte < 0x20 && byte != 0x09) || byte == 0x7F
    }

    /// Consumes one TOML value. A nil path means the value is not recorded.
    private mutating func value(_ path: [String]?) throws {
        guard let byte = current else { throw Invalid() }
        if has("\"\"\"") {
            try multilineString(quote: UInt8(ascii: "\""), escapes: true)
            leaf(path, isTrue: false)
        } else if has("'''") {
            try multilineString(quote: UInt8(ascii: "'"), escapes: false)
            leaf(path, isTrue: false)
        } else if byte == UInt8(ascii: "\"") {
            _ = try basicString()
            leaf(path, isTrue: false)
        } else if byte == UInt8(ascii: "'") {
            _ = try literalString()
            leaf(path, isTrue: false)
        } else if byte == UInt8(ascii: "[") {
            pos += 1
            while true {
                skipBlank(newlines: true)
                if has("]") { pos += 1; break }
                try value(nil)
                skipBlank(newlines: true)
                if has(",") { pos += 1; continue }
                guard has("]") else { throw Invalid() }
            }
            leaf(path, isTrue: false)
        } else if byte == UInt8(ascii: "{") {
            pos += 1
            skipSpace()
            leaf(path, isTrue: false)
            if has("}") { pos += 1; return }
            while true {
                let child = try key()
                skipSpace()
                guard has("=") else { throw Invalid() }
                pos += 1
                skipSpace()
                try value(try assign(path, child))
                skipSpace()
                if has(",") { pos += 1; continue }
                guard has("}") else { throw Invalid() }
                pos += 1
                return
            }
        } else {
            let start = pos
            while let next = current, !Array(",]}#\r\n".utf8).contains(next) { pos += 1 }
            while pos > start, bytes[pos - 1] == UInt8(ascii: " ") || bytes[pos - 1] == UInt8(ascii: "\t") { pos -= 1 }
            let token = String(decoding: bytes[start..<pos], as: UTF8.self)
            if token == "true" || token == "false" {
                leaf(path, isTrue: token == "true")
                return
            }
            guard Self.isScalarToken(token) else { throw Invalid() }
            leaf(path, isTrue: false)
        }
    }

    private mutating func leaf(_ path: [String]?, isTrue: Bool) {
        guard let path else { return }
        kinds[path] = .value
        leaves.append(Leaf(path: path, isTrue: isTrue))
    }

    private static func only(_ text: Substring, _ allowed: String) -> Bool {
        text.unicodeScalars.allSatisfy { allowed.unicodeScalars.contains($0) }
    }

    /// Accepts the shapes of TOML numbers and date-times. Rejects bare words,
    /// which TOML does not allow as values.
    static func isScalarToken(_ token: String) -> Bool {
        let text = Substring(token)
        if text.count >= 2, text.hasPrefix("0"), let base = text.dropFirst().first, "xob".contains(base) {
            let digits = base == "x" ? "0123456789abcdefABCDEF_" : (base == "o" ? "01234567_" : "01_")
            return text.count > 2 && only(text.dropFirst(2), digits)
        }
        var unsigned = text
        if unsigned.hasPrefix("+") { unsigned = unsigned.dropFirst() }
        if unsigned.hasPrefix("-") { unsigned = unsigned.dropFirst() }
        if unsigned == "inf" || unsigned == "nan" { return unsigned.count + 1 >= text.count }
        guard let first = unsigned.first, first.isASCII, first.isNumber else { return false }
        let bytes = Array(text.utf8)
        if unsigned.count == text.count && (text.contains(":") || (bytes.count >= 10 && bytes[4] == UInt8(ascii: "-"))) {
            let parts = text.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: false)
            let spaced = parts.count == 2
            return only(parts[0], "0123456789-:.+TtZz") && (!spaced || (!parts[1].isEmpty && only(parts[1], "0123456789-:.+Zz")))
        }
        return only(unsigned, "0123456789_.eE+-")
    }

    private mutating func basicString() throws -> String {
        pos += 1
        var out: [UInt8] = []
        while let byte = current {
            if byte == UInt8(ascii: "\"") {
                pos += 1
                return String(decoding: out, as: UTF8.self)
            } else if Self.isControl(byte) {
                throw Invalid()
            } else if byte == UInt8(ascii: "\\") {
                try escape(into: &out)
            } else {
                out.append(byte)
                pos += 1
            }
        }
        throw Invalid()
    }

    private mutating func escape(into out: inout [UInt8]) throws {
        guard pos + 1 < bytes.count else { throw Invalid() }
        let code = bytes[pos + 1]
        pos += 2
        let simple: [UInt8: UInt8] = [
            UInt8(ascii: "b"): 0x08, UInt8(ascii: "t"): 0x09, UInt8(ascii: "n"): 0x0A, UInt8(ascii: "f"): 0x0C,
            UInt8(ascii: "r"): 0x0D, UInt8(ascii: "\""): 0x22, UInt8(ascii: "\\"): 0x5C,
        ]
        if let value = simple[code] {
            out.append(value)
            return
        }
        let width = code == UInt8(ascii: "u") ? 4 : (code == UInt8(ascii: "U") ? 8 : 0)
        guard width > 0, pos + width <= bytes.count else { throw Invalid() }
        let hex = String(decoding: bytes[pos..<pos + width], as: UTF8.self)
        guard Self.only(Substring(hex), "0123456789abcdefABCDEF"), let number = UInt32(hex, radix: 16),
              let scalar = Unicode.Scalar(number) else { throw Invalid() }
        pos += width
        out.append(contentsOf: Array(String(Character(scalar)).utf8))
    }

    private mutating func literalString() throws -> String {
        pos += 1
        let start = pos
        while let byte = current {
            if byte == UInt8(ascii: "'") {
                let value = String(decoding: bytes[start..<pos], as: UTF8.self)
                pos += 1
                return value
            }
            if Self.isControl(byte) { throw Invalid() }
            pos += 1
        }
        throw Invalid()
    }

    /// Skips a triple-quoted string. Up to two extra quote characters directly
    /// before the closing delimiter belong to the content.
    private mutating func multilineString(quote: UInt8, escapes: Bool) throws {
        let delimiter = [quote, quote, quote]
        pos += 3
        while let byte = current {
            if escapes && byte == UInt8(ascii: "\\") {
                pos += 2
                continue
            }
            if Self.isControl(byte) && byte != 0x0A && !has("\r\n") { throw Invalid() }
            if pos + 3 <= bytes.count && Array(bytes[pos..<pos + 3]) == delimiter {
                pos += 3
                var extra = 0
                while extra < 2, current == quote { pos += 1; extra += 1 }
                return
            }
            pos += 1
        }
        throw Invalid()
    }
}
