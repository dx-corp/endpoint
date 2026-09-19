import Foundation
import Testing
@testable import MerlinMacOS

// Hash-bound tests: the AUTH point must not let a fixed byte cap alone
// decide whether a sha256 selector runs (padding bypass).

@Suite("file hashing bounds")
struct EnrichTests {
    /// 256 KiB of filler: several read chunks, so the bound checks run.
    private func tempFile() throws -> String {
        let path = NSTemporaryDirectory() + "merlin-hash-\(UUID().uuidString)"
        try Data(repeating: 0x41, count: 256 * 1024).write(to: URL(fileURLWithPath: path))
        return path
    }

    @Test("an unbounded hash is the plain sha256")
    func unbounded() throws {
        let path = try tempFile()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let hash = try sha256File(path: path)
        #expect(hash.count == 64)
        #expect(try sha256File(path: path, maxBytes: 1024 * 1024) == hash)
    }

    @Test("the byte limit rejects oversized files")
    func byteLimit() throws {
        let path = try tempFile()
        defer { try? FileManager.default.removeItem(atPath: path) }
        #expect(throws: (any Error).self) {
            try sha256File(path: path, maxBytes: 64 * 1024)
        }
    }

    @Test("an exhausted time budget stops the hash")
    func timeBudget() throws {
        let path = try tempFile()
        defer { try? FileManager.default.removeItem(atPath: path) }
        #expect(throws: (any Error).self) {
            try sha256File(path: path, budget: 0)
        }
        // A budget that cannot be exhausted leaves the hash intact.
        #expect(try sha256File(path: path, budget: 3600).count == 64)
    }
}

@Suite("signing identity cache")
struct SigningIdentityCacheTests {
    @Test("replacing a file at the same path does not reuse signing identity")
    func replacementInvalidatesCache() throws {
        let path = NSTemporaryDirectory() + "merlin-signing-cache-\(UUID().uuidString)"
        try Data("first".utf8).write(to: URL(fileURLWithPath: path))
        defer { try? FileManager.default.removeItem(atPath: path) }
        let cache = SigningInfoCache(ttl: 3600) { candidate in
            let body = try? String(contentsOfFile: candidate, encoding: .utf8)
            return SigningInfo(
                teamId: body, signingId: nil, cdhash: nil,
                adhoc: false, platformBinary: false
            )
        }
        #expect(cache.info(path: path)?.teamId == "first")
        try FileManager.default.removeItem(atPath: path)
        try Data("second".utf8).write(to: URL(fileURLWithPath: path))
        #expect(cache.info(path: path)?.teamId == "second")
    }
}
