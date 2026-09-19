import Foundation
import Testing
@testable import MerlinMacOS

// Spool segmentation: rotation triggers, naming, gzip validity, orphan
// sweep, live-file durability across rotation.

@Suite("segmentation")
struct SegmentationTests {
    private func tempDir() throws -> String {
        let dir = NSTemporaryDirectory() + "merlin-seg-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        return dir
    }

    private func lines(_ path: String) -> [String] {
        (try? String(contentsOfFile: path, encoding: .utf8))?
            .split(separator: "\n").map(String.init) ?? []
    }

    private func dirFiles(_ dir: String) -> [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []
    }

    /// Wait for the background compressor to finish a rotated segment.
    private func awaitGz(in dir: String, timeout: TimeInterval = 8) -> String? {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            let files = dirFiles(dir)
            if let gz = files.first(where: { $0.hasSuffix(".jsonl.gz") }),
               !files.contains(String(gz.dropLast(3))) {
                // Compression publishes the gzip before removing the source;
                // wait for the complete background operation, not just the
                // first visible intermediate file.
                return gz
            }
            usleep(100_000)
        }
        return nil
    }

    @Test("segment naming and isSegmentFile classification")
    func naming() {
        let ts = segmentTimestamp()
        #expect(ts.count == 15)
        let p = segmentPath(for: "/tmp/merlin-events.jsonl", timestamp: ts)
        #expect(p.hasPrefix("/tmp/merlin-events.\(ts)"))
        #expect(p.hasSuffix(".jsonl"))
        let name = (p as NSString).lastPathComponent
        #expect(isSegmentFile(name, liveName: "merlin-events.jsonl"))
        #expect(!isSegmentFile("merlin-events.jsonl", liveName: "merlin-events.jsonl")) // the live file
        #expect(isSegmentFile(name + ".gz", liveName: "merlin-events.jsonl") == false) // already compressed
        #expect(!isSegmentFile("other.jsonl", liveName: "merlin-events.jsonl"))
        #expect(!isSegmentFile("merlin-events.notimestamp.jsonl", liveName: "merlin-events.jsonl"))
    }

    @Test("gzip output is valid and round-trips byte-for-byte")
    func gzipValidity() throws {
        let payload = Data(String(repeating: "{\"kind\":\"exec\"}\n{\"kind\":\"exit\"}\n", count: 100).utf8)
        let gz = try gzipData(payload)
        // gzip magic + method.
        #expect(gz[0] == 0x1f && gz[1] == 0x8b && gz[2] == 0x08)
        // gunzip via /usr/bin/gunzip and compare byte-for-byte.
        let tmp = NSTemporaryDirectory() + "merlin-gz-\(UUID().uuidString).jsonl.gz"
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        try gz.write(to: URL(fileURLWithPath: tmp))
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/gunzip")
        proc.arguments = ["-c", tmp]
        let pipe = Pipe()
        proc.standardOutput = pipe
        try proc.run()
        let out = pipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        #expect(proc.terminationStatus == 0)
        #expect(out == payload)
        // CRC32 spot check (gzip compatibility vector).
        #expect(crc32(Data("123456789".utf8)) == 0xCBF4_3926)
    }

    @Test("bytes trigger rotates; lines land across live + segment")
    func bytesRotation() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let live = dir + "/merlin-events.jsonl"
        let spool = try SpoolWriter(path: live)
        spool.segmentation = SegmentConfig(interval: 0, maxBytes: 1) // rotate after every event
        spool.write(SpoolEvent(kind: .exec, pid: 1, comm: "a", exe: "/bin/a", matchedRules: []))
        // Disable the trigger after proving one rotation so the second event
        // exercises the fresh live file instead of rotating a second segment.
        spool.segmentation = nil
        spool.write(SpoolEvent(kind: .exec, pid: 2, comm: "b", exe: "/bin/b", matchedRules: []))
        guard let gz = awaitGz(in: dir) else {
            Issue.record("no compressed segment appeared")
            return
        }
        // Live file holds the newest event; the segment holds the first.
        #expect(lines(live).count == 1)
        let segName = String(gz.dropLast(3)) // strip .gz
        #expect(dirFiles(dir).contains(segName) == false) // uncompressed original deleted
        #expect(dirFiles(dir).contains(gz))
    }

    @Test("interval trigger rotates; no empty segments without events")
    func intervalRotation() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let live = dir + "/merlin-events.jsonl"
        let spool = try SpoolWriter(path: live)
        spool.segmentation = SegmentConfig(interval: 0.05, maxBytes: 0)
        usleep(100_000) // past the interval, but nothing written → no rotation
        #expect(dirFiles(dir).count == 1)
        spool.write(SpoolEvent(kind: .exec, pid: 1, comm: "a", exe: "/bin/a", matchedRules: []))
        spool.write(SpoolEvent(kind: .exec, pid: 2, comm: "b", exe: "/bin/b", matchedRules: []))
        guard awaitGz(in: dir) != nil else {
            Issue.record("no compressed segment appeared")
            return
        }
        // Durability: every line written survives across live + segment.
        var all: [String] = []
        for name in dirFiles(dir) where name.hasSuffix(".jsonl") || name.hasSuffix(".jsonl.gz") {
            if name.hasSuffix(".gz") {
                let proc = Process()
                proc.executableURL = URL(fileURLWithPath: "/usr/bin/gunzip")
                proc.arguments = ["-c", dir + "/" + name]
                let pipe = Pipe()
                proc.standardOutput = pipe
                try? proc.run()
                let out = pipe.fileHandleForReading.readDataToEndOfFile()
                proc.waitUntilExit()
                all += String(decoding: out, as: UTF8.self).split(separator: "\n").map(String.init)
            } else {
                all += lines(dir + "/" + name)
            }
        }
        #expect(all.count == 2)
    }

    @Test("orphan sweep compresses stray uncompressed segments, skips the live file")
    func orphanSweep() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let live = dir + "/merlin-events.jsonl"
        let orphan = segmentPath(for: live, timestamp: segmentTimestamp())
        try "{\"kind\":\"exec\",\"pid\":9}\n".write(toFile: orphan, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: orphan)
        let spool = try SpoolWriter(path: live)
        let compressed = sweepSegmentOrphans(livePath: live)
        #expect(compressed == [orphan])
        #expect(dirFiles(dir).contains(((orphan + ".gz") as NSString).lastPathComponent))
        #expect(!dirFiles(dir).contains((orphan as NSString).lastPathComponent))
        // The live file is untouched and still writable.
        spool.write(SpoolEvent(kind: .exec, pid: 1, comm: "a", exe: "/bin/a", matchedRules: []))
        #expect(lines(live).count == 1)
        // Sweeping again is a no-op (already compressed).
        #expect(sweepSegmentOrphans(livePath: live).isEmpty)
    }

    @Test("segment compression rejects symlink sources and destinations")
    func compressionRejectsSymlinks() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let target = dir + "/target.jsonl"
        let sourceLink = dir + "/merlin-events.20260817-010203.jsonl"
        FileManager.default.createFile(atPath: target, contents: Data("event\n".utf8), attributes: [.posixPermissions: 0o600])
        try FileManager.default.createSymbolicLink(atPath: sourceLink, withDestinationPath: target)
        #expect(throws: (any Error).self) { try compressSegment(at: sourceLink) }

        let source = dir + "/merlin-events.20260817-020304.jsonl"
        FileManager.default.createFile(atPath: source, contents: Data("event\n".utf8), attributes: [.posixPermissions: 0o600])
        try FileManager.default.createSymbolicLink(atPath: source + ".gz", withDestinationPath: target)
        #expect(throws: (any Error).self) { try compressSegment(at: source) }
        #expect((try? String(contentsOfFile: target, encoding: .utf8)) == "event\n")
    }
}
