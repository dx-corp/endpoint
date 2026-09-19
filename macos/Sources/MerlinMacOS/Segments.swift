// Spool segmentation: rotate the live JSONL spool into timestamped,
// immutable segments and gzip the finished ones.
//
// Layout (next to the live file, in --spool-dir terms):
//   merlin-events.jsonl                     live, plain JSONL, never compressed
//   merlin-events.20260802-141530.jsonl.gz  finished segment, compressed
//
// Rotation triggers (checked after each write — no events means no
// rotation, so empty segments are never produced): the live file exceeds
// --segment-bytes, or --segment-interval seconds elapsed since the last
// rotation. Compression runs on a background queue off the write path,
// in-process (Apple's Compression framework, COMPRESSION_ZLIB, re-wrapped
// as gzip — no subprocess, no new deps). The uncompressed segment is
// deleted only after a successful compress+fsync. A crash mid-compression
// leaves a stray uncompressed segment; a startup sweep compresses those
// orphans (never the live file).

import Compression
import Foundation

private let maxSegmentBytes = 64 << 20

struct SegmentConfig: Sendable {
    /// Seconds between rotations; 0 = no time-based rotation.
    var interval: TimeInterval = 0
    /// Rotate when the live file exceeds this many bytes; 0 = no
    /// size-based rotation.
    var maxBytes: Int64 = 0

    var enabled: Bool { interval > 0 || maxBytes > 0 }
}

/// Timestamp format used in segment names: yyyyMMdd-HHmmss (local time).
func segmentTimestamp(_ date: Date = Date()) -> String {
    var t = time_t(date.timeIntervalSince1970)
    var tm = tm()
    localtime_r(&t, &tm)
    return String(
        format: "%04d%02d%02d-%02d%02d%02d",
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
        tm.tm_hour, tm.tm_min, tm.tm_sec
    )
}

/// Name of the segment file for a live spool path (before compression):
/// "merlin-events.jsonl" → "merlin-events.<yyyyMMdd-HHmmss>.jsonl".
func segmentPath(for livePath: String, timestamp: String) -> String {
    let base = livePath.hasSuffix(".jsonl") ? String(livePath.dropLast(6)) : livePath
    return "\(base).\(timestamp).jsonl"
}

/// Filenames that are finished (possibly uncompressed) segments of
/// `liveName`: "<base>.<8 digits>-<6 digits>.jsonl" where base is the
/// live name minus its ".jsonl" suffix.
func isSegmentFile(_ name: String, liveName: String) -> Bool {
    let base = liveName.hasSuffix(".jsonl") ? String(liveName.dropLast(6)) : liveName
    guard name.hasPrefix(base + "."), name.hasSuffix(".jsonl") else { return false }
    let mid = name.dropFirst(base.count + 1).dropLast(6)
    guard mid.count == 15, mid[mid.index(mid.startIndex, offsetBy: 8)] == "-" else { return false }
    return mid.allSatisfy { $0.isNumber || $0 == "-" }
}

/// gzip (RFC 1952) via the Compression framework. Empirically on macOS 27
/// COMPRESSION_ZLIB emits a RAW deflate stream (verified: no 0x78 zlib
/// header, no adler32 trailer — the stream decodes with zero skip), so
/// the gzip wrapper is just header + deflate + CRC32/ISIZE trailer. The
/// test suite validates output with /usr/bin/gunzip.
func gzipData(_ input: Data) throws -> Data {
    let dstCap = input.count + 4096
    var deflate = Data(count: dstCap)
    let written: Int = deflate.withUnsafeMutableBytes { dst in
        input.withUnsafeBytes { src in
            compression_encode_buffer(
                dst.baseAddress!, dstCap,
                src.baseAddress!, input.count,
                nil, COMPRESSION_ZLIB
            )
        }
    }
    guard written > 0 else {
        throw MerlinError.plain("deflate compression failed")
    }
    deflate = deflate.prefix(written)

    var out = Data()
    out.append(contentsOf: [0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0x03]) // gzip header, mtime 0, os unix
    out.append(deflate)
    var crc = crc32(input)
    var isize = UInt32(truncatingIfNeeded: input.count)
    withUnsafeBytes(of: &crc) { out.append(contentsOf: $0) }
    withUnsafeBytes(of: &isize) { out.append(contentsOf: $0) }
    return out
}

/// CRC-32/ISO-HDLC (gzip trailer), table-driven.
private let crcTable: [UInt32] = (0 ..< 256).map { n in
    var c = UInt32(n)
    for _ in 0 ..< 8 {
        c = c & 1 != 0 ? 0xEDB8_8320 ^ (c >> 1) : c >> 1
    }
    return c
}

func crc32(_ data: Data) -> UInt32 {
    var crc: UInt32 = 0xFFFF_FFFF
    for byte in data {
        crc = crcTable[Int((crc ^ UInt32(byte)) & 0xff)] ^ (crc >> 8)
    }
    return crc ^ 0xFFFF_FFFF
}

/// Compress one finished segment to "<path>.gz" and delete the original —
/// only after the compressed file is fully written and fsynced. The whole
/// segment is read into memory (segments are rotation-bounded; fine for a
/// teaching sensor).
func compressSegment(at path: String) throws {
    let sourceFD = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
    guard sourceFD >= 0 else { throw MerlinError.plain("opening segment \(path): errno \(errno)") }
    defer { close(sourceFD) }
    var sourceStat = stat()
    guard fstat(sourceFD, &sourceStat) == 0,
          sourceStat.st_mode & S_IFMT == S_IFREG,
          sourceStat.st_uid == geteuid(),
          sourceStat.st_mode & 0o077 == 0,
          sourceStat.st_size >= 0,
          sourceStat.st_size <= maxSegmentBytes else {
        throw MerlinError.plain("segment \(path) is not a private bounded regular file")
    }
    var input = Data()
    var buffer = [UInt8](repeating: 0, count: 65_536)
    while input.count <= maxSegmentBytes {
        let count = buffer.withUnsafeMutableBytes { read(sourceFD, $0.baseAddress, $0.count) }
        if count < 0 { throw MerlinError.plain("reading segment \(path): errno \(errno)") }
        if count == 0 { break }
        input.append(contentsOf: buffer.prefix(count))
        if input.count > maxSegmentBytes { throw MerlinError.plain("segment \(path) exceeds the read limit") }
    }
    let gz = try gzipData(input)
    let gzPath = path + ".gz"
    let outputFD = open(gzPath, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
    guard outputFD >= 0 else { throw MerlinError.plain("creating \(gzPath): errno \(errno)") }
    var published = false
    defer {
        close(outputFD)
        if !published { unlink(gzPath) }
    }
    do {
        try gz.withUnsafeBytes { raw in
            var written = 0
            while written < raw.count {
                let count = write(outputFD, raw.baseAddress!.advanced(by: written), raw.count - written)
                guard count > 0 else { throw MerlinError.plain("writing \(gzPath): errno \(errno)") }
                written += count
            }
        }
        guard fsync(outputFD) == 0 else { throw MerlinError.plain("fsync \(gzPath): errno \(errno)") }
        published = true
    } catch {
        throw MerlinError.context("fsync \(gzPath)", error)
    }
    do {
        try FileManager.default.removeItem(atPath: path)
    } catch {
        throw MerlinError.context("removing compressed segment \(path)", error)
    }
}

/// Compress any orphaned uncompressed segments next to `livePath`
/// (leftover from a crash mid-compression). The live file itself is never
/// touched. Returns the paths that were compressed.
@discardableResult
func sweepSegmentOrphans(livePath: String) -> [String] {
    let dir = (livePath as NSString).deletingLastPathComponent
    let liveName = (livePath as NSString).lastPathComponent
    let names = (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []
    var compressed: [String] = []
    for name in names where isSegmentFile(name, liveName: liveName) {
        let path = (dir as NSString).appendingPathComponent(name)
        do {
            try compressSegment(at: path)
            compressed.append(path)
        } catch {
            merlinLog("warn", "segment orphan sweep: \(error)")
        }
    }
    if !compressed.isEmpty {
        merlinLog("info", "segment sweep: compressed \(compressed.count) orphaned segment(s)")
    }
    return compressed
}
