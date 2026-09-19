// Append-only JSONL event spool — the analog of Falcon's crash-safe CLFS
// channel logs, minus the crash safety guarantees (plain write+flush per
// event; good enough for a teaching sensor). Same contract as
// merlin/src/spool.rs: one JSON object per line, flushed immediately.

import Foundation

func nowTs() -> Double { Date().timeIntervalSince1970 }

/// Log to stderr, like the Linux daemon's env_logger output.
func merlinLog(_ level: String, _ msg: String) {
    FileHandle.standardError.write(Data("merlin-macos \(level): \(msg)\n".utf8))
}

final class SpoolWriter: @unchecked Sendable {
    private var handle: FileHandle
    private let encoder = JSONEncoder()
    private let lock = NSLock()
    let path: String
    /// Segmentation config; set after init (see Segments.swift). nil = off.
    var segmentation: SegmentConfig? {
        didSet {
            if segmentation?.enabled == true {
                let p = path
                segmentQueue.async { sweepSegmentOrphans(livePath: p) }
            }
        }
    }

    private var bytesWritten: Int64 = 0
    private var lastRotation = nowTs()
    private var eventsAttempted: UInt64 = 0
    private var eventsDropped: UInt64 = 0
    private var eventsWritten: UInt64 = 0
    private var writeFailures: UInt64 = 0
    private var healthTimer: DispatchSourceTimer?
    private let segmentQueue = DispatchQueue(label: "merlin.segments", qos: .utility)

    init(path: String) throws {
        // The daemon may be root while the path is user-controlled. Open the
        // final component atomically without following links, then validate
        // the object through the descriptor rather than its pathname.
        self.path = path
        let opened = try SpoolWriter.openLive(path: path)
        handle = opened.handle
        bytesWritten = opened.size
        merlinLog("info", "spooling events to \(path)")
    }

    /// Open (and validate) the live spool file. Shared by init and
    /// rotation.
    private static func openLive(path: String) throws -> (handle: FileHandle, size: Int64) {
        let fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard fd >= 0 else {
            throw MerlinError.plain("opening spool \(path): errno \(errno)")
        }
        var st = stat()
        guard fstat(fd, &st) == 0 else {
            close(fd)
            throw MerlinError.plain("stating spool \(path): errno \(errno)")
        }
        guard st.st_mode & S_IFMT == S_IFREG else {
            close(fd)
            throw MerlinError.plain("spool \(path) is not a regular file")
        }
        guard st.st_uid == geteuid() else {
            close(fd)
            throw MerlinError.plain("spool \(path) is not owned by the daemon user")
        }
        guard st.st_mode & 0o022 == 0 else {
            close(fd)
            throw MerlinError.plain("spool \(path) is group/other writable")
        }
        return (FileHandle(fileDescriptor: fd, closeOnDealloc: true), st.st_size)
    }

    /// Every event becomes one JSON line, flushed immediately.
    func write(_ event: SpoolEvent) {
        lock.lock()
        defer { lock.unlock() }
        eventsAttempted &+= 1
        writeLocked(event)
    }

    /// Start a periodic, provider-independent health stream. A zero or
    /// negative interval intentionally disables it, preserving the normal
    /// event-only mode for constrained deployments.
    func startHealth(interval: TimeInterval, capabilities: [String]) {
        guard interval > 0 else { return }
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "merlin.health", qos: .utility))
        timer.schedule(deadline: .now() + interval, repeating: interval)
        timer.setEventHandler { [weak self] in
            self?.writeHealth(interval: interval, capabilities: capabilities)
        }
        healthTimer = timer
        timer.resume()
    }

    private func writeHealth(interval: TimeInterval, capabilities: [String]) {
        lock.lock()
        defer { lock.unlock() }
        let attempted = eventsAttempted
        let dropped = eventsDropped
        let dropRate = attempted == 0 ? 0.0 : Double(dropped) / Double(attempted)
        writeLocked(SpoolEvent(
            kind: .health,
            healthStatus: "ok",
            healthCapabilities: capabilities,
            healthEventsAttempted: attempted,
            healthEventsAccepted: attempted >= dropped ? attempted - dropped : 0,
            healthEventsDropped: dropped,
            healthDropRate: dropRate,
            healthEventsWritten: eventsWritten,
            healthWriteFailures: writeFailures,
            healthIntervalSeconds: interval
        ))
    }

    /// Encode, append, flush and account for one event. Caller holds `lock`.
    private func writeLocked(_ event: SpoolEvent) {
        do {
            var event = event
            event.spooledTs = nowTs()
            var data = try encoder.encode(event)
            data.append(0x0a) // \n
            handle.write(data)
            try handle.synchronize()
            bytesWritten += Int64(data.count)
            eventsWritten &+= 1
        } catch {
            writeFailures &+= 1
            eventsDropped &+= 1
            merlinLog("error", "spool write failed: \(error)")
        }
        rotateIfDueLocked()
    }

    /// Rotation triggers, evaluated after each write: size exceeded, or
    /// interval elapsed since the last rotation with new bytes present
    /// (empty segments are never produced). Caller holds `lock`.
    private func rotateIfDueLocked() {
        guard let seg = segmentation, seg.enabled, bytesWritten > 0 else { return }
        let sizeDue = seg.maxBytes > 0 && bytesWritten >= seg.maxBytes
        let timeDue = seg.interval > 0 && nowTs() - lastRotation >= seg.interval
        guard sizeDue || timeDue else { return }
        rotateLocked()
    }

    /// Close the live file, rename it to a timestamped segment, reopen a
    /// fresh live file, and hand the segment to the background compressor.
    /// Caller holds `lock`. A rotation failure keeps the current live
    /// file — telemetry continuity beats segmentation.
    private func rotateLocked() {
        do {
            try handle.synchronize()
            handle.closeFile()
            let segPath = segmentPath(for: path, timestamp: segmentTimestamp())
            // A same-second rotation after a crash could collide; don't
            // clobber an existing segment.
            if FileManager.default.fileExists(atPath: segPath) {
                throw MerlinError.plain("segment \(segPath) already exists")
            }
            try FileManager.default.moveItem(atPath: path, toPath: segPath)
            let opened = try SpoolWriter.openLive(path: path)
            handle = opened.handle
            bytesWritten = 0
            lastRotation = nowTs()
            merlinLog("info", "rotated spool to segment \(segPath)")
            segmentQueue.async {
                do {
                    try compressSegment(at: segPath)
                } catch {
                    merlinLog("warn", "segment compression failed (kept uncompressed): \(error)")
                }
            }
        } catch {
            merlinLog("warn", "spool rotation failed (continuing on live file): \(error)")
            // Best effort: reopen if the handle is dead.
            if let reopened = try? SpoolWriter.openLive(path: path) {
                handle = reopened.handle
            }
        }
    }
}
