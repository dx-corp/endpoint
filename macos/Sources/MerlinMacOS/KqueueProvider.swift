// kqueue provider — entitlement-free process telemetry via EVFILT_PROC.
//
// The "get around the limitation" provider: no Endpoint Security
// entitlement, no auditd, no root needed for same-user visibility (it works
// as a plain user for the user's own processes, which also makes it
// testable without sudo). Every pid on the system gets a kqueue EVFILT_PROC
// filter (NOTE_FORK|NOTE_EXEC|NOTE_EXIT|NOTE_EXITSTATUS); NOTE_FORK chains
// registration onto discovered children, and a ~1s periodic full rescan of
// proc_listpids closes the remaining fork→registration race (fused
// posix_spawn execs).
//
// TELEMETRY ONLY: kqueue has no synchronous hook, so `block` rules cannot
// deny an exec — the engine degrades them to kill+log with a startup
// warning, exactly like the BSM provider (same race window: the exec
// already happened).
//
// Pid reuse: every registration records the process start time
// (pbi_start_tvsec/usec); before enriching or acting on an event the
// current start time is compared, so a recycled pid is never enriched or
// killed as the wrong process.
//
// Limits vs ES: exec events arrive after the new image is running, and
// cross-user enrichment (proc_pidpath / KERN_PROCARGS2) requires root.
// Exit status comes from NOTE_EXITSTATUS (wait(2)-style, in kevent data):
// the kernel only provides it for our own children or processes we may
// signal (same uid, or root) — exit_code/exit_status spool null otherwise.

import Foundation

/// Process start time, recorded at registration for the pid-reuse guard.
struct ProcStart: Equatable {
    let sec: UInt64
    let usec: UInt64
}

final class KqueueProvider: @unchecked Sendable {
    private let engine: Engine
    private var kq: Int32 = -1
    private let selfPID = getpid()
    private var thread: Thread?
    private let lock = NSLock()
    private var running = false
    private let signingCache = SigningInfoCache()
    /// Last-known identity per pid, for exit enrichment: by the time
    /// NOTE_EXIT arrives the process is usually a zombie and proc_pidinfo
    /// no longer answers.
    private var lastKnown: [pid_t: (uid: UInt32, comm: String)] = [:]
    /// Every pid we currently hold a filter on, mapped to the process start
    /// time recorded at registration (nil when proc_pidinfo was already
    /// unreadable — cross-user without root). The start time is the
    /// pid-reuse guard; it is also how fork handling tells newly seen pids
    /// from known ones (NOTE_FORK does not identify the child, see
    /// handle()).
    private var registered: [pid_t: ProcStart?] = [:]

    init(engine: Engine) {
        self.engine = engine
    }

    func start() throws {
        let fd = Darwin.kqueue()
        guard fd >= 0 else {
            throw MerlinError.plain("kqueue() failed: errno \(errno)")
        }
        kq = fd
        var seeded = 0
        // Seed self as well: forks BY this process are how children get
        // discovered (exec/exit of self are still filtered in handle()).
        for pid in allPids() where pid > 0 {
            track(pid, start: procStart(of: pid))
            seeded += 1
        }
        lock.lock()
        running = true
        lock.unlock()
        let t = Thread { [weak self] in self?.drainLoop() }
        t.name = "merlin.kqueue"
        t.start()
        thread = t
        merlinLog("info", "kqueue provider: EVFILT_PROC NOTE_FORK|NOTE_EXEC|NOTE_EXIT|NOTE_EXITSTATUS on \(seeded) pids, 1s full rescan (telemetry only — exec blocking unavailable)")
    }

    func stop() {
        lock.lock()
        running = false
        lock.unlock()
        if kq >= 0 {
            close(kq)
            kq = -1
        }
    }

    /// Process start time for the pid-reuse guard (nil when proc_pidinfo
    /// is unreadable — gone, or cross-user without root).
    private func procStart(of pid: pid_t) -> ProcStart? {
        procInfo(pid).map { ProcStart(sec: $0.startSec, usec: $0.startUsec) }
    }

    /// Register one pid for fork/exec/exit (+ exit status where the kernel
    /// permits it) and remember its start time. EV_ADD failures are
    /// ignored on purpose: the process may have died between listing and
    /// registration, and EVFILT_PROC registrations EV_DELETE themselves on
    /// process death. Returns true if the pid was newly tracked.
    @discardableResult
    private func track(_ pid: pid_t, start: ProcStart?) -> Bool {
        lock.lock()
        let isNew = registered[pid] == nil
        if isNew { registered[pid] = start }
        lock.unlock()
        guard isNew else { return false }
        var change = Darwin.kevent()
        change.ident = UInt(bitPattern: Int(pid))
        change.filter = Int16(EVFILT_PROC)
        change.flags = UInt16(EV_ADD | EV_ENABLE)
        // NOTE_EXITSTATUS: the kernel attaches the wait(2)-style exit
        // status to NOTE_EXIT for our children and processes we may signal
        // (same uid, or root); withheld silently otherwise.
        change.fflags = UInt32(NOTE_FORK) | UInt32(NOTE_EXEC) | UInt32(NOTE_EXIT) | UInt32(NOTE_EXITSTATUS)
        kevent(kq, &change, 1, nil, 0, nil)
        return true
    }

    private func untrack(_ pid: pid_t) {
        lock.lock()
        registered.removeValue(forKey: pid)
        lastKnown.removeValue(forKey: pid)
        lock.unlock()
    }

    /// Single consumer thread: drain kevents and route them into the
    /// engine, like the praudit readability handler in the BSM provider.
    /// Every ~1s (4 idle 250ms polls) a full proc_listpids rescan picks up
    /// pids the NOTE_FORK path missed.
    private func drainLoop() {
        // `kevent` unqualified resolves to the kevent(2) function, not the
        // struct; qualify with the module name in both positions.
        var events: [Darwin.kevent] = Array(repeating: Darwin.kevent(), count: 64)
        var timeout = timespec(tv_sec: 0, tv_nsec: 250_000_000)
        var idleRounds = 0
        while isRunning() {
            let n = kevent(kq, nil, 0, &events, Int32(events.count), &timeout)
            if n < 0 {
                if errno == EINTR { continue }
                if isRunning() {
                    merlinLog("error", "kevent(EVFILT_PROC) failed: errno \(errno); kqueue telemetry stopped")
                }
                return
            }
            for i in 0 ..< Int(n) {
                handle(events[i])
            }
            idleRounds += 1
            if idleRounds >= 4 {
                idleRounds = 0
                rescan()
            }
        }
    }

    /// Periodic full rescan (~1s). Closes the fork→registration race for
    /// fused spawns: a posix_spawn'd child can exec before NOTE_FORK
    /// handling registered it (the exec event is lost), but the rescan
    /// still picks the pid up within a second, so its re-exec and exit are
    /// seen. Newly discovered pids get a (late) fork event.
    private func rescan() {
        for pid in allPids() where pid > 0 {
            lock.lock()
            let known = registered[pid] != nil
            lock.unlock()
            if known { continue }
            let info = procInfo(pid)
            guard track(pid, start: info.map { ProcStart(sec: $0.startSec, usec: $0.startUsec) }) else { continue }
            guard pid != selfPID, let info else { continue }
            lock.lock()
            lastKnown[pid] = (info.uid, info.comm)
            lock.unlock()
            engine.handleFork(
                pid: pid, ppid: info.ppid, comm: info.comm, exe: pidPath(pid),
                identity: info.identity
            )
        }
    }

    private func isRunning() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return running
    }

    private func handle(_ ev: kevent) {
        let pid = pid_t(ev.ident)
        let fflags = ev.fflags

        if fflags & UInt32(NOTE_FORK) != 0 {
            // NOTE_FORK fires on the forking pid, but — unlike the BSD
            // documentation suggests — `data` does NOT carry the child pid
            // on macOS (empirically 0 on macOS 27, arm64). Discover the
            // child via libproc instead: list the parent's children and
            // register the ones we don't know yet. Registration happens
            // before any event handling so the child's exec (often
            // microseconds away) is not missed; there is still a small
            // fork→registration race window, documented in the README.
            //
            // No selfPID skip here on purpose: forks BY this process must
            // still register the child (the test suite spawns children of
            // the daemon process itself). The daemon never forks in
            // production, so this adds no noise.
            for child in childPids(of: pid) where child > 0 && child != selfPID {
                let info = procInfo(child)
                guard track(child, start: info.map { ProcStart(sec: $0.startSec, usec: $0.startUsec) }) else { continue }
                if let info {
                    lock.lock()
                    lastKnown[child] = (info.uid, info.comm)
                    lock.unlock()
                }
                engine.handleFork(
                    pid: child, ppid: pid,
                    comm: info?.comm, exe: pidPath(child), identity: info?.identity
                )
            }
        }
        guard pid != selfPID else { return }
        if fflags & UInt32(NOTE_EXEC) != 0 {
            handleExecEvent(pid: pid)
        }
        if fflags & UInt32(NOTE_EXIT) != 0 {
            lock.lock()
            let known = lastKnown[pid]
            lock.unlock()
            untrack(pid)
            // NOTE_EXITSTATUS: data carries the wait(2)-style status when
            // the kernel allowed it for us (own children, same uid, root);
            // otherwise the flag is absent and exit_code/exit_status spool
            // null. Engine.handleExit applies the same (status>>8)&0xff
            // formula as the Linux port.
            let status: Int32? = fflags & UInt32(NOTE_EXITSTATUS) != 0
                ? Int32(ev.data & 0x000fffff) // NOTE_PDATAMASK
                : nil
            engine.handleExit(pid: pid, uid: known?.uid, comm: known?.comm, status: status)
        }
    }

    /// Pid-reuse guard: true when the process currently occupying `pid` is
    /// the same one we registered (start times match). A mismatch means the
    /// pid was recycled between event generation and enrichment — the event
    /// must be dropped, never acted on. Unverifiable (registration or
    /// current info unreadable) fails open, like the rest of the sensor.
    private func isSameProcess(_ pid: pid_t, current: ProcInfo?) -> Bool {
        lock.lock()
        let recorded = registered[pid] ?? nil
        lock.unlock()
        guard let recorded, let current else { return true }
        return recorded.sec == current.startSec && recorded.usec == current.startUsec
    }

    private func handleExecEvent(pid: pid_t) {
        // Enrichment races the process lifetime; if it already exited and
        // left nothing readable, the event is dropped (same documented race
        // as the other providers' /proc-style enrichment).
        let info = procInfo(pid)
        guard isSameProcess(pid, current: info) else {
            merlinLog("warn", "pid \(pid) recycled between event and enrichment; dropping exec event")
            // The filter died with the old process; register the new
            // occupant so its lifecycle is covered.
            untrack(pid)
            track(pid, start: info.map { ProcStart(sec: $0.startSec, usec: $0.startUsec) })
            return
        }
        guard let exe = pidPath(pid) ?? info?.comm else { return }
        let args = procArgs(pid)
        let cmdline = args?.isEmpty == false ? args?.joined(separator: " ") : nil
        if let info {
            lock.lock()
            lastKnown[pid] = (info.uid, info.comm)
            lock.unlock()
        }
        var sha256: String?
        if engine.needsSHA256ForNotify {
            sha256 = try? sha256File(path: exe, maxBytes: 64 * 1024 * 1024)
        }
        // SecStaticCode enrichment (team_id/signing_id/cdhash, adhoc and
        // platform-binary flags) + quarantine xattr — cached per path.
        // Platform-binary is runtime state; csops on the pid is the truth.
        let signing = signingCache.info(path: exe)
        engine.handleExec(
            pid: pid, ppid: info?.ppid, uid: info?.uid,
            comm: (exe as NSString).lastPathComponent, exe: exe,
            cmdline: cmdline, sha256: sha256, cdhash: signing?.cdhash,
            signing: signing, quarantined: isQuarantined(path: exe),
            platformBinary: isPlatformBinary(pid: pid), identity: info?.identity
        )
    }
}

/// All pids on the system via libproc.
func allPids() -> [pid_t] {
    let byteCount = proc_listpids(UInt32(PROC_ALL_PIDS), 0, nil, 0)
    guard byteCount > 0 else { return [] }
    var buf = [pid_t](repeating: 0, count: Int(byteCount) / MemoryLayout<pid_t>.size + 16)
    let n = proc_listpids(UInt32(PROC_ALL_PIDS), 0, &buf, Int32(buf.count * MemoryLayout<pid_t>.size))
    guard n > 0 else { return [] }
    return buf.prefix(Int(n) / MemoryLayout<pid_t>.size).filter { $0 > 0 }
}

/// Direct children of a pid via libproc (used to discover the child a
/// NOTE_FORK refers to, since macOS doesn't put it in kevent data).
/// NB: unlike proc_listpids (which returns bytes), proc_listchildpids
/// returns a pid COUNT — verified empirically on macOS 27. The NULL-buffer
/// call returns an upper bound suitable for sizing.
func childPids(of ppid: pid_t) -> [pid_t] {
    let upper = proc_listchildpids(ppid, nil, 0)
    guard upper > 0 else { return [] }
    var buf = [pid_t](repeating: 0, count: Int(upper) + 16)
    let n = proc_listchildpids(ppid, &buf, Int32(buf.count * MemoryLayout<pid_t>.size))
    guard n > 0 else { return [] }
    return buf.prefix(Int(n)).filter { $0 > 0 }
}

/// Executable path for a pid (MAXPATHLEN-capped), or nil if the process is
/// gone or cross-user and we're not root.
func pidPath(_ pid: pid_t) -> String? {
    var buf = [CChar](repeating: 0, count: Int(MAXPATHLEN))
    let n = proc_pidpath(pid, &buf, UInt32(buf.count))
    guard n > 0 else { return nil }
    return String(decoding: buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
}

/// argv via sysctl KERN_PROCARGS2. Layout: int32 argc, NUL-terminated exec
/// path, padding NULs, then argc NUL-terminated argv strings (env follows,
/// ignored). The kernel refuses cross-user queries for non-root callers;
/// nil means "unavailable", not "no args".
func procArgs(_ pid: pid_t) -> [String]? {
    var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
    var size = 0
    guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > MemoryLayout<Int32>.size else { return nil }
    var buf = [UInt8](repeating: 0, count: size)
    guard sysctl(&mib, 3, &buf, &size, nil, 0) == 0, size > MemoryLayout<Int32>.size else { return nil }
    buf = Array(buf.prefix(size))
    let argc = buf.withUnsafeBytes { $0.load(as: Int32.self) }
    var i = MemoryLayout<Int32>.size
    func readString() -> String? {
        guard i < buf.count, let end = buf[i...].firstIndex(of: 0) else { return nil }
        let s = String(decoding: buf[i ..< end], as: UTF8.self)
        i = end + 1
        return s
    }
    guard readString() != nil else { return nil } // exec path
    while i < buf.count, buf[i] == 0 { i += 1 } // alignment padding
    var args: [String] = []
    for _ in 0 ..< max(argc, 0) {
        guard let s = readString() else { break }
        args.append(s)
    }
    return args.isEmpty ? nil : args
}
