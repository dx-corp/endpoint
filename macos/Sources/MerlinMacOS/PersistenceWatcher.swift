// Persistence-path watcher — entitlement-free file telemetry for the
// classic macOS persistence locations (LaunchAgents/LaunchDaemons,
// periodic scripts).
//
// Mechanism: O_EVTONLY open per watched directory + a DispatchSource
// vnode watch (NOTE_WRITE|NOTE_DELETE|NOTE_RENAME|NOTE_ATTRIB). A vnode
// event says "the directory changed", not what changed, so each event
// triggers a shallow rescan and a snapshot diff (create/modify/delete/
// rename — renames are matched by inode). pid attribution is NOT
// available from vnode watches (unlike FSEvents' process info, which is
// itself best-effort): file events spool pid as null, documented.
//
// One level of subdirectories is watched too (e.g. /private/etc/periodic
// holds daily/weekly/monthly). Newly created subdirectories pick up a
// watch on the next rescan; a deleted/renamed watched directory is
// re-watched when it reappears.
//
// For .plist files under a LaunchAgents/LaunchDaemons directory,
// create/modify events are enriched with the plist's Label and
// Program/ProgramArguments (best-effort PropertyListSerialization parse —
// a malformed plist yields nulls, never a crash).

import Foundation

/// What the watcher reports for one path.
struct FileWatchEvent: Equatable {
    enum Op: String {
        case create, modify, delete, rename
    }

    var path: String
    var op: Op
    var label: String?
    var program: String?
}

/// Snapshot entry for one file: identity (inode) + change evidence.
struct FileMeta: Equatable {
    var inode: UInt64
    var mtime: TimeInterval
    var size: Int64
}

/// Pure snapshot diff — the heart of the watcher, unit-tested directly.
/// `old`/`new` map path → metadata for one directory (shallow). A path
/// whose inode vanished from `old` and reappears under a different name
/// is a rename (reported once, not create+delete).
func diffSnapshots(old: [String: FileMeta], new: [String: FileMeta]) -> [FileWatchEvent] {
    // Renames first: inode present under different paths in old and new.
    let newInodes: [UInt64: String] = new.reduce(into: [:]) { $0[$1.value.inode] = $1.key }
    var renamedFrom: Set<String> = []
    var renamedTo: Set<String> = []
    var events: [FileWatchEvent] = []
    for (path, meta) in old where new[path] == nil {
        if let moved = newInodes[meta.inode], moved != path, old[moved] == nil {
            events.append(FileWatchEvent(path: moved, op: .rename))
            renamedFrom.insert(path)
            renamedTo.insert(moved)
        }
    }
    for (path, meta) in new {
        guard !renamedTo.contains(path) else { continue }
        guard let prev = old[path] else {
            events.append(FileWatchEvent(path: path, op: .create))
            continue
        }
        if prev.inode != meta.inode || prev.mtime != meta.mtime || prev.size != meta.size {
            events.append(FileWatchEvent(path: path, op: .modify))
        }
    }
    for (path, _) in old where new[path] == nil && !renamedFrom.contains(path) {
        events.append(FileWatchEvent(path: path, op: .delete))
    }
    return events.sorted { $0.path < $1.path }
}

/// Best-effort Label + Program extraction from a LaunchAgent/Daemon
/// plist. Malformed input returns nils — never throws, never crashes.
func extractLaunchItemInfo(path: String) -> (label: String?, program: String?) {
    let fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    guard fd >= 0 else { return (nil, nil) }
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    let data = handle.readData(ofLength: 1 << 20)
    guard data.count < 1 << 20,
          let obj = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
          let dict = obj as? [String: Any]
    else { return (nil, nil) }
    let label = dict["Label"] as? String
    let program = (dict["Program"] as? String)
        ?? (dict["ProgramArguments"] as? [Any])?.compactMap { $0 as? String }.first
    return (label, program)
}

/// LoginHook/LogoutHook from com.apple.loginwindow.plist (both optional
/// strings; nils when absent or the plist is unreadable).
func extractLoginHooks(path: String) -> (login: String?, logout: String?) {
    guard let data = FileManager.default.contents(atPath: path),
          let obj = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
          let dict = obj as? [String: Any]
    else { return (nil, nil) }
    return (dict["LoginHook"] as? String, dict["LogoutHook"] as? String)
}

/// Best-effort summary of com.apple.loginitems.plist: item names when the
/// (legacy, undocumented) format yields them, else just a count, else
/// nil. Modern login items live in BackgroundTaskManagement and are NOT
/// visible here — documented in the README.
func loginItemsSummary(path: String) -> String? {
    guard let data = FileManager.default.contents(atPath: path),
          let obj = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
          let dict = obj as? [String: Any]
    else { return nil }
    for value in dict.values {
        guard let items = value as? [[String: Any]] else { continue }
        let names = items.compactMap { $0["Name"] as? String }
        if !names.isEmpty { return names.joined(separator: ", ") }
        return "\(items.count) item(s)"
    }
    return nil
}

/// What the persistence watcher watches: directories (shallow + one
/// level of subdirectories) and individual files. Injectable into the
/// watcher for tests.
struct WatchTargets {
    var dirs: [String]
    var files: [String]
}

/// KnockKnock-style persistence locations. Root watches every /Users/*
// home; a plain user gets their own plus the world-readable system paths.
func persistenceWatchTargets(root: Bool) -> WatchTargets {
    var dirs = [
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "/private/etc/periodic",
        "/usr/lib/cron/tabs",
        "/var/at/tabs",
        "/Library/StartupItems",
        "/Library/PrivilegedHelperTools",
        "/Library/LaunchServices",
        "/Library/PreferencePanes",
        "/Library/Screen Savers",
        "/Library/Internet Plug-Ins",
        "/Library/Audio/Plug-Ins/HAL",
        "/Library/Security/SecurityAgentPlugins",
        "/Library/Spotlight",
        "/Library/QuickLook",
    ]
    var files = [
        "/private/etc/rc.common",
        "/Library/Preferences/com.apple.loginwindow.plist",
    ]
    let homes = root
        ? ((try? FileManager.default.contentsOfDirectory(atPath: "/Users")) ?? []).map { "/Users/\($0)" }
        : [NSHomeDirectory()]
    for home in homes {
        dirs += [
            "\(home)/Library/LaunchAgents",
            "\(home)/Library/LaunchServices",
            "\(home)/Library/PreferencePanes",
            "\(home)/Library/Screen Savers",
            "\(home)/Library/Internet Plug-Ins",
            "\(home)/Library/Audio/Plug-Ins/HAL",
            "\(home)/Library/Security/SecurityAgentPlugins",
            "\(home)/Library/Spotlight",
            "\(home)/Library/QuickLook",
        ]
        for rc in [".zshrc", ".zprofile", ".bash_profile", ".bashrc"] {
            files.append("\(home)/\(rc)")
        }
        files.append("\(home)/Library/Preferences/com.apple.loginitems.plist")
    }
    return WatchTargets(dirs: dirs, files: files)
}

/// Enrich a create/modify event with plist details where the path calls
/// for it: Label/Program for LaunchAgents/Daemons, hooks for
/// com.apple.loginwindow.plist, a summary for com.apple.loginitems.plist.
func enrichFileEvent(_ ev: inout FileWatchEvent) {
    guard ev.op == .create || ev.op == .modify else { return }
    let name = (ev.path as NSString).lastPathComponent
    if name == "com.apple.loginwindow.plist" {
        let hooks = extractLoginHooks(path: ev.path)
        ev.label = "loginwindow"
        ev.program = [hooks.login, hooks.logout].compactMap { $0 }.joined(separator: " | ")
        if ev.program?.isEmpty == true { ev.program = nil }
        return
    }
    if name == "com.apple.loginitems.plist" {
        ev.label = "loginitems"
        ev.program = loginItemsSummary(path: ev.path)
        return
    }
    if ev.path.hasSuffix(".plist"),
       ev.path.contains("LaunchAgents") || ev.path.contains("LaunchDaemons")
    {
        let info = extractLaunchItemInfo(path: ev.path)
        ev.label = info.label
        ev.program = info.program
    }
}

final class PersistenceWatcher: @unchecked Sendable {
    private struct DirWatch {
        var fd: Int32
        var source: DispatchSourceFileSystemObject
        var snapshot: [String: FileMeta]
        var fileWatches: [String: (fd: Int32, source: DispatchSourceFileSystemObject)]
    }

    private let queue = DispatchQueue(label: "merlin.persistence")
    private let onEvent: (FileWatchEvent) -> Void
    private let lock = NSLock()
    /// Watched directory → its watch state (dir vnode + per-file vnodes).
    private var watches: [String: DirWatch] = [:]
    /// Standalone watched files (shell rc files, rc.common, preference
    /// plists) → fd/source plus last known metadata.
    private var fileTargets: [String: (fd: Int32, source: DispatchSourceFileSystemObject, meta: FileMeta?)] = [:]
    private var running = false
    private var stopped = false

    /// `dirs` are watched shallow plus one level of subdirectories;
    /// `files` are individual file targets (missing files are retried
    /// every 5s until they appear).
    init(dirs: [String], files: [String] = [], onEvent: @escaping (FileWatchEvent) -> Void) {
        self.onEvent = onEvent
        for dir in dirs {
            addWatchRecursive(dir, depth: 1)
        }
        for file in files {
            addFileTarget(file)
        }
    }

    deinit { stop() }

    func stop() {
        lock.lock()
        let all = watches
        watches.removeAll()
        let targets = fileTargets
        fileTargets.removeAll()
        running = false
        stopped = true
        lock.unlock()
        for (_, w) in all {
            w.source.cancel()
            close(w.fd)
            for (_, fw) in w.fileWatches {
                fw.source.cancel()
                close(fw.fd)
            }
        }
        for (_, t) in targets {
            t.source.cancel()
            close(t.fd)
        }
    }

    /// Snapshot one directory (shallow, regular files and symlinks).
    private func snapshot(_ dir: String) -> [String: FileMeta] {
        var out: [String: FileMeta] = [:]
        let names = (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []
        for name in names {
            let path = dir + "/" + name
            var st = stat()
            guard lstat(path, &st) == 0 else { continue }
            out[path] = FileMeta(
                inode: UInt64(st.st_ino),
                mtime: TimeInterval(st.st_mtimespec.tv_sec) + TimeInterval(st.st_mtimespec.tv_nsec) / 1e9,
                size: st.st_size
            )
        }
        return out
    }

    private func addWatchRecursive(_ dir: String, depth: Int) {
        addWatch(dir)
        guard depth > 0 else { return }
        for name in (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? [] {
            let path = dir + "/" + name
            var st = stat()
            if lstat(path, &st) == 0, st.st_mode & S_IFMT == S_IFDIR {
                addWatchRecursive(path, depth: depth - 1)
            }
        }
    }

    private func makeSource(_ fd: Int32, handler: @escaping () -> Void) -> DispatchSourceFileSystemObject {
        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.write, .delete, .rename, .attrib],
            queue: queue
        )
        source.setEventHandler(handler: handler)
        source.resume()
        return source
    }

    private func addWatch(_ dir: String) {
        lock.lock()
        defer { lock.unlock() }
        guard watches[dir] == nil else { return }
        var dirStat = stat()
        guard lstat(dir, &dirStat) == 0, dirStat.st_mode & S_IFMT == S_IFDIR else { return }
        let fd = open(dir, O_EVTONLY | O_NOFOLLOW)
        guard fd >= 0 else { return } // missing/unreadable dir: skip silently
        let source = makeSource(fd) { [weak self] in self?.directoryChanged(dir) }
        let snap = snapshot(dir)
        var w = DirWatch(fd: fd, source: source, snapshot: snap, fileWatches: [:])
        // Per-file vnode watches: a directory NOTE_WRITE only covers entry
        // changes (create/delete/rename), never content modification of
        // the files inside — modify needs a watch per file.
        for path in snap.keys {
            if let fw = openFileWatch(dir: dir, path: path) {
                w.fileWatches[path] = fw
            }
        }
        watches[dir] = w
        if !running { running = true }
    }

    /// Caller must hold `lock`.
    private func openFileWatch(dir: String, path: String) -> (fd: Int32, source: DispatchSourceFileSystemObject)? {
        var st = stat()
        guard lstat(path, &st) == 0, st.st_mode & S_IFMT == S_IFREG else { return nil }
        let fd = open(path, O_EVTONLY | O_NOFOLLOW)
        guard fd >= 0 else { return nil }
        let source = makeSource(fd) { [weak self] in self?.fileChanged(dir: dir, path: path) }
        return (fd, source)
    }

    private func fileChanged(dir: String, path: String) {
        var st = stat()
        guard lstat(path, &st) == 0, st.st_mode & S_IFMT == S_IFREG else { return } // gone or replaced by a link: the dir event reports it
        let meta = FileMeta(
            inode: UInt64(st.st_ino),
            mtime: TimeInterval(st.st_mtimespec.tv_sec) + TimeInterval(st.st_mtimespec.tv_nsec) / 1e9,
            size: st.st_size
        )
        lock.lock()
        let prev = watches[dir]?.snapshot[path]
        if prev != meta { watches[dir]?.snapshot[path] = meta }
        lock.unlock()
        guard let prev, prev != meta, prev.inode == meta.inode else { return }
        var ev = FileWatchEvent(path: path, op: .modify)
        enrichFileEvent(&ev)
        onEvent(ev)
    }

    /// Watch one standalone file; missing targets retry until they appear
    /// (shell rc files often don't exist yet).
    ///
    /// Unlike the directory watches, this deliberately follows symlinks: a
    /// standalone target is a well-known path whose *contents* matter, and
    /// dotfile managers routinely make `~/.zshrc` a symlink into a checkout.
    /// `O_NOFOLLOW` here would silently stop watching those. In a watched
    /// directory the symlink itself is the artifact (dropping one into
    /// LaunchAgents is the persistence), so that side does not follow.
    private func addFileTarget(_ path: String) {
        lock.lock()
        let already = fileTargets[path] != nil
        let stoppedNow = stopped
        lock.unlock()
        guard !already, !stoppedNow else { return }
        var st = stat()
        guard stat(path, &st) == 0 else {
            queue.asyncAfter(deadline: .now() + 5) { [weak self] in self?.addFileTarget(path) }
            return
        }
        let fd = open(path, O_EVTONLY)
        guard fd >= 0 else {
            queue.asyncAfter(deadline: .now() + 5) { [weak self] in self?.addFileTarget(path) }
            return
        }
        let meta = FileMeta(
            inode: UInt64(st.st_ino),
            mtime: TimeInterval(st.st_mtimespec.tv_sec) + TimeInterval(st.st_mtimespec.tv_nsec) / 1e9,
            size: st.st_size
        )
        let source = makeSource(fd) { [weak self] in self?.fileTargetChanged(path) }
        lock.lock()
        fileTargets[path] = (fd, source, meta)
        if !running { running = true }
        lock.unlock()
    }

    private func fileTargetChanged(_ path: String) {
        var st = stat()
        guard stat(path, &st) == 0 else {
            // Deleted (or renamed away): report, drop the watch, retry for
            // reappearance.
            lock.lock()
            let t = fileTargets.removeValue(forKey: path)
            let wasRunning = running
            lock.unlock()
            if let t {
                t.source.cancel()
                close(t.fd)
            }
            var ev = FileWatchEvent(path: path, op: .delete)
            enrichFileEvent(&ev)
            onEvent(ev)
            if wasRunning {
                queue.asyncAfter(deadline: .now() + 5) { [weak self] in self?.addFileTarget(path) }
            }
            return
        }
        let meta = FileMeta(
            inode: UInt64(st.st_ino),
            mtime: TimeInterval(st.st_mtimespec.tv_sec) + TimeInterval(st.st_mtimespec.tv_nsec) / 1e9,
            size: st.st_size
        )
        lock.lock()
        let prev = fileTargets[path]?.meta
        fileTargets[path]?.meta = meta
        lock.unlock()
        guard let prev, prev != meta else { return }
        var ev = FileWatchEvent(path: path, op: .modify)
        enrichFileEvent(&ev)
        onEvent(ev)
        if prev.inode != meta.inode {
            // The path names a different file now — an atomic `mv` replace or
            // a retargeted symlink. The vnode watch is pinned to the old
            // inode, so without re-opening every later write goes unseen.
            rewatchFileTarget(path)
        }
    }

    /// Re-establish a standalone file watch on the inode the path names now.
    private func rewatchFileTarget(_ path: String) {
        lock.lock()
        let t = fileTargets.removeValue(forKey: path)
        lock.unlock()
        if let t {
            t.source.cancel()
            close(t.fd)
        }
        addFileTarget(path)
    }

    private func directoryChanged(_ dir: String) {
        var st = stat()
        guard lstat(dir, &st) == 0, st.st_mode & S_IFMT == S_IFDIR else {
            // The watched directory itself is gone: everything in it went
            // with it, then re-watch when it reappears.
            lock.lock()
            let old = watches[dir]?.snapshot ?? [:]
            if let w = watches.removeValue(forKey: dir) {
                w.source.cancel()
                if w.fd >= 0 { close(w.fd) }
                for (_, fw) in w.fileWatches {
                    fw.source.cancel()
                    close(fw.fd)
                }
            }
            let wasRunning = running
            lock.unlock()
            for ev in diffSnapshots(old: old, new: [:]) { onEvent(ev) }
            if wasRunning {
                queue.asyncAfter(deadline: .now() + 5) { [weak self] in
                    self?.reAddIfReappeared(dir)
                }
            }
            return
        }
        lock.lock()
        let old = watches[dir]?.snapshot ?? [:]
        lock.unlock()
        let new = snapshot(dir)
        let events = diffSnapshots(old: old, new: new)
        lock.lock()
        if watches[dir] != nil {
            watches[dir]?.snapshot = new
            // Re-arm file watches from scratch: cheap (these dirs hold a
            // handful of files) and self-heals inode swaps (atomic saves).
            for (_, fw) in watches[dir]?.fileWatches ?? [:] {
                fw.source.cancel()
                close(fw.fd)
            }
            watches[dir]?.fileWatches = [:]
            for path in new.keys {
                if let fw = openFileWatch(dir: dir, path: path) {
                    watches[dir]?.fileWatches[path] = fw
                }
            }
        }
        lock.unlock()
        for var ev in events {
            enrichFileEvent(&ev)
            onEvent(ev)
        }
        // New subdirectories get a watch (one level only — addWatchRecursive
        // from a root of depth 1 covers the watched set by construction;
        // anything deeper is out of scope on purpose).
        for (path, _) in new {
            var fst = stat()
            if lstat(path, &fst) == 0, fst.st_mode & S_IFMT == S_IFDIR, old[path] == nil {
                queue.async { [weak self] in self?.addWatch(path) }
            }
        }
    }

    private func reAddIfReappeared(_ dir: String) {
        lock.lock()
        let alive = running
        lock.unlock()
        guard alive else { return }
        var st = stat()
        if lstat(dir, &st) == 0, st.st_mode & S_IFMT == S_IFDIR {
            addWatch(dir)
        } else {
            queue.asyncAfter(deadline: .now() + 5) { [weak self] in
                self?.reAddIfReappeared(dir)
            }
        }
    }
}

/// Spool sink used by the daemon: one file event per line, pid always
/// null (no attribution from vnode watches).
func spoolFileEvent(_ spool: SpoolWriter) -> (FileWatchEvent) -> Void {
    { ev in
        var st = stat()
        let exists = lstat(ev.path, &st) == 0
        let identity: (UInt64?, UInt64?) = exists
            ? (UInt64(st.st_dev), UInt64(st.st_ino))
            : (nil, nil)
        spool.write(SpoolEvent(
            kind: .file, pid: nil, path: ev.path,
            op: ev.op.rawValue, label: ev.label, program: ev.program,
            fileDevice: identity.0, fileInode: identity.1,
            fileSize: exists ? UInt64(st.st_size) : nil,
            fileMode: exists ? String(st.st_mode & 0o7777, radix: 8) : nil,
            contentCollected: false
        ))
    }
}
