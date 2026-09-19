// Endpoint Security provider — the primary macOS collector/enforcer.
//
// Mapping to the Linux port (and to Falcon):
//   ES_EVENT_TYPE_AUTH_EXEC  ≈ fanotify FAN_OPEN_EXEC_PERM: the exec parks
//     in-kernel until es_respond_auth_result delivers the verdict — the
//     macOS analog of the driver writing an NTSTATUS to
//     CreateInfo->CreationStatus. A deny gives the execing thread EPERM.
//   ES_EVENT_TYPE_NOTIFY_EXEC/EXIT/FORK ≈ the eBPF tracepoints/kprobe:
//     asynchronous telemetry, enriched and spooled.
//   es_new_client ≈ the kernel driver accepting CSFalconService's
//     registration; it requires the restricted
//     com.apple.developer.endpoint-security.client entitlement.
//
// Failure policy: fail OPEN. If anything internal goes wrong at the AUTH
// point we allow and log — a sensor must never wedge execs system-wide.

import Foundation

@preconcurrency import EndpointSecurity
import MerlinEndpointSecurityCompat

/// Stand-in deadline used only when the mach timebase is unreadable, so a
/// broken clock conversion never silently reverts AUTH hashing to a fixed
/// byte cap. Halved like a real deadline before it becomes the budget.
private let conservativeHashBudget: TimeInterval = 2

// bsm/libbsm.h audit-token helpers are not exposed to Swift; declare them.
@_silgen_name("audit_token_to_pid")
func audit_token_to_pid(_ token: audit_token_t) -> pid_t
@_silgen_name("audit_token_to_ruid")
func audit_token_to_ruid(_ token: audit_token_t) -> uid_t

func esString(_ token: es_string_token_t) -> String {
    guard let data = token.data, token.length > 0 else { return "" }
    return String(decoding: UnsafeRawBufferPointer(start: data, count: token.length), as: UTF8.self)
}

/// cdhash from an es_process_t: 20 bytes, hex-encoded (40 chars).
func cdhashHex(_ process: UnsafePointer<es_process_t>) -> String {
    var cd = process.pointee.cdhash
    return withUnsafeBytes(of: &cd) { $0.map { String(format: "%02x", $0) }.joined() }
}

enum ESError: Error, CustomStringConvertible {
    case newClient(es_new_client_result_t)
    case subscribe(es_return_t)

    var description: String {
        switch self {
        case .newClient(let r): return "es_new_client failed: \(describeNewClientResult(r))"
        case .subscribe(let r): return "es_subscribe failed (\(r.rawValue))"
        }
    }
}

func describeNewClientResult(_ r: es_new_client_result_t) -> String {
    switch r {
    case ES_NEW_CLIENT_RESULT_SUCCESS: return "success"
    case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT: return "invalid argument (internal)"
    case ES_NEW_CLIENT_RESULT_ERR_INTERNAL: return "internal error"
    case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
        return "not entitled — binary lacks a granted com.apple.developer.endpoint-security.client entitlement"
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
        return "not permitted — Endpoint Security clients must run as root (retry with sudo)"
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
        return "not privileged — run as root"
    case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
        return "too many Endpoint Security clients on this system"
    default: return "unknown result \(r.rawValue)"
    }
}

final class ESProvider: @unchecked Sendable {
    private var client: OpaquePointer?
    private let engine: Engine
    private let selfPID = getpid()
    private let signingCache = SigningInfoCache()

    init(engine: Engine) {
        self.engine = engine
    }

    func start() throws {
        let engine = self.engine
        let selfPID = self.selfPID
        let signingCache = self.signingCache
        var newClient: OpaquePointer?
        let result = es_new_client(&newClient) { client, message in
            ESProvider.handle(
                client: client, message: message, engine: engine,
                selfPID: selfPID, signingCache: signingCache
            )
        }
        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let newClient else {
            throw ESError.newClient(result)
        }
        var coreEvents: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_EXEC,
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_EXIT,
            ES_EVENT_TYPE_NOTIFY_FORK,
        ]
        let coreSub = es_subscribe(newClient, &coreEvents, UInt32(coreEvents.count))
        guard coreSub == ES_RETURN_SUCCESS else {
            es_delete_client(newClient)
            throw ESError.subscribe(coreSub)
        }

        // Optional visibility must never take down the core AUTH_EXEC
        // enforcement path on an older macOS release. Subscribe one event at
        // a time so an unsupported event is a measurable warn, not a reason
        // to lose exec blocking entirely.
        let optionalEvents: [es_event_type_t] = [
            // Notify-only file lifecycle: no AUTH response is required, so
            // this preserves the provider's fail-open enforcement boundary.
            ES_EVENT_TYPE_NOTIFY_CREATE,
            ES_EVENT_TYPE_NOTIFY_WRITE,
            ES_EVENT_TYPE_NOTIFY_RENAME,
            ES_EVENT_TYPE_NOTIFY_UNLINK,
            ES_EVENT_TYPE_NOTIFY_MMAP,
            ES_EVENT_TYPE_NOTIFY_MPROTECT,
            ES_EVENT_TYPE_NOTIFY_SETMODE,
            ES_EVENT_TYPE_NOTIFY_SETOWNER,
            ES_EVENT_TYPE_NOTIFY_SETFLAGS,
            // Security transitions and injection-adjacent signals.
            ES_EVENT_TYPE_NOTIFY_SETUID,
            ES_EVENT_TYPE_NOTIFY_SETGID,
            ES_EVENT_TYPE_NOTIFY_SETEUID,
            ES_EVENT_TYPE_NOTIFY_SETEGID,
            ES_EVENT_TYPE_NOTIFY_SETREUID,
            ES_EVENT_TYPE_NOTIFY_SETREGID,
            ES_EVENT_TYPE_NOTIFY_SIGNAL,
            ES_EVENT_TYPE_NOTIFY_TRACE,
            ES_EVENT_TYPE_NOTIFY_GET_TASK,
            ES_EVENT_TYPE_NOTIFY_KEXTLOAD,
            ES_EVENT_TYPE_NOTIFY_MOUNT,
            ES_EVENT_TYPE_NOTIFY_UNMOUNT,
            ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED,
            // Modern macOS login items and background agents/daemons are
            // registered with Background Task Management rather than being
            // represented solely by a file mutation we can observe.
            ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
            ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE,
        ]
        var optionalCount = 0
        for event in optionalEvents {
            var one = [event]
            let sub = es_subscribe(newClient, &one, 1)
            if sub == ES_RETURN_SUCCESS {
                optionalCount += 1
            } else {
                merlinLog("warn", "Endpoint Security optional event \(event.rawValue) unavailable (\(sub.rawValue)); core exec enforcement remains active")
            }
        }
        client = newClient
        merlinLog("info", "Endpoint Security: subscribed core exec/process plus (optionalCount)/(optionalEvents.count) optional file/security telemetry events")
    }

    func stop() {
        if let c = client {
            es_delete_client(c)
            client = nil
        }
    }

    private static func handle(
        client: OpaquePointer,
        message: UnsafePointer<es_message_t>,
        engine: Engine,
        selfPID: pid_t,
        signingCache: SigningInfoCache
    ) {
        if handleTCCModify(message: message, engine: engine) {
            return
        }
        switch message.pointee.event_type {
        case ES_EVENT_TYPE_AUTH_EXEC:
            handleAuthExec(client: client, message: message, engine: engine, selfPID: selfPID, signingCache: signingCache)
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            handleNotifyExec(message: message, engine: engine, selfPID: selfPID, signingCache: signingCache)
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            let proc = message.pointee.process
            let pid = audit_token_to_pid(proc.pointee.audit_token)
            guard pid != selfPID else { return }
            let uid = audit_token_to_ruid(proc.pointee.audit_token)
            engine.handleExit(
                pid: pid, uid: uid, comm: procInfo(pid)?.comm,
                status: message.pointee.event.exit.stat,
                identity: processIdentity(proc)
            )
        case ES_EVENT_TYPE_NOTIFY_FORK:
            let child = message.pointee.event.fork.child
            let proc = message.pointee.process
            let pid = audit_token_to_pid(child.pointee.audit_token)
            guard pid != selfPID else { return }
            let exe = esString(child.pointee.executable.pointee.path)
            engine.handleFork(
                pid: pid, ppid: audit_token_to_pid(proc.pointee.audit_token),
                comm: (exe as NSString).lastPathComponent, exe: exe,
                identity: processIdentity(child)
            )
        case ES_EVENT_TYPE_NOTIFY_CREATE:
            handleCreate(message: message, engine: engine)
        case ES_EVENT_TYPE_NOTIFY_WRITE:
            let file = message.pointee.event.write.target
            handleFile(message: message, engine: engine, file: file, op: "write")
        case ES_EVENT_TYPE_NOTIFY_RENAME:
            handleRename(message: message, engine: engine)
        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            let file = message.pointee.event.unlink.target
            handleFile(message: message, engine: engine, file: file, op: "delete")
        case ES_EVENT_TYPE_NOTIFY_MMAP:
            let event = message.pointee.event.mmap
            let protection = UInt64(bitPattern: Int64(event.protection))
            handleFile(
                message: message, engine: engine, file: event.source, op: "mmap",
                label: "memory_map"
            )
            handleSecurity(
                message: message, engine: engine, syscall: "mmap",
                syscallNumber: nil, args: [0, 0, protection],
                wXTransition: event.protection & (PROT_WRITE | PROT_EXEC) == (PROT_WRITE | PROT_EXEC)
            )
        case ES_EVENT_TYPE_NOTIFY_MPROTECT:
            let event = message.pointee.event.mprotect
            let protection = UInt64(bitPattern: Int64(event.protection))
            handleSecurity(
                message: message, engine: engine, syscall: "mprotect",
                syscallNumber: nil, args: [UInt64(event.address), UInt64(event.size), protection],
                wXTransition: event.protection & (PROT_WRITE | PROT_EXEC) == (PROT_WRITE | PROT_EXEC)
            )
        case ES_EVENT_TYPE_NOTIFY_SETMODE:
            let file = message.pointee.event.setmode.target
            handleFile(message: message, engine: engine, file: file, op: "chmod")
        case ES_EVENT_TYPE_NOTIFY_SETOWNER:
            let file = message.pointee.event.setowner.target
            handleFile(message: message, engine: engine, file: file, op: "chown")
        case ES_EVENT_TYPE_NOTIFY_SETFLAGS:
            let file = message.pointee.event.setflags.target
            handleFile(message: message, engine: engine, file: file, op: "setflags")
        case ES_EVENT_TYPE_NOTIFY_SETUID:
            handleSecurity(message: message, engine: engine, syscall: "setuid", syscallNumber: nil, args: [UInt64(message.pointee.event.setuid.uid)], wXTransition: nil)
        case ES_EVENT_TYPE_NOTIFY_SETGID:
            handleSecurity(message: message, engine: engine, syscall: "setgid", syscallNumber: nil, args: [UInt64(message.pointee.event.setgid.gid)], wXTransition: nil)
        case ES_EVENT_TYPE_NOTIFY_SETEUID:
            handleSecurity(message: message, engine: engine, syscall: "seteuid", syscallNumber: nil, args: [UInt64(message.pointee.event.seteuid.euid)], wXTransition: nil)
        case ES_EVENT_TYPE_NOTIFY_SETEGID:
            handleSecurity(message: message, engine: engine, syscall: "setegid", syscallNumber: nil, args: [UInt64(message.pointee.event.setegid.egid)], wXTransition: nil)
        case ES_EVENT_TYPE_NOTIFY_SETREUID:
            let event = message.pointee.event.setreuid
            handleSecurity(message: message, engine: engine, syscall: "setreuid", syscallNumber: nil, args: [UInt64(event.ruid), UInt64(event.euid)], wXTransition: nil)
        case ES_EVENT_TYPE_NOTIFY_SETREGID:
            let event = message.pointee.event.setregid
            handleSecurity(message: message, engine: engine, syscall: "setregid", syscallNumber: nil, args: [UInt64(event.rgid), UInt64(event.egid)], wXTransition: nil)
        case ES_EVENT_TYPE_NOTIFY_SIGNAL:
            let event = message.pointee.event.signal
            handleSecurity(
                message: message, engine: engine, syscall: "signal", syscallNumber: nil,
                args: [UInt64(event.sig), UInt64(audit_token_to_pid(event.target.pointee.audit_token))],
                wXTransition: nil
            )
        case ES_EVENT_TYPE_NOTIFY_TRACE:
            let target = message.pointee.event.trace.target
            handleSecurity(
                message: message, engine: engine, syscall: "ptrace", syscallNumber: nil,
                args: [UInt64(audit_token_to_pid(target.pointee.audit_token))], wXTransition: nil
            )
        case ES_EVENT_TYPE_NOTIFY_GET_TASK:
            handleSecurity(message: message, engine: engine, syscall: "task_for_pid", syscallNumber: nil, args: nil, wXTransition: nil)
        case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
            handleSecurity(message: message, engine: engine, syscall: "kextload", syscallNumber: nil, args: nil, wXTransition: nil)
        case ES_EVENT_TYPE_NOTIFY_MOUNT:
            handleSecurity(message: message, engine: engine, syscall: "mount", syscallNumber: nil, args: nil, wXTransition: nil)
        case ES_EVENT_TYPE_NOTIFY_UNMOUNT:
            handleSecurity(message: message, engine: engine, syscall: "unmount", syscallNumber: nil, args: nil, wXTransition: nil)
        case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
            handleSecurity(message: message, engine: engine, syscall: "cs_invalidated", syscallNumber: nil, args: nil, wXTransition: nil)
        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD:
            let event = message.pointee.event.btm_launch_item_add
            handleBackgroundTask(
                message: message, engine: engine, item: event.pointee.item,
                instigator: event.pointee.instigator, app: event.pointee.app,
                executablePath: esString(event.pointee.executable_path),
                op: "create", signal: "background_task_add"
            )
        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE:
            let event = message.pointee.event.btm_launch_item_remove
            handleBackgroundTask(
                message: message, engine: engine, item: event.pointee.item,
                instigator: event.pointee.instigator, app: event.pointee.app,
                executablePath: nil, op: "delete", signal: "background_task_remove"
            )
        default:
            break
        }
    }

    /// Synchronous allow/deny. Respond promptly: the exec is parked in the
    /// kernel and the message carries a deadline. Fail open on any error.
    private static func handleAuthExec(
        client: OpaquePointer,
        message: UnsafePointer<es_message_t>,
        engine: Engine,
        selfPID: pid_t,
        signingCache: SigningInfoCache
    ) {
        func respond(_ result: es_auth_result_t, cache: Bool) {
            es_respond_auth_result(client, message, result, cache)
        }
        /// Time left before the ES deadline; nil when the message carries
        /// no deadline. An unreadable timebase still yields a budget —
        /// falling back to a byte cap would restore the padding bypass.
        func secondsUntil(_ deadline: UInt64) -> TimeInterval? {
            guard deadline > 0 else { return nil }
            let now = mach_absolute_time()
            guard deadline > now else { return 0 }
            var timebase = mach_timebase_info_data_t()
            guard mach_timebase_info(&timebase) == KERN_SUCCESS, timebase.denom != 0 else {
                return conservativeHashBudget
            }
            let nanos = Double(deadline - now) * Double(timebase.numer) / Double(timebase.denom)
            return nanos / 1_000_000_000
        }
        // Past the ES deadline the kernel applies its default action anyway;
        // answer allow immediately rather than computing a stale verdict.
        if message.pointee.deadline > 0, mach_absolute_time() > message.pointee.deadline {
            respond(ES_AUTH_RESULT_ALLOW, cache: false)
            return
        }
        let target = message.pointee.event.exec.target
        let pid = audit_token_to_pid(target.pointee.audit_token)
        if pid == selfPID {
            respond(ES_AUTH_RESULT_ALLOW, cache: true)
            return
        }
        let path = esString(target.pointee.executable.pointee.path)
        let cdhash = cdhashHex(target)
        let uid = audit_token_to_ruid(target.pointee.audit_token)
        let file = target.pointee.executable
        let fileIdentity = FileIdentity(
            device: UInt64(file.pointee.stat.st_dev), inode: UInt64(file.pointee.stat.st_ino)
        )
        var sha256: String?
        if engine.needsSHA256ForAuth {
            do {
                // Bound the hash by the ES deadline rather than a fixed
                // byte count: a fixed cap is attacker-controllable (pad the
                // payload past it and the sha256 selector never runs), and
                // the deadline is what the verdict actually has to meet.
                // Spend at most half of it so the response still lands.
                let remaining = secondsUntil(message.pointee.deadline)
                let cap: UInt64? = remaining == nil ? 64 * 1024 * 1024 : nil
                sha256 = try sha256File(
                    path: path,
                    maxBytes: cap,
                    budget: remaining.map { $0 / 2 },
                    expectedIdentity: fileIdentity
                )
            } catch {
                // Fail open for this selector (hard rule at AUTH_EXEC):
                // rules still match on basename/cdhash/uid.
                merlinLog(
                    "warn",
                    "AUTH_EXEC sha256 failed for \(path): \(error); hash-based block rules cannot be evaluated for this exec"
                )
            }
        }
        let teamId = engine.needsSigningForAuth ? signingCache.info(path: path)?.teamId : nil
        let verdict = engine.authVerdict(pid: pid, uid: uid, path: path, sha256: sha256, cdhash: cdhash, teamId: teamId)
        if verdict.allow {
            respond(ES_AUTH_RESULT_ALLOW, cache: true)
        } else {
            merlinLog("info", "AUTH_EXEC DENY pid=\(pid) path=\(path) rules=\(verdict.matched)")
            respond(ES_AUTH_RESULT_DENY, cache: false)
        }
    }

    /// Asynchronous exec telemetry: args from the event, enrichment via
    /// libproc, log/kill rules in the engine.
    private static func handleNotifyExec(
        message: UnsafePointer<es_message_t>,
        engine: Engine,
        selfPID: pid_t,
        signingCache: SigningInfoCache
    ) {
        let target = message.pointee.event.exec.target
        let pid = audit_token_to_pid(target.pointee.audit_token)
        guard pid != selfPID else { return }
        let path = esString(target.pointee.executable.pointee.path)
        let cdhash = cdhashHex(target)
        let uid = audit_token_to_ruid(target.pointee.audit_token)
        let ppid = target.pointee.ppid
        var ev = message.pointee.event.exec
        let args: [String] = withUnsafePointer(to: &ev) { evp in
            let n = es_exec_arg_count(evp)
            return (0 ..< n).map { esString(es_exec_arg(evp, $0)) }
        }
        let cmdline = args.isEmpty ? nil : args.joined(separator: " ")

        var sha256: String?
        if engine.needsSHA256ForNotify {
            sha256 = try? sha256File(path: path, maxBytes: 64 * 1024 * 1024)
        }
        let signing = signingCache.info(path: path)
        engine.handleExec(
            pid: pid, ppid: ppid, uid: uid,
            comm: (path as NSString).lastPathComponent, exe: path,
            cmdline: cmdline, sha256: sha256, cdhash: cdhash,
            signing: signing, quarantined: isQuarantined(path: path),
            platformBinary: isPlatformBinary(pid: pid), identity: processIdentity(target)
        )
    }

    private static func processIdentity(_ process: UnsafeMutablePointer<es_process_t>) -> ProcessIdentity {
        ProcessIdentity(
            startSec: UInt64(process.pointee.start_time.tv_sec),
            startUsec: UInt64(process.pointee.start_time.tv_usec)
        )
    }

    private static func handleCreate(message: UnsafePointer<es_message_t>, engine: Engine) {
        let event = message.pointee.event.create
        switch event.destination_type {
        case ES_DESTINATION_TYPE_EXISTING_FILE:
            handleFile(message: message, engine: engine, file: event.destination.existing_file, op: "create")
        case ES_DESTINATION_TYPE_NEW_PATH:
            let dir = event.destination.new_path.dir
            let filename = esString(event.destination.new_path.filename)
            let path = esString(dir.pointee.path) + "/" + filename
            handleFile(
                message: message, engine: engine, path: path, device: UInt64(dir.pointee.stat.st_dev),
                inode: nil, op: "create"
            )
        default:
            break
        }
    }

    private static func handleRename(message: UnsafePointer<es_message_t>, engine: Engine) {
        let event = message.pointee.event.rename
        let path: String?
        let device: UInt64?
        let inode: UInt64?
        switch event.destination_type {
        case ES_DESTINATION_TYPE_EXISTING_FILE:
            let file = event.destination.existing_file
            path = esString(file.pointee.path)
            device = UInt64(file.pointee.stat.st_dev)
            inode = UInt64(file.pointee.stat.st_ino)
        case ES_DESTINATION_TYPE_NEW_PATH:
            let dir = event.destination.new_path.dir
            path = esString(dir.pointee.path) + "/" + esString(event.destination.new_path.filename)
            device = UInt64(dir.pointee.stat.st_dev)
            inode = nil
        default:
            path = nil
            device = nil
            inode = nil
        }
        handleFile(
            message: message, engine: engine, path: path, device: device,
            inode: inode, op: "rename", label: "filesystem"
        )
        // The source is useful when a destination is new and the kernel did
        // not provide an existing-file identity.
        let source = event.source
        handleFile(
            message: message, engine: engine, file: source, op: "rename_source",
            label: "filesystem"
        )
    }

    private static func handleFile(
        message: UnsafePointer<es_message_t>, engine: Engine,
        file: UnsafeMutablePointer<es_file_t>, op: String,
        label: String? = nil
    ) {
        handleFile(
            message: message, engine: engine, path: esString(file.pointee.path),
            device: UInt64(file.pointee.stat.st_dev), inode: UInt64(file.pointee.stat.st_ino),
            size: UInt64(file.pointee.stat.st_size), mode: String(file.pointee.stat.st_mode & 0o7777, radix: 8),
            op: op, label: label
        )
    }

    private static func handleFile(
        message: UnsafePointer<es_message_t>, engine: Engine,
        path: String?, device: UInt64?, inode: UInt64?, size: UInt64? = nil, mode: String? = nil, op: String,
        label: String? = nil
    ) {
        let proc = message.pointee.process
        let pid = audit_token_to_pid(proc.pointee.audit_token)
        engine.handleFile(
            pid: pid, uid: audit_token_to_ruid(proc.pointee.audit_token), path: path,
            op: op, label: label ?? persistenceLabel(path), device: device, inode: inode,
            size: size, mode: mode
        )
    }

    private static func handleSecurity(
        message: UnsafePointer<es_message_t>, engine: Engine, syscall: String,
        syscallNumber: UInt32?, args: [UInt64]?, wXTransition: Bool?
    ) {
        let proc = message.pointee.process
        let pid = audit_token_to_pid(proc.pointee.audit_token)
        engine.handleSecurity(
            pid: pid, uid: audit_token_to_ruid(proc.pointee.audit_token), comm: procInfo(pid)?.comm,
            syscall: syscall, syscallNumber: syscallNumber, args: args,
            wXTransition: wXTransition, identity: processIdentity(proc)
        )
    }

    private static func handleBackgroundTask(
        message: UnsafePointer<es_message_t>, engine: Engine,
        item: UnsafeMutablePointer<es_btm_launch_item_t>,
        instigator: UnsafeMutablePointer<es_process_t>?,
        app: UnsafeMutablePointer<es_process_t>?,
        executablePath: String?, op: String, signal: String
    ) {
        // The instigator is the process that asked BTM to change state. Some
        // system-originated registrations omit it; the registering app, and
        // finally the message's process, still provide a useful actor PID.
        let actor = instigator ?? app ?? message.pointee.process
        let actorPID = audit_token_to_pid(actor.pointee.audit_token)
        let rawURL = esString(item.pointee.item_url)
        let appURL = esString(item.pointee.app_url)
        let path = btmFilePath(rawURL.isEmpty ? appURL : rawURL)
        let program = executablePath.flatMap { $0.isEmpty ? nil : $0 }
            ?? btmFilePath(appURL)
        var signals = ["persistence_change", signal]
        if item.pointee.managed { signals.append("background_task_managed") }
        if item.pointee.legacy { signals.append("background_task_legacy") }
        let type = btmItemTypeName(item.pointee.item_type)
        engine.handleBackgroundTask(
            pid: actorPID, path: path, op: op,
            label: "background_task/\(type)", program: program, signals: signals
        )
        merlinLog(
            "info",
            "BTM \(op) type=\(type) pid=\(actorPID) path=\(path ?? "?") program=\(program ?? "?")"
        )
    }

    private static func handleTCCModify(message: UnsafePointer<es_message_t>, engine: Engine) -> Bool {
        var service = [CChar](repeating: 0, count: 129)
        var identity = [CChar](repeating: 0, count: 257)
        var identityType: UInt32 = 0
        var updateType: UInt32 = 0
        var right: UInt32 = 0
        var reason: UInt32 = 0
        let handled = service.withUnsafeMutableBufferPointer { serviceBuffer in
            identity.withUnsafeMutableBufferPointer { identityBuffer in
                merlin_es_tcc_modify_info(
                    message,
                    serviceBuffer.baseAddress, serviceBuffer.count,
                    identityBuffer.baseAddress, identityBuffer.count,
                    &identityType, &updateType, &right, &reason
                )
            }
        }
        guard handled else { return false }

        let serviceText = String(decoding: service.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
        let identityText = String(decoding: identity.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
        let actor = message.pointee.process
        let actorPID = audit_token_to_pid(actor.pointee.audit_token)
        engine.handleTCCModify(
            pid: actorPID,
            uid: audit_token_to_ruid(actor.pointee.audit_token),
            comm: procInfo(actorPID)?.comm,
            service: serviceText,
            identityHash: sha256Hex(Data(identityText.utf8)),
            identityType: tccIdentityTypeName(identityType),
            updateType: tccUpdateTypeName(updateType),
            right: String(right),
            reason: String(reason),
            identity: processIdentity(actor)
        )
        return true
    }

    private static func tccIdentityTypeName(_ type: UInt32) -> String {
        switch type {
        case 0: return "bundle_id"
        case 1: return "executable_path"
        case 2: return "policy_id"
        case 3: return "file_provider_domain_id"
        default: return "unknown"
        }
    }

    private static func tccUpdateTypeName(_ type: UInt32) -> String {
        switch type {
        case 1: return "create"
        case 2: return "modify"
        case 3: return "delete"
        default: return "unknown"
        }
    }

    private static func btmItemTypeName(_ type: es_btm_item_type_t) -> String {
        switch type {
        case ES_BTM_ITEM_TYPE_USER_ITEM: return "user_item"
        case ES_BTM_ITEM_TYPE_APP: return "app"
        case ES_BTM_ITEM_TYPE_LOGIN_ITEM: return "login_item"
        case ES_BTM_ITEM_TYPE_AGENT: return "agent"
        case ES_BTM_ITEM_TYPE_DAEMON: return "daemon"
        default: return "unknown"
        }
    }

    private static func btmFilePath(_ value: String) -> String? {
        guard !value.isEmpty else { return nil }
        if let url = URL(string: value), url.isFileURL { return url.path }
        return value
    }

    private static func persistenceLabel(_ path: String?) -> String? {
        guard let path else { return nil }
        if path.contains("LaunchAgents") || path.contains("LaunchDaemons") { return "launchd" }
        if path.contains("/periodic/") || path.contains("/cron") { return "scheduler" }
        if path.hasSuffix("authorized_keys") { return "ssh_authorized_keys" }
        if path.hasSuffix("/etc/profile") || path.contains("/etc/profile.d/") { return "shell_startup" }
        return "filesystem"
    }
}
