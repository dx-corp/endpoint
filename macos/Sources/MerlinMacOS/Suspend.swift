// SIGSTOP quasi-blocking: the `suspend` rule action.
//
// Without the Endpoint Security entitlement there is no synchronous
// exec hook on macOS — `block` degrades to a reactive SIGKILL. The
// suspend action is the closest available approximation:
// stop → evaluate → decide.
//
//   1. A matching exec event immediately SIGSTOPs the pid (frozen
//      before it gets further into startup).
//   2. Full enrichment runs against the FROZEN process (sha256 bounded,
//      signing info incl. team_id/cdhash, quarantine, ancestors).
//   3. The ruleset is re-evaluated with the enriched context. Any KILL
//      rule still matching → SIGKILL (kill event with via_suspend:
//      true). Otherwise → SIGCONT and the exec event is marked
//      suspend_released: true. (The decision is made by kill rules
//      alone: the triggering suspend rule always re-matches, and
//      counting it would kill every inspected process — guardrail 4.)
//
// Guardrails (all unit-tested):
//   - The standard failsafes apply BEFORE SIGSTOP: never suspend
//     pid 1, the daemon itself, or own-team processes.
//   - Freeze budget: enrichment+evaluation over 2s (default), or any
//     error, resumes the process immediately — a wedged sensor must
//     never leave frozen processes around. Daemon shutdown SIGCONTs
//     everything still held (SuspendedPids registry).
//   - Process identity (start time) is re-validated after enrichment,
//     before any kill — same rule as the plain kill path.
//   - No second-stage match = always resume: suspend is "stop and
//     inspect", never "stop forever".
//
// Honest framing (documented in reference.md): this is quasi-blocking,
// not prevention — kqueue delivery latency and the fused posix_spawn
// race still apply — but in practice the process gets ~zero useful
// runtime.

import Foundation

/// Pids currently frozen by the suspend path. Daemon shutdown releases
/// all of them so a sensor exit never leaves stopped processes behind.
final class SuspendedPids: @unchecked Sendable {
    static let shared = SuspendedPids()

    private let lock = NSLock()
    private var held: [Int32: ProcessIdentity] = [:]

    func hold(_ pid: Int32, identity: ProcessIdentity) {
        lock.withLock { held[pid] = identity }
    }

    func release(_ pid: Int32) {
        _ = lock.withLock { held.removeValue(forKey: pid) }
    }

    var count: Int {
        lock.withLock { held.count }
    }

    /// SIGCONT each held pid only while it still names the process we stopped.
    /// Returns the pids that were safely released.
    @discardableResult
    func releaseAll(
        processIdentity: @Sendable (Int32) -> ProcessIdentity? = { procInfo($0)?.identity },
        signal: @Sendable (Int32, Int32) -> Int32 = { Darwin.kill($0, $1) }
    ) -> [Int32] {
        let processes = lock.withLock { () -> [Int32: ProcessIdentity] in
            let all = held
            held.removeAll()
            return all
        }
        var released: [Int32] = []
        for (pid, identity) in processes where processIdentity(pid) == identity {
            if signal(pid, SIGCONT) == 0 {
                released.append(pid)
            }
        }
        if !released.isEmpty {
            merlinLog("info", "shutdown: SIGCONT \(released.count) suspended process(es): \(released)")
        }
        return released
    }
}
