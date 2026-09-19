import Foundation
import Testing
@testable import MerlinMacOS

// Spool event JSON encoding — field-name and shape parity with the Linux
// port's serde_json output (null-when-absent, snake_case keys).

private func encodeToDict(_ event: SpoolEvent) throws -> [String: Any] {
    let data = try JSONEncoder().encode(event)
    // Exactly one line when written to the spool.
    #expect(!data.contains(0x0a))
    let obj = try JSONSerialization.jsonObject(with: data)
    guard let dict = obj as? [String: Any] else {
        Issue.record("event did not encode to a JSON object")
        return [:]
    }
    return dict
}

@Suite("event encoding")
struct EventEncodingTests {
    @Test("exec event key set and null-when-absent")
    func execEvent() throws {
        let e = SpoolEvent(
            kind: .exec, pid: 123, ppid: 1, uid: 501, comm: "zsh",
            exe: "/bin/zsh", cmdline: "zsh -c id", sha256: nil, cdhash: "abcd",
            matchedRules: [], ancestors: [Ancestor(pid: 1, comm: "launchd")],
            quarantined: false, unsigned: nil, isPlatformBinary: true
        )
        let d = try encodeToDict(e)
        #expect(Set(d.keys) == [
            "ts", "kind", "source", "source_seq", "pid", "ppid", "uid", "comm", "exe", "cmdline",
            "sha256", "cdhash", "matched_rules", "ancestors",
            "quarantined", "unsigned", "is_platform_binary", "pid_start_sec", "pid_start_usec",
            "schema_version", "boot_id", "event_id", "process_key", "signals", "spooled_ts",
        ])
        #expect(d["kind"] as? String == "exec")
        #expect(d["pid"] as? Int == 123)
        #expect(d["cdhash"] as? String == "abcd")
        #expect(d["sha256"] is NSNull) // absent evidence is an explicit null, like the Linux port
        #expect(d["quarantined"] as? Bool == false)
        #expect(d["unsigned"] is NSNull) // undetermined enrichment is null too
        #expect(d["is_platform_binary"] as? Bool == true)
        let ancestors = d["ancestors"] as? [[String: Any]]
        #expect(ancestors?.first?["pid"] as? Int == 1)
        #expect(ancestors?.first?["comm"] as? String == "launchd")
    }

    @Test("exit event key set, exit_status formula")
    func exitEvent() throws {
        let e = SpoolEvent(kind: .exit, pid: 5, uid: 0, comm: "id", exitCode: 256, exitStatus: 1)
        let d = try encodeToDict(e)
        #expect(Set(d.keys) == ["ts", "kind", "source", "source_seq", "pid", "uid", "comm", "exit_code", "exit_status", "pid_start_sec", "pid_start_usec", "schema_version", "boot_id", "event_id", "process_key", "signals", "spooled_ts"])
        #expect(d["exit_code"] as? Int == 256)
        #expect(d["exit_status"] as? Int == 1)
    }

    @Test("deny event key set (fanotify/FAN_DENY analog)")
    func denyEvent() throws {
        let e = SpoolEvent(
            kind: .deny, pid: 9, uid: 501, path: "/tmp/merlin-evil",
            sha256: "ff", cdhash: nil, matchedRules: ["block-merlin-evil"]
        )
        let d = try encodeToDict(e)
        #expect(Set(d.keys) == ["ts", "kind", "source", "source_seq", "pid", "uid", "path", "sha256", "cdhash", "matched_rules", "schema_version", "boot_id", "event_id", "process_key", "signals", "spooled_ts"])
        #expect(d["kind"] as? String == "deny")
        #expect(d["matched_rules"] as? [String] == ["block-merlin-evil"])
        #expect(d["cdhash"] is NSNull)
    }

    @Test("kill event key set")
    func killEvent() throws {
        let e = SpoolEvent(kind: .kill, pid: 9, uid: 501, comm: "nc", exe: "/usr/bin/nc", matchedRules: ["kill-netcat"])
        let d = try encodeToDict(e)
        #expect(Set(d.keys) == ["ts", "kind", "source", "source_seq", "pid", "uid", "comm", "exe", "matched_rules", "schema_version", "boot_id", "event_id", "process_key", "signals", "spooled_ts"])
    }

    @Test("fork event key set")
    func forkEvent() throws {
        let e = SpoolEvent(kind: .fork, pid: 10, ppid: 1, comm: "sh", exe: "/bin/sh")
        let d = try encodeToDict(e)
        #expect(Set(d.keys) == ["ts", "kind", "source", "source_seq", "pid", "ppid", "comm", "exe", "pid_start_sec", "pid_start_usec", "parent_pid_start_sec", "parent_pid_start_usec", "schema_version", "boot_id", "event_id", "process_key", "signals", "spooled_ts"])
    }

    @Test("connect event key set (Linux schema parity)")
    func connectEvent() throws {
        let e = SpoolEvent(
            kind: .connect, pid: 4242, uid: 501, comm: "curl",
            saddr: "192.168.1.10", daddr: "93.184.216.34", dport: 443
        )
        let d = try encodeToDict(e)
        // Exact Linux port key set (merlin/src/telemetry.rs handle_connect).
        #expect(Set(d.keys) == ["ts", "kind", "source", "source_seq", "pid", "uid", "comm", "saddr", "daddr", "sport", "dport", "family", "protocol", "old_state", "state", "pid_start_sec", "pid_start_usec", "schema_version", "boot_id", "event_id", "process_key", "signals", "spooled_ts"])
        #expect(d["kind"] as? String == "connect")
        #expect(d["dport"] as? Int == 443)
        #expect(d["saddr"] as? String == "192.168.1.10")
        // Unattributed flow: pid/uid/comm are explicit nulls.
        let e2 = SpoolEvent(kind: .connect, saddr: "10.0.0.2", daddr: "1.1.1.1", dport: 53)
        let d2 = try encodeToDict(e2)
        #expect(d2["pid"] is NSNull)
        #expect(d2["comm"] is NSNull)
        // IPv6 event: same key set — the address string shows the family.
        let e3 = SpoolEvent(
            kind: .connect, pid: 4242, uid: 501, comm: "curl",
            saddr: "2001:db8::1", daddr: "2606:2800:20::1", dport: 443
        )
        let d3 = try encodeToDict(e3)
        #expect(Set(d3.keys) == Set(d.keys))
        #expect(d3["daddr"] as? String == "2606:2800:20::1")
    }

    @Test("security event carries opaque transition evidence")
    func securityEvent() throws {
        let e = SpoolEvent(
            kind: .security, pid: 42, uid: 0, comm: "injector",
            syscall: "mprotect", syscallNumber: nil, args: [0x1000, 0x2000, 0x6],
            wXTransition: true, namespaceValid: nil
        )
        let d = try encodeToDict(e)
        #expect(d["syscall"] as? String == "mprotect")
        #expect(d["w_x_transition"] as? Bool == true)
        #expect(d["args"] as? [Int] == [4096, 8192, 6])
        #expect(d["content_collected"] == nil)
        #expect(Set(d.keys) == [
            "ts", "kind", "source", "source_seq", "pid", "uid", "comm",
            "syscall", "syscall_nr", "args", "w_x_transition", "namespace_valid",
            "pid_start_sec", "pid_start_usec",
            "schema_version", "boot_id", "event_id", "process_key", "signals", "spooled_ts",
        ])
    }

    @Test("TCC event carries hashed identity and decision metadata")
    func tccEvent() throws {
        let identityHash = String(repeating: "a", count: 64)
        let e = SpoolEvent(
            kind: .security, pid: 42, uid: 0, comm: "tccd",
            syscall: "tcc_modify", tccService: "kTCCServiceSystemPolicyAllFiles",
            tccIdentityHash: identityHash, tccIdentityType: "bundle_id",
            tccUpdateType: "modify", tccRight: "2", tccReason: "4"
        )
        let d = try encodeToDict(e)
        #expect(d["tcc_service"] as? String == "kTCCServiceSystemPolicyAllFiles")
        #expect(d["tcc_identity_hash"] as? String == identityHash)
        #expect(d["tcc_identity_type"] as? String == "bundle_id")
        #expect(d["tcc_update_type"] as? String == "modify")
        #expect(d["tcc_right"] as? String == "2")
        #expect(d["tcc_reason"] as? String == "4")
        #expect(d["identity"] == nil)
    }

    @Test("health event exposes fleet capability and loss counters")
    func healthEvent() throws {
        let e = SpoolEvent(
            kind: .health,
            healthStatus: "ok",
            healthCapabilities: ["kqueue", "bounded_spool"],
            healthEventsAttempted: 12,
            healthEventsAccepted: 12,
            healthEventsDropped: 0,
            healthDropRate: 0,
            healthEventsWritten: 12,
            healthWriteFailures: 0,
            healthIntervalSeconds: 10
        )
        let d = try encodeToDict(e)
        #expect(d["schema_version"] as? Int == 1)
        #expect(d["event_id"] as? String != nil)
        #expect(d["capabilities"] as? [String] == ["kqueue", "bounded_spool"])
        #expect(d["events_dropped"] as? Int == 0)
        #expect(d["drop_rate"] as? Double == 0)
    }
}

@Suite("spool")
struct SpoolTests {
    @Test("appends one flushed JSON line per event")
    func spoolAppend() throws {
        let path = NSTemporaryDirectory() + "merlin-spool-test-\(UUID().uuidString).jsonl"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let spool = try SpoolWriter(path: path)
        spool.write(SpoolEvent(kind: .exec, pid: 1, comm: "a", exe: "/bin/a", matchedRules: []))
        spool.write(SpoolEvent(kind: .exit, pid: 1, exitCode: 0, exitStatus: 0))
        let text = try String(contentsOfFile: path, encoding: .utf8)
        let lines = text.split(separator: "\n")
        #expect(lines.count == 2)
        let first = try JSONSerialization.jsonObject(with: Data(lines[0].utf8)) as? [String: Any]
        let second = try JSONSerialization.jsonObject(with: Data(lines[1].utf8)) as? [String: Any]
        #expect(first?["kind"] as? String == "exec")
        #expect(second?["kind"] as? String == "exit")
    }

    @Test("appends to an existing spool instead of truncating")
    func spoolAppendsNotTruncates() throws {
        let path = NSTemporaryDirectory() + "merlin-spool-test-\(UUID().uuidString).jsonl"
        defer { try? FileManager.default.removeItem(atPath: path) }
        try "{\"kind\":\"old\"}\n".write(toFile: path, atomically: true, encoding: .utf8)
        let spool = try SpoolWriter(path: path)
        spool.write(SpoolEvent(kind: .exit, pid: 2))
        let lines = try String(contentsOfFile: path, encoding: .utf8).split(separator: "\n")
        #expect(lines.count == 2)
        #expect(lines[0].contains("\"old\""))
    }

    @Test("spool rejects symlink paths")
    func spoolRejectsSymlink() throws {
        let target = NSTemporaryDirectory() + "merlin-spool-target-\(UUID().uuidString).jsonl"
        let link = NSTemporaryDirectory() + "merlin-spool-link-\(UUID().uuidString).jsonl"
        defer {
            try? FileManager.default.removeItem(atPath: target)
            try? FileManager.default.removeItem(atPath: link)
        }
        try Data("sentinel\n".utf8).write(to: URL(fileURLWithPath: target))
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: target)
        do {
            _ = try SpoolWriter(path: link)
            Issue.record("spool must reject symlink paths")
        } catch {
            // Expected: O_NOFOLLOW rejects the final symlink component.
        }
        #expect(String(data: try Data(contentsOf: URL(fileURLWithPath: target)), encoding: .utf8) == "sentinel\n")
    }
}
