import Foundation
import Testing
@testable import MerlinMacOS

// PKTAP + unified-log + posture tests — all pure/fixture-based (no root).

/// Build a v2 PKTAP record (40-byte fixed prefix + variable fields).
private func v2Record(
    pid: Int32 = 0, epid: Int32 = 0, ifname: String = "en0",
    comm: String = "", ecomm: String = "",
    dlt: UInt16 = 1, pre: UInt16 = 0, payload: [UInt8] = []
) -> [UInt8] {
    var body: [UInt8] = []
    var offsets: (ifn: UInt8, comm: UInt8, ecomm: UInt8) = (0, 0, 0)
    func field(_ s: String, set: inout UInt8) {
        if s.isEmpty { return }
        set = UInt8(40 + body.count)
        body += Array(s.utf8) + [0]
    }
    field(ifname, set: &offsets.ifn)
    field(comm, set: &offsets.comm)
    field(ecomm, set: &offsets.ecomm)
    let length = UInt8(40 + body.count)
    var hdr: [UInt8] = [
        length, 0, 0, offsets.ifn, offsets.comm, offsets.ecomm,
        UInt8(dlt & 0xff), UInt8(dlt >> 8),
        UInt8(pre & 0xff), UInt8(pre >> 8),
        0, 0, // frame_post_length
        0, 0, // iftype
        0, 6, // ipproto
        0, 0, 0, 0, // protocol_family
        0, 0, 0, 0, // svc
        0, 0, 0, 0, // flowid
    ]
    hdr += withUnsafeBytes(of: pid.littleEndian) { Array($0) }
    hdr += withUnsafeBytes(of: epid.littleEndian) { Array($0) }
    hdr += withUnsafeBytes(of: UInt32(0x0008_0000).littleEndian) { Array($0) } // flags = V2
    return hdr + body + payload
}

/// Build a v1 PKTAP record (fixed 156-byte layout).
private func v1Record(
    pid: Int32 = 0, epid: Int32 = 0, ifname: String = "en0",
    comm: String = "", ecomm: String = "",
    dlt: UInt32 = 1, pre: UInt32 = 0, payload: [UInt8] = []
) -> [UInt8] {
    var hdr = [UInt8](repeating: 0, count: 156)
    withUnsafeBytes(of: UInt32(156).littleEndian) { hdr.replaceSubrange(0 ..< 4, with: $0) }
    withUnsafeBytes(of: UInt32(1).littleEndian) { hdr.replaceSubrange(4 ..< 8, with: $0) } // type_next
    withUnsafeBytes(of: dlt.littleEndian) { hdr.replaceSubrange(8 ..< 12, with: $0) }
    for (i, b) in ifname.utf8.enumerated() { hdr[12 + i] = b }
    withUnsafeBytes(of: pre.littleEndian) { hdr.replaceSubrange(44 ..< 48, with: $0) }
    withUnsafeBytes(of: pid.littleEndian) { hdr.replaceSubrange(52 ..< 56, with: $0) }
    for (i, b) in comm.utf8.enumerated() { hdr[56 + i] = b }
    withUnsafeBytes(of: epid.littleEndian) { hdr.replaceSubrange(84 ..< 88, with: $0) }
    for (i, b) in ecomm.utf8.enumerated() { hdr[88 + i] = b }
    return hdr + payload
}

/// Ethernet/IPv4/TCP SYN frame (from the bpf test suite shape).
private func synFrame() -> [UInt8] {
    var b: [UInt8] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x08, 0x00]
    b += [0x45, 0, 0, 40, 0, 1, 0, 0, 64, 6, 0, 0]
    b += [192, 168, 1, 10, 93, 184, 216, 34]
    b += [0xC8, 0x02, 0x01, 0xBB] // sport 51202, dport 443
    b += [0, 0, 0, 0, 0, 0, 0, 0]
    b += [5 << 4, 0x02, 0x20, 0, 0, 0, 0, 0]
    return b
}

@Suite("pktap record parsing")
struct PktapParseTests {
    @Test("v2: fields, offsets, payload, effective attribution")
    func v2() {
        let frame = synFrame()
        let rec = v2Record(pid: 100, epid: 200, ifname: "en0", comm: "nsurlsessiond", ecomm: "Safari", payload: frame)
        let parsed = rec.withUnsafeBytes { parsePktapRecord($0) }
        #expect(parsed?.meta.pid == 100)
        #expect(parsed?.meta.epid == 200)
        #expect(parsed?.meta.comm == "nsurlsessiond")
        #expect(parsed?.meta.ecomm == "Safari")
        #expect(parsed?.meta.ifname == "en0")
        #expect(parsed?.dlt == 1)
        // Delegated: attribute to effective, record via_pid.
        #expect(parsed?.meta.attrPid == 200)
        #expect(parsed?.meta.attrComm == "Safari")
        #expect(parsed?.meta.viaPid == 100)
        // The payload parses as a real TCP SYN.
        var pkt: ParsedPacket?
        if let parsed {
            pkt = parsed.payload.withUnsafeBytes { parsePacket($0, link: .en10mb) }
        }
        #expect(pkt?.proto == 6)
        #expect(pkt?.synOnly == true)
        #expect(pkt?.dport == 443)
    }

    @Test("v2: no delegation (epid == pid) attributes directly, no via_pid")
    func v2NoDelegation() {
        let rec = v2Record(pid: 300, epid: 300, comm: "curl")
        let parsed = rec.withUnsafeBytes { parsePktapRecord($0) }
        #expect(parsed?.meta.attrPid == 300)
        #expect(parsed?.meta.viaPid == nil)
    }

    @Test("v2: missing optional fields (no epid, no comm)")
    func v2Sparse() {
        let rec = v2Record(pid: 42, epid: 0, ifname: "", comm: "")
        let parsed = rec.withUnsafeBytes { parsePktapRecord($0) }
        #expect(parsed?.meta.pid == 42)
        #expect(parsed?.meta.epid == nil)
        #expect(parsed?.meta.comm == nil)
        #expect(parsed?.meta.attrPid == 42)
        #expect(parsed?.meta.attrComm == nil)
    }

    @Test("v1: fixed-layout record parses with effective attribution")
    func v1() {
        let frame = synFrame()
        let rec = v1Record(pid: 555, epid: 777, comm: "nsurlsessiond", ecomm: "gh", payload: frame)
        let parsed = rec.withUnsafeBytes { parsePktapRecord($0) }
        #expect(parsed?.meta.pid == 555)
        #expect(parsed?.meta.epid == 777)
        #expect(parsed?.meta.comm == "nsurlsessiond")
        #expect(parsed?.meta.ecomm == "gh")
        #expect(parsed?.meta.attrPid == 777)
        #expect(parsed?.meta.viaPid == 555)
        var pkt: ParsedPacket?
        if let parsed {
            pkt = parsed.payload.withUnsafeBytes { parsePacket($0, link: .en10mb) }
        }
        #expect(pkt?.synOnly == true)
    }

    @Test("DLT dispatch: en10mb, null, raw map; unknown rejected")
    func dltDispatch() {
        #expect(linkTypeForDlt(1) == .en10mb)
        #expect(linkTypeForDlt(0) == .null)
        #expect(linkTypeForDlt(12) == .raw)
        #expect(linkTypeForDlt(999) == nil)
    }

    @Test("truncated and short records are rejected")
    func truncation() {
        #expect([UInt8](repeating: 0, count: 10).withUnsafeBytes { parsePktapRecord($0) } == nil)
        // v2 with bogus length larger than the buffer
        var rec = v2Record(pid: 1)
        rec[0] = 255
        #expect(rec.withUnsafeBytes { parsePktapRecord($0) } == nil)
    }
}

@Suite("mdns log parsing")
struct MdnsLogParseTests {
    @Test("query-start line parses pid, comm, redacted qname, qtype")
    func queryStart() {
        let line = #"{"formatString":"[R%u] DNSServiceQueryRecord START -- qname: %{sensitive}, qtype: %{mdns:rrtype}d, flags: 0x%X, interface index: %d, client pid: %d (%{public}s), name hash: %{mdns:dn_hash}u","eventMessage":"[R636276] DNSServiceQueryRecord START -- qname: <private> <dn:I/vUYw>, qtype: A, flags: 0x1D000, interface index: 0, client pid: 46484 (codex), name hash: <dn:I/vUYw>","processID":570}"#
        let q = parseMdnsLogLine(line)
        #expect(q?.pid == 46484)
        #expect(q?.comm == "codex")
        #expect(q?.qname == "<private> <dn:I/vUYw>")
        #expect(q?.qtype == "A")
        #expect(qtypeNumber(q?.qtype ?? "") == 1)
        #expect(qtypeNumber("AAAA") == 28)
        #expect(qtypeNumber("HTTPS") == 65)
        #expect(qtypeNumber("WAT") == 0)
    }

    @Test("non-query lines and malformed input are skipped")
    func rejects() {
        #expect(parseMdnsLogLine("not json") == nil)
        #expect(parseMdnsLogLine(#"{"formatString":"[R%u] DNSServiceCreateConnection START PID[%d](%{public}s)","eventMessage":"[R1] DNSServiceCreateConnection START PID[94388](gh)"}"#) == nil)
        #expect(parseMdnsLogLine(#"{"formatString":"[R%u] DNSServiceQueryRecord START -- qname","eventMessage":"[R1] DNSServiceQueryRecord START -- qname: no pid here"}"#) == nil)
    }
}

@Suite("verdict parsing and rate cap")
struct VerdictTests {
    @Test("syspolicy line parses subsystem, message, pid, comm")
    func parse() {
        let line = #"{"subsystem":"com.apple.syspolicy","eventMessage":"not allowed: /tmp/evil","processID":9338,"processImagePath":"/usr/libexec/syspolicyd"}"#
        let v = parseVerdictLine(line)
        #expect(v?.subsystem == "com.apple.syspolicy")
        #expect(v?.message == "not allowed: /tmp/evil")
        #expect(v?.pid == 9338)
        #expect(v?.comm == "syspolicyd")
        #expect(parseVerdictLine("garbage") == nil)
        #expect(parseVerdictLine(#"{"subsystem":"com.apple.TCC","eventMessage":"deny camera for pid 1001"}"#)?.subsystem == "com.apple.TCC")
    }

    @Test("token bucket: burst drains, then rate-limits")
    func bucket() {
        var b = TokenBucket(rate: 1, burst: 3)
        // #expect can't wrap a mutating call; evaluate first.
        let r1 = b.take()
        let r2 = b.take()
        let r3 = b.take()
        let r4 = b.take()
        #expect(r1 && r2 && r3)
        #expect(!r4) // drained
        usleep(1_100_000)
        let r5 = b.take()
        #expect(r5) // refilled ~1 token
    }
}

@Suite("posture summaries")
struct PostureTests {
    @Test("proxy and DNS summaries")
    func summaries() {
        #expect(summarizeProxies(nil) == "no proxy configuration")
        #expect(summarizeProxies([:]) == "no proxies enabled")
        #expect(summarizeProxies(["HTTPEnable": 1, "HTTPProxy": "10.0.0.1", "HTTPPort": 8080]).contains("http=10.0.0.1"))
        #expect(summarizeProxies(["ProxyAutoConfigURLString": "http://evil/pac"]).contains("pac=http://evil/pac"))
        #expect(summarizeDNS(nil) == "no resolver addresses")
        #expect(summarizeDNS(["ServerAddresses": ["1.1.1.1", "8.8.8.8"]]) == "resolvers=1.1.1.1,8.8.8.8")
    }

    @Test("event tap listing doesn't crash and matches CG shape")
    func taps() {
        for tap in currentEventTaps() {
            #expect(tap.tappingPid >= 0)
        }
    }
}
