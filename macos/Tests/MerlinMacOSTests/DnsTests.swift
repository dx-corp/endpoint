import Foundation
import Testing
@testable import MerlinMacOS

// DNS parser tests — canned wire-format messages, all pure/offline.

/// Build a DNS message: header + one question (+ optional answer section
/// with a compression pointer, which must be ignored).
private func dnsMessage(
    id: UInt16 = 0x1234,
    isResponse: Bool = false,
    rcode: UInt16 = 0,
    qname: String = "example.com",
    qtype: UInt16 = 1,
    withAnswer: Bool = false,
    truncateTo: Int? = nil
) -> [UInt8] {
    var b: [UInt8] = []
    func u16(_ v: UInt16) { b += [UInt8(v >> 8), UInt8(v & 0xff)] }
    u16(id)
    u16((isResponse ? 0x8000 : 0) | 0x0100 | (rcode & 0xF)) // QR + RD + rcode
    u16(1) // qdcount
    u16(withAnswer ? 1 : 0) // ancount
    u16(0); u16(0) // nscount, arcount
    for label in qname.split(separator: ".", omittingEmptySubsequences: false) {
        b.append(UInt8(label.count))
        b += Array(label.utf8)
    }
    b.append(0)
    u16(qtype)
    u16(1) // qclass IN
    if withAnswer {
        // Answer: name as a compression pointer to offset 12 — present in
        // real responses, must not affect question parsing.
        b += [0xC0, 0x0C]
        u16(qtype); u16(1)
        b += [0, 0, 0, 60] // TTL
        u16(4)
        b += [93, 184, 216, 34]
    }
    if let t = truncateTo { b = Array(b.prefix(t)) }
    return b
}

private func parse(_ bytes: [UInt8]) -> DnsMessage? {
    bytes.withUnsafeBytes { parseDns($0) }
}

@Suite("dns parser")
struct DnsParserTests {
    @Test("A query parses: id, direction, qname, qtype, no rcode")
    func query() {
        let m = parse(dnsMessage())
        #expect(m?.id == 0x1234)
        #expect(m?.isResponse == false)
        #expect(m?.direction == "query")
        #expect(m?.rcode == nil)
        #expect(m?.qname == "example.com")
        #expect(m?.qtype == 1)
        #expect(m?.qtypeName == "A")
    }

    @Test("AAAA query parses with qtype name")
    func aaaaQuery() {
        let m = parse(dnsMessage(qname: "ipv6.example.com", qtype: 28))
        #expect(m?.qtype == 28)
        #expect(m?.qtypeName == "AAAA")
        #expect(m?.qname == "ipv6.example.com")
    }

    @Test("NXDOMAIN response carries rcode 3")
    func nxdomain() {
        let m = parse(dnsMessage(isResponse: true, rcode: 3, withAnswer: false))
        #expect(m?.isResponse == true)
        #expect(m?.direction == "response")
        #expect(m?.rcode == 3)
    }

    @Test("successful response with compressed answer name parses (pointer ignored)")
    func responseWithAnswer() {
        let m = parse(dnsMessage(isResponse: true, rcode: 0, withAnswer: true))
        #expect(m?.rcode == 0)
        #expect(m?.qname == "example.com")
    }

    @Test("compression pointer inside qname is rejected as malformed")
    func pointerInQuestion() {
        var b = dnsMessage()
        // Replace the first label's length byte with a pointer marker.
        b[12] = 0xC0
        b[13] = 0x00
        #expect(parse(b) == nil)
    }

    @Test("truncated and malformed messages are rejected safely")
    func malformed() {
        #expect(parse(dnsMessage(truncateTo: 5)) == nil) // truncated header
        #expect(parse(dnsMessage(truncateTo: 14)) == nil) // truncated mid-qname
        #expect(parse(dnsMessage(truncateTo: 12 + 12)) == nil) // missing qtype/qclass
        #expect(parse([]) == nil)
        // qdcount 0
        var b = dnsMessage()
        b[5] = 0
        #expect(parse(b) == nil)
        // label length overruns the buffer
        var c = dnsMessage()
        c[12] = 200
        #expect(parse(c) == nil)
    }

    @Test("unknown qtype renders RFC 3597 style")
    func unknownQtype() {
        let m = parse(dnsMessage(qtype: 99))
        #expect(m?.qtypeName == "TYPE99")
    }

    @Test("DNS over TCP: 2-byte length prefix is stripped")
    func tcp() {
        let msg = dnsMessage()
        var tcp: [UInt8] = [UInt8(msg.count >> 8), UInt8(msg.count & 0xff)] + msg
        let m = tcp.withUnsafeBytes { parseDnsTcp($0) }
        #expect(m?.qname == "example.com")
        // Declared length longer than the payload → nil
        tcp[1] = UInt8(msg.count + 10)
        #expect(tcp.withUnsafeBytes { parseDnsTcp($0) } == nil)
        // Truncated prefix
        #expect([UInt8(0)].withUnsafeBytes { parseDnsTcp($0) } == nil)
    }
}

@Suite("dns event encoding")
struct DnsEventEncodingTests {
    @Test("dns event key set")
    func dnsEvent() throws {
        let e = SpoolEvent(
            kind: .dns, pid: 4242, uid: 501, comm: "curl",
            query: "exfil.example.com", qtype: "A",
            direction: "response", rcode: 3
        )
        let data = try JSONEncoder().encode(e)
        let d = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        #expect(Set(d?.keys ?? Dictionary<String, Any>().keys) == ["ts", "kind", "source", "source_seq", "pid", "uid", "comm", "query", "qtype", "direction", "rcode", "pid_start_sec", "pid_start_usec", "schema_version", "boot_id", "event_id", "process_key", "signals", "spooled_ts"])
        #expect(d?["query"] as? String == "exfil.example.com")
        #expect(d?["direction"] as? String == "response")
        #expect(d?["rcode"] as? Int == 3)
        // Queries spool rcode as an explicit null.
        let q = SpoolEvent(kind: .dns, query: "a.b", qtype: "AAAA", direction: "query")
        let dq = try JSONSerialization.jsonObject(with: JSONEncoder().encode(q)) as? [String: Any]
        #expect(dq?["rcode"] is NSNull)
        #expect(dq?["pid"] is NSNull)
    }
}
