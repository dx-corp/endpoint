// DNS message parsing for the BPF network provider — pure, no deps.
//
// Minimal: header + first question. Query names are never compressed in
// practice (RFC 1035 allows pointers anywhere a name appears, but stubs
// don't emit them in questions); a compression pointer inside the
// question's qname is rejected as malformed rather than followed — safe
// by construction against pointer loops. Answer/authority/additional
// sections are not parsed (we want the question and the rcode, not the
// records).

import Foundation

struct DnsMessage: Equatable {
    var id: UInt16
    var isResponse: Bool
    /// Response code (responses only): 0 NOERROR, 3 NXDOMAIN, 2 SERVFAIL…
    var rcode: Int?
    var qname: String
    var qtype: UInt16
    var qclass: UInt16

    var direction: String { isResponse ? "response" : "query" }

    /// RFC 3597-style rendering for the spool: well-known names, TYPE<n>
    /// for the rest.
    var qtypeName: String {
        switch qtype {
        case 1: return "A"
        case 2: return "NS"
        case 5: return "CNAME"
        case 6: return "SOA"
        case 12: return "PTR"
        case 15: return "MX"
        case 16: return "TXT"
        case 28: return "AAAA"
        case 33: return "SRV"
        case 64: return "SVCB"
        case 65: return "HTTPS"
        case 255: return "ANY"
        default: return "TYPE\(qtype)"
        }
    }
}

/// Parse one DNS message (a UDP payload, or a TCP payload with the 2-byte
/// length prefix already stripped). Only the first question is reported;
/// multi-question messages are essentially never seen from stubs.
/// Returns nil for anything truncated or malformed.
func parseDns(_ buf: UnsafeRawBufferPointer) -> DnsMessage? {
    guard buf.count >= 12 else { return nil }
    func u16(_ at: Int) -> UInt16 { UInt16(buf[at]) << 8 | UInt16(buf[at + 1]) }
    let id = u16(0)
    let flags = u16(2)
    let qdcount = Int(u16(4))
    guard qdcount >= 1 else { return nil }

    // Question name: length-prefixed labels, no compression pointers.
    var off = 12
    var labels: [String] = []
    while true {
        guard off < buf.count else { return nil }
        let len = Int(buf[off])
        if len == 0 {
            off += 1
            break
        }
        if len & 0xC0 != 0 { return nil } // compression pointer in qname: reject
        guard off + 1 + len <= buf.count else { return nil }
        labels.append(String(decoding: buf[off + 1 ..< off + 1 + len], as: UTF8.self))
        off += 1 + len
    }
    guard off + 4 <= buf.count else { return nil }
    let qtype = u16(off)
    let qclass = u16(off + 2)

    let isResponse = flags & 0x8000 != 0
    return DnsMessage(
        id: id,
        isResponse: isResponse,
        rcode: isResponse ? Int(flags & 0x000F) : nil,
        qname: labels.joined(separator: "."),
        qtype: qtype,
        qclass: qclass
    )
}

/// DNS over TCP: 2-byte length prefix, then the message. Naive single
/// segment: parse only when the whole message is present in this payload.
func parseDnsTcp(_ buf: UnsafeRawBufferPointer) -> DnsMessage? {
    guard buf.count >= 2 else { return nil }
    let len = Int(UInt16(buf[0]) << 8 | UInt16(buf[1]))
    guard buf.count >= 2 + len else { return nil }
    return parseDns(UnsafeRawBufferPointer(rebasing: buf[2 ..< 2 + len]))
}
