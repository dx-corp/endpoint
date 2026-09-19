import Foundation
import Testing
@testable import MerlinMacOS

// BpfProvider unit tests — all pure/offline: the packet parser on canned
// bytes (v4 and v6), the flow-tuple TTL tracker, and the attribution
// cache against a mock sweeper. Live capture and the libproc sweep need
// root and are covered by the manual live test instead.

/// Build an Ethernet/IP/TCP-or-UDP frame (v4 or v6).
private func frame(
    v6: Bool = false,
    proto: UInt8 = 6,
    saddr: (UInt8, UInt8, UInt8, UInt8) = (192, 168, 1, 10),
    daddr: (UInt8, UInt8, UInt8, UInt8) = (93, 184, 216, 34),
    saddr6: [UInt8] = [0x20, 0x01, 0x0d, 0xb8] + [UInt8](repeating: 0, count: 11) + [0x01],
    daddr6: [UInt8] = [0x26, 0x06, 0x28, 0x00, 0x00, 0x20] + [UInt8](repeating: 0, count: 9) + [0x01],
    sport: UInt16 = 51_234,
    dport: UInt16 = 443,
    tcpFlags: UInt8 = 0x02, // SYN
    ihlWords: UInt8 = 5,
    extHeaders: [UInt8] = [], // prepended extension-header bytes (v6), first byte = final next-header
    truncateTo: Int? = nil
) -> [UInt8] {
    var b: [UInt8] = []
    // Ethernet II
    b += [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff] // dst mac
    b += [0x11, 0x22, 0x33, 0x44, 0x55, 0x66] // src mac
    b += v6 ? [0x86, 0xdd] : [0x08, 0x00]
    // L4
    var l4: [UInt8] = [UInt8(sport >> 8), UInt8(sport & 0xff), UInt8(dport >> 8), UInt8(dport & 0xff)]
    if proto == 6 {
        l4 += [0, 0, 0, 0, 0, 0, 0, 0] // seq, ack
        l4 += [5 << 4, tcpFlags, 0x20, 0x00, 0, 0, 0, 0] // doff, flags, win, csum, urg
    } else {
        l4 += [0, UInt8(8 + 4), 0, 0] // len, csum
    }
    if v6 {
        let payload = extHeaders + l4
        b += [6 << 4, 0, 0, 0] // version/tc/flow
        b += [UInt8(payload.count >> 8), UInt8(payload.count & 0xff)]
        b += [extHeaders.isEmpty ? proto : 0, 64] // next header (0 = hop-by-hop when exts present), hop limit
        b += saddr6 + daddr6
        b += payload
    } else {
        let ihl = Int(ihlWords) * 4
        let total = ihl + l4.count
        b += [4 << 4 | ihlWords, 0, UInt8(total >> 8), UInt8(total & 0xff)]
        b += [0, 1, 0, 0, 64, proto, 0, 0] // id, frag, ttl, proto, csum
        b += [saddr.0, saddr.1, saddr.2, saddr.3]
        b += [daddr.0, daddr.1, daddr.2, daddr.3]
        b += [UInt8](repeating: 0, count: ihl - 20) // options
        b += l4
    }
    if let t = truncateTo { b = Array(b.prefix(t)) }
    return b
}

/// Hop-by-hop extension header (8 bytes): nh=proto, len=0, 6 pad bytes.
private func hopByHop(next: UInt8) -> [UInt8] {
    [next, 0, 0, 0, 0, 0, 0, 0]
}

private func parse(_ bytes: [UInt8], link: LinkType = .en10mb) -> ParsedPacket? {
    bytes.withUnsafeBytes { parsePacket($0, link: link) }
}

@Suite("bpf packet parser")
struct BpfParserTests {
    @Test("TCP SYN parses with addresses, ports, synOnly")
    func tcpSyn() {
        let p = parse(frame())
        #expect(p?.proto == 6)
        #expect(p.map { addrString($0.saddr) } == "192.168.1.10")
        #expect(p.map { addrString($0.daddr) } == "93.184.216.34")
        #expect(p?.sport == 51_234)
        #expect(p?.dport == 443)
        #expect(p?.synOnly == true)
    }

    @Test("SYN+ACK is not synOnly; ACK-only is not synOnly")
    func tcpFlags() {
        #expect(parse(frame(tcpFlags: 0x12))?.synOnly == false)
        #expect(parse(frame(tcpFlags: 0x10))?.synOnly == false)
    }

    @Test("UDP datagram (DNS query shape) parses")
    func udpDns() {
        let p = parse(frame(proto: 17, daddr: (1, 1, 1, 1), dport: 53))
        #expect(p?.proto == 17)
        #expect(p?.dport == 53)
        #expect(p?.synOnly == false)
        #expect(p.map { addrString($0.daddr) } == "1.1.1.1")
    }

    @Test("IPv4 header options (ihl > 5) shift L4 correctly")
    func ipOptions() {
        let p = parse(frame(ihlWords: 6))
        #expect(p?.dport == 443)
        #expect(p?.synOnly == true)
    }

    @Test("malformed input is rejected")
    func malformed() {
        #expect(parse(frame(truncateTo: 10)) == nil) // truncated ethernet
        #expect(parse(frame(truncateTo: 20)) == nil) // truncated IP header
        #expect(parse(frame(truncateTo: 36)) == nil) // truncated TCP header
        #expect(parse(frame(proto: 1)) == nil) // ICMP: not TCP/UDP
        #expect(parse([]) == nil)
        // ARP ethertype
        var arp = frame()
        arp[12] = 0x08; arp[13] = 0x06
        #expect(parse(arp) == nil)
    }

    @Test("DLT_NULL loopback frames parse (host-order AF header)")
    func dltNull() {
        var b: [UInt8] = [UInt8(AF_INET), 0, 0, 0] // little-endian AF_INET
        b += frame().dropFirst(14) // strip ethernet, keep IP+L4
        let p = parse(b, link: .null)
        #expect(p?.dport == 443)
        #expect(p?.synOnly == true)
        // wrong family → nil
        var bad = b
        bad[0] = 0xff
        #expect(parse(bad, link: .null) == nil)
    }

    @Test("IPv6 TCP SYN parses (compressed rendering)")
    func tcp6Syn() {
        let p = parse(frame(v6: true))
        #expect(p?.proto == 6)
        #expect(p?.synOnly == true)
        #expect(p.map { addrString($0.saddr) } == "2001:db8::1")
        #expect(p.map { addrString($0.daddr) } == "2606:2800:20::1")
        #expect(p?.sport == 51_234)
        #expect(p?.dport == 443)
    }

    @Test("IPv6 UDP DNS parses")
    func udp6Dns() {
        let p = parse(frame(v6: true, proto: 17, dport: 53))
        #expect(p?.proto == 17)
        #expect(p?.dport == 53)
        #expect(p.map { addrString($0.daddr) } == "2606:2800:20::1")
    }

    @Test("IPv6 hop-by-hop extension header is walked to L4")
    func extHeaderWalk() {
        let p = parse(frame(v6: true, extHeaders: hopByHop(next: 6)))
        #expect(p?.proto == 6)
        #expect(p?.dport == 443)
        #expect(p?.synOnly == true)
        // Extension header whose final next-header is not TCP/UDP → nil
        #expect(parse(frame(v6: true, extHeaders: hopByHop(next: 58))) == nil) // ICMPv6
        // Truncated inside the extension chain → nil
        #expect(parse(frame(v6: true, extHeaders: hopByHop(next: 6), truncateTo: 14 + 40 + 4)) == nil)
    }

    @Test("v4 and v6 addresses never collide in a tuple")
    func addressFamiliesDistinct() {
        #expect(IPAddress.v4(1) != IPAddress(isV6: true, hi: 1, lo: 0))
    }
}

@Suite("bpf record stream")
struct BpfRecordStreamTests {
    /// Serialize one bpf record: 18-byte bpf_hdr + padding to hdrlen,
    /// frame, then BPF_WORDALIGN stride padding.
    private func record(_ frame: [UInt8], hdrlen: Int = 20) -> [UInt8] {
        var b = [UInt8](repeating: 0, count: 8) // tv_sec, tv_usec
        b += withUnsafeBytes(of: UInt32(frame.count).littleEndian) { Array($0) } // caplen
        b += withUnsafeBytes(of: UInt32(frame.count).littleEndian) { Array($0) } // datalen
        b += withUnsafeBytes(of: UInt16(hdrlen).littleEndian) { Array($0) }
        b += [UInt8](repeating: 0, count: hdrlen - 18) // alignment padding
        b += frame
        b += [UInt8](repeating: 0, count: ((hdrlen + frame.count + 3) & ~3) - hdrlen - frame.count)
        return b
    }

    @Test("two records with padded hdrlen and unaligned caplens both parse")
    func twoRecords() {
        // Regression for the live-capture bug: bh_hdrlen includes
        // BPF_WORDALIGN padding (20, not 18), data starts at off+hdrlen,
        // and the stride is align(hdrlen+caplen). v4 frame is 54 bytes,
        // v6 UDP frame is 62 — both unaligned, so the stride math matters.
        let v4 = frame() // TCP SYN, 54 bytes
        let v6udp = frame(v6: true, proto: 17, dport: 53) // 62 bytes
        #expect(v4.count % 4 != 0 && v6udp.count % 4 != 0)
        let stream = record(v4) + record(v6udp)
        let frames = stream.withUnsafeBytes { bpfFrames($0) }
        #expect(frames.count == 2)
        let p1 = frames[0].withUnsafeBytes { parsePacket($0, link: .en10mb) }
        let p2 = frames[1].withUnsafeBytes { parsePacket($0, link: .en10mb) }
        #expect(p1?.proto == 6)
        #expect(p1?.synOnly == true)
        #expect(p1.map { addrString($0.daddr) } == "93.184.216.34")
        #expect(p2?.proto == 17)
        #expect(p2?.dport == 53)
        #expect(p2.map { addrString($0.daddr) } == "2606:2800:20::1")
    }

    @Test("malformed/truncated trailing record stops the walk gracefully")
    func malformedStops() {
        let good = record(frame())
        // Truncated second record: header claims a full frame, buffer ends early.
        var truncated = record(frame(truncateTo: 20))
        truncated = Array(truncated.prefix(12))
        // hdrlen smaller than the real header size.
        var badHdrlen = record(frame())
        badHdrlen[16] = 10
        for stream in [good + truncated, good + badHdrlen, truncated] {
            let frames = stream.withUnsafeBytes { bpfFrames($0) }
            #expect(frames.count == (stream == truncated ? 0 : 1))
        }
    }
}

@Suite("flow tracker")
struct FlowTrackerTests {
    private let key = FlowKey(proto: 6, saddr: .v4(0xC0A8_010A), sport: 1234, daddr: .v4(0x5DB8_D822), dport: 443)

    @Test("tuple is new once per TTL window")
    func ttlWindow() {
        var t = FlowTracker(ttl: 300)
        #expect(t.isNew(key, now: 1000) == true)
        #expect(t.isNew(key, now: 1001) == false)
        #expect(t.isNew(key, now: 1299) == false)
        #expect(t.isNew(key, now: 1301) == true) // TTL expired → fires again
    }

    @Test("different tuples are independent")
    func independence() {
        var t = FlowTracker(ttl: 300)
        var other = key
        other.dport = 80
        #expect(t.isNew(key, now: 0) == true)
        #expect(t.isNew(other, now: 0) == true)
        #expect(t.isNew(key, now: 1) == false)
    }

    @Test("tuple tracker evicts oldest entries at its bound")
    func boundedEntries() {
        var t = FlowTracker(ttl: 300, maxEntries: 2)
        var second = key
        second.dport = 80
        var third = key
        third.dport = 8080
        let first = t.isNew(key, now: 0)
        let secondResult = t.isNew(second, now: 1)
        let thirdResult = t.isNew(third, now: 2)
        let reinserted = t.isNew(key, now: 3)
        #expect(first)
        #expect(secondResult)
        #expect(thirdResult)
        #expect(reinserted) // key was the oldest and was evicted
    }
}

/// Mock sweeper: counts invocations, returns a canned attribution (or nil).
private final class MockSweeper: SocketSweeping, @unchecked Sendable {
    var calls = 0
    var revalidations = 0
    var seen: [FlowKey] = []
    var result: SocketAttribution? = SocketAttribution(pid: 4242, comm: "curl", uid: 501)
    /// What the single-pid re-check reports; defaults to the cached value.
    var revalidationResult: SocketAttribution??

    func attribute(_ flow: FlowKey) -> SocketAttribution? {
        calls += 1
        seen.append(flow)
        return result
    }

    func revalidate(_ attribution: SocketAttribution, flow _: FlowKey) -> SocketAttribution? {
        revalidations += 1
        return revalidationResult ?? attribution
    }
}

@Suite("attribution cache")
struct AttributionCacheTests {
    private let key = FlowKey(proto: 6, saddr: .v4(1), sport: 2, daddr: .v4(3), dport: 4)

    @Test("positive attribution is cached for the TTL")
    func positiveCaching() {
        let mock = MockSweeper()
        let cache = AttributionCache(sweeper: mock, ttl: 60, negativeTTL: 10)
        #expect(cache.attribute(key, now: 1000)?.comm == "curl")
        #expect(cache.attribute(key, now: 1001)?.pid == 4242)
        #expect(mock.calls == 1) // second hit served from cache
        _ = cache.attribute(key, now: 1061)
        #expect(mock.calls == 2) // TTL expired → re-sweep
    }

    @Test("failures are cached briefly (no sweep per packet)")
    func negativeCaching() {
        let mock = MockSweeper()
        mock.result = nil
        let cache = AttributionCache(sweeper: mock, ttl: 60, negativeTTL: 10)
        #expect(cache.attribute(key, now: 1000) == nil)
        #expect(cache.attribute(key, now: 1005) == nil)
        #expect(mock.calls == 1)
        _ = cache.attribute(key, now: 1011)
        #expect(mock.calls == 2)
    }

    @Test("v6 tuples flow through attribution unchanged")
    func v6TupleAttribution() {
        let mock = MockSweeper()
        let cache = AttributionCache(sweeper: mock)
        let key6 = FlowKey(
            proto: 17,
            saddr: IPAddress(isV6: true, hi: 0x2001_0db8_0000_0000, lo: 1),
            sport: 53_000,
            daddr: IPAddress(isV6: true, hi: 0x2606_2800_0020_0000, lo: 1),
            dport: 53
        )
        #expect(cache.attribute(key6, now: 0)?.comm == "curl")
        #expect(mock.seen == [key6]) // sweeper receives the exact v6 tuple
    }

    @Test("kill rules re-check the cached pid instead of re-sweeping")
    func revalidatedCaching() {
        let mock = MockSweeper()
        let cache = AttributionCache(sweeper: mock, ttl: 60, negativeTTL: 10)
        #expect(cache.attribute(key, now: 1000, revalidate: true)?.pid == 4242)
        #expect(cache.attribute(key, now: 1001, revalidate: true)?.pid == 4242)
        #expect(mock.calls == 1) // no second system-wide sweep
        #expect(mock.revalidations == 1)
    }

    @Test("a cached pid that no longer owns the tuple falls back to a sweep")
    func revalidationFailureResweeps() {
        let mock = MockSweeper()
        let cache = AttributionCache(sweeper: mock, ttl: 60, negativeTTL: 10)
        _ = cache.attribute(key, now: 1000, revalidate: true)
        mock.revalidationResult = .some(nil)
        mock.result = SocketAttribution(pid: 77, comm: "nc", uid: 501)
        #expect(cache.attribute(key, now: 1001, revalidate: true)?.pid == 77)
        #expect(mock.calls == 2)
    }

    @Test("a recycled pid (identity changed) falls back to a sweep")
    func revalidationIdentityChangeResweeps() {
        let mock = MockSweeper()
        mock.result = SocketAttribution(
            pid: 4242, comm: "curl", uid: 501,
            identity: ProcessIdentity(startSec: 100, startUsec: 0)
        )
        let cache = AttributionCache(sweeper: mock, ttl: 60, negativeTTL: 10)
        _ = cache.attribute(key, now: 1000, revalidate: true)
        mock.revalidationResult = SocketAttribution(
            pid: 4242, comm: "nc", uid: 501,
            identity: ProcessIdentity(startSec: 900, startUsec: 0)
        )
        _ = cache.attribute(key, now: 1001, revalidate: true)
        #expect(mock.calls == 2)
    }

    @Test("failures stay cached even when kill rules are active")
    func negativeCachingWithRevalidation() {
        let mock = MockSweeper()
        mock.result = nil
        let cache = AttributionCache(sweeper: mock, ttl: 60, negativeTTL: 10)
        #expect(cache.attribute(key, now: 1000, revalidate: true) == nil)
        #expect(cache.attribute(key, now: 1005, revalidate: true) == nil)
        #expect(mock.calls == 1)
        #expect(mock.revalidations == 0)
    }

    @Test("attribution cache evicts oldest entries at its bound")
    func boundedEntries() {
        let mock = MockSweeper()
        let cache = AttributionCache(sweeper: mock, maxEntries: 2)
        var second = key
        second.dport = 5
        var third = key
        third.dport = 6
        _ = cache.attribute(key, now: 0)
        _ = cache.attribute(second, now: 1)
        _ = cache.attribute(third, now: 2)
        _ = cache.attribute(key, now: 3)
        #expect(mock.calls == 4) // the oldest key was evicted
    }
}
