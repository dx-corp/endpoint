import Foundation
import Testing
@testable import MerlinMacOS

// Blindspot fixes: DoH-suspect tagging, own/system-resolver keys, and the
// socket-table lookup order (cache → table → targeted sweep).

@Suite("doh suspect tagging")
struct DohSuspectTests {
    private func engine(_ rulesYaml: String = "rules: []") throws -> Engine {
        let spool = NSTemporaryDirectory() + "merlin-doh-\(UUID().uuidString).jsonl"
        return Engine(rules: try Rules.parse(rulesYaml), spool: try SpoolWriter(path: spool), canBlock: false)
    }

    @Test("known resolvers on 443/853 are suspect; everything else is not")
    func builtinSet() throws {
        let e = try engine()
        #expect(e.isDohSuspect(daddr: "1.1.1.1", dport: 443))
        #expect(e.isDohSuspect(daddr: "8.8.8.8", dport: 853))
        #expect(e.isDohSuspect(daddr: "2606:4700:4700::1111", dport: 443))
        #expect(e.isDohSuspect(daddr: "2001:4860:4860::8888", dport: 443))
        #expect(e.isDohSuspect(daddr: "2620:fe::fe", dport: 853))
        // Plain HTTPS to anyone else is unaffected.
        #expect(!e.isDohSuspect(daddr: "93.184.216.34", dport: 443))
        // Resolver on port 53 is normal DNS, not DoH.
        #expect(!e.isDohSuspect(daddr: "1.1.1.1", dport: 53))
        #expect(!e.isDohSuspect(daddr: "1.1.1.1", dport: 80))
    }

    @Test("rules-file doh_resolvers extends the set (additive)")
    func customResolvers() throws {
        let e = try engine("""
        rules: []
        doh_resolvers:
          - 10.99.0.53
        """)
        #expect(e.isDohSuspect(daddr: "10.99.0.53", dport: 443))
        #expect(!e.isDohSuspect(daddr: "10.99.0.53", dport: 53))
        #expect(e.isDohSuspect(daddr: "1.1.1.1", dport: 443)) // builtins still apply
    }

    @Test("connect event carries doh_suspect only when true")
    func conditionalEncoding() throws {
        let e = SpoolEvent(
            kind: .connect, pid: 1, uid: 501, comm: "curl",
            saddr: "192.168.1.10", daddr: "1.1.1.1", dport: 443, dohSuspect: true
        )
        let d = try JSONSerialization.jsonObject(with: JSONEncoder().encode(e)) as? [String: Any]
        #expect(d?["doh_suspect"] as? Bool == true)
        let plain = SpoolEvent(kind: .connect, pid: 1, saddr: "10.0.0.2", daddr: "93.184.216.34", dport: 443)
        let dp = try JSONSerialization.jsonObject(with: JSONEncoder().encode(plain)) as? [String: Any]
        #expect(dp?["doh_suspect"] == nil) // conditional: key absent, not null
        #expect(dp?["own_resolver"] == nil)
        #expect(dp?["via_system_resolver"] == nil)
    }
}

@Suite("resolver attribution keys")
struct ResolverKeyTests {
    @Test("dns event: own_resolver / via_system_resolver are mutually exclusive and conditional")
    func dnsKeys() throws {
        let own = SpoolEvent(kind: .dns, pid: 1, comm: "curl", query: "x.co", qtype: "A", direction: "query", ownResolver: true)
        let d1 = try JSONSerialization.jsonObject(with: JSONEncoder().encode(own)) as? [String: Any]
        #expect(d1?["own_resolver"] as? Bool == true)
        #expect(d1?["via_system_resolver"] == nil)

        let sys = SpoolEvent(kind: .dns, pid: 1, comm: "mDNSResponder", query: "x.co", qtype: "A", direction: "query", viaSystemResolver: true)
        let d2 = try JSONSerialization.jsonObject(with: JSONEncoder().encode(sys)) as? [String: Any]
        #expect(d2?["via_system_resolver"] as? Bool == true)
        #expect(d2?["own_resolver"] == nil)

        let none = SpoolEvent(kind: .dns, query: "x.co", qtype: "A", direction: "query")
        let d3 = try JSONSerialization.jsonObject(with: JSONEncoder().encode(none)) as? [String: Any]
        #expect(d3?["own_resolver"] == nil)
        #expect(d3?["via_system_resolver"] == nil)
    }
}

@Suite("socket table lookup order")
struct SocketTableOrderTests {
    private let key = FlowKey(proto: 6, saddr: .v4(0x0A00_0002), sport: 51000, daddr: .v4(0x5DB8_D822), dport: 443)
    private let udpKey = FlowKey(proto: 17, saddr: .v4(0x0A00_0002), sport: 53000, daddr: .v4(0x0101_0101), dport: 53)

    @Test("cache → table → sweep: table hit never invokes the sweeper")
    func tableHitShortCircuits() {
        let mock = MockSweep()
        let cache = AttributionCache(sweeper: mock)
        var table = SocketTable()
        table.exact[key] = SocketAttribution(pid: 4242, comm: "curl", uid: 501)
        cache.setTable(table)
        #expect(cache.attribute(key, now: 1000)?.comm == "curl")
        #expect(mock.calls == 0)
    }

    @Test("table miss falls through to the targeted sweep")
    func tableMissSweeps() {
        let mock = MockSweep()
        mock.result = SocketAttribution(pid: 777, comm: "dig", uid: 501)
        let cache = AttributionCache(sweeper: mock)
        cache.setTable(SocketTable()) // empty table
        #expect(cache.attribute(key, now: 1000)?.comm == "dig")
        #expect(mock.calls == 1)
        // …and the result is cached afterwards.
        #expect(cache.attribute(key, now: 1001)?.comm == "dig")
        #expect(mock.calls == 1)
    }

    @Test("unconnected UDP resolves via local endpoint incl. wildcard bind")
    func udpLocalLookup() {
        let mock = MockSweep()
        let cache = AttributionCache(sweeper: mock)
        var table = SocketTable()
        // A resolver socket bound to 0.0.0.0:53000.
        table.udpLocal[UdpLocalKey(laddr: .v4(0), lport: 53000)] = SocketAttribution(pid: 555, comm: "dig", uid: 501)
        cache.setTable(table)
        #expect(cache.attribute(udpKey, now: 0)?.comm == "dig")
        #expect(mock.calls == 0)
    }

    @Test("negative cache TTL shrank to 3s")
    func negativeTTL() {
        let mock = MockSweep()
        mock.result = nil
        let cache = AttributionCache(sweeper: mock)
        #expect(cache.negativeTTL == 3)
        _ = cache.attribute(key, now: 1000)
        _ = cache.attribute(key, now: 1002)
        #expect(mock.calls == 1)
        _ = cache.attribute(key, now: 1004)
        #expect(mock.calls == 2)
    }

    /// Mock sweeper (socketTable() default = unsupported).
    private final class MockSweep: SocketSweeping, @unchecked Sendable {
        var calls = 0
        var result: SocketAttribution? = SocketAttribution(pid: 4242, comm: "curl", uid: 501)

        func attribute(_ flow: FlowKey) -> SocketAttribution? {
            calls += 1
            return result
        }
    }
}
