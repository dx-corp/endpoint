// BPF network provider — entitlement-free IPv4+IPv6 connect telemetry.
//
// Complements the process providers (es/kqueue/bsm): packets are captured
// from /dev/bpf (root required — /dev/bpf* is root-only), new outbound
// flows are detected with a seen-tuple tracker, and each new flow is
// attributed to a process by sweeping libproc socket tables
// (PROC_PIDLISTFDS + PROC_PIDFDSOCKETINFO). Emits `connect` events in the
// Linux port's exact spool schema (ts/kind/pid/uid/comm/saddr/daddr/dport)
// — the address strings show the family (no family field, schema parity).
// No payload inspection; QUIC is plain UDP here.
//
// Accuracy caveats (documented in the README): the packet is seen before
// the sweep runs, so a very short-lived flow can exit before attribution;
// a reused tuple can inherit the previous owner's cached attribution for
// up to the cache TTL; and flows first seen mid-stream (capture started
// late) are emitted without a SYN.

import Foundation

// MARK: - Addresses

/// An IPv4 or IPv6 address, packed big-endian (hi holds bytes 0...7, lo
/// bytes 8...15; IPv4 uses hi's low 32 bits only). The family flag keeps
/// an IPv4 tuple and the numerically equal IPv6 tuple distinct.
struct IPAddress: Hashable {
    var isV6: Bool
    var hi: UInt64
    var lo: UInt64

    static func v4(_ packedBE: UInt32) -> IPAddress {
        IPAddress(isV6: false, hi: UInt64(packedBE), lo: 0)
    }

    static func v6(_ bytes: UnsafeRawBufferPointer) -> IPAddress {
        var hi: UInt64 = 0
        var lo: UInt64 = 0
        for i in 0 ..< 8 { hi = hi << 8 | UInt64(bytes[i]) }
        for i in 8 ..< 16 { lo = lo << 8 | UInt64(bytes[i]) }
        return IPAddress(isV6: true, hi: hi, lo: lo)
    }
}

/// Dotted-quad for v4, inet_ntop compression for v6.
func addrString(_ addr: IPAddress) -> String {
    if addr.isV6 {
        var bytes: [UInt8] = []
        for shift in stride(from: 56, through: 0, by: -8) {
            bytes.append(UInt8(addr.hi >> shift & 0xff))
        }
        for shift in stride(from: 56, through: 0, by: -8) {
            bytes.append(UInt8(addr.lo >> shift & 0xff))
        }
        var out = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        bytes.withUnsafeBytes { raw in
            _ = inet_ntop(AF_INET6, raw.baseAddress, &out, socklen_t(INET6_ADDRSTRLEN))
        }
        return String(decoding: out.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
    let p = UInt32(addr.hi)
    return "\(p >> 24).\(p >> 16 & 0xff).\(p >> 8 & 0xff).\(p & 0xff)"
}

// MARK: - Packet parsing (pure)

enum LinkType: UInt32 {
    case null = 0 // DLT_NULL: 4-byte AF header (host byte order), then IP
    case en10mb = 1 // DLT_EN10MB: Ethernet II
    case raw = 12 // DLT_RAW: bare IP packet
    case pktap = 258 // DLT_PKTAP: pktap_header + packet (value per libpcap; not in the SDK's bpf.h)
}

struct ParsedPacket: Equatable {
    var proto: UInt8 // 6 = TCP, 17 = UDP
    var saddr: IPAddress
    var daddr: IPAddress
    var sport: UInt16 // host byte order
    var dport: UInt16
    var synOnly: Bool // TCP SYN set, ACK clear — definitive outbound connect
    /// Frame-relative L4 payload range (DNS parsing reads it; caplen
    /// truncation is reflected in payloadLength).
    var payloadOffset: Int
    var payloadLength: Int
}

/// Parse one captured frame into an IPv4/IPv6 TCP/UDP packet, or nil for
/// anything else (truncated, other ethertypes, other protocols).
/// Pure; feeds both the provider and the tests.
func parsePacket(_ buf: UnsafeRawBufferPointer, link: LinkType) -> ParsedPacket? {
    var off = 0
    switch link {
    case .en10mb:
        guard buf.count >= 14 else { return nil }
        let ethertype = UInt16(buf[12]) << 8 | UInt16(buf[13])
        guard ethertype == 0x0800 || ethertype == 0x86DD else { return nil }
        off = 14
    case .null:
        guard buf.count >= 4 else { return nil }
        // 4-byte protocol family, host byte order (little-endian here).
        let fam = UInt32(buf[0]) | UInt32(buf[1]) << 8 | UInt32(buf[2]) << 16 | UInt32(buf[3]) << 24
        guard fam == UInt32(AF_INET) || fam == UInt32(AF_INET6) else { return nil }
        off = 4
    case .raw:
        off = 0 // bare IP; the version nibble below selects v4/v6
    case .pktap:
        return nil // PKTAP records are parsed by PktapProvider, not here
    }
    guard buf.count >= off + 1 else { return nil }
    switch buf[off] >> 4 {
    case 4: return parseIPv4(buf, at: off)
    case 6: return parseIPv6(buf, at: off)
    default: return nil
    }
}

private func parseIPv4(_ buf: UnsafeRawBufferPointer, at ip: Int) -> ParsedPacket? {
    guard buf.count >= ip + 20 else { return nil }
    let ihl = Int(buf[ip] & 0x0f) * 4
    guard ihl >= 20, buf.count >= ip + ihl else { return nil }
    let totalLen = Int(UInt16(buf[ip + 2]) << 8 | UInt16(buf[ip + 3]))
    guard totalLen >= ihl, buf.count >= ip + min(totalLen, ihl + 4) else { return nil }
    let proto = buf[ip + 9]
    guard proto == 6 || proto == 17 else { return nil }
    func addr(_ at: Int) -> IPAddress {
        IPAddress.v4(UInt32(buf[at]) << 24 | UInt32(buf[at + 1]) << 16 | UInt32(buf[at + 2]) << 8 | UInt32(buf[at + 3]))
    }
    return parseL4(
        buf, at: ip + ihl, proto: proto,
        saddr: addr(ip + 12), daddr: addr(ip + 16)
    )
}

private func parseIPv6(_ buf: UnsafeRawBufferPointer, at ip: Int) -> ParsedPacket? {
    guard buf.count >= ip + 40 else { return nil }
    let payloadLen = Int(UInt16(buf[ip + 4]) << 8 | UInt16(buf[ip + 5]))
    guard buf.count >= ip + 40 + min(payloadLen, 4) else { return nil }
    func addr(_ at: Int) -> IPAddress {
        IPAddress.v6(UnsafeRawBufferPointer(rebasing: buf[at ..< at + 16]))
    }
    let saddr = addr(ip + 8)
    let daddr = addr(ip + 24)

    // Walk extension headers (hop-by-hop 0, routing 43, destination 60,
    // fragment 44). Non-first fragments have no L4 header — skipped.
    // Iteration-capped against malformed chains.
    var nh = buf[ip + 6]
    var off = ip + 40
    var hops = 0
    while hops < 8 {
        switch nh {
        case 6, 17:
            return parseL4(buf, at: off, proto: nh, saddr: saddr, daddr: daddr)
        case 0, 43, 60:
            guard buf.count >= off + 2 else { return nil }
            let len = (Int(buf[off + 1]) + 1) * 8
            nh = buf[off]
            off += len
        case 44: // fragment: fixed 8 bytes; first fragment only
            guard buf.count >= off + 8 else { return nil }
            let fragWord = UInt16(buf[off + 2]) << 8 | UInt16(buf[off + 3])
            guard fragWord >> 3 == 0 else { return nil } // non-first fragment
            nh = buf[off]
            off += 8
        default:
            return nil // AH/ESP/unknown: not TCP/UDP telemetry
        }
        hops += 1
        guard buf.count >= off + 4 else { return nil }
    }
    return nil
}

private func parseL4(
    _ buf: UnsafeRawBufferPointer, at l4: Int, proto: UInt8,
    saddr: IPAddress, daddr: IPAddress
) -> ParsedPacket? {
    guard buf.count >= l4 + 4 else { return nil }
    let sport = UInt16(buf[l4]) << 8 | UInt16(buf[l4 + 1])
    let dport = UInt16(buf[l4 + 2]) << 8 | UInt16(buf[l4 + 3])
    var synOnly = false
    var payloadOffset = l4 + 4
    if proto == 6 {
        guard buf.count >= l4 + 20 else { return nil }
        let dataOffset = Int(buf[l4 + 12] >> 4) * 4
        guard dataOffset >= 20, buf.count >= l4 + dataOffset else { return nil }
        let flags = buf[l4 + 13]
        synOnly = flags & 0x02 != 0 && flags & 0x10 == 0 // SYN && !ACK
        payloadOffset = l4 + dataOffset
    } else {
        payloadOffset = l4 + 8 // UDP header
    }
    return ParsedPacket(
        proto: proto, saddr: saddr, daddr: daddr, sport: sport, dport: dport,
        synOnly: synOnly,
        payloadOffset: payloadOffset,
        payloadLength: max(0, buf.count - payloadOffset)
    )
}

// MARK: - Flow tracking

struct FlowKey: Hashable {
    var proto: UInt8
    var saddr: IPAddress
    var sport: UInt16
    var daddr: IPAddress
    var dport: UInt16
}

/// Seen-tuple tracker: a tuple is "new" once per TTL window. The TTL lets
/// a genuinely re-established connection re-fire instead of being
/// suppressed forever.
struct FlowTracker {
    let ttl: TimeInterval
    let maxEntries: Int
    private var seen: [FlowKey: TimeInterval] = [:]

    init(ttl: TimeInterval = 300, maxEntries: Int = 8192) {
        self.ttl = ttl
        self.maxEntries = maxEntries
    }

    mutating func isNew(_ key: FlowKey, now: TimeInterval) -> Bool {
        seen = seen.filter { now - $0.value < ttl }
        if let last = seen[key], now - last < ttl { return false }
        if seen.count >= maxEntries, let oldest = seen.min(by: { $0.value < $1.value })?.key {
            seen.removeValue(forKey: oldest)
        }
        seen[key] = now
        return true
    }
}

// MARK: - Process attribution

struct SocketAttribution: Equatable {
    var pid: Int32
    var comm: String
    var uid: UInt32
    var identity: ProcessIdentity? = nil
}

/// Abstracted for tests (the real sweeper needs root and live sockets).
protocol SocketSweeping: Sendable {
    func attribute(_ flow: FlowKey) -> SocketAttribution?
    /// Re-confirm that a previously attributed process still owns `flow`.
    /// One process' fd table instead of a system-wide sweep.
    func revalidate(_ attribution: SocketAttribution, flow: FlowKey) -> SocketAttribution?
    /// Point-in-time snapshot of the whole socket table (background
    /// refresh). Default: unsupported (empty table).
    func socketTable() -> SocketTable
}

extension SocketSweeping {
    func revalidate(_: SocketAttribution, flow: FlowKey) -> SocketAttribution? {
        attribute(flow)
    }

    func socketTable() -> SocketTable { SocketTable() }
}

struct UdpLocalKey: Hashable, Sendable {
    var laddr: IPAddress
    var lport: UInt16
}

/// A point-in-time socket-table snapshot, built by a ~1s background
/// refresh so steady-state attribution is a map lookup instead of a full
/// pid×fd sweep per flow.
struct SocketTable: Sendable {
    /// TCP sockets and connected UDP sockets, keyed by exact 4-tuple.
    var exact: [FlowKey: SocketAttribution] = [:]
    /// Unconnected UDP sockets (wildcard foreign endpoint), keyed by
    /// local endpoint.
    var udpLocal: [UdpLocalKey: SocketAttribution] = [:]

    func lookup(_ flow: FlowKey) -> SocketAttribution? {
        if let hit = exact[flow] { return hit }
        guard flow.proto == 17 else { return nil }
        if let hit = udpLocal[UdpLocalKey(laddr: flow.saddr, lport: flow.sport)] { return hit }
        // Socket bound to a wildcard local address.
        let anyAddr = flow.saddr.isV6
            ? IPAddress(isV6: true, hi: 0, lo: 0)
            : IPAddress.v4(0)
        return udpLocal[UdpLocalKey(laddr: anyAddr, lport: flow.sport)]
    }
}

/// Tuple → attribution, in lookup order: TTL cache → background socket
/// table → one targeted sweep. Positive cache entries live `ttl`;
/// failures are cached briefly (`negativeTTL`) so an unattributable flow
/// (e.g. a short-lived DNS exchange) doesn't trigger a sweep per packet.
final class AttributionCache: @unchecked Sendable {
    let ttl: TimeInterval
    let negativeTTL: TimeInterval
    private let sweeper: any SocketSweeping
    private let lock = NSLock()
    let maxEntries: Int
    private var cache: [FlowKey: (value: SocketAttribution?, at: TimeInterval)] = [:]
    private var table: SocketTable?

    init(sweeper: any SocketSweeping, ttl: TimeInterval = 60, negativeTTL: TimeInterval = 3, maxEntries: Int = 8192) {
        self.sweeper = sweeper
        self.ttl = ttl
        self.negativeTTL = negativeTTL
        self.maxEntries = maxEntries
    }

    /// `revalidate` is set when a kill rule can act on the result: a cached
    /// pid is then re-confirmed against the live fd table (and its process
    /// identity) before it is handed out, so a recycled pid or a tuple that
    /// moved to another process falls back to a full sweep instead of
    /// naming the wrong process. Negative entries are always cached — they
    /// can never target a process, and re-sweeping them is what made every
    /// DNS packet pay for a system-wide walk.
    func attribute(_ flow: FlowKey, now: TimeInterval, revalidate: Bool = false) -> SocketAttribution? {
        lock.lock()
        let hit = cache[flow]
        let table = self.table
        lock.unlock()
        if let hit, now - hit.at < (hit.value == nil ? negativeTTL : ttl) {
            guard let cached = hit.value else { return nil }
            if !revalidate { return cached }
            if let fresh = sweeper.revalidate(cached, flow: flow), fresh.identity == cached.identity {
                store(flow, fresh, now)
                return fresh
            }
        }
        // Background table first; a miss falls through to the targeted
        // sweep (covers sockets born after the last refresh).
        let value = table?.lookup(flow) ?? sweeper.attribute(flow)
        store(flow, value, now)
        return value
    }

    /// Install the latest background snapshot (BpfProvider refreshes ~1s).
    func setTable(_ table: SocketTable) {
        lock.lock()
        self.table = table
        lock.unlock()
    }

    private func store(_ flow: FlowKey, _ value: SocketAttribution?, _ now: TimeInterval) {
        lock.lock()
        defer { lock.unlock() }
        if cache.count >= maxEntries, cache[flow] == nil,
           let oldest = cache.min(by: { $0.value.at < $1.value.at })?.key
        {
            cache.removeValue(forKey: oldest)
        }
        cache[flow] = (value, now)
    }
}

/// libproc sweep: walk every pid's fd table, inspect sockets, stop at the
/// first 4-tuple match. Expensive (hundreds of pids × fd listings) — only
/// ever called for new tuples via AttributionCache.
struct LibprocSweeper: SocketSweeping {
    private let selfPID = getpid()

    func attribute(_ flow: FlowKey) -> SocketAttribution? {
        var found: SocketAttribution?
        for pid in allPids() where pid > 0 && pid != selfPID {
            if let hit = match(pid: pid, flow: flow) {
                // Wildcard UDP sockets are ambiguous when more than one
                // process shares a local port. Fail open rather than pick a
                // PID that a later kill rule could terminate incorrectly.
                if found != nil { return nil }
                found = hit
            }
        }
        return found
    }

    /// Single-process re-check for a cached attribution. It cannot see a
    /// second owner that appeared since (the "first pid wins" caveat for
    /// unconnected UDP sockets below), so the engine still re-reads the
    /// process identity before it signals.
    func revalidate(_ attribution: SocketAttribution, flow: FlowKey) -> SocketAttribution? {
        guard attribution.pid > 0, attribution.pid != selfPID else { return nil }
        return match(pid: attribution.pid, flow: flow)
    }

    /// Full socket-table snapshot for the background refresh (~1s). One
    /// pid×fd walk instead of one per new flow; steady-state attribution
    /// becomes a map lookup.
    func socketTable() -> SocketTable {
        var table = SocketTable()
        for pid in allPids() where pid > 0 && pid != selfPID {
            collect(pid: pid, into: &table)
        }
        return table
    }

    /// Listening sockets for the snapshot-diff inventory: TCP in
    /// TSI_S_LISTEN, plus unconnected UDP sockets bound to a port (the
    /// UDP "listener" shape).
    func listeningSockets() -> Set<ListenSocket> {
        var out: Set<ListenSocket> = []
        for pid in allPids() where pid > 0 && pid != selfPID {
            var size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
            guard size > 0 else { continue }
            var fds = [proc_fdinfo](repeating: proc_fdinfo(proc_fd: 0, proc_fdtype: 0), count: Int(size) / MemoryLayout<proc_fdinfo>.size + 8)
            size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fds, Int32(fds.count * MemoryLayout<proc_fdinfo>.size))
            guard size > 0 else { continue }
            for fd in fds.prefix(Int(size) / MemoryLayout<proc_fdinfo>.size) where fd.proc_fdtype == PROX_FDTYPE_SOCKET {
                var sfi = socket_fdinfo()
                let sz = Int32(MemoryLayout<socket_fdinfo>.size)
                guard proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDSOCKETINFO, &sfi, sz) == sz else { continue }
                let psi = sfi.psi
                func wildcard(_ a: IPAddress) -> Bool { a.hi == 0 && a.lo == 0 }
                switch psi.soi_protocol {
                case IPPROTO_TCP:
                    let ini = psi.soi_proto.pri_tcp.tcpsi_ini
                    guard psi.soi_proto.pri_tcp.tcpsi_state == TSI_S_LISTEN else { continue }
                    let port = UInt16(truncatingIfNeeded: ini.insi_lport).byteSwapped
                    guard port != 0 else { continue }
                    out.insert(ListenSocket(proto: "tcp", port: port, pid: pid))
                case IPPROTO_UDP:
                    let ini = psi.soi_proto.pri_in
                    let lport = UInt16(truncatingIfNeeded: ini.insi_lport).byteSwapped
                    let fport = UInt16(truncatingIfNeeded: ini.insi_fport).byteSwapped
                    let faddr: IPAddress = ini.insi_vflag & 0x2 != 0
                        ? v6Addr(ini.insi_faddr.ina_6)
                        : IPAddress.v4(packBE(ini.insi_faddr.ina_46.i46a_addr4))
                    guard lport != 0, fport == 0, wildcard(faddr) else { continue }
                    out.insert(ListenSocket(proto: "udp", port: lport, pid: pid))
                default:
                    continue
                }
            }
        }
        return out
    }

    private struct Endpoints {
        var proto: UInt8
        var laddr: IPAddress
        var lport: UInt16
        var faddr: IPAddress
        var fport: UInt16
    }

    private func socketEndpoints(pid: pid_t, fd: Int32) -> Endpoints? {
        var sfi = socket_fdinfo()
        let size = Int32(MemoryLayout<socket_fdinfo>.size)
        guard proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &sfi, size) == size else { return nil }
        let psi = sfi.psi
        let ini: in_sockinfo
        let proto: UInt8
        switch psi.soi_protocol {
        case IPPROTO_TCP:
            ini = psi.soi_proto.pri_tcp.tcpsi_ini
            proto = 6
        case IPPROTO_UDP:
            ini = psi.soi_proto.pri_in
            proto = 17
        default:
            return nil
        }
        let lport = UInt16(truncatingIfNeeded: ini.insi_lport).byteSwapped
        let fport = UInt16(truncatingIfNeeded: ini.insi_fport).byteSwapped
        // ini_vflag: ini_IPV4 = 0x1, ini_IPV6 = 0x2 (xnu sys/proc_info.h).
        let laddr: IPAddress
        let faddr: IPAddress
        if ini.insi_vflag & 0x2 != 0, psi.soi_family == AF_INET6 {
            laddr = v6Addr(ini.insi_laddr.ina_6)
            faddr = v6Addr(ini.insi_faddr.ina_6)
        } else if ini.insi_vflag & 0x1 != 0, psi.soi_family == AF_INET {
            laddr = IPAddress.v4(packBE(ini.insi_laddr.ina_46.i46a_addr4))
            faddr = IPAddress.v4(packBE(ini.insi_faddr.ina_46.i46a_addr4))
        } else {
            return nil
        }
        return Endpoints(proto: proto, laddr: laddr, lport: lport, faddr: faddr, fport: fport)
    }

    private func collect(pid: pid_t, into table: inout SocketTable) {
        var size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard size > 0 else { return }
        var fds = [proc_fdinfo](repeating: proc_fdinfo(proc_fd: 0, proc_fdtype: 0), count: Int(size) / MemoryLayout<proc_fdinfo>.size + 8)
        size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fds, Int32(fds.count * MemoryLayout<proc_fdinfo>.size))
        guard size > 0 else { return }
        func wildcard(_ a: IPAddress) -> Bool { a.hi == 0 && a.lo == 0 }
        var attr: SocketAttribution?
        for fd in fds.prefix(Int(size) / MemoryLayout<proc_fdinfo>.size) where fd.proc_fdtype == PROX_FDTYPE_SOCKET {
            guard let e = socketEndpoints(pid: pid, fd: fd.proc_fd) else { continue }
            if attr == nil {
                let info = procInfo(pid)
                attr = SocketAttribution(
                    pid: pid, comm: info?.comm ?? "pid \(pid)",
                    uid: info?.uid ?? 0, identity: info?.identity
                )
            }
            let key = FlowKey(proto: e.proto, saddr: e.laddr, sport: e.lport, daddr: e.faddr, dport: e.fport)
            if e.proto == 6 || !wildcard(e.faddr) || e.fport != 0 {
                table.exact[key] = attr
            } else {
                table.udpLocal[UdpLocalKey(laddr: e.laddr, lport: e.lport)] = attr
            }
        }
    }

    private func match(pid: pid_t, flow: FlowKey) -> SocketAttribution? {
        var size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard size > 0 else { return nil }
        var fds = [proc_fdinfo](repeating: proc_fdinfo(proc_fd: 0, proc_fdtype: 0), count: Int(size) / MemoryLayout<proc_fdinfo>.size + 8)
        size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fds, Int32(fds.count * MemoryLayout<proc_fdinfo>.size))
        guard size > 0 else { return nil }
        for fd in fds.prefix(Int(size) / MemoryLayout<proc_fdinfo>.size)
        where fd.proc_fdtype == PROX_FDTYPE_SOCKET && socketMatches(pid: pid, fd: fd.proc_fd, flow: flow) {
            let info = procInfo(pid)
            return SocketAttribution(
                pid: pid,
                comm: info?.comm ?? "pid \(pid)",
                uid: info?.uid ?? 0,
                identity: info?.identity
            )
        }
        return nil
    }

    private func socketMatches(pid: pid_t, fd: Int32, flow: FlowKey) -> Bool {
        var sfi = socket_fdinfo()
        let size = Int32(MemoryLayout<socket_fdinfo>.size)
        guard proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &sfi, size) == size else { return false }
        let psi = sfi.psi
        let ini: in_sockinfo
        switch Int32(flow.proto) {
        case IPPROTO_TCP:
            guard psi.soi_protocol == IPPROTO_TCP else { return false }
            ini = psi.soi_proto.pri_tcp.tcpsi_ini
        case IPPROTO_UDP:
            guard psi.soi_protocol == IPPROTO_UDP else { return false }
            ini = psi.soi_proto.pri_in
        default:
            return false
        }
        // ini_vflag: ini_IPV4 = 0x1, ini_IPV6 = 0x2 (xnu sys/proc_info.h;
        // the constants are not exported by the public SDK header).
        let lport = UInt16(truncatingIfNeeded: ini.insi_lport).byteSwapped
        let fport = UInt16(truncatingIfNeeded: ini.insi_fport).byteSwapped
        guard lport == flow.sport else { return false }
        let isUdp = flow.proto == 17
        // UDP resolver sockets are typically unconnected: foreign addr and
        // port are wildcard. For those, the local port is the whole match
        // (caveat: two unconnected sockets sharing a local port in
        // different processes are indistinguishable — first pid wins).
        if isUdp {
            guard fport == 0 || fport == flow.dport else { return false }
        } else {
            guard fport == flow.dport else { return false }
        }
        let laddr: IPAddress
        let faddr: IPAddress
        if flow.saddr.isV6 {
            guard psi.soi_family == AF_INET6, ini.insi_vflag & 0x2 != 0 else { return false }
            laddr = v6Addr(ini.insi_laddr.ina_6)
            faddr = v6Addr(ini.insi_faddr.ina_6)
        } else {
            guard psi.soi_family == AF_INET, ini.insi_vflag & 0x1 != 0 else { return false }
            laddr = IPAddress.v4(packBE(ini.insi_laddr.ina_46.i46a_addr4))
            faddr = IPAddress.v4(packBE(ini.insi_faddr.ina_46.i46a_addr4))
        }
        if isUdp {
            func wildcard(_ a: IPAddress) -> Bool { a.hi == 0 && a.lo == 0 }
            return (wildcard(laddr) || laddr == flow.saddr)
                && (wildcard(faddr) || faddr == flow.daddr)
        }
        return laddr == flow.saddr && faddr == flow.daddr
    }
}

/// in_addr.s_addr memory bytes repacked big-endian, matching the parser.
private func packBE(_ addr: in_addr) -> UInt32 {
    withUnsafeBytes(of: addr.s_addr) { b in
        UInt32(b[0]) << 24 | UInt32(b[1]) << 16 | UInt32(b[2]) << 8 | UInt32(b[3])
    }
}

/// in6_addr memory bytes repacked big-endian, matching the parser.
private func v6Addr(_ addr: in6_addr) -> IPAddress {
    withUnsafeBytes(of: addr) { IPAddress.v6($0) }
}

// MARK: - BPF device plumbing

// ioctl constants from <net/bpf.h> (_IOC encoding: dir|len<<16|'b'<<8|num).
let BIOCGBLEN: UInt = 0x4004_4266 // _IOR('b',102,u_int)
let BIOCSBLEN: UInt = 0xC004_4266 // _IOWR('b',102,u_int)
let BIOCSETIF: UInt = 0x8020_426C // _IOW('b',108,struct ifreq)
let BIOCGETDLT: UInt = 0x4004_426A // _IOR('b',106,u_int)
let BIOCIMMEDIATE: UInt = 0x8004_4270 // _IOW('b',112,u_int)

struct BpfInterface {
    let name: String
    let fd: Int32
    let link: LinkType
}

/// Active interfaces (up, non-loopback) worth capturing on. Loopback is
/// skipped: both endpoints are local, which makes the outbound heuristic
/// meaningless and the volume high on a dev box.
private func captureInterfaces() -> [String] {
    var names: Set<String> = []
    var ifaddr: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&ifaddr) == 0 else { return [] }
    defer { freeifaddrs(ifaddr) }
    var cur = ifaddr
    while let p = cur {
        let flags = p.pointee.ifa_flags
        if flags & UInt32(IFF_UP) != 0, flags & UInt32(IFF_LOOPBACK) == 0,
           p.pointee.ifa_addr != nil,
           p.pointee.ifa_addr.pointee.sa_family == AF_INET || p.pointee.ifa_addr.pointee.sa_family == AF_INET6
        {
            names.insert(String(cString: p.pointee.ifa_name))
        }
        cur = p.pointee.ifa_next
    }
    return names.sorted()
}

/// All local addresses (v4 + v6, including link-local/ULA; ::1 excluded)
/// — the outbound heuristic: a packet is outbound when its source is one
/// of ours.
func localAddrs() -> Set<IPAddress> {
    var result: Set<IPAddress> = []
    var ifaddr: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&ifaddr) == 0 else { return result }
    defer { freeifaddrs(ifaddr) }
    var cur = ifaddr
    while let p = cur {
        if p.pointee.ifa_addr != nil {
            switch p.pointee.ifa_addr.pointee.sa_family {
            case sa_family_t(AF_INET):
                p.pointee.ifa_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    _ = result.insert(.v4(packBE(sin.pointee.sin_addr)))
                }
            case sa_family_t(AF_INET6):
                p.pointee.ifa_addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                    let addr = v6Addr(sin6.pointee.sin6_addr)
                    if addr != v6Addr(in6addr_loopback) { // ::1 stays out
                        _ = result.insert(addr)
                    }
                }
            default:
                break
            }
        }
        cur = p.pointee.ifa_next
    }
    return result
}

enum BpfError: Error, CustomStringConvertible {
    case noDevice
    case noInterface

    var description: String {
        switch self {
        case .noDevice: return "no /dev/bpf* device could be opened (needs root)"
        case .noInterface: return "no capture-capable interface (DLT_EN10MB/DLT_NULL) found"
        }
    }
}

func openBpfDevice() throws -> Int32 {
    for i in 0 ..< 8 {
        let fd = open("/dev/bpf\(i)", O_RDWR | O_NONBLOCK)
        if fd >= 0 { return fd }
    }
    throw BpfError.noDevice
}

func bindInterface(fd: Int32, name: String) throws -> LinkType {
    var len: UInt32 = 262_144
    _ = ioctl(fd, BIOCSBLEN, &len) // best-effort; must precede BIOCSETIF
    var ifreq = [UInt8](repeating: 0, count: 32) // ifr_name[16] + ifr_addr
    let nameBytes = Array(name.utf8.prefix(15))
    ifreq.replaceSubrange(0 ..< nameBytes.count, with: nameBytes)
    guard ioctl(fd, BIOCSETIF, &ifreq) == 0 else {
        throw MerlinError.plain("BIOCSETIF \(name) failed: errno \(errno)")
    }
    var immediate: UInt32 = 1
    _ = ioctl(fd, BIOCIMMEDIATE, &immediate)
    var dlt: UInt32 = 0
    guard ioctl(fd, BIOCGETDLT, &dlt) == 0, let link = LinkType(rawValue: dlt) else {
        throw MerlinError.plain("interface \(name): unsupported data-link type \(dlt)")
    }
    return link
}

// MARK: - Provider

/// Walk one bpf read buffer into captured frames. Pure and internal for
/// tests — this is the math the first live run broke.
///
/// Record layout (macOS): bpf_hdr {tv_sec,tv_usec,caplen,datalen,hdrlen}
/// = 18 bytes (BPF_TIMEVAL is two 32-bit fields), BUT bh_hdrlen is the
/// header PLUS BPF_WORDALIGN padding (BPF_WORDALIGN(18) = 20) and is the
/// offset from record start to the packet data; the record stride is
/// BPF_WORDALIGN(hdrlen + caplen). So: data at off+hdrlen, next record at
/// off+align(hdrlen+caplen) — never off+18 / off+hdrlen.
///
/// Stops gracefully at the first malformed or truncated record.
func bpfFrames(_ buf: UnsafeRawBufferPointer) -> [UnsafeRawBufferPointer] {
    var frames: [UnsafeRawBufferPointer] = []
    var off = 0
    while off + 18 <= buf.count {
        let caplen = Int(buf.loadUnaligned(fromByteOffset: off + 8, as: UInt32.self))
        let hdrlen = Int(buf.loadUnaligned(fromByteOffset: off + 16, as: UInt16.self))
        guard hdrlen >= 18, off + hdrlen + caplen <= buf.count else { break }
        frames.append(UnsafeRawBufferPointer(rebasing: buf[off + hdrlen ..< off + hdrlen + caplen]))
        off += (hdrlen + caplen + 3) & ~3 // BPF_WORDALIGN
    }
    return frames
}

final class BpfProvider: @unchecked Sendable {
    private let engine: Engine
    private var ifaces: [BpfInterface] = []
    private var thread: Thread?
    private let lock = NSLock()
    private var running = false
    private var tracker = FlowTracker()
    private let attributor: AttributionCache
    private let sweeper: any SocketSweeping
    private let freshAttribution: Bool
    private var locals: Set<IPAddress> = []
    private var tableTimer: DispatchSourceTimer?

    init(engine: Engine, sweeper: any SocketSweeping = LibprocSweeper()) {
        self.engine = engine
        self.sweeper = sweeper
        attributor = AttributionCache(sweeper: sweeper)
        freshAttribution = engine.needsFreshNetworkAttribution
    }

    /// Open one /dev/bpf fd per capture interface and bind it.
    func start() throws {
        let candidates = captureInterfaces()
        locals = localAddrs()
        var opened: [BpfInterface] = []
        for name in candidates {
            do {
                let fd = try openBpfDevice()
                do {
                    let link = try bindInterface(fd: fd, name: name)
                    opened.append(BpfInterface(name: name, fd: fd, link: link))
                } catch {
                    close(fd)
                    merlinLog("warn", "bpf: skipping \(name): \(error)")
                }
            } catch {
                break // out of /dev/bpf devices
            }
        }
        guard !opened.isEmpty else {
            throw candidates.isEmpty ? BpfError.noInterface : BpfError.noDevice
        }
        ifaces = opened
        lock.lock()
        running = true
        lock.unlock()
        // Background socket-table refresh (~1s): steady-state attribution
        // is a map lookup; a table miss falls back to the targeted sweep.
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "merlin.bpf.table", qos: .utility))
        timer.schedule(deadline: .now(), repeating: 1.0)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            self.attributor.setTable(self.sweeper.socketTable())
        }
        timer.resume()
        tableTimer = timer
        let t = Thread { [weak self] in self?.captureLoop() }
        t.name = "merlin.bpf"
        t.start()
        thread = t
        merlinLog("info", "bpf network provider: capturing on \(opened.map(\.name).joined(separator: ", ")) (IPv4+IPv6 TCP/UDP connect telemetry)")
    }

    func stop() {
        tableTimer?.cancel()
        tableTimer = nil
        lock.lock()
        running = false
        lock.unlock()
        for i in ifaces { close(i.fd) }
        ifaces = []
    }

    private func isRunning() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return running
    }

    private func captureLoop() {
        var buf = [UInt8](repeating: 0, count: 262_144)
        while isRunning() {
            var fds = ifaces.map { pollfd(fd: $0.fd, events: Int16(POLLIN), revents: 0) }
            let n = poll(&fds, nfds_t(fds.count), 250)
            if n < 0 {
                if errno == EINTR { continue }
                if isRunning() {
                    merlinLog("error", "bpf poll failed: errno \(errno); network telemetry stopped")
                }
                return
            }
            for (i, iface) in ifaces.enumerated() where fds[i].revents & Int16(POLLIN) != 0 {
                let got = buf.withUnsafeMutableBytes { raw in
                    read(iface.fd, raw.baseAddress, raw.count)
                }
                if got > 0 {
                    buf.withUnsafeBytes { raw in
                        processBuffer(UnsafeRawBufferPointer(rebasing: raw.prefix(got)), link: iface.link)
                    }
                }
            }
        }
    }

    /// Feed each captured frame in one bpf read buffer to the parser (the
    /// record-walk itself is the pure, testable bpfFrames below).
    private func processBuffer(_ buf: UnsafeRawBufferPointer, link: LinkType) {
        for frame in bpfFrames(buf) {
            if let pkt = parsePacket(frame, link: link) {
                handlePacket(pkt, frame: frame)
            }
        }
    }

    private func handlePacket(_ pkt: ParsedPacket, frame: UnsafeRawBufferPointer) {
        // DNS first: both directions are interesting (queries give the
        // qname, responses give the rcode → NXDOMAIN visibility). A
        // response's source is the resolver, so the outbound heuristic
        // below can't gate this.
        if pkt.dport == 53, locals.contains(pkt.saddr) {
            handleDns(pkt, frame: frame, queryDir: true)
        } else if pkt.sport == 53, locals.contains(pkt.daddr) {
            handleDns(pkt, frame: frame, queryDir: false)
        }

        // Outbound heuristic: source is a local address. (On the capture
        // interfaces loopback is excluded, so this is a clean signal.)
        guard locals.contains(pkt.saddr) else { return }
        let key = FlowKey(proto: pkt.proto, saddr: pkt.saddr, sport: pkt.sport, daddr: pkt.daddr, dport: pkt.dport)
        let now = nowTs()
        // TCP SYN-without-ACK is the definitive connect; anything else from
        // an unseen tuple is a flow first seen mid-stream — still a
        // connect worth recording once.
        guard tracker.isNew(key, now: now) else { return }
        let attr = attributor.attribute(key, now: now, revalidate: freshAttribution)
        engine.handleConnect(
            pid: attr?.pid, uid: attr?.uid, comm: attr?.comm,
            identity: attr?.identity,
            saddr: addrString(pkt.saddr), daddr: addrString(pkt.daddr),
            sport: pkt.sport, dport: pkt.dport,
            family: pkt.saddr.isV6 ? UInt16(AF_INET6) : UInt16(AF_INET),
            protocolNumber: pkt.proto,
            state: pkt.proto == 6 ? (pkt.synOnly ? "syn_sent" : "observed") : "datagram"
        )
    }

    /// Parse the DNS payload of a port-53 packet and spool a dns event.
    /// `queryDir` is true for our query (dst 53), false for the resolver's
    /// response (src 53). Attribution sweeps with the tuple oriented
    /// local→foreign either way; unconnected UDP resolver sockets match on
    /// local port alone (see LibprocSweeper).
    private func handleDns(_ pkt: ParsedPacket, frame: UnsafeRawBufferPointer, queryDir: Bool) {
        let payload = UnsafeRawBufferPointer(rebasing: frame[pkt.payloadOffset ..< pkt.payloadOffset + pkt.payloadLength])
        let msg = pkt.proto == 17 ? parseDns(payload) : parseDnsTcp(payload)
        guard let msg else { return }
        let key = queryDir
            ? FlowKey(proto: pkt.proto, saddr: pkt.saddr, sport: pkt.sport, daddr: pkt.daddr, dport: pkt.dport)
            : FlowKey(proto: pkt.proto, saddr: pkt.daddr, sport: pkt.dport, daddr: pkt.saddr, dport: pkt.sport)
        let attr = attributor.attribute(key, now: nowTs(), revalidate: freshAttribution)
        engine.handleDns(pid: attr?.pid, uid: attr?.uid, comm: attr?.comm, identity: attr?.identity, msg: msg)
    }
}

/// Shared stop-capable surface for network providers (BpfProvider,
/// PktapProvider) so RunCommand can hold either.
protocol NetworkProviding: AnyObject {
    func stop()
}

extension BpfProvider: NetworkProviding {}
