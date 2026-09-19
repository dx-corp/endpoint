// PktapProvider — kernel-authoritative network attribution via DLT_PKTAP.
//
// Sibling of BpfProvider (same bpf plumbing, record walk, packet parser,
// flow tracking, DNS parsing) with one decisive difference: attribution
// comes from the PKTAP header the kernel stamps on every packet —
// pth_pid/pth_comm plus the EFFECTIVE pid/comm for delegated flows —
// instead of a libproc socket sweep. The nsurlsessiond problem (every
// HTTP flow attributing to the daemon, not the requesting app) is solved
// by the kernel: when pth_epid differs from pth_pid we attribute to the
// effective pid and record the immediate one as via_pid.
//
// Header layouts (xnu-12377 bsd/net/pktap.h):
//   v1 struct pktap_header — fixed 156-byte layout.
//   v2 struct pktap_v2_hdr — 40-byte fixed prefix + offset-indexed
//   variable fields (uuid/euuid/ifname/comm/ecomm), used on modern
//   macOS; PTH_FLAG_V2_HDR (0x00080000) lives at offset 36 in BOTH
//   layouts and distinguishes them.
// Binding: BIOCSETIF "pktap" alone captures ALL interfaces — tcpdump's
// ",all" suffix is libpcap-level syntax for that same default.
//
// Root required (like /dev/bpf generally).

import Foundation

/// DLT_PKTAP — not exported by the SDK's <net/bpf.h>; value from
/// pcap/dlt.h (libpcap) and xnu. BIOCGETDLT on the bound interface is
/// the authority at runtime; this is the expected value.
let DLT_PKTAP_VALUE: UInt32 = 258

private let PTH_FLAG_V2_HDR: UInt32 = 0x0008_0000

struct PktapMeta: Equatable {
    var pid: Int32?
    var comm: String?
    var epid: Int32?
    var ecomm: String?
    var ifname: String?

    /// Attribution per the kernel: effective identity when delegated.
    var attrPid: Int32? { epid != nil && epid != pid ? epid : pid }
    var attrComm: String? { epid != nil && epid != pid ? ecomm ?? comm : comm }
    /// Immediate pid, only when it differs from the attributed one.
    var viaPid: Int32? { epid != nil && epid != pid ? pid : nil }
}

private func cStringAt(_ buf: UnsafeRawBufferPointer, offset: Int, max: Int) -> String? {
    guard offset > 0, offset + 1 <= buf.count else { return nil }
    let end = min(offset + max, buf.count)
    let s = String(decoding: buf[offset ..< end].prefix { $0 != 0 }, as: UTF8.self)
    return s.isEmpty ? nil : s
}

/// Parse one PKTAP record into metadata + the packet payload (after the
/// header and pth_frame_pre_length). Handles both header versions.
func parsePktapRecord(_ buf: UnsafeRawBufferPointer) -> (meta: PktapMeta, dlt: UInt32, payload: UnsafeRawBufferPointer)? {
    guard buf.count >= 40 else { return nil }
    let flags = buf.loadUnaligned(fromByteOffset: 36, as: UInt32.self)
    if flags & PTH_FLAG_V2_HDR != 0 {
        // v2: 40-byte fixed prefix; offsets are from header start.
        let length = Int(buf[0])
        guard length >= 40, length <= buf.count else { return nil }
        let pre = Int(buf.loadUnaligned(fromByteOffset: 8, as: UInt16.self))
        let dlt = UInt32(buf.loadUnaligned(fromByteOffset: 6, as: UInt16.self))
        let pid = buf.loadUnaligned(fromByteOffset: 28, as: Int32.self)
        let epid = buf.loadUnaligned(fromByteOffset: 32, as: Int32.self)
        let ifOff = Int(buf[3])
        let commOff = Int(buf[4])
        let ecommOff = Int(buf[5])
        var meta = PktapMeta()
        meta.pid = pid > 0 ? pid : nil
        meta.epid = epid > 0 ? epid : nil
        meta.ifname = cStringAt(buf, offset: ifOff, max: min(length - ifOff, 24))
        meta.comm = cStringAt(buf, offset: commOff, max: min(length - commOff, 17))
        meta.ecomm = cStringAt(buf, offset: ecommOff, max: min(length - ecommOff, 17))
        let start = length + pre
        guard start <= buf.count else { return nil }
        return (meta, dlt, UnsafeRawBufferPointer(rebasing: buf[start...]))
    }
    // v1: fixed 156-byte struct pktap_header.
    let length = Int(buf.loadUnaligned(fromByteOffset: 0, as: UInt32.self))
    guard length >= 156, length <= buf.count else { return nil }
    let dlt = buf.loadUnaligned(fromByteOffset: 8, as: UInt32.self)
    let pre = Int(buf.loadUnaligned(fromByteOffset: 44, as: UInt32.self))
    var meta = PktapMeta()
    meta.ifname = cStringAt(buf, offset: 12, max: 24)
    let pid = buf.loadUnaligned(fromByteOffset: 52, as: Int32.self)
    let epid = buf.loadUnaligned(fromByteOffset: 84, as: Int32.self)
    meta.pid = pid > 0 ? pid : nil
    meta.epid = epid > 0 ? epid : nil
    meta.comm = cStringAt(buf, offset: 56, max: 17)
    meta.ecomm = cStringAt(buf, offset: 88, max: 17)
    let start = length + pre
    guard start <= buf.count else { return nil }
    return (meta, dlt, UnsafeRawBufferPointer(rebasing: buf[start...]))
}

/// Map a PKTAP-reported DLT to the parser's LinkType.
func linkTypeForDlt(_ dlt: UInt32) -> LinkType? {
    switch dlt {
    case 1: return .en10mb
    case 0: return .null
    case 12: return .raw
    default: return nil
    }
}

final class PktapProvider: @unchecked Sendable {
    private let engine: Engine
    private var iface: BpfInterface?
    private var thread: Thread?
    private let lock = NSLock()
    private var running = false
    private var tracker = FlowTracker()
    private var locals: Set<IPAddress> = []

    init(engine: Engine) {
        self.engine = engine
    }

    func start() throws {
        locals = localAddrs()
        let fd = try openBpfDevice()
        let link = try bindInterface(fd: fd, name: "pktap")
        guard link == .pktap else {
            close(fd)
            throw MerlinError.plain("pktap bind returned unexpected DLT \(link.rawValue)")
        }
        iface = BpfInterface(name: "pktap", fd: fd, link: link)
        lock.lock()
        running = true
        lock.unlock()
        let t = Thread { [weak self] in self?.captureLoop() }
        t.name = "merlin.pktap"
        t.start()
        thread = t
        merlinLog("info", "pktap network provider: DLT_PKTAP, kernel process attribution (effective pid for delegated flows)")
    }

    func stop() {
        lock.lock()
        running = false
        lock.unlock()
        if let i = iface { close(i.fd) }
        iface = nil
    }

    private func isRunning() -> Bool {
        lock.withLock { running }
    }

    private func captureLoop() {
        var buf = [UInt8](repeating: 0, count: 262_144)
        while isRunning() {
            guard let fd = iface?.fd else { return }
            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let n = poll(&pfd, 1, 250)
            if n < 0 {
                if errno == EINTR { continue }
                if isRunning() {
                    merlinLog("error", "pktap poll failed: errno \(errno); network telemetry stopped")
                }
                return
            }
            guard n > 0, pfd.revents & Int16(POLLIN) != 0 else { continue }
            let got = buf.withUnsafeMutableBytes { raw in
                read(fd, raw.baseAddress, raw.count)
            }
            guard got > 0 else { continue }
            buf.withUnsafeBytes { raw in
                for record in bpfFrames(UnsafeRawBufferPointer(rebasing: raw.prefix(got))) {
                    guard let (meta, dlt, payload) = parsePktapRecord(record),
                          let link = linkTypeForDlt(dlt),
                          let pkt = parsePacket(payload, link: link)
                    else { continue }
                    handlePacket(pkt, meta: meta, frame: payload)
                }
            }
        }
    }

    private func handlePacket(_ pkt: ParsedPacket, meta: PktapMeta, frame: UnsafeRawBufferPointer) {
        if pkt.dport == 53, locals.contains(pkt.saddr) {
            handleDns(pkt, meta: meta, frame: frame, queryDir: true)
        } else if pkt.sport == 53, locals.contains(pkt.daddr) {
            handleDns(pkt, meta: meta, frame: frame, queryDir: false)
        }
        guard locals.contains(pkt.saddr) else { return }
        let key = FlowKey(proto: pkt.proto, saddr: pkt.saddr, sport: pkt.sport, daddr: pkt.daddr, dport: pkt.dport)
        guard tracker.isNew(key, now: nowTs()) else { return }
        let info = meta.attrPid.flatMap { procInfo($0) }
        engine.handleConnect(
            pid: meta.attrPid, uid: info?.uid, comm: meta.attrComm,
            identity: info?.identity,
            saddr: addrString(pkt.saddr), daddr: addrString(pkt.daddr),
            sport: pkt.sport, dport: pkt.dport, viaPid: meta.viaPid
        )
    }

    private func handleDns(_ pkt: ParsedPacket, meta: PktapMeta, frame: UnsafeRawBufferPointer, queryDir: Bool) {
        let range = pkt.payloadOffset ..< pkt.payloadOffset + pkt.payloadLength
        guard range.upperBound <= frame.count else { return }
        let payload = UnsafeRawBufferPointer(rebasing: frame[range])
        let msg = pkt.proto == 17 ? parseDns(payload) : parseDnsTcp(payload)
        guard let msg else { return }
        let info = meta.attrPid.flatMap { procInfo($0) }
        engine.handleDns(
            pid: meta.attrPid, uid: info?.uid, comm: meta.attrComm,
            identity: info?.identity, msg: msg, viaPid: meta.viaPid
        )
    }
}

extension PktapProvider: NetworkProviding {}
