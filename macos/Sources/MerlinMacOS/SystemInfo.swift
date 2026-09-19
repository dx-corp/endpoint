import Darwin
import Foundation

/// Read-only host facts shared with the managed-device heartbeat. Keep this
/// inventory bounded and free of usernames, paths, addresses, and processes.
struct DeviceNetworkInterface: Encodable, Sendable {
    let name: String
    let kind: String
    let state: String
    let mtu: UInt32?

    enum CodingKeys: String, CodingKey {
        case name
        case kind
        case state
        case mtu
    }
}

struct DeviceOSInfo: Encodable, Sendable {
    let osName: String
    let osVersion: String
    let osPrettyName: String
    let osID: String
    let osCodename: String
    let osBuild: String
    let kernel: String
    let kernelBuild: String
    let architecture: String
    let cpuModel: String
    let hardwareModel: String
    let uptimeSeconds: UInt64
    let cpuCount: UInt32
    let loadAverage: [Double]
    let memoryTotalBytes: UInt64
    let memoryAvailableBytes: UInt64?
    let swapTotalBytes: UInt64
    let swapFreeBytes: UInt64
    let diskTotalBytes: UInt64
    let diskFreeBytes: UInt64
    let rootFilesystem: String
    let virtualization: String
    let containerized: Bool
    let networkInterfaces: [String]
    let networkInterfaceDetails: [DeviceNetworkInterface]

    enum CodingKeys: String, CodingKey {
        case osName = "os_name"
        case osVersion = "os_version"
        case osPrettyName = "os_pretty_name"
        case osID = "os_id"
        case osCodename = "os_codename"
        case osBuild = "os_build"
        case kernel
        case kernelBuild = "kernel_build"
        case architecture
        case cpuModel = "cpu_model"
        case hardwareModel = "hardware_model"
        case uptimeSeconds = "uptime_seconds"
        case cpuCount = "cpu_count"
        case loadAverage = "load_average"
        case memoryTotalBytes = "memory_total_bytes"
        case memoryAvailableBytes = "memory_available_bytes"
        case swapTotalBytes = "swap_total_bytes"
        case swapFreeBytes = "swap_free_bytes"
        case diskTotalBytes = "disk_total_bytes"
        case diskFreeBytes = "disk_free_bytes"
        case rootFilesystem = "root_filesystem"
        case virtualization
        case containerized
        case networkInterfaces = "network_interfaces"
        case networkInterfaceDetails = "network_interface_details"
    }
}

private func sysctlUInt64(_ name: String) -> UInt64? {
    var value: UInt64 = 0
    var size = MemoryLayout<UInt64>.size
    guard sysctlbyname(name, &value, &size, nil, 0) == 0 else { return nil }
    return value
}

private func sysctlString(_ name: String) -> String? {
    var size = 0
    guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return nil }
    var bytes = [UInt8](repeating: 0, count: size)
    let result = bytes.withUnsafeMutableBytes { raw in
        sysctlbyname(name, raw.baseAddress, &size, nil, 0)
    }
    guard result == 0 else { return nil }
    return String(decoding: bytes.prefix { $0 != 0 }, as: UTF8.self)
        .trimmingCharacters(in: .whitespacesAndNewlines)
}

private func bootTime() -> Date? {
    var boot = timeval()
    var size = MemoryLayout<timeval>.size
    guard sysctlbyname("kern.boottime", &boot, &size, nil, 0) == 0 else { return nil }
    return Date(timeIntervalSince1970: Double(boot.tv_sec) + Double(boot.tv_usec) / 1_000_000)
}

private func loadAverage() -> [Double] {
    var values = [Double](repeating: 0, count: 3)
    let count = values.withUnsafeMutableBufferPointer { buffer in
        getloadavg(buffer.baseAddress, 3)
    }
    return count == 3 ? values : [0, 0, 0]
}

/// macOS does not expose MemAvailable in a proc-style file. Treat free,
/// inactive, and speculative pages as reclaimable memory for the inventory.
private func memoryAvailableBytes() -> UInt64? {
    var statistics = vm_statistics64_data_t()
    var count = mach_msg_type_number_t(MemoryLayout<vm_statistics64_data_t>.size / MemoryLayout<integer_t>.size)
    let result = withUnsafeMutablePointer(to: &statistics) { pointer in
        pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { rebound in
            host_statistics64(mach_host_self(), HOST_VM_INFO64, rebound, &count)
        }
    }
    guard result == KERN_SUCCESS else { return nil }
    let pages = UInt64(statistics.free_count)
        .saturatingAdding(UInt64(statistics.inactive_count))
        .saturatingAdding(UInt64(statistics.speculative_count))
    return pages.saturatingMultiplied(by: UInt64(getpagesize()))
}

private func rootDiskBytes() -> (total: UInt64, free: UInt64) {
    var stats = statfs()
    guard statfs("/", &stats) == 0 else { return (0, 0) }
    let blockSize = UInt64(stats.f_bsize)
    return (
        UInt64(stats.f_blocks).saturatingMultiplied(by: blockSize),
        UInt64(stats.f_bavail).saturatingMultiplied(by: blockSize)
    )
}

private func rootFilesystem() -> String {
    var stats = statfs()
    guard statfs("/", &stats) == 0 else { return "" }
    return withUnsafePointer(to: &stats.f_fstypename) { pointer in
        pointer.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) }
    }
}

private func swapBytes() -> (total: UInt64, free: UInt64) {
    var usage = xsw_usage()
    var size = MemoryLayout<xsw_usage>.size
    guard sysctlbyname("vm.swapusage", &usage, &size, nil, 0) == 0 else { return (0, 0) }
    return (usage.xsu_total, usage.xsu_avail)
}

private extension UInt64 {
    func saturatingAdding(_ value: UInt64) -> UInt64 {
        addingReportingOverflow(value).overflow ? UInt64.max : self + value
    }

    func saturatingMultiplied(by value: UInt64) -> UInt64 {
        multipliedReportingOverflow(by: value).overflow ? UInt64.max : self * value
    }
}

private func interfaceKind(_ name: String) -> String {
    if name == "lo0" { return "loopback" }
    if name.hasPrefix("utun") { return "tunnel" }
    if name == "awdl0" || name == "llw0" { return "wireless" }
    if name.hasPrefix("en") { return "ethernet" }
    if name.hasPrefix("bridge") { return "bridge" }
    return "interface"
}

private func interfaceDetails() -> [DeviceNetworkInterface] {
    var pointer: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&pointer) == 0 else { return [] }
    defer { freeifaddrs(pointer) }

    var details: [String: DeviceNetworkInterface] = [:]
    var current = pointer
    while let item = current {
        if let name = item.pointee.ifa_name {
            let interfaceName = String(cString: name).prefix(128).description
            let flags = item.pointee.ifa_flags
            let state = (flags & UInt32(IFF_UP)) != 0 ? "up" : "down"
            var mtu: UInt32?
            if let data = item.pointee.ifa_data?.assumingMemoryBound(to: if_data.self) {
                let value = data.pointee.ifi_mtu
                mtu = value > 0 ? UInt32(value) : nil
            }
            let retainedMTU = mtu ?? details[interfaceName]?.mtu
            details[interfaceName] = DeviceNetworkInterface(
                name: interfaceName,
                kind: interfaceKind(interfaceName),
                state: state,
                mtu: retainedMTU
            )
        }
        current = item.pointee.ifa_next
    }
    return details.values.sorted { $0.name < $1.name }.prefix(64).map { $0 }
}

func syncHostName() -> String {
    let raw = ProcessInfo.processInfo.hostName
    let allowed = raw.unicodeScalars.filter { scalar in
        CharacterSet.alphanumerics.contains(scalar) || scalar == "." || scalar == "_" || scalar == "-"
    }
    let value = String(String.UnicodeScalarView(allowed)).prefix(128)
    return value.isEmpty ? "macos-host" : String(value)
}

func collectDeviceOSInfo() -> DeviceOSInfo {
    let version = ProcessInfo.processInfo.operatingSystemVersion
    let versionString = "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"
    let disk = rootDiskBytes()
    let uptime = bootTime().map { max(0, Date().timeIntervalSince($0)) } ?? 0
    let interfaces = interfaceDetails()
    let swap = swapBytes()
    let containerized = FileManager.default.fileExists(atPath: "/.dockerenv")
    let virtualization = (sysctlUInt64("kern.hv_vmm_present") == 1) ? "virtual_machine" : "not_detected"
    return DeviceOSInfo(
        osName: "macOS",
        osVersion: versionString,
        osPrettyName: "macOS \(versionString)",
        osID: "macos",
        osCodename: "",
        osBuild: sysctlString("kern.osversion") ?? "",
        kernel: sysctlString("kern.osrelease") ?? "",
        kernelBuild: sysctlString("kern.version") ?? "",
        architecture: sysctlString("hw.machine") ?? "",
        cpuModel: sysctlString("machdep.cpu.brand_string") ?? sysctlString("hw.model") ?? "",
        hardwareModel: sysctlString("hw.model") ?? "",
        uptimeSeconds: UInt64(uptime),
        cpuCount: UInt32(max(0, ProcessInfo.processInfo.activeProcessorCount)),
        loadAverage: loadAverage(),
        memoryTotalBytes: sysctlUInt64("hw.memsize") ?? 0,
        memoryAvailableBytes: memoryAvailableBytes(),
        swapTotalBytes: swap.total,
        swapFreeBytes: swap.free,
        diskTotalBytes: disk.total,
        diskFreeBytes: disk.free,
        rootFilesystem: rootFilesystem(),
        virtualization: virtualization,
        containerized: containerized,
        networkInterfaces: interfaces.map(\.name),
        networkInterfaceDetails: interfaces
    )
}
