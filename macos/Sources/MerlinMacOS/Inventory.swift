import CryptoKit
import Foundation
import Darwin

/// Bounded endpoint hygiene inventory for managed macOS devices. Collection is
/// read-only and intentionally avoids file contents, usernames, addresses, or
/// process arguments.
struct DeviceInventory: Encodable, Sendable {
    let collectedAt: String
    let packageManager: String
    let packages: [DevicePackage]
    let services: [DeviceService]
    let users: [DeviceUser]
    let groups: [String]
    let listeningPorts: [DeviceListeningPort]
    let containers: [DeviceContainer]
    let processes: [DeviceProcess]
    let fim: [DeviceFIMEntry]
    let sca: [DeviceSCAResult]
    let vulnerabilities: [DeviceVulnerability]
    let agentCLIs: [DeviceAgentCLI]
    let agentApps: [DeviceAgentApp]
    let mcpServers: [DeviceMCPServer]
    let agentAssets: [DeviceAgentAsset]
    let cloudProvider: String
    let cloudInstanceID: String
    let cloudRegion: String
    let collectionSource: String

    enum CodingKeys: String, CodingKey {
        case collectedAt = "collected_at"
        case packageManager = "package_manager"
        case packages, services, users, groups
        case listeningPorts = "listening_ports"
        case containers, processes, fim, sca, vulnerabilities
        case agentCLIs = "agent_clis"
        case agentApps = "agent_apps"
        case mcpServers = "mcp_servers"
        case agentAssets = "agent_assets"
        case cloudProvider = "cloud_provider"
        case cloudInstanceID = "cloud_instance_id"
        case cloudRegion = "cloud_region"
        case collectionSource = "collection_source"
    }
}

struct DeviceAgentCLI: Encodable, Sendable { let name: String }
struct DeviceAgentApp: Encodable, Sendable { let name: String }
struct DeviceMCPServer: Encodable, Sendable { let client: String; let name: String }
struct DeviceAgentAsset: Encodable, Sendable { let client: String; let kind: String; let name: String }

struct DevicePackage: Encodable, Sendable {
    let name: String
    let version: String
    let architecture: String
    let manager: String
}

struct DeviceService: Encodable, Sendable {
    let name: String
    let state: String
    let source: String
}

struct DeviceUser: Encodable, Sendable {
    let name: String
    let uid: UInt64
    let admin: Bool
    let shell: String
    let source: String
}

struct DeviceListeningPort: Encodable, Sendable {
    let protocolName: String
    let port: UInt16
    let state: String
    let source: String

    enum CodingKeys: String, CodingKey {
        case protocolName = "protocol"
        case port, state, source
    }
}

struct DeviceContainer: Encodable, Sendable {
    let id: String
    let name: String
    let image: String
    let state: String
    let runtime: String
}

struct DeviceProcess: Encodable, Sendable {
    let pid: UInt32
    let name: String
    let executable: String
    let user: String
    let state: String
}

struct DeviceFIMEntry: Encodable, Sendable {
    let path: String
    let sha256: String
    let sizeBytes: UInt64
    let mode: String
    let modifiedUnix: Int64
    let status: String

    enum CodingKeys: String, CodingKey {
        case path, sha256
        case sizeBytes = "size_bytes"
        case mode
        case modifiedUnix = "modified_unix"
        case status
    }
}

struct DeviceSCAResult: Encodable, Sendable {
    let id: String
    let title: String
    let status: String
    let severity: String
    let detail: String
    let frameworks: [String]
}

struct DeviceVulnerability: Encodable, Sendable {
    let id: String
    let package: String
    let installed: String
    let severity: String
    let fixedVersion: String
    let summary: String
    let source: String

    enum CodingKeys: String, CodingKey {
        case id, package, installed, severity
        case fixedVersion = "fixed_version"
        case summary, source
    }
}

private let inventoryLimit = 256
private let inventoryReadLimit = 2 << 20

func collectDeviceInventory() -> DeviceInventory {
    let packages = collectMacPackages()
    let discovery = collectMacAgentDiscovery()
    return DeviceInventory(
        collectedAt: String(format: "%.3f", Date().timeIntervalSince1970),
        packageManager: packages.manager,
        packages: packages.items,
        services: collectMacServices(),
        users: collectMacUsers(),
        groups: collectMacGroups(),
        listeningPorts: collectMacListeningPorts(),
        containers: collectMacContainers(),
        processes: collectMacProcesses(),
        fim: collectMacFIM(),
        sca: collectMacSCA(),
        vulnerabilities: [],
        agentCLIs: discovery.clis,
        agentApps: discovery.apps,
        mcpServers: discovery.servers,
        agentAssets: discovery.assets,
        cloudProvider: inventoryText(ProcessInfo.processInfo.environment["MERLIN_CLOUD_PROVIDER"], 128),
        cloudInstanceID: inventoryText(ProcessInfo.processInfo.environment["MERLIN_CLOUD_INSTANCE_ID"], 128),
        cloudRegion: inventoryText(ProcessInfo.processInfo.environment["MERLIN_CLOUD_REGION"], 128),
        collectionSource: "macos-agent"
    )
}

private func collectMacAgentDiscovery() -> (clis: [DeviceAgentCLI], apps: [DeviceAgentApp], servers: [DeviceMCPServer], assets: [DeviceAgentAsset]) {
    let root = "/Users"
    let users = ((try? FileManager.default.contentsOfDirectory(atPath: root)) ?? []).sorted().prefix(64)
    let homes = ["/var/root"] + users.map { "\(root)/\($0)" }.filter { path in
        var isDirectory: ObjCBool = false
        return FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory) && isDirectory.boolValue
    }
    return collectMacAgentDiscovery(homes: homes, systemBins: ["/usr/local/bin", "/opt/homebrew/bin", "/usr/bin"])
}

// Fixed probes only: no CLI execution and no configuration values are emitted.
func collectMacAgentDiscovery(homes: [String], systemBins: [String], appRoots: [String]? = nil) -> (clis: [DeviceAgentCLI], apps: [DeviceAgentApp], servers: [DeviceMCPServer], assets: [DeviceAgentAsset]) {
    let names = ["cursor", "codex", "claude", "gemini", "opencode", "aider", "maestro", "amp", "goose", "qwen", "pi"]
    let bins = systemBins + homes.flatMap { ["\($0)/.local/bin", "\($0)/.npm-global/bin", "\($0)/.bun/bin", "\($0)/.cargo/bin", "\($0)/.codex/bin"] }
    let clis = names.filter { name in
        bins.contains { bin in
            let path = "\(bin)/\(name)"
            let attributes = try? FileManager.default.attributesOfItem(atPath: path)
            return FileManager.default.isExecutableFile(atPath: path) && attributes?[.type] as? FileAttributeType == .typeRegular
        }
    }.map { DeviceAgentCLI(name: $0) }
    let appRoots = appRoots ?? (["/Applications", "/System/Applications"] + homes.prefix(65).map { "\($0)/Applications" })
    let apps = [("cursor", "Cursor.app"), ("codex", "Codex.app")].compactMap { name, bundle -> DeviceAgentApp? in
        for root in appRoots {
            var info = stat()
            if lstat("\(root)/\(bundle)", &info) == 0 && (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR) {
                return DeviceAgentApp(name: name)
            }
        }
        return nil
    }

    let configs: [(String, String, Bool)] = [
        ("claude", "Library/Application Support/Claude/claude_desktop_config.json", false),
        ("claude", ".claude.json", false),
        ("cursor", ".cursor/mcp.json", false),
        ("gemini", ".gemini/settings.json", false),
        ("vscode", "Library/Application Support/Code/User/mcp.json", false),
        ("codex", ".codex/config.toml", true),
        ("opencode", ".config/opencode/opencode.json", false),
        ("claude", ".claude/settings.json", false),
        ("amp", ".config/amp/settings.json", false),
        ("qwen", ".qwen/settings.json", false),
        ("pi", ".pi/agent/settings.json", false),
    ]
    var found = Set<String>()
    var assetNames = Set<String>()
    for home in homes.prefix(65) {
        let assetDirs: [(String, String, String, String)] = [
            ("agents", "skill", ".agents/skills", "skill"),
            ("codex", "skill", ".codex/skills", "skill"),
            ("claude", "skill", ".claude/skills", "skill"),
            ("claude", "agent", ".claude/agents", "md"),
            ("gemini", "skill", ".gemini/skills", "skill"),
            ("gemini", "extension", ".gemini/extensions", "directory"),
            ("opencode", "skill", ".config/opencode/skills", "skill"),
            ("opencode", "plugin", ".config/opencode/plugins", "js-ts"),
            ("opencode", "agent", ".config/opencode/agents", "md"),
            ("amp", "skill", ".config/amp/skills", "skill"),
            ("qwen", "skill", ".qwen/skills", "skill"),
            ("pi", "skill", ".pi/agent/skills", "skill"),
            ("pi", "extension", ".pi/agent/extensions", "js-ts"),
        ]
        for (client, kind, relative, format) in assetDirs {
            let directory = "\(home)/\(relative)"
            for entry in boundedAgentDirectoryEntries(directory) {
                let path = "\(directory)/\(entry)"
                var info = stat()
                guard lstat(path, &info) == 0 else { continue }
                let type = info.st_mode & mode_t(S_IFMT)
                let name: String?
                if format == "skill" && type == mode_t(S_IFDIR) {
                    var manifest = stat()
                    let manifestPath = "\(path)/SKILL.md"
                    name = lstat(manifestPath, &manifest) == 0 && (manifest.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG) ? entry : nil
                } else if format == "directory" && type == mode_t(S_IFDIR) {
                    var manifest = stat()
                    name = lstat("\(path)/gemini-extension.json", &manifest) == 0 && (manifest.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG) ? entry : nil
                } else if type == mode_t(S_IFREG) && format == "md" && entry.hasSuffix(".md") {
                    name = String(entry.dropLast(3))
                } else if type == mode_t(S_IFREG) && format == "js-ts" && (entry.hasSuffix(".js") || entry.hasSuffix(".ts")) {
                    name = String(entry.dropLast(3))
                } else { name = nil }
                if let name, safeAgentAssetName(name) {
                    assetNames.insert("\(client)\u{0}\(kind)\u{0}\(name)")
                    if client == "gemini" && kind == "extension", let data = readAgentConfigNoFollow("\(path)/gemini-extension.json") {
                        let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
                        for server in ((object?["mcpServers"] as? [String: Any]).map { Array($0.keys) } ?? []) where safeAgentAssetName(server) {
                            found.insert("gemini\u{0}\(server)")
                        }
                    }
                    if assetNames.count >= 128 { break }
                }
            }
            if assetNames.count >= 128 { break }
        }
        for (client, relative, isTOML) in configs {
            guard let data = readAgentConfigNoFollow("\(home)/\(relative)") else { continue }
            assetNames.insert("\(client)\u{0}config\u{0}user")
            if client == "claude" && relative == ".claude/settings.json" {
                let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
                let plugins = object?["enabledPlugins"] as? [String: Bool] ?? [:]
                for (name, enabled) in plugins where enabled && safeAgentAssetName(name) {
                    assetNames.insert("claude\u{0}plugin\u{0}\(name)")
                }
                continue
            }
            let names: [String]
            if client == "amp" {
                let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
                names = (object?["amp.mcpServers"] as? [String: Any]).map { Array($0.keys) } ?? []
            } else if client == "opencode" {
                let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
                names = (object?["mcp"] as? [String: Any]).map { Array($0.keys) } ?? []
            } else if isTOML {
                let body = String(data: data, encoding: .utf8) ?? ""
                names = body.split(separator: "\n").compactMap { line in
                    let section = line.trimmingCharacters(in: .whitespaces)
                    guard section.hasPrefix("[mcp_servers."), section.hasSuffix("]") else { return nil }
                    let raw = String(section.dropFirst("[mcp_servers.".count).dropLast())
                    let quoted = raw.hasPrefix("\"") && raw.hasSuffix("\"") && raw.count >= 2
                    let name = quoted ? String(raw.dropFirst().dropLast()) : raw
                    return name.isEmpty || name.contains(where: { "[]".contains($0) }) || (!quoted && name.contains(".")) ? nil : name
                }
            } else {
                let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
                let entries = (object?["mcpServers"] ?? object?["servers"]) as? [String: Any]
                names = entries.map { Array($0.keys) } ?? []
            }
            for name in names where name.utf8.count <= 128 && !name.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) {
                found.insert("\(client)\u{0}\(name)")
                if found.count >= 128 { break }
            }
            if found.count >= 128 { break }
        }
        if found.count >= 128 { break }
    }
    let servers = found.sorted().prefix(128).compactMap { entry -> DeviceMCPServer? in
        let parts = entry.split(separator: "\u{0}", maxSplits: 1)
        guard parts.count == 2 else { return nil }
        return DeviceMCPServer(client: String(parts[0]), name: String(parts[1]))
    }
    let assets = assetNames.sorted().prefix(128).compactMap { entry -> DeviceAgentAsset? in
        let parts = entry.split(separator: "\u{0}")
        guard parts.count == 3 else { return nil }
        return DeviceAgentAsset(client: String(parts[0]), kind: String(parts[1]), name: String(parts[2]))
    }
    return (clis, apps, servers, assets)
}

private func boundedAgentDirectoryEntries(_ path: String) -> [String] {
    let fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
    guard fd >= 0 else { return [] }
    guard let directory = fdopendir(fd) else { close(fd); return [] }
    defer { closedir(directory) }
    var names = [String]()
    while names.count < 256, let entry = readdir(directory) {
        let name = withUnsafePointer(to: &entry.pointee.d_name) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: 1) { String(cString: $0) }
        }
        if name != "." && name != ".." { names.append(name) }
    }
    return names.sorted()
}

private func safeAgentAssetName(_ name: String) -> Bool {
    !name.isEmpty && name.utf8.count <= 128 && !name.hasPrefix(".") &&
        !name.contains("/") && !name.contains("\\") &&
        !name.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
}

private func readAgentConfigNoFollow(_ path: String) -> Data? {
    let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
    guard fd >= 0 else { return nil }
    defer { close(fd) }
    var info = stat()
    guard fstat(fd, &info) == 0, (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG), info.st_size >= 0, info.st_size <= 64 << 10 else { return nil }
    var bytes = [UInt8](repeating: 0, count: Int(info.st_size) + 1)
    let capacity = bytes.count
    let count = read(fd, &bytes, capacity)
    guard count >= 0, count <= 64 << 10 else { return nil }
    return Data(bytes.prefix(count))
}

private func inventoryText(_ value: String?, _ limit: Int) -> String {
    guard let value else { return "" }
    return String(value.trimmingCharacters(in: .whitespacesAndNewlines).prefix(limit))
}

private func boundedText(_ value: String, _ limit: Int) -> String {
    String(value.trimmingCharacters(in: .whitespacesAndNewlines).prefix(limit))
}

private func readBoundedText(_ path: String, limit: Int = inventoryReadLimit) -> String? {
    guard let data = FileManager.default.contents(atPath: path), data.count <= limit else { return nil }
    return String(data: data, encoding: .utf8)
}

private func collectMacPackages() -> (manager: String, items: [DevicePackage]) {
    var packages: [DevicePackage] = []
    let applicationRoots = [
        "/Applications",
        "/System/Applications",
        (NSHomeDirectory() as NSString).appendingPathComponent("Applications")
    ]
    var seen = Set<String>()
    for root in applicationRoots {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: root) else { continue }
        for name in names.sorted() where name.hasSuffix(".app") {
            guard packages.count < inventoryLimit else { break }
            let path = (root as NSString).appendingPathComponent(name)
            guard let bundle = Bundle(path: path) else { continue }
            let identifier = boundedText(bundle.bundleIdentifier ?? name, 160)
            guard seen.insert(identifier).inserted else { continue }
            packages.append(DevicePackage(
                name: identifier,
                version: boundedText(bundle.infoDictionary?["CFBundleShortVersionString"] as? String ?? bundle.infoDictionary?["CFBundleVersion"] as? String ?? "", 160),
                architecture: "",
                manager: "app-bundle"
            ))
        }
    }
    for root in ["/opt/homebrew/Cellar", "/usr/local/Cellar"] {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: root) else { continue }
        for name in names.sorted() where packages.count < inventoryLimit {
            let packagePath = (root as NSString).appendingPathComponent(name)
            guard let versions = try? FileManager.default.contentsOfDirectory(atPath: packagePath),
                  let version = versions.sorted().last else { continue }
            packages.append(DevicePackage(name: boundedText(name, 160), version: boundedText(version, 160), architecture: "", manager: "homebrew"))
        }
    }
    packages.sort { $0.name == $1.name ? $0.version < $1.version : $0.name < $1.name }
    return (packages.contains(where: { $0.manager == "homebrew" }) ? "homebrew" : "app-bundle", Array(packages.prefix(inventoryLimit)))
}

private func collectMacServices() -> [DeviceService] {
    let roots = [
        "/Library/LaunchDaemons",
        "/System/Library/LaunchDaemons",
        "/Library/LaunchAgents",
        (NSHomeDirectory() as NSString).appendingPathComponent("Library/LaunchAgents")
    ]
    var seen = Set<String>()
    var result: [DeviceService] = []
    for root in roots {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: root) else { continue }
        for name in names.sorted() where name.hasSuffix(".plist") && result.count < inventoryLimit {
            let service = boundedText((name as NSString).deletingPathExtension, 160)
            guard seen.insert(service).inserted else { continue }
            result.append(DeviceService(name: service, state: "installed", source: root))
        }
    }
    return result
}

private func collectMacUsers() -> [DeviceUser] {
    guard let body = readBoundedText("/etc/passwd", limit: 256 << 10) else { return [] }
    return body.split(separator: "\n").prefix(inventoryLimit).compactMap { line in
        let fields = line.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        guard fields.count >= 7, let uid = UInt64(fields[2]), !fields[0].isEmpty else { return nil }
        return DeviceUser(name: boundedText(fields[0], 128), uid: uid, admin: uid == 0, shell: boundedText(fields[6], 256), source: "passwd")
    }
}

private func collectMacGroups() -> [String] {
    guard let body = readBoundedText("/etc/group", limit: 256 << 10) else { return [] }
    return Array(Set(body.split(separator: "\n").prefix(inventoryLimit).compactMap { line in
        let name = String(line.split(separator: ":", omittingEmptySubsequences: false).first ?? "")
        return name.isEmpty ? nil : boundedText(name, 128)
    })).sorted().prefix(inventoryLimit).map { $0 }
}

private func collectMacListeningPorts() -> [DeviceListeningPort] {
    guard let output = runInventoryCommand("/usr/sbin/netstat", arguments: ["-an", "-p", "tcp"], limit: 512 << 10) else { return [] }
    var seen = Set<String>()
    var result: [DeviceListeningPort] = []
    for line in output.split(separator: "\n") where result.count < inventoryLimit {
        let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
        guard fields.count >= 6, fields[0].hasPrefix("tcp"), fields.contains(where: { $0.uppercased() == "LISTEN" }) else { continue }
        guard let portText = fields.first(where: { $0.contains(".") })?.split(separator: ".").last, let port = UInt16(portText) else { continue }
        let key = "tcp:\(port)"
        guard seen.insert(key).inserted else { continue }
        result.append(DeviceListeningPort(protocolName: "tcp", port: port, state: "listening", source: "netstat"))
    }
    return result.sorted { $0.port < $1.port }
}

private func collectMacContainers() -> [DeviceContainer] {
    let roots = ["/var/lib/docker/containers", (NSHomeDirectory() as NSString).appendingPathComponent(".docker/containers")]
    var result: [DeviceContainer] = []
    for root in roots {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: root) else { continue }
        for name in names.sorted() where result.count < inventoryLimit {
            result.append(DeviceContainer(id: boundedText(name, 128), name: "", image: "", state: "unknown", runtime: "docker"))
        }
    }
    return result
}

private func collectMacProcesses() -> [DeviceProcess] {
    guard let output = runInventoryCommand("/bin/ps", arguments: ["-axo", "pid=,user=,state=,comm="], limit: 512 << 10) else { return [] }
    return output.split(separator: "\n").prefix(inventoryLimit).compactMap { line in
        let fields = line.split(maxSplits: 3, whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
        guard fields.count >= 4, let pid = UInt32(fields[0]), pid > 0 else { return nil }
        return DeviceProcess(
            pid: pid,
            name: boundedText((fields[3] as NSString).lastPathComponent, 256),
            executable: boundedText(fields[3], 512),
            user: boundedText(fields[1], 128),
            state: boundedText(fields[2], 32)
        )
    }.sorted { $0.pid < $1.pid }
}

private func collectMacFIM() -> [DeviceFIMEntry] {
    let paths = ["/etc/passwd", "/etc/group", "/etc/ssh/sshd_config", "/etc/sudoers"]
    return paths.map { path in
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: path),
              let data = FileManager.default.contents(atPath: path), data.count <= inventoryReadLimit else {
            return DeviceFIMEntry(path: path, sha256: "", sizeBytes: 0, mode: "", modifiedUnix: 0, status: "missing")
        }
        let modified = (attributes[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0
        let permissions = (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
        return DeviceFIMEntry(
            path: path,
            sha256: SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined(),
            sizeBytes: UInt64((attributes[.size] as? NSNumber)?.int64Value ?? 0),
            mode: String(format: "%o", permissions),
            modifiedUnix: Int64(modified),
            status: "present"
        )
    }
}

private func collectMacSCA() -> [DeviceSCAResult] {
    let frameworks = ["CIS", "NIST 800-53"]
    let ssh = readBoundedText("/etc/ssh/sshd_config", limit: 256 << 10) ?? ""
    let rootLogin = sshSetting(ssh, key: "PermitRootLogin")
    let passwordAuth = sshSetting(ssh, key: "PasswordAuthentication")
    var result = [DeviceSCAResult]()
    result.append(DeviceSCAResult(
        id: "macos.ssh.root_login",
        title: "Root SSH login is restricted",
        status: rootLogin == "no" || rootLogin == "prohibit-password" ? "pass" : (rootLogin == nil ? "unknown" : "fail"),
        severity: "high",
        detail: rootLogin.map { "PermitRootLogin is configured as \($0)." } ?? "sshd_config was not readable or did not specify the setting.",
        frameworks: frameworks
    ))
    result.append(DeviceSCAResult(
        id: "macos.ssh.password_auth",
        title: "SSH password authentication is disabled",
        status: passwordAuth == "no" ? "pass" : (passwordAuth == nil ? "unknown" : "fail"),
        severity: "medium",
        detail: passwordAuth.map { "PasswordAuthentication is configured as \($0)." } ?? "sshd_config was not readable or did not specify the setting.",
        frameworks: frameworks
    ))
    let firewall = runInventoryCommand("/usr/libexec/ApplicationFirewall/socketfilterfw", arguments: ["--getglobalstate"], limit: 4096) ?? ""
    let firewallEnabled = firewall.localizedCaseInsensitiveContains("enabled")
    result.append(DeviceSCAResult(
        id: "macos.firewall.present",
        title: "The application firewall is active",
        status: firewall.isEmpty ? "unknown" : (firewallEnabled ? "pass" : "fail"),
        severity: "high",
        detail: firewall.isEmpty ? "Firewall state could not be read by the bounded collector." : firewall.trimmingCharacters(in: .whitespacesAndNewlines),
        frameworks: frameworks
    ))
    let sensitivePaths = ["/etc/passwd", "/etc/group", "/etc/sudoers", "/etc/ssh/sshd_config"]
    var checkedSensitive = 0
    var writableSensitive = 0
    for path in sensitivePaths {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: path),
              let permissions = (attributes[.posixPermissions] as? NSNumber)?.uint16Value else { continue }
        checkedSensitive += 1
        if permissions & 0o022 != 0 { writableSensitive += 1 }
    }
    result.append(DeviceSCAResult(
        id: "macos.rootcheck.sensitive_permissions",
        title: "Sensitive system files have safe permissions",
        status: checkedSensitive == 0 ? "unknown" : (writableSensitive == 0 ? "pass" : "fail"),
        severity: "high",
        detail: checkedSensitive == 0 ? "No sensitive system files were readable by the bounded collector." : (writableSensitive == 0 ? "Sensitive system files are not group/world-writable." : "One or more sensitive system files are writable by a group or user."),
        frameworks: frameworks
    ))
    return result
}

private func sshSetting(_ body: String, key: String) -> String? {
    for line in body.split(separator: "\n") {
        let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
        if fields.count >= 2, fields[0] == key, !fields[1].hasPrefix("#") { return boundedText(fields[1].lowercased(), 64) }
    }
    return nil
}

private func runInventoryCommand(_ path: String, arguments: [String], limit: Int) -> String? {
    let process = Process()
    let pipe = Pipe()
    process.executableURL = URL(fileURLWithPath: path)
    process.arguments = arguments
    process.standardOutput = pipe
    process.standardError = FileHandle.nullDevice
    do {
        try process.run()
        // Drain while the child is running. Waiting first can deadlock when a
        // busy host's process or socket listing fills the pipe buffer.
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(data: data.prefix(limit), encoding: .utf8)
    } catch {
        return nil
    }
}
