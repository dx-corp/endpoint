import Foundation

// What an MCP server definition runs, reduced to an identity that is safe to
// send, with the rules of the Linux and Windows collectors
// (merlin/src/ai_discovery/mcp_identity.rs): for a local (stdio) server, the
// package or image a known runner starts (npx, bunx, pnpm dlx, yarn dlx,
// npm exec, uvx, pipx run, docker run, podman run) or else the program file
// name; for a remote server, the URL host name.
//
// Nothing after the package spec is read into the result, and values of
// flags such as --env, --index-url or --env-file are skipped, so arguments,
// environment, headers, paths, query strings and tokens never reach it. A
// spec that looks like a path, a URL or an assignment is refused and the
// runner name is reported instead.

/// One MCP server a config declares: its name, transport and identity.
struct MCPEntry: Sendable {
    let name: String
    let transport: String
    let package: String
    let host: String

    init(name: String, command: String?, args: [String], url: String?) {
        let transport = url != nil && command == nil ? "remote" : (command != nil && url == nil ? "stdio" : "unknown")
        self.name = name
        self.transport = transport
        self.package = transport == "stdio" ? mcpStdioPackage(command ?? "", Array(args.prefix(mcpMaxArgs))) : ""
        self.host = transport == "remote" ? mcpRemoteHost(url ?? "") : ""
    }
}

/// At most this many arguments are looked at for a package spec.
let mcpMaxArgs = 64

private struct MCPRunner {
    let names: [String]
    /// A leading subcommand the runner needs (pnpm dlx, docker run).
    let subcommand: String?
    let valueFlags: Set<String>
    let packageFlags: Set<String>
    /// Package names on this registry are lowercase (npm, OCI repositories).
    let lowercaseName: Bool
}

private let mcpRunners: [MCPRunner] = [
    MCPRunner(names: ["npx", "bunx"], subcommand: nil,
              valueFlags: ["-c", "--call", "--node-options", "--registry", "--cache", "--userconfig"],
              packageFlags: ["-p", "--package"], lowercaseName: true),
    MCPRunner(names: ["pnpm", "yarn"], subcommand: "dlx",
              valueFlags: ["-c", "--registry", "--cache-dir"],
              packageFlags: ["-p", "--package"], lowercaseName: true),
    MCPRunner(names: ["npm"], subcommand: "exec",
              valueFlags: ["-c", "--call", "--registry", "--cache", "--userconfig", "-w", "--workspace"],
              packageFlags: ["-p", "--package"], lowercaseName: true),
    MCPRunner(names: ["uvx"], subcommand: nil,
              valueFlags: ["--with", "--with-requirements", "--python", "-p", "--index", "--index-url",
                           "--extra-index-url", "--default-index", "--find-links", "-f", "--constraint", "-c",
                           "--override", "--build-constraint", "--refresh-package", "--reinstall-package",
                           "--upgrade-package", "--exclude-newer", "--cache-dir", "--config-file", "--directory",
                           "--project", "--env-file", "--keyring-provider", "--resolution", "--prerelease",
                           "--allow-insecure-host", "--index-strategy", "--link-mode", "--color"],
              packageFlags: ["--from"], lowercaseName: false),
    MCPRunner(names: ["pipx"], subcommand: "run",
              valueFlags: ["--python", "--pip-args", "--index-url", "-i"],
              packageFlags: ["--spec"], lowercaseName: false),
    MCPRunner(names: ["docker", "podman"], subcommand: "run",
              valueFlags: ["-e", "--env", "--env-file", "-v", "--volume", "--mount", "--name", "-p", "--publish",
                           "--network", "--net", "-w", "--workdir", "-u", "--user", "--entrypoint", "-l", "--label",
                           "--label-file", "--add-host", "--cpus", "-m", "--memory", "--platform", "--pull",
                           "--restart", "--device", "--cap-add", "--cap-drop", "--security-opt", "--tmpfs",
                           "--ulimit", "-h", "--hostname", "--dns", "--log-driver", "--log-opt", "--runtime",
                           "--gpus", "--ipc", "--pid", "--cidfile", "--group-add", "--secret"],
              packageFlags: [], lowercaseName: true),
]

/// The file name of a program path, Unix or Windows style.
private func mcpBaseName(_ command: String) -> String {
    String(command.split(whereSeparator: { $0 == "/" || $0 == "\\" }).last ?? Substring(command))
}

private func isASCIIAlphanumeric(_ byte: UInt8) -> Bool {
    (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A)
}

/// A package spec or image reference worth reporting: bounded, from the
/// characters registries use, and not a path, URL or flag. npm and OCI names
/// are lowercase and have no `_` or `=`, which also keeps tokens such as
/// `ghp_...` from passing for one.
private func mcpSafeSpec(_ spec: String, lowercaseName: Bool) -> Bool {
    var name = Substring(spec)
    if let at = spec.lastIndex(of: "@"), at != spec.startIndex { name = spec[..<at] }
    name = name.split(separator: ":", omittingEmptySubsequences: false).first ?? name
    let allowed = Array("@/._:+~-".utf8)
    let python = Array("=<>!,_".utf8)
    return !spec.isEmpty && spec.utf8.count <= 214 && !spec.contains("://") && !spec.contains("..")
        && !["-", ".", "/", "~"].contains(where: { spec.hasPrefix($0) })
        && spec.utf8.allSatisfy { isASCIIAlphanumeric($0) || allowed.contains($0) || (!lowercaseName && python.contains($0)) }
        && (!lowercaseName || !name.utf8.contains { $0 >= 0x41 && $0 <= 0x5A })
}

/// A program file name, when it is one: bounded and without spaces or
/// unusual characters (which would suggest a path fragment or a value).
private func mcpSafeProgram(_ program: String) -> String {
    let allowed = Array("._+-".utf8)
    let ok = !program.isEmpty && program.utf8.count <= 128 && !program.hasPrefix(".") && !program.hasPrefix("-")
        && program.utf8.allSatisfy { isASCIIAlphanumeric($0) || allowed.contains($0) }
    return ok ? program : ""
}

/// The identity of a stdio server: its package or image for a known runner,
/// else its program's file name.
func mcpStdioPackage(_ command: String, _ args: [String]) -> String {
    // Some configs put the whole command line in `command`.
    var words = command.split(whereSeparator: { $0.isWhitespace }).map(String.init)
    let program: String
    if let first = words.first, mcpRunners.contains(where: { $0.names.contains(mcpBaseName(first)) }) {
        program = mcpBaseName(words.removeFirst())
    } else {
        words = []
        program = mcpBaseName(command.trimmingCharacters(in: .whitespacesAndNewlines))
    }
    guard let runner = mcpRunners.first(where: { $0.names.contains(program) }) else {
        return mcpSafeProgram(program)
    }
    words += args
    var rest = words.makeIterator()
    if let subcommand = runner.subcommand, rest.next() != subcommand {
        return mcpSafeProgram(program)
    }
    var fromFlag: String?
    while let word = rest.next() {
        if word == "--" { continue }
        if word.hasPrefix("-"), let equals = word.firstIndex(of: "=") {
            if runner.packageFlags.contains(String(word[..<equals])) && fromFlag == nil {
                fromFlag = String(word[word.index(after: equals)...])
            }
            continue
        }
        if runner.packageFlags.contains(word) {
            if let value = rest.next(), fromFlag == nil { fromFlag = value }
            continue
        }
        if runner.valueFlags.contains(word) {
            _ = rest.next()
            continue
        }
        if word.hasPrefix("-") { continue }
        let spec = fromFlag ?? word
        return mcpSafeSpec(spec, lowercaseName: runner.lowercaseName) ? spec : program
    }
    if let spec = fromFlag, mcpSafeSpec(spec, lowercaseName: runner.lowercaseName) { return spec }
    return program
}

/// The host name of a remote server's URL: no scheme, user, password, port,
/// path, query or fragment. Empty when the URL is not http(s) or ws(s).
func mcpRemoteHost(_ url: String) -> String {
    let url = url.trimmingCharacters(in: .whitespacesAndNewlines)
    guard let separator = url.range(of: "://") else { return "" }
    let scheme = url[..<separator.lowerBound].lowercased()
    guard ["http", "https", "ws", "wss"].contains(scheme) else { return "" }
    let rest = url[separator.upperBound...]
    let authority = rest.split(omittingEmptySubsequences: false, whereSeparator: { "/?#".contains($0) }).first ?? ""
    let hostPort = authority.split(separator: "@", omittingEmptySubsequences: false).last ?? ""
    var host: String
    if hostPort.hasPrefix("[") {
        guard let close = hostPort.firstIndex(of: "]") else { return "" }
        host = String(hostPort[...close])
    } else {
        host = String(hostPort.split(separator: ":", omittingEmptySubsequences: false).first ?? "")
    }
    // ASCII only, as on Linux: a non-ASCII letter stays and is refused below.
    host = String(decoding: host.utf8.map { $0 >= 0x41 && $0 <= 0x5A ? $0 + 0x20 : $0 }, as: UTF8.self)
    let allowed = Array(".-:[]".utf8)
    let ok = !host.isEmpty && host.utf8.count <= 253 && host.utf8.allSatisfy { isASCIIAlphanumeric($0) || allowed.contains($0) }
    return ok ? host : ""
}
