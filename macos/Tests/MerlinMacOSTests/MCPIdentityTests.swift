import Foundation
import Testing
@testable import MerlinMacOS

// The same cases as merlin/src/ai_discovery/mcp_identity.rs: both collectors
// report one identity for one server definition.
@Suite("MCP server identity")
struct MCPIdentityTests {
    @Test("a known runner reports only its package spec")
    func runnerPackage() {
        let cases: [(String, [String], String)] = [
            ("npx", ["-y", "@modelcontextprotocol/server-github"], "@modelcontextprotocol/server-github"),
            ("npx", ["--yes", "@upstash/context7-mcp@1.0.14", "--api-key", "SECRET"], "@upstash/context7-mcp@1.0.14"),
            ("/opt/homebrew/bin/npx", ["-p", "mcp-remote@0.1", "mcp-remote", "https://x"], "mcp-remote@0.1"),
            ("npx -y figma-developer-mcp --figma-api-key=SECRET", [], "figma-developer-mcp"),
            ("bunx", ["chrome-devtools-mcp@latest"], "chrome-devtools-mcp@latest"),
            ("pnpm", ["dlx", "@playwright/mcp"], "@playwright/mcp"),
            ("npm", ["exec", "--", "tavily-mcp"], "tavily-mcp"),
            ("uvx", ["mcp-server-fetch"], "mcp-server-fetch"),
            ("uvx", ["--index-url", "https://user:SECRET@pypi.corp/simple", "awslabs.aws-api-mcp-server@latest"], "awslabs.aws-api-mcp-server@latest"),
            ("uvx", ["--from", "git-mcp==1.2", "git-mcp-server"], "git-mcp==1.2"),
            ("pipx", ["run", "mcp-server-time"], "mcp-server-time"),
            ("docker", ["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN=SECRET", "ghcr.io/github/github-mcp-server"], "ghcr.io/github/github-mcp-server"),
            ("docker", ["run", "--env-file", "/home/alice/.env", "--rm", "-i", "mcp/postgres:latest", "postgresql://u:SECRET@db/x"], "mcp/postgres:latest"),
            ("podman", ["run", "-i", "--env=TOKEN=SECRET", "docker.io/mcp/time"], "docker.io/mcp/time"),
        ]
        for (command, args, want) in cases {
            #expect(mcpStdioPackage(command, args) == want, "\(command) \(args)")
        }
    }

    @Test("anything else reports the program name or nothing")
    func programName() {
        let cases: [(String, [String], String)] = [
            ("node", ["/Users/alice/work/server.js", "--token", "SECRET"], "node"),
            ("/Users/alice/.local/bin/my-mcp", ["SECRET"], "my-mcp"),
            ("C:\\Users\\alice\\mcp\\server.exe", [], "server.exe"),
            ("python3", ["-m", "server", "--key=SECRET"], "python3"),
            ("npx", ["/home/alice/pkg"], "npx"),
            ("npx", ["./local-server"], "npx"),
            ("npx", ["https://user:SECRET@git.example/pkg.tgz"], "npx"),
            ("npx", ["ghp_SECRETtoken"], "npx"),
            ("docker", ["run", "--some-new-flag", "SECRETVALUE", "img"], "docker"),
            ("docker", ["compose", "up"], "docker"),
            ("pnpm", ["install"], "pnpm"),
            ("npx", ["-y"], "npx"),
            ("my server with spaces", [], ""),
        ]
        for (command, args, want) in cases {
            #expect(mcpStdioPackage(command, args) == want, "\(command) \(args)")
        }
    }

    @Test("a remote server reports only its host name")
    func remoteHost() {
        let cases: [(String, String)] = [
            ("https://api.githubcopilot.com/mcp/", "api.githubcopilot.com"),
            ("https://user:SECRET@mcp.example.com:8443/sse?token=SECRET#x", "mcp.example.com"),
            ("HTTPS://MCP.Linear.app/sse", "mcp.linear.app"),
            ("http://[::1]:3000/mcp", "[::1]"),
            ("wss://ws.example.org/socket", "ws.example.org"),
            ("file:///home/alice/server", ""),
            ("not a url", ""),
            ("https://bad host/", ""),
        ]
        for (url, want) in cases {
            #expect(mcpRemoteHost(url) == want, "\(url)")
        }
    }

    @Test("discovery reports package and host and never a planted secret")
    func discoveryCarriesIdentityWithoutSecrets() throws {
        let home = NSTemporaryDirectory() + "merlin-mcp-identity-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: home) }
        try FileManager.default.createDirectory(atPath: home + "/.cursor", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: home + "/.codex", withIntermediateDirectories: true)
        try #"{"mcpServers":{"github":{"command":"docker","args":["run","-i","--rm","-e","GITHUB_TOKEN=private-secret","ghcr.io/github/github-mcp-server"],"env":{"GITHUB_TOKEN":"private-secret"}},"linear":{"url":"https://user:private-secret@mcp.linear.app/sse?token=private-secret","headers":{"Authorization":"Bearer private-secret"}},"local":{"command":"/Users/alice/private-secret/bin/run-mcp","args":["--key","private-secret"]}}}"#.write(toFile: home + "/.cursor/mcp.json", atomically: true, encoding: .utf8)
        try "[mcp_servers.fetch]\ncommand = \"uvx\"\nargs = [\"--index-url\", \"https://u:private-secret@pypi.corp/simple\", \"mcp-server-fetch\"]\nenv = { KEY = \"private-secret\" }\n[mcp_servers.docs]\nurl = \"https://docs.example.com/mcp?key=private-secret\"\n".write(toFile: home + "/.codex/config.toml", atomically: true, encoding: .utf8)
        let servers = collectMacAgentDiscovery(homes: [home], systemBins: []).servers
        func server(_ name: String) -> DeviceMCPServer? { servers.first { $0.name == name } }
        #expect(server("github")?.package == "ghcr.io/github/github-mcp-server")
        #expect(server("linear")?.host == "mcp.linear.app")
        #expect(server("linear")?.package == "")
        #expect(server("local")?.package == "run-mcp")
        #expect(server("fetch")?.package == "mcp-server-fetch")
        #expect(server("docs")?.host == "docs.example.com")
        let payload = String(decoding: try JSONEncoder().encode(servers), as: UTF8.self)
        #expect(!payload.contains("private-secret"))
        #expect(!payload.contains("/Users/alice"))
        // Empty identities are left out of the JSON, as on Linux.
        let bare = String(decoding: try JSONEncoder().encode(DeviceMCPServer(client: "c", name: "n", source: "s", transport: "unknown")), as: UTF8.self)
        #expect(!bare.contains("package") && !bare.contains("host"))
    }
}
