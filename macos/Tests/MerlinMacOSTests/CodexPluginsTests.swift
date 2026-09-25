import Foundation
import Testing
@testable import MerlinMacOS

@Suite("codex enabled plugins")
struct CodexPluginsTests {
    private func names(_ body: String) -> [String] {
        codexEnabledPluginNames(Data(body.utf8))
    }

    @Test("table headers report only explicit boolean true and safe names")
    func tableHeaders() {
        let body = "[plugins.\"audit@marketplace\"]\nenabled = true\nsecret = 'private'\n[plugins.\"off@marketplace\"]\nenabled = false\n[plugins.\"unset@marketplace\"]\nfoo = true\n[plugins.\"text@marketplace\"]\nenabled = \"true\"\n[plugins.\"https://private.example/path\"]\nenabled = true\n"
        #expect(names(body) == ["audit@marketplace"])
    }

    @Test("inline tables, dotted keys, literal keys, escapes, and CRLF")
    func keyForms() {
        let body = "model = \"gpt\"\r\n[plugins]\r\ninline = { enabled = true, token = \"secret\" }\r\n'literal@m'.enabled = true # comment\r\n\"esc\\u0041pe\" . enabled = true\r\n"
        #expect(names(body) == ["escApe", "inline", "literal@m"])
        #expect(names("plugins.dotted.enabled = true\n") == ["dotted"])
        #expect(names("plugins = { a = { enabled = true }, b = { enabled = false } }\n") == ["a"])
    }

    @Test("nested tables, arrays of tables, and multi-line values are not plugin entries")
    func structure() {
        #expect(names("[plugins.outer.inner]\nenabled = true\n[[plugins_list]]\nenabled = true\n[mcp_servers.plugins]\nenabled = true\n").isEmpty)
        let body = "[mcp_servers.x]\nargs = [\n  \"a\", # note\n  \"[plugins.fake]\",\n]\nnote = \"\"\"\n[plugins.fake2]\nenabled = true\n\"\"\"\nraw = '''\n[plugins.fake3]\n'''\nwhen = 1979-05-27 07:32:00Z\n[plugins.real]\nenabled = true\n"
        #expect(names(body) == ["real"])
    }

    @Test("unsafe names are skipped")
    func unsafeNames() {
        let long = String(repeating: "x", count: 129)
        let body = "[plugins.\".hidden\"]\nenabled = true\n[plugins.\"a/b\"]\nenabled = true\n[plugins.\"ctl\\u0001\"]\nenabled = true\n[plugins.\"\(long)\"]\nenabled = true\n[plugins.ok]\nenabled = true\n"
        #expect(names(body) == ["ok"])
    }

    @Test("invalid documents yield no names")
    func invalidDocuments() {
        #expect(names("[plugins.ok]\nenabled = true\n[broken\n").isEmpty)
        #expect(names("[plugins.ok]\nenabled = true\nenabled = true\n").isEmpty)
        #expect(names("[plugins.ok]\nenabled = true\n[plugins.ok]\nother = 1\n").isEmpty)
        #expect(names("[plugins.ok]\nenabled = true\nx = \"open\n").isEmpty)
        #expect(names("[plugins]\nx.enabled = true\n[plugins.x]\n").isEmpty)
        #expect(names("[plugins.x]\nenabled = true\nv = abc\n").isEmpty)
        #expect(names("[plugins.x]\nenabled = true\ns = \"ctl\u{01}\"\n").isEmpty)
        #expect(names("\u{FEFF}[plugins.bom]\nenabled = true\n") == ["bom"])
        var bytes = Array("[plugins.ok]\nenabled = true\nx = \"".utf8)
        bytes += [0xFF, 0x22, 0x0A]
        #expect(codexEnabledPluginNames(Data(bytes)).isEmpty)
    }

    @Test("names are sorted and bounded to 128")
    func bounded() {
        let body = (0..<200).reversed().map { String(format: "[plugins.\"p%03d@m\"]\nenabled = true\n", $0) }.joined()
        let result = names(body)
        #expect(result.count == 128)
        #expect(result.first == "p000@m")
        #expect(result.last == "p127@m")
    }

    @Test("agent discovery reports Codex enabled plugins without configuration values")
    func discovery() throws {
        let home = NSTemporaryDirectory() + "merlin-codex-plugins-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: home) }
        try FileManager.default.createDirectory(atPath: home + "/.codex", withIntermediateDirectories: true)
        try "[mcp_servers.github]\nurl = 'https://secret.example'\n[plugins.\"audit@marketplace\"]\nenabled = true\ntoken = 'secret-token'\n[plugins.\"off@marketplace\"]\nenabled = false\n"
            .write(toFile: home + "/.codex/config.toml", atomically: true, encoding: .utf8)

        let discovered = collectMacAgentDiscovery(homes: [home], systemBins: [], appRoots: [])
        #expect(discovered.assets.contains { $0.client == "codex" && $0.kind == "plugin" && $0.name == "audit@marketplace" && $0.source == ".codex/config.toml" })
        #expect(!discovered.assets.contains { $0.name == "off@marketplace" })
        #expect(discovered.servers.contains { $0.client == "codex" && $0.name == "github" })
        let payload = String(decoding: try JSONEncoder().encode(discovered.assets), as: UTF8.self)
        #expect(!payload.contains("secret"))
    }
}
