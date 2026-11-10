import Foundation
import Testing
@testable import MerlinMacOS

@Suite("AI extensions")
struct AIExtensionTests {
    @Test("only declared editor and Chrome extensions are named, and a linked profile is not followed")
    func onlyDeclaredExtensionsAreNamed() throws {
        let home = NSTemporaryDirectory() + "merlin-extensions-\(UUID().uuidString)"
        let elsewhere = NSTemporaryDirectory() + "merlin-extensions-elsewhere-\(UUID().uuidString)"
        defer {
            try? FileManager.default.removeItem(atPath: home)
            try? FileManager.default.removeItem(atPath: elsewhere)
        }
        let chrome = home + "/" + macChromeUserDataDirectory
        for directory in [
            "/.vscode/extensions/anthropic.claude-code-2.0.0",
            "/.vscode/extensions/ms-python.python-2025.1.0",
            "/.vscode/extensions/github.copilot-labs-0.1.0",
        ] {
            try FileManager.default.createDirectory(atPath: home + directory, withIntermediateDirectories: true)
        }
        for directory in [
            "/Default/Extensions/fcoeoabgfenejglbffodgkkbkcdhcgfn/1.0_0",
            "/Default/Extensions/aapocclcgogkmnckokdopfmhonfmgoek/1.0_0",
            "/Guest Profile/Extensions/ejcfepkfckglbgocfkanmcdngdijcgld/1.0_0",
        ] {
            try FileManager.default.createDirectory(atPath: chrome + directory, withIntermediateDirectories: true)
        }
        try FileManager.default.createDirectory(
            atPath: elsewhere + "/Extensions/ejcfepkfckglbgocfkanmcdngdijcgld/1.0_0", withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: chrome + "/Profile 2", withDestinationPath: elsewhere)

        let discovered = collectMacAgentDiscovery(homes: [home], systemBins: [], appRoots: [])
        let extensions = discovered.assets.filter { $0.kind == "extension" }.map { "\($0.client) \($0.name) \($0.source)" }.sorted()
        #expect(extensions == [
            "chrome fcoeoabgfenejglbffodgkkbkcdhcgfn \(macChromeUserDataDirectory)",
            "vscode Anthropic.claude-code .vscode/extensions",
        ])
    }

    @Test("an editor extension directory is matched by its whole declared id")
    func editorExtensionMatching() {
        #expect(editorAIExtension("github.copilot-chat-0.32.4") == "GitHub.copilot-chat")
        #expect(editorAIExtension("github.copilot-1.388.0") == "GitHub.copilot")
        #expect(editorAIExtension("github.copilot-labs-0.1.0") == nil)
        #expect(editorAIExtension("anthropic.claude-code") == nil)
        #expect(chromiumProfile("Default") && chromiumProfile("Profile 12"))
        #expect(!chromiumProfile("System Profile") && !chromiumProfile("Profile 1234"))
    }
}
