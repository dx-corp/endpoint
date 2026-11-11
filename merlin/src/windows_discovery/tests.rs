//! Ported from the Go collector's main_test.go, project_test.go,
//! codex_plugins_test.go and path_containment_test.go, which are the spec for
//! Windows discovery. They run on Linux against `PortableFs` with fixture
//! profiles; `handle_fs` carries the Windows-only handle tests.

use super::contained::{canonical_windows_path, windows_path_within};
use super::*;
use std::fs;
use std::os::unix::fs::symlink;

fn tempdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "merlin-windows-discovery-{}-{tag}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(path: &Path, body: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
}

fn roots(base: &Path) -> DiscoveryRoots {
    DiscoveryRoots {
        profiles: base.join("Users"),
        system_bins: Vec::new(),
        app_roots: Vec::new(),
        workspaces: Vec::new(),
    }
}

fn discover(roots: &DiscoveryRoots) -> (WindowsDiscovery, String) {
    let found = collect(&PortableFs, roots);
    let encoded = serde_json::to_string(&found).unwrap();
    (found, encoded)
}

fn projects(workspaces: &[&Path]) -> (WindowsDiscovery, String) {
    let empty = tempdir("no-profiles");
    let mut roots = roots(&empty);
    roots.workspaces = workspaces.iter().map(|root| root.to_path_buf()).collect();
    discover(&roots)
}

fn assert_absent(encoded: &str, forbidden: &[&str]) {
    for value in forbidden {
        assert!(!encoded.contains(value), "leaked {value:?}: {encoded}");
    }
}

fn assert_present(encoded: &str, expected: &[&str]) {
    for value in expected {
        assert!(encoded.contains(value), "missing {value:?}: {encoded}");
    }
}

#[test]
fn discovery_reports_names_without_config_values_or_paths() {
    let base = tempdir("names");
    let profile = base.join("Users/secret-account");
    write(
        &profile.join("AppData/Roaming/npm/claude.cmd"),
        "secret-shim",
    );
    write(
        &profile.join(".cursor/mcp.json"),
        r#"{"mcpServers":{"safe-server":{"url":"https://mcp.example/secret.example/mcp","env":{"API_KEY":"secret-key"}}}}"#,
    );
    write(
        &profile.join(".codex/config.toml"),
        "[mcp_servers.codex-server]\nurl = 'https://mcp.example/secret.example'\n",
    );
    write(
        &profile.join(".claude/settings.json"),
        r#"{"enabledPlugins":{"approved-plugin":true,"disabled-plugin":false}}"#,
    );
    write(
        &profile.join(".agents/skills/sample-skill/SKILL.md"),
        "secret prompt",
    );
    write(
        &profile.join(".claude/agents/sample-agent.md"),
        "secret prompt",
    );
    write(&base.join("Program Files/Cursor/Cursor.exe"), "app");
    let mut roots = roots(&base);
    roots.app_roots = vec![base.join("Program Files")];
    let (found, encoded) = discover(&roots);
    assert_absent(
        &encoded,
        &[
            "secret-account",
            "secret.example",
            "secret-key",
            "secret prompt",
            "secret-shim",
            "disabled-plugin",
            base.to_str().unwrap(),
        ],
    );
    assert_present(
        &encoded,
        &[
            "safe-server",
            "codex-server",
            "approved-plugin",
            "sample-skill",
            "sample-agent",
        ],
    );
    assert_eq!(
        found.agent_clis,
        vec![DeviceAgentCLI {
            name: "claude".into(),
            location: String::new(),
        }]
    );
    assert_eq!(
        found.agent_apps,
        vec![DeviceAgentApp {
            name: "cursor".into()
        }]
    );
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn additional_client_discovery_is_bounded_and_redacted() {
    let base = tempdir("clients");
    let profile = base.join("Users/private-account");
    for (relative, body) in [
        (
            ".gemini/settings.json",
            r#"{"mcpServers":{"gemini-remote":{"url":"https://mcp.example/private.example"}}}"#,
        ),
        (
            "AppData/Roaming/Code/User/mcp.json",
            r#"{"servers":{"vscode-local":{"command":"node","args":["private-command"]}}}"#,
        ),
        (
            ".config/opencode/opencode.json",
            r#"{"mcp":{"opencode-remote":{"url":"https://mcp.example/private.example"}}}"#,
        ),
        (
            "AppData/Roaming/opencode/opencode.json",
            r#"{"mcp":{"opencode-roaming":{"command":"node","args":["private-command"]}}}"#,
        ),
        (
            ".config/amp/settings.json",
            r#"{"amp.mcpServers":{"amp-local":{"command":"node","args":["private-command"]}}}"#,
        ),
        (
            ".qwen/settings.json",
            r#"{"mcpServers":{"qwen-remote":{"url":"https://mcp.example/private.example"}}}"#,
        ),
        (
            ".pi/agent/settings.json",
            r#"{"mcpServers":{"pi-local":{"command":"node","args":["private-command"]}}}"#,
        ),
        (
            ".maestro/config.toml",
            "[mcp_servers.maestro-local]\ncommand = 'node'\nargs = ['private-command']\n",
        ),
        (
            ".composer/config.toml",
            "[mcp_servers.composer-remote]\nurl = 'https://mcp.example/private.example'\n",
        ),
        (
            ".gemini/extensions/private-extension/gemini-extension.json",
            r#"{"mcpServers":{"extension-server":{"url":"https://mcp.example/private.example"}}}"#,
        ),
        (
            ".maestro/plugins/private-plugin/mcp.json",
            r#"{"mcpServers":{"plugin-server":{"command":"node","args":["private-command"]}}}"#,
        ),
    ] {
        write(&join_relative(&profile, relative), body);
    }
    for relative in [
        ".gemini/skills/gemini-skill/SKILL.md",
        ".config/opencode/skills/opencode-skill/SKILL.md",
        ".config/amp/skills/amp-skill/SKILL.md",
        ".qwen/skills/qwen-skill/SKILL.md",
        ".pi/agent/skills/pi-skill/SKILL.md",
        ".composer/skills/maestro-skill/SKILL.md",
        ".config/opencode/plugins/plugin.js",
        ".config/opencode/agents/reviewer.md",
        ".pi/agent/extensions/extension.ts",
        "AppData/Roaming/npm/amp.cmd",
        ".bun/bin/qwen.exe",
        ".codex/bin/pi.cmd",
    ] {
        write(&join_relative(&profile, relative), "private-content");
    }
    let (found, encoded) = discover(&roots(&base));
    assert_absent(
        &encoded,
        &[
            base.to_str().unwrap(),
            "private-account",
            "private.example",
            "private-command",
            "private-content",
        ],
    );
    assert_present(
        &encoded,
        &[
            "gemini-remote",
            "vscode-local",
            "opencode-remote",
            "opencode-roaming",
            "amp-local",
            "qwen-remote",
            "pi-local",
            "maestro-local",
            "composer-remote",
            "extension-server",
            "plugin-server",
            "gemini-skill",
            "opencode-skill",
            "amp-skill",
            "qwen-skill",
            "pi-skill",
            "maestro-skill",
            r#""name":"plugin""#,
            r#""name":"reviewer""#,
            r#""name":"extension""#,
            r#""name":"amp""#,
            r#""name":"qwen""#,
            r#""name":"pi""#,
        ],
    );
    let mut names: Vec<&str> = found
        .mcp_servers
        .iter()
        .map(|server| server.name.as_str())
        .collect();
    names.sort_unstable();
    let mut expected = [
        "amp-local",
        "composer-remote",
        "extension-server",
        "gemini-remote",
        "maestro-local",
        "opencode-remote",
        "opencode-roaming",
        "pi-local",
        "plugin-server",
        "qwen-remote",
        "vscode-local",
    ];
    expected.sort_unstable();
    assert_eq!(names, expected);
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn manifest_reads_are_bounded_and_a_linked_parent_is_not_followed() {
    let base = tempdir("manifest-limit");
    let profile = base.join("Users/person");
    for index in 0..40 {
        write(
            &profile.join(format!(
                ".gemini/extensions/extension-{index:02}/gemini-extension.json"
            )),
            &format!(
                r#"{{"mcpServers":{{"server-{index:02}":{{"command":"node","args":["secret"]}}}}}}"#
            ),
        );
    }
    let outside = tempdir("manifest-limit-outside");
    write(
        &outside.join("opencode/opencode.json"),
        r#"{"mcp":{"linked-secret":{}}}"#,
    );
    symlink(&outside, profile.join(".config")).unwrap();
    let (found, encoded) = discover(&roots(&base));
    assert_eq!(found.mcp_servers.len(), MAX_MANIFEST_READS);
    assert_absent(&encoded, &["linked-secret"]);
    fs::remove_dir_all(base).unwrap();
    fs::remove_dir_all(outside).unwrap();
}

#[test]
fn cursor_user_agents_and_local_plugins() {
    let base = tempdir("cursor");
    let profile = base.join("Users/private-account");
    let local = profile.join(".cursor/plugins/local");
    write(
        &profile.join(".cursor/agents/reviewer.md"),
        "private agent instructions",
    );
    write(
        &profile.join(".cursor/agents/oversized.md"),
        &"x".repeat((64 << 10) + 1),
    );
    write(
        &local.join("audit/plugin.json"),
        r#"{"name":"audit","command":"node","args":["private-command"]}"#,
    );
    write(
        &local.join("nested/.cursor-plugin/plugin.json"),
        r#"{"name":"nested","url":"https://mcp.example/private.example"}"#,
    );
    write(&local.join("invalid/plugin.json"), "not JSON");
    write(&local.join("unnamed/plugin.json"), "{}");
    write(
        &local.join("oversized/plugin.json"),
        &"x".repeat((64 << 10) + 1),
    );
    write(&local.join(".hidden/plugin.json"), r#"{"name":"hidden"}"#);
    let outside = tempdir("cursor-outside");
    write(&outside.join("plugin.json"), r#"{"name":"linked"}"#);
    fs::create_dir_all(local.join("linked")).unwrap();
    symlink(
        outside.join("plugin.json"),
        local.join("linked/plugin.json"),
    )
    .unwrap();
    fs::create_dir_all(local.join("linked-parent")).unwrap();
    symlink(&outside, local.join("linked-parent/.cursor-plugin")).unwrap();
    let (_, encoded) = discover(&roots(&base));
    assert_absent(
        &encoded,
        &[
            base.to_str().unwrap(),
            "private-account",
            "private agent instructions",
            "private-command",
            "private.example",
            "invalid",
            "unnamed",
            "oversized",
            "linked",
            "hidden",
        ],
    );
    assert_present(
        &encoded,
        &[
            r#""client":"cursor","kind":"agent","name":"reviewer","source":".cursor/agents""#,
            r#""client":"cursor","kind":"plugin","name":"audit","source":".cursor/plugins/local""#,
            r#""client":"cursor","kind":"plugin","name":"nested","source":".cursor/plugins/local""#,
        ],
    );
    fs::remove_dir_all(base).unwrap();
    fs::remove_dir_all(outside).unwrap();
}

#[test]
fn cursor_plugin_manifest_reads_are_bounded() {
    let base = tempdir("cursor-limit");
    let profile = base.join("Users/person");
    for index in 0..40 {
        let name = format!("plugin-{index:02}");
        write(
            &profile.join(format!(".cursor/plugins/local/{name}/plugin.json")),
            &format!(r#"{{"name":"{name}"}}"#),
        );
    }
    let (found, _) = discover(&roots(&base));
    assert_eq!(found.agent_assets.len(), MAX_MANIFEST_READS);
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn mcp_transport_classification_does_not_emit_values() {
    // Secrets sit in arguments and URL paths, which are never read into an
    // entry; only the program name and URL host are.
    let entries = json_mcp_entries(
        r#"{"mcpServers":{"local":{"command":"node","args":["secret-command"]},"remote":{"url":"https://mcp.example/secret"},"ambiguous":{"command":"node","args":["secret"],"url":"https://mcp.example/secret.example"}}}"#,
        &["mcpServers"],
    );
    let rows: std::collections::BTreeMap<&str, (&str, &str, &str)> = entries
        .iter()
        .map(|e| {
            (
                e.name.as_str(),
                (e.transport.as_str(), e.package.as_str(), e.host.as_str()),
            )
        })
        .collect();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows["local"], ("stdio", "node", ""));
    assert_eq!(rows["remote"], ("remote", "", "mcp.example"));
    assert_eq!(rows["ambiguous"], ("unknown", "", ""));
    let toml_location = windows_locations(Scope::User)
        .find(|location| location.format == Format::Toml)
        .unwrap();
    let toml_entries = config_mcp_entries(
        toml_location,
        "[mcp_servers.docs]\nurl = 'https://mcp.example/secret'\n[mcp_servers.local]\ncommand = 'node'\nargs = ['secret']\n",
    );
    let toml_rows: Vec<(&str, &str, &str, &str)> = toml_entries
        .iter()
        .map(|e| {
            (
                e.name.as_str(),
                e.transport.as_str(),
                e.package.as_str(),
                e.host.as_str(),
            )
        })
        .collect();
    assert_eq!(
        toml_rows,
        vec![
            ("docs", "remote", "", "mcp.example"),
            ("local", "stdio", "node", "")
        ]
    );
    assert!(!format!("{rows:?}{toml_rows:?}").contains("secret"));
}

#[test]
fn discovery_skips_linked_and_oversized_configs() {
    let base = tempdir("linked-configs");
    let profile = base.join("Users/person");
    let outside = base.join("outside.json");
    write(&outside, r#"{"mcpServers":{"linked-secret":{}}}"#);
    fs::create_dir_all(profile.join(".cursor")).unwrap();
    symlink(&outside, profile.join(".cursor/mcp.json")).unwrap();
    write(
        &profile.join(".claude.json"),
        &format!(
            r#"{}{{"mcpServers":{{"oversized-secret":{{}}}}}}"#,
            "x".repeat(64 << 10)
        ),
    );
    let linked_parent = base.join("linked-parent");
    write(
        &linked_parent.join("Roaming/Claude/claude_desktop_config.json"),
        r#"{"mcpServers":{"parent-secret":{}}}"#,
    );
    symlink(&linked_parent, profile.join("AppData")).unwrap();
    let (_, encoded) = discover(&roots(&base));
    assert_absent(
        &encoded,
        &["linked-secret", "oversized-secret", "parent-secret"],
    );
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn profiles_are_capped_and_linked_profiles_skipped() {
    let base = tempdir("profiles");
    for index in 0..70 {
        write(
            &base.join(format!("Users/person-{index:02}/.cursor/mcp.json")),
            &format!(r#"{{"mcpServers":{{"server-{index:02}":{{}}}}}}"#),
        );
    }
    let outside = tempdir("profiles-outside");
    write(
        &outside.join(".cursor/mcp.json"),
        r#"{"mcpServers":{"linked-profile":{}}}"#,
    );
    symlink(&outside, base.join("Users/aaa-linked")).unwrap();
    let (found, encoded) = discover(&roots(&base));
    assert_eq!(found.mcp_servers.len(), MAX_PROFILES);
    assert_absent(&encoded, &["linked-profile", "server-64"]);
    fs::remove_dir_all(base).unwrap();
    fs::remove_dir_all(outside).unwrap();
}

#[test]
fn declared_ai_extensions_are_found_in_the_editor_and_chrome_profiles_and_no_others() {
    let base = tempdir("ai-extensions");
    let profile = base.join("Users/person");
    let user_data = "AppData/Local/Google/Chrome/User Data";
    for directory in [
        ".vscode/extensions/anthropic.claude-code-2.0.0".to_string(),
        ".vscode/extensions/ms-python.python-2025.1.0".into(),
        format!("{user_data}/Default/Extensions/fcoeoabgfenejglbffodgkkbkcdhcgfn/1.0_0"),
        format!("{user_data}/Default/Extensions/aapocclcgogkmnckokdopfmhonfmgoek/1.0_0"),
        format!("{user_data}/System Profile/Extensions/ejcfepkfckglbgocfkanmcdngdijcgld/1.0_0"),
    ] {
        fs::create_dir_all(profile.join(directory)).unwrap();
    }
    let (found, encoded) = discover(&roots(&base));
    let mut extensions: Vec<_> = found
        .agent_assets
        .iter()
        .filter(|asset| asset.kind == "extension")
        .map(|asset| {
            (
                asset.client.as_str(),
                asset.name.as_str(),
                asset.source.as_str(),
            )
        })
        .collect();
    extensions.sort();
    assert_eq!(
        extensions,
        vec![
            ("chrome", "fcoeoabgfenejglbffodgkkbkcdhcgfn", user_data),
            ("vscode", "Anthropic.claude-code", ".vscode/extensions"),
        ]
    );
    assert_absent(
        &encoded,
        &[
            "ms-python",
            "aapocclcgogkmnckokdopfmhonfmgoek",
            "ejcfepkfckglbgocfkanmcdngdijcgld",
        ],
    );
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn every_declared_windows_location_has_a_reader() {
    // Formats the Windows reader handles; a new format in the manifest must
    // be handled here before it is declared for windows.
    for location in windows_locations(Scope::User).chain(windows_locations(Scope::Project)) {
        let handled = match (location.scope, location.kind) {
            (_, "config") => matches!(
                location.format,
                Format::Json | Format::Toml | Format::CodexToml
            ),
            (Scope::User, "cli") => location.format == Format::Executable,
            (Scope::User, _) => matches!(
                location.format,
                Format::SkillDir
                    | Format::Md
                    | Format::CursorAgent
                    | Format::JsTs
                    | Format::GeminiExtension
                    | Format::PluginDir
                    | Format::CursorPlugin
                    | Format::EditorExtensions
                    | Format::ChromiumExtensions
            ),
            (Scope::Project, _) => {
                matches!(
                    location.format,
                    Format::SkillDir | Format::Md | Format::PluginDir
                )
            }
            // build.rs keeps system rows off windows.
            (Scope::System, _) => false,
        };
        assert!(handled, "no Windows reader for {location:?}");
    }
}

// Codex plugins (codex_plugins_test.go): only `plugins.<name>.enabled = true`
// with a safe name counts, and a document that fails to parse yields nothing.
#[test]
fn codex_enabled_plugin_names_match_the_linux_semantics() {
    let long = "x".repeat(129);
    let cases: &[(&str, String, &[&str])] = &[
        (
            "table headers report only explicit true",
            "[plugins.\"audit@marketplace\"]\nenabled = true\nsecret = 'private'\n[plugins.\"off@marketplace\"]\nenabled = false\n[plugins.\"unset@marketplace\"]\nfoo = true\n[plugins.\"text@marketplace\"]\nenabled = \"true\"\n[plugins.\"https://private.example/path\"]\nenabled = true\n".into(),
            &["audit@marketplace"],
        ),
        (
            "inline tables, dotted keys, literal keys, and CRLF",
            "model = \"gpt\"\r\n[plugins]\r\ninline = { enabled = true, token = \"secret\" }\r\n'literal@m'.enabled = true # comment\r\n\"esc\\u0041pe\" . enabled = true\r\n".into(),
            &["escApe", "inline", "literal@m"],
        ),
        ("top-level dotted plugins table", "plugins.dotted.enabled = true\n".into(), &["dotted"]),
        (
            "whole inline plugins value",
            "plugins = { a = { enabled = true }, b = { enabled = false } }\n".into(),
            &["a"],
        ),
        (
            "nested and array tables are not plugin entries",
            "[plugins.outer.inner]\nenabled = true\n[[plugins_list]]\nenabled = true\n[mcp_servers.plugins]\nenabled = true\n".into(),
            &[],
        ),
        (
            "multi-line values do not open tables",
            "[mcp_servers.x]\nargs = [\n  \"a\", # note\n  \"[plugins.fake]\",\n]\nnote = \"\"\"\n[plugins.fake2]\nenabled = true\n\"\"\"\nraw = '''\n[plugins.fake3]\n'''\nwhen = 1979-05-27 07:32:00Z\n[plugins.real]\nenabled = true\n".into(),
            &["real"],
        ),
        (
            "unsafe names are skipped",
            format!("[plugins.\".hidden\"]\nenabled = true\n[plugins.\"a/b\"]\nenabled = true\n[plugins.\"ctl\\u0001\"]\nenabled = true\n[plugins.\"{long}\"]\nenabled = true\n[plugins.ok]\nenabled = true\n"),
            &["ok"],
        ),
        ("invalid document", "[plugins.ok]\nenabled = true\n[broken\n".into(), &[]),
        ("duplicate key", "[plugins.ok]\nenabled = true\nenabled = true\n".into(), &[]),
        ("duplicate table", "[plugins.ok]\nenabled = true\n[plugins.ok]\nother = 1\n".into(), &[]),
        ("unterminated string", "[plugins.ok]\nenabled = true\nx = \"open\n".into(), &[]),
        (
            "header reopening a dotted-key table",
            "[plugins]\nx.enabled = true\n[plugins.x]\n".into(),
            &[],
        ),
        ("bare word value", "[plugins.x]\nenabled = true\nv = abc\n".into(), &[]),
        ("control character in string", "[plugins.x]\nenabled = true\ns = \"ctl\x01\"\n".into(), &[]),
        ("leading byte order mark", "\u{FEFF}[plugins.bom]\nenabled = true\n".into(), &["bom"]),
    ];
    for (name, body, want) in cases {
        assert_eq!(codex_enabled_plugin_names(body), *want, "{name}");
    }
}

#[test]
fn codex_enabled_plugin_names_are_sorted_and_bounded() {
    let body: String = (0..MAX_FINDINGS + 72)
        .rev()
        .map(|index| format!("[plugins.\"p{index:03}@m\"]\nenabled = true\n"))
        .collect();
    let names = codex_enabled_plugin_names(&body);
    assert_eq!(names.len(), MAX_FINDINGS);
    assert_eq!(names.first().map(String::as_str), Some("p000@m"));
    let last = format!("p{:03}@m", MAX_FINDINGS - 1);
    assert_eq!(names.last(), Some(&last));
}

#[test]
fn discovery_reports_codex_enabled_plugins_without_values() {
    let base = tempdir("codex-plugins");
    let profile = base.join("Users/secret-account");
    write(
        &profile.join(".codex/config.toml"),
        "[mcp_servers.codex-server]\nurl = 'https://mcp.example/secret.example'\n[plugins.\"audit@marketplace\"]\nenabled = true\ntoken = 'secret-token'\n[plugins.\"off@marketplace\"]\nenabled = false\n",
    );
    let (found, encoded) = discover(&roots(&base));
    assert!(found.agent_assets.contains(&DeviceAgentAsset {
        location: String::new(),
        client: "codex".into(),
        kind: "plugin".into(),
        name: "audit@marketplace".into(),
        source: ".codex/config.toml".into(),
        ..Default::default()
    }));
    assert_absent(
        &encoded,
        &[
            "off@marketplace",
            "secret-token",
            "secret.example",
            "secret-account",
            base.to_str().unwrap(),
        ],
    );
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn a_codex_config_that_is_not_utf8_yields_no_plugins() {
    let base = tempdir("codex-utf8");
    let path = base.join("Users/person/.codex/config.toml");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, b"[plugins.ok]\nenabled = true\nx = \"\xff\"\n").unwrap();
    let (found, _) = discover(&roots(&base));
    assert!(
        found
            .agent_assets
            .iter()
            .all(|asset| asset.kind != "plugin")
    );
    fs::remove_dir_all(base).unwrap();
}

// Projects (project_test.go).
#[test]
fn project_discovery_is_bounded_and_redacted() {
    let base = tempdir("projects");
    let root = base.join("private-workspaces");
    for index in 0..40 {
        write(
            &root.join(format!("project-{index:02}/.mcp.json")),
            &format!(
                r#"{{"mcpServers":{{"server-{index:02}":{{"command":"node","args":["private-secret"]}}}}}}"#
            ),
        );
    }
    let project = root.join("project-00");
    write(
        &project.join(".cursor/mcp.json"),
        r#"{"mcpServers":{"docs":{"url":"https://mcp.example/private.example/mcp"}}}"#,
    );
    write(
        &project.join(".opencode/opencode.json"),
        r#"{"mcp":{"code-search":{"url":"https://mcp.example/private.example/mcp"}},"secret":"private-secret"}"#,
    );
    write(
        &project.join(".agents/mcp.json"),
        r#"{"mcpServers":{"agent-search":{"command":"node","args":["private-secret"]}}}"#,
    );
    write(
        &project.join(".agents/skills/review/SKILL.md"),
        "private instructions",
    );
    write(
        &project.join(".claude/agents/reviewer.md"),
        "private instructions",
    );
    write(
        &project.join(".claude/settings.json"),
        r#"{"enabledPlugins":{"audit@marketplace":true,"off@marketplace":false},"secret":"private-secret"}"#,
    );
    write(
        &project.join(".maestro/plugins/audit/mcp.json"),
        r#"{"mcpServers":{"pluginsearch":{"url":"https://mcp.example/private.example/mcp"}}}"#,
    );
    let outside = tempdir("projects-outside");
    write(
        &outside.join(".mcp.json"),
        r#"{"mcpServers":{"linked-secret":{}}}"#,
    );
    symlink(&outside, root.join("project-41")).unwrap();
    let (found, encoded) = projects(&[&root]);
    // One server per visited descendant, plus project-00's Cursor, OpenCode,
    // agents and plugin servers.
    assert_eq!(found.mcp_servers.len(), MAX_PROJECT_DESCENDANTS + 4);
    assert_absent(
        &encoded,
        &[
            root.to_str().unwrap(),
            "private-workspaces",
            "private-secret",
            "private instructions",
            "private.example",
            "linked-secret",
            "project-33",
            "off@marketplace",
        ],
    );
    assert_present(
        &encoded,
        &[
            "project/.mcp.json",
            "project/.cursor/mcp.json",
            "project/.opencode/opencode.json",
            "project/.agents/mcp.json",
            "code-search",
            "agent-search",
            "project/.maestro/plugins/*/mcp.json",
            "project/.agents/skills",
            "reviewer",
            "audit@marketplace",
            "project/.maestro/plugins",
        ],
    );
    fs::remove_dir_all(base).unwrap();
    fs::remove_dir_all(outside).unwrap();
}

#[test]
fn workspace_root_validation() {
    let base = tempdir("roots");
    assert!(valid_workspace_root(
        base.join("Projects").to_str().unwrap()
    ));
    let traversal = format!("{}/../private", base.display());
    let long = "x".repeat(513);
    for invalid in [
        "",
        "relative",
        r"\\server\share",
        "//server/share",
        &traversal,
        &long,
    ] {
        assert!(!valid_workspace_root(invalid), "accepted {invalid:?}");
    }
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn project_discovery_includes_grandchildren_but_not_deeper_directories() {
    let root = tempdir("project-depth");
    let project = root.join("team/project");
    write(
        &project.join(".mcp.json"),
        r#"{"mcpServers":{"nested":{"command":"node","args":["private-secret"]}}}"#,
    );
    write(
        &project.join(".agents/skills/review/SKILL.md"),
        "private instructions",
    );
    write(
        &project.join("deeper/.mcp.json"),
        r#"{"mcpServers":{"too-deep":{}}}"#,
    );
    let (_, encoded) = projects(&[&root]);
    assert_present(
        &encoded,
        &[
            "nested",
            "review",
            "project/.mcp.json",
            "project/.agents/skills",
        ],
    );
    assert_absent(
        &encoded,
        &[
            "too-deep",
            "private-secret",
            "private instructions",
            "team",
            "deeper",
        ],
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn project_discovery_caps_descendants_across_both_levels() {
    let root = tempdir("project-cap");
    for index in 0..40 {
        write(
            &root.join(format!("team/project-{index:02}/.mcp.json")),
            &format!(r#"{{"mcpServers":{{"server-{index:02}":{{}}}}}}"#),
        );
    }
    let (found, _) = projects(&[&root]);
    // The team directory itself uses one of the descendants.
    assert_eq!(found.mcp_servers.len(), MAX_PROJECT_DESCENDANTS - 1);
    assert!(
        found
            .mcp_servers
            .iter()
            .all(|server| server.name != format!("server-{:02}", MAX_PROJECT_DESCENDANTS - 1))
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn project_discovery_does_not_follow_a_nested_directory_link() {
    let root = tempdir("project-link");
    let outside = tempdir("project-link-outside");
    write(
        &outside.join(".mcp.json"),
        r#"{"mcpServers":{"linked-secret":{}}}"#,
    );
    fs::create_dir_all(root.join("team")).unwrap();
    symlink(&outside, root.join("team/linked")).unwrap();
    let (found, _) = projects(&[&root]);
    assert!(found.mcp_servers.is_empty(), "{:?}", found.mcp_servers);
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(outside).unwrap();
}

#[test]
fn user_and_project_findings_merge_and_deduplicate() {
    let base = tempdir("merge");
    write(
        &base.join("Users/person/.cursor/mcp.json"),
        r#"{"mcpServers":{"docs":{}}}"#,
    );
    write(
        &base.join("work/app/.cursor/mcp.json"),
        r#"{"mcpServers":{"docs":{}}}"#,
    );
    let mut roots = roots(&base);
    roots.workspaces = vec![base.join("work")];
    let (found, _) = discover(&roots);
    let sources: Vec<&str> = found
        .mcp_servers
        .iter()
        .map(|server| server.source.as_str())
        .collect();
    assert_eq!(
        sources,
        vec![".cursor/mcp.json", "project/.cursor/mcp.json"]
    );
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn off_host_findings_merge_deduplicated_and_capped() {
    let server = |name: &str, location: &str| DeviceMCPServer {
        client: "codex".into(),
        name: name.into(),
        source: ".codex/config.toml".into(),
        transport: "stdio".into(),
        location: location.into(),
        package: String::new(),
        host: String::new(),
        matched_rules: Vec::new(),
    };
    let mut discovery = WindowsDiscovery {
        mcp_servers: vec![server("docs", "")],
        ..WindowsDiscovery::default()
    };
    let mut wsl: Vec<DeviceMCPServer> = (0..MAX_FINDINGS)
        .map(|index| server(&format!("s{index:03}"), "wsl:Ubuntu"))
        .collect();
    wsl.push(server("docs", ""));
    merge_off_host(&mut discovery, wsl, Vec::new());
    assert_eq!(discovery.mcp_servers.len(), MAX_FINDINGS);
    let hosts = discovery
        .mcp_servers
        .iter()
        .filter(|s| s.location.is_empty())
        .count();
    assert_eq!(hosts, 1, "the host server appears once");
}

// Process names (process_test.go).
#[test]
fn agent_process_names_match_case_insensitively_and_exactly() {
    for name in [
        "Cursor.exe",
        "cursor.exe",
        "CURSOR.EXE",
        "Claude.exe",
        "claude.exe",
        "codex.exe",
        "CODEX.exe",
        "  Cursor.exe  ",
    ] {
        assert!(is_agent_process(name), "{name:?}");
    }
    for name in [
        "cursor",
        "claude",
        "codex",
        "Cursor",
        "notepad.exe",
        "cursor-helper.exe",
        "",
        "claude.exe.exe",
    ] {
        assert!(!is_agent_process(name), "{name:?}");
    }
}

// Path containment (path_containment_test.go).
#[test]
fn canonical_windows_path_rejects_aliases_and_traversal() {
    let cases: &[(&str, Option<&str>)] = &[
        (r"C:\Users\Person\.cursor", Some(r"c:\Users\Person\.cursor")),
        (
            r"\\?\C:\Users\Person\.cursor",
            Some(r"c:\Users\Person\.cursor"),
        ),
        (r"C:\Projects\", Some(r"c:\Projects")),
        ("C:/Projects/", Some(r"c:\Projects")),
        (r"C:\", Some(r"c:\")),
        (r"C:\Projects\\", None),
        (r"C:\Projects\..\", None),
        (r"C:\Users\Person\..\Windows", None),
        (r"C:\Users\Person\.\file", None),
        (r"C:\Users\Person\\file", None),
        (r"C:\Users\Person\file:stream", None),
        (r"\\server\share\file", None),
        (r"\\?\UNC\server\share\file", None),
        (r"\\.\C:\Users\file", None),
        (r"C:relative\file", None),
    ];
    for (input, want) in cases {
        assert_eq!(canonical_windows_path(input).as_deref(), *want, "{input}");
    }
}

#[test]
fn windows_path_within_uses_components_and_exact_case() {
    let root = r"c:\Users\Person";
    for target in [
        root,
        r"c:\Users\Person\.cursor",
        r"c:\Users\Person\.cursor\config.json",
    ] {
        assert!(
            windows_path_within(root, target),
            "{target} must be within {root}"
        );
    }
    for target in [
        r"c:\Users\Person2\secret",
        r"c:\Users\person\secret",
        r"d:\Users\Person\secret",
    ] {
        assert!(
            !windows_path_within(root, target),
            "{target} escaped {root}"
        );
    }
}

#[test]
fn a_config_is_read_up_to_its_own_limit_and_a_larger_one_is_reported_not_scanned() {
    let base = tempdir("config-limit");
    let profile = base.join("Users/private-account");
    let claude = windows_locations(Scope::User)
        .find(|l| l.path == ".claude.json")
        .unwrap();
    let pad = |server: &str, size: u64| {
        let head = format!(
            r#"{{"mcpServers":{{"{server}":{{"url":"https://{server}.example/mcp"}}}},"pad":""#
        );
        format!("{head}{}\"}}", "x".repeat(size as usize - head.len() - 2))
    };
    // Over the default limit, within its own: read.
    write(
        &profile.join(".claude.json"),
        &pad("big", MAX_CONFIG_BYTES + 1024),
    );
    // No limit of its own and over the default: reported, not read.
    write(
        &profile.join(".cursor/mcp.json"),
        &pad("cursor-big", MAX_CONFIG_BYTES + 1),
    );
    let (found, encoded) = discover(&roots(&base));
    assert!(
        found
            .mcp_servers
            .iter()
            .any(|s| s.name == "big" && s.host == "big.example")
    );
    assert!(!found.mcp_servers.iter().any(|s| s.name == "cursor-big"));
    assert_eq!(
        found
            .coverage
            .iter()
            .map(|c| (c.location.as_str(), c.source.as_str(), c.reason.as_str()))
            .collect::<Vec<_>>(),
        [("", ".cursor/mcp.json", "too_large")]
    );
    // Coverage travels as ai_location_coverage, not inside the discovery.
    assert_absent(&encoded, &["too_large"]);
    let inventory =
        crate::windows_checkin::Inventory::new(found, std::time::SystemTime::UNIX_EPOCH);
    let wire = serde_json::to_value(&inventory).unwrap();
    assert_eq!(
        wire["ai_location_coverage"],
        serde_json::json!([{"source": ".cursor/mcp.json", "state": "not_scanned", "reason": "too_large"}])
    );

    write(
        &profile.join(".claude.json"),
        &pad("big", claude.max_bytes + 1),
    );
    let (found, _) = discover(&roots(&base));
    assert!(!found.mcp_servers.iter().any(|s| s.name == "big"));
    assert!(
        found
            .coverage
            .iter()
            .any(|c| c.source == ".claude.json" && c.reason == "too_large")
    );
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn a_profile_with_more_skills_than_the_cap_reports_the_list_truncated() {
    let base = tempdir("truncated");
    let profile = base.join("Users/private-account");
    for index in 0..MAX_FINDINGS + 20 {
        write(
            &profile.join(format!(".claude/skills/s{index:04}/SKILL.md")),
            "x",
        );
    }
    let (found, _) = discover(&roots(&base));
    assert!(found.agent_assets.len() <= MAX_FINDINGS);
    assert_eq!(
        found
            .coverage
            .iter()
            .map(|c| (c.state.as_str(), c.reason.as_str()))
            .collect::<Vec<_>>(),
        [("truncated", "agent_assets")]
    );
    let inventory =
        crate::windows_checkin::Inventory::new(found, std::time::SystemTime::UNIX_EPOCH);
    assert_eq!(
        serde_json::to_value(&inventory).unwrap()["ai_location_coverage"],
        serde_json::json!([{"state": "truncated", "reason": "agent_assets"}])
    );
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn codex_configs_are_read_up_to_their_own_limit_in_profiles_and_projects() {
    let codex = |scope: Scope| {
        windows_locations(scope)
            .find(|l| l.path == ".codex/config.toml")
            .unwrap()
    };
    let (user, project_row) = (codex(Scope::User), codex(Scope::Project));
    let pad = |server: &str, size: u64| {
        let head = format!(
            "[mcp_servers.{server}]\ncommand = \"npx\"\nargs = [\"-y\", \"{server}-mcp\"]\n# "
        );
        format!("{head}{}\n", "x".repeat(size as usize - head.len() - 1))
    };
    let base = tempdir("codex-limit");
    let profile = base.join("Users/private-account");
    write(
        &profile.join(".codex/config.toml"),
        &pad("homebig", MAX_CONFIG_BYTES + 1024),
    );
    let (found, _) = discover(&roots(&base));
    assert!(found.mcp_servers.iter().any(|s| s.name == "homebig"));
    assert!(found.coverage.is_empty());
    assert!(user.max_bytes > MAX_CONFIG_BYTES);

    let workspace = tempdir("codex-limit-workspace");
    write(
        &workspace.join("within/.codex/config.toml"),
        &pad("projectbig", MAX_CONFIG_BYTES + 1024),
    );
    write(
        &workspace.join("over/.codex/config.toml"),
        &pad("toolarge", project_row.max_bytes + 1),
    );
    let (found, encoded) = projects(&[&workspace]);
    assert!(found.mcp_servers.iter().any(|s| s.name == "projectbig"));
    assert!(!found.mcp_servers.iter().any(|s| s.name == "toolarge"));
    assert_eq!(
        found
            .coverage
            .iter()
            .map(|c| (c.source.as_str(), c.reason.as_str()))
            .collect::<Vec<_>>(),
        [("project/.codex/config.toml", "too_large")]
    );
    assert_absent(&encoded, &["private-account", "codex-limit-workspace"]);
    fs::remove_dir_all(base).unwrap();
    fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn claude_code_project_mcp_servers_are_read_without_their_project_paths() {
    let base = tempdir("claude-project-mcp");
    let profile = base.join("Users/private-account");
    write(
        &profile.join(".claude.json"),
        r#"{"projects":{"C:/Users/private-account/customer-private":{"mcpServers":{"granola":{"url":"https://mcp.granola.ai/mcp?key=private-secret"}}}}}"#,
    );
    let (found, encoded) = discover(&roots(&base));
    assert!(found.mcp_servers.iter().any(|s| s.name == "granola"
        && s.source == ".claude.json/projects/*"
        && s.host == "mcp.granola.ai"));
    assert_absent(
        &encoded,
        &["customer-private", "private-secret", "private-account"],
    );
    fs::remove_dir_all(base).unwrap();
}
