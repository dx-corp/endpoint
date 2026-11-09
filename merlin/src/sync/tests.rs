use super::*;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn agent_discovery_reports_names_without_config_values_or_symlinks() {
    let root = tmpdir("agent-discovery");
    let home = root.join("home");
    let bin = home.join(".local/bin");
    fs::create_dir_all(&bin).unwrap();
    let executable = bin.join("codex");
    fs::write(&executable, "#!/bin/sh\n").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    let cursor = bin.join("cursor");
    fs::write(&cursor, "#!/bin/sh\n").unwrap();
    fs::set_permissions(&cursor, fs::Permissions::from_mode(0o755)).unwrap();
    fs::create_dir_all(home.join(".codex")).unwrap();
    fs::write(
        home.join(".codex/config.toml"),
        "[mcp_servers.github]\nurl = 'https://secret.example'\n[mcp_servers.\"/Users/private/work\"]\ncommand = 'secret'\n",
    )
    .unwrap();
    fs::create_dir_all(home.join(".cursor")).unwrap();
    fs::write(
        home.join(".cursor/mcp.json"),
        r#"{"mcpServers":{"docs":{"command":"secret"},"https://private.example/mcp":{"url":"secret"},"C:\\Users\\private":{"command":"secret"}}}"#,
    )
    .unwrap();
    fs::create_dir_all(home.join(".agents/skills/review")).unwrap();
    fs::write(
        home.join(".agents/skills/review/SKILL.md"),
        "secret instructions",
    )
    .unwrap();
    fs::create_dir_all(home.join(".pi/agent")).unwrap();
    std::os::unix::fs::symlink(home.join(".agents/skills"), home.join(".pi/agent/skills")).unwrap();
    fs::create_dir_all(home.join(".gemini/extensions/workspace")).unwrap();
    fs::write(
        home.join(".gemini/extensions/workspace/gemini-extension.json"),
        r#"{"mcpServers":{"search":{"env":{"TOKEN":"secret"}}}}"#,
    )
    .unwrap();
    fs::create_dir_all(home.join(".gemini/extensions/not-extension")).unwrap();
    fs::write(
        home.join(".gemini/extensions/not-extension/SKILL.md"),
        "ignored",
    )
    .unwrap();
    fs::create_dir_all(home.join(".claude/agents")).unwrap();
    fs::write(home.join(".claude/agents/reviewer.md"), "secret prompt").unwrap();
    fs::write(
        home.join(".claude/settings.json"),
        r#"{"enabledPlugins":{"audit@marketplace":true,"off@marketplace":false}}"#,
    )
    .unwrap();
    fs::create_dir_all(home.join(".config/amp")).unwrap();
    fs::write(
        home.join(".config/amp/settings.json"),
        r#"{"amp.mcpServers":{"db":{"command":"secret"}}}"#,
    )
    .unwrap();
    fs::create_dir_all(home.join(".config/opencode/plugins")).unwrap();
    fs::write(
        home.join(".config/opencode/plugins/trace.ts"),
        "secret plugin",
    )
    .unwrap();
    fs::create_dir_all(home.join(".maestro/plugins/audit/.plugin")).unwrap();
    fs::write(
        home.join(".maestro/plugins/audit/.plugin/plugin.json"),
        "secret plugin",
    )
    .unwrap();
    fs::write(
        home.join(".maestro/plugins/audit/mcp.json"),
        r#"{"mcpServers":{"pluginsearch":{"command":"secret"}}}"#,
    )
    .unwrap();
    fs::create_dir_all(home.join(".maestro/plugins/convention")).unwrap();
    fs::create_dir_all(home.join(".composer/skills/review")).unwrap();
    fs::write(
        home.join(".composer/skills/review/SKILL.md"),
        "secret skill",
    )
    .unwrap();
    fs::write(
        home.join(".maestro/config.toml"),
        "[mcp_servers.managed]\nurl = 'https://secret.example'\n",
    )
    .unwrap();
    let (clis, servers, assets) = collect_agent_discovery_from(std::slice::from_ref(&home), &[]);
    assert_eq!(
        clis,
        vec![
            DeviceAgentCLI {
                name: "codex".into()
            },
            DeviceAgentCLI {
                name: "cursor".into()
            },
        ]
    );
    assert_eq!(
        servers,
        vec![
            DeviceMCPServer {
                client: "amp".into(),
                name: "db".into(),
                source: ".config/amp/settings.json".into(),
                transport: "stdio".into()
            },
            DeviceMCPServer {
                client: "codex".into(),
                name: "github".into(),
                source: ".codex/config.toml".into(),
                transport: "remote".into()
            },
            DeviceMCPServer {
                client: "cursor".into(),
                name: "docs".into(),
                source: ".cursor/mcp.json".into(),
                transport: "stdio".into()
            },
            DeviceMCPServer {
                client: "gemini".into(),
                name: "search".into(),
                source: ".gemini/extensions/*/gemini-extension.json".into(),
                transport: "unknown".into()
            },
            DeviceMCPServer {
                client: "maestro".into(),
                name: "managed".into(),
                source: ".maestro/config.toml".into(),
                transport: "remote".into()
            },
            DeviceMCPServer {
                client: "maestro".into(),
                name: "pluginsearch".into(),
                source: ".maestro/plugins/*/mcp.json".into(),
                transport: "stdio".into()
            },
        ]
    );
    let serialized = serde_json::to_string(&servers).unwrap();
    assert!(!serialized.contains("secret"));
    assert!(!serialized.contains("/Users/private/work"));
    assert!(!serialized.contains("https://private.example/mcp"));
    assert!(!serialized.contains("C:\\\\Users"));
    assert!(
        assets
            .iter()
            .any(|item| item.client == "codex" && item.kind == "config")
    );
    assert!(
        assets
            .iter()
            .any(|item| item.client == "agents" && item.kind == "skill" && item.name == "review")
    );
    assert!(
        assets
            .iter()
            .any(|item| item.client == "claude" && item.kind == "agent" && item.name == "reviewer")
    );
    assert!(assets.iter().any(|item| item.client == "claude"
        && item.kind == "plugin"
        && item.name == "audit@marketplace"));
    assert!(
        assets
            .iter()
            .any(|item| item.client == "opencode" && item.kind == "plugin" && item.name == "trace")
    );
    assert!(
        assets
            .iter()
            .any(|item| item.client == "maestro" && item.kind == "plugin" && item.name == "audit")
    );
    assert!(
        assets
            .iter()
            .any(|item| item.client == "maestro" && item.kind == "skill" && item.name == "review")
    );
    assert!(assets.iter().any(|item| item.client == "maestro"
        && item.kind == "plugin"
        && item.name == "convention"));
    assert!(!assets.iter().any(|item| item.name == "off@marketplace"));
    assert!(!assets.iter().any(|item| item.name == "not-extension"));
    assert!(
        !assets
            .iter()
            .any(|item| item.client == "pi" && item.name == "review")
    );
    assert!(!serde_json::to_string(&assets).unwrap().contains("secret"));
    fs::remove_file(home.join(".cursor/mcp.json")).unwrap();
    std::os::unix::fs::symlink(
        home.join(".codex/config.toml"),
        home.join(".cursor/mcp.json"),
    )
    .unwrap();
    assert_eq!(collect_agent_discovery_from(&[home], &[]).1.len(), 5);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn user_cursor_and_codex_plugin_probes_validate_files_and_hide_values() {
    let root = tmpdir("user-agent-plugins");
    let home = root.join("home");
    fs::create_dir_all(home.join(".cursor/agents")).unwrap();
    fs::write(home.join(".cursor/agents/reviewer.md"), "private prompt").unwrap();
    fs::write(home.join(".cursor/agents/.hidden.md"), "private prompt").unwrap();
    std::os::unix::fs::symlink(
        home.join(".cursor/agents/reviewer.md"),
        home.join(".cursor/agents/linked.md"),
    )
    .unwrap();
    for plugin in [
        "agent-format",
        "cursor-format",
        "invalid",
        "linked",
        "oversized",
    ] {
        fs::create_dir_all(home.join(".cursor/plugins/local").join(plugin)).unwrap();
    }
    fs::write(
        home.join(".cursor/plugins/local/agent-format/plugin.json"),
        r#"{"name":"agent-format","description":"private"}"#,
    )
    .unwrap();
    fs::create_dir_all(home.join(".cursor/plugins/local/cursor-format/.cursor-plugin")).unwrap();
    fs::write(
        home.join(".cursor/plugins/local/cursor-format/.cursor-plugin/plugin.json"),
        r#"{"name":"cursor-format","url":"https://private.example"}"#,
    )
    .unwrap();
    fs::write(
        home.join(".cursor/plugins/local/invalid/plugin.json"),
        "not json",
    )
    .unwrap();
    std::os::unix::fs::symlink(
        home.join(".cursor/plugins/local/agent-format/plugin.json"),
        home.join(".cursor/plugins/local/linked/plugin.json"),
    )
    .unwrap();
    fs::write(
        home.join(".cursor/plugins/local/oversized/plugin.json"),
        format!(
            "{{\"name\":\"oversized\",\"data\":\"{}\"}}",
            "x".repeat(65 << 10)
        ),
    )
    .unwrap();
    fs::create_dir_all(home.join(".codex")).unwrap();
    fs::write(
        home.join(".codex/config.toml"),
        "[plugins.\"audit@marketplace\"]\nenabled = true\nsecret = 'private'\n[plugins.\"off@marketplace\"]\nenabled = false\n[plugins.\"unset@marketplace\"]\nfoo = true\n[plugins.\"https://private.example/path\"]\nenabled = true\n",
    )
    .unwrap();
    let (_, _, assets) = collect_agent_discovery_from(std::slice::from_ref(&home), &[]);
    for (client, kind, name) in [
        ("cursor", "agent", "reviewer"),
        ("cursor", "plugin", "agent-format"),
        ("cursor", "plugin", "cursor-format"),
        ("codex", "plugin", "audit@marketplace"),
    ] {
        assert!(
            assets
                .iter()
                .any(|asset| asset.client == client && asset.kind == kind && asset.name == name),
            "missing {client}/{kind}/{name}"
        );
    }
    for name in [
        ".hidden",
        "linked",
        "invalid",
        "oversized",
        "off@marketplace",
        "unset@marketplace",
        "https://private.example/path",
    ] {
        assert!(
            !assets.iter().any(|asset| asset.name == name),
            "unexpected {name}"
        );
    }
    let output = serde_json::to_string(&assets).unwrap();
    assert!(!output.contains("private"));
    assert!(!output.contains("https://"));
    assert!(!output.contains("plugin.json"));

    // A symlink in any parent, including the user directory, is rejected.
    let link = root.join("linked-home");
    std::os::unix::fs::symlink(&home, &link).unwrap();
    let (_, _, linked_assets) = collect_agent_discovery_from(&[link], &[]);
    assert!(
        !linked_assets
            .iter()
            .any(|asset| asset.kind == "plugin" && asset.client == "cursor")
    );
    assert!(
        !linked_assets
            .iter()
            .any(|asset| asset.kind == "agent" && asset.client == "cursor")
    );
    assert!(
        !linked_assets
            .iter()
            .any(|asset| asset.kind == "plugin" && asset.client == "codex")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn user_cursor_probe_keeps_asset_and_directory_entry_caps() {
    let root = tmpdir("user-agent-cap");
    let home = root.join("home");
    let agents = home.join(".cursor/agents");
    fs::create_dir_all(&agents).unwrap();
    for index in 0..300 {
        fs::write(agents.join(format!("agent-{index:03}.md")), "private").unwrap();
    }
    let (_, _, assets) = collect_agent_discovery_from(&[home], &[]);
    assert!(assets.len() <= 128);
    assert!(
        assets
            .iter()
            .all(|asset| asset.client == "cursor" && asset.kind == "agent")
    );
    let plugin_home = root.join("plugin-home");
    for index in 0..300 {
        let plugin = plugin_home.join(format!(".cursor/plugins/local/plugin-{index:03}"));
        fs::create_dir_all(&plugin).unwrap();
        fs::write(plugin.join("plugin.json"), "invalid").unwrap();
    }
    let mut plugin_assets = BTreeSet::new();
    let mut manifest_reads = 0;
    collect_cursor_user_assets(&plugin_home, &mut plugin_assets, &mut manifest_reads);
    assert_eq!(manifest_reads, 256);
    assert!(plugin_assets.is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn project_discovery_is_bounded_and_hides_paths_and_values() {
    let root =
        std::env::temp_dir().join(format!("merlin-project-discovery-{}", std::process::id()));
    let project = root.join("team/customer-private");
    fs::create_dir_all(project.join(".cursor")).unwrap();
    fs::create_dir_all(project.join(".opencode")).unwrap();
    fs::create_dir_all(project.join(".agents")).unwrap();
    fs::create_dir_all(project.join(".claude/skills/review")).unwrap();
    fs::create_dir_all(project.join(".maestro/plugins/audit")).unwrap();
    fs::write(
        project.join(".maestro/plugins/audit/mcp.json"),
        r#"{"mcpServers":{"pluginsearch":{"url":"https://private.example/mcp"}}}"#,
    )
    .unwrap();
    fs::write(project.join(".claude/settings.json"), r#"{"enabledPlugins":{"audit@marketplace":true,"off@marketplace":false},"secret":"private-secret"}"#).unwrap();
    fs::write(
        project.join(".cursor/mcp.json"),
        r#"{"mcpServers":{"docs":{"command":"private-secret"}}}"#,
    )
    .unwrap();
    fs::write(
        project.join(".opencode/opencode.json"),
        r#"{"mcp":{"code-search":{"url":"https://private.example/mcp"}},"secret":"private-secret"}"#,
    )
    .unwrap();
    fs::write(
        project.join(".agents/mcp.json"),
        r#"{"mcpServers":{"agent-search":{"command":"private-secret"}}}"#,
    )
    .unwrap();
    fs::write(
        project.join(".claude/skills/review/SKILL.md"),
        "private-secret",
    )
    .unwrap();
    let (servers, assets) = collect_project_agent_discovery(std::slice::from_ref(&root));
    assert!(servers.iter().any(|item| item.name == "docs"
        && item.source == "project/.cursor/mcp.json"
        && item.transport == "stdio"));
    assert!(servers.iter().any(|item| item.name == "pluginsearch"
        && item.source == "project/.maestro/plugins/*/mcp.json"
        && item.transport == "remote"));
    assert!(servers.iter().any(|item| item.client == "opencode"
        && item.name == "code-search"
        && item.source == "project/.opencode/opencode.json"
        && item.transport == "remote"));
    assert!(servers.iter().any(|item| item.client == "agents"
        && item.name == "agent-search"
        && item.source == "project/.agents/mcp.json"
        && item.transport == "stdio"));
    assert!(assets.iter().any(|item| item.client == "opencode"
        && item.kind == "config"
        && item.source == "project/.opencode/opencode.json"));
    assert!(
        assets
            .iter()
            .any(|item| item.name == "review" && item.source == "project/.claude/skills")
    );
    assert!(assets.iter().any(|item| item.name == "audit@marketplace"
        && item.kind == "plugin"
        && item.source == "project/.claude/settings.json"));
    assert!(assets.iter().any(|item| item.name == "audit"
        && item.kind == "plugin"
        && item.source == "project/.maestro/plugins"));
    assert!(!assets.iter().any(|item| item.name == "off@marketplace"));
    let payload = serde_json::to_string(&(servers, assets)).unwrap();
    assert!(!payload.contains("customer-private"));
    assert!(!payload.contains("team"));
    assert!(!payload.contains("private-secret"));
    fs::remove_file(project.join(".cursor/mcp.json")).unwrap();
    std::os::unix::fs::symlink(
        project.join(".claude/skills/review/SKILL.md"),
        project.join(".cursor/mcp.json"),
    )
    .unwrap();
    assert!(
        !collect_project_agent_discovery(std::slice::from_ref(&root))
            .0
            .iter()
            .any(|item| item.name == "docs")
    );
    let outside = tmpdir("project-outside");
    fs::create_dir_all(outside.join(".cursor")).unwrap();
    fs::write(
        outside.join(".cursor/mcp.json"),
        r#"{"mcpServers":{"outside":{"command":"ignored"}}}"#,
    )
    .unwrap();
    std::os::unix::fs::symlink(&outside, root.join("linked-project")).unwrap();
    std::os::unix::fs::symlink(&project, root.join("linked-team")).unwrap();
    assert!(
        !collect_project_agent_discovery(std::slice::from_ref(&root))
            .0
            .iter()
            .any(|item| item.name == "outside")
    );
    assert!(
        collect_project_agent_discovery(&[root.join("linked-team")])
            .0
            .is_empty()
    );
    fs::remove_dir_all(outside).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn project_discovery_caps_descendants_and_depth() {
    let root = tmpdir("project-depth-cap");
    for index in 0..31 {
        fs::create_dir_all(root.join(format!("a{index:02}/deep/.cursor"))).unwrap();
    }
    fs::write(
        root.join("a00/deep/.cursor/mcp.json"),
        r#"{"mcpServers":{"within-cap":{"command":"ignored"}}}"#,
    )
    .unwrap();
    fs::write(
        root.join("a01/deep/.cursor/mcp.json"),
        r#"{"mcpServers":{"past-cap":{"command":"ignored"}}}"#,
    )
    .unwrap();
    fs::create_dir_all(root.join("a00/deep/too-deep/.cursor")).unwrap();
    fs::write(
        root.join("a00/deep/too-deep/.cursor/mcp.json"),
        r#"{"mcpServers":{"past-depth":{"command":"ignored"}}}"#,
    )
    .unwrap();
    assert_eq!(
        project_discovery::project_directory_count(&root, Instant::now() + Duration::from_secs(5),),
        33
    );
    let (servers, _) = collect_project_agent_discovery(std::slice::from_ref(&root));
    assert!(servers.iter().any(|item| item.name == "within-cap"));
    assert!(!servers.iter().any(|item| item.name == "past-cap"));
    assert!(!servers.iter().any(|item| item.name == "past-depth"));
    fs::remove_dir_all(root).unwrap();
}

/// Minimal one-shot HTTP responder: reads one request (headers +
/// content-length body), calls `respond` with (headers, body), writes
/// back the returned raw response.
fn mock_server(respond: impl Fn(Vec<u8>, Vec<u8>) -> String + Send + Sync + 'static) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut headers = Vec::new();
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let trimmed = line.trim_end();
                if trimmed.is_empty() {
                    break;
                }
                if let Some(v) = trimmed.to_ascii_lowercase().strip_prefix("content-length:") {
                    content_length = v.trim().parse().unwrap();
                }
                headers.extend_from_slice(line.as_bytes());
            }
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body).unwrap();
            // This fixture handles one request per accepted connection.
            // Tell HTTP/1.1 clients not to reuse a socket that the fixture
            // drops after writing the response.
            let response =
                respond(headers, body).replacen("\r\n\r\n", "\r\nConnection: close\r\n\r\n", 1);
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
        }
    });
    format!("http://127.0.0.1:{port}")
}

fn ok_response(status: &str) -> String {
    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n")
}

fn signed_policy_envelope(
    sha: &str,
    body: &str,
    signing_seed: u8,
    required_capabilities: &[&str],
    format: &str,
) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let key = ed25519_dalek::SigningKey::from_bytes(&[signing_seed; 32]);
    let payload = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "artifact_sha256": sha,
        "source_policy_sha256": sha,
        "target_platform": "linux",
        "target_agent_version": env!("CARGO_PKG_VERSION"),
        "required_capabilities": required_capabilities,
        "format": format,
        "artifact": base64::engine::general_purpose::STANDARD.encode(body.as_bytes()),
    }))
    .unwrap();
    let mut signed = POLICY_ENVELOPE_DOMAIN.to_vec();
    signed.extend_from_slice(&payload);
    let envelope = serde_json::json!({
        "schema_version": 1,
        "signed_payload": base64::engine::general_purpose::STANDARD.encode(&payload),
        "signatures": [{
            "key_id": policy_public_key_id(&key.verifying_key().to_bytes()),
            "algorithm": "Ed25519",
            "value": base64::engine::general_purpose::STANDARD.encode(key.sign(&signed).to_bytes()),
        }],
    });
    serde_json::to_vec(&envelope).unwrap()
}

fn rules_response(sha: &str, body: &str, signing_seed: u8) -> String {
    let response_body =
        signed_policy_envelope(sha, body, signing_seed, &["rules_sync"], "application/yaml");
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.merlin.policy-envelope+json\r\nContent-Length: {}\r\n\r\n{}",
        response_body.len(),
        String::from_utf8(response_body).unwrap()
    )
}

fn tmpdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("merlin-sync-test-{}-{tag}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn test_client(base: &str, dir: &Path) -> SyncClient {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let client = SyncClient::new(
        SyncConfig {
            base_url: base.to_string(),
            key: b"test-key".to_vec(),
            device_id: Some("dev_0123456789abcdef01234567".to_string()),
            device_token: Some("enrollment-token".to_string()),
            policy_public_key: signing_key.verifying_key().to_bytes().to_vec(),
            policy_public_keys: vec![],
            sensor_mode: "test".to_string(),
        },
        dir.join("merlin-events.jsonl"),
        &dir.join("rules.yaml"),
        RulesHandle::new(Rules {
            schema_version: 1,
            rules: vec![],
            doh_resolvers: vec![],
        }),
        "deadbeef".to_string(),
    );
    // Most tests upload segments named in 2026-08; enrollment rules have
    // their own tests below.
    let mut client = client;
    client.not_before = None;
    client
}

fn write_segment(dir: &Path, name: &str, lines: &str) -> PathBuf {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    let path = dir.join(name);
    let mut out = fs::File::create(&path).unwrap();
    {
        let mut enc = GzEncoder::new(&mut out, Compression::default());
        enc.write_all(lines.as_bytes()).unwrap();
        enc.finish().unwrap();
    }
    out.sync_all().unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    // Age it past the mid-compression guard.
    let cpath = std::ffi::CString::new(path.display().to_string()).unwrap();
    let past = libc::timespec {
        tv_sec: 1000,
        tv_nsec: 0,
    };
    let times = [past, past];
    unsafe { libc::utimensat(libc::AT_FDCWD, cpath.as_ptr(), times.as_ptr(), 0) };
    path
}

#[test]
fn key_parsing_hex_base64_raw() {
    assert_eq!(parse_key(&"ab".repeat(32)), vec![0xab; 32]);
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(b"hello-key");
    assert_eq!(parse_key(&b64), b"hello-key");
    assert_eq!(parse_key("raw key with spaces"), b"raw key with spaces");
    assert_eq!(sync_auth_header(b"raw key"), "Bearer 726177206b6579");
}

#[test]
fn signed_policy_accepts_every_advertised_desired_state_capability() {
    let body = "rules: []\ndesired_state:\n  schema: desired_state.v1\n  revision: 1\n  target: {platform: linux}\n  assertions:\n    - assertion_id: screen-lock\n      security.screen_lock: {enabled: true, idle_seconds: 300}\n";
    let sha = sha256_hex(body.as_bytes());
    let required_capabilities = std::iter::once("rules_sync")
        .chain(desired_state::CAPABILITIES.iter().copied())
        .collect::<Vec<_>>();
    let envelope = signed_policy_envelope(
        &sha,
        body,
        7,
        &required_capabilities,
        desired_state::ARTIFACT_FORMAT,
    );
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32])
        .verifying_key()
        .to_bytes()
        .to_vec();

    let verified = decode_policy_envelope(&envelope, Some(&sha), std::iter::once(key))
        .expect("the agent must accept every capability it advertises");

    assert_eq!(verified.artifact, body.as_bytes());
    assert_eq!(verified.format, desired_state::ARTIFACT_FORMAT);

    let unreviewed = signed_policy_envelope(
        &sha,
        body,
        7,
        &["rules_sync", "desired_state.v1", "executor.shell"],
        desired_state::ARTIFACT_FORMAT,
    );
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32])
        .verifying_key()
        .to_bytes()
        .to_vec();
    let error = decode_policy_envelope(&unreviewed, Some(&sha), std::iter::once(key))
        .err()
        .expect("unreviewed executors must stay outside the protocol");
    assert!(error.to_string().contains("unsupported capability"));
}

#[test]
fn backoff_grows_and_caps() {
    assert_eq!(backoff_secs(0), 2);
    assert!(backoff_secs(1) > backoff_secs(0));
    assert!(backoff_secs(2) > backoff_secs(1));
    assert_eq!(backoff_secs(30), 60);
}

#[test]
fn upload_acks_and_deletes_after_2xx() {
    let dir = tmpdir("ack");
    let base = mock_server(|headers: Vec<u8>, _| {
        let headers = String::from_utf8_lossy(&headers);
        assert!(headers.starts_with("POST /v1/devices/dev_0123456789abcdef01234567/events "));
        let has_auth = headers.lines().any(|line| {
            let Some((name, value)) = line.split_once(':') else {
                return false;
            };
            name.eq_ignore_ascii_case("authorization") && value.trim() == "Bearer enrollment-token"
        });
        assert!(
            has_auth,
            "upload request is missing its bearer authorization header"
        );
        ok_response("202 Accepted")
    });
    let client = test_client(&base, &dir);
    let seg = write_segment(
        &dir,
        "merlin-events.20260802-010203.jsonl.gz",
        "{\"kind\":\"exec\"}\n",
    );
    client.upload_pending().unwrap();
    assert!(!seg.exists(), "acked segment must be deleted");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_permanently_rejected_segment_is_quarantined_and_later_ones_still_upload() {
    let dir = tmpdir("reject");
    let base = mock_server(|headers: Vec<u8>, _| {
        let headers = String::from_utf8_lossy(&headers).to_string();
        if headers.contains("20260802-010203") {
            ok_response("400 Bad Request")
        } else {
            ok_response("202 Accepted")
        }
    });
    let client = test_client(&base, &dir);
    let bad = write_segment(
        &dir,
        "merlin-events.20260802-010203.jsonl.gz",
        "{\"kind\":\"exec\"}\n",
    );
    let good = write_segment(
        &dir,
        "merlin-events.20260802-020304.jsonl.gz",
        "{\"kind\":\"exec\"}\n",
    );
    client.upload_pending().unwrap();
    assert!(!bad.exists() && !good.exists());
    assert!(
        dir.join("quarantine/rejected/merlin-events.20260802-010203.jsonl.gz")
            .exists()
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_retryable_status_keeps_the_segment_and_stops_the_pass() {
    for status in [
        "503 Service Unavailable",
        "429 Too Many Requests",
        "408 Request Timeout",
        "401 Unauthorized",
        "403 Forbidden",
        "404 Not Found",
    ] {
        let dir = tmpdir("retry");
        let base = mock_server(move |_, _| ok_response(status));
        let client = test_client(&base, &dir);
        let seg = write_segment(
            &dir,
            "merlin-events.20260802-010203.jsonl.gz",
            "{\"kind\":\"exec\"}\n",
        );
        assert!(client.upload_pending().is_err(), "{status}");
        assert!(seg.exists(), "{status} keeps the segment");
        assert!(
            !dir.join("quarantine").exists(),
            "{status} never quarantines"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}

#[test]
fn segments_recorded_before_enrollment_never_upload() {
    let dir = tmpdir("pre-enroll");
    let base = mock_server(|headers: Vec<u8>, _| {
        let headers = String::from_utf8_lossy(&headers).to_string();
        assert!(
            !headers.contains("20260802-010203"),
            "a pre-enrollment segment was uploaded"
        );
        ok_response("202 Accepted")
    });
    let mut client = test_client(&base, &dir);
    client.not_before = segment_unix_secs("merlin-events.20260802-120000.jsonl.gz");
    let before = write_segment(
        &dir,
        "merlin-events.20260802-010203.jsonl.gz",
        "{\"kind\":\"exec\"}\n",
    );
    let after = write_segment(
        &dir,
        "merlin-events.20260802-130000.jsonl.gz",
        "{\"kind\":\"exec\"}\n",
    );
    client.upload_pending().unwrap();
    assert!(!before.exists() && !after.exists());
    assert!(
        dir.join("quarantine/pre-enrollment/merlin-events.20260802-010203.jsonl.gz")
            .exists()
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn the_device_marker_keeps_its_start_and_resets_for_another_identity() {
    let dir = tmpdir("marker");
    fs::write(
        dir.join(DEVICE_MARKER),
        "dev_0123456789abcdef01234567 1000\n",
    )
    .unwrap();
    let same = test_client("http://127.0.0.1:9", &dir).with_device_marker();
    assert_eq!(same.not_before, Some(1000));
    fs::write(dir.join(DEVICE_MARKER), "dev_someoneelse 1000\n").unwrap();
    let other = test_client("http://127.0.0.1:9", &dir).with_device_marker();
    assert!(
        other.not_before.is_some_and(|t| t > 1000),
        "a different identity starts over"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn the_pending_spool_is_capped_by_evicting_the_oldest() {
    let dir = tmpdir("cap");
    let base = mock_server(|_, _| ok_response("503 Service Unavailable"));
    let mut client = test_client(&base, &dir);
    let line = "{\"kind\":\"exec\",\"pad\":\"".to_string() + &"x".repeat(4096) + "\"}\n";
    let old = write_segment(&dir, "merlin-events.20260802-010000.jsonl.gz", &line);
    let mid = write_segment(&dir, "merlin-events.20260802-020000.jsonl.gz", &line);
    let new = write_segment(&dir, "merlin-events.20260802-030000.jsonl.gz", &line);
    let one = fs::metadata(&new).unwrap().len();
    client.spool_max_bytes = one * 2;
    let _ = client.upload_pending();
    assert!(!old.exists(), "the oldest segment is evicted");
    assert!(mid.exists() && new.exists(), "newer segments stay");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn segment_names_parse_to_unix_seconds_in_order() {
    let a = segment_unix_secs("merlin-events.20261108-230746.jsonl.gz").unwrap();
    let b = segment_unix_secs("merlin-events.20261108-230812.jsonl").unwrap();
    assert_eq!(b - a, 26);
    assert_eq!(segment_unix_secs("merlin-events.jsonl"), None);
    assert_eq!(
        segment_unix_secs("merlin-events.2026110-230746.jsonl.gz"),
        None
    );
}

#[test]
fn upload_failure_keeps_segment() {
    let dir = tmpdir("fail");
    let base = mock_server(|_, _| ok_response("500 Internal Server Error"));
    let client = test_client(&base, &dir);
    let seg = write_segment(
        &dir,
        "merlin-events.20260802-010203.jsonl.gz",
        "{\"kind\":\"exec\"}\n",
    );
    assert!(client.upload_pending().is_err());
    assert!(seg.exists(), "failed upload keeps the segment");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn check_in_sends_device_identity_and_accepts_empty_queue() {
    let dir = tmpdir("check-in");
    let base = mock_server(|headers, body| {
        let headers = String::from_utf8_lossy(&headers);
        assert!(headers.lines().any(|line| {
            let Some((name, value)) = line.split_once(':') else {
                return false;
            };
            name.eq_ignore_ascii_case("authorization") && value.trim() == "Bearer enrollment-token"
        }));
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["host"].as_str(), Some("test-host"));
        assert_eq!(body["platform"].as_str(), Some("linux"));
        assert_eq!(body["current_rules_sha256"].as_str(), Some("deadbeef"));
        assert!(body["os_info"].is_object());
        assert_eq!(
            body["os_info"]["architecture"].as_str(),
            Some(std::env::consts::ARCH)
        );
        assert_eq!(
            body["os_info"]["load_average"].as_array().map(Vec::len),
            Some(3)
        );
        assert!(body["os_info"]["os_pretty_name"].is_string());
        assert!(body["os_info"]["cpu_model"].is_string());
        assert!(body["os_info"]["network_interface_details"].is_array());
        assert_eq!(
            body["manifest_version"].as_u64(),
            Some(u64::from(crate::manifest::MANIFEST_VERSION))
        );
        let active: Vec<&str> = body["active_collectors"]
            .as_array()
            .expect("active_collectors")
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        let every: Vec<&str> = crate::manifest::COLLECTORS.iter().map(|c| c.id).collect();
        assert_eq!(
            active, every,
            "the Linux agent runs every collector it declares"
        );
        posture_wire_tests::assert_linux_posture(&body["posture"]);
        posture_wire_tests::assert_linux_hardening(&body["hardening"]);
        let response_body = br#"{"pending_update":null}"#;
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            response_body.len(),
            String::from_utf8_lossy(response_body)
        )
    });
    let mut client = test_client(&base, &dir);
    client.host = "test-host".to_string();
    client.cfg.device_id = Some("dev_0123456789abcdef01234567".to_string());
    client.cfg.device_token = Some("enrollment-token".to_string());
    client.check_in().unwrap();
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn check_in_applies_and_acknowledges_queued_rules_update() {
    let dir = tmpdir("check-in-update");
    let rules_body = "rules:\n  - name: queued-update\n    action: log\n";
    let target_sha = sha256_hex(rules_body.as_bytes());
    let response_sha = target_sha.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_server = Arc::clone(&calls);
    let base = mock_server(
        move |_, body| match calls_for_server.fetch_add(1, Ordering::Relaxed) {
            0 => {
                let response_body = format!(
                    "{{\"pending_update\":{{\"update_id\":\"upd_0123456789abcdef01234567\",\"kind\":\"rules\",\"target_rules_sha256\":\"{response_sha}\"}}}}"
                );
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    response_body.len(),
                    response_body
                )
            }
            1 => rules_response(&response_sha, rules_body, 7),
            2 => {
                let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(body["status"].as_str(), Some("applied"));
                assert_eq!(body["rules_sha256"].as_str(), Some(response_sha.as_str()));
                ok_response("200 OK")
            }
            call => panic!("unexpected sync request {call}"),
        },
    );
    let mut client = test_client(&base, &dir);
    client.cfg.device_id = Some("dev_0123456789abcdef01234567".to_string());
    client.cfg.device_token = Some("enrollment-token".to_string());
    client.check_in().unwrap();
    assert_eq!(client.current_sha, target_sha);
    assert_eq!(calls.load(Ordering::Relaxed), 3);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "requires MERLIN_E2E_BASE_URL, device credentials, and a live server"]
fn device_lifecycle_against_live_server_on_linux() {
    let base = std::env::var("MERLIN_E2E_BASE_URL").expect("MERLIN_E2E_BASE_URL");
    let device_id = std::env::var("MERLIN_E2E_DEVICE_ID").expect("MERLIN_E2E_DEVICE_ID");
    let device_token = std::env::var("MERLIN_E2E_DEVICE_TOKEN").expect("MERLIN_E2E_DEVICE_TOKEN");
    let admin_token = std::env::var("MERLIN_E2E_ADMIN_TOKEN").expect("MERLIN_E2E_ADMIN_TOKEN");
    let key = parse_key(&std::env::var("MERLIN_E2E_SYNC_KEY").expect("MERLIN_E2E_SYNC_KEY"));
    let dir = tmpdir("live-device-lifecycle");
    let ca_pem = fs::read(std::env::var("MERLIN_E2E_CA_CERT").expect("MERLIN_E2E_CA_CERT"))
        .expect("read E2E CA certificate");
    let ca = ureq::tls::Certificate::from_pem(&ca_pem).expect("parse E2E CA certificate");
    let e2e_agent: ureq::Agent = ureq::Agent::config_builder()
        .tls_config(
            ureq::tls::TlsConfig::builder()
                .root_certs(ureq::tls::RootCerts::new_with_certs(&[ca]))
                .build(),
        )
        .build()
        .into();
    let mut client = SyncClient::new(
        SyncConfig {
            base_url: base.trim_end_matches('/').to_string(),
            key,
            device_id: Some(device_id.clone()),
            device_token: Some(device_token),
            policy_public_key: parse_key(
                &std::env::var("MERLIN_E2E_POLICY_PUBLIC_KEY")
                    .expect("MERLIN_E2E_POLICY_PUBLIC_KEY"),
            ),
            policy_public_keys: vec![],
            sensor_mode: "test".to_string(),
        },
        dir.join("merlin-events.jsonl"),
        &dir.join("rules.yaml"),
        RulesHandle::new(Rules {
            schema_version: 1,
            rules: vec![],
            doh_resolvers: vec![],
        }),
        "0".repeat(64),
    );
    client.agent = e2e_agent.clone();

    let expected_host = hostname();
    assert!(!expected_host.is_empty());
    let segment = write_segment(
        &dir,
        "merlin-events.20260817-000000.jsonl.gz",
        "{\"schema_version\":1,\"boot_id\":\"managed-e2e\",\"event_id\":\"managed-e2e:1\",\"source\":\"linux-e2e\",\"source_seq\":1,\"kind\":\"exec\"}\n",
    );
    client.upload_pending().expect("live HTTPS segment upload");
    assert!(
        !segment.exists(),
        "server acknowledgement must delete the uploaded segment"
    );
    client.check_in().expect("initial live check-in");

    let admin_auth = format!("Bearer {admin_token}");
    let mut queued = e2e_agent
        .post(&format!(
            "{}/v1/admin/devices/{device_id}/updates",
            base.trim_end_matches('/')
        ))
        .header("Authorization", &admin_auth)
        .send(&[])
        .expect("queue live device update");
    let queued_body = queued.body_mut().read_to_vec().expect("read queued update");
    let queued_json: serde_json::Value =
        serde_json::from_slice(&queued_body).expect("decode queued update");
    let target_sha = queued_json["update"]["target_rules_sha256"]
        .as_str()
        .expect("queued target sha")
        .to_string();
    assert_ne!(target_sha, "0".repeat(64));

    client
        .check_in()
        .expect("live check-in applies and acknowledges policy update");
    assert_eq!(client.current_sha, target_sha);
    assert!(client.synced_marker.exists());

    let mut detail = e2e_agent
        .get(&format!(
            "{}/v1/admin/devices/{device_id}",
            base.trim_end_matches('/')
        ))
        .header("Authorization", &admin_auth)
        .call()
        .expect("read live device detail");
    let detail_body = detail
        .body_mut()
        .read_to_vec()
        .expect("read live device detail");
    let detail_json: serde_json::Value =
        serde_json::from_slice(&detail_body).expect("decode live device detail");
    let device = &detail_json["device"];
    assert_eq!(device["host"].as_str(), Some(expected_host.as_str()));
    assert_eq!(device["platform"].as_str(), Some("linux"));
    assert_eq!(
        device["agent_version"].as_str(),
        Some(env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(device["status"].as_str(), Some("healthy"));
    assert_eq!(
        device["capabilities"].as_array(),
        Some(&vec![
            serde_json::Value::String("segment_upload".to_string()),
            serde_json::Value::String("rules_sync".to_string()),
            serde_json::Value::String("system_inventory".to_string()),
            serde_json::Value::String("file_integrity".to_string()),
            serde_json::Value::String("security_configuration_assessment".to_string()),
            serde_json::Value::String("rootcheck".to_string()),
            serde_json::Value::String("container_inventory".to_string()),
            serde_json::Value::String("cloud_inventory".to_string()),
            serde_json::Value::String("posture_reporting".to_string()),
            serde_json::Value::String("linux_boot_trust_posture".to_string()),
            serde_json::Value::String("desired_state.v1".to_string()),
            serde_json::Value::String("executor.apt".to_string()),
            serde_json::Value::String("executor.systemd".to_string()),
            serde_json::Value::String("executor.sysctl".to_string()),
        ])
    );
    assert!(detail_json["inventory"]["processes"].is_array());
    assert_eq!(
        device["current_rules_sha256"].as_str(),
        Some(target_sha.as_str())
    );
    assert_eq!(detail_json["updates"][0]["kind"].as_str(), Some("rules"));
    assert_eq!(
        detail_json["updates"][0]["status"].as_str(),
        Some("applied")
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn rules_applied_only_with_valid_signature() {
    let dir = tmpdir("apply");
    let body =
        "rules:\n  - name: synced-marker\n    match:\n      path_basename: x\n    action: log\n";
    let sha = sha256_hex(body.as_bytes());
    let base = mock_server(move |_, _| rules_response(&sha, body, 7));
    let mut client = test_client(&base, &dir);
    assert!(client.sync_rules(&sha256_hex(body.as_bytes())).unwrap());
    assert_eq!(client.handle.get().rules.len(), 1);
    assert_eq!(client.handle.get().rules[0].name, "synced-marker");
    assert!(client.synced_marker.exists());
    let mode = fs::metadata(&client.synced_marker).unwrap().permissions();
    assert_eq!(mode.mode() & 0o777, 0o600);
    let (cached, cached_sha) = load_cached_policy(&client.cfg, &dir.join("rules.yaml"))
        .unwrap()
        .expect("verified cached policy");
    assert_eq!(cached_sha, sha256_hex(body.as_bytes()));
    assert_eq!(cached.rules[0].name, "synced-marker");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn missing_cached_policy_keeps_bootstrap_rules() {
    let dir = tmpdir("cache-missing");
    let client = test_client("http://127.0.0.1:1", &dir);
    assert!(
        load_cached_policy(&client.cfg, &dir.join("rules.yaml"))
            .unwrap()
            .is_none()
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn tampered_cached_policy_is_rejected_on_offline_restart() {
    let dir = tmpdir("cached-tamper");
    let body = "rules:\n  - name: cached\n    action: log\n";
    let sha = sha256_hex(body.as_bytes());
    let base = mock_server(move |_, _| rules_response(&sha, body, 7));
    let mut client = test_client(&base, &dir);
    assert!(client.sync_rules(&sha256_hex(body.as_bytes())).unwrap());
    let mut envelope = fs::read(&client.synced_marker).unwrap();
    let middle = envelope.len() / 2;
    envelope[middle] ^= 1;
    fs::write(&client.synced_marker, envelope).unwrap();
    fs::set_permissions(&client.synced_marker, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(load_cached_policy(&client.cfg, &dir.join("rules.yaml")).is_err());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn rotation_window_accepts_new_trusted_key() {
    let dir = tmpdir("key-rotation");
    let body = "rules:\n  - name: rotated-key\n    action: log\n";
    let sha = sha256_hex(body.as_bytes());
    let base = mock_server(move |_, _| rules_response(&sha, body, 8));
    let mut client = test_client(&base, &dir);
    client.cfg.policy_public_keys.push(
        ed25519_dalek::SigningKey::from_bytes(&[8; 32])
            .verifying_key()
            .to_bytes()
            .to_vec(),
    );
    assert!(client.sync_rules(&sha256_hex(body.as_bytes())).unwrap());
    assert_eq!(client.handle.get().rules[0].name, "rotated-key");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn rules_rejected_on_bad_signature_and_bad_yaml() {
    let dir = tmpdir("reject");
    let good_body =
        "rules:\n  - name: keepme\n    match:\n      path_basename: x\n    action: log\n";
    let sha = sha256_hex(good_body.as_bytes());
    // Wrong key signs the response.
    let base = mock_server(move |_, _| rules_response(&sha, good_body, 8));
    let mut client = test_client(&base, &dir);
    assert!(
        client
            .sync_rules(&sha256_hex(good_body.as_bytes()))
            .is_err()
    );
    assert!(
        client.handle.get().rules.is_empty(),
        "unverified rules must not apply"
    );

    // Valid signature, unparsable YAML: last-known-good preserved.
    let garbage = "rules: [not, valid";
    let garbage_sha = sha256_hex(garbage.as_bytes());
    let base2 = mock_server(move |_, _| rules_response(&garbage_sha, garbage, 7));
    let mut client2 = test_client(&base2, &dir);
    assert!(!client2.sync_rules(&sha256_hex(garbage.as_bytes())).unwrap());
    assert!(client2.handle.get().rules.is_empty());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn the_enrollment_time_starts_the_spool_when_recorded_and_never_in_the_future() {
    assert_eq!(enrollment_start(Some("1000"), 5000), 1000);
    assert_eq!(enrollment_start(Some(" 1000\n"), 5000), 1000);
    assert_eq!(enrollment_start(None, 5000), 5000);
    assert_eq!(enrollment_start(Some("not-a-time"), 5000), 5000);
    assert_eq!(
        enrollment_start(Some("9999"), 5000),
        5000,
        "a future time is ignored"
    );
}

#[test]
fn only_statuses_that_read_and_refused_the_bytes_are_permanent() {
    for status in [400, 413, 415, 422] {
        assert!(permanent_rejection(status), "{status}");
    }
    for status in [401, 403, 404, 408, 409, 429, 500, 502, 503] {
        assert!(!permanent_rejection(status), "{status}");
    }
}

#[test]
fn a_replayed_segment_is_quarantined_but_other_conflicts_keep_the_data() {
    let dir = tmpdir("replay");
    let base = mock_server(|headers: Vec<u8>, _| {
        let headers = String::from_utf8_lossy(&headers).to_string();
        let body = if headers.contains("20260802-010203") {
            r#"{"error":"telemetry sequence replay"}"#
        } else {
            r#"{"error":"device re-enrollment required before telemetry upload"}"#
        };
        format!(
            "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    });
    let client = test_client(&base, &dir);
    let replayed = write_segment(
        &dir,
        "merlin-events.20260802-010203.jsonl.gz",
        "{\"kind\":\"exec\"}\n",
    );
    let kept = write_segment(
        &dir,
        "merlin-events.20260802-020304.jsonl.gz",
        "{\"kind\":\"exec\"}\n",
    );
    assert!(
        client.upload_pending().is_err(),
        "re-enrollment required backs off"
    );
    assert!(!replayed.exists());
    assert!(
        dir.join("quarantine/replay/merlin-events.20260802-010203.jsonl.gz")
            .exists()
    );
    assert!(kept.exists(), "a non-replay conflict keeps the segment");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn only_the_replay_body_counts_as_a_replay() {
    assert!(is_sequence_replay(
        r#"{"error":"telemetry sequence replay"}"#
    ));
    assert!(!is_sequence_replay(
        r#"{"error":"device re-enrollment required before telemetry upload"}"#
    ));
    assert!(!is_sequence_replay("telemetry sequence replay"));
    assert!(!is_sequence_replay(""));
}
