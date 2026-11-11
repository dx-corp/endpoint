use super::*;

#[test]
fn claude_plugin_cache_reports_installed_plugins_their_servers_and_skills() {
    let root = tmpdir("claude-plugin-cache");
    let home = root.join("home");
    let cache = home.join(".claude/plugins/cache");
    let location = AI_LOCATIONS
        .iter()
        .find(|location| location.format == Format::ClaudePluginCache)
        .unwrap();
    let current = cache.join("official/deploy-tools/1.2.0");
    fs::create_dir_all(current.join("skills/deploy")).unwrap();
    fs::write(current.join("skills/deploy/SKILL.md"), "private-secret").unwrap();
    // A skill directory without a SKILL.md, and one whose SKILL.md is a link.
    fs::create_dir_all(current.join("skills/notes")).unwrap();
    fs::create_dir_all(current.join("skills/linked")).unwrap();
    std::os::unix::fs::symlink(
        current.join("skills/deploy/SKILL.md"),
        current.join("skills/linked/SKILL.md"),
    )
    .unwrap();
    fs::write(
        current.join(".mcp.json"),
        r#"{"mcpServers":{"deploy-api":{"command":"private-secret"}},"servers":{"docs":{"url":"https://private-secret"}}}"#,
    )
    .unwrap();
    fs::create_dir_all(current.join(".claude-plugin")).unwrap();
    fs::write(
        current.join(".claude-plugin/plugin.json"),
        r#"{"name":"deploy-tools","mcpServers":{"inline-api":{"command":"node","args":["private-secret"]}}}"#,
    )
    .unwrap();
    // A manifest whose mcpServers names a file adds nothing by itself.
    let pathed = cache.join("official/pathed/2.0.0/.claude-plugin");
    fs::create_dir_all(&pathed).unwrap();
    fs::write(
        pathed.join("plugin.json"),
        r#"{"name":"pathed","mcpServers":"./mcp/servers.json"}"#,
    )
    .unwrap();
    // A version Claude Code replaced: it waits for deletion and is not loaded.
    let replaced = cache.join("official/stale-tool/0.9.0");
    fs::create_dir_all(replaced.join("skills/old")).unwrap();
    fs::write(replaced.join("skills/old/SKILL.md"), "x").unwrap();
    fs::write(replaced.join(".orphaned_at"), "1700000000000").unwrap();
    fs::write(replaced.join(".mcp.json"), r#"{"mcpServers":{"old":{}}}"#).unwrap();
    // A marketplace that is a link is not followed.
    let outside = root.join("outside/linked-tool/1.0.0");
    fs::create_dir_all(&outside).unwrap();
    fs::write(
        outside.join(".mcp.json"),
        r#"{"mcpServers":{"outside":{}}}"#,
    )
    .unwrap();
    std::os::unix::fs::symlink(root.join("outside"), cache.join("linked")).unwrap();

    let RootScan {
        mcp_servers: servers,
        agent_assets: assets,
        ..
    } = collect_agent_discovery_from(std::slice::from_ref(&home), &[]);
    let label = location.label();
    let found: BTreeSet<(String, String, String)> = assets
        .iter()
        .filter(|asset| asset.source.starts_with(&label))
        .map(|asset| (asset.kind.clone(), asset.name.clone(), asset.source.clone()))
        .collect();
    assert_eq!(
        found,
        BTreeSet::from([
            ("plugin".into(), "pathed".into(), label.clone()),
            ("plugin".into(), "deploy-tools".into(), label.clone()),
            (
                "skill".into(),
                "deploy-tools:deploy".into(),
                format!("{label}/*/skills")
            ),
        ])
    );
    let servers: BTreeSet<(String, String, String)> = servers
        .iter()
        .filter(|server| server.source.starts_with(&label))
        .map(|server| {
            (
                server.name.clone(),
                server.source.clone(),
                server.transport.clone(),
            )
        })
        .collect();
    let mcp_label = format!("{label}/*/.mcp.json");
    let manifest_label = format!("{label}/*/.claude-plugin/plugin.json");
    assert_eq!(
        servers,
        BTreeSet::from([
            ("inline-api".into(), manifest_label, "stdio".into()),
            ("deploy-api".into(), mcp_label.clone(), "stdio".into()),
            ("docs".into(), mcp_label, "remote".into()),
        ])
    );
    let payload = serde_json::to_string(&(&assets, &servers)).unwrap();
    assert!(!payload.contains("private-secret"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_full_asset_list_still_reports_plugin_cache_mcp_servers() {
    let root = tmpdir("claude-plugin-cache-full-assets");
    let home = root.join("home");
    // More skills than the asset cap, read before the plugin cache.
    for index in 0..MAX_AGENT_FINDINGS + 12 {
        let skill = home.join(format!(".claude/skills/s{index:03}"));
        fs::create_dir_all(&skill).unwrap();
        fs::write(skill.join("SKILL.md"), "x").unwrap();
    }
    let version = home.join(".claude/plugins/cache/official/slack/1.0.0");
    fs::create_dir_all(&version).unwrap();
    fs::write(
        version.join(".mcp.json"),
        r#"{"mcpServers":{"slack":{"type":"http","url":"https://mcp.slack.com/mcp?token=private-secret"}}}"#,
    )
    .unwrap();
    let gemini = home.join(".gemini/extensions/notes");
    fs::create_dir_all(&gemini).unwrap();
    fs::write(
        gemini.join("gemini-extension.json"),
        r#"{"mcpServers":{"notes":{"command":"npx","args":["-y","notes-mcp","--key","private-secret"]}}}"#,
    )
    .unwrap();

    let RootScan {
        mcp_servers: servers,
        agent_assets: assets,
        ..
    } = collect_agent_discovery_from(std::slice::from_ref(&home), &[]);
    assert!(assets.len() <= MAX_AGENT_FINDINGS, "the asset cap holds");
    let names: BTreeSet<(&str, &str)> = servers
        .iter()
        .map(|server| (server.name.as_str(), server.source.as_str()))
        .collect();
    assert!(
        names.contains(&("slack", ".claude/plugins/cache/*/.mcp.json")),
        "{names:?}"
    );
    assert!(
        names.contains(&("notes", ".gemini/extensions/*/gemini-extension.json")),
        "{names:?}"
    );
    let payload = serde_json::to_string(&servers).unwrap();
    assert!(!payload.contains("private-secret"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn claude_plugin_cache_walk_stops_at_its_directory_budget() {
    let root = tmpdir("claude-plugin-cache-budget");
    let home = root.join("home");
    // 300 marketplaces with one empty directory each: more than the budget.
    for index in 0..300 {
        fs::create_dir_all(home.join(format!(".claude/plugins/cache/m{index:03}/p"))).unwrap();
    }
    let location = AI_LOCATIONS
        .iter()
        .find(|location| location.format == Format::ClaudePluginCache)
        .unwrap();
    let mut opened = 0;
    collect_claude_plugin_cache(
        &home,
        location,
        (&mut BTreeSet::new(), &mut BTreeSet::new()),
        &mut opened,
        &mut ContentScan::new(),
    );
    assert_eq!(opened, MAX_CLAUDE_CACHE_DIRS);
    fs::remove_dir_all(root).unwrap();
}
