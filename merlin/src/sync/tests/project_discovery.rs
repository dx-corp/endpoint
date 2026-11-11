use super::*;

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
        r#"{"mcpServers":{"docs":{"command":"node","args":["private-secret"]}}}"#,
    )
    .unwrap();
    fs::write(
        project.join(".opencode/opencode.json"),
        r#"{"mcp":{"code-search":{"url":"https://private.example/mcp"}},"secret":"private-secret"}"#,
    )
    .unwrap();
    fs::write(
        project.join(".agents/mcp.json"),
        r#"{"mcpServers":{"agent-search":{"command":"node","args":["private-secret"]}}}"#,
    )
    .unwrap();
    fs::write(
        project.join(".claude/skills/review/SKILL.md"),
        "private-secret",
    )
    .unwrap();
    let (servers, assets) =
        collect_project_agent_discovery(std::slice::from_ref(&root), &mut Vec::new());
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
        !collect_project_agent_discovery(std::slice::from_ref(&root), &mut Vec::new())
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
        !collect_project_agent_discovery(std::slice::from_ref(&root), &mut Vec::new())
            .0
            .iter()
            .any(|item| item.name == "outside")
    );
    assert!(
        collect_project_agent_discovery(&[root.join("linked-team")], &mut Vec::new())
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
        crate::sync::project_discovery::project_directory_count(
            &root,
            Instant::now() + Duration::from_secs(5),
        ),
        33
    );
    let (servers, _) =
        collect_project_agent_discovery(std::slice::from_ref(&root), &mut Vec::new());
    assert!(servers.iter().any(|item| item.name == "within-cap"));
    assert!(!servers.iter().any(|item| item.name == "past-cap"));
    assert!(!servers.iter().any(|item| item.name == "past-depth"));
    fs::remove_dir_all(root).unwrap();
}
