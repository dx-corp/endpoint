use super::*;
use crate::ai_discovery::{DeviceMCPServer, json_mcp_entries, keep_valid_mcp_facts};
use crate::manifest::AI_CONTENT_RULES;

/// A made-up GitHub token: the right shape and enough entropy, no account.
/// Split with `concat!` so the source never holds a whole token: the public
/// projection rejects any file that does.
const TOKEN: &str = concat!("ghp", "_Zx8kQ2mNv7Rt4Lp9Wc3Hb6Jd1Fg5Ys0Ea2Uo");

#[test]
fn every_declared_gitleaks_rule_and_allowlist_compiles() {
    let engine = engine().expect("the gitleaks rules compile");
    let declared = AI_CONTENT_RULES
        .iter()
        .filter(|rule| rule.engine == "gitleaks")
        .count();
    // gitleaks v8.30.1 has 222 rules; five are scoped to a repository path
    // (one of them, pkcs12-file, has no regex).
    assert_eq!(declared, 217);
    assert_eq!(engine.rules.len(), declared);
    assert_eq!(GITLEAKS_RULES.len(), declared);
}

#[test]
fn a_token_in_an_mcp_entry_is_reported_by_rule_id_only() {
    let config = format!(
        r#"{{"mcpServers":{{"github":{{"command":"npx","args":["-y","@modelcontextprotocol/server-github"],"env":{{"GITHUB_PERSONAL_ACCESS_TOKEN":"{TOKEN}"}}}},"docs":{{"url":"https://docs.example.com/mcp"}}}}}}"#
    );
    let entries = json_mcp_entries(&config, &["mcpServers"]);
    let rules: Vec<_> = entries
        .iter()
        .map(|entry| (entry.name.as_str(), entry.matched_rules.clone()))
        .collect();
    assert_eq!(
        rules,
        // gitleaks reports a named token under the generic key rule too.
        vec![
            (
                "github",
                vec!["generic-api-key".to_string(), "github-pat".to_string()]
            ),
            ("docs", vec![]),
        ]
    );
    let sent: Vec<DeviceMCPServer> = entries
        .into_iter()
        .map(|entry| entry.server("claude", ".claude.json".into()))
        .collect();
    let wire = serde_json::to_string(&sent).unwrap();
    assert!(
        wire.contains("\"matched_rules\":[\"generic-api-key\",\"github-pat\"]"),
        "{wire}"
    );
    assert!(
        !wire.contains(&TOKEN[4..]) && !wire.contains("GITHUB_PERSONAL_ACCESS_TOKEN"),
        "{wire}"
    );
}

#[test]
fn a_toml_mcp_table_is_checked_too() {
    let config = format!(
        "[mcp_servers.github]\ncommand = \"npx\"\n[mcp_servers.github.env]\nGITHUB_TOKEN = \"{TOKEN}\"\n"
    );
    let entries = crate::ai_discovery::codex_mcp_entries(&config);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].matched_rules,
        vec!["generic-api-key".to_string(), "github-pat".to_string()]
    );
}

#[test]
fn low_entropy_placeholders_and_plain_text_match_nothing() {
    let placeholder = format!("token: ghp_{}", "a".repeat(36));
    assert_eq!(
        secret_rule_ids(placeholder.as_bytes()),
        Vec::<String>::new()
    );
    let plain = b"---\nname: review\n---\nRead the diff and list the risky changes.\n";
    assert_eq!(secret_rule_ids(plain), Vec::<String>::new());
    // The global allowlist's stopword: a secret holding the alphabet.
    assert!(contains(
        b"xabcdefghijklmnopqrstuvwxyzx",
        b"abcdefghijklmnopqrstuvwxyz"
    ));
}

#[test]
fn the_entropy_and_brace_translations_match_gitleaks() {
    assert_eq!(shannon_entropy(b""), 0.0);
    assert_eq!(shannon_entropy(b"aaaa"), 0.0);
    assert!((shannon_entropy(b"abcd") - 2.0).abs() < 1e-12);
    assert_eq!(trim_newlines(b"\n\nab\n"), b"ab");
    // Go reads `{` that starts no repetition as a literal.
    let translated = GITLEAKS_ALLOWLIST
        .regexes
        .iter()
        .find(|pattern| pattern.starts_with(r"^\$\{(?:[A-Z_]"))
        .expect("build.rs escaped the literal brace");
    assert!(compile(translated).unwrap().is_match(b"${HOME}"));
}

#[test]
fn a_forged_mcp_rule_id_from_a_child_scan_is_dropped() {
    let mut server = DeviceMCPServer {
        client: "claude".into(),
        name: "github".into(),
        source: ".claude.json".into(),
        transport: "stdio".into(),
        location: String::new(),
        package: String::new(),
        host: String::new(),
        matched_rules: vec![
            "github-pat".into(),
            "/home/user/.ssh/id_rsa".into(),
            "autonomy_abuse_generic".into(),
            "github-pat".into(),
        ],
    };
    keep_valid_mcp_facts(&mut server);
    assert_eq!(server.matched_rules, vec!["github-pat".to_string()]);
}

#[cfg(target_os = "linux")]
#[test]
fn a_skill_holding_a_token_reports_the_rule_with_its_hash() {
    let skill = format!("---\nname: deploy\n---\nUse this token: {TOKEN}\n");
    let facts = crate::ai_discovery::ContentScan::new()
        .check(skill.as_bytes())
        .expect("checked");
    assert!(
        facts.matched_rules.contains(&"github-pat".to_string()),
        "{facts:?}"
    );
    assert!(!format!("{facts:?}").contains(&TOKEN[4..]));
}
