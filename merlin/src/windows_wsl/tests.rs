//! Ported from the Go collector's wsl_test.go.

use super::*;
use crate::windows_discovery::PortableFs;
use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;

const UBUNTU_ID: &str = "0123abcd-4567-89ab-cdef-000102030405";
const FEDORA_ID: &str = "0123abcd-4567-89ab-cdef-000102030406";

fn tempdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("merlin-wsl-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(dir: &Path, name: &str, value: &Value) {
    fs::write(dir.join(name), serde_json::to_vec(value).unwrap()).unwrap();
}

fn plugin_status(scans: bool) -> Value {
    json!({"schema_version": 1, "wsl_version": "2.4.4", "scans": scans, "registrations": scans, "loaded_at": 1})
}

fn scanned_from(id: &str, distro: &str, location: &str, mcp_source: &str) -> Value {
    json!({
        "schema_version": 1, "distro_id": id, "distro": distro, "state": "scanned", "reason": null, "observed_at": 1_794_000_000,
        "findings": {
            "clis": [{"name": "claude"}],
            "mcp_servers": [{"location": location, "client": "codex", "name": "github", "source": mcp_source, "transport": "remote"}],
            "agent_assets": [{"location": location, "client": "claude", "kind": "skill", "name": "review", "source": ".claude/skills"}],
        },
    })
}

fn scanned(id: &str, distro: &str, location: &str) -> Value {
    scanned_from(id, distro, location, ".codex/config.toml")
}

fn distro(id: &str, name: &str) -> RegisteredDistro {
    RegisteredDistro {
        id: id.into(),
        name: name.into(),
    }
}

fn by_location(result: &WslInventory) -> BTreeMap<&str, &DeviceAiLocationCoverage> {
    result
        .coverage
        .iter()
        .map(|entry| (entry.location.as_str(), entry))
        .collect()
}

#[test]
fn scans_become_findings_and_registered_distros_without_one_are_not_scanned() {
    let dir = tempdir("scans");
    write(&dir, "plugin.json", &plugin_status(true));
    write(
        &dir,
        &format!("{UBUNTU_ID}.json"),
        &scanned(UBUNTU_ID, "Ubuntu", "wsl:Ubuntu"),
    );
    let registered = [distro(UBUNTU_ID, "Ubuntu"), distro(FEDORA_ID, "Fedora")];
    let result = collect(&PortableFs, &dir, &registered);
    assert_eq!(result.mcp_servers.len(), 1);
    let server = &result.mcp_servers[0];
    assert_eq!(
        (
            server.client.as_str(),
            server.name.as_str(),
            server.source.as_str(),
            server.transport.as_str(),
            server.location.as_str()
        ),
        (
            "codex",
            "github",
            ".codex/config.toml",
            "remote",
            "wsl:Ubuntu"
        )
    );
    assert_eq!(result.agent_assets.len(), 1);
    assert_eq!(result.agent_assets[0].location, "wsl:Ubuntu");
    let coverage = by_location(&result);
    assert_eq!(
        *coverage["wsl:Ubuntu"],
        DeviceAiLocationCoverage {
            location: "wsl:Ubuntu".into(),
            source: String::new(),
            state: "scanned".into(),
            reason: String::new(),
            observed_at: 1_794_000_000,
        }
    );
    assert_eq!(
        *coverage["wsl:Fedora"],
        not_scanned("wsl:Fedora".into(), NOT_STARTED, 0)
    );
    assert_eq!(
        result.coverage[0].state, "not_scanned",
        "not-scanned places sort first"
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn without_a_working_plugin_registered_distros_are_not_scanned_with_its_reason() {
    let registered = [distro(FEDORA_ID, "Fedora")];
    let base = tempdir("no-plugin");
    let missing = collect(&PortableFs, &base.join("absent"), &registered);
    assert_eq!(missing.coverage.len(), registered.len());
    assert_eq!(missing.coverage[0].reason, PLUGIN_MISSING);
    write(&base, "plugin.json", &plugin_status(false));
    let old = collect(&PortableFs, &base, &registered);
    assert_eq!(old.coverage[0].reason, UNSUPPORTED);
    assert!(
        collect(&PortableFs, &base.join("absent"), &[])
            .coverage
            .is_empty(),
        "no WSL: nothing reported"
    );
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn plugin_files_are_checked_again_before_they_are_sent() {
    let dir = tempdir("checked");
    write(&dir, "plugin.json", &plugin_status(true));
    // A finding tagged for another distribution discards the scan.
    write(
        &dir,
        &format!("{UBUNTU_ID}.json"),
        &scanned(UBUNTU_ID, "Ubuntu", "wsl:Other"),
    );
    // An absolute source label discards the scan.
    write(
        &dir,
        &format!("{FEDORA_ID}.json"),
        &scanned_from(
            FEDORA_ID,
            "Fedora",
            "wsl:Fedora",
            "/home/alice/.codex/config.toml",
        ),
    );
    // A mismatched id, a name that cannot be a location, and a file that is
    // not a state file are ignored.
    write(
        &dir,
        "0123abcd-4567-89ab-cdef-000102030407.json",
        &scanned(UBUNTU_ID, "Debian", "wsl:Debian"),
    );
    let spaced = "0123abcd-4567-89ab-cdef-000102030408";
    write(
        &dir,
        &format!("{spaced}.json"),
        &scanned(spaced, "my distro", "wsl:my distro"),
    );
    write(
        &dir,
        "notes.json",
        &scanned(UBUNTU_ID, "Alpine", "wsl:Alpine"),
    );
    // An unknown reason is reported as a failed scan, never dropped.
    let arch = "0123abcd-4567-89ab-cdef-000102030409";
    write(
        &dir,
        &format!("{arch}.json"),
        &json!({"schema_version": 1, "distro_id": arch, "distro": "Arch", "state": "not_scanned", "reason": "unsupported_name", "observed_at": 5}),
    );
    let result = collect(&PortableFs, &dir, &[]);
    assert!(
        result.mcp_servers.is_empty() && result.agent_assets.is_empty(),
        "unchecked findings kept"
    );
    let coverage = by_location(&result);
    let expected = ["wsl:Arch", "wsl:Fedora", "wsl:Ubuntu"];
    assert_eq!(coverage.keys().copied().collect::<Vec<_>>(), expected);
    for location in expected {
        assert_eq!(coverage[location].state, "not_scanned", "{location}");
        assert_eq!(coverage[location].reason, SCAN_FAILED, "{location}");
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_linked_state_file_is_refused() {
    let dir = tempdir("linked");
    let outside = tempdir("linked-outside");
    write(
        &outside,
        "elsewhere.json",
        &scanned(UBUNTU_ID, "Ubuntu", "wsl:Ubuntu"),
    );
    std::os::unix::fs::symlink(
        outside.join("elsewhere.json"),
        dir.join(format!("{UBUNTU_ID}.json")),
    )
    .unwrap();
    let result = collect(&PortableFs, &dir, &[]);
    assert!(result.coverage.is_empty() && result.mcp_servers.is_empty());
    fs::remove_dir_all(dir).unwrap();
    fs::remove_dir_all(outside).unwrap();
}

#[test]
fn the_same_name_in_two_accounts_is_not_scanned_if_either_is() {
    let dir = tempdir("same-name");
    write(&dir, "plugin.json", &plugin_status(true));
    write(
        &dir,
        &format!("{UBUNTU_ID}.json"),
        &scanned(UBUNTU_ID, "Ubuntu", "wsl:Ubuntu"),
    );
    let result = collect(&PortableFs, &dir, &[distro(FEDORA_ID, "Ubuntu")]);
    assert_eq!(result.coverage.len(), 1);
    assert_eq!(result.coverage[0].state, "not_scanned");
    assert!(!result.mcp_servers.is_empty());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn coverage_is_capped() {
    let dir = tempdir("capped");
    let registered: Vec<RegisteredDistro> = (0..MAX_COVERAGE + 8)
        .map(|index| {
            distro(
                &format!("0123abcd-4567-89ab-cdef-{index:012}"),
                &format!("distro-{index:02}"),
            )
        })
        .collect();
    assert_eq!(
        collect(&PortableFs, &dir, &registered).coverage.len(),
        MAX_COVERAGE
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn lxss_keys_become_the_plugin_file_stem() {
    assert_eq!(
        lxss_distro_id("{0123ABCD-4567-89AB-CDEF-000102030405}").as_deref(),
        Some(UBUNTU_ID)
    );
    for key in [
        "0123abcd-4567-89ab-cdef-000102030405",
        "{not-a-guid}",
        "{0123ABCD-4567-89AB-CDEF-00010203040Z}",
    ] {
        assert!(lxss_distro_id(key).is_none(), "{key}");
    }
}

#[test]
fn a_skill_hash_and_its_matched_rule_ids_reach_the_check_in_and_forged_ones_do_not() {
    let dir = tempdir("content-facts");
    write(&dir, "plugin.json", &plugin_status(true));
    let mut state = scanned(UBUNTU_ID, "Ubuntu", "wsl:Ubuntu");
    let hash = "ab".repeat(32);
    state["findings"]["agent_assets"] = json!([
        {"location": "wsl:Ubuntu", "client": "claude", "kind": "skill", "name": "helper", "source": ".claude/skills",
         "sha256": hash, "matched_rules": ["prompt_injection_generic", "not-a-declared-rule"]},
        {"location": "wsl:Ubuntu", "client": "claude", "kind": "skill", "name": "forged", "source": ".claude/skills",
         "sha256": "/home/alice/.claude/skills/forged/SKILL.md", "matched_rules": ["prompt_injection_generic"]},
    ]);
    write(&dir, &format!("{UBUNTU_ID}.json"), &state);
    let result = collect(&PortableFs, &dir, &[distro(UBUNTU_ID, "Ubuntu")]);
    let asset = |name: &str| {
        result
            .agent_assets
            .iter()
            .find(|asset| asset.name == name)
            .unwrap_or_else(|| panic!("{name} in {:?}", result.agent_assets))
    };
    assert_eq!(asset("helper").sha256, hash);
    assert_eq!(asset("helper").matched_rules, ["prompt_injection_generic"]);
    assert!(asset("forged").sha256.is_empty() && asset("forged").matched_rules.is_empty());
    fs::remove_dir_all(dir).unwrap();
}
