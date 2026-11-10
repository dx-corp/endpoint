//! `merlin scan-ai-locations` reads only inside the root it is given.
//!
//! chroot needs root. The test runs the binary directly as root, or as root
//! of a new user namespace (`unshare -r`) where that is allowed, and says so
//! and passes when neither is available.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn tmpdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("merlin-scan-root-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_scan(root: &Path, location: &str) -> Option<Output> {
    let binary = env!("CARGO_BIN_EXE_merlin");
    let args = [
        "scan-ai-locations",
        "--root",
        root.to_str().unwrap(),
        "--location",
        location,
    ];
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return Command::new(binary).args(args).output().ok();
    }
    let probe = Command::new("unshare")
        .args(["-r", "chroot", "/", "true"])
        .output()
        .ok()?;
    if !probe.status.success() {
        return None;
    }
    Command::new("unshare")
        .arg("-r")
        .arg(binary)
        .args(args)
        .output()
        .ok()
}

#[test]
fn a_scanned_root_cannot_reach_host_files_through_its_symlinks() {
    let base = tmpdir("escape");
    let root = base.join("container-root");
    // Inside the root: one skill and one MCP config that belong to it.
    fs::create_dir_all(root.join("root/.claude/skills/review")).unwrap();
    fs::write(
        root.join("root/.claude/skills/review/SKILL.md"),
        "private-secret",
    )
    .unwrap();
    fs::create_dir_all(root.join("home/dev/.cursor")).unwrap();
    fs::write(
        root.join("home/dev/.cursor/mcp.json"),
        r#"{"mcpServers":{"inside":{"command":"private-secret"}}}"#,
    )
    .unwrap();
    // On the host, outside the root: a config the container points at with
    // an absolute symlink. Followed from the host, it would be read.
    let outside = base.join("host-only/.gemini");
    fs::create_dir_all(&outside).unwrap();
    fs::write(
        outside.join("settings.json"),
        r#"{"mcpServers":{"escaped":{"command":"private-secret"}}}"#,
    )
    .unwrap();
    symlink(&outside, root.join("home/dev/.gemini")).unwrap();
    // `..` past the root also stays inside it.
    symlink(
        "../../../../../../host-only/.gemini",
        root.join("root/.gemini"),
    )
    .unwrap();

    let Some(output) = run_scan(&root, "container:ghcr.io/acme/dev:1") else {
        eprintln!("skipped: needs root or unprivileged user namespaces for chroot");
        fs::remove_dir_all(base).unwrap();
        return;
    };
    assert!(
        output.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let scan: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let servers = scan["mcp_servers"].as_array().unwrap();
    let assets = scan["agent_assets"].as_array().unwrap();
    assert!(servers.iter().any(|s| s["name"] == "inside"
        && s["source"] == ".cursor/mcp.json"
        && s["location"] == "container:ghcr.io/acme/dev:1"));
    assert!(assets.iter().any(|a| a["name"] == "review"
        && a["source"] == ".claude/skills"
        && a["location"] == "container:ghcr.io/acme/dev:1"));
    assert!(!stdout.contains("escaped"), "read a host file: {stdout}");
    assert!(!stdout.contains("private-secret"));
    assert!(!stdout.contains(base.to_str().unwrap()), "printed a path");
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn a_location_that_is_not_a_container_or_wsl_name_is_refused() {
    let root = tmpdir("refused");
    for location in ["host", "container:/etc", "wsl:/mnt/c", "anything"] {
        let output = Command::new(env!("CARGO_BIN_EXE_merlin"))
            .args([
                "scan-ai-locations",
                "--root",
                root.to_str().unwrap(),
                "--location",
                location,
            ])
            .output()
            .unwrap();
        assert!(!output.status.success(), "{location} was accepted");
        assert!(output.stdout.is_empty());
    }
    fs::remove_dir_all(root).unwrap();
}
