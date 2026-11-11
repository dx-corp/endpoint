use super::agent_discovery::{
    AGENT_FILE_LIMIT, MAX_AGENT_HOMES, agent_homes_from, collect_cursor_plugins,
};
use super::container_discovery::RootScan;
use super::plugin_cache::{MAX_CLAUDE_CACHE_DIRS, collect_claude_plugin_cache};
use super::*;
use crate::ai_discovery::{ContentScan, MAX_AGENT_FINDINGS};
use crate::manifest::{AI_LOCATIONS, AiLocation, Format, Scope};
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

mod agent_discovery;
mod ai_extensions;
mod check_in_policy;
mod fim;
mod plugin_cache;
mod project_discovery;
mod spool_upload;

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
