use super::*;

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
