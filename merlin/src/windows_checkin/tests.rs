//! Ported from the Go collector's TestConfigAndCheckIn, plus the wire shape
//! the server's check-in handler reads.

use super::*;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::time::UNIX_EPOCH;

use crate::posture_report::{Collector, summarize};

const DEVICE: &str = "dev_0123456789abcdef01234567";
const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn config_json(url: &str) -> String {
    format!(r#"{{"sync_url":"{url}","device_id":"{DEVICE}","device_token":"{TOKEN}"}}"#)
}

fn posture() -> DevicePosture {
    summarize(
        BTreeMap::new(),
        "1.000".into(),
        Collector {
            provider: "deixic-windows-collector",
            root: true,
            max_age_seconds: 3600,
            capabilities: Vec::new(),
            started: std::time::Instant::now(),
        },
        |_| 0,
    )
}

struct FakeTransport {
    status: u16,
    reply: &'static str,
    seen: RefCell<Option<(String, String, serde_json::Value)>>,
}

impl Transport for FakeTransport {
    fn post(&self, url: &str, token: &str, body: Vec<u8>, _limit: u64) -> Result<(u16, Vec<u8>)> {
        let body = serde_json::from_slice(&body).unwrap();
        *self.seen.borrow_mut() = Some((url.into(), token.into(), body));
        Ok((self.status, self.reply.as_bytes().to_vec()))
    }
}

fn fake(status: u16, reply: &'static str) -> FakeTransport {
    FakeTransport {
        status,
        reply,
        seen: RefCell::new(None),
    }
}

fn check_in(host: &str) -> CheckIn<'_> {
    let at = UNIX_EPOCH + Duration::from_millis(1_760_400_000_123);
    CheckIn::new(
        host,
        Inventory::new(WindowsDiscovery::default(), at),
        posture(),
    )
}

#[test]
fn a_valid_configuration_is_accepted_and_normalized() {
    let config = parse_config(config_json("https://sync.example.com/").as_bytes()).unwrap();
    assert_eq!(config.sync_url, "https://sync.example.com");
    let config = parse_config(config_json("https://sync.example.com:8443").as_bytes()).unwrap();
    assert_eq!(config.sync_url, "https://sync.example.com:8443");
    assert!(
        !format!("{config:?}").contains(TOKEN),
        "Debug must not print the token"
    );
}

#[test]
fn unsafe_or_malformed_configuration_is_refused_without_echoing_it() {
    for url in [
        "https://user:password@example.com",
        "http://example.com",
        "https://example.com/path",
        "https://example.com/?q=1",
        "https://example.com/#frag",
        "https://",
        "example.com",
    ] {
        let error = parse_config(config_json(url).as_bytes())
            .unwrap_err()
            .to_string();
        assert!(
            !error.contains("password") && !error.contains("example"),
            "{error}"
        );
    }
    let bad_id = config_json("https://example.com").replace(DEVICE, "dev_XYZ");
    assert!(parse_config(bad_id.as_bytes()).is_err());
    let bad_token = config_json("https://example.com").replace(TOKEN, "short");
    let error = parse_config(bad_token.as_bytes()).unwrap_err().to_string();
    assert!(!error.contains("short"));
    assert!(parse_config(b"not json").is_err());
    let mut padded = config_json("https://example.com").into_bytes();
    padded.resize(MAX_CONFIG_BYTES as usize + 1, b' ');
    assert!(parse_config(&padded).is_err(), "oversized configuration");
    let roots: Vec<String> = (0..=MAX_WORKSPACE_ROOTS)
        .map(|i| format!("\"/w{i}\""))
        .collect();
    let too_many = format!(
        r#"{{"sync_url":"https://example.com","device_id":"{DEVICE}","device_token":"{TOKEN}","workspace_roots":[{}]}}"#,
        roots.join(",")
    );
    assert!(parse_config(too_many.as_bytes()).is_err());
    let traversal = format!(
        r#"{{"sync_url":"https://example.com","device_id":"{DEVICE}","device_token":"{TOKEN}","workspace_roots":["/w/../x"]}}"#
    );
    assert!(parse_config(traversal.as_bytes()).is_err());
}

#[test]
fn the_check_in_posts_the_inventory_only_report_and_bounds_the_interval() {
    let config = parse_config(config_json("https://sync.example.com").as_bytes()).unwrap();
    let transport = fake(200, r#"{"next_check_in_seconds":10}"#);
    let interval = post_check_in(&transport, &config, &check_in("windows-device")).unwrap();
    assert_eq!(interval, MIN_INTERVAL);
    let (url, token, body) = transport.seen.into_inner().unwrap();
    assert_eq!(
        url,
        format!("https://sync.example.com/v1/devices/{DEVICE}/check-in")
    );
    assert_eq!(token, TOKEN);
    assert_eq!(body["host"], "windows-device");
    assert_eq!(body["platform"], "windows");
    assert_eq!(body["agent_version"], AGENT_VERSION);
    assert_eq!(body["os_version"], "");
    assert_eq!(body["sensor_mode"], "inventory-only");
    assert_eq!(body["status"], "healthy");
    assert_eq!(
        body["capabilities"],
        serde_json::json!(["system_inventory", "agent_discovery"])
    );
    assert_eq!(body["health"], serde_json::json!({"drop_rate": 0.0}));
    assert_eq!(body["posture"]["schema_version"], 2);
    let inventory = &body["inventory"];
    assert_eq!(inventory["collected_at"], "1760400000.123");
    assert_eq!(inventory["collection_source"], "windows-agent");
    assert!(
        inventory.get("ai_location_coverage").is_none(),
        "omitted when empty, as Go's omitempty"
    );
    for list in [
        "agent_clis",
        "agent_apps",
        "mcp_servers",
        "agent_assets",
        "processes",
    ] {
        assert!(inventory[list].is_array(), "{list}");
    }
}

#[test]
fn the_interval_is_bounded_and_failures_are_errors() {
    let config = parse_config(config_json("https://sync.example.com").as_bytes()).unwrap();
    for (reply, expected) in [
        (r#"{"next_check_in_seconds":999999}"#, MAX_INTERVAL),
        (r#"{"next_check_in_seconds":120}"#, Duration::from_secs(120)),
        ("{}", MIN_INTERVAL),
    ] {
        let transport = fake(200, reply);
        assert_eq!(
            post_check_in(&transport, &config, &check_in("h")).unwrap(),
            expected
        );
    }
    let unauthorized = post_check_in(&fake(401, "{}"), &config, &check_in("h"));
    assert!(unauthorized.is_err());
    assert_eq!(next_wait(unauthorized), RETRY_INTERVAL);
    assert_eq!(next_wait(Ok(MAX_INTERVAL)), MAX_INTERVAL);
    assert!(post_check_in(&fake(200, "not json"), &config, &check_in("h")).is_err());
}

#[test]
fn hostnames_are_trimmed_and_bounded() {
    assert_eq!(valid_host("  desk  ").unwrap(), "desk");
    assert!(valid_host("   ").is_err());
    assert!(valid_host(&"x".repeat(129)).is_err());
}
