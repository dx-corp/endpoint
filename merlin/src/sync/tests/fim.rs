use super::*;

#[test]
fn fim_serializes_sha256_and_metadata_without_a_file_body() {
    let entry = DeviceFIMEntry {
        path: "/etc/example".into(),
        sha256: "abc123".into(),
        size_bytes: 42,
        mode: "600".into(),
        modified_unix: 1_700_000_000,
        status: "present".into(),
    };
    assert_eq!(
        serde_json::to_value(entry).unwrap(),
        serde_json::json!({
            "path": "/etc/example",
            "sha256": "abc123",
            "size_bytes": 42,
            "mode": "600",
            "modified_unix": 1_700_000_000,
            "status": "present"
        })
    );
}
