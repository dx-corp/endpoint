use super::*;

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
