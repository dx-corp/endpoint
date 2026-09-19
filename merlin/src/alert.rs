//! Alert webhook: compact JSON POSTs for high-signal decisions (deny,
//! kill, credential-change to root). Fire-and-forget by design — alerting
//! must never slow or block the sensor: a bounded queue (drop-with-counter
//! at 1000 queued), one worker thread, 5s POST timeout, errors logged and
//! forgotten.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::sync;

pub const QUEUE_CAP: usize = 1000;
const POST_TIMEOUT: Duration = Duration::from_secs(5);
const REPORT_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct AlertHook {
    tx: SyncSender<Value>,
    dropped: Arc<AtomicU64>,
}

impl AlertHook {
    fn new(tx: SyncSender<Value>, dropped: Arc<AtomicU64>) -> Self {
        AlertHook { tx, dropped }
    }

    /// Queue an alert for the worker. Full queue → drop with counter.
    pub fn fire(&self, event: Value) {
        match self.tx.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {}
        }
    }

    /// Compact alert body shared by all call sites.
    pub fn alert(kind: &str, rules: &[String], comm: &str, exe: Option<&str>) -> Value {
        serde_json::json!({
            "kind": kind,
            "rules": rules,
            "host": sync::hostname(),
            "comm": comm,
            "exe": exe,
            "ts": crate::spool::now_ts(),
        })
    }
}

/// Start the webhook worker thread. Returns the handle producers use.
pub fn spawn(url: String) -> AlertHook {
    let (tx, rx) = sync_channel::<Value>(QUEUE_CAP);
    let dropped = Arc::new(AtomicU64::new(0));
    let worker_dropped = Arc::clone(&dropped);
    log::info!(
        "alerts: webhook to {url} (queue {QUEUE_CAP}, timeout {}s)",
        POST_TIMEOUT.as_secs()
    );
    thread::Builder::new()
        .name("alert-webhook".into())
        .spawn(move || {
            let agent = ureq::Agent::new_with_config(
                ureq::Agent::config_builder()
                    .timeout_global(Some(POST_TIMEOUT))
                    .build(),
            );
            let mut last_report = Instant::now();
            for event in rx.iter() {
                if last_report.elapsed() >= REPORT_INTERVAL {
                    let n = worker_dropped.swap(0, Ordering::Relaxed);
                    if n > 0 {
                        log::warn!("alerts: {n} alerts dropped (queue full) in the last 60s");
                    }
                    last_report = Instant::now();
                }
                let body = event.to_string();
                let result = agent
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .send(body.as_bytes());
                if let Err(e) = result {
                    // Fail-open: an alerting outage must never become a
                    // sensor outage.
                    log::warn!("alerts: webhook POST failed: {e}");
                }
            }
        })
        .expect("spawning alert webhook thread");
    AlertHook::new(tx, dropped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc::Receiver;

    /// One-shot HTTP sink: returns the URL and a receiver that yields the
    /// captured request body.
    fn http_sink() -> (String, Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = sync_channel::<String>(1);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
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
                }
                let mut body = vec![0u8; content_length];
                reader.read_exact(&mut body).unwrap();
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .unwrap();
                stream.flush().unwrap();
                let _ = tx.send(String::from_utf8_lossy(&body).into_owned());
            }
        });
        (format!("http://127.0.0.1:{port}"), rx)
    }

    #[test]
    fn webhook_posts_compact_json() {
        let (url, rx) = http_sink();
        let hook = spawn(url);
        hook.fire(AlertHook::alert(
            "kill",
            &["kill-netcat".to_string()],
            "nc",
            Some("/usr/bin/nc"),
        ));
        let body = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("sink must receive the POST");
        let parsed: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["kind"], "kill");
        assert_eq!(parsed["rules"][0], "kill-netcat");
        assert_eq!(parsed["comm"], "nc");
        assert_eq!(parsed["exe"], "/usr/bin/nc");
        assert!(parsed["host"].is_string());
        assert!(parsed["ts"].is_number());
    }

    #[test]
    fn full_queue_drops_with_counter() {
        // No worker consuming: the queue fills and fire() drops.
        let (tx, _rx) = sync_channel::<Value>(2);
        let dropped = Arc::new(AtomicU64::new(0));
        let hook = AlertHook::new(tx, Arc::clone(&dropped));
        for _ in 0..10 {
            hook.fire(AlertHook::alert("deny", &[], "evil", None));
        }
        assert_eq!(dropped.load(Ordering::Relaxed), 8);
    }
}
