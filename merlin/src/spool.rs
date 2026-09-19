//! Append-only JSONL event spool — the analog of Falcon's crash-safe CLFS
//! channel logs, minus the crash safety guarantees (plain write+flush per
//! event; good enough for a teaching sensor).
//!
//! Segmentation (parity with the macOS port): the live file stays plain
//! JSONL, flushed per event. When --segment-interval or --segment-bytes
//! trips (checked after each write, so quiet periods never produce empty
//! segments), the live file is renamed to
//! `<base>.<yyyyMMdd-HHmmss>.jsonl` next to itself, a fresh live file is
//! opened, and the segment is gzip-compressed on a background task — never
//! on the write path. The uncompressed segment is deleted only after a
//! successful compress+fsync; a crash leaves an orphan that a startup
//! sweep compresses. Rotation failure keeps the live file and logs:
//! telemetry continuity beats segmentation.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use flate2::Compression;
use flate2::write::GzEncoder;
use serde_json::{Map, Value};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinHandle;

pub fn now_ts() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

static EVENT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

static EVENTS_ATTEMPTED: AtomicU64 = AtomicU64::new(0);
static EVENTS_ACCEPTED: AtomicU64 = AtomicU64::new(0);
static EVENTS_DROPPED: AtomicU64 = AtomicU64::new(0);
static EVENTS_WRITTEN: AtomicU64 = AtomicU64::new(0);
static WRITE_FAILURES: AtomicU64 = AtomicU64::new(0);
static KERNEL_EVENTS_DROPPED: AtomicU64 = AtomicU64::new(0);
static BOOT_ID: OnceLock<String> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub events_attempted: u64,
    pub events_accepted: u64,
    pub events_dropped: u64,
    pub events_written: u64,
    pub write_failures: u64,
    pub kernel_events_dropped: u64,
}

pub fn metrics_snapshot() -> MetricsSnapshot {
    MetricsSnapshot {
        events_attempted: EVENTS_ATTEMPTED.load(Ordering::Relaxed),
        events_accepted: EVENTS_ACCEPTED.load(Ordering::Relaxed),
        events_dropped: EVENTS_DROPPED.load(Ordering::Relaxed),
        events_written: EVENTS_WRITTEN.load(Ordering::Relaxed),
        write_failures: WRITE_FAILURES.load(Ordering::Relaxed),
        kernel_events_dropped: KERNEL_EVENTS_DROPPED.load(Ordering::Relaxed),
    }
}

/// Publish the monotonic lower-bound counter read from the eBPF per-CPU
/// stats map. Missing/unsupported maps leave the value at zero.
pub fn set_kernel_events_dropped(value: u64) {
    KERNEL_EVENTS_DROPPED.store(value, Ordering::Relaxed);
}

/// Runtime health metadata shared by all Linux providers.
#[derive(Debug, Clone)]
pub struct HealthConfig {
    pub interval: Duration,
    pub capabilities: Vec<String>,
    pub arch: String,
    pub syscall_abi: String,
    pub queue_capacity: usize,
}

/// Monotonic process-local sequence for correlating events from the lossy
/// producers. It is evidence ordering, not a claim that no kernel events
/// were dropped; the documented fail-open/backpressure behavior remains.
pub fn next_sequence() -> u64 {
    EVENT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
}

fn boot_id() -> &'static str {
    BOOT_ID
        .get_or_init(|| {
            std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "unknown".to_string())
        })
        .as_str()
}

fn numeric(object: &Map<String, Value>, key: &str) -> Option<u64> {
    object.get(key).and_then(Value::as_u64)
}

fn bool_value(object: &Map<String, Value>, key: &str) -> Option<bool> {
    object.get(key).and_then(Value::as_bool)
}

fn signals_for(object: &Map<String, Value>) -> Vec<&'static str> {
    let mut signals = Vec::new();
    let kind = object.get("kind").and_then(Value::as_str).unwrap_or("");
    match kind {
        "exec" => {
            if object.get("fileless").and_then(Value::as_bool) == Some(true) {
                signals.push("fileless_execution");
            }
            if object.get("exe_deleted").and_then(Value::as_bool) == Some(true) {
                signals.push("deleted_executable");
            }
        }
        "memfd" => signals.push("memfd_create"),
        "file" => signals.push("persistence_change"),
        "socket" => {
            if object.get("state").and_then(Value::as_str) == Some("listen") {
                signals.push("network_listener");
            }
        }
        "security" => {
            if object.get("w_x_transition").and_then(Value::as_bool) == Some(true) {
                signals.push("w_x_transition");
            }
            match object.get("syscall").and_then(Value::as_str).unwrap_or("") {
                "ptrace" | "process_vm_readv" | "process_vm_writev" => {
                    signals.push("process_injection")
                }
                "init_module" | "delete_module" | "finit_module" => {
                    signals.push("kernel_module_change")
                }
                "mount" | "pivot_root" | "umount2" => signals.push("mount_or_root_change"),
                "unshare" | "setns" => signals.push("namespace_change"),
                "setuid" | "setgid" | "setreuid" | "setregid" | "setresuid" | "setresgid"
                | "capset" => signals.push("privilege_change"),
                "bpf" => signals.push("bpf_program"),
                "userfaultfd" => signals.push("userfaultfd"),
                _ => {}
            }
        }
        _ => {}
    }
    signals
}

/// Add bounded, payload-free correlation metadata at the last producer
/// boundary. Explicit null process keys make missing namespace/start-time
/// evidence visible rather than silently presenting a recycled pid as stable.
fn decorate_event(event: &mut Value) {
    let Some(object) = event.as_object_mut() else {
        return;
    };
    object.insert("schema_version".into(), Value::from(1u64));
    object.insert("boot_id".into(), Value::from(boot_id()));
    object.insert("spooled_ts".into(), Value::from(now_ts()));
    let source_seq = numeric(object, "source_seq").unwrap_or_else(next_sequence);
    object.insert("source_seq".into(), Value::from(source_seq));
    object.insert(
        "event_id".into(),
        Value::from(format!("{}:{}", boot_id(), source_seq)),
    );

    let namespace_valid = bool_value(object, "namespace_valid")
        .or_else(|| bool_value(object, "pid_ns_valid"))
        .unwrap_or(true);
    let process_key = if namespace_valid {
        numeric(object, "pid")
            .zip(numeric(object, "pid_start_time"))
            .map(|(pid, start)| format!("{}:{}:{}", boot_id(), pid, start))
    } else {
        None
    };
    object.insert(
        "process_key".into(),
        process_key.map(Value::from).unwrap_or(Value::Null),
    );
    let signals = signals_for(object);
    object.insert(
        "signals".into(),
        if signals.is_empty() {
            Value::Null
        } else {
            Value::Array(signals.into_iter().map(Value::from).collect())
        },
    );
}

fn write_value(spool: &mut LiveSpool, mut event: Value, now: SystemTime) -> Option<PathBuf> {
    decorate_event(&mut event);
    spool.write_line(&event.to_string(), now)
}

fn health_event(config: &HealthConfig) -> Value {
    let metrics = metrics_snapshot();
    let drop_rate = if metrics.events_attempted == 0 {
        0.0
    } else {
        metrics.events_dropped as f64 / metrics.events_attempted as f64
    };
    serde_json::json!({
        "ts": now_ts(),
        "source": "linux-spool",
        "source_seq": next_sequence(),
        "kind": "health",
        "status": "ok",
        "arch": config.arch,
        "syscall_abi": config.syscall_abi,
        "capabilities": config.capabilities,
        "queue_capacity": config.queue_capacity,
        "events_attempted": metrics.events_attempted,
        "events_accepted": metrics.events_accepted,
        "events_dropped": metrics.events_dropped,
        "drop_rate": drop_rate,
        "events_written": metrics.events_written,
        "write_failures": metrics.write_failures,
        "kernel_events_dropped": metrics.kernel_events_dropped,
    })
}

/// Rotation thresholds; both 0 = segmentation off.
#[derive(Debug, Clone, Copy, Default)]
pub struct SegmentConfig {
    pub interval_secs: u64,
    pub max_bytes: u64,
}

impl SegmentConfig {
    pub fn enabled(&self) -> bool {
        self.interval_secs > 0 || self.max_bytes > 0
    }
}

/// Open the live spool (or a segment) with the daemon's file invariants:
/// O_NOFOLLOW|O_CLOEXEC, mode 0600, and fstat-verified regular file owned
/// by the daemon user and not group/other writable. Returns (file, size).
fn open_hardened(path: &Path, append: bool) -> Result<(File, u64)> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(append)
        .truncate(!append)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening spool {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("statting spool {}", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!("spool {} is not a regular file", path.display());
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        anyhow::bail!("spool {} is not owned by the daemon user", path.display());
    }
    if metadata.mode() & 0o022 != 0 {
        anyhow::bail!("spool {} is group/other writable", path.display());
    }
    Ok((file, metadata.size()))
}

/// The live spool file plus rotation state.
pub struct LiveSpool {
    file: File,
    path: PathBuf,
    bytes_written: u64,
    last_rotation: SystemTime,
    seg: SegmentConfig,
}

impl LiveSpool {
    pub fn open(path: PathBuf, seg: SegmentConfig) -> Result<Self> {
        Self::open_at(path, seg, SystemTime::now())
    }

    /// `open` with an explicit rotation-clock start (tests).
    pub fn open_at(path: PathBuf, seg: SegmentConfig, now: SystemTime) -> Result<Self> {
        let (file, size) = open_hardened(&path, true)?;
        log::info!("spooling events to {}", path.display());
        Ok(LiveSpool {
            file,
            path,
            bytes_written: size,
            last_rotation: now,
            seg,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write one event line, flush, then rotate if a trigger tripped.
    /// Returns the finished (uncompressed) segment path when a rotation
    /// happened; the caller compresses it off the write path.
    pub fn write_line(&mut self, line: &str, now: SystemTime) -> Option<PathBuf> {
        if let Err(e) = writeln!(self.file, "{line}").and_then(|_| self.file.flush()) {
            WRITE_FAILURES.fetch_add(1, Ordering::Relaxed);
            log::error!("spool write failed: {e}");
            return None;
        }
        EVENTS_WRITTEN.fetch_add(1, Ordering::Relaxed);
        self.bytes_written += line.len() as u64 + 1;
        self.maybe_rotate(now)
    }

    /// Triggers: size exceeded, or interval elapsed since the last
    /// rotation — but never with zero new bytes (no empty segments).
    fn rotation_due(&self, now: SystemTime) -> bool {
        if !self.seg.enabled() || self.bytes_written == 0 {
            return false;
        }
        if self.seg.max_bytes > 0 && self.bytes_written >= self.seg.max_bytes {
            return true;
        }
        if self.seg.interval_secs > 0 {
            if let Ok(elapsed) = now.duration_since(self.last_rotation) {
                if elapsed >= Duration::from_secs(self.seg.interval_secs) {
                    return true;
                }
            }
        }
        false
    }

    fn maybe_rotate(&mut self, now: SystemTime) -> Option<PathBuf> {
        if !self.rotation_due(now) {
            return None;
        }
        match self.rotate(now) {
            Ok(segment) => Some(segment),
            Err(e) => {
                log::warn!("spool rotation failed (continuing on live file): {e:#}");
                // Back off: don't retry (and re-fail) on every event.
                self.last_rotation = now;
                None
            }
        }
    }

    /// Close out the live file, rename it to a timestamped segment, and
    /// reopen a fresh live file.
    pub fn rotate(&mut self, now: SystemTime) -> Result<PathBuf> {
        let segment = segment_path(&self.path, &timestamp(now));
        if segment.exists() {
            anyhow::bail!("segment {} already exists", segment.display());
        }
        self.file.flush()?;
        fs::rename(&self.path, &segment)
            .with_context(|| format!("renaming live spool to {}", segment.display()))?;
        let (file, _) = open_hardened(&self.path, true)?;
        self.file = file;
        self.bytes_written = 0;
        self.last_rotation = now;
        log::info!("rotated spool to segment {}", segment.display());
        Ok(segment)
    }
}

/// Segment timestamp format: yyyyMMdd-HHmmss, local time (same as macOS).
pub fn timestamp(now: SystemTime) -> String {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&secs, &mut tm) };
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

/// "merlin-events.jsonl" + "20260802-141530" →
/// "merlin-events.20260802-141530.jsonl".
pub fn segment_path(live: &Path, ts: &str) -> PathBuf {
    let s = live.to_string_lossy();
    let base = s.strip_suffix(".jsonl").unwrap_or(&s);
    PathBuf::from(format!("{base}.{ts}.jsonl"))
}

/// Is `name` a finished (possibly uncompressed) segment of `live_name`?
pub fn is_segment_name(name: &str, live_name: &str) -> bool {
    let base = live_name.strip_suffix(".jsonl").unwrap_or(live_name);
    let Some(mid) = name
        .strip_prefix(&format!("{base}."))
        .and_then(|s| s.strip_suffix(".jsonl"))
    else {
        return false;
    };
    mid.len() == 15
        && mid.as_bytes()[8] == b'-'
        && mid.bytes().all(|b| b.is_ascii_digit() || b == b'-')
}

pub struct SegmentFile {
    pub body: Vec<u8>,
    pub modified: SystemTime,
}

/// Read a finished segment through a descriptor that cannot follow a symlink.
pub fn read_segment_no_follow(path: &Path, max_bytes: u64) -> Result<SegmentFile> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("opening segment {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("statting segment {}", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!("segment {} is not a regular file", path.display());
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        anyhow::bail!("segment {} is not owned by the daemon user", path.display());
    }
    if metadata.mode() & 0o077 != 0 {
        anyhow::bail!("segment {} is not private", path.display());
    }
    if metadata.len() > max_bytes {
        anyhow::bail!("segment {} exceeds the read limit", path.display());
    }
    let modified = metadata
        .modified()
        .with_context(|| format!("reading segment timestamp {}", path.display()))?;
    let mut body = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes + 1)
        .read_to_end(&mut body)
        .with_context(|| format!("reading segment {}", path.display()))?;
    if body.len() as u64 > max_bytes {
        anyhow::bail!("segment {} exceeds the read limit", path.display());
    }
    Ok(SegmentFile { body, modified })
}

/// Compress one finished segment to "<path>.gz" and delete the original —
/// only after the compressed file is fully written and fsynced. The whole
/// segment is read into memory (segments are rotation-bounded; fine for a
/// teaching sensor). Real gzip (RFC 1952) via flate2/miniz_oxide.
pub fn compress_segment(path: &Path) -> Result<PathBuf> {
    let input = read_segment_no_follow(path, 64 << 20)?.body;
    let gz_path = PathBuf::from(format!("{}.gz", path.display()));
    let mut out = OpenOptions::new()
        .create_new(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .mode(0o600)
        .open(&gz_path)
        .with_context(|| format!("creating {}", gz_path.display()))?;
    {
        let mut enc = GzEncoder::new(&mut out, Compression::default());
        enc.write_all(&input)?;
        enc.finish()?;
    }
    out.sync_all()?;
    fs::remove_file(path)?;
    Ok(gz_path)
}

/// Startup sweep: compress orphaned (uncompressed) segments next to the
/// live file. The live file itself is never touched.
pub fn sweep_orphans(live_path: &Path) -> Result<usize> {
    let dir = live_path.parent().unwrap_or(Path::new("."));
    let live_name = live_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut swept = 0;
    for entry in fs::read_dir(dir).with_context(|| format!("sweeping {}", dir.display()))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !is_segment_name(&name, &live_name) {
            continue;
        }
        match compress_segment(&entry.path()) {
            Ok(_) => {
                log::info!("swept orphaned segment {name}");
                swept += 1;
            }
            Err(e) => log::warn!("orphan sweep could not compress {name}: {e:#}"),
        }
    }
    Ok(swept)
}

/// Spawn the spool writer task. Every received event becomes one JSON
/// line, flushed immediately. Finished segments are compressed on
/// background tasks, never on the write path.
pub async fn spawn(
    path: PathBuf,
    mut rx: Receiver<Value>,
    seg: SegmentConfig,
    health: HealthConfig,
) -> Result<JoinHandle<()>> {
    let mut spool = LiveSpool::open(path, seg)?;
    if seg.enabled() {
        match sweep_orphans(spool.path()) {
            Ok(n) if n > 0 => log::info!("orphan sweep compressed {n} segment(s)"),
            Ok(_) => {}
            Err(e) => log::warn!("orphan sweep failed: {e:#}"),
        }
    }
    Ok(tokio::spawn(async move {
        let mut timer =
            (health.interval > Duration::ZERO).then(|| tokio::time::interval(health.interval));
        loop {
            if let Some(timer) = timer.as_mut() {
                tokio::select! {
                    event = rx.recv() => {
                        let Some(event) = event else { break };
                        if let Some(segment) = write_value(&mut spool, event, SystemTime::now()) {
                            tokio::task::spawn_blocking(move || {
                                if let Err(e) = compress_segment(&segment) {
                                    log::warn!("segment compression failed (kept uncompressed): {e:#}");
                                }
                            });
                        }
                    }
                    _ = timer.tick() => {
                        if let Some(segment) = write_value(&mut spool, health_event(&health), SystemTime::now()) {
                            tokio::task::spawn_blocking(move || {
                                if let Err(e) = compress_segment(&segment) {
                                    log::warn!("segment compression failed (kept uncompressed): {e:#}");
                                }
                            });
                        }
                    }
                }
            } else {
                let Some(event) = rx.recv().await else { break };
                if let Some(segment) = write_value(&mut spool, event, SystemTime::now()) {
                    tokio::task::spawn_blocking(move || {
                        if let Err(e) = compress_segment(&segment) {
                            log::warn!("segment compression failed (kept uncompressed): {e:#}");
                        }
                    });
                }
            }
        }
    }))
}

/// Producers are synchronous (fanotify and ring-buffer callbacks), so they
/// use try_send. Dropping telemetry under pressure is intentional and keeps
/// enforcement responsive and memory-bounded.
pub fn try_send(tx: &Sender<Value>, event: Value) -> bool {
    EVENTS_ATTEMPTED.fetch_add(1, Ordering::Relaxed);
    match tx.try_send(event) {
        Ok(()) => {
            EVENTS_ACCEPTED.fetch_add(1, Ordering::Relaxed);
            true
        }
        Err(e) => {
            EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed);
            log::warn!("dropping telemetry event under spool backpressure: {e}");
            false
        }
    }
}

/// Read back a compressed segment (tests and forensics).
#[cfg(test)]
fn gunzip(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut dec = flate2::read::GzDecoder::new(File::open(path)?);
    let mut s = String::new();
    dec.read_to_string(&mut s)?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("merlin-test-{}-{tag}.jsonl", std::process::id()))
    }

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn cleanup(p: &Path) {
        let _ = fs::remove_file(p);
        let _ = fs::remove_file(PathBuf::from(format!("{}.gz", p.display())));
    }

    #[test]
    fn bounded_channel_drops_when_full() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        assert!(try_send(&tx, serde_json::json!({"kind": "first"})));
        assert!(!try_send(&tx, serde_json::json!({"kind": "second"})));
    }

    #[test]
    fn decoration_exposes_identity_and_observe_only_signals() {
        let mut event = serde_json::json!({
            "kind": "security",
            "source_seq": 9,
            "pid": 42,
            "pid_start_time": 77,
            "namespace_valid": true,
            "syscall": "ptrace",
            "w_x_transition": true,
        });
        decorate_event(&mut event);
        assert_eq!(event["schema_version"], 1);
        assert_eq!(
            event["event_id"]
                .as_str()
                .unwrap()
                .split(':')
                .next()
                .unwrap()
                .is_empty(),
            false
        );
        assert_eq!(event["process_key"].as_str().unwrap().split(':').count(), 3);
        assert_eq!(
            event["signals"],
            serde_json::json!(["w_x_transition", "process_injection"])
        );
    }

    #[test]
    fn invalid_namespace_never_gets_a_process_key() {
        let mut event = serde_json::json!({
            "kind": "exec",
            "pid": 42,
            "pid_start_time": 77,
            "namespace_valid": false,
        });
        decorate_event(&mut event);
        assert!(event["process_key"].is_null());
    }

    #[test]
    fn segment_naming_and_matching() {
        let live = Path::new("/x/merlin-events.jsonl");
        let seg = segment_path(live, "20260802-141530");
        assert_eq!(seg, Path::new("/x/merlin-events.20260802-141530.jsonl"));
        assert!(is_segment_name(
            "merlin-events.20260802-141530.jsonl",
            "merlin-events.jsonl"
        ));
        assert!(!is_segment_name(
            "merlin-events.jsonl",
            "merlin-events.jsonl"
        ));
        assert!(!is_segment_name(
            "merlin-events.20260802-141530.jsonl.gz",
            "merlin-events.jsonl"
        ));
        assert!(!is_segment_name(
            "other.20260802-141530.jsonl",
            "merlin-events.jsonl"
        ));
        assert!(!is_segment_name(
            "merlin-events.not-a-time.jsonl",
            "merlin-events.jsonl"
        ));
    }

    #[test]
    fn bytes_trigger_rotates_and_live_continues() {
        let live = tmp("bytes");
        cleanup(&live);
        let mut spool = LiveSpool::open(
            live.clone(),
            SegmentConfig {
                interval_secs: 0,
                max_bytes: 50,
            },
        )
        .unwrap();
        assert!(
            spool
                .write_line("{\"kind\":\"exec\",\"n\":1}", at(1000))
                .is_none()
        );
        let segment = spool
            .write_line(
                "{\"kind\":\"exec\",\"n\":2-this-pushes-past-50-bytes}",
                at(1001),
            )
            .expect("size trigger must rotate");
        // The segment holds everything up to the rotation point; the fresh
        // live file continues seamlessly afterwards.
        spool.write_line("{\"kind\":\"exec\",\"n\":3}", at(1002));
        let seg_text = fs::read_to_string(&segment).unwrap();
        assert!(seg_text.contains("\"n\":1") && seg_text.contains("\"n\":2"));
        let live_text = fs::read_to_string(&live).unwrap();
        assert_eq!(live_text, "{\"kind\":\"exec\",\"n\":3}\n");
        cleanup(&live);
        cleanup(&segment);
    }

    #[test]
    fn interval_trigger_and_no_empty_segments() {
        let live = tmp("interval");
        cleanup(&live);
        let mut spool = LiveSpool::open_at(
            live.clone(),
            SegmentConfig {
                interval_secs: 5,
                max_bytes: 0,
            },
            at(1000),
        )
        .unwrap();
        spool.write_line("one", at(1000));
        assert!(spool.write_line("two", at(1003)).is_none());
        // Interval elapsed with new bytes present → rotate on this write.
        let segment = spool
            .write_line("three", at(1006))
            .expect("interval trigger must rotate");
        assert_eq!(fs::read_to_string(&live).unwrap(), "");
        // Fresh window: the very next write does NOT rotate again.
        assert!(spool.write_line("four", at(1007)).is_none());
        // Quiet period: with zero bytes since the last rotation, a
        // much-later write rotates only after landing (never an empty
        // segment in between).
        let segment2 = spool
            .write_line("five", at(2000))
            .expect("interval elapsed with new bytes");
        let seg_text = fs::read_to_string(&segment).unwrap();
        assert_eq!(seg_text, "one\ntwo\nthree\n");
        assert_eq!(fs::read_to_string(&segment2).unwrap(), "four\nfive\n");
        assert_eq!(fs::read_to_string(&live).unwrap(), "");
        cleanup(&live);
        cleanup(&segment);
        cleanup(&segment2);
    }

    #[test]
    fn gzip_roundtrip_line_for_line() {
        let live = tmp("gzip");
        cleanup(&live);
        let mut spool = LiveSpool::open(
            live.clone(),
            SegmentConfig {
                interval_secs: 0,
                max_bytes: 10,
            },
        )
        .unwrap();
        // "alpha\n" = 6 bytes, "beta\n" pushes past 10 → rotation.
        assert!(spool.write_line("alpha", at(1000)).is_none());
        let segment = spool
            .write_line("beta", at(1001))
            .expect("size trigger must rotate");
        assert!(spool.write_line("gamma", at(1002)).is_none());
        let gz = compress_segment(&segment).unwrap();
        assert!(
            !segment.exists(),
            "uncompressed segment deleted after compress+fsync"
        );
        let decoded = gunzip(&gz).unwrap();
        assert_eq!(decoded, "alpha\nbeta\n");
        assert_eq!(fs::read_to_string(&live).unwrap(), "gamma\n");
        cleanup(&live);
        cleanup(&segment);
    }

    #[test]
    fn orphan_sweep_compresses_strays_not_live() {
        let live = tmp("sweep");
        cleanup(&live);
        let orphan = segment_path(&live, "20260101-000000");
        fs::write(&orphan, "orphaned\n").unwrap();
        fs::set_permissions(&orphan, fs::Permissions::from_mode(0o600)).unwrap();
        let mut spool = LiveSpool::open(
            live.clone(),
            SegmentConfig {
                interval_secs: 60,
                max_bytes: 0,
            },
        )
        .unwrap();
        spool.write_line("live-data", at(1000));
        drop(spool);
        let swept = sweep_orphans(&live).unwrap();
        assert_eq!(swept, 1);
        assert!(!orphan.exists());
        assert!(PathBuf::from(format!("{}.gz", orphan.display())).exists());
        assert_eq!(fs::read_to_string(&live).unwrap(), "live-data\n");
        cleanup(&live);
        cleanup(&orphan);
    }

    #[test]
    fn rotation_failure_keeps_live_file() {
        let live = tmp("fail");
        cleanup(&live);
        let now = at(1000);
        // Pre-create the would-be segment so rotation must fail.
        let blocker = segment_path(&live, &timestamp(now));
        fs::write(&blocker, "occupying").unwrap();
        let mut spool = LiveSpool::open(
            live.clone(),
            SegmentConfig {
                interval_secs: 0,
                max_bytes: 5,
            },
        )
        .unwrap();
        assert!(spool.write_line("more-than-five-bytes", now).is_none());
        // Live file still works afterwards.
        spool.write_line("still-alive", now);
        let text = fs::read_to_string(&live).unwrap();
        assert!(text.contains("more-than-five-bytes") && text.contains("still-alive"));
        assert_eq!(fs::read_to_string(&blocker).unwrap(), "occupying");
        cleanup(&live);
        let _ = fs::remove_file(&blocker);
    }

    #[test]
    fn live_open_rejects_symlink() {
        let live = tmp("symlink");
        let target = tmp("symlink-target");
        cleanup(&live);
        fs::write(&target, "x").unwrap();
        std::os::unix::fs::symlink(&target, &live).unwrap();
        let err = LiveSpool::open(live.clone(), SegmentConfig::default())
            .err()
            .expect("symlinked spool must be rejected");
        assert!(format!("{err:#}").contains("opening spool"), "{err:#}");
        cleanup(&live);
        let _ = fs::remove_file(&target);
    }

    #[test]
    fn segment_read_rejects_symlink() {
        let target = tmp("segment-read-target");
        let link = tmp("segment-read-link");
        fs::write(&target, b"telemetry").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let error = read_segment_no_follow(&link, 1024)
            .err()
            .expect("symlinked segment must be rejected");
        assert!(format!("{error:#}").contains("opening segment"));
        let _ = fs::remove_file(link);
        let _ = fs::remove_file(target);
    }
}
