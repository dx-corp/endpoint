//! Deixic Endpoint telemetry and policy enforcement for Linux.
//!
//! eBPF tracepoints/kprobe collect exec/exit/connect telemetry into a ring
//! buffer; a fanotify monitor provides synchronous exec blocking; a YAML
//! rules engine drives log/kill/block actions; everything lands in an
//! append-only JSONL spool.

mod alert;
mod bpfcheck;
mod check;
mod desired_state;
mod dnsmon;
mod fanotify_mon;
mod fileless;
mod filemon;
mod linux_posture;
mod netifmon;
mod persistence_mon;
mod portability;
mod posture;
mod proctree;
mod rules;
mod scripts;
mod spool;
mod sync;
mod taskstats;
mod telemetry;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "merlin",
    version,
    about = "Deixic Endpoint: endpoint telemetry and policy enforcement for Linux"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Load the eBPF collector, start the fanotify enforcement monitor and
    /// stream events to the JSONL spool.
    Run {
        /// YAML rules file (repeatable; multiple files are merged).
        #[arg(long, default_value = "rules/block-demo.yaml")]
        rules: Vec<PathBuf>,
        /// Append-only JSONL event spool.
        #[arg(long, default_value = "./merlin-events.jsonl")]
        spool: PathBuf,
        /// Path to the compiled eBPF object.
        #[arg(long)]
        ebpf: Option<PathBuf>,
        /// Disable the bounded persistence-surface inventory.
        #[arg(long)]
        no_persistence_watch: bool,
        /// Seconds spent hashing one executable at the synchronous
        /// exec-block point before it counts as unhashable. Every exec on
        /// the box queues behind this.
        #[arg(long, default_value_t = fanotify_mon::HashPolicy::default().budget.as_secs_f64())]
        max_hash_seconds: f64,
        /// Allow execs that blow --max-hash-seconds even when a hash-based
        /// block rule would have to be resolved against them. A payload an
        /// attacker can make slow to read then bypasses those rules.
        #[arg(long)]
        allow_unhashable: bool,
        /// Emit a periodic health event with capability and loss counters;
        /// set to 0 to disable the timer.
        #[arg(long, default_value_t = 10)]
        health_interval_seconds: u64,
        /// Extra path for file-state telemetry (repeatable; directories
        /// get dirent + child-write events, files get modify events).
        /// The default persistence locations are always watched.
        #[arg(long)]
        watch: Vec<PathBuf>,
        /// Rotate the spool after this many seconds (0 = off). Quiet
        /// periods never produce empty segments.
        #[arg(long, default_value_t = 0)]
        segment_interval: u64,
        /// Rotate the spool when the live file exceeds this many bytes
        /// (0 = off).
        #[arg(long, default_value_t = 0)]
        segment_bytes: u64,
        /// Cap the `security` syscall event stream at this many events per
        /// second at the spool dispatch point (0 = unlimited). Event
        /// generation is unaffected; excess events are counted and dropped.
        #[arg(long, default_value_t = 50.0)]
        security_rate_limit: f64,
        /// Sync server base URL (e.g. http://host:8443). Enables segment
        /// upload and managed-rules sync. Off by default.
        #[arg(long)]
        sync: Option<String>,
        /// Legacy unmanaged telemetry key (hex or base64; falls back to
        /// MERLIN_LEGACY_SYNC_KEY). Managed devices do not use it.
        #[arg(long)]
        sync_key: Option<String>,
        /// Registered device id (falls back to MERLIN_DEVICE_ID). Enables
        /// authenticated device check-ins and policy update delivery.
        #[arg(long)]
        device_id: Option<String>,
        /// One-time enrollment token for the registered device (falls back
        /// to MERLIN_DEVICE_TOKEN).
        #[arg(long)]
        device_token: Option<String>,
        /// Trusted Ed25519 policy public key, hex or base64 (falls back to
        /// MERLIN_POLICY_PUBLIC_KEY). Required for managed policy delivery.
        #[arg(long)]
        policy_public_key: Option<String>,
        /// Comma-separated trusted Ed25519 public keys for a rotation window
        /// (falls back to MERLIN_POLICY_PUBLIC_KEYS).
        #[arg(long)]
        policy_public_keys: Option<String>,
        /// POST compact JSON alerts (deny/kill/cred-to-root) to this URL.
        /// Fire-and-forget, bounded queue, off by default.
        #[arg(long)]
        alert_webhook: Option<String>,
    },
    /// Verify fanotify support and eBPF attach, print readiness.
    Check {
        /// Path to the compiled eBPF object.
        #[arg(long)]
        ebpf: Option<PathBuf>,
        /// Emit a capability report as one JSON object.
        #[arg(long)]
        json: bool,
    },
    /// Print the sha256 of a file, ready to paste into a rules file.
    GenHash { path: PathBuf },
    /// One-shot posture report: AF_PACKET holders and container-socket peers.
    Posture,
}

fn default_ebpf_candidates() -> Vec<PathBuf> {
    vec![
        PathBuf::from("./merlin-ebpf.o"),
        PathBuf::from("merlin-ebpf/target/bpfel-unknown-none/release/merlin-ebpf"),
        PathBuf::from("../merlin-ebpf/target/bpfel-unknown-none/release/merlin-ebpf"),
    ]
}

fn resolve_ebpf_path(arg: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = arg {
        return Ok(p);
    }
    if let Ok(p) = std::env::var("MERLIN_EBPF_PATH") {
        return Ok(PathBuf::from(p));
    }
    default_ebpf_candidates()
        .into_iter()
        .find(|p| p.exists())
        .context("no eBPF object found; pass --ebpf or set MERLIN_EBPF_PATH")
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Posture => posture::run(),
        Cmd::GenHash { path } => {
            let hash = fanotify_mon::sha256_path(&path)?;
            println!("{hash}  {}", path.display());
            Ok(())
        }
        Cmd::Check { ebpf, json } => {
            let path = match ebpf {
                Some(p) => Some(p),
                None => default_ebpf_candidates().into_iter().find(|p| p.exists()),
            };
            let ok = check::run(path, json).await?;
            std::process::exit(if ok { 0 } else { 1 });
        }
        Cmd::Run {
            rules,
            spool,
            ebpf,
            no_persistence_watch,
            max_hash_seconds,
            allow_unhashable,
            health_interval_seconds,
            watch,
            segment_interval,
            segment_bytes,
            security_rate_limit,
            sync,
            sync_key,
            device_id,
            device_token,
            policy_public_key,
            policy_public_keys,
            alert_webhook,
        } => {
            anyhow::ensure!(
                max_hash_seconds.is_finite() && max_hash_seconds > 0.0,
                "--max-hash-seconds must be a positive number of seconds"
            );
            anyhow::ensure!(
                security_rate_limit.is_finite() && security_rate_limit >= 0.0,
                "--security-rate-limit must be a non-negative number (0 = unlimited)"
            );
            let policy = fanotify_mon::HashPolicy {
                budget: std::time::Duration::from_secs_f64(max_hash_seconds),
                allow_unhashable,
            };
            let segmentation = spool::SegmentConfig {
                interval_secs: segment_interval,
                max_bytes: segment_bytes,
            };
            let device_id = device_id
                .or_else(|| std::env::var("MERLIN_DEVICE_ID").ok())
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty());
            let device_token = device_token
                .or_else(|| std::env::var("MERLIN_DEVICE_TOKEN").ok())
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty());
            let policy_public_key = policy_public_key
                .or_else(|| std::env::var("MERLIN_POLICY_PUBLIC_KEY").ok())
                .map(|value| sync::parse_key(&value));
            let policy_public_keys = policy_public_keys
                .or_else(|| std::env::var("MERLIN_POLICY_PUBLIC_KEYS").ok())
                .map(|value| {
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(sync::parse_key)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            anyhow::ensure!(
                device_id.is_some() == device_token.is_some(),
                "--device-id and --device-token must be supplied together"
            );
            anyhow::ensure!(
                device_id.is_none()
                    || policy_public_key
                        .as_ref()
                        .is_some_and(|key| key.len() == 32)
                    || !policy_public_keys.is_empty(),
                "managed policy delivery requires --policy-public-key or --policy-public-keys"
            );
            anyhow::ensure!(
                policy_public_keys.iter().all(|key| key.len() == 32),
                "every managed policy public key must be 32 bytes"
            );
            anyhow::ensure!(
                policy_public_key.as_ref().is_none_or(|key| key.len() == 32),
                "the managed policy public key must be 32 bytes"
            );
            let sync_cfg = match sync {
                Some(url) => {
                    let key = sync_key.or_else(|| std::env::var("MERLIN_LEGACY_SYNC_KEY").ok());
                    anyhow::ensure!(
                        device_id.is_some() || key.is_some(),
                        "--sync requires managed device credentials or --sync-key/MERLIN_LEGACY_SYNC_KEY"
                    );
                    Some(sync::SyncConfig {
                        base_url: url.trim_end_matches('/').to_string(),
                        key: key.as_deref().map(sync::parse_key).unwrap_or_default(),
                        device_id,
                        device_token,
                        policy_public_key: policy_public_key.unwrap_or_default(),
                        policy_public_keys,
                        sensor_mode: "sensor_policy".to_string(),
                    })
                }
                None => {
                    anyhow::ensure!(
                        device_id.is_none() && device_token.is_none(),
                        "--device-id and --device-token require --sync"
                    );
                    None
                }
            };
            run(
                rules,
                spool,
                resolve_ebpf_path(ebpf)?,
                no_persistence_watch,
                watch,
                policy,
                segmentation,
                health_interval_seconds,
                security_rate_limit,
                sync_cfg,
                alert_webhook,
            )
            .await
        }
    }
}

async fn run(
    rules_paths: Vec<PathBuf>,
    spool_path: PathBuf,
    ebpf_path: PathBuf,
    no_persistence_watch: bool,
    watch: Vec<PathBuf>,
    hash_policy: fanotify_mon::HashPolicy,
    segmentation: spool::SegmentConfig,
    health_interval_seconds: u64,
    security_rate_limit: f64,
    sync_cfg: Option<sync::SyncConfig>,
    alert_webhook: Option<String>,
) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!("merlin run needs root (eBPF load + fanotify permission events); use sudo");
    }

    let mut merged = rules::Rules {
        schema_version: 1,
        rules: Vec::new(),
        doh_resolvers: Vec::new(),
    };
    let mut merged_source = Vec::new();
    for path in &rules_paths {
        let (part, source) = rules::Rules::load_with_source(path)
            .with_context(|| format!("loading rules from {}", path.display()))?;
        merged_source.extend_from_slice(&source);
        log::info!("loaded {} rules from {}", part.rules.len(), path.display());
        merged.rules.extend(part.rules);
    }
    let first_rules = rules_paths
        .first()
        .cloned()
        .unwrap_or_else(|| PathBuf::from("rules.yaml"));
    let mut current_rules_sha = sync::sha256_hex(&merged_source);
    if let Some(cfg) = sync_cfg.as_ref() {
        match sync::load_cached_policy(cfg, &first_rules) {
            Ok(Some((cached, sha))) => {
                log::info!(
                    "loaded {} verified cached managed rules (sha256 {})",
                    cached.rules.len(),
                    sha
                );
                merged = cached;
                current_rules_sha = sha;
            }
            Ok(None) => {}
            Err(error) => {
                log::warn!("cached managed policy rejected ({error:#}); using bootstrap rules")
            }
        }
    }
    let rules = rules::RulesHandle::new(merged);
    for rule in &rules.get().rules {
        if let Some(note) = &rule.note {
            log::debug!("rule {}: {}", rule.name, note);
        }
    }

    // Telemetry is intentionally lossy under backpressure, but must not let
    // attacker-driven event volume grow the daemon without a memory bound.
    let (tx, rx) = tokio::sync::mpsc::channel(4096);
    let portability = portability::require_ready()?;
    let mut capabilities = vec![
        "linux-ebpf".into(),
        "fanotify_exec_prevention".into(),
        "persistence_metadata".into(),
        "bounded_telemetry".into(),
    ];
    capabilities.push(format!(
        "tracepoint_layouts:{}",
        portability.tracepoints.len()
    ));
    spool::spawn(
        spool_path.clone(),
        rx,
        segmentation,
        spool::HealthConfig {
            interval: std::time::Duration::from_secs(health_interval_seconds),
            capabilities,
            arch: portability.arch.to_string(),
            syscall_abi: portability.abi_name().to_string(),
            queue_capacity: 4096,
        },
    )
    .await?;

    // Lineage cache shared by the telemetry task (exec/exit events) and
    // the file monitor (pid attribution for file events).
    let table = Arc::new(Mutex::new(proctree::ProcTable::sweep()));
    log::info!(
        "process table seeded with {} pids",
        table.lock().unwrap().len()
    );

    // Enforcement monitor first: if fanotify is broken we fail before
    // attaching the collector.
    let alert = alert_webhook.map(alert::spawn);

    fanotify_mon::spawn(rules.clone(), tx.clone(), hash_policy, alert.clone())?;

    let _persistence = if no_persistence_watch {
        log::info!("persistence watch disabled by --no-persistence-watch");
        None
    } else {
        match persistence_mon::spawn(tx.clone()) {
            Ok(handle) => Some(handle),
            Err(e) => {
                // Inventory is telemetry-only. A watcher startup failure must
                // not turn into an enforcement outage or a fail-closed path.
                log::warn!("persistence watch unavailable: {e:#}");
                None
            }
        }
    };

    // DNS telemetry (AF_PACKET, port 53 both directions).
    dnsmon::spawn(tx.clone())?;

    // Network/task/BPF telemetry threads are fail-open: a startup failure
    // is telemetry loss, never a daemon outage.
    if let Err(e) = netifmon::spawn(tx.clone()) {
        log::warn!("netifmon unavailable: {e:#}");
    }
    if let Err(e) = taskstats::spawn(tx.clone()) {
        log::warn!("taskstats unavailable: {e:#}");
    }
    bpfcheck::spawn(tx.clone());

    // File-state telemetry (notification-only fanotify groups).
    filemon::spawn(&watch, rules.clone(), Arc::clone(&table), tx.clone())?;

    // Managed-mode sync (segment upload + rules hot-reload). Fail-open by
    // design; a sync outage never affects collection.
    if let Some(cfg) = sync_cfg {
        let client = sync::SyncClient::new(
            cfg,
            spool_path.clone(),
            &first_rules,
            rules.clone(),
            current_rules_sha,
        );
        sync::spawn(client)?;
    }

    let bpf = aya::Ebpf::load_file(&ebpf_path)
        .with_context(|| format!("loading eBPF object {}", ebpf_path.display()))?;
    telemetry::spawn(bpf, rules, tx, table, security_rate_limit, alert).await?;

    log::info!("merlin is running; ctrl-c to stop");
    tokio::signal::ctrl_c().await?;
    log::info!("shutting down");
    Ok(())
}
