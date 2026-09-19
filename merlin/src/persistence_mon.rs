//! Bounded persistence-surface inventory for Linux.
//!
//! Companion to `filemon` (the fanotify file-state monitor): the two
//! deliberately overlap on some paths — this module is the broad polling
//! layer, filemon is the real-time pid-attributed one. See "Two
//! persistence layers, deliberately" in docs/linux-sensor.md.
//!
//! eBPF is excellent at process and syscall context, but pathname capture for
//! every filesystem operation is kernel/version dependent and easy to make
//! unsafe. This watcher deliberately observes a small, explicit set of
//! persistence locations from userspace. It uses `symlink_metadata`, caps
//! recursion and entries, and records metadata only — never file contents.
//! A baseline is kept in memory; only create/modify/delete/rename deltas are
//! spooled. Failure is telemetry-only and never changes enforcement.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::Value;
use tokio::sync::mpsc::Sender;

use crate::spool;

const MAX_DEPTH: usize = 2;
const MAX_ENTRIES: usize = 4096;
const DEFAULT_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileMeta {
    device: u64,
    inode: u64,
    size: u64,
    mtime_ns: i128,
    mode: u32,
    uid: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Observed {
    meta: FileMeta,
    label: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileDelta {
    path: String,
    label: &'static str,
    op: &'static str,
    observed: Option<Observed>,
}

/// Named high-value persistence surfaces. The list is intentionally reviewable
/// and conservative rather than a recursive scan of the whole filesystem.
pub fn watch_targets() -> Vec<(PathBuf, &'static str, bool)> {
    vec![
        (PathBuf::from("/etc/systemd/system"), "systemd", true),
        (PathBuf::from("/lib/systemd/system"), "systemd", true),
        (PathBuf::from("/usr/lib/systemd/system"), "systemd", true),
        (PathBuf::from("/etc/cron.d"), "cron", true),
        (PathBuf::from("/etc/cron.daily"), "cron", true),
        (PathBuf::from("/etc/cron.hourly"), "cron", true),
        (PathBuf::from("/etc/cron.weekly"), "cron", true),
        (PathBuf::from("/etc/cron.monthly"), "cron", true),
        (PathBuf::from("/var/spool/cron"), "cron", true),
        (PathBuf::from("/etc/crontab"), "cron", false),
        (
            PathBuf::from("/etc/ssh/authorized_keys"),
            "ssh_authorized_keys",
            false,
        ),
        (
            PathBuf::from("/root/.ssh/authorized_keys"),
            "ssh_authorized_keys",
            false,
        ),
        (PathBuf::from("/etc/profile"), "shell_startup", false),
        (PathBuf::from("/etc/profile.d"), "shell_startup", true),
        (PathBuf::from("/etc/rc.local"), "shell_startup", false),
        (PathBuf::from("/etc/udev/rules.d"), "udev", true),
        (PathBuf::from("/etc/modules"), "kernel_modules", false),
        (PathBuf::from("/etc/modules-load.d"), "kernel_modules", true),
        (PathBuf::from("/etc/modprobe.d"), "kernel_modules", true),
    ]
}

/// Start the watcher thread after taking a baseline. The returned thread is
/// intentionally detached by the daemon: the process lifetime owns it, and a
/// closed spool channel causes it to exit naturally.
pub fn spawn(tx: Sender<Value>) -> Result<thread::JoinHandle<()>> {
    let baseline = snapshot_targets();
    log::info!(
        "persistence watch: baseline contains {} metadata entries",
        baseline.len()
    );
    thread::Builder::new()
        .name("persistence".into())
        .spawn(move || run_loop(tx, baseline))
        .context("spawning persistence watcher thread")
}

fn run_loop(tx: Sender<Value>, mut previous: HashMap<String, Observed>) {
    loop {
        thread::sleep(DEFAULT_INTERVAL);
        let current = snapshot_targets();
        for delta in diff_snapshots(&previous, &current) {
            let Some(event) = delta_event(delta) else {
                continue;
            };
            if !spool::try_send(&tx, event) {
                // Backpressure remains fail-open and bounded, just like the
                // eBPF and fanotify producers.
            }
        }
        previous = current;
        if tx.is_closed() {
            return;
        }
    }
}

fn snapshot_targets() -> HashMap<String, Observed> {
    let mut out = HashMap::new();
    let mut count = 0usize;
    for (path, label, recursive) in watch_targets() {
        if count >= MAX_ENTRIES {
            log::warn!("persistence watch entry cap {} reached", MAX_ENTRIES);
            break;
        }
        if recursive {
            collect_dir(&path, label, 0, &mut out, &mut count);
        } else {
            collect_file(&path, label, &mut out, &mut count);
        }
    }
    out
}

fn collect_dir(
    path: &Path,
    label: &'static str,
    depth: usize,
    out: &mut HashMap<String, Observed>,
    count: &mut usize,
) {
    if depth > MAX_DEPTH || *count >= MAX_ENTRIES {
        return;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        if *count >= MAX_ENTRIES {
            return;
        }
        let child = entry.path();
        let Ok(meta) = fs::symlink_metadata(&child) else {
            continue;
        };
        if meta.file_type().is_dir() && !meta.file_type().is_symlink() && depth < MAX_DEPTH {
            collect_dir(&child, label, depth + 1, out, count);
        } else {
            insert_meta(child, label, meta, out, count);
        }
    }
}

fn collect_file(
    path: &Path,
    label: &'static str,
    out: &mut HashMap<String, Observed>,
    count: &mut usize,
) {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return;
    };
    insert_meta(path.to_path_buf(), label, meta, out, count);
}

fn insert_meta(
    path: PathBuf,
    label: &'static str,
    meta: fs::Metadata,
    out: &mut HashMap<String, Observed>,
    count: &mut usize,
) {
    let Some(path) = path.to_str() else { return };
    out.insert(
        path.to_string(),
        Observed {
            meta: FileMeta {
                device: meta.dev(),
                inode: meta.ino(),
                size: meta.size(),
                mtime_ns: i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec()),
                mode: meta.mode(),
                uid: meta.uid(),
            },
            label,
        },
    );
    *count += 1;
}

fn diff_snapshots(
    old: &HashMap<String, Observed>,
    new: &HashMap<String, Observed>,
) -> Vec<FileDelta> {
    let mut deltas = Vec::new();
    let mut renamed_inodes: HashMap<(u64, u64), String> = HashMap::new();
    for (path, old_value) in old {
        if !new.contains_key(path) {
            renamed_inodes.insert((old_value.meta.device, old_value.meta.inode), path.clone());
        }
    }
    for (path, current) in new {
        match old.get(path) {
            None => {
                let op = if renamed_inodes.contains_key(&(current.meta.device, current.meta.inode))
                {
                    "rename"
                } else {
                    "create"
                };
                deltas.push(FileDelta {
                    path: path.clone(),
                    label: current.label,
                    op,
                    observed: Some(current.clone()),
                });
            }
            Some(previous) if previous != current => deltas.push(FileDelta {
                path: path.clone(),
                label: current.label,
                op: "modify",
                observed: Some(current.clone()),
            }),
            _ => {}
        }
    }
    for (path, previous) in old {
        if !new.contains_key(path)
            && !new.values().any(|current| {
                current.meta.device == previous.meta.device
                    && current.meta.inode == previous.meta.inode
            })
        {
            deltas.push(FileDelta {
                path: path.clone(),
                label: previous.label,
                op: "delete",
                observed: None,
            });
        }
    }
    deltas.sort_by(|a, b| a.path.cmp(&b.path));
    deltas
}

fn delta_event(delta: FileDelta) -> Option<Value> {
    let observed = delta.observed;
    Some(serde_json::json!({
        "ts": spool::now_ts(),
        "source": "linux-persistence",
        "source_seq": spool::next_sequence(),
        "kind": "file",
        "pid": Value::Null,
        "uid": observed.as_ref().map(|v| v.meta.uid),
        "path": delta.path,
        "op": delta.op,
        "label": delta.label,
        "device": observed.as_ref().map(|v| v.meta.device),
        "inode": observed.as_ref().map(|v| v.meta.inode),
        "size": observed.as_ref().map(|v| v.meta.size),
        "mode": observed.as_ref().map(|v| format!("{:o}", v.meta.mode & 0o7777)),
        "namespace_valid": Value::Null,
        "content_collected": false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(inode: u64, size: u64) -> Observed {
        Observed {
            meta: FileMeta {
                device: 1,
                inode,
                size,
                mtime_ns: 1,
                mode: 0o100644,
                uid: 0,
            },
            label: "test",
        }
    }

    #[test]
    fn diff_classifies_lifecycle_and_rename() {
        let old = HashMap::from([
            ("/old".to_string(), observed(7, 1)),
            ("/gone".to_string(), observed(8, 1)),
            ("/changed".to_string(), observed(9, 1)),
        ]);
        let new = HashMap::from([
            ("/new".to_string(), observed(7, 1)),
            ("/changed".to_string(), observed(9, 2)),
        ]);
        let events = diff_snapshots(&old, &new);
        assert!(events.iter().any(|e| e.path == "/new" && e.op == "rename"));
        assert!(events.iter().any(|e| e.path == "/gone" && e.op == "delete"));
        assert!(
            events
                .iter()
                .any(|e| e.path == "/changed" && e.op == "modify")
        );
    }
}
