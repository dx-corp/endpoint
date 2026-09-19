//! File-state telemetry: fanotify *notification* marks on persistence
//! locations, separate from the exec-blocking permission group.
//!
//! Companion to `persistence_mon` (the bounded polling inventory): the two
//! deliberately overlap on some paths — this module is the real-time,
//! pid-attributed, rule-matched layer. See "Two persistence layers,
//! deliberately" in docs/linux-sensor.md.
//!
//! Two fanotify groups, one thread each:
//! - a plain group for FAN_CLOSE_WRITE. Directories are marked with
//!   FAN_EVENT_ON_CHILD, files directly. Events carry an open fd, so the
//!   full path is a /proc/self/fd readlink away.
//! - an FID group (FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME)
//!   for the dirent events FAN_CREATE / FAN_DELETE / FAN_MOVED_FROM /
//!   FAN_MOVED_TO, which only exist in FID mode. Events carry the parent
//!   dir's file handle plus the child name; handles are mapped back to the
//!   marked dir paths captured at setup with name_to_handle_at (no
//!   open_by_handle_at, no extra caps needed).
//!
//! pid attribution comes from the event metadata (fanotify reports the
//! actor's pid translated into the listener's pid namespace — 0 means the
//! process is not visible here, the fanotify analog of pid_ns_valid; such
//! events spool with null attribution and no /proc or lineage lookups).
//! comm/cmdline/lineage are resolved from /proc and the proctree cache,
//! best-effort.
//!
//! Backpressure: like every producer, filemon sends via spool::try_send on
//! the bounded (4096) channel — a full channel drops the event with a
//! warning. Telemetry is lossy under pressure; enforcement never blocks.
//!
//! Ops: create | modify | delete | rename. FAN_MOVED_TO maps to "rename"
//! (a new path appeared — the persistence-relevant direction) and
//! FAN_MOVED_FROM to "delete" (the path left the watch). A queued event
//! can carry several op bits when the kernel coalesces (e.g. create+rename
//! of the same entry before we drain); each bit spools its own event.

use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::Value;
use tokio::sync::mpsc::Sender;

use crate::proctree::ProcTable;
use crate::rules::{Action, MatchCtx, Rules, RulesHandle};
use crate::{spool, telemetry};

const FAN_CLOEXEC: u32 = 0x1;
const FAN_CLASS_NOTIF: u32 = 0x0;
const FAN_REPORT_FID: u32 = 0x200;
const FAN_REPORT_DIR_FID: u32 = 0x400;
const FAN_REPORT_NAME: u32 = 0x800;
const FAN_MARK_ADD: u32 = 0x1;
const FAN_CLOSE_WRITE: u64 = 0x8;
const FAN_MOVED_FROM: u64 = 0x40;
const FAN_MOVED_TO: u64 = 0x80;
const FAN_CREATE: u64 = 0x100;
const FAN_DELETE: u64 = 0x200;
const FAN_EVENT_ON_CHILD: u64 = 0x0800_0000;
const FANOTIFY_METADATA_VERSION: u8 = 3;
const FAN_EVENT_INFO_TYPE_DFID_NAME: u8 = 2;
const AT_EMPTY_PATH: i32 = 0x1000;
const FILE_HANDLE_CAP: usize = 128;

#[repr(C)]
#[derive(Copy, Clone)]
struct Metadata {
    event_len: u32,
    vers: u8,
    _reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

const METADATA_LEN: usize = std::mem::size_of::<Metadata>();

/// Map one fanotify event mask to spool ops (see module docs). Pure.
pub fn ops_for_mask(mask: u64) -> Vec<&'static str> {
    let mut ops = Vec::new();
    if mask & FAN_CREATE != 0 {
        ops.push("create");
    }
    if mask & FAN_CLOSE_WRITE != 0 {
        ops.push("modify");
    }
    if mask & FAN_MOVED_TO != 0 {
        ops.push("rename");
    }
    if mask & (FAN_DELETE | FAN_MOVED_FROM) != 0 {
        ops.push("delete");
    }
    ops
}

/// Suppress repeat (path, op) events inside a short window. fanotify
/// delivers one CLOSE_WRITE per close, so storms only happen when a writer
/// genuinely re-opens repeatedly; the window just collapses those.
pub struct Dedupe {
    seen: HashMap<(String, String), Instant>,
    window: Duration,
}

impl Dedupe {
    pub fn new(window: Duration) -> Self {
        Dedupe {
            seen: HashMap::new(),
            window,
        }
    }

    pub fn allow(&mut self, path: &str, op: &str, now: Instant) -> bool {
        let key = (path.to_string(), op.to_string());
        if let Some(t) = self.seen.get(&key) {
            if now.duration_since(*t) < self.window {
                return false;
            }
        }
        // Bound the map: drop entries outside the window once it grows.
        if self.seen.len() > 4096 {
            let window = self.window;
            self.seen.retain(|_, t| now.duration_since(*t) < window);
        }
        self.seen.insert(key, now);
        true
    }
}

#[derive(Debug, Clone)]
pub struct DirWatch {
    pub path: PathBuf,
    /// Basename allowlist (used for /etc → ld.so.preload, where watching
    /// every dirent event would be noise). None = report everything.
    pub filter: Option<Vec<String>>,
}

#[derive(Debug, Default)]
pub struct WatchSet {
    pub dirs: Vec<DirWatch>,
    pub files: Vec<PathBuf>,
}

/// Default persistence locations. Missing paths are skipped silently —
/// they vary by distro and user setup.
pub fn default_watches() -> WatchSet {
    let mut set = WatchSet::default();
    let mut dir = |p: &str| {
        let path = PathBuf::from(p);
        if path.is_dir() {
            set.dirs.push(DirWatch { path, filter: None });
        }
    };
    let mut file = |p: &str| {
        let path = PathBuf::from(p);
        if path.is_file() {
            set.files.push(path);
        }
    };

    dir("/var/spool/cron/crontabs");
    dir("/etc/cron.d");
    dir("/etc/cron.daily");
    dir("/etc/cron.hourly");
    dir("/etc/cron.weekly");
    dir("/etc/cron.monthly");
    dir("/etc/systemd/system");
    dir("/etc/systemd/user");
    dir("/etc/profile.d");
    file("/etc/crontab");
    file("/etc/profile");
    file("/etc/bash.bashrc");

    if let Ok(home) = std::fs::read_dir("/home") {
        for entry in home.flatten() {
            let h = entry.path();
            if !h.is_dir() {
                continue;
            }
            let systemd_user = h.join(".config/systemd/user");
            if systemd_user.is_dir() {
                set.dirs.push(DirWatch {
                    path: systemd_user,
                    filter: None,
                });
            }
            let ssh = h.join(".ssh");
            if ssh.is_dir() {
                set.dirs.push(DirWatch {
                    path: ssh,
                    filter: None,
                });
            }
            for rc in [".bashrc", ".profile", ".zshrc"] {
                let p = h.join(rc);
                if p.is_file() {
                    set.files.push(p);
                }
            }
        }
    }

    // /etc/ld.so.preload usually does not exist, so a file mark is
    // impossible; watch /etc dirent events filtered down to it.
    set.dirs.push(DirWatch {
        path: PathBuf::from("/etc"),
        filter: Some(vec!["ld.so.preload".to_string()]),
    });
    set
}

fn fanotify_init(flags: u32) -> Result<i32> {
    let fd = unsafe {
        libc::syscall(
            libc::SYS_fanotify_init,
            flags,
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    } as i32;
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("fanotify_init");
    }
    Ok(fd)
}

fn fanotify_mark(fd: i32, mask: u64, path: &Path) -> Result<()> {
    let cpath = CString::new(path.as_os_str().as_encoded_bytes())?;
    let rc = unsafe {
        libc::syscall(
            libc::SYS_fanotify_mark,
            fd,
            FAN_MARK_ADD,
            mask,
            libc::AT_FDCWD,
            cpath.as_ptr(),
        )
    } as i32;
    if rc < 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("fanotify_mark {}", path.display()));
    }
    Ok(())
}

/// name_to_handle_at key for a watched dir: handle type + bytes, matching
/// what DFID_NAME records carry. Needs no special caps.
fn dir_handle_key(path: &Path) -> Result<Vec<u8>> {
    let cpath = CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut buf = [0u8; 8 + FILE_HANDLE_CAP];
    buf[..4].copy_from_slice(&(FILE_HANDLE_CAP as u32).to_ne_bytes());
    let mut mount_id: i32 = 0;
    let rc = unsafe {
        libc::syscall(
            libc::SYS_name_to_handle_at,
            libc::AT_FDCWD,
            cpath.as_ptr(),
            buf.as_mut_ptr(),
            &mut mount_id,
            AT_EMPTY_PATH,
        )
    } as i32;
    if rc < 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("name_to_handle_at {}", path.display()));
    }
    let bytes = u32::from_ne_bytes(buf[..4].try_into().unwrap()) as usize;
    let htype = i32::from_ne_bytes(buf[4..8].try_into().unwrap());
    let mut key = htype.to_ne_bytes().to_vec();
    key.extend_from_slice(&buf[8..8 + bytes]);
    Ok(key)
}

struct DirEntry {
    key: Vec<u8>,
    path: PathBuf,
    filter: Option<Vec<String>>,
}

/// Start both monitor groups. Failures to mark individual paths degrade
/// gracefully (logged); a failure to create either group is fatal.
pub fn spawn(
    extra: &[PathBuf],
    rules: RulesHandle,
    table: Arc<Mutex<ProcTable>>,
    tx: Sender<Value>,
) -> Result<()> {
    let mut set = default_watches();
    for p in extra {
        if p.is_dir() {
            set.dirs.push(DirWatch {
                path: p.clone(),
                filter: None,
            });
        } else if p.is_file() {
            set.files.push(p.clone());
        } else {
            log::warn!(
                "--watch {}: not an existing file or dir, skipped",
                p.display()
            );
        }
    }

    // --- group 1: FAN_CLOSE_WRITE (fd-carrying events) ---
    let cw_fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_NOTIF)?;
    let mut cw_marks = 0;
    for d in set.dirs.iter().filter(|d| d.filter.is_none()) {
        match fanotify_mark(cw_fd, FAN_CLOSE_WRITE | FAN_EVENT_ON_CHILD, &d.path) {
            Ok(()) => cw_marks += 1,
            Err(e) => log::warn!("close_write mark on {}: {e:#}", d.path.display()),
        }
    }
    for f in &set.files {
        match fanotify_mark(cw_fd, FAN_CLOSE_WRITE, f) {
            Ok(()) => cw_marks += 1,
            Err(e) => log::warn!("close_write mark on {}: {e:#}", f.display()),
        }
    }
    log::info!("filemon: {cw_marks} close_write marks");

    // --- group 2: dirent events via FID ---
    let fid_fd = fanotify_init(
        FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME,
    )?;
    let mut dirs: Vec<DirEntry> = Vec::new();
    for d in &set.dirs {
        let mask = FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM | FAN_MOVED_TO | FAN_EVENT_ON_CHILD;
        match (
            fanotify_mark(fid_fd, mask, &d.path),
            dir_handle_key(&d.path),
        ) {
            (Ok(()), Ok(key)) => {
                dirs.push(DirEntry {
                    key,
                    path: d.path.clone(),
                    filter: d.filter.clone(),
                });
            }
            (Err(e), _) => log::warn!("fid mark on {}: {e:#}", d.path.display()),
            (_, Err(e)) => log::warn!("handle for {}: {e:#}", d.path.display()),
        }
    }
    log::info!("filemon: {} dirent marks", dirs.len());

    spawn_thread("filemon-cw", {
        let rules = rules.clone();
        let table = Arc::clone(&table);
        let tx = tx.clone();
        move || cw_loop(cw_fd, rules, table, tx)
    })?;
    spawn_thread("filemon-fid", move || {
        fid_loop(fid_fd, dirs, rules, table, tx)
    })?;
    Ok(())
}

fn spawn_thread(name: &str, f: impl FnOnce() + Send + 'static) -> Result<()> {
    std::thread::Builder::new()
        .name(name.into())
        .spawn(f)
        .context("spawning filemon thread")?;
    Ok(())
}

fn read_events(fd: i32, buf: &mut [u8], on_meta: &mut impl FnMut(&Metadata, &[u8])) {
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            log::error!("filemon read failed: {err}; monitor stopped");
            return;
        }
        let n = n as usize;
        let mut off = 0usize;
        while off + METADATA_LEN <= n {
            let meta: Metadata =
                unsafe { std::ptr::read_unaligned(buf[off..].as_ptr() as *const Metadata) };
            let len = meta.event_len as usize;
            if len < METADATA_LEN || off + len > n {
                break;
            }
            if meta.vers == FANOTIFY_METADATA_VERSION {
                on_meta(&meta, &buf[off + METADATA_LEN..off + len]);
            }
            off += len;
        }
    }
}

fn cw_loop(fd: i32, rules: RulesHandle, table: Arc<Mutex<ProcTable>>, tx: Sender<Value>) {
    let mut buf = vec![0u8; 64 * 1024];
    let mut dedupe = Dedupe::new(Duration::from_millis(1500));
    read_events(fd, &mut buf, &mut |meta, _records| {
        if meta.fd < 0 || meta.mask & FAN_CLOSE_WRITE == 0 {
            return;
        }
        let path = std::fs::read_link(format!("/proc/self/fd/{}", meta.fd))
            .ok()
            .map(|p| p.display().to_string());
        unsafe { libc::close(meta.fd) };
        let Some(path) = path else { return };
        emit(
            &tx,
            &rules.get(),
            &table,
            &mut dedupe,
            &path,
            "modify",
            meta.pid,
        );
    });
}

fn fid_loop(
    fd: i32,
    dirs: Vec<DirEntry>,
    rules: RulesHandle,
    table: Arc<Mutex<ProcTable>>,
    tx: Sender<Value>,
) {
    let mut buf = vec![0u8; 64 * 1024];
    let mut dedupe = Dedupe::new(Duration::from_millis(1500));
    read_events(fd, &mut buf, &mut |meta, records| {
        let Some((dir, name)) = parse_dfid_name(records, &dirs) else {
            return;
        };
        if let Some(filter) = &dir.filter {
            if !filter.iter().any(|f| f == &name) {
                return;
            }
        }
        let path = format!("{}/{}", dir.path.display(), name);
        for op in ops_for_mask(meta.mask) {
            emit(&tx, &rules.get(), &table, &mut dedupe, &path, op, meta.pid);
        }
    });
}

/// Extract (watched dir, child name) from a DFID_NAME info record.
/// Layout: header(4) + fsid(8) + file_handle(4 bytes len + 4 type + data)
/// + NUL-terminated name. Pure record parsing; tested.
fn parse_dfid_name<'a>(records: &'a [u8], dirs: &'a [DirEntry]) -> Option<(&'a DirEntry, String)> {
    let mut off = 0usize;
    while off + 4 <= records.len() {
        let info_type = records[off];
        let len = u16::from_ne_bytes(records[off + 2..off + 4].try_into().ok()?) as usize;
        if len < 4 || off + len > records.len() {
            return None;
        }
        let rec = &records[off..off + len];
        if info_type == FAN_EVENT_INFO_TYPE_DFID_NAME && rec.len() >= 4 + 8 + 8 {
            let hbytes = u32::from_ne_bytes(rec[12..16].try_into().ok()?) as usize;
            if 20 + hbytes >= rec.len() {
                return None;
            }
            let htype = i32::from_ne_bytes(rec[16..20].try_into().ok()?);
            let mut key = htype.to_ne_bytes().to_vec();
            key.extend_from_slice(&rec[20..20 + hbytes]);
            let name_bytes = &rec[20 + hbytes..];
            let end = name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(name_bytes.len());
            let name = String::from_utf8_lossy(&name_bytes[..end]).into_owned();
            if name.is_empty() {
                return None;
            }
            if let Some(dir) = dirs.iter().find(|d| d.key == key) {
                return Some((dir, name));
            }
            return None;
        }
        off += len;
    }
    None
}

fn emit(
    tx: &Sender<Value>,
    rules: &Rules,
    table: &Arc<Mutex<ProcTable>>,
    dedupe: &mut Dedupe,
    path: &str,
    op: &str,
    pid: i32,
) {
    if !dedupe.allow(path, op, Instant::now()) {
        return;
    }
    // pid 0: the acting process is not visible in our pid namespace — no
    // /proc or lineage lookups on a number that means nothing here.
    let pid_u32 = u32::try_from(pid).ok().filter(|p| *p > 0);
    let comm = pid_u32
        .and_then(telemetry::proc_status)
        .and_then(|s| s.name);
    let cmdline = pid_u32.and_then(telemetry::proc_cmdline);
    let uid = pid_u32.and_then(telemetry::proc_uid);
    let (parent_basename, ancestor_comms) = pid_u32
        .map(|p| {
            let lin = table.lock().unwrap().lineage_of(p);
            let comms = lin.comms();
            (lin.parent_basename, comms)
        })
        .unwrap_or_default();

    let basename = path.rsplit('/').next();
    let ctx = MatchCtx {
        sha256: None,
        basename,
        path: Some(path),
        cmdline: cmdline.as_deref(),
        uid,
        comm: comm.as_deref(),
        parent_basename: parent_basename.as_deref(),
        ancestors: &ancestor_comms,
    };
    // Only log rules apply to file events: kill/block are exec-context
    // actions (documented in linux-sensor.md).
    let matched: Vec<String> = rules
        .rules
        .iter()
        .filter(|r| r.action == Action::Log && r.matches(&ctx))
        .map(|r| r.name.clone())
        .collect();

    spool::try_send(
        tx,
        serde_json::json!({
            "ts": spool::now_ts(),
            "kind": "file",
            "path": path,
            "op": op,
            "pid": pid_u32,
            "comm": comm,
            "matched_rules": matched,
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_mapping() {
        assert_eq!(ops_for_mask(FAN_CREATE), vec!["create"]);
        assert_eq!(ops_for_mask(FAN_CLOSE_WRITE), vec!["modify"]);
        assert_eq!(ops_for_mask(FAN_DELETE), vec!["delete"]);
        assert_eq!(ops_for_mask(FAN_MOVED_TO), vec!["rename"]);
        assert_eq!(ops_for_mask(FAN_MOVED_FROM), vec!["delete"]);
        // Coalesced queue entry (seen live: create+rename of one entry).
        assert_eq!(
            ops_for_mask(FAN_CREATE | FAN_MOVED_FROM),
            vec!["create", "delete"]
        );
        assert_eq!(
            ops_for_mask(FAN_MOVED_TO | FAN_DELETE),
            vec!["rename", "delete"]
        );
        assert!(ops_for_mask(0).is_empty());
    }

    #[test]
    fn dedupe_collapses_storms() {
        let mut d = Dedupe::new(Duration::from_millis(1500));
        let t0 = Instant::now();
        assert!(d.allow("/etc/cron.d/x", "modify", t0));
        assert!(!d.allow("/etc/cron.d/x", "modify", t0 + Duration::from_millis(500)));
        // Different op or different path still goes through.
        assert!(d.allow("/etc/cron.d/x", "create", t0 + Duration::from_millis(500)));
        assert!(d.allow("/etc/cron.d/y", "modify", t0 + Duration::from_millis(500)));
        // After the window it fires again.
        assert!(d.allow("/etc/cron.d/x", "modify", t0 + Duration::from_millis(1600)));
    }

    #[test]
    fn dfid_name_parsing() {
        // header(type=2, pad, len) + fsid(8) + handle_len + handle_type +
        // handle bytes + name NUL
        let handle = [0x0a, 0x00, 0x34, 0x52];
        let mut rec = vec![2u8, 0, 0, 0]; // len patched below
        rec.extend_from_slice(&[0; 8]); // fsid
        rec.extend_from_slice(&(handle.len() as u32).to_ne_bytes());
        rec.extend_from_slice(&1i32.to_ne_bytes());
        rec.extend_from_slice(&handle);
        rec.extend_from_slice(b"merlin-test\0");
        let len = rec.len() as u16;
        rec[2..4].copy_from_slice(&len.to_ne_bytes());

        let dirs = vec![DirEntry {
            key: [1i32.to_ne_bytes().to_vec(), handle.to_vec()].concat(),
            path: PathBuf::from("/etc/cron.d"),
            filter: None,
        }];
        let (dir, name) = parse_dfid_name(&rec, &dirs).unwrap();
        assert_eq!(dir.path, PathBuf::from("/etc/cron.d"));
        assert_eq!(name, "merlin-test");

        // Unknown handle → None, no panic.
        let other = vec![DirEntry {
            key: vec![9, 9, 9],
            path: PathBuf::from("/x"),
            filter: None,
        }];
        assert!(parse_dfid_name(&rec, &other).is_none());
        // Truncated record → None, no panic.
        assert!(parse_dfid_name(&rec[..10], &dirs).is_none());
    }
}
