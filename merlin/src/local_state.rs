//! This device as the installed agent left it on disk, for the local screen's
//! Overview page: the enrollment (device id, sync host and enrollment time,
//! never the token or keys), whether the assigned rules only observe, whether
//! a sensor is running, and what waits in the spool with the sensor's last
//! health event. It reads files only, opens none through a symlink, and says
//! why when it cannot read something instead of guessing.

use std::fs::File;
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::rules::{Action, Rules};
use crate::spool;

/// Where the packaged agent keeps its state (packaging/linux).
pub struct Paths {
    pub env_file: PathBuf,
    pub rules_file: PathBuf,
    pub spool_live: PathBuf,
    pub proc_root: PathBuf,
}

impl Paths {
    pub fn installed() -> Self {
        Paths {
            env_file: "/etc/merlin/merlin.env".into(),
            rules_file: "/etc/merlin/rules.yaml".into(),
            spool_live: "/var/lib/merlin/merlin-events.jsonl".into(),
            proc_root: "/proc".into(),
        }
    }
}

/// Everything the Overview page shows, read at one instant.
pub struct Local {
    pub enrollment: Enrollment,
    pub mode: Mode,
    pub running: Option<bool>,
    pub spool: Spool,
}

pub fn read(paths: &Paths) -> Local {
    Local {
        enrollment: read_enrollment(&paths.env_file),
        mode: read_mode(&paths.rules_file),
        running: sensor_running(&paths.proc_root),
        spool: read_spool(&paths.spool_live),
    }
}

/// Why a file could not be read, in words for the screen.
fn unreadable(what: &str, error: &std::io::Error) -> String {
    match error.kind() {
        ErrorKind::NotFound => format!("no {what} on this computer"),
        ErrorKind::PermissionDenied => format!("run with sudo to read the {what}"),
        _ => format!("{what} unreadable: {error}"),
    }
}

fn open_no_follow(path: &Path) -> std::io::Result<File> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Enrollment {
    pub device_id: Option<String>,
    pub sync_host: Option<String>,
    pub enrolled_at: Option<u64>,
    pub unavailable: Option<String>,
}

/// Keeps only the device id, the sync host and the enrollment time from the
/// credential file; every other line, including the token, is dropped.
pub fn read_enrollment(path: &Path) -> Enrollment {
    let mut text = String::new();
    if let Err(error) =
        open_no_follow(path).and_then(|file| file.take(64 * 1024).read_to_string(&mut text))
    {
        return Enrollment {
            unavailable: Some(unreadable("enrollment", &error)),
            ..Default::default()
        };
    }
    let mut enrollment = Enrollment::default();
    for (key, value) in text.lines().filter_map(|line| line.split_once('=')) {
        let value = value.trim().trim_matches(['"', '\'']);
        match key.trim() {
            "MERLIN_DEVICE_ID" if !value.is_empty() => enrollment.device_id = Some(value.into()),
            "MERLIN_SYNC_URL" => {
                enrollment.sync_host = value
                    .split_once("://")
                    .and_then(|(_, rest)| rest.split('/').next())
                    .filter(|host| !host.is_empty())
                    .map(str::to_owned)
            }
            "MERLIN_ENROLLED_AT" => enrollment.enrolled_at = value.parse().ok(),
            _ => {}
        }
    }
    enrollment
}

/// What the assigned rules let the agent do on this computer.
#[derive(Debug, PartialEq, Eq)]
pub enum Mode {
    /// Every rule only records.
    ObserveOnly {
        rules: usize,
    },
    /// Some rule blocks a program from starting or stops a running one.
    Enforcing {
        block: usize,
        kill: usize,
    },
    Unavailable(String),
}

pub fn read_mode(rules_path: &Path) -> Mode {
    match Rules::load_with_source(rules_path) {
        Ok((rules, _)) => {
            let count = |action| {
                rules
                    .rules
                    .iter()
                    .filter(|rule| rule.action == action)
                    .count()
            };
            match (count(Action::Block), count(Action::Kill)) {
                (0, 0) => Mode::ObserveOnly {
                    rules: rules.rules.len(),
                },
                (block, kill) => Mode::Enforcing { block, kill },
            }
        }
        Err(error) => Mode::Unavailable(match error.downcast_ref::<std::io::Error>() {
            Some(io) => unreadable("rules", io),
            None => format!("rules unreadable: {error:#}"),
        }),
    }
}

const MAX_PROCESS_ENTRIES: usize = 4096;
const MAX_COMM_BYTES: u64 = 64;
const MAX_CMDLINE_BYTES: u64 = 64 * 1024;

fn read_bounded(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let file = open_no_follow(path)?;
    let mut body = Vec::new();
    file.take(limit + 1).read_to_end(&mut body)?;
    if body.len() as u64 > limit {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("{} exceeds the read limit", path.display()),
        ));
    }
    Ok(body)
}

fn merlin_process(process: &Path, read_cmdline: impl FnOnce() -> Option<Vec<u8>>) -> bool {
    let merlin_executable = read_bounded(&process.join("comm"), MAX_COMM_BYTES)
        .is_ok_and(|comm| comm == b"merlin" || comm == b"merlin\n")
        || std::fs::read_link(process.join("exe")).is_ok_and(|exe| {
            exe.file_name()
                .is_some_and(|name| name == std::ffi::OsStr::new("merlin"))
        });
    if !merlin_executable {
        return false;
    }
    let Some(cmdline) = read_cmdline() else {
        return false;
    };
    let mut args = cmdline.split(|byte| *byte == 0);
    let program = args
        .next()
        .and_then(|argv0| argv0.rsplit(|b| *b == b'/').next());
    program == Some(b"merlin") && args.next() == Some(b"run")
}

/// Whether a `merlin run` process is in the process table; None when the
/// table cannot be read. Only a process whose comm or exe names Merlin has its
/// bounded command line inspected.
pub fn sensor_running(proc_root: &Path) -> Option<bool> {
    let me = std::process::id().to_string();
    let running = std::fs::read_dir(proc_root)
        .ok()?
        .flatten()
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name != me && name.bytes().all(|b| b.is_ascii_digit())
        })
        .take(MAX_PROCESS_ENTRIES)
        .any(|entry| {
            merlin_process(&entry.path(), || {
                read_bounded(&entry.path().join("cmdline"), MAX_CMDLINE_BYTES).ok()
            })
        });
    Some(running)
}

/// The sensor's last health event in the live spool.
#[derive(Debug, PartialEq)]
pub struct Health {
    pub ts: f64,
    pub events_written: u64,
    pub events_dropped: u64,
    pub kernel_events_dropped: u64,
}

#[derive(Debug, Default, PartialEq)]
pub struct Spool {
    /// Finished segments waiting for the server to accept them.
    pub queued_segments: usize,
    pub queued_bytes: u64,
    pub health: Option<Health>,
    pub unavailable: Option<String>,
}

/// How far back from the end of the live spool to look for a health event.
const TAIL_BYTES: u64 = 256 * 1024;

pub fn read_spool(live: &Path) -> Spool {
    let mut spool = Spool::default();
    let live_name = live
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let entries = match std::fs::read_dir(live.parent().unwrap_or(Path::new("."))) {
        Ok(entries) => entries,
        Err(error) => {
            return Spool {
                unavailable: Some(unreadable("spool", &error)),
                ..spool
            };
        }
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let finished = name.strip_suffix(".gz").unwrap_or(&name);
        // DirEntry::metadata does not follow a symlink.
        match entry.metadata() {
            Ok(meta) if meta.is_file() && spool::is_segment_name(finished, &live_name) => {
                spool.queued_segments += 1;
                spool.queued_bytes += meta.len();
            }
            _ => {}
        }
    }
    let mut tail = String::new();
    if let Ok(mut file) = open_no_follow(live) {
        let start = file
            .metadata()
            .map(|meta| meta.len().saturating_sub(TAIL_BYTES))
            .unwrap_or(0);
        if file.seek(SeekFrom::Start(start)).is_ok()
            && file.take(TAIL_BYTES).read_to_string(&mut tail).is_ok()
        {
            spool.health = last_health(&tail);
        }
    }
    spool
}

fn last_health(lines: &str) -> Option<Health> {
    lines.lines().rev().find_map(|line| {
        let event: serde_json::Value = serde_json::from_str(line).ok()?;
        (event.get("kind")?.as_str()? == "health").then(|| {
            let count = |key: &str| {
                event
                    .get(key)
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0)
            };
            Health {
                ts: event
                    .get("ts")
                    .and_then(serde_json::Value::as_f64)
                    .unwrap_or(0.0),
                events_written: count("events_written"),
                events_dropped: count("events_dropped"),
                kernel_events_dropped: count("kernel_events_dropped"),
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("merlin-local-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_installed_paths_are_the_ones_the_package_uses() {
        let launcher = include_str!("../../packaging/linux/merlin-launcher.sh");
        let unit = include_str!("../../packaging/linux/merlin.service");
        let paths = Paths::installed();
        assert!(launcher.contains(&format!("--spool {}", paths.spool_live.display())));
        assert!(launcher.contains(&format!("RULES={}", paths.rules_file.display())));
        assert!(unit.contains(&format!("EnvironmentFile={}", paths.env_file.display())));
        assert_eq!(paths.proc_root, Path::new("/proc"));
    }

    #[test]
    fn enrollment_keeps_the_device_host_and_time_and_never_the_token() {
        let dir = dir("enroll");
        let env = dir.join("merlin.env");
        std::fs::write(
            &env,
            "MERLIN_SYNC_URL=https://merlin-sync.example.com/v1\nMERLIN_DEVICE_ID=dev_1\nMERLIN_DEVICE_TOKEN=secret-token\nMERLIN_ENROLLED_AT=1700000000\n",
        )
        .unwrap();
        let enrollment = read_enrollment(&env);
        assert_eq!(
            enrollment,
            Enrollment {
                device_id: Some("dev_1".into()),
                sync_host: Some("merlin-sync.example.com".into()),
                enrolled_at: Some(1_700_000_000),
                unavailable: None,
            }
        );
        assert!(!format!("{enrollment:?}").contains("secret-token"));
        // A symlink is refused, and a missing file says so.
        let link = dir.join("link.env");
        std::os::unix::fs::symlink(&env, &link).unwrap();
        assert!(read_enrollment(&link).unavailable.is_some());
        assert_eq!(
            read_enrollment(&dir.join("none")).unavailable.as_deref(),
            Some("no enrollment on this computer")
        );
    }

    #[test]
    fn spool_counts_finished_segments_and_finds_the_last_health_event() {
        let dir = dir("spool");
        let live = dir.join("merlin-events.jsonl");
        std::fs::write(
            &live,
            "{\"kind\":\"health\",\"ts\":1.0,\"events_written\":1}\n{\"kind\":\"health\",\"ts\":2.0,\"events_written\":9,\"events_dropped\":3}\n{\"kind\":\"exec\",\"ts\":3.0}\n",
        )
        .unwrap();
        std::fs::write(dir.join("merlin-events.20261109-120000.jsonl"), "x\n").unwrap();
        std::fs::write(dir.join("merlin-events.20261109-120500.jsonl.gz"), "yy").unwrap();
        std::fs::write(dir.join("other.jsonl"), "z").unwrap();
        let spool = read_spool(&live);
        assert_eq!((spool.queued_segments, spool.queued_bytes), (2, 4));
        assert_eq!(
            spool.health,
            Some(Health {
                ts: 2.0,
                events_written: 9,
                events_dropped: 3,
                kernel_events_dropped: 0
            })
        );
        assert!(
            read_spool(&dir.join("missing/merlin-events.jsonl"))
                .unavailable
                .is_some()
        );
    }

    #[test]
    fn sensor_matches_comm_or_exe_before_reading_only_merlin_cmdline() {
        let dir = dir("mode");
        assert!(matches!(
            read_mode(&dir.join("rules.yaml")),
            Mode::Unavailable(_)
        ));
        let proc_root = dir.join("proc");
        let unrelated = proc_root.join("42");
        std::fs::create_dir_all(&unrelated).unwrap();
        std::fs::write(unrelated.join("comm"), "bash\n").unwrap();
        std::os::unix::fs::symlink("/usr/bin/bash", unrelated.join("exe")).unwrap();
        std::fs::write(
            unrelated.join("cmdline"),
            b"/usr/bin/merlin\0run\0unrelated-secret\0",
        )
        .unwrap();
        assert!(!merlin_process(&unrelated, || {
            panic!("an unrelated process command line was read")
        }));
        assert_eq!(sensor_running(&proc_root), Some(false));

        let by_comm = proc_root.join("43");
        std::fs::create_dir_all(&by_comm).unwrap();
        std::fs::write(by_comm.join("comm"), "merlin\n").unwrap();
        std::fs::write(
            by_comm.join("cmdline"),
            b"/usr/local/libexec/merlin/merlin\0screen\0",
        )
        .unwrap();
        assert_eq!(sensor_running(&proc_root), Some(false));
        std::fs::write(
            by_comm.join("cmdline"),
            b"/usr/local/libexec/merlin/merlin\0run\0--rules\0",
        )
        .unwrap();
        assert_eq!(sensor_running(&proc_root), Some(true));

        std::fs::write(by_comm.join("comm"), "renamed\n").unwrap();
        std::os::unix::fs::symlink("/usr/local/libexec/merlin/merlin", by_comm.join("exe"))
            .unwrap();
        assert_eq!(sensor_running(&proc_root), Some(true));
        assert_eq!(sensor_running(&dir.join("no-proc")), None);
    }

    #[test]
    fn sensor_rejects_spoofed_argv_and_oversized_matching_cmdline() {
        let dir = dir("cmdline-bound");
        let proc_root = dir.join("proc");
        let process = proc_root.join("43");
        std::fs::create_dir_all(&process).unwrap();
        std::fs::write(process.join("comm"), "merlin\n").unwrap();
        std::fs::write(process.join("cmdline"), b"/bin/bash\0run\0").unwrap();
        assert_eq!(sensor_running(&proc_root), Some(false));

        let mut oversized = b"/usr/bin/merlin\0run\0".to_vec();
        oversized.resize(MAX_CMDLINE_BYTES as usize + 1, b'x');
        std::fs::write(process.join("cmdline"), oversized).unwrap();
        assert_eq!(sensor_running(&proc_root), Some(false));
        assert!(read_bounded(&process.join("cmdline"), MAX_CMDLINE_BYTES).is_err());
    }
}
