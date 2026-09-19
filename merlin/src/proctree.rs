//! pid → process-metadata cache, fed by exec events plus a /proc sweep at
//! daemon startup. Each entry carries the process start time (jiffies from
//! /proc/<pid>/stat field 22): when an observation shows a different start
//! time than the cached entry, the pid was reused and the entry is
//! replaced. The cache lets the ancestors chain survive parents that have
//! already exited, as long as they were seen while alive.

use std::collections::HashMap;

pub const ANCESTOR_DEPTH: usize = 8;

#[derive(Debug, Clone, Default)]
pub struct ProcInfo {
    pub start_time: u64,
    pub ppid: Option<u32>,
    pub comm: Option<String>,
    pub exe: Option<String>,
    // Kept per the macOS cache shape (pid → {ppid, exe, cmdline, start});
    // nothing reads it yet — lineage matching only needs comm/exe.
    #[allow(dead_code)]
    pub cmdline: Option<String>,
}

#[derive(Default)]
pub struct ProcTable {
    map: HashMap<u32, ProcInfo>,
}

impl ProcTable {
    /// Snapshot every process visible in /proc.
    pub fn sweep() -> Self {
        let mut table = ProcTable::default();
        let Ok(dir) = std::fs::read_dir("/proc") else {
            return table;
        };
        for entry in dir.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            if let Some(info) = observe(pid) {
                table.map.insert(pid, info);
            }
        }
        table
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Fresh observations win, with one guard: if the cached entry has a
    /// *newer* start time than the observation, the observation is stale
    /// (out-of-order ring-buffer delivery across a pid reuse) and must not
    /// overwrite the newer process. A different start time otherwise means
    /// the pid was recycled and the old entry is replaced.
    pub fn upsert(&mut self, pid: u32, info: ProcInfo) {
        if let Some(old) = self.map.get(&pid) {
            if old.start_time > info.start_time {
                return;
            }
        }
        self.map.insert(pid, info);
    }

    pub fn remove(&mut self, pid: u32) {
        self.map.remove(&pid);
    }

    /// Return the last validated start time even after the process has
    /// exited. This keeps exit evidence correlated without trusting a
    /// recycled pid or racing a disappearing /proc entry.
    pub fn start_time(&mut self, pid: u32) -> Option<u64> {
        self.map
            .get(&pid)
            .map(|info| info.start_time)
            .or_else(|| observe(pid).map(|info| info.start_time))
    }

    /// Resolve one pid, falling back to a live /proc read on cache miss
    /// (e.g. a process that started before the sweep finished).
    fn resolve(&mut self, pid: u32) -> Option<&ProcInfo> {
        if !self.map.contains_key(&pid) {
            if let Some(info) = observe(pid) {
                self.map.insert(pid, info);
            }
        }
        self.map.get(&pid)
    }

    /// Walk parents from `ppid`, deepest-first order is caller-facing as
    /// nearest-first; stops after pid 1, capped at ANCESTOR_DEPTH.
    pub fn ancestors(&mut self, ppid: Option<u32>) -> Vec<(u32, Option<String>)> {
        let mut chain = Vec::new();
        let mut cur = ppid;
        for _ in 0..ANCESTOR_DEPTH {
            let Some(pid) = cur else { break };
            if pid == 0 {
                break;
            }
            let Some(info) = self.resolve(pid) else { break };
            chain.push((pid, info.comm.clone()));
            if pid == 1 {
                break;
            }
            cur = info.ppid;
        }
        chain
    }

    /// Lineage for the rule engine: the parent's basename (exe basename,
    /// comm fallback) plus the ancestor comm chain. Missing evidence (dead
    /// or never-seen parents, pid-reuse misses) yields None/empty — the
    /// caller treats that as "no lineage", never as a match.
    pub fn lineage(&mut self, ppid: Option<u32>) -> Lineage {
        let parent_basename = ppid.and_then(|pp| {
            self.resolve(pp).and_then(|info| {
                info.exe
                    .as_deref()
                    .and_then(|e| e.rsplit('/').next().map(String::from))
                    .or_else(|| info.comm.clone())
            })
        });
        Lineage {
            ancestors: self.ancestors(ppid),
            parent_basename,
        }
    }

    /// Lineage for a pid (resolves the pid first to find its parent).
    pub fn lineage_of(&mut self, pid: u32) -> Lineage {
        let ppid = self.resolve(pid).and_then(|i| i.ppid);
        self.lineage(ppid)
    }
}

pub struct Lineage {
    pub ancestors: Vec<(u32, Option<String>)>,
    pub parent_basename: Option<String>,
}

impl Lineage {
    /// Ancestor comms only, for the ancestor_comm_contains selector.
    pub fn comms(&self) -> Vec<String> {
        self.ancestors
            .iter()
            .filter_map(|(_, c)| c.clone())
            .collect()
    }
}

/// Read one process from /proc. None when it is already gone.
pub fn observe(pid: u32) -> Option<ProcInfo> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (comm, ppid, start_time) = parse_stat(&stat)?;
    Some(ProcInfo {
        start_time,
        ppid: Some(ppid),
        comm: Some(comm),
        exe: std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.display().to_string()),
        cmdline: crate::telemetry::proc_cmdline(pid),
    })
}

/// Parse /proc/<pid>/stat into (comm, ppid, start_time). comm sits in
/// parens and may itself contain spaces or parens, so split at the LAST
/// ')'. Fields after it are numbered from 3 (state): ppid is field 4,
/// start_time (jiffies since boot) is field 22.
pub fn parse_stat(stat: &str) -> Option<(String, u32, u64)> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let comm = stat.get(open + 1..close)?.to_string();
    let rest: Vec<&str> = stat.get(close + 1..)?.split_whitespace().collect();
    // rest[0] = state (field 3), rest[1] = ppid (field 4), rest[19] = starttime (field 22)
    let ppid: u32 = rest.get(1)?.parse().ok()?;
    let start_time: u64 = rest.get(19)?.parse().ok()?;
    Some((comm, ppid, start_time))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_stat_plain() {
        let (comm, ppid, start) =
            parse_stat("1234 (bash) S 1200 1234 1234 0 -1 4194304 100 0 0 0 10 5 0 0 20 0 1 0 987654 100 200 0 0 0 0 0")
                .unwrap();
        assert_eq!(comm, "bash");
        assert_eq!(ppid, 1200);
        assert_eq!(start, 987654);
    }

    #[test]
    fn parse_stat_tricky_comm() {
        // comm with spaces and parens: split must happen at the last ')'.
        let (comm, ppid, _) =
            parse_stat("99 (weird (name) here) S 1 99 99 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 42 0 0 0")
                .unwrap();
        assert_eq!(comm, "weird (name) here");
        assert_eq!(ppid, 1);
    }

    #[test]
    fn ancestors_stop_at_init() {
        let mut t = ProcTable::default();
        t.upsert(
            1,
            ProcInfo {
                start_time: 1,
                ppid: Some(0),
                comm: Some("systemd".into()),
                ..Default::default()
            },
        );
        t.upsert(
            100,
            ProcInfo {
                start_time: 2,
                ppid: Some(1),
                comm: Some("sshd".into()),
                ..Default::default()
            },
        );
        assert_eq!(t.start_time(100), Some(2));
        let chain = t.ancestors(Some(100));
        assert_eq!(
            chain,
            vec![
                (100, Some("sshd".to_string())),
                (1, Some("systemd".to_string()))
            ]
        );
    }

    fn fake_lineage_table() -> ProcTable {
        // sh(300) ← curl(200) ← bash(100) ← systemd(1)
        let mut t = ProcTable::default();
        t.upsert(
            1,
            ProcInfo {
                start_time: 1,
                ppid: Some(0),
                comm: Some("systemd".into()),
                exe: Some("/usr/lib/systemd/systemd".into()),
                ..Default::default()
            },
        );
        t.upsert(
            100,
            ProcInfo {
                start_time: 2,
                ppid: Some(1),
                comm: Some("bash".into()),
                exe: Some("/usr/bin/bash".into()),
                ..Default::default()
            },
        );
        t.upsert(
            200,
            ProcInfo {
                start_time: 3,
                ppid: Some(100),
                comm: Some("curl".into()),
                exe: Some("/usr/bin/curl".into()),
                ..Default::default()
            },
        );
        t.upsert(
            300,
            ProcInfo {
                start_time: 4,
                ppid: Some(200),
                comm: Some("sh".into()),
                exe: Some("/usr/bin/dash".into()),
                ..Default::default()
            },
        );
        t
    }

    #[test]
    fn lineage_finds_parent_basename_and_ancestor_comms() {
        let mut t = fake_lineage_table();
        let lin = t.lineage_of(300);
        // Parent basename prefers the exe basename over comm.
        assert_eq!(lin.parent_basename.as_deref(), Some("curl"));
        assert_eq!(lin.comms(), vec!["curl", "bash", "systemd"]);
    }

    #[test]
    fn lineage_parent_basename_falls_back_to_comm() {
        let mut t = fake_lineage_table();
        // Drop exe evidence for curl: comm must substitute.
        t.upsert(
            200,
            ProcInfo {
                start_time: 3,
                ppid: Some(100),
                comm: Some("curl".into()),
                exe: None,
                ..Default::default()
            },
        );
        assert_eq!(t.lineage_of(300).parent_basename.as_deref(), Some("curl"));
    }

    #[test]
    fn lineage_miss_fails_safe() {
        // Unknown pid, never seen: no lineage, no panic. resolve() will try
        // /proc and find nothing (pid 4_000_000 cannot exist).
        let mut t = ProcTable::default();
        let lin = t.lineage_of(4_000_000);
        assert_eq!(lin.parent_basename, None);
        assert!(lin.ancestors.is_empty());
    }
}
