//! Runtime portability and ABI validation for the kernel collector.
//!
//! The eBPF object contains fixed tracepoint field offsets because it is a
//! deliberately small teaching collector. This module makes that boundary
//! explicit: before attach, we validate the host tracepoint format files and
//! select a syscall-number profile for the host architecture. Unsupported or
//! layout-drifted hosts are reported as incomplete instead of receiving
//! misleading security-transition evidence.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

#[derive(Debug, Clone, Copy)]
pub struct SyscallAbi {
    pub id: u32,
    pub name: &'static str,
    pub syscalls: &'static [(&'static str, u32)],
}

// Linux x86_64 syscall ABI. Keep this table beside the eBPF filter so the
// loader and collector can be reviewed as one contract.
const X86_64_SYSCALLS: &[(&str, u32)] = &[
    ("mmap", 9),
    ("mprotect", 10),
    ("socket", 41),
    ("connect", 42),
    ("accept", 43),
    ("shutdown", 48),
    ("bind", 49),
    ("listen", 50),
    ("execve", 59),
    ("ptrace", 101),
    ("setuid", 105),
    ("setgid", 106),
    ("setreuid", 113),
    ("setregid", 114),
    ("setresuid", 117),
    ("setresgid", 119),
    ("capset", 126),
    ("pivot_root", 155),
    ("mount", 165),
    ("umount2", 166),
    ("init_module", 175),
    ("delete_module", 176),
    ("unshare", 272),
    ("setns", 308),
    ("process_vm_writev", 310),
    ("process_vm_readv", 311),
    ("finit_module", 313),
    ("seccomp", 317),
    ("bpf", 321),
    ("execveat", 322),
    ("userfaultfd", 323),
    ("clone3", 435),
];

// Linux arm64 uses the asm-generic syscall numbering. This is intentionally
// explicit rather than inferred from the host libc, because the value is
// copied into the detached eBPF object at runtime.
const AARCH64_SYSCALLS: &[(&str, u32)] = &[
    ("pivot_root", 41),
    ("mount", 40),
    ("umount2", 39),
    ("capset", 91),
    ("unshare", 97),
    ("init_module", 105),
    ("delete_module", 106),
    ("ptrace", 117),
    ("setregid", 143),
    ("setgid", 144),
    ("setreuid", 145),
    ("setuid", 146),
    ("setresuid", 147),
    ("setresgid", 149),
    ("socket", 198),
    ("bind", 200),
    ("listen", 201),
    ("accept", 202),
    ("connect", 203),
    ("shutdown", 210),
    ("execve", 221),
    ("mmap", 222),
    ("mprotect", 226),
    ("setns", 268),
    ("process_vm_readv", 270),
    ("process_vm_writev", 271),
    ("finit_module", 273),
    ("seccomp", 277),
    ("bpf", 280),
    ("execveat", 281),
    ("userfaultfd", 282),
    ("clone3", 435),
];

static X86_64: SyscallAbi = SyscallAbi {
    id: 1,
    name: "x86_64",
    syscalls: X86_64_SYSCALLS,
};
static AARCH64: SyscallAbi = SyscallAbi {
    id: 2,
    name: "aarch64",
    syscalls: AARCH64_SYSCALLS,
};

pub fn host_arch() -> &'static str {
    std::env::consts::ARCH
}

pub fn host_abi() -> Option<&'static SyscallAbi> {
    match host_arch() {
        "x86_64" => Some(&X86_64),
        "aarch64" => Some(&AARCH64),
        _ => None,
    }
}

pub fn syscall_name(abi_id: u32, nr: u32) -> &'static str {
    let abi = match abi_id {
        1 => &X86_64,
        2 => &AARCH64,
        _ => return "unknown",
    };
    abi.syscalls
        .iter()
        .find_map(|(name, number)| (*number == nr).then_some(*name))
        .unwrap_or("unknown")
}

#[derive(Debug, Clone)]
pub struct TracepointCheck {
    pub group: &'static str,
    pub event: &'static str,
    pub ok: bool,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct PortabilityReport {
    pub arch: &'static str,
    pub abi: Option<&'static SyscallAbi>,
    pub tracepoints: Vec<TracepointCheck>,
}

impl PortabilityReport {
    pub fn ready(&self) -> bool {
        self.abi.is_some() && self.tracepoints.iter().all(|check| check.ok)
    }

    pub fn abi_name(&self) -> &'static str {
        self.abi.map(|abi| abi.name).unwrap_or("unsupported")
    }

    pub fn summary(&self) -> String {
        let failed = self.tracepoints.iter().filter(|check| !check.ok).count();
        if self.abi.is_none() {
            return format!("unsupported architecture {}", self.arch);
        }
        if failed == 0 {
            format!(
                "{} ABI and {} tracepoint layouts validated",
                self.abi_name(),
                self.tracepoints.len()
            )
        } else {
            format!(
                "{} tracepoint layout checks failed on {}",
                failed, self.arch
            )
        }
    }
}

const LAYOUTS: &[(&str, &str, &[(&str, usize)])] = &[
    ("sched", "sched_process_exec", &[("filename", 8)]),
    (
        "sched",
        "sched_process_fork",
        &[
            ("parent_comm", 8),
            ("parent_pid", 12),
            ("child_comm", 16),
            ("child_pid", 20),
        ],
    ),
    (
        "sock",
        "inet_sock_set_state",
        &[
            ("oldstate", 16),
            ("newstate", 20),
            ("sport", 24),
            ("dport", 26),
            ("family", 28),
            ("saddr", 32),
            ("daddr", 36),
            ("saddr_v6", 40),
            ("daddr_v6", 56),
        ],
    ),
    (
        "syscalls",
        "sys_enter_memfd_create",
        &[("uname", 16), ("flags", 24)],
    ),
    ("raw_syscalls", "sys_enter", &[("id", 8), ("args", 16)]),
];

pub fn probe() -> PortabilityReport {
    PortabilityReport {
        arch: host_arch(),
        abi: host_abi(),
        tracepoints: LAYOUTS
            .iter()
            .map(|(group, event, fields)| check_layout(group, event, fields))
            .collect(),
    }
}

pub fn require_ready() -> Result<PortabilityReport> {
    let report = probe();
    if report.abi.is_none() {
        bail!(
            "unsupported Linux architecture {}; security syscall capture is disabled",
            report.arch
        );
    }
    if let Some(failed) = report.tracepoints.iter().find(|check| !check.ok) {
        bail!(
            "tracepoint layout validation failed for {}/{}: {}",
            failed.group,
            failed.event,
            failed.reason
        );
    }
    Ok(report)
}

fn tracepoint_format(group: &str, event: &str) -> Result<String> {
    let candidates = [
        format!("/sys/kernel/tracing/events/{group}/{event}/format"),
        format!("/sys/kernel/debug/tracing/events/{group}/{event}/format"),
    ];
    for candidate in candidates {
        if Path::new(&candidate).is_file() {
            return fs::read_to_string(&candidate).with_context(|| format!("reading {candidate}"));
        }
    }
    bail!("tracepoint format file is unavailable")
}

fn check_layout(
    group: &'static str,
    event: &'static str,
    fields: &[(&str, usize)],
) -> TracepointCheck {
    let result = tracepoint_format(group, event).and_then(|format| {
        for (field, expected) in fields {
            let Some(actual) = field_offset(&format, field) else {
                bail!("field {field} is missing")
            };
            if actual != *expected {
                bail!("field {field} offset {actual}, expected {expected}")
            }
        }
        Ok(())
    });
    match result {
        Ok(()) => TracepointCheck {
            group,
            event,
            ok: true,
            reason: "expected fields and offsets match".into(),
        },
        Err(error) => TracepointCheck {
            group,
            event,
            ok: false,
            reason: error.to_string(),
        },
    }
}

fn field_offset(format: &str, wanted: &str) -> Option<usize> {
    format.lines().find_map(|line| {
        let line = line.trim();
        let declaration = line.strip_prefix("field:")?;
        let name = declaration.split(';').next()?.split_whitespace().last()?;
        let name = name.split('[').next().unwrap_or(name);
        if name != wanted {
            return None;
        }
        let offset = line.split("offset:").nth(1)?.split(';').next()?.trim();
        offset.parse().ok()
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn syscall_profiles_have_unique_numbers() {
        for abi in [&X86_64, &AARCH64] {
            let mut numbers = HashSet::new();
            for (_, number) in abi.syscalls {
                assert!(
                    numbers.insert(number),
                    "duplicate syscall {} in {}",
                    number,
                    abi.name
                );
            }
        }
    }

    #[test]
    fn names_are_abi_specific() {
        assert_eq!(syscall_name(1, 9), "mmap");
        assert_eq!(syscall_name(2, 222), "mmap");
        assert_eq!(syscall_name(1, 222), "unknown");
    }

    #[test]
    fn parses_tracepoint_field_offsets() {
        let text = "field:__u8 saddr_v6[16]; offset:40; size:16;\nfield:int id; offset:8; size:4;";
        assert_eq!(field_offset(text, "saddr_v6"), Some(40));
        assert_eq!(field_offset(text, "id"), Some(8));
        assert_eq!(field_offset(text, "missing"), None);
    }
}
