//! Interpreter-script detection (execve_script, kunai-style).
//!
//! When an interpreter execs with a script file operand (`python3
//! /tmp/x.py`, `sh deploy.sh`), emit a dedicated `script` event with the
//! script's path and a bounded, no-follow sha256. Code-mode invocations
//! (`python3 -c …`, `perl -e …`, `bash -c …`, `python3 -m mod`) carry no
//! script file and stay plain execs.
//!
//! Bounds per the security invariants: O_NOFOLLOW|O_CLOEXEC on the script,
//! fstat regular-file check, ELF-magic exclusion (a "script" that is
//! itself a binary is just an exec), hashing capped at
//! SCRIPT_HASH_MAX_BYTES — any failure is fail-open (null hash), never an
//! enforcement change.

use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

/// Kernel comms treated as interpreters. Exact-match, like the rules
/// engine's comm selector.
pub const INTERPRETERS: [&str; 9] = [
    "sh", "bash", "dash", "zsh", "python", "python3", "perl", "ruby", "node",
];

/// Hash budget for a script file. Way past any real script.
pub const SCRIPT_HASH_MAX_BYTES: u64 = 4 * 1024 * 1024;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// Pick the script operand out of an interpreter's argv, if any. The first
/// non-flag argument is the candidate; seeing a code-mode flag (-c, -e,
/// -m, including attached forms like -c'code') settles it: no script file.
pub fn script_candidate<'a>(comm: &str, args: &'a [String]) -> Option<&'a str> {
    if !INTERPRETERS.contains(&comm) || args.len() < 2 {
        return None;
    }
    for arg in &args[1..] {
        if let Some(rest) = arg.strip_prefix('-') {
            if rest.starts_with('c') || rest.starts_with('e') || rest == "m" {
                return None;
            }
            continue; // other flags (-u, -O, -I, -W …) are skipped
        }
        return Some(arg.as_str());
    }
    None
}

pub fn is_elf_magic(header: &[u8]) -> bool {
    header.starts_with(&ELF_MAGIC)
}

pub struct ScriptFile {
    pub sha256: Option<String>,
}

/// Validate and hash the script candidate. None when the file is not a
/// readable regular file or is itself an ELF binary. The hash is
/// fail-open: a read error mid-file still reports the path, hashless.
pub fn inspect_script(path: &str) -> Option<ScriptFile> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() {
        return None;
    }
    let mut magic = [0u8; 4];
    if file.read_exact(&mut magic).is_err() || is_elf_magic(&magic) {
        return None;
    }
    let sha256 = hash_bounded(file, path).ok();
    Some(ScriptFile { sha256 })
}

fn hash_bounded(mut file: File, display: &str) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut limited = (&mut file).take(SCRIPT_HASH_MAX_BYTES + 1);
    let copied = std::io::copy(&mut limited, &mut hasher)
        .with_context(|| format!("hashing script {display}"))?;
    if copied > SCRIPT_HASH_MAX_BYTES {
        anyhow::bail!("script {display} exceeds the hash budget");
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// /proc/<pid>/cmdline as an argv vector (the joined-string form loses
/// quoting boundaries).
pub fn proc_cmdline_args(pid: u32) -> Option<Vec<String>> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let args: Vec<String> = raw
        .split(|&b| b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect();
    if args.is_empty() { None } else { Some(args) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(argv: &[&str]) -> Vec<String> {
        argv.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn candidate_basic_and_flags() {
        assert_eq!(
            script_candidate("python3", &args(&["python3", "/tmp/hello.py"])),
            Some("/tmp/hello.py")
        );
        assert_eq!(
            script_candidate("sh", &args(&["sh", "-x", "/tmp/deploy.sh"])),
            Some("/tmp/deploy.sh")
        );
        assert_eq!(
            script_candidate("python3", &args(&["python3", "-u", "script.py"])),
            Some("script.py")
        );
    }

    #[test]
    fn candidate_code_mode_is_none() {
        assert_eq!(
            script_candidate("python3", &args(&["python3", "-c", "print(1)"])),
            None
        );
        assert_eq!(script_candidate("perl", &args(&["perl", "-e", "1"])), None);
        assert_eq!(script_candidate("bash", &args(&["bash", "-c", "id"])), None);
        assert_eq!(script_candidate("ruby", &args(&["ruby", "-e',p 1'"])), None);
        assert_eq!(
            script_candidate("python3", &args(&["python3", "-m", "http.server"])),
            None
        );
        // Interactive shell: no operand at all.
        assert_eq!(script_candidate("bash", &args(&["bash"])), None);
        assert_eq!(script_candidate("zsh", &args(&["-zsh"])), None);
    }

    #[test]
    fn candidate_non_interpreter_is_none() {
        assert_eq!(script_candidate("curl", &args(&["curl", "/tmp/x"])), None);
        assert_eq!(script_candidate("crontab", &args(&["crontab", "-e"])), None);
    }

    #[test]
    fn elf_magic_detection() {
        assert!(is_elf_magic(b"\x7fELF\x02\x01"));
        assert!(!is_elf_magic(b"#!/bin/python3\n"));
        assert!(!is_elf_magic(b""));
    }

    #[test]
    fn inspect_script_real_files() {
        let dir = std::env::temp_dir().join(format!("merlin-script-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let script = dir.join("hello.py");
        fs::write(&script, "print('hello')\n").unwrap();
        let info = inspect_script(&script.display().to_string()).unwrap();
        assert!(info.sha256.is_some());
        // An ELF-ish file is not a script.
        let fake_elf = dir.join("elf.py");
        fs::write(&fake_elf, b"\x7fELF\x02\x01\x01\x00fake").unwrap();
        assert!(inspect_script(&fake_elf.display().to_string()).is_none());
        // Missing file → None, no panic.
        assert!(inspect_script(&dir.join("nope.py").display().to_string()).is_none());
        let _ = fs::remove_dir_all(&dir);
    }
}
