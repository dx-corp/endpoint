//! Agent files read beneath a home with no symlink on the way, up to a
//! limit: a declared config may set its own (`max_bytes`), and a larger file
//! is reported (`ConfigRead::TooLarge`) instead of read.

use std::ffi::{CString, OsStr};
use std::fs;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::ai_discovery::ConfigRead;

use super::{agent_regular_file_exists_at, open_agent_directory};

/// A regular file in `parent`, never through a link, with its size.
pub(super) fn open_agent_regular_file_sized_at(
    parent: &fs::File,
    name: &OsStr,
) -> Option<(fs::File, u64)> {
    let name = CString::new(name.as_bytes()).ok()?;
    // Refuse a device node before opening it: inside a container, its root
    // can create one, and opening some devices (a watchdog) has effects.
    if !agent_regular_file_exists_at(parent, &name) {
        return None;
    }
    // O_NONBLOCK prevents an attacker from stalling a root collector with a FIFO.
    // SAFETY: `parent` is open during the call and `name` is NUL terminated.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }
    // SAFETY: the successful descriptor is owned solely by this File.
    let file = unsafe { fs::File::from_raw_fd(fd) };
    let meta = file.metadata().ok().filter(|meta| meta.is_file())?;
    Some((file, meta.len()))
}

/// Read `name` in `parent` up to `limit` bytes; a larger file is not read.
pub(super) fn read_agent_file_limited_at(
    parent: &fs::File,
    name: &str,
    limit: u64,
) -> Option<ConfigRead> {
    let (file, size) = open_agent_regular_file_sized_at(parent, OsStr::new(name))?;
    if size > limit {
        return Some(ConfigRead::TooLarge);
    }
    let mut body = String::new();
    file.take(limit + 1).read_to_string(&mut body).ok()?;
    // The file can grow between the size check and the read.
    Some(if body.len() as u64 > limit {
        ConfigRead::TooLarge
    } else {
        ConfigRead::Body(body)
    })
}

/// `read_agent_config_beneath` up to `limit` bytes, saying when the file is
/// larger instead of reading it.
pub(super) fn read_agent_config_limited(
    home: &Path,
    relative: &str,
    limit: u64,
) -> Option<ConfigRead> {
    let (parent, file) = relative.rsplit_once('/').unwrap_or(("", relative));
    let directory = open_agent_directory(&home.join(parent))?;
    read_agent_file_limited_at(&directory, file, limit)
}
