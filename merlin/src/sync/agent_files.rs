//! Agent file opens the model-file posture check needs beyond the inventory's:
//! a regular file of any size and a symlink's target, both without following
//! any link.

use std::ffi::{CString, OsStr, OsString};
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};

/// Open `name` in `parent` as a regular file of any size, never through a
/// symlink, a FIFO or a device node.
pub(crate) fn open_agent_file_at(parent: &fs::File, name: &OsStr) -> Option<fs::File> {
    super::open_agent_regular_file_within(parent, name, u64::MAX)
}

/// The target of the symlink `name` in `parent`, read without following it;
/// `None` when `name` is not a symlink or its target is over 4 KiB.
pub(crate) fn read_agent_link_at(parent: &fs::File, name: &OsStr) -> Option<OsString> {
    let name = CString::new(name.as_bytes()).ok()?;
    let mut target = vec![0u8; 4097];
    // SAFETY: `parent` is open during the call, `name` is NUL terminated and
    // `target` is a writable buffer of the length passed.
    let len = unsafe {
        libc::readlinkat(
            parent.as_raw_fd(),
            name.as_ptr(),
            target.as_mut_ptr().cast(),
            target.len(),
        )
    };
    let len = usize::try_from(len)
        .ok()
        .filter(|len| *len < target.len())?;
    target.truncate(len);
    Some(OsString::from_vec(target))
}
