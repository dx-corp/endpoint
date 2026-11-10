//! The deployed Windows reader. It verifies the handle it opened rather than
//! a path checked before a second open: each target is opened with
//! `FILE_FLAG_OPEN_REPARSE_POINT`, refused when the handle is a reparse point,
//! a hard-linked file or not a disk file or directory, and kept only when
//! `GetFinalPathNameByHandleW` names exactly the requested path beneath the
//! root's own final path. Exact equality refuses an intermediate junction
//! even when it points somewhere else inside the root. Directories are listed
//! from the verified handle (`GetFileInformationByHandleEx`), never reopened
//! by name.

use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;

use windows_sys::Win32::Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_FULL_DIR_INFO, FILE_NAME_NORMALIZED, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_TYPE_DISK, FileFullDirectoryInfo, FileFullDirectoryRestartInfo,
    GetFileInformationByHandle, GetFileInformationByHandleEx, GetFileType,
    GetFinalPathNameByHandleW, OPEN_EXISTING, VOLUME_NAME_DOS,
};

use super::contained::{ContainedFs, canonical_windows_path, windows_path_within};

#[cfg(test)]
#[path = "handle_fs_tests.rs"]
mod tests;

/// Longest final path accepted, in UTF-16 units (the NT path limit).
const MAX_FINAL_PATH: usize = 32_767;

pub(crate) struct HandleFs;

/// An opened, verified target and its size in bytes.
struct Opened {
    file: File,
    size: u64,
}

fn wide(path: &str) -> Option<Vec<u16>> {
    let mut units: Vec<u16> = std::ffi::OsStr::new(path).encode_wide().collect();
    if units.contains(&0) {
        return None;
    }
    units.push(0);
    Some(units)
}

/// Open `path` without following a final reparse point and check the handle:
/// not a reparse point, the expected kind, a disk object, and for a file at
/// most one hard link.
fn open_no_reparse(path: &str, directory: bool) -> Option<Opened> {
    let name = wide(path)?;
    let mut flags = FILE_FLAG_OPEN_REPARSE_POINT;
    if directory {
        flags |= FILE_FLAG_BACKUP_SEMANTICS;
    }
    // SAFETY: `name` is a NUL-terminated UTF-16 string that outlives the
    // call; the security attributes and template handle are null, which
    // CreateFileW accepts.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            flags,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return None;
    }
    // SAFETY: `handle` is a valid handle this function exclusively owns; the
    // File closes it on every return path below.
    let file = unsafe { File::from_raw_handle(handle) };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is open for the call and `info` is a valid out
    // pointer of the documented type.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return None;
    }
    let is_directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || is_directory != directory
        || (!directory && info.nNumberOfLinks > 1)
    {
        return None;
    }
    // SAFETY: the handle is open for the call.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK {
        return None;
    }
    let size = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
    Some(Opened { file, size })
}

/// The canonical final path of an open handle. Volume GUID, UNC and device
/// paths are refused by `canonical_windows_path`.
fn final_path(file: &File) -> Option<String> {
    let mut buffer = vec![0u16; 512];
    loop {
        // SAFETY: the handle is open and `buffer` holds `buffer.len()` units.
        let length = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                buffer.as_mut_ptr(),
                u32::try_from(buffer.len()).ok()?,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        } as usize;
        if length == 0 {
            return None;
        }
        if length < buffer.len() {
            let value = OsString::from_wide(&buffer[..length]).into_string().ok()?;
            return canonical_windows_path(&value);
        }
        if length > MAX_FINAL_PATH {
            return None;
        }
        // On a short buffer the return value is the size needed, including
        // the terminating NUL.
        buffer = vec![0u16; length + 1];
    }
}

/// Open `path` beneath `root` and verify both handles by final path.
fn open_within(root: &Path, path: &Path, directory: bool) -> Option<Opened> {
    let wanted_root = canonical_windows_path(root.to_str()?)?;
    let wanted_path = canonical_windows_path(path.to_str()?)?;
    if !windows_path_within(&wanted_root, &wanted_path) {
        return None;
    }
    let root_handle = open_no_reparse(&wanted_root, true)?;
    let actual_root = final_path(&root_handle.file)?;
    if actual_root != wanted_root || (wanted_path == wanted_root && !directory) {
        return None;
    }
    let opened = open_no_reparse(&wanted_path, directory)?;
    let actual_path = final_path(&opened.file)?;
    (actual_path == wanted_path && windows_path_within(&actual_root, &actual_path))
        .then_some(opened)
}

/// Entry names of a verified directory handle, read with
/// `GetFileInformationByHandleEx` so the directory is never reopened by name.
fn list_directory(directory: &File, limit: usize) -> Vec<String> {
    // u64 storage keeps each FILE_FULL_DIR_INFO record 8-byte aligned.
    let mut buffer = vec![0u64; 8 << 10];
    let byte_len = u32::try_from(buffer.len() * 8).unwrap_or(u32::MAX);
    let mut names = Vec::new();
    let mut class = FileFullDirectoryRestartInfo;
    let mut visited = 0usize;
    'batches: while visited < limit {
        // SAFETY: the handle is an open directory and `buffer` is writable
        // for `byte_len` bytes.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                directory.as_raw_handle(),
                class,
                buffer.as_mut_ptr().cast(),
                byte_len,
            )
        };
        if ok == 0 {
            // ERROR_NO_MORE_FILES ends the listing; any other error ends it
            // early, which only omits entries.
            break;
        }
        class = FileFullDirectoryInfo;
        let bytes: &[u8] = {
            let pointer = buffer.as_ptr().cast::<u8>();
            // SAFETY: the u64 buffer is initialized and `byte_len` bytes long.
            unsafe { std::slice::from_raw_parts(pointer, byte_len as usize) }
        };
        let mut offset = 0usize;
        loop {
            let header = std::mem::offset_of!(FILE_FULL_DIR_INFO, FileName);
            // The whole struct must lie in the buffer before it is borrowed.
            if offset + std::mem::size_of::<FILE_FULL_DIR_INFO>() > bytes.len() {
                break 'batches;
            }
            // SAFETY: a whole FILE_FULL_DIR_INFO lies within the initialized
            // buffer (checked above); the buffer is 8-byte aligned and the
            // kernel places each record at an 8-byte aligned offset, which
            // satisfies the struct's alignment.
            let record = unsafe { &*bytes.as_ptr().add(offset).cast::<FILE_FULL_DIR_INFO>() };
            let name_len = record.FileNameLength as usize;
            let name_start = offset + header;
            if name_start + name_len > bytes.len() || !name_len.is_multiple_of(2) {
                break 'batches;
            }
            let units: Vec<u16> = bytes[name_start..name_start + name_len]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            if let Ok(name) = OsString::from_wide(&units).into_string() {
                if name != "." && name != ".." {
                    visited += 1;
                    names.push(name);
                }
            }
            if visited >= limit || record.NextEntryOffset == 0 {
                break;
            }
            offset += record.NextEntryOffset as usize;
        }
    }
    names.truncate(limit);
    names.sort();
    names
}

impl ContainedFs for HandleFs {
    fn read_within(&self, root: &Path, path: &Path, limit: u64) -> Option<Vec<u8>> {
        let opened = open_within(root, path, false)?;
        if opened.size > limit {
            return None;
        }
        let mut body = Vec::new();
        opened.file.take(limit + 1).read_to_end(&mut body).ok()?;
        (body.len() as u64 <= limit).then_some(body)
    }

    fn regular_file_within(&self, root: &Path, path: &Path, limit: u64) -> bool {
        open_within(root, path, false).is_some_and(|opened| opened.size <= limit)
    }

    fn directory_within(&self, root: &Path, path: &Path) -> bool {
        open_within(root, path, true).is_some()
    }

    fn entries_within(&self, root: &Path, path: &Path, limit: usize) -> Vec<String> {
        if limit == 0 || limit > 256 {
            return Vec::new();
        }
        open_within(root, path, true)
            .map(|opened| list_directory(&opened.file, limit))
            .unwrap_or_default()
    }
}
