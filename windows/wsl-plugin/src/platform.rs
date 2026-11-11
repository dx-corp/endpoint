//! What differs between the deployed Windows DLL and the portable test build:
//! where the plugin's folders are, and how a scanner's stdout socket is read.

use std::path::{Path, PathBuf};

/// Wall-clock limit for reading one scan's output.
#[cfg(windows)]
const READ_TIMEOUT_MS: u32 = 30_000;

/// The state folder (`%ProgramData%\Deixic\Endpoint\wsl`) and the install
/// folder's `wsl` directory, next to this DLL.
#[cfg(windows)]
pub fn directories() -> Option<(PathBuf, PathBuf)> {
    use windows_sys::Win32::Foundation::HMODULE;
    use windows_sys::Win32::System::LibraryLoader::{
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        GetModuleFileNameW, GetModuleHandleExW,
    };

    let program_data = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    let state = program_data.join("Deixic").join("Endpoint").join("wsl");

    let mut module: HMODULE = std::ptr::null_mut();
    let anchor = directories as *const u16;
    // SAFETY: the flags look up the module holding `anchor` (this DLL) without
    // taking a reference, and `module` receives its handle.
    let found = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            anchor,
            &mut module,
        )
    };
    if found == 0 {
        return None;
    }
    let mut buffer = vec![0u16; 32_768];
    // SAFETY: `buffer` holds `buffer.len()` UTF-16 units.
    let length =
        unsafe { GetModuleFileNameW(module, buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return None;
    }
    let dll = PathBuf::from(String::from_utf16_lossy(&buffer[..length]));
    Some((state, dll.parent()?.join("wsl")))
}

#[cfg(windows)]
pub fn scanner_present(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file())
}

/// Read the scanner's stdout until it closes, within the size and time
/// limits, then close the socket.
#[cfg(windows)]
pub fn read_socket(socket: crate::ffi::Socket) -> Option<Vec<u8>> {
    use windows_sys::Win32::Networking::WinSock::{
        SO_RCVTIMEO, SOL_SOCKET, closesocket, recv, setsockopt,
    };

    let timeout = READ_TIMEOUT_MS.to_ne_bytes();
    // SAFETY: `socket` is the open socket WSL handed this plugin; the option
    // value is a DWORD of milliseconds.
    unsafe {
        setsockopt(
            socket,
            SOL_SOCKET,
            SO_RCVTIMEO,
            timeout.as_ptr(),
            timeout.len() as i32,
        )
    };
    let started = std::time::Instant::now();
    let mut body = Vec::new();
    let mut chunk = [0u8; 16 << 10];
    let complete = loop {
        if started.elapsed().as_millis() > u128::from(READ_TIMEOUT_MS) {
            break false;
        }
        // SAFETY: `chunk` is writable for its full length.
        let read = unsafe { recv(socket, chunk.as_mut_ptr(), chunk.len() as i32, 0) };
        if read == 0 {
            break true;
        }
        if read < 0 {
            break false;
        }
        body.extend_from_slice(&chunk[..read as usize]);
        if body.len() > crate::state::MAX_SCAN_BYTES {
            break false;
        }
    };
    // SAFETY: the plugin owns the socket and closes it once.
    unsafe { closesocket(socket) };
    complete.then_some(body)
}

#[cfg(not(windows))]
pub(crate) use portable::{directories, read_socket, scanner_present};

/// The portable build exists for tests: it has no folders unless a test sets
/// them, and reads a scanner's output from what the test queued.
#[cfg(not(windows))]
pub mod portable {
    use super::{Path, PathBuf};
    use std::collections::HashMap;
    use std::sync::Mutex;

    pub(crate) static DIRECTORIES: Mutex<Option<(PathBuf, PathBuf)>> = Mutex::new(None);
    pub(crate) static SOCKETS: Mutex<Option<HashMap<usize, Vec<u8>>>> = Mutex::new(None);

    pub fn directories() -> Option<(PathBuf, PathBuf)> {
        DIRECTORIES.lock().ok()?.clone()
    }

    pub fn scanner_present(path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file())
    }

    pub fn read_socket(socket: crate::ffi::Socket) -> Option<Vec<u8>> {
        SOCKETS.lock().ok()?.as_mut()?.remove(&socket)
    }
}
