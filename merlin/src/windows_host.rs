//! The Windows reads behind posture and the process snapshot: HKLM and
//! loaded-user-hive registry values (64-bit view), a `CreateToolhelp32Snapshot`
//! process list, `QueryFullProcessImageNameW` and two fixed PowerShell
//! expressions run by absolute path. Nothing here writes.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Read;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
    HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, KEY_WOW64_64KEY, REG_DWORD, REG_SZ,
    RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW,
};
use windows_sys::Win32::System::SystemInformation::{ComputerNameDnsHostname, GetComputerNameExW};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

use crate::ai_discovery::DeviceProcess;
use crate::windows_discovery::{MAX_AGENT_PROCESSES, is_agent_process};
use crate::windows_posture::{PostureSources, RegRead};
use crate::windows_wsl::{RegisteredDistro, lxss_distro_id};

const MAX_UNINSTALL_ENTRIES: usize = 4096;
const MAX_LOADED_USER_HIVES: usize = 64;
const MAX_LXSS_DISTROS: usize = 64;
const MAX_POWERSHELL_OUTPUT: u64 = 4096;
const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
/// `CREATE_NO_WINDOW`: PowerShell runs without a console window.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub(crate) struct WindowsHost;

/// The DNS host name, as Go's `os.Hostname` reads it on Windows.
pub(crate) fn hostname() -> anyhow::Result<String> {
    let mut buffer = [0u16; 256];
    let mut size = buffer.len() as u32;
    // SAFETY: `buffer` holds `size` UTF-16 units and `size` is a valid
    // in/out pointer for the call.
    let ok = unsafe { GetComputerNameExW(ComputerNameDnsHostname, buffer.as_mut_ptr(), &mut size) };
    anyhow::ensure!(ok != 0, "read hostname");
    OsString::from_wide(&buffer[..(size as usize).min(buffer.len())])
        .into_string()
        .map_err(|_| anyhow::anyhow!("hostname is not valid Unicode"))
}

fn wide(value: &str) -> Vec<u16> {
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// An open registry key, closed on drop.
struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the key was opened by RegOpenKeyExW and is closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

enum Opened {
    Key(Key),
    Missing,
    Denied,
    Failed,
}

fn open_key(root: HKEY, path: &str) -> Opened {
    let name = wide(path);
    let mut key: HKEY = std::ptr::null_mut();
    // SAFETY: `name` is NUL terminated and outlives the call; `key` is a
    // valid out pointer.
    let status =
        unsafe { RegOpenKeyExW(root, name.as_ptr(), 0, KEY_READ | KEY_WOW64_64KEY, &mut key) };
    match status {
        ERROR_SUCCESS => Opened::Key(Key(key)),
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Opened::Missing,
        ERROR_ACCESS_DENIED => Opened::Denied,
        _ => Opened::Failed,
    }
}

fn dword_value(key: &Key, name: &str) -> RegRead {
    let name = wide(name);
    let mut kind = 0u32;
    let mut value = 0u32;
    let mut size = std::mem::size_of::<u32>() as u32;
    // SAFETY: the key is open, `name` is NUL terminated and the data pointer
    // addresses `size` writable bytes.
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            std::ptr::null(),
            &mut kind,
            (&mut value as *mut u32).cast(),
            &mut size,
        )
    };
    match status {
        ERROR_SUCCESS if kind == REG_DWORD && size == 4 => RegRead::Found(value),
        ERROR_SUCCESS => RegRead::Failed,
        ERROR_FILE_NOT_FOUND => RegRead::Missing,
        ERROR_ACCESS_DENIED => RegRead::Denied,
        _ => RegRead::Failed,
    }
}

/// A `REG_SZ` value of at most 511 UTF-16 units, or empty.
fn string_value(key: &Key, name: &str) -> String {
    let name = wide(name);
    let mut kind = 0u32;
    let mut buffer = [0u16; 512];
    let mut size = (buffer.len() * 2) as u32;
    // SAFETY: the key is open, `name` is NUL terminated and the data pointer
    // addresses `size` writable bytes.
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            std::ptr::null(),
            &mut kind,
            buffer.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if status != ERROR_SUCCESS || kind != REG_SZ {
        return String::new();
    }
    let units = &buffer[..(size as usize / 2).min(buffer.len())];
    let end = units
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(units.len());
    OsString::from_wide(&units[..end])
        .into_string()
        .unwrap_or_default()
}

fn subkeys(key: &Key, limit: usize) -> Vec<String> {
    let mut names = Vec::new();
    for index in 0u32.. {
        if names.len() >= limit {
            break;
        }
        let mut buffer = [0u16; 256];
        let mut size = buffer.len() as u32;
        // SAFETY: the key is open and `buffer` holds `size` units; the
        // reserved, class and time pointers may be null.
        let status = unsafe {
            RegEnumKeyExW(
                key.0,
                index,
                buffer.as_mut_ptr(),
                &mut size,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            break;
        }
        let units = &buffer[..(size as usize).min(buffer.len())];
        if let Ok(name) = OsString::from_wide(units).into_string() {
            names.push(name);
        }
    }
    names
}

/// `DisplayName` under each Uninstall subkey of `root\path`.
fn display_names(root: HKEY, path: &str) -> Option<Vec<String>> {
    let Opened::Key(key) = open_key(root, path) else {
        return None;
    };
    Some(
        subkeys(&key, MAX_UNINSTALL_ENTRIES)
            .into_iter()
            .filter_map(|child| match open_key(key.0, &child) {
                Opened::Key(entry) => Some(string_value(&entry, "DisplayName")),
                _ => None,
            })
            .filter(|name| !name.is_empty())
            .collect(),
    )
}

/// Interactive user hives loaded under HKEY_USERS.
fn user_sids(users: &Key) -> Vec<String> {
    subkeys(users, MAX_LOADED_USER_HIVES)
        .into_iter()
        .filter(|sid| sid.starts_with("S-1-5-21-") && !sid.ends_with("_Classes"))
        .collect()
}

/// A process snapshot handle, closed on drop.
struct Snapshot(HANDLE);

impl Drop for Snapshot {
    fn drop(&mut self) {
        // SAFETY: the handle came from CreateToolhelp32Snapshot and is closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// Every process in a point-in-time snapshot: (pid, image file name).
fn snapshot_processes() -> Option<Vec<(u32, String)>> {
    // SAFETY: no pointers are passed; the result is checked below.
    let handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return None;
    }
    let snapshot = Snapshot(handle);
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut processes = Vec::new();
    // SAFETY: the snapshot is open and `entry` is a PROCESSENTRY32W whose
    // dwSize is set, as both calls require.
    let mut more = unsafe { Process32FirstW(snapshot.0, &mut entry) } != 0;
    while more {
        let end = entry
            .szExeFile
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(entry.szExeFile.len());
        let name = OsString::from_wide(&entry.szExeFile[..end])
            .to_string_lossy()
            .into_owned();
        processes.push((entry.th32ProcessID, name));
        // SAFETY: as above.
        more = unsafe { Process32NextW(snapshot.0, &mut entry) } != 0;
    }
    Some(processes)
}

/// The full image path of `pid`, best effort: empty when the process has
/// exited or cannot be opened for limited query.
fn image_path(pid: u32) -> String {
    // SAFETY: no pointers are passed; the handle is checked and closed below.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return String::new();
    }
    let process = Snapshot(handle);
    let mut buffer = [0u16; 1024];
    let mut size = buffer.len() as u32;
    // SAFETY: the process handle is open and `buffer` holds `size` units.
    let ok = unsafe {
        QueryFullProcessImageNameW(
            process.0,
            PROCESS_NAME_WIN32,
            buffer.as_mut_ptr(),
            &mut size,
        )
    };
    if ok == 0 {
        return String::new();
    }
    OsString::from_wide(&buffer[..(size as usize).min(buffer.len())])
        .into_string()
        .unwrap_or_default()
}

/// The running agent processes (`Cursor.exe`, `Claude.exe`, `codex.exe`),
/// at most `MAX_AGENT_PROCESSES`, by pid: pid, the image name Windows
/// reports and, best effort, the full image path. Never a command line,
/// arguments or environment.
pub(crate) fn agent_processes() -> Vec<DeviceProcess> {
    let mut found: Vec<DeviceProcess> = snapshot_processes()
        .unwrap_or_default()
        .into_iter()
        .filter(|(pid, name)| *pid != 0 && is_agent_process(name))
        .take(MAX_AGENT_PROCESSES)
        .map(|(pid, name)| DeviceProcess {
            pid,
            name,
            executable: image_path(pid),
            user: String::new(),
            state: String::new(),
        })
        .collect();
    found.sort_by_key(|process| process.pid);
    found
}

/// WSL distributions in each loaded user hive's Lxss key: one subkey per
/// distribution, named by its id in braces, with DistributionName. Read
/// only; distributions of users whose hive is not loaded are not listed.
pub(crate) fn registered_wsl_distros() -> Vec<RegisteredDistro> {
    let Opened::Key(users) = open_key(HKEY_USERS, "") else {
        return Vec::new();
    };
    let mut distros = Vec::new();
    for sid in user_sids(&users) {
        let path = format!(r"{sid}\Software\Microsoft\Windows\CurrentVersion\Lxss");
        let Opened::Key(lxss) = open_key(users.0, &path) else {
            continue;
        };
        for child in subkeys(&lxss, MAX_LXSS_DISTROS) {
            let Some(id) = lxss_distro_id(&child) else {
                continue;
            };
            if let Opened::Key(key) = open_key(lxss.0, &child) {
                distros.push(RegisteredDistro {
                    id,
                    name: string_value(&key, "DistributionName"),
                });
            }
        }
    }
    distros
}

impl PostureSources for WindowsHost {
    fn dword(&self, key: &str, name: &str) -> RegRead {
        match open_key(HKEY_LOCAL_MACHINE, key) {
            Opened::Key(key) => dword_value(&key, name),
            Opened::Missing => RegRead::Missing,
            Opened::Denied => RegRead::Denied,
            Opened::Failed => RegRead::Failed,
        }
    }

    /// Machine-wide (64- and 32-bit) installs and per-user installs in
    /// loaded user hives. Program names only.
    fn programs(&self) -> Option<Vec<String>> {
        let mut names = display_names(HKEY_LOCAL_MACHINE, UNINSTALL)?;
        names.extend(
            display_names(
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            )
            .unwrap_or_default(),
        );
        if let Opened::Key(users) = open_key(HKEY_USERS, "") {
            for sid in user_sids(&users) {
                names.extend(
                    display_names(users.0, &format!(r"{sid}\{UNINSTALL}")).unwrap_or_default(),
                );
            }
        }
        Some(names)
    }

    fn processes(&self) -> Option<Vec<String>> {
        snapshot_processes().map(|all| all.into_iter().map(|(_, name)| name).collect())
    }

    /// Each loaded user hive's screen saver values; a Group Policy value
    /// overrides the user's own.
    fn user_desktops(&self) -> Option<Vec<BTreeMap<String, String>>> {
        let Opened::Key(users) = open_key(HKEY_USERS, "") else {
            return None;
        };
        let names = [
            "ScreenSaveActive",
            "ScreenSaverIsSecure",
            "ScreenSaveTimeOut",
        ];
        let desktops = user_sids(&users)
            .into_iter()
            .map(|sid| {
                let mut desktop = BTreeMap::new();
                for path in [
                    r"\Control Panel\Desktop",
                    r"\Software\Policies\Microsoft\Windows\Control Panel\Desktop",
                ] {
                    if let Opened::Key(key) = open_key(users.0, &format!("{sid}{path}")) {
                        for name in names {
                            let value = string_value(&key, name);
                            if !value.is_empty() {
                                desktop.insert(name.to_string(), value);
                            }
                        }
                    }
                }
                desktop
            })
            .collect();
        Some(desktops)
    }

    /// One fixed expression with the system PowerShell by absolute path, no
    /// profile, no window, bounded time and bounded output.
    fn powershell(&self, expression: &str, timeout: Duration) -> Option<String> {
        let root = std::env::var_os("SystemRoot").filter(|root| !root.is_empty())?;
        let binary = std::path::Path::new(&root)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        let mut child = Command::new(binary)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
            ])
            .arg(expression)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .ok()?;
        let stdout = child.stdout.take()?;
        let reader = std::thread::spawn(move || {
            let mut output = Vec::new();
            stdout
                .take(MAX_POWERSHELL_OUTPUT)
                .read_to_end(&mut output)
                .ok()?;
            Some(output)
        });
        let deadline = Instant::now() + timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
            }
        };
        let output = reader.join().ok().flatten()?;
        status.filter(|status| status.success())?;
        Some(String::from_utf8_lossy(&output).trim().to_string())
    }

    /// Whether HKLM\SECURITY opens: true for SYSTEM, which install.ps1 runs
    /// the collector as.
    fn elevated(&self) -> bool {
        matches!(open_key(HKEY_LOCAL_MACHINE, "SECURITY"), Opened::Key(_))
    }
}
