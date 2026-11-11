//! Deixic Endpoint WSL plugin.
//!
//! wslservice loads this DLL and calls its hooks. When a person starts a WSL
//! distribution, the plugin mounts the install folder's `wsl` directory
//! read-only into the WSL VM and runs the static Linux scanner there:
//! `merlin scan-ai-locations --root /proc/<init pid>/root --location
//! wsl:<name>`. The scanner chroots into the distribution and prints the AI
//! tool names and labels it finds. The plugin writes the result to one state
//! file per distribution, which the Windows collector sends at its next
//! check-in.
//!
//! The plugin never starts a distribution and never delays one: every hook
//! copies what it needs and returns `S_OK` at once, the scan runs on its own
//! thread, and a failed scan is recorded, never reported through
//! `PluginError`. A distribution that is registered but has not started, or
//! whose scan failed, is recorded as not scanned, never as clean.

pub mod ffi;
mod platform;
mod state;

use std::collections::HashSet;
use std::ffi::CString;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::{Mutex, RwLock};

use ffi::{
    Guid, Hresult, S_OK, WslDistributionInformation, WslOfflineDistributionInformation,
    WslPluginApiV1, WslPluginHooksV1, WslSessionId, WslSessionInformation,
};
use state::{DistroState, StateDir};

/// Where the install folder's `wsl` directory appears inside the WSL VM.
const MOUNT_POINT: &str = "/deixic-endpoint";
const MOUNT_NAME: &str = "deixic-endpoint";
const SCANNER: &str = "merlin";
/// Longest distribution name read from WSL, in UTF-16 units.
const MAX_NAME_UNITS: usize = 256;

struct Plugin {
    api: &'static WslPluginApiV1,
    state: StateDir,
    /// The install folder's `wsl` directory, holding the static scanner.
    scanner_dir: PathBuf,
    /// Sessions whose VM already has the scanner folder mounted.
    mounted: Mutex<HashSet<WslSessionId>>,
}

static PLUGIN: RwLock<Option<&'static Plugin>> = RwLock::new(None);

fn plugin() -> Option<&'static Plugin> {
    *PLUGIN.read().unwrap_or_else(|poison| poison.into_inner())
}

/// Runs a hook body, turning a panic into `S_OK` so it can never unwind into
/// wslservice or fail a VM or distribution start.
fn guarded(body: impl FnOnce()) -> Hresult {
    let _ = catch_unwind(AssertUnwindSafe(body));
    S_OK
}

/// The plugin entry point wslservice calls when it loads the DLL.
///
/// # Safety
/// `api` and `hooks` are null or the structs wslservice passes; `api` stays
/// valid while the DLL is loaded.
#[no_mangle]
pub(crate) unsafe extern "C" fn WSLPluginAPIV1_EntryPoint(
    api: *const WslPluginApiV1,
    hooks: *mut WslPluginHooksV1,
) -> Hresult {
    guarded(|| {
        // SAFETY: per the contract above; null pointers load nothing.
        let (Some(api), Some(hooks)) = (unsafe { api.as_ref() }, unsafe { hooks.as_mut() }) else {
            return;
        };
        let Some((state_dir, scanner_dir)) = platform::directories() else {
            return;
        };
        let state = StateDir::new(state_dir);
        let version = api.version;
        // InitPid, which the scan needs, exists from 2.0.5. On an older WSL
        // the plugin registers no hook and says so; returning an error here
        // would stop WSL from starting at all.
        let scans =
            version.at_least(2, 0, 5) && api.mount_folder.is_some() && api.execute_binary.is_some();
        let registrations = scans && version.at_least(2, 1, 2);
        state.write_plugin_status(&version, scans, registrations);
        if !scans {
            return;
        }
        let plugin: &'static Plugin = Box::leak(Box::new(Plugin {
            api,
            state,
            scanner_dir,
            mounted: Mutex::new(HashSet::new()),
        }));
        *PLUGIN.write().unwrap_or_else(|poison| poison.into_inner()) = Some(plugin);
        hooks.on_vm_stopping = Some(on_vm_stopping);
        hooks.on_distribution_started = Some(on_distribution_started);
        if registrations {
            hooks.on_distribution_registered = Some(on_distribution_registered);
            hooks.on_distribution_unregistered = Some(on_distribution_unregistered);
        }
    })
}

unsafe extern "C" fn on_vm_stopping(session: *const WslSessionInformation) -> Hresult {
    guarded(|| {
        // SAFETY: WSL passes a session valid for this call.
        let (Some(plugin), Some(session)) = (plugin(), unsafe { session.as_ref() }) else {
            return;
        };
        // The next VM in this session needs the folder mounted again.
        plugin
            .mounted
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(&session.session_id);
    })
}

/// A distribution started. Copy what the scan needs, since WSL's pointers
/// are valid only during this call, and scan on another thread.
unsafe extern "C" fn on_distribution_started(
    session: *const WslSessionInformation,
    distribution: *const WslDistributionInformation,
) -> Hresult {
    guarded(|| {
        // SAFETY: WSL passes structs valid for this call; the entry point
        // registered this hook only on WSL 2.0.5 or later, where init_pid exists.
        let (Some(plugin), Some(session), Some(distribution)) =
            (plugin(), unsafe { session.as_ref() }, unsafe {
                distribution.as_ref()
            })
        else {
            return;
        };
        let job = ScanJob {
            session: session.session_id,
            id: distribution.id,
            // SAFETY: WSL's distribution name is a NUL-terminated string.
            name: unsafe { ffi::wide_to_string(distribution.name, MAX_NAME_UNITS) }
                .unwrap_or_default(),
            init_pid: distribution.init_pid,
        };
        let fallback = (job.id, job.name.clone());
        if spawn_scan(plugin, job).is_err() {
            plugin.state.write(
                &fallback.0,
                &DistroState::not_scanned(&fallback.1, "scan_not_started"),
            );
        }
    })
}

unsafe extern "C" fn on_distribution_registered(
    _session: *const WslSessionInformation,
    distribution: *const WslOfflineDistributionInformation,
) -> Hresult {
    guarded(|| {
        // SAFETY: WSL passes a struct valid for this call (WSL 2.1.2 or later).
        let (Some(plugin), Some(distribution)) = (plugin(), unsafe { distribution.as_ref() })
        else {
            return;
        };
        // SAFETY: WSL's distribution name is a NUL-terminated string.
        let name =
            unsafe { ffi::wide_to_string(distribution.name, MAX_NAME_UNITS) }.unwrap_or_default();
        plugin.state.record_registered(
            &distribution.id,
            &DistroState::not_scanned(&name, "not_started"),
        );
    })
}

unsafe extern "C" fn on_distribution_unregistered(
    _session: *const WslSessionInformation,
    distribution: *const WslOfflineDistributionInformation,
) -> Hresult {
    guarded(|| {
        // SAFETY: WSL passes a struct valid for this call (WSL 2.1.2 or later).
        let (Some(plugin), Some(distribution)) = (plugin(), unsafe { distribution.as_ref() })
        else {
            return;
        };
        plugin.state.remove(&distribution.id);
    })
}

struct ScanJob {
    session: WslSessionId,
    id: Guid,
    name: String,
    init_pid: u32,
}

#[cfg(not(test))]
fn spawn_scan(plugin: &'static Plugin, job: ScanJob) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("deixic-wsl-scan".into())
        .spawn(move || run_scan(plugin, job))
        .map(|_| ())
}

#[cfg(test)]
fn spawn_scan(plugin: &'static Plugin, job: ScanJob) -> std::io::Result<()> {
    let handle = std::thread::Builder::new().spawn(move || run_scan(plugin, job))?;
    tests::WORKERS.lock().unwrap().push(handle);
    Ok(())
}

/// The location shape merlin-sync accepts for a WSL distribution.
fn wsl_location(name: &str) -> Option<String> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    valid.then(|| format!("wsl:{name}"))
}

fn run_scan(plugin: &'static Plugin, job: ScanJob) {
    let result = catch_unwind(AssertUnwindSafe(|| scan(plugin, &job)));
    let state = match result {
        Ok(Ok(findings)) => DistroState::scanned(&job.name, findings),
        Ok(Err(reason)) => DistroState::not_scanned(&job.name, reason),
        Err(_) => DistroState::not_scanned(&job.name, "scan_failed"),
    };
    plugin.state.write(&job.id, &state);
}

fn scan(plugin: &Plugin, job: &ScanJob) -> Result<serde_json::Value, &'static str> {
    let location = wsl_location(&job.name).ok_or("unsupported_name")?;
    if job.init_pid <= 1 {
        return Err("no_init_pid");
    }
    if !platform::scanner_present(&plugin.scanner_dir.join(SCANNER)) {
        return Err("scanner_missing");
    }
    ensure_mounted(plugin, job.session);
    let root = format!("/proc/{}/root", job.init_pid);
    let path = format!("{MOUNT_POINT}/{SCANNER}");
    let arguments = [
        path.as_str(),
        "scan-ai-locations",
        "--root",
        &root,
        "--location",
        &location,
    ];
    let output = execute(plugin, job.session, &arguments)?;
    state::checked_scan(&output, &location).ok_or("scan_failed")
}

/// Mount the scanner folder read-only once per VM. A failure is not fatal
/// here: a folder left mounted by an earlier load still serves the scan, and
/// a missing one makes the scan fail and be recorded.
fn ensure_mounted(plugin: &Plugin, session: WslSessionId) {
    let mut mounted = plugin
        .mounted
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    if mounted.contains(&session) {
        return;
    }
    let Some(mount_folder) = plugin.api.mount_folder else {
        return;
    };
    let windows_path = ffi::to_wide(&plugin.scanner_dir.to_string_lossy());
    let linux_path = ffi::to_wide(MOUNT_POINT);
    let name = ffi::to_wide(MOUNT_NAME);
    // SAFETY: every argument is a NUL-terminated UTF-16 string that outlives
    // the call; ReadOnly is TRUE.
    let result = unsafe {
        mount_folder(
            session,
            windows_path.as_ptr(),
            linux_path.as_ptr(),
            1,
            name.as_ptr(),
        )
    };
    if result >= 0 {
        mounted.insert(session);
    }
}

fn execute(
    plugin: &Plugin,
    session: WslSessionId,
    arguments: &[&str],
) -> Result<Vec<u8>, &'static str> {
    let execute_binary = plugin.api.execute_binary.ok_or("scan_failed")?;
    let owned = arguments
        .iter()
        .map(|argument| CString::new(*argument))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "scan_failed")?;
    let mut pointers: Vec<ffi::Lpcstr> = owned.iter().map(|argument| argument.as_ptr()).collect();
    pointers.push(std::ptr::null());
    let mut socket: ffi::Socket = 0;
    // SAFETY: the path and NULL-terminated argument array outlive the call;
    // `socket` receives the process's stdout socket on success.
    let result = unsafe { execute_binary(session, pointers[0], pointers.as_ptr(), &mut socket) };
    if result < 0 {
        return Err("scan_failed");
    }
    platform::read_socket(socket).ok_or("scan_failed")
}

#[cfg(test)]
mod tests;
