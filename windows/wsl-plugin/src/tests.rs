//! The plugin's hooks driven through a mocked `WSLPluginAPIV1` table, as
//! wslservice would call them. No real WSL is involved.

use std::ffi::CStr;
use std::path::Path;
use std::sync::mpsc;
use std::sync::{Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::Value;

use super::*;
use crate::ffi::{Socket, WslVersion, to_wide};
use crate::platform::portable;

pub(crate) static WORKERS: Mutex<Vec<JoinHandle<()>>> = Mutex::new(Vec::new());
static SERIAL: Mutex<()> = Mutex::new(());
static CALLS: Mutex<Vec<String>> = Mutex::new(Vec::new());
/// What the mocked ExecuteBinary does: print this output, or fail with None.
static OUTPUT: Mutex<Option<Vec<u8>>> = Mutex::new(None);
/// When set, ExecuteBinary waits for a message before it returns.
static GATE: Mutex<Option<mpsc::Receiver<()>>> = Mutex::new(None);

const E_FAIL: Hresult = 0x8000_4005_u32 as i32;

fn calls() -> Vec<String> {
    CALLS.lock().unwrap().clone()
}

unsafe fn wide(value: ffi::Lpcwstr) -> String {
    unsafe { ffi::wide_to_string(value, 4096) }.unwrap()
}

unsafe extern "C" fn mock_mount(
    session: WslSessionId,
    windows_path: ffi::Lpcwstr,
    linux_path: ffi::Lpcwstr,
    read_only: i32,
    name: ffi::Lpcwstr,
) -> Hresult {
    let call = unsafe {
        format!(
            "mount {session} {} {} ro={read_only} {}",
            wide(windows_path),
            wide(linux_path),
            wide(name)
        )
    };
    CALLS.lock().unwrap().push(call);
    S_OK
}

unsafe extern "C" fn mock_execute(
    session: WslSessionId,
    path: ffi::Lpcstr,
    arguments: *const ffi::Lpcstr,
    socket: *mut Socket,
) -> Hresult {
    let mut words = vec![
        unsafe { CStr::from_ptr(path) }
            .to_string_lossy()
            .into_owned(),
    ];
    let mut index = 1;
    loop {
        let argument = unsafe { *arguments.add(index) };
        if argument.is_null() {
            break;
        }
        words.push(
            unsafe { CStr::from_ptr(argument) }
                .to_string_lossy()
                .into_owned(),
        );
        index += 1;
    }
    CALLS
        .lock()
        .unwrap()
        .push(format!("exec {session} {}", words.join(" ")));
    if let Some(gate) = GATE.lock().unwrap().take() {
        let _ = gate.recv_timeout(Duration::from_secs(10));
    }
    let Some(output) = OUTPUT.lock().unwrap().clone() else {
        return E_FAIL;
    };
    let id = 4242 + index;
    portable::SOCKETS
        .lock()
        .unwrap()
        .get_or_insert_with(Default::default)
        .insert(id, output);
    unsafe { *socket = id };
    S_OK
}

unsafe extern "C" fn mock_plugin_error(_message: ffi::Lpcwstr) -> Hresult {
    CALLS.lock().unwrap().push("plugin_error".into());
    S_OK
}

fn api(major: u32, minor: u32, revision: u32) -> &'static WslPluginApiV1 {
    Box::leak(Box::new(WslPluginApiV1 {
        version: WslVersion {
            major,
            minor,
            revision,
        },
        mount_folder: Some(mock_mount),
        execute_binary: Some(mock_execute),
        plugin_error: Some(mock_plugin_error),
    }))
}

fn empty_hooks() -> WslPluginHooksV1 {
    WslPluginHooksV1 {
        on_vm_started: None,
        on_vm_stopping: None,
        on_distribution_started: None,
        on_distribution_stopping: None,
        on_distribution_registered: None,
        on_distribution_unregistered: None,
    }
}

struct Fixture {
    _serial: MutexGuard<'static, ()>,
    dir: PathBuf,
    hooks: WslPluginHooksV1,
}

impl Fixture {
    /// Load the plugin against a mocked WSL of this version, with the
    /// scanner installed or not.
    fn load(version: (u32, u32, u32), with_scanner: bool) -> Self {
        let serial = SERIAL.lock().unwrap_or_else(|poison| poison.into_inner());
        CALLS.lock().unwrap().clear();
        *OUTPUT.lock().unwrap() = None;
        let dir = std::env::temp_dir().join(format!(
            "deixic-wsl-plugin-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let scanner_dir = dir.join("install").join("wsl");
        std::fs::create_dir_all(&scanner_dir).unwrap();
        if with_scanner {
            std::fs::write(scanner_dir.join("merlin"), b"\x7fELF").unwrap();
        }
        *portable::DIRECTORIES.lock().unwrap() = Some((dir.join("state"), scanner_dir));
        *PLUGIN.write().unwrap() = None;
        let mut hooks = empty_hooks();
        let api = api(version.0, version.1, version.2);
        let result = unsafe { WSLPluginAPIV1_EntryPoint(api, &mut hooks) };
        assert_eq!(result, S_OK, "loading must never fail WSL");
        Fixture {
            _serial: serial,
            dir,
            hooks,
        }
    }

    fn state(&self, file: &str) -> Option<Value> {
        let body = std::fs::read(self.dir.join("state").join(file)).ok()?;
        Some(serde_json::from_slice(&body).unwrap())
    }

    fn start(&self, session: u32, id: Guid, name: &str, init_pid: u32) -> Hresult {
        let name = to_wide(name);
        let session = WslSessionInformation {
            session_id: session,
            user_token: std::ptr::null_mut(),
            user_sid: std::ptr::null_mut(),
        };
        let distribution = WslDistributionInformation {
            id,
            name: name.as_ptr(),
            pid_namespace: 4026531836,
            package_family_name: std::ptr::null(),
            init_pid,
        };
        let hook = self.hooks.on_distribution_started.expect("started hook");
        unsafe { hook(&session, &distribution) }
    }

    fn register(&self, id: Guid, name: &str, registered: bool) -> Hresult {
        let name = to_wide(name);
        let session = WslSessionInformation {
            session_id: 1,
            user_token: std::ptr::null_mut(),
            user_sid: std::ptr::null_mut(),
        };
        let distribution = WslOfflineDistributionInformation {
            id,
            name: name.as_ptr(),
            package_family_name: std::ptr::null(),
        };
        let hook = if registered {
            self.hooks.on_distribution_registered
        } else {
            self.hooks.on_distribution_unregistered
        }
        .expect("registration hook");
        unsafe { hook(&session, &distribution) }
    }

    fn stop_vm(&self, session: u32) {
        let session = WslSessionInformation {
            session_id: session,
            user_token: std::ptr::null_mut(),
            user_sid: std::ptr::null_mut(),
        };
        let hook = self.hooks.on_vm_stopping.expect("vm stopping hook");
        assert_eq!(unsafe { hook(&session) }, S_OK);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        wait_for_scans();
        *PLUGIN.write().unwrap() = None;
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn wait_for_scans() {
    let handles: Vec<_> = WORKERS.lock().unwrap().drain(..).collect();
    for handle in handles {
        handle.join().unwrap();
    }
}

fn id(n: u8) -> Guid {
    Guid {
        data1: 0xA0B0_C0D0,
        data2: 1,
        data3: 2,
        data4: [0, 0, 0, 0, 0, 0, 0, n],
    }
}

fn file(id: Guid) -> String {
    format!("{}.json", id.file_stem())
}

fn scanner_output(location: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "clis": [{"name": "claude"}],
        "mcp_servers": [{"location": location, "client": "codex", "name": "github", "source": ".codex/config.toml", "transport": "remote"}],
        "agent_assets": [{"location": location, "client": "claude", "kind": "skill", "name": "review", "source": ".claude/skills"}],
    }))
    .unwrap()
}

#[test]
fn a_started_distribution_is_scanned_through_the_mounted_scanner() {
    let fixture = Fixture::load((2, 4, 4), true);
    *OUTPUT.lock().unwrap() = Some(scanner_output("wsl:Ubuntu-24.04"));
    assert_eq!(fixture.start(7, id(1), "Ubuntu-24.04", 812), S_OK);
    wait_for_scans();

    let scanner_dir = fixture.dir.join("install").join("wsl");
    assert_eq!(
        calls(),
        vec![
            format!("mount 7 {} /deixic-endpoint ro=1 deixic-endpoint", scanner_dir.display()),
            "exec 7 /deixic-endpoint/merlin scan-ai-locations --root /proc/812/root --location wsl:Ubuntu-24.04".to_string(),
        ]
    );
    let state = fixture.state(&file(id(1))).expect("state file");
    assert_eq!(state["state"], "scanned");
    assert_eq!(state["distro"], "Ubuntu-24.04");
    assert_eq!(state["findings"]["mcp_servers"][0]["name"], "github");
    assert_eq!(
        state["findings"]["agent_assets"][0]["location"],
        "wsl:Ubuntu-24.04"
    );
    let plugin = fixture.state("plugin.json").unwrap();
    assert_eq!(
        (plugin["wsl_version"].as_str(), plugin["scans"].as_bool()),
        (Some("2.4.4"), Some(true))
    );

    // The folder is mounted once per VM, and again after the VM stops.
    assert_eq!(fixture.start(7, id(2), "Debian", 900), S_OK);
    wait_for_scans();
    fixture.stop_vm(7);
    assert_eq!(fixture.start(7, id(2), "Debian", 950), S_OK);
    wait_for_scans();
    let mounts = calls()
        .iter()
        .filter(|call| call.starts_with("mount"))
        .count();
    assert_eq!(mounts, 2);
}

#[test]
fn the_start_hook_returns_before_the_scan_finishes() {
    let fixture = Fixture::load((2, 4, 4), true);
    *OUTPUT.lock().unwrap() = Some(scanner_output("wsl:Ubuntu"));
    let (release, gate) = mpsc::channel();
    *GATE.lock().unwrap() = Some(gate);
    // ExecuteBinary is blocked, yet the hook has already returned S_OK.
    assert_eq!(fixture.start(3, id(3), "Ubuntu", 500), S_OK);
    assert!(fixture.state(&file(id(3))).is_none());
    release.send(()).unwrap();
    wait_for_scans();
    assert_eq!(fixture.state(&file(id(3))).unwrap()["state"], "scanned");
}

#[test]
fn a_failed_or_untrusted_scan_is_not_scanned_and_never_a_plugin_error() {
    let fixture = Fixture::load((2, 4, 4), true);
    // ExecuteBinary fails.
    assert_eq!(fixture.start(1, id(4), "Ubuntu", 500), S_OK);
    wait_for_scans();
    let state = fixture.state(&file(id(4))).unwrap();
    assert_eq!(
        (state["state"].as_str(), state["reason"].as_str()),
        (Some("not_scanned"), Some("scan_failed"))
    );
    assert!(state["findings"].is_null());

    // Output tagged with another location is refused.
    *OUTPUT.lock().unwrap() = Some(scanner_output("wsl:Other"));
    assert_eq!(fixture.start(1, id(5), "Ubuntu", 500), S_OK);
    wait_for_scans();
    // Output that is not the scanner's JSON is refused.
    *OUTPUT.lock().unwrap() = Some(b"not json".to_vec());
    assert_eq!(fixture.start(1, id(6), "Debian", 501), S_OK);
    wait_for_scans();
    for distro in [id(5), id(6)] {
        assert_eq!(
            fixture.state(&file(distro)).unwrap()["reason"],
            "scan_failed"
        );
    }
    // A name merlin-sync cannot carry, or a missing init pid, is never run.
    assert_eq!(fixture.start(1, id(7), "my distro", 500), S_OK);
    assert_eq!(fixture.start(1, id(8), "Ubuntu", 0), S_OK);
    wait_for_scans();
    assert_eq!(
        fixture.state(&file(id(7))).unwrap()["reason"],
        "unsupported_name"
    );
    assert_eq!(
        fixture.state(&file(id(8))).unwrap()["reason"],
        "no_init_pid"
    );
    assert!(!calls().iter().any(|call| call == "plugin_error"));
}

#[test]
fn without_the_scanner_nothing_runs_and_the_distribution_is_not_scanned() {
    let fixture = Fixture::load((2, 4, 4), false);
    assert_eq!(fixture.start(1, id(9), "Ubuntu", 500), S_OK);
    wait_for_scans();
    assert_eq!(
        fixture.state(&file(id(9))).unwrap()["reason"],
        "scanner_missing"
    );
    assert!(calls().is_empty());
}

#[test]
fn registered_distributions_are_not_scanned_until_they_start() {
    let fixture = Fixture::load((2, 4, 4), true);
    assert_eq!(fixture.register(id(10), "Fedora", true), S_OK);
    let state = fixture.state(&file(id(10))).unwrap();
    assert_eq!(
        (state["state"].as_str(), state["reason"].as_str()),
        (Some("not_scanned"), Some("not_started"))
    );

    // A scan that already landed is not replaced by a late registration.
    *OUTPUT.lock().unwrap() = Some(scanner_output("wsl:Alpine"));
    assert_eq!(fixture.start(1, id(11), "Alpine", 500), S_OK);
    wait_for_scans();
    assert_eq!(fixture.register(id(11), "Alpine", true), S_OK);
    assert_eq!(fixture.state(&file(id(11))).unwrap()["state"], "scanned");

    assert_eq!(fixture.register(id(10), "Fedora", false), S_OK);
    assert!(fixture.state(&file(id(10))).is_none());
}

#[test]
fn an_old_wsl_loads_without_hooks_and_says_it_cannot_scan() {
    let fixture = Fixture::load((2, 0, 4), true);
    let hooks = &fixture.hooks;
    assert!(hooks.on_vm_stopping.is_none() && hooks.on_distribution_started.is_none());
    assert!(
        hooks.on_distribution_registered.is_none() && hooks.on_distribution_unregistered.is_none()
    );
    let plugin = fixture.state("plugin.json").unwrap();
    assert_eq!(
        (plugin["wsl_version"].as_str(), plugin["scans"].as_bool()),
        (Some("2.0.4"), Some(false))
    );
}

#[test]
fn registration_hooks_are_written_only_where_wsl_allocates_them() {
    // 2.0.5 has InitPid but its hooks table ends before the registration slots.
    let fixture = Fixture::load((2, 0, 5), true);
    assert!(fixture.hooks.on_distribution_started.is_some());
    assert!(fixture.hooks.on_distribution_registered.is_none());
    assert_eq!(
        fixture.state("plugin.json").unwrap()["registrations"],
        false
    );
}

#[test]
fn null_arguments_and_missing_folders_never_fail_the_load() {
    let _serial = SERIAL.lock().unwrap_or_else(|poison| poison.into_inner());
    let mut hooks = empty_hooks();
    assert_eq!(
        unsafe { WSLPluginAPIV1_EntryPoint(std::ptr::null(), &mut hooks) },
        S_OK
    );
    *portable::DIRECTORIES.lock().unwrap() = None;
    assert_eq!(
        unsafe { WSLPluginAPIV1_EntryPoint(api(2, 4, 4), &mut hooks) },
        S_OK
    );
    assert!(hooks.on_distribution_started.is_none());
}

#[test]
fn checked_scan_keeps_the_caps() {
    let location = "wsl:Ubuntu";
    let many = serde_json::json!({
        "clis": [],
        "mcp_servers": vec![serde_json::json!({"location": location}); 129],
        "agent_assets": [],
    });
    assert!(state::checked_scan(&serde_json::to_vec(&many).unwrap(), location).is_none());
    assert!(state::checked_scan(&vec![b' '; state::MAX_SCAN_BYTES + 1], location).is_none());
    assert!(state::checked_scan(b"{\"clis\":[]}", location).is_none());
    assert!(Path::new(MOUNT_POINT).is_absolute());
}
