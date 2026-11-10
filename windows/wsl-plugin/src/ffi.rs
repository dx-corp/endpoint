//! The C ABI of Microsoft's WSL plugin API (`WslPluginApi.h`), limited to the
//! fields this plugin touches. Field order and widths match the header; every
//! callback uses the platform C calling convention, as the header declares.
//!
//! Older WSL builds pass shorter structs: `InitPid` exists from 2.0.5 and the
//! registration hooks from 2.1.2. Callers check `WSLVersion` before touching
//! either, so the plugin never reads or writes past what WSL allocated.

use std::ffi::{c_char, c_void};

pub type Hresult = i32;
pub type WslSessionId = u32;
pub type Socket = usize;
pub type Lpcwstr = *const u16;
pub type Lpcstr = *const c_char;

pub const S_OK: Hresult = 0;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    /// Lowercase registry form without braces, used as the state file name.
    pub fn file_stem(&self) -> String {
        let d = &self.data4;
        format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.data1, self.data2, self.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
        )
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WslVersion {
    pub major: u32,
    pub minor: u32,
    pub revision: u32,
}

impl WslVersion {
    pub fn at_least(&self, major: u32, minor: u32, revision: u32) -> bool {
        (self.major, self.minor, self.revision) >= (major, minor, revision)
    }
}

#[repr(C)]
pub struct WslVmCreationSettings {
    pub custom_configuration_flags: i32,
}

#[repr(C)]
pub struct WslSessionInformation {
    pub session_id: WslSessionId,
    pub user_token: *mut c_void,
    pub user_sid: *mut c_void,
}

#[repr(C)]
pub struct WslDistributionInformation {
    pub id: Guid,
    pub name: Lpcwstr,
    pub pid_namespace: u64,
    pub package_family_name: Lpcwstr,
    /// Introduced in 2.0.5.
    pub init_pid: u32,
}

#[repr(C)]
pub struct WslOfflineDistributionInformation {
    pub id: Guid,
    pub name: Lpcwstr,
    pub package_family_name: Lpcwstr,
}

pub type MountFolder = unsafe extern "C" fn(
    session: WslSessionId,
    windows_path: Lpcwstr,
    linux_path: Lpcwstr,
    read_only: i32,
    name: Lpcwstr,
) -> Hresult;
pub type ExecuteBinary = unsafe extern "C" fn(
    session: WslSessionId,
    path: Lpcstr,
    arguments: *const Lpcstr,
    socket: *mut Socket,
) -> Hresult;
pub type PluginError = unsafe extern "C" fn(message: Lpcwstr) -> Hresult;
/// A slot this plugin never calls; every C function pointer has one width.
pub type Unused = unsafe extern "C" fn();

pub type OnVmStarted = unsafe extern "C" fn(
    session: *const WslSessionInformation,
    settings: *const WslVmCreationSettings,
) -> Hresult;
pub type OnVmStopping = unsafe extern "C" fn(session: *const WslSessionInformation) -> Hresult;
pub type OnDistribution = unsafe extern "C" fn(
    session: *const WslSessionInformation,
    distribution: *const WslDistributionInformation,
) -> Hresult;
pub type OnOfflineDistribution = unsafe extern "C" fn(
    session: *const WslSessionInformation,
    distribution: *const WslOfflineDistributionInformation,
) -> Hresult;

/// `WSLPluginAPIV1`. Only the first four fields exist in every WSL build
/// that loads plugins; the rest are never read.
#[repr(C)]
pub struct WslPluginApiV1 {
    pub version: WslVersion,
    pub mount_folder: Option<MountFolder>,
    pub execute_binary: Option<ExecuteBinary>,
    pub plugin_error: Option<PluginError>,
}

/// `WSLPluginHooksV1`, through the 2.1.2 registration hooks. The plugin
/// writes no later slot.
#[repr(C)]
pub struct WslPluginHooksV1 {
    pub on_vm_started: Option<OnVmStarted>,
    pub on_vm_stopping: Option<OnVmStopping>,
    pub on_distribution_started: Option<OnDistribution>,
    pub on_distribution_stopping: Option<OnDistribution>,
    /// Introduced in 2.1.2.
    pub on_distribution_registered: Option<OnOfflineDistribution>,
    /// Introduced in 2.1.2.
    pub on_distribution_unregistered: Option<OnOfflineDistribution>,
}

/// Reads a NUL-terminated UTF-16 string WSL owns for the duration of a hook.
///
/// # Safety
/// `value` is null or points to a NUL-terminated UTF-16 string.
pub unsafe fn wide_to_string(value: Lpcwstr, max_units: usize) -> Option<String> {
    if value.is_null() {
        return None;
    }
    let mut units = Vec::new();
    for offset in 0..=max_units {
        // SAFETY: the caller promises a NUL-terminated string; the loop stops
        // at the terminator or one unit past the bound.
        let unit = unsafe { *value.add(offset) };
        if unit == 0 {
            return Some(String::from_utf16_lossy(&units));
        }
        units.push(unit);
    }
    None
}

pub fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    // Offsets on 64-bit Windows, from WslPluginApi.h.
    #[test]
    fn layouts_match_the_header() {
        assert_eq!(size_of::<Guid>(), 16);
        assert_eq!(offset_of!(WslDistributionInformation, name), 16);
        assert_eq!(offset_of!(WslDistributionInformation, pid_namespace), 24);
        assert_eq!(
            offset_of!(WslDistributionInformation, package_family_name),
            32
        );
        assert_eq!(offset_of!(WslDistributionInformation, init_pid), 40);
        assert_eq!(offset_of!(WslOfflineDistributionInformation, name), 16);
        assert_eq!(offset_of!(WslSessionInformation, user_token), 8);
        assert_eq!(offset_of!(WslPluginApiV1, mount_folder), 16);
        assert_eq!(offset_of!(WslPluginApiV1, execute_binary), 24);
        assert_eq!(offset_of!(WslPluginApiV1, plugin_error), 32);
        assert_eq!(offset_of!(WslPluginHooksV1, on_distribution_started), 16);
        assert_eq!(offset_of!(WslPluginHooksV1, on_distribution_registered), 32);
        assert_eq!(size_of::<WslPluginHooksV1>(), 48);
    }

    #[test]
    fn guid_file_stem_is_lowercase_registry_form() {
        let id = Guid {
            data1: 0x0123_ABCD,
            data2: 0x4567,
            data3: 0x89AB,
            data4: [0xCD, 0xEF, 0, 1, 2, 3, 4, 5],
        };
        assert_eq!(id.file_stem(), "0123abcd-4567-89ab-cdef-000102030405");
    }
}
