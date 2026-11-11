//! Declared AI editor and browser extensions in one home (see
//! `ai_discovery::extensions`), opened with no symlink anywhere below the
//! home like every other location.

use std::collections::BTreeSet;
use std::path::Path;

use super::agent_discovery::{
    agent_entry_type, open_agent_child_dir, open_agent_directory, read_agent_dir_entries,
};
use crate::ai_discovery::{
    DeviceAgentAsset, MAX_BROWSER_PROFILES, chromium_extension_id, chromium_profile,
    editor_extension_id,
};
use crate::manifest::{AiLocation, Format};

/// The declared extensions one editor-extensions or chromium-extensions
/// location holds, each an asset named by its id.
pub(super) fn collect_ai_extensions(
    home: &Path,
    location: &AiLocation,
    assets: &mut BTreeSet<DeviceAgentAsset>,
) {
    let Some(directory) = open_agent_directory(&home.join(location.path)) else {
        return;
    };
    let mut add = |id: &str| {
        assets.insert(DeviceAgentAsset {
            client: location.client.into(),
            kind: location.kind.into(),
            name: id.into(),
            source: location.label(),
            ..Default::default()
        });
    };
    let declared_directories = |directory: &std::fs::File, id: fn(&str) -> Option<&'static str>| {
        read_agent_dir_entries(directory)
            .unwrap_or_default()
            .into_iter()
            .filter(|entry| agent_entry_type(directory, entry) == Some(libc::S_IFDIR))
            .filter_map(|entry| entry.to_str().and_then(id))
            .collect::<Vec<_>>()
    };
    match location.format {
        Format::EditorExtensions => {
            declared_directories(&directory, editor_extension_id)
                .into_iter()
                .for_each(&mut add);
        }
        Format::ChromiumExtensions => {
            let profiles = read_agent_dir_entries(&directory)
                .unwrap_or_default()
                .into_iter()
                .filter(|entry| entry.to_str().is_some_and(chromium_profile))
                .take(MAX_BROWSER_PROFILES);
            for profile in profiles {
                let Some(extensions) = open_agent_child_dir(&directory, profile.as_encoded_bytes())
                    .and_then(|profile| open_agent_child_dir(&profile, b"Extensions"))
                else {
                    continue;
                };
                declared_directories(&extensions, chromium_extension_id)
                    .into_iter()
                    .for_each(&mut add);
            }
        }
        _ => {}
    }
}
