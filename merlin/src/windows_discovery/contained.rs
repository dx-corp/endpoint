//! Reads confined to an approved directory. Windows discovery runs as SYSTEM
//! over directories users control, so every read names the directory it must
//! stay inside (`root`) and fails closed: a reparse point (symlink or
//! junction) anywhere between `root` and the target, a path that leaves
//! `root`, an oversized file or anything that is not a plain file or
//! directory is skipped. Inventory may omit an asset; it must never read
//! outside the approved directory.
//!
//! The deployed reader is `handle_fs::HandleFs`, which checks the handle it
//! opened. `PortableFs` keeps the same fail-closed shape with `lstat` so the
//! discovery rules are tested on Linux.

use std::path::Path;

/// Reads beneath an approved root. Every method refuses a `path` outside
/// `root` or reached through a link.
pub(crate) trait ContainedFs {
    /// The bytes of the regular file `path`, when it is at most `limit` bytes.
    fn read_within(&self, root: &Path, path: &Path, limit: u64) -> Option<Vec<u8>>;
    /// Whether `path` is a regular file of at most `limit` bytes.
    fn regular_file_within(&self, root: &Path, path: &Path, limit: u64) -> bool;
    /// Whether `path` is a directory (`root` itself counts).
    fn directory_within(&self, root: &Path, path: &Path) -> bool;
    /// The names of the first `limit` (at most 256) entries of the directory
    /// `path`, sorted. Names that are not valid Unicode are left out.
    fn entries_within(&self, root: &Path, path: &Path, limit: usize) -> Vec<String>;
}

/// The canonical spelling of a local absolute DOS path: `/` becomes `\`, a
/// `\\?\` prefix and one trailing separator are dropped and the drive letter
/// is lower-cased. UNC and device paths, `.`/`..` components, empty
/// components and alternate data streams (`:` in a component) are refused.
/// Path components keep their case: Windows can enable case-sensitive
/// directories, and folding could conflate two of them.
pub(crate) fn canonical_windows_path(value: &str) -> Option<String> {
    let mut value = value.replace('/', "\\");
    if let Some(rest) = value.strip_prefix(r"\\?\") {
        value = rest.to_string();
    }
    // Admin-configured roots commonly end with one separator.
    if value.len() > 3 && value.ends_with('\\') {
        value.pop();
    }
    let bytes = value.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return None;
    }
    if value.len() > 3 {
        for component in value[3..].split('\\') {
            if component.is_empty()
                || component == "."
                || component == ".."
                || component.contains([':', '\0'])
            {
                return None;
            }
        }
    }
    let drive = bytes[0].to_ascii_lowercase() as char;
    Some(format!("{drive}{}", &value[1..]))
}

/// Whether canonical `target` is `root` or beneath it, comparing whole
/// components with exact case.
pub(crate) fn windows_path_within(root: &str, target: &str) -> bool {
    if root == target {
        return true;
    }
    if root.ends_with('\\') {
        return target.starts_with(root);
    }
    target
        .strip_prefix(root)
        .is_some_and(|rest| rest.starts_with('\\'))
}

/// A workspace root an admin may configure: a local absolute path of at most
/// 512 bytes, not UNC, with no `.` or `..` component.
pub(crate) fn valid_workspace_root(root: &str) -> bool {
    !root.is_empty()
        && root.len() <= 512
        && Path::new(root).is_absolute()
        && !root.starts_with(r"\\")
        && !root.starts_with("//")
        && root
            .split(['/', '\\'])
            .all(|component| component != "." && component != "..")
}

/// `relative` (a manifest path, `/`-separated) joined onto `base` one
/// component at a time, so the result uses the platform separator.
pub(crate) fn join_relative(base: &Path, relative: &str) -> std::path::PathBuf {
    relative
        .split('/')
        .filter(|segment| !segment.is_empty())
        .fold(base.to_path_buf(), |path, segment| path.join(segment))
}

/// `lstat`-based containment for tests on Linux. It checks each component
/// below `root` by name, which a racing writer could defeat; the deployed
/// Windows reader binds every check to the opened handle instead.
#[cfg(not(windows))]
pub(crate) struct PortableFs;

#[cfg(not(windows))]
impl PortableFs {
    fn within(root: &Path, path: &Path) -> bool {
        path.strip_prefix(root).is_ok_and(|relative| {
            relative
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_)))
        })
    }

    fn plain_directory(path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir())
    }

    /// `root` and every directory from it down to `directory` are plain
    /// directories, not links.
    fn directories_within(root: &Path, directory: &Path) -> bool {
        if !Self::within(root, directory) || !Self::plain_directory(root) {
            return false;
        }
        let Ok(relative) = directory.strip_prefix(root) else {
            return false;
        };
        let mut current = root.to_path_buf();
        relative.components().all(|component| {
            current.push(component);
            Self::plain_directory(&current)
        })
    }

    fn regular_file(root: &Path, path: &Path, limit: u64) -> Option<std::fs::Metadata> {
        let parent = path.parent()?;
        if path == root || !Self::directories_within(root, parent) {
            return None;
        }
        std::fs::symlink_metadata(path)
            .ok()
            .filter(|meta| meta.is_file() && meta.len() <= limit)
    }
}

#[cfg(not(windows))]
impl ContainedFs for PortableFs {
    fn read_within(&self, root: &Path, path: &Path, limit: u64) -> Option<Vec<u8>> {
        use std::io::Read;
        Self::regular_file(root, path, limit)?;
        let file = std::fs::File::open(path).ok()?;
        let mut body = Vec::new();
        file.take(limit + 1).read_to_end(&mut body).ok()?;
        (body.len() as u64 <= limit).then_some(body)
    }

    fn regular_file_within(&self, root: &Path, path: &Path, limit: u64) -> bool {
        Self::regular_file(root, path, limit).is_some()
    }

    fn directory_within(&self, root: &Path, path: &Path) -> bool {
        Self::directories_within(root, path)
    }

    fn entries_within(&self, root: &Path, path: &Path, limit: usize) -> Vec<String> {
        if limit == 0 || limit > 256 || !Self::directories_within(root, path) {
            return Vec::new();
        }
        let Ok(entries) = std::fs::read_dir(path) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .take(limit)
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect();
        names.sort();
        names
    }
}
