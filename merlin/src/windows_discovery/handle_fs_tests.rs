//! Ported from the Go collector's read_windows_test.go. These need a real
//! Windows file system; creating symlinks needs Developer Mode or elevation,
//! and the tests that need one skip (pass with a note) without it.

use super::*;
use std::fs;
use std::os::windows::fs::{symlink_dir, symlink_file};
use std::path::PathBuf;

fn tempdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("merlin-handle-fs-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_trailing_root_separator_is_accepted() {
    let root = tempdir("trailing");
    let path = root.join("config.json");
    fs::write(&path, "safe").unwrap();
    let spelled = PathBuf::from(format!("{}\\", root.display()));
    assert_eq!(
        HandleFs.read_within(&spelled, &path, 64 << 10).as_deref(),
        Some(&b"safe"[..])
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn linked_intermediate_directories_are_refused() {
    let root = tempdir("linked");
    let inside = root.join("config");
    fs::create_dir(&inside).unwrap();
    let file = inside.join("settings.json");
    fs::write(&file, "safe").unwrap();
    assert_eq!(
        HandleFs.read_within(&root, &file, 64 << 10).as_deref(),
        Some(&b"safe"[..])
    );
    assert_eq!(
        HandleFs.entries_within(&root, &inside, 256),
        vec!["settings.json".to_string()]
    );
    let outside = tempdir("linked-outside");
    fs::write(outside.join("secret.json"), "secret").unwrap();
    let link = root.join("linked");
    if symlink_dir(&outside, &link).is_err() {
        eprintln!("directory symlinks unavailable; skipping");
        return;
    }
    let internal = root.join("internal-link");
    if symlink_dir(&inside, &internal).is_ok() {
        assert!(
            HandleFs
                .read_within(&root, &internal.join("settings.json"), 64 << 10)
                .is_none()
        );
    }
    assert!(
        HandleFs
            .read_within(&root, &link.join("secret.json"), 64 << 10)
            .is_none()
    );
    assert!(!HandleFs.directory_within(&root, &link));
    assert!(HandleFs.entries_within(&root, &link, 256).is_empty());
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(outside).unwrap();
}

#[test]
fn verified_handles_survive_path_replacement() {
    let root = tempdir("replace");
    let outside = tempdir("replace-outside");
    let original = root.join("config.json");
    fs::write(&original, "approved").unwrap();
    let outside_file = outside.join("secret.json");
    fs::write(&outside_file, "outside").unwrap();
    let opened = open_within(&root, &original, false).unwrap();
    fs::rename(&original, root.join("config.moved")).unwrap();
    if symlink_file(&outside_file, &original).is_err() {
        eprintln!("file symlinks unavailable; skipping");
        return;
    }
    let mut body = String::new();
    (&opened.file).read_to_string(&mut body).unwrap();
    assert_eq!(body, "approved");

    let directory = root.join("agents");
    fs::create_dir(&directory).unwrap();
    fs::write(directory.join("safe.md"), "safe").unwrap();
    fs::write(outside.join("secret.md"), "outside").unwrap();
    let held = open_within(&root, &directory, true).unwrap();
    fs::rename(&directory, root.join("agents.moved")).unwrap();
    symlink_dir(&outside, &directory).unwrap();
    assert_eq!(list_directory(&held.file, 256), vec!["safe.md".to_string()]);
    drop(opened);
    drop(held);
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(outside).unwrap();
}
