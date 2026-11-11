//! File integrity hashes of fixed system paths.

use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::{DeviceFIMEntry, bounded_read_path, hex_encode};

pub(super) fn fim_paths() -> Vec<String> {
    let configured = std::env::var("MERLIN_FIM_PATHS").unwrap_or_default();
    let values = if configured.trim().is_empty() {
        vec![
            "/etc/passwd".to_string(),
            "/etc/group".to_string(),
            "/etc/ssh/sshd_config".to_string(),
            "/etc/sudoers".to_string(),
        ]
    } else {
        configured
            .split(',')
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .take(256)
            .collect()
    };
    values
}

pub(super) fn collect_fim() -> Vec<DeviceFIMEntry> {
    fim_paths()
        .into_iter()
        .take(256)
        .map(|path| {
            let path_ref = Path::new(&path);
            let Ok(metadata) = fs::metadata(path_ref) else {
                return DeviceFIMEntry {
                    path,
                    sha256: String::new(),
                    size_bytes: 0,
                    mode: String::new(),
                    modified_unix: 0,
                    status: "missing".into(),
                };
            };
            let sha256 = bounded_read_path(path_ref, 2 << 20)
                .map(|body| hex_encode(&Sha256::digest(&body)))
                .unwrap_or_default();
            DeviceFIMEntry {
                path,
                sha256,
                size_bytes: metadata.len(),
                mode: format!("{:o}", metadata.mode() & 0o7777),
                modified_unix: metadata.mtime(),
                status: "present".into(),
            }
        })
        .collect()
}
