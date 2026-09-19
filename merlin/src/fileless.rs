//! Fileless-execution detection: classify the /proc/<pid>/exe readlink of
//! an exec event. Pure functions; the /proc plumbing lives in telemetry.

use std::io;
use std::path::PathBuf;

#[derive(Debug, PartialEq, Eq)]
pub enum ExeClass {
    Normal(String),
    /// exe readlinks to "/memfd:<name> (deleted)" — the process executed
    /// from an anonymous in-memory file (memfd_create + fexecve).
    Fileless(String),
    /// readlink failed with ENOENT but the process is still alive: proc
    /// cannot resolve the exe at all, which a normal deleted binary does
    /// not cause (that still resolves with a " (deleted)" suffix).
    /// Suspicious.
    MissingAlive,
    /// Process already gone; the usual enrichment race, not signal.
    Missing,
}

/// "/memfd:<name> (deleted)" is the exact shape proc uses for an exe that
/// is an unnamed memfd.
pub fn is_memfd_path(s: &str) -> bool {
    s.starts_with("/memfd:") && s.ends_with(" (deleted)")
}

/// A normal executable can be unlinked after it is opened. It remains
/// executable, but the deleted suffix is useful lineage evidence and should
/// not be conflated with a memfd-backed image.
pub fn is_deleted_executable_path(s: &str) -> bool {
    s.ends_with(" (deleted)") && !is_memfd_path(s)
}

pub fn classify_exe(result: &io::Result<PathBuf>, process_alive: bool) -> ExeClass {
    match result {
        Ok(p) => {
            let s = p.display().to_string();
            if is_memfd_path(&s) {
                ExeClass::Fileless(s)
            } else {
                ExeClass::Normal(s)
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound && process_alive => ExeClass::MissingAlive,
        Err(_) => ExeClass::Missing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> io::Result<PathBuf> {
        Ok(PathBuf::from(s))
    }

    fn enoent() -> io::Result<PathBuf> {
        Err(io::Error::new(io::ErrorKind::NotFound, "no such file"))
    }

    #[test]
    fn memfd_path_is_fileless() {
        assert!(is_memfd_path("/memfd:payload (deleted)"));
        assert!(!is_memfd_path("/tmp/payload (deleted)"));
        assert!(!is_memfd_path("/memfd:still-open")); // no (deleted) suffix
        assert_eq!(
            classify_exe(&ok("/memfd:payload (deleted)"), true),
            ExeClass::Fileless("/memfd:payload (deleted)".into())
        );
    }

    #[test]
    fn normal_and_deleted_paths() {
        assert_eq!(
            classify_exe(&ok("/usr/bin/id"), true),
            ExeClass::Normal("/usr/bin/id".into())
        );
        assert!(is_deleted_executable_path("/tmp/id (deleted)"));
        assert!(!is_deleted_executable_path("/memfd:id (deleted)"));
        // A regular binary unlinked after exec still resolves; not fileless.
        assert_eq!(
            classify_exe(&ok("/tmp/id (deleted)"), true),
            ExeClass::Normal("/tmp/id (deleted)".into())
        );
    }

    #[test]
    fn enoent_alive_is_suspicious_gone_is_race() {
        assert_eq!(classify_exe(&enoent(), true), ExeClass::MissingAlive);
        assert_eq!(classify_exe(&enoent(), false), ExeClass::Missing);
        let eacces = Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"));
        assert_eq!(classify_exe(&eacces, true), ExeClass::Missing);
    }
}
