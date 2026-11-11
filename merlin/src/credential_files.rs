//! Where the declared credential files (`credential_files` in the collection
//! manifest) live under each home, and which one a path is.
//!
//! The file monitor marks these places for opens and reports an open with the
//! credential's declared name. Nothing here opens or reads a credential file:
//! places are found with metadata calls only.

use std::path::{Path, PathBuf};

use crate::manifest::{CREDENTIAL_FILES, CredentialFile};

/// A place to mark for opens: a directory (opens of its files) or one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mark {
    Dir(PathBuf),
    File(PathBuf),
}

/// One declared credential in one home, with its directory resolved.
#[derive(Debug, Clone)]
pub struct Place {
    pub name: &'static str,
    /// The directory the credential sits in (canonical: what an open reports).
    dir: PathBuf,
    /// The file name, or the prefix of a directory row.
    file: &'static str,
    /// Whether `file` is a prefix.
    prefixed: bool,
    not_suffix: &'static str,
}

impl Place {
    /// Is `path` (as an open reports it) this credential?
    fn holds(&self, path: &Path) -> bool {
        let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str()))
        else {
            return false;
        };
        dir == self.dir
            && if self.prefixed {
                name.starts_with(self.file)
                    && (self.not_suffix.is_empty() || !name.ends_with(self.not_suffix))
            } else {
                name == self.file
            }
    }
}

/// The places of every declared credential under `homes`, and the marks
/// that cover them, deduplicated. A credential whose directory does not
/// exist is skipped. One directly in a home is marked as a file, and only
/// when it exists, so the home's other files raise no events; any other is
/// marked through its directory, which survives the file being replaced or
/// created later.
pub fn places(homes: &[PathBuf]) -> (Vec<Place>, Vec<Mark>) {
    places_for(CREDENTIAL_FILES, homes)
}

fn places_for(declared: &[CredentialFile], homes: &[PathBuf]) -> (Vec<Place>, Vec<Mark>) {
    let mut places = Vec::new();
    let mut marks = Vec::new();
    for home in homes {
        let Ok(home) = home.canonicalize() else {
            continue;
        };
        for c in declared {
            let full = home.join(c.path);
            let prefixed = !c.prefix.is_empty();
            let (dir, file) = if prefixed {
                (full, c.prefix)
            } else {
                let Some(file) = Path::new(c.path).file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                // file_name of a plain relative path is its last part, which
                // the manifest holds for 'static.
                let file = &c.path[c.path.len() - file.len()..];
                match full.parent() {
                    Some(parent) => (parent.to_path_buf(), file),
                    None => continue,
                }
            };
            // A linked directory would report another directory's files.
            let Ok(meta) = dir.symlink_metadata() else {
                continue;
            };
            if !meta.is_dir() {
                continue;
            }
            let mark = if dir == home {
                let path = dir.join(file);
                if !path.symlink_metadata().is_ok_and(|m| m.is_file()) {
                    continue;
                }
                Mark::File(path)
            } else {
                Mark::Dir(dir.clone())
            };
            if !marks.contains(&mark) {
                marks.push(mark);
            }
            places.push(Place {
                name: c.name,
                dir,
                file,
                prefixed,
                not_suffix: c.not_suffix,
            });
        }
    }
    (places, marks)
}

/// The declared name of the credential at `path`, if it is one.
pub fn name_for(places: &[Place], path: &str) -> Option<&'static str> {
    let path = Path::new(path);
    places.iter().find(|p| p.holds(path)).map(|p| p.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_home(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "merlin-cred-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.canonicalize().unwrap()
    }

    fn touch(home: &Path, relative: &str) -> String {
        let path = home.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"not read").unwrap();
        path.display().to_string()
    }

    #[test]
    fn every_declared_credential_is_named_by_its_path_and_a_near_miss_is_not() {
        let home = temp_home("all");
        for c in CREDENTIAL_FILES {
            let relative = if c.prefix.is_empty() {
                c.path.to_string()
            } else {
                format!("{}/{}example", c.path, c.prefix)
            };
            touch(&home, &relative);
        }
        let (places, marks) = places(std::slice::from_ref(&home));
        for c in CREDENTIAL_FILES {
            let relative = if c.prefix.is_empty() {
                c.path.to_string()
            } else {
                format!("{}/{}example", c.path, c.prefix)
            };
            let path = home.join(&relative).display().to_string();
            assert_eq!(name_for(&places, &path), Some(c.name), "{relative}");
            // The same name one directory deeper is not the credential.
            let deeper = home.join("other").join(&relative).display().to_string();
            assert_eq!(name_for(&places, &deeper), None, "{deeper}");
        }
        // A file directly in the home is marked itself, never the home.
        assert!(!marks.contains(&Mark::Dir(home.clone())));
        assert!(marks.contains(&Mark::File(home.join(".netrc"))));
        assert!(marks.contains(&Mark::Dir(home.join(".aws"))));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn an_ssh_public_key_and_other_ssh_files_are_not_credentials() {
        let home = temp_home("ssh");
        let key = touch(&home, ".ssh/id_ed25519");
        let public = touch(&home, ".ssh/id_ed25519.pub");
        let known = touch(&home, ".ssh/known_hosts");
        let (places, _) = places(std::slice::from_ref(&home));
        assert_eq!(name_for(&places, &key), Some("ssh_key"));
        assert_eq!(name_for(&places, &public), None);
        assert_eq!(name_for(&places, &known), None);
        // Other files in a credential's directory are not that credential.
        let config = touch(&home, ".aws/config");
        let (places, _) = places_for(CREDENTIAL_FILES, std::slice::from_ref(&home));
        assert_eq!(name_for(&places, &config), None);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_missing_directory_or_a_linked_one_is_not_watched() {
        let home = temp_home("missing");
        let elsewhere = temp_home("elsewhere");
        std::os::unix::fs::symlink(&elsewhere, home.join(".kube")).unwrap();
        let (places, marks) = places(std::slice::from_ref(&home));
        assert!(places.is_empty(), "{places:?}");
        assert!(marks.is_empty(), "{marks:?}");
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&elsewhere);
    }
}
