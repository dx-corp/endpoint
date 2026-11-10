//! Unsafe pickles in local model caches: the `model_files_unsafe_pickle`
//! posture check.
//!
//! The collector walks the `kind = "model"` rows of the collection
//! manifest's `ai_locations` under each home directory (Hugging Face's hub
//! cache, Ollama's and LM Studio's model directories), opening every
//! directory and file with no symlink anywhere below the home. The one link
//! it resolves is a Hugging Face snapshot entry of the form
//! `../../blobs/<hex>` (one more `../` per subdirectory), resolved lexically
//! to the repository's own `blobs` directory and opened there without
//! following anything. Each pickle (a raw pickle, or a PyTorch zip's stored
//! `data.pkl`) is walked opcode by opcode and never unpickled.
//!
//! Only the check id, a fixed reason and a hash of the per-file verdicts
//! leave the device: never paths, file names or contents. With no pickle
//! file in any cache, there is no check.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::manifest::{AiLocation, Format};
use crate::sync::{
    agent_entry_type, open_agent_child_dir, open_agent_directory, open_agent_file_at,
    read_agent_dir_entries, read_agent_link_at,
};

use super::{PostureCheck, evidence_check};

#[path = "linux_posture_pickle.rs"]
mod pickle;

use pickle::Verdict;

pub(super) const CHECK: &str = "model_files_unsafe_pickle";
const SOURCE: &str = "model_files";
/// At most this many pickle files are walked per collection.
const MAX_PICKLE_FILES: usize = 64;
/// At most this many directory entries are looked at per collection.
const MAX_ENTRIES: usize = 4096;
/// Directories deeper than this below a cache are not entered.
const MAX_DEPTH: usize = 6;
/// The whole collection stops after this long.
const BUDGET: Duration = Duration::from_secs(5);
/// Verdicts remembered across collections, keyed by file identity.
const MAX_REMEMBERED: usize = 4096;

/// File names that may hold a pickle: modelscan's pickle and PyTorch
/// extensions, and names with no extension (content-addressed blobs).
const PICKLE_EXTENSIONS: &[&str] = &[
    "pkl", "pickle", "joblib", "dill", "dat", "data", "bin", "pt", "pth", "ckpt",
];

const UNSAFE: &str = "A model file in a local model cache imports a function that can run code when the file is loaded";
const NOT_CHECKED: &str =
    "Not checked: a model file could not be parsed, was not opened, or the scan ran out of time";
const CLEAN: &str =
    "No pickle model file in a local model cache imports a function that can run code";

pub(super) struct ModelPaths {
    /// Home directories whose model caches are read.
    pub homes: Vec<PathBuf>,
    pub budget: Duration,
}

impl ModelPaths {
    pub fn new(homes: Vec<PathBuf>) -> Self {
        Self {
            homes,
            budget: BUDGET,
        }
    }
}

/// A regular file's identity: device, inode, size, modification and change
/// times. A file whose identity is unchanged is not read again.
type FileKey = (u64, u64, u64, i64, i64, i64, i64);

/// Verdicts by file identity; `None` is "not a pickle".
#[derive(Default)]
pub(super) struct Remembered(HashMap<FileKey, Option<Verdict>>);

#[derive(Default)]
struct Tally {
    unsafe_files: usize,
    unparsed_files: usize,
    clean_files: usize,
    pickle_files: usize,
    exhausted: bool,
    receipt: String,
}

struct Walk<'a> {
    deadline: Instant,
    entries: usize,
    remembered: &'a mut Remembered,
    tally: Tally,
}

impl Walk<'_> {
    /// Counts one directory entry against the caps; false once they are hit.
    fn spend(&mut self) -> bool {
        self.entries += 1;
        if self.entries > MAX_ENTRIES || Instant::now() >= self.deadline {
            self.tally.exhausted = true;
        }
        !self.tally.exhausted
    }

    fn entries(&mut self, directory: &File) -> Vec<OsString> {
        let entries = read_agent_dir_entries(directory).unwrap_or_default();
        if entries.len() >= 256 {
            // The listing is capped; what lies past it was not looked at.
            self.tally.exhausted = true;
        }
        entries
    }

    /// A pickle-named entry that exists but was not opened (a symlink, a
    /// file that could not be opened).
    fn unopened(&mut self) {
        self.tally.unparsed_files += 1;
        self.tally.receipt.push_str("unopened\n");
    }

    fn file(&mut self, file: File) {
        let Ok(meta) = file.metadata() else {
            return self.unopened();
        };
        let key = (
            meta.dev(),
            meta.ino(),
            meta.size(),
            meta.mtime(),
            meta.mtime_nsec(),
            meta.ctime(),
            meta.ctime_nsec(),
        );
        let verdict = match self.remembered.0.get(&key) {
            Some(verdict) => *verdict,
            None => {
                if self.tally.pickle_files >= MAX_PICKLE_FILES || Instant::now() >= self.deadline {
                    self.tally.exhausted = true;
                    return;
                }
                let verdict = pickle::scan_file(&file, meta.size());
                if self.remembered.0.len() >= MAX_REMEMBERED {
                    self.remembered.0.clear();
                }
                self.remembered.0.insert(key, verdict);
                verdict
            }
        };
        let Some(verdict) = verdict else {
            return;
        };
        self.tally.pickle_files += 1;
        if self.tally.pickle_files > MAX_PICKLE_FILES {
            self.tally.exhausted = true;
            return;
        }
        let (count, word) = match verdict {
            Verdict::Unsafe => (&mut self.tally.unsafe_files, "unsafe\n"),
            Verdict::Unparsed => (&mut self.tally.unparsed_files, "unparsed\n"),
            Verdict::Clean => (&mut self.tally.clean_files, "clean\n"),
        };
        *count += 1;
        self.tally.receipt.push_str(word);
    }

    /// Ollama and LM Studio: every pickle-named regular file below the
    /// directory. A symlink is never followed.
    fn model_dir(&mut self, directory: &File, depth: usize) {
        for name in self.entries(directory) {
            if !self.spend() {
                return;
            }
            match agent_entry_type(directory, &name) {
                Some(libc::S_IFDIR) if depth < MAX_DEPTH => {
                    if let Some(child) = open_agent_child_dir(directory, name.as_bytes()) {
                        self.model_dir(&child, depth + 1);
                    }
                }
                Some(libc::S_IFREG) if may_be_pickle(&name) => {
                    match open_agent_file_at(directory, &name) {
                        Some(file) => self.file(file),
                        None => self.unopened(),
                    }
                }
                Some(libc::S_IFLNK) if may_be_pickle(&name) => self.unopened(),
                _ => {}
            }
        }
    }

    /// Hugging Face's hub cache: `<repo>/snapshots/<revision>/...`, each
    /// entry a link to `<repo>/blobs/<hex>` (or, with symlinks off, the
    /// file itself).
    fn hf_hub(&mut self, hub: &File) {
        for repo_name in self.entries(hub) {
            if !self.spend() {
                return;
            }
            let Some(repo) = open_agent_child_dir(hub, repo_name.as_bytes()) else {
                continue;
            };
            let Some(snapshots) = open_agent_child_dir(&repo, b"snapshots") else {
                continue;
            };
            let mut seen = HashSet::new();
            for revision in self.entries(&snapshots) {
                if !self.spend() {
                    return;
                }
                if let Some(revision) = open_agent_child_dir(&snapshots, revision.as_bytes()) {
                    self.snapshot(&repo, &revision, 0, &mut seen);
                }
            }
        }
    }

    fn snapshot(
        &mut self,
        repo: &File,
        directory: &File,
        depth: usize,
        seen: &mut HashSet<OsString>,
    ) {
        for name in self.entries(directory) {
            if !self.spend() {
                return;
            }
            match agent_entry_type(directory, &name) {
                Some(libc::S_IFDIR) if depth < MAX_DEPTH => {
                    if let Some(child) = open_agent_child_dir(directory, name.as_bytes()) {
                        self.snapshot(repo, &child, depth + 1, seen);
                    }
                }
                Some(libc::S_IFREG) if may_be_pickle(&name) => {
                    match open_agent_file_at(directory, &name) {
                        Some(file) => self.file(file),
                        None => self.unopened(),
                    }
                }
                Some(libc::S_IFLNK) if may_be_pickle(&name) => {
                    let blob = read_agent_link_at(directory, &name)
                        .and_then(|target| hf_blob_name(&target, depth));
                    let Some(blob) = blob else {
                        self.unopened();
                        continue;
                    };
                    if !seen.insert(blob.clone()) {
                        continue;
                    }
                    let file = open_agent_child_dir(repo, b"blobs")
                        .and_then(|blobs| open_agent_file_at(&blobs, &blob));
                    match file {
                        Some(file) => self.file(file),
                        None => self.unopened(),
                    }
                }
                _ => {}
            }
        }
    }
}

/// Whether a file name may hold a pickle (see `PICKLE_EXTENSIONS`).
fn may_be_pickle(name: &OsStr) -> bool {
    let name = name.as_bytes();
    match name.iter().rposition(|byte| *byte == b'.') {
        None => true,
        Some(dot) => {
            let extension = &name[dot + 1..];
            PICKLE_EXTENSIONS
                .iter()
                .any(|known| extension.eq_ignore_ascii_case(known.as_bytes()))
        }
    }
}

/// The blob a Hugging Face snapshot link names, when the link is exactly
/// `../` repeated `depth + 2` times, then `blobs/<hex>`: a path that stays
/// in the repository and is resolved here, lexically, never by following it.
fn hf_blob_name(target: &OsStr, depth: usize) -> Option<OsString> {
    let mut rest = target.as_bytes();
    for _ in 0..depth + 2 {
        rest = rest.strip_prefix(b"../")?;
    }
    let hex = rest.strip_prefix(b"blobs/")?;
    let valid = (8..=128).contains(&hex.len()) && hex.iter().all(u8::is_ascii_hexdigit);
    valid.then(|| OsStr::from_bytes(hex).to_os_string())
}

/// The model cache rows this collector reads on Linux, in declared order.
fn locations() -> impl Iterator<Item = &'static AiLocation> {
    AiLocation::models("linux")
}

pub(super) fn collect(
    paths: &ModelPaths,
    observed_at: &str,
    privilege: &'static str,
    checks: &mut BTreeMap<&'static str, PostureCheck>,
) {
    static REMEMBERED: OnceLock<Mutex<Remembered>> = OnceLock::new();
    let mut remembered = REMEMBERED
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(check) = evaluate(paths, &mut remembered, observed_at, privilege) {
        checks.insert(CHECK, check);
    }
}

fn evaluate(
    paths: &ModelPaths,
    remembered: &mut Remembered,
    observed_at: &str,
    privilege: &'static str,
) -> Option<PostureCheck> {
    let mut walk = Walk {
        deadline: Instant::now() + paths.budget,
        entries: 0,
        remembered,
        tally: Tally::default(),
    };
    'homes: for home in &paths.homes {
        for location in locations() {
            if walk.tally.exhausted {
                break 'homes;
            }
            let Some(root) = open_agent_directory(&home.join(location.path)) else {
                continue;
            };
            match location.format {
                Format::HfHub => walk.hf_hub(&root),
                _ => walk.model_dir(&root, 0),
            }
        }
    }
    let tally = walk.tally;
    let (status, value, severity, detail) = if tally.unsafe_files > 0 {
        ("finding", "unsafe_import", Some("high"), UNSAFE)
    } else if tally.unparsed_files > 0 || tally.exhausted {
        ("unknown", "not_checked", None, NOT_CHECKED)
    } else if tally.clean_files > 0 {
        ("pass", "clean", None, CLEAN)
    } else {
        return None;
    };
    let mut receipt = tally.receipt;
    if tally.exhausted {
        receipt.push_str("exhausted\n");
    }
    Some(evidence_check(
        status,
        value,
        severity,
        detail,
        SOURCE,
        privilege,
        observed_at,
        receipt.as_bytes(),
    ))
}

/// Whether `path` is one of the model caches below `home`, for tests.
#[cfg(test)]
fn declared(relative: &str) -> bool {
    locations().any(|location| location.path == relative)
}

#[cfg(test)]
mod tests {
    use super::pickle::fixtures::*;
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NONCE: AtomicU64 = AtomicU64::new(0);

    const HUB: &str = ".cache/huggingface/hub";
    const OLLAMA: &str = ".ollama/models";
    const LMSTUDIO: &str = ".lmstudio/models";
    /// A blob name shaped like huggingface_hub's (a 64-digit hex hash).
    fn blob() -> String {
        "0123456789abcdef".repeat(4)
    }

    struct Fixture {
        root: PathBuf,
        paths: ModelPaths,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "merlin-model-posture-{name}-{}-{}",
                std::process::id(),
                NONCE.fetch_add(1, Ordering::Relaxed)
            ));
            let homes = vec![root.join("home/alice"), root.join("home/bob")];
            for home in &homes {
                fs::create_dir_all(home).unwrap();
            }
            Self {
                paths: ModelPaths::new(homes),
                root,
            }
        }

        fn home(&self, index: usize) -> &Path {
            &self.paths.homes[index]
        }

        fn write(&self, home: usize, relative: &str, body: &[u8]) -> PathBuf {
            let path = self.home(home).join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, body).unwrap();
            path
        }

        /// A Hugging Face repository with `file` in one snapshot, linked to
        /// its blob the way huggingface_hub writes it.
        fn hf_file(&self, home: usize, repo: &str, file: &str, body: &[u8]) {
            let repo = format!("{HUB}/{repo}");
            self.write(home, &format!("{repo}/blobs/{}", blob()), body);
            let snapshot = self
                .home(home)
                .join(format!("{repo}/snapshots/2439f60ef33a"));
            let link = snapshot.join(file);
            fs::create_dir_all(link.parent().unwrap()).unwrap();
            let depth = file.matches('/').count();
            symlink(format!("{}blobs/{}", "../".repeat(depth + 2), blob()), link).unwrap();
        }

        fn check(&self) -> Option<PostureCheck> {
            evaluate(
                &self.paths,
                &mut Remembered::default(),
                "1700000000.000",
                "root",
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn the_three_model_caches_are_declared_for_linux() {
        for relative in [HUB, OLLAMA, LMSTUDIO] {
            assert!(declared(relative), "{relative} is a model row");
        }
        assert!(locations().all(|location| location.kind == "model"));
    }

    #[test]
    fn no_cache_or_no_pickle_means_no_check() {
        let fixture = Fixture::new("empty");
        assert!(fixture.check().is_none());
        fixture.write(0, &format!("{OLLAMA}/blobs/sha256-0011"), b"GGUF\x03\0\0\0");
        fixture.write(
            1,
            &format!("{LMSTUDIO}/pub/model/model.gguf"),
            b"\x80\x02N.",
        );
        fixture.hf_file(0, "models--x--y", "model.safetensors", b"\x80\x02N.");
        assert!(
            fixture.check().is_none(),
            "no pickle-named file holds a pickle"
        );
    }

    #[test]
    fn a_malicious_hugging_face_checkpoint_is_a_finding_that_names_nothing() {
        let fixture = Fixture::new("hf-unsafe");
        fixture.hf_file(
            0,
            "models--alice--private-model",
            "pytorch_model.bin",
            &zip(&[("archive/data.pkl", &stack_global_call(4, "os", "system"))]),
        );
        let check = fixture.check().expect("a pickle was read");
        assert_eq!(check.status, "finding");
        assert_eq!(check.severity, Some("high"));
        assert_eq!(check.value.as_deref(), Some("unsafe_import"));
        let wire = serde_json::to_string(&check).unwrap();
        for leaked in [
            "alice",
            "private-model",
            "pytorch_model",
            "/home",
            blob().as_str(),
            "os.system",
            "huggingface",
        ] {
            assert!(!wire.contains(leaked), "{leaked} must not leave the device");
        }
    }

    #[test]
    fn nested_snapshot_files_resolve_to_their_blob() {
        let fixture = Fixture::new("hf-nested");
        fixture.hf_file(
            0,
            "models--x--diffusion",
            "text_encoder/pytorch_model.bin",
            &global_call(2, "subprocess", "Popen"),
        );
        assert_eq!(fixture.check().unwrap().status, "finding");
    }

    #[test]
    fn clean_pickles_in_every_cache_pass() {
        let fixture = Fixture::new("clean");
        fixture.hf_file(
            0,
            "models--x--y",
            "pytorch_model.bin",
            &zip(&[("archive/data.pkl", &torch_state_dict())]),
        );
        fixture.write(1, &format!("{OLLAMA}/blobs/sha256-aa"), &plain_dict(4));
        fixture.write(1, &format!("{LMSTUDIO}/pub/model/model.pt"), &plain_dict(2));
        let check = fixture.check().unwrap();
        assert_eq!(check.status, "pass");
        assert_eq!(check.value.as_deref(), Some("clean"));
    }

    #[test]
    fn an_unparseable_pickle_is_not_checked_and_a_finding_still_wins() {
        let fixture = Fixture::new("unparsed");
        let whole = plain_dict(2);
        fixture.write(
            0,
            &format!("{LMSTUDIO}/pub/model/model.pkl"),
            &whole[..whole.len() - 2],
        );
        let check = fixture.check().unwrap();
        assert_eq!(check.status, "unknown");
        assert_eq!(check.value.as_deref(), Some("not_checked"));
        fixture.write(
            1,
            &format!("{OLLAMA}/evil.pkl"),
            &global_call(2, "os", "system"),
        );
        assert_eq!(fixture.check().unwrap().status, "finding");
    }

    #[test]
    fn links_other_than_a_snapshot_blob_are_never_followed() {
        let fixture = Fixture::new("links");
        let outside = fixture.write(0, "outside/evil.pkl", &global_call(2, "os", "system"));
        // A link to a pickle elsewhere, in a model directory and in a snapshot.
        let lmstudio = fixture.home(0).join(format!("{LMSTUDIO}/pub/model"));
        fs::create_dir_all(&lmstudio).unwrap();
        symlink(&outside, lmstudio.join("model.pkl")).unwrap();
        let snapshot = fixture
            .home(1)
            .join(format!("{HUB}/models--x--y/snapshots/abc"));
        fs::create_dir_all(&snapshot).unwrap();
        symlink(
            "../../../../../../outside/evil.pkl",
            snapshot.join("pytorch_model.bin"),
        )
        .unwrap();
        let check = fixture.check().unwrap();
        assert_eq!(
            check.status, "unknown",
            "an unopened pickle name is not checked, never read"
        );
        // A symlinked cache directory is not entered at all.
        let fixture = Fixture::new("linked-cache");
        let real = fixture.root.join("real-models");
        fs::create_dir_all(&real).unwrap();
        fs::write(real.join("evil.pkl"), global_call(2, "os", "system")).unwrap();
        fs::create_dir_all(fixture.home(0).join(".ollama")).unwrap();
        symlink(&real, fixture.home(0).join(OLLAMA)).unwrap();
        assert!(fixture.check().is_none());
    }

    #[test]
    fn hf_blob_links_resolve_only_in_the_documented_form() {
        let name = "0123456789abcdef".repeat(2) + "01234567";
        let link = format!("../../blobs/{name}");
        let hex = OsStr::new(&link);
        assert_eq!(hf_blob_name(hex, 0).as_deref(), Some(OsStr::new(&name)));
        assert!(hf_blob_name(hex, 1).is_none());
        assert!(hf_blob_name(OsStr::new("../../../blobs/abcdef0123"), 1).is_some());
        for bad in [
            "../../blobs/../../etc/passwd",
            "../../blobs/abc/def0123456",
            "/home/alice/.cache/huggingface/hub/models--x/blobs/abcdef0123",
            "../blobs/abcdef0123",
            "../../blobs/xyz",
        ] {
            assert!(hf_blob_name(OsStr::new(bad), 0).is_none(), "{bad}");
        }
    }

    #[test]
    fn the_file_cap_and_the_time_budget_make_the_check_not_checked() {
        let fixture = Fixture::new("caps");
        for index in 0..=MAX_PICKLE_FILES {
            fixture.write(0, &format!("{OLLAMA}/m{index}.pkl"), &plain_dict(2));
        }
        assert_eq!(
            fixture.check().unwrap().value.as_deref(),
            Some("not_checked")
        );

        let mut fixture = Fixture::new("budget");
        fixture.write(0, &format!("{OLLAMA}/m.pkl"), &plain_dict(2));
        assert_eq!(fixture.check().unwrap().value.as_deref(), Some("clean"));
        fixture.paths.budget = Duration::ZERO;
        assert_eq!(
            fixture.check().unwrap().value.as_deref(),
            Some("not_checked")
        );
    }

    #[test]
    fn an_unchanged_file_is_not_read_again() {
        let fixture = Fixture::new("remembered");
        let path = fixture.write(0, &format!("{OLLAMA}/m.pkl"), &plain_dict(2));
        let mut remembered = Remembered::default();
        let first = evaluate(&fixture.paths, &mut remembered, "1", "root").unwrap();
        assert_eq!(first.status, "pass");
        assert_eq!(remembered.0.len(), 1);
        // Same identity: the remembered verdict is reused.
        let again = evaluate(&fixture.paths, &mut remembered, "2", "root").unwrap();
        assert_eq!(again.status, "pass");
        // A rewrite changes the identity and is read.
        fs::write(&path, global_call(2, "os", "system")).unwrap();
        let changed = evaluate(&fixture.paths, &mut remembered, "3", "root").unwrap();
        assert_eq!(changed.status, "finding");
    }
}
