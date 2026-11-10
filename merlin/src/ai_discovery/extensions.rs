//! AI editor and browser extensions, named only when their id is declared in
//! `ai_extensions`. The directory names an editor or browser keeps extensions
//! under are matched against that list; any other extension is never named.

use crate::manifest::{AI_EXTENSIONS, AiExtension, ExtensionStore};

/// Browser profiles read per user data directory.
pub(crate) const MAX_BROWSER_PROFILES: usize = 16;

fn declared(store: ExtensionStore) -> impl Iterator<Item = &'static AiExtension> {
    AI_EXTENSIONS.iter().filter(move |e| e.store == store)
}

/// The declared extension an editor extension directory holds. VS Code and
/// its forks name it `<publisher>.<name>-<version>`, in lowercase.
pub(crate) fn editor_extension_id(directory: &str) -> Option<&'static str> {
    declared(ExtensionStore::VscodeMarketplace)
        .find(|e| {
            directory
                .get(..e.id.len())
                .is_some_and(|id| id.eq_ignore_ascii_case(e.id))
                && directory[e.id.len()..]
                    .strip_prefix('-')
                    .is_some_and(|version| version.starts_with(|c: char| c.is_ascii_digit()))
        })
        .map(|e| e.id)
}

/// The declared extension a Chromium profile's `Extensions/<id>` directory
/// is.
pub(crate) fn chromium_extension_id(directory: &str) -> Option<&'static str> {
    declared(ExtensionStore::ChromeWebStore)
        .find(|e| e.id == directory)
        .map(|e| e.id)
}

/// A Chromium profile directory: `Default` or `Profile <n>`.
pub(crate) fn chromium_profile(directory: &str) -> bool {
    directory == "Default"
        || directory
            .strip_prefix("Profile ")
            .is_some_and(|n| (1..=3).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_editor_extension_is_named_by_its_declared_id_and_no_other_is() {
        assert_eq!(
            editor_extension_id("anthropic.claude-code-2.0.31"),
            Some("Anthropic.claude-code")
        );
        assert_eq!(
            editor_extension_id("github.copilot-chat-0.32.4"),
            Some("GitHub.copilot-chat")
        );
        assert_eq!(
            editor_extension_id("github.copilot-1.388.0"),
            Some("GitHub.copilot")
        );
        // A longer id that starts with a declared one is not that extension.
        assert_eq!(editor_extension_id("github.copilot-labs-0.1.0"), None);
        assert_eq!(editor_extension_id("anthropic.claude-code"), None);
        assert_eq!(editor_extension_id("ms-python.python-2025.1.0"), None);
        assert_eq!(editor_extension_id(".obsolete"), None);
    }

    #[test]
    fn a_browser_extension_is_named_only_by_its_exact_declared_id() {
        assert_eq!(
            chromium_extension_id("fcoeoabgfenejglbffodgkkbkcdhcgfn"),
            Some("fcoeoabgfenejglbffodgkkbkcdhcgfn")
        );
        assert_eq!(
            chromium_extension_id("FCOEOABGFENEJGLBFFODGKKBKCDHCGFN"),
            None
        );
        assert_eq!(
            chromium_extension_id("aapocclcgogkmnckokdopfmhonfmgoek"),
            None
        );
        assert!(chromium_profile("Default") && chromium_profile("Profile 12"));
        for other in [
            "System Profile",
            "Guest Profile",
            "Profile ",
            "Profile 1234",
            "Crashpad",
        ] {
            assert!(!chromium_profile(other), "{other}");
        }
    }

    #[test]
    fn every_declared_id_is_found_where_its_store_keeps_it() {
        for e in AI_EXTENSIONS {
            let found = match e.store {
                ExtensionStore::VscodeMarketplace => {
                    editor_extension_id(&format!("{}-1.0.0", e.id.to_ascii_lowercase()))
                }
                ExtensionStore::ChromeWebStore => chromium_extension_id(e.id),
            };
            assert_eq!(found, Some(e.id));
        }
    }
}
