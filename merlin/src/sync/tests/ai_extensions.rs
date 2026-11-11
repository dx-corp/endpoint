use super::*;

#[test]
fn only_declared_ai_extensions_are_named_and_a_linked_profile_is_not_followed() {
    let root = tmpdir("ai-extensions");
    let home = root.join("home");
    let editor = home.join(".vscode/extensions");
    for installed in [
        "anthropic.claude-code-2.0.0",
        "ms-python.python-2025.1.0",
        "github.copilot-labs-0.1.0",
    ] {
        fs::create_dir_all(editor.join(installed)).unwrap();
    }
    // A file is not an installed extension.
    fs::write(editor.join("github.copilot-chat-0.1.0"), "").unwrap();
    let chrome = home.join(".config/google-chrome");
    for id in [
        "Default/Extensions/fcoeoabgfenejglbffodgkkbkcdhcgfn/1.0_0",
        "Default/Extensions/aapocclcgogkmnckokdopfmhonfmgoek/1.0_0",
        "Guest Profile/Extensions/ejcfepkfckglbgocfkanmcdngdijcgld/1.0_0",
    ] {
        fs::create_dir_all(chrome.join(id)).unwrap();
    }
    let elsewhere = root.join("elsewhere");
    fs::create_dir_all(elsewhere.join("Extensions/ejcfepkfckglbgocfkanmcdngdijcgld/1.0_0"))
        .unwrap();
    std::os::unix::fs::symlink(&elsewhere, chrome.join("Profile 2")).unwrap();

    let RootScan {
        agent_assets: assets,
        ..
    } = collect_agent_discovery_from(std::slice::from_ref(&home), &[]);
    let extensions: Vec<_> = assets
        .iter()
        .filter(|asset| asset.kind == "extension")
        .map(|asset| {
            (
                asset.client.as_str(),
                asset.name.as_str(),
                asset.source.as_str(),
            )
        })
        .collect();
    assert_eq!(
        extensions,
        vec![
            (
                "chrome",
                "fcoeoabgfenejglbffodgkkbkcdhcgfn",
                ".config/google-chrome"
            ),
            ("vscode", "Anthropic.claude-code", ".vscode/extensions"),
        ]
    );
}
