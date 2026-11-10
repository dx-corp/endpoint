//! Compiles the collection manifest (`../collection-manifest.toml`, its one
//! declaration) into the constants `src/manifest.rs` serves, so the agent
//! keeps `&'static` manifest data and every reader of it stays unchanged.

use std::fmt::Write as _;
use std::path::Path;

const SOURCE: &str = "../collection-manifest.toml";

fn main() {
    println!("cargo:rerun-if-changed={SOURCE}");
    let text = std::fs::read_to_string(SOURCE).expect("read collection-manifest.toml");
    let manifest: toml::Table = text.parse().expect("parse collection-manifest.toml");
    let out = Path::new(&std::env::var("OUT_DIR").unwrap()).join("manifest_data.rs");
    std::fs::write(out, generate(&manifest)).expect("write manifest_data.rs");
}

/// The table's keys must be exactly `keys`: a typo fails the build.
fn exact<'a>(table: &'a toml::Table, keys: &[&str], what: &str) -> &'a toml::Table {
    let mut found: Vec<&str> = table.keys().map(String::as_str).collect();
    let mut wanted = keys.to_vec();
    found.sort_unstable();
    wanted.sort_unstable();
    assert_eq!(found, wanted, "{what} must have exactly these keys");
    table
}

fn string(table: &toml::Table, key: &str) -> String {
    let value = table[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} must be a string"));
    format!("{value:?}")
}

fn strings(table: &toml::Table, key: &str) -> String {
    let items = table[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} must be an array"));
    let quoted: Vec<String> = items
        .iter()
        .map(|item| {
            format!(
                "{:?}",
                item.as_str()
                    .unwrap_or_else(|| panic!("{key} holds strings"))
            )
        })
        .collect();
    format!("&[{}]", quoted.join(", "))
}

fn tables<'a>(table: &'a toml::Table, key: &'a str) -> impl Iterator<Item = &'a toml::Table> {
    table[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} must be an array of tables"))
        .iter()
        .map(move |item| {
            item.as_table()
                .unwrap_or_else(|| panic!("{key} holds tables"))
        })
}

/// `while_enrolled` -> `WhileEnrolled`, for the enum variants.
fn variant(table: &toml::Table, key: &str, allowed: &[&str]) -> String {
    let value = table[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(
        allowed.contains(&value),
        "{key} {value:?} is not one of {allowed:?}"
    );
    value
        .split('_')
        .map(|word| word[..1].to_uppercase() + &word[1..])
        .collect()
}

fn generate(m: &toml::Table) -> String {
    let m = exact(
        m,
        &[
            "manifest_version",
            "journal",
            "inventory_fields",
            "event_kinds",
            "ai_locations",
            "collectors",
            "never_collected",
            "local",
        ],
        "the manifest",
    );
    let version = m["manifest_version"]
        .as_integer()
        .expect("manifest_version must be an integer");
    let mut out = String::new();
    writeln!(out, "pub const MANIFEST_VERSION: u32 = {version};").unwrap();
    writeln!(out, "pub const JOURNAL: &str = {};", string(m, "journal")).unwrap();
    writeln!(
        out,
        "pub const INVENTORY_FIELDS: &[&str] = {};",
        strings(m, "inventory_fields")
    )
    .unwrap();
    writeln!(
        out,
        "pub const EVENT_KINDS: &[&str] = {};",
        strings(m, "event_kinds")
    )
    .unwrap();
    out.push_str("pub const COLLECTORS: &[Collector] = &[\n");
    for c in tables(m, "collectors") {
        let c = exact(
            c,
            &[
                "id",
                "group",
                "title",
                "what",
                "why",
                "records",
                "capabilities",
                "retention",
            ],
            "a collector",
        );
        writeln!(
            out,
            "    Collector {{ id: {}, group: Group::{}, title: {}, what: {}, why: {}, records: {}, capabilities: {}, retention: Retention::{} }},",
            string(c, "id"),
            variant(c, "group", &["checks", "inventory", "ai_tools", "security_events", "agent"]),
            string(c, "title"),
            string(c, "what"),
            string(c, "why"),
            strings(c, "records"),
            strings(c, "capabilities"),
            variant(c, "retention", &["while_enrolled", "telemetry_window"]),
        )
        .unwrap();
    }
    out.push_str("];\npub const NEVER_COLLECTED: &[Never] = &[\n");
    for n in tables(m, "never_collected") {
        let n = exact(n, &["claim", "proof"], "a never-claim");
        writeln!(
            out,
            "    Never {{ claim: {}, proof: {} }},",
            string(n, "claim"),
            string(n, "proof")
        )
        .unwrap();
    }
    out.push_str("];\npub const LOCAL: &[LocalStore] = &[\n");
    for l in tables(m, "local") {
        let l = exact(l, &["path", "holds"], "a local store");
        writeln!(
            out,
            "    LocalStore {{ path: {}, holds: {} }},",
            string(l, "path"),
            string(l, "holds")
        )
        .unwrap();
    }
    out.push_str("];\npub const AI_LOCATIONS: &[AiLocation] = &[\n");
    for l in tables(m, "ai_locations") {
        out.push_str(&ai_location(l));
    }
    out.push_str("];\n");
    out
}

/// Formats the Linux collector reads; `Format::<PascalCase>` in manifest.rs.
const FORMATS: &[&str] = &[
    "executable",
    "json",
    "toml",
    "codex-toml",
    "skill-dir",
    "md",
    "js-ts",
    "plugin-dir",
    "gemini-extension",
    "cursor-agent",
    "cursor-plugin",
];

/// `codex-toml` -> `CodexToml`.
fn pascal(value: &str) -> String {
    value
        .split(['-', '_'])
        .map(|word| word[..1].to_uppercase() + &word[1..])
        .collect()
}

/// One `ai_locations` row as an `AiLocation` literal. A row that names an
/// unknown key, kind, format, scope or platform, an unsafe path, or a field
/// its format does not read fails the build.
fn ai_location(l: &toml::Table) -> String {
    const REQUIRED: &[&str] = &["client", "kind", "path", "format", "scope"];
    const OPTIONAL: &[&str] = &["platforms", "mcp_keys", "plugins_key", "mcp_files"];
    for key in l.keys() {
        assert!(
            REQUIRED.contains(&key.as_str()) || OPTIONAL.contains(&key.as_str()),
            "ai_locations: unknown key {key:?}"
        );
    }
    let text = |key: &str| -> &str {
        l.get(key)
            .unwrap_or_else(|| panic!("ai_locations: a row needs {key}"))
            .as_str()
            .unwrap_or_else(|| panic!("ai_locations: {key} must be a string"))
    };
    let list = |key: &str| -> Vec<&str> {
        l.get(key).map_or_else(Vec::new, |value| {
            value
                .as_array()
                .unwrap_or_else(|| panic!("ai_locations: {key} must be an array"))
                .iter()
                .map(|item| {
                    item.as_str()
                        .unwrap_or_else(|| panic!("ai_locations: {key} holds strings"))
                })
                .collect()
        })
    };
    let (client, kind, path, format, scope) = (
        text("client"),
        text("kind"),
        text("path"),
        text("format"),
        text("scope"),
    );
    assert!(!client.is_empty(), "ai_locations: {path}: empty client");
    assert!(
        ["cli", "config", "skill", "agent", "plugin", "extension"].contains(&kind),
        "ai_locations: {path}: unknown kind {kind:?}"
    );
    assert!(
        FORMATS.contains(&format),
        "ai_locations: {path}: unknown format {format:?}"
    );
    assert!(
        ["user", "project"].contains(&scope),
        "ai_locations: {path}: unknown scope {scope:?}"
    );
    assert!(
        !path.starts_with('/')
            && !path.contains('\\')
            && path
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != ".."),
        "ai_locations: {path:?} must be a plain relative path"
    );
    assert_eq!(
        kind == "config",
        ["json", "toml", "codex-toml"].contains(&format),
        "ai_locations: {path}: kind config goes with format json, toml or codex-toml"
    );
    assert_eq!(
        kind == "cli",
        format == "executable",
        "ai_locations: {path}: kind cli goes with format executable"
    );
    assert!(
        kind != "cli" || (scope == "user" && !path.contains('/')),
        "ai_locations: {path}: a cli is a bare executable name with scope user"
    );
    let needs_mcp_keys = format == "json" || format == "gemini-extension";
    let has = |key: &str| l.contains_key(key);
    assert!(
        has("mcp_keys") == needs_mcp_keys || (format == "plugin-dir" && has("mcp_files")),
        "ai_locations: {path}: mcp_keys is required for json and gemini-extension rows and for plugin-dir rows with mcp_files"
    );
    assert!(
        format == "plugin-dir" || !has("mcp_files"),
        "ai_locations: {path}: only plugin-dir reads mcp_files"
    );
    assert!(
        format == "json" || !has("plugins_key"),
        "ai_locations: {path}: only json reads plugins_key"
    );
    let platforms = if has("platforms") {
        list("platforms")
    } else {
        vec!["linux", "macos", "windows"]
    };
    assert!(!platforms.is_empty(), "ai_locations: {path}: no platforms");
    for platform in &platforms {
        assert!(
            ["linux", "macos", "windows"].contains(platform),
            "ai_locations: {path}: unknown platform {platform:?}"
        );
    }
    let strs = |items: Vec<&str>| {
        let quoted: Vec<String> = items.iter().map(|item| format!("{item:?}")).collect();
        format!("&[{}]", quoted.join(", "))
    };
    let plugins_key = if has("plugins_key") {
        text("plugins_key")
    } else {
        ""
    };
    format!(
        "    AiLocation {{ client: {client:?}, kind: {kind:?}, path: {path:?}, format: Format::{}, scope: Scope::{}, platforms: {}, mcp_keys: {}, plugins_key: {plugins_key:?}, mcp_files: {} }},\n",
        pascal(format),
        pascal(scope),
        strs(platforms),
        strs(list("mcp_keys")),
        strs(list("mcp_files")),
    )
}
