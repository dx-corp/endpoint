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
            "ai_agent_processes",
            "ai_extensions",
            "ai_content_rules",
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
    out.push_str(&ai_agent_processes(m));
    out.push_str(&ai_extensions(m));
    out.push_str(&ai_content_rules(m));
    out
}

/// The `ai_agent_processes` rows as `AI_AGENT_PROCESSES`. A client that no
/// ai_locations row names, a name that is not a bare file name, or a name
/// declared twice (here or as a cli row) fails the build.
fn ai_agent_processes(m: &toml::Table) -> String {
    let locations: Vec<&toml::Table> = tables(m, "ai_locations").collect();
    let field = |row: &toml::Table, key: &str| -> String {
        row.get(key)
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("ai_agent_processes: {key} must be a string"))
            .to_owned()
    };
    let mut names: Vec<String> = locations
        .iter()
        .filter(|l| l.get("kind").and_then(toml::Value::as_str) == Some("cli"))
        .map(|l| field(l, "path"))
        .collect();
    let mut out = String::from("pub const AI_AGENT_PROCESSES: &[AiAgentProcess] = &[\n");
    for row in tables(m, "ai_agent_processes") {
        let row = exact(row, &["client", "name"], "an ai_agent_processes row");
        let (client, name) = (field(row, "client"), field(row, "name"));
        assert!(
            locations
                .iter()
                .any(|l| l.get("client").and_then(toml::Value::as_str) == Some(client.as_str())),
            "ai_agent_processes: {name}: client {client:?} is not named by ai_locations"
        );
        assert!(
            !name.is_empty()
                && name.len() <= 64
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
            "ai_agent_processes: {name:?} must be a bare file name of letters, digits, '.', '_' or '-'"
        );
        assert!(
            !names.contains(&name),
            "ai_agent_processes: {name} is declared twice"
        );
        names.push(name.clone());
        writeln!(
            out,
            "    AiAgentProcess {{ client: {client:?}, name: {name:?} }},"
        )
        .unwrap();
    }
    out.push_str("];\n");
    out
}

/// The `ai_extensions` rows as `AI_EXTENSIONS`. An id that is not its
/// store's shape, or is declared twice, fails the build.
fn ai_extensions(m: &toml::Table) -> String {
    let mut out = String::from("pub const AI_EXTENSIONS: &[AiExtension] = &[\n");
    let mut seen = std::collections::BTreeSet::new();
    for row in tables(m, "ai_extensions") {
        let row = exact(
            row,
            &["store", "id", "name", "publisher"],
            "an ai_extensions row",
        );
        let text = |key: &str| {
            row[key]
                .as_str()
                .unwrap_or_else(|| panic!("ai_extensions: {key} must be a string"))
        };
        let (store, id) = (text("store"), text("id"));
        let part = |part: &str| {
            !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        };
        let shaped = match store {
            "vscode-marketplace" => id
                .split_once('.')
                .is_some_and(|(publisher, name)| part(publisher) && part(name)),
            "chrome-web-store" => id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b)),
            _ => panic!("ai_extensions: {id}: unknown store {store:?}"),
        };
        assert!(shaped, "ai_extensions: {id:?} is not a {store} id");
        assert!(
            seen.insert(id.to_ascii_lowercase()),
            "ai_extensions: {id} is declared twice"
        );
        assert!(
            !text("name").is_empty() && !text("publisher").is_empty(),
            "ai_extensions: {id}: name and publisher are required"
        );
        writeln!(
            out,
            "    AiExtension {{ store: ExtensionStore::{}, id: {}, name: {}, publisher: {} }},",
            pascal(store),
            string(row, "id"),
            string(row, "name"),
            string(row, "publisher"),
        )
        .unwrap();
    }
    out.push_str("];\n");
    out
}

/// The `ai_content_rules` rows as `AI_CONTENT_RULES`, and each rule file they
/// name, once, compiled in as `AI_CONTENT_SOURCES` (path under `rules/ai/`,
/// source text). An unknown key or engine, a repeated id or a path outside
/// `rules/ai/` fails the build.
fn ai_content_rules(m: &toml::Table) -> String {
    let mut rules = String::from("pub const AI_CONTENT_RULES: &[AiContentRule] = &[\n");
    let mut sources = String::from("pub const AI_CONTENT_SOURCES: &[(&str, &str)] = &[\n");
    let mut ids = Vec::new();
    let mut files = Vec::new();
    for row in tables(m, "ai_content_rules") {
        let row = exact(row, &["id", "engine", "file"], "an ai_content_rules row");
        let text = |key: &str| {
            row[key]
                .as_str()
                .unwrap_or_else(|| panic!("ai_content_rules: {key} must be a string"))
        };
        let (id, engine, file) = (text("id"), text("engine"), text("file"));
        assert!(
            !id.is_empty()
                && id.len() <= 64
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
            "ai_content_rules: {id:?} must be at most 64 letters, digits, _ or -"
        );
        assert!(
            !ids.contains(&id),
            "ai_content_rules: {id} is declared twice"
        );
        ids.push(id);
        assert_eq!(
            engine, "yara",
            "ai_content_rules: {id}: engine must be yara"
        );
        assert!(
            file.ends_with(".yara")
                && file
                    .split('/')
                    .all(|part| !part.is_empty() && part != "." && part != ".."),
            "ai_content_rules: {id}: file {file:?} must be a .yara path under rules/ai/"
        );
        writeln!(
            rules,
            "    AiContentRule {{ id: {id:?}, engine: {engine:?}, file: {file:?} }},"
        )
        .unwrap();
        if !files.contains(&file) {
            files.push(file);
            println!("cargo:rerun-if-changed=../rules/ai/{file}");
            writeln!(
                sources,
                "    ({file:?}, include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/../rules/ai/{file}\"))),"
            )
            .unwrap();
        }
    }
    rules.push_str("];\n");
    sources.push_str("];\n");
    rules + &sources
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
    "claude-plugin-cache",
    "hf-hub",
    "model-dir",
    "editor-extensions",
    "chromium-extensions",
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
    const OPTIONAL: &[&str] = &[
        "platforms",
        "mcp_keys",
        "plugins_key",
        "mcp_files",
        "max_bytes",
    ];
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
        [
            "cli",
            "config",
            "skill",
            "agent",
            "plugin",
            "extension",
            "model"
        ]
        .contains(&kind),
        "ai_locations: {path}: unknown kind {kind:?}"
    );
    assert!(
        FORMATS.contains(&format),
        "ai_locations: {path}: unknown format {format:?}"
    );
    assert!(
        ["user", "project", "system"].contains(&scope),
        "ai_locations: {path}: unknown scope {scope:?}"
    );
    // A system path is absolute; every other path is relative.
    let system = scope == "system";
    let plain = |relative: &str| {
        !relative.contains('\\')
            && relative
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
    };
    assert!(
        match path.strip_prefix('/') {
            Some(relative) => system && plain(relative),
            None => !system && plain(path),
        },
        "ai_locations: {path:?} must be a plain relative path, or a plain absolute path with scope system"
    );
    assert!(
        !system || (kind == "config" && format == "json"),
        "ai_locations: {path}: a system row is a json config"
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
    assert_eq!(
        kind == "model",
        ["hf-hub", "model-dir"].contains(&format),
        "ai_locations: {path}: kind model goes with format hf-hub or model-dir"
    );
    assert!(
        kind != "model" || (scope == "user" && list("platforms") == ["linux"]),
        "ai_locations: {path}: a model row has scope user and platforms [\"linux\"]"
    );
    assert!(
        !format.ends_with("-extensions") || (kind == "extension" && scope == "user"),
        "ai_locations: {path}: {format} rows are user-scope extensions"
    );
    let needs_mcp_keys = format == "json" || format == "gemini-extension";
    let reads_mcp_files = format == "plugin-dir" || format == "claude-plugin-cache";
    let has = |key: &str| l.contains_key(key);
    assert!(
        has("mcp_keys") == needs_mcp_keys || (reads_mcp_files && has("mcp_files")),
        "ai_locations: {path}: mcp_keys is required for json and gemini-extension rows and for plugin-dir and claude-plugin-cache rows with mcp_files"
    );
    assert!(
        reads_mcp_files || !has("mcp_files"),
        "ai_locations: {path}: only plugin-dir and claude-plugin-cache read mcp_files"
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
    assert!(
        !system || (has("platforms") && !platforms.contains(&"windows")),
        "ai_locations: {path}: a system row names linux or macos platforms"
    );
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
    // A user config's own read limit; 64 KiB (the default) up to 16 MiB.
    let max_bytes = l.get("max_bytes").map_or(64 << 10, |value| {
        let bytes = value
            .as_integer()
            .unwrap_or_else(|| panic!("ai_locations: {path}: max_bytes must be an integer"));
        assert!(
            kind == "config" && scope == "user",
            "ai_locations: {path}: only a user config row sets max_bytes"
        );
        assert!(
            (64 << 10..=16 << 20).contains(&bytes),
            "ai_locations: {path}: max_bytes must be from 64 KiB to 16 MiB"
        );
        bytes
    });
    let plugins_key = if has("plugins_key") {
        text("plugins_key")
    } else {
        ""
    };
    format!(
        "    AiLocation {{ client: {client:?}, kind: {kind:?}, path: {path:?}, format: Format::{}, scope: Scope::{}, platforms: {}, mcp_keys: {}, plugins_key: {plugins_key:?}, mcp_files: {}, max_bytes: {max_bytes} }},\n",
        pascal(format),
        pascal(scope),
        strs(platforms),
        strs(list("mcp_keys")),
        strs(list("mcp_files")),
    )
}
