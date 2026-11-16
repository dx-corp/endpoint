//! Compiles in the one declared cap on findings per list, the collection
//! manifest's `ai_findings_cap`, so the plugin accepts exactly what the
//! scanner it runs can print. (merlin's build parses the whole manifest as
//! TOML and checks the value; here the one line is enough.)

use std::path::Path;

const MANIFEST: &str = "../../collection-manifest.d/ai_locations.toml";

fn main() {
    println!("cargo:rerun-if-changed={MANIFEST}");
    let manifest = std::fs::read_to_string(MANIFEST).expect("read the collection manifest");
    let cap: usize = manifest
        .lines()
        .find_map(|line| line.strip_prefix("ai_findings_cap = "))
        .and_then(|value| value.trim().parse().ok())
        .filter(|cap| (1..=4096).contains(cap))
        .expect("the collection manifest declares ai_findings_cap, an integer from 1 to 4096");
    let out = Path::new(&std::env::var("OUT_DIR").unwrap()).join("caps.rs");
    std::fs::write(
        out,
        format!("/// MCP servers, and agent assets, accepted from one scan (each).\npub(crate) const MAX_FINDINGS: usize = {cap};\n"),
    )
    .expect("write caps.rs");
}
