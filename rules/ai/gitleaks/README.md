# gitleaks rules

`gitleaks.toml` is the default configuration of
[gitleaks](https://github.com/gitleaks/gitleaks) (`config/gitleaks.toml`,
release v8.30.1, commit `83d9cd684c87d95d656c1458ef04895a7f1cbd8e`, SHA-256
`e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`), copied
unchanged. Copyright (c) 2019 Zachary Rice, licensed under the MIT License; the
license text is in [LICENSE](LICENSE).

The Deixic Endpoint agent compiles its rules in (`merlin/build.rs`) and runs
them on the content of AI skill, custom agent and plugin manifest files, next
to the skill-scanner YARA rules, and on each MCP server entry of an AI client
config. Only the ids of the rules that matched are reported: never the secret,
the line or a hash of either.

What runs, as gitleaks `detect` does: each rule's keywords as a prefilter, its
regex, its `secretGroup` (else the first non-empty group), its `entropy`
threshold, and its and the global allowlists' `regexes`, `stopwords`,
`regexTarget` and `condition`. Not run: the five rules scoped to a repository
`path` (one, `pkcs12-file`, has no regex), so 217 of 222 run; allowlist `paths` and `commits` (there is
no repository here; a path criterion never holds), and gitleaks' base64, hex
and percent decoding passes. Two translations keep Go RE2 meaning in Rust's
`regex`: `\w`, `\d` and `\s` are ASCII (Unicode off, as in Go), and a `{`
that starts no repetition is escaped (Go reads it as a literal).

To update, copy `config/gitleaks.toml` from a newer release and update the
release, commit and SHA-256 above; `cargo test -p merlin` checks every rule
compiles.
