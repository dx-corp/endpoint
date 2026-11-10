# skill-scanner YARA rules

These `.yara` files are the YARA rules of Cisco AI Defense
[skill-scanner](https://github.com/cisco-ai-defense/skill-scanner)
(`skill_scanner/data/packs/core/yara/`, commit
`c558c421157c546ec417cf23778ce81a3a8f35fd`), copied unchanged. Copyright 2026
Cisco Systems, Inc. and its affiliates, licensed under the Apache License 2.0;
the license text is in [LICENSE](LICENSE).

The Deixic Endpoint agent compiles them in and runs them with YARA-X on the
content of AI skill, custom agent and plugin manifest files it finds. Each rule
id is declared in `ai_content_rules` of `../../../collection-manifest.toml`.
Only skill-scanner's YARA rules are used: its LLM, Cisco API, signature and
Python analyzers, and the post-filters its Python code applies to YARA matches,
are not run.

To update, copy the files from a newer skill-scanner commit, update the commit
above and the ids in `ai_content_rules`; `cargo test -p merlin` fails until
they agree.
