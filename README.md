# Deixic Endpoint

Deixic Endpoint is the device agent for process, network, file, and security
telemetry with rule-backed local responses. The implementation retains the
`merlin` binary, package paths, configuration names, and protocol identifiers
for compatibility.

This source distribution contains the Linux Rust agent, its eBPF collector,
the macOS Swift agent, rules and content packs, packaging scripts, and tests.
The managed sync service and admin application are separate private services
and are not part of this repository.

## Linux source build

The host agent uses stable Rust. The eBPF crate is a detached workspace that
requires nightly Rust, `rust-src`, and `bpf-linker`:

```sh
cargo test --locked -p merlin-common
(cd merlin-ebpf && cargo +nightly build --locked --release)
cargo build --locked --release
sudo ./target/release/merlin check --json
sudo ./target/release/merlin run --rules rules/block-demo.yaml
```

`run` needs the Linux capabilities required for eBPF and fanotify. The example
rules are for review and testing; evaluate them against your environment before
enforcement.

## macOS source build

See `macos/README.md` for the Swift package, tests, and unsigned local package
workflow. Apple entitlement, Developer ID, notarization, and stapling authority
remain outside this source projection.

## Packages and trust

See `docs/install.md` for the package contents and signature checks. Release
artifacts continue to be built and signed from `dx-corp/mono`; this repository
does not publish an alternate package or signing identity.

The typed remediation boundary is documented in `docs/desired-state.md`.
Compatibility names and migration limits are recorded in
`docs/DEIXIC_ENDPOINT_MIGRATION.md`.

Validate a prepared projection with:

```sh
node scripts/distribution-validation.mjs --name endpoint --target .
```

On Linux the validator runs the deterministic package test. On macOS it checks
the package scripts syntactically because the package builder requires GNU tar.
It also validates Cargo metadata and runs the shared agent tests on both hosts.
