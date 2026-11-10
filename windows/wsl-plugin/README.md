# Deixic Endpoint WSL plugin

A WSL plugin DLL (Rust `cdylib`, `WslPluginApi.h` V1) that lists AI tools in
WSL distributions without installing anything in them and without starting
one. wslservice loads it from the path registered under
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss\Plugins`. wslservice
loads only a DLL with a trusted Authenticode signature. The release signs it
and the Windows installer registers it only when its signature is valid; see
the [Windows collector guide](../README.md).

## What it does

- **A distribution starts** (`OnDistributionStarted`): the hook copies the
  session id, distribution id, name and init pid, starts a thread and returns
  `S_OK`. The thread mounts the install folder's `wsl` directory read-only at
  `/deixic-endpoint` in the WSL VM (once per VM), then runs
  `/deixic-endpoint/merlin scan-ai-locations --root /proc/<init pid>/root
  --location wsl:<name>` with `ExecuteBinary`. That static scanner chroots into
  the distribution and prints names and labels only. The plugin accepts the
  output only when it is the scanner's JSON, within its caps (32 CLIs, 128 MCP
  servers, 128 assets, 1 MiB, 30 seconds), with every finding tagged with the
  requested location.
- **A distribution is registered** (`OnDistributionRegistered`, WSL 2.1.2+):
  it is recorded as not scanned until it starts. **Unregistered**: its record
  is deleted.
- **The VM stops**: the next VM is mounted again.

No hook ever returns an error or calls `PluginError`, so a scan problem can
never stop WSL, the VM or a distribution from starting. On WSL older than
2.0.5 (no `InitPid`) the plugin registers no hook and records that it cannot
scan. It writes the registration hooks only on 2.1.2+, where WSL allocates
them.

## Handoff contract

The plugin and the Windows collector share only these files, in
`%ProgramData%\Deixic\Endpoint\wsl`. The folder inherits the install's
SYSTEM and Administrators ACL. Each file is written under a temporary name
and renamed, so a reader sees a whole file or the previous one. Readers must
validate every field again; the files are inputs, not trusted facts.

`plugin.json`, written when wslservice loads the plugin:

```json
{"schema_version":1,"wsl_version":"2.4.4","scans":true,"registrations":true,"loaded_at":1794000000}
```

`scans` is false when this WSL cannot be scanned; then every distribution is
not scanned.

`<distribution id>.json`, one per distribution. The id is WSL's distribution
GUID in lowercase registry form without braces:

```json
{
  "schema_version":1,
  "distro_id":"0123abcd-4567-89ab-cdef-000102030405",
  "distro":"Ubuntu-24.04",
  "state":"scanned",
  "reason":null,
  "observed_at":1794000000,
  "findings":{
    "clis":[{"name":"claude"}],
    "mcp_servers":[{"location":"wsl:Ubuntu-24.04","client":"codex","name":"github","source":".codex/config.toml","transport":"remote"}],
    "agent_assets":[{"location":"wsl:Ubuntu-24.04","client":"claude","kind":"skill","name":"review","source":".claude/skills"}]
  }
}
```

`state` is `scanned` or `not_scanned`. A `not_scanned` record has no
findings and one `reason`: `not_started` (registered, never started since),
`scan_failed`, `scanner_missing` (no `wsl\merlin`, as in the arm64 package),
`unsupported_name` (the name is not 1 to 64 letters, digits, `.`, `_` or `-`,
so it cannot be a `wsl:` location), `no_init_pid` or `scan_not_started`.
`observed_at` is Unix seconds. A `scanned` record holds the latest scan from
the most recent start; the collector decides how old a scan may be.

Distributions that existed before the plugin was installed have no record
until they start. A reader that must list them as not scanned reads the
registered distributions itself.

## Build and test

```sh
cargo test -p deixic-wsl-plugin
cargo clippy -p deixic-wsl-plugin --all-targets -- -D warnings
cargo build --release -p deixic-wsl-plugin --target x86_64-pc-windows-gnu
```

Tests load the plugin through a mocked `WSLPluginAPIV1` table and call its
hooks as wslservice would; no real WSL is involved. The plugin has not run
under a real wslservice yet.
