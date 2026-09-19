# Desired state v1

Deixic Endpoint delivers remediation as an immutable, signed, identity-bound
policy artifact. `desired_state.v1` is a closed union of reviewed assertion
types, not a remote command protocol. Unknown fields fail validation at the
control plane and again on the device.

```yaml
schema_version: 1
rules: []
desired_state:
  schema: desired_state.v1
  revision: 42
  target:
    platform: linux
  assertions:
    - assertion_id: package.openssh
      system.package:
        name: openssh-server
        state: present
    - assertion_id: service.ssh
      system.service:
        name: ssh
        enabled: true
        running: true
    - assertion_id: sysctl.kptr
      system.sysctl:
        name: kernel.kptr_restrict
        value: "2"
```

The v1 schema reserves these assertion types:

- `system.package`, `system.service`, `system.file`, `system.sysctl`, and
  `system.firewall`
- `desktop.dconf` and `browser.policy`
- `security.screen_lock`, `security.secure_boot`,
  `security.disk_encryption`, and `security.local_admin`
- `firmware.minimum_version`

Every compiled artifact declares the exact executor capabilities it needs.
Assignment fails unless a device advertised all of them. Linux currently
supports `system.package` through `apt`, `system.service` through `systemd`,
`system.sysctl` through `sysctl`, `system.file` through a descriptor-relative
managed-file executor, `desktop.dconf` through the system dconf database,
`browser.policy` through Chrome/Chromium enterprise-policy files, and
`security.screen_lock` through system dconf policy. The other schema members
remain reserved and are not assigned until a reviewed native executor
advertises the matching capability. This lets the protocol grow without a
generic escape hatch.

Managed files are confined below `/etc/merlin/managed-config`. The executor
opens the root and every path component with `O_NOFOLLOW`, writes an exclusive
temporary file, applies the declared mode, syncs it, and installs it with a
descriptor-relative atomic rename. dconf fragments live below
`/etc/dconf/db/local.d` and are compliant only after `/usr/bin/dconf update`
produces a database at least as fresh as the fragment. Browser policies are
one canonical JSON document per named policy below the platform's managed
Chrome or Chromium policy directory.
Screen-lock policy also owns a dconf lock fragment, so managed timeout and lock
keys cannot be overridden by a user session.

There is intentionally no `shell`, `command`, script, or arbitrary executable
assertion. The agent invokes fixed absolute paths, passes validated arguments
without a shell, clears the inherited environment, bounds output, and kills an
executor after 120 seconds. Future adapters should orchestrate the platform
primitive: LUKS2, `fwupd`/LVFS, `apt`, `nftables`, `dconf`, `systemd`, or
Chrome/Chromium enterprise policy. They must not reimplement those systems.

## Receipts

Each attempted assertion returns evidence bound to the authenticated device
and assigned artifact:

```json
{
  "device_id": "dev_...",
  "artifact_sha": "<sha256>",
  "assertion_id": "package.openssh",
  "observed_before": [{"present": false}],
  "action_taken": {"operations": [{"executor": "apt_ensure_present"}]},
  "observed_after": [{"present": true, "version": "1:9.6p1-3"}],
  "result": "applied",
  "reboot_required": false,
  "timestamp": 1788000000
}
```

Results are `compliant`, `applied`, or `failed`. The control plane rejects
unstructured evidence, duplicate assertion IDs, mismatched device/artifact
bindings, future timestamps, and an applied update containing a failed
receipt. Each receipt is also appended to the immutable PostgreSQL control
evidence ledger in the same transaction that acknowledges the device update.
Its deterministic evidence ID binds the device, update, assertion, artifact,
and receipt digest. The bounded device-update history remains an operational
view; it is no longer the historical evidence store.
