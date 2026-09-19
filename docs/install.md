# Building and installing Deixic Endpoint packages

The Linux packaging scripts assemble the agent binary, eBPF object, systemd
unit, example configuration, and rules into a deterministic tar archive. Build
the binaries first, then run:

```sh
SOURCE_DATE_EPOCH=0 packaging/linux/build-package.sh 0.1.0 \
  target/release/merlin merlin-ebpf/target/bpfel-unknown-none/release/merlin-ebpf dist
sh packaging/linux/test-packaging.sh
```

The package test requires GNU tar. The archive has no device credential. After
extracting it, install and configure a root-owned mode `0600` environment file:

```sh
sudo ./install.sh
sudo install -o root -g root -m 600 \
  payload/etc/merlin/merlin.env.example /etc/merlin/merlin.env
sudo editor /etc/merlin/merlin.env
sudo systemctl enable --now merlin
```

Verify a downloaded Linux archive's attestation and both Sigstore bundles
before installation. The accepted keyless identity is the exact tagged Mono
release workflow:

```text
https://github.com/dx-corp/mono/.github/workflows/merlin-sensor-release.yml@refs/tags/merlin-v<version>
```

`packaging/linux/release-attestation.py verify` binds the archive digest,
version, source revision, repository, and workflow identity. `cosign
verify-blob` verifies the publisher signature. A source checkout does not prove
that a separate archive was published or signed.

The macOS package builder is `macos/packaging/build-pkg.sh`. An unsigned local
package can exercise assembly. Distribution requires the authorized Developer
ID application and installer identities followed by notarization and stapling.
Verify delivered packages with `pkgutil --check-signature` and `spctl --assess
--type install --verbose=2` before `installer -pkg`.
