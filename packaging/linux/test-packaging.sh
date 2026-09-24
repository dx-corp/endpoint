#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/merlin-linux-package-test.XXXXXX")
trap 'rm -rf "$TEMP_DIR"' EXIT HUP INT TERM

for script in build-package.sh install.sh merlin-launcher.sh uninstall.sh verify-install.sh test-verify-install.sh; do
  sh -n "$SCRIPT_DIR/$script"
done
printf '#!/bin/sh\nexit 0\n' > "$TEMP_DIR/merlin"
chmod 755 "$TEMP_DIR/merlin"
printf 'test ebpf object\n' > "$TEMP_DIR/merlin-ebpf.o"
SOURCE_DATE_EPOCH=0 "$SCRIPT_DIR/build-package.sh" 0.0.0-test "$TEMP_DIR/merlin" "$TEMP_DIR/merlin-ebpf.o" "$TEMP_DIR/dist"

ARCH=$(uname -m)
ARCHIVE=$TEMP_DIR/dist/merlin-0.0.0-test-linux-$ARCH.tar.gz
[ -f "$ARCHIVE" ] || { printf '%s\n' 'package archive was not created' >&2; exit 1; }
tar -xzf "$ARCHIVE" -C "$TEMP_DIR"
ROOT=$TEMP_DIR/merlin-0.0.0-test-linux-$ARCH
for path in install.sh verify-install.sh uninstall.sh payload/usr/local/libexec/merlin/merlin payload/usr/local/libexec/merlin/merlin-ebpf.o payload/usr/local/libexec/merlin/merlin-launcher payload/usr/lib/systemd/system/merlin.service payload/etc/merlin/rules.yaml payload/etc/merlin/merlin.env.example; do
  [ -f "$ROOT/$path" ] || { printf 'package path is missing: %s\n' "$path" >&2; exit 1; }
done
grep -F 'EnvironmentFile=/etc/merlin/merlin.env' "$ROOT/payload/usr/lib/systemd/system/merlin.service" >/dev/null
grep -F 'ExecStart=/usr/local/libexec/merlin/merlin-launcher' "$ROOT/payload/usr/lib/systemd/system/merlin.service" >/dev/null
grep -F 'MERLIN_POLICY_PUBLIC_KEYS=' "$ROOT/payload/etc/merlin/merlin.env.example" >/dev/null

SOURCE_SHA=1111111111111111111111111111111111111111
ATTESTATION=$TEMP_DIR/dist/merlin-release-attestation.json
python3 "$SCRIPT_DIR/release-attestation.py" write \
  --artifact "$ARCHIVE" \
  --version 0.0.0-test \
  --source-sha "$SOURCE_SHA" \
  --attestation "$ATTESTATION"
python3 "$SCRIPT_DIR/release-attestation.py" verify \
  --artifact "$ARCHIVE" \
  --version 0.0.0-test \
  --source-sha "$SOURCE_SHA" \
  --attestation "$ATTESTATION"
printf 'tampered\n' >> "$ARCHIVE"
if python3 "$SCRIPT_DIR/release-attestation.py" verify \
  --artifact "$ARCHIVE" \
  --version 0.0.0-test \
  --source-sha "$SOURCE_SHA" \
  --attestation "$ATTESTATION" 2>/dev/null; then
  printf '%s\n' 'tampered package unexpectedly passed attestation verification' >&2
  exit 1
fi
printf '%s\n' 'Linux packaging tests passed.'
"$SCRIPT_DIR/test-verify-install.sh"
