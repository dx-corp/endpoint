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
# install.sh stops before touching anything when an administrator-level unit
# or drop-in would override the packaged unit, and names the files; with
# MERLIN_INSTALL_MIGRATE_UNITS=1 it moves them aside instead.
FIXTURE=$TEMP_DIR/shadow
mkdir -p "$FIXTURE/etc/systemd/system/merlin.service.d" "$FIXTURE/etc/merlin" "$FIXTURE/bin"
: > "$FIXTURE/etc/systemd/system/merlin.service"
: > "$FIXTURE/etc/systemd/system/merlin.service.d/10-tracing-mount.conf"
# Rewrite only the host paths (preceded by a space or quote), never the
# payload's own /etc/merlin copies, and drop the root check for the fixture.
sed "s@\([ \"]\)/etc/systemd/system@\1$FIXTURE/etc/systemd/system@g; s@\([ \"=]\)/etc/merlin@\1$FIXTURE/etc/merlin@g; s@\[ \"\$(id -u)\" -eq 0 \]@true@" \
  "$ROOT/install.sh" > "$FIXTURE/install.sh"
chmod 755 "$FIXTURE/install.sh"
cp -R "$ROOT/payload" "$FIXTURE/payload"
# A stand-in for install(1): creates directories for -d, installs nothing.
cat > "$FIXTURE/bin/install" <<'STUB'
#!/bin/sh
if [ "$1" = -d ]; then
  shift
  while [ $# -gt 0 ]; do
    case "$1" in -*) shift 2 ;; *) mkdir -p "$1"; shift ;; esac
  done
fi
exit 0
STUB
chmod 755 "$FIXTURE/bin/install"
if PATH="$FIXTURE/bin:$PATH" "$FIXTURE/install.sh" > "$TEMP_DIR/shadow-output" 2>&1; then
  printf '%s\n' 'install.sh ran although an overriding unit was present' >&2
  exit 1
fi
grep -F "$FIXTURE/etc/systemd/system/merlin.service" "$TEMP_DIR/shadow-output" >/dev/null
grep -F "10-tracing-mount.conf" "$TEMP_DIR/shadow-output" >/dev/null
grep -F 'MERLIN_INSTALL_MIGRATE_UNITS=1' "$TEMP_DIR/shadow-output" >/dev/null
[ -e "$FIXTURE/etc/systemd/system/merlin.service" ] || { printf '%s\n' 'install.sh must not move units without the opt-in' >&2; exit 1; }
# With the opt-in the overriding files move aside and the install proceeds
# to the (stubbed) install step.
sed -i.bak "s@systemctl daemon-reload@true@" "$FIXTURE/install.sh"
if ! MERLIN_INSTALL_MIGRATE_UNITS=1 PATH="$FIXTURE/bin:$PATH" "$FIXTURE/install.sh" > "$TEMP_DIR/shadow-output" 2>&1; then
  cat "$TEMP_DIR/shadow-output" >&2
  printf '%s\n' 'install.sh with MERLIN_INSTALL_MIGRATE_UNITS=1 should move the units aside and continue' >&2
  exit 1
fi
[ ! -e "$FIXTURE/etc/systemd/system/merlin.service" ] || { printf '%s\n' 'the overriding unit was not moved' >&2; exit 1; }
[ ! -e "$FIXTURE/etc/systemd/system/merlin.service.d" ] || { printf '%s\n' 'the empty drop-in directory was not removed' >&2; exit 1; }
ls "$FIXTURE"/etc/merlin/superseded-units/*/merlin.service >/dev/null
ls "$FIXTURE"/etc/merlin/superseded-units/*/10-tracing-mount.conf >/dev/null
printf '%s\n' 'Linux packaging tests passed.'
"$SCRIPT_DIR/test-verify-install.sh"
