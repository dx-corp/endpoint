#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/merlin-linux-verify-test.XXXXXX")
trap 'rm -rf "$TEMP_DIR"' EXIT HUP INT TERM
mkdir -p "$TEMP_DIR/bin" "$TEMP_DIR/usr/local/libexec/merlin" "$TEMP_DIR/usr/lib/systemd/system" "$TEMP_DIR/etc/merlin"
chmod 755 "$TEMP_DIR/usr/local/libexec" "$TEMP_DIR/usr/local/libexec/merlin" "$TEMP_DIR/etc/merlin" "$TEMP_DIR/usr/lib/systemd/system"
for file in merlin merlin-ebpf.o merlin-launcher; do
  : > "$TEMP_DIR/usr/local/libexec/merlin/$file"
done
chmod 755 "$TEMP_DIR/usr/local/libexec/merlin/merlin" "$TEMP_DIR/usr/local/libexec/merlin/merlin-launcher"
chmod 644 "$TEMP_DIR/usr/local/libexec/merlin/merlin-ebpf.o"
: > "$TEMP_DIR/etc/merlin/merlin.env"
: > "$TEMP_DIR/etc/merlin/rules.yaml"
chmod 600 "$TEMP_DIR/etc/merlin/merlin.env"
chmod 644 "$TEMP_DIR/etc/merlin/rules.yaml"
sed "s@/usr/local/libexec/merlin@$TEMP_DIR/usr/local/libexec/merlin@g; s@/etc/merlin@$TEMP_DIR/etc/merlin@g" \
  "$SCRIPT_DIR/merlin.service" > "$TEMP_DIR/usr/lib/systemd/system/merlin.service"
chmod 644 "$TEMP_DIR/usr/lib/systemd/system/merlin.service"

# Rewrite only the fixed installation root for a fixture copy. The shipped
# verifier has no path or command overrides that could weaken fleet checks.
sed "s@/usr/local/libexec@$TEMP_DIR/usr/local/libexec@g; s@/usr/lib/systemd/system@$TEMP_DIR/usr/lib/systemd/system@g; s@/etc/merlin@$TEMP_DIR/etc/merlin@g" \
  "$SCRIPT_DIR/verify-install.sh" > "$TEMP_DIR/verify-install.sh"
chmod 755 "$TEMP_DIR/verify-install.sh"
cat > "$TEMP_DIR/bin/stat" <<'EOF'
#!/bin/sh
case "$2" in
  %u) printf '0\n' ;;
  %a) python3 -c 'import os, stat, sys; print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode))[2:])' "$4" ;;
  *) exit 2 ;;
esac
EOF
cat > "$TEMP_DIR/bin/systemctl" <<'EOF'
#!/bin/sh
case "$1" in
  is-enabled|is-active) [ "${MOCK_SERVICE_STATE:-ready}" = ready ] ;;
  show)
    case "$2" in
      --property=FragmentPath) printf '%s\n' "$MOCK_UNIT" ;;
      --property=DropInPaths) printf '%s\n' "${MOCK_DROPINS:-}" ;;
      --property=ExecStart) printf '{ path=%s ; argv[]=%s%s ; ignore_errors=no ; }\n' "$MOCK_LAUNCHER" "$MOCK_LAUNCHER" "${MOCK_EXTRA_ARG:-}" ;;
      --property=ExecCondition|--property=ExecStartPre|--property=ExecStartPost) printf '%s\n' "${MOCK_EXTRA_COMMAND:-}" ;;
      --property=EnvironmentFiles) printf '%s (ignore_errors=no)%s\n' "$MOCK_CONFIG" "${MOCK_EXTRA_CONFIG:-}" ;;
      *) exit 2 ;;
    esac ;;
  *) exit 2 ;;
esac
EOF
chmod 755 "$TEMP_DIR/bin/stat" "$TEMP_DIR/bin/systemctl"
export PATH="$TEMP_DIR/bin:$PATH"
export MOCK_UNIT="$TEMP_DIR/usr/lib/systemd/system/merlin.service"
export MOCK_LAUNCHER="$TEMP_DIR/usr/local/libexec/merlin/merlin-launcher"
export MOCK_CONFIG="$TEMP_DIR/etc/merlin/merlin.env"

verify_ok() {
  "$TEMP_DIR/verify-install.sh" > "$TEMP_DIR/output" 2>&1 || { cat "$TEMP_DIR/output" >&2; exit 1; }
}
verify_bad() {
  if "$TEMP_DIR/verify-install.sh" > "$TEMP_DIR/output" 2>&1; then
    printf 'unsafe installation unexpectedly verified: %s\n' "$1" >&2
    exit 1
  fi
  ! grep -F 'secret-device-token' "$TEMP_DIR/output" >/dev/null || exit 1
}

verify_ok
chmod 777 "$TEMP_DIR/etc/merlin"
verify_bad 'writable configuration directory'
chmod 755 "$TEMP_DIR/etc/merlin"
printf 'secret-device-token\n' > "$TEMP_DIR/etc/merlin/merlin.env"
chmod 644 "$TEMP_DIR/etc/merlin/merlin.env"
verify_bad 'public configuration'
chmod 600 "$TEMP_DIR/etc/merlin/merlin.env"
verify_ok
mv "$TEMP_DIR/etc/merlin/merlin.env" "$TEMP_DIR/etc/merlin/merlin.env.real"
ln -s merlin.env.real "$TEMP_DIR/etc/merlin/merlin.env"
verify_bad 'symbolic-link configuration'
rm "$TEMP_DIR/etc/merlin/merlin.env"
mv "$TEMP_DIR/etc/merlin/merlin.env.real" "$TEMP_DIR/etc/merlin/merlin.env"
MOCK_SERVICE_STATE=inactive; export MOCK_SERVICE_STATE
verify_bad 'inactive service'
unset MOCK_SERVICE_STATE
MOCK_UNIT=/usr/lib/systemd/system/other.service; export MOCK_UNIT
verify_bad 'unexpected loaded unit'
export MOCK_UNIT="$TEMP_DIR/usr/lib/systemd/system/merlin.service"
MOCK_DROPINS=/etc/systemd/system/merlin.service.d/override.conf; export MOCK_DROPINS
verify_bad 'unit override'
unset MOCK_DROPINS
MOCK_CONFIG=/etc/elsewhere.conf; export MOCK_CONFIG
verify_bad 'unexpected configuration path'
export MOCK_CONFIG="$TEMP_DIR/etc/merlin/merlin.env"
MOCK_EXTRA_ARG=' --unsafe'; export MOCK_EXTRA_ARG
verify_bad 'extra service command argument'
unset MOCK_EXTRA_ARG
MOCK_EXTRA_COMMAND='{ path=/bin/true ; argv[]=/bin/true ; }'; export MOCK_EXTRA_COMMAND
verify_bad 'extra service command'
unset MOCK_EXTRA_COMMAND
MOCK_EXTRA_CONFIG=' /etc/extra.env (ignore_errors=no)'; export MOCK_EXTRA_CONFIG
verify_bad 'extra environment file'
unset MOCK_EXTRA_CONFIG
rm "$TEMP_DIR/etc/merlin/rules.yaml"
verify_bad 'missing rules policy'
printf '%s\n' 'Linux installation verification tests passed.'
