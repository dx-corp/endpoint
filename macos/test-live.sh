#!/bin/sh
# Live test for merlin-macos. Paste-able; run it directly:
#
#     macos/test-live.sh
#
# It asks for your sudo password once (sudo -v), then:
#   1. stages a copy of /usr/bin/id as /tmp/merlin-evil
#   2. writes a block rule with this machine's sha256 of that copy
#   3. runs the readiness probe (sudo merlin-macos check)
#   4. starts the daemon with --provider auto (ES if the entitlement is
#      honored, otherwise the kqueue provider with block degraded to
#      kill; OpenBSM is the last-resort fallback and is inert on macOS 14+)
#   5. attempts the blocked exec and inspects the spool
#
# Works whether or not the ES entitlement is honored — it detects which
# provider actually started from the daemon's own log.
set -eu

MACOS_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$MACOS_DIR/.build/release/MerlinMacOS"
EVIL=/tmp/merlin-evil
RULES=/tmp/merlin-rules-live.yaml
SPOOL=/tmp/merlin-events-live.jsonl
DAEMON_LOG=/tmp/merlin-daemon-live.log
DAEMON_PID=

[ -x "$BIN" ] || { echo "build first: $MACOS_DIR/build.sh" >&2; exit 1; }

echo "==> caching sudo credentials"
sudo -v
# Leftovers from a previous run may be root-owned (if the script itself was
# invoked with sudo); clear them before staging as the invoking user.
sudo rm -f "$EVIL" "$RULES" "$SPOOL" "$DAEMON_LOG" /tmp/merlin-evil.c

echo "==> 1. staging $EVIL (a freshly compiled demo binary)"
# NOTE: do not demo with a copy of an Apple platform binary (e.g. cp
# /usr/bin/id /tmp/...) — macOS Launch Constraints SIGKILL those at exec
# before merlin ever sees them. The demo target must be a non-Apple binary.
printf 'int main(void){return 0;}\n' > /tmp/merlin-evil.c
cc -o "$EVIL" /tmp/merlin-evil.c

echo "==> 2. writing $RULES with this machine's sha256"
HASH="$("$BIN" gen-hash "$EVIL" | awk 'NR==1{print $1}')"
cat > "$RULES" <<EOF
rules:
  - name: block-merlin-evil
    match:
      sha256: "$HASH"
      path_basename: merlin-evil   # fallback if hashing fails
    action: block
EOF
cat "$RULES"
echo "    note: content-based blocking hashes match bytes, not paths — any other"
echo "    file with identical bytes would be blocked too."

echo "==> 3. readiness probe"
sudo "$BIN" check || true

echo "==> 4. starting the daemon (--provider auto)"
sudo rm -f "$SPOOL"
# Redirect in the invoking shell on purpose: the log stays user-owned so the
# rest of this script can read it without sudo.
# shellcheck disable=SC2024
sudo "$BIN" run --rules "$RULES" --spool "$SPOOL" --provider auto >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
sleep 2
cat "$DAEMON_LOG"
if grep -q "provider: Endpoint Security" "$DAEMON_LOG"; then
    PROVIDER=es
elif grep -q "provider: kqueue EVFILT_PROC" "$DAEMON_LOG"; then
    PROVIDER=kqueue
else
    PROVIDER=bsm
fi
echo "    provider in use: $PROVIDER"

cleanup() {
    echo "==> stopping the daemon"
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        sudo kill -INT "$DAEMON_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "==> 5. attempting the blocked exec: $EVIL"
set +e
if [ "$PROVIDER" = es ]; then
    "$EVIL"
    rc=$?
    echo "    exit=$rc (expect 126 with 'Operation not permitted' — AUTH_EXEC deny → EPERM)"
elif [ "$PROVIDER" = kqueue ]; then
    echo "    (kqueue provider: block degrades to kill — the process starts, then OUR SIGKILL lands)"
    "$EVIL"
    rc=$?
    echo "    exit=$rc (expect 137 = SIGKILL from the daemon; spool shows exec + kill events)"
else
    echo "    (BSM provider: block degrades to kill — the process starts, then SIGKILL lands)"
    "$EVIL"
    rc=$?
    echo "    exit=$rc (expect 137 = killed by SIGKILL from the daemon)"
fi
set -e

echo "==> 6. generating ordinary telemetry"
/bin/echo "hello from merlin live test" >/dev/null
sleep 1

echo "==> 7. spool highlights"
sudo grep -h '"kind":"\(deny\|kill\)"' "$SPOOL" 2>/dev/null || echo "    (no deny/kill events)"
echo "    -- last 3 events --"
sudo tail -n 3 "$SPOOL" 2>/dev/null || echo "    (spool empty)"

if [ "$PROVIDER" = bsm ]; then
    if ! sudo grep -q '"kind":"exec"' "$SPOOL" 2>/dev/null; then
        echo
        echo "    NOTE: no exec events from the BSM provider. OpenBSM needs auditd"
        echo "    running with the 'ex' audit class. On this macOS there is no"
        echo "    /etc/security/audit_control by default; create one with"
        echo "    'flags:ex,lo,ad' and start auditd:"
        echo "      sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist"
    fi
fi

echo "==> done. Full spool: $SPOOL   daemon log: $DAEMON_LOG"
