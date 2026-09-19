#!/bin/sh
set -eu

CONFIG=/etc/merlin/merlin.env
BIN=/usr/local/libexec/merlin/merlin
EBPF=/usr/local/libexec/merlin/merlin-ebpf.o
RULES=/etc/merlin/rules.yaml

die() {
  printf 'merlin-launcher: %s\n' "$*" >&2
  exit 78
}

[ "$(id -u)" -eq 0 ] || die 'service must run as root'
[ -f "$CONFIG" ] || die 'configuration is missing'
[ ! -L "$CONFIG" ] || die 'configuration must not be a symbolic link'
[ "$(stat -c %u "$CONFIG")" = "0" ] || die 'configuration owner must be root'
[ "$(stat -c %a "$CONFIG")" = "600" ] || die 'configuration mode must be 0600'
[ "$(stat -c %s "$CONFIG")" -le 16384 ] || die 'configuration exceeds 16 KiB'
[ -x "$BIN" ] || die 'sensor binary is missing'
[ -f "$EBPF" ] && [ ! -L "$EBPF" ] || die 'eBPF object is missing or unsafe'
[ -f "$RULES" ] && [ ! -L "$RULES" ] || die 'rules file is missing or unsafe'

case "${MERLIN_SYNC_URL:-}" in
  https://*) ;;
  *) die 'MERLIN_SYNC_URL must use https' ;;
esac
case "${MERLIN_DEVICE_ID:-}" in
  dev_[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
  *) die 'MERLIN_DEVICE_ID is invalid' ;;
esac
case "${MERLIN_DEVICE_TOKEN:-}" in
  *[!0-9A-Fa-f]*|'') die 'MERLIN_DEVICE_TOKEN must be hexadecimal' ;;
esac
[ "${#MERLIN_DEVICE_TOKEN}" -eq 64 ] || die 'MERLIN_DEVICE_TOKEN must contain 64 hexadecimal characters'
[ -n "${MERLIN_POLICY_PUBLIC_KEYS:-}" ] || die 'MERLIN_POLICY_PUBLIC_KEYS is required'
old_ifs=$IFS
set -f
IFS=,
for policy_key in $MERLIN_POLICY_PUBLIC_KEYS; do
  case "$policy_key" in
    *[!0-9A-Fa-f]*|'') die 'MERLIN_POLICY_PUBLIC_KEYS must contain comma-separated hexadecimal keys' ;;
  esac
  [ "${#policy_key}" -eq 64 ] || die 'each policy public key must contain 64 hexadecimal characters'
done
IFS=$old_ifs
set +f

exec "$BIN" run \
  --ebpf "$EBPF" \
  --rules "$RULES" \
  --spool /var/lib/merlin/merlin-events.jsonl \
  --segment-interval 300 \
  --segment-bytes 8388608 \
  --snapshot-interval 60 \
  --posture-interval 3600 \
  --sync "$MERLIN_SYNC_URL"
