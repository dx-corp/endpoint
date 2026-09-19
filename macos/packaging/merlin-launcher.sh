#!/bin/sh
# Root launchd wrapper for Deixic Endpoint. Secrets stay in a root-owned plist and are
# passed through the environment, never launchd ProgramArguments or process
# command lines.
set -eu

PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

BASE_DIR=${MERLIN_BASE_DIR:-/Library/Application Support/Merlin}
CONFIG_PATH=${MERLIN_CONFIG_PATH:-$BASE_DIR/config.plist}
BIN_PATH=${MERLIN_BIN_PATH:-$BASE_DIR/bin/merlin-macos}
RULES_PATH=${MERLIN_RULES_PATH:-$BASE_DIR/rules/rules.yaml}
SPOOL_PATH=${MERLIN_SPOOL_PATH:-$BASE_DIR/spool/merlin-events.jsonl}
EXPECTED_OWNER_UID=${MERLIN_CONFIG_OWNER_UID:-0}

die() {
  printf 'merlin-launcher: %s\n' "$*" >&2
  exit 78
}

plist_value() {
  /usr/bin/plutil -extract "$1" raw -o - "$CONFIG_PATH" 2>/dev/null || return 1
}

validate_config() {
  [ -f "$CONFIG_PATH" ] || die "configuration is missing: $CONFIG_PATH"
  [ ! -L "$CONFIG_PATH" ] || die "configuration must not be a symbolic link"
  /usr/bin/plutil -lint "$CONFIG_PATH" >/dev/null || die "configuration is not a valid plist"

  owner_uid=$(/usr/bin/stat -f '%u' "$CONFIG_PATH")
  mode=$(/usr/bin/stat -f '%Lp' "$CONFIG_PATH")
  size=$(/usr/bin/stat -f '%z' "$CONFIG_PATH")
  [ "$owner_uid" = "$EXPECTED_OWNER_UID" ] || die "configuration owner must be uid $EXPECTED_OWNER_UID"
  [ "$mode" = "600" ] || die "configuration mode must be 600 (found $mode)"
  [ "$size" -le 16384 ] || die "configuration exceeds the 16 KiB size limit"

  SYNC_URL=$(plist_value SyncURL) || die "configuration is missing SyncURL"
  MERLIN_DEVICE_ID=$(plist_value DeviceID) || die "configuration is missing DeviceID"
  MERLIN_DEVICE_TOKEN=$(plist_value DeviceToken) || die "configuration is missing DeviceToken"
  MERLIN_POLICY_PUBLIC_KEYS=$(plist_value PolicyPublicKeys) || die "configuration is missing PolicyPublicKeys"

  case "$SYNC_URL" in
    https://*) ;;
    *) die "SyncURL must use https" ;;
  esac
  case "$MERLIN_DEVICE_ID" in
    dev_[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
    *) die "DeviceID is not a valid Deixic Endpoint device id" ;;
  esac
  case "$MERLIN_DEVICE_TOKEN" in
    *[!0-9A-Fa-f]*|'') die "DeviceToken must be hexadecimal" ;;
  esac
  [ "${#MERLIN_DEVICE_TOKEN}" -eq 64 ] || die "DeviceToken must contain 64 hexadecimal characters"
  [ -n "$MERLIN_POLICY_PUBLIC_KEYS" ] || die "PolicyPublicKeys must contain at least one key"
  old_ifs=$IFS
  IFS=,
  for policy_key in $MERLIN_POLICY_PUBLIC_KEYS; do
    case "$policy_key" in
      *[!0-9A-Fa-f]*|'') die "PolicyPublicKeys must be comma-separated hexadecimal keys" ;;
    esac
    [ "${#policy_key}" -eq 64 ] || die "each PolicyPublicKeys entry must contain 64 hexadecimal characters"
  done
  IFS=$old_ifs

  export MERLIN_DEVICE_ID MERLIN_DEVICE_TOKEN MERLIN_POLICY_PUBLIC_KEYS
}

validate_config

if [ "${1:-}" = "--validate-config" ]; then
  printf '%s\n' 'Deixic Endpoint configuration is valid.'
  exit 0
fi

[ "$(/usr/bin/id -u)" -eq 0 ] || die "the launch daemon must run as root"
[ -x "$BIN_PATH" ] || die "sensor binary is missing or not executable: $BIN_PATH"
[ -f "$RULES_PATH" ] || die "rules file is missing: $RULES_PATH"
[ ! -L "$RULES_PATH" ] || die "rules file must not be a symbolic link"

exec "$BIN_PATH" run \
  --rules "$RULES_PATH" \
  --spool "$SPOOL_PATH" \
  --segment-interval 300 \
  --segment-bytes 8388608 \
  --snapshot-interval 60 \
  --posture-interval 3600 \
  --sync "$SYNC_URL"
