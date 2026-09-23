#!/bin/sh
# Installs a device-specific Deixic Endpoint plist without exposing credentials in argv.
# MDM should create a 0600 temporary plist, invoke this tool, then remove it.
set -eu

PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

BASE_DIR=/Library/Application Support/Merlin
CONFIG_PATH=$BASE_DIR/config.plist
LAUNCHD_PLIST=/Library/LaunchDaemons/com.evalops.merlin.plist
LABEL=com.evalops.merlin
LAUNCHER=$BASE_DIR/bin/merlin-launcher

usage() {
  printf '%s\n' "usage: $0 install <source.plist> | status | verify | start | stop" >&2
  exit 64
}

require_root() {
  [ "$(id -u)" -eq 0 ] || { printf '%s\n' 'merlin-configure must run as root' >&2; exit 77; }
}

bootout() {
  launchctl bootout "system/$LABEL" >/dev/null 2>&1 || true
}

require_root
command=${1:-}
case "$command" in
  install)
    [ "$#" -eq 2 ] || usage
    source_path=$2
    [ -f "$source_path" ] || { printf 'configuration not found: %s\n' "$source_path" >&2; exit 66; }
    [ ! -L "$source_path" ] || { printf '%s\n' 'configuration source must not be a symbolic link' >&2; exit 65; }
    mkdir -p "$BASE_DIR"
    temp_path=$BASE_DIR/.config.plist.new
    trap 'rm -f "$temp_path"' EXIT HUP INT TERM
    install -o root -g wheel -m 600 "$source_path" "$temp_path"
    MERLIN_CONFIG_PATH=$temp_path "$LAUNCHER" --validate-config >/dev/null
    mv -f "$temp_path" "$CONFIG_PATH"
    chown root:wheel "$CONFIG_PATH"
    chmod 600 "$CONFIG_PATH"
    trap - EXIT HUP INT TERM
    bootout
    launchctl bootstrap system "$LAUNCHD_PLIST"
    launchctl kickstart -k "system/$LABEL"
    printf '%s\n' 'Deixic Endpoint configuration installed and service started.'
    ;;
  status)
    [ "$#" -eq 1 ] || usage
    if [ -f "$CONFIG_PATH" ]; then
      "$LAUNCHER" --validate-config
    else
      printf '%s\n' 'Deixic Endpoint configuration is not installed.'
    fi
    launchctl print "system/$LABEL" 2>/dev/null | sed -n '1,30p' || true
    ;;
  verify)
    [ "$#" -eq 1 ] || usage
    pkgutil --pkg-info com.evalops.merlin.sensor >/dev/null 2>&1 || {
      printf '%s\n' 'Deixic Endpoint package receipt is missing.' >&2; exit 1;
    }
    [ -f "$CONFIG_PATH" ] && [ ! -L "$CONFIG_PATH" ] || {
      printf '%s\n' 'Deixic Endpoint configuration is missing or linked.' >&2; exit 1;
    }
    [ "$(stat -f '%Su:%Sg:%Lp' "$CONFIG_PATH")" = 'root:wheel:600' ] || {
      printf '%s\n' 'Deixic Endpoint configuration ownership or mode is invalid.' >&2; exit 1;
    }
    "$LAUNCHER" --validate-config >/dev/null || {
      printf '%s\n' 'Deixic Endpoint configuration is invalid.' >&2; exit 1;
    }
    service_state=$(launchctl print "system/$LABEL" 2>/dev/null) || {
      printf '%s\n' 'Deixic Endpoint launch daemon is not loaded.' >&2; exit 1;
    }
    printf '%s\n' "$service_state" | grep -Eq '^[[:space:]]*state = running$' || {
      printf '%s\n' 'Deixic Endpoint launch daemon is not running.' >&2; exit 1;
    }
    printf '%s\n' 'Deixic Endpoint package, configuration, and launch daemon verified.'
    ;;
  start)
    [ "$#" -eq 1 ] || usage
    "$LAUNCHER" --validate-config >/dev/null
    bootout
    launchctl bootstrap system "$LAUNCHD_PLIST"
    launchctl kickstart -k "system/$LABEL"
    ;;
  stop)
    [ "$#" -eq 1 ] || usage
    bootout
    ;;
  *) usage ;;
esac
