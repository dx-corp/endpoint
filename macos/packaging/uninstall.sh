#!/bin/sh
# Deliberately preserves the device credential plist unless --purge is given.
set -eu

[ "$(id -u)" -eq 0 ] || { printf '%s\n' 'uninstall must run as root' >&2; exit 77; }

purge=false
if [ "${1:-}" = "--purge" ]; then
  purge=true
elif [ "$#" -ne 0 ]; then
  printf 'usage: %s [--purge]\n' "$0" >&2
  exit 64
fi

launchctl bootout system/com.evalops.merlin >/dev/null 2>&1 || true
rm -f /Library/LaunchDaemons/com.evalops.merlin.plist /usr/local/sbin/merlin-configure
rm -rf '/Library/Application Support/Merlin/bin' '/Library/Application Support/Merlin/rules'
rm -rf "/Applications/Deixic Endpoint.app"
if [ "$purge" = true ]; then
  rm -rf '/Library/Application Support/Merlin' '/Library/Logs/Merlin'
  printf '%s\n' 'Deixic Endpoint was removed, including credentials, spool, and logs.'
else
  printf '%s\n' 'Deixic Endpoint was removed; credentials, spool, and logs were preserved. Use --purge to remove them.'
fi
