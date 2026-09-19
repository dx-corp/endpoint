#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { printf '%s\n' 'uninstall must run as root' >&2; exit 77; }
purge=false
if [ "${1:-}" = "--purge" ]; then
  purge=true
elif [ "$#" -ne 0 ]; then
  printf 'usage: %s [--purge]\n' "$0" >&2
  exit 64
fi

systemctl disable --now merlin >/dev/null 2>&1 || true
rm -f /usr/lib/systemd/system/merlin.service
rm -f /usr/local/libexec/merlin/merlin /usr/local/libexec/merlin/merlin-ebpf.o /usr/local/libexec/merlin/merlin-launcher
rmdir /usr/local/libexec/merlin >/dev/null 2>&1 || true
systemctl daemon-reload

if [ "$purge" = true ]; then
  rm -f /etc/merlin/merlin.env /etc/merlin/merlin.env.example /etc/merlin/rules.yaml
  rmdir /etc/merlin >/dev/null 2>&1 || true
  rm -rf /var/lib/merlin
  printf '%s\n' 'Deixic Endpoint was removed, including configuration and retained telemetry.'
else
  printf '%s\n' 'Deixic Endpoint was removed; configuration and retained telemetry were preserved. Use --purge to remove them.'
fi
