#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { printf '%s\n' 'install must run as root' >&2; exit 77; }

PACKAGE_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
PAYLOAD=$PACKAGE_DIR/payload
for path in \
  "$PAYLOAD/usr/local/libexec/merlin/merlin" \
  "$PAYLOAD/usr/local/libexec/merlin/merlin-ebpf.o" \
  "$PAYLOAD/usr/local/libexec/merlin/merlin-launcher" \
  "$PAYLOAD/etc/merlin/rules.yaml" \
  "$PAYLOAD/etc/merlin/merlin.env.example" \
  "$PAYLOAD/usr/lib/systemd/system/merlin.service"; do
  [ -f "$path" ] || { printf 'package payload is missing: %s\n' "$path" >&2; exit 65; }
  [ ! -L "$path" ] || { printf 'package payload must not contain a symbolic link: %s\n' "$path" >&2; exit 65; }
done

# An administrator-level unit or drop-in overrides the packaged unit in
# /usr/lib: systemd would load /etc/systemd/system/merlin.service (or merge
# merlin.service.d/*.conf) and keep running whatever it names. dev-desktop,
# 2026-11-09: an older /opt/merlin install's unit and a 10-tracing-mount.conf
# drop-in made the service run the old binary after a successful enrollment.
# Stop and say exactly what to move aside; MERLIN_INSTALL_MIGRATE_UNITS=1 moves
# them into /etc/merlin/superseded-units/<time>/ instead.
shadowing=''
for path in /etc/systemd/system/merlin.service /etc/systemd/system/merlin.service.d/*.conf; do
  [ -e "$path" ] || [ -L "$path" ] || continue
  shadowing="$shadowing $path"
done
if [ -n "$shadowing" ]; then
  if [ "${MERLIN_INSTALL_MIGRATE_UNITS:-0}" = 1 ]; then
    superseded=/etc/merlin/superseded-units/$(date -u +%Y%m%dT%H%M%SZ)
    install -d -o root -g root -m 700 /etc/merlin "$superseded"
    for path in $shadowing; do
      mv -- "$path" "$superseded/"
      printf 'moved %s to %s\n' "$path" "$superseded/"
    done
    rmdir /etc/systemd/system/merlin.service.d 2>/dev/null || true
  else
    printf '%s\n' 'Deixic Endpoint install stopped: systemd would override the packaged unit with:' >&2
    for path in $shadowing; do printf '  %s\n' "$path" >&2; done
    printf '%s\n' 'Move them aside and retry, for example:' >&2
    for path in $shadowing; do printf '  sudo mv %s %s.superseded\n' "$path" "$path" >&2; done
    printf '%s\n' 'or run again with MERLIN_INSTALL_MIGRATE_UNITS=1 to move them into /etc/merlin/superseded-units/.' >&2
    exit 70
  fi
fi

install -d -o root -g root -m 755 /usr/local/libexec/merlin /etc/merlin /usr/lib/systemd/system
install -d -o root -g root -m 700 /var/lib/merlin
install -o root -g root -m 755 "$PAYLOAD/usr/local/libexec/merlin/merlin" /usr/local/libexec/merlin/merlin
install -o root -g root -m 644 "$PAYLOAD/usr/local/libexec/merlin/merlin-ebpf.o" /usr/local/libexec/merlin/merlin-ebpf.o
install -o root -g root -m 755 "$PAYLOAD/usr/local/libexec/merlin/merlin-launcher" /usr/local/libexec/merlin/merlin-launcher
install -o root -g root -m 644 "$PAYLOAD/usr/lib/systemd/system/merlin.service" /usr/lib/systemd/system/merlin.service

if [ ! -e /etc/merlin/rules.yaml ]; then
  install -o root -g root -m 600 "$PAYLOAD/etc/merlin/rules.yaml" /etc/merlin/rules.yaml
fi
if [ ! -e /etc/merlin/merlin.env.example ]; then
  install -o root -g root -m 600 "$PAYLOAD/etc/merlin/merlin.env.example" /etc/merlin/merlin.env.example
fi

systemctl daemon-reload
printf '%s\n' 'Deixic Endpoint is installed but not started.'
printf '%s\n' 'Create /etc/merlin/merlin.env with mode 0600, then run: systemctl enable --now merlin'
