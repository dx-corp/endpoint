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
