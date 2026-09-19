#!/bin/sh
set -eu

[ "$#" -eq 4 ] || { printf 'usage: %s <version> <merlin-binary> <ebpf-object> <output-directory>\n' "$0" >&2; exit 64; }
VERSION=$1
BINARY=$2
EBPF_OBJECT=$3
OUTPUT_DIR=$4
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
REPO_DIR=$(dirname "$(dirname "$SCRIPT_DIR")")

case "$VERSION" in
  ''|*[!0-9A-Za-z._-]*) printf 'invalid package version: %s\n' "$VERSION" >&2; exit 64 ;;
esac
[ -x "$BINARY" ] || { printf 'Deixic Endpoint binary is missing or not executable: %s\n' "$BINARY" >&2; exit 66; }
[ -f "$EBPF_OBJECT" ] || { printf 'eBPF object is missing: %s\n' "$EBPF_OBJECT" >&2; exit 66; }

ARCH=$(uname -m)
case "$ARCH" in
  x86_64|aarch64) ;;
  arm64) ARCH=aarch64 ;;
  *) printf 'unsupported package architecture: %s\n' "$ARCH" >&2; exit 64 ;;
esac

STAGE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/merlin-linux-package.XXXXXX")
trap 'rm -rf "$STAGE_DIR"' EXIT HUP INT TERM
NAME=merlin-$VERSION-linux-$ARCH
ROOT=$STAGE_DIR/$NAME
mkdir -p \
  "$ROOT/payload/usr/local/libexec/merlin" \
  "$ROOT/payload/usr/lib/systemd/system" \
  "$ROOT/payload/etc/merlin" \
  "$OUTPUT_DIR"

install -m 755 "$BINARY" "$ROOT/payload/usr/local/libexec/merlin/merlin"
install -m 644 "$EBPF_OBJECT" "$ROOT/payload/usr/local/libexec/merlin/merlin-ebpf.o"
install -m 755 "$SCRIPT_DIR/merlin-launcher.sh" "$ROOT/payload/usr/local/libexec/merlin/merlin-launcher"
install -m 644 "$SCRIPT_DIR/merlin.service" "$ROOT/payload/usr/lib/systemd/system/merlin.service"
install -m 600 "$SCRIPT_DIR/merlin.env.example" "$ROOT/payload/etc/merlin/merlin.env.example"
install -m 600 "$REPO_DIR/rules/content/linux-lolbins.yaml" "$ROOT/payload/etc/merlin/rules.yaml"
install -m 755 "$SCRIPT_DIR/install.sh" "$ROOT/install.sh"
install -m 755 "$SCRIPT_DIR/uninstall.sh" "$ROOT/uninstall.sh"

ARCHIVE=$OUTPUT_DIR/$NAME.tar.gz
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" -czf "$ARCHIVE" -C "$STAGE_DIR" "$NAME"
printf 'Built Linux package: %s\n' "$ARCHIVE"
