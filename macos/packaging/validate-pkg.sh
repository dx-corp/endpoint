#!/bin/sh
set -eu

[ "$#" -eq 1 ] || { printf 'usage: %s <Merlin.pkg>\n' "$0" >&2; exit 64; }
PACKAGE=$1
[ -f "$PACKAGE" ] || { printf 'package not found: %s\n' "$PACKAGE" >&2; exit 66; }

for tool in pkgutil codesign plutil; do
  command -v "$tool" >/dev/null 2>&1 || { printf 'required tool is missing: %s\n' "$tool" >&2; exit 69; }
done

if pkgutil --payload-files "$PACKAGE" | grep -E '(^|/)\._' >/dev/null; then
  if [ "${MERLIN_REJECT_APPLEDOUBLE:-0}" = "1" ]; then
    printf '%s\n' 'package contains AppleDouble metadata entries' >&2
    exit 65
  fi
  printf '%s\n' 'Package contains AppleDouble metadata entries; rebuild outside a provenance-enforcing workspace for a clean release payload.' >&2
fi

EXPAND_DIR=$(mktemp -d "${TMPDIR:-/tmp}/merlin-pkg-validate.XXXXXX")
trap 'rm -rf "$EXPAND_DIR"' EXIT HUP INT TERM
pkgutil --expand-full "$PACKAGE" "$EXPAND_DIR/expanded"

PAYLOAD_ROOT=$(find "$EXPAND_DIR/expanded" -type d -name Payload -print | head -1)
[ -n "$PAYLOAD_ROOT" ] || { printf '%s\n' 'expanded package has no payload' >&2; exit 65; }

BIN="$PAYLOAD_ROOT/Library/Application Support/Merlin/bin/merlin-macos"
LAUNCHER="$PAYLOAD_ROOT/Library/Application Support/Merlin/bin/merlin-launcher"
RULES="$PAYLOAD_ROOT/Library/Application Support/Merlin/rules/rules.yaml"
PLIST="$PAYLOAD_ROOT/Library/LaunchDaemons/com.evalops.merlin.plist"
CONFIGURE="$PAYLOAD_ROOT/usr/local/sbin/merlin-configure"

for path in "$BIN" "$LAUNCHER" "$RULES" "$PLIST" "$CONFIGURE"; do
  [ -e "$path" ] || { printf 'required payload path is missing: %s\n' "$path" >&2; exit 65; }
done

APP="$PAYLOAD_ROOT/Applications/Deixic Endpoint.app"
[ -x "$APP/Contents/MacOS/MerlinEndpointApp" ] || { printf '%s\n' 'GUI payload missing' >&2; exit 65; }
[ "$(plutil -extract CFBundleIdentifier raw "$APP/Contents/Info.plist")" = com.merlin.agent ]
[ "$(plutil -extract LSUIElement raw "$APP/Contents/Info.plist")" = true ]
[ -d "$APP/Contents/Frameworks/Sparkle.framework" ]
codesign --verify --deep --strict --verbose=2 "$APP"
codesign --verify --strict --verbose=2 "$BIN"
plutil -lint "$PLIST" >/dev/null
sh -n "$LAUNCHER" "$CONFIGURE"

scripts_dir=$(find "$EXPAND_DIR/expanded" -type d -name Scripts -print | head -1)
[ -n "$scripts_dir" ] || { printf '%s\n' 'expanded package has no installer scripts' >&2; exit 65; }
sh -n "$scripts_dir/preinstall" "$scripts_dir/postinstall"

if pkgutil --check-signature "$PACKAGE" >/dev/null 2>&1; then
  pkgutil --check-signature "$PACKAGE"
elif [ "${MERLIN_REQUIRE_SIGNED_PKG:-0}" = "1" ]; then
  printf '%s\n' 'package does not have a valid Installer signature' >&2
  exit 65
else
  printf '%s\n' 'Package is unsigned; structure and payload signature are valid, but production MDM requires an Installer identity.' >&2
fi

printf '%s\n' 'Deixic Endpoint package validation passed.'
