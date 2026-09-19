#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
MACOS_DIR=$(dirname "$SCRIPT_DIR")
REPO_DIR=$(dirname "$MACOS_DIR")
VERSION=${MERLIN_PKG_VERSION:-0.1.0}
OUTPUT=${MERLIN_PKG_OUTPUT:-$MACOS_DIR/.build/Merlin-$VERSION.pkg}
CODE_SIGN_IDENTITY=${MERLIN_CODE_SIGN_IDENTITY:--}
INSTALLER_SIGN_IDENTITY=${MERLIN_INSTALLER_SIGN_IDENTITY:-}
ARCHES=${MERLIN_BUILD_ARCHES:-$(uname -m)}
MODE=${MERLIN_RELEASE_MODE:-development}
export MERLIN_PKG_VERSION="$VERSION"
"$SCRIPT_DIR/validate-release-config.sh"

case "$VERSION" in
  ''|*[!0-9A-Za-z._-]*) printf 'invalid package version: %s\n' "$VERSION" >&2; exit 64 ;;
esac

for tool in swift pkgbuild codesign plutil; do
  command -v "$tool" >/dev/null 2>&1 || { printf 'required tool is missing: %s\n' "$tool" >&2; exit 69; }
done

set --
for arch in $ARCHES; do
  case "$arch" in
    arm64|x86_64) set -- "$@" --arch "$arch" ;;
    *) printf 'unsupported architecture: %s\n' "$arch" >&2; exit 64 ;;
  esac
done

printf 'Building Deixic Endpoint for: %s\n' "$ARCHES"
(cd "$MACOS_DIR" && swift build -c release "$@")
BIN_DIR=$(cd "$MACOS_DIR" && swift build -c release "$@" --show-bin-path)
SOURCE_BIN=$BIN_DIR/MerlinMacOS
[ -x "$SOURCE_BIN" ] || { printf 'built binary not found: %s\n' "$SOURCE_BIN" >&2; exit 70; }

STAGE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/merlin-pkg.XXXXXX")
trap 'rm -rf "$STAGE_DIR"' EXIT HUP INT TERM
ROOT_DIR=$STAGE_DIR/root
SCRIPTS_DIR=$STAGE_DIR/scripts

mkdir -p \
  "$ROOT_DIR/Library/Application Support/Merlin/bin" \
  "$ROOT_DIR/Library/Application Support/Merlin/rules" \
  "$ROOT_DIR/Library/LaunchDaemons" \
  "$ROOT_DIR/usr/local/sbin" \
  "$SCRIPTS_DIR" \
  "$(dirname "$OUTPUT")"

install -m 755 "$SOURCE_BIN" "$ROOT_DIR/Library/Application Support/Merlin/bin/merlin-macos"
install -m 755 "$SCRIPT_DIR/merlin-launcher.sh" "$ROOT_DIR/Library/Application Support/Merlin/bin/merlin-launcher"
install -m 644 "$REPO_DIR/rules/content/macos-lolbins.yaml" "$ROOT_DIR/Library/Application Support/Merlin/rules/rules.yaml"
install -m 644 "$SCRIPT_DIR/com.evalops.merlin.plist" "$ROOT_DIR/Library/LaunchDaemons/com.evalops.merlin.plist"
install -m 755 "$SCRIPT_DIR/merlin-configure.sh" "$ROOT_DIR/usr/local/sbin/merlin-configure"
install -m 755 "$SCRIPT_DIR/scripts/preinstall" "$SCRIPTS_DIR/preinstall"
install -m 755 "$SCRIPT_DIR/scripts/postinstall" "$SCRIPTS_DIR/postinstall"

if [ "$CODE_SIGN_IDENTITY" = "-" ]; then
  printf '%s\n' 'Ad-hoc signing sensor binary (development artifact).'
  codesign --force --identifier com.evalops.merlin.collector --sign - "$ROOT_DIR/Library/Application Support/Merlin/bin/merlin-macos"
else
  if [ "${MERLIN_ENDPOINT_SECURITY_ENTITLEMENT:-0}" = "1" ]; then
    if [ "${MERLIN_CODESIGN_TIMESTAMP:-1}" = "1" ]; then
      codesign --force --identifier com.evalops.merlin.collector --options runtime --timestamp --sign "$CODE_SIGN_IDENTITY" --entitlements "$MACOS_DIR/entitlements.plist" "$ROOT_DIR/Library/Application Support/Merlin/bin/merlin-macos"
    else
      codesign --force --identifier com.evalops.merlin.collector --options runtime --timestamp=none --sign "$CODE_SIGN_IDENTITY" --entitlements "$MACOS_DIR/entitlements.plist" "$ROOT_DIR/Library/Application Support/Merlin/bin/merlin-macos"
    fi
  else
    if [ "${MERLIN_CODESIGN_TIMESTAMP:-1}" = "1" ]; then
      codesign --force --identifier com.evalops.merlin.collector --options runtime --timestamp --sign "$CODE_SIGN_IDENTITY" "$ROOT_DIR/Library/Application Support/Merlin/bin/merlin-macos"
    else
      codesign --force --identifier com.evalops.merlin.collector --options runtime --timestamp=none --sign "$CODE_SIGN_IDENTITY" "$ROOT_DIR/Library/Application Support/Merlin/bin/merlin-macos"
    fi
  fi
fi
codesign --verify --strict --verbose=2 "$ROOT_DIR/Library/Application Support/Merlin/bin/merlin-macos"

MERLIN_APP_BINARY="$BIN_DIR/MerlinEndpointApp" MERLIN_APP_OUTPUT="$ROOT_DIR/Applications/Deixic Endpoint.app" \
  "$SCRIPT_DIR/build-app.sh"

# Finder metadata and quarantine xattrs otherwise become `._*` AppleDouble
# payload entries, which are noisy and can make deterministic MDM validation
# fail. The Mach-O code signature is stored in the binary and survives this.
/usr/bin/xattr -cr "$ROOT_DIR" 2>/dev/null || true

if [ -n "$INSTALLER_SIGN_IDENTITY" ]; then
  COPYFILE_DISABLE=1 pkgbuild \
    --root "$ROOT_DIR" \
    --component-plist "$SCRIPT_DIR/EndpointApp.component.plist" \
    --scripts "$SCRIPTS_DIR" \
    --identifier com.evalops.merlin.sensor \
    --version "$VERSION" \
    --install-location / \
    --sign "$INSTALLER_SIGN_IDENTITY" \
    "$OUTPUT"
else
  COPYFILE_DISABLE=1 pkgbuild \
    --root "$ROOT_DIR" \
    --component-plist "$SCRIPT_DIR/EndpointApp.component.plist" \
    --scripts "$SCRIPTS_DIR" \
    --identifier com.evalops.merlin.sensor \
    --version "$VERSION" \
    --install-location / \
    "$OUTPUT"
fi

MERLIN_REQUIRE_SIGNED_PKG=$([ -n "$INSTALLER_SIGN_IDENTITY" ] && printf 1 || printf 0) \
  "$SCRIPT_DIR/validate-pkg.sh" "$OUTPUT"
if [ "$MODE" = "production" ]; then
  xcrun notarytool submit "$OUTPUT" --keychain-profile "$MERLIN_NOTARY_PROFILE" --wait
  xcrun stapler staple "$OUTPUT"
  xcrun stapler validate "$OUTPUT"
  spctl --assess --type install --verbose=2 "$OUTPUT"
fi
printf 'Built Deixic Endpoint package: %s\n' "$OUTPUT"
