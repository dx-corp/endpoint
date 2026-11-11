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
# Optional: the keychain holding the signing identities (CI unlocks a
# dedicated one), and the collector's Developer ID provisioning profile.
SIGNING_KEYCHAIN=${MERLIN_SIGNING_KEYCHAIN:-}
COLLECTOR_PROFILE=${MERLIN_COLLECTOR_PROVISIONING_PROFILE:-}
COLLECTOR_ID=com.evalops.merlin.collector
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
# A production package carries its release's collection manifest version; the
# release is the only writer (main carries 0, a development build). The
# checkout is put back once the collector is compiled, so nothing is committed.
MANIFEST_SWIFT=$MACOS_DIR/Sources/MerlinMacOS/Manifest.swift
MANIFEST_TOML=$REPO_DIR/collection-manifest.d/settings.toml
if [ "$MODE" = "production" ]; then
  MANIFEST_BACKUP=$(mktemp -d "${TMPDIR:-/tmp}/merlin-manifest.XXXXXX")
  cp "$MANIFEST_SWIFT" "$MANIFEST_BACKUP/Manifest.swift"
  cp "$MANIFEST_TOML" "$MANIFEST_BACKUP/settings.toml"
  trap 'cp "$MANIFEST_BACKUP/Manifest.swift" "$MANIFEST_SWIFT"; cp "$MANIFEST_BACKUP/settings.toml" "$MANIFEST_TOML"; rm -rf "$MANIFEST_BACKUP"' EXIT HUP INT TERM
  "$REPO_DIR/packaging/stamp-manifest-version.sh" "$VERSION" "$REPO_DIR"
fi
(cd "$MACOS_DIR" && swift build -c release "$@")
BIN_DIR=$(cd "$MACOS_DIR" && swift build -c release "$@" --show-bin-path)
if [ "$MODE" = "production" ]; then
  cp "$MANIFEST_BACKUP/Manifest.swift" "$MANIFEST_SWIFT"
  cp "$MANIFEST_BACKUP/settings.toml" "$MANIFEST_TOML"
  rm -rf "$MANIFEST_BACKUP"
  trap - EXIT HUP INT TERM
fi
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

# The collector lives in an app-like bundle: only a bundle can carry the
# provisioning profile that backs its restricted Endpoint Security
# entitlement. bin/merlin-macos stays as a link for MCP hooks and operators.
COLLECTOR_APP="$ROOT_DIR/Library/Application Support/Merlin/MerlinCollector.app"
mkdir -p "$COLLECTOR_APP/Contents/MacOS"
install -m 755 "$SOURCE_BIN" "$COLLECTOR_APP/Contents/MacOS/merlin-macos"
install -m 644 "$SCRIPT_DIR/Collector.Info.plist" "$COLLECTOR_APP/Contents/Info.plist"
plutil -replace CFBundleVersion -string "$VERSION" "$COLLECTOR_APP/Contents/Info.plist"
plutil -replace CFBundleShortVersionString -string "$VERSION" "$COLLECTOR_APP/Contents/Info.plist"
ln -s ../MerlinCollector.app/Contents/MacOS/merlin-macos "$ROOT_DIR/Library/Application Support/Merlin/bin/merlin-macos"
install -m 755 "$SCRIPT_DIR/merlin-launcher.sh" "$ROOT_DIR/Library/Application Support/Merlin/bin/merlin-launcher"
install -m 644 "$REPO_DIR/rules/content/macos-lolbins.yaml" "$ROOT_DIR/Library/Application Support/Merlin/rules/rules.yaml"
install -m 644 "$SCRIPT_DIR/com.evalops.merlin.plist" "$ROOT_DIR/Library/LaunchDaemons/com.evalops.merlin.plist"
install -m 755 "$SCRIPT_DIR/merlin-configure.sh" "$ROOT_DIR/usr/local/sbin/merlin-configure"
install -m 755 "$SCRIPT_DIR/scripts/preinstall" "$SCRIPTS_DIR/preinstall"
install -m 755 "$SCRIPT_DIR/scripts/postinstall" "$SCRIPTS_DIR/postinstall"

COLLECTOR_ENTITLEMENTS=
if [ "${MERLIN_ENDPOINT_SECURITY_ENTITLEMENT:-0}" = "1" ]; then
  COLLECTOR_ENTITLEMENTS=$MACOS_DIR/entitlements.plist
fi
if [ -n "$COLLECTOR_PROFILE" ]; then
  # The profile must be the collector's and must grant Endpoint Security, or
  # AMFI kills the daemon at exec. The signature names the same App ID and
  # team as the profile, as Xcode would.
  PROFILE_PLIST=$STAGE_DIR/collector-profile.plist
  security cms -D -i "$COLLECTOR_PROFILE" > "$PROFILE_PLIST" ||
    { printf 'cannot decode collector provisioning profile: %s\n' "$COLLECTOR_PROFILE" >&2; exit 65; }
  PROFILE_TEAM=$(plutil -extract TeamIdentifier.0 raw "$PROFILE_PLIST")
  PROFILE_APP_ID=$(plutil -extract 'Entitlements.com\.apple\.application-identifier' raw "$PROFILE_PLIST")
  [ "$PROFILE_APP_ID" = "$PROFILE_TEAM.$COLLECTOR_ID" ] ||
    { printf 'collector profile is for %s, not %s.%s\n' "$PROFILE_APP_ID" "$PROFILE_TEAM" "$COLLECTOR_ID" >&2; exit 65; }
  [ "$(plutil -extract 'Entitlements.com\.apple\.developer\.endpoint-security\.client' raw "$PROFILE_PLIST" 2>/dev/null)" = true ] ||
    { printf '%s\n' 'collector profile does not grant com.apple.developer.endpoint-security.client' >&2; exit 65; }
  if [ "$MODE" = "production" ]; then
    [ "$(plutil -extract ProvisionsAllDevices raw "$PROFILE_PLIST" 2>/dev/null)" = true ] ||
      { printf '%s\n' 'production needs a Developer ID profile (ProvisionsAllDevices), not a development profile' >&2; exit 65; }
  fi
  install -m 644 "$COLLECTOR_PROFILE" "$COLLECTOR_APP/Contents/embedded.provisionprofile"
  COLLECTOR_ENTITLEMENTS=$STAGE_DIR/collector.entitlements
  cp "$MACOS_DIR/entitlements.plist" "$COLLECTOR_ENTITLEMENTS"
  plutil -insert 'com\.apple\.application-identifier' -string "$PROFILE_APP_ID" "$COLLECTOR_ENTITLEMENTS"
  plutil -insert 'com\.apple\.developer\.team-identifier' -string "$PROFILE_TEAM" "$COLLECTOR_ENTITLEMENTS"
fi

set -- --force --identifier "$COLLECTOR_ID"
if [ "$CODE_SIGN_IDENTITY" = "-" ]; then
  printf '%s\n' 'Ad-hoc signing sensor binary (development artifact).'
  set -- "$@" --sign -
else
  set -- "$@" --options runtime --sign "$CODE_SIGN_IDENTITY"
  if [ "${MERLIN_CODESIGN_TIMESTAMP:-1}" = "1" ]; then set -- "$@" --timestamp; else set -- "$@" --timestamp=none; fi
  [ -z "$SIGNING_KEYCHAIN" ] || set -- "$@" --keychain "$SIGNING_KEYCHAIN"
  [ -z "$COLLECTOR_ENTITLEMENTS" ] || set -- "$@" --entitlements "$COLLECTOR_ENTITLEMENTS"
fi
codesign "$@" "$COLLECTOR_APP"
codesign --verify --strict --verbose=2 "$COLLECTOR_APP"

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
    ${SIGNING_KEYCHAIN:+--keychain "$SIGNING_KEYCHAIN"} \
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
  xcrun notarytool submit "$OUTPUT" --keychain-profile "$MERLIN_NOTARY_PROFILE" \
    ${SIGNING_KEYCHAIN:+--keychain "$SIGNING_KEYCHAIN"} --wait
  xcrun stapler staple "$OUTPUT"
  xcrun stapler validate "$OUTPUT"
  spctl --assess --type install --verbose=2 "$OUTPUT"
fi
printf 'Built Deixic Endpoint package: %s\n' "$OUTPUT"
