#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
MACOS_DIR=$(dirname "$SCRIPT_DIR")
"$SCRIPT_DIR/validate-release-config.sh"
BINARY=${MERLIN_APP_BINARY:-$MACOS_DIR/.build/release/MerlinEndpointApp}
APP=${MERLIN_APP_OUTPUT:-$MACOS_DIR/.build/Deixic Endpoint.app}
IDENTITY=${MERLIN_CODE_SIGN_IDENTITY:--}
VERSION=${MERLIN_PKG_VERSION:-0.1.0}
[ -x "$BINARY" ] || { printf 'GUI binary not found: %s\n' "$BINARY" >&2; exit 66; }
[ ! -e "$APP" ] || { printf 'App output already exists: %s\n' "$APP" >&2; exit 73; }
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Frameworks"
install -m 755 "$BINARY" "$APP/Contents/MacOS/MerlinEndpointApp"
install -m 644 "$SCRIPT_DIR/EndpointApp.Info.plist" "$APP/Contents/Info.plist"
plutil -replace CFBundleVersion -string "$VERSION" "$APP/Contents/Info.plist"
plutil -replace CFBundleShortVersionString -string "$VERSION" "$APP/Contents/Info.plist"
if [ -n "${MERLIN_UPDATE_FEED_URL:-}" ]; then
  plutil -insert SUFeedURL -string "$MERLIN_UPDATE_FEED_URL" "$APP/Contents/Info.plist"
  plutil -insert SUPublicEDKey -string "$MERLIN_UPDATE_PUBLIC_KEY" "$APP/Contents/Info.plist"
  plutil -replace SUEnableAutomaticChecks -bool YES "$APP/Contents/Info.plist"
fi
if [ "${MERLIN_NATIVE_SIGN_IN_ENABLED:-0}" = 1 ]; then
  plutil -insert MerlinNativeSignInEnabled -bool YES "$APP/Contents/Info.plist"
  plutil -insert MerlinOrganizationID -string "$MERLIN_ORGANIZATION_ID" "$APP/Contents/Info.plist"
  plutil -insert MerlinWorkspaceID -string "$MERLIN_WORKSPACE_ID" "$APP/Contents/Info.plist"
  plutil -insert MerlinOAuthResource -string "$MERLIN_OAUTH_RESOURCE" "$APP/Contents/Info.plist"
fi
FRAMEWORK=${MERLIN_SPARKLE_FRAMEWORK:-$(find "$MACOS_DIR/.build/artifacts" -path '*/macos-arm64_x86_64/Sparkle.framework' -type d -print -quit)}
[ -d "$FRAMEWORK" ] || { printf '%s\n' 'Resolved Sparkle.framework missing; resolve/build the pinned SwiftPM dependency first.' >&2; exit 66; }
ditto "$FRAMEWORK" "$APP/Contents/Frameworks/Sparkle.framework"
# Preserve vendor helper entitlements and identifiers; re-sign inside-out so
# hardened runtime library validation sees one distribution team throughout.
find "$APP/Contents/Frameworks" -depth \( -type f -perm -111 -o -name '*.xpc' -o -name '*.app' -o -name '*.framework' \) -print | while IFS= read -r code; do
  if codesign -d "$code" >/dev/null 2>&1; then
    if [ "$IDENTITY" = - ]; then
      codesign --force --sign - --preserve-metadata=identifier,entitlements "$code"
    else
      codesign --force --sign "$IDENTITY" --options runtime --timestamp --preserve-metadata=identifier,entitlements "$code"
    fi
  fi
done
if [ "$IDENTITY" = - ]; then
  codesign --force --sign - --identifier com.merlin.agent "$APP"
else
  codesign --force --sign "$IDENTITY" --options runtime --timestamp --identifier com.merlin.agent "$APP"
fi
codesign --verify --deep --strict --verbose=2 "$APP"
printf 'Built Deixic Endpoint app: %s\n' "$APP"
