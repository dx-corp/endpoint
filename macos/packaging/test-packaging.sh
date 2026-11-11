#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/merlin-packaging-test.XXXXXX")
trap 'rm -rf "$TEMP_DIR"' EXIT HUP INT TERM

plutil -lint "$SCRIPT_DIR/com.evalops.merlin.plist" "$SCRIPT_DIR/config.example.plist" >/dev/null
sh -n \
  "$SCRIPT_DIR/build-pkg.sh" \
  "$SCRIPT_DIR/validate-pkg.sh" \
  "$SCRIPT_DIR/merlin-launcher.sh" \
  "$SCRIPT_DIR/merlin-configure.sh" \
  "$SCRIPT_DIR/scripts/preinstall" \
  "$SCRIPT_DIR/scripts/postinstall" \
  "$SCRIPT_DIR/uninstall.sh"

cp "$SCRIPT_DIR/config.example.plist" "$TEMP_DIR/config.plist"
plutil -replace DeviceToken -string "$(printf 'b%.0s' $(jot 64 1))" "$TEMP_DIR/config.plist"
plutil -replace PolicyPublicKeys -string "$(printf 'c%.0s' $(jot 64 1)),$(printf 'd%.0s' $(jot 64 1))" "$TEMP_DIR/config.plist"
chmod 600 "$TEMP_DIR/config.plist"
MERLIN_CONFIG_PATH=$TEMP_DIR/config.plist \
MERLIN_CONFIG_OWNER_UID=$(id -u) \
  "$SCRIPT_DIR/merlin-launcher.sh" --validate-config >/dev/null

chmod 644 "$TEMP_DIR/config.plist"
if MERLIN_CONFIG_PATH=$TEMP_DIR/config.plist MERLIN_CONFIG_OWNER_UID=$(id -u) \
  "$SCRIPT_DIR/merlin-launcher.sh" --validate-config >/dev/null 2>&1; then
  printf '%s\n' 'world-readable configuration unexpectedly passed validation' >&2
  exit 1
fi

if grep -Eq 'SyncKey|DeviceToken|MERLIN_SYNC_KEY|MERLIN_DEVICE_TOKEN' "$SCRIPT_DIR/com.evalops.merlin.plist"; then
  printf '%s\n' 'launchd plist must not contain credentials' >&2
  exit 1
fi

plutil -lint "$SCRIPT_DIR/EndpointApp.Info.plist" "$SCRIPT_DIR/EndpointApp.component.plist" "$SCRIPT_DIR/Collector.Info.plist" >/dev/null
plutil -lint "$SCRIPT_DIR/mdm/deixic-endpoint.mobileconfig" "$SCRIPT_DIR/mdm/deixic-endpoint-network-filter.mobileconfig" >/dev/null
[ "$(plutil -extract CFBundleIdentifier raw "$SCRIPT_DIR/Collector.Info.plist")" = com.evalops.merlin.collector ]
sh -n "$SCRIPT_DIR/build-app.sh" "$SCRIPT_DIR/validate-release-config.sh"
bash -n "$SCRIPT_DIR/build-appcast.sh" "$SCRIPT_DIR/test-update-signing.sh"
bash "$SCRIPT_DIR/test-update-signing.sh"
python3 "$SCRIPT_DIR/../../packaging/test-universal-build.py"
# Exercise the actual bundle writer without rebuilding or launching the GUI.
# The Mach-O stand-in and framework copy are signed ad hoc inside this fixture.
SPARKLE_CACHE=${EVALOPS_TOOL_CACHE:-${RUNNER_TOOL_CACHE:+${RUNNER_TOOL_CACHE}/evalops-tools}}
SPARKLE_CACHE=${SPARKLE_CACHE:-$HOME/.cache/evalops-tools}
tar -xJf "$SPARKLE_CACHE/52bf9e88cdd972fc0c81501377a880e90d47031bd8ca5462488f843e2609e192" \
  -C "$TEMP_DIR" ./Sparkle.framework
MERLIN_RELEASE_MODE=development MERLIN_CODE_SIGN_IDENTITY=- MERLIN_NATIVE_SIGN_IN_ENABLED=0 \
MERLIN_APP_BINARY=/usr/bin/true MERLIN_APP_OUTPUT="$TEMP_DIR/fixture.app" \
MERLIN_SPARKLE_FRAMEWORK="$TEMP_DIR/Sparkle.framework" \
MERLIN_UPDATE_FEED_URL=https://github.com/dx-corp/endpoint/releases/latest/download/appcast.xml \
MERLIN_UPDATE_PUBLIC_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
  "$SCRIPT_DIR/build-app.sh"
[ "$(plutil -extract SURequireSignedFeed raw "$TEMP_DIR/fixture.app/Contents/Info.plist")" = true ]
[ "$(plutil -extract SUEnableAutomaticChecks raw "$TEMP_DIR/fixture.app/Contents/Info.plist")" = true ]
[ "$(plutil -extract MachServices.com\.evalops\.merlin\.status raw "$SCRIPT_DIR/com.evalops.merlin.plist" 2>/dev/null || true)" = true ] ||
  /usr/libexec/PlistBuddy -c 'Print :MachServices:com.evalops.merlin.status' "$SCRIPT_DIR/com.evalops.merlin.plist" | grep -q true
if MERLIN_RELEASE_MODE=production MERLIN_CODE_SIGN_IDENTITY=- "$SCRIPT_DIR/validate-release-config.sh" >/dev/null 2>&1; then
  printf '%s\n' 'Production accepted ad-hoc signing' >&2; exit 1
fi
if MERLIN_RELEASE_MODE=production MERLIN_CODE_SIGN_IDENTITY='Developer ID Application: Test (TEAMID0000)' \
  MERLIN_INSTALLER_SIGN_IDENTITY='Developer ID Installer: Test (TEAMID0000)' MERLIN_NOTARY_PROFILE=test \
  MERLIN_UPDATE_FEED_URL=https://updates.invalid/appcast.xml MERLIN_UPDATE_PUBLIC_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
  MERLIN_ENDPOINT_SECURITY_ENTITLEMENT=1 MERLIN_COLLECTOR_PROVISIONING_PROFILE='' \
  "$SCRIPT_DIR/validate-release-config.sh" >/dev/null 2>&1; then
  printf '%s\n' 'Production accepted Endpoint Security without a provisioning profile' >&2; exit 1
fi
if MERLIN_UPDATE_FEED_URL=http://invalid.test MERLIN_UPDATE_PUBLIC_KEY=bad "$SCRIPT_DIR/validate-release-config.sh" >/dev/null 2>&1; then
  printf '%s\n' 'Updates accepted insecure feed/key' >&2; exit 1
fi
if MERLIN_UPDATE_FEED_URL=https://invalid.test MERLIN_UPDATE_PUBLIC_KEY= "$SCRIPT_DIR/validate-release-config.sh" >/dev/null 2>&1; then
  printf '%s\n' 'Updates accepted missing key' >&2; exit 1
fi
for invalid in missing-resource missing-tenant malformed-tenant; do
  resource=https://merlin.dx-corp.net
  organization=org_test
  workspace=workspace_test
  case "$invalid" in
    missing-resource) resource= ;;
    missing-tenant) workspace= ;;
    malformed-tenant) organization='org test' ;;
  esac
  if MERLIN_NATIVE_SIGN_IN_ENABLED=1 MERLIN_OAUTH_RESOURCE="$resource" MERLIN_ORGANIZATION_ID="$organization" MERLIN_WORKSPACE_ID="$workspace" "$SCRIPT_DIR/validate-release-config.sh" >/dev/null 2>&1; then
    printf 'Native sign-in accepted %s\n' "$invalid" >&2; exit 1
  fi
done
MERLIN_NATIVE_SIGN_IN_ENABLED=1 MERLIN_OAUTH_RESOURCE=https://merlin.dx-corp.net MERLIN_ORGANIZATION_ID=org_test MERLIN_WORKSPACE_ID=workspace_test "$SCRIPT_DIR/validate-release-config.sh"
printf '%s\n' 'macOS packaging tests passed.'
