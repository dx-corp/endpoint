#!/bin/sh
# Build merlin-macos (release + debug) and codesign both, attempting the
# Endpoint Security client entitlement.
#
# The entitlement is restricted. codesign will happily EMBED it, but the
# kernel (taskgated/amfi) only lets the process exec if a provisioning
# profile associated with the signing identity actually grants it. On an
# account without the ES grant the signed binary is killed at exec
# (SIGKILL; amfid logs "No matching profile found"). This script detects
# that with a launch smoke-test and falls back to a signature WITHOUT the
# entitlement, which keeps the binary usable for check/gen-hash/BSM — the
# ES provider will then report "not entitled" at `merlin-macos check`.
set -u
cd "$(dirname "$0")"

# Override this in CI or on another developer machine.  Keeping the local
# default preserves the existing one-command development build without making
# the packaging pipeline depend on one hard-coded identity.
IDENTITY="${MERLIN_CODE_SIGN_IDENTITY:-Apple Development: Jonathan Haas (ANKL75WYGW)}"

set -e
echo "==> swift build -c release"
swift build -c release
echo "==> swift build (debug)"
swift build
set +e

sign() {
    bin="$1"
    echo "==> codesign $bin (with ES entitlement)"
    if codesign --force --sign "$IDENTITY" --entitlements entitlements.plist --timestamp=none "$bin"; then
        if "$bin" --help >/dev/null 2>&1; then
            echo "    signed OK and launches — entitlement is backed by a provisioning profile"
            return 0
        fi
        echo "    signed, but AMFI killed it at exec: this identity has no provisioning"
        echo "    profile granting com.apple.developer.endpoint-security.client."
        echo "    Re-signing WITHOUT the entitlement so the binary stays usable"
        echo "    (check/gen-hash/BSM provider work; ES provider reports 'not entitled')."
    else
        echo "    codesign with entitlement failed; re-signing without it."
    fi
    codesign --force --sign "$IDENTITY" --timestamp=none "$bin" \
        && echo "    re-signed without ES entitlement"
}

sign .build/release/MerlinMacOS
sign .build/debug/MerlinMacOS

echo "==> signature + embedded entitlements (release binary)"
codesign -d --entitlements - .build/release/MerlinMacOS 2>&1 || true
