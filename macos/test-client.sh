#!/bin/sh
# XCTest runs outside the app bundle, so its runner needs the resolved binary
# framework directory as a test-only rpath. Release apps use Contents/Frameworks.
set -eu
MACOS_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
cd "$MACOS_DIR"
swift package resolve
FRAMEWORK=$(find "$MACOS_DIR/.build/artifacts/sparkle" -path '*/macos-arm64_x86_64/Sparkle.framework' -type d -print -quit)
[ -d "$FRAMEWORK" ] || { printf '%s\n' 'Pinned Sparkle framework was not resolved.' >&2; exit 66; }
swift test -Xlinker -rpath -Xlinker "$(dirname "$FRAMEWORK")" "$@"
