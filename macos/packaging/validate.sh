#!/bin/sh

set -eu

if [ "$#" -ne 1 ]; then
	printf '%s\n' "usage: $0 <signed .app or .systemextension>" >&2
	exit 64
fi

BUNDLE_PATH=$1
if [ ! -d "$BUNDLE_PATH" ]; then
	printf 'bundle not found: %s\n' "$BUNDLE_PATH" >&2
	exit 66
fi

printf 'Verifying code signature: %s\n' "$BUNDLE_PATH"
codesign --verify --deep --strict --verbose=2 "$BUNDLE_PATH"

printf '%s\n' 'Embedded entitlements:'
codesign -d --entitlements :- "$BUNDLE_PATH"

if command -v spctl >/dev/null 2>&1; then
	printf 'Assessing execution policy: %s\n' "$BUNDLE_PATH"
	spctl --assess --type execute --verbose=2 "$BUNDLE_PATH"
else
	printf '%s\n' 'spctl is unavailable; execution-policy assessment was skipped.' >&2
fi

printf '%s\n' 'Bundle validation passed.'
