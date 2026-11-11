#!/usr/bin/env bash
# Called only by the protected trusted-main job, after source/artifact admission.
set -euo pipefail
umask 077
[[ $# == 3 ]] || { echo 'usage: notarize-candidate.sh CANDIDATE PACKAGE RECEIPT' >&2; exit 64; }
candidate="$1"
package="$2"
receipt="$3"
[[ ! -e "$receipt" ]] || { echo 'Refusing to replace a notarization receipt.' >&2; exit 73; }
: "${MAESTRO_NOTARY_KEY_P8:?Protected notarization key is required}"
: "${MAESTRO_NOTARY_KEY_ID:?Protected notarization key ID is required}"
: "${MAESTRO_NOTARY_ISSUER_ID:?Protected notarization issuer is required}"
# Dependency builds never run here. Do not pass credential environment values
# even to metadata, hashing, directory creation or staple/validation commands.
export -n MAESTRO_NOTARY_KEY_P8 MAESTRO_NOTARY_KEY_ID MAESTRO_NOTARY_ISSUER_ID
script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
binding="$script_dir/../../packaging/protected-notarization.py"
python3 "$binding" verify-candidate --candidate "$candidate" --package "$package"
submitted_sha="$(shasum -a 256 "$package" | awk '{print $1}')"
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/merlin-notary.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
key="$work/key.p8"
result="$work/result.json"
printf '%s' "$MAESTRO_NOTARY_KEY_P8" > "$key"
unset MAESTRO_NOTARY_KEY_P8
xcrun notarytool submit "$package" --key "$key" \
  --key-id "$MAESTRO_NOTARY_KEY_ID" --issuer "$MAESTRO_NOTARY_ISSUER_ID" \
  --wait --timeout 30m --no-progress --output-format json > "$result"
unset MAESTRO_NOTARY_KEY_ID MAESTRO_NOTARY_ISSUER_ID
python3 "$binding" check-response --response "$result"
xcrun stapler staple "$package"
xcrun stapler validate "$package"
spctl --assess --type install --verbose=2 "$package"
python3 "$binding" receipt --candidate "$candidate" --response "$result" \
  --package "$package" --submitted-sha256 "$submitted_sha" --output "$receipt"
python3 "$binding" verify-receipt --candidate "$candidate" --package "$package" --receipt "$receipt"
echo 'Exact admitted package notarized, stapled and receipt-bound.'
