#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(cd -- "$script_dir/../../../.." && pwd)"
[[ $# == 3 ]] || { echo 'usage: build-appcast.sh VERSION PACKAGE OUTPUT' >&2; exit 64; }
version="$1"
package="$2"
output="$3"
[[ ! -e "$output" ]] || { echo 'Appcast output already exists; refusing replacement.' >&2; exit 73; }
[[ -n "${MERLIN_UPDATE_SIGNING_KEY:-}" && -n "${MERLIN_UPDATE_PUBLIC_KEY:-}" ]] || {
  echo 'Update signing requires MERLIN_UPDATE_SIGNING_KEY and MERLIN_UPDATE_PUBLIC_KEY.' >&2
  exit 64
}
[[ "${MERLIN_UPDATE_FEED_URL:-}" == 'https://github.com/dx-corp/endpoint/releases/latest/download/appcast.xml' ]] || {
  echo 'Update feed must use the published dx-corp/endpoint appcast URL.' >&2
  exit 64
}
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/merlin-appcast.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
printf '%s' "$MERLIN_UPDATE_SIGNING_KEY" > "$work/update-key"
unset MERLIN_UPDATE_SIGNING_KEY
swift -module-cache-path "$work/swift-module-cache" "$script_dir/verify-update-key.swift" \
  "$work/update-key" "$MERLIN_UPDATE_PUBLIC_KEY"

# Same release as the app's exact SwiftPM dependency. The official release asset
# digest pins the native tool; no key is imported into a host keychain.
archive="$work/Sparkle-2.9.6.tar.xz"
bash "$repo_root/scripts/ci/fetch-pinned-tool.sh" \
  --sha256 52bf9e88cdd972fc0c81501377a880e90d47031bd8ca5462488f843e2609e192 \
  --out "$archive" 'https://github.com/sparkle-project/Sparkle/releases/download/2.9.6/Sparkle-2.9.6.tar.xz'
tar -xJf "$archive" -C "$work" ./bin/sign_update
sign_update="$work/bin/sign_update"
"$sign_update" --ed-key-file "$work/update-key" "$package" > "$work/package-signature"
python3 "$script_dir/../../packaging/release-appcast.py" --version "$version" \
  --package "$package" --signature "$work/package-signature" > "$work/appcast.xml"
signature="$(python3 - "$work/appcast.xml" <<'PY'
import sys
import xml.etree.ElementTree as ET
print(ET.parse(sys.argv[1]).find('channel/item/enclosure').get(
    '{http://www.andymatuschak.org/xml-namespaces/sparkle}edSignature'))
PY
)"
"$sign_update" --ed-key-file "$work/update-key" --verify "$package" "$signature"
"$sign_update" --ed-key-file "$work/update-key" "$work/appcast.xml"
"$sign_update" --ed-key-file "$work/update-key" --verify "$work/appcast.xml"
mv -- "$work/appcast.xml" "$output"
