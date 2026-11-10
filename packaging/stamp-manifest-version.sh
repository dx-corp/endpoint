#!/bin/sh
# Sets the collection manifest version for a release build. The release is the
# only writer: main keeps `manifest_version = 0` (a development build) in
# collection-manifest.toml and `static let version = 0` in the macOS
# Manifest.swift, and pull requests never change either. A release build runs
# this on its own checkout before compiling; nothing is committed.
#
# The version is the release's MAJOR.MINOR.PATCH as one number,
# MAJOR*10000 + MINOR*100 + PATCH (merlin-v0.1.3 -> 103), so every platform
# built from one tag reports the same version, later releases report larger
# ones, and no state outside the tag is needed. A pre-release or build suffix
# (0.2.0-rc.1, 0.2.0+linux) uses its core numbers. Each part must be below 100,
# which keeps the result under the servers' bound of 1,000,000.
#
# usage: stamp-manifest-version.sh RELEASE_VERSION [PRODUCT_DIR]
#   RELEASE_VERSION  0.1.3, v0.1.3 or merlin-v0.1.3
#   PRODUCT_DIR      products/deixic-endpoint (default: this script's parent)
set -eu

fail() { printf 'stamp-manifest-version: %s\n' "$1" >&2; exit 64; }

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  fail 'usage: stamp-manifest-version.sh RELEASE_VERSION [PRODUCT_DIR]'
fi
release=$1
product=${2:-$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)}
toml=$product/collection-manifest.toml
swift=$product/macos/Sources/MerlinMacOS/Manifest.swift

core=${release#merlin-}
core=${core#v}
core=${core%%[-+]*}
version=$(printf '%s\n' "$core" | awk -F. '
  NF == 3 && $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $1 < 100 && $2 < 100 && $3 < 100 {
    print $1 * 10000 + $2 * 100 + $3
  }') || true
[ -n "$version" ] || fail "release version $release is not MAJOR.MINOR.PATCH with each part below 100"
[ "$version" -gt 0 ] || fail 'release version 0.0.0 is the development build'

# Each file must hold the placeholder exactly once: a stamped or hand-edited
# checkout is refused rather than silently overwritten.
toml_line='manifest_version = 0'
swift_line='    static let version = 0'
[ "$(grep -c -x -F "$toml_line" "$toml")" = 1 ] || fail "$toml does not hold the placeholder line '$toml_line' exactly once"
[ "$(grep -c -x -F "$swift_line" "$swift")" = 1 ] || fail "$swift does not hold the placeholder line '$swift_line' exactly once"

replace() {
  file=$1 from=$2 to=$3
  awk -v from="$from" -v to="$to" '$0 == from { print to; next } { print }' "$file" > "$file.stamp"
  mv "$file.stamp" "$file"
  [ "$(grep -c -x -F "$to" "$file")" = 1 ] || fail "$file was not stamped"
}
replace "$toml" "$toml_line" "manifest_version = $version"
replace "$swift" "$swift_line" "    static let version = $version"

printf 'manifest_version %s for release %s\n' "$version" "$release"
