#!/bin/sh
# SwiftPM's combined --arch mode needs full Xcode's XCBuild. The owned signer
# has Command Line Tools, which support each architecture through SwiftPM.
set -eu
[ "$#" -ge 2 ] || { echo 'usage: build-universal.sh PACKAGE_DIRECTORY ARCH...' >&2; exit 64; }
PACKAGE=$1
shift
ARM=0
INTEL=0
for arch do
  case "$arch" in
    arm64) ARM=1 ;;
    x86_64) INTEL=1 ;;
    *) printf 'unsupported architecture: %s\n' "$arch" >&2; exit 64 ;;
  esac
done
cd "$PACKAGE"
PACKAGE=$(pwd)
ARM_BIN=
INTEL_BIN=
for arch in arm64 x86_64; do
  case "$arch" in
    arm64) [ "$ARM" = 1 ] || continue ;;
    x86_64) [ "$INTEL" = 1 ] || continue ;;
  esac
  # Retain the normal .build/artifacts location for the pinned Sparkle
  # framework and reuse SwiftPM's per-triple build caches. Only the final
  # binary directory is returned on stdout; compiler output stays visible.
  swift build -c release --arch "$arch" >&2
  bin=$(swift build -c release --arch "$arch" --show-bin-path)
  for product in MerlinMacOS MerlinEndpointApp; do
    [ -x "$bin/$product" ] || { printf 'built product missing: %s\n' "$bin/$product" >&2; exit 70; }
    lipo "$bin/$product" -verify_arch "$arch"
  done
  case "$arch" in
    arm64) ARM_BIN=$bin ;;
    x86_64) INTEL_BIN=$bin ;;
  esac
done
if [ "$ARM" = 1 ] && [ "$INTEL" = 1 ]; then
  output=$PACKAGE/.build/merlin-universal-release
  mkdir -p "$output"
  for product in MerlinMacOS MerlinEndpointApp; do
    lipo -create "$ARM_BIN/$product" "$INTEL_BIN/$product" -output "$output/$product"
    chmod 755 "$output/$product"
    lipo "$output/$product" -verify_arch arm64 x86_64
  done
  printf '%s\n' "$output"
elif [ "$ARM" = 1 ]; then
  printf '%s\n' "$ARM_BIN"
else
  printf '%s\n' "$INTEL_BIN"
fi
