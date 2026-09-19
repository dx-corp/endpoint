#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname "$0")" && pwd)
gate="$script_dir/inspect-projection-state.sh"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/projection-state-test.XXXXXX")
trap 'rm -rf "$scratch"' EXIT HUP INT TERM

make_bootstrap() {
  root=$1
  git init -q -b main "$root"
  git -C "$root" config user.name 'Projection validation test'
  git -C "$root" config user.email 'projection-validation@example.invalid'
  printf '# bootstrap\n' > "$root/README.md"
  git -C "$root" add README.md
  git -C "$root" commit -q -m bootstrap
}

bootstrap="$scratch/bootstrap"
make_bootstrap "$bootstrap"
bootstrap_output="$scratch/bootstrap-output"
(
  cd "$bootstrap"
  GITHUB_OUTPUT="$bootstrap_output" bash "$gate"
)
grep -Fx 'present=false' "$bootstrap_output" >/dev/null

unreceipted="$scratch/unreceipted"
make_bootstrap "$unreceipted"
mkdir "$unreceipted/src"
printf 'console.log("unreceipted");\n' > "$unreceipted/src/code.js"
if (
  cd "$unreceipted"
  bash "$gate"
) >"$scratch/unreceipted-output" 2>"$scratch/unreceipted-error"; then
  printf 'Unreceipted payload unexpectedly passed.\n' >&2
  exit 1
fi
grep -F 'Projection payload exists without provenance' "$scratch/unreceipted-error" >/dev/null

removed="$scratch/removed"
make_bootstrap "$removed"
printf '{}\n' > "$removed/.repository-projection.json"
mkdir "$removed/src"
printf 'console.log("projected");\n' > "$removed/src/code.js"
git -C "$removed" add .repository-projection.json src/code.js
git -C "$removed" commit -q -m projection
projection_base=$(git -C "$removed" rev-parse HEAD)
git -C "$removed" rm -q .repository-projection.json src/code.js
git -C "$removed" commit -q -m remove-projection
if (
  cd "$removed"
  PROJECTION_BASE_SHA="$projection_base" bash "$gate"
) >"$scratch/removed-output" 2>"$scratch/removed-error"; then
  printf 'Removed projection receipt unexpectedly passed.\n' >&2
  exit 1
fi
grep -F 'Projection provenance existed in the comparison base' "$scratch/removed-error" >/dev/null

printf 'Projection state gate tests passed.\n'
