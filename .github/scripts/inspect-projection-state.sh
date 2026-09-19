#!/usr/bin/env bash
set -euo pipefail

write_output() {
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf '%s\n' "$1" >> "$GITHUB_OUTPUT"
  else
    printf '%s\n' "$1"
  fi
}

if [[ -f .repository-projection.json ]]; then
  write_output 'present=true'
  exit 0
fi

base_sha="${PROJECTION_BASE_SHA:-}"
if [[ -n "$base_sha" && "$base_sha" != '0000000000000000000000000000000000000000' ]]; then
  if [[ ! "$base_sha" =~ ^[0-9a-f]{40}$ ]]; then
    printf 'Projection comparison base is not a commit SHA: %s\n' "$base_sha" >&2
    exit 1
  fi
  if ! git cat-file -e "${base_sha}^{commit}" 2>/dev/null; then
    printf 'Projection comparison base is unavailable: %s\n' "$base_sha" >&2
    exit 1
  fi
  if git cat-file -e "${base_sha}:.repository-projection.json" 2>/dev/null; then
    printf 'Projection provenance existed in the comparison base and cannot be removed.\n' >&2
    exit 1
  fi
fi

unexpected="$(find . -mindepth 1 \( -path './.git' -o -path './.github' \) -prune -o \( -path './README.md' -o -path './SECURITY.md' -o -path './CONTRIBUTING.md' -o -path './CODEOWNERS' \) -prune -o -print)"
if [[ -n "$unexpected" ]]; then
  printf 'Projection payload exists without provenance:\n%s\n' "$unexpected" >&2
  exit 1
fi

write_output 'present=false'
printf 'Projection payload has not landed; validated the destination-owned bootstrap tree.\n'
