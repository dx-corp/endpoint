#!/bin/sh
# Runs before builds, signing, or network operations. No credential values are read.
set -eu
fail() { printf '%s\n' "$1" >&2; exit 64; }
case "${MERLIN_PKG_VERSION:-0.1.0}" in
  ''|*[!0-9.]*) fail 'Package version must use decimal version components.' ;;
esac
case "${MERLIN_RELEASE_MODE:-development}" in
  development) ;;
  production)
    case "${MERLIN_CODE_SIGN_IDENTITY:-}" in 'Developer ID Application: '*) ;; *) fail 'Production requires a Developer ID Application identity name.' ;; esac
    case "${MERLIN_INSTALLER_SIGN_IDENTITY:-}" in 'Developer ID Installer: '*) ;; *) fail 'Production requires a Developer ID Installer identity name.' ;; esac
    [ -n "${MERLIN_NOTARY_PROFILE:-}" ] || fail 'Production requires MERLIN_NOTARY_PROFILE.'
    [ "${MERLIN_CODESIGN_TIMESTAMP:-1}" = 1 ] || fail 'Production requires secure timestamps.'
    [ -n "${MERLIN_UPDATE_FEED_URL:-}" ] && [ -n "${MERLIN_UPDATE_PUBLIC_KEY:-}" ] || fail 'Production requires an approved update feed and public EdDSA key.'
    ;;
  *) fail 'MERLIN_RELEASE_MODE must be development or production.' ;;
esac
MERLIN_UPDATE_PUBLIC_KEY=${MERLIN_UPDATE_PUBLIC_KEY:-}
if [ -n "${MERLIN_UPDATE_FEED_URL:-}${MERLIN_UPDATE_PUBLIC_KEY:-}" ]; then
  case "${MERLIN_UPDATE_FEED_URL:-}" in https://*) ;; *) fail 'Updates require an HTTPS feed.' ;; esac
  [ "${#MERLIN_UPDATE_PUBLIC_KEY}" = 44 ] || fail 'Updates require a base64 Ed25519 public key (32 bytes).'
  bytes=$(printf '%s' "$MERLIN_UPDATE_PUBLIC_KEY" | /usr/bin/base64 -D 2>/dev/null | wc -c | tr -d ' ')
  [ "$bytes" = 32 ] || fail 'Invalid update public key.'
fi

case "${MERLIN_NATIVE_SIGN_IN_ENABLED:-0}" in
  0) ;;
  1)
    [ "${MERLIN_OAUTH_RESOURCE:-}" = https://merlin.dx-corp.net ] || fail 'Native sign-in requires the exact Merlin OAuth resource.'
    for tenant in "${MERLIN_ORGANIZATION_ID:-}" "${MERLIN_WORKSPACE_ID:-}"; do
      case "$tenant" in
        ''|*[!A-Za-z0-9_-]*) fail 'Native sign-in requires explicit organization and workspace identifiers.' ;;
      esac
      [ "${#tenant}" -le 128 ] || fail 'Native sign-in tenant identifier is too long.'
    done
    ;;
  *) fail 'MERLIN_NATIVE_SIGN_IN_ENABLED must be 0 or 1.' ;;
esac
