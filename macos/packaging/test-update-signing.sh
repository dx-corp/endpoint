#!/usr/bin/env bash
set -euo pipefail
umask 077
script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/merlin-update-signing-test.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
export RUNNER_TEMP="$work"
# Public RFC8032 test vector, never a production signing credential.
read -r MERLIN_UPDATE_SIGNING_KEY MERLIN_UPDATE_PUBLIC_KEY < <(python3 - <<'PY'
import base64
print(base64.b64encode(bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')).decode(),
      base64.b64encode(bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')).decode())
PY
)
export MERLIN_UPDATE_SIGNING_KEY MERLIN_UPDATE_PUBLIC_KEY
export MERLIN_UPDATE_FEED_URL='https://github.com/dx-corp/endpoint/releases/latest/download/appcast.xml'
package="$work/Merlin-0.1.3.pkg"
printf 'fixture package bytes\n' > "$package"
bash "$script_dir/build-appcast.sh" 0.1.3 "$package" "$work/appcast.xml"
[[ -s "$work/appcast.xml" ]]
if MERLIN_UPDATE_PUBLIC_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
  bash "$script_dir/build-appcast.sh" 0.1.3 "$package" "$work/wrong-key.xml"; then
  echo 'Wrong configured update public key was accepted.' >&2; exit 1
fi
[[ ! -e "$work/wrong-key.xml" ]]
# Reuse the checksum-pinned tool archive already fetched above, not a second download.
archive="${EVALOPS_TOOL_CACHE:-${RUNNER_TOOL_CACHE:+${RUNNER_TOOL_CACHE}/evalops-tools}}"
archive="${archive:-$HOME/.cache/evalops-tools}/52bf9e88cdd972fc0c81501377a880e90d47031bd8ca5462488f843e2609e192"
tar -xJf "$archive" -C "$work" ./bin/sign_update
printf '%s' "$MERLIN_UPDATE_SIGNING_KEY" > "$work/test-key"
signature="$(python3 - "$work/appcast.xml" <<'PY'
import sys
import xml.etree.ElementTree as ET
print(ET.parse(sys.argv[1]).find('channel/item/enclosure').get(
    '{http://www.andymatuschak.org/xml-namespaces/sparkle}edSignature'))
PY
)"
printf 'tampered bytes\n' >> "$package"
if "$work/bin/sign_update" --ed-key-file "$work/test-key" --verify "$package" "$signature"; then
  echo 'Tampered package was accepted.' >&2; exit 1
fi
python3 - "$work/appcast.xml" <<'PY'
import sys
from pathlib import Path
p = Path(sys.argv[1])
p.write_text(p.read_text().replace('Merlin-0.1.3.pkg', 'Merlin-0.1.4.pkg'))
PY
if "$work/bin/sign_update" --ed-key-file "$work/test-key" --verify "$work/appcast.xml"; then
  echo 'Tampered appcast URL was accepted.' >&2; exit 1
fi
echo 'Actual Sparkle package/feed signatures and key binding passed.'
