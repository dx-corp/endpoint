#!/bin/sh
# Offline-first macOS validation harness.
#
# It exercises the fixture/unit suite, builds the CLI, and validates the JSON
# contracts emitted by `check` and `posture` without requiring root, an ES
# entitlement, a NetworkExtension entitlement, or a sync server. Set
# MERLIN_MACOS_LIVE=1 to append the privileged end-to-end smoke test.
set -eu

MACOS_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$MACOS_DIR"

actual_arch=$(uname -m)
expected_arch=${MERLIN_EXPECTED_ARCH:-}
if [ -n "$expected_arch" ] && [ "$actual_arch" != "$expected_arch" ]; then
    echo "architecture mismatch: got $actual_arch, expected $expected_arch" >&2
    exit 1
fi

echo "macOS matrix target: $(sw_vers -productVersion) / $actual_arch"
"$MACOS_DIR/test-client.sh"
swift build

binary="$MACOS_DIR/.build/debug/MerlinMacOS"
check_status=0
check_json=$(
    "$binary" check --json
) || check_status=$?
posture_json=$("$binary" posture --json)

CHECK_JSON="$check_json" POSTURE_JSON="$posture_json" python3 - <<'PY'
import json
import os

check = json.loads(os.environ["CHECK_JSON"])
posture = json.loads(os.environ["POSTURE_JSON"])
report = posture.get("report")
if check.get("platform") != "macos":
    raise SystemExit("check JSON did not identify macos")
if not isinstance(check.get("capabilities"), list):
    raise SystemExit("check JSON has no capability list")
if not isinstance(report, dict):
    raise SystemExit("posture JSON has no managed report")
for key in ("schema_version", "collected_at", "overall", "risk_score", "checks", "findings", "coverage"):
    if key not in report:
        raise SystemExit(f"posture report missing {key}")
if report["schema_version"] != 2:
    raise SystemExit("posture report is not schema version 2")
if not 0 <= report["risk_score"] <= 100:
    raise SystemExit("posture risk score is outside 0..100")
if report["coverage"].get("checks_total", 0) != len(report["checks"]):
    raise SystemExit("posture coverage count does not match checks")
if report["coverage"].get("checks_with_evidence") != len(report["checks"]):
    raise SystemExit("posture evidence count does not match checks")
if any(not isinstance(check.get("evidence"), dict) for check in report["checks"].values()):
    raise SystemExit("posture check is missing evidence metadata")
print(f"validated posture: {report['overall']} risk={report['risk_score']} checks={len(report['checks'])} findings={len(report['findings'])}")
PY

if [ "$check_status" -ne 0 ]; then
    echo "readiness probe returned $check_status; JSON contract is valid but no complete provider matrix was available" >&2
fi

if [ "${MERLIN_MACOS_LIVE:-0}" = "1" ]; then
    sudo "$MACOS_DIR/test-live.sh"
fi
