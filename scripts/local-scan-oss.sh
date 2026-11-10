#!/usr/bin/env bash
# Local "shift-left" gate WITHOUT a Checkmarx tenant.
# SAST = Bandit, SCA = pip-audit, IaC = KICS (open-source Checkmarx engine, via Docker).
# Exit code != 0 when any High finding is present (same idea as the CI threshold gate).
set -uo pipefail
cd "$(dirname "$0")/.."
FAIL=0

echo "== SAST (Bandit, Medium+ — Bandit rates SQLi as Medium) =="
.venv/bin/bandit -r app -ll || FAIL=1

echo; echo "== SCA (pip-audit) =="
.venv/bin/pip-audit -r requirements.txt || FAIL=1

echo; echo "== IaC (KICS via Docker, fail on HIGH) =="
docker run --rm -v "$PWD":/path checkmarx/kics:latest scan \
  -p /path --exclude-paths /path/.venv --fail-on high --no-progress \
  --report-formats json -o /path/kics-report >/dev/null
KICS_RC=$?
docker run --rm -v "$PWD":/path --entrypoint cat checkmarx/kics:latest /path/kics-report/results.json 2>/dev/null \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print("KICS:", d.get("severity_counters"))' || true
[ $KICS_RC -ne 0 ] && FAIL=1

echo
if [ $FAIL -ne 0 ]; then echo "❌ GATE FAILED: High-severity findings present"; exit 1; fi
echo "✅ GATE PASSED"
