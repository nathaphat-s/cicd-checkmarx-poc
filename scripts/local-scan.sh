#!/usr/bin/env bash
# Local "shift-left" gate, no account needed. Exit code != 0 when any High finding is present.
# SAST = Semgrep, SCA = npm audit, IaC = KICS (all via Docker / npm).
set -uo pipefail
cd "$(dirname "$0")/.."
FAIL=0

echo "== SAST (Semgrep, ERROR severity) =="
docker run --rm -v "$PWD":/src -w /src semgrep/semgrep:latest semgrep scan \
  --config p/owasp-top-ten --config p/nodejsscan --config p/secrets --config p/react \
  --severity ERROR --error --quiet --exclude node_modules --exclude .next || FAIL=1

echo; echo "== SCA (npm audit, high+) =="
npm audit --omit=dev --audit-level=high || FAIL=1

echo; echo "== IaC (KICS, fail on HIGH) =="
docker run --rm -v "$PWD":/path checkmarx/kics:latest scan -p /path \
  --exclude-paths /path/node_modules,/path/.next --fail-on high --no-progress \
  --report-formats json -o /path/kics-report >/dev/null
KICS_RC=$?
python3 -c 'import json; d=json.load(open("kics-report/results.json")); print("KICS:", d.get("severity_counters"))' 2>/dev/null || true
[ $KICS_RC -ne 0 ] && FAIL=1

echo
if [ $FAIL -ne 0 ]; then echo "❌ GATE FAILED: High-severity findings present"; exit 1; fi
echo "✅ GATE PASSED"
