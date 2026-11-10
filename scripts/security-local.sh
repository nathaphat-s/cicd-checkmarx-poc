#!/usr/bin/env bash
# Run the same checks as CI on your machine and build reports/local/report.html before you push.
# Usage: npm run security:local
# First time only: npx snyk auth   (logs the Snyk CLI in with your Snyk account)
# Output goes to reports/, which is git-ignored, so it is never committed or pushed.
set -uo pipefail
cd "$(dirname "$0")/.."
OUT=reports/local

if ! npx --yes snyk whoami --experimental >/dev/null 2>&1; then
  echo "Snyk CLI is not logged in. Run this once, then try again:  npx snyk auth" >&2
  exit 1
fi
rm -rf "$OUT" && mkdir -p "$OUT"

echo "== Unit tests"
npx vitest run --reporter=default --reporter=json --outputFile.json="$OUT/test-results.json"
BUILD=$([ $? -eq 0 ] && echo success || echo failure)

echo; echo "== Snyk (Code, Open Source, IaC) — gate: High and above"
SNYK=success
npx --yes snyk code test --severity-threshold=high --sarif-file-output="$OUT/snyk-code.sarif" || SNYK=failure
npx --yes snyk test --severity-threshold=high --json-file-output="$OUT/snyk-oss.json" || SNYK=failure
npx --yes snyk iac test k8s --severity-threshold=high --json-file-output="$OUT/snyk-iac.json" || SNYK=failure

echo
BUILD=$BUILD SNYK=$SNYK BRANCH="$(git rev-parse --abbrev-ref HEAD)" SHA="$(git rev-parse HEAD)" \
  node scripts/build-report.mjs "$OUT" "$OUT/report.html" | head -12
echo; echo "Full report: $OUT/report.html"
[ -z "${NO_OPEN:-}" ] && command -v open >/dev/null && open "$OUT/report.html" || true
[ "$BUILD" = success ] && [ "$SNYK" = success ]
