#!/usr/bin/env bash
# Run the same checks as CI on your machine and build reports/local/report.html before you push.
# Usage: npm run security:local
# Each scanner runs only when you have set it up, the others show as "not run" in the report:
#   Snyk:   npx snyk auth                              (once)
#   Aikido: export AIKIDO_API_KEY=<token>              (Aikido → Settings → Integrations → Local scanner)
#   GHAS:   CodeQL runs only on GitHub Actions; see open alerts with  npm run ghas:alerts
# Output goes to reports/, which is git-ignored, so it is never committed or pushed.
set -uo pipefail
cd "$(dirname "$0")/.."
OUT=reports/local
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
SHA="$(git rev-parse HEAD)"
rm -rf "$OUT" && mkdir -p "$OUT"

echo "== Unit tests"
npx vitest run --reporter=default --reporter=json --outputFile.json="$OUT/test-results.json"
BUILD=$([ $? -eq 0 ] && echo success || echo failure)

IMAGE_OK=false
if docker build -q -t poc-app:local . >/dev/null; then IMAGE_OK=true; else echo "Docker build failed (is Docker running?) — container scans skipped"; fi

SNYK=skipped
if npx --yes snyk whoami --experimental >/dev/null 2>&1; then
  echo; echo "== Snyk (Code, Open Source, IaC, Container) — gate: High and above"
  SNYK=success
  npx --yes snyk code test --severity-threshold=high --sarif-file-output="$OUT/snyk-code.sarif" || SNYK=failure
  npx --yes snyk test --severity-threshold=high --json-file-output="$OUT/snyk-oss.json" || SNYK=failure
  npx --yes snyk iac test k8s --severity-threshold=high --json-file-output="$OUT/snyk-iac.json" || SNYK=failure
  if [ "$IMAGE_OK" = true ]; then
    npx --yes snyk container test poc-app:local --file=Dockerfile --exclude-app-vulns --severity-threshold=high \
      --json-file-output="$OUT/snyk-container.json" || SNYK=failure
  fi
else
  echo; echo "== Snyk skipped (not logged in: run  npx snyk auth)"
fi

AIKIDO=skipped
if [ -n "${AIKIDO_API_KEY:-}" ]; then
  echo; echo "== Aikido local scanner (code + image) — gate: High and above, new issues vs main"
  AIKIDO=success
  BASE="$(git merge-base origin/main HEAD)"
  if [ "$BASE" = "$SHA" ]; then MODE=(--gating-mode release); else MODE=(--gating-mode pr --base-commit-id "$BASE" --head-commit-id "$SHA"); fi
  SCANNER=aikidosecurity/local-scanner:latest
  docker run --rm -v "$PWD":/src -w /src -e AIKIDO_API_KEY --entrypoint aikido-local-scanner "$SCANNER" \
    scan /src --repositoryname "$(basename "$(git rev-parse --show-toplevel)")" --branchname "$BRANCH" \
    "${MODE[@]}" --fail-on high --exclude node_modules --exclude .next \
    --gating-result-output "/src/$OUT/aikido-code.json" || AIKIDO=failure
  if [ "$IMAGE_OK" = true ]; then
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD/$OUT":/out -e AIKIDO_API_KEY \
      --entrypoint aikido-local-scanner "$SCANNER" image-scan poc-app:local --image-name poc-app --tag "${BRANCH//\//-}" \
      "${MODE[@]}" --fail-on high --gating-result-output /out/aikido-container.json || AIKIDO=failure
  fi
else
  echo; echo "== Aikido skipped (AIKIDO_API_KEY not set)"
fi

echo
BUILD=$BUILD SNYK=$SNYK AIKIDO=$AIKIDO GHAS=skipped BRANCH="$BRANCH" SHA="$SHA" \
  node scripts/build-report.mjs "$OUT" "$OUT/report.html" | head -16
echo; echo "Full report: $OUT/report.html"
[ -z "${NO_OPEN:-}" ] && command -v open >/dev/null && open "$OUT/report.html" || true
[ "$BUILD" = success ] && [ "$SNYK" != failure ] && [ "$AIKIDO" != failure ]
