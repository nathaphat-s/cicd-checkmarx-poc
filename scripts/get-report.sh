#!/usr/bin/env bash
# Download the report.html that CI built for a PR (or the current branch) and open it locally.
# Usage: npm run report            -> current branch
#        npm run report -- 4       -> PR #4
# If the run is still in progress it waits, then downloads the report as soon as it finishes.
# Reports land in reports/, which is git-ignored, so they are never committed or pushed.
# Needs the GitHub CLI (gh) logged in to an account that can read this repo.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ $# -ge 1 ]; then
  BRANCH="$(gh pr view "$1" --json headRefName --jq .headRefName)"
  LABEL="pr-$1"
else
  BRANCH="$(git rev-parse --abbrev-ref HEAD)"
  LABEL="${BRANCH//\//-}"
fi

RUN_ID="$(gh run list --workflow ci.yml --branch "$BRANCH" --limit 1 --json databaseId --jq '.[0].databaseId')"
if [ -z "$RUN_ID" ]; then
  echo "No CI run found for branch '$BRANCH'. Run the workflow first (Actions → Run workflow)." >&2
  exit 1
fi

# If the pipeline is still running, wait for it to finish, then download the report
STATUS="$(gh run view "$RUN_ID" --json status --jq .status)"
if [ "$STATUS" != "completed" ]; then
  echo "Pipeline run $RUN_ID is $STATUS, waiting for it to finish..."
  gh run watch "$RUN_ID" --interval 10 >/dev/null || true
fi

OUT="reports/$LABEL"
rm -rf "$OUT" && mkdir -p "$OUT"
gh run download "$RUN_ID" -n security-report -D "$OUT"
echo "Report for branch '$BRANCH' (run $RUN_ID): $OUT/report.html"
[ -z "${NO_OPEN:-}" ] && command -v open >/dev/null && open "$OUT/report.html" || true
