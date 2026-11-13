#!/usr/bin/env bash
# Show the open GitHub Advanced Security alerts of this repo: Code scanning (CodeQL), Dependabot and Secret scanning.
# Usage: npm run ghas:alerts                 -> all open alerts
#        npm run ghas:alerts -- demo/nextjs-vulnerable   -> code scanning alerts of that branch only
# Uses your own gh login: the workflow's GITHUB_TOKEN cannot read Dependabot or Secret scanning alerts,
# so these two never appear in report.html; this script is how you see them next to it.
# Raw JSON is saved to reports/ghas-alerts/ (git-ignored).
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
OUT=reports/ghas-alerts
mkdir -p "$OUT"
REF_ARG=()
[ $# -ge 1 ] && REF_ARG=(-f ref="refs/heads/$1")

fetch() { # name, endpoint, extra args...
  local name=$1 endpoint=$2; shift 2
  if gh api -X GET "repos/$REPO/$endpoint" -f state=open -f per_page=100 "$@" > "$OUT/$name.json" 2> "$OUT/$name.err"; then
    rm -f "$OUT/$name.err"
  else
    echo "[]" > "$OUT/$name.json"
    echo "  ($name: $(head -n 1 "$OUT/$name.err"))"
  fi
}

echo "== Code scanning (CodeQL)${1:+ on $1}"
fetch code-scanning code-scanning/alerts ${REF_ARG[@]+"${REF_ARG[@]}"}
jq -r '.[] | "  [\(.rule.security_severity_level // .rule.severity)] \(.rule.description)  \(.most_recent_instance.location.path):\(.most_recent_instance.location.start_line)"' "$OUT/code-scanning.json"

echo; echo "== Dependabot alerts (default branch)"
fetch dependabot dependabot/alerts
jq -r '.[] | "  [\(.security_advisory.severity)] \(.dependency.package.name) \(.security_vulnerability.vulnerable_version_range): \(.security_advisory.summary)"' "$OUT/dependabot.json"

echo; echo "== Secret scanning"
fetch secret-scanning secret-scanning/alerts
jq -r '.[] | "  \(.secret_type_display_name)  \(.html_url)"' "$OUT/secret-scanning.json"

echo; echo "Saved to $OUT/  ·  Security tab: https://github.com/$REPO/security"
