#!/usr/bin/env bash
# Run the SAME Checkmarx One scan as CI, from your Mac, using the cx CLI Docker image.
# Requires: export CX_BASE_URI CX_TENANT CX_CLIENT_ID CX_CLIENT_SECRET  (see README)
set -euo pipefail
cd "$(dirname "$0")/.."
: "${CX_BASE_URI:?set CX_BASE_URI}"; : "${CX_TENANT:?set CX_TENANT}"
: "${CX_CLIENT_ID:?set CX_CLIENT_ID}"; : "${CX_CLIENT_SECRET:?set CX_CLIENT_SECRET}"
BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo local)"

docker run --rm -v "$PWD":/src -w /src \
  -e CX_BASE_URI -e CX_TENANT -e CX_CLIENT_ID -e CX_CLIENT_SECRET \
  checkmarx/ast-cli:latest scan create \
  --project-name "cicd-checkmarx-poc" --branch "$BRANCH" \
  -s /src --file-filter '!.venv,!kics-report,!cx-report' \
  --scan-types sast,sca,kics \
  --threshold "sast-high=1;sca-high=1;kics-high=1" \
  --report-format summaryConsole,summaryHTML --output-path /src/cx-report
