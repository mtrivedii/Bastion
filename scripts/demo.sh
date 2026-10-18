#!/usr/bin/env bash
# Seed-and-fix demo against a running Drydock. Uploads an SBOM with a vulnerable
# package, scans it, uploads a fixed SBOM, scans again, and checks that the
# finding was marked resolved.
#
# Needs internet access (Drydock asks api.osv.dev).
# Usage: BASE=http://127.0.0.1:8000 DRYDOCK_API_KEY=... scripts/demo.sh
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:8000}"
PROJECT="${PROJECT:-demo}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"

auth=()
if [ -n "${DRYDOCK_API_KEY:-}" ]; then
  auth=(-H "X-API-Key: ${DRYDOCK_API_KEY}")
fi
api() { curl -fsS "${auth[@]}" "$@"; }

scan() {
  local file="$1" id status
  id=$(api -F "file=@${file}" "${BASE}/sboms?project=${PROJECT}" | jq -r '.id // empty')
  [ -n "${id}" ] || { echo "upload of ${file} failed" >&2; return 1; }
  api -X POST "${BASE}/sboms/${id}/scan" >/dev/null
  for _ in $(seq 1 90); do
    status=$(api "${BASE}/sboms/${id}/findings" | jq -r .scan_status)
    [ "${status}" = "completed" ] && { echo "${id}"; return 0; }
    [ "${status}" = "failed" ] && { echo "scan failed for ${file}" >&2; return 1; }
    sleep 2
  done
  echo "scan timed out for ${file}" >&2
  return 1
}

echo "1. Uploading and scanning the vulnerable SBOM (PyYAML 5.3)"
first=$(scan "${HERE}/demo/seed_vulnerable_sbom.json") || exit 1
open=$(api "${BASE}/sboms/${first}/findings?state=open" | jq '.findings | length')
echo "   open findings: ${open}"
[ "${open}" -gt 0 ] || { echo "expected findings for PyYAML 5.3" >&2; exit 1; }
api "${BASE}/sboms/${first}/findings?state=open" \
  | jq -r '.findings[] | "   \(.severity)\t\(.cvss_score // "-")\t\(.vuln_id)\t\(.summary)"' | head -5

echo "2. Uploading and scanning the fixed SBOM (PyYAML 6.0)"
second=$(scan "${HERE}/demo/seed_fixed_sbom.json") || exit 1
still_open=$(api "${BASE}/sboms/${second}/findings?state=open" | jq '.findings | length')
resolved=$(api "${BASE}/sboms/${first}/findings?state=resolved" | jq '.findings | length')
echo "   open in the new submission: ${still_open}, resolved from the old one: ${resolved}"
[ "${still_open}" -eq 0 ] || { echo "the fixed SBOM should have no open findings" >&2; exit 1; }
[ "${resolved}" -eq "${open}" ] || { echo "every earlier finding should now be resolved" >&2; exit 1; }

echo "3. Project summary"
api "${BASE}/projects/${PROJECT}/summary" | jq .
echo "Demo passed."
