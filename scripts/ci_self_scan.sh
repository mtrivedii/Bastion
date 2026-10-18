#!/usr/bin/env bash
# Uploads an SBOM to a running Drydock, scans it, and writes the findings and
# project summary next to the given output prefix.
# Usage: ci_self_scan.sh <base-url> <api-key> <sbom.json> <output-prefix> [project]
set -euo pipefail

BASE="${1:?base url}"
KEY="${2:?api key}"
SBOM="${3:?sbom file}"
OUT="${4:?output prefix}"
PROJECT="${5:-bastion}"

auth=(-H "X-API-Key: ${KEY}")

id=$(curl -fsS "${auth[@]}" -F "file=@${SBOM}" "${BASE}/sboms?project=${PROJECT}" | jq -r .id)
curl -fsS -X POST "${auth[@]}" "${BASE}/sboms/${id}/scan" >/dev/null

status=pending
for _ in $(seq 1 90); do
  status=$(curl -fsS "${auth[@]}" "${BASE}/sboms/${id}/findings" | jq -r .scan_status)
  [ "${status}" = "completed" ] && break
  if [ "${status}" = "failed" ]; then
    echo "scan failed" >&2
    exit 1
  fi
  sleep 2
done
if [ "${status}" != "completed" ]; then
  echo "scan did not finish in time (status: ${status})" >&2
  exit 1
fi

curl -fsS "${auth[@]}" "${BASE}/sboms/${id}/findings" >"${OUT}-findings.json"
curl -fsS "${auth[@]}" "${BASE}/projects/${PROJECT}/summary" >"${OUT}-summary.json"

{
  echo "### Drydock scan of this build's own SBOM"
  echo
  echo "| Severity | Open findings |"
  echo "|---|---|"
  jq -r '.open_by_severity | to_entries[] | "| \(.key) | \(.value) |"' "${OUT}-summary.json"
  echo
  echo "$(jq -r '.findings | length' "${OUT}-findings.json") finding(s) listed in total. Report only, this step does not block the build."
} | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
