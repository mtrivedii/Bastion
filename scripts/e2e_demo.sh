#!/usr/bin/env bash
# Used by the kind cluster test: reach the API through a port-forward, run the
# demo with the generated API key, and check that calls without a key are refused.
set -euo pipefail

kubectl -n drydock port-forward svc/drydock 8000:80 >/tmp/pf.log 2>&1 &
pf=$!
trap 'kill "$pf" 2>/dev/null || true' EXIT

for _ in $(seq 1 30); do
  curl -fsS http://127.0.0.1:8000/health >/dev/null 2>&1 && break
  sleep 2
done
curl -fsS http://127.0.0.1:8000/health

key=$(kubectl -n drydock get secret drydock -o jsonpath='{.data.api-key}' | base64 -d)
DRYDOCK_API_KEY="$key" "$(dirname "$0")/demo.sh"

code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/sboms)
echo "status without key: ${code}"
[ "${code}" = "401" ]
