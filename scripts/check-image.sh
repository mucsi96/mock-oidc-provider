#!/usr/bin/env bash
set -euo pipefail

image=${1:?Set the image to verify}
runtime=${CONTAINER_RUNTIME:-docker}
container=$("$runtime" run --detach --rm --publish 127.0.0.1::8090 \
  --env PORT=8090 \
  --env ISSUER_ID=test \
  --env SUB=test-user \
  --env "NAME=Test User" \
  --env PREFERRED_USERNAME=test-user@example.invalid \
  --env ROLES=reader,writer \
  --env "SCP=openid profile" \
  --env AUD=mock-api \
  --env OID=00000000-0000-0000-0000-000000000001 \
  "$image")

cleanup() {
  status=$?
  if (( status != 0 )); then
    "$runtime" logs "$container" >&2 || true
  fi
  "$runtime" rm --force "$container" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

address=$("$runtime" port "$container" 8090/tcp)
base_url="http://$address"
curl --fail --silent --show-error --retry 30 --retry-all-errors --retry-delay 1 --max-time 5 \
  "$base_url/health" >/dev/null
node "$(dirname "$0")/check-oidc.mjs" "$base_url"
