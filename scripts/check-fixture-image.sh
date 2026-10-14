#!/usr/bin/env bash
set -euo pipefail
image=${1:?Set the image to verify}
runtime=${CONTAINER_RUNTIME:-docker}
directory=$(mktemp -d)
container=
cleanup() {
  status=$?
  if [[ -n "$container" ]]; then
    if (( status != 0 )); then "$runtime" logs "$container" >&2 || true; fi
    "$runtime" rm --force "$container" >/dev/null 2>&1 || true
  fi
  rm -rf "$directory"
  exit "$status"
}
trap cleanup EXIT
node - "$directory/config.json" <<'JS'
const fs = require('node:fs');
const clients = Object.fromEntries(['hello', 'cooking'].map(app => [app + '-web', {
  secret: app + '-test-secret', redirect_uri: 'https://' + app + '.example.invalid/callback',
  api_audience: app + '-api', api_scope: 'api://' + app + '-api/api-access',
  allowed_users: ['owner'], roles: {owner: ['read']},
}]));
fs.writeFileSync(process.argv[2], JSON.stringify({issuer_url: 'https://issuer.example.invalid/test', access_token_ttl_secs: 5, clients}));
JS
container=$("$runtime" run --detach --rm --publish 127.0.0.1::8090 \
  --volume "$directory:/fixture:ro" --env FIXTURE_CONFIG_FILE=/fixture/config.json \
  --env PORT=8090 --env ISSUER_ID=test --env SUB=owner --env NAME=Owner \
  --env PREFERRED_USERNAME=owner@example.invalid --env OID=00000000-0000-0000-0000-000000000001 \
  --env ROLES=read --env SCP=api-access --env AUD=unused "$image")
address=$("$runtime" port "$container" 8090/tcp)
curl --fail --silent --show-error --retry 30 --retry-all-errors --retry-delay 1 --max-time 5 "http://$address/health" >/dev/null
node "$(dirname "$0")/check-fixture.mjs" "http://$address"
