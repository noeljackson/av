#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
compose=(
  docker compose
  --project-name av-local-managed
  --file "$root/tests/integration/compose.yml"
  --file "$root/tests/local-managed.compose.yml"
)

if [[ -n ${AV_IMAGE:-} ]]; then
  docker image inspect "$AV_IMAGE" >/dev/null
else
  docker build --tag av:local-managed "$root"
  AV_IMAGE=av:local-managed
fi
export AV_IMAGE

"${compose[@]}" up --detach --wait postgres redis infisical openbao upstream
"${compose[@]}" up --detach av
"${compose[@]}" up --detach --no-deps managed-seed
managed_seed=$("${compose[@]}" ps --all --quiet managed-seed)
[[ -n "$managed_seed" ]]
[[ $(docker wait "$managed_seed") == 0 ]]

printf '%s\n' 'AV local managed test UI: http://127.0.0.1:14322'
printf '%s\n' 'Basic owner test login: operator / password'
printf '%s\n' 'OIDC uses Zitadel; choose GitHub there if it is enabled for your account.'
printf '%s\n' 'Stop it with: docker compose --project-name av-local-managed --file tests/integration/compose.yml --file tests/local-managed.compose.yml down --volumes'
