#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
compose=(docker compose --project-name "av-security-${UID}-$$" --file "$root/tests/integration/compose.yml" --profile security)

cleanup() {
  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

"${compose[@]}" config --quiet
if [[ -n ${AV_IMAGE:-} ]]; then
  docker image inspect "$AV_IMAGE" >/dev/null
else
  "${compose[@]}" build av
fi
"${compose[@]}" up --detach --wait postgres redis infisical openbao upstream
"${compose[@]}" up --detach av
"${compose[@]}" up --detach --no-deps managed-seed
managed_seed=$("${compose[@]}" ps --all --quiet managed-seed)
[[ -n "$managed_seed" ]]
[[ $(docker wait "$managed_seed") == 0 ]]
"${compose[@]}" run --no-deps --rm verify
"${compose[@]}" run --no-deps --rm zap

printf 'security_scan=ok\n'
