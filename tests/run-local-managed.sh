#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary_secret_directory=''

cleanup() {
  if [[ -n $temporary_secret_directory && -d $temporary_secret_directory ]]; then
    find "$temporary_secret_directory" -type f -exec shred --remove --zero {} + 2>/dev/null || true
    rmdir "$temporary_secret_directory" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if [[ ${AV_TEST_GITHUB_OAUTH:-0} == 1 ]]; then
  command -v bao >/dev/null || {
    printf '%s\n' 'AV_TEST_GITHUB_OAUTH=1 requires an authenticated OpenBao CLI.' >&2
    exit 1
  }
  command -v gh >/dev/null || {
    printf '%s\n' 'AV_TEST_GITHUB_OAUTH=1 requires an authenticated GitHub CLI.' >&2
    exit 1
  }
  temporary_secret_directory=$(mktemp -d)
  chmod 700 "$temporary_secret_directory"
  openbao_mount=${AV_TEST_GITHUB_OPENBAO_MOUNT:-apps}
  openbao_path=${AV_TEST_GITHUB_OPENBAO_PATH:-av/local}
  openbao_secret_path="${openbao_mount%/}/${openbao_path#/}"
  # Use the explicit KV v2 data endpoint. The human policy is deliberately
  # not allowed to enumerate OpenBao mounts, which `bao kv get` tries first.
  bao read -field=GITHUB_CLIENT_ID "${openbao_mount%/}/data/${openbao_path#/}" \
    > "$temporary_secret_directory/client-id"
  bao read -field=GITHUB_CLIENT_SECRET "${openbao_mount%/}/data/${openbao_path#/}" \
    > "$temporary_secret_directory/client-secret"
  [[ -s $temporary_secret_directory/client-id && -s $temporary_secret_directory/client-secret ]] || {
    printf '%s\n' 'OpenBao returned an empty GitHub OAuth credential field.' >&2
    exit 1
  }
  export AV_TEST_GITHUB_CLIENT_ID
  AV_TEST_GITHUB_CLIENT_ID=$(<"$temporary_secret_directory/client-id")
  export AV_TEST_GITHUB_CLIENT_SECRET_FILE="$temporary_secret_directory/client-secret"
  export AV_TEST_GITHUB_OWNER_ID
  AV_TEST_GITHUB_OWNER_ID=$(gh api user --jq .id)
fi

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
if [[ -n ${AV_TEST_GITHUB_CLIENT_ID:-} ]]; then
  printf '%s\n' 'GitHub OAuth is enabled for the configured local test account.'
else
  printf '%s\n' 'GitHub OAuth is disabled. Run with AV_TEST_GITHUB_OAUTH=1 to read apps/av/local from OpenBao.'
fi
printf '%s\n' 'Stop it with: docker compose --project-name av-local-managed --file tests/integration/compose.yml --file tests/local-managed.compose.yml down --volumes'
