#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=integration-tls.sh
# Resolved from the repository root at runtime.
# shellcheck disable=SC1091
source "$root/tests/integration-tls.sh"
# shellcheck source=sensitive-output.sh
# shellcheck disable=SC1091
source "$root/tests/sensitive-output.sh"
compose=(docker compose --project-name "av-security-${UID}-$$" --file "$root/tests/integration/compose.yml" --profile security)
workdir=$(mktemp -d "$root/.tmp.security-scan.XXXXXX")
export AV_POSTGRES_TLS_DIR="$workdir/postgres-tls"

cleanup() {
  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$workdir"
}
report_failure() {
  local status=$1
  local line=$2
  printf 'security scan failed at line %d\n' "$line" >&2
  exit "$status"
}
trap cleanup EXIT
trap 'report_failure "$?" "$LINENO"' ERR

generate_integration_tls "$AV_POSTGRES_TLS_DIR"

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

# Export only disposable synthetic canaries into the mode-0700 harness
# directory, then scan both process logs and persisted audit metadata without
# printing any matching value.
mkdir "$workdir/canaries"
chmod 0700 "$workdir/canaries"
# shellcheck disable=SC2016 # The disposable child shell expands its UID/GID.
"${compose[@]}" run --no-deps --rm \
  --env "HOST_UID=$(id -u)" \
  --env "HOST_GID=$(id -g)" \
  --volume "$workdir/canaries:/host-results" \
  --entrypoint sh verify -ec '
    umask 077
    cp /results/agent-token /results/proxy-session-token /host-results/
    chown "$HOST_UID:$HOST_GID" /host-results/agent-token /host-results/proxy-session-token
  '
docker logs "$("${compose[@]}" ps --quiet av)" >"$workdir/av.log" 2>&1
chmod 0600 "$workdir/av.log"
"${compose[@]}" exec --no-TTY postgres \
  psql -U infisical -d av -tAc \
  "SELECT concat_ws('|', actor, action, profile, route, executable_basename) FROM av_audit_events" \
  >"$workdir/audit.log"
chmod 0600 "$workdir/audit.log"
for canary in \
  infisical-ok \
  openbao+ok \
  managed-ui-password \
  av-request-body-canary-9e8c \
  av-sensitive-header-canary-7d31
do
  assert_literal_absent_from \
    "sensitive canary" "$canary" "$workdir/av.log" "$workdir/audit.log"
done
for canary_file in "$workdir"/canaries/*; do
  assert_pattern_file_absent_from \
    "raw session or agent capability" \
    "$canary_file" "$workdir/av.log" "$workdir/audit.log"
done

printf 'security_scan=ok\n'
