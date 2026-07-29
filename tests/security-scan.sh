#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
compose=(docker compose --project-name "av-security-${UID}-$$" --file "$root/tests/integration/compose.yml" --profile security)
workdir=$(mktemp -d "$root/.tmp.security-scan.XXXXXX")
export AV_POSTGRES_TLS_DIR="$workdir/postgres-tls"

cleanup() {
  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$workdir"
}
trap cleanup EXIT

mkdir -p "$AV_POSTGRES_TLS_DIR"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$AV_POSTGRES_TLS_DIR/server.key" \
  -out "$AV_POSTGRES_TLS_DIR/server.crt" \
  -subj "/CN=postgres" \
  -addext "subjectAltName=DNS:postgres" >/dev/null 2>&1
chmod 0600 "$AV_POSTGRES_TLS_DIR/server.key"

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
