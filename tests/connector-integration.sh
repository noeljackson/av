#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
compose=(docker compose --project-name "av-connectors-${UID}-$$" --file "$root/tests/integration/compose.yml")
workdir=$(mktemp -d "$root/.tmp.connector-cli.XXXXXX")
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
openssl req -x509 -newkey ed25519 -nodes -days 1 \
  -keyout "$AV_POSTGRES_TLS_DIR/proxy-ca.key" \
  -out "$AV_POSTGRES_TLS_DIR/proxy-ca.crt" \
  -subj "/CN=av-integration-proxy-ca" >/dev/null 2>&1
openssl req -x509 -newkey ed25519 -nodes -days 1 \
  -keyout "$AV_POSTGRES_TLS_DIR/proxy-transport-ca.key" \
  -out "$AV_POSTGRES_TLS_DIR/proxy-transport-ca.crt" \
  -subj "/CN=AV synthetic transport test CA" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$AV_POSTGRES_TLS_DIR/proxy-transport.key" \
  -out "$AV_POSTGRES_TLS_DIR/proxy-transport.csr" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" >/dev/null 2>&1
openssl x509 -req -days 1 \
  -in "$AV_POSTGRES_TLS_DIR/proxy-transport.csr" \
  -CA "$AV_POSTGRES_TLS_DIR/proxy-transport-ca.crt" \
  -CAkey "$AV_POSTGRES_TLS_DIR/proxy-transport-ca.key" \
  -CAcreateserial \
  -copy_extensions copy \
  -out "$AV_POSTGRES_TLS_DIR/proxy-transport.crt" >/dev/null 2>&1
openssl req -x509 -newkey ed25519 -nodes -days 1 \
  -keyout "$AV_POSTGRES_TLS_DIR/tunnel-ca.key" \
  -out "$AV_POSTGRES_TLS_DIR/tunnel-ca.crt" \
  -subj "/CN=AV synthetic tunnel test CA" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$AV_POSTGRES_TLS_DIR/tunnel.key" \
  -out "$AV_POSTGRES_TLS_DIR/tunnel.csr" \
  -subj "/CN=upstream-tunnel" \
  -addext "subjectAltName=DNS:upstream-tunnel" >/dev/null 2>&1
openssl x509 -req -days 1 \
  -in "$AV_POSTGRES_TLS_DIR/tunnel.csr" \
  -CA "$AV_POSTGRES_TLS_DIR/tunnel-ca.crt" \
  -CAkey "$AV_POSTGRES_TLS_DIR/tunnel-ca.key" \
  -CAcreateserial \
  -copy_extensions copy \
  -out "$AV_POSTGRES_TLS_DIR/tunnel.crt" >/dev/null 2>&1
# Disposable synthetic fixtures are bind-mounted read-only for AV's non-root
# runtime UID and removed by the harness trap.
chmod 0444 \
  "$AV_POSTGRES_TLS_DIR/proxy-ca.key" \
  "$AV_POSTGRES_TLS_DIR/proxy-ca.crt" \
  "$AV_POSTGRES_TLS_DIR/proxy-transport-ca.crt" \
  "$AV_POSTGRES_TLS_DIR/proxy-transport.key" \
  "$AV_POSTGRES_TLS_DIR/proxy-transport.crt" \
  "$AV_POSTGRES_TLS_DIR/tunnel.crt" \
  "$AV_POSTGRES_TLS_DIR/tunnel.key"

"${compose[@]}" config --quiet
if [[ -n ${AV_IMAGE:-} ]]; then
  docker image inspect "$AV_IMAGE" >/dev/null
else
  "${compose[@]}" build av
fi
"${compose[@]}" up --detach --wait postgres redis infisical openbao upstream openbao-agent
"${compose[@]}" up --detach --no-deps av
"${compose[@]}" up --detach --no-deps managed-seed
managed_seed=$("${compose[@]}" ps --all --quiet managed-seed)
[[ -n "$managed_seed" ]]
[[ $(docker wait "$managed_seed") == 0 ]]
av_container=$("${compose[@]}" ps --quiet av)
AV_UI_CONTAINER="$av_container" AV_UI_EXPECT_MANAGED=1 AV_UI_EXPECT_PROFILE=infisical-integration AV_UI_URL=http://127.0.0.1:14322 \
  "$root/tests/ui-smoke.sh"
"${compose[@]}" run --no-deps --rm verify

# Exercise the release CLI, not just AV's HTTP API. The CLI runs in a
# disposable, capability-free container sharing AV's network namespace. That
# makes the test endpoint loopback without publishing a host port or adding a
# production insecure-transport exception.
docker cp "$av_container:/usr/local/bin/av" "$workdir/av"
chmod 0755 "$workdir/av"
run_cli() {
  docker run --rm --pull never \
    --network "container:$av_container" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --volume "$workdir/av:/usr/local/bin/av:ro" \
    --env AV_URL=http://127.0.0.1:14322 \
    --env AV_BASIC_USER=operator \
    --env AV_BASIC_PASSWORD=password \
    docker.io/library/python:3.13-alpine@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0 \
    /usr/local/bin/av "$@"
}

run_cli profiles >"$workdir/profiles"
grep --quiet '^infisical-integration' "$workdir/profiles"
grep --quiet '^openbao-integration' "$workdir/profiles"

run_cli routes >"$workdir/routes"
grep --quiet $'^openbao-upstream\tinjecting\topenbao-integration\tupstream-auth$' "$workdir/routes"
grep --quiet $'^openbao-stream\tinjecting\topenbao-integration\tupstream-stream$' "$workdir/routes"
grep --quiet $'^openbao-x-api\tinjecting\topenbao-integration\tupstream-x-api$' "$workdir/routes"
grep --quiet $'^credentialless-upstream\ttunnel\topenbao-integration\tupstream-tunnel$' "$workdir/routes"
if grep --quiet '^ungranted-upstream' "$workdir/routes"; then
  echo "ungranted route was disclosed by CLI discovery" >&2
  exit 1
fi

# shellcheck disable=SC2016 # The child shell, not this harness, expands these variables.
run_cli infisical-integration -- sh -eu -c '
  test "${INFISICAL_MARKER:-}" = infisical-ok
  test -z "${AV_TOKEN:-}"
  test -z "${AV_BASIC_USER:-}"
  test -z "${AV_BASIC_PASSWORD:-}"
'
# shellcheck disable=SC2016 # The child shell, not this harness, expands these variables.
run_cli openbao-integration -- sh -eu -c '
  test "${OPENBAO_MARKER:-}" = openbao+ok
  test -z "${AV_TOKEN:-}"
  test -z "${AV_BASIC_USER:-}"
  test -z "${AV_BASIC_PASSWORD:-}"
'

# The wrapped child trusts a synthetic upstream CA that is deliberately
# distinct from AV's interception CA. Successful HTTPS therefore proves that
# the configured credentialless destination remained opaque end to end.
if ! docker run --rm --pull never \
  --network "container:$av_container" \
  --read-only \
  --tmpfs /tmp \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --volume "$workdir/av:/usr/local/bin/av:ro" \
  --volume "$AV_POSTGRES_TLS_DIR/proxy-transport-ca.crt:/trust/transport.crt:ro" \
  --volume "$AV_POSTGRES_TLS_DIR/tunnel-ca.crt:/trust/tunnel-ca.crt:ro" \
  --env AV_URL=http://127.0.0.1:14322 \
  --env AV_BASIC_USER=operator \
  --env AV_BASIC_PASSWORD=password \
  --env AV_PROXY_TRANSPORT_CA_FILE=/trust/transport.crt \
  --env AV_SYSTEM_CA_FILE=/trust/tunnel-ca.crt \
  --env RUST_LOG=av=debug \
  docker.io/library/python:3.13-alpine@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0 \
  /usr/local/bin/av run openbao-integration -- python -c \
  'import os, urllib.request; assert "AV_SYSTEM_CA_FILE" not in os.environ; assert urllib.request.urlopen("https://upstream-tunnel/tunnel", timeout=10).read() == b"credentialless-tunnel-ok"'; then
  "${compose[@]}" logs --no-color av upstream >&2
  exit 1
fi

printf 'connector_cli_integration=ok\n'
