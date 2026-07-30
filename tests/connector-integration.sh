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
compose=(docker compose --project-name "av-connectors-${UID}-$$" --file "$root/tests/integration/compose.yml")
if [[ ${AV_ENFORCED_CONTAINER_TEST:-0} == 1 ]]; then
  compose+=(--file "$root/tests/integration/enforced-container.compose.yml")
fi
workdir=$(mktemp -d "$root/.tmp.connector-cli.XXXXXX")
export AV_POSTGRES_TLS_DIR="$workdir/postgres-tls"
test_containers=()

cleanup() {
  if ((${#test_containers[@]})); then
    docker rm --force "${test_containers[@]}" >/dev/null 2>&1 || true
  fi
  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$workdir"
}
report_failure() {
  local status=$1
  local line=$2
  printf 'connector integration failed at line %d\n' "$line" >&2
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
grep --quiet '^openbao-dynamic' "$workdir/profiles"
grep --quiet '^openbao-integration' "$workdir/profiles"

run_cli routes >"$workdir/routes"
grep --quiet $'^openbao-upstream\tinjecting\topenbao-integration\tupstream-auth$' "$workdir/routes"
grep --quiet $'^openbao-stream\tinjecting\topenbao-integration\tupstream-stream$' "$workdir/routes"
grep --quiet $'^openbao-dynamic-buffered\tinjecting\topenbao-dynamic\tupstream-dynamic$' "$workdir/routes"
grep --quiet $'^openbao-dynamic-error\tinjecting\topenbao-dynamic\tupstream$' "$workdir/routes"
grep --quiet $'^openbao-dynamic-stream\tinjecting\topenbao-dynamic\tupstream-dynamic-stream$' "$workdir/routes"
grep --quiet $'^openbao-x-api\tinjecting\topenbao-integration\tupstream-x-api$' "$workdir/routes"
grep --quiet $'^credentialless-upstream\ttunnel\topenbao-integration\tupstream-tunnel$' "$workdir/routes"
if grep --quiet '^ungranted-upstream' "$workdir/routes"; then
  echo "ungranted route was disclosed by CLI discovery" >&2
  exit 1
fi

if [[ ${AV_ENFORCED_CONTAINER_TEST:-0} == 1 ]]; then
  postgres_container=$("${compose[@]}" ps --quiet postgres)
  AV_ENFORCED_CLI="${AV_ENFORCED_CLI:-$workdir/av}" \
    AV_ENFORCED_SERVER_CONTAINER="$av_container" \
    AV_ENFORCED_POSTGRES_CONTAINER="$postgres_container" \
    "$root/tests/enforced-container-smoke.sh"
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

dynamic_role_count() {
  "${compose[@]}" exec --no-TTY postgres \
    psql -U infisical -d av -tAc "
      SELECT count(*)
      FROM pg_auth_members memberships
      JOIN pg_roles parent ON parent.oid = memberships.roleid
      WHERE parent.rolname = 'av_owner'
    "
}

wait_for_dynamic_role_count() {
  local expected=$1
  for _ in $(seq 1 100); do
    if [[ $(dynamic_role_count) == "$expected" ]]; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

# A buffered Tier 2 request owns one dynamic credential and revokes it before
# returning the redacted response.
dynamic_role_baseline=$(dynamic_role_count)
docker run --rm --pull never \
  --network "container:$av_container" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  docker.io/library/python:3.13-alpine@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0 \
  python -c '
import base64
import re
import urllib.request

request = urllib.request.Request(
    "http://127.0.0.1:14322/v1/proxy/openbao-dynamic-buffered/dynamic",
    headers={"Authorization": "Basic " + base64.b64encode(b"operator:password").decode()},
)
body = urllib.request.urlopen(request, timeout=10).read()
assert re.fullmatch(rb"(?:\[REDACTED\])+", body)
'
[[ $(dynamic_role_count) == "$dynamic_role_baseline" ]]

# A connect failure after acquisition also revokes rather than waiting for TTL.
docker run --rm --pull never \
  --network "container:$av_container" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  docker.io/library/python:3.13-alpine@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0 \
  python -c '
import base64
import urllib.error
import urllib.request

request = urllib.request.Request(
    "http://127.0.0.1:14322/v1/proxy/openbao-dynamic-error/dynamic-error",
    headers={"Authorization": "Basic " + base64.b64encode(b"operator:password").decode()},
)
try:
    urllib.request.urlopen(request, timeout=10)
except urllib.error.HTTPError as error:
    assert error.code == 502
else:
    raise AssertionError("dynamic proxy failure route unexpectedly succeeded")
'
wait_for_dynamic_role_count "$dynamic_role_baseline"

# Dropping a streaming response triggers the lease guard immediately; it must
# not wait for the upstream's delayed tail or the ten-second backend TTL.
docker run --rm --pull never \
  --network "container:$av_container" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  docker.io/library/python:3.13-alpine@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0 \
  python -c '
import base64
import urllib.request

request = urllib.request.Request(
    "http://127.0.0.1:14322/v1/proxy/openbao-dynamic-stream/dynamic-stream",
    headers={
        "Authorization": "Basic " + base64.b64encode(b"operator:password").decode(),
        "Accept": "text/event-stream",
    },
)
response = urllib.request.urlopen(request, timeout=10)
assert response.readline() == b"data: ready\n"
response.close()
'
wait_for_dynamic_role_count "$dynamic_role_baseline"

# A real OpenBao database lease is owned by the wrapped child: it stays usable
# across renewal, is synchronously revoked when the child exits, and never
# exposes the backend lease ID to the child.
mkdir "$workdir/dynamic-credentials"
chmod 0700 "$workdir/dynamic-credentials"
docker run --rm --pull never \
  --network "container:$av_container" \
  --user "$(id -u):$(id -g)" \
  --read-only \
  --tmpfs /tmp \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --volume "$workdir/av:/usr/local/bin/av:ro" \
  --volume "$workdir/dynamic-credentials:/capture" \
  --env AV_URL=http://127.0.0.1:14322 \
  --env AV_BASIC_USER=operator \
  --env AV_BASIC_PASSWORD=password \
  --entrypoint /usr/local/bin/av \
  docker.io/library/postgres:14-alpine@sha256:f1341c01408dc7278e9d365ed4f860cd3f87dd16b4464ac326fc0f422083a579 \
  openbao-dynamic -- sh -ec '
    umask 077
    printf "%s\n" "$DATABASE_USER" > /capture/user
    printf "%s\n" "$DATABASE_PASSWORD" > /capture/password
    PGPASSWORD="$DATABASE_PASSWORD" psql -h postgres -U "$DATABASE_USER" -d av -tAc "SELECT 1" >/dev/null
    sleep 12
    PGPASSWORD="$DATABASE_PASSWORD" psql -h postgres -U "$DATABASE_USER" -d av -tAc "SELECT 1" >/dev/null
  '
if docker run --rm --pull never \
  --network "container:$av_container" \
  --user "$(id -u):$(id -g)" \
  --read-only \
  --tmpfs /tmp \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --volume "$workdir/dynamic-credentials:/capture:ro" \
  --entrypoint sh \
  docker.io/library/postgres:14-alpine@sha256:f1341c01408dc7278e9d365ed4f860cd3f87dd16b4464ac326fc0f422083a579 \
  -ec '
    IFS= read -r user < /capture/user
    IFS= read -r password < /capture/password
    PGPASSWORD="$password" psql -h postgres -U "$user" -d av -tAc "SELECT 1" >/dev/null 2>&1
  '; then
  echo "revoked OpenBao database credential remained usable" >&2
  exit 1
fi

# Grant removal is enforced at renewal time. The wrapper must terminate the
# child and AV must revoke the credential rather than letting the environment
# grant remain usable until the backend's maximum TTL.
mkdir "$workdir/revoked-grant-credentials"
chmod 0700 "$workdir/revoked-grant-credentials"
revoked_grant_container=$(docker run --detach --pull never \
  --network "container:$av_container" \
  --user "$(id -u):$(id -g)" \
  --read-only \
  --tmpfs /tmp \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --volume "$workdir/av:/usr/local/bin/av:ro" \
  --volume "$workdir/revoked-grant-credentials:/capture" \
  --env AV_URL=http://127.0.0.1:14322 \
  --env AV_BASIC_USER=operator \
  --env AV_BASIC_PASSWORD=password \
  --entrypoint /usr/local/bin/av \
  docker.io/library/postgres:14-alpine@sha256:f1341c01408dc7278e9d365ed4f860cd3f87dd16b4464ac326fc0f422083a579 \
  openbao-dynamic -- sh -ec '
    umask 077
    printf "%s\n" "$DATABASE_USER" > /capture/user
    printf "%s\n" "$DATABASE_PASSWORD" > /capture/password
    PGPASSWORD="$DATABASE_PASSWORD" psql -h postgres -U "$DATABASE_USER" -d av -tAc "SELECT 1" >/dev/null
    sleep 120
  ')
test_containers+=("$revoked_grant_container")
for _ in $(seq 1 50); do
  if [[ -s "$workdir/revoked-grant-credentials/user" && -s "$workdir/revoked-grant-credentials/password" ]]; then
    break
  fi
  sleep 0.2
done
[[ -s "$workdir/revoked-grant-credentials/user" ]]
[[ -s "$workdir/revoked-grant-credentials/password" ]]
# shellcheck disable=SC2016 # The disposable database container expands this.
"${compose[@]}" run --no-deps --rm managed-seed sh -ec '
  database_url="$(cat /state/av-control-plane-url)"
  psql "$database_url" -v ON_ERROR_STOP=1 -c \
    "DELETE FROM av_capability_grants WHERE subject = '\''basic:operator'\'' AND profile = '\''openbao-dynamic'\''" >/dev/null
'
if ! revoked_grant_status=$(timeout 20s docker wait "$revoked_grant_container"); then
  echo "dynamic profile child survived grant revocation" >&2
  exit 1
fi
if [[ "$revoked_grant_status" == 0 ]]; then
  echo "dynamic profile wrapper exited successfully after grant revocation" >&2
  exit 1
fi
if docker run --rm --pull never \
  --network "container:$av_container" \
  --user "$(id -u):$(id -g)" \
  --read-only \
  --tmpfs /tmp \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --volume "$workdir/revoked-grant-credentials:/capture:ro" \
  --entrypoint sh \
  docker.io/library/postgres:14-alpine@sha256:f1341c01408dc7278e9d365ed4f860cd3f87dd16b4464ac326fc0f422083a579 \
  -ec '
    IFS= read -r user < /capture/user
    IFS= read -r password < /capture/password
    PGPASSWORD="$password" psql -h postgres -U "$user" -d av -tAc "SELECT 1" >/dev/null 2>&1
  '; then
  echo "grant-revoked OpenBao database credential remained usable" >&2
  exit 1
fi

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

# Every normal connector CI run proves that static connector values, request
# canaries, and both fields of real short-lived database credentials are absent
# from AV process logs and its persisted audit metadata.
docker logs "$av_container" >"$workdir/av.log" 2>&1
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
    "sensitive connector canary" "$canary" "$workdir/av.log" "$workdir/audit.log"
done
for canary_file in \
  "$workdir/dynamic-credentials/user" \
  "$workdir/dynamic-credentials/password" \
  "$workdir/revoked-grant-credentials/user" \
  "$workdir/revoked-grant-credentials/password"
do
  assert_pattern_file_absent_from \
    "short-lived database credential" \
    "$canary_file" "$workdir/av.log" "$workdir/audit.log"
done

printf 'connector_cli_integration=ok\n'
