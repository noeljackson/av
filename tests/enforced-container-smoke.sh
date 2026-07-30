#!/usr/bin/env bash
set -euo pipefail

: "${AV_ENFORCED_CLI:?set AV_ENFORCED_CLI to the release AV CLI}"
: "${AV_ENFORCED_SERVER_CONTAINER:?set AV_ENFORCED_SERVER_CONTAINER to the AV server container}"
: "${AV_ENFORCED_POSTGRES_CONTAINER:?set AV_ENFORCED_POSTGRES_CONTAINER to the integration PostgreSQL container}"
: "${AV_POSTGRES_TLS_DIR:?set AV_POSTGRES_TLS_DIR to the disposable integration TLS directory}"

target_image='docker.io/library/python:3.13-alpine@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0'
helper_image=$(docker inspect "$AV_ENFORCED_SERVER_CONTAINER" --format '{{.Image}}')
workspace=$(dirname "$AV_ENFORCED_CLI")
interrupted_pid=''

# shellcheck disable=SC2329 # Invoked by the EXIT trap.
cleanup() {
  if [[ -n $interrupted_pid ]]; then
    kill -KILL "$interrupted_pid" >/dev/null 2>&1 || true
    docker ps --all --quiet --filter "name=^/av-${interrupted_pid}-" |
      xargs --no-run-if-empty docker rm --force >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

docker image inspect "$target_image" "$helper_image" >/dev/null

run_enforced() {
  AV_URL=http://127.0.0.1:14322 \
    AV_BASIC_USER=operator \
    AV_BASIC_PASSWORD=password \
    AV_PROXY_TRANSPORT_CA_FILE="$AV_POSTGRES_TLS_DIR/proxy-transport-ca.crt" \
    AV_SYSTEM_CA_FILE="$AV_POSTGRES_TLS_DIR/tunnel-ca.crt" \
    "$AV_ENFORCED_CLI" run openbao-integration \
      --container \
      --image "$target_image" \
      --helper-image "$helper_image" \
      --workspace "$workspace" \
      -- "$@"
}

# The child receives only a loopback proxy and public CA material. It can use
# an explicitly granted HTTPS tunnel, but the network-none namespace has no
# route for direct TCP, metadata, UDP/443, or an undeclared proxy destination.
run_enforced python -c '
import os
import socket
import urllib.request

for name in (
    "AV_TOKEN",
    "AV_AGENT_TOKEN",
    "AV_AGENT_TOKEN_FILE",
    "AV_BASIC_USER",
    "AV_BASIC_PASSWORD",
    "AV_PROXY_TRANSPORT_CA_FILE",
    "AV_SYSTEM_CA_FILE",
):
    assert name not in os.environ, name
for name in ("NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy"):
    assert os.environ.get(name, "") == "", name

assert (
    urllib.request.urlopen(
        "https://upstream-tunnel/tunnel", timeout=10
    ).read()
    == b"credentialless-tunnel-ok"
)

for address in (("1.1.1.1", 443), ("169.254.169.254", 80)):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        sock.connect(address)
        raise AssertionError(f"direct TCP unexpectedly reached {address}")
    except OSError:
        pass
    finally:
        sock.close()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    try:
        sock.sendto(b"x", ("1.1.1.1", 443))
        raise AssertionError("direct UDP unexpectedly succeeded")
    except OSError:
        pass
finally:
    sock.close()

try:
    urllib.request.urlopen("https://unknown.invalid/", timeout=3)
    raise AssertionError("unknown proxy destination unexpectedly succeeded")
except Exception:
    pass

print("enforced_container_smoke=ok")
'

revocation_count() {
  docker exec "$AV_ENFORCED_POSTGRES_CONTAINER" \
    psql -U infisical -d av -tAc \
    "SELECT count(*) FROM av_audit_events WHERE action = 'transparent_proxy_session_revoked'"
}

active_session_count() {
  docker exec "$AV_ENFORCED_POSTGRES_CONTAINER" \
    psql -U infisical -d av -tAc \
    "SELECT count(*) FROM av_proxy_sessions WHERE subject = 'basic:operator' AND revoked = FALSE"
}

before_revocations=$(revocation_count)
before_active=$(active_session_count)
AV_URL=http://127.0.0.1:14322 \
  AV_BASIC_USER=operator \
  AV_BASIC_PASSWORD=password \
  AV_PROXY_TRANSPORT_CA_FILE="$AV_POSTGRES_TLS_DIR/proxy-transport-ca.crt" \
  AV_SYSTEM_CA_FILE="$AV_POSTGRES_TLS_DIR/tunnel-ca.crt" \
  "$AV_ENFORCED_CLI" run openbao-integration \
    --container \
    --image "$target_image" \
    --helper-image "$helper_image" \
    --workspace "$workspace" \
    -- python -c 'import time; time.sleep(120)' &
interrupted_pid=$!

container_started=0
for _ in $(seq 1 100); do
  if docker ps --format '{{.Names}}' | grep --quiet "^av-${interrupted_pid}-.*-child$"; then
    container_started=1
    break
  fi
  sleep 0.1
done
[[ $container_started == 1 ]]

kill -INT "$interrupted_pid"
set +e
wait "$interrupted_pid"
status=$?
set -e
[[ $status == 130 ]]

for _ in $(seq 1 100); do
  remaining=$(docker ps --all --quiet --filter "name=^/av-${interrupted_pid}-" | wc -l)
  active=$(active_session_count)
  after_revocations=$(revocation_count)
  if [[ $remaining == 0 && $active == "$before_active" && $after_revocations -gt $before_revocations ]]; then
    interrupted_pid=''
    printf '%s\n' 'enforced_container_interrupt_cleanup=ok'
    exit 0
  fi
  sleep 0.1
done

printf '%s\n' 'enforced container interruption did not remove containers and revoke its session' >&2
exit 1
