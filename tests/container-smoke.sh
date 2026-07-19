#!/usr/bin/env bash
set -euo pipefail

image=${1:-av:test}
container="av-container-smoke-$$"
workdir=$(mktemp -d)
trap 'docker rm -f "$container" >/dev/null 2>&1 || true; rm -rf "$workdir"' EXIT

printf '%s\n' 'correct-horse-test-only' >"$workdir/password"
chmod 0444 "$workdir/password"

[[ $(docker image inspect "$image" --format '{{.Config.User}}') == "65532:65532" ]]

docker run --detach --name "$container" \
  --publish 127.0.0.1::14322 \
  --mount "type=bind,src=$PWD/tests/config.basic.container.json,dst=/etc/av/config.json,readonly" \
  --mount "type=bind,src=$workdir/password,dst=/run/av/password,readonly" \
  "$image" serve --config /etc/av/config.json >/dev/null

port=$(docker port "$container" 14322/tcp | awk -F: 'NR == 1 {print $NF}')
base_url="http://127.0.0.1:$port"
for _ in {1..30}; do
  curl --fail --silent "$base_url/healthz" >/dev/null 2>&1 && break
  sleep 1
done
curl --fail --silent "$base_url/healthz" >/dev/null

status=$(curl --silent --output "$workdir/profiles" --write-out '%{http_code}' \
  --user 'operator:correct-horse-test-only' "$base_url/v1/profiles")
[[ "$status" == "200" ]]
grep --quiet '"name":"container-smoke"' "$workdir/profiles"

status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --user 'operator:wrong-password' "$base_url/v1/profiles")
[[ "$status" == "401" ]]

status=$(curl --silent --output /dev/null --write-out '%{http_code}' "$base_url/v1/profiles")
[[ "$status" == "401" ]]

status=$(curl --silent --output "$workdir/status" --write-out '%{http_code}' "$base_url/v1/status")
[[ "$status" == "200" ]]
grep --quiet '"basicEnabled":true' "$workdir/status"
grep --quiet '"persistenceEnabled":false' "$workdir/status"

status=$(curl --silent --output /dev/null --write-out '%{http_code}' "$base_url/v1/register")
[[ "$status" == "404" ]]

printf 'container_basic_auth=ok\n'
