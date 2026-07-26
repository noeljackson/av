#!/usr/bin/env bash
set -euo pipefail

image=${1:-av:test}
container="av-container-smoke-$$"
workdir=$(mktemp -d)
trap 'docker rm -f "$container" >/dev/null 2>&1 || true; rm -rf "$workdir"' EXIT

# shellcheck disable=SC2016 # literal synthetic Argon2id PHC test fixture
printf '%s\n' '$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc' >"$workdir/password.argon2id"
chmod 0444 "$workdir/password.argon2id"

[[ $(docker image inspect "$image" --format '{{.Config.User}}') == "65532:65532" ]]

docker run --detach --name "$container" \
  --publish 127.0.0.1::14322 \
  --mount "type=bind,src=$PWD/tests/config.basic.container.json,dst=/etc/av/config.json,readonly" \
  --mount "type=bind,src=$workdir/password.argon2id,dst=/run/av/password.argon2id,readonly" \
  "$image" serve --config /etc/av/config.json >/dev/null

port=$(docker port "$container" 14322/tcp | awk -F: 'NR == 1 {print $NF}')
base_url="http://127.0.0.1:$port"
for _ in {1..30}; do
  curl --fail --silent "$base_url/healthz" >/dev/null 2>&1 && break
  sleep 1
done
curl --fail --silent "$base_url/healthz" >/dev/null

curl --fail --silent --dump-header "$workdir/root-headers" \
  --output "$workdir/root" "$base_url/"
for header in \
  cache-control \
  content-security-policy \
  x-content-type-options \
  referrer-policy \
  permissions-policy
do
  grep --ignore-case --quiet "^${header}:" "$workdir/root-headers"
done
grep --quiet 'authentication required' "$workdir/root"
grep --quiet 'src="/assets/av.js"' "$workdir/root"
if grep --quiet 'container-smoke' "$workdir/root"; then
  echo 'locked UI leaked runtime configuration' >&2
  exit 1
fi

curl --fail --silent --dump-header "$workdir/ui-asset-headers" \
  --output "$workdir/ui-asset" "$base_url/assets/av.js"
grep --ignore-case --quiet '^content-type: text/javascript' "$workdir/ui-asset-headers"
grep --quiet 'code_challenge_method: "S256"' "$workdir/ui-asset"

AV_UI_CONTAINER="$container" AV_UI_URL=http://127.0.0.1:14322 tests/ui-smoke.sh

status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --user 'operator:password' "$base_url/ui/owner") # gitleaks:allow -- synthetic smoke-test credential
[[ "$status" == "404" ]]

status=$(curl --silent --output "$workdir/ui-session" --write-out '%{http_code}' \
  --user 'operator:password' "$base_url/ui/session") # gitleaks:allow -- synthetic smoke-test credential
[[ "$status" == "200" ]]
grep --quiet 'runtime matrix' "$workdir/ui-session"
grep --quiet 'container-smoke' "$workdir/ui-session"

status=$(curl --silent --output "$workdir/profiles" --write-out '%{http_code}' \
  --user 'operator:password' "$base_url/v1/profiles") # gitleaks:allow -- synthetic smoke-test credential
[[ "$status" == "200" ]]
grep --quiet '"name":"container-smoke"' "$workdir/profiles"

status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --user 'operator:wrong-password' "$base_url/v1/profiles") # gitleaks:allow -- synthetic negative-test credential
[[ "$status" == "401" ]]

status=$(curl --silent --output /dev/null --write-out '%{http_code}' "$base_url/v1/profiles")
[[ "$status" == "401" ]]

# The generated Connect contract is the preferred control-plane surface. Keep
# this at HTTP level so the release image, routing, JSON codec, and auth all
# get exercised together.
status=$(curl --silent --output "$workdir/connect-profiles" --write-out '%{http_code}' \
  --header 'Content-Type: application/json' \
  --header 'Connect-Protocol-Version: 1' \
  --data '{}' \
  --user 'operator:password' "$base_url/av.v1.SessionService/ListProfiles") # gitleaks:allow -- synthetic smoke-test credential
[[ "$status" == "200" ]]
grep --quiet '"name":"container-smoke"' "$workdir/connect-profiles"

status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --header 'Content-Type: application/json' \
  --header 'Connect-Protocol-Version: 1' \
  --data '{}' "$base_url/av.v1.SessionService/ListProfiles")
[[ "$status" == "401" ]]

# Both generated Connect service namespaces must be routed ahead of the UI
# fallback. This unauthenticated control request proves that it reaches AV's
# auth boundary instead of the static-file handler.
status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --header 'Content-Type: application/json' \
  --header 'Connect-Protocol-Version: 1' \
  --data '{}' "$base_url/av.v1.ControlService/ListBasicUsers")
[[ "$status" == "401" ]]

status=$(curl --silent --output /dev/null --write-out '%{http_code}' "$base_url/v1/status")
[[ "$status" == "401" ]]

status=$(curl --silent --output "$workdir/status" --write-out '%{http_code}' \
  --user 'operator:password' "$base_url/v1/status") # gitleaks:allow -- synthetic smoke-test credential
[[ "$status" == "200" ]]
grep --quiet '"basicEnabled":true' "$workdir/status"
grep --quiet '"persistenceEnabled":false' "$workdir/status"

status=$(curl --silent --output /dev/null --write-out '%{http_code}' "$base_url/v1/register")
[[ "$status" == "404" ]]

printf 'container_basic_auth=ok\n'
