#!/usr/bin/env bash
# Release-image test for SessionService and `av run`. Rust tests cover the
# intercepted request policy; this verifies the two-container lifecycle.
set -euo pipefail

image=${1:-${AV_IMAGE:-av:test}}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d "$root/.tmp.transparent-smoke.XXXXXX")
server="av-transparent-smoke-${UID}-$$"
extract="${server}-extract"
client="${server}-client"
busybox='docker.io/library/busybox@sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028'

cleanup() {
  docker rm -f "$server" "$extract" "$client" >/dev/null 2>&1 || true
  find "$tmp" -mindepth 1 -type f -delete 2>/dev/null || true
  rmdir "$tmp" 2>/dev/null || true
}
trap cleanup EXIT

openssl req -x509 -newkey ed25519 -nodes -days 1 -subj '/CN=av-transparent-smoke' \
  -keyout "$tmp/ca.key" -out "$tmp/ca.crt" >/dev/null 2>&1
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' \
  -keyout "$tmp/transport.key" -out "$tmp/transport.crt" >/dev/null 2>&1
# shellcheck disable=SC2016 # Literal synthetic Argon2id fixture, not shell variables.
printf '%s\n' '$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc' >"$tmp/password.argon2id"
printf '%s\n' 'synthetic-connector-token' >"$tmp/connector-token"
printf '%s\n' 'sqlite:/state/av.sqlite' >"$tmp/database-url"
cat >"$tmp/config.json" <<'EOF'
{"listen":"0.0.0.0:14322","public_url":"http://127.0.0.1:14322","mode":"managed","managed":{"database_url_file":"/state/database-url","initial_owner_oidc_subject":"basic:operator"},"auth":{"mode":"basic","issuer":"","client_id":"","audiences":[],"scopes":[],"signing_algorithms":["RS256"],"allowed_groups":[],"group_claim":"groups","basic_users":[{"username":"operator","password_hash_file":"/state/password.argon2id"}]},"connectors":{"synthetic":{"kind":"infisical","base_url":"http://127.0.0.1:9","auth":{"type":"token","token_file":"/state/connector-token"}}},"profiles":{"smoke":{"connector":"synthetic","project_id":"synthetic","environment":"dev","secret_path":"/","allowed_keys":["API_TOKEN"]}},"proxy_routes":{"synthetic":{"profile":"smoke","base_url":"https://api.example.test","secret_key":"API_TOKEN","header":"Authorization","header_prefix":"Bearer ","allowed_methods":["GET"],"allowed_path_prefixes":["/v1"],"allowed_request_headers":[],"allowed_response_headers":[],"allowed_query_parameters":[],"allowed_content_types":[],"max_body_bytes":1024}},"transparent_proxy":{"listen":"0.0.0.0:14323","proxy_url":"https://localhost:14323","transport_tls_certificate_file":"/state/transport.crt","transport_tls_private_key_file":"/state/transport.key","ca_certificate_file":"/state/ca.crt","ca_private_key_file":"/state/ca.key","session_ttl_seconds":5,"session_max_lifetime_seconds":20},"max_connector_concurrency":1,"api_rate_limit_per_second":50,"api_rate_limit_burst":100}
EOF
chmod 0700 "$tmp"

docker run --detach --name "$server" --read-only --tmpfs /tmp --network none \
  --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges:true --volume "$tmp:/state" \
  --env AV_ALLOW_INSECURE_CONNECTORS=integration-tests-only \
  "$image" serve --config /state/config.json >/dev/null
for _ in $(seq 1 20); do
  if docker run --rm --network "container:$server" "$busybox" \
    wget -qO- http://127.0.0.1:14322/healthz >/dev/null 2>&1; then break; fi
  sleep 1
done
if ! docker run --rm --network "container:$server" "$busybox" \
  wget -qO- http://127.0.0.1:14322/healthz >/dev/null; then
  docker logs "$server" >&2 || true
  exit 1
fi
password_hash=$(<"$tmp/password.argon2id")
sqlite3 "$tmp/av.sqlite" \
  "INSERT INTO av_basic_users (username, password_hash, enabled) VALUES ('operator', '$password_hash', 1);"
docker run --rm --network "container:$server" "$busybox" \
  wget -qO- --header='Authorization: Basic b3BlcmF0b3I6cGFzc3dvcmQ=' \
  --post-data='subject=basic%3Aoperator&profile=smoke' \
  http://127.0.0.1:14322/ui/owner/grants >/dev/null

docker create --name "$extract" "$image" >/dev/null
docker cp "$extract:/usr/local/bin/av" "$tmp/av"
chmod 0755 "$tmp/av"
docker run --rm --network "container:$server" --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges:true --volume "$tmp/av:/usr/local/bin/av:ro" \
  --volume "$tmp/transport.crt:/trust/transport.crt:ro" \
  --env AV_URL=http://127.0.0.1:14322 --env AV_BASIC_USER=operator --env AV_BASIC_PASSWORD=password \
  --env AV_PROXY_TRANSPORT_CA_FILE=/trust/transport.crt \
  --env AV_SYSTEM_CA_FILE=/trust/transport.crt \
  "$busybox" /usr/local/bin/av run smoke -- sh -ec '
    case "${HTTPS_PROXY:-}" in http://127.0.0.1:*) ;; *) exit 1;; esac
    test -f "$SSL_CERT_FILE"
    test -z "${AV_TOKEN:-}"
    test -z "${AV_BASIC_USER:-}"
    test -z "${AV_BASIC_PASSWORD:-}"
    test -z "${AV_PROXY_TRANSPORT_CA_FILE:-}"
    sleep 12
  '

# Revoking the live profile grant must make the next renewal fail and kill the
# child; it must not leave an orphaned 30-second process behind.
docker run --detach --name "$client" --network "container:$server" --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --volume "$tmp/av:/usr/local/bin/av:ro" \
  --volume "$tmp/transport.crt:/trust/transport.crt:ro" \
  --env AV_URL=http://127.0.0.1:14322 --env AV_BASIC_USER=operator --env AV_BASIC_PASSWORD=password \
  --env AV_PROXY_TRANSPORT_CA_FILE=/trust/transport.crt \
  --env AV_SYSTEM_CA_FILE=/trust/transport.crt \
  "$busybox" /usr/local/bin/av run smoke -- sleep 30 >/dev/null
sleep 1
docker run --rm --network "container:$server" "$busybox" \
  wget -qO- --header='Authorization: Basic b3BlcmF0b3I6cGFzc3dvcmQ=' \
  --post-data='subject=basic%3Aoperator&profile=smoke' \
  http://127.0.0.1:14322/ui/owner/grants/revoke >/dev/null
for _ in $(seq 1 10); do
  if [[ $(docker inspect --format '{{.State.Running}}' "$client") == false ]]; then
    break
  fi
  sleep 1
done
if [[ $(docker inspect --format '{{.State.Running}}' "$client") != false ]]; then
  echo "revoked proxy session did not terminate its child" >&2
  exit 1
fi
if [[ $(docker inspect --format '{{.State.ExitCode}}' "$client") == 0 ]]; then
  echo "revoked proxy session unexpectedly exited successfully" >&2
  exit 1
fi
printf 'transparent_container_smoke=ok\n'
