#!/usr/bin/env bash

# Generate disposable TLS material shared by the integration, security, and
# local managed harnesses. The caller owns and removes the target directory.
generate_integration_tls() {
  local target=$1

  mkdir -p "$target"
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$target/server.key" \
    -out "$target/server.crt" \
    -subj "/CN=postgres" \
    -addext "subjectAltName=DNS:postgres" >/dev/null 2>&1
  chmod 0600 "$target/server.key"

  openssl req -x509 -newkey ed25519 -nodes -days 1 \
    -keyout "$target/proxy-ca.key" \
    -out "$target/proxy-ca.crt" \
    -subj "/CN=av-integration-proxy-ca" >/dev/null 2>&1
  openssl req -x509 -newkey ed25519 -nodes -days 1 \
    -keyout "$target/proxy-transport-ca.key" \
    -out "$target/proxy-transport-ca.crt" \
    -subj "/CN=AV synthetic transport test CA" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$target/proxy-transport.key" \
    -out "$target/proxy-transport.csr" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost" >/dev/null 2>&1
  openssl x509 -req -days 1 \
    -in "$target/proxy-transport.csr" \
    -CA "$target/proxy-transport-ca.crt" \
    -CAkey "$target/proxy-transport-ca.key" \
    -CAcreateserial \
    -copy_extensions copy \
    -out "$target/proxy-transport.crt" >/dev/null 2>&1

  openssl req -x509 -newkey ed25519 -nodes -days 1 \
    -keyout "$target/tunnel-ca.key" \
    -out "$target/tunnel-ca.crt" \
    -subj "/CN=AV synthetic tunnel test CA" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$target/tunnel.key" \
    -out "$target/tunnel.csr" \
    -subj "/CN=upstream-tunnel" \
    -addext "subjectAltName=DNS:upstream-tunnel" >/dev/null 2>&1
  openssl x509 -req -days 1 \
    -in "$target/tunnel.csr" \
    -CA "$target/tunnel-ca.crt" \
    -CAkey "$target/tunnel-ca.key" \
    -CAcreateserial \
    -copy_extensions copy \
    -out "$target/tunnel.crt" >/dev/null 2>&1

  # AV runs as a non-root distroless UID. These are disposable synthetic
  # fixtures, mounted read-only and destroyed by each harness cleanup trap.
  chmod 0444 \
    "$target/proxy-ca.key" \
    "$target/proxy-ca.crt" \
    "$target/proxy-transport-ca.crt" \
    "$target/proxy-transport.key" \
    "$target/proxy-transport.crt" \
    "$target/tunnel.crt" \
    "$target/tunnel.key"
}
