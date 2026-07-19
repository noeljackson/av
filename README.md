# av

`av` is a stateless, OIDC-authenticated connector and credential proxy. It does
not have registration, a user database, or an application-secret database.
Infisical and OpenBao are connector backends; neither is embedded in `av`, and
switching a profile between them does not change the CLI or proxy contract.

## What it implements

| Tier | `av` behavior | Credential exposure |
|---|---|---|
| 1 — dynamic | OpenBao reads, including dynamic-secret response data | Generated values are limited by the backend lease |
| 2 — proxy | Fixed HTTPS origin, method/path allowlist, server-side header injection | Credential never enters the caller |
| 3 — process environment | Authenticated profile lease followed by local child-process execution | Only the `av` process and its child receive values |

An Infisical profile maps directly to an existing project, environment, and
path; no dedicated `av` project is required. OpenBao profiles map to an API
secret path such as `secret/data/infra` or `database/creds/read-only`.

## Daily use

```bash
# One OIDC device login; the bearer token stays in the Linux kernel user keyring.
av login

av profiles
av infra -- ./scripts/atmos-run terraform plan headscale -s system
av codewire-dev -- cargo test
av codewire-prod -- ./scripts/check-production

av logout
```

`av codewire-dev -- ...` fetches the configured Infisical profile and adds the
returned keys only to the child process. It never writes application secrets to
disk or to the kernel keyring. The keyring contains only the short-lived OIDC
access token. `AV_TOKEN` is available for CI; optional Basic credentials use
`AV_BASIC_USER` and `AV_BASIC_PASSWORD`.

For Tier 2, callers use a named route:

```text
https://av.tail.noel.sh/v1/proxy/cloudflare-dns/zones/<zone>/dns_records
```

The caller supplies its OIDC bearer token. `av` strips caller authorization,
cookies, hop-by-hop headers, and redirects; checks the configured method/path;
then injects the Infisical credential at the fixed upstream origin. There is no
arbitrary destination parameter. Hetzner is intentionally not part of the
initial route set.

## Authentication

Production mode is `oidc` or `oidc_or_basic`. OIDC discovery, JWT signature,
issuer, audience, expiry, and group membership are verified by the server. The
browser UI uses Authorization Code + PKCE; the CLI uses Device Authorization.
Configure both grants on the Zitadel public client and register the exact UI
callback, normally `https://av.tail.noel.sh/`.

Basic auth is optional and static: usernames are config, password values are
read from mounted files on every request. There is no sign-up endpoint. Disabled
auth is rejected unless the listener is loopback and
`AV_ALLOW_INSECURE_AUTH=1` is explicitly set.

## Configuration

Configuration is strict JSON; unknown fields fail startup. Start from
[`config.example.json`](config.example.json). Connector credentials are file
references, never literal values in the config. Infisical supports Kubernetes,
Universal, and token auth. OpenBao supports Kubernetes, AppRole, and token auth;
Kubernetes is preferred for in-cluster workloads and AppRole for external
automation.

```bash
AV_ALLOW_INSECURE_AUTH=1 cargo run -- serve --config config.local.json
```

## Supply-chain posture

- Rust and JavaScript dependency versions are exact and committed in locks.
- The UI uses Bun with lifecycle scripts disabled, an isolated linker, and a
  30-day minimum release age for direct and transitive packages.
- `.supplychain/bun-baseline.json` records reviewed integrity, maintainer, and
  advertised provenance metadata.
- CI uses `noeljackson/supplychain` pinned to an immutable commit.
- Release artifacts and container images are built by GitHub Actions and receive
  GitHub artifact attestations.

Run the local gates with:

```bash
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
(cd ui && /usr/bin/bun install --frozen-lockfile && /usr/bin/bun run check && /usr/bin/bun run build)
supplychain verify-bun --minimum-age-days=30 --baseline=../.supplychain/bun-baseline.json ui
helm lint chart/av
tests/connector-integration.sh
```

The integration runner starts separate pinned containers for AV, Infisical,
Postgres, Redis, OpenBao, and a credential-aware upstream. It bootstraps only
disposable test data on an internal Docker network, verifies both connector
reads plus Tier 2 injection, and removes containers and volumes on exit.

Install or update the CLI repeatedly from an attested release without a
`curl | sh` path:

```bash
./scripts/install                 # latest release
AV_VERSION=v0.1.0 ./scripts/install
```

## Helm

The chart never creates connector credentials. Mount an existing Kubernetes
Secret with `credentialSecrets`, and put only file paths in `config`. Tailnet
ingress/DNS policy belongs in downstream values, so the chart remains
upstreamable.

```bash
helm upgrade --install av oci://ghcr.io/noeljackson/charts/av \
  --namespace av --create-namespace -f values.av.yaml
```
