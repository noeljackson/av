# av

`av` is an OIDC-authenticated connector and credential proxy. It does not have
registration or an application-secret database. Infisical and OpenBao are
connector backends; neither is embedded in `av`, and switching a profile
between them does not change the CLI or proxy contract.

AV has two deliberately separate operating modes:

- **Static** (the default) has an immutable JSON policy and no database.
- **Managed** retains the immutable connector bootstrap in JSON, but puts
  owner-managed Basic users and redacted audit metadata in SQLite (local) or an
  existing PostgreSQL database (Kubernetes). It never persists connector
  credentials or fetched secret values.

## What it implements

| Tier | `av` behavior | Credential exposure |
|---|---|---|
| 1 — dynamic | Reserved for lease-aware OpenBao engines | Not enabled until AV can revoke and renew leases |
| 2 — proxy | Fixed HTTPS origin and explicit method/path/query/header/content policy | Credential never enters the caller |
| 3 — process environment | Authenticated profile lease followed by local child-process execution | Only the `av` process and its child receive values |

An Infisical profile maps directly to an existing project, environment, and
path; no dedicated `av` project is required. OpenBao profiles currently map to
non-leased KV API paths such as `secret/data/infra`. Responses carrying a lease
are rejected until AV implements lease ownership and revocation.

## Daily use

```bash
# One OIDC device login; the bearer token stays in the Linux kernel user keyring.
av login

av profiles
av infra -- ./scripts/atmos-run terraform plan headscale -s system
av example-dev -- cargo test
av example-prod -- ./scripts/check-production

av logout
```

`av example-dev -- ...` fetches the configured Infisical profile and adds the
returned keys only to the child process. It never writes application secrets to
disk or to the kernel keyring. The keyring contains only the short-lived OIDC
access token. `AV_TOKEN` is available for CI; optional Basic credentials use
`AV_BASIC_USER` and `AV_BASIC_PASSWORD`.

For Tier 2, callers use a named route:

```text
https://av.tail.noel.sh/v1/proxy/cloudflare-dns/zones/<zone>/dns_records
```

The caller supplies its OIDC bearer token. `av` forwards only explicitly
allowlisted headers and query keys, checks method, canonical path, content type,
and body size, then inserts exactly one credential header at the fixed upstream
origin. Redirect and credential-bearing response headers are never forwarded.
There is no arbitrary destination parameter. Hetzner is intentionally not part
of the initial route set.

All `/v1/*` requests pass through a bounded in-process token bucket before
authentication or connector work. The defaults allow 50 requests per second
with a burst of 100 per AV process. Keep an ingress per-client limit as the
outer layer; the application limit is a global circuit breaker, not a
distributed client quota.

## Authentication

Production mode is `oidc` or `oidc_or_basic`. OIDC discovery, an explicit
asymmetric signing-algorithm allowlist, JWT signature, issuer, audience, expiry,
and group membership are verified by the server. The
browser UI uses Authorization Code + PKCE; the CLI uses Device Authorization.
Configure both grants on the Zitadel public client and register the exact UI
callback, normally `https://av.tail.noel.sh/`.

Basic auth is optional. In static mode, usernames are config and mounted files
hold Argon2id PHC hashes, never plaintext passwords. In managed mode, the first
configured OIDC subject is inserted only into an empty database and is the
owner; that owner can manage enabled Basic users through the authenticated
control API. Passwords are accepted only on the encrypted request, immediately
hashed with AV's bounded Argon2id policy, and never returned or audited. Hashes
are validated at startup in static mode.
AV accepts only bounded Argon2id v19 parameters (19–64 MiB, 2–6 iterations,
parallelism 1–4), and password verification is limited to two concurrent jobs.
There is no sign-up endpoint. Disabled auth is rejected unless the listener is loopback and
`AV_ALLOW_INSECURE_AUTH=1` is explicitly set.

### Local managed AV

`av local init` is a local-only control-plane bootstrap. It creates a
mode-`0600` JSON file and database URL file under XDG directories and a SQLite
database under XDG state. It does not start a service, register users, or store
any connector credential.

```bash
av local init \
  --issuer https://zitadel.example.com \
  --client-id av-local \
  --allowed-role av-users \
  --owner-subject '<exact Zitadel OIDC sub>'
av serve --config "${XDG_CONFIG_HOME:-$HOME/.config}/av/bootstrap.json"
```

Treat the `owner-subject` as an irreversible bootstrap value for a fresh local
database: changing it in JSON later does not replace an existing owner. Remove
the database explicitly if you intend to discard that local control plane.

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
tests/security-scan.sh
```

The integration runner starts separate pinned containers for AV, Infisical,
Postgres, Redis, OpenBao, and a credential-aware upstream. It bootstraps only
disposable test data on an internal Docker network, verifies both connector
reads plus hostile Tier 2 behavior, then copies the release CLI from the AV
image and verifies `av profiles` and both `av <profile> -- <command>` paths.
The CLI checks that wrapper credentials never reach its child process. The
runner removes containers and volumes on exit.
The security runner adds a pinned, isolated ZAP passive scan. See
[`SECURITY.md`](SECURITY.md) for the trust boundaries and test procedure.

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

For one shared AV control plane in a cluster, select managed mode and reference
an **existing** Secret whose selected key is a PostgreSQL URL. The URL is
mounted only as `/var/run/av/control-plane/database-url`; Helm never places it
in values, a ConfigMap, or the AV database. AV creates its own tables at
startup, so no separately privileged migration Job is needed at this stage.

```yaml
controlPlane:
  mode: managed
  existingDatabaseSecret:
    name: av-control-plane-postgres
    key: database-url
  initialOwnerOidcSubject: "<exact Zitadel OIDC sub>"
```

Managed mode refuses to render without both the existing Secret name and first
owner subject. The database is your lifecycle, backup, and network-policy
responsibility; AV's chart intentionally has no bundled PostgreSQL dependency.

```bash
helm upgrade --install av oci://ghcr.io/noeljackson/charts/av \
  --namespace av --create-namespace -f values.av.yaml
```
