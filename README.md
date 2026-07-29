# av

`av` is an OIDC-authenticated connector and credential proxy. It does not have
registration or an application-secret database. Infisical, OpenBao, and Google
Secret Manager are connector backends; none is embedded in `av`, and switching
a profile between them does not change the CLI or proxy contract.

AV has two deliberately separate operating modes:

- **Static** (the default) has an immutable JSON policy and no database.
- **Managed** retains the immutable connector bootstrap in JSON, but puts
  owner-managed Basic users and redacted audit metadata in SQLite (local) or an
  existing PostgreSQL database (Kubernetes). It never persists connector
  credentials or fetched secret values. Managed profile access is
  deny-by-default and granted to exact authenticated subjects.

## What it implements

| Tier | `av` behavior | Credential exposure |
|---|---|---|
| 1 — dynamic | OpenBao or Infisical mints a short-lived credential owned by one Tier 2 request/WebSocket or Tier 3 child | Exported fields reach only a granted Tier 3 child; Tier 2 callers receive none |
| 2 — proxy | Fixed HTTPS origin and explicit method/path/query/header/content policy | Credential never enters the caller |
| 3 — process environment | Authenticated profile lease followed by local child-process execution | Only the `av` process and its child receive values |

An Infisical profile maps directly to an existing project, environment, and
path; no dedicated `av` project is required. OpenBao profiles currently map to
KV paths such as `secret/data/infra` or explicitly configured dynamic engine
paths such as `database/creds/example`. Dynamic backend IDs remain inside AV;
AV renews and revokes them for the exact child, request, stream, or WebSocket
that owns them.
Google Secret Manager profiles map each exported local name to an exact secret
version resource and authenticate with ADC/Workload Identity Federation. See
[secret backends](docs/secret-backends.md) for the backend and IAM contract.

## Daily use

```bash
# One OIDC device login; the bearer token stays in the Linux kernel user keyring.
av login

av profiles
av routes
av infra -- ./scripts/atmos-run terraform plan headscale -s system
av example-dev -- cargo test
av example-prod -- ./scripts/check-production

av logout
```

`av example-dev -- ...` fetches the configured Infisical profile and adds the
returned keys only to the child process. It never writes application secrets to
disk or to the kernel keyring. The keyring contains only the short-lived OIDC
access token. `AV_TOKEN` is available for CI; optional Basic credentials use
`AV_BASIC_USER` and `AV_BASIC_PASSWORD`. Managed automation should use a named
agent token from a private `AV_AGENT_TOKEN_FILE`; see
[access control](docs/access-control.md).

See [using AV with coding agents](docs/using-av-with-coding-agents.md) for a
generic application example with Codex and Claude, and for the boundary between
AV's explicit proxy routes and a transparent `HTTPS_PROXY` design.
The transparent proxy is opt-in and private: it requires managed sessions, a
deployment CA, a private listener, and workload egress enforcement. Use
`av run <profile> -- codex` or `av run <profile> -- claude`; never set a remote
AV listener directly as a child's `HTTPS_PROXY`. The complete deployment and
security contract is in [transparent proxy design](docs/transparent-proxy-design.md).
WebSocket upgrades remain denied unless the route declares exact
Origin/subprotocol policy plus message, byte, and lifetime limits; live grants
and sessions remain enforced after the upgrade.
The stable product boundaries and active implementation sequence are tracked in
the [roadmap](docs/roadmap.md).

For Tier 2, callers use a named route:

```text
https://av.tail.noel.sh/v1/proxy/cloudflare-dns/zones/<zone>/dns_records
```

The caller supplies its OIDC bearer token. `av` forwards only explicitly
allowlisted headers and query keys, checks method, canonical path, content type,
and body size, then constructs one typed Bearer, fixed-header, or Basic
credential at the fixed upstream origin. Optional request-body injection uses
declared `__AV_SECRET_NAME__` placeholders that must each occur exactly once;
it is deliberately not a template language. Redirect and credential-bearing
response headers are never forwarded.
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

For the full Docker-only browser test stack (managed RBAC, synthetic
Infisical/OpenBao connectors, and a Basic owner login), run:

```bash
AV_IMAGE=av:ui-playwright tests/run-local-managed.sh
```

Open `http://127.0.0.1:14322`. The disposable owner is `operator` / `password`.
To test direct GitHub login, create a dedicated OAuth App with the exact
callback `http://127.0.0.1:14322/auth/github/callback`. Store both fields in
OpenBao KV v2 at `apps/av/local`: `GITHUB_CLIENT_ID` and
`GITHUB_CLIENT_SECRET`. With an authenticated local `bao` CLI, the harness
materializes the secret into a fresh mode-`0700` temporary directory, mounts it
only into the disposable setup container, copies it into the disposable AV
state volume, and removes the host file when setup completes. The secret is
never a Git value, environment value, process argument, browser value, or AV
log.

```bash
AV_TEST_GITHUB_OAUTH=1 AV_IMAGE=av:ui-playwright tests/run-local-managed.sh
```

GitHub OAuth is a local managed-only mode. AV uses PKCE and server-side code
exchange, requests only `read:user`, and allowlists immutable numeric GitHub
account IDs. The local harness obtains the configured account ID from `gh api
user`, so this setup admits only the authenticated `noeljackson` account rather
than trusting a changeable login name. Deployments may instead or additionally
set `auth.github.allowed_organizations` to GitHub organization slugs; AV then
requires active membership in any configured organization and requests
`read:org` only for that mode. AV discards the GitHub access token. The browser
receives only an AV-issued, HttpOnly, SameSite cookie that is accepted solely by
UI routes; it cannot authenticate AV's API, connector, or proxy routes.

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

### Managed profile policy

Static mode preserves the simple model: every identity that passes the OIDC
role check can use every configured profile and Tier 2 route. Managed mode is
stricter: profiles and routes are unavailable until an owner or operator grants
the exact OIDC, GitHub, Basic, or named-agent subject a predefined profile.
Each grant independently permits `proxy`, `environment`, or `both` delivery and
may expire. Owners manage instance roles; operators manage accounts, agents,
and grants; auditors read redacted audit events. Revocation and expiry take
effect on the next request, and AV protects the last owner. The Connect API,
CLI, and authenticated browser interface enforce the same rules.

Connector definitions and their credential-file references remain immutable
bootstrap configuration; the control plane deliberately cannot add, edit, or
retrieve provider credentials.

## Configuration

Configuration is strict JSON; unknown fields fail startup. Start from
[`config.example.json`](config.example.json). Connector credentials are file
references, never literal values in the config. Infisical supports Kubernetes,
Universal, and token auth. OpenBao supports Kubernetes, AppRole, and token auth;
Kubernetes is preferred for in-cluster workloads and AppRole for external
automation. Google Secret Manager uses Application Default Credentials; use
Workload Identity Federation in Kubernetes and never a service-account key.

```bash
AV_ALLOW_INSECURE_AUTH=1 cargo run -- serve --config config.local.json
```

## Supply-chain posture

- Rust dependency versions are exact and committed in `Cargo.lock`.
- The UI is compiled into the Rust binary: Askama renders HTML fragments and a
  small first-party browser module performs direct PKCE. Managed owner forms
  use a vendored, SRI-verified HTMX release. There is no Node, Bun, package
  lock, or browser-side dependency install in the release image.
- CI uses `noeljackson/supplychain` pinned to an immutable commit.
- Release artifacts and container images are built by GitHub Actions and receive
  GitHub artifact attestations. The exact published image is scanned again,
  carries BuildKit provenance and an SPDX SBOM, and has a separately attested
  downloadable SPDX asset.

Run the local gates with:

```bash
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
helm lint chart/av
tests/connector-integration.sh
tests/security-scan.sh
AV_UI_CONTAINER=av-ui-local AV_UI_URL=http://127.0.0.1:14322 tests/ui-smoke.sh
./scripts/verify-release vX.Y.Z
```

The integration runner starts separate pinned containers for AV, Infisical,
Postgres, Redis, OpenBao, and a credential-aware upstream. It bootstraps only
disposable test data on an internal Docker network, verifies both connector
reads plus hostile Tier 2 behavior, then copies the release CLI from the AV
image and verifies `av profiles` and both `av <profile> -- <command>` paths.
The CLI checks that wrapper credentials never reach its child process. The
runner removes containers and volumes on exit.
The security runner adds fail-closed capability/credential leak canaries and a
pinned, isolated ZAP passive scan. See [`SECURITY.md`](SECURITY.md) for the
trust boundaries, security gates, and reproducible release verification.

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
