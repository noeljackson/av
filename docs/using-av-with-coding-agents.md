# Using AV with coding agents

This guide uses a fictional `orchard-api` application. It has a development
profile called `orchard-dev`, an operations profile called `orchard-ops`, and a
provider API that AV reaches through a named `orchard-provider` proxy route.

Profiles and routes are deployment configuration. An AV owner grants those
predefined capabilities to a person or agent identity; the identity does not
create a profile or choose a secret path.

## First use

Authenticate once on the workstation, then inspect the capabilities granted to
your identity:

```bash
av login
av profiles
```

The OIDC access token stays in the Linux kernel keyring. It is not put in an
environment variable, a shell history entry, or a project file.

## Tier 3: run an agent with a profile

Use Tier 3 only when the coding agent or the application actually needs secret
values locally, such as a development database URL or a provider SDK that
cannot use a brokered HTTP route.

```bash
# Starts Codex with only orchard-dev's allowlisted keys in its process environment.
av orchard-dev -- codex

# The same model for Claude Code.
av orchard-dev -- claude

# Run the application itself with the same narrowly scoped profile.
av orchard-dev -- ./bin/orchard-api
```

`av` fetches the profile, starts exactly that child process, and does not write
the values to `.env` or disk. The child process can still read its own
environment, so treat Tier 3 as the compatibility path: grant the smallest
possible profile and do not put production and development credentials in the
same profile.

For an agent task, the practical workflow is:

1. Give the agent an `orchard-dev` profile, never an unrestricted platform
   profile.
2. Start the agent with `av orchard-dev -- codex` or
   `av orchard-dev -- claude`.
3. Keep irreversible production operations in a separate `orchard-ops`
   profile with a separate grant and human review.
4. End the child process when the task finishes. The profile values disappear
   with that process.

## Tier 2: use a named proxy route

Tier 2 is for an application that only needs to make a provider API call. The
application does **not** receive the provider credential.

```text
orchard-api or an agent tool
  └─ AV /v1/proxy/orchard-provider/v1/widgets
       └─ fixed provider origin with the configured credential injected
```

The route configuration fixes the upstream origin, profile, typed credential
injection, allowed methods, path prefixes, query keys, request headers, response
headers, content types, and request-size limit. AV then performs the following
for each request:

1. Authenticates the caller with its AV identity.
2. Checks that identity has the route's profile capability.
3. Rejects undeclared paths, methods, query fields, and headers.
4. Fetches the configured credential from Infisical, OpenBao, or Google Secret
   Manager.
5. Removes any caller-provided injection header and constructs AV's configured
   Bearer, fixed-header, or Basic credential.
6. Sends the request only to the fixed upstream origin.
7. Returns only allowlisted response headers and redacts the injected secret if
   an upstream body or header echoes it.

For provider APIs that require a secret in a request body, configure an exact
placeholder map such as
`"__AV_SECRET_WEBHOOK__": "PROVIDER_WEBHOOK_SECRET"`. Every configured
placeholder must occur exactly once in the bounded request body and the route
must allow its content type. AV performs byte-for-byte replacement after policy
validation. There are no expressions, loops, includes, or environment
expansion, so this cannot become a general template interpreter.

For example, an `orchard-api` tool can call its configured AV endpoint rather
than the provider directly:

```text
POST https://av.example.internal/v1/proxy/orchard-provider/v1/widgets
Authorization: Bearer <short-lived AV OIDC token>
Content-Type: application/json
```

The bearer token authorizes AV; it is not the provider credential. The provider
credential never crosses into the agent or application process.

## Codex and Claude with the transparent proxy

For a deployment that has enabled the private transparent listener and its
egress policy, launch the agent through a profile-scoped helper:

```bash
av run orchard-dev -- codex
av run orchard-dev -- claude
```

The child receives `HTTP_PROXY` and `HTTPS_PROXY` pointed only at a loopback
helper plus the deployment CA certificate. It does not receive AV's remote
session capability or a provider credential. The helper validates the remote
AV proxy's HTTPS certificate before sending that capability, mints one
short-lived, revocable session, and removes it when the child exits. The remote
proxy URL itself must be an HTTPS DNS origin; only the process-local loopback
helper is HTTP.

WebSocket-capable tools use the same `HTTPS_PROXY` path. The route must opt in
to WebSockets and declare exact Origin/subprotocol and connection limits; a
named `/v1/proxy/...` URL does not accept upgrades. This keeps AV authentication
on the outer CONNECT request and leaves the inner `Authorization` header
available for the provider credential.

This still is not permission for arbitrary egress. AV accepts only configured
HTTPS hosts, maps each to one immutable named route, and applies that route's
method/path/query/header policy after TLS interception. If the workload lacks
the accompanying NetworkPolicy/Cilium allowlist, this mode is cooperative and
must not be treated as injection containment.

Use Tier 2 from a narrow tool or application endpoint that knows the named AV
route when the action can be modeled explicitly. For `orchard-api`, that tool
exposes only operations such as `list_widgets` and `create_widget`; internally
it calls the `orchard-provider` AV route.

```text
Codex / Claude
  └─ orchard tool: create_widget
       └─ AV named proxy route
            └─ provider API with injected credential
```

This is the preferred design for agent actions because prompt injection cannot
turn a capability to create a development widget into arbitrary access to the
provider account.

For a named non-human agent, create a private token file and grant proxy
delivery only:

```bash
av agents create orchard-coder --out "${XDG_RUNTIME_DIR}/orchard-coder.token"
av agents grant orchard-coder orchard-dev --mode proxy
AV_AGENT_TOKEN_FILE="${XDG_RUNTIME_DIR}/orchard-coder.token" \
  av run orchard-dev -- codex
```

The remote agent token authorizes the wrapper, but the wrapper removes the
token-file variable and token from the Codex process. Codex receives the
loopback proxy variables and CA paths, including `CODEX_CA_CERTIFICATE`.

Read [the transparent proxy design](transparent-proxy-design.md) before
enabling it. Certificate-pinned SDKs cannot use this mode; use an explicit
named route or a deliberately scoped local-secret exception instead.
