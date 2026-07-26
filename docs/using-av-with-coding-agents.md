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

The route configuration fixes the upstream origin, profile, credential key,
allowed methods, path prefixes, query keys, request headers, response headers,
content types, and request-size limit. AV then performs the following for each
request:

1. Authenticates the caller with its AV identity.
2. Checks that identity has the route's profile capability.
3. Rejects undeclared paths, methods, query fields, and headers.
4. Fetches the configured credential from Infisical or OpenBao.
5. Removes any caller-provided injection header and inserts AV's credential.
6. Sends the request only to the fixed upstream origin.
7. Returns only allowlisted response headers and redacts the injected secret if
   an upstream body or header echoes it.

For example, an `orchard-api` tool can call its configured AV endpoint rather
than the provider directly:

```text
POST https://av.example.internal/v1/proxy/orchard-provider/v1/widgets
Authorization: Bearer <short-lived AV OIDC token>
Content-Type: application/json
```

The bearer token authorizes AV; it is not the provider credential. The provider
credential never crosses into the agent or application process.

## Codex and Claude with Tier 2

Current AV uses **explicit named reverse-proxy routes**. It is not yet a
transparent forward proxy, so setting `HTTPS_PROXY` for Codex or Claude will
not make their arbitrary outbound requests pass through AV.

Use Tier 2 from a narrow tool or application endpoint that knows the named AV
route. Give Codex or Claude access to that tool, rather than giving either the
provider token. For `orchard-api`, that tool exposes only operations such as
`list_widgets` and `create_widget`; internally it calls the
`orchard-provider` AV route.

```text
Codex / Claude
  └─ orchard tool: create_widget
       └─ AV named proxy route
            └─ provider API with injected credential
```

This is the preferred design for agent actions because prompt injection cannot
turn a capability to create a development widget into arbitrary access to the
provider account.

## Transparent proxy is a separate future feature

Agent Vault takes a different approach: its clients set `HTTP_PROXY`,
`HTTPS_PROXY`, and trust its local CA, then it MITMs normal HTTPS requests and
substitutes credentials. That is convenient for unmodified SDKs, but it also
requires per-session CA handling, a private proxy network, and firewall rules
that prevent direct egress bypass.

Do not configure AV as `HTTPS_PROXY` today. AV's current security contract is
the explicit named route shown above. If transparent proxying is added later,
it should be a separate, opt-in mode with the same private-network and
deny-direct-egress requirements.
