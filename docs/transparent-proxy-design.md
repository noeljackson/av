# Transparent proxy design

## Status

This document specifies AV's planned transparent proxy. **It is not available
yet.** Current AV supports only the explicit named routes at
`/v1/proxy/<route>/...`; setting `HTTP_PROXY` or `HTTPS_PROXY` to an AV address
does not work and must not be used as a security control.

The feature exists to make unmodified command-line tools, SDKs, MCP servers,
Codex, and Claude Code usable without putting a provider credential in their
environment. It is not a replacement for the explicit route model. The two
models serve different needs:

| Model | Best for | Caller sees provider secret? |
|---|---|---|
| Named route | Purpose-built application tools and high-risk actions | No |
| Transparent proxy | Existing SDKs and tools that cannot be changed | No |
| `av <profile> -- command` | A tool that genuinely needs a local secret value | Yes; only for the child lifetime |

Use a named route whenever an application can be changed. Transparent proxying
is a compatibility layer, not permission to give an agent arbitrary network
access.

## Security contract

The transparent listener must meet all of these properties before it is
advertised or enabled:

1. It is a **private** service. It is never exposed by public Ingress, a public
   LoadBalancer, or a tailnet funnel.
2. It is **strict deny**. A destination not backed by a configured AV connector
   route fails closed. There is no pass-through mode.
3. A session is short-lived, profile-scoped, auditable, and revocable. It is a
   capability to make policy-approved requests; it is not a provider
   credential.
4. AV does TLS interception only for configured connector hosts. A caller does
   not get a general-purpose decryption service.
5. AV removes caller-supplied credential headers before injecting its own
   credential. It never forwards a provider credential to the workload.
6. Direct outbound paths are blocked at the workload boundary. Proxy environment
   variables make compliant software use AV; egress policy makes bypassing AV
   fail.
7. The proxy does not accept a destination supplied by a request body, header,
   redirect, DNS rebinding trick, or `CONNECT` target that is outside its
   configured connector catalog.

If an environment cannot enforce direct-egress denial, AV must describe this
mode as *cooperative*. It remains useful for credential non-disclosure, but it
does not contain a compromised agent's outbound network access.

## Architecture

The public control plane and the credential proxy are separate listeners with
separate exposure rules.

```text
human browser                         agent workload
      |                                      |
      | OIDC / PKCE                          | HTTP_PROXY / HTTPS_PROXY
      v                                      v
AV control API                         local session helper
(normal HTTPS)                                |
      |                                      | authenticated private tunnel
      |                                      v
      +------------------------------> AV transparent proxy
                                             |
                                   only configured upstream hosts
                                             v
                                      provider API
```

The control API can have normal TLS and OIDC protections. The transparent
proxy must have private network reachability only. In Kubernetes, use a
dedicated ClusterIP Service port and do not put that port in an Ingress.

### Why a local session helper

Putting a session token in a URL such as
`HTTPS_PROXY=http://token@proxy.internal:14322` is convenient, but the child
process can read and exfiltrate that token. A scoped token is less damaging
than a provider key, yet it is still a reusable capability until it expires.

`av run` should instead start a loopback-only helper and give the child only a
localhost proxy address:

```text
HTTPS_PROXY=http://127.0.0.1:42173
HTTP_PROXY=http://127.0.0.1:42173
```

The helper keeps the remote session credential in memory, attaches proxy
authentication upstream, installs the session CA in its own restricted
directory, and dies with the child. The child may use the local proxy while it
runs, but it does not receive the remote session credential in an environment
variable, command line, or project file.

This is a containment improvement, not a magical sandbox. A process that can
send HTTP through its loopback proxy can exercise the session's allowed
capabilities until the helper is stopped. The profile and connector policy must
therefore remain narrow.

## Request lifecycle

1. A human authenticates with `av login`; the workstation OIDC token remains
   in the kernel keyring.
2. `av run orchard-dev -- codex` asks AV to mint a short-lived proxy session
   for the caller's granted `orchard-dev` profile.
3. AV records the identity, profile, expiry, and session identifier; it returns
   a session credential only to the local helper over authenticated TLS.
4. The helper starts a loopback HTTP forward proxy, configures CA trust for the
   child, and launches `codex`.
5. A client request reaches the helper. The helper authenticates to AV's
   private proxy listener; AV accepts only a configured `CONNECT host:443` or
   an allowed plaintext HTTP destination.
6. AV maps the host to exactly one connector route, enforces that route's
   method/path/query/header/content policy, fetches the provider credential,
   strips caller auth, and injects the fixed credential form.
7. AV sends the request to the fixed HTTPS upstream, redacts any echoed
   credential, returns only permitted response headers, and records the policy
   decision and status.
8. When the command exits, the helper terminates and AV revokes the session.
   Expiry and explicit revocation are independent backstops.

The proxy must reject HTTP `CONNECT` for a non-catalog host before attempting
DNS resolution or a TCP connection. It must not follow redirects across hosts,
allow an upstream proxy, or reuse an upstream client connection across distinct
credential contexts.

## TLS and certificate authority

HTTPS interception is necessary because an HTTP forward proxy otherwise sees
only `CONNECT host:port`, not the request path or headers that AV must enforce
and modify. It introduces a new, sensitive component: an AV certificate
authority (CA).

The initial implementation must use these rules:

- Generate a dedicated proxy CA for each AV deployment; do not reuse the
  public control-plane certificate or a corporate root CA.
- Keep the CA private key only in the AV server's private credential mount or a
  hardware/key-management boundary. It never appears in Helm values, browser
  downloads, workload filesystems, logs, or backups without encryption.
- Issue certificates only for configured connector DNS names. Never issue a
  certificate based on an arbitrary `CONNECT` hostname.
- Give the client the CA **certificate** only. A client must never receive the
  CA private key.
- Prefer a short-lived, session-specific intermediate CA or leaf certificates
  so a leaked trust certificate has a small operational scope. The exact key
  hierarchy must be documented and rotation-tested before release.
- Block HTTP/3/QUIC (`UDP/443`) from workloads. QUIC bypasses an HTTP CONNECT
  proxy and cannot be policy-inspected this way.
- Document certificate-pinning incompatibility. A pinned SDK cannot be
  transparently intercepted; use a named route, a provider-supported dynamic
  credential, or a deliberate Tier 3 exception for that integration.

The proxy listener itself may use plain HTTP *inside a private, authenticated
transport* because the TLS being intercepted belongs to the upstream request.
Where the network has any untrusted hop, wrap the proxy transport in mTLS or
keep the session helper and proxy on an authenticated private overlay. A public
HTTP proxy listener is never acceptable.

## Connector policy

A transparent service reuses AV's immutable connector policy rather than
creating a free-form "service" database. Each policy entry must contain:

- the exact HTTPS origin and hostname;
- one profile whose grant permits use of the service;
- the credential key and a fixed injection location;
- allowed methods and canonical path prefixes;
- explicit query, request-header, response-header, content-type, and body-size
  allowlists; and
- enabled/disabled state owned by immutable deployment configuration.

The proxy must enforce the same policy as an explicit named route. In
particular, it must reject traversal encodings, duplicate query parameters,
hop-by-hop headers, `Proxy-Authorization` forwarding, cross-host redirects,
and undeclared CRUD methods. A configured `Authorization` injection always
overwrites the caller's `Authorization`; it never appends a second value.

One host may map to multiple policies only when AV can choose unambiguously
from authenticated session/profile and canonical path. Otherwise configuration
validation must reject it. Ambiguity is a security failure, not a runtime
selection problem.

## Kubernetes deployment and egress enforcement

For a workload namespace, configure a default-deny egress policy, then allow
only:

1. DNS to the cluster's approved resolver, if required;
2. the AV transparent-proxy Service on its private proxy port; and
3. explicitly documented non-HTTP control-plane dependencies, if any.

Do **not** allow arbitrary TCP/443 simply because AV is present. That would
allow a compromised workload to unset `HTTPS_PROXY` and directly call any
internet host. With Cilium, combine ordinary NetworkPolicy with an egress
policy that denies direct external destinations, including UDP/443. Equivalent
controls are required for any other CNI before this is called enforced mode.

The AV proxy Service itself gets egress only to the configured provider DNS
names/IPs and its secret backend. Its inbound policy accepts only approved
workload namespaces and the local-helper bridge where applicable. The public
control API and private proxy port have separate NetworkPolicies.

Before deployment, test all four paths from a disposable workload:

| Attempt | Required result |
|---|---|
| Allowed provider call through AV | Success and audit event |
| Undeclared provider host through AV | `403` before DNS/TCP |
| Direct allowed-provider call | Network failure |
| UDP/443 to allowed-provider host | Network failure |

## Operator workflow (when implemented)

This is the intended ergonomic interface, shown here so the contract is
reviewable. These commands must not be advertised as available until the
feature ships.

```bash
# Grant the person the existing orchard-dev profile in AV's owner UI.
av login
av profiles

# Launch a coding agent. The local helper starts and exits with this command.
av run orchard-dev -- codex
av run orchard-dev -- claude

# An unmodified SDK inherits the same proxy environment when started this way.
av run orchard-dev -- ./bin/orchard-worker
```

Inside Codex or Claude, the normal workflow is simply to use a configured
provider tool or SDK. The agent does not run `av ... -- env`, does not copy a
token into a prompt, and does not add provider keys to a `.env` file. AV's
profile and connector policy determine which provider operations succeed.

For a high-impact operation, prefer a narrow application tool backed by an
explicit named route over giving the agent broad transparent access to a
provider API. Human confirmation and a distinct operations profile remain
appropriate for production changes.

## Comparison with Agent Vault

Agent Vault demonstrates the useful ergonomic core: a separate forward-proxy
listener, `HTTP_PROXY`/`HTTPS_PROXY`, a trusted CA, and credential injection.
AV should retain that interoperability while choosing stricter defaults:

| Concern | Agent Vault capability | AV requirement |
|---|---|---|
| Unmatched hosts | Can be configured to deny, but pass-through is a documented default | Always deny |
| Session handoff | Scoped proxy token can be placed in proxy URL | Local helper keeps remote capability out of child environment |
| Policy source | Mutable vault/service catalog | Immutable AV connector policy plus managed profile grants |
| Exposure | Private networking recommended | Private listener and egress enforcement required |
| Route policy | Service matching | Fixed origin plus explicit request/response constraints |

This comparison does not imply compatibility with Agent Vault's API, storage,
or credential database. AV continues to use Infisical and OpenBao as connector
backends and does not store application credentials itself.

## Required security tests before release

The feature is not complete until automated tests cover at least:

- successful CONNECT interception and credential injection for one allowed host;
- rejection before connection of unknown hosts, IP literals, internal ranges,
  alternate ports, HTTP `CONNECT`, malformed authority, and DNS-rebinding
  attempts;
- method/path/query/header/body-policy enforcement after TLS interception;
- caller-auth stripping and response-secret redaction;
- session expiration, explicit revocation, profile-grant revocation, and helper
  teardown;
- CA key non-disclosure, certificate hostname restrictions, and rotation;
- `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, and proxy-bypass behavior for Codex,
  Claude Code, curl, and at least one SDK;
- direct TCP and UDP/443 egress denial in the Kubernetes integration fixture;
- malformed proxy authentication, replay, concurrency, rate-limit, request
  smuggling, oversized body, WebSocket, redirect, and connection-reuse cases;
- audit records that contain no provider secret, session credential, request
  body, or sensitive header value.

Run these as Docker/Kubernetes integration tests, not only unit tests. The
test environment must use synthetic credentials and a controlled upstream that
can prove whether a credential was injected or leaked.

## Delivery sequence

1. Add strict configuration types and reject unsafe or ambiguous connector host
   mappings. Keep the feature disabled by default.
2. Implement session issuance, revocation, audit metadata, and the private
   listener with unknown-host denial. Do not enable TLS interception yet.
3. Add CA lifecycle and CONNECT interception with the full hostile-request test
   suite.
4. Add the local `av run` helper and Codex/Claude smoke tests.
5. Add Helm Service/NetworkPolicy templates and a Cilium-backed enforced-egress
   integration test. Publish deployment guidance only after that test passes.

At each stage, an incomplete feature must fail closed and remain unavailable to
normal users. No deployment should acquire a public proxy port or a permissive
fallback merely to make a demo work.
