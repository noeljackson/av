# Transparent proxy design

## Status

AV implements this as an **opt-in, private deployment feature**. It is disabled
by default: an operator must configure managed mode, a deployment CA, the
private proxy listener, and workload egress enforcement before `av run` is
usable. It is never a public forward proxy and must not be exposed through an
Ingress, LoadBalancer, or tailnet funnel.

The feature exists to make unmodified command-line tools, SDKs, MCP servers,
Codex, and Claude Code usable without putting a provider credential in their
environment. It is not a replacement for the explicit route model. The two
models serve different needs:

| Model | Best for | Caller sees provider secret? |
|---|---|---|
| Named route | Purpose-built application tools and high-risk actions | No |
| Cooperative `av run` | Host SDKs and tools that cannot be changed | No |
| Enforced `av run --container` or Kubernetes policy | Untrusted local/containerized or cluster workloads | No |
| `av <profile> -- command` | A tool that genuinely needs a local secret value | Yes; only for the child lifetime |

Use a named route whenever an application can be changed. Transparent proxying
is a compatibility layer, not permission to give an agent arbitrary network
access.

## Security contract

The transparent listener must meet all of these properties before it is
advertised or enabled:

1. It is a **private** service. It is never exposed by public Ingress, a public
   LoadBalancer, or a tailnet funnel.
2. It is **strict deny**. A destination not backed by a configured AV injecting
   route or exact credentialless tunnel fails closed. There is no unmatched
   pass-through mode.
3. A session is short-lived, profile-scoped, auditable, and revocable. It is a
   capability to make policy-approved requests; it is not a provider
   credential.
4. AV does TLS interception only for configured injecting-route hosts.
   Credentialless tunnel bytes remain end-to-end opaque. A caller does not get
   a general-purpose decryption or forwarding service.
5. AV removes caller-supplied credential headers before injecting its own
   credential. It never forwards a provider credential to the workload.
6. Direct outbound paths are blocked at the workload boundary. Proxy environment
   variables make compliant software use AV; egress policy makes bypassing AV
   fail.
7. The proxy does not accept a destination supplied by a request body, header,
   redirect, DNS rebinding trick, or `CONNECT` target that is outside its
   configured connector catalog.

If an environment cannot enforce direct-egress denial, AV describes the mode
as *cooperative*. `av run` on an ordinary host is always in this category. It
remains useful for credential non-disclosure, but it does not contain a
compromised agent's outbound network access. Local enforced execution uses
`av run --container`; Kubernetes enforcement uses workload NetworkPolicy/Cilium.

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

### Enforced Docker launcher

`av run --container` is the local enforcement boundary. The host AV process
acquires and owns the remote session, opens a mode-`0700` Unix-socket
directory, and launches two digest-pinned containers:

```text
host av process (OIDC/agent auth + remote session capability)
  |
  | private Unix socket; not mounted in target
  v
AV relay sidecar (`--network none`, loopback :3128, no AV token)
  ^
  | shared network namespace, loopback only
  |
target child (`--network container:<relay>`)
```

The sidecar cannot contact AV or the internet itself. It only translates the
child's loopback TCP connection into the host-owned Unix stream. The host
helper validates the private AV proxy's transport TLS and adds the remote
session capability. The target receives the public interception CA and system
trust bundle, but no AV authentication, remote capability, connector
credential, CA private key, or relay socket.

Both image arguments must be a `name@sha256:<digest>` reference or an exact
local `sha256:<content-id>`. AV verifies that both are already present and uses
Docker's `--pull never`; mutable tags and surprise network fetches fail before
a session is created. The target has a read-only root filesystem,
`no-new-privileges`, all capabilities dropped, bounded PIDs, private tmpfs
paths, and one explicit `/workspace` bind mount. Docker Engine, the image
contents, and that writable workspace remain deliberate trust boundaries.

The network namespace has only loopback. It has no route for direct TCP,
metadata/link-local addresses, DNS, or QUIC/UDP. HTTPS clients send DNS
hostnames in CONNECT to the loopback helper, and AV resolves only a configured
destination after authorization. Unknown Docker/runtime state or relay
failure terminates the child and fails closed. Normal exit, Ctrl-C, renewal
failure, and helper failure remove both named containers and revoke the AV
session.

## Request lifecycle

1. A human authenticates with `av login`; the workstation OIDC token remains
   in the kernel keyring.
2. `av run orchard-dev -- codex` asks AV to mint a short-lived proxy session
   for the caller's granted `orchard-dev` profile.
3. AV records the identity, profile, expiry, and session identifier; it returns
   a session credential only to the local helper over authenticated TLS.
4. The helper starts a loopback HTTP forward proxy, configures CA trust for the
   child, and launches `codex`. Replacement-style trust variables receive a
   private bundle containing the normal system roots plus AV's interception CA;
   additional-CA variables receive only AV's CA. Credentialless tunnels
   therefore retain ordinary upstream trust.
5. A client request reaches the helper. The helper first authenticates the
   network proxy's HTTPS transport certificate, then sends its session
   capability. AV accepts only a configured `CONNECT host:443`; plaintext
   network proxy traffic and plaintext upstream destinations are rejected.
6. AV maps the host to exactly one immutable destination. An injecting route
   gets TLS interception, HTTP policy, and fixed credential injection. A
   credentialless tunnel gets raw end-to-end TLS relay and never invokes a
   secret backend.
7. AV sends the request to the fixed HTTPS upstream, redacts any echoed
   credential, returns only permitted response headers, and records the policy
   decision and status.
8. While the child remains alive, the helper renews the same capability before
   each five-minute sliding expiry. Renewal rechecks the original subject and
   live proxy grant and cannot extend beyond the deployment's absolute session
   lifetime.
9. When the command exits, the helper terminates and AV revokes the session.
   If renewal fails, the helper closes and the child is terminated. Expiry and
   explicit revocation remain independent backstops.

The defaults are a five-minute sliding TTL and an eight-hour absolute lifetime.
Helm exposes these as `transparentProxy.sessionTtlSeconds` and
`transparentProxy.sessionMaxLifetimeSeconds`. Shorter TTLs reduce revocation
latency during tests; longer than one hour is rejected for a sliding window,
and the absolute lifetime cannot exceed 24 hours. Starting a new child always
creates a new independently audited session and capability.

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

The network-exposed proxy listener uses HTTPS independently of the upstream TLS
that AV intercepts. The helper validates its configured DNS name against public
WebPKI roots, or an explicitly configured private trust anchor, before sending
the session capability. The process-local helper remains an HTTP proxy bound
only to loopback so existing SDKs can use it without learning the remote
capability. A plaintext network proxy listener is never supported.

Transport TLS certificates are re-read for every new proxy connection.
Kubernetes may atomically rotate the projected certificate/key pair; an
incomplete or invalid update keeps the last known-good pair. The interception
CA is different: it signs configured upstream leaves and is loaded once per AV
process. Rotate it with a controlled singleton restart, which revokes active
sessions and leases; then relaunch affected `av run` children so each receives
the new public CA certificate. Never mount the interception private key into a
client workload and never reuse the transport certificate as that CA.

## Connector policy

A transparent service reuses AV's immutable connector policy rather than
creating a free-form "service" database. Each policy entry must contain:

- the exact HTTPS origin and hostname;
- one profile whose grant permits use of the service;
- one fixed typed injection mode: Bearer, constrained `Authorization`/`X-*`
  header, or Basic with a configured username and backend-sourced password;
- optionally, exact one-use `__AV_SECRET_NAME__` request-body placeholders
  mapped to backend keys;
- allowed methods and canonical path prefixes;
- explicit query, request-header, response-header, content-type, and body-size
  allowlists;
- an explicit buffered or streaming response mode with a total byte ceiling;
  and
- enabled/disabled state owned by immutable deployment configuration.

The proxy must enforce the same policy as an explicit named route. In
particular, it must reject traversal encodings, duplicate query parameters,
hop-by-hop headers, `Proxy-Authorization` forwarding, cross-host redirects,
and undeclared CRUD methods. A configured `Authorization` injection always
overwrites the caller's `Authorization`; it never appends a second value.
Only routes whose fixed origin is standard HTTPS on port 443 are eligible for
transparent interception. Other explicit named routes remain usable through
`/v1/proxy/<route>/...` but are absent from the CONNECT destination catalog.

Typed injection is intentionally small. AV constructs the wire value itself and
never accepts the username, header name, prefix, or credential key from the
proxied request. Body substitution is exact and bounded: every declared
placeholder must occur once, undeclared placeholders have no meaning, the
content type must be allowlisted, and the substituted result must remain under
`max_body_bytes`. Both header and body credential values feed the response
redactor.

Streaming is opt-in per route with `response_mode: "streaming"` and a bounded
`max_response_bytes`. AV begins forwarding ordinary and `text/event-stream`
responses before upstream completion. The redactor retains only the minimum
cross-chunk overlap needed to catch raw, Base64, URL-safe Base64,
percent-encoded, and JSON-escaped credential forms split across arbitrary
upstream chunks. Exceeding the byte ceiling terminates the body stream; it
never silently switches to an unbounded relay.

WebSockets are also denied by default. They are available only through a
transparent proxy session because the CONNECT capability authenticates the
caller before the inner `Authorization` header is replaced with the provider
credential. A route opts in with a bounded policy:

```json
{
  "websocket": {
    "allowed_origins": ["https://app.example.internal"],
    "allow_missing_origin": false,
    "allowed_subprotocols": ["events.v1"],
    "max_duration_seconds": 300,
    "max_message_bytes": 1048576,
    "max_total_bytes": 67108864
  }
}
```

Origins and subprotocols are exact; wildcards are unsupported. Non-browser
clients may omit `Origin` only when `allow_missing_origin` is explicitly true.
AV rejects WebSocket extensions (including compression), validates the
challenge response and selected subprotocol, parses frames in both directions,
redacts credential values in text, binary, ping, pong, and close payloads, and
enforces message, connection-byte, and lifetime ceilings. It rechecks the
session and profile grant every second, so expiry, session revocation, agent
disablement, or grant revocation terminates a live socket.

One host maps to exactly one injecting route or credentialless tunnel.
Configuration validation rejects overlaps rather than choosing from decrypted
paths at runtime. Ambiguity is a security failure.

## Credentialless TLS tunnels

Some wrapped tools also need ordinary HTTPS control-plane access that carries
no AV-managed provider credential: for example, an explicitly approved source
host or package mirror. Configure these separately from `proxy_routes`:

```json
{
  "proxy_tunnels": {
    "source-control": {
      "profile": "orchard-dev",
      "host": "github.com",
      "allow_private_ips": false
    }
  }
}
```

A tunnel declaration is an exact DNS host on port 443. It has no path policy
because AV does not terminate its TLS. The caller must have a proxy grant for
the tunnel's profile, and `av routes` shows only destinations visible through
that grant. Unknown hosts and overlaps with injecting routes fail
configuration or CONNECT authorization before DNS.

AV resolves a configured tunnel only after authenticating the session and
checking its live grant. It rejects mixed or unsafe DNS answers. Loopback,
link-local, multicast, unspecified, broadcast, documentation, and metadata
addresses are always denied. RFC1918, unique-local IPv6, benchmark, and CGNAT
addresses require `allow_private_ips: true`; this explicit opt-in is useful for
private Kubernetes and tailnet control planes without weakening public routes.

Credentialless means AV does not fetch, inject, inspect, redact, or persist
anything from the TLS stream. It is still a network capability, so declarations
should be narrow and the workload must retain direct-egress denial.

## Kubernetes deployment and egress enforcement

AV is a protected singleton in the current Helm chart. Dynamic lease handles
are deliberately process-local, so `replicaCount` other than one fails
rendering and the Deployment uses `Recreate`. Dependency-aware `/readyz`
checks the managed control-plane database and becomes unavailable as shutdown
begins; `/healthz` remains a process-local liveness check. Graceful shutdown
has a bounded concurrent lease cleanup window, with provider TTLs as the crash
backstop.

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

## Operator workflow

```bash
# Grant the person the existing orchard-dev profile in AV's owner UI.
av login
av profiles

# Launch a coding agent. The local helper starts and exits with this command.
av run orchard-dev -- codex
av run orchard-dev -- claude

# An unmodified SDK inherits the same proxy environment when started this way.
av run orchard-dev -- ./bin/orchard-worker

# Local enforced mode: both images are already present and digest-pinned.
av run orchard-dev \
  --container \
  --image 'ghcr.io/example/orchard-agent@sha256:<digest>' \
  --helper-image 'ghcr.io/noeljackson/av@sha256:<digest>' \
  --workspace "$PWD" \
  -- codex
```

Inside Codex or Claude, the normal workflow is simply to use a configured
provider tool or SDK. The agent does not run `av ... -- env`, does not copy a
token into a prompt, and does not add provider keys to a `.env` file. AV's
profile and connector policy determine which provider operations succeed.

The proxy origin returned by AV must use a publicly trusted HTTPS certificate.
For a deliberately private test deployment, point the helper at one additional
PEM trust anchor without exposing it to the child:

```bash
AV_PROXY_TRANSPORT_CA_FILE=/absolute/path/to/transport-ca.pem \
  av run orchard-dev -- ./bin/orchard-worker
```

This trust anchor authenticates only the outer helper-to-AV transport. It is
separate from the deployment's MITM CA certificate, which AV supplies to the
child for configured provider hosts.

`av run` discovers the host's system PEM trust bundle and appends AV's public
interception certificate in a mode-`0600` temporary directory. On a platform
without a standard Linux bundle path, set `AV_SYSTEM_CA_FILE` to an absolute
PEM bundle. The helper reads it and removes that variable from the child
environment. It never modifies the machine trust store. This distinction is
required for credentialless tunnels: their upstream certificate must chain to
the normal system bundle (or an explicitly supplied private upstream CA), not
to AV's interception CA.

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
| Local bypass control | Proxy environment is cooperative | `run --container` supplies a network-none target and relay |

This comparison does not imply compatibility with Agent Vault's API, storage,
or credential database. AV continues to use Infisical and OpenBao as connector
backends and does not store application credentials itself.

## Security verification

The implementation is kept available only with these test layers:

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
- an end-to-end credentialless HTTPS tunnel whose upstream certificate is
  signed by a CA distinct from AV's interception CA;
- direct TCP and UDP/443 egress denial in the Kubernetes integration fixture;
- a real `run --container` network-none fixture proving permitted HTTPS,
  direct-TCP/metadata/UDP/unknown-host denial, no child AV credentials,
  digest-only launch, Ctrl-C container removal, and persisted session
  revocation;
- WebSocket handshake injection, exact Origin/subprotocol enforcement,
  bidirectional frame redaction, bounded lifetime/bytes, and live grant
  revocation;
- malformed proxy authentication, replay, concurrency, rate-limit, request
  smuggling, oversized body, undeclared WebSocket, redirect, and
  connection-reuse cases;
- audit records that contain no provider secret, session credential, request
  body, or sensitive header value.

AV's unit and raw-TCP tests are Rust tests: `cargo test` starts
controlled Rust upstreams and raw TCP proxy clients, rather than making Python
or shell the authority for proxy behavior. Kubernetes deployment validation may
use a Rust probe image launched by the test harness. The environment must use
synthetic credentials and a controlled upstream that can prove whether a
credential was injected or leaked.
