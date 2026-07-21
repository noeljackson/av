# AV security model

AV is a credential boundary, not a sandbox for its callers. An identity with the
configured `allowed_groups` role can use every configured profile and route.
Profile endpoints intentionally return Tier 3 values to the calling process;
that process can print or transmit them. Tier 2 routes are the mechanism for
keeping a provider credential out of the caller.

## Trust boundaries

- AV configuration, its Kubernetes workload identity, Infisical/OpenBao, and
  explicitly configured provider origins are trusted administrative inputs.
- OIDC identities are authenticated and role checked, but requests and child
  processes are untrusted.
- Connector credentials exist only in mounted files or AV memory. Configuration
  contains paths and public identifiers, never credential values.
- OpenBao KV reads are supported. AV rejects leased dynamic-secret responses
  until it can return lease metadata and revoke or renew the lease correctly.
- Tier 2 assumes the configured provider is not intentionally malicious. AV
  removes common accidental credential reflections, but a provider that already
  received a credential can encode it in unbounded ways.

## Required production controls

- Use OIDC-only mode, short-lived access tokens, RS256 or another explicitly
  configured asymmetric signing algorithm, and the narrow `av-users` role.
- Use Kubernetes workload authentication for in-cluster connectors. Static token
  and AppRole files are compatibility options, not the preferred deployment.
- Keep ingress private, enable rate limiting, and default-deny egress except DNS,
  the identity provider, connector backends, and named Tier 2 providers.
- Give connector identities access only to the projects, paths, and keys exposed
  by configured profiles. Provider credentials must be scoped independently of
  AV's route policy.
- Keep production logs outside the AV pod. Logs contain subject, profile/route,
  status, and key count, but never values.

## Verification

Run the required local gates:

```bash
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
helm lint chart/av
tests/connector-integration.sh
tests/security-scan.sh
```

The integration stack contains only disposable synthetic credentials. Its
hostile upstream checks header smuggling, request-policy bypasses, redirects,
credential reflection, malformed queries, traversal, body limits, and origin
enforcement. `tests/security-scan.sh` additionally runs a pinned ZAP image on an
internal Docker network with no writable host mounts, capabilities, or Internet
egress.
ZAP is treated as an untrusted test workload rather than part of AV: the
digest-pinned `bare` image has a read-only root filesystem, no Linux
capabilities, no privilege escalation, synthetic credentials, and disposable
tmpfs state. Its upstream vulnerability report remains visible in the scheduled
workflow but is informational; AV's own image vulnerability gate is fail-closed.

Never point automated active scanning at a production AV instance. Before a
release expands access beyond its current operators, run a source-assisted
manual review against a disposable deployment and include OIDC token confusion,
JWKS rotation/flooding, connector impersonation, Tier 2 confused-deputy abuse,
and Kubernetes egress containment in scope.

Report suspected vulnerabilities privately through GitHub's security advisory
interface. Do not include real credentials, tokens, or unredacted responses in
an issue or report.
