# AV production operator guide

This is the portable path for installing, validating, upgrading, recovering,
and rolling back AV. Deployment-specific DNS, ingress, tailnet, database, and
secret-store resources belong in downstream infrastructure. Provider secret
values never belong in this repository, Helm values, AV's API, or AV's
database.

## 1. Prepare the dependencies

Before installing AV, provide:

- a private HTTPS ingress for the control UI and API;
- an OIDC public client with Authorization Code + PKCE for the browser and
  Device Authorization for the CLI;
- an existing PostgreSQL database with encrypted, tested backups;
- one or more external secret stores with workload authentication;
- a private HTTPS origin for the optional transparent proxy;
- separate transport TLS and interception CA certificates for that proxy; and
- default-deny workload egress when transparent proxying must be enforced.

Use Kubernetes or cloud workload identity for connectors. Static tokens,
service-account key files, and credentials embedded in Helm values are not a
production bootstrap path.

AV supports two managed-database delivery patterns:

1. `controlPlane.openbaoAgent` renders renewable OpenBao database credentials
   into pod tmpfs. This is the preferred Kubernetes pattern.
2. `controlPlane.existingDatabaseSecret` mounts an existing Secret as a file.
   This is intended for simpler deployments whose secret controller already
   owns rotation.

The chart does not create PostgreSQL, OpenBao, Infisical, Google Secret
Manager, certificates, ingress policy, or backup infrastructure.

## 2. Verify the release before deployment

Choose one version and verify it before referring to its image:

```bash
git clone https://github.com/noeljackson/av.git
cd av
./scripts/verify-release vX.Y.Z
```

The verifier checks the binary and image-SBOM checksums, GitHub/Sigstore
attestations, the exact release workflow and tag ref, the OCI image
attestation, and the registry SBOM.

Resolve and record the immutable image digest:

```bash
docker buildx imagetools inspect ghcr.io/noeljackson/av:vX.Y.Z
```

Use the chart version and image digest together. Never deploy a mutable tag
without `image.digest`.

## 3. Define immutable policy

Start with `chart/av/values.yaml` and `config.example.json`. Keep these values
in Git:

- public OIDC identifiers and accepted signing algorithms;
- connector types, endpoints, and credential-file paths;
- exact profiles and exported fields;
- fixed proxy origins and request policies;
- Kubernetes Secret names, ServiceAccount names, and workload selectors; and
- the chart version and image digest.

Keep credential bytes in their owning external store. AV's UI and database
manage identities, roles, grants, sessions, and redacted audit records only.
They cannot create connectors, profiles, routes, or secrets.

Production OIDC should normally use:

```yaml
config:
  auth:
    mode: oidc
    issuer: https://id.example.com
    client_id: av-public-client
    audiences: [av-public-client]
    scopes: [openid, groups]
    signing_algorithms: [RS256]
    allowed_groups: [av-users]
    group_claim: groups
```

The exact `controlPlane.initialOwnerOidcSubject` is used only when an empty
managed database receives its first owner. Changing the value later does not
transfer ownership.

Read [secret backends](secret-backends.md) before configuring Infisical,
OpenBao, or Google Secret Manager. Read
[transparent proxy design](transparent-proxy-design.md) before enabling its
private listener or egress policies.

## 4. Render, install, and inspect

Render locally before contacting the cluster:

```bash
helm lint chart/av -f values.production.yaml
helm template av chart/av -f values.production.yaml >/tmp/av-rendered.yaml
```

Review the rendered file for public desired state only. If it contains a
provider credential, database URL, bearer token, or private key value, stop
and fix the delivery design.

Install the verified chart and wait for dependency-aware readiness:

```bash
helm upgrade --install av oci://ghcr.io/noeljackson/charts/av \
  --version X.Y.Z \
  --namespace av \
  --create-namespace \
  --atomic \
  --wait \
  --timeout 10m \
  -f values.production.yaml

kubectl rollout status deployment/av -n av --timeout=5m
kubectl port-forward --namespace av service/av 14322:80
# In a second terminal:
curl --fail http://127.0.0.1:14322/readyz
```

Use the private HTTPS `/readyz` endpoint directly when it is reachable from
the operator network. `/healthz` proves
the process is alive; `/readyz` also proves managed database and connector
dependencies are usable.

## 5. Bootstrap authorization

Log in through the same OIDC client configured for the deployment:

```bash
av --api-url https://av.example.internal login
av --api-url https://av.example.internal profiles
av --api-url https://av.example.internal roles list
```

An owner grants an exact human, Basic, GitHub, or named-agent subject access to
an existing profile. A grant independently allows `proxy`, `environment`, or
`both` delivery and may expire. Owners and operators do not implicitly receive
profile access.

For non-human automation:

```bash
umask 077
av --api-url https://av.example.internal agents create builder \
  --out "${XDG_RUNTIME_DIR}/av-builder.token"
av --api-url https://av.example.internal agents grant builder example-dev \
  --mode proxy
```

Mount the token file only into the wrapper process and set
`AV_AGENT_TOKEN_FILE`; AV removes that input from its child environment.
Rotation, disable, deletion, and grant revocation invalidate active sessions.
See [access control](access-control.md) for the complete role matrix.

## 6. Validate the three delivery tiers

Use synthetic or narrowly scoped test credentials. Do not print environment
values or provider responses containing credentials.

Tier 1 is a property of the selected OpenBao or Infisical dynamic profile.
Verify that AV acquires one short-lived backend lease, the operation succeeds,
and the lease is synchronously revoked when the request, stream, WebSocket, or
child ends.

Tier 2 keeps the provider credential out of the caller. Verify:

- one allowed named or transparent request succeeds;
- an undeclared host, method, path, query, content type, and oversized body
  fail;
- redirects and credential-bearing response headers are not forwarded; and
- grant removal stops active WebSockets and prevents the next request.

Use `provider_operations` for actions in AV's curated provider catalog. AV
then owns the fixed origin, authentication scheme, method, exact path, and
request/response limits. Use raw `proxy_routes` only as a reviewed advanced
escape hatch for operations that AV does not yet model.

For a compatible command-line client:

```bash
av --api-url https://av.example.internal run example-dev -- \
  curl --fail https://api.example.com/allowed/path
```

This host mode is cooperative. For enforced Kubernetes use, label only the
intended workload and enable both the chart NetworkPolicy and, when available,
its Cilium policy. Prove direct TCP/443, UDP/443, metadata endpoints, and
undeclared destinations fail while the AV proxy remains reachable.

Tier 3 deliberately puts selected values in one child process:

```bash
av --api-url https://av.example.internal example-dev -- \
  sh -c 'test -n "${EXAMPLE_API_TOKEN:-}"'
```

Verify the wrapper's OIDC, Basic, agent-token, and connector-authentication
inputs are absent from that child. Revoke the grant or force lease renewal to
fail and confirm the child is terminated and its backend lease is revoked.

## 7. Back up and recover

AV has no application-secret backup. Back up each owning secret store using its
native procedure. Separately preserve:

- Git-managed Helm values and connector policy;
- the managed PostgreSQL database;
- OIDC client configuration;
- certificate issuer state and recovery material; and
- the exact release version and image digest.

Exercise recovery in an isolated namespace or cluster:

1. restore PostgreSQL to a new protected endpoint;
2. restore or reconnect the external stores and workload identities;
3. restore transport TLS and interception-CA issuer capability;
4. render the same Git-managed policy against the recovered dependencies;
5. deploy the same verified AV release digest;
6. confirm the existing owner, roles, grants, audit records, and disabled
   agents are present; and
7. rerun the Tier 1–3 and egress-denial checks.

Do not change `initialOwnerOidcSubject` to recover a lost owner. Recover the
database and identity provider, or use a separately documented database
break-glass procedure with an audit record.

## 8. Rotate certificates

Transport TLS and the interception CA are separate.

- Rotate transport TLS through the deployment's certificate issuer, then
  restart AV and verify the private proxy hostname before creating a session.
- Rotate the interception CA only during a maintenance window. Restart AV,
  terminate existing proxy sessions, and relaunch clients so they receive the
  new public CA bundle.
- Never copy either private key into Git, AV configuration, AV's database, or
  a client workload.

After rotation, verify plaintext remains rejected, the transport certificate
matches the private proxy hostname, one allowed TLS request works, and an
unknown host still fails closed.

## 9. Upgrade and rollback

Before upgrading:

1. verify the new release and record its digest;
2. capture and test a managed-database backup;
3. render and review the new chart;
4. run the release's connector and policy smoke tests in a disposable
   environment; and
5. retain the previous chart version, image digest, values, and database
   backup.

Upgrade with `helm upgrade --atomic --wait`. Then validate readiness,
authentication, RBAC, all configured delivery tiers, audit records, session
revocation, and egress denial.

For an application-only regression whose database schema is compatible, use:

```bash
helm rollback av PREVIOUS_REVISION --namespace av --wait --timeout 10m
```

If a release changed the managed schema incompatibly, restore the matching
pre-upgrade database backup before redeploying the previous chart and image
digest. Never assume a down migration exists.

## 10. Release acceptance record

For each production release, record without secret values:

- release tag, source commit, chart version, and image digest;
- binary, image, SBOM, provenance, vulnerability, and CI results;
- OIDC and optional Basic authentication results;
- owner/operator/auditor and named-agent grant results;
- Tier 1 dynamic lease issuance and synchronous cleanup;
- Tier 2 named, transparent, tunnel, and revocation results;
- Tier 3 static/dynamic child cleanup;
- direct-egress and metadata denial;
- readiness, graceful shutdown, certificate rotation, backup/restore, upgrade,
  and rollback results; and
- explicit exceptions with an owner and follow-up issue.

Never place tokens, environment values, request bodies, credentials, private
keys, or unredacted responses in that record.
