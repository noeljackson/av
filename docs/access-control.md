# Access control

Managed AV separates instance administration from capability delivery. Backend
configuration remains immutable deployment policy; the database stores only
roles, explicit grants, agent-token digests, sessions, and redacted audit
metadata.

There are four instance roles:

| Role | May do |
|---|---|
| `owner` | Manage roles and perform every operator/auditor action |
| `operator` | Manage Basic accounts, agents, profile grants, and sessions |
| `auditor` | Read redacted audit events |
| `user` | Use only explicitly granted capabilities |

An authenticated identity with no stored role is a `user`. The initial owner is
inserted only when the managed database is empty. AV refuses to demote the last
owner.

Profile grants also have a delivery mode:

| Mode | Allows |
|---|---|
| `proxy` | Tier 2 named routes and transparent proxy sessions |
| `environment` | Tier 3 child-process environment delivery |
| `both` | Both delivery paths; use only when required |

Grants may have a Unix-time expiry. Expiry and revocation are checked on every
request. A proxy-only identity cannot call the environment endpoint, even when
it can see the profile name.

## Named agents

An agent is a non-human principal named `agent:NAME`. Create it while logged in
as an owner or operator:

```bash
av agents create builder --out "${XDG_RUNTIME_DIR}/av-builder.token"
export AV_AGENT_TOKEN_FILE="${XDG_RUNTIME_DIR}/av-builder.token"
```

The output file is mode `0600`. AV returns the 256-bit token only from create
or rotate and stores only its SHA-256 digest. Prefer `AV_AGENT_TOKEN_FILE` over
putting the token directly in an environment variable. AV validates the file
type, size, permissions, and token shape.

Grant only the delivery path the agent needs:

```bash
av agents grant builder orchard-dev --mode proxy
av agents grant builder orchard-build --mode environment \
  --expires-unix-seconds 1800000000
av agents revoke builder orchard-build
```

Use `av agents rotate builder --out PATH` after suspected exposure. Rotation,
disable, and deletion revoke the agent's active proxy sessions. Deletion also
removes its grants.

The wrapper removes `AV_AGENT_TOKEN_FILE`, `AV_AGENT_TOKEN`, OIDC tokens, and
Basic credentials from the launched child. The child receives only its granted
proxy settings or profile values.

## Roles

Owners can inspect and change explicit role bindings:

```bash
av roles list
av roles set 'oidc:operator-subject' operator
av roles set 'github:12345678' auditor
```

The managed browser interface exposes the same operations. Operators see
account, agent, and grant controls but not owner-only role controls. Ordinary
users do not receive the management panel, and the logged-out screen reveals
no connector, profile, role, or principal details.

AV deliberately has no registration, invitation, proposal, approval-link, or
provider-secret form. An owner or operator grants a capability that already
exists in deployment configuration.
