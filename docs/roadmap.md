# AV roadmap

AV is a credential broker, not a secrets manager. External stores own secret
values; Git-managed deployment configuration defines connectors, profiles,
destinations, and proxy policy; AV persists only identities, grants, sessions,
non-replayable token hashes, and redacted audit records.

The durable roadmap is tracked in
[GitHub issue #12](https://github.com/noeljackson/av/issues/12). Each workstream
has its own acceptance criteria and implementation history:

| Workstream | Tracking issue | Status |
| --- | --- | --- |
| Backend contract and Google Secret Manager | [#13](https://github.com/noeljackson/av/issues/13) | Implemented; live Workload Identity Federation validation remains |
| Named agents and explicit RBAC grants | [#17](https://github.com/noeljackson/av/issues/17) | Implemented and covered by SQLite, PostgreSQL, CLI, and browser tests |
| Proxy parity | [#16](https://github.com/noeljackson/av/issues/16) | Implemented: exact credentialless tunnels [#18](https://github.com/noeljackson/av/issues/18), sliding sessions [#19](https://github.com/noeljackson/av/issues/19), and streaming/typed injection/WebSockets [#20](https://github.com/noeljackson/av/issues/20) |
| OpenBao and Infisical dynamic leases | [#14](https://github.com/noeljackson/av/issues/14) | Complete: backend adapters [#21](https://github.com/noeljackson/av/issues/21), child ownership [#22](https://github.com/noeljackson/av/issues/22), and Tier 2 request/stream/WebSocket cleanup [#23](https://github.com/noeljackson/av/issues/23) |
| Production hardening, isolation, and deployment | [#15](https://github.com/noeljackson/av/issues/15) | In progress: Helm operations [#25](https://github.com/noeljackson/av/issues/25), security/release proof [#26](https://github.com/noeljackson/av/issues/26), and cooperative/enforced runtime isolation [#24](https://github.com/noeljackson/av/issues/24) are complete; production deployment/docs [#27](https://github.com/noeljackson/av/issues/27) remains |

## Fixed product boundaries

- AV never accepts provider secret values through its UI, API, or database.
- Backends are reviewed Rust drivers compiled into the signed AV binary, not
  runtime executable plugins.
- Owners and operators grant only capabilities already declared in deployment
  policy. There are no proposals, invitations, or approval links.
- Proxy traffic is either an explicitly declared credential-injecting route or
  an exact-host credentialless TLS tunnel. AV is not a general-purpose proxy.
- Google Secret Manager uses Application Default Credentials or Workload
  Identity Federation. Service-account key files are intentionally unsupported.
- Unknown connectors, profiles, routes, destinations, principals, and delivery
  modes fail closed.

Issues preserve task state and design discussion; this document preserves the
stable architecture and operator-facing sequence. Update both when a workstream
changes scope or reaches its acceptance criteria.
