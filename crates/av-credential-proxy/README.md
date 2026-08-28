# av-credential-proxy

`av-credential-proxy` contains AV's reusable, fail-closed credential proxy
engine. It deliberately has no identity provider, database, secret backend,
network listener, process launcher, UI, or deployment integration.

External consumers should pin an AV Git commit; the crate is not published to
crates.io. Its minimum supported Rust version is 1.91.1. An embedding host
deserializes `ProxyRouteConfig`, calls `validate_proxy_route` once before making
the immutable configuration reachable, and then uses `validate_proxy_request`,
`prepare_credentials`, `prepare_outbound_headers`, and `build_target_url` for
each authorized request. Transparent HTTPS clients additionally use
`TransparentRouteCatalog`, `authorize_connect_request`, and
`ProxyCertificateAuthority`.

The embedding host owns:

- authenticating a workload and binding it to an exact credential profile;
- resolving credential values and owning any dynamic lease;
- enforcing that the workload cannot bypass the selected proxy transport;
- resolving DNS, opening upstream connections, and recording audit decisions;
- choosing the Rustls crypto provider and retaining interception CA material.

The library owns:

- exact CONNECT destination authorization before DNS;
- route and tunnel policy validation;
- method, path, query, header, body, and WebSocket validation;
- typed credential injection and exact body substitution;
- response redaction, including streaming chunk boundaries;
- tunnel IP classification; and
- single-host interception certificate issuance without exporting private keys.

Validation is a required lifecycle step, not an authorization decision. The
host must separately prove that the caller may use the route's `profile` before
resolving any credential. The host must also bound request bodies before passing
their length to the policy engine and bound/redact every upstream response using
the returned `RedactionSet`. Dynamic lease renewal and revocation stay with the
host because only it knows when authorization or a VM session ends.

Receiving a proxy capability grants use of the bound route. It does not reveal
the provider credential, but it does not prevent the workload from exercising
the allowed provider capability or exfiltrating data through an allowed
destination. The embedding host must keep bindings narrow and deny alternate
egress paths.
