//! Reusable, fail-closed credential proxy primitives.
//!
//! This crate owns security-sensitive request policy, credential injection,
//! response redaction, CONNECT authorization, tunnel address classification,
//! and interception certificate issuance. Authentication, credential storage,
//! network transport, audit persistence, and lifecycle remain host concerns.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod ca;
mod catalog;
mod policy;
mod redaction;

pub use ca::ProxyCertificateAuthority;
pub use catalog::{
    AuthorizedConnect, ProxySessionCredential, TransparentDestination, TransparentRouteCatalog,
    authorize_connect_request, canonical_tunnel_host, mint_proxy_session_credential,
    proxy_session_token_hash, tunnel_ip_allowed,
};
pub use policy::{
    CredentialSource, PreparedCredentials, ProxyInjectionConfig, ProxyResponseMode,
    ProxyRouteConfig, ProxyTunnelConfig, ProxyWebSocketConfig, ValidatedProxyRequest,
    build_target_url, enforce_transparent_tunnel_target, is_websocket_attempt, prepare_credentials,
    prepare_outbound_headers, prepare_websocket_credentials, validate_proxy_request,
    validate_proxy_route, validate_proxy_tunnel, validate_websocket_handshake,
    websocket_subprotocols,
};
pub use redaction::{RedactionSet, StreamingRedactor};
