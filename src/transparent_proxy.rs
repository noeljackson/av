//! Compatibility re-exports for AV's shared credential-proxy engine.

pub use av_credential_proxy::{
    AuthorizedConnect, ProxySessionCredential, TransparentDestination, TransparentRouteCatalog,
    authorize_connect_request, canonical_tunnel_host, mint_proxy_session_credential,
    proxy_session_token_hash, tunnel_ip_allowed,
};
