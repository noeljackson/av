//! Strict destination matching for AV's planned transparent proxy.
//!
//! The network listener and TLS interception are intentionally not implemented
//! here. This catalog is the security-critical first step: a CONNECT authority
//! must select exactly one immutable AV route before AV can resolve DNS or open
//! an upstream connection. There is no fallback or pass-through destination.

use std::{collections::BTreeMap, net::IpAddr};

use anyhow::{Context, Result, bail};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::Zeroizing;

use crate::config::ProxyRouteConfig;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransparentRouteCatalog {
    routes_by_host: BTreeMap<String, String>,
}

/// A one-time generated proxy capability. `token` is intentionally separate
/// from `token_hash`: callers return the former to the local helper once and
/// persist only the latter.
#[derive(Debug)]
pub struct ProxySessionCredential {
    pub session_id: String,
    pub token: Zeroizing<String>,
    pub token_hash: [u8; 32],
}

pub fn mint_proxy_session_credential() -> ProxySessionCredential {
    let mut session_id_bytes = [0_u8; 16];
    let mut token_bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut session_id_bytes);
    OsRng.fill_bytes(&mut token_bytes);
    let token = Zeroizing::new(URL_SAFE_NO_PAD.encode(token_bytes));
    let token_hash = proxy_session_token_hash(token.as_bytes());
    ProxySessionCredential {
        session_id: URL_SAFE_NO_PAD.encode(session_id_bytes),
        token,
        token_hash,
    }
}

pub fn proxy_session_token_hash(token: &[u8]) -> [u8; 32] {
    Sha256::digest(token).into()
}

impl TransparentRouteCatalog {
    /// Build the strict host catalog from AV's immutable named-route policy.
    ///
    /// The first transparent-proxy release supports one route per DNS host and
    /// only the standard HTTPS port. Multiple policies for one host are easy to
    /// make ambiguous before request decryption, so configuration must be
    /// rejected rather than choosing one at runtime.
    pub fn from_proxy_routes(routes: &BTreeMap<String, ProxyRouteConfig>) -> Result<Self> {
        let mut routes_by_host = BTreeMap::new();
        for (route_name, route) in routes {
            let url = Url::parse(&route.base_url)
                .with_context(|| format!("parse proxy route {route_name} base URL"))?;
            if url.scheme() != "https" {
                bail!("transparent proxy route {route_name} must use HTTPS");
            }
            if url.port_or_known_default() != Some(443) {
                bail!("transparent proxy route {route_name} must use the default HTTPS port 443");
            }
            let host =
                canonical_dns_host(url.host_str().with_context(|| {
                    format!("transparent proxy route {route_name} has no host")
                })?)?;
            if let Some(existing) = routes_by_host.insert(host.clone(), route_name.clone()) {
                bail!(
                    "transparent proxy routes {existing} and {route_name} share host {host}; one host may have only one route"
                );
            }
        }
        Ok(Self { routes_by_host })
    }

    /// Return the single policy route matching an HTTP CONNECT authority.
    ///
    /// The caller must treat `None` as a deny decision and must not perform DNS
    /// resolution or connect an upstream socket first.
    pub fn route_for_connect_authority(&self, authority: &str) -> Option<&str> {
        let host = canonical_connect_authority(authority).ok()?;
        self.routes_by_host.get(&host).map(String::as_str)
    }

    pub fn is_empty(&self) -> bool {
        self.routes_by_host.is_empty()
    }
}

fn canonical_connect_authority(authority: &str) -> Result<String> {
    // Parsing through URL rejects ambiguous userinfo and produces a normalized
    // IDNA hostname. CONNECT authorities have no path, query, or fragment.
    if authority.is_empty()
        || authority.contains('/')
        || authority.contains('?')
        || authority.contains('#')
        || authority.contains('@')
        || authority.chars().any(char::is_whitespace)
    {
        bail!("invalid CONNECT authority");
    }
    let url = Url::parse(&format!("https://{authority}")).context("parse CONNECT authority")?;
    if url.port_or_known_default() != Some(443) || url.path() != "/" {
        bail!("CONNECT authority must use port 443");
    }
    canonical_dns_host(url.host_str().context("CONNECT authority has no host")?)
}

fn canonical_dns_host(host: &str) -> Result<String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.parse::<IpAddr>().is_ok() {
        bail!("transparent proxy destinations must be DNS names, not IP literals");
    }
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(base_url: &str) -> ProxyRouteConfig {
        ProxyRouteConfig {
            profile: "example".into(),
            base_url: base_url.into(),
            secret_key: "TOKEN".into(),
            header: "Authorization".into(),
            header_prefix: "Bearer ".into(),
            allowed_methods: vec!["GET".into()],
            allowed_path_prefixes: vec!["/v1/".into()],
            allowed_request_headers: vec![],
            allowed_response_headers: vec![],
            allowed_query_parameters: vec![],
            allowed_content_types: vec![],
            max_body_bytes: 1024,
        }
    }

    fn catalog(entries: &[(&str, &str)]) -> Result<TransparentRouteCatalog> {
        let routes = entries
            .iter()
            .map(|(name, base_url)| ((*name).to_owned(), route(base_url)))
            .collect();
        TransparentRouteCatalog::from_proxy_routes(&routes)
    }

    #[test]
    fn accepts_only_the_configured_dns_host_on_https_443() {
        let catalog = catalog(&[("provider", "https://api.example.test/v1")]).unwrap();

        assert_eq!(
            catalog.route_for_connect_authority("api.example.test:443"),
            Some("provider")
        );
        assert_eq!(
            catalog.route_for_connect_authority("API.EXAMPLE.TEST.:443"),
            Some("provider")
        );
        assert_eq!(
            catalog.route_for_connect_authority("api.example.test"),
            Some("provider")
        );
    }

    #[test]
    fn denies_unknown_hosts_before_any_upstream_decision() {
        let catalog = catalog(&[("provider", "https://api.example.test")]).unwrap();

        assert_eq!(
            catalog.route_for_connect_authority("other.example.test:443"),
            None
        );
        assert_eq!(
            catalog.route_for_connect_authority("api.example.test:8443"),
            None
        );
        assert_eq!(catalog.route_for_connect_authority("127.0.0.1:443"), None);
        assert_eq!(catalog.route_for_connect_authority("[::1]:443"), None);
    }

    #[test]
    fn rejects_ambiguous_routes_for_one_host() {
        let error = catalog(&[
            ("provider-read", "https://api.example.test/v1/read"),
            ("provider-write", "https://api.example.test/v1/write"),
        ])
        .unwrap_err();

        assert!(error.to_string().contains("share host api.example.test"));
    }

    #[test]
    fn rejects_nonstandard_ports_and_ip_literal_route_hosts() {
        let port_error = catalog(&[("provider", "https://api.example.test:8443")]).unwrap_err();
        assert!(port_error.to_string().contains("port 443"));

        let ip_error = catalog(&[("provider", "https://192.0.2.10")]).unwrap_err();
        assert!(ip_error.to_string().contains("not IP literals"));
    }

    #[test]
    fn rejects_malformed_or_credential_bearing_connect_authorities() {
        let catalog = catalog(&[("provider", "https://api.example.test")]).unwrap();

        for authority in [
            "user@api.example.test:443",
            "api.example.test:443/path",
            "api.example.test:443?query=value",
            "api.example.test:443#fragment",
            "api.example.test:443 extra",
        ] {
            assert_eq!(
                catalog.route_for_connect_authority(authority),
                None,
                "{authority}"
            );
        }
    }

    #[test]
    fn proxy_session_credentials_are_opaque_and_store_only_a_digest() {
        let first = mint_proxy_session_credential();
        let second = mint_proxy_session_credential();

        assert_ne!(first.session_id, second.session_id);
        assert_ne!(first.token, second.token);
        assert_eq!(
            first.token_hash,
            proxy_session_token_hash(first.token.as_bytes())
        );
        assert_eq!(
            second.token_hash,
            proxy_session_token_hash(second.token.as_bytes())
        );
        assert_eq!(first.token_hash.len(), 32);
        assert!(!first.session_id.contains('='));
        assert!(!first.token.contains('='));
    }
}
