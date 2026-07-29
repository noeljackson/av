//! Strict destination matching for AV's planned transparent proxy.
//!
//! The network listener and TLS interception are intentionally not implemented
//! here. This catalog is the security-critical first step: a CONNECT authority
//! must select exactly one immutable AV route before AV can resolve DNS or open
//! an upstream connection. There is no fallback or pass-through destination.

use std::{collections::BTreeMap, net::IpAddr};

use anyhow::{Context, Result, bail};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use axum::http::{HeaderMap, Method, Uri, header};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::Zeroizing;

use crate::config::{ProxyRouteConfig, ProxyTunnelConfig};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransparentRouteCatalog {
    destinations_by_host: BTreeMap<String, TransparentDestination>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransparentDestination {
    Injecting {
        name: String,
        profile: String,
    },
    Tunnel {
        name: String,
        profile: String,
        host: String,
        allow_private_ips: bool,
    },
}

impl TransparentDestination {
    pub fn name(&self) -> &str {
        match self {
            Self::Injecting { name, .. } | Self::Tunnel { name, .. } => name,
        }
    }

    pub fn profile(&self) -> &str {
        match self {
            Self::Injecting { profile, .. } | Self::Tunnel { profile, .. } => profile,
        }
    }

    pub fn mode(&self) -> &'static str {
        match self {
            Self::Injecting { .. } => "injecting",
            Self::Tunnel { .. } => "tunnel",
        }
    }
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedConnect {
    pub destination: TransparentDestination,
    pub host: String,
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
    /// Build the strict host catalog from AV's immutable route and tunnel
    /// policy.
    ///
    /// The first transparent-proxy release supports one route per DNS host and
    /// only the standard HTTPS port. Multiple policies for one host are easy to
    /// make ambiguous before request decryption, so configuration must be
    /// rejected rather than choosing one at runtime.
    pub fn from_config(
        routes: &BTreeMap<String, ProxyRouteConfig>,
        tunnels: &BTreeMap<String, ProxyTunnelConfig>,
    ) -> Result<Self> {
        let mut destinations_by_host = BTreeMap::new();
        for (route_name, route) in routes {
            let url = Url::parse(&route.base_url)
                .with_context(|| format!("parse proxy route {route_name} base URL"))?;
            // Named routes may deliberately target a nonstandard or
            // integration-only origin. They remain available through the
            // explicit route API but are not eligible for transparent MITM.
            if url.scheme() != "https" || url.port_or_known_default() != Some(443) {
                continue;
            }
            let host =
                canonical_dns_host(url.host_str().with_context(|| {
                    format!("transparent proxy route {route_name} has no host")
                })?)?;
            let destination = TransparentDestination::Injecting {
                name: route_name.clone(),
                profile: route.profile.clone(),
            };
            if let Some(existing) = destinations_by_host.insert(host.clone(), destination) {
                bail!(
                    "transparent proxy destinations {} and {route_name} share host {host}; one host may have only one destination",
                    existing.name()
                );
            }
        }
        for (tunnel_name, tunnel) in tunnels {
            let host = canonical_tunnel_host(&tunnel.host)?;
            let destination = TransparentDestination::Tunnel {
                name: tunnel_name.clone(),
                profile: tunnel.profile.clone(),
                host: host.clone(),
                allow_private_ips: tunnel.allow_private_ips,
            };
            if let Some(existing) = destinations_by_host.insert(host.clone(), destination) {
                bail!(
                    "transparent proxy destinations {} and {tunnel_name} share host {host}; one host may have only one destination",
                    existing.name()
                );
            }
        }
        Ok(Self {
            destinations_by_host,
        })
    }

    /// Return the single policy route matching an HTTP CONNECT authority.
    ///
    /// The caller must treat `None` as a deny decision and must not perform DNS
    /// resolution or connect an upstream socket first.
    pub fn destination_for_connect_authority(
        &self,
        authority: &str,
    ) -> Option<&TransparentDestination> {
        let host = canonical_connect_authority(authority).ok()?;
        self.destinations_by_host.get(&host)
    }

    pub fn is_empty(&self) -> bool {
        self.destinations_by_host.is_empty()
    }
}

/// Validate the only forward-proxy request shape AV accepts. This function is
/// deliberately free of DNS and sockets: callers must complete it before any
/// upstream operation.
pub fn authorize_connect_request(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    catalog: &TransparentRouteCatalog,
) -> Result<AuthorizedConnect> {
    if method != Method::CONNECT {
        bail!("transparent proxy accepts CONNECT only");
    }
    let authority = uri
        .authority()
        .map(|value| value.as_str())
        .context("CONNECT request has no authority")?;
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .context("CONNECT request has no valid Host header")?;
    if headers.get_all(header::HOST).iter().count() != 1
        || canonical_connect_authority(host)? != canonical_connect_authority(authority)?
    {
        bail!("CONNECT Host header must exactly identify the requested authority");
    }
    let canonical_authority = canonical_connect_authority(authority)?;
    let destination = catalog
        .destinations_by_host
        .get(&canonical_authority)
        .context("CONNECT destination is not configured")?;
    let values: Vec<_> = headers.get_all("proxy-authorization").iter().collect();
    if values.len() != 1 {
        bail!("CONNECT request requires exactly one proxy bearer capability");
    }
    let value = values[0]
        .to_str()
        .context("CONNECT proxy authorization is not valid text")?;
    let token = value
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
        .context("CONNECT proxy authorization must use Bearer")?;
    if token
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        bail!("CONNECT proxy bearer capability is malformed");
    }
    Ok(AuthorizedConnect {
        destination: destination.clone(),
        host: canonical_authority,
        token_hash: proxy_session_token_hash(token.as_bytes()),
    })
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

pub fn canonical_tunnel_host(host: &str) -> Result<String> {
    if host.contains([':', '/', '?', '#', '@']) || host.chars().any(char::is_whitespace) {
        bail!("tunnel host must be an exact DNS name without a port");
    }
    canonical_dns_host(host)
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
            injection: None,
            body_substitutions: BTreeMap::new(),
            allowed_methods: vec!["GET".into()],
            allowed_path_prefixes: vec!["/v1/".into()],
            allowed_request_headers: vec![],
            allowed_response_headers: vec![],
            allowed_query_parameters: vec![],
            allowed_content_types: vec![],
            max_body_bytes: 1024,
            response_mode: crate::config::ProxyResponseMode::Buffered,
            max_response_bytes: 4 * 1024 * 1024,
            websocket: None,
        }
    }

    fn catalog(entries: &[(&str, &str)]) -> Result<TransparentRouteCatalog> {
        let routes = entries
            .iter()
            .map(|(name, base_url)| ((*name).to_owned(), route(base_url)))
            .collect();
        TransparentRouteCatalog::from_config(&routes, &BTreeMap::new())
    }

    #[test]
    fn accepts_only_the_configured_dns_host_on_https_443() {
        let catalog = catalog(&[("provider", "https://api.example.test/v1")]).unwrap();

        assert_eq!(
            catalog
                .destination_for_connect_authority("api.example.test:443")
                .map(TransparentDestination::name),
            Some("provider"),
        );
        assert_eq!(
            catalog
                .destination_for_connect_authority("API.EXAMPLE.TEST.:443")
                .map(TransparentDestination::name),
            Some("provider"),
        );
        assert_eq!(
            catalog
                .destination_for_connect_authority("api.example.test")
                .map(TransparentDestination::name),
            Some("provider"),
        );
    }

    #[test]
    fn denies_unknown_hosts_before_any_upstream_decision() {
        let catalog = catalog(&[("provider", "https://api.example.test")]).unwrap();

        assert_eq!(
            catalog.destination_for_connect_authority("other.example.test:443"),
            None
        );
        assert_eq!(
            catalog.destination_for_connect_authority("api.example.test:8443"),
            None
        );
        assert_eq!(
            catalog.destination_for_connect_authority("127.0.0.1:443"),
            None
        );
        assert_eq!(catalog.destination_for_connect_authority("[::1]:443"), None);
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
    fn excludes_nonstandard_routes_and_rejects_ip_literal_route_hosts() {
        let nonstandard = catalog(&[("provider", "https://api.example.test:8443")]).unwrap();
        assert!(nonstandard.is_empty());

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
                catalog.destination_for_connect_authority(authority),
                None,
                "{authority}"
            );
        }
    }

    #[test]
    fn connect_authority_parser_rejects_generated_delimiter_control_and_port_variants() {
        let catalog = catalog(&[("provider", "https://api.example.test")]).unwrap();

        for byte in 0_u8..=0x7f {
            if byte.is_ascii_control() || byte.is_ascii_whitespace() {
                let authority = format!(
                    "api.example{byte_as_char}.test:443",
                    byte_as_char = byte as char
                );
                assert_eq!(
                    catalog.destination_for_connect_authority(&authority),
                    None,
                    "accepted ASCII byte 0x{byte:02x}"
                );
            }
        }
        for delimiter in ['/', '?', '#', '@'] {
            for position in 0..="api.example.test:443".len() {
                let mut authority = "api.example.test:443".to_owned();
                authority.insert(position, delimiter);
                assert_eq!(
                    catalog.destination_for_connect_authority(&authority),
                    None,
                    "accepted delimiter {delimiter:?} at byte {position}"
                );
            }
        }
        for port in [0, 1, 80, 442, 444, 8443, 65_535] {
            assert_eq!(
                catalog.destination_for_connect_authority(&format!("api.example.test:{port}")),
                None,
                "accepted non-HTTPS port {port}"
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

    #[test]
    fn connect_authorization_requires_exact_authority_and_one_bearer() {
        let catalog = catalog(&[("provider", "https://api.example.test/v1")]).unwrap();
        let credential = mint_proxy_session_credential();
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "api.example.test:443".parse().unwrap());
        headers.insert(
            "proxy-authorization",
            format!("Bearer {}", credential.token.as_str())
                .parse()
                .unwrap(),
        );
        let authorized = authorize_connect_request(
            &Method::CONNECT,
            &"api.example.test:443".parse::<Uri>().unwrap(),
            &headers,
            &catalog,
        )
        .unwrap();
        assert_eq!(authorized.destination.name(), "provider");
        assert_eq!(authorized.destination.mode(), "injecting");
        assert_eq!(authorized.host, "api.example.test");
        assert_eq!(authorized.token_hash, credential.token_hash);

        let wrong_host = "other.example.test:443".parse().unwrap();
        headers.insert(header::HOST, wrong_host);
        assert!(
            authorize_connect_request(
                &Method::CONNECT,
                &"api.example.test:443".parse::<Uri>().unwrap(),
                &headers,
                &catalog
            )
            .is_err()
        );
        headers.insert(header::HOST, "api.example.test:443".parse().unwrap());
        headers.insert("proxy-authorization", "Basic Zm9vOmJhcg==".parse().unwrap());
        assert!(
            authorize_connect_request(
                &Method::CONNECT,
                &"api.example.test:443".parse::<Uri>().unwrap(),
                &headers,
                &catalog
            )
            .is_err()
        );
        assert!(
            authorize_connect_request(
                &Method::GET,
                &"api.example.test:443".parse::<Uri>().unwrap(),
                &headers,
                &catalog
            )
            .is_err()
        );
    }

    #[test]
    fn tunnel_destinations_are_exact_and_cannot_overlap_injecting_routes() {
        let tunnels = BTreeMap::from([(
            "control-plane".into(),
            ProxyTunnelConfig {
                profile: "example".into(),
                host: "control.example.test".into(),
                allow_private_ips: false,
            },
        )]);
        let catalog = TransparentRouteCatalog::from_config(&BTreeMap::new(), &tunnels).unwrap();
        let destination = catalog
            .destination_for_connect_authority("control.example.test:443")
            .unwrap();
        assert_eq!(destination.name(), "control-plane");
        assert_eq!(destination.profile(), "example");
        assert_eq!(destination.mode(), "tunnel");

        let routes =
            BTreeMap::from([("injecting".into(), route("https://control.example.test/v1"))]);
        let error = TransparentRouteCatalog::from_config(&routes, &tunnels).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("share host control.example.test")
        );
    }

    #[test]
    fn connect_authorization_rejects_duplicate_or_unknown_destinations() {
        let catalog = catalog(&[("provider", "https://api.example.test")]).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "api.example.test:443".parse().unwrap());
        headers.append("proxy-authorization", "Bearer first".parse().unwrap());
        headers.append("proxy-authorization", "Bearer second".parse().unwrap());
        assert!(
            authorize_connect_request(
                &Method::CONNECT,
                &"api.example.test:443".parse::<Uri>().unwrap(),
                &headers,
                &catalog
            )
            .is_err()
        );

        let mut unknown_headers = HeaderMap::new();
        unknown_headers.insert(header::HOST, "unknown.example.test:443".parse().unwrap());
        unknown_headers.insert("proxy-authorization", "Bearer capability".parse().unwrap());
        assert!(
            authorize_connect_request(
                &Method::CONNECT,
                &"unknown.example.test:443".parse::<Uri>().unwrap(),
                &unknown_headers,
                &catalog
            )
            .is_err()
        );
    }
}
