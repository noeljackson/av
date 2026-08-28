use std::{collections::BTreeMap, fmt, net::IpAddr};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{HeaderMap, Method, Uri, header};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::{ProxyRouteConfig, ProxyTunnelConfig};

/// A fail-closed mapping from one HTTPS host to one injecting route or tunnel.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct TransparentRouteCatalog {
    destinations_by_host: BTreeMap<String, TransparentDestination>,
}

impl fmt::Debug for TransparentRouteCatalog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransparentRouteCatalog")
            .field("destination_count", &self.destinations_by_host.len())
            .finish()
    }
}

/// The immutable action selected by a validated CONNECT destination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransparentDestination {
    /// Terminate TLS, enforce the named route, and inject its credential.
    Injecting {
        /// Host-owned route identifier.
        name: String,
        /// Host-owned credential and authorization binding.
        profile: String,
    },
    /// Relay end-to-end TLS without credential access or HTTP inspection.
    Tunnel {
        /// Host-owned tunnel identifier.
        name: String,
        /// Host-owned authorization binding.
        profile: String,
        /// Exact configured DNS host.
        host: String,
        /// Whether RFC1918, unique-local, benchmark, and CGNAT results may be used.
        allow_private_ips: bool,
    },
}

impl TransparentDestination {
    /// Return the host-owned route or tunnel identifier.
    pub fn name(&self) -> &str {
        match self {
            Self::Injecting { name, .. } | Self::Tunnel { name, .. } => name,
        }
    }

    /// Return the opaque host-owned authorization and credential binding.
    pub fn profile(&self) -> &str {
        match self {
            Self::Injecting { profile, .. } | Self::Tunnel { profile, .. } => profile,
        }
    }

    /// Return `injecting` or `tunnel` for status and audit metadata.
    pub fn mode(&self) -> &'static str {
        match self {
            Self::Injecting { .. } => "injecting",
            Self::Tunnel { .. } => "tunnel",
        }
    }
}

/// A newly minted short-lived proxy session capability.
///
/// The raw token may be handed to a trusted transport helper. Persist only
/// `token_hash`; neither value is included in `Debug` output.
pub struct ProxySessionCredential {
    /// Random, non-secret session identifier.
    pub session_id: String,
    /// Short-lived raw bearer capability.
    pub token: Zeroizing<String>,
    /// SHA-256 digest suitable for server-side lookup.
    pub token_hash: [u8; 32],
}

impl fmt::Debug for ProxySessionCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxySessionCredential")
            .field("session_id", &self.session_id)
            .field("token", &"[REDACTED]")
            .field("token_hash", &"[REDACTED]")
            .finish()
    }
}

/// A CONNECT request whose syntax and destination have been authorized.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizedConnect {
    /// Exact catalog entry selected before DNS or upstream connection.
    pub destination: TransparentDestination,
    /// Canonical DNS host without a port.
    pub host: String,
    /// Digest of the caller's proxy capability for host-side session lookup.
    pub token_hash: [u8; 32],
}

impl fmt::Debug for AuthorizedConnect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedConnect")
            .field("destination", &self.destination)
            .field("host", &self.host)
            .field("token_hash", &"[REDACTED]")
            .finish()
    }
}

/// Mint a random proxy session identifier, token, and server-side digest.
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

/// Hash a raw proxy session capability for digest-only server persistence.
pub fn proxy_session_token_hash(token: &[u8]) -> [u8; 32] {
    Sha256::digest(token).into()
}

impl TransparentRouteCatalog {
    /// Build an unambiguous catalog from immutable route and tunnel policy.
    ///
    /// Only standard HTTPS injecting routes are eligible for transparent TLS
    /// interception. Explicit named routes on other origins remain a host
    /// concern and are omitted. One host may appear only once in a catalog.
    pub fn from_config(
        routes: &BTreeMap<String, ProxyRouteConfig>,
        tunnels: &BTreeMap<String, ProxyTunnelConfig>,
    ) -> Result<Self> {
        let mut destinations_by_host = BTreeMap::new();
        for (route_name, route) in routes {
            let url = Url::parse(&route.base_url)
                .with_context(|| format!("parse proxy route {route_name} base URL"))?;
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

    /// Resolve one CONNECT authority without performing DNS or network I/O.
    pub fn destination_for_connect_authority(
        &self,
        authority: &str,
    ) -> Option<&TransparentDestination> {
        let host = canonical_connect_authority(authority).ok()?;
        self.destinations_by_host.get(&host)
    }

    /// Return whether this catalog has no eligible destinations.
    pub fn is_empty(&self) -> bool {
        self.destinations_by_host.is_empty()
    }
}

/// Validate a CONNECT request and select its exact immutable destination.
///
/// This function performs no DNS or socket work. Callers must not resolve or
/// connect until it succeeds and the returned token digest is authorized.
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
    if authority.is_empty()
        || authority.contains('/')
        || authority.contains('?')
        || authority.contains('#')
        || authority.contains('@')
        || authority.chars().any(char::is_whitespace)
    {
        bail!("invalid CONNECT authority");
    }
    let (host, port) = authority
        .rsplit_once(':')
        .context("CONNECT authority must include a port")?;
    if port != "443" || host.contains(':') {
        bail!("CONNECT authority must explicitly use port 443");
    }
    canonical_dns_host(host)
}

/// Canonicalize an exact tunnel host and reject ports, URLs, and IP literals.
pub fn canonical_tunnel_host(host: &str) -> Result<String> {
    if host.contains([':', '/', '?', '#', '@']) || host.chars().any(char::is_whitespace) {
        bail!("tunnel host must be an exact DNS name without a port");
    }
    canonical_dns_host(host)
}

fn canonical_dns_host(host: &str) -> Result<String> {
    if host.ends_with("..") {
        bail!("transparent proxy destination has an invalid DNS name");
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    let Host::Domain(host) = Host::parse(host).context("parse transparent proxy DNS name")? else {
        bail!("transparent proxy destinations must be DNS names, not IP literals");
    };
    if host.is_empty()
        || host.len() > 253
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || !label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                || !label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
    {
        bail!("transparent proxy destination has an invalid DNS name");
    }
    Ok(host.to_ascii_lowercase())
}

/// Classify a resolved tunnel address before a host opens an upstream socket.
///
/// Loopback, link-local, multicast, unspecified, broadcast, documentation,
/// and metadata-adjacent ranges are always denied. Private, CGNAT, benchmark,
/// and IPv6 unique-local ranges require the route's explicit opt-in.
pub fn tunnel_ip_allowed(address: IpAddr, allow_private_ips: bool) -> bool {
    match address {
        IpAddr::V4(address) => {
            if address.is_unspecified()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_broadcast()
                || address.is_documentation()
                || address.octets()[0] == 0
                || address.octets()[0] >= 240
                || ipv4_in_prefix(address, std::net::Ipv4Addr::new(192, 0, 0, 0), 24)
            {
                return false;
            }
            allow_private_ips
                || (!address.is_private()
                    && !ipv4_in_prefix(address, std::net::Ipv4Addr::new(100, 64, 0, 0), 10)
                    && !ipv4_in_prefix(address, std::net::Ipv4Addr::new(198, 18, 0, 0), 15))
        }
        IpAddr::V6(address) => {
            if let Some(address) = address.to_ipv4_mapped() {
                return tunnel_ip_allowed(IpAddr::V4(address), allow_private_ips);
            }
            if address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || address.is_unicast_link_local()
                || address.segments()[0] == 0x2001 && address.segments()[1] == 0x0db8
                || address.segments()[0] == 0x2001 && address.segments()[1] == 0
                || address.segments()[0] == 0x2002
            {
                return false;
            }
            if address.is_unique_local() {
                return allow_private_ips;
            }
            address.segments()[0] & 0xe000 == 0x2000
        }
    }
}

fn ipv4_in_prefix(address: std::net::Ipv4Addr, network: std::net::Ipv4Addr, prefix: u32) -> bool {
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    u32::from(address) & mask == u32::from(network) & mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProxyInjectionConfig, ProxyResponseMode, ProxyWebSocketConfig};

    fn route(base_url: &str) -> ProxyRouteConfig {
        ProxyRouteConfig {
            profile: "example".into(),
            base_url: base_url.into(),
            secret_key: String::new(),
            header: String::new(),
            header_prefix: String::new(),
            injection: Some(ProxyInjectionConfig::Bearer {
                secret_key: "TOKEN".into(),
            }),
            body_substitutions: BTreeMap::new(),
            allowed_methods: vec!["GET".into()],
            allowed_exact_paths: Vec::new(),
            allowed_path_prefixes: vec!["/v1/".into()],
            allowed_request_headers: vec![],
            allowed_response_headers: vec![],
            allowed_query_parameters: vec![],
            allowed_content_types: vec![],
            max_body_bytes: 1024,
            response_mode: ProxyResponseMode::Buffered,
            max_response_bytes: 4 * 1024 * 1024,
            websocket: None::<ProxyWebSocketConfig>,
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
                .destination_for_connect_authority("API.EXAMPLE.TEST.:443")
                .map(TransparentDestination::name),
            Some("provider")
        );
        assert_eq!(
            catalog.destination_for_connect_authority("api.example.test:8443"),
            None
        );
        assert_eq!(
            catalog.destination_for_connect_authority("api.example.test"),
            None
        );
        assert_eq!(
            catalog.destination_for_connect_authority("127.0.0.1:443"),
            None
        );
    }

    #[test]
    fn rejects_ambiguous_or_malformed_destinations() {
        let error = catalog(&[
            ("provider-read", "https://api.example.test/v1/read"),
            ("provider-write", "https://api.example.test/v1/write"),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("share host api.example.test"));

        let catalog = catalog(&[("provider", "https://api.example.test")]).unwrap();
        for authority in [
            "user@api.example.test:443",
            "api.example.test:443/path",
            "api.example.test:443?query=value",
            "api.example.test:443#fragment",
            "api.example.test:443 extra",
        ] {
            assert_eq!(catalog.destination_for_connect_authority(authority), None);
        }
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
        assert_eq!(authorized.host, "api.example.test");
        assert_eq!(authorized.token_hash, credential.token_hash);

        headers.insert(header::HOST, "other.example.test:443".parse().unwrap());
        assert!(
            authorize_connect_request(
                &Method::CONNECT,
                &"api.example.test:443".parse::<Uri>().unwrap(),
                &headers,
                &catalog
            )
            .is_err()
        );
    }

    #[test]
    fn credentials_are_random_and_debug_redacted() {
        let first = mint_proxy_session_credential();
        let second = mint_proxy_session_credential();
        assert_ne!(first.session_id, second.session_id);
        assert_ne!(first.token, second.token);
        assert_eq!(
            first.token_hash,
            proxy_session_token_hash(first.token.as_bytes())
        );
        let debug = format!("{first:?}");
        assert!(!debug.contains(first.token.as_str()));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn tunnel_ip_policy_blocks_metadata_and_requires_private_opt_in() {
        assert!(tunnel_ip_allowed("1.1.1.1".parse().unwrap(), false));
        assert!(!tunnel_ip_allowed("10.0.0.1".parse().unwrap(), false));
        assert!(tunnel_ip_allowed("10.0.0.1".parse().unwrap(), true));
        assert!(!tunnel_ip_allowed(
            "100.100.100.100".parse().unwrap(),
            false
        ));
        assert!(tunnel_ip_allowed("100.100.100.100".parse().unwrap(), true));
        for address in [
            "127.0.0.1",
            "169.254.169.254",
            "0.0.0.1",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "64:ff9b::a00:1",
        ] {
            assert!(
                !tunnel_ip_allowed(address.parse().unwrap(), true),
                "{address}"
            );
        }
    }
}
