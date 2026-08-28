use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri, header};
use serde::Deserialize;
use url::Url;
use zeroize::Zeroize;

use crate::{RedactionSet, canonical_tunnel_host};

/// Immutable policy for one credential-injecting upstream origin.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyRouteConfig {
    /// Opaque host-owned credential and authorization binding.
    pub profile: String,
    /// Fixed upstream origin and optional base path.
    pub base_url: String,
    /// Legacy secret key; new configurations should use `injection`.
    #[serde(default)]
    pub secret_key: String,
    /// Legacy injection header; new configurations should use `injection`.
    #[serde(default)]
    pub header: String,
    /// Legacy injection prefix; new configurations should use `injection`.
    #[serde(default)]
    pub header_prefix: String,
    /// Typed credential construction performed inside the trusted host.
    #[serde(default)]
    pub injection: Option<ProxyInjectionConfig>,
    /// Exact one-use body placeholders mapped to credential keys.
    #[serde(default)]
    pub body_substitutions: BTreeMap<String, String>,
    /// Allowed CRUD methods.
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    /// Exact canonical paths.
    #[serde(default)]
    pub allowed_exact_paths: Vec<String>,
    /// Canonical path subtrees with segment-boundary matching.
    #[serde(default)]
    pub allowed_path_prefixes: Vec<String>,
    /// Caller headers that may reach the upstream.
    #[serde(default = "default_allowed_request_headers")]
    pub allowed_request_headers: Vec<String>,
    /// Upstream headers that may reach the caller after redaction.
    #[serde(default = "default_allowed_response_headers")]
    pub allowed_response_headers: Vec<String>,
    /// Unique query parameter names accepted from the caller.
    #[serde(default)]
    pub allowed_query_parameters: Vec<String>,
    /// Lowercase media types accepted when a request has a body.
    #[serde(default)]
    pub allowed_content_types: Vec<String>,
    /// Maximum request bytes before and after substitution.
    #[serde(default = "default_proxy_max_body_bytes")]
    pub max_body_bytes: usize,
    /// Buffered or bounded streaming response handling.
    #[serde(default)]
    pub response_mode: ProxyResponseMode,
    /// Maximum upstream response bytes.
    #[serde(default = "default_proxy_max_response_bytes")]
    pub max_response_bytes: usize,
    /// Optional bounded WebSocket policy.
    #[serde(default)]
    pub websocket: Option<ProxyWebSocketConfig>,
}

/// Typed credential construction supported by the proxy engine.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProxyInjectionConfig {
    /// Construct `Authorization: Bearer <credential>`.
    Bearer {
        /// Credential key resolved by the host.
        secret_key: String,
    },
    /// Construct an `Authorization` or `X-*` header.
    Header {
        /// Credential key resolved by the host.
        secret_key: String,
        /// Exact header name.
        header: String,
        /// Fixed non-secret value prefix.
        #[serde(default)]
        prefix: String,
    },
    /// Construct an RFC 7617 Basic authorization value.
    Basic {
        /// Fixed non-secret username.
        username: String,
        /// Password key resolved by the host.
        password_secret_key: String,
    },
}

/// Response delivery mode for a route.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyResponseMode {
    /// Read, bound, redact, and then return the complete response.
    #[default]
    Buffered,
    /// Redact incrementally while enforcing a total byte ceiling.
    Streaming,
}

/// Explicit limits for a WebSocket route.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyWebSocketConfig {
    /// Exact browser Origin values; wildcards are unsupported.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Whether a non-browser client may omit Origin.
    #[serde(default)]
    pub allow_missing_origin: bool,
    /// Exact subprotocol tokens the caller may request.
    #[serde(default)]
    pub allowed_subprotocols: Vec<String>,
    /// Maximum connection lifetime.
    #[serde(default = "default_websocket_max_duration_seconds")]
    pub max_duration_seconds: u64,
    /// Maximum decoded message bytes.
    #[serde(default = "default_websocket_max_message_bytes")]
    pub max_message_bytes: usize,
    /// Maximum total bytes in both directions.
    #[serde(default = "default_websocket_max_total_bytes")]
    pub max_total_bytes: u64,
}

/// Exact credentialless HTTPS destination.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyTunnelConfig {
    /// Opaque host-owned authorization binding.
    pub profile: String,
    /// Exact DNS host; port 443 is implicit.
    pub host: String,
    /// Explicitly permit private, CGNAT, benchmark, and unique-local results.
    #[serde(default)]
    pub allow_private_ips: bool,
}

/// Host-owned read-only credential resolution for one already-authorized request.
pub trait CredentialSource {
    /// Return one credential value by its immutable policy key.
    fn credential(&self, key: &str) -> Option<&str>;
}

impl CredentialSource for BTreeMap<String, String> {
    fn credential(&self, key: &str) -> Option<&str> {
        self.get(key).map(String::as_str)
    }
}

/// Validated request fields safe to combine with a fixed route origin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedProxyRequest {
    normalized_path: String,
    query: Vec<(String, String)>,
}

impl ValidatedProxyRequest {
    /// Return the canonical leading-slash path.
    pub fn normalized_path(&self) -> &str {
        &self.normalized_path
    }

    /// Return the decoded, unique, allowlisted query pairs.
    pub fn query(&self) -> &[(String, String)] {
        &self.query
    }
}

/// Trusted credential transformation output for one request.
///
/// This type has no `Debug` implementation because it contains the outbound
/// credential header and substituted request body.
pub struct PreparedCredentials {
    injection_name: HeaderName,
    injection_value: HeaderValue,
    body: Vec<u8>,
    redaction: RedactionSet,
}

impl PreparedCredentials {
    /// Return the sensitive outbound header name.
    pub fn injection_name(&self) -> &HeaderName {
        &self.injection_name
    }

    /// Return the sensitive outbound header value.
    pub fn injection_value(&self) -> &HeaderValue {
        &self.injection_value
    }

    /// Return the substituted request body.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Consume the prepared material after the host has constructed headers.
    pub fn into_body_and_redaction(self) -> (Vec<u8>, RedactionSet) {
        (self.body, self.redaction)
    }
}

/// Validate one route independently of any host profile registry.
pub fn validate_proxy_route(
    name: &str,
    route: &ProxyRouteConfig,
    allow_insecure_http: bool,
    transparent_proxy_configured: bool,
) -> Result<()> {
    validate_policy_name("proxy route", name)?;
    validate_binding(&route.profile)
        .with_context(|| format!("proxy route {name} profile is invalid"))?;
    let base = Url::parse(&route.base_url)
        .with_context(|| format!("proxy route {name} base_url must be a URL"))?;
    if base.host_str().is_none()
        || (base.scheme() != "https" && !(base.scheme() == "http" && allow_insecure_http))
    {
        bail!("proxy route {name} base_url must use HTTPS");
    }
    if has_url_credentials(&base) || base.query().is_some() || base.fragment().is_some() {
        bail!("proxy route {name} base_url may not contain credentials, query, or fragment");
    }
    if route.allowed_methods.is_empty()
        || (route.allowed_exact_paths.is_empty() && route.allowed_path_prefixes.is_empty())
    {
        bail!("proxy route {name} must constrain methods and at least one path");
    }
    if !(1..=4 * 1024 * 1024).contains(&route.max_body_bytes) {
        bail!("proxy route {name} max_body_bytes must be between 1 and 4194304");
    }
    if route.max_response_bytes == 0 || route.max_response_bytes > 256 * 1024 * 1024 {
        bail!("proxy route {name} max_response_bytes must be between 1 and 268435456");
    }
    if route.allowed_methods.iter().any(|method| {
        !matches!(
            method.to_ascii_uppercase().as_str(),
            "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE"
        )
    }) {
        bail!("proxy route {name} contains a non-CRUD HTTP method");
    }
    if route
        .allowed_exact_paths
        .iter()
        .chain(&route.allowed_path_prefixes)
        .any(|path| !safe_policy_path(path))
    {
        bail!("proxy route {name} contains an unsafe path policy");
    }

    let (injection_header, injection_secret_keys): (&str, Vec<&str>) = match &route.injection {
        None => {
            if route.secret_key.is_empty() || route.header.is_empty() {
                bail!("proxy route {name} legacy injection requires secret_key and header");
            }
            (route.header.as_str(), vec![route.secret_key.as_str()])
        }
        Some(ProxyInjectionConfig::Bearer { secret_key }) => {
            reject_mixed_legacy_injection(name, route)?;
            ("authorization", vec![secret_key.as_str()])
        }
        Some(ProxyInjectionConfig::Header {
            secret_key,
            header,
            prefix,
        }) => {
            reject_mixed_legacy_injection(name, route)?;
            if prefix.chars().any(char::is_control) {
                bail!("proxy route {name} injection prefix contains control characters");
            }
            (header.as_str(), vec![secret_key.as_str()])
        }
        Some(ProxyInjectionConfig::Basic {
            username,
            password_secret_key,
        }) => {
            reject_mixed_legacy_injection(name, route)?;
            if username.is_empty()
                || username.len() > 256
                || username.contains(':')
                || username.chars().any(char::is_control)
            {
                bail!("proxy route {name} basic username is invalid");
            }
            ("authorization", vec![password_secret_key.as_str()])
        }
    };
    for secret_key in injection_secret_keys {
        validate_credential_key(secret_key)
            .with_context(|| format!("proxy route {name} injection secret key is invalid"))?;
    }
    if !injection_header.eq_ignore_ascii_case("authorization")
        && !injection_header.to_ascii_lowercase().starts_with("x-")
    {
        bail!("proxy route {name} may inject Authorization or an X-* header only");
    }
    HeaderName::from_bytes(injection_header.as_bytes())
        .with_context(|| format!("proxy route {name} injection header is invalid"))?;
    validate_proxy_header_allowlist(
        name,
        "request",
        &route.allowed_request_headers,
        Some(injection_header),
    )?;
    validate_proxy_header_allowlist(name, "response", &route.allowed_response_headers, None)?;
    validate_string_allowlist(
        name,
        "query parameter",
        &route.allowed_query_parameters,
        |value| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        },
    )?;
    if route.body_substitutions.len() > 16 {
        bail!("proxy route {name} may define at most 16 body substitutions");
    }
    if !route.body_substitutions.is_empty() && route.allowed_content_types.is_empty() {
        bail!("proxy route {name} body substitutions require explicit allowed content types");
    }
    for (placeholder, secret_key) in &route.body_substitutions {
        if !valid_body_placeholder(placeholder) {
            bail!("proxy route {name} contains an invalid body placeholder");
        }
        validate_credential_key(secret_key).with_context(|| {
            format!("proxy route {name} body substitution secret key is invalid")
        })?;
    }
    validate_string_allowlist(
        name,
        "content type",
        &route.allowed_content_types,
        |value| {
            !value.is_empty()
                && value == value.to_ascii_lowercase()
                && !value.contains(';')
                && value.split_once('/').is_some()
                && HeaderValue::from_str(value).is_ok()
        },
    )?;
    if let Some(websocket) = &route.websocket {
        if !transparent_proxy_configured
            || base.scheme() != "https"
            || base.port_or_known_default() != Some(443)
        {
            bail!("proxy route {name} WebSockets require the transparent proxy and standard HTTPS");
        }
        if !route
            .allowed_methods
            .iter()
            .any(|method| method.eq_ignore_ascii_case("GET"))
        {
            bail!("proxy route {name} WebSockets require GET");
        }
        if websocket.allowed_origins.is_empty() && !websocket.allow_missing_origin {
            bail!("proxy route {name} WebSockets require allowed_origins or allow_missing_origin");
        }
        if websocket.allowed_origins.len() > 32 || websocket.allowed_subprotocols.len() > 16 {
            bail!("proxy route {name} WebSocket policy is too large");
        }
        for origin in &websocket.allowed_origins {
            validate_websocket_origin(origin)
                .with_context(|| format!("proxy route {name} has an invalid WebSocket origin"))?;
        }
        validate_string_allowlist(
            name,
            "WebSocket subprotocol",
            &websocket.allowed_subprotocols,
            valid_http_token,
        )?;
        if !(1..=24 * 60 * 60).contains(&websocket.max_duration_seconds)
            || !(1..=16 * 1024 * 1024).contains(&websocket.max_message_bytes)
            || !(1..=1024 * 1024 * 1024).contains(&websocket.max_total_bytes)
        {
            bail!("proxy route {name} WebSocket limits are outside safe bounds");
        }
    }
    Ok(())
}

/// Validate one exact credentialless tunnel independently of host grants.
pub fn validate_proxy_tunnel(name: &str, tunnel: &ProxyTunnelConfig) -> Result<()> {
    validate_policy_name("proxy tunnel", name)?;
    validate_binding(&tunnel.profile)
        .with_context(|| format!("proxy tunnel {name} profile is invalid"))?;
    canonical_tunnel_host(&tunnel.host)
        .with_context(|| format!("proxy tunnel {name} has an invalid host"))?;
    Ok(())
}

/// Validate method, path, query, body size, and content type for one route.
pub fn validate_proxy_request(
    route: &ProxyRouteConfig,
    path: &str,
    query: Option<&str>,
    method: &Method,
    headers: &HeaderMap,
    body_len: usize,
) -> Result<ValidatedProxyRequest> {
    if !route
        .allowed_methods
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(method.as_str()))
    {
        bail!("method is not allowed");
    }
    let normalized_path = format!("/{}", path.trim_start_matches('/'));
    if !safe_policy_path(&normalized_path) {
        bail!("path contains a traversal sequence");
    }
    if !route.allowed_exact_paths.contains(&normalized_path)
        && !route
            .allowed_path_prefixes
            .iter()
            .any(|prefix| path_matches_prefix(&normalized_path, prefix))
    {
        bail!("path is not allowed");
    }
    if body_len > route.max_body_bytes {
        bail!("request body is too large");
    }
    enforce_proxy_content_type(route, headers, body_len)?;
    let query = validate_proxy_query(route, query)?;
    Ok(ValidatedProxyRequest {
        normalized_path,
        query,
    })
}

/// Re-bind a decrypted HTTP request to its already-authorized CONNECT host.
pub fn enforce_transparent_tunnel_target(
    route: &ProxyRouteConfig,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<()> {
    if uri.scheme().is_some() || uri.authority().is_some() || !uri.path().starts_with('/') {
        bail!("transparent tunnel requires an origin-form request target");
    }
    if headers.get_all(header::HOST).iter().count() != 1 {
        bail!("transparent tunnel requires exactly one Host header");
    }
    if headers.contains_key(header::PROXY_AUTHORIZATION) {
        bail!("transparent tunnel must not contain proxy authorization");
    }
    let configured =
        Url::parse(&route.base_url).context("transparent route base URL disappeared")?;
    if configured.scheme() != "https" || configured.port_or_known_default() != Some(443) {
        bail!("transparent tunnel route is not standard HTTPS");
    }
    let supplied_host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .context("transparent tunnel Host header is invalid")?;
    let supplied = Url::parse(&format!("https://{supplied_host}"))
        .context("transparent tunnel Host header is malformed")?;
    if supplied.username() != ""
        || supplied.password().is_some()
        || supplied.port_or_known_default() != Some(443)
        || supplied.host_str() != configured.host_str()
        || supplied.path() != "/"
        || supplied.query().is_some()
        || supplied.fragment().is_some()
    {
        bail!("transparent tunnel Host does not match its configured route");
    }
    Ok(())
}

/// Resolve policy credential keys and construct the only outbound credential material.
pub fn prepare_credentials(
    route: &ProxyRouteConfig,
    credentials: &(impl CredentialSource + ?Sized),
    body: &[u8],
) -> Result<PreparedCredentials> {
    if body.len() > route.max_body_bytes {
        bail!("request body is too large");
    }
    let (injection_name, injection_value, mut sensitive_values) =
        build_proxy_injection(route, credentials)?;
    let (body, body_sensitive_values) = apply_body_substitutions(route, credentials, body)?;
    sensitive_values.extend(body_sensitive_values);
    let redaction = RedactionSet::new(&sensitive_values);
    for value in &mut sensitive_values {
        value.zeroize();
    }
    Ok(PreparedCredentials {
        injection_name,
        injection_value,
        body,
        redaction,
    })
}

/// Resolve only the injection credential for a bodyless WebSocket upgrade.
///
/// Body substitutions are intentionally not evaluated because an HTTP upgrade
/// request cannot carry a proxied application body.
pub fn prepare_websocket_credentials(
    route: &ProxyRouteConfig,
    credentials: &(impl CredentialSource + ?Sized),
) -> Result<PreparedCredentials> {
    let (injection_name, injection_value, mut sensitive_values) =
        build_proxy_injection(route, credentials)?;
    let redaction = RedactionSet::new(&sensitive_values);
    for value in &mut sensitive_values {
        value.zeroize();
    }
    Ok(PreparedCredentials {
        injection_name,
        injection_value,
        body: Vec::new(),
        redaction,
    })
}

/// Copy only allowlisted caller headers and overwrite the injection header.
pub fn prepare_outbound_headers(
    route: &ProxyRouteConfig,
    inbound: &HeaderMap,
    prepared: &PreparedCredentials,
) -> Result<HeaderMap> {
    validate_proxy_header_allowlist(
        "runtime",
        "request",
        &route.allowed_request_headers,
        Some(prepared.injection_name().as_str()),
    )?;
    let mut outbound = HeaderMap::new();
    for configured in &route.allowed_request_headers {
        let name = HeaderName::from_bytes(configured.as_bytes())?;
        if let Some(value) = inbound.get(&name) {
            outbound.insert(name, value.clone());
        }
    }
    outbound.remove(prepared.injection_name());
    outbound.insert(
        prepared.injection_name().clone(),
        prepared.injection_value().clone(),
    );
    Ok(outbound)
}

/// Combine a fixed route origin with one validated path and query.
pub fn build_target_url(route: &ProxyRouteConfig, request: &ValidatedProxyRequest) -> Result<Url> {
    let mut target = Url::parse(&route.base_url).context("proxy route base URL disappeared")?;
    if !matches!(target.scheme(), "https" | "http")
        || target.host_str().is_none()
        || has_url_credentials(&target)
        || target.query().is_some()
        || target.fragment().is_some()
    {
        bail!("proxy route base URL is unsafe");
    }
    let target_path = format!(
        "{}{}",
        target.path().trim_end_matches('/'),
        request.normalized_path()
    );
    target.set_path(&target_path);
    target.set_query(None);
    if !request.query().is_empty() {
        target.query_pairs_mut().extend_pairs(request.query());
    }
    Ok(target)
}

/// Detect whether headers attempt any WebSocket upgrade shape.
pub fn is_websocket_attempt(headers: &HeaderMap) -> bool {
    [
        header::UPGRADE,
        header::SEC_WEBSOCKET_KEY,
        header::SEC_WEBSOCKET_VERSION,
        header::SEC_WEBSOCKET_PROTOCOL,
        header::SEC_WEBSOCKET_EXTENSIONS,
    ]
    .iter()
    .any(|name| headers.contains_key(name))
        || header_contains_token(headers, header::CONNECTION, "upgrade")
}

/// Validate a caller WebSocket handshake against exact route policy.
pub fn validate_websocket_handshake(
    headers: &HeaderMap,
    policy: &ProxyWebSocketConfig,
) -> Result<()> {
    if !header_contains_token(headers, header::CONNECTION, "upgrade")
        || !single_header_equals(headers, header::UPGRADE, "websocket")
        || !single_header_equals(headers, header::SEC_WEBSOCKET_VERSION, "13")
        || headers.contains_key(header::SEC_WEBSOCKET_EXTENSIONS)
    {
        bail!("WebSocket upgrade headers are invalid or extensions were requested");
    }
    let key = single_header_text(headers, header::SEC_WEBSOCKET_KEY)?;
    if !matches!(STANDARD.decode(key.as_bytes()), Ok(decoded) if decoded.len() == 16) {
        bail!("WebSocket key is invalid");
    }
    match single_optional_header_text(headers, header::ORIGIN)? {
        Some(origin) => {
            if !policy
                .allowed_origins
                .iter()
                .any(|allowed| allowed == origin)
            {
                bail!("WebSocket Origin is not allowed");
            }
        }
        None if !policy.allow_missing_origin => bail!("WebSocket Origin is required"),
        None => {}
    }
    let requested = websocket_subprotocols(headers)?;
    if requested.iter().any(|protocol| {
        !policy
            .allowed_subprotocols
            .iter()
            .any(|allowed| allowed == protocol)
    }) {
        bail!("WebSocket subprotocol is not allowed");
    }
    Ok(())
}

/// Parse one exact, duplicate-free WebSocket subprotocol list.
pub fn websocket_subprotocols(headers: &HeaderMap) -> Result<Vec<String>> {
    let Some(value) = single_optional_header_text(headers, header::SEC_WEBSOCKET_PROTOCOL)? else {
        return Ok(Vec::new());
    };
    let mut unique = BTreeSet::new();
    let mut protocols = Vec::new();
    for protocol in value.split(',').map(str::trim) {
        if !valid_http_token(protocol) || !unique.insert(protocol.to_owned()) {
            bail!("WebSocket subprotocol list is invalid");
        }
        protocols.push(protocol.to_owned());
    }
    Ok(protocols)
}

fn build_proxy_injection(
    route: &ProxyRouteConfig,
    credentials: &(impl CredentialSource + ?Sized),
) -> Result<(HeaderName, HeaderValue, Vec<Vec<u8>>)> {
    let (name, value, mut sensitive_values) = match &route.injection {
        None => {
            let secret = credentials
                .credential(&route.secret_key)
                .context("proxy credential is unavailable")?;
            (
                route.header.as_str(),
                format!("{}{}", route.header_prefix, secret),
                vec![secret.as_bytes().to_vec()],
            )
        }
        Some(ProxyInjectionConfig::Bearer { secret_key }) => {
            let secret = credentials
                .credential(secret_key)
                .context("proxy bearer credential is unavailable")?;
            (
                "authorization",
                format!("Bearer {secret}"),
                vec![secret.as_bytes().to_vec()],
            )
        }
        Some(ProxyInjectionConfig::Header {
            secret_key,
            header,
            prefix,
        }) => {
            let secret = credentials
                .credential(secret_key)
                .context("proxy header credential is unavailable")?;
            (
                header.as_str(),
                format!("{prefix}{secret}"),
                vec![secret.as_bytes().to_vec()],
            )
        }
        Some(ProxyInjectionConfig::Basic {
            username,
            password_secret_key,
        }) => {
            if username.is_empty()
                || username.len() > 256
                || username.contains(':')
                || username.chars().any(char::is_control)
            {
                bail!("proxy basic username is invalid");
            }
            let password = credentials
                .credential(password_secret_key)
                .context("proxy basic password is unavailable")?;
            let mut pair = format!("{username}:{password}");
            let value = format!("Basic {}", STANDARD.encode(pair.as_bytes()));
            let sensitive = vec![password.as_bytes().to_vec(), pair.as_bytes().to_vec()];
            pair.zeroize();
            ("authorization", value, sensitive)
        }
    };
    if !name.eq_ignore_ascii_case("authorization") && !name.to_ascii_lowercase().starts_with("x-") {
        bail!("proxy may inject Authorization or an X-* header only");
    }
    sensitive_values.push(value.as_bytes().to_vec());
    let name = HeaderName::from_bytes(name.as_bytes())?;
    let mut value = HeaderValue::from_str(&value)?;
    value.set_sensitive(true);
    Ok((name, value, sensitive_values))
}

fn apply_body_substitutions(
    route: &ProxyRouteConfig,
    credentials: &(impl CredentialSource + ?Sized),
    body: &[u8],
) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
    if route.body_substitutions.len() > 16 {
        bail!("proxy route may define at most 16 body substitutions");
    }
    let mut output = body.to_vec();
    let mut sensitive_values = Vec::with_capacity(route.body_substitutions.len());
    for (placeholder, secret_key) in &route.body_substitutions {
        if !valid_body_placeholder(placeholder) {
            bail!("proxy route contains an invalid body placeholder");
        }
        let secret = credentials
            .credential(secret_key)
            .with_context(|| format!("body substitution secret {secret_key} is unavailable"))?;
        let occurrences = output
            .windows(placeholder.len())
            .filter(|window| *window == placeholder.as_bytes())
            .count();
        if occurrences != 1 {
            bail!("body placeholder must appear exactly once");
        }
        let position = output
            .windows(placeholder.len())
            .position(|window| window == placeholder.as_bytes())
            .context("body placeholder disappeared")?;
        let resulting_length = output
            .len()
            .saturating_sub(placeholder.len())
            .saturating_add(secret.len());
        if resulting_length > route.max_body_bytes {
            bail!("substituted request body is too large");
        }
        output.splice(
            position..position + placeholder.len(),
            secret.as_bytes().iter().copied(),
        );
        sensitive_values.push(secret.as_bytes().to_vec());
    }
    Ok((output, sensitive_values))
}

fn enforce_proxy_content_type(
    route: &ProxyRouteConfig,
    headers: &HeaderMap,
    body_len: usize,
) -> Result<()> {
    if body_len == 0 {
        return Ok(());
    }
    let values = headers
        .get_all(header::CONTENT_TYPE)
        .iter()
        .collect::<Vec<_>>();
    if values.len() != 1 {
        bail!("request body requires exactly one Content-Type");
    }
    let content_type = values[0]
        .to_str()
        .ok()
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .context("request body requires a valid Content-Type")?;
    if !route
        .allowed_content_types
        .iter()
        .any(|allowed| allowed == &content_type)
    {
        bail!("request Content-Type is not allowed");
    }
    Ok(())
}

fn validate_proxy_query(
    route: &ProxyRouteConfig,
    query: Option<&str>,
) -> Result<Vec<(String, String)>> {
    let Some(query) = query.filter(|query| !query.is_empty()) else {
        return Ok(Vec::new());
    };
    validate_percent_encoding(query)?;
    let mut names = BTreeSet::new();
    let mut validated = Vec::new();
    for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if name.chars().any(char::is_control) || value.chars().any(char::is_control) {
            bail!("query contains control characters");
        }
        if !route
            .allowed_query_parameters
            .iter()
            .any(|allowed| allowed == name.as_ref())
        {
            bail!("query parameter is not allowed");
        }
        if !names.insert(name.to_string()) {
            bail!("duplicate query parameters are not allowed");
        }
        validated.push((name.into_owned(), value.into_owned()));
    }
    Ok(validated)
}

fn path_matches_prefix(path: &str, configured_prefix: &str) -> bool {
    let normalized_prefix = format!("/{}", configured_prefix.trim_matches('/'));
    if normalized_prefix == "/" {
        return true;
    }
    path == normalized_prefix
        || path
            .strip_prefix(&normalized_prefix)
            .is_some_and(|remainder| remainder.starts_with('/'))
}

fn safe_policy_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains(['?', '#', '\\', '%'])
        && !path.contains("//")
        && !path.chars().any(char::is_control)
        && !path.split('/').any(|segment| matches!(segment, "." | ".."))
}

fn reject_mixed_legacy_injection(name: &str, route: &ProxyRouteConfig) -> Result<()> {
    if !route.secret_key.is_empty() || !route.header.is_empty() || !route.header_prefix.is_empty() {
        bail!("proxy route {name} may not mix typed and legacy injection fields");
    }
    Ok(())
}

fn validate_policy_name(kind: &str, name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        bail!("{kind} name {name:?} must use lowercase letters, digits, and hyphens");
    }
    Ok(())
}

fn validate_binding(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        bail!("binding must contain 1-256 non-control characters");
    }
    Ok(())
}

fn validate_credential_key(value: &str) -> Result<()> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        bail!("credential key is empty");
    };
    if !(first == b'_' || first.is_ascii_alphabetic())
        || !bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
    {
        bail!("credential key must match [A-Za-z_][A-Za-z0-9_]*");
    }
    Ok(())
}

fn validate_proxy_header_allowlist(
    route_name: &str,
    direction: &str,
    headers: &[String],
    injection_header: Option<&str>,
) -> Result<()> {
    const FORBIDDEN: &[&str] = &[
        "authorization",
        "connection",
        "content-length",
        "cookie",
        "forwarded",
        "host",
        "location",
        "proxy-authenticate",
        "proxy-authorization",
        "set-cookie",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "user-agent",
        "www-authenticate",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-port",
        "x-forwarded-proto",
        "x-http-method-override",
        "x-method-override",
        "x-original-url",
        "x-real-ip",
        "x-rewrite-url",
    ];
    let mut unique = BTreeSet::new();
    for configured in headers {
        let lower = configured.to_ascii_lowercase();
        if configured != &lower
            || HeaderName::from_bytes(configured.as_bytes()).is_err()
            || FORBIDDEN.contains(&lower.as_str())
            || injection_header.is_some_and(|header| header.eq_ignore_ascii_case(configured))
        {
            bail!("proxy route {route_name} contains unsafe {direction} header {configured:?}");
        }
        if !unique.insert(lower) {
            bail!("proxy route {route_name} repeats {direction} header {configured:?}");
        }
    }
    Ok(())
}

fn validate_string_allowlist(
    route_name: &str,
    kind: &str,
    values: &[String],
    valid: impl Fn(&str) -> bool,
) -> Result<()> {
    let mut unique = BTreeSet::new();
    for value in values {
        if !valid(value) {
            bail!("proxy route {route_name} contains invalid {kind} {value:?}");
        }
        if !unique.insert(value) {
            bail!("proxy route {route_name} repeats {kind} {value:?}");
        }
    }
    Ok(())
}

fn validate_websocket_origin(value: &str) -> Result<()> {
    let origin = Url::parse(value).context("origin must be a URL")?;
    if !matches!(origin.scheme(), "https" | "http")
        || origin.host_str().is_none()
        || has_url_credentials(&origin)
        || origin.query().is_some()
        || origin.fragment().is_some()
        || !matches!(origin.path(), "" | "/")
    {
        bail!("origin must be an exact HTTP(S) origin");
    }
    Ok(())
}

fn valid_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn validate_percent_encoding(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                bail!("query contains invalid percent encoding");
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn valid_body_placeholder(value: &str) -> bool {
    let Some(name) = value
        .strip_prefix("__AV_SECRET_")
        .and_then(|value| value.strip_suffix("__"))
    else {
        return false;
    };
    !name.is_empty()
        && value.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn has_url_credentials(url: &Url) -> bool {
    !url.username().is_empty() || url.password().is_some()
}

fn header_contains_token(headers: &HeaderMap, name: HeaderName, expected: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case(expected))
        })
    })
}

fn single_header_equals(headers: &HeaderMap, name: HeaderName, expected: &str) -> bool {
    single_header_text(headers, name).is_ok_and(|value| value.eq_ignore_ascii_case(expected))
}

fn single_header_text(headers: &HeaderMap, name: HeaderName) -> Result<&str> {
    let values = headers.get_all(name).iter().collect::<Vec<_>>();
    if values.len() != 1 {
        bail!("WebSocket header must occur exactly once");
    }
    values[0]
        .to_str()
        .context("WebSocket header is not valid text")
}

fn single_optional_header_text(headers: &HeaderMap, name: HeaderName) -> Result<Option<&str>> {
    let values = headers.get_all(name).iter().collect::<Vec<_>>();
    match values.as_slice() {
        [] => Ok(None),
        [value] => Ok(Some(
            value
                .to_str()
                .context("WebSocket header is not valid text")?,
        )),
        _ => bail!("WebSocket header may occur at most once"),
    }
}

fn default_allowed_request_headers() -> Vec<String> {
    ["accept", "content-type", "if-match", "if-none-match"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn default_allowed_response_headers() -> Vec<String> {
    ["content-type", "etag", "last-modified", "retry-after"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn default_proxy_max_body_bytes() -> usize {
    1024 * 1024
}

fn default_proxy_max_response_bytes() -> usize {
    4 * 1024 * 1024
}

fn default_websocket_max_duration_seconds() -> u64 {
    5 * 60
}

fn default_websocket_max_message_bytes() -> usize {
    1024 * 1024
}

fn default_websocket_max_total_bytes() -> u64 {
    64 * 1024 * 1024
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(methods: &[&str], prefixes: &[&str]) -> ProxyRouteConfig {
        ProxyRouteConfig {
            profile: "example".into(),
            base_url: "https://api.example.test/v1".into(),
            secret_key: String::new(),
            header: String::new(),
            header_prefix: String::new(),
            injection: Some(ProxyInjectionConfig::Bearer {
                secret_key: "API_TOKEN".into(),
            }),
            body_substitutions: BTreeMap::new(),
            allowed_methods: methods.iter().map(|value| (*value).into()).collect(),
            allowed_exact_paths: Vec::new(),
            allowed_path_prefixes: prefixes.iter().map(|value| (*value).into()).collect(),
            allowed_request_headers: vec!["content-type".into()],
            allowed_response_headers: vec!["content-type".into()],
            allowed_query_parameters: vec!["source".into()],
            allowed_content_types: vec!["application/json".into()],
            max_body_bytes: 1024,
            response_mode: ProxyResponseMode::Buffered,
            max_response_bytes: 4096,
            websocket: None,
        }
    }

    #[test]
    fn route_validation_rejects_unsafe_policy() {
        let route = route(&["GET"], &["/zones"]);
        validate_proxy_route("provider", &route, false, false).unwrap();

        let mut unsafe_route = route.clone();
        unsafe_route.allowed_path_prefixes = vec!["/zones/%2e%2e".into()];
        assert!(validate_proxy_route("provider", &unsafe_route, false, false).is_err());
        unsafe_route = route.clone();
        unsafe_route.allowed_request_headers = vec!["authorization".into()];
        assert!(validate_proxy_route("provider", &unsafe_route, false, false).is_err());
    }

    #[test]
    fn request_validation_enforces_method_path_query_and_content_type() {
        let route = route(&["GET", "POST"], &["/zones"]);
        let headers = HeaderMap::from_iter([(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        )]);
        let validated = validate_proxy_request(
            &route,
            "/zones/123",
            Some("source=integration"),
            &Method::POST,
            &headers,
            2,
        )
        .unwrap();
        assert_eq!(validated.normalized_path(), "/zones/123");
        assert_eq!(validated.query(), [("source".into(), "integration".into())]);

        assert!(
            validate_proxy_request(
                &route,
                "/zones/../admin",
                None,
                &Method::GET,
                &HeaderMap::new(),
                0
            )
            .is_err()
        );

        let mut duplicate_content_type = headers;
        duplicate_content_type.append(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        assert!(
            validate_proxy_request(
                &route,
                "/zones/123",
                None,
                &Method::POST,
                &duplicate_content_type,
                2,
            )
            .is_err()
        );
        assert!(
            validate_proxy_request(
                &route,
                "/zones/123",
                Some("other=value"),
                &Method::GET,
                &HeaderMap::new(),
                0
            )
            .is_err()
        );
    }

    #[test]
    fn typed_injection_and_body_substitution_are_redacted() {
        let credentials = BTreeMap::from([("API_TOKEN".into(), "secret+value".into())]);
        let mut route = route(&["POST"], &["/"]);
        route.injection = Some(ProxyInjectionConfig::Basic {
            username: "service-user".into(),
            password_secret_key: "API_TOKEN".into(),
        });
        route
            .body_substitutions
            .insert("__AV_SECRET_TOKEN__".into(), "API_TOKEN".into());
        let prepared =
            prepare_credentials(&route, &credentials, br#"{"token":"__AV_SECRET_TOKEN__"}"#)
                .unwrap();
        assert_eq!(prepared.injection_name(), header::AUTHORIZATION);
        assert_eq!(
            prepared.injection_value(),
            HeaderValue::from_static("Basic c2VydmljZS11c2VyOnNlY3JldCt2YWx1ZQ==")
        );
        assert_eq!(prepared.body(), br#"{"token":"secret+value"}"#);
        let (body, redaction) = prepared.into_body_and_redaction();
        assert_eq!(redaction.redact_bytes(&body), br#"{"token":"[REDACTED]"}"#);
    }

    #[test]
    fn transparent_target_rejects_host_smuggling() {
        let route = route(&["GET"], &["/"]);
        let uri = "/v1/models".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "api.example.test".parse().unwrap());
        enforce_transparent_tunnel_target(&route, &uri, &headers).unwrap();
        headers.insert(header::HOST, "attacker.example.test".parse().unwrap());
        assert!(enforce_transparent_tunnel_target(&route, &uri, &headers).is_err());

        headers.insert(header::HOST, "api.example.test/hidden".parse().unwrap());
        assert!(enforce_transparent_tunnel_target(&route, &uri, &headers).is_err());
    }

    #[test]
    fn request_construction_rechecks_critical_route_invariants() {
        let credentials = BTreeMap::from([("API_TOKEN".into(), "secret-value".into())]);
        let route = route(&["GET"], &["/zones"]);
        let validated = validate_proxy_request(
            &route,
            "/zones/123",
            None,
            &Method::GET,
            &HeaderMap::new(),
            0,
        )
        .unwrap();

        let mut unsafe_base = route.clone();
        unsafe_base.base_url = "https://user:password@api.example.test".into();
        assert!(build_target_url(&unsafe_base, &validated).is_err());

        let mut unsafe_header = route.clone();
        unsafe_header.injection = Some(ProxyInjectionConfig::Header {
            secret_key: "API_TOKEN".into(),
            header: "cookie".into(),
            prefix: String::new(),
        });
        assert!(prepare_credentials(&unsafe_header, &credentials, b"").is_err());

        let mut unsafe_allowlist = route.clone();
        unsafe_allowlist.allowed_request_headers = vec!["host".into()];
        let prepared = prepare_credentials(&unsafe_allowlist, &credentials, b"").unwrap();
        assert!(prepare_outbound_headers(&unsafe_allowlist, &HeaderMap::new(), &prepared).is_err());

        let mut empty_placeholder = route;
        empty_placeholder
            .body_substitutions
            .insert(String::new(), "API_TOKEN".into());
        assert!(prepare_credentials(&empty_placeholder, &credentials, b"").is_err());
    }

    #[test]
    fn websocket_policy_and_credentials_are_explicit_and_bodyless() {
        let policy = ProxyWebSocketConfig {
            allowed_origins: vec!["https://app.example.test".into()],
            allow_missing_origin: false,
            allowed_subprotocols: vec!["events.v1".into()],
            max_duration_seconds: 60,
            max_message_bytes: 1024,
            max_total_bytes: 4096,
        };
        let mut headers = HeaderMap::from_iter([
            (header::CONNECTION, HeaderValue::from_static("Upgrade")),
            (header::UPGRADE, HeaderValue::from_static("websocket")),
            (
                header::SEC_WEBSOCKET_VERSION,
                HeaderValue::from_static("13"),
            ),
            (
                header::SEC_WEBSOCKET_KEY,
                HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
            ),
            (
                header::SEC_WEBSOCKET_PROTOCOL,
                HeaderValue::from_static("events.v1"),
            ),
            (
                header::ORIGIN,
                HeaderValue::from_static("https://app.example.test"),
            ),
        ]);
        validate_websocket_handshake(&headers, &policy).unwrap();
        headers.insert(
            header::SEC_WEBSOCKET_EXTENSIONS,
            HeaderValue::from_static("permessage-deflate"),
        );
        assert!(validate_websocket_handshake(&headers, &policy).is_err());

        let credentials = BTreeMap::from([("API_TOKEN".into(), "secret-value".into())]);
        let mut route = route(&["GET"], &["/events"]);
        route
            .body_substitutions
            .insert("__AV_SECRET_TOKEN__".into(), "API_TOKEN".into());
        let prepared = prepare_websocket_credentials(&route, &credentials).unwrap();
        assert!(prepared.body().is_empty());
        let reflected = prepared.injection_value().clone();
        let (_, redaction) = prepared.into_body_and_redaction();
        assert_eq!(redaction.redact_bytes(reflected.as_bytes()), b"[REDACTED]");
    }
}
