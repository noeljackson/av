use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{any, get},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use serde::Serialize;
use tokio::sync::Semaphore;
use tower_http::{
    services::{ServeDir, ServeFile},
    set_header::SetResponseHeaderLayer,
    trace::TraceLayer,
};

use crate::{
    auth::Authenticator,
    config::{AuthMode, Config, ProfileConfig, ProxyRouteConfig},
    connector::Connector,
};

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    auth: Authenticator,
    connectors: Arc<BTreeMap<String, Connector>>,
    connector_slots: Arc<Semaphore>,
    proxy_client: reqwest::Client,
}

#[derive(Serialize)]
struct ProfileSummary<'a> {
    name: &'a str,
    environment: &'a str,
    path: &'a str,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicStatus {
    oidc_enabled: bool,
    basic_enabled: bool,
    persistence_enabled: bool,
    registration_enabled: bool,
    connectors: Vec<PublicConnector>,
    profile_count: usize,
    proxy_routes: Vec<String>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct PublicConnector {
    name: String,
    kind: String,
}

pub async fn run(config: Config) -> Result<()> {
    let auth = Authenticator::new(config.auth.clone()).await?;
    let content_security_policy = content_security_policy(&config)?;
    let mut connectors = BTreeMap::new();
    let allow_insecure_http = config.allow_insecure_connector_http();
    for (name, connector) in &config.connectors {
        connectors.insert(
            name.clone(),
            Connector::new(connector.clone(), allow_insecure_http)?,
        );
    }
    let proxy_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("av-proxy/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let state = AppState {
        config: Arc::new(config.clone()),
        auth,
        connectors: Arc::new(connectors),
        connector_slots: Arc::new(Semaphore::new(config.max_connector_concurrency)),
        proxy_client,
    };
    let ui_dir = PathBuf::from(&config.ui_dir);
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(health))
        .route("/v1/auth/config", get(auth_config))
        .route("/v1/status", get(status))
        .route("/v1/profiles", get(profiles))
        .route("/v1/profiles/{profile}/secrets", get(profile_secrets))
        .route("/v1/proxy/{route}/{*path}", any(proxy))
        .route("/v1/{*path}", any(api_not_found))
        .fallback_service(
            ServeDir::new(&ui_dir).not_found_service(ServeFile::new(ui_dir.join("index.html"))),
        )
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("content-security-policy"),
            content_security_policy,
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("listen on {}", config.listen))?;
    tracing::info!(listen = %config.listen, "av is ready");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

fn content_security_policy(config: &Config) -> Result<HeaderValue> {
    let mut connect_src = "'self'".to_owned();
    if matches!(config.auth.mode, AuthMode::Oidc | AuthMode::OidcOrBasic) {
        let issuer = url::Url::parse(&config.auth.issuer).context("parse OIDC issuer for CSP")?;
        connect_src.push(' ');
        connect_src.push_str(issuer.origin().ascii_serialization().as_str());
    }
    HeaderValue::from_str(&format!(
        "default-src 'self'; connect-src {connect_src}; script-src 'self'; style-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    ))
    .context("build Content-Security-Policy")
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

async fn api_not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "api endpoint not found\n")
}

async fn auth_config(State(state): State<AppState>) -> impl IntoResponse {
    no_store(axum::Json(state.auth.public_config()).into_response())
}

async fn status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(error) = state.auth.authorize(&headers).await {
        return unauthorized(error);
    }
    no_store(axum::Json(public_status(&state.config)).into_response())
}

fn public_status(config: &Config) -> PublicStatus {
    PublicStatus {
        oidc_enabled: matches!(config.auth.mode, AuthMode::Oidc | AuthMode::OidcOrBasic),
        basic_enabled: matches!(config.auth.mode, AuthMode::Basic | AuthMode::OidcOrBasic),
        persistence_enabled: false,
        registration_enabled: false,
        connectors: config
            .connectors
            .iter()
            .map(|(name, connector)| PublicConnector {
                name: name.clone(),
                kind: connector.kind().into(),
            })
            .collect(),
        profile_count: config.profiles.len(),
        proxy_routes: config.proxy_routes.keys().cloned().collect(),
    }
}

async fn profiles(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(error) = state.auth.authorize(&headers).await {
        return unauthorized(error);
    }
    let profiles: Vec<_> = state
        .config
        .profiles
        .iter()
        .map(|(name, profile)| ProfileSummary {
            name,
            environment: &profile.environment,
            path: &profile.secret_path,
        })
        .collect();
    no_store(axum::Json(profiles).into_response())
}

async fn profile_secrets(
    State(state): State<AppState>,
    Path(profile): Path<String>,
    headers: HeaderMap,
) -> Response {
    let identity = match state.auth.authorize(&headers).await {
        Ok(identity) => identity,
        Err(error) => return unauthorized(error),
    };
    let Some(profile_config) = state.config.profiles.get(&profile) else {
        return (StatusCode::NOT_FOUND, "profile not found\n").into_response();
    };
    match fetch_secrets(&state, profile_config).await {
        Ok(secrets) => {
            tracing::info!(subject = %identity.subject, profile, key_count = secrets.len(), "profile leased");
            no_store(axum::Json(secrets).into_response())
        }
        Err(error) => internal_error(error),
    }
}

async fn proxy(
    State(state): State<AppState>,
    Path((route_name, path)): Path<(String, String)>,
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let identity = match state.auth.authorize(&headers).await {
        Ok(identity) => identity,
        Err(error) => return unauthorized(error),
    };
    let Some(route) = state.config.proxy_routes.get(&route_name) else {
        return (StatusCode::NOT_FOUND, "proxy route not found\n").into_response();
    };
    if !is_trusted_browser_origin(&headers, &state.config.public_url) {
        tracing::warn!(subject = %identity.subject, route = route_name, "proxy request rejected for untrusted browser origin");
        return (StatusCode::FORBIDDEN, "proxy request forbidden\n").into_response();
    }
    let normalized_path = match enforce_proxy_policy(route, &path, &method) {
        Ok(path) => path,
        Err(error) => {
            tracing::warn!(subject = %identity.subject, route = route_name, path, error = %error, "proxy request forbidden by route policy");
            return (StatusCode::FORBIDDEN, "proxy request forbidden\n").into_response();
        }
    };
    if body.len() > route.max_body_bytes {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            "proxy request is too large\n",
        )
            .into_response();
    }
    if let Err(error) = enforce_proxy_content_type(route, &headers, body.len()) {
        tracing::warn!(subject = %identity.subject, route = route_name, error = %error, "proxy request content type rejected by route policy");
        return (StatusCode::FORBIDDEN, "proxy request forbidden\n").into_response();
    }
    let query = match validate_proxy_query(route, uri.query()) {
        Ok(query) => query,
        Err(error) => {
            tracing::warn!(subject = %identity.subject, route = route_name, error = %error, "proxy request query rejected by route policy");
            return (StatusCode::FORBIDDEN, "proxy request forbidden\n").into_response();
        }
    };
    match proxy_request(
        &state,
        route,
        &normalized_path,
        &query,
        method,
        headers,
        body,
    )
    .await
    {
        Ok(response) => {
            tracing::info!(subject = %identity.subject, route = route_name, path, status = response.status().as_u16(), "proxy request");
            no_store(response)
        }
        Err(error) => {
            tracing::warn!(subject = %identity.subject, route = route_name, path, error = %error, "proxy request denied or failed");
            (StatusCode::BAD_GATEWAY, "proxy request failed\n").into_response()
        }
    }
}

async fn proxy_request(
    state: &AppState,
    route: &ProxyRouteConfig,
    normalized_path: &str,
    query: &[(String, String)],
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let profile = state
        .config
        .profiles
        .get(&route.profile)
        .context("proxy profile disappeared")?;
    let secrets = fetch_secrets(state, profile).await?;
    let secret = secrets
        .get(&route.secret_key)
        .context("proxy credential is unavailable")?;
    let mut target =
        url::Url::parse(&route.base_url).context("proxy route base URL disappeared")?;
    let target_path = format!("{}{}", target.path().trim_end_matches('/'), normalized_path);
    target.set_path(&target_path);
    target.set_query(None);
    if !query.is_empty() {
        target.query_pairs_mut().extend_pairs(query);
    }
    let mut outbound_headers = HeaderMap::new();
    for configured in &route.allowed_request_headers {
        let name = HeaderName::from_bytes(configured.as_bytes())?;
        if let Some(value) = headers.get(&name) {
            outbound_headers.insert(name, value.clone());
        }
    }
    let injection_name = HeaderName::from_bytes(route.header.as_bytes())?;
    outbound_headers.remove(&injection_name);
    let mut injection_value = HeaderValue::from_str(&format!("{}{}", route.header_prefix, secret))?;
    injection_value.set_sensitive(true);
    outbound_headers.insert(injection_name, injection_value);
    let mut upstream = state
        .proxy_client
        .request(method, target)
        .headers(outbound_headers)
        .body(body)
        .send()
        .await?;
    let status = upstream.status();
    if upstream
        .content_length()
        .is_some_and(|length| length > 4 * 1024 * 1024)
    {
        bail!("upstream response is too large");
    }
    let upstream_headers = upstream.headers().clone();
    let mut bytes = Vec::new();
    while let Some(chunk) = upstream.chunk().await? {
        if bytes.len().saturating_add(chunk.len()) > 4 * 1024 * 1024 {
            bail!("upstream response is too large");
        }
        bytes.extend_from_slice(&chunk);
    }
    let bytes = redact(&bytes, secret.as_bytes());
    let mut response = Response::builder().status(status);
    for configured in &route.allowed_response_headers {
        let name = HeaderName::from_bytes(configured.as_bytes())?;
        if let Some(value) = upstream_headers.get(&name)
            && let Some(value) = redact_header(value, secret.as_bytes())
        {
            response = response.header(name, value);
        }
    }
    Ok(response.body(axum::body::Body::from(bytes))?)
}

fn enforce_proxy_policy(route: &ProxyRouteConfig, path: &str, method: &Method) -> Result<String> {
    if !route
        .allowed_methods
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(method.as_str()))
    {
        bail!("method is not allowed");
    }

    let normalized_path = format!("/{}", path.trim_start_matches('/'));
    if normalized_path.contains('\\')
        || normalized_path.contains('%')
        || normalized_path.contains("//")
        || normalized_path.chars().any(char::is_control)
        || normalized_path
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
    {
        bail!("path contains a traversal sequence");
    }

    if !route
        .allowed_path_prefixes
        .iter()
        .any(|prefix| path_matches_prefix(&normalized_path, prefix))
    {
        bail!("path is not allowed");
    }
    Ok(normalized_path)
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

fn is_trusted_browser_origin(headers: &HeaderMap, public_url: &str) -> bool {
    let origin_allowed = headers
        .get(header::ORIGIN)
        .and_then(|origin| origin.to_str().ok())
        .is_none_or(|origin| origin == public_url);
    let fetch_site_allowed = headers
        .get(HeaderName::from_static("sec-fetch-site"))
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| matches!(value, "same-origin" | "none"));
    origin_allowed && fetch_site_allowed
}

async fn fetch_secrets(
    state: &AppState,
    profile: &ProfileConfig,
) -> Result<BTreeMap<String, String>> {
    let _permit = tokio::time::timeout(Duration::from_secs(5), state.connector_slots.acquire())
        .await
        .context("connector concurrency queue timed out")?
        .context("connector concurrency limiter is closed")?;
    state
        .connectors
        .get(&profile.connector)
        .context("profile connector disappeared")?
        .secrets(profile)
        .await
}

fn enforce_proxy_content_type(
    route: &ProxyRouteConfig,
    headers: &HeaderMap,
    body_len: usize,
) -> Result<()> {
    if body_len == 0 {
        return Ok(());
    }
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
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

fn redact(body: &[u8], secret: &[u8]) -> Vec<u8> {
    let mut output = body.to_vec();
    for encoding in credential_encodings(secret) {
        output = redact_exact(&output, &encoding);
    }
    output
}

fn redact_exact(body: &[u8], secret: &[u8]) -> Vec<u8> {
    if secret.is_empty() || body.len() < secret.len() {
        return body.to_vec();
    }
    let mut output = Vec::with_capacity(body.len());
    let mut offset = 0;
    while let Some(position) = body[offset..]
        .windows(secret.len())
        .position(|window| window == secret)
    {
        let absolute = offset + position;
        output.extend_from_slice(&body[offset..absolute]);
        output.extend_from_slice(b"[REDACTED]");
        offset = absolute + secret.len();
    }
    output.extend_from_slice(&body[offset..]);
    output
}

fn credential_encodings(secret: &[u8]) -> Vec<Vec<u8>> {
    let percent_encoded = url::form_urlencoded::byte_serialize(secret).collect::<String>();
    let mut encodings = vec![
        secret.to_vec(),
        STANDARD.encode(secret).into_bytes(),
        STANDARD_NO_PAD.encode(secret).into_bytes(),
        URL_SAFE.encode(secret).into_bytes(),
        URL_SAFE_NO_PAD.encode(secret).into_bytes(),
        percent_encoded.as_bytes().to_vec(),
        lowercase_percent_hex(&percent_encoded).into_bytes(),
    ];
    if let Ok(secret) = std::str::from_utf8(secret)
        && let Ok(json) = serde_json::to_string(secret)
    {
        encodings.push(json.as_bytes()[1..json.len() - 1].to_vec());
    }
    encodings.sort_by_key(|value| std::cmp::Reverse(value.len()));
    encodings.dedup();
    encodings
}

fn lowercase_percent_hex(value: &str) -> String {
    let mut bytes = value.as_bytes().to_vec();
    let mut index = 0;
    while index + 2 < bytes.len() {
        if bytes[index] == b'%' {
            bytes[index + 1].make_ascii_lowercase();
            bytes[index + 2].make_ascii_lowercase();
            index += 3;
        } else {
            index += 1;
        }
    }
    String::from_utf8(bytes).expect("percent encoding is ASCII")
}

fn redact_header(value: &HeaderValue, secret: &[u8]) -> Option<HeaderValue> {
    let redacted = redact(value.as_bytes(), secret);
    HeaderValue::from_bytes(&redacted).ok()
}

fn unauthorized(error: anyhow::Error) -> Response {
    tracing::warn!(error = %error, "authentication rejected");
    let mut response = (StatusCode::UNAUTHORIZED, "authentication required\n").into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer, Basic realm=\"av\""),
    );
    no_store(response)
}

fn internal_error(error: anyhow::Error) -> Response {
    tracing::error!(error = %error, "connector request failed");
    no_store((StatusCode::BAD_GATEWAY, "connector request failed\n").into_response())
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

async fn shutdown() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl-C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install terminate handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy_route(methods: &[&str], prefixes: &[&str]) -> ProxyRouteConfig {
        ProxyRouteConfig {
            profile: "infra".into(),
            base_url: "https://api.example.com".into(),
            secret_key: "API_TOKEN".into(),
            header: "Authorization".into(),
            header_prefix: "Bearer ".into(),
            allowed_methods: methods.iter().map(|value| (*value).into()).collect(),
            allowed_path_prefixes: prefixes.iter().map(|value| (*value).into()).collect(),
            allowed_request_headers: vec!["accept".into(), "content-type".into()],
            allowed_response_headers: vec!["content-type".into()],
            allowed_query_parameters: vec!["source".into()],
            allowed_content_types: vec!["application/json".into()],
            max_body_bytes: 1024,
        }
    }

    #[test]
    fn proxy_policy_enforces_crud_methods_before_connector_access() {
        let full_crud = proxy_route(&["GET", "POST", "PUT", "PATCH", "DELETE"], &["/zones"]);
        for method in [
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ] {
            assert!(enforce_proxy_policy(&full_crud, "zones/123", &method).is_ok());
        }
        for method in [Method::OPTIONS, Method::TRACE, Method::CONNECT] {
            assert!(enforce_proxy_policy(&full_crud, "zones/123", &method).is_err());
        }

        let read_only = proxy_route(&["GET"], &["/zones"]);
        assert!(enforce_proxy_policy(&read_only, "zones/123", &Method::GET).is_ok());
        assert!(enforce_proxy_policy(&read_only, "zones/123", &Method::POST).is_err());
        assert!(enforce_proxy_policy(&read_only, "zones/123", &Method::DELETE).is_err());
    }

    #[test]
    fn proxy_policy_uses_path_boundaries_and_rejects_traversal_encodings() {
        let route = proxy_route(&["GET"], &["/zones/"]);
        assert_eq!(
            enforce_proxy_policy(&route, "zones/123/records", &Method::GET).unwrap(),
            "/zones/123/records"
        );
        assert!(enforce_proxy_policy(&route, "zones-evil/123", &Method::GET).is_err());
        assert!(enforce_proxy_policy(&route, "zones/../admin", &Method::GET).is_err());
        assert!(enforce_proxy_policy(&route, "zones/%2e%2e/admin", &Method::GET).is_err());
        assert!(enforce_proxy_policy(&route, "zones/%2Fadmin", &Method::GET).is_err());
        assert!(enforce_proxy_policy(&route, "zones\\admin", &Method::GET).is_err());
        assert!(enforce_proxy_policy(&route, "zones/file..name", &Method::GET).is_ok());
    }

    #[test]
    fn proxy_rejects_cross_origin_browser_requests() {
        let mut headers = HeaderMap::new();
        assert!(is_trusted_browser_origin(
            &headers,
            "https://av.example.com"
        ));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://av.example.com"),
        );
        assert!(is_trusted_browser_origin(
            &headers,
            "https://av.example.com"
        ));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        );
        assert!(!is_trusted_browser_origin(
            &headers,
            "https://av.example.com"
        ));
        headers.remove(header::ORIGIN);
        headers.insert(
            HeaderName::from_static("sec-fetch-site"),
            HeaderValue::from_static("same-site"),
        );
        assert!(!is_trusted_browser_origin(
            &headers,
            "https://av.example.com"
        ));
    }

    #[test]
    fn runtime_status_exposes_capabilities_without_connector_credentials() {
        let config: Config = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1:14322",
            "public_url": "http://127.0.0.1:14322",
            "ui_dir": "ui/dist",
            "auth": {
                "mode": "oidc_or_basic",
                "issuer": "https://identity.example.com",
                "client_id": "public-client",
                "allowed_groups": ["av-users"],
                "basic_users": [{"username": "fallback", "password_hash_file": "/run/secret"}]
            },
            "connectors": {
                "infisical": {
                    "base_url": "https://infisical.example.com",
                    "auth": {
                        "type": "kubernetes",
                        "identity_id": "identity-id",
                        "token_file": "/var/run/secrets/token"
                    }
                }
            },
            "profiles": {},
            "proxy_routes": {}
        }))
        .unwrap();

        let status = public_status(&config);
        assert!(status.oidc_enabled);
        assert!(status.basic_enabled);
        assert!(!status.persistence_enabled);
        assert!(!status.registration_enabled);
        assert_eq!(
            status.connectors,
            [PublicConnector {
                name: "infisical".into(),
                kind: "infisical".into()
            }]
        );
        assert_eq!(status.profile_count, 0);
        assert!(status.proxy_routes.is_empty());
        let policy = content_security_policy(&config).unwrap();
        let policy = policy.to_str().unwrap();
        assert_eq!(
            policy,
            "default-src 'self'; connect-src 'self' https://identity.example.com; script-src 'self'; style-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        );
    }

    #[test]
    fn proxy_response_redacts_common_credential_encodings() {
        assert_eq!(
            redact(b"before secret-token after", b"secret-token"),
            b"before [REDACTED] after"
        );
        assert_eq!(redact(b"c2VjcmV0LXRva2Vu", b"secret-token"), b"[REDACTED]");
        assert_eq!(redact(b"secret%2Btoken", b"secret+token"), b"[REDACTED]");
    }

    #[test]
    fn proxy_query_requires_declared_unique_parameters() {
        let route = proxy_route(&["GET"], &["/zones"]);
        assert_eq!(
            validate_proxy_query(&route, Some("source=integration")).unwrap(),
            [("source".into(), "integration".into())]
        );
        assert!(validate_proxy_query(&route, Some("other=value")).is_err());
        assert!(validate_proxy_query(&route, Some("source=one&source=two")).is_err());
        assert!(validate_proxy_query(&route, Some("source=%ZZ")).is_err());
    }

    #[test]
    fn proxy_body_requires_an_allowed_content_type() {
        let route = proxy_route(&["POST"], &["/zones"]);
        let mut headers = HeaderMap::new();
        assert!(enforce_proxy_content_type(&route, &headers, 0).is_ok());
        assert!(enforce_proxy_content_type(&route, &headers, 1).is_err());
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        assert!(enforce_proxy_content_type(&route, &headers, 1).is_ok());
    }
}
