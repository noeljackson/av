use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{any, get},
};
use serde::Serialize;
use tower_http::{
    services::{ServeDir, ServeFile},
    set_header::SetResponseHeaderLayer,
    trace::TraceLayer,
};

use crate::{
    auth::Authenticator,
    config::{Config, ProfileConfig, ProxyRouteConfig},
    infisical::InfisicalConnector,
};

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    auth: Authenticator,
    connectors: Arc<BTreeMap<String, InfisicalConnector>>,
    proxy_client: reqwest::Client,
}

#[derive(Serialize)]
struct ProfileSummary<'a> {
    name: &'a str,
    environment: &'a str,
    path: &'a str,
}

pub async fn run(config: Config) -> Result<()> {
    let auth = Authenticator::new(config.auth.clone()).await?;
    let mut connectors = BTreeMap::new();
    for (name, connector) in &config.connectors {
        connectors.insert(name.clone(), InfisicalConnector::new(connector.clone())?);
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
        proxy_client,
    };
    let ui_dir = PathBuf::from(&config.ui_dir);
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(health))
        .route("/v1/auth/config", get(auth_config))
        .route("/v1/profiles", get(profiles))
        .route("/v1/profiles/{profile}/secrets", get(profile_secrets))
        .route("/v1/proxy/{route}/{*path}", any(proxy))
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static(
                "default-src 'self'; connect-src 'self' https:; script-src 'self'; style-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self' https:",
            ),
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
        .fallback_service(
            ServeDir::new(&ui_dir).not_found_service(ServeFile::new(ui_dir.join("index.html"))),
        )
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

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

async fn auth_config(State(state): State<AppState>) -> impl IntoResponse {
    no_store(axum::Json(state.auth.public_config()).into_response())
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
    match proxy_request(&state, route, &path, method, headers, body).await {
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
    path: &str,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    if !route
        .allowed_methods
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(method.as_str()))
    {
        bail!("method is not allowed");
    }
    let normalized_path = format!("/{}", path.trim_start_matches('/'));
    if normalized_path.contains("..")
        || !route
            .allowed_path_prefixes
            .iter()
            .any(|prefix| normalized_path.starts_with(prefix))
    {
        bail!("path is not allowed");
    }
    let profile = state
        .config
        .profiles
        .get(&route.profile)
        .context("proxy profile disappeared")?;
    let secrets = fetch_secrets(state, profile).await?;
    let secret = secrets
        .get(&route.secret_key)
        .context("proxy credential is unavailable")?;
    let target = format!(
        "{}{}",
        route.base_url.trim_end_matches('/'),
        normalized_path
    );
    let mut request = state.proxy_client.request(method, target).body(body);
    for (name, value) in &headers {
        if is_forwardable_request_header(name) {
            request = request.header(name, value);
        }
    }
    let injection_name = HeaderName::from_bytes(route.header.as_bytes())?;
    let injection_value = HeaderValue::from_str(&format!("{}{}", route.header_prefix, secret))?;
    let upstream = request
        .header(injection_name, injection_value)
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
    let bytes = upstream.bytes().await?;
    let bytes = redact(&bytes, secret.as_bytes());
    let mut response = Response::builder().status(status);
    for (name, value) in &upstream_headers {
        if is_forwardable_response_header(name) {
            response = response.header(name, value);
        }
    }
    Ok(response.body(axum::body::Body::from(bytes))?)
}

async fn fetch_secrets(
    state: &AppState,
    profile: &ProfileConfig,
) -> Result<BTreeMap<String, String>> {
    state
        .connectors
        .get(&profile.connector)
        .context("profile connector disappeared")?
        .secrets(profile)
        .await
}

fn is_forwardable_request_header(name: &HeaderName) -> bool {
    !matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "authorization"
            | "cookie"
            | "connection"
            | "host"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn is_forwardable_response_header(name: &HeaderName) -> bool {
    !matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "connection" | "set-cookie" | "transfer-encoding" | "upgrade"
    )
}

fn redact(body: &[u8], secret: &[u8]) -> Vec<u8> {
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

    #[test]
    fn proxy_response_redacts_exact_credential_bytes() {
        assert_eq!(
            redact(b"before secret-token after", b"secret-token"),
            b"before [REDACTED] after"
        );
    }

    #[test]
    fn authorization_and_cookies_never_forward() {
        assert!(!is_forwardable_request_header(&header::AUTHORIZATION));
        assert!(!is_forwardable_request_header(&header::COOKIE));
        assert!(is_forwardable_request_header(&header::CONTENT_TYPE));
    }
}
