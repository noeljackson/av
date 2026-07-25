use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use askama::Template;
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{any, get},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use serde::Serialize;
use tokio::{
    sync::{Mutex, Semaphore},
    time::Instant,
};
use tower_http::{set_header::SetResponseHeaderLayer, trace::TraceLayer};
use zeroize::Zeroizing;

use crate::{
    auth::Authenticator,
    av::v1::{
        AuditEvent as RpcAuditEvent, AuthConfig as RpcAuthConfig, BasicUser as RpcBasicUser,
        Connector as RpcConnector, ControlService, ControlServiceExt, EnvironmentValue,
        GetAuthConfigRequest, GetProfileEnvironmentRequest, GetStatusRequest, GrantProfileRequest,
        ListAuditEventsRequest, ListAuditEventsResponse, ListBasicUsersRequest,
        ListBasicUsersResponse, ListProfileGrantsRequest, ListProfileGrantsResponse,
        ListProfilesRequest, ListProfilesResponse, Profile as RpcProfile, ProfileEnvironment,
        ProfileGrant as RpcProfileGrant, RevokeProfileRequest, SessionService, SessionServiceExt,
        SetBasicUserEnabledRequest, Status as RpcStatus, UpsertBasicUserRequest,
    },
    config::{AuthMode, Config, ConfigMode, ProfileConfig, ProxyRouteConfig},
    connector::Connector,
    store::Store,
};

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    auth: Authenticator,
    connectors: Arc<BTreeMap<String, Connector>>,
    connector_slots: Arc<Semaphore>,
    api_rate_limiter: ApiRateLimiter,
    proxy_client: reqwest::Client,
    store: Option<Store>,
}

#[derive(Clone)]
struct ConnectSessionService {
    state: AppState,
}

#[derive(Clone)]
struct ConnectControlService {
    state: AppState,
}

#[allow(refining_impl_trait)]
impl ControlService for ConnectControlService {
    async fn list_basic_users(
        &self,
        ctx: connectrpc::RequestContext,
        _request: connectrpc::ServiceRequest<'_, ListBasicUsersRequest>,
    ) -> connectrpc::ServiceResult<ListBasicUsersResponse> {
        require_owner(&self.state, ctx.headers()).await?;
        let store = managed_store(&self.state)?;
        let users = store
            .list_basic_users()
            .await
            .map_err(|_| connectrpc::ConnectError::internal("managed store unavailable"))?;
        connectrpc::Response::ok(ListBasicUsersResponse {
            users: users
                .into_iter()
                .map(|user| RpcBasicUser {
                    username: user.username,
                    enabled: user.enabled,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        })
    }

    async fn upsert_basic_user(
        &self,
        ctx: connectrpc::RequestContext,
        request: connectrpc::ServiceRequest<'_, UpsertBasicUserRequest>,
    ) -> connectrpc::ServiceResult<RpcBasicUser> {
        let identity = require_owner(&self.state, ctx.headers()).await?;
        let username = request.username;
        if !valid_basic_username(username) {
            return Err(connectrpc::ConnectError::invalid_argument(
                "invalid Basic username",
            ));
        }
        if request.password.len() < 12 || request.password.len() > 1024 {
            return Err(connectrpc::ConnectError::invalid_argument(
                "Basic passwords must be between 12 and 1024 characters",
            ));
        }
        let password = request.password.to_owned();
        let password_hash = tokio::task::spawn_blocking(move || hash_basic_password(password))
            .await
            .map_err(|_| connectrpc::ConnectError::internal("password hashing failed"))?
            .map_err(|_| connectrpc::ConnectError::internal("password hashing failed"))?;
        let store = managed_store(&self.state)?;
        store
            .upsert_basic_user(username, &password_hash)
            .await
            .map_err(|_| connectrpc::ConnectError::internal("managed store unavailable"))?;
        audit_event(
            &self.state,
            &identity.subject,
            "basic_user_upsert",
            None,
            None,
            None,
        )
        .await
        .map_err(|_| connectrpc::ConnectError::internal("audit persistence unavailable"))?;
        connectrpc::Response::ok(RpcBasicUser {
            username: username.to_owned(),
            enabled: true,
            ..Default::default()
        })
    }

    async fn set_basic_user_enabled(
        &self,
        ctx: connectrpc::RequestContext,
        request: connectrpc::ServiceRequest<'_, SetBasicUserEnabledRequest>,
    ) -> connectrpc::ServiceResult<RpcBasicUser> {
        let identity = require_owner(&self.state, ctx.headers()).await?;
        let username = request.username;
        if !valid_basic_username(username) {
            return Err(connectrpc::ConnectError::invalid_argument(
                "invalid Basic username",
            ));
        }
        let store = managed_store(&self.state)?;
        let enabled = request.enabled;
        if !store
            .set_basic_user_enabled(username, enabled)
            .await
            .map_err(|_| connectrpc::ConnectError::internal("managed store unavailable"))?
        {
            return Err(connectrpc::ConnectError::not_found("Basic user not found"));
        }
        audit_event(
            &self.state,
            &identity.subject,
            if enabled {
                "basic_user_enabled"
            } else {
                "basic_user_disabled"
            },
            None,
            None,
            None,
        )
        .await
        .map_err(|_| connectrpc::ConnectError::internal("audit persistence unavailable"))?;
        connectrpc::Response::ok(RpcBasicUser {
            username: username.to_owned(),
            enabled,
            ..Default::default()
        })
    }

    async fn list_audit_events(
        &self,
        ctx: connectrpc::RequestContext,
        request: connectrpc::ServiceRequest<'_, ListAuditEventsRequest>,
    ) -> connectrpc::ServiceResult<ListAuditEventsResponse> {
        require_owner(&self.state, ctx.headers()).await?;
        let store = managed_store(&self.state)?;
        let limit = if request.limit == 0 {
            100
        } else {
            request.limit
        };
        let events = store
            .list_audit_events(i64::from(limit))
            .await
            .map_err(|_| connectrpc::ConnectError::internal("managed store unavailable"))?;
        connectrpc::Response::ok(ListAuditEventsResponse {
            events: events
                .into_iter()
                .map(|event| RpcAuditEvent {
                    created_unix_seconds: event.created_unix_seconds,
                    actor: event.actor,
                    action: event.action,
                    profile: event.profile.unwrap_or_default(),
                    route: event.route.unwrap_or_default(),
                    executable_basename: event.executable_basename.unwrap_or_default(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        })
    }

    async fn list_profile_grants(
        &self,
        ctx: connectrpc::RequestContext,
        request: connectrpc::ServiceRequest<'_, ListProfileGrantsRequest>,
    ) -> connectrpc::ServiceResult<ListProfileGrantsResponse> {
        require_owner(&self.state, ctx.headers()).await?;
        let profile = request.profile;
        require_known_profile(&self.state, profile)?;
        let grants = managed_store(&self.state)?
            .list_profile_grants(profile)
            .await
            .map_err(|_| connectrpc::ConnectError::internal("managed store unavailable"))?;
        connectrpc::Response::ok(ListProfileGrantsResponse {
            grants: grants
                .into_iter()
                .map(|grant| RpcProfileGrant {
                    profile: grant.profile,
                    subject: grant.subject,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        })
    }

    async fn grant_profile(
        &self,
        ctx: connectrpc::RequestContext,
        request: connectrpc::ServiceRequest<'_, GrantProfileRequest>,
    ) -> connectrpc::ServiceResult<RpcProfileGrant> {
        let identity = require_owner(&self.state, ctx.headers()).await?;
        let profile = request.profile;
        let subject = request.subject;
        require_known_profile(&self.state, profile)?;
        if !valid_policy_subject(subject) {
            return Err(connectrpc::ConnectError::invalid_argument(
                "invalid policy subject",
            ));
        }
        managed_store(&self.state)?
            .grant_profile(subject, profile)
            .await
            .map_err(|_| connectrpc::ConnectError::internal("managed store unavailable"))?;
        audit_event(
            &self.state,
            &identity.subject,
            "profile_grant",
            Some(profile),
            None,
            None,
        )
        .await
        .map_err(|_| connectrpc::ConnectError::internal("audit persistence unavailable"))?;
        connectrpc::Response::ok(RpcProfileGrant {
            profile: profile.to_owned(),
            subject: subject.to_owned(),
            ..Default::default()
        })
    }

    async fn revoke_profile(
        &self,
        ctx: connectrpc::RequestContext,
        request: connectrpc::ServiceRequest<'_, RevokeProfileRequest>,
    ) -> connectrpc::ServiceResult<RpcProfileGrant> {
        let identity = require_owner(&self.state, ctx.headers()).await?;
        let profile = request.profile;
        let subject = request.subject;
        require_known_profile(&self.state, profile)?;
        if !valid_policy_subject(subject) {
            return Err(connectrpc::ConnectError::invalid_argument(
                "invalid policy subject",
            ));
        }
        if !managed_store(&self.state)?
            .revoke_profile(subject, profile)
            .await
            .map_err(|_| connectrpc::ConnectError::internal("managed store unavailable"))?
        {
            return Err(connectrpc::ConnectError::not_found(
                "profile grant not found",
            ));
        }
        audit_event(
            &self.state,
            &identity.subject,
            "profile_grant_revoked",
            Some(profile),
            None,
            None,
        )
        .await
        .map_err(|_| connectrpc::ConnectError::internal("audit persistence unavailable"))?;
        connectrpc::Response::ok(RpcProfileGrant {
            profile: profile.to_owned(),
            subject: subject.to_owned(),
            ..Default::default()
        })
    }
}

fn managed_store(state: &AppState) -> std::result::Result<&Store, connectrpc::ConnectError> {
    state.store.as_ref().ok_or_else(|| {
        connectrpc::ConnectError::failed_precondition("managed control plane is disabled")
    })
}

async fn require_owner(
    state: &AppState,
    headers: &HeaderMap,
) -> std::result::Result<crate::auth::Identity, connectrpc::ConnectError> {
    let identity = authorize_connect(state, headers).await?;
    let store = managed_store(state)?;
    if !store
        .is_owner(&identity.subject)
        .await
        .map_err(|_| connectrpc::ConnectError::internal("managed store unavailable"))?
    {
        return Err(connectrpc::ConnectError::permission_denied(
            "owner access required",
        ));
    }
    Ok(identity)
}

fn valid_basic_username(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.contains(':')
        && !value.chars().any(char::is_control)
}

fn valid_policy_subject(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 255 && !value.chars().any(char::is_control)
}

fn require_known_profile(
    state: &AppState,
    profile: &str,
) -> std::result::Result<(), connectrpc::ConnectError> {
    if state.config.profiles.contains_key(profile) {
        Ok(())
    } else {
        Err(connectrpc::ConnectError::not_found("profile not found"))
    }
}

fn hash_basic_password(password: String) -> Result<String> {
    let password = Zeroizing::new(password);
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(19 * 1024, 2, 1, None)
        .map_err(|error| anyhow::anyhow!("configure Argon2id: {error}"))?;
    let hash = Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password(password.as_bytes(), &salt)
        .map_err(|error| anyhow::anyhow!("hash Basic password: {error}"))?
        .to_string();
    Ok(hash)
}

#[allow(refining_impl_trait)]
impl SessionService for ConnectSessionService {
    async fn get_auth_config(
        &self,
        _ctx: connectrpc::RequestContext,
        _request: connectrpc::ServiceRequest<'_, GetAuthConfigRequest>,
    ) -> connectrpc::ServiceResult<RpcAuthConfig> {
        let auth = self.state.auth.public_config();
        connectrpc::Response::ok(RpcAuthConfig {
            mode: auth.mode,
            issuer: auth.issuer,
            client_id: auth.client_id,
            scopes: auth.scopes,
            authorization_endpoint: auth.authorization_endpoint.unwrap_or_default(),
            token_endpoint: auth.token_endpoint.unwrap_or_default(),
            device_authorization_endpoint: auth.device_authorization_endpoint.unwrap_or_default(),
            ..Default::default()
        })
    }

    async fn get_status(
        &self,
        ctx: connectrpc::RequestContext,
        _request: connectrpc::ServiceRequest<'_, GetStatusRequest>,
    ) -> connectrpc::ServiceResult<RpcStatus> {
        authorize_connect(&self.state, ctx.headers()).await?;
        let status = public_status(&self.state.config);
        connectrpc::Response::ok(RpcStatus {
            oidc_enabled: status.oidc_enabled,
            basic_enabled: status.basic_enabled,
            persistence_enabled: status.persistence_enabled,
            registration_enabled: status.registration_enabled,
            connectors: status
                .connectors
                .into_iter()
                .map(|connector| RpcConnector {
                    name: connector.name,
                    kind: connector.kind,
                    ..Default::default()
                })
                .collect(),
            profile_count: status.profile_count as u32,
            proxy_routes: status.proxy_routes,
            api_rate_limit_per_second: status.api_rate_limit_per_second,
            api_rate_limit_burst: status.api_rate_limit_burst,
            ..Default::default()
        })
    }

    async fn list_profiles(
        &self,
        ctx: connectrpc::RequestContext,
        _request: connectrpc::ServiceRequest<'_, ListProfilesRequest>,
    ) -> connectrpc::ServiceResult<ListProfilesResponse> {
        let identity = authorize_connect(&self.state, ctx.headers()).await?;
        let allowed = permitted_profile_names(&self.state, &identity.subject)
            .await
            .map_err(|_| connectrpc::ConnectError::internal("managed store unavailable"))?;
        let profiles = self
            .state
            .config
            .profiles
            .iter()
            .filter(|(name, _)| allowed.contains(*name))
            .map(|(name, profile)| RpcProfile {
                name: name.clone(),
                environment: profile.environment.clone(),
                secret_path: profile.secret_path.clone(),
                ..Default::default()
            })
            .collect();
        connectrpc::Response::ok(ListProfilesResponse {
            profiles,
            ..Default::default()
        })
    }

    async fn get_profile_environment(
        &self,
        ctx: connectrpc::RequestContext,
        request: connectrpc::ServiceRequest<'_, GetProfileEnvironmentRequest>,
    ) -> connectrpc::ServiceResult<ProfileEnvironment> {
        let identity = authorize_connect(&self.state, ctx.headers()).await?;
        let profile_name = request.profile;
        let Some(profile) = self.state.config.profiles.get(profile_name) else {
            return Err(connectrpc::ConnectError::not_found("profile not found"));
        };
        if !profile_permitted(&self.state, &identity.subject, profile_name)
            .await
            .map_err(|_| connectrpc::ConnectError::internal("managed store unavailable"))?
        {
            return Err(connectrpc::ConnectError::permission_denied(
                "profile access is not granted",
            ));
        }
        let executable = request.executable_basename;
        if !valid_executable_basename(executable) {
            return Err(connectrpc::ConnectError::invalid_argument(
                "executable_basename must be a basename without control characters",
            ));
        }
        let secrets = fetch_secrets(&self.state, profile)
            .await
            .map_err(|error| {
                tracing::warn!(subject = %identity.subject, profile = profile_name, error = %error, "profile environment unavailable");
                connectrpc::ConnectError::internal("profile environment unavailable")
            })?;
        tracing::info!(
            subject = %identity.subject,
            profile = profile_name,
            executable,
            key_count = secrets.len(),
            "profile leased"
        );
        audit_event(
            &self.state,
            &identity.subject,
            "profile_lease",
            Some(profile_name),
            None,
            Some(executable),
        )
        .await
        .map_err(|_| connectrpc::ConnectError::internal("audit persistence unavailable"))?;
        connectrpc::Response::ok(ProfileEnvironment {
            values: secrets
                .into_iter()
                .map(|(name, value)| EnvironmentValue {
                    name,
                    value,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        })
    }
}

async fn authorize_connect(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<crate::auth::Identity, connectrpc::ConnectError> {
    state
        .auth
        .authorize(headers)
        .await
        .map_err(|_| connectrpc::ConnectError::unauthenticated("authentication required"))
}

async fn permitted_profile_names(state: &AppState, subject: &str) -> Result<BTreeSet<String>> {
    match &state.store {
        None => Ok(state.config.profiles.keys().cloned().collect()),
        Some(store) => Ok(store
            .list_allowed_profiles(subject)
            .await?
            .into_iter()
            .filter(|profile| state.config.profiles.contains_key(profile))
            .collect()),
    }
}

async fn profile_permitted(state: &AppState, subject: &str, profile: &str) -> Result<bool> {
    match &state.store {
        None => Ok(true),
        Some(store) => store.profile_allowed(subject, profile).await,
    }
}

fn valid_executable_basename(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.contains(['/', '\\'])
        && !value.chars().any(char::is_control)
}

#[derive(Clone)]
struct ApiRateLimiter {
    rate_per_second: f64,
    capacity: f64,
    state: Arc<Mutex<ApiRateLimitState>>,
}

struct ApiRateLimitState {
    tokens: f64,
    last_refill: Instant,
}

impl ApiRateLimiter {
    fn new(rate_per_second: u32, burst: u32) -> Self {
        Self {
            rate_per_second: f64::from(rate_per_second),
            capacity: f64::from(burst),
            state: Arc::new(Mutex::new(ApiRateLimitState {
                tokens: f64::from(burst),
                last_refill: Instant::now(),
            })),
        }
    }

    async fn try_acquire(&self) -> bool {
        let mut state = self.state.lock().await;
        let now = Instant::now();
        state.tokens = (state.tokens
            + now.duration_since(state.last_refill).as_secs_f64() * self.rate_per_second)
            .min(self.capacity);
        state.last_refill = now;
        if state.tokens < 1.0 {
            return false;
        }
        state.tokens -= 1.0;
        true
    }
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
    api_rate_limit_per_second: u32,
    api_rate_limit_burst: u32,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct PublicConnector {
    name: String,
    kind: String,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate;

#[derive(Template)]
#[template(path = "session.html")]
struct SessionTemplate<'a> {
    status: PublicStatus,
    profiles: Vec<ProfileSummary<'a>>,
}

pub async fn run(config: Config) -> Result<()> {
    let store = match config.mode {
        ConfigMode::Static => None,
        ConfigMode::Managed => Some(
            Store::connect(
                config
                    .managed
                    .as_ref()
                    .expect("managed configuration is validated before server startup"),
            )
            .await?,
        ),
    };
    let auth = Authenticator::new(config.auth.clone(), store.clone()).await?;
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
        api_rate_limiter: ApiRateLimiter::new(
            config.api_rate_limit_per_second,
            config.api_rate_limit_burst,
        ),
        proxy_client,
        store,
    };
    // Register every service before translating into Axum. Mount the resulting
    // service at each generated service namespace rather than merging its
    // catch-all fallback: the UI fallback must not receive RPC POSTs.
    let connect_router = Arc::new(ConnectControlService {
        state: state.clone(),
    })
    .register(connectrpc::Router::new());
    let connect_router = Arc::new(ConnectSessionService {
        state: state.clone(),
    })
    .register(connect_router)
    .into_axum_service();
    let app = Router::new()
        .route("/", get(ui_index))
        .route("/assets/av.css", get(ui_css))
        .route("/assets/av.js", get(ui_js))
        .route("/healthz", get(health))
        .route("/readyz", get(health))
        .route("/v1/auth/config", get(auth_config))
        .route("/v1/status", get(status))
        .route("/v1/profiles", get(profiles))
        .route("/v1/profiles/{profile}/secrets", get(profile_secrets))
        .route("/v1/proxy/{route}/{*path}", any(proxy))
        .route("/ui/session", get(ui_session))
        .route("/v1/{*path}", any(api_not_found))
        .route_service("/av.v1.SessionService/{*path}", connect_router.clone())
        .route_service("/av.v1.ControlService/{*path}", connect_router)
        .fallback(get(ui_not_found))
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            enforce_api_rate_limit,
        ))
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

async fn ui_index() -> Response {
    match IndexTemplate.render() {
        Ok(page) => no_store(Html(page).into_response()),
        Err(error) => {
            tracing::error!(%error, "render UI index");
            no_store((StatusCode::INTERNAL_SERVER_ERROR, "UI unavailable\n").into_response())
        }
    }
}

async fn ui_css() -> Response {
    no_store(
        (
            [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
            include_str!("../assets/av.css"),
        )
            .into_response(),
    )
}

async fn ui_js() -> Response {
    no_store(
        (
            [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
            include_str!("../assets/av.js"),
        )
            .into_response(),
    )
}

async fn ui_not_found() -> Response {
    no_store((StatusCode::NOT_FOUND, "not found\n").into_response())
}

async fn api_not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "api endpoint not found\n")
}

async fn enforce_api_rate_limit(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if (request.uri().path().starts_with("/v1/") || request.uri().path().starts_with("/av.v1."))
        && !state.api_rate_limiter.try_acquire().await
    {
        let mut response =
            (StatusCode::TOO_MANY_REQUESTS, "api rate limit exceeded\n").into_response();
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return no_store(response);
    }
    next.run(request).await
}

async fn auth_config(State(state): State<AppState>) -> impl IntoResponse {
    no_store(axum::Json(state.auth.public_config()).into_response())
}

async fn ui_session(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let identity = match state.auth.authorize(&headers).await {
        Ok(identity) => identity,
        Err(error) => return unauthorized(error),
    };
    let allowed = match permitted_profile_names(&state, &identity.subject).await {
        Ok(allowed) => allowed,
        Err(error) => return internal_error(error),
    };
    let profiles = state
        .config
        .profiles
        .iter()
        .filter(|(name, _)| allowed.contains(*name))
        .map(|(name, profile)| ProfileSummary {
            name,
            environment: &profile.environment,
            path: &profile.secret_path,
        })
        .collect();
    match (SessionTemplate {
        status: public_status(&state.config),
        profiles,
    })
    .render()
    {
        Ok(page) => no_store(Html(page).into_response()),
        Err(error) => {
            tracing::error!(%error, "render authenticated UI session");
            no_store((StatusCode::INTERNAL_SERVER_ERROR, "UI unavailable\n").into_response())
        }
    }
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
        persistence_enabled: config.mode == ConfigMode::Managed,
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
        api_rate_limit_per_second: config.api_rate_limit_per_second,
        api_rate_limit_burst: config.api_rate_limit_burst,
    }
}

async fn profiles(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let identity = match state.auth.authorize(&headers).await {
        Ok(identity) => identity,
        Err(error) => return unauthorized(error),
    };
    let allowed = match permitted_profile_names(&state, &identity.subject).await {
        Ok(allowed) => allowed,
        Err(error) => return internal_error(error),
    };
    let profiles: Vec<_> = state
        .config
        .profiles
        .iter()
        .filter(|(name, _)| allowed.contains(*name))
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
    match profile_permitted(&state, &identity.subject, &profile).await {
        Ok(true) => {}
        Ok(false) => {
            return (StatusCode::FORBIDDEN, "profile access is not granted\n").into_response();
        }
        Err(error) => return internal_error(error),
    }
    match fetch_secrets(&state, profile_config).await {
        Ok(secrets) => {
            tracing::info!(subject = %identity.subject, profile, key_count = secrets.len(), "profile leased");
            if let Err(error) = audit_event(
                &state,
                &identity.subject,
                "profile_lease",
                Some(&profile),
                None,
                Some("legacy-api"),
            )
            .await
            {
                return internal_error(error);
            }
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
    match profile_permitted(&state, &identity.subject, &route.profile).await {
        Ok(true) => {}
        Ok(false) => return (StatusCode::FORBIDDEN, "proxy request forbidden\n").into_response(),
        Err(error) => return internal_error(error),
    }
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
    if let Err(error) = audit_event(
        &state,
        &identity.subject,
        "proxy_request_started",
        Some(&route.profile),
        Some(&route_name),
        None,
    )
    .await
    {
        return internal_error(error);
    }
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

async fn audit_event(
    state: &AppState,
    actor: &str,
    action: &str,
    profile: Option<&str>,
    route: Option<&str>,
    executable_basename: Option<&str>,
) -> Result<()> {
    if let Some(store) = &state.store {
        store
            .record_audit(actor, action, profile, route, executable_basename)
            .await?;
    }
    Ok(())
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
        assert_eq!(status.api_rate_limit_per_second, 50);
        assert_eq!(status.api_rate_limit_burst, 100);
        let policy = content_security_policy(&config).unwrap();
        let policy = policy.to_str().unwrap();
        assert_eq!(
            policy,
            "default-src 'self'; connect-src 'self' https://identity.example.com; script-src 'self'; style-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        );
    }

    #[test]
    fn locked_ui_does_not_render_runtime_configuration() {
        let page = IndexTemplate.render().unwrap();
        assert!(page.contains("authentication required"));
        assert!(!page.contains("connectors"));
        assert!(!page.contains("profile"));
        assert!(!page.contains("identity.example.com"));
    }

    #[test]
    fn authenticated_ui_escapes_configuration_values() {
        let page = SessionTemplate {
            status: PublicStatus {
                oidc_enabled: true,
                basic_enabled: false,
                persistence_enabled: true,
                registration_enabled: false,
                connectors: vec![PublicConnector {
                    name: "<script>connector</script>".into(),
                    kind: "infisical".into(),
                }],
                profile_count: 1,
                proxy_routes: vec!["<script>route</script>".into()],
                api_rate_limit_per_second: 50,
                api_rate_limit_burst: 100,
            },
            profiles: vec![ProfileSummary {
                name: "<script>profile</script>",
                environment: "dev",
                path: "/",
            }],
        }
        .render()
        .unwrap();
        assert!(page.contains("&#60;script&#62;profile&#60;/script&#62;"));
        assert!(page.contains("&#60;script&#62;connector&#60;/script&#62;"));
        assert!(!page.contains("<script>profile</script>"));
        assert!(!page.contains("<script>connector</script>"));
    }

    #[tokio::test]
    async fn application_rate_limiter_enforces_its_burst_capacity() {
        let limiter = ApiRateLimiter::new(1, 2);
        assert!(limiter.try_acquire().await);
        assert!(limiter.try_acquire().await);
        assert!(!limiter.try_acquire().await);
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
