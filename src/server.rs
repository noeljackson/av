use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{
        PasswordHasher, SaltString,
        rand_core::{OsRng, RngCore},
    },
};
use askama::Template;
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Form, Path, Query, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{any, get, post},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use http_body_util::{BodyExt, Empty, Full};
use hyper::{
    Request as HyperRequest, Response as HyperResponse, body::Incoming, server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore},
    time::Instant,
};
use tower_http::{set_header::SetResponseHeaderLayer, trace::TraceLayer};
use zeroize::Zeroizing;

use crate::{
    auth::Authenticator,
    av::v1::{
        AuditEvent as RpcAuditEvent, AuthConfig as RpcAuthConfig, BasicUser as RpcBasicUser,
        Connector as RpcConnector, ControlService, ControlServiceExt, CreateProxySessionRequest,
        EnvironmentValue, GetAuthConfigRequest, GetProfileEnvironmentRequest, GetStatusRequest,
        GrantProfileRequest, ListAuditEventsRequest, ListAuditEventsResponse,
        ListBasicUsersRequest, ListBasicUsersResponse, ListProfileGrantsRequest,
        ListProfileGrantsResponse, ListProfilesRequest, ListProfilesResponse,
        Profile as RpcProfile, ProfileEnvironment, ProfileGrant as RpcProfileGrant,
        ProxySessionLease, RevokeProfileRequest, RevokeProxySessionRequest, SessionService,
        SessionServiceExt, SetBasicUserEnabledRequest, Status as RpcStatus, UpsertBasicUserRequest,
    },
    config::{AuthMode, Config, ConfigMode, GithubAuthConfig, ProfileConfig, ProxyRouteConfig},
    connector::Connector,
    proxy_ca::ProxyCertificateAuthority,
    store::Store,
    transparent_proxy::{
        TransparentRouteCatalog, authorize_connect_request, mint_proxy_session_credential,
    },
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
    github_browser_auth: Option<GithubBrowserAuth>,
    transparent_proxy: Option<Arc<TransparentProxyRuntime>>,
}

struct TransparentProxyRuntime {
    listen: String,
    proxy_url: String,
    session_ttl: Duration,
    catalog: TransparentRouteCatalog,
    certificate_authority: ProxyCertificateAuthority,
}

const GITHUB_AUTHORIZATION_ENDPOINT: &str = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_ENDPOINT: &str = "https://github.com/login/oauth/access_token";
const GITHUB_USER_ENDPOINT: &str = "https://api.github.com/user";
const GITHUB_ORGANIZATION_MEMBERSHIP_ENDPOINT: &str =
    "https://api.github.com/user/memberships/orgs";
const GITHUB_STATE_COOKIE: &str = "av_github_state";
const GITHUB_SESSION_COOKIE: &str = "av_github_session";
const GITHUB_AUTH_TTL: Duration = Duration::from_secs(10 * 60);
const GITHUB_SESSION_TTL: Duration = Duration::from_secs(60 * 60);

#[derive(Clone)]
struct GithubBrowserAuth {
    client_id: String,
    client_secret: Arc<Zeroizing<String>>,
    allowed_user_ids: BTreeSet<u64>,
    allowed_organizations: BTreeSet<String>,
    client: reqwest::Client,
    pending: Arc<Mutex<BTreeMap<String, GithubPendingLogin>>>,
    sessions: Arc<Mutex<BTreeMap<String, GithubBrowserSession>>>,
}

struct GithubPendingLogin {
    verifier: String,
    expires_at: SystemTime,
}

struct GithubBrowserSession {
    identity: crate::auth::Identity,
    expires_at: SystemTime,
}

#[derive(Deserialize)]
struct GithubCallback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct GithubTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct GithubUser {
    id: u64,
}

#[derive(Deserialize)]
struct GithubOrganizationMembership {
    state: String,
}

impl GithubBrowserAuth {
    fn new(config: &GithubAuthConfig) -> Result<Self> {
        let client_secret = std::fs::read_to_string(&config.client_secret_file)
            .with_context(|| format!("read GitHub client secret {}", config.client_secret_file))?;
        let client_secret = client_secret.trim().to_owned();
        if client_secret.is_empty() {
            bail!("GitHub client secret file is empty");
        }
        let client = reqwest::Client::builder()
            .https_only(true)
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("av/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("build GitHub OAuth client")?;
        Ok(Self {
            client_id: config.client_id.clone(),
            client_secret: Arc::new(Zeroizing::new(client_secret)),
            allowed_user_ids: config.allowed_user_ids.iter().copied().collect(),
            allowed_organizations: config
                .allowed_organizations
                .iter()
                .map(|organization| organization.to_ascii_lowercase())
                .collect(),
            client,
            pending: Arc::new(Mutex::new(BTreeMap::new())),
            sessions: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    async fn start(&self, redirect_uri: &str) -> Result<(String, String)> {
        let state = random_browser_token();
        // GitHub requires a 43-128 character PKCE verifier. Two independent
        // URL-safe values provide 256 bits without putting it in browser storage.
        let verifier = format!("{}{}", random_browser_token(), random_browser_token());
        let challenge = URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier.as_bytes()));
        let now = SystemTime::now();
        let mut pending = self.pending.lock().await;
        pending.retain(|_, item| item.expires_at > now);
        pending.insert(
            state.clone(),
            GithubPendingLogin {
                verifier,
                expires_at: now + GITHUB_AUTH_TTL,
            },
        );
        let mut url = url::Url::parse(GITHUB_AUTHORIZATION_ENDPOINT)
            .expect("constant GitHub authorization URL is valid");
        let scope = if self.allowed_organizations.is_empty() {
            "read:user"
        } else {
            // Private organization membership is not available from the public
            // profile endpoint. Request it only when organization policy is used.
            "read:user read:org"
        };
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", scope)
            .append_pair("state", &state)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        Ok((url.into(), state))
    }

    async fn finish(
        &self,
        state: &str,
        code: &str,
        redirect_uri: &str,
    ) -> Result<crate::auth::Identity> {
        let pending = self
            .pending
            .lock()
            .await
            .remove(state)
            .filter(|item| item.expires_at > SystemTime::now())
            .context("GitHub OAuth state was rejected")?;
        let token: GithubTokenResponse = self
            .client
            .post(GITHUB_TOKEN_ENDPOINT)
            .header(header::ACCEPT, "application/json")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("code_verifier", pending.verifier.as_str()),
            ])
            .send()
            .await
            .context("exchange GitHub OAuth code")?
            .error_for_status()
            .context("GitHub OAuth code exchange failed")?
            .json()
            .await
            .context("decode GitHub OAuth token response")?;
        let user: GithubUser = self
            .client
            .get(GITHUB_USER_ENDPOINT)
            .bearer_auth(&token.access_token)
            .header(header::ACCEPT, "application/vnd.github+json")
            .send()
            .await
            .context("fetch GitHub OAuth identity")?
            .error_for_status()
            .context("GitHub OAuth identity request failed")?
            .json()
            .await
            .context("decode GitHub OAuth identity")?;
        if !self.is_allowed_user(&user, &token.access_token).await? {
            bail!("GitHub user is not allowed");
        }
        Ok(crate::auth::Identity {
            // GitHub's immutable numeric account identifier prevents a renamed
            // or recycled login from inheriting policy grants.
            subject: format!("github:{}", user.id),
        })
    }

    async fn is_allowed_user(&self, user: &GithubUser, access_token: &str) -> Result<bool> {
        if self.allowed_user_ids.contains(&user.id) {
            return Ok(true);
        }
        for organization in &self.allowed_organizations {
            if self
                .has_active_organization_membership(access_token, organization)
                .await?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn has_active_organization_membership(
        &self,
        access_token: &str,
        organization: &str,
    ) -> Result<bool> {
        let endpoint = github_organization_membership_endpoint(organization);
        let response = self
            .client
            .get(endpoint)
            .bearer_auth(access_token)
            .header(header::ACCEPT, "application/vnd.github+json")
            .send()
            .await
            .context("check GitHub organization membership")?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(false);
        }
        let membership: GithubOrganizationMembership = response
            .error_for_status()
            .context("GitHub organization membership request failed")?
            .json()
            .await
            .context("decode GitHub organization membership")?;
        Ok(membership.state == "active")
    }

    async fn create_session(&self, identity: crate::auth::Identity) -> String {
        let token = random_browser_token();
        let now = SystemTime::now();
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|_, session| session.expires_at > now);
        sessions.insert(
            token.clone(),
            GithubBrowserSession {
                identity,
                expires_at: now + GITHUB_SESSION_TTL,
            },
        );
        token
    }

    async fn session_identity(&self, token: &str) -> Option<crate::auth::Identity> {
        let mut sessions = self.sessions.lock().await;
        let now = SystemTime::now();
        sessions.retain(|_, session| session.expires_at > now);
        sessions.get(token).map(|session| session.identity.clone())
    }

    async fn remove_session(&self, token: &str) {
        self.sessions.lock().await.remove(token);
    }
}

fn github_organization_membership_endpoint(organization: &str) -> String {
    format!("{GITHUB_ORGANIZATION_MEMBERSHIP_ENDPOINT}/{organization}")
}

fn random_browser_token() -> String {
    // Browser OAuth state and session values cross both a URL query and a
    // strict cookie parser. SaltString uses a password-salt alphabet, which
    // may include characters that are valid in a URL only after escaping but
    // intentionally rejected by cookie_value().
    let mut bytes = [0_u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
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

fn external_identity_subject(kind: &str, identity: &str) -> Result<String> {
    let identity = identity.trim();
    match kind {
        "github" => {
            let account_id = identity
                .parse::<u64>()
                .context("GitHub account ID must be numeric")?;
            if account_id == 0 {
                bail!("GitHub account ID must be numeric");
            }
            Ok(format!("github:{account_id}"))
        }
        "oidc" => {
            if !valid_policy_subject(identity)
                || identity.starts_with("basic:")
                || identity.starts_with("github:")
            {
                bail!("OIDC subject is invalid");
            }
            Ok(identity.to_owned())
        }
        _ => bail!("identity kind is invalid"),
    }
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

    async fn create_proxy_session(
        &self,
        ctx: connectrpc::RequestContext,
        request: connectrpc::ServiceRequest<'_, CreateProxySessionRequest>,
    ) -> connectrpc::ServiceResult<ProxySessionLease> {
        let identity = authorize_connect(&self.state, ctx.headers()).await?;
        let runtime = self
            .state
            .transparent_proxy
            .as_ref()
            .context("transparent proxy is not configured")
            .map_err(|_| {
                connectrpc::ConnectError::failed_precondition("transparent proxy is not configured")
            })?;
        let store = self
            .state
            .store
            .as_ref()
            .context("managed store is unavailable")
            .map_err(|_| {
                connectrpc::ConnectError::failed_precondition("managed proxy sessions are required")
            })?;
        let profile = request.profile;
        if !self.state.config.profiles.contains_key(profile) {
            return Err(connectrpc::ConnectError::not_found("profile not found"));
        }
        if !profile_permitted(&self.state, &identity.subject, profile)
            .await
            .map_err(|_| connectrpc::ConnectError::internal("managed store unavailable"))?
        {
            return Err(connectrpc::ConnectError::permission_denied(
                "profile access is not granted",
            ));
        }
        let credential = mint_proxy_session_credential();
        let expires_unix_seconds = SystemTime::now()
            .checked_add(runtime.session_ttl)
            .context("proxy session expiry overflow")
            .and_then(|time| {
                time.duration_since(UNIX_EPOCH)
                    .context("system clock is before Unix epoch")
            })
            .and_then(|duration| {
                i64::try_from(duration.as_secs())
                    .context("proxy session expiry is outside supported range")
            })
            .map_err(|_| {
                connectrpc::ConnectError::internal("proxy session clock is unavailable")
            })?;
        store
            .create_proxy_session(
                &credential.session_id,
                &credential.token_hash,
                &identity.subject,
                profile,
                expires_unix_seconds,
            )
            .await
            .map_err(|error| {
                tracing::error!(%error, "create transparent proxy session");
                connectrpc::ConnectError::internal("proxy session is unavailable")
            })?;
        audit_event(
            &self.state,
            &identity.subject,
            "transparent_proxy_session_created",
            Some(profile),
            Some(&credential.session_id),
            None,
        )
        .await
        .map_err(|_| connectrpc::ConnectError::internal("audit persistence unavailable"))?;
        connectrpc::Response::ok(ProxySessionLease {
            session_id: credential.session_id,
            token: credential.token.to_string(),
            proxy_url: runtime.proxy_url.clone(),
            ca_certificate_pem: runtime.certificate_authority.certificate_pem().to_owned(),
            expires_unix_seconds,
            revoked: false,
            ..Default::default()
        })
    }

    async fn revoke_proxy_session(
        &self,
        ctx: connectrpc::RequestContext,
        request: connectrpc::ServiceRequest<'_, RevokeProxySessionRequest>,
    ) -> connectrpc::ServiceResult<ProxySessionLease> {
        let identity = authorize_connect(&self.state, ctx.headers()).await?;
        let session_id = request.session_id;
        if session_id.is_empty()
            || session_id.len() > 256
            || session_id.chars().any(char::is_control)
        {
            return Err(connectrpc::ConnectError::invalid_argument(
                "session_id is invalid",
            ));
        }
        let store = self
            .state
            .store
            .as_ref()
            .context("managed store is unavailable")
            .map_err(|_| {
                connectrpc::ConnectError::failed_precondition("managed proxy sessions are required")
            })?;
        let revoked = store
            .revoke_proxy_session_for_subject(session_id, &identity.subject)
            .await
            .map_err(|error| {
                tracing::error!(%error, "revoke transparent proxy session");
                connectrpc::ConnectError::internal("proxy session is unavailable")
            })?;
        audit_event(
            &self.state,
            &identity.subject,
            "transparent_proxy_session_revoked",
            None,
            Some(session_id),
            None,
        )
        .await
        .map_err(|_| connectrpc::ConnectError::internal("audit persistence unavailable"))?;
        connectrpc::Response::ok(ProxySessionLease {
            session_id: session_id.to_owned(),
            revoked,
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
    github_enabled: bool,
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

#[derive(Template)]
#[template(path = "owner.html")]
struct OwnerTemplate {
    basic_users: Vec<OwnerBasicUser>,
    profiles: Vec<String>,
    principals: Vec<OwnerPrincipal>,
}

struct OwnerBasicUser {
    username: String,
    enabled: bool,
}

struct OwnerPrincipal {
    label: String,
    kind: String,
    subject: String,
    profiles: Vec<String>,
}

#[derive(Deserialize)]
struct BasicUserForm {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct BasicUserEnabledForm {
    username: String,
    enabled: bool,
}

#[derive(Deserialize)]
struct ProfileGrantForm {
    profile: String,
    subject: String,
}

#[derive(Deserialize)]
struct ExternalProfileGrantForm {
    profile: String,
    identity_kind: String,
    identity: String,
}

pub async fn run(config: Config) -> Result<()> {
    let transparent_proxy = config
        .transparent_proxy
        .as_ref()
        .map(|proxy| {
            Ok::<_, anyhow::Error>(Arc::new(TransparentProxyRuntime {
                listen: proxy.listen.clone(),
                proxy_url: proxy.proxy_url.clone(),
                session_ttl: Duration::from_secs(proxy.session_ttl_seconds),
                catalog: TransparentRouteCatalog::from_proxy_routes(&config.proxy_routes)?,
                certificate_authority: ProxyCertificateAuthority::load(
                    std::path::Path::new(&proxy.ca_certificate_file),
                    std::path::Path::new(&proxy.ca_private_key_file),
                )?,
            }))
        })
        .transpose()?;
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
    let github_browser_auth = config
        .auth
        .github
        .as_ref()
        .map(GithubBrowserAuth::new)
        .transpose()?;
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
        github_browser_auth,
        transparent_proxy: transparent_proxy.clone(),
    };
    if let Some(transparent_proxy) = transparent_proxy {
        let listener = TcpListener::bind(&transparent_proxy.listen)
            .await
            .with_context(|| {
                format!(
                    "bind transparent proxy listener {}",
                    transparent_proxy.listen
                )
            })?;
        let listener_state = state.clone();
        tokio::spawn(async move {
            if let Err(error) =
                run_transparent_proxy_listener(listener, listener_state, transparent_proxy).await
            {
                tracing::error!(%error, "transparent proxy listener stopped");
            }
        });
    }
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
        .route("/assets/htmx-2.0.10.min.js", get(ui_htmx))
        .route("/healthz", get(health))
        .route("/readyz", get(health))
        .route("/v1/auth/config", get(auth_config))
        .route("/auth/github/start", get(github_start))
        .route("/auth/github/callback", get(github_callback))
        .route("/auth/github/logout", post(github_logout))
        .route("/v1/status", get(status))
        .route("/v1/profiles", get(profiles))
        .route("/v1/profiles/{profile}/secrets", get(profile_secrets))
        .route("/v1/proxy/{route}/{*path}", any(proxy))
        .route("/ui/session", get(ui_session))
        .route("/ui/owner", get(ui_owner))
        .route("/ui/owner/basic-users", post(ui_upsert_basic_user))
        .route(
            "/ui/owner/basic-users/enabled",
            post(ui_set_basic_user_enabled),
        )
        .route("/ui/owner/grants", post(ui_grant_profile))
        .route("/ui/owner/external-grants", post(ui_grant_external_profile))
        .route("/ui/owner/grants/revoke", post(ui_revoke_profile))
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
        // OAuth authorization codes can appear in a callback query string.
        // Logging only the normalized path keeps credentials out of traces.
        .layer(TraceLayer::new_for_http().make_span_with(|request: &Request| {
            tracing::info_span!("http_request", method = %request.method(), path = request.uri().path())
        }))
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

async fn ui_htmx() -> Response {
    no_store(
        (
            [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
            include_str!("../assets/vendor/htmx-2.0.10.min.js"),
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

async fn github_start(State(state): State<AppState>) -> Response {
    let Some(github) = &state.github_browser_auth else {
        return ui_not_found().await;
    };
    let redirect_uri = github_callback_url(&state.config.public_url);
    let (location, state_token) = match github.start(&redirect_uri).await {
        Ok(value) => value,
        Err(error) => return internal_error(error),
    };
    let cookie = github_state_cookie(&state_token);
    no_store(
        (
            StatusCode::FOUND,
            [(header::LOCATION, location), (header::SET_COOKIE, cookie)],
        )
            .into_response(),
    )
}

async fn github_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<GithubCallback>,
) -> Response {
    let Some(github) = &state.github_browser_auth else {
        return ui_not_found().await;
    };
    let Some(state_token) = query.state.as_deref() else {
        return github_callback_rejected();
    };
    let Some(cookie_state) = cookie_value(&headers, GITHUB_STATE_COOKIE) else {
        return github_callback_rejected();
    };
    if query.error.is_some() || cookie_state != state_token {
        return github_callback_rejected();
    }
    let Some(code) = query.code.as_deref() else {
        return github_callback_rejected();
    };
    let redirect_uri = github_callback_url(&state.config.public_url);
    let identity = match github.finish(state_token, code, &redirect_uri).await {
        Ok(identity) => identity,
        Err(error) => {
            tracing::warn!(%error, "GitHub browser login rejected");
            return github_callback_rejected();
        }
    };
    let session = github.create_session(identity).await;
    github_callback_success(&session)
}

fn github_callback_success(session: &str) -> Response {
    let mut response = no_store((StatusCode::FOUND, [(header::LOCATION, "/")]).into_response());
    // HeaderMap::insert would retain only one Set-Cookie value. Both are
    // necessary: establish the browser session and invalidate OAuth state.
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&github_session_cookie(session))
            .expect("URL-safe browser session is a valid cookie value"),
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_github_state_cookie())
            .expect("cleared state cookie is a valid header value"),
    );
    response
}

async fn github_logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(github) = &state.github_browser_auth
        && let Some(session) = cookie_value(&headers, GITHUB_SESSION_COOKIE)
    {
        github.remove_session(session).await;
    }
    no_store(
        (
            StatusCode::NO_CONTENT,
            [(header::SET_COOKIE, clear_github_session_cookie())],
        )
            .into_response(),
    )
}

async fn ui_session(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let identity = match ui_identity(&state, &headers).await {
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

async fn ui_owner(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = ui_require_owner(&state, &headers).await {
        return response;
    }
    render_owner_panel(&state).await
}

async fn ui_upsert_basic_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<BasicUserForm>,
) -> Response {
    if !is_trusted_browser_origin(&headers, &state.config.public_url) {
        return no_store((StatusCode::FORBIDDEN, "owner request forbidden\n").into_response());
    }
    let identity = match ui_require_owner(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !valid_basic_username(&form.username) {
        return ui_bad_request("invalid Basic username");
    }
    if form.password.len() < 12 || form.password.len() > 1024 {
        return ui_bad_request("Basic passwords must be between 12 and 1024 characters");
    }
    let password_hash =
        match tokio::task::spawn_blocking(move || hash_basic_password(form.password)).await {
            Ok(Ok(hash)) => hash,
            _ => return internal_error(anyhow::anyhow!("password hashing failed")),
        };
    let store = match state.store.as_ref() {
        Some(store) => store,
        None => return ui_not_found().await,
    };
    if let Err(error) = store
        .upsert_basic_user(&form.username, &password_hash)
        .await
    {
        return internal_error(error);
    }
    if let Err(error) = audit_event(
        &state,
        &identity.subject,
        "basic_user_upsert",
        None,
        None,
        Some("managed-ui"),
    )
    .await
    {
        return internal_error(error);
    }
    render_owner_panel(&state).await
}

async fn ui_set_basic_user_enabled(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<BasicUserEnabledForm>,
) -> Response {
    if !is_trusted_browser_origin(&headers, &state.config.public_url) {
        return no_store((StatusCode::FORBIDDEN, "owner request forbidden\n").into_response());
    }
    let identity = match ui_require_owner(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !valid_basic_username(&form.username) {
        return ui_bad_request("invalid Basic username");
    }
    let store = match state.store.as_ref() {
        Some(store) => store,
        None => return ui_not_found().await,
    };
    match store
        .set_basic_user_enabled(&form.username, form.enabled)
        .await
    {
        Ok(true) => {}
        Ok(false) => return ui_bad_request("Basic user not found"),
        Err(error) => return internal_error(error),
    }
    let action = if form.enabled {
        "basic_user_enabled"
    } else {
        "basic_user_disabled"
    };
    if let Err(error) = audit_event(
        &state,
        &identity.subject,
        action,
        None,
        None,
        Some("managed-ui"),
    )
    .await
    {
        return internal_error(error);
    }
    render_owner_panel(&state).await
}

async fn ui_grant_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ProfileGrantForm>,
) -> Response {
    ui_grant_profile_subject(&state, &headers, form).await
}

async fn ui_grant_external_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ExternalProfileGrantForm>,
) -> Response {
    let subject = match external_identity_subject(&form.identity_kind, &form.identity) {
        Ok(subject) => subject,
        Err(error) => return ui_bad_request(error.to_string()),
    };
    ui_grant_profile_subject(
        &state,
        &headers,
        ProfileGrantForm {
            profile: form.profile,
            subject,
        },
    )
    .await
}

async fn ui_grant_profile_subject(
    state: &AppState,
    headers: &HeaderMap,
    form: ProfileGrantForm,
) -> Response {
    if !is_trusted_browser_origin(headers, &state.config.public_url) {
        return no_store((StatusCode::FORBIDDEN, "owner request forbidden\n").into_response());
    }
    let identity = match ui_require_owner(state, headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if let Err(error) = require_known_profile(state, &form.profile) {
        return ui_bad_request(error.to_string());
    }
    if !valid_policy_subject(&form.subject) {
        return ui_bad_request("invalid policy subject");
    }
    let store = match state.store.as_ref() {
        Some(store) => store,
        None => return ui_not_found().await,
    };
    if let Err(error) = store.grant_profile(&form.subject, &form.profile).await {
        return internal_error(error);
    }
    if let Err(error) = audit_event(
        state,
        &identity.subject,
        "profile_grant",
        Some(&form.profile),
        None,
        Some("managed-ui"),
    )
    .await
    {
        return internal_error(error);
    }
    render_owner_panel(state).await
}

async fn ui_revoke_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ProfileGrantForm>,
) -> Response {
    if !is_trusted_browser_origin(&headers, &state.config.public_url) {
        return no_store((StatusCode::FORBIDDEN, "owner request forbidden\n").into_response());
    }
    let identity = match ui_require_owner(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if let Err(error) = require_known_profile(&state, &form.profile) {
        return ui_bad_request(error.to_string());
    }
    if !valid_policy_subject(&form.subject) {
        return ui_bad_request("invalid policy subject");
    }
    let store = match state.store.as_ref() {
        Some(store) => store,
        None => return ui_not_found().await,
    };
    match store.revoke_profile(&form.subject, &form.profile).await {
        Ok(true) => {}
        Ok(false) => return ui_bad_request("profile grant not found"),
        Err(error) => return internal_error(error),
    }
    if let Err(error) = audit_event(
        &state,
        &identity.subject,
        "profile_grant_revoked",
        Some(&form.profile),
        None,
        Some("managed-ui"),
    )
    .await
    {
        return internal_error(error);
    }
    render_owner_panel(&state).await
}

async fn ui_require_owner(
    state: &AppState,
    headers: &HeaderMap,
) -> std::result::Result<crate::auth::Identity, Response> {
    let identity = ui_identity(state, headers).await.map_err(unauthorized)?;
    let Some(store) = state.store.as_ref() else {
        return Err(ui_not_found().await);
    };
    match store.is_owner(&identity.subject).await {
        Ok(true) => Ok(identity),
        Ok(false) => Err(no_store(
            (StatusCode::FORBIDDEN, "owner access required\n").into_response(),
        )),
        Err(error) => Err(internal_error(error)),
    }
}

async fn ui_identity(state: &AppState, headers: &HeaderMap) -> Result<crate::auth::Identity> {
    if let Some(github) = &state.github_browser_auth
        && let Some(session) = cookie_value(headers, GITHUB_SESSION_COOKIE)
        && let Some(identity) = github.session_identity(session).await
    {
        return Ok(identity);
    }
    state.auth.authorize(headers).await
}

fn github_callback_url(public_url: &str) -> String {
    format!("{}/auth/github/callback", public_url.trim_end_matches('/'))
}

fn github_state_cookie(state: &str) -> String {
    format!(
        "{GITHUB_STATE_COOKIE}={state}; Path=/auth/github; HttpOnly; SameSite=Lax; Max-Age={}",
        GITHUB_AUTH_TTL.as_secs()
    )
}

fn clear_github_state_cookie() -> String {
    format!("{GITHUB_STATE_COOKIE}=; Path=/auth/github; HttpOnly; SameSite=Lax; Max-Age=0")
}

fn github_session_cookie(session: &str) -> String {
    format!(
        "{GITHUB_SESSION_COOKIE}={session}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        GITHUB_SESSION_TTL.as_secs()
    )
}

fn clear_github_session_cookie() -> String {
    format!("{GITHUB_SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())?
        .split(';')
        .map(str::trim)
        .find_map(|pair| {
            pair.split_once('=')
                .filter(|(key, _)| *key == name)
                .map(|(_, value)| value)
        })
        .filter(|value| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
}

fn github_callback_rejected() -> Response {
    no_store(
        (
            StatusCode::UNAUTHORIZED,
            [(header::SET_COOKIE, clear_github_state_cookie())],
            "GitHub login was rejected\n",
        )
            .into_response(),
    )
}

async fn render_owner_panel(state: &AppState) -> Response {
    let Some(store) = state.store.as_ref() else {
        return ui_not_found().await;
    };
    let stored_basic_users = match store.list_basic_users().await {
        Ok(users) => users,
        Err(error) => return internal_error(error),
    };
    let profiles: Vec<_> = state.config.profiles.keys().cloned().collect();
    let mut grants_by_subject: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for profile in &profiles {
        let profile_grants = match store.list_profile_grants(profile).await {
            Ok(grants) => grants,
            Err(error) => return internal_error(error),
        };
        for grant in profile_grants {
            grants_by_subject
                .entry(grant.subject)
                .or_default()
                .push(grant.profile);
        }
    }
    let basic_users = stored_basic_users
        .iter()
        .map(|user| OwnerBasicUser {
            username: user.username.clone(),
            enabled: user.enabled,
        })
        .collect();
    let mut principals = Vec::new();
    for user in stored_basic_users {
        let subject = format!("basic:{}", user.username);
        let profiles = grants_by_subject.remove(&subject).unwrap_or_default();
        principals.push(OwnerPrincipal {
            label: user.username,
            kind: "Basic account".into(),
            subject,
            profiles,
        });
    }
    principals.extend(grants_by_subject.into_iter().map(|(subject, profiles)| {
        let (label, kind) = display_principal(&subject);
        OwnerPrincipal {
            label,
            kind,
            subject,
            profiles,
        }
    }));
    match (OwnerTemplate {
        basic_users,
        profiles,
        principals,
    })
    .render()
    {
        Ok(page) => no_store(Html(page).into_response()),
        Err(error) => {
            tracing::error!(%error, "render managed owner UI");
            no_store((StatusCode::INTERNAL_SERVER_ERROR, "UI unavailable\n").into_response())
        }
    }
}

fn display_principal(subject: &str) -> (String, String) {
    if let Some(username) = subject.strip_prefix("basic:") {
        return (username.to_owned(), "Basic account".into());
    }
    if let Some(account_id) = subject.strip_prefix("github:") {
        return (format!("GitHub account #{account_id}"), "GitHub".into());
    }
    ("OIDC identity".into(), "OIDC".into())
}

fn ui_bad_request(message: impl AsRef<str>) -> Response {
    no_store((StatusCode::BAD_REQUEST, format!("{}\n", message.as_ref())).into_response())
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
        github_enabled: matches!(config.auth.mode, AuthMode::GithubOrBasic),
        basic_enabled: matches!(
            config.auth.mode,
            AuthMode::Basic | AuthMode::OidcOrBasic | AuthMode::GithubOrBasic
        ),
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

async fn run_transparent_proxy_listener(
    listener: TcpListener,
    state: AppState,
    runtime: Arc<TransparentProxyRuntime>,
) -> Result<()> {
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .context("accept transparent proxy connection")?;
        let state = state.clone();
        let runtime = runtime.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_transparent_proxy_connection(stream, state, runtime).await {
                tracing::debug!(%peer, %error, "transparent proxy connection ended");
            }
        });
    }
}

async fn serve_transparent_proxy_connection(
    stream: TcpStream,
    state: AppState,
    runtime: Arc<TransparentProxyRuntime>,
) -> Result<()> {
    let service = service_fn(move |request| {
        let state = state.clone();
        let runtime = runtime.clone();
        async move { Ok::<_, Infallible>(transparent_connect_response(request, state, runtime).await) }
    });
    http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await
        .context("serve transparent proxy HTTP connection")
}

async fn transparent_connect_response(
    mut request: HyperRequest<Incoming>,
    state: AppState,
    runtime: Arc<TransparentProxyRuntime>,
) -> HyperResponse<Empty<Bytes>> {
    // The private listener is not an Internet service, but a compromised
    // in-cluster workload must still not be able to exhaust AV's session or
    // TLS work. Share the bounded application token bucket with the control
    // plane rather than leaving CONNECT unmetered.
    if !state.api_rate_limiter.try_acquire().await {
        return transparent_response(StatusCode::TOO_MANY_REQUESTS, "proxy rate limit exceeded\n");
    }
    if request
        .headers()
        .get(header::CONTENT_LENGTH)
        .is_some_and(|value| value != "0")
    {
        return transparent_response(StatusCode::BAD_REQUEST, "CONNECT must not include a body\n");
    }
    let authorized = match authorize_connect_request(
        request.method(),
        request.uri(),
        request.headers(),
        &runtime.catalog,
    ) {
        Ok(authorized) => authorized,
        Err(error) => {
            tracing::warn!(%error, "transparent proxy CONNECT denied");
            return transparent_response(StatusCode::FORBIDDEN, "proxy request forbidden\n");
        }
    };
    let Some(store) = &state.store else {
        return transparent_proxy_auth_required();
    };
    let session = match store.active_proxy_session(&authorized.token_hash).await {
        Ok(Some(session)) => session,
        Ok(None) => return transparent_proxy_auth_required(),
        Err(error) => {
            tracing::error!(%error, "read transparent proxy session");
            return transparent_response(StatusCode::SERVICE_UNAVAILABLE, "proxy unavailable\n");
        }
    };
    let Some(route) = state.config.proxy_routes.get(&authorized.route_name) else {
        return transparent_response(StatusCode::FORBIDDEN, "proxy request forbidden\n");
    };
    if session.profile != route.profile {
        return transparent_response(StatusCode::FORBIDDEN, "proxy request forbidden\n");
    }
    match profile_permitted(&state, &session.subject, &session.profile).await {
        Ok(true) => {}
        Ok(false) => {
            return transparent_response(StatusCode::FORBIDDEN, "proxy request forbidden\n");
        }
        Err(error) => {
            tracing::error!(%error, "check transparent proxy grant");
            return transparent_response(StatusCode::SERVICE_UNAVAILABLE, "proxy unavailable\n");
        }
    }
    let host = authorized.host.clone();
    let upgraded = hyper::upgrade::on(&mut request);
    let state_for_tunnel = state.clone();
    let runtime_for_tunnel = runtime.clone();
    let route_name = authorized.route_name.clone();
    let token_hash = authorized.token_hash;
    let session_id = session.session_id.clone();
    tokio::spawn(async move {
        match upgraded.await {
            Ok(upgraded) => {
                if let Err(error) = serve_transparent_tls_tunnel(
                    upgraded,
                    state_for_tunnel,
                    runtime_for_tunnel,
                    route_name,
                    host,
                    token_hash,
                    session_id,
                )
                .await
                {
                    tracing::debug!(%error, "transparent proxy TLS tunnel ended");
                }
            }
            Err(error) => tracing::debug!(%error, "transparent proxy CONNECT upgrade failed"),
        }
    });
    if let Err(error) = audit_event(
        &state,
        &session.subject,
        "transparent_proxy_connect",
        Some(&session.profile),
        Some(&authorized.route_name),
        None,
    )
    .await
    {
        tracing::error!(%error, "record transparent proxy CONNECT audit event");
        return transparent_response(StatusCode::SERVICE_UNAVAILABLE, "proxy unavailable\n");
    }
    transparent_response(StatusCode::OK, "")
}

async fn serve_transparent_tls_tunnel(
    upgraded: hyper::upgrade::Upgraded,
    state: AppState,
    runtime: Arc<TransparentProxyRuntime>,
    route_name: String,
    host: String,
    token_hash: [u8; 32],
    session_id: String,
) -> Result<()> {
    let leaf = runtime.certificate_authority.issue_leaf(&host)?;
    let tls = tokio_rustls::TlsAcceptor::from(Arc::new(leaf.server_config()?))
        .accept(TokioIo::new(upgraded))
        .await
        .context("accept transparent proxy TLS")?;
    let service = service_fn(move |request| {
        let state = state.clone();
        let route_name = route_name.clone();
        let token_hash = token_hash;
        let session_id = session_id.clone();
        async move {
            Ok::<_, Infallible>(
                transparent_tunnel_response(request, state, route_name, token_hash, session_id)
                    .await,
            )
        }
    });
    http1::Builder::new()
        .serve_connection(TokioIo::new(tls), service)
        .await
        .context("serve transparent proxy TLS request")
}

async fn transparent_tunnel_response(
    request: HyperRequest<Incoming>,
    state: AppState,
    route_name: String,
    token_hash: [u8; 32],
    session_id: String,
) -> HyperResponse<Full<Bytes>> {
    if !state.api_rate_limiter.try_acquire().await {
        return transparent_full_response(
            StatusCode::TOO_MANY_REQUESTS,
            "proxy rate limit exceeded\n",
        );
    }
    let Some(store) = &state.store else {
        return transparent_full_response(
            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            "proxy authentication required\n",
        );
    };
    let session = match store.active_proxy_session(&token_hash).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return transparent_full_response(
                StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                "proxy authentication required\n",
            );
        }
        Err(error) => {
            tracing::error!(%error, "read transparent proxy tunnel session");
            return transparent_full_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "proxy unavailable\n",
            );
        }
    };
    let Some(route) = state.config.proxy_routes.get(&route_name) else {
        return transparent_full_response(StatusCode::FORBIDDEN, "proxy request forbidden\n");
    };
    if session.session_id != session_id || session.profile != route.profile {
        return transparent_full_response(StatusCode::FORBIDDEN, "proxy request forbidden\n");
    }
    match profile_permitted(&state, &session.subject, &session.profile).await {
        Ok(true) => {}
        Ok(false) => {
            return transparent_full_response(StatusCode::FORBIDDEN, "proxy request forbidden\n");
        }
        Err(error) => {
            tracing::error!(%error, "check transparent proxy tunnel grant");
            return transparent_full_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "proxy unavailable\n",
            );
        }
    }
    let (parts, body) = request.into_parts();
    if let Err(error) = enforce_transparent_tunnel_target(route, &parts.uri, &parts.headers) {
        tracing::warn!(%error, route = route_name, "transparent proxy request target denied");
        return transparent_full_response(StatusCode::FORBIDDEN, "proxy request forbidden\n");
    }
    let normalized_path = match enforce_proxy_policy(route, parts.uri.path(), &parts.method) {
        Ok(path) => path,
        Err(error) => {
            tracing::warn!(%error, route = route_name, "transparent proxy request denied by route policy");
            return transparent_full_response(StatusCode::FORBIDDEN, "proxy request forbidden\n");
        }
    };
    let body = match collect_transparent_body(body, route.max_body_bytes).await {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(%error, route = route_name, "transparent proxy request body rejected");
            return transparent_full_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "proxy request is too large\n",
            );
        }
    };
    if let Err(error) = enforce_proxy_content_type(route, &parts.headers, body.len()) {
        tracing::warn!(%error, route = route_name, "transparent proxy content type rejected");
        return transparent_full_response(StatusCode::FORBIDDEN, "proxy request forbidden\n");
    }
    let query = match validate_proxy_query(route, parts.uri.query()) {
        Ok(query) => query,
        Err(error) => {
            tracing::warn!(%error, route = route_name, "transparent proxy query rejected");
            return transparent_full_response(StatusCode::FORBIDDEN, "proxy request forbidden\n");
        }
    };
    let response = match proxy_request(
        &state,
        route,
        &normalized_path,
        &query,
        parts.method,
        parts.headers,
        body,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(%error, route = route_name, "transparent proxy upstream request failed");
            return transparent_full_response(StatusCode::BAD_GATEWAY, "proxy request failed\n");
        }
    };
    if let Err(error) = audit_event(
        &state,
        &session.subject,
        "transparent_proxy_request",
        Some(&session.profile),
        Some(&route_name),
        None,
    )
    .await
    {
        tracing::error!(%error, "record transparent proxy request audit event");
        return transparent_full_response(StatusCode::SERVICE_UNAVAILABLE, "proxy unavailable\n");
    }
    let (parts, body) = response.into_parts();
    let body = match axum::body::to_bytes(body, 4 * 1024 * 1024).await {
        Ok(body) => body,
        Err(error) => {
            tracing::error!(%error, "read bounded transparent proxy response");
            return transparent_full_response(StatusCode::BAD_GATEWAY, "proxy request failed\n");
        }
    };
    let mut response = HyperResponse::builder().status(parts.status);
    for (name, value) in &parts.headers {
        response = response.header(name, value);
    }
    response.body(Full::new(body)).unwrap_or_else(|_| {
        transparent_full_response(StatusCode::BAD_GATEWAY, "proxy request failed\n")
    })
}

async fn collect_transparent_body(mut body: Incoming, maximum: usize) -> Result<Bytes> {
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.context("read transparent proxy request body")?;
        if let Ok(data) = frame.into_data() {
            if bytes.len().saturating_add(data.len()) > maximum {
                bail!("transparent proxy request body is too large");
            }
            bytes.extend_from_slice(&data);
        }
    }
    Ok(Bytes::from(bytes))
}

fn transparent_proxy_auth_required() -> HyperResponse<Empty<Bytes>> {
    HyperResponse::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header(header::PROXY_AUTHENTICATE, "Bearer")
        .body(Empty::new())
        .expect("constant transparent proxy authentication response")
}

fn transparent_response(status: StatusCode, message: &str) -> HyperResponse<Empty<Bytes>> {
    let _ = message;
    HyperResponse::builder()
        .status(status)
        .body(Empty::new())
        .expect("constant transparent proxy response")
}

fn transparent_full_response(status: StatusCode, message: &str) -> HyperResponse<Full<Bytes>> {
    HyperResponse::builder()
        .status(status)
        .body(Full::new(Bytes::copy_from_slice(message.as_bytes())))
        .expect("constant transparent proxy response")
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

/// The TLS tunnel is already bound to a catalog host by CONNECT. Repeat that
/// check on the decrypted HTTP request so a client cannot smuggle a different
/// target through an absolute-form URI, Host header, or nested proxy auth.
/// Any allowed caller headers are later copied by `proxy_request`; everything
/// else is dropped rather than forwarded to the provider.
fn enforce_transparent_tunnel_target(
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
    if headers
        .get_all(header::PROXY_AUTHORIZATION)
        .iter()
        .next()
        .is_some()
    {
        bail!("transparent tunnel must not contain proxy authorization");
    }
    let configured =
        url::Url::parse(&route.base_url).context("transparent route base URL disappeared")?;
    let supplied_host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .context("transparent tunnel Host header is invalid")?;
    let supplied = url::Url::parse(&format!("https://{supplied_host}"))
        .context("transparent tunnel Host header is malformed")?;
    if supplied.username() != ""
        || supplied.password().is_some()
        || supplied.port_or_known_default() != Some(443)
        || supplied.host_str() != configured.host_str()
    {
        bail!("transparent tunnel Host does not match its configured route");
    }
    Ok(())
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
    use crate::{
        config::{
            AuthConfig, BasicUserConfig, ConnectorConfig, ManagedConfig, TransparentProxyConfig,
        },
        connector::Connector,
        transparent_proxy::{mint_proxy_session_credential, proxy_session_token_hash},
    };
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
    use rustls::{
        ClientConfig, RootCertStore, ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    };
    use std::{collections::BTreeMap, sync::Arc};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

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

    async fn transparent_test_context() -> (
        AppState,
        Arc<TransparentProxyRuntime>,
        Store,
        String,
        Vec<u8>,
    ) {
        let directory = tempfile::tempdir().unwrap();
        // Keep the fixture directory alive for the test process. The database
        // pool has opened it before this intentional leak; its contents are
        // synthetic and the operating system removes it at process exit.
        let directory = Box::leak(Box::new(directory));
        let database = directory.path().join("av.sqlite");
        let database_url_file = directory.path().join("database-url");
        std::fs::write(&database_url_file, format!("sqlite:{}", database.display())).unwrap();
        let store = Store::connect(&ManagedConfig {
            database_url_file: database_url_file.display().to_string(),
            initial_owner_oidc_subject: "basic:operator".into(),
        })
        .await
        .unwrap();
        store
            .grant_profile("basic:operator", "infra")
            .await
            .unwrap();
        let credential = mint_proxy_session_credential();
        let token = credential.token.to_string();
        store
            .create_proxy_session(
                &credential.session_id,
                &credential.token_hash,
                "basic:operator",
                "infra",
                (SystemTime::now() + Duration::from_secs(60))
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .try_into()
                    .unwrap(),
            )
            .await
            .unwrap();

        let mut ca_params = CertificateParams::new(vec!["av-test-ca".into()]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_certificate_file = directory.path().join("ca.crt");
        let ca_private_key_file = directory.path().join("ca.key");
        std::fs::write(&ca_certificate_file, ca_cert.pem()).unwrap();
        std::fs::write(&ca_private_key_file, ca_key.serialize_pem()).unwrap();

        let mut profiles = BTreeMap::new();
        profiles.insert(
            "infra".into(),
            ProfileConfig {
                connector: "unused".into(),
                project_id: "project".into(),
                environment: "dev".into(),
                secret_path: "/".into(),
                allowed_keys: vec![],
            },
        );
        let route = proxy_route(&["GET"], &["/v1/"]);
        let mut routes = BTreeMap::new();
        routes.insert("provider".into(), route);
        let config = Config {
            listen: "127.0.0.1:0".into(),
            public_url: "http://127.0.0.1:14322".into(),
            mode: ConfigMode::Managed,
            managed: Some(ManagedConfig {
                database_url_file: database_url_file.display().to_string(),
                initial_owner_oidc_subject: "basic:operator".into(),
            }),
            auth: AuthConfig {
                mode: AuthMode::Basic,
                issuer: String::new(),
                client_id: String::new(),
                audiences: vec![],
                scopes: vec![],
                signing_algorithms: vec![],
                allowed_groups: vec![],
                group_claim: "groups".into(),
                basic_users: Vec::<BasicUserConfig>::new(),
                github: None,
            },
            connectors: BTreeMap::new(),
            profiles,
            proxy_routes: routes.clone(),
            transparent_proxy: Some(TransparentProxyConfig {
                listen: "127.0.0.1:0".into(),
                proxy_url: "http://127.0.0.1:1".into(),
                ca_certificate_file: ca_certificate_file.display().to_string(),
                ca_private_key_file: ca_private_key_file.display().to_string(),
                session_ttl_seconds: 60,
            }),
            max_connector_concurrency: 1,
            api_rate_limit_per_second: 10,
            api_rate_limit_burst: 10,
        };
        let state = AppState {
            config: Arc::new(config.clone()),
            auth: Authenticator::new(config.auth.clone(), Some(store.clone()))
                .await
                .unwrap(),
            connectors: Arc::new(BTreeMap::new()),
            connector_slots: Arc::new(Semaphore::new(1)),
            api_rate_limiter: ApiRateLimiter::new(10, 10),
            proxy_client: reqwest::Client::builder().build().unwrap(),
            store: Some(store.clone()),
            github_browser_auth: None,
            transparent_proxy: None,
        };
        let runtime = Arc::new(TransparentProxyRuntime {
            listen: "127.0.0.1:0".into(),
            proxy_url: "http://127.0.0.1:1".into(),
            session_ttl: Duration::from_secs(60),
            catalog: TransparentRouteCatalog::from_proxy_routes(&routes).unwrap(),
            certificate_authority: ProxyCertificateAuthority::load(
                &ca_certificate_file,
                &ca_private_key_file,
            )
            .unwrap(),
        });
        (state, runtime, store, token, ca_cert.der().to_vec())
    }

    async fn serve_one_transparent_connection(
        state: AppState,
        runtime: Arc<TransparentProxyRuntime>,
    ) -> (TcpStream, tokio::task::JoinHandle<Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_transparent_proxy_connection(stream, state, runtime).await
        });
        (TcpStream::connect(address).await.unwrap(), task)
    }

    async fn raw_connect(stream: &mut TcpStream, authority: &str, token: &str) -> Vec<u8> {
        stream
            .write_all(
                format!(
                    "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Bearer {token}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = stream.read(&mut chunk).await.unwrap();
            assert!(read > 0, "proxy closed before an HTTP response");
            response.extend_from_slice(&chunk[..read]);
            if response.windows(4).any(|window| window == b"\r\n\r\n") {
                return response;
            }
        }
    }

    async fn read_test_http_header<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 2048];
        loop {
            let read = stream.read(&mut chunk).await.unwrap();
            assert!(read > 0, "connection closed before HTTP headers");
            bytes.extend_from_slice(&chunk[..read]);
            assert!(bytes.len() <= 32 * 1024, "HTTP test headers exceeded bound");
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                return bytes;
            }
        }
    }

    fn test_upstream_tls_config() -> (ServerConfig, Vec<u8>) {
        crate::proxy_ca::install_rustls_provider().unwrap();
        let mut ca_params = CertificateParams::new(vec!["upstream-test-ca".into()]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().unwrap();
        let ca_certificate = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["api.example.com".into()])
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(leaf.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
            )
            .unwrap();
        (config, ca_certificate.der().to_vec())
    }

    #[tokio::test]
    async fn transparent_tls_enforces_policy_injects_only_provider_auth_and_redacts_response() {
        let (mut state, runtime, _store, token, proxy_ca_der) = transparent_test_context().await;
        let secrets_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let secrets_address = secrets_listener.local_addr().unwrap();
        let secret_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(secret_file.path(), "connector-test-token\n").unwrap();
        let connector_config: ConnectorConfig = serde_json::from_value(serde_json::json!({
            "base_url": format!("http://{secrets_address}"),
            "auth": {"type": "token", "token_file": secret_file.path()},
        }))
        .unwrap();
        let connector = Connector::new(connector_config, true).unwrap();
        state.connectors = Arc::new(BTreeMap::from([("unused".to_owned(), connector)]));
        let secrets_task = tokio::spawn(async move {
            let (mut stream, _) = secrets_listener.accept().await.unwrap();
            let request = read_test_http_header(&mut stream).await;
            assert!(request.starts_with(b"GET /api/v3/secrets/raw?"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 76\r\nConnection: close\r\n\r\n{\"secrets\":[{\"secretKey\":\"API_TOKEN\",\"secretValue\":\"upstream-test-secret\"}]}" )
                .await
                .unwrap();
        });

        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream_listener.local_addr().unwrap();
        let (upstream_config, upstream_ca_der) = test_upstream_tls_config();
        state.proxy_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(reqwest::Certificate::from_der(&upstream_ca_der).unwrap())
            .resolve("api.example.com", upstream_address)
            .build()
            .unwrap();
        let (upstream_request_sent, upstream_request_received) = tokio::sync::oneshot::channel();
        let upstream_task = tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let mut stream = TlsAcceptor::from(Arc::new(upstream_config))
                .accept(stream)
                .await
                .unwrap();
            let request = read_test_http_header(&mut stream).await;
            upstream_request_sent.send(request).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 31\r\nConnection: close\r\n\r\n{\"echo\":\"upstream-test-secret\"}")
                .await
                .unwrap();
        });

        let (mut proxy, proxy_task) =
            serve_one_transparent_connection(state.clone(), runtime.clone()).await;
        assert!(
            raw_connect(&mut proxy, "api.example.com:443", &token)
                .await
                .starts_with(b"HTTP/1.1 200")
        );
        let mut proxy_roots = RootCertStore::empty();
        proxy_roots
            .add(CertificateDer::from(proxy_ca_der.clone()))
            .unwrap();
        let tls = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(proxy_roots)
                .with_no_client_auth(),
        ));
        let mut tunnel = tls
            .connect(ServerName::try_from("api.example.com").unwrap(), proxy)
            .await
            .unwrap();
        tunnel
            .write_all(b"GET /v1/allowed?source=transparent-test HTTP/1.1\r\nHost: api.example.com\r\nAccept: application/json\r\nAuthorization: Bearer caller-controlled\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tunnel.read_to_end(&mut response).await.unwrap();
        assert!(
            response.starts_with(b"HTTP/1.1 200"),
            "unexpected transparent response status: {}",
            String::from_utf8_lossy(&response)
                .lines()
                .next()
                .unwrap_or("<no response>")
        );
        assert!(
            !response
                .windows(b"upstream-test-secret".len())
                .any(|window| window == b"upstream-test-secret")
        );
        assert!(
            response
                .windows(b"[REDACTED]".len())
                .any(|window| window == b"[REDACTED]")
        );

        let upstream_request = upstream_request_received.await.unwrap();
        let upstream_request = std::str::from_utf8(&upstream_request).unwrap();
        let canonical_upstream_request = upstream_request.to_ascii_lowercase();
        assert!(
            upstream_request.starts_with("GET /v1/allowed?source=transparent-test HTTP/1.1\r\n")
        );
        assert!(
            canonical_upstream_request.contains("authorization: bearer upstream-test-secret\r\n")
        );
        assert!(!upstream_request.contains("caller-controlled"));

        proxy_task.await.unwrap().unwrap();
        upstream_task.await.unwrap();
        secrets_task.await.unwrap();

        let (mut denied_proxy, denied_task) =
            serve_one_transparent_connection(state, runtime).await;
        assert!(
            raw_connect(&mut denied_proxy, "api.example.com:443", &token)
                .await
                .starts_with(b"HTTP/1.1 200")
        );
        let mut denied_roots = RootCertStore::empty();
        denied_roots
            .add(CertificateDer::from(proxy_ca_der))
            .unwrap();
        let denied_tls = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(denied_roots)
                .with_no_client_auth(),
        ));
        let mut denied_tunnel = denied_tls
            .connect(
                ServerName::try_from("api.example.com").unwrap(),
                denied_proxy,
            )
            .await
            .unwrap();
        denied_tunnel
            .write_all(b"GET /v1/allowed HTTP/1.1\r\nHost: api.example.com\r\nProxy-Authorization: Bearer caller-controlled\r\n\r\n")
            .await
            .unwrap();
        let denied_response = read_test_http_header(&mut denied_tunnel).await;
        assert!(denied_response.starts_with(b"HTTP/1.1 403"));
        drop(denied_tunnel);
        denied_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn raw_tcp_connect_denies_unknown_destinations_and_honors_live_revocation() {
        let (state, runtime, store, token, ca_der) = transparent_test_context().await;

        let (mut unknown, task) =
            serve_one_transparent_connection(state.clone(), runtime.clone()).await;
        assert!(
            raw_connect(&mut unknown, "unknown.example.test:443", &token)
                .await
                .starts_with(b"HTTP/1.1 403")
        );
        drop(unknown);
        task.await.unwrap().unwrap();

        let (mut invalid, task) =
            serve_one_transparent_connection(state.clone(), runtime.clone()).await;
        assert!(
            raw_connect(&mut invalid, "api.example.com:443", "wrong-token")
                .await
                .starts_with(b"HTTP/1.1 407")
        );
        drop(invalid);
        task.await.unwrap().unwrap();

        let (mut allowed, task) =
            serve_one_transparent_connection(state.clone(), runtime.clone()).await;
        assert!(
            raw_connect(&mut allowed, "api.example.com:443", &token)
                .await
                .starts_with(b"HTTP/1.1 200")
        );
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(ca_der)).unwrap();
        let tls = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        let tls_stream = tls
            .connect(ServerName::try_from("api.example.com").unwrap(), allowed)
            .await
            .unwrap();
        drop(tls_stream);
        task.await.unwrap().unwrap();

        store
            .revoke_profile("basic:operator", "infra")
            .await
            .unwrap();
        let (mut revoked_grant, task) =
            serve_one_transparent_connection(state.clone(), runtime.clone()).await;
        assert!(
            raw_connect(&mut revoked_grant, "api.example.com:443", &token)
                .await
                .starts_with(b"HTTP/1.1 403")
        );
        drop(revoked_grant);
        task.await.unwrap().unwrap();

        let active = store
            .active_proxy_session(&proxy_session_token_hash(token.as_bytes()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(active.subject, "basic:operator");
        store
            .revoke_proxy_session(&active.session_id)
            .await
            .unwrap();
        let (mut revoked_session, task) = serve_one_transparent_connection(state, runtime).await;
        assert!(
            raw_connect(&mut revoked_session, "api.example.com:443", &token)
                .await
                .starts_with(b"HTTP/1.1 407")
        );
        drop(revoked_session);
        task.await.unwrap().unwrap();
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
    fn transparent_tunnel_binds_decrypted_request_to_connect_host() {
        let route = proxy_route(&["GET"], &["/v1/"]);
        let uri = "/v1/allowed".parse::<Uri>().unwrap();
        let mut valid_headers = HeaderMap::new();
        valid_headers.insert(header::HOST, HeaderValue::from_static("api.example.com"));
        assert!(enforce_transparent_tunnel_target(&route, &uri, &valid_headers).is_ok());

        let mut wrong_host = valid_headers.clone();
        wrong_host.insert(header::HOST, HeaderValue::from_static("other.example.com"));
        assert!(enforce_transparent_tunnel_target(&route, &uri, &wrong_host).is_err());

        let mut nested_proxy_auth = valid_headers;
        nested_proxy_auth.insert(
            header::PROXY_AUTHORIZATION,
            HeaderValue::from_static("Bearer caller-controlled"),
        );
        assert!(enforce_transparent_tunnel_target(&route, &uri, &nested_proxy_auth).is_err());

        let absolute = "https://api.example.com/v1/allowed".parse::<Uri>().unwrap();
        let mut absolute_headers = HeaderMap::new();
        absolute_headers.insert(header::HOST, HeaderValue::from_static("api.example.com"));
        assert!(enforce_transparent_tunnel_target(&route, &absolute, &absolute_headers).is_err());
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
                github_enabled: false,
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

    #[test]
    fn owner_ui_escapes_principal_labels_and_usernames() {
        let page = OwnerTemplate {
            basic_users: vec![OwnerBasicUser {
                username: "<script>user</script>".into(),
                enabled: true,
            }],
            profiles: vec!["<script>profile</script>".into()],
            principals: vec![OwnerPrincipal {
                label: "<script>identity</script>".into(),
                kind: "OIDC".into(),
                subject: "<script>subject</script>".into(),
                profiles: vec!["<script>profile</script>".into()],
            }],
        }
        .render()
        .unwrap();
        assert!(page.contains("&#60;script&#62;user&#60;/script&#62;"));
        assert!(page.contains("&#60;script&#62;identity&#60;/script&#62;"));
        assert!(page.contains("&#60;script&#62;subject&#60;/script&#62;"));
        assert!(!page.contains("<script>subject</script>"));
    }

    #[test]
    fn external_identity_grants_use_canonical_subjects_and_friendly_labels() {
        assert_eq!(
            external_identity_subject("github", " 12345 ").unwrap(),
            "github:12345"
        );
        assert!(external_identity_subject("github", "not-a-number").is_err());
        assert_eq!(
            external_identity_subject("oidc", "zitadel-subject").unwrap(),
            "zitadel-subject"
        );
        assert!(external_identity_subject("oidc", "basic:operator").is_err());
        assert_eq!(
            display_principal("github:12345"),
            ("GitHub account #12345".into(), "GitHub".into())
        );
    }

    #[tokio::test]
    async fn application_rate_limiter_enforces_its_burst_capacity() {
        let limiter = ApiRateLimiter::new(1, 2);
        assert!(limiter.try_acquire().await);
        assert!(limiter.try_acquire().await);
        assert!(!limiter.try_acquire().await);
    }

    #[tokio::test]
    async fn github_start_uses_pkce_and_never_puts_the_client_secret_in_the_redirect() {
        let directory = tempfile::tempdir().unwrap();
        let secret_file = directory.path().join("github-client-secret");
        std::fs::write(&secret_file, "synthetic-client-secret\n").unwrap();
        let github = GithubBrowserAuth::new(&GithubAuthConfig {
            client_id: "synthetic-client-id".into(),
            client_secret_file: secret_file.display().to_string(),
            allowed_user_ids: vec![12345],
            allowed_organizations: vec![],
        })
        .unwrap();
        let (redirect, state) = github
            .start("http://127.0.0.1:14322/auth/github/callback")
            .await
            .unwrap();
        let redirect = url::Url::parse(&redirect).unwrap();
        assert_eq!(
            redirect.as_str().split('?').next(),
            Some(GITHUB_AUTHORIZATION_ENDPOINT)
        );
        let query: BTreeMap<_, _> = redirect.query_pairs().into_owned().collect();
        assert_eq!(query.get("client_id"), Some(&"synthetic-client-id".into()));
        assert_eq!(query.get("state"), Some(&state));
        assert_eq!(query.get("code_challenge_method"), Some(&"S256".into()));
        assert!(
            query
                .get("code_challenge")
                .is_some_and(|value| value.len() >= 43)
        );
        assert!(!redirect.as_str().contains("synthetic-client-secret"));
        assert!(github_state_cookie(&state).contains("HttpOnly; SameSite=Lax"));
        assert!(github_session_cookie("session").contains("HttpOnly; SameSite=Lax"));

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("{GITHUB_STATE_COOKIE}={state}")).unwrap(),
        );
        assert_eq!(
            cookie_value(&headers, GITHUB_STATE_COOKIE),
            Some(state.as_str())
        );
    }

    #[tokio::test]
    async fn github_organization_policy_requests_membership_scope() {
        let github = GithubBrowserAuth {
            client_id: "synthetic-client-id".into(),
            client_secret: Arc::new(Zeroizing::new("synthetic-client-secret".into())),
            allowed_user_ids: BTreeSet::new(),
            allowed_organizations: ["example-org".to_owned()].into_iter().collect(),
            client: reqwest::Client::new(),
            pending: Arc::new(Mutex::new(BTreeMap::new())),
            sessions: Arc::new(Mutex::new(BTreeMap::new())),
        };
        let (redirect, _) = github
            .start("http://127.0.0.1:14322/auth/github/callback")
            .await
            .unwrap();
        let redirect = url::Url::parse(&redirect).unwrap();
        let query: BTreeMap<_, _> = redirect.query_pairs().into_owned().collect();
        assert_eq!(query.get("scope"), Some(&"read:user read:org".into()));
        assert_eq!(
            github_organization_membership_endpoint("example-org"),
            "https://api.github.com/user/memberships/orgs/example-org"
        );
    }

    #[test]
    fn browser_tokens_are_safe_for_urls_and_strict_cookie_parsing() {
        for _ in 0..16 {
            let token = random_browser_token();
            assert_eq!(token.len(), 43);
            assert!(
                token
                    .bytes()
                    .all(|byte| { byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' })
            );

            let mut headers = HeaderMap::new();
            headers.insert(
                header::COOKIE,
                HeaderValue::from_str(&format!("{GITHUB_SESSION_COOKIE}={token}")).unwrap(),
            );
            assert_eq!(
                cookie_value(&headers, GITHUB_SESSION_COOKIE),
                Some(token.as_str())
            );
        }
    }

    #[test]
    fn successful_github_callback_sets_session_and_clears_oauth_state() {
        let response = github_callback_success("session-token");
        assert_eq!(response.status(), StatusCode::FOUND);
        let cookies: Vec<_> = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        assert_eq!(cookies.len(), 2);
        assert!(
            cookies
                .iter()
                .any(|cookie| cookie.starts_with("av_github_session=session-token;"))
        );
        assert!(
            cookies
                .iter()
                .any(|cookie| cookie.starts_with("av_github_state=;"))
        );
    }

    #[test]
    fn github_browser_auth_allows_only_configured_immutable_account_ids() {
        let github = GithubBrowserAuth {
            client_id: "synthetic-client-id".into(),
            client_secret: Arc::new(Zeroizing::new("synthetic-client-secret".into())),
            allowed_user_ids: [12345].into_iter().collect(),
            allowed_organizations: BTreeSet::new(),
            client: reqwest::Client::new(),
            pending: Arc::new(Mutex::new(BTreeMap::new())),
            sessions: Arc::new(Mutex::new(BTreeMap::new())),
        };
        assert!(github.allowed_user_ids.contains(&12345));
        assert!(!github.allowed_user_ids.contains(&67890));
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
