use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    io,
    net::{IpAddr, Ipv4Addr},
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
use futures_util::{SinkExt, StreamExt, stream};
use http_body_util::{BodyExt, Empty};
use hyper::{
    Request as HyperRequest, Response as HyperResponse, body::Incoming, server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream, lookup_host},
    sync::{Mutex, Semaphore},
    time::Instant,
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Message,
        handshake::derive_accept_key,
        protocol::{Role, WebSocketConfig},
    },
};
use tower_http::{set_header::SetResponseHeaderLayer, trace::TraceLayer};
use zeroize::Zeroizing;

use crate::{
    auth::Authenticator,
    av::v1::{
        Agent as RpcAgent, AgentCredential, AuditEvent as RpcAuditEvent,
        AuthConfig as RpcAuthConfig, BasicUser as RpcBasicUser, Connector as RpcConnector,
        ControlService, ControlServiceExt, CreateAgentRequest, CreateProxySessionRequest,
        DeleteAgentRequest, EnvironmentValue, GetAuthConfigRequest, GetProfileEnvironmentRequest,
        GetStatusRequest, GrantProfileRequest, ListAgentsRequest, ListAgentsResponse,
        ListAuditEventsRequest, ListAuditEventsResponse, ListBasicUsersRequest,
        ListBasicUsersResponse, ListPrincipalRolesRequest, ListPrincipalRolesResponse,
        ListProfileGrantsRequest, ListProfileGrantsResponse, ListProfilesRequest,
        ListProfilesResponse, ListProxyDestinationsRequest, ListProxyDestinationsResponse,
        PrincipalRole as RpcPrincipalRole, Profile as RpcProfile, ProfileEnvironment,
        ProfileEnvironmentLease, ProfileGrant as RpcProfileGrant,
        ProxyDestination as RpcProxyDestination, ProxySessionLease,
        RenewProfileEnvironmentLeaseRequest, RenewProxySessionRequest,
        RevokeProfileEnvironmentLeaseRequest, RevokeProfileRequest, RevokeProxySessionRequest,
        RotateAgentRequest, SessionService, SessionServiceExt, SetAgentEnabledRequest,
        SetBasicUserEnabledRequest, SetPrincipalRoleRequest, Status as RpcStatus,
        UpsertBasicUserRequest,
    },
    config::{
        AuthMode, Config, ConfigMode, GithubAuthConfig, ProfileConfig, ProxyInjectionConfig,
        ProxyResponseMode, ProxyRouteConfig, ProxyWebSocketConfig,
    },
    connector::{BackendLease, Connector, SecretAcquisition},
    proxy_ca::ProxyCertificateAuthority,
    store::{GrantMode, PrincipalRole, Store},
    transparent_proxy::{
        TransparentDestination, TransparentRouteCatalog, authorize_connect_request,
        mint_proxy_session_credential,
    },
    transport_tls::ReloadingTransportTls,
};

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    auth: Authenticator,
    connectors: Arc<BTreeMap<String, Connector>>,
    connector_slots: Arc<Semaphore>,
    api_rate_limiter: ApiRateLimiter,
    proxy_client: reqwest::Client,
    websocket_client: reqwest::Client,
    store: Option<Store>,
    github_browser_auth: Option<GithubBrowserAuth>,
    transparent_proxy: Option<Arc<TransparentProxyRuntime>>,
    dynamic_leases: DynamicLeaseRegistry,
}

const MAX_ACTIVE_DYNAMIC_LEASES: usize = 1024;

#[derive(Clone, Default)]
struct DynamicLeaseRegistry {
    active: Arc<Mutex<BTreeMap<String, ActiveDynamicLease>>>,
}

struct ActiveDynamicLease {
    subject: String,
    profile: String,
    connector: String,
    lease: BackendLease,
}

impl DynamicLeaseRegistry {
    async fn insert(
        &self,
        subject: String,
        profile: String,
        connector: String,
        lease: BackendLease,
    ) -> std::result::Result<String, ActiveDynamicLease> {
        let item = ActiveDynamicLease {
            subject,
            profile,
            connector,
            lease,
        };
        let mut active = self.active.lock().await;
        let now = SystemTime::now();
        active.retain(|_, item| item.lease.expires_at() > now);
        if active.len() >= MAX_ACTIVE_DYNAMIC_LEASES {
            return Err(item);
        }
        let mut selected = None;
        for _ in 0..8 {
            let handle = format!("av_lease_{}", random_browser_token());
            if !active.contains_key(&handle) {
                selected = Some(handle);
                break;
            }
        }
        let Some(handle) = selected else {
            return Err(item);
        };
        active.insert(handle.clone(), item);
        Ok(handle)
    }

    async fn take_for_subject(&self, handle: &str, subject: &str) -> Option<ActiveDynamicLease> {
        let mut active = self.active.lock().await;
        let item = active.get(handle)?;
        if item.subject != subject || item.lease.expires_at() <= SystemTime::now() {
            return None;
        }
        active.remove(handle)
    }

    async fn restore(
        &self,
        handle: String,
        lease: ActiveDynamicLease,
    ) -> std::result::Result<(), ActiveDynamicLease> {
        let mut active = self.active.lock().await;
        if active.contains_key(&handle) {
            return Err(lease);
        }
        active.insert(handle, lease);
        Ok(())
    }

    async fn drain(&self) -> Vec<ActiveDynamicLease> {
        std::mem::take(&mut *self.active.lock().await)
            .into_values()
            .collect()
    }
}

struct TransparentProxyRuntime {
    listen: String,
    proxy_url: String,
    session_ttl: Duration,
    session_max_lifetime: Duration,
    catalog: TransparentRouteCatalog,
    certificate_authority: ProxyCertificateAuthority,
    transport_tls: ReloadingTransportTls,
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
        require_operator(&self.state, ctx.headers()).await?;
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
        let identity = require_operator(&self.state, ctx.headers()).await?;
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
        let identity = require_operator(&self.state, ctx.headers()).await?;
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

    async fn list_agents(
        &self,
        ctx: connectrpc::RequestContext,
        _request: connectrpc::ServiceRequest<'_, ListAgentsRequest>,
    ) -> connectrpc::ServiceResult<ListAgentsResponse> {
        require_operator(&self.state, ctx.headers()).await?;
        let agents = managed_store(&self.state)?
            .list_agents()
            .await
            .map_err(|_| connectrpc::ConnectError::internal("managed store unavailable"))?;
        connectrpc::Response::ok(ListAgentsResponse {
            agents: agents
                .into_iter()
                .map(|agent| RpcAgent {
                    name: agent.name,
                    enabled: agent.enabled,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        })
    }

    async fn create_agent(
        &self,
        ctx: connectrpc::RequestContext,
        request: connectrpc::ServiceRequest<'_, CreateAgentRequest>,
    ) -> connectrpc::ServiceResult<AgentCredential> {
        let identity = require_operator(&self.state, ctx.headers()).await?;
        let name = request.name;
        if !valid_agent_name(name) {
            return Err(connectrpc::ConnectError::invalid_argument(
                "invalid agent name",
            ));
        }
        let (token, token_hash) = mint_agent_token();
        managed_store(&self.state)?
            .create_agent(name, &token_hash)
            .await
            .map_err(|error| {
                if error
                    .downcast_ref::<sqlx::Error>()
                    .and_then(sqlx::Error::as_database_error)
                    .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
                {
                    connectrpc::ConnectError::already_exists("agent already exists")
                } else {
                    connectrpc::ConnectError::internal("managed store unavailable")
                }
            })?;
        audit_event(
            &self.state,
            &identity.subject,
            "agent_created",
            None,
            None,
            None,
        )
        .await
        .map_err(|_| connectrpc::ConnectError::internal("audit persistence unavailable"))?;
        connectrpc::Response::ok(AgentCredential {
            name: name.to_owned(),
            token: token.to_string(),
            enabled: true,
            ..Default::default()
        })
    }

    async fn rotate_agent(
        &self,
        ctx: connectrpc::RequestContext,
        request: connectrpc::ServiceRequest<'_, RotateAgentRequest>,
    ) -> connectrpc::ServiceResult<AgentCredential> {
        let identity = require_operator(&self.state, ctx.headers()).await?;
        let name = request.name;
        if !valid_agent_name(name) {
            return Err(connectrpc::ConnectError::invalid_argument(
                "invalid agent name",
            ));
        }
        let (token, token_hash) = mint_agent_token();
        if !managed_store(&self.state)?
            .rotate_agent_token(name, &token_hash)
            .await
            .map_err(|_| connectrpc::ConnectError::internal("managed store unavailable"))?
        {
            return Err(connectrpc::ConnectError::not_found("agent not found"));
        }
        audit_event(
            &self.state,
            &identity.subject,
            "agent_token_rotated",
            None,
            None,
            None,
        )
        .await
        .map_err(|_| connectrpc::ConnectError::internal("audit persistence unavailable"))?;
        connectrpc::Response::ok(AgentCredential {
            name: name.to_owned(),
            token: token.to_string(),
            enabled: true,
            ..Default::default()
        })
    }

    async fn set_agent_enabled(
        &self,
        ctx: connectrpc::RequestContext,
        request: connectrpc::ServiceRequest<'_, SetAgentEnabledRequest>,
    ) -> connectrpc::ServiceResult<RpcAgent> {
        let identity = require_operator(&self.state, ctx.headers()).await?;
        let name = request.name;
        if !valid_agent_name(name) {
            return Err(connectrpc::ConnectError::invalid_argument(
                "invalid agent name",
            ));
        }
        let enabled = request.enabled;
        if !managed_store(&self.state)?
            .set_agent_enabled(name, enabled)
            .await
            .map_err(|_| connectrpc::ConnectError::internal("managed store unavailable"))?
        {
            return Err(connectrpc::ConnectError::not_found("agent not found"));
        }
        audit_event(
            &self.state,
            &identity.subject,
            if enabled {
                "agent_enabled"
            } else {
                "agent_disabled"
            },
            None,
            None,
            None,
        )
        .await
        .map_err(|_| connectrpc::ConnectError::internal("audit persistence unavailable"))?;
        connectrpc::Response::ok(RpcAgent {
            name: name.to_owned(),
            enabled,
            ..Default::default()
        })
    }

    async fn delete_agent(
        &self,
        ctx: connectrpc::RequestContext,
        request: connectrpc::ServiceRequest<'_, DeleteAgentRequest>,
    ) -> connectrpc::ServiceResult<RpcAgent> {
        let identity = require_operator(&self.state, ctx.headers()).await?;
        let name = request.name;
        if !valid_agent_name(name) {
            return Err(connectrpc::ConnectError::invalid_argument(
                "invalid agent name",
            ));
        }
        if !managed_store(&self.state)?
            .delete_agent(name)
            .await
            .map_err(|_| connectrpc::ConnectError::internal("managed store unavailable"))?
        {
            return Err(connectrpc::ConnectError::not_found("agent not found"));
        }
        audit_event(
            &self.state,
            &identity.subject,
            "agent_deleted",
            None,
            None,
            None,
        )
        .await
        .map_err(|_| connectrpc::ConnectError::internal("audit persistence unavailable"))?;
        connectrpc::Response::ok(RpcAgent {
            name: name.to_owned(),
            enabled: false,
            ..Default::default()
        })
    }

    async fn list_principal_roles(
        &self,
        ctx: connectrpc::RequestContext,
        _request: connectrpc::ServiceRequest<'_, ListPrincipalRolesRequest>,
    ) -> connectrpc::ServiceResult<ListPrincipalRolesResponse> {
        require_owner(&self.state, ctx.headers()).await?;
        let roles = managed_store(&self.state)?
            .list_principal_roles()
            .await
            .map_err(|_| connectrpc::ConnectError::internal("managed store unavailable"))?;
        connectrpc::Response::ok(ListPrincipalRolesResponse {
            roles: roles
                .into_iter()
                .map(|binding| RpcPrincipalRole {
                    subject: binding.subject,
                    role: binding.role.as_str().into(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        })
    }

    async fn set_principal_role(
        &self,
        ctx: connectrpc::RequestContext,
        request: connectrpc::ServiceRequest<'_, SetPrincipalRoleRequest>,
    ) -> connectrpc::ServiceResult<RpcPrincipalRole> {
        let identity = require_owner(&self.state, ctx.headers()).await?;
        let subject = request.subject;
        if !valid_policy_subject(subject) {
            return Err(connectrpc::ConnectError::invalid_argument(
                "invalid policy subject",
            ));
        }
        let role = PrincipalRole::parse(request.role).map_err(|_| {
            connectrpc::ConnectError::invalid_argument(
                "principal role must be owner, operator, auditor, or user",
            )
        })?;
        managed_store(&self.state)?
            .set_principal_role(subject, role)
            .await
            .map_err(|error| {
                if error.to_string().contains("last owner") {
                    connectrpc::ConnectError::failed_precondition("cannot remove the last owner")
                } else {
                    connectrpc::ConnectError::internal("managed store unavailable")
                }
            })?;
        audit_event(
            &self.state,
            &identity.subject,
            "principal_role_changed",
            None,
            None,
            None,
        )
        .await
        .map_err(|_| connectrpc::ConnectError::internal("audit persistence unavailable"))?;
        connectrpc::Response::ok(RpcPrincipalRole {
            subject: subject.to_owned(),
            role: role.as_str().into(),
            ..Default::default()
        })
    }

    async fn list_audit_events(
        &self,
        ctx: connectrpc::RequestContext,
        request: connectrpc::ServiceRequest<'_, ListAuditEventsRequest>,
    ) -> connectrpc::ServiceResult<ListAuditEventsResponse> {
        require_auditor(&self.state, ctx.headers()).await?;
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
        require_operator(&self.state, ctx.headers()).await?;
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
                    mode: grant.mode.as_str().into(),
                    expires_unix_seconds: grant.expires_unix_seconds.unwrap_or_default(),
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
        let identity = require_operator(&self.state, ctx.headers()).await?;
        let profile = request.profile;
        let subject = request.subject;
        require_known_profile(&self.state, profile)?;
        if !valid_policy_subject(subject) {
            return Err(connectrpc::ConnectError::invalid_argument(
                "invalid policy subject",
            ));
        }
        let mode = parse_grant_mode(request.mode)?;
        let expires_unix_seconds =
            (request.expires_unix_seconds != 0).then_some(request.expires_unix_seconds);
        managed_store(&self.state)?
            .grant_profile_mode(subject, profile, mode, expires_unix_seconds)
            .await
            .map_err(|error| {
                if error.to_string().contains("expiry must be in the future") {
                    connectrpc::ConnectError::invalid_argument(
                        "profile grant expiry must be in the future",
                    )
                } else {
                    connectrpc::ConnectError::internal("managed store unavailable")
                }
            })?;
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
            mode: mode.as_str().into(),
            expires_unix_seconds: expires_unix_seconds.unwrap_or_default(),
            ..Default::default()
        })
    }

    async fn revoke_profile(
        &self,
        ctx: connectrpc::RequestContext,
        request: connectrpc::ServiceRequest<'_, RevokeProfileRequest>,
    ) -> connectrpc::ServiceResult<RpcProfileGrant> {
        let identity = require_operator(&self.state, ctx.headers()).await?;
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

async fn require_operator(
    state: &AppState,
    headers: &HeaderMap,
) -> std::result::Result<crate::auth::Identity, connectrpc::ConnectError> {
    let identity = authorize_connect(state, headers).await?;
    let role = managed_store(state)?
        .principal_role(&identity.subject)
        .await
        .map_err(|_| connectrpc::ConnectError::internal("managed store unavailable"))?;
    if !role.can_operate() {
        return Err(connectrpc::ConnectError::permission_denied(
            "operator access required",
        ));
    }
    Ok(identity)
}

async fn require_auditor(
    state: &AppState,
    headers: &HeaderMap,
) -> std::result::Result<crate::auth::Identity, connectrpc::ConnectError> {
    let identity = authorize_connect(state, headers).await?;
    let role = managed_store(state)?
        .principal_role(&identity.subject)
        .await
        .map_err(|_| connectrpc::ConnectError::internal("managed store unavailable"))?;
    if !role.can_audit() {
        return Err(connectrpc::ConnectError::permission_denied(
            "auditor access required",
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

fn valid_agent_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn mint_agent_token() -> (Zeroizing<String>, [u8; 32]) {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let token = Zeroizing::new(format!("av_agent_{}", URL_SAFE_NO_PAD.encode(bytes)));
    let token_hash = sha2::Sha256::digest(token.as_bytes()).into();
    bytes.fill(0);
    (token, token_hash)
}

fn valid_policy_subject(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 255 && !value.chars().any(char::is_control)
}

fn parse_grant_mode(value: &str) -> std::result::Result<GrantMode, connectrpc::ConnectError> {
    match value {
        "" | "both" => Ok(GrantMode::Both),
        "proxy" => Ok(GrantMode::Proxy),
        "environment" => Ok(GrantMode::Environment),
        _ => Err(connectrpc::ConnectError::invalid_argument(
            "profile grant mode must be both, proxy, or environment",
        )),
    }
}

fn validate_proxy_session_id(
    session_id: &str,
) -> std::result::Result<(), connectrpc::ConnectError> {
    if session_id.is_empty() || session_id.len() > 256 || session_id.chars().any(char::is_control) {
        return Err(connectrpc::ConnectError::invalid_argument(
            "session_id is invalid",
        ));
    }
    Ok(())
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

    async fn list_proxy_destinations(
        &self,
        ctx: connectrpc::RequestContext,
        _request: connectrpc::ServiceRequest<'_, ListProxyDestinationsRequest>,
    ) -> connectrpc::ServiceResult<ListProxyDestinationsResponse> {
        let identity = authorize_connect(&self.state, ctx.headers()).await?;
        let mut destinations = Vec::new();
        for (name, route) in &self.state.config.proxy_routes {
            if profile_permitted(
                &self.state,
                &identity.subject,
                &route.profile,
                GrantMode::Proxy,
            )
            .await
            .map_err(|_| connectrpc::ConnectError::internal("managed store unavailable"))?
            {
                let host = url::Url::parse(&route.base_url)
                    .ok()
                    .and_then(|url| url.host_str().map(str::to_owned))
                    .ok_or_else(|| {
                        connectrpc::ConnectError::internal("proxy route configuration unavailable")
                    })?;
                destinations.push(RpcProxyDestination {
                    name: name.clone(),
                    profile: route.profile.clone(),
                    host,
                    mode: "injecting".into(),
                    ..Default::default()
                });
            }
        }
        for (name, tunnel) in &self.state.config.proxy_tunnels {
            if profile_permitted(
                &self.state,
                &identity.subject,
                &tunnel.profile,
                GrantMode::Proxy,
            )
            .await
            .map_err(|_| connectrpc::ConnectError::internal("managed store unavailable"))?
            {
                destinations.push(RpcProxyDestination {
                    name: name.clone(),
                    profile: tunnel.profile.clone(),
                    host: tunnel.host.clone(),
                    mode: "tunnel".into(),
                    ..Default::default()
                });
            }
        }
        destinations.sort_by(|left, right| left.name.cmp(&right.name));
        connectrpc::Response::ok(ListProxyDestinationsResponse {
            destinations,
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
        if !profile_permitted(
            &self.state,
            &identity.subject,
            profile_name,
            GrantMode::Environment,
        )
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
        let mut acquisition = acquire_secrets(&self.state, profile)
            .await
            .map_err(|error| {
                tracing::warn!(subject = %identity.subject, profile = profile_name, error = %error, "profile environment unavailable");
                connectrpc::ConnectError::internal("profile environment unavailable")
            })?;
        let (lease_id, expires_unix_seconds) = if let Some(lease) = acquisition.lease.take() {
            let expires = match dynamic_lease_expiry(&lease) {
                Ok(expires) => expires,
                Err(error) => {
                    tracing::error!(profile = profile_name, %error, "dynamic lease expiry invalid");
                    let active = ActiveDynamicLease {
                        subject: identity.subject.clone(),
                        profile: profile_name.to_owned(),
                        connector: profile.connector.clone(),
                        lease,
                    };
                    if let Err(revoke_error) = revoke_dynamic_lease(&self.state, &active).await {
                        tracing::error!(
                            profile = profile_name,
                            error = %revoke_error,
                            "revoke dynamic lease with invalid expiry"
                        );
                    }
                    return Err(connectrpc::ConnectError::internal(
                        "profile environment unavailable",
                    ));
                }
            };
            match self
                .state
                .dynamic_leases
                .insert(
                    identity.subject.clone(),
                    profile_name.to_owned(),
                    profile.connector.clone(),
                    lease,
                )
                .await
            {
                Ok(handle) => (handle, expires),
                Err(active) => {
                    if let Err(error) = revoke_dynamic_lease(&self.state, &active).await {
                        tracing::error!(
                            profile = profile_name,
                            connector = %profile.connector,
                            %error,
                            "revoke unregistered dynamic lease"
                        );
                    }
                    return Err(connectrpc::ConnectError::resource_exhausted(
                        "active dynamic lease limit reached",
                    ));
                }
            }
        } else {
            (String::new(), 0)
        };
        tracing::info!(
            subject = %identity.subject,
            profile = profile_name,
            executable,
            key_count = acquisition.values.len(),
            "profile leased"
        );
        if let Err(error) = audit_event(
            &self.state,
            &identity.subject,
            "profile_lease",
            Some(profile_name),
            None,
            Some(executable),
        )
        .await
        {
            if !lease_id.is_empty()
                && let Some(active) = self
                    .state
                    .dynamic_leases
                    .take_for_subject(&lease_id, &identity.subject)
                    .await
                && let Err(revoke_error) = revoke_dynamic_lease(&self.state, &active).await
            {
                tracing::error!(
                    profile = profile_name,
                    error = %revoke_error,
                    "revoke dynamic lease after audit failure"
                );
            }
            tracing::error!(%error, "persist profile lease audit event");
            return Err(connectrpc::ConnectError::internal(
                "audit persistence unavailable",
            ));
        }
        connectrpc::Response::ok(ProfileEnvironment {
            values: acquisition
                .values
                .into_iter()
                .map(|(name, value)| EnvironmentValue {
                    name,
                    value,
                    ..Default::default()
                })
                .collect(),
            lease_id,
            expires_unix_seconds,
            ..Default::default()
        })
    }

    async fn renew_profile_environment_lease(
        &self,
        ctx: connectrpc::RequestContext,
        request: connectrpc::ServiceRequest<'_, RenewProfileEnvironmentLeaseRequest>,
    ) -> connectrpc::ServiceResult<ProfileEnvironmentLease> {
        let identity = authorize_connect(&self.state, ctx.headers()).await?;
        let handle = request.lease_id;
        validate_dynamic_lease_handle(handle)?;
        let Some(mut active) = self
            .state
            .dynamic_leases
            .take_for_subject(handle, &identity.subject)
            .await
        else {
            return Err(connectrpc::ConnectError::not_found(
                "active dynamic lease not found",
            ));
        };
        if !profile_permitted(
            &self.state,
            &identity.subject,
            &active.profile,
            GrantMode::Environment,
        )
        .await
        .map_err(|_| connectrpc::ConnectError::internal("managed store unavailable"))?
        {
            if let Err(error) = revoke_dynamic_lease(&self.state, &active).await {
                tracing::error!(profile = %active.profile, %error, "revoke ungranted dynamic lease");
            }
            return Err(connectrpc::ConnectError::permission_denied(
                "profile access is not granted",
            ));
        }
        let Some(connector) = self.state.connectors.get(&active.connector) else {
            let _ = self
                .state
                .dynamic_leases
                .restore(handle.to_owned(), active)
                .await;
            return Err(connectrpc::ConnectError::internal(
                "profile connector unavailable",
            ));
        };
        if !active.lease.renewable() {
            if let Err(error) = connector.revoke(&active.lease).await {
                tracing::error!(profile = %active.profile, %error, "revoke non-renewable dynamic lease");
            }
            return Err(connectrpc::ConnectError::failed_precondition(
                "dynamic lease is not renewable",
            ));
        }
        if let Err(error) = connector.renew(&mut active.lease).await {
            tracing::warn!(profile = %active.profile, %error, "dynamic lease renewal failed");
            if let Err(revoke_error) = connector.revoke(&active.lease).await {
                tracing::error!(profile = %active.profile, error = %revoke_error, "revoke failed dynamic lease");
                if let Err(active) = self
                    .state
                    .dynamic_leases
                    .restore(handle.to_owned(), active)
                    .await
                {
                    tracing::error!(
                        profile = %active.profile,
                        "dynamic lease registry collision after failed revocation"
                    );
                }
            }
            return Err(connectrpc::ConnectError::internal(
                "dynamic lease renewal failed",
            ));
        }
        let expires_unix_seconds = match dynamic_lease_expiry(&active.lease) {
            Ok(expires) => expires,
            Err(error) => {
                tracing::error!(profile = %active.profile, %error, "renewed dynamic lease expiry invalid");
                if let Err(revoke_error) = revoke_dynamic_lease(&self.state, &active).await {
                    tracing::error!(
                        profile = %active.profile,
                        error = %revoke_error,
                        "revoke dynamic lease with invalid renewed expiry"
                    );
                    let _ = self
                        .state
                        .dynamic_leases
                        .restore(handle.to_owned(), active)
                        .await;
                }
                return Err(connectrpc::ConnectError::internal(
                    "dynamic lease expiry is invalid",
                ));
            }
        };
        let profile = active.profile.clone();
        if let Err(error) = audit_event(
            &self.state,
            &identity.subject,
            "profile_lease_renewed",
            Some(&profile),
            None,
            None,
        )
        .await
        {
            if let Err(revoke_error) = revoke_dynamic_lease(&self.state, &active).await {
                tracing::error!(
                    profile = %active.profile,
                    error = %revoke_error,
                    "revoke dynamic lease after renewal audit failure"
                );
            }
            tracing::error!(%error, "persist dynamic lease renewal audit event");
            return Err(connectrpc::ConnectError::internal(
                "audit persistence unavailable",
            ));
        }
        if let Err(active) = self
            .state
            .dynamic_leases
            .restore(handle.to_owned(), active)
            .await
        {
            if let Err(error) = revoke_dynamic_lease(&self.state, &active).await {
                tracing::error!(profile = %active.profile, %error, "revoke colliding dynamic lease");
            }
            return Err(connectrpc::ConnectError::internal(
                "dynamic lease registry unavailable",
            ));
        }
        connectrpc::Response::ok(ProfileEnvironmentLease {
            lease_id: handle.to_owned(),
            expires_unix_seconds,
            revoked: false,
            ..Default::default()
        })
    }

    async fn revoke_profile_environment_lease(
        &self,
        ctx: connectrpc::RequestContext,
        request: connectrpc::ServiceRequest<'_, RevokeProfileEnvironmentLeaseRequest>,
    ) -> connectrpc::ServiceResult<ProfileEnvironmentLease> {
        let identity = authorize_connect(&self.state, ctx.headers()).await?;
        let handle = request.lease_id;
        validate_dynamic_lease_handle(handle)?;
        let Some(active) = self
            .state
            .dynamic_leases
            .take_for_subject(handle, &identity.subject)
            .await
        else {
            return Err(connectrpc::ConnectError::not_found(
                "active dynamic lease not found",
            ));
        };
        if let Err(error) = revoke_dynamic_lease(&self.state, &active).await {
            tracing::error!(profile = %active.profile, %error, "dynamic lease revocation failed");
            if let Err(active) = self
                .state
                .dynamic_leases
                .restore(handle.to_owned(), active)
                .await
            {
                tracing::error!(
                    profile = %active.profile,
                    "dynamic lease registry collision after failed revocation"
                );
            }
            return Err(connectrpc::ConnectError::internal(
                "dynamic lease revocation failed",
            ));
        }
        audit_event(
            &self.state,
            &identity.subject,
            "profile_lease_revoked",
            Some(&active.profile),
            None,
            None,
        )
        .await
        .map_err(|_| connectrpc::ConnectError::internal("audit persistence unavailable"))?;
        connectrpc::Response::ok(ProfileEnvironmentLease {
            lease_id: handle.to_owned(),
            expires_unix_seconds: 0,
            revoked: true,
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
        if !profile_permitted(&self.state, &identity.subject, profile, GrantMode::Proxy)
            .await
            .map_err(|_| connectrpc::ConnectError::internal("managed store unavailable"))?
        {
            return Err(connectrpc::ConnectError::permission_denied(
                "profile access is not granted",
            ));
        }
        let credential = mint_proxy_session_credential();
        let now = SystemTime::now();
        let expiration = |lifetime| {
            now.checked_add(lifetime)
                .context("proxy session expiry overflow")
                .and_then(|time| {
                    time.duration_since(UNIX_EPOCH)
                        .context("system clock is before Unix epoch")
                })
                .and_then(|duration| {
                    i64::try_from(duration.as_secs())
                        .context("proxy session expiry is outside supported range")
                })
        };
        let expires_unix_seconds = expiration(runtime.session_ttl).map_err(|_| {
            connectrpc::ConnectError::internal("proxy session clock is unavailable")
        })?;
        let maximum_expires_unix_seconds =
            expiration(runtime.session_max_lifetime).map_err(|_| {
                connectrpc::ConnectError::internal("proxy session clock is unavailable")
            })?;
        store
            .create_proxy_session(
                &credential.session_id,
                &credential.token_hash,
                &identity.subject,
                profile,
                expires_unix_seconds,
                maximum_expires_unix_seconds,
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

    async fn renew_proxy_session(
        &self,
        ctx: connectrpc::RequestContext,
        request: connectrpc::ServiceRequest<'_, RenewProxySessionRequest>,
    ) -> connectrpc::ServiceResult<ProxySessionLease> {
        let identity = authorize_connect(&self.state, ctx.headers()).await?;
        let session_id = request.session_id;
        validate_proxy_session_id(session_id)?;
        let runtime = self.state.transparent_proxy.as_ref().ok_or_else(|| {
            connectrpc::ConnectError::failed_precondition("transparent proxy is not configured")
        })?;
        let store = self.state.store.as_ref().ok_or_else(|| {
            connectrpc::ConnectError::failed_precondition("managed proxy sessions are required")
        })?;
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
        let Some(session) = store
            .renew_proxy_session_for_subject(session_id, &identity.subject, expires_unix_seconds)
            .await
            .map_err(|error| {
                tracing::error!(%error, "renew transparent proxy session");
                connectrpc::ConnectError::internal("proxy session is unavailable")
            })?
        else {
            return Err(connectrpc::ConnectError::not_found(
                "active proxy session not found",
            ));
        };
        match profile_permitted(
            &self.state,
            &identity.subject,
            &session.profile,
            GrantMode::Proxy,
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => {
                let _ = store.revoke_proxy_session(session_id).await;
                return Err(connectrpc::ConnectError::permission_denied(
                    "profile access is not granted",
                ));
            }
            Err(error) => {
                tracing::error!(%error, "check transparent proxy renewal grant");
                return Err(connectrpc::ConnectError::internal(
                    "managed store unavailable",
                ));
            }
        }
        audit_event(
            &self.state,
            &identity.subject,
            "transparent_proxy_session_renewed",
            Some(&session.profile),
            Some(session_id),
            None,
        )
        .await
        .map_err(|_| connectrpc::ConnectError::internal("audit persistence unavailable"))?;
        connectrpc::Response::ok(ProxySessionLease {
            session_id: session.session_id,
            expires_unix_seconds: session.expires_unix_seconds,
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
        validate_proxy_session_id(session_id)?;
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

async fn profile_permitted(
    state: &AppState,
    subject: &str,
    profile: &str,
    mode: GrantMode,
) -> Result<bool> {
    match &state.store {
        None => Ok(true),
        Some(store) => store.profile_allowed_for(subject, profile, mode).await,
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
    agents: Vec<OwnerAgent>,
    profiles: Vec<String>,
    principals: Vec<OwnerPrincipal>,
    issued_agent_credential: Option<IssuedAgentCredential>,
    can_manage_roles: bool,
}

struct OwnerBasicUser {
    username: String,
    enabled: bool,
}

struct OwnerAgent {
    name: String,
    enabled: bool,
}

struct IssuedAgentCredential {
    name: String,
    token: String,
}

struct OwnerPrincipal {
    label: String,
    kind: String,
    subject: String,
    role: String,
    grants: Vec<OwnerGrant>,
}

struct OwnerGrant {
    profile: String,
    mode: String,
    expires_unix_seconds: Option<i64>,
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
struct AgentForm {
    name: String,
}

#[derive(Deserialize)]
struct AgentEnabledForm {
    name: String,
    enabled: bool,
}

#[derive(Deserialize)]
struct PrincipalRoleForm {
    subject: String,
    role: String,
}

#[derive(Deserialize)]
struct ProfileGrantForm {
    profile: String,
    subject: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    expires_unix_seconds: String,
}

#[derive(Deserialize)]
struct ExternalProfileGrantForm {
    profile: String,
    identity_kind: String,
    identity: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    expires_unix_seconds: String,
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
                session_max_lifetime: Duration::from_secs(proxy.session_max_lifetime_seconds),
                catalog: TransparentRouteCatalog::from_config(
                    &config.proxy_routes,
                    &config.proxy_tunnels,
                )?,
                certificate_authority: ProxyCertificateAuthority::load(
                    std::path::Path::new(&proxy.ca_certificate_file),
                    std::path::Path::new(&proxy.ca_private_key_file),
                )?,
                transport_tls: ReloadingTransportTls::load(
                    std::path::Path::new(&proxy.transport_tls_certificate_file),
                    std::path::Path::new(&proxy.transport_tls_private_key_file),
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
            Connector::new(connector.clone(), allow_insecure_http).await?,
        );
    }
    let proxy_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("av-proxy/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let websocket_client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("av-websocket/", env!("CARGO_PKG_VERSION")))
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
        websocket_client,
        store,
        github_browser_auth,
        transparent_proxy: transparent_proxy.clone(),
        dynamic_leases: DynamicLeaseRegistry::default(),
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
        .route("/ui/owner/agents", post(ui_create_agent))
        .route("/ui/owner/agents/rotate", post(ui_rotate_agent))
        .route("/ui/owner/agents/enabled", post(ui_set_agent_enabled))
        .route("/ui/owner/agents/delete", post(ui_delete_agent))
        .route("/ui/owner/roles", post(ui_set_principal_role))
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
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("listen on {}", config.listen))?;
    tracing::info!(listen = %config.listen, "av is ready");
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await;
    revoke_all_dynamic_leases(&state).await;
    result?;
    Ok(())
}

async fn revoke_all_dynamic_leases(state: &AppState) {
    for active in state.dynamic_leases.drain().await {
        if let Err(error) = revoke_dynamic_lease(state, &active).await {
            tracing::error!(
                profile = %active.profile,
                connector = %active.connector,
                %error,
                "dynamic lease revocation failed during shutdown"
            );
        }
    }
}

async fn revoke_dynamic_lease(state: &AppState, active: &ActiveDynamicLease) -> Result<()> {
    state
        .connectors
        .get(&active.connector)
        .context("dynamic lease connector disappeared")?
        .revoke(&active.lease)
        .await
}

fn dynamic_lease_expiry(lease: &BackendLease) -> Result<i64> {
    let duration = lease
        .expires_at()
        .duration_since(UNIX_EPOCH)
        .context("dynamic lease expiry predates the Unix epoch")?;
    i64::try_from(duration.as_secs()).context("dynamic lease expiry is outside supported range")
}

fn validate_dynamic_lease_handle(
    handle: &str,
) -> std::result::Result<(), connectrpc::ConnectError> {
    if !handle.starts_with("av_lease_")
        || handle.len() != "av_lease_".len() + 43
        || !handle["av_lease_".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(connectrpc::ConnectError::invalid_argument(
            "dynamic lease handle is invalid",
        ));
    }
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
    let identity = match ui_require_operator(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    render_owner_panel(&state, &identity.subject, None).await
}

async fn ui_upsert_basic_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<BasicUserForm>,
) -> Response {
    if !is_trusted_browser_origin(&headers, &state.config.public_url) {
        return no_store((StatusCode::FORBIDDEN, "owner request forbidden\n").into_response());
    }
    let identity = match ui_require_operator(&state, &headers).await {
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
    render_owner_panel(&state, &identity.subject, None).await
}

async fn ui_set_basic_user_enabled(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<BasicUserEnabledForm>,
) -> Response {
    if !is_trusted_browser_origin(&headers, &state.config.public_url) {
        return no_store((StatusCode::FORBIDDEN, "owner request forbidden\n").into_response());
    }
    let identity = match ui_require_operator(&state, &headers).await {
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
    render_owner_panel(&state, &identity.subject, None).await
}

async fn ui_create_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AgentForm>,
) -> Response {
    let identity = match ui_authorize_owner_mutation(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !valid_agent_name(&form.name) {
        return ui_bad_request("invalid agent name");
    }
    let (token, token_hash) = mint_agent_token();
    let store = match state.store.as_ref() {
        Some(store) => store,
        None => return ui_not_found().await,
    };
    if let Err(error) = store.create_agent(&form.name, &token_hash).await {
        if error
            .downcast_ref::<sqlx::Error>()
            .and_then(sqlx::Error::as_database_error)
            .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
        {
            return ui_bad_request("agent already exists");
        }
        return internal_error(error);
    }
    if let Err(error) = audit_event(
        &state,
        &identity.subject,
        "agent_created",
        None,
        None,
        Some("managed-ui"),
    )
    .await
    {
        return internal_error(error);
    }
    render_owner_panel(
        &state,
        &identity.subject,
        Some(IssuedAgentCredential {
            name: form.name,
            token: token.to_string(),
        }),
    )
    .await
}

async fn ui_rotate_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AgentForm>,
) -> Response {
    let identity = match ui_authorize_owner_mutation(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !valid_agent_name(&form.name) {
        return ui_bad_request("invalid agent name");
    }
    let (token, token_hash) = mint_agent_token();
    let store = match state.store.as_ref() {
        Some(store) => store,
        None => return ui_not_found().await,
    };
    match store.rotate_agent_token(&form.name, &token_hash).await {
        Ok(true) => {}
        Ok(false) => return ui_bad_request("agent not found"),
        Err(error) => return internal_error(error),
    }
    if let Err(error) = audit_event(
        &state,
        &identity.subject,
        "agent_token_rotated",
        None,
        None,
        Some("managed-ui"),
    )
    .await
    {
        return internal_error(error);
    }
    render_owner_panel(
        &state,
        &identity.subject,
        Some(IssuedAgentCredential {
            name: form.name,
            token: token.to_string(),
        }),
    )
    .await
}

async fn ui_set_agent_enabled(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AgentEnabledForm>,
) -> Response {
    let identity = match ui_authorize_owner_mutation(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !valid_agent_name(&form.name) {
        return ui_bad_request("invalid agent name");
    }
    let store = match state.store.as_ref() {
        Some(store) => store,
        None => return ui_not_found().await,
    };
    match store.set_agent_enabled(&form.name, form.enabled).await {
        Ok(true) => {}
        Ok(false) => return ui_bad_request("agent not found"),
        Err(error) => return internal_error(error),
    }
    if let Err(error) = audit_event(
        &state,
        &identity.subject,
        if form.enabled {
            "agent_enabled"
        } else {
            "agent_disabled"
        },
        None,
        None,
        Some("managed-ui"),
    )
    .await
    {
        return internal_error(error);
    }
    render_owner_panel(&state, &identity.subject, None).await
}

async fn ui_delete_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AgentForm>,
) -> Response {
    let identity = match ui_authorize_owner_mutation(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !valid_agent_name(&form.name) {
        return ui_bad_request("invalid agent name");
    }
    let store = match state.store.as_ref() {
        Some(store) => store,
        None => return ui_not_found().await,
    };
    match store.delete_agent(&form.name).await {
        Ok(true) => {}
        Ok(false) => return ui_bad_request("agent not found"),
        Err(error) => return internal_error(error),
    }
    if let Err(error) = audit_event(
        &state,
        &identity.subject,
        "agent_deleted",
        None,
        None,
        Some("managed-ui"),
    )
    .await
    {
        return internal_error(error);
    }
    render_owner_panel(&state, &identity.subject, None).await
}

async fn ui_authorize_owner_mutation(
    state: &AppState,
    headers: &HeaderMap,
) -> std::result::Result<crate::auth::Identity, Response> {
    if !is_trusted_browser_origin(headers, &state.config.public_url) {
        return Err(no_store(
            (StatusCode::FORBIDDEN, "owner request forbidden\n").into_response(),
        ));
    }
    ui_require_operator(state, headers).await
}

async fn ui_set_principal_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<PrincipalRoleForm>,
) -> Response {
    if !is_trusted_browser_origin(&headers, &state.config.public_url) {
        return no_store((StatusCode::FORBIDDEN, "owner request forbidden\n").into_response());
    }
    let identity = match ui_require_owner(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if !valid_policy_subject(&form.subject) {
        return ui_bad_request("invalid policy subject");
    }
    let role = match PrincipalRole::parse(&form.role) {
        Ok(role) => role,
        Err(_) => return ui_bad_request("role must be owner, operator, auditor, or user"),
    };
    let store = match state.store.as_ref() {
        Some(store) => store,
        None => return ui_not_found().await,
    };
    if let Err(error) = store.set_principal_role(&form.subject, role).await {
        if error.to_string().contains("last owner") {
            return ui_bad_request("cannot remove the last owner");
        }
        return internal_error(error);
    }
    if let Err(error) = audit_event(
        &state,
        &identity.subject,
        "principal_role_changed",
        None,
        None,
        Some("managed-ui"),
    )
    .await
    {
        return internal_error(error);
    }
    render_owner_panel(&state, &identity.subject, None).await
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
            mode: form.mode,
            expires_unix_seconds: form.expires_unix_seconds,
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
    let identity = match ui_require_operator(state, headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if let Err(error) = require_known_profile(state, &form.profile) {
        return ui_bad_request(error.to_string());
    }
    if !valid_policy_subject(&form.subject) {
        return ui_bad_request("invalid policy subject");
    }
    let mode = match form.mode.as_str() {
        "" | "both" => GrantMode::Both,
        "proxy" => GrantMode::Proxy,
        "environment" => GrantMode::Environment,
        _ => return ui_bad_request("grant mode must be both, proxy, or environment"),
    };
    let expires_unix_seconds = if form.expires_unix_seconds.trim().is_empty() {
        None
    } else {
        match form.expires_unix_seconds.parse::<i64>() {
            Ok(value) => Some(value),
            Err(_) => return ui_bad_request("grant expiry must be a Unix timestamp"),
        }
    };
    let store = match state.store.as_ref() {
        Some(store) => store,
        None => return ui_not_found().await,
    };
    if let Err(error) = store
        .grant_profile_mode(&form.subject, &form.profile, mode, expires_unix_seconds)
        .await
    {
        if error.to_string().contains("expiry must be in the future") {
            return ui_bad_request("grant expiry must be in the future");
        }
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
    render_owner_panel(state, &identity.subject, None).await
}

async fn ui_revoke_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ProfileGrantForm>,
) -> Response {
    if !is_trusted_browser_origin(&headers, &state.config.public_url) {
        return no_store((StatusCode::FORBIDDEN, "owner request forbidden\n").into_response());
    }
    let identity = match ui_require_operator(&state, &headers).await {
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
    render_owner_panel(&state, &identity.subject, None).await
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

async fn ui_require_operator(
    state: &AppState,
    headers: &HeaderMap,
) -> std::result::Result<crate::auth::Identity, Response> {
    let identity = ui_identity(state, headers).await.map_err(unauthorized)?;
    let Some(store) = state.store.as_ref() else {
        return Err(ui_not_found().await);
    };
    match store.principal_role(&identity.subject).await {
        Ok(role) if role.can_operate() => Ok(identity),
        Ok(_) => Err(no_store(
            (StatusCode::FORBIDDEN, "operator access required\n").into_response(),
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

async fn render_owner_panel(
    state: &AppState,
    viewer_subject: &str,
    issued_agent_credential: Option<IssuedAgentCredential>,
) -> Response {
    let Some(store) = state.store.as_ref() else {
        return ui_not_found().await;
    };
    let stored_basic_users = match store.list_basic_users().await {
        Ok(users) => users,
        Err(error) => return internal_error(error),
    };
    let stored_agents = match store.list_agents().await {
        Ok(agents) => agents,
        Err(error) => return internal_error(error),
    };
    let role_bindings = match store.list_principal_roles().await {
        Ok(bindings) => bindings,
        Err(error) => return internal_error(error),
    };
    let can_manage_roles = match store.principal_role(viewer_subject).await {
        Ok(PrincipalRole::Owner) => true,
        Ok(_) => false,
        Err(error) => return internal_error(error),
    };
    let mut roles_by_subject: BTreeMap<_, _> = role_bindings
        .into_iter()
        .map(|binding| (binding.subject, binding.role))
        .collect();
    let profiles: Vec<_> = state.config.profiles.keys().cloned().collect();
    let mut grants_by_subject: BTreeMap<String, Vec<OwnerGrant>> = BTreeMap::new();
    for profile in &profiles {
        let profile_grants = match store.list_profile_grants(profile).await {
            Ok(grants) => grants,
            Err(error) => return internal_error(error),
        };
        for grant in profile_grants {
            grants_by_subject
                .entry(grant.subject)
                .or_default()
                .push(OwnerGrant {
                    profile: grant.profile,
                    mode: grant.mode.as_str().into(),
                    expires_unix_seconds: grant.expires_unix_seconds,
                });
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
        let grants = grants_by_subject.remove(&subject).unwrap_or_default();
        let role = roles_by_subject
            .remove(&subject)
            .unwrap_or_default()
            .as_str()
            .into();
        principals.push(OwnerPrincipal {
            label: user.username,
            kind: "Basic account".into(),
            subject,
            role,
            grants,
        });
    }
    for agent in &stored_agents {
        let subject = format!("agent:{}", agent.name);
        let grants = grants_by_subject.remove(&subject).unwrap_or_default();
        let role = roles_by_subject
            .remove(&subject)
            .unwrap_or_default()
            .as_str()
            .into();
        principals.push(OwnerPrincipal {
            label: agent.name.clone(),
            kind: "Agent".into(),
            subject,
            role,
            grants,
        });
    }
    principals.extend(grants_by_subject.into_iter().map(|(subject, grants)| {
        let (label, kind) = display_principal(&subject);
        let role = roles_by_subject
            .remove(&subject)
            .unwrap_or_default()
            .as_str()
            .into();
        OwnerPrincipal {
            label,
            kind,
            subject,
            role,
            grants,
        }
    }));
    principals.extend(roles_by_subject.into_iter().map(|(subject, role)| {
        let (label, kind) = display_principal(&subject);
        OwnerPrincipal {
            label,
            kind,
            subject,
            role: role.as_str().into(),
            grants: Vec::new(),
        }
    }));
    principals.sort_by(|left, right| left.subject.cmp(&right.subject));
    match (OwnerTemplate {
        basic_users,
        agents: stored_agents
            .into_iter()
            .map(|agent| OwnerAgent {
                name: agent.name,
                enabled: agent.enabled,
            })
            .collect(),
        profiles,
        principals,
        issued_agent_credential,
        can_manage_roles,
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
    if let Some(name) = subject.strip_prefix("agent:") {
        return (name.to_owned(), "Agent".into());
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
            let (acceptor, reload_error) = runtime.transport_tls.acceptor();
            if let Some(error) = reload_error {
                tracing::warn!(%error, "retain last valid transparent proxy transport certificate");
            }
            let stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::debug!(%peer, %error, "transparent proxy transport TLS rejected");
                    return;
                }
            };
            if let Err(error) = serve_transparent_proxy_connection(stream, state, runtime).await {
                tracing::debug!(%peer, %error, "transparent proxy connection ended");
            }
        });
    }
}

async fn serve_transparent_proxy_connection(
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
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
    if session.profile != authorized.destination.profile() {
        return transparent_response(StatusCode::FORBIDDEN, "proxy request forbidden\n");
    }
    match profile_permitted(&state, &session.subject, &session.profile, GrantMode::Proxy).await {
        Ok(true) => {}
        Ok(false) => {
            return transparent_response(StatusCode::FORBIDDEN, "proxy request forbidden\n");
        }
        Err(error) => {
            tracing::error!(%error, "check transparent proxy grant");
            return transparent_response(StatusCode::SERVICE_UNAVAILABLE, "proxy unavailable\n");
        }
    }
    let tunnel_upstream = match &authorized.destination {
        TransparentDestination::Injecting { .. } => None,
        TransparentDestination::Tunnel {
            host,
            allow_private_ips,
            ..
        } => match connect_credentialless_upstream(host, *allow_private_ips).await {
            Ok(upstream) => Some(upstream),
            Err(error) => {
                tracing::warn!(
                    %error,
                    destination = authorized.destination.name(),
                    "credentialless tunnel upstream denied or unavailable"
                );
                return transparent_response(StatusCode::BAD_GATEWAY, "proxy request failed\n");
            }
        },
    };
    let upgraded = hyper::upgrade::on(&mut request);
    let state_for_tunnel = state.clone();
    let runtime_for_tunnel = runtime.clone();
    let destination = authorized.destination.clone();
    let destination_name = destination.name().to_owned();
    let host = authorized.host.clone();
    let token_hash = authorized.token_hash;
    let session_id = session.session_id.clone();
    tokio::spawn(async move {
        match upgraded.await {
            Ok(upgraded) => match destination {
                TransparentDestination::Injecting { name, .. } => {
                    if let Err(error) = serve_transparent_tls_tunnel(
                        upgraded,
                        state_for_tunnel,
                        runtime_for_tunnel,
                        name,
                        host,
                        token_hash,
                        session_id,
                    )
                    .await
                    {
                        tracing::debug!(%error, "transparent proxy TLS tunnel ended");
                    }
                }
                TransparentDestination::Tunnel { .. } => {
                    if let Some(upstream) = tunnel_upstream
                        && let Err(error) = serve_credentialless_tunnel(upgraded, upstream).await
                    {
                        tracing::debug!(%error, "credentialless TLS tunnel ended");
                    }
                }
            },
            Err(error) => tracing::debug!(%error, "transparent proxy CONNECT upgrade failed"),
        }
    });
    if let Err(error) = audit_event(
        &state,
        &session.subject,
        "transparent_proxy_connect",
        Some(&session.profile),
        Some(&destination_name),
        None,
    )
    .await
    {
        tracing::error!(%error, "record transparent proxy CONNECT audit event");
        return transparent_response(StatusCode::SERVICE_UNAVAILABLE, "proxy unavailable\n");
    }
    transparent_response(StatusCode::OK, "")
}

async fn connect_credentialless_upstream(host: &str, allow_private_ips: bool) -> Result<TcpStream> {
    let mut addresses = lookup_host((host, 443))
        .await
        .with_context(|| format!("resolve configured tunnel host {host}"))?
        .collect::<BTreeSet<_>>();
    if addresses.is_empty() || addresses.len() > 16 {
        bail!("configured tunnel host resolved to an invalid number of addresses");
    }
    if addresses
        .iter()
        .any(|address| !tunnel_ip_allowed(address.ip(), allow_private_ips))
    {
        bail!("configured tunnel host resolved to a denied address");
    }
    let mut last_error = None;
    for address in std::mem::take(&mut addresses) {
        match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(address)).await {
            Ok(Ok(stream)) => {
                stream
                    .set_nodelay(true)
                    .context("configure credentialless tunnel socket")?;
                return Ok(stream);
            }
            Ok(Err(error)) => last_error = Some(anyhow::Error::new(error)),
            Err(error) => last_error = Some(anyhow::Error::new(error)),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("tunnel upstream is unavailable")))
}

fn tunnel_ip_allowed(address: IpAddr, allow_private_ips: bool) -> bool {
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
            {
                return false;
            }
            allow_private_ips
                || (!address.is_private()
                    && !ipv4_in_prefix(address, Ipv4Addr::new(100, 64, 0, 0), 10)
                    && !ipv4_in_prefix(address, Ipv4Addr::new(198, 18, 0, 0), 15))
        }
        IpAddr::V6(address) => {
            if address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || address.is_unicast_link_local()
                || address.segments()[0] == 0x2001 && address.segments()[1] == 0x0db8
            {
                return false;
            }
            allow_private_ips || !address.is_unique_local()
        }
    }
}

fn ipv4_in_prefix(address: Ipv4Addr, network: Ipv4Addr, prefix: u32) -> bool {
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    u32::from(address) & mask == u32::from(network) & mask
}

async fn serve_credentialless_tunnel(
    upgraded: hyper::upgrade::Upgraded,
    upstream: TcpStream,
) -> Result<()> {
    relay_credentialless_tunnel(TokioIo::new(upgraded), upstream).await
}

async fn relay_credentialless_tunnel(
    mut client: impl AsyncRead + AsyncWrite + Unpin,
    mut upstream: impl AsyncRead + AsyncWrite + Unpin,
) -> Result<()> {
    tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .context("relay credentialless TLS tunnel")?;
    Ok(())
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
        .with_upgrades()
        .await
        .context("serve transparent proxy TLS request")
}

async fn transparent_tunnel_response(
    mut request: HyperRequest<Incoming>,
    state: AppState,
    route_name: String,
    token_hash: [u8; 32],
    session_id: String,
) -> HyperResponse<axum::body::Body> {
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
    match profile_permitted(&state, &session.subject, &session.profile, GrantMode::Proxy).await {
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
    let websocket_attempt = is_websocket_attempt(request.headers());
    let websocket_upgrade = if websocket_attempt {
        let Some(websocket) = &route.websocket else {
            return transparent_full_response(StatusCode::FORBIDDEN, "proxy request forbidden\n");
        };
        if let Err(error) = validate_websocket_handshake(request.headers(), websocket) {
            tracing::warn!(%error, route = route_name, "transparent WebSocket handshake denied");
            return transparent_full_response(StatusCode::FORBIDDEN, "proxy request forbidden\n");
        }
        Some(hyper::upgrade::on(&mut request))
    } else {
        None
    };
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
    if websocket_attempt && !body.is_empty() {
        return transparent_full_response(
            StatusCode::FORBIDDEN,
            "WebSocket upgrade body is forbidden\n",
        );
    }
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
    let response_result = if let Some(client_upgrade) = websocket_upgrade {
        proxy_websocket_request(
            &state,
            route,
            &normalized_path,
            &query,
            parts.method,
            parts.headers,
            PendingWebSocketUpgrade {
                client: client_upgrade,
                token_hash,
                session_id: session.session_id.clone(),
            },
        )
        .await
    } else {
        proxy_request(
            &state,
            route,
            &normalized_path,
            &query,
            parts.method,
            parts.headers,
            body,
        )
        .await
    };
    let response = match response_result {
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
    response
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

fn transparent_full_response(status: StatusCode, message: &str) -> HyperResponse<axum::body::Body> {
    HyperResponse::builder()
        .status(status)
        .body(axum::body::Body::from(message.to_owned()))
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
    match profile_permitted(&state, &identity.subject, &profile, GrantMode::Environment).await {
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
    if is_websocket_attempt(&headers) {
        return (
            StatusCode::FORBIDDEN,
            "WebSockets require a transparent proxy session\n",
        )
            .into_response();
    }
    match profile_permitted(&state, &identity.subject, &route.profile, GrantMode::Proxy).await {
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

fn is_websocket_attempt(headers: &HeaderMap) -> bool {
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

fn validate_websocket_handshake(headers: &HeaderMap, policy: &ProxyWebSocketConfig) -> Result<()> {
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

fn websocket_subprotocols(headers: &HeaderMap) -> Result<Vec<String>> {
    let Some(value) = single_optional_header_text(headers, header::SEC_WEBSOCKET_PROTOCOL)? else {
        return Ok(Vec::new());
    };
    let mut unique = BTreeSet::new();
    let mut protocols = Vec::new();
    for protocol in value.split(',').map(str::trim) {
        if protocol.is_empty()
            || !protocol.bytes().all(|byte| {
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
            || !unique.insert(protocol.to_owned())
        {
            bail!("WebSocket subprotocol list is invalid");
        }
        protocols.push(protocol.to_owned());
    }
    Ok(protocols)
}

async fn proxy_websocket_request(
    state: &AppState,
    route: &ProxyRouteConfig,
    normalized_path: &str,
    query: &[(String, String)],
    method: Method,
    headers: HeaderMap,
    upgrade: PendingWebSocketUpgrade,
) -> Result<Response> {
    let policy = route
        .websocket
        .clone()
        .context("WebSockets are not enabled for this route")?;
    if method != Method::GET {
        bail!("WebSocket upgrade requires GET");
    }
    validate_websocket_handshake(&headers, &policy)?;
    let profile = state
        .config
        .profiles
        .get(&route.profile)
        .context("proxy profile disappeared")?;
    let secrets = fetch_secrets(state, profile).await?;
    let (injection_name, injection_value, sensitive_values) =
        build_proxy_injection(route, &secrets)?;
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
    for name in [
        header::ORIGIN,
        header::SEC_WEBSOCKET_KEY,
        header::SEC_WEBSOCKET_VERSION,
        header::SEC_WEBSOCKET_PROTOCOL,
    ] {
        if let Some(value) = headers.get(&name) {
            outbound_headers.insert(name, value.clone());
        }
    }
    outbound_headers.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    outbound_headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    outbound_headers.remove(&injection_name);
    outbound_headers.insert(injection_name, injection_value);

    let upstream = state
        .websocket_client
        .request(method, target)
        .headers(outbound_headers)
        .send()
        .await?;
    if upstream.status() != StatusCode::SWITCHING_PROTOCOLS
        || !header_contains_token(upstream.headers(), header::CONNECTION, "upgrade")
        || !single_header_equals(upstream.headers(), header::UPGRADE, "websocket")
        || upstream
            .headers()
            .contains_key(header::SEC_WEBSOCKET_EXTENSIONS)
    {
        bail!("upstream rejected or returned an unsafe WebSocket upgrade");
    }
    let request_key = single_header_text(&headers, header::SEC_WEBSOCKET_KEY)?;
    let expected_accept = derive_accept_key(request_key.as_bytes());
    if single_header_text(upstream.headers(), header::SEC_WEBSOCKET_ACCEPT)? != expected_accept {
        bail!("upstream returned an invalid WebSocket accept value");
    }
    let requested_protocols = websocket_subprotocols(&headers)?;
    let selected_protocol =
        single_optional_header_text(upstream.headers(), header::SEC_WEBSOCKET_PROTOCOL)?
            .map(str::to_owned);
    if selected_protocol.as_ref().is_some_and(|selected| {
        !requested_protocols
            .iter()
            .any(|requested| requested == selected)
            || !policy
                .allowed_subprotocols
                .iter()
                .any(|allowed| allowed == selected)
    }) {
        bail!("upstream selected an unrequested WebSocket subprotocol");
    }
    let upstream_upgrade = upstream.upgrade().await?;
    let session = WebSocketSessionContext {
        state: state.clone(),
        token_hash: upgrade.token_hash,
        session_id: upgrade.session_id,
        profile: route.profile.clone(),
        policy,
        sensitive_values,
    };
    tokio::spawn(async move {
        let result = async {
            let client = upgrade.client.await.context("upgrade WebSocket client")?;
            relay_websocket_session(client, upstream_upgrade, session).await
        }
        .await;
        if let Err(error) = result {
            tracing::debug!(%error, "transparent WebSocket session ended");
        }
    });

    let mut response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::CONNECTION, "Upgrade")
        .header(header::UPGRADE, "websocket")
        .header(header::SEC_WEBSOCKET_ACCEPT, expected_accept);
    if let Some(protocol) = selected_protocol {
        response = response.header(header::SEC_WEBSOCKET_PROTOCOL, protocol);
    }
    Ok(response.body(axum::body::Body::empty())?)
}

struct PendingWebSocketUpgrade {
    client: hyper::upgrade::OnUpgrade,
    token_hash: [u8; 32],
    session_id: String,
}

struct WebSocketSessionContext {
    state: AppState,
    token_hash: [u8; 32],
    session_id: String,
    profile: String,
    policy: ProxyWebSocketConfig,
    sensitive_values: Vec<Vec<u8>>,
}

async fn relay_websocket_session(
    client: hyper::upgrade::Upgraded,
    upstream: reqwest::Upgraded,
    session: WebSocketSessionContext,
) -> Result<()> {
    relay_websocket_streams(TokioIo::new(client), upstream, session).await
}

async fn relay_websocket_streams(
    client: impl AsyncRead + AsyncWrite + Unpin,
    upstream: impl AsyncRead + AsyncWrite + Unpin,
    session: WebSocketSessionContext,
) -> Result<()> {
    let WebSocketSessionContext {
        state,
        token_hash,
        session_id,
        profile,
        policy,
        sensitive_values,
    } = session;
    let websocket_config = WebSocketConfig::default()
        .write_buffer_size(0)
        .max_write_buffer_size(policy.max_message_bytes.saturating_add(1024))
        .max_message_size(Some(policy.max_message_bytes))
        .max_frame_size(Some(policy.max_message_bytes));
    let mut client =
        WebSocketStream::from_raw_socket(client, Role::Server, Some(websocket_config)).await;
    let mut upstream =
        WebSocketStream::from_raw_socket(upstream, Role::Client, Some(websocket_config)).await;
    let deadline = tokio::time::sleep(Duration::from_secs(policy.max_duration_seconds));
    tokio::pin!(deadline);
    let mut session_check = tokio::time::interval(Duration::from_secs(1));
    session_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut total_bytes = 0_u64;

    loop {
        tokio::select! {
            _ = &mut deadline => bail!("WebSocket lifetime limit reached"),
            _ = session_check.tick() => {
                if !websocket_session_is_active(&state, &token_hash, &session_id, &profile).await? {
                    bail!("WebSocket session was revoked, expired, or lost its grant");
                }
            }
            incoming = client.next() => {
                let Some(message) = incoming else {
                    return Ok(());
                };
                let message = message.context("read caller WebSocket message")?;
                total_bytes = total_bytes.saturating_add(message.len() as u64);
                if total_bytes > policy.max_total_bytes {
                    bail!("WebSocket byte limit reached");
                }
                let closed = message.is_close();
                let message = redact_websocket_message(message, &sensitive_values)?;
                tokio::time::timeout(Duration::from_secs(5), upstream.send(message))
                    .await
                    .context("upstream WebSocket write timed out")??;
                if closed {
                    return Ok(());
                }
            }
            incoming = upstream.next() => {
                let Some(message) = incoming else {
                    return Ok(());
                };
                let message = message.context("read upstream WebSocket message")?;
                total_bytes = total_bytes.saturating_add(message.len() as u64);
                if total_bytes > policy.max_total_bytes {
                    bail!("WebSocket byte limit reached");
                }
                let closed = message.is_close();
                let message = redact_websocket_message(message, &sensitive_values)?;
                tokio::time::timeout(Duration::from_secs(5), client.send(message))
                    .await
                    .context("caller WebSocket write timed out")??;
                if closed {
                    return Ok(());
                }
            }
        }
    }
}

async fn websocket_session_is_active(
    state: &AppState,
    token_hash: &[u8; 32],
    session_id: &str,
    profile: &str,
) -> Result<bool> {
    let store = state
        .store
        .as_ref()
        .context("managed proxy sessions are required")?;
    let Some(session) = store.active_proxy_session(token_hash).await? else {
        return Ok(false);
    };
    if session.session_id != session_id || session.profile != profile {
        return Ok(false);
    }
    profile_permitted(state, &session.subject, profile, GrantMode::Proxy).await
}

fn redact_websocket_message(message: Message, sensitive_values: &[Vec<u8>]) -> Result<Message> {
    Ok(match message {
        Message::Text(value) => Message::Text(
            String::from_utf8(redact_secrets(value.as_bytes(), sensitive_values))?.into(),
        ),
        Message::Binary(value) => {
            Message::Binary(Bytes::from(redact_secrets(&value, sensitive_values)))
        }
        Message::Ping(value) => {
            Message::Ping(Bytes::from(redact_secrets(&value, sensitive_values)))
        }
        Message::Pong(value) => {
            Message::Pong(Bytes::from(redact_secrets(&value, sensitive_values)))
        }
        Message::Close(frame) => Message::Close(
            frame
                .map(|frame| {
                    let reason = String::from_utf8(redact_secrets(
                        frame.reason.as_bytes(),
                        sensitive_values,
                    ))?;
                    Ok::<_, anyhow::Error>(tokio_tungstenite::tungstenite::protocol::CloseFrame {
                        code: frame.code,
                        reason: reason.into(),
                    })
                })
                .transpose()?,
        ),
        Message::Frame(_) => bail!("raw WebSocket frames are not supported"),
    })
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
    let (injection_name, injection_value, mut sensitive_values) =
        build_proxy_injection(route, &secrets)?;
    let (body, body_sensitive_values) = apply_body_substitutions(route, &secrets, &body)?;
    sensitive_values.extend(body_sensitive_values);
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
    outbound_headers.remove(&injection_name);
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
        .is_some_and(|length| length > route.max_response_bytes as u64)
    {
        bail!("upstream response is too large");
    }
    let upstream_headers = upstream.headers().clone();
    let mut response = Response::builder().status(status);
    for configured in &route.allowed_response_headers {
        let name = HeaderName::from_bytes(configured.as_bytes())?;
        if let Some(value) = upstream_headers.get(&name)
            && let Some(value) = redact_header(value, &sensitive_values)
        {
            response = response.header(name, value);
        }
    }
    match route.response_mode {
        ProxyResponseMode::Buffered => {
            let mut bytes = Vec::new();
            while let Some(chunk) = upstream.chunk().await? {
                if bytes.len().saturating_add(chunk.len()) > route.max_response_bytes {
                    bail!("upstream response is too large");
                }
                bytes.extend_from_slice(&chunk);
            }
            let bytes = redact_secrets(&bytes, &sensitive_values);
            Ok(response.body(axum::body::Body::from(bytes))?)
        }
        ProxyResponseMode::Streaming => {
            let maximum = route.max_response_bytes;
            let redactor = StreamingRedactor::new_multiple(&sensitive_values);
            let body_stream = stream::try_unfold(
                (upstream, redactor, 0_usize, false),
                move |(mut upstream, mut redactor, mut total, finished)| async move {
                    if finished {
                        return Ok(None);
                    }
                    loop {
                        match upstream.chunk().await.map_err(io::Error::other)? {
                            Some(chunk) => {
                                total = total.saturating_add(chunk.len());
                                if total > maximum {
                                    return Err(io::Error::other(
                                        "upstream streaming response is too large",
                                    ));
                                }
                                let output = redactor.push(&chunk);
                                if !output.is_empty() {
                                    return Ok(Some((
                                        Bytes::from(output),
                                        (upstream, redactor, total, false),
                                    )));
                                }
                            }
                            None => {
                                let output = redactor.finish();
                                if output.is_empty() {
                                    return Ok(None);
                                }
                                return Ok(Some((
                                    Bytes::from(output),
                                    (upstream, redactor, total, true),
                                )));
                            }
                        }
                    }
                },
            );
            Ok(response.body(axum::body::Body::from_stream(body_stream))?)
        }
    }
}

fn build_proxy_injection(
    route: &ProxyRouteConfig,
    secrets: &BTreeMap<String, String>,
) -> Result<(HeaderName, HeaderValue, Vec<Vec<u8>>)> {
    let (name, value, mut sensitive_values) = match &route.injection {
        None => {
            let secret = secrets
                .get(&route.secret_key)
                .context("proxy credential is unavailable")?;
            (
                route.header.as_str(),
                format!("{}{}", route.header_prefix, secret),
                vec![secret.as_bytes().to_vec()],
            )
        }
        Some(ProxyInjectionConfig::Bearer { secret_key }) => {
            let secret = secrets
                .get(secret_key)
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
            let secret = secrets
                .get(secret_key)
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
            let password = secrets
                .get(password_secret_key)
                .context("proxy basic password is unavailable")?;
            let pair = format!("{username}:{password}");
            let value = format!("Basic {}", STANDARD.encode(pair.as_bytes()));
            (
                "authorization",
                value,
                vec![password.as_bytes().to_vec(), pair.into_bytes()],
            )
        }
    };
    sensitive_values.push(value.as_bytes().to_vec());
    let name = HeaderName::from_bytes(name.as_bytes())?;
    let mut value = HeaderValue::from_str(&value)?;
    value.set_sensitive(true);
    Ok((name, value, sensitive_values))
}

fn apply_body_substitutions(
    route: &ProxyRouteConfig,
    secrets: &BTreeMap<String, String>,
    body: &[u8],
) -> Result<(Bytes, Vec<Vec<u8>>)> {
    let mut output = body.to_vec();
    let mut sensitive_values = Vec::with_capacity(route.body_substitutions.len());
    for (placeholder, secret_key) in &route.body_substitutions {
        let secret = secrets
            .get(secret_key)
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
    Ok((Bytes::from(output), sensitive_values))
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
    let mut acquisition = acquire_secrets(state, profile).await?;
    let connector = state
        .connectors
        .get(&profile.connector)
        .context("profile connector disappeared")?;
    if let Some(lease) = acquisition.lease.take() {
        if let Err(error) = connector.revoke(&lease).await {
            tracing::error!(
                profile_connector = %profile.connector,
                %error,
                "revoke unsupported dynamic lease handoff"
            );
        }
        bail!("dynamic lease delivery is not available through this path yet");
    }
    Ok(acquisition.values)
}

async fn acquire_secrets(state: &AppState, profile: &ProfileConfig) -> Result<SecretAcquisition> {
    let _permit = tokio::time::timeout(Duration::from_secs(5), state.connector_slots.acquire())
        .await
        .context("connector concurrency queue timed out")?
        .context("connector concurrency limiter is closed")?;
    state
        .connectors
        .get(&profile.connector)
        .context("profile connector disappeared")?
        .acquire(profile)
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

struct StreamingRedactor {
    pending: Vec<u8>,
    patterns: Vec<Vec<u8>>,
    maximum_pattern_length: usize,
}

impl StreamingRedactor {
    #[cfg(test)]
    fn new(secret: &[u8]) -> Self {
        Self::new_multiple(&[secret.to_vec()])
    }

    fn new_multiple(secrets: &[Vec<u8>]) -> Self {
        let mut patterns = secrets
            .iter()
            .flat_map(|secret| credential_encodings(secret))
            .filter(|pattern| !pattern.is_empty())
            .collect::<Vec<_>>();
        patterns.sort_by_key(|value| std::cmp::Reverse(value.len()));
        patterns.dedup();
        let maximum_pattern_length = patterns.iter().map(Vec::len).max().unwrap_or(1);
        Self {
            pending: Vec::new(),
            patterns,
            maximum_pattern_length,
        }
    }

    fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(chunk);
        self.emit(false)
    }

    fn finish(&mut self) -> Vec<u8> {
        self.emit(true)
    }

    fn emit(&mut self, finished: bool) -> Vec<u8> {
        let safe_limit = if finished {
            self.pending.len()
        } else {
            self.pending
                .len()
                .saturating_sub(self.maximum_pattern_length.saturating_sub(1))
        };
        let mut consumed = 0;
        let mut output = Vec::with_capacity(safe_limit);
        while consumed < safe_limit {
            if let Some(pattern) = self
                .patterns
                .iter()
                .find(|pattern| self.pending[consumed..].starts_with(pattern.as_slice()))
            {
                output.extend_from_slice(b"[REDACTED]");
                consumed += pattern.len();
            } else {
                output.push(self.pending[consumed]);
                consumed += 1;
            }
        }
        self.pending.drain(..consumed);
        output
    }
}

#[cfg(test)]
fn redact(body: &[u8], secret: &[u8]) -> Vec<u8> {
    redact_secrets(body, &[secret.to_vec()])
}

fn redact_secrets(body: &[u8], secrets: &[Vec<u8>]) -> Vec<u8> {
    let mut output = body.to_vec();
    let mut patterns = secrets
        .iter()
        .flat_map(|secret| credential_encodings(secret))
        .collect::<Vec<_>>();
    patterns.sort_by_key(|value| std::cmp::Reverse(value.len()));
    patterns.dedup();
    for pattern in patterns {
        output = redact_exact(&output, &pattern);
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

fn redact_header(value: &HeaderValue, secrets: &[Vec<u8>]) -> Option<HeaderValue> {
    let redacted = redact_secrets(value.as_bytes(), secrets);
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
        pki_types::{
            CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, pem::PemObject,
        },
    };
    use std::{collections::BTreeMap, sync::Arc};
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
        net::TcpStream,
    };
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    fn proxy_route(methods: &[&str], prefixes: &[&str]) -> ProxyRouteConfig {
        ProxyRouteConfig {
            profile: "infra".into(),
            base_url: "https://api.example.com".into(),
            secret_key: "API_TOKEN".into(),
            header: "Authorization".into(),
            header_prefix: "Bearer ".into(),
            injection: None,
            body_substitutions: BTreeMap::new(),
            allowed_methods: methods.iter().map(|value| (*value).into()).collect(),
            allowed_path_prefixes: prefixes.iter().map(|value| (*value).into()).collect(),
            allowed_request_headers: vec!["accept".into(), "content-type".into()],
            allowed_response_headers: vec!["content-type".into()],
            allowed_query_parameters: vec!["source".into()],
            allowed_content_types: vec!["application/json".into()],
            max_body_bytes: 1024,
            response_mode: crate::config::ProxyResponseMode::Buffered,
            max_response_bytes: 4 * 1024 * 1024,
            websocket: None,
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
            database_credentials_file: String::new(),
            postgres: None,
            database_reload_interval_seconds: 0,
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
        let expiry: i64 = (SystemTime::now() + Duration::from_secs(60))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .try_into()
            .unwrap();
        store
            .create_proxy_session(
                &credential.session_id,
                &credential.token_hash,
                "basic:operator",
                "infra",
                expiry,
                expiry + 60,
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
        let transport_key = KeyPair::generate().unwrap();
        let transport_certificate = CertificateParams::new(vec!["av.example.test".into()])
            .unwrap()
            .self_signed(&transport_key)
            .unwrap();
        let transport_certificate_file = directory.path().join("transport.crt");
        let transport_private_key_file = directory.path().join("transport.key");
        std::fs::write(&transport_certificate_file, transport_certificate.pem()).unwrap();
        std::fs::write(&transport_private_key_file, transport_key.serialize_pem()).unwrap();

        let mut profiles = BTreeMap::new();
        profiles.insert(
            "infra".into(),
            ProfileConfig {
                connector: "unused".into(),
                project_id: "project".into(),
                environment: "dev".into(),
                secret_path: "/".into(),
                allowed_keys: vec![],
                exports: BTreeMap::new(),
                dynamic_secret: None,
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
                database_credentials_file: String::new(),
                postgres: None,
                database_reload_interval_seconds: 0,
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
            proxy_tunnels: BTreeMap::new(),
            transparent_proxy: Some(TransparentProxyConfig {
                listen: "127.0.0.1:0".into(),
                proxy_url: "https://av.example.test:14323".into(),
                transport_tls_certificate_file: transport_certificate_file.display().to_string(),
                transport_tls_private_key_file: transport_private_key_file.display().to_string(),
                ca_certificate_file: ca_certificate_file.display().to_string(),
                ca_private_key_file: ca_private_key_file.display().to_string(),
                session_ttl_seconds: 60,
                session_max_lifetime_seconds: 120,
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
            websocket_client: reqwest::Client::builder().http1_only().build().unwrap(),
            store: Some(store.clone()),
            github_browser_auth: None,
            transparent_proxy: None,
            dynamic_leases: DynamicLeaseRegistry::default(),
        };
        let runtime = Arc::new(TransparentProxyRuntime {
            listen: "127.0.0.1:0".into(),
            proxy_url: "https://av.example.test:14323".into(),
            session_ttl: Duration::from_secs(60),
            session_max_lifetime: Duration::from_secs(120),
            catalog: TransparentRouteCatalog::from_config(&routes, &BTreeMap::new()).unwrap(),
            certificate_authority: ProxyCertificateAuthority::load(
                &ca_certificate_file,
                &ca_private_key_file,
            )
            .unwrap(),
            transport_tls: ReloadingTransportTls::load(
                &transport_certificate_file,
                &transport_private_key_file,
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

    async fn raw_connect(
        stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
        authority: &str,
        token: &str,
    ) -> Vec<u8> {
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

    #[tokio::test]
    async fn network_proxy_listener_requires_verified_transport_tls() {
        let (state, runtime, _store, _token, _ca_der) = transparent_test_context().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(run_transparent_proxy_listener(
            listener,
            state.clone(),
            runtime,
        ));

        let mut plaintext = TcpStream::connect(address).await.unwrap();
        plaintext
            .write_all(b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n")
            .await
            .unwrap();
        let mut rejected = [0_u8; 1];
        match tokio::time::timeout(Duration::from_secs(1), plaintext.read(&mut rejected)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(1)) => assert_ne!(rejected[0], b'H'),
            Ok(Ok(_)) => unreachable!("one-byte read returned more than one byte"),
            Ok(Err(_)) | Err(_) => {}
        }

        let transport_path = std::path::Path::new(
            &state
                .config
                .transparent_proxy
                .as_ref()
                .unwrap()
                .transport_tls_certificate_file,
        );
        let transport_pem = std::fs::read(transport_path).unwrap();
        let transport_certificate = CertificateDer::from_pem_slice(&transport_pem).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(transport_certificate).unwrap();
        let connector = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        let stream = TcpStream::connect(address).await.unwrap();
        let mut stream = connector
            .connect(ServerName::try_from("av.example.test").unwrap(), stream)
            .await
            .unwrap();
        assert!(
            raw_connect(&mut stream, "api.example.com:443", "invalid")
                .await
                .starts_with(b"HTTP/1.1 407")
        );
        task.abort();
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
        let connector = Connector::new(connector_config, true).await.unwrap();
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
    async fn transparent_websocket_injects_redacts_and_stops_when_grant_is_revoked() {
        let (mut state, mut runtime, store, token, proxy_ca_der) = transparent_test_context().await;
        let mut config = (*state.config).clone();
        let route = config.proxy_routes.get_mut("provider").unwrap();
        route.websocket = Some(websocket_policy());
        state.config = Arc::new(config);
        Arc::get_mut(&mut runtime).unwrap().catalog =
            TransparentRouteCatalog::from_config(&state.config.proxy_routes, &BTreeMap::new())
                .unwrap();

        let secrets_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let secrets_address = secrets_listener.local_addr().unwrap();
        let secret_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(secret_file.path(), "connector-test-token\n").unwrap();
        let connector_config: ConnectorConfig = serde_json::from_value(serde_json::json!({
            "base_url": format!("http://{secrets_address}"),
            "auth": {"type": "token", "token_file": secret_file.path()},
        }))
        .unwrap();
        let connector = Connector::new(connector_config, true).await.unwrap();
        state.connectors = Arc::new(BTreeMap::from([("unused".to_owned(), connector)]));
        let secrets_task = tokio::spawn(async move {
            let (mut stream, _) = secrets_listener.accept().await.unwrap();
            let _request = read_test_http_header(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 76\r\nConnection: close\r\n\r\n{\"secrets\":[{\"secretKey\":\"API_TOKEN\",\"secretValue\":\"upstream-test-secret\"}]}" )
                .await
                .unwrap();
        });

        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream_listener.local_addr().unwrap();
        let (upstream_config, upstream_ca_der) = test_upstream_tls_config();
        state.proxy_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(reqwest::Certificate::from_der(&upstream_ca_der).unwrap())
            .resolve("api.example.com", upstream_address)
            .build()
            .unwrap();
        state.websocket_client = reqwest::Client::builder()
            .http1_only()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(reqwest::Certificate::from_der(&upstream_ca_der).unwrap())
            .resolve("api.example.com", upstream_address)
            .build()
            .unwrap();
        let upstream_task = tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let mut stream = TlsAcceptor::from(Arc::new(upstream_config))
                .accept(stream)
                .await
                .unwrap();
            let request = read_test_http_header(&mut stream).await;
            let request_text = String::from_utf8(request).unwrap();
            let request_lower = request_text.to_ascii_lowercase();
            assert!(request_text.starts_with("GET /v1/socket HTTP/1.1\r\n"));
            assert!(request_lower.contains("authorization: bearer upstream-test-secret\r\n"));
            assert!(request_lower.contains("origin: https://app.example.test\r\n"));
            assert!(request_lower.contains("sec-websocket-protocol: events.v1\r\n"));
            let accept = derive_accept_key(b"dGhlIHNhbXBsZSBub25jZQ==");
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: events.v1\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let mut socket = WebSocketStream::from_raw_socket(stream, Role::Server, None).await;
            assert_eq!(
                socket.next().await.unwrap().unwrap(),
                Message::text("caller hello")
            );
            socket
                .send(Message::text("upstream-test-secret from provider"))
                .await
                .unwrap();
            let _ = socket.next().await;
        });

        let (mut proxy, proxy_task) =
            serve_one_transparent_connection(state.clone(), runtime).await;
        assert!(
            raw_connect(&mut proxy, "api.example.com:443", &token)
                .await
                .starts_with(b"HTTP/1.1 200")
        );
        let mut proxy_roots = RootCertStore::empty();
        proxy_roots.add(CertificateDer::from(proxy_ca_der)).unwrap();
        let tls = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(proxy_roots)
                .with_no_client_auth(),
        ));
        let mut tunnel = tls
            .connect(ServerName::try_from("api.example.com").unwrap(), proxy)
            .await
            .unwrap();
        const RFC_WEBSOCKET_REQUEST: &[u8] = b"GET /v1/socket HTTP/1.1\r\nHost: api.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: events.v1\r\nOrigin: https://app.example.test\r\n\r\n"; // gitleaks:allow -- RFC 6455 public example nonce
        tunnel.write_all(RFC_WEBSOCKET_REQUEST).await.unwrap();
        let response = read_test_http_header(&mut tunnel).await;
        assert!(response.starts_with(b"HTTP/1.1 101"));
        let mut socket = WebSocketStream::from_raw_socket(tunnel, Role::Client, None).await;
        socket.send(Message::text("caller hello")).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap(),
            Message::text("[REDACTED] from provider")
        );

        store
            .revoke_profile("basic:operator", "infra")
            .await
            .unwrap();
        let closed = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .expect("WebSocket remained open after grant revocation");
        assert!(closed.is_none() || closed.is_some_and(|result| result.is_err()));

        proxy_task.await.unwrap().unwrap();
        upstream_task.await.unwrap();
        secrets_task.await.unwrap();
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
            agents: vec![OwnerAgent {
                name: "<script>agent</script>".into(),
                enabled: true,
            }],
            profiles: vec!["<script>profile</script>".into()],
            principals: vec![OwnerPrincipal {
                label: "<script>identity</script>".into(),
                kind: "OIDC".into(),
                subject: "<script>subject</script>".into(),
                role: "owner".into(),
                grants: vec![OwnerGrant {
                    profile: "<script>profile</script>".into(),
                    mode: "<script>mode</script>".into(),
                    expires_unix_seconds: None,
                }],
            }],
            issued_agent_credential: Some(IssuedAgentCredential {
                name: "<script>issued</script>".into(),
                token: "<script>token</script>".into(),
            }),
            can_manage_roles: true,
        }
        .render()
        .unwrap();
        assert!(page.contains("&#60;script&#62;user&#60;/script&#62;"));
        assert!(page.contains("&#60;script&#62;identity&#60;/script&#62;"));
        assert!(page.contains("&#60;script&#62;subject&#60;/script&#62;"));
        assert!(page.contains("&#60;script&#62;token&#60;/script&#62;"));
        assert!(!page.contains("<script>subject</script>"));
    }

    #[test]
    fn operator_ui_does_not_render_owner_role_controls() {
        let page = OwnerTemplate {
            basic_users: vec![],
            agents: vec![],
            profiles: vec!["example".into()],
            principals: vec![OwnerPrincipal {
                label: "developer".into(),
                kind: "OIDC".into(),
                subject: "oidc:developer".into(),
                role: "user".into(),
                grants: vec![],
            }],
            issued_agent_credential: None,
            can_manage_roles: false,
        }
        .render()
        .unwrap();
        assert!(!page.contains("/ui/owner/roles"));
        assert!(page.contains("OIDC / user"));
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
    fn streaming_redaction_catches_credentials_split_across_every_chunk_boundary() {
        let secret = b"stream+secret";
        let encoded = STANDARD.encode(secret);
        let percent = url::form_urlencoded::byte_serialize(secret).collect::<String>();
        let input = format!("before stream+secret middle {encoded} after {percent}");
        let mut redactor = StreamingRedactor::new(secret);
        let mut output = Vec::new();
        for byte in input.as_bytes() {
            output.extend(redactor.push(std::slice::from_ref(byte)));
        }
        output.extend(redactor.finish());

        assert!(!output.windows(secret.len()).any(|window| window == secret));
        assert!(
            !output
                .windows(encoded.len())
                .any(|window| window == encoded.as_bytes())
        );
        assert!(
            !output
                .windows(percent.len())
                .any(|window| window == percent.as_bytes())
        );
        assert_eq!(
            std::str::from_utf8(&output)
                .unwrap()
                .matches("[REDACTED]")
                .count(),
            3
        );
    }

    #[test]
    fn credentialless_tunnel_ip_policy_blocks_metadata_and_requires_private_opt_in() {
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
        ] {
            assert!(
                !tunnel_ip_allowed(address.parse().unwrap(), true),
                "{address}"
            );
        }
    }

    #[tokio::test]
    async fn credentialless_tunnel_relays_bytes_without_http_or_tls_interception() {
        let (mut child, helper_side) = tokio::io::duplex(1024);
        let (upstream_side, mut upstream) = tokio::io::duplex(1024);
        let relay = tokio::spawn(relay_credentialless_tunnel(helper_side, upstream_side));

        child.write_all(b"opaque-client-tls").await.unwrap();
        let mut request = [0_u8; 17];
        upstream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"opaque-client-tls");

        upstream.write_all(b"opaque-server-tls").await.unwrap();
        let mut response = [0_u8; 17];
        child.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"opaque-server-tls");

        drop(child);
        drop(upstream);
        relay.await.unwrap().unwrap();
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

    #[test]
    fn typed_proxy_injection_constructs_credentials_inside_av() {
        let secrets = BTreeMap::from([("API_TOKEN".into(), "secret+value".into())]);
        let mut route = proxy_route(&["POST"], &["/"]);
        route.secret_key.clear();
        route.header.clear();
        route.header_prefix.clear();
        route.injection = Some(ProxyInjectionConfig::Basic {
            username: "service-user".into(),
            password_secret_key: "API_TOKEN".into(),
        });
        let (name, value, sensitive) = build_proxy_injection(&route, &secrets).unwrap();
        assert_eq!(name, header::AUTHORIZATION);
        assert_eq!(
            value,
            HeaderValue::from_static("Basic c2VydmljZS11c2VyOnNlY3JldCt2YWx1ZQ==")
        );
        let reflected = redact_secrets(value.as_bytes(), &sensitive);
        assert_eq!(reflected, b"[REDACTED]");
    }

    #[test]
    fn body_substitution_requires_every_placeholder_exactly_once() {
        let secrets = BTreeMap::from([("API_TOKEN".into(), "secret+value".into())]);
        let mut route = proxy_route(&["POST"], &["/"]);
        route
            .body_substitutions
            .insert("__AV_SECRET_TOKEN__".into(), "API_TOKEN".into());
        let (body, sensitive) =
            apply_body_substitutions(&route, &secrets, br#"{"token":"__AV_SECRET_TOKEN__"}"#)
                .unwrap();
        assert_eq!(body, r#"{"token":"secret+value"}"#);
        assert_eq!(
            redact_secrets(&body, &sensitive),
            br#"{"token":"[REDACTED]"}"#
        );
        assert!(apply_body_substitutions(&route, &secrets, b"missing").is_err());
        assert!(
            apply_body_substitutions(&route, &secrets, b"__AV_SECRET_TOKEN____AV_SECRET_TOKEN__")
                .is_err()
        );
    }

    fn websocket_policy() -> ProxyWebSocketConfig {
        ProxyWebSocketConfig {
            allowed_origins: vec!["https://app.example.test".into()],
            allow_missing_origin: false,
            allowed_subprotocols: vec!["events.v1".into()],
            max_duration_seconds: 60,
            max_message_bytes: 1024,
            max_total_bytes: 4096,
        }
    }

    fn websocket_headers() -> HeaderMap {
        HeaderMap::from_iter([
            (
                header::CONNECTION,
                HeaderValue::from_static("keep-alive, Upgrade"),
            ),
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
        ])
    }

    #[test]
    fn websocket_handshake_is_explicit_and_rejects_extensions_or_untrusted_origins() {
        let policy = websocket_policy();
        let mut headers = websocket_headers();
        assert!(validate_websocket_handshake(&headers, &policy).is_ok());
        headers.insert(
            header::SEC_WEBSOCKET_EXTENSIONS,
            HeaderValue::from_static("permessage-deflate"),
        );
        assert!(validate_websocket_handshake(&headers, &policy).is_err());
        headers.remove(header::SEC_WEBSOCKET_EXTENSIONS);
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://hostile.example"),
        );
        assert!(validate_websocket_handshake(&headers, &policy).is_err());
    }

    #[tokio::test]
    async fn websocket_relay_redacts_both_directions_and_stops_on_revocation() {
        let (state, _runtime, store, token, _ca_der) = transparent_test_context().await;
        let token_hash = proxy_session_token_hash(token.as_bytes());
        let session = store
            .active_proxy_session(&token_hash)
            .await
            .unwrap()
            .unwrap();
        let (caller_io, relay_client) = tokio::io::duplex(4096);
        let (relay_upstream, provider_io) = tokio::io::duplex(4096);
        let relay = tokio::spawn(relay_websocket_streams(
            relay_client,
            relay_upstream,
            WebSocketSessionContext {
                state,
                token_hash,
                session_id: session.session_id.clone(),
                profile: session.profile.clone(),
                policy: websocket_policy(),
                sensitive_values: vec![b"provider-secret".to_vec()],
            },
        ));
        let mut caller = WebSocketStream::from_raw_socket(caller_io, Role::Client, None).await;
        let mut provider = WebSocketStream::from_raw_socket(provider_io, Role::Server, None).await;

        provider
            .send(Message::text("provider-secret from upstream"))
            .await
            .unwrap();
        assert_eq!(
            caller.next().await.unwrap().unwrap(),
            Message::text("[REDACTED] from upstream")
        );
        caller
            .send(Message::binary(b"caller provider-secret".as_slice()))
            .await
            .unwrap();
        assert_eq!(
            provider.next().await.unwrap().unwrap(),
            Message::binary(b"caller [REDACTED]".as_slice())
        );

        assert!(
            store
                .revoke_proxy_session(&session.session_id)
                .await
                .unwrap()
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(2), relay)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
    }

    #[tokio::test]
    async fn websocket_relay_enforces_the_bidirectional_byte_ceiling() {
        let (state, _runtime, store, token, _ca_der) = transparent_test_context().await;
        let token_hash = proxy_session_token_hash(token.as_bytes());
        let session = store
            .active_proxy_session(&token_hash)
            .await
            .unwrap()
            .unwrap();
        let (caller_io, relay_client) = tokio::io::duplex(4096);
        let (relay_upstream, provider_io) = tokio::io::duplex(4096);
        let mut policy = websocket_policy();
        policy.max_total_bytes = 4;
        let relay = tokio::spawn(relay_websocket_streams(
            relay_client,
            relay_upstream,
            WebSocketSessionContext {
                state,
                token_hash,
                session_id: session.session_id,
                profile: session.profile,
                policy,
                sensitive_values: vec![b"provider-secret".to_vec()],
            },
        ));
        let mut caller = WebSocketStream::from_raw_socket(caller_io, Role::Client, None).await;
        let _provider = WebSocketStream::from_raw_socket(provider_io, Role::Server, None).await;
        caller.send(Message::text("12345")).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), relay)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
    }

    #[tokio::test]
    async fn dynamic_lease_handles_are_subject_bound_and_non_replayable() {
        let registry = DynamicLeaseRegistry::default();
        let lease = BackendLease::OpenBao(crate::connector::OpenBaoLease {
            id: Zeroizing::new("database/creds/example/synthetic".into()),
            renewable: true,
            expires_at: SystemTime::now() + Duration::from_secs(60),
            renew_increment: Duration::from_secs(30),
        });
        let handle = match registry
            .insert(
                "oidc:owner".into(),
                "database".into(),
                "openbao".into(),
                lease,
            )
            .await
        {
            Ok(handle) => handle,
            Err(_) => panic!("synthetic lease should fit in an empty registry"),
        };
        assert!(validate_dynamic_lease_handle(&handle).is_ok());
        assert!(
            registry
                .take_for_subject(&handle, "oidc:other")
                .await
                .is_none()
        );
        let active = registry
            .take_for_subject(&handle, "oidc:owner")
            .await
            .unwrap();
        assert_eq!(active.profile, "database");
        assert!(
            registry
                .take_for_subject(&handle, "oidc:owner")
                .await
                .is_none()
        );
        assert!(validate_dynamic_lease_handle("database/creds/provider/id").is_err());
    }
}
