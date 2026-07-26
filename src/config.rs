use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    path::Path,
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_public_url")]
    pub public_url: String,
    #[serde(default)]
    pub mode: ConfigMode,
    #[serde(default)]
    pub managed: Option<ManagedConfig>,
    pub auth: AuthConfig,
    #[serde(default)]
    pub connectors: BTreeMap<String, ConnectorConfig>,
    #[serde(default)]
    pub profiles: BTreeMap<String, ProfileConfig>,
    #[serde(default)]
    pub proxy_routes: BTreeMap<String, ProxyRouteConfig>,
    /// The planned private CONNECT/MITM listener. It is intentionally absent
    /// from ordinary deployments and must never share the public API listener.
    #[serde(default)]
    pub transparent_proxy: Option<TransparentProxyConfig>,
    #[serde(default = "default_max_connector_concurrency")]
    pub max_connector_concurrency: usize,
    #[serde(default = "default_api_rate_limit_per_second")]
    pub api_rate_limit_per_second: u32,
    #[serde(default = "default_api_rate_limit_burst")]
    pub api_rate_limit_burst: u32,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfigMode {
    #[default]
    Static,
    Managed,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedConfig {
    /// Absolute file path mounted from an existing Secret. The database URL is
    /// never accepted from Helm values or written to AV's database.
    pub database_url_file: String,
    /// Exact OIDC subject that becomes the first owner on an empty shared
    /// control-plane database. Local Basic bootstrap is added by `av local init`.
    #[serde(default)]
    pub initial_owner_oidc_subject: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    Oidc,
    Basic,
    OidcOrBasic,
    GithubOrBasic,
    Disabled,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub mode: AuthMode,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub audiences: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default = "default_oidc_signing_algorithms")]
    pub signing_algorithms: Vec<OidcSigningAlgorithm>,
    #[serde(default)]
    pub allowed_groups: Vec<String>,
    #[serde(default = "default_group_claim")]
    pub group_claim: String,
    #[serde(default)]
    pub basic_users: Vec<BasicUserConfig>,
    #[serde(default)]
    pub github: Option<GithubAuthConfig>,
}

/// GitHub OAuth is deliberately limited to a loopback managed instance. It
/// authenticates the local browser UI only; GitHub access tokens never become
/// AV API credentials.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubAuthConfig {
    pub client_id: String,
    pub client_secret_file: String,
    /// Immutable GitHub numeric account IDs permitted to use the local UI.
    #[serde(default)]
    pub allowed_user_ids: Vec<u64>,
    /// GitHub organization slugs whose active members may use the local UI.
    #[serde(default)]
    pub allowed_organizations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BasicUserConfig {
    pub username: String,
    pub password_hash_file: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub enum OidcSigningAlgorithm {
    #[serde(rename = "RS256")]
    Rs256,
    #[serde(rename = "RS384")]
    Rs384,
    #[serde(rename = "RS512")]
    Rs512,
    #[serde(rename = "PS256")]
    Ps256,
    #[serde(rename = "PS384")]
    Ps384,
    #[serde(rename = "PS512")]
    Ps512,
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "ES384")]
    Es384,
    #[serde(rename = "EdDSA")]
    EdDsa,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum ConnectorConfig {
    OpenBao(OpenBaoConfig),
    Infisical(InfisicalConfig),
}

impl ConnectorConfig {
    pub fn base_url(&self) -> &str {
        match self {
            Self::OpenBao(config) => &config.base_url,
            Self::Infisical(config) => &config.base_url,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::OpenBao(_) => "openbao",
            Self::Infisical(_) => "infisical",
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InfisicalKind {
    #[default]
    Infisical,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfisicalConfig {
    #[serde(default, rename = "kind")]
    _kind: InfisicalKind,
    pub base_url: String,
    pub auth: InfisicalAuth,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum InfisicalAuth {
    Kubernetes {
        identity_id: String,
        #[serde(default = "default_service_account_token_file")]
        token_file: String,
    },
    Universal {
        client_id_file: String,
        client_secret_file: String,
    },
    Token {
        token_file: String,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OpenBaoKind {
    #[serde(rename = "openbao")]
    OpenBao,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenBaoConfig {
    #[serde(rename = "kind")]
    _kind: OpenBaoKind,
    pub base_url: String,
    #[serde(default)]
    pub namespace: String,
    pub auth: OpenBaoAuth,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum OpenBaoAuth {
    #[serde(rename = "approle")]
    AppRole {
        role_id_file: String,
        secret_id_file: String,
        #[serde(default = "default_approle_mount_path")]
        mount_path: String,
    },
    Kubernetes {
        role: String,
        #[serde(default = "default_service_account_token_file")]
        token_file: String,
        #[serde(default = "default_kubernetes_mount_path")]
        mount_path: String,
    },
    Token {
        token_file: String,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    pub connector: String,
    #[serde(default)]
    pub project_id: String,
    #[serde(default)]
    pub environment: String,
    #[serde(default = "default_secret_path")]
    pub secret_path: String,
    #[serde(default)]
    pub allowed_keys: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyRouteConfig {
    pub profile: String,
    pub base_url: String,
    pub secret_key: String,
    pub header: String,
    #[serde(default)]
    pub header_prefix: String,
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    #[serde(default)]
    pub allowed_path_prefixes: Vec<String>,
    #[serde(default = "default_allowed_request_headers")]
    pub allowed_request_headers: Vec<String>,
    #[serde(default = "default_allowed_response_headers")]
    pub allowed_response_headers: Vec<String>,
    #[serde(default)]
    pub allowed_query_parameters: Vec<String>,
    #[serde(default)]
    pub allowed_content_types: Vec<String>,
    #[serde(default = "default_proxy_max_body_bytes")]
    pub max_body_bytes: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransparentProxyConfig {
    /// Private TCP listener for CONNECT traffic. This must be exposed only by
    /// a private Service; public exposure is rejected by chart policy as well.
    pub listen: String,
    /// Private HTTP forward-proxy URL used by local helpers. This is separate
    /// from the public control API URL and must not include credentials.
    pub proxy_url: String,
    /// PEM-encoded deployment CA certificate mounted from an existing Secret.
    pub ca_certificate_file: String,
    /// PEM-encoded deployment CA private key mounted from an existing Secret.
    pub ca_private_key_file: String,
    #[serde(default = "default_proxy_session_ttl_seconds")]
    pub session_ttl_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicAuthConfig {
    pub mode: String,
    pub issuer: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub device_authorization_endpoint: Option<String>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read configuration {}", path.display()))?;
        let config: Self = serde_json::from_str(&raw)
            .with_context(|| format!("parse JSON configuration {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        let public_url = Url::parse(&self.public_url).context("public_url must be a URL")?;
        if public_url.scheme() != "https" && !public_url.host_str().is_some_and(is_loopback_host) {
            bail!("public_url must use HTTPS unless it is loopback");
        }
        if public_url.host_str().is_none()
            || has_url_credentials(&public_url)
            || public_url.query().is_some()
            || public_url.fragment().is_some()
            || !matches!(public_url.path(), "" | "/")
        {
            bail!("public_url must be an origin without credentials, query, fragment, or path");
        }

        match (self.mode, &self.managed) {
            (ConfigMode::Static, None) => {}
            (ConfigMode::Static, Some(_)) => {
                bail!("managed configuration is only valid when mode is managed")
            }
            (ConfigMode::Managed, Some(managed)) => {
                if !Path::new(&managed.database_url_file).is_absolute() {
                    bail!("managed.database_url_file must be an absolute path");
                }
                if managed.initial_owner_oidc_subject.trim().is_empty() {
                    bail!("managed.initial_owner_oidc_subject must be non-empty");
                }
            }
            (ConfigMode::Managed, None) => bail!("managed mode requires a managed configuration"),
        }

        match self.auth.mode {
            AuthMode::Oidc | AuthMode::OidcOrBasic => {
                if self.auth.issuer.is_empty() || self.auth.client_id.is_empty() {
                    bail!("OIDC requires issuer and client_id");
                }
                if self.auth.allowed_groups.is_empty() {
                    bail!("OIDC requires at least one allowed_group");
                }
                let issuer = Url::parse(&self.auth.issuer).context("auth.issuer must be a URL")?;
                if (issuer.scheme() != "https"
                    && !(issuer.scheme() == "http"
                        && issuer.host_str().is_some_and(is_loopback_host)))
                    || issuer.host_str().is_none()
                    || has_url_credentials(&issuer)
                    || issuer.query().is_some()
                    || issuer.fragment().is_some()
                {
                    bail!("auth.issuer must be a trusted HTTPS URL");
                }
            }
            AuthMode::GithubOrBasic => {
                let github = self
                    .auth
                    .github
                    .as_ref()
                    .context("github_or_basic requires auth.github")?;
                if self.mode != ConfigMode::Managed
                    || !public_url.host_str().is_some_and(is_loopback_host)
                {
                    bail!("github_or_basic is only allowed for a loopback managed instance");
                }
                if github.client_id.trim().is_empty()
                    || (github.allowed_user_ids.is_empty()
                        && github.allowed_organizations.is_empty())
                    || !Path::new(&github.client_secret_file).is_absolute()
                {
                    bail!(
                        "github_or_basic requires a client_id, at least one allowed_user_id or allowed_organization, and an absolute client_secret_file"
                    );
                }
                for organization in &github.allowed_organizations {
                    if !valid_github_organization(organization) {
                        bail!(
                            "github allowed_organizations must contain valid GitHub organization slugs"
                        );
                    }
                }
            }
            AuthMode::Basic => {}
            AuthMode::Disabled => {
                let host = self
                    .listen
                    .rsplit_once(':')
                    .map(|(host, _)| host.trim_matches(['[', ']']))
                    .unwrap_or(&self.listen);
                if !is_loopback_host(host) || std::env::var_os("AV_ALLOW_INSECURE_AUTH").is_none() {
                    bail!(
                        "disabled auth requires a loopback listener and AV_ALLOW_INSECURE_AUTH=1"
                    );
                }
            }
        }
        if self.auth.mode != AuthMode::GithubOrBasic && self.auth.github.is_some() {
            bail!("auth.github is only valid with github_or_basic");
        }

        if matches!(
            self.auth.mode,
            AuthMode::Basic | AuthMode::OidcOrBasic | AuthMode::GithubOrBasic
        ) && self.auth.basic_users.is_empty()
            && self.mode == ConfigMode::Static
        {
            bail!("basic auth mode requires basic_users");
        }
        let mut basic_usernames = BTreeSet::new();
        for user in &self.auth.basic_users {
            if user.username.is_empty()
                || user.username.contains(':')
                || user.username.chars().any(char::is_control)
            {
                bail!("basic auth usernames must be non-empty and may not contain ':' or controls");
            }
            if !basic_usernames.insert(&user.username) {
                bail!("basic auth usernames must be unique");
            }
            if !Path::new(&user.password_hash_file).is_absolute() {
                bail!("basic auth password hash files must use absolute paths");
            }
        }

        if matches!(self.auth.mode, AuthMode::Oidc | AuthMode::OidcOrBasic)
            && self.auth.signing_algorithms.is_empty()
        {
            bail!("OIDC requires at least one asymmetric signing_algorithm");
        }
        if !(1..=256).contains(&self.max_connector_concurrency) {
            bail!("max_connector_concurrency must be between 1 and 256");
        }
        if !(1..=10_000).contains(&self.api_rate_limit_per_second) {
            bail!("api_rate_limit_per_second must be between 1 and 10000");
        }
        if !(1..=50_000).contains(&self.api_rate_limit_burst) {
            bail!("api_rate_limit_burst must be between 1 and 50000");
        }

        let allow_insecure_connector_http = self.allow_insecure_connector_http();
        for (name, connector) in &self.connectors {
            validate_name("connector", name)?;
            let base = Url::parse(connector.base_url())
                .with_context(|| format!("connector {name} base_url must be a URL"))?;
            if base.host_str().is_none()
                || has_url_credentials(&base)
                || base.query().is_some()
                || base.fragment().is_some()
            {
                bail!("connector {name} base_url may not contain credentials, query, or fragment");
            }
            if base.scheme() != "https"
                && !(base.scheme() == "http" && allow_insecure_connector_http)
            {
                bail!("connector {name} base_url must use HTTPS");
            }
            validate_connector_auth(name, connector)?;
        }

        for (name, profile) in &self.profiles {
            validate_name("profile", name)?;
            let Some(connector) = self.connectors.get(&profile.connector) else {
                bail!(
                    "profile {name} references unknown connector {}",
                    profile.connector
                );
            };
            match connector {
                ConnectorConfig::Infisical(_) => {
                    if profile.project_id.is_empty() || profile.environment.is_empty() {
                        bail!("Infisical profile {name} requires project_id and environment");
                    }
                    if !profile.secret_path.starts_with('/') {
                        bail!("Infisical profile {name} secret_path must start with /");
                    }
                }
                ConnectorConfig::OpenBao(_) => {
                    validate_openbao_secret_path(name, &profile.secret_path)?;
                }
            }
        }

        for (name, route) in &self.proxy_routes {
            validate_name("proxy route", name)?;
            if !self.profiles.contains_key(&route.profile) {
                bail!(
                    "proxy route {name} references unknown profile {}",
                    route.profile
                );
            }
            let base = Url::parse(&route.base_url)
                .with_context(|| format!("proxy route {name} base_url must be a URL"))?;
            if base.host_str().is_none()
                || (base.scheme() != "https"
                    && !(base.scheme() == "http" && allow_insecure_connector_http))
            {
                bail!("proxy route {name} base_url must use HTTPS");
            }
            if has_url_credentials(&base) || base.query().is_some() || base.fragment().is_some() {
                bail!(
                    "proxy route {name} base_url may not contain credentials, query, or fragment"
                );
            }
            if route.allowed_methods.is_empty() || route.allowed_path_prefixes.is_empty() {
                bail!("proxy route {name} must constrain both methods and path prefixes");
            }
            if route.allowed_methods.iter().any(|method| {
                !matches!(
                    method.to_ascii_uppercase().as_str(),
                    "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE"
                )
            }) {
                bail!("proxy route {name} contains a non-CRUD HTTP method");
            }
            if route.allowed_path_prefixes.iter().any(|prefix| {
                !prefix.starts_with('/')
                    || prefix.contains(['?', '#', '\\', '%'])
                    || prefix.contains("//")
                    || prefix.chars().any(char::is_control)
                    || prefix
                        .split('/')
                        .any(|segment| matches!(segment, "." | ".."))
            }) {
                bail!("proxy route {name} contains an unsafe path prefix");
            }
            if !route.header.eq_ignore_ascii_case("authorization")
                && !route.header.to_ascii_lowercase().starts_with("x-")
            {
                bail!("proxy route {name} may inject Authorization or an X-* header only");
            }
            if axum::http::HeaderName::from_bytes(route.header.as_bytes()).is_err() {
                bail!("proxy route {name} injection header is invalid");
            }
            validate_proxy_header_allowlist(
                name,
                "request",
                &route.allowed_request_headers,
                Some(&route.header),
            )?;
            validate_proxy_header_allowlist(
                name,
                "response",
                &route.allowed_response_headers,
                None,
            )?;
            validate_string_allowlist(
                name,
                "query parameter",
                &route.allowed_query_parameters,
                |value| {
                    !value.is_empty()
                        && value.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                        })
                },
            )?;
            validate_string_allowlist(
                name,
                "content type",
                &route.allowed_content_types,
                |value| {
                    !value.is_empty()
                        && value == value.to_ascii_lowercase()
                        && !value.contains(';')
                        && value.split_once('/').is_some()
                        && axum::http::HeaderValue::from_str(value).is_ok()
                },
            )?;
            if !(1..=4 * 1024 * 1024).contains(&route.max_body_bytes) {
                bail!("proxy route {name} max_body_bytes must be between 1 and 4194304");
            }
        }

        if let Some(transparent_proxy) = &self.transparent_proxy {
            validate_transparent_proxy(self, transparent_proxy)?;
        }
        Ok(())
    }

    pub fn allow_insecure_connector_http(&self) -> bool {
        let public_host_is_loopback = Url::parse(&self.public_url)
            .ok()
            .and_then(|url| url.host_str().map(is_loopback_host))
            .unwrap_or(false);
        public_host_is_loopback
            && std::env::var("AV_ALLOW_INSECURE_CONNECTORS")
                .is_ok_and(|value| value == "integration-tests-only")
    }
}

fn validate_connector_auth(name: &str, connector: &ConnectorConfig) -> Result<()> {
    let credential_files: Vec<&str> = match connector {
        ConnectorConfig::Infisical(config) => match &config.auth {
            InfisicalAuth::Kubernetes {
                identity_id,
                token_file,
            } => {
                if identity_id.is_empty() {
                    bail!("Infisical connector {name} identity_id may not be empty");
                }
                vec![token_file]
            }
            InfisicalAuth::Universal {
                client_id_file,
                client_secret_file,
            } => vec![client_id_file, client_secret_file],
            InfisicalAuth::Token { token_file } => vec![token_file],
        },
        ConnectorConfig::OpenBao(config) => {
            if !config.namespace.is_empty()
                && axum::http::HeaderValue::from_str(&config.namespace).is_err()
            {
                bail!("OpenBao connector {name} namespace is not a valid HTTP header value");
            }
            match &config.auth {
                OpenBaoAuth::AppRole {
                    role_id_file,
                    secret_id_file,
                    mount_path,
                } => {
                    validate_openbao_mount_path(name, mount_path)?;
                    vec![role_id_file, secret_id_file]
                }
                OpenBaoAuth::Kubernetes {
                    role,
                    token_file,
                    mount_path,
                } => {
                    if role.is_empty() {
                        bail!("OpenBao connector {name} Kubernetes role may not be empty");
                    }
                    validate_openbao_mount_path(name, mount_path)?;
                    vec![token_file]
                }
                OpenBaoAuth::Token { token_file } => vec![token_file],
            }
        }
    };
    if credential_files
        .iter()
        .any(|path| !Path::new(path).is_absolute())
    {
        bail!("connector {name} credential files must use absolute paths");
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
            || axum::http::HeaderName::from_bytes(configured.as_bytes()).is_err()
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

fn validate_transparent_proxy(config: &Config, proxy: &TransparentProxyConfig) -> Result<()> {
    if config.mode != ConfigMode::Managed {
        bail!("transparent_proxy requires managed mode for session revocation");
    }
    let listener = proxy
        .listen
        .parse::<SocketAddr>()
        .context("transparent_proxy.listen must be an IP socket address")?;
    let api_listener = config
        .listen
        .parse::<SocketAddr>()
        .context("listen must be an IP socket address when transparent_proxy is configured")?;
    if listener.port() == 0 || listener == api_listener {
        bail!("transparent_proxy.listen must be a distinct non-zero listener");
    }
    let proxy_url =
        Url::parse(&proxy.proxy_url).context("transparent_proxy.proxy_url must be a URL")?;
    if proxy_url.scheme() != "http"
        || proxy_url.host_str().is_none()
        || proxy_url.port().is_none()
        || has_url_credentials(&proxy_url)
        || proxy_url.query().is_some()
        || proxy_url.fragment().is_some()
        || !matches!(proxy_url.path(), "" | "/")
    {
        bail!(
            "transparent_proxy.proxy_url must be a credential-free HTTP origin with an explicit port"
        );
    }
    let certificate = Path::new(&proxy.ca_certificate_file);
    let private_key = Path::new(&proxy.ca_private_key_file);
    if !certificate.is_absolute() || !private_key.is_absolute() || certificate == private_key {
        bail!("transparent proxy CA certificate and key must be distinct absolute file paths");
    }
    if !(60..=3600).contains(&proxy.session_ttl_seconds) {
        bail!("transparent proxy session_ttl_seconds must be between 60 and 3600");
    }
    if config.proxy_routes.is_empty() {
        bail!("transparent_proxy requires at least one immutable proxy route");
    }
    crate::transparent_proxy::TransparentRouteCatalog::from_proxy_routes(&config.proxy_routes)?;
    Ok(())
}

fn validate_openbao_mount_path(name: &str, mount_path: &str) -> Result<()> {
    let normalized = mount_path.trim_matches('/');
    if normalized.is_empty()
        || normalized.split('/').any(|segment| {
            segment.is_empty()
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
    {
        bail!("OpenBao connector {name} has an invalid auth mount_path");
    }
    Ok(())
}

fn validate_openbao_secret_path(name: &str, secret_path: &str) -> Result<()> {
    let normalized = secret_path.trim_matches('/');
    let lower = normalized.to_ascii_lowercase();
    if normalized.is_empty()
        || secret_path.contains(['?', '#', '\\'])
        || lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || normalized
            .split('/')
            .any(|segment| matches!(segment, "" | "." | ".."))
    {
        bail!("OpenBao profile {name} has an unsafe secret_path");
    }
    Ok(())
}

fn has_url_credentials(url: &Url) -> bool {
    !url.username().is_empty() || url.password().is_some()
}

fn validate_name(kind: &str, name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        bail!("{kind} name {name:?} must use lowercase letters, digits, and hyphens");
    }
    Ok(())
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn default_listen() -> String {
    "127.0.0.1:14322".into()
}

fn default_public_url() -> String {
    "http://127.0.0.1:14322".into()
}

fn default_secret_path() -> String {
    "/".into()
}

fn default_service_account_token_file() -> String {
    "/var/run/secrets/kubernetes.io/serviceaccount/token".into()
}

fn default_approle_mount_path() -> String {
    "approle".into()
}

fn default_kubernetes_mount_path() -> String {
    "kubernetes".into()
}

fn default_group_claim() -> String {
    "groups".into()
}

fn default_oidc_signing_algorithms() -> Vec<OidcSigningAlgorithm> {
    vec![OidcSigningAlgorithm::Rs256]
}

fn default_max_connector_concurrency() -> usize {
    16
}

fn default_api_rate_limit_per_second() -> u32 {
    50
}

fn default_api_rate_limit_burst() -> u32 {
    100
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

fn default_proxy_session_ttl_seconds() -> u64 {
    15 * 60
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn base_config() -> Config {
        Config {
            listen: "127.0.0.1:14322".into(),
            public_url: "http://127.0.0.1:14322".into(),
            mode: ConfigMode::Static,
            managed: None,
            auth: AuthConfig {
                mode: AuthMode::Disabled,
                issuer: String::new(),
                client_id: String::new(),
                audiences: vec![],
                scopes: vec![],
                signing_algorithms: vec![OidcSigningAlgorithm::Rs256],
                allowed_groups: vec![],
                group_claim: "groups".into(),
                basic_users: vec![],
                github: None,
            },
            connectors: BTreeMap::new(),
            profiles: BTreeMap::new(),
            proxy_routes: BTreeMap::new(),
            transparent_proxy: None,
            max_connector_concurrency: 16,
            api_rate_limit_per_second: 50,
            api_rate_limit_burst: 100,
        }
    }

    #[test]
    fn disabled_auth_is_never_accepted_accidentally() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("AV_ALLOW_INSECURE_AUTH") };
        assert!(base_config().validate().is_err());
    }

    #[test]
    fn managed_mode_requires_an_absolute_database_url_file_and_first_owner() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("AV_ALLOW_INSECURE_AUTH", "1") };
        let mut config = base_config();
        config.mode = ConfigMode::Managed;
        config.managed = Some(ManagedConfig {
            database_url_file: "relative/database-url".into(),
            initial_owner_oidc_subject: String::new(),
        });
        assert!(config.validate().is_err());
        config.managed.as_mut().unwrap().database_url_file = "/run/av/database-url".into();
        assert!(config.validate().is_err());
        config.managed.as_mut().unwrap().initial_owner_oidc_subject = "oidc:owner".into();
        assert!(config.validate().is_ok());
        unsafe { std::env::remove_var("AV_ALLOW_INSECURE_AUTH") };
    }

    #[test]
    fn github_browser_auth_is_limited_to_loopback_managed_instances() {
        let mut config = base_config();
        config.mode = ConfigMode::Managed;
        config.managed = Some(ManagedConfig {
            database_url_file: "/run/av/database-url".into(),
            initial_owner_oidc_subject: "github:12345".into(),
        });
        config.auth.mode = AuthMode::GithubOrBasic;
        config.auth.github = Some(GithubAuthConfig {
            client_id: "github-client-id".into(),
            client_secret_file: "/run/av/github-client-secret".into(),
            allowed_user_ids: vec![12345],
            allowed_organizations: vec![],
        });
        assert!(config.validate().is_ok());
        config.public_url = "https://av.example.test".into();
        assert!(config.validate().is_err());
        config.public_url = "http://127.0.0.1:14322".into();
        config.mode = ConfigMode::Static;
        config.managed = None;
        assert!(config.validate().is_err());
    }

    #[test]
    fn github_browser_auth_requires_an_immutable_user_or_valid_organization_policy() {
        let mut config = base_config();
        config.mode = ConfigMode::Managed;
        config.managed = Some(ManagedConfig {
            database_url_file: "/run/av/database-url".into(),
            initial_owner_oidc_subject: "github:12345".into(),
        });
        config.auth.mode = AuthMode::GithubOrBasic;
        config.auth.github = Some(GithubAuthConfig {
            client_id: "github-client-id".into(),
            client_secret_file: "/run/av/github-client-secret".into(),
            allowed_user_ids: vec![],
            allowed_organizations: vec!["example-org".into()],
        });
        assert!(config.validate().is_ok());

        config.auth.github.as_mut().unwrap().allowed_organizations = vec!["invalid_org".into()];
        assert!(config.validate().is_err());
        config.auth.github.as_mut().unwrap().allowed_organizations = vec![];
        assert!(config.validate().is_err());
    }

    #[test]
    fn proxy_requires_a_fixed_https_origin_and_policy() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("AV_ALLOW_INSECURE_AUTH", "1") };
        let mut config = base_config();
        config.connectors.insert(
            "main".into(),
            ConnectorConfig::Infisical(InfisicalConfig {
                _kind: InfisicalKind::Infisical,
                base_url: "https://infisical.example".into(),
                auth: InfisicalAuth::Kubernetes {
                    identity_id: "identity".into(),
                    token_file: "/token".into(),
                },
            }),
        );
        config.profiles.insert(
            "infra".into(),
            ProfileConfig {
                connector: "main".into(),
                project_id: "project".into(),
                environment: "prod".into(),
                secret_path: "/".into(),
                allowed_keys: vec![],
            },
        );
        config.proxy_routes.insert(
            "unsafe".into(),
            ProxyRouteConfig {
                profile: "infra".into(),
                base_url: "http://example.com".into(),
                secret_key: "TOKEN".into(),
                header: "Authorization".into(),
                header_prefix: "Bearer ".into(),
                allowed_methods: vec![],
                allowed_path_prefixes: vec![],
                allowed_request_headers: default_allowed_request_headers(),
                allowed_response_headers: default_allowed_response_headers(),
                allowed_query_parameters: vec![],
                allowed_content_types: vec![],
                max_body_bytes: default_proxy_max_body_bytes(),
            },
        );
        assert!(config.validate().is_err());

        {
            let route = config.proxy_routes.get_mut("unsafe").unwrap();
            route.base_url = "https://api.example.com".into();
            route.header = "X-Api-Key".into();
            route.allowed_methods = vec!["GET".into()];
            route.allowed_path_prefixes = vec!["/zones".into()];
            route.allowed_request_headers = vec!["x-api-key".into()];
        }
        assert!(config.validate().is_err());

        {
            let route = config.proxy_routes.get_mut("unsafe").unwrap();
            route.allowed_request_headers = vec!["accept".into()];
            route.allowed_response_headers = vec!["location".into()];
        }
        assert!(config.validate().is_err());
        unsafe { std::env::remove_var("AV_ALLOW_INSECURE_AUTH") };
    }

    #[test]
    fn transparent_proxy_is_managed_private_and_unambiguous() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("AV_ALLOW_INSECURE_AUTH", "1") };
        let mut config = base_config();
        config.mode = ConfigMode::Managed;
        config.managed = Some(ManagedConfig {
            database_url_file: "/run/av/database-url".into(),
            initial_owner_oidc_subject: "oidc:owner".into(),
        });
        config.connectors.insert(
            "main".into(),
            ConnectorConfig::Infisical(InfisicalConfig {
                _kind: InfisicalKind::Infisical,
                base_url: "https://infisical.example.test".into(),
                auth: InfisicalAuth::Kubernetes {
                    identity_id: "identity".into(),
                    token_file: "/run/token".into(),
                },
            }),
        );
        config.profiles.insert(
            "example".into(),
            ProfileConfig {
                connector: "main".into(),
                project_id: "project".into(),
                environment: "dev".into(),
                secret_path: "/".into(),
                allowed_keys: vec![],
            },
        );
        config.proxy_routes.insert(
            "provider".into(),
            ProxyRouteConfig {
                profile: "example".into(),
                base_url: "https://api.example.test/v1".into(),
                secret_key: "TOKEN".into(),
                header: "Authorization".into(),
                header_prefix: "Bearer ".into(),
                allowed_methods: vec!["GET".into()],
                allowed_path_prefixes: vec!["/v1/".into()],
                allowed_request_headers: vec![],
                allowed_response_headers: vec![],
                allowed_query_parameters: vec![],
                allowed_content_types: vec![],
                max_body_bytes: default_proxy_max_body_bytes(),
            },
        );
        config.transparent_proxy = Some(TransparentProxyConfig {
            listen: "127.0.0.1:14323".into(),
            proxy_url: "http://av-proxy.example.test:14323".into(),
            ca_certificate_file: "/run/av/proxy/ca.crt".into(),
            ca_private_key_file: "/run/av/proxy/ca.key".into(),
            session_ttl_seconds: 900,
        });
        assert!(config.validate().is_ok());

        config.mode = ConfigMode::Static;
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("only valid when mode is managed")
        );
        config.mode = ConfigMode::Managed;
        config.transparent_proxy.as_mut().unwrap().listen = config.listen.clone();
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("distinct")
        );
        config.transparent_proxy.as_mut().unwrap().listen = "127.0.0.1:14323".into();
        config.transparent_proxy.as_mut().unwrap().proxy_url =
            "https://av-proxy.example.test:14323".into();
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("credential-free HTTP origin")
        );
        config.transparent_proxy.as_mut().unwrap().proxy_url =
            "http://av-proxy.example.test:14323".into();
        config
            .transparent_proxy
            .as_mut()
            .unwrap()
            .session_ttl_seconds = 30;
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("between 60 and 3600")
        );
        unsafe { std::env::remove_var("AV_ALLOW_INSECURE_AUTH") };
    }

    #[test]
    fn parses_legacy_infisical_and_typed_openbao_connectors() {
        let legacy: ConnectorConfig = serde_json::from_value(serde_json::json!({
            "base_url": "https://infisical.example",
            "auth": {
                "type": "universal",
                "client_id_file": "/run/client-id",
                "client_secret_file": "/run/client-secret"
            }
        }))
        .unwrap();
        assert!(matches!(legacy, ConnectorConfig::Infisical(_)));

        let openbao: ConnectorConfig = serde_json::from_value(serde_json::json!({
            "kind": "openbao",
            "base_url": "https://openbao.example",
            "auth": {
                "type": "approle",
                "role_id_file": "/run/role-id",
                "secret_id_file": "/run/secret-id"
            }
        }))
        .unwrap();
        assert!(matches!(openbao, ConnectorConfig::OpenBao(_)));
    }
}
fn valid_github_organization(organization: &str) -> bool {
    let bytes = organization.as_bytes();
    (1..=39).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}
