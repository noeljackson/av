use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
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
    #[serde(default = "default_ui_dir")]
    pub ui_dir: String,
    pub auth: AuthConfig,
    #[serde(default)]
    pub connectors: BTreeMap<String, ConnectorConfig>,
    #[serde(default)]
    pub profiles: BTreeMap<String, ProfileConfig>,
    #[serde(default)]
    pub proxy_routes: BTreeMap<String, ProxyRouteConfig>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    Oidc,
    Basic,
    OidcOrBasic,
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
    #[serde(default)]
    pub allowed_groups: Vec<String>,
    #[serde(default = "default_group_claim")]
    pub group_claim: String,
    #[serde(default)]
    pub basic_users: Vec<BasicUserConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BasicUserConfig {
    pub username: String,
    pub password_file: String,
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

        if matches!(self.auth.mode, AuthMode::Basic | AuthMode::OidcOrBasic)
            && self.auth.basic_users.is_empty()
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
            if !Path::new(&user.password_file).is_absolute() {
                bail!("basic auth password files must use absolute paths");
            }
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
                let lower = prefix.to_ascii_lowercase();
                !prefix.starts_with('/')
                    || prefix.contains(['?', '#', '\\'])
                    || lower.contains("%2e")
                    || lower.contains("%2f")
                    || lower.contains("%5c")
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

fn default_ui_dir() -> String {
    "ui/dist".into()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn base_config() -> Config {
        Config {
            listen: "127.0.0.1:14322".into(),
            public_url: "http://127.0.0.1:14322".into(),
            ui_dir: "ui/dist".into(),
            auth: AuthConfig {
                mode: AuthMode::Disabled,
                issuer: String::new(),
                client_id: String::new(),
                audiences: vec![],
                scopes: vec![],
                allowed_groups: vec![],
                group_claim: "groups".into(),
                basic_users: vec![],
            },
            connectors: BTreeMap::new(),
            profiles: BTreeMap::new(),
            proxy_routes: BTreeMap::new(),
        }
    }

    #[test]
    fn disabled_auth_is_never_accepted_accidentally() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("AV_ALLOW_INSECURE_AUTH") };
        assert!(base_config().validate().is_err());
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
            },
        );
        assert!(config.validate().is_err());
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
