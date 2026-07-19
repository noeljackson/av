use std::{collections::BTreeMap, net::IpAddr, path::Path};

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
    pub connectors: BTreeMap<String, InfisicalConfig>,
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
#[serde(deny_unknown_fields)]
pub struct InfisicalConfig {
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
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    pub connector: String,
    pub project_id: String,
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

        match self.auth.mode {
            AuthMode::Oidc | AuthMode::OidcOrBasic => {
                if self.auth.issuer.is_empty() || self.auth.client_id.is_empty() {
                    bail!("OIDC requires issuer and client_id");
                }
                if self.auth.allowed_groups.is_empty() {
                    bail!("OIDC requires at least one allowed_group");
                }
                Url::parse(&self.auth.issuer).context("auth.issuer must be a URL")?;
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

        for (name, profile) in &self.profiles {
            validate_name("profile", name)?;
            if !self.connectors.contains_key(&profile.connector) {
                bail!(
                    "profile {name} references unknown connector {}",
                    profile.connector
                );
            }
            if !profile.secret_path.starts_with('/') {
                bail!("profile {name} secret_path must start with /");
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
            if base.scheme() != "https" || base.host_str().is_none() {
                bail!("proxy route {name} base_url must be an HTTPS origin");
            }
            if route.allowed_methods.is_empty() || route.allowed_path_prefixes.is_empty() {
                bail!("proxy route {name} must constrain both methods and path prefixes");
            }
            if !route.header.eq_ignore_ascii_case("authorization")
                && !route.header.to_ascii_lowercase().starts_with("x-")
            {
                bail!("proxy route {name} may inject Authorization or an X-* header only");
            }
        }

        Ok(())
    }
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
            InfisicalConfig {
                base_url: "https://infisical.example".into(),
                auth: InfisicalAuth::Kubernetes {
                    identity_id: "identity".into(),
                    token_file: "/token".into(),
                },
            },
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
}
