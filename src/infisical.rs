use std::{collections::BTreeMap, path::Path, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use tokio::{sync::Mutex, time::Instant};
use url::Url;

use crate::config::{InfisicalAuth, InfisicalConfig, ProfileConfig};

#[derive(Clone)]
pub struct InfisicalConnector {
    config: InfisicalConfig,
    client: reqwest::Client,
    token: Arc<Mutex<Option<CachedToken>>>,
}

struct CachedToken {
    value: String,
    expires_at: Instant,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Deserialize)]
struct SecretsResponse {
    secrets: Vec<Secret>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Secret {
    secret_key: String,
    secret_value: String,
}

impl InfisicalConnector {
    pub fn new(config: InfisicalConfig) -> Result<Self> {
        let base = Url::parse(&config.base_url).context("invalid Infisical base_url")?;
        if base.scheme() != "https" && !base.host_str().is_some_and(is_loopback) {
            bail!("Infisical base_url must use HTTPS unless it is loopback");
        }
        Ok(Self {
            config,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(20))
                .https_only(base.scheme() == "https")
                .user_agent(concat!("av/", env!("CARGO_PKG_VERSION")))
                .build()?,
            token: Arc::new(Mutex::new(None)),
        })
    }

    pub async fn secrets(&self, profile: &ProfileConfig) -> Result<BTreeMap<String, String>> {
        let token = self.authenticate().await?;
        let mut url = Url::parse(&format!(
            "{}/api/v3/secrets/raw",
            self.config.base_url.trim_end_matches('/')
        ))?;
        url.query_pairs_mut()
            .append_pair("workspaceId", &profile.project_id)
            .append_pair("environment", &profile.environment)
            .append_pair("secretPath", &profile.secret_path)
            .append_pair("include_imports", "true");

        let response = self.client.get(url).bearer_auth(token).send().await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(BTreeMap::new());
        }
        if !response.status().is_success() {
            bail!(
                "Infisical secret read failed with status {}",
                response.status()
            );
        }
        let response: SecretsResponse =
            response.json().await.context("decode Infisical response")?;
        let mut secrets = BTreeMap::new();
        for secret in response.secrets {
            if profile.allowed_keys.is_empty() || profile.allowed_keys.contains(&secret.secret_key)
            {
                secrets.insert(secret.secret_key, secret.secret_value);
            }
        }
        Ok(secrets)
    }

    async fn authenticate(&self) -> Result<String> {
        let mut guard = self.token.lock().await;
        if let Some(token) = guard.as_ref()
            && Instant::now() < token.expires_at
        {
            return Ok(token.value.clone());
        }

        let (path, body) = match &self.config.auth {
            InfisicalAuth::Kubernetes {
                identity_id,
                token_file,
            } => {
                let jwt = read_secret_file(token_file)?;
                (
                    "/api/v1/auth/kubernetes-auth/login",
                    serde_json::json!({"identityId": identity_id, "jwt": jwt}),
                )
            }
            InfisicalAuth::Universal {
                client_id_file,
                client_secret_file,
            } => (
                "/api/v1/auth/universal-auth/login",
                serde_json::json!({
                    "clientId": read_secret_file(client_id_file)?,
                    "clientSecret": read_secret_file(client_secret_file)?,
                }),
            ),
        };

        let response = self
            .client
            .post(format!(
                "{}{}",
                self.config.base_url.trim_end_matches('/'),
                path
            ))
            .json(&body)
            .send()
            .await
            .context("authenticate to Infisical")?;
        if !response.status().is_success() {
            bail!(
                "Infisical authentication failed with status {}",
                response.status()
            );
        }
        let auth: AuthResponse = response
            .json()
            .await
            .context("decode Infisical auth response")?;
        let lifetime = auth.expires_in.saturating_sub(60).max(1);
        *guard = Some(CachedToken {
            value: auth.access_token.clone(),
            expires_at: Instant::now() + Duration::from_secs(lifetime),
        });
        Ok(auth.access_token)
    }
}

fn read_secret_file(path: impl AsRef<Path>) -> Result<String> {
    let path = path.as_ref();
    let value = std::fs::read_to_string(path)
        .with_context(|| format!("read credential file {}", path.display()))?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        bail!("credential file {} is empty", path.display());
    }
    Ok(value)
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}
