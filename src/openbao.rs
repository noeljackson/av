use std::{collections::BTreeMap, path::Path, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use reqwest::RequestBuilder;
use serde::Deserialize;
use serde_json::Value;
use tokio::{sync::Mutex, time::Instant};
use url::Url;

use crate::config::{OpenBaoAuth, OpenBaoConfig, ProfileConfig};

#[derive(Clone)]
pub struct OpenBaoConnector {
    config: OpenBaoConfig,
    client: reqwest::Client,
    token: Arc<Mutex<Option<CachedToken>>>,
}

struct CachedToken {
    value: String,
    expires_at: Instant,
}

#[derive(Deserialize)]
struct AuthResponse {
    auth: AuthDetails,
}

#[derive(Deserialize)]
struct AuthDetails {
    client_token: String,
    lease_duration: u64,
}

#[derive(Deserialize)]
struct SecretResponse {
    data: Value,
    #[serde(default)]
    lease_id: String,
    #[serde(default)]
    renewable: bool,
    #[serde(default)]
    lease_duration: u64,
}

impl OpenBaoConnector {
    pub fn new(config: OpenBaoConfig, allow_insecure_http: bool) -> Result<Self> {
        let base = Url::parse(&config.base_url).context("invalid OpenBao base_url")?;
        if base.scheme() != "https" && !(base.scheme() == "http" && allow_insecure_http) {
            bail!("OpenBao base_url must use HTTPS");
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
        let path = profile.secret_path.trim_matches('/');
        let request = self
            .client
            .get(format!(
                "{}/v1/{path}",
                self.config.base_url.trim_end_matches('/')
            ))
            .header("X-Vault-Token", token);
        let response = self.with_namespace(request).send().await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(BTreeMap::new());
        }
        if !response.status().is_success() {
            bail!(
                "OpenBao secret read failed with status {}",
                response.status()
            );
        }
        let response: SecretResponse = response.json().await.context("decode OpenBao response")?;
        decode_secret_response(response, &profile.allowed_keys)
    }

    async fn authenticate(&self) -> Result<String> {
        if let OpenBaoAuth::Token { token_file } = &self.config.auth {
            return read_secret_file(token_file);
        }

        let mut guard = self.token.lock().await;
        if let Some(token) = guard.as_ref()
            && Instant::now() < token.expires_at
        {
            return Ok(token.value.clone());
        }

        let (mount_path, body) = match &self.config.auth {
            OpenBaoAuth::AppRole {
                role_id_file,
                secret_id_file,
                mount_path,
            } => (
                mount_path,
                serde_json::json!({
                    "role_id": read_secret_file(role_id_file)?,
                    "secret_id": read_secret_file(secret_id_file)?,
                }),
            ),
            OpenBaoAuth::Kubernetes {
                role,
                token_file,
                mount_path,
            } => (
                mount_path,
                serde_json::json!({
                    "role": role,
                    "jwt": read_secret_file(token_file)?,
                }),
            ),
            OpenBaoAuth::Token { .. } => unreachable!("token auth returned above"),
        };
        let request = self.client.post(format!(
            "{}/v1/auth/{}/login",
            self.config.base_url.trim_end_matches('/'),
            mount_path.trim_matches('/')
        ));
        let response = self.with_namespace(request).json(&body).send().await?;
        if !response.status().is_success() {
            bail!(
                "OpenBao authentication failed with status {}",
                response.status()
            );
        }
        let auth: AuthResponse = response
            .json()
            .await
            .context("decode OpenBao auth response")?;
        if auth.auth.client_token.is_empty() {
            bail!("OpenBao authentication returned an empty token");
        }
        let lifetime = auth.auth.lease_duration.saturating_sub(30).max(1);
        *guard = Some(CachedToken {
            value: auth.auth.client_token.clone(),
            expires_at: Instant::now() + Duration::from_secs(lifetime),
        });
        Ok(auth.auth.client_token)
    }

    fn with_namespace(&self, request: RequestBuilder) -> RequestBuilder {
        if self.config.namespace.is_empty() {
            request
        } else {
            request.header("X-Vault-Namespace", &self.config.namespace)
        }
    }
}

fn decode_secret_response(
    response: SecretResponse,
    allowed_keys: &[String],
) -> Result<BTreeMap<String, String>> {
    if !response.lease_id.is_empty() || response.renewable || response.lease_duration > 0 {
        bail!("OpenBao dynamic secret leases are not supported yet");
    }
    decode_secret_data(response.data, allowed_keys)
}

fn decode_secret_data(data: Value, allowed_keys: &[String]) -> Result<BTreeMap<String, String>> {
    let root = data
        .as_object()
        .context("OpenBao secret data is not an object")?;
    let values = root.get("data").and_then(Value::as_object).unwrap_or(root);
    let mut secrets = BTreeMap::new();
    for (key, value) in values {
        if !allowed_keys.is_empty() && !allowed_keys.contains(key) {
            continue;
        }
        let value = match value {
            Value::String(value) => value.clone(),
            Value::Bool(value) => value.to_string(),
            Value::Number(value) => value.to_string(),
            Value::Null => continue,
            Value::Array(_) | Value::Object(_) => {
                bail!("OpenBao secret {key} is not a scalar value")
            }
        };
        secrets.insert(key.clone(), value);
    }
    Ok(secrets)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_kv_v2_and_filters_keys() {
        let data = serde_json::json!({
            "data": {"ALLOWED": "one", "DENIED": "two", "COUNT": 3},
            "metadata": {"version": 1}
        });
        let secrets = decode_secret_data(data, &["ALLOWED".into(), "COUNT".into()]).unwrap();
        assert_eq!(secrets.get("ALLOWED").unwrap(), "one");
        assert_eq!(secrets.get("COUNT").unwrap(), "3");
        assert!(!secrets.contains_key("DENIED"));
        assert!(!secrets.contains_key("metadata"));
    }

    #[test]
    fn rejects_unmanaged_dynamic_secret_leases() {
        let response = SecretResponse {
            data: serde_json::json!({"username": "leased-user", "password": "synthetic"}),
            lease_id: "database/creds/example/lease".into(),
            renewable: true,
            lease_duration: 60,
        };
        assert!(decode_secret_response(response, &[]).is_err());
    }

    #[test]
    fn rejects_nested_secret_values() {
        let data = serde_json::json!({"nested": {"secret": "value"}});
        assert!(decode_secret_data(data, &[]).is_err());
    }
}
