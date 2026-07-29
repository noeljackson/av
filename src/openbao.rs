use std::{
    collections::BTreeMap,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, bail};
use reqwest::RequestBuilder;
use serde::Deserialize;
use serde_json::Value;
use tokio::{sync::Mutex, time::Instant};
use url::Url;

use crate::{
    config::{OpenBaoAuth, OpenBaoConfig, ProfileConfig},
    connector::{BackendLease, OpenBaoLease, SecretAcquisition},
};
use zeroize::Zeroizing;

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

#[derive(Deserialize)]
struct LeaseResponse {
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

    pub async fn acquire(&self, profile: &ProfileConfig) -> Result<SecretAcquisition> {
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
            return Ok(SecretAcquisition {
                values: BTreeMap::new(),
                lease: None,
            });
        }
        if !response.status().is_success() {
            bail!(
                "OpenBao secret read failed with status {}",
                response.status()
            );
        }
        let response: SecretResponse = response.json().await.context("decode OpenBao response")?;
        decode_secret_response(response, profile)
    }

    pub async fn renew(&self, lease: &mut OpenBaoLease) -> Result<()> {
        if !lease.renewable {
            bail!("OpenBao lease is not renewable");
        }
        let token = self.authenticate().await?;
        let request = self
            .client
            .post(format!(
                "{}/v1/sys/leases/renew",
                self.config.base_url.trim_end_matches('/')
            ))
            .header("X-Vault-Token", token)
            .json(&serde_json::json!({
                "lease_id": lease.id.as_str(),
                "increment": lease.renew_increment.as_secs(),
            }));
        let response = self.with_namespace(request).send().await?;
        if !response.status().is_success() {
            bail!(
                "OpenBao lease renewal failed with status {}",
                response.status()
            );
        }
        let renewed: LeaseResponse = response
            .json()
            .await
            .context("decode OpenBao lease renewal")?;
        validate_lease_id(&renewed.lease_id)?;
        if renewed.lease_id != lease.id.as_str() {
            bail!("OpenBao lease renewal returned a different lease ID");
        }
        lease.renewable = renewed.renewable;
        lease.expires_at = lease_expiry(renewed.lease_duration)?;
        Ok(())
    }

    pub async fn revoke(&self, lease: &OpenBaoLease) -> Result<()> {
        let token = self.authenticate().await?;
        let request = self
            .client
            .post(format!(
                "{}/v1/sys/leases/revoke",
                self.config.base_url.trim_end_matches('/')
            ))
            .header("X-Vault-Token", token)
            .json(&serde_json::json!({
                "lease_id": lease.id.as_str(),
                "sync": true,
            }));
        let response = self.with_namespace(request).send().await?;
        if !response.status().is_success() && response.status() != reqwest::StatusCode::NOT_FOUND {
            bail!(
                "OpenBao lease revocation failed with status {}",
                response.status()
            );
        }
        Ok(())
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
    profile: &ProfileConfig,
) -> Result<SecretAcquisition> {
    let values = decode_secret_data(response.data, &profile.allowed_keys)?;
    match &profile.dynamic_secret {
        None => {
            if !response.lease_id.is_empty() || response.renewable || response.lease_duration > 0 {
                bail!("OpenBao returned a lease for a profile not configured as dynamic");
            }
            Ok(SecretAcquisition {
                values,
                lease: None,
            })
        }
        Some(dynamic) => {
            validate_lease_id(&response.lease_id)?;
            Ok(SecretAcquisition {
                values,
                lease: Some(BackendLease::OpenBao(OpenBaoLease {
                    id: Zeroizing::new(response.lease_id),
                    renewable: response.renewable,
                    expires_at: lease_expiry(response.lease_duration)?,
                    renew_increment: Duration::from_secs(dynamic.ttl_seconds),
                })),
            })
        }
    }
}

fn validate_lease_id(lease_id: &str) -> Result<()> {
    if lease_id.is_empty() || lease_id.len() > 4096 || lease_id.chars().any(char::is_control) {
        bail!("OpenBao returned an invalid lease ID");
    }
    Ok(())
}

fn lease_expiry(lease_duration: u64) -> Result<SystemTime> {
    if !(1..=24 * 60 * 60).contains(&lease_duration) {
        bail!("OpenBao returned a lease duration outside AV's safe bounds");
    }
    SystemTime::now()
        .checked_add(Duration::from_secs(lease_duration))
        .context("OpenBao lease expiry is outside the system clock range")
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
    use crate::config::{DynamicSecretConfig, ProfileConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn synthetic_openbao(
        responses: Vec<String>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<Vec<Vec<u8>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0_u8; 2048];
                loop {
                    let read = stream.read(&mut buffer).await.unwrap();
                    assert!(read > 0);
                    request.extend_from_slice(&buffer[..read]);
                    let Some(header_end) = request
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .map(|index| index + 4)
                    else {
                        continue;
                    };
                    let header = std::str::from_utf8(&request[..header_end]).unwrap();
                    let content_length = header
                        .lines()
                        .find_map(|line| {
                            line.split_once(':').and_then(|(name, value)| {
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().unwrap())
                            })
                        })
                        .unwrap_or(0);
                    if request.len() >= header_end + content_length {
                        break;
                    }
                }
                stream.write_all(response.as_bytes()).await.unwrap();
                requests.push(request);
            }
            requests
        });
        (address, task)
    }

    fn http_json(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    fn static_profile() -> ProfileConfig {
        ProfileConfig {
            connector: "openbao".into(),
            project_id: String::new(),
            environment: String::new(),
            secret_path: "secret/data/example".into(),
            allowed_keys: vec![],
            exports: BTreeMap::new(),
            dynamic_secret: None,
        }
    }

    fn dynamic_profile() -> ProfileConfig {
        ProfileConfig {
            connector: "openbao".into(),
            project_id: String::new(),
            environment: String::new(),
            secret_path: "database/creds/application".into(),
            allowed_keys: vec![],
            exports: BTreeMap::from([
                (
                    "DATABASE_USER".into(),
                    crate::config::ProfileExportConfig {
                        resource: String::new(),
                        field: "username".into(),
                    },
                ),
                (
                    "DATABASE_PASSWORD".into(),
                    crate::config::ProfileExportConfig {
                        resource: String::new(),
                        field: "password".into(),
                    },
                ),
            ]),
            dynamic_secret: Some(DynamicSecretConfig {
                name: String::new(),
                project_slug: String::new(),
                ttl_seconds: 60,
            }),
        }
    }

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
        assert!(decode_secret_response(response, &static_profile()).is_err());
    }

    #[tokio::test]
    async fn acquires_renews_and_synchronously_revokes_dynamic_lease() {
        let lease_id = "database/creds/application/synthetic-lease";
        let acquired = serde_json::json!({
            "data": {"username": "leased-user", "password": "synthetic-password"},
            "lease_id": lease_id,
            "renewable": true,
            "lease_duration": 60
        })
        .to_string();
        let renewed = serde_json::json!({
            "lease_id": lease_id,
            "renewable": true,
            "lease_duration": 45
        })
        .to_string();
        let (address, server) = synthetic_openbao(vec![
            http_json(&acquired),
            http_json(&renewed),
            "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".into(),
        ])
        .await;
        let token = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(token.path(), "synthetic-root-token\n").unwrap();
        let config: OpenBaoConfig = serde_json::from_value(serde_json::json!({
            "kind": "openbao",
            "base_url": format!("http://{address}"),
            "auth": {"type": "token", "token_file": token.path()},
        }))
        .unwrap();
        let connector = OpenBaoConnector::new(config, true).unwrap();
        let mut acquired = connector.acquire(&dynamic_profile()).await.unwrap();
        assert_eq!(acquired.values["username"], "leased-user");
        let BackendLease::OpenBao(mut lease) = acquired.lease.take().unwrap() else {
            panic!("expected OpenBao lease");
        };
        let first_expiry = lease.expires_at;
        connector.renew(&mut lease).await.unwrap();
        assert!(lease.expires_at < first_expiry);
        connector.revoke(&lease).await.unwrap();

        let requests = server.await.unwrap();
        assert!(requests[0].starts_with(b"GET /v1/database/creds/application HTTP/1.1\r\n"));
        assert!(requests[1].starts_with(b"POST /v1/sys/leases/renew HTTP/1.1\r\n"));
        assert!(requests[2].starts_with(b"POST /v1/sys/leases/revoke HTTP/1.1\r\n"));
        let renewal = std::str::from_utf8(&requests[1]).unwrap();
        let revocation = std::str::from_utf8(&requests[2]).unwrap();
        assert!(renewal.contains(lease_id));
        assert!(renewal.contains("\"increment\":60"));
        assert!(revocation.contains(lease_id));
        assert!(revocation.contains("\"sync\":true"));
    }

    #[test]
    fn dynamic_lease_requires_valid_id_and_bounded_ttl() {
        let profile = dynamic_profile();
        for (lease_id, lease_duration) in [("", 60), ("valid", 0), ("valid", 86_401)] {
            let response = SecretResponse {
                data: serde_json::json!({"username": "leased-user"}),
                lease_id: lease_id.into(),
                renewable: true,
                lease_duration,
            };
            assert!(decode_secret_response(response, &profile).is_err());
        }
    }

    #[test]
    fn rejects_nested_secret_values() {
        let data = serde_json::json!({"nested": {"secret": "value"}});
        assert!(decode_secret_data(data, &[]).is_err());
    }
}
