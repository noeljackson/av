use std::{
    collections::BTreeMap,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{sync::Mutex, time::Instant};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    config::{InfisicalAuth, InfisicalConfig, ProfileConfig},
    connector::{BackendLease, InfisicalLease, SecretAcquisition},
};

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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DynamicLeaseResponse {
    lease: DynamicLease,
    #[serde(default)]
    data: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DynamicLeaseOnlyResponse {
    lease: DynamicLease,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DynamicLease {
    id: String,
    expire_at: String,
}

impl InfisicalConnector {
    pub fn new(config: InfisicalConfig, allow_insecure_http: bool) -> Result<Self> {
        let base = Url::parse(&config.base_url).context("invalid Infisical base_url")?;
        if base.scheme() != "https" && !(base.scheme() == "http" && allow_insecure_http) {
            bail!("Infisical base_url must use HTTPS");
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
        if profile.dynamic_secret.is_some() {
            return self.acquire_dynamic(profile).await;
        }
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
            return Ok(SecretAcquisition {
                values: BTreeMap::new(),
                lease: None,
            });
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
        Ok(SecretAcquisition {
            values: secrets,
            lease: None,
        })
    }

    async fn acquire_dynamic(&self, profile: &ProfileConfig) -> Result<SecretAcquisition> {
        let dynamic = profile
            .dynamic_secret
            .as_ref()
            .context("dynamic Infisical profile lost its configuration")?;
        let token = self.authenticate().await?;
        let response = self
            .client
            .post(format!(
                "{}/api/v1/dynamic-secrets/leases",
                self.config.base_url.trim_end_matches('/')
            ))
            .bearer_auth(token)
            .json(&serde_json::json!({
                "dynamicSecretName": dynamic.name,
                "projectSlug": dynamic.project_slug,
                "environmentSlug": profile.environment,
                "ttl": format!("{}s", dynamic.ttl_seconds),
                "path": profile.secret_path,
            }))
            .send()
            .await?;
        if !response.status().is_success() {
            bail!(
                "Infisical dynamic lease creation failed with status {}",
                response.status()
            );
        }
        let response: DynamicLeaseResponse = response
            .json()
            .await
            .context("decode Infisical dynamic lease")?;
        validate_dynamic_lease_id(&response.lease.id)?;
        let expires_at = parse_dynamic_expiry(&response.lease.expire_at)?;
        Ok(SecretAcquisition {
            values: decode_dynamic_data(response.data)?,
            lease: Some(BackendLease::Infisical(InfisicalLease {
                id: Zeroizing::new(response.lease.id),
                project_slug: dynamic.project_slug.clone(),
                environment: profile.environment.clone(),
                path: profile.secret_path.clone(),
                expires_at,
                renew_increment: Duration::from_secs(dynamic.ttl_seconds),
            })),
        })
    }

    pub async fn renew(&self, lease: &mut InfisicalLease) -> Result<()> {
        let token = self.authenticate().await?;
        let response = self
            .client
            .post(self.dynamic_lease_url(lease.id.as_str(), Some("renew"))?)
            .bearer_auth(token)
            .json(&serde_json::json!({
                "projectSlug": lease.project_slug,
                "environmentSlug": lease.environment,
                "ttl": format!("{}s", lease.renew_increment.as_secs()),
                "path": lease.path,
            }))
            .send()
            .await?;
        if !response.status().is_success() {
            bail!(
                "Infisical dynamic lease renewal failed with status {}",
                response.status()
            );
        }
        let response: DynamicLeaseOnlyResponse = response
            .json()
            .await
            .context("decode Infisical dynamic lease renewal")?;
        validate_dynamic_lease_id(&response.lease.id)?;
        if response.lease.id != lease.id.as_str() {
            bail!("Infisical lease renewal returned a different lease ID");
        }
        lease.expires_at = parse_dynamic_expiry(&response.lease.expire_at)?;
        Ok(())
    }

    pub async fn revoke(&self, lease: &InfisicalLease) -> Result<()> {
        let token = self.authenticate().await?;
        let response = self
            .client
            .delete(self.dynamic_lease_url(lease.id.as_str(), None)?)
            .bearer_auth(token)
            .json(&serde_json::json!({
                "projectSlug": lease.project_slug,
                "environmentSlug": lease.environment,
                "path": lease.path,
                "isForced": false,
            }))
            .send()
            .await?;
        if !response.status().is_success() && response.status() != reqwest::StatusCode::NOT_FOUND {
            bail!(
                "Infisical dynamic lease revocation failed with status {}",
                response.status()
            );
        }
        Ok(())
    }

    fn dynamic_lease_url(&self, lease_id: &str, suffix: Option<&str>) -> Result<Url> {
        validate_dynamic_lease_id(lease_id)?;
        let mut url = Url::parse(&format!(
            "{}/api/v1/dynamic-secrets/leases/",
            self.config.base_url.trim_end_matches('/')
        ))?;
        url.path_segments_mut()
            .map_err(|_| anyhow::anyhow!("Infisical base URL cannot contain lease paths"))?
            .pop_if_empty()
            .push(lease_id);
        if let Some(suffix) = suffix {
            url.path_segments_mut()
                .map_err(|_| anyhow::anyhow!("Infisical base URL cannot contain lease paths"))?
                .push(suffix);
        }
        Ok(url)
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
            InfisicalAuth::Token { token_file } => return read_secret_file(token_file),
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

fn decode_dynamic_data(data: Value) -> Result<BTreeMap<String, String>> {
    let values = data
        .as_object()
        .context("Infisical dynamic lease data is not an object")?;
    let mut decoded = BTreeMap::new();
    for (key, value) in values {
        let value = match value {
            Value::String(value) => value.clone(),
            Value::Bool(value) => value.to_string(),
            Value::Number(value) => value.to_string(),
            Value::Null => continue,
            Value::Array(_) | Value::Object(_) => {
                bail!("Infisical dynamic lease field {key} is not scalar")
            }
        };
        decoded.insert(key.clone(), value);
    }
    Ok(decoded)
}

fn validate_dynamic_lease_id(lease_id: &str) -> Result<()> {
    if lease_id.is_empty()
        || lease_id.len() > 128
        || !lease_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        bail!("Infisical returned an invalid dynamic lease ID");
    }
    Ok(())
}

fn parse_dynamic_expiry(expire_at: &str) -> Result<SystemTime> {
    let expiry = OffsetDateTime::parse(expire_at, &Rfc3339)
        .context("Infisical returned an invalid dynamic lease expiry")?;
    let seconds = u64::try_from(expiry.unix_timestamp())
        .context("Infisical dynamic lease expiry predates the Unix epoch")?;
    let expiry = UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .context("Infisical dynamic lease expiry is outside the system clock range")?;
    let remaining = expiry
        .duration_since(SystemTime::now())
        .context("Infisical returned an already expired dynamic lease")?;
    if remaining > Duration::from_secs(24 * 60 * 60 + 60) {
        bail!("Infisical returned a dynamic lease expiry outside AV's safe bounds");
    }
    Ok(expiry)
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
    use crate::{
        config::{DynamicSecretConfig, ProfileExportConfig},
        connector::BackendLease,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn synthetic_infisical(
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

    fn expiry_after(seconds: i64) -> String {
        (OffsetDateTime::now_utc() + time::Duration::seconds(seconds))
            .format(&Rfc3339)
            .unwrap()
    }

    fn dynamic_profile() -> ProfileConfig {
        ProfileConfig {
            connector: "infisical".into(),
            project_id: String::new(),
            environment: "dev".into(),
            secret_path: "/database".into(),
            allowed_keys: vec![],
            exports: BTreeMap::from([
                (
                    "DATABASE_USER".into(),
                    ProfileExportConfig {
                        resource: String::new(),
                        field: "username".into(),
                    },
                ),
                (
                    "DATABASE_PASSWORD".into(),
                    ProfileExportConfig {
                        resource: String::new(),
                        field: "password".into(),
                    },
                ),
            ]),
            dynamic_secret: Some(DynamicSecretConfig {
                name: "application-database".into(),
                project_slug: "example-app".into(),
                ttl_seconds: 60,
            }),
        }
    }

    #[tokio::test]
    async fn creates_renews_and_revokes_dynamic_lease() {
        let lease_id = "123e4567-e89b-12d3-a456-426614174000";
        let acquired = serde_json::json!({
            "lease": {"id": lease_id, "expireAt": expiry_after(60)},
            "dynamicSecret": {},
            "data": {"username": "leased-user", "password": "synthetic-password"}
        })
        .to_string();
        let renewed = serde_json::json!({
            "lease": {"id": lease_id, "expireAt": expiry_after(45)}
        })
        .to_string();
        let revoked = serde_json::json!({
            "lease": {"id": lease_id, "expireAt": expiry_after(1)}
        })
        .to_string();
        let (address, server) = synthetic_infisical(vec![
            http_json(&acquired),
            http_json(&renewed),
            http_json(&revoked),
        ])
        .await;
        let token = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(token.path(), "synthetic-machine-token\n").unwrap();
        let config: InfisicalConfig = serde_json::from_value(serde_json::json!({
            "kind": "infisical",
            "base_url": format!("http://{address}"),
            "auth": {"type": "token", "token_file": token.path()},
        }))
        .unwrap();
        let connector = InfisicalConnector::new(config, true).unwrap();
        let mut acquired = connector.acquire(&dynamic_profile()).await.unwrap();
        assert_eq!(acquired.values["username"], "leased-user");
        let BackendLease::Infisical(mut lease) = acquired.lease.take().unwrap() else {
            panic!("expected Infisical lease");
        };
        let first_expiry = lease.expires_at;
        connector.renew(&mut lease).await.unwrap();
        assert!(lease.expires_at < first_expiry);
        connector.revoke(&lease).await.unwrap();

        let requests = server.await.unwrap();
        assert!(requests[0].starts_with(b"POST /api/v1/dynamic-secrets/leases HTTP/1.1\r\n"));
        assert!(requests[1].starts_with(
            format!("POST /api/v1/dynamic-secrets/leases/{lease_id}/renew HTTP/1.1\r\n").as_bytes()
        ));
        assert!(requests[2].starts_with(
            format!("DELETE /api/v1/dynamic-secrets/leases/{lease_id} HTTP/1.1\r\n").as_bytes()
        ));
        let creation = std::str::from_utf8(&requests[0]).unwrap();
        let renewal = std::str::from_utf8(&requests[1]).unwrap();
        let revocation = std::str::from_utf8(&requests[2]).unwrap();
        assert!(creation.contains("\"dynamicSecretName\":\"application-database\""));
        assert!(creation.contains("\"projectSlug\":\"example-app\""));
        assert!(renewal.contains("\"ttl\":\"60s\""));
        assert!(revocation.contains("\"isForced\":false"));
    }

    #[test]
    fn dynamic_lease_rejects_nested_values_ids_and_expiry() {
        assert!(decode_dynamic_data(serde_json::json!({"nested": {"value": "no"}})).is_err());
        assert!(validate_dynamic_lease_id("").is_err());
        assert!(validate_dynamic_lease_id("../lease").is_err());
        assert!(parse_dynamic_expiry("not-a-time").is_err());
        assert!(parse_dynamic_expiry(&expiry_after(-1)).is_err());
        assert!(parse_dynamic_expiry(&expiry_after(90_000)).is_err());
    }
}
