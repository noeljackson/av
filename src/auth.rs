use std::{collections::BTreeMap, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use axum::http::{HeaderMap, header};
use base64::{Engine, engine::general_purpose::STANDARD};
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::Deserialize;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

use crate::config::{AuthConfig, AuthMode, PublicAuthConfig};

#[derive(Clone)]
pub struct Authenticator {
    config: AuthConfig,
    client: reqwest::Client,
    discovery: Option<Discovery>,
    jwks: Arc<RwLock<Option<JwkSet>>>,
}

#[derive(Clone, Debug, Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    device_authorization_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Debug)]
pub struct Identity {
    pub subject: String,
}

impl Authenticator {
    pub async fn new(config: AuthConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .https_only(!config.issuer.starts_with("http://127.0.0.1"))
            .user_agent(concat!("av/", env!("CARGO_PKG_VERSION")))
            .build()?;
        let discovery = if matches!(config.mode, AuthMode::Oidc | AuthMode::OidcOrBasic) {
            let endpoint = format!(
                "{}/.well-known/openid-configuration",
                config.issuer.trim_end_matches('/')
            );
            let discovery: Discovery = client
                .get(endpoint)
                .send()
                .await
                .context("fetch OIDC discovery")?
                .error_for_status()
                .context("OIDC discovery status")?
                .json()
                .await
                .context("decode OIDC discovery")?;
            if discovery.issuer.trim_end_matches('/') != config.issuer.trim_end_matches('/') {
                bail!("OIDC discovery issuer does not match configured issuer");
            }
            Some(discovery)
        } else {
            None
        };
        let authenticator = Self {
            config,
            client,
            discovery,
            jwks: Arc::new(RwLock::new(None)),
        };
        if authenticator.discovery.is_some() {
            authenticator.refresh_jwks().await?;
        }
        Ok(authenticator)
    }

    pub fn public_config(&self) -> PublicAuthConfig {
        let discovery = self.discovery.as_ref();
        PublicAuthConfig {
            mode: match self.config.mode {
                AuthMode::Oidc => "oidc",
                AuthMode::Basic => "basic",
                AuthMode::OidcOrBasic => "oidc_or_basic",
                AuthMode::Disabled => "disabled",
            }
            .into(),
            issuer: self.config.issuer.clone(),
            client_id: self.config.client_id.clone(),
            scopes: if self.config.scopes.is_empty() {
                vec![
                    "openid".into(),
                    "profile".into(),
                    "email".into(),
                    "groups".into(),
                ]
            } else {
                self.config.scopes.clone()
            },
            authorization_endpoint: discovery.map(|item| item.authorization_endpoint.clone()),
            token_endpoint: discovery.map(|item| item.token_endpoint.clone()),
            device_authorization_endpoint: discovery
                .and_then(|item| item.device_authorization_endpoint.clone()),
        }
    }

    pub async fn authorize(&self, headers: &HeaderMap) -> Result<Identity> {
        if self.config.mode == AuthMode::Disabled {
            return Ok(Identity {
                subject: "local-insecure".into(),
            });
        }
        let authorization = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .context("missing Authorization header")?;

        if let Some(token) = authorization.strip_prefix("Bearer ")
            && matches!(self.config.mode, AuthMode::Oidc | AuthMode::OidcOrBasic)
        {
            return self.authorize_oidc(token).await;
        }
        if let Some(encoded) = authorization.strip_prefix("Basic ")
            && matches!(self.config.mode, AuthMode::Basic | AuthMode::OidcOrBasic)
        {
            return self.authorize_basic(encoded);
        }
        bail!("unsupported authentication scheme")
    }

    async fn authorize_oidc(&self, token: &str) -> Result<Identity> {
        let header = decode_header(token).context("invalid bearer token header")?;
        let kid = header.kid.context("bearer token has no key id")?;

        let mut jwk = self.find_jwk(&kid).await;
        if jwk.is_none() {
            self.refresh_jwks().await?;
            jwk = self.find_jwk(&kid).await;
        }
        let jwk = jwk.context("bearer token key is not trusted")?;
        let key = DecodingKey::from_jwk(&jwk).context("unsupported OIDC signing key")?;
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(std::slice::from_ref(&self.config.issuer));
        let audiences = if self.config.audiences.is_empty() {
            vec![self.config.client_id.clone()]
        } else {
            self.config.audiences.clone()
        };
        validation.set_audience(&audiences);
        let claims = decode::<Claims>(token, &key, &validation)
            .context("bearer token validation failed")?
            .claims;

        if !claim_allows_group(
            claims.extra.get(&self.config.group_claim),
            &self.config.allowed_groups,
        ) {
            bail!("OIDC identity is not in an allowed group");
        }
        Ok(Identity {
            subject: claims.sub,
        })
    }

    fn authorize_basic(&self, encoded: &str) -> Result<Identity> {
        let decoded = STANDARD
            .decode(encoded)
            .context("invalid Basic authorization")?;
        let decoded = String::from_utf8(decoded).context("invalid Basic authorization encoding")?;
        let (username, password) = decoded
            .split_once(':')
            .context("invalid Basic authorization payload")?;
        for user in &self.config.basic_users {
            if user.username != username {
                continue;
            }
            let expected = std::fs::read_to_string(&user.password_file)
                .with_context(|| format!("read password file for {username}"))?;
            let expected = expected.trim_end().as_bytes();
            if expected.len() == password.len() && expected.ct_eq(password.as_bytes()).into() {
                return Ok(Identity {
                    subject: format!("basic:{username}"),
                });
            }
        }
        bail!("invalid Basic credentials")
    }

    async fn find_jwk(&self, kid: &str) -> Option<jsonwebtoken::jwk::Jwk> {
        self.jwks
            .read()
            .await
            .as_ref()
            .and_then(|set| set.find(kid))
            .cloned()
    }

    async fn refresh_jwks(&self) -> Result<()> {
        let uri = &self
            .discovery
            .as_ref()
            .context("OIDC is not configured")?
            .jwks_uri;
        let set = self
            .client
            .get(uri)
            .send()
            .await
            .context("fetch OIDC signing keys")?
            .error_for_status()
            .context("OIDC signing key status")?
            .json::<JwkSet>()
            .await
            .context("decode OIDC signing keys")?;
        *self.jwks.write().await = Some(set);
        Ok(())
    }
}

fn claim_allows_group(claim: Option<&serde_json::Value>, allowed_groups: &[String]) -> bool {
    match claim {
        Some(serde_json::Value::Array(groups)) => groups
            .iter()
            .filter_map(serde_json::Value::as_str)
            .any(|group| allowed_groups.iter().any(|allowed| allowed == group)),
        // Zitadel represents project roles as an object keyed by role name. The values
        // identify the organizations that granted each role and are not group names.
        Some(serde_json::Value::Object(roles)) => roles
            .keys()
            .any(|role| allowed_groups.iter().any(|allowed| allowed == role)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::claim_allows_group;

    #[test]
    fn accepts_standard_group_arrays() {
        let claim = serde_json::json!(["developers", "av-users"]);
        assert!(claim_allows_group(Some(&claim), &["av-users".into()]));
        assert!(!claim_allows_group(Some(&claim), &["operators".into()]));
    }

    #[test]
    fn accepts_zitadel_project_role_objects() {
        let claim = serde_json::json!({
            "av-users": {"org-id": "noel"},
            "unrelated-role": {"org-id": "noel"}
        });
        assert!(claim_allows_group(Some(&claim), &["av-users".into()]));
        assert!(!claim_allows_group(Some(&claim), &["operators".into()]));
    }

    #[test]
    fn rejects_malformed_group_claims() {
        let claim = serde_json::json!("av-users");
        assert!(!claim_allows_group(Some(&claim), &["av-users".into()]));
        assert!(!claim_allows_group(None, &["av-users".into()]));
    }
}
