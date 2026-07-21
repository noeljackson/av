use std::{collections::BTreeMap, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::http::{HeaderMap, header};
use base64::{Engine, engine::general_purpose::STANDARD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::Deserialize;
use tokio::{
    sync::{Mutex, RwLock},
    time::Instant,
};

use crate::config::{AuthConfig, AuthMode, OidcSigningAlgorithm, PublicAuthConfig};

const JWKS_REFRESH_COOLDOWN: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct Authenticator {
    config: AuthConfig,
    client: reqwest::Client,
    discovery: Option<Discovery>,
    jwks: Arc<RwLock<Option<JwkSet>>>,
    jwks_refresh: Arc<Mutex<JwksRefreshState>>,
    basic_credentials: Arc<Vec<BasicCredential>>,
}

#[derive(Default)]
struct JwksRefreshState {
    last_attempt: Option<Instant>,
}

#[derive(Clone)]
struct BasicCredential {
    username: String,
    password_hash: String,
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
        let basic_credentials = load_basic_credentials(&config)?;
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
            jwks_refresh: Arc::new(Mutex::new(JwksRefreshState::default())),
            basic_credentials: Arc::new(basic_credentials),
        };
        if authenticator.discovery.is_some() {
            authenticator.refresh_jwks(true).await?;
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
                vec!["openid".into()]
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
            return self.authorize_basic(encoded).await;
        }
        bail!("unsupported authentication scheme")
    }

    async fn authorize_oidc(&self, token: &str) -> Result<Identity> {
        let header = decode_header(token).context("invalid bearer token header")?;
        let allowed_algorithms: Vec<_> = self
            .config
            .signing_algorithms
            .iter()
            .copied()
            .map(oidc_algorithm)
            .collect();
        let default_algorithm = allowed_algorithms
            .first()
            .copied()
            .context("OIDC has no trusted signing algorithms")?;
        if !allowed_algorithms.contains(&header.alg) {
            bail!("bearer token uses an untrusted signing algorithm");
        }
        let kid = header.kid.context("bearer token has no key id")?;

        let mut jwk = self.find_jwk(&kid).await;
        if jwk.is_none() {
            self.refresh_jwks(false).await?;
            jwk = self.find_jwk(&kid).await;
        }
        let jwk = jwk.context("bearer token key is not trusted")?;
        let key = DecodingKey::from_jwk(&jwk).context("unsupported OIDC signing key")?;
        let mut validation = Validation::new(default_algorithm);
        validation.algorithms = allowed_algorithms;
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

    async fn authorize_basic(&self, encoded: &str) -> Result<Identity> {
        let decoded = STANDARD
            .decode(encoded)
            .context("invalid Basic authorization")?;
        let decoded = String::from_utf8(decoded).context("invalid Basic authorization encoding")?;
        let (username, password) = decoded
            .split_once(':')
            .context("invalid Basic authorization payload")?;
        let requested = self
            .basic_credentials
            .iter()
            .find(|credential| credential.username == username);
        let comparison = requested
            .or_else(|| self.basic_credentials.first())
            .context("Basic authentication has no configured credentials")?;
        let password = password.to_owned();
        let password_hash = comparison.password_hash.clone();
        let valid = tokio::task::spawn_blocking(move || {
            let hash = PasswordHash::new(&password_hash)
                .map_err(|error| anyhow::anyhow!("parse Argon2id password hash: {error}"))?;
            Ok::<_, anyhow::Error>(
                Argon2::default()
                    .verify_password(password.as_bytes(), &hash)
                    .is_ok(),
            )
        })
        .await
        .context("join Basic password verification")??;
        if valid && requested.is_some() {
            return Ok(Identity {
                subject: format!("basic:{username}"),
            });
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

    async fn refresh_jwks(&self, force: bool) -> Result<()> {
        let mut refresh = self.jwks_refresh.lock().await;
        if !force
            && refresh
                .last_attempt
                .is_some_and(|attempt| attempt.elapsed() < JWKS_REFRESH_COOLDOWN)
        {
            return Ok(());
        }
        refresh.last_attempt = Some(Instant::now());
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

fn load_basic_credentials(config: &AuthConfig) -> Result<Vec<BasicCredential>> {
    config
        .basic_users
        .iter()
        .map(|user| {
            let password_hash = std::fs::read_to_string(&user.password_hash_file)
                .with_context(|| format!("read password hash file for {}", user.username))?;
            let password_hash = password_hash.trim().to_owned();
            let parsed = PasswordHash::new(&password_hash).map_err(|error| {
                anyhow::anyhow!(
                    "parse Argon2id password hash for {}: {error}",
                    user.username
                )
            })?;
            if parsed.algorithm.as_str() != "argon2id" {
                bail!("password hash for {} must use Argon2id", user.username);
            }
            Ok(BasicCredential {
                username: user.username.clone(),
                password_hash,
            })
        })
        .collect()
}

fn oidc_algorithm(algorithm: OidcSigningAlgorithm) -> Algorithm {
    match algorithm {
        OidcSigningAlgorithm::Rs256 => Algorithm::RS256,
        OidcSigningAlgorithm::Rs384 => Algorithm::RS384,
        OidcSigningAlgorithm::Rs512 => Algorithm::RS512,
        OidcSigningAlgorithm::Ps256 => Algorithm::PS256,
        OidcSigningAlgorithm::Ps384 => Algorithm::PS384,
        OidcSigningAlgorithm::Ps512 => Algorithm::PS512,
        OidcSigningAlgorithm::Es256 => Algorithm::ES256,
        OidcSigningAlgorithm::Es384 => Algorithm::ES384,
        OidcSigningAlgorithm::EdDsa => Algorithm::EdDSA,
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
    use super::*;
    use crate::config::BasicUserConfig;
    use axum::http::HeaderValue;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn oidc_test_authenticator() -> Authenticator {
        Authenticator {
            config: AuthConfig {
                mode: AuthMode::Oidc,
                issuer: "https://identity.example".into(),
                client_id: "av".into(),
                audiences: vec!["av-project".into()],
                scopes: vec!["openid".into()],
                signing_algorithms: vec![OidcSigningAlgorithm::Rs256],
                allowed_groups: vec!["av-users".into()],
                group_claim: "roles".into(),
                basic_users: vec![],
            },
            client: reqwest::Client::new(),
            discovery: None,
            jwks: Arc::new(RwLock::new(None)),
            jwks_refresh: Arc::new(Mutex::new(JwksRefreshState::default())),
            basic_credentials: Arc::new(Vec::new()),
        }
    }

    #[tokio::test]
    async fn basic_login_accepts_only_the_configured_argon2id_hash() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let password_hash_file =
            std::env::temp_dir().join(format!("av-basic-auth-{}-{nonce}", std::process::id()));
        std::fs::write(
            &password_hash_file,
            "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc\n",
        )
        .unwrap();
        let authenticator = Authenticator::new(AuthConfig {
            mode: AuthMode::Basic,
            issuer: String::new(),
            client_id: String::new(),
            audiences: vec![],
            scopes: vec![],
            signing_algorithms: vec![OidcSigningAlgorithm::Rs256],
            allowed_groups: vec![],
            group_claim: "groups".into(),
            basic_users: vec![BasicUserConfig {
                username: "operator".into(),
                password_hash_file: password_hash_file.display().to_string(),
            }],
        })
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", STANDARD.encode("operator:password")))
                .unwrap(),
        );
        assert_eq!(
            authenticator.authorize(&headers).await.unwrap().subject,
            "basic:operator"
        );

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", STANDARD.encode("operator:wrong"))).unwrap(),
        );
        assert!(authenticator.authorize(&headers).await.is_err());
        std::fs::remove_file(password_hash_file).unwrap();
    }

    #[tokio::test]
    async fn oidc_rejects_unconfigured_signing_algorithms_before_key_lookup() {
        let authenticator = oidc_test_authenticator();
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("attacker-key".into());
        let token = encode(
            &header,
            &serde_json::json!({
                "sub": "attacker",
                "exp": 4102444800_u64,
                "aud": "av-project",
                "iss": "https://identity.example",
                "roles": ["av-users"]
            }),
            &EncodingKey::from_secret(b"integration-only"),
        )
        .unwrap();
        let error = authenticator.authorize_oidc(&token).await.unwrap_err();
        assert!(error.to_string().contains("untrusted signing algorithm"));
    }

    #[tokio::test]
    async fn repeated_unknown_keys_do_not_bypass_the_jwks_refresh_cooldown() {
        let authenticator = oidc_test_authenticator();
        let attempt = Instant::now();
        authenticator.jwks_refresh.lock().await.last_attempt = Some(attempt);
        authenticator.refresh_jwks(false).await.unwrap();
        assert_eq!(
            authenticator.jwks_refresh.lock().await.last_attempt,
            Some(attempt)
        );
    }

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
