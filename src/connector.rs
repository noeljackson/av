use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime},
};

use anyhow::{Result, bail};
use zeroize::Zeroizing;

use crate::{
    config::{ConnectorConfig, ProfileConfig},
    google_secret_manager::GoogleSecretManagerConnector,
    infisical::InfisicalConnector,
    openbao::OpenBaoConnector,
};

#[allow(async_fn_in_trait)]
pub trait SecretBackend {
    fn kind(&self) -> &'static str;
    async fn acquire(&self, profile: &ProfileConfig) -> Result<SecretAcquisition>;
}

pub struct SecretAcquisition {
    pub values: BTreeMap<String, String>,
    pub lease: Option<BackendLease>,
}

pub enum BackendLease {
    OpenBao(OpenBaoLease),
    Infisical(InfisicalLease),
}

pub struct OpenBaoLease {
    pub(crate) id: Zeroizing<String>,
    pub(crate) renewable: bool,
    pub(crate) expires_at: SystemTime,
    pub(crate) renew_increment: Duration,
}

pub struct InfisicalLease {
    pub(crate) id: Zeroizing<String>,
    pub(crate) project_slug: String,
    pub(crate) environment: String,
    pub(crate) path: String,
    pub(crate) expires_at: SystemTime,
    pub(crate) renew_increment: Duration,
}

impl BackendLease {
    pub fn expires_at(&self) -> SystemTime {
        match self {
            Self::OpenBao(lease) => lease.expires_at,
            Self::Infisical(lease) => lease.expires_at,
        }
    }

    pub fn renewable(&self) -> bool {
        match self {
            Self::OpenBao(lease) => lease.renewable,
            // Infisical may reject renewals for provider-specific fixed leases.
            // AV treats the configured lease as renewable until that explicit
            // API response says otherwise.
            Self::Infisical(_) => true,
        }
    }
}

#[derive(Clone)]
pub enum Connector {
    Infisical(InfisicalConnector),
    OpenBao(OpenBaoConnector),
    GoogleSecretManager(GoogleSecretManagerConnector),
}

impl Connector {
    pub async fn new(config: ConnectorConfig, allow_insecure_http: bool) -> Result<Self> {
        match config {
            ConnectorConfig::Infisical(config) => Ok(Self::Infisical(InfisicalConnector::new(
                config,
                allow_insecure_http,
            )?)),
            ConnectorConfig::OpenBao(config) => Ok(Self::OpenBao(OpenBaoConnector::new(
                config,
                allow_insecure_http,
            )?)),
            ConnectorConfig::GoogleSecretManager(config) => Ok(Self::GoogleSecretManager(
                GoogleSecretManagerConnector::new(config).await?,
            )),
        }
    }

    pub async fn acquire(&self, profile: &ProfileConfig) -> Result<SecretAcquisition> {
        let mut acquisition = match self {
            Self::Infisical(connector) => connector.acquire(profile).await,
            Self::OpenBao(connector) => connector.acquire(profile).await,
            Self::GoogleSecretManager(connector) => connector.acquire(profile).await,
        }?;
        acquisition.values = apply_exports(acquisition.values, profile)?;
        Ok(acquisition)
    }

    pub async fn renew(&self, lease: &mut BackendLease) -> Result<()> {
        match (self, lease) {
            (Self::OpenBao(connector), BackendLease::OpenBao(lease)) => {
                connector.renew(lease).await
            }
            (Self::Infisical(connector), BackendLease::Infisical(lease)) => {
                connector.renew(lease).await
            }
            _ => bail!("lease backend does not match its connector"),
        }
    }

    pub async fn revoke(&self, lease: &BackendLease) -> Result<()> {
        match (self, lease) {
            (Self::OpenBao(connector), BackendLease::OpenBao(lease)) => {
                connector.revoke(lease).await
            }
            (Self::Infisical(connector), BackendLease::Infisical(lease)) => {
                connector.revoke(lease).await
            }
            _ => bail!("lease backend does not match its connector"),
        }
    }
}

fn apply_exports(
    mut values: BTreeMap<String, String>,
    profile: &ProfileConfig,
) -> Result<BTreeMap<String, String>> {
    if profile.exports.is_empty() {
        return Ok(values);
    }

    let mut exported = BTreeMap::new();
    for (local_name, export) in &profile.exports {
        let field = if export.field.is_empty() {
            local_name
        } else {
            &export.field
        };
        let Some(value) = values.remove(field) else {
            bail!("configured profile export field {field} was not returned by the backend");
        };
        exported.insert(local_name.clone(), value);
    }
    Ok(exported)
}

impl SecretBackend for InfisicalConnector {
    fn kind(&self) -> &'static str {
        "infisical"
    }

    async fn acquire(&self, profile: &ProfileConfig) -> Result<SecretAcquisition> {
        InfisicalConnector::acquire(self, profile).await
    }
}

impl SecretBackend for OpenBaoConnector {
    fn kind(&self) -> &'static str {
        "openbao"
    }

    async fn acquire(&self, profile: &ProfileConfig) -> Result<SecretAcquisition> {
        OpenBaoConnector::acquire(self, profile).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProfileExportConfig;

    fn profile(exports: BTreeMap<String, ProfileExportConfig>) -> ProfileConfig {
        ProfileConfig {
            connector: "test".into(),
            project_id: String::new(),
            environment: String::new(),
            secret_path: "/".into(),
            allowed_keys: vec![],
            exports,
            dynamic_secret: None,
        }
    }

    #[test]
    fn path_backend_exports_are_explicit_and_rename_fields() {
        let profile = profile(BTreeMap::from([(
            "API_TOKEN".into(),
            ProfileExportConfig {
                resource: String::new(),
                field: "UPSTREAM_TOKEN".into(),
            },
        )]));
        let values = BTreeMap::from([
            ("UPSTREAM_TOKEN".into(), "synthetic-value".into()),
            ("UNEXPORTED".into(), "must-not-escape".into()),
        ]);

        let exported = apply_exports(values, &profile).unwrap();
        assert_eq!(
            exported,
            BTreeMap::from([("API_TOKEN".into(), "synthetic-value".into())])
        );
    }

    #[test]
    fn missing_explicit_export_fails_closed() {
        let profile = profile(BTreeMap::from([(
            "API_TOKEN".into(),
            ProfileExportConfig {
                resource: String::new(),
                field: "MISSING".into(),
            },
        )]));

        assert!(apply_exports(BTreeMap::new(), &profile).is_err());
    }
}
