use std::collections::BTreeMap;

use anyhow::{Result, bail};

use crate::{
    config::{ConnectorConfig, ProfileConfig},
    google_secret_manager::GoogleSecretManagerConnector,
    infisical::InfisicalConnector,
    openbao::OpenBaoConnector,
};

#[allow(async_fn_in_trait)]
pub trait SecretBackend {
    fn kind(&self) -> &'static str;
    async fn secrets(&self, profile: &ProfileConfig) -> Result<BTreeMap<String, String>>;
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

    pub async fn secrets(&self, profile: &ProfileConfig) -> Result<BTreeMap<String, String>> {
        let values = match self {
            Self::Infisical(connector) => connector.secrets(profile).await,
            Self::OpenBao(connector) => connector.secrets(profile).await,
            Self::GoogleSecretManager(connector) => return connector.secrets(profile).await,
        }?;
        apply_exports(values, profile)
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

    async fn secrets(&self, profile: &ProfileConfig) -> Result<BTreeMap<String, String>> {
        InfisicalConnector::secrets(self, profile).await
    }
}

impl SecretBackend for OpenBaoConnector {
    fn kind(&self) -> &'static str {
        "openbao"
    }

    async fn secrets(&self, profile: &ProfileConfig) -> Result<BTreeMap<String, String>> {
        OpenBaoConnector::secrets(self, profile).await
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
