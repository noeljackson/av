use std::collections::BTreeMap;

use anyhow::Result;

use crate::{
    config::{ConnectorConfig, ProfileConfig},
    infisical::InfisicalConnector,
    openbao::OpenBaoConnector,
};

#[derive(Clone)]
pub enum Connector {
    Infisical(InfisicalConnector),
    OpenBao(OpenBaoConnector),
}

impl Connector {
    pub fn new(config: ConnectorConfig, allow_insecure_http: bool) -> Result<Self> {
        match config {
            ConnectorConfig::Infisical(config) => Ok(Self::Infisical(InfisicalConnector::new(
                config,
                allow_insecure_http,
            )?)),
            ConnectorConfig::OpenBao(config) => Ok(Self::OpenBao(OpenBaoConnector::new(
                config,
                allow_insecure_http,
            )?)),
        }
    }

    pub async fn secrets(&self, profile: &ProfileConfig) -> Result<BTreeMap<String, String>> {
        match self {
            Self::Infisical(connector) => connector.secrets(profile).await,
            Self::OpenBao(connector) => connector.secrets(profile).await,
        }
    }
}
