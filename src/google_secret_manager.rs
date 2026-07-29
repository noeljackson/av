use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc};

use anyhow::{Context, Result, bail};
use google_cloud_secretmanager_v1::{
    client::SecretManagerService, model::AccessSecretVersionResponse,
};

use crate::{
    config::{GoogleSecretManagerConfig, ProfileConfig},
    connector::{SecretAcquisition, SecretBackend},
};

const MAX_SECRET_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct GoogleSecretManagerConnector {
    client: Arc<dyn GoogleSecretClient>,
}

trait GoogleSecretClient: Send + Sync {
    fn access<'a>(
        &'a self,
        resource: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<AccessSecretVersionResponse>> + Send + 'a>>;
}

impl GoogleSecretClient for SecretManagerService {
    fn access<'a>(
        &'a self,
        resource: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<AccessSecretVersionResponse>> + Send + 'a>> {
        Box::pin(async move {
            self.access_secret_version()
                .set_name(resource)
                .send()
                .await
                .with_context(|| format!("access Google Secret Manager resource {resource}"))
        })
    }
}

impl GoogleSecretManagerConnector {
    pub async fn new(_config: GoogleSecretManagerConfig) -> Result<Self> {
        let client = SecretManagerService::builder()
            .build()
            .await
            .context("initialize Google Secret Manager with Application Default Credentials")?;
        Ok(Self {
            client: Arc::new(client),
        })
    }

    #[cfg(test)]
    fn from_client(client: impl GoogleSecretClient + 'static) -> Self {
        Self {
            client: Arc::new(client),
        }
    }

    async fn access(&self, resource: &str) -> Result<String> {
        let response = self.client.access(resource).await?;
        let payload = response
            .payload
            .context("Google Secret Manager response has no payload")?;
        if payload.data.is_empty() {
            bail!("Google Secret Manager payload is empty");
        }
        if payload.data.len() > MAX_SECRET_BYTES {
            bail!("Google Secret Manager payload exceeds 64 KiB");
        }
        let expected = payload
            .data_crc32c
            .context("Google Secret Manager payload has no CRC32C checksum")?;
        let expected = u32::try_from(expected)
            .context("Google Secret Manager payload has an invalid CRC32C checksum")?;
        if crc32c(&payload.data) != expected {
            bail!("Google Secret Manager payload failed CRC32C verification");
        }
        String::from_utf8(payload.data.to_vec())
            .context("Google Secret Manager payload is not UTF-8 text")
    }
}

impl SecretBackend for GoogleSecretManagerConnector {
    fn kind(&self) -> &'static str {
        "google_secret_manager"
    }

    async fn acquire(&self, profile: &ProfileConfig) -> Result<SecretAcquisition> {
        let mut values = BTreeMap::new();
        for (local_name, export) in &profile.exports {
            values.insert(local_name.clone(), self.access(&export.resource).await?);
        }
        Ok(SecretAcquisition {
            values,
            lease: None,
        })
    }
}

// Table-free CRC32C (Castagnoli). Secret Manager payloads are capped at 64 KiB,
// so keeping this tiny and dependency-free is preferable to expanding the
// release supply chain for a checksum primitive.
fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f6_3b78_u32 & (0_u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use google_cloud_secretmanager_v1::model::{AccessSecretVersionResponse, SecretPayload};

    use super::*;
    use crate::config::ProfileExportConfig;

    #[derive(Clone, Debug)]
    struct Stub {
        response: AccessSecretVersionResponse,
    }

    impl GoogleSecretClient for Stub {
        fn access<'a>(
            &'a self,
            _resource: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<AccessSecretVersionResponse>> + Send + 'a>>
        {
            let response = self.response.clone();
            Box::pin(async move { Ok(response) })
        }
    }

    fn profile(resource: &str) -> ProfileConfig {
        ProfileConfig {
            connector: "google".into(),
            project_id: String::new(),
            environment: String::new(),
            secret_path: "/".into(),
            allowed_keys: vec![],
            exports: BTreeMap::from([(
                "API_TOKEN".into(),
                ProfileExportConfig {
                    resource: resource.into(),
                    field: String::new(),
                },
            )]),
            dynamic_secret: None,
        }
    }

    fn connector(data: &[u8], checksum: Option<i64>) -> GoogleSecretManagerConnector {
        let payload = SecretPayload::new()
            .set_data(data.to_vec())
            .set_or_clear_data_crc32c(checksum);
        let response = AccessSecretVersionResponse::new().set_payload(payload);
        GoogleSecretManagerConnector::from_client(Stub { response })
    }

    #[test]
    fn crc32c_matches_castagnoli_check_value() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    }

    #[tokio::test]
    async fn resolves_an_explicit_resource_after_checksum_verification() {
        let data = b"synthetic-google-value";
        let connector = connector(data, Some(i64::from(crc32c(data))));
        let acquisition = connector
            .acquire(&profile(
                "projects/example/secrets/api-token/versions/latest",
            ))
            .await
            .unwrap();
        assert!(acquisition.lease.is_none());
        assert_eq!(
            acquisition.values.get("API_TOKEN").unwrap(),
            "synthetic-google-value"
        );
    }

    #[tokio::test]
    async fn rejects_missing_or_corrupt_checksums_and_binary_payloads() {
        let resource = "projects/example/secrets/api-token/versions/latest";
        assert!(
            connector(b"value", None)
                .acquire(&profile(resource))
                .await
                .is_err()
        );
        assert!(
            connector(b"value", Some(1))
                .acquire(&profile(resource))
                .await
                .is_err()
        );
        let binary = [0xff, 0xfe];
        assert!(
            connector(&binary, Some(i64::from(crc32c(&binary))))
                .acquire(&profile(resource))
                .await
                .is_err()
        );
    }
}
