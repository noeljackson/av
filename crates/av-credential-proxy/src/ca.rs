use std::{fs, path::Path, sync::Arc, time::SystemTime};

use anyhow::{Context, Result};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::{
    ServerConfig,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

const LEAF_VALIDITY: Duration = Duration::hours(8);

/// A deployment-scoped interception CA whose private material never leaves the object.
pub struct ProxyCertificateAuthority {
    issuer: Issuer<'static, KeyPair>,
    certificate_pem: String,
}

impl ProxyCertificateAuthority {
    /// Load one CA certificate and matching private key from host-owned files.
    pub fn load(certificate_path: &Path, private_key_path: &Path) -> Result<Self> {
        let certificate_pem = fs::read_to_string(certificate_path)
            .with_context(|| format!("read proxy CA certificate {}", certificate_path.display()))?;
        let private_key_pem =
            Zeroizing::new(fs::read_to_string(private_key_path).with_context(|| {
                format!("read proxy CA private key {}", private_key_path.display())
            })?);
        let signing_key =
            KeyPair::from_pem(&private_key_pem).context("parse proxy CA private key")?;
        let issuer = Issuer::from_ca_cert_pem(&certificate_pem, signing_key)
            .context("parse proxy CA certificate")?;
        Ok(Self {
            issuer,
            certificate_pem,
        })
    }

    /// Return only the public CA certificate for an explicitly scoped client trust bundle.
    pub fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }

    /// Issue an ephemeral single-host leaf and return a ready server configuration.
    ///
    /// The caller selects the Rustls crypto provider. The generated private key
    /// is moved directly into Rustls and is never returned through this API.
    pub fn issue_server_config(
        &self,
        host: &str,
        provider: Arc<CryptoProvider>,
    ) -> Result<ServerConfig> {
        validate_leaf_host(host)?;
        let mut params = CertificateParams::new(vec![host.to_owned()])
            .context("create proxy leaf certificate parameters")?;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let now = OffsetDateTime::from(SystemTime::now());
        params.not_before = now - Duration::minutes(5);
        params.not_after = now + LEAF_VALIDITY;
        let signing_key = KeyPair::generate().context("generate proxy leaf private key")?;
        let certificate = params
            .signed_by(&signing_key, &self.issuer)
            .context("sign proxy leaf certificate")?;
        let private_key = Zeroizing::new(signing_key.serialize_der());
        ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .context("select proxy TLS protocol versions")?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(certificate.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key.to_vec())),
            )
            .context("configure proxy TLS leaf")
    }
}

fn validate_leaf_host(host: &str) -> Result<()> {
    crate::canonical_tunnel_host(host)
        .context("proxy leaf host must be one DNS name without wildcard, port, or IP literal")
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, DistinguishedName, DnType};
    use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    fn write_test_ca(
        directory: &tempfile::TempDir,
    ) -> (std::path::PathBuf, std::path::PathBuf, Vec<u8>) {
        let mut params = CertificateParams::new(vec!["av-test-ca".into()]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "AV test proxy CA");
        params.distinguished_name = name;
        let signing_key = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&signing_key).unwrap();
        let certificate_path = directory.path().join("ca.crt");
        let private_key_path = directory.path().join("ca.key");
        fs::write(&certificate_path, certificate.pem()).unwrap();
        fs::write(&private_key_path, signing_key.serialize_pem()).unwrap();
        (
            certificate_path,
            private_key_path,
            certificate.der().to_vec(),
        )
    }

    fn provider() -> Arc<CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    #[test]
    fn loads_a_mounted_ca_and_issues_only_single_dns_host_leaves() {
        let directory = tempfile::tempdir().unwrap();
        let (certificate_path, private_key_path, _) = write_test_ca(&directory);
        let authority =
            ProxyCertificateAuthority::load(&certificate_path, &private_key_path).unwrap();

        assert!(!authority.certificate_pem().is_empty());
        assert!(
            authority
                .issue_server_config("api.example.test", provider())
                .is_ok()
        );
        for invalid in ["", "*.example.test", "127.0.0.1", "api.example.test:443"] {
            assert!(
                authority.issue_server_config(invalid, provider()).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn rejects_a_missing_or_invalid_mounted_ca() {
        let directory = tempfile::tempdir().unwrap();
        assert!(
            ProxyCertificateAuthority::load(
                &directory.path().join("missing"),
                &directory.path().join("missing-key")
            )
            .is_err()
        );
        let certificate_path = directory.path().join("ca.crt");
        let private_key_path = directory.path().join("ca.key");
        fs::write(&certificate_path, "not a certificate").unwrap();
        fs::write(&private_key_path, "not a key").unwrap();
        assert!(ProxyCertificateAuthority::load(&certificate_path, &private_key_path).is_err());
    }

    #[tokio::test]
    async fn deployment_ca_trusts_only_the_issued_connector_host() {
        let directory = tempfile::tempdir().unwrap();
        let (certificate_path, private_key_path, ca_der) = write_test_ca(&directory);
        let authority =
            ProxyCertificateAuthority::load(&certificate_path, &private_key_path).unwrap();
        let server = TlsAcceptor::from(Arc::new(
            authority
                .issue_server_config("api.example.test", provider())
                .unwrap(),
        ));
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            let mut stream = server.accept(server_io).await.unwrap();
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            byte
        });

        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(ca_der)).unwrap();
        let client = TlsConnector::from(Arc::new(
            ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        let mut stream = client
            .connect(ServerName::try_from("api.example.test").unwrap(), client_io)
            .await
            .unwrap();
        stream.write_all(b"x").await.unwrap();
        assert_eq!(server_task.await.unwrap(), [b'x']);

        let wrong_server = TlsAcceptor::from(Arc::new(
            authority
                .issue_server_config("api.example.test", provider())
                .unwrap(),
        ));
        let (wrong_client_io, wrong_server_io) = tokio::io::duplex(16 * 1024);
        let wrong_server_task = tokio::spawn(async move {
            let _ = wrong_server.accept(wrong_server_io).await;
        });
        assert!(
            client
                .connect(
                    ServerName::try_from("other.example.test").unwrap(),
                    wrong_client_io,
                )
                .await
                .is_err()
        );
        wrong_server_task.await.unwrap();
    }
}
