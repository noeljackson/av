//! Deployment CA loading and host-specific leaf issuance for AV's private
//! transparent proxy. The CA key is mounted from an existing Secret and is
//! never returned, logged, or persisted by AV.

use std::{fs, path::Path, sync::OnceLock, time::SystemTime};

use anyhow::{Context, Result, bail};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

const LEAF_VALIDITY: Duration = Duration::hours(8);
static RUSTLS_PROVIDER: OnceLock<Result<(), String>> = OnceLock::new();

pub struct ProxyCertificateAuthority {
    issuer: Issuer<'static, KeyPair>,
    certificate_pem: String,
}

pub struct IssuedLeafCertificate {
    pub certificate_der: Vec<u8>,
    pub private_key_der: Zeroizing<Vec<u8>>,
}

impl ProxyCertificateAuthority {
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

    /// The public CA certificate is supplied to the local helper so its child
    /// can trust only this proxy's issued leaf certificates. The private key
    /// remains inside this struct.
    pub fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }

    /// Issue an eight-hour server leaf for a single configured DNS name.
    /// Callers must first use `TransparentRouteCatalog`; this method accepts no
    /// wildcard, IP literal, or multi-host certificate request.
    pub fn issue_leaf(&self, host: &str) -> Result<IssuedLeafCertificate> {
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
        Ok(IssuedLeafCertificate {
            certificate_der: certificate.der().to_vec(),
            private_key_der: Zeroizing::new(signing_key.serialize_der()),
        })
    }
}

impl IssuedLeafCertificate {
    pub fn server_config(&self) -> Result<ServerConfig> {
        install_rustls_provider()?;
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(self.certificate_der.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.private_key_der.to_vec())),
            )
            .context("configure proxy TLS leaf")
    }
}

/// AV already uses aws-lc-rs for JWT crypto. Rustls can compile multiple
/// providers transitively, so select the same provider explicitly rather than
/// letting feature ordering choose a process-global default.
pub fn install_rustls_provider() -> Result<()> {
    RUSTLS_PROVIDER
        .get_or_init(|| {
            rustls::crypto::aws_lc_rs::default_provider()
                .install_default()
                .map_err(|_| "install aws-lc-rs as the Rustls crypto provider".to_owned())
        })
        .as_ref()
        .map_err(|error| anyhow::anyhow!("{error}"))
        .map(|_| ())
}

fn validate_leaf_host(host: &str) -> Result<()> {
    if host.is_empty()
        || host.parse::<std::net::IpAddr>().is_ok()
        || host.contains('*')
        || host.contains(['/', '\\', ':'])
        || host.chars().any(char::is_whitespace)
    {
        bail!("proxy leaf host must be one DNS name without wildcard, port, or IP literal");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, DistinguishedName, DnType};
    use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
    use std::sync::Arc;
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

    #[test]
    fn loads_a_mounted_ca_and_issues_only_single_dns_host_leaves() {
        let directory = tempfile::tempdir().unwrap();
        let (certificate_path, private_key_path, _) = write_test_ca(&directory);
        let authority =
            ProxyCertificateAuthority::load(&certificate_path, &private_key_path).unwrap();
        let leaf = authority.issue_leaf("api.example.test").unwrap();

        assert!(!authority.certificate_pem().is_empty());
        assert!(!leaf.certificate_der.is_empty());
        assert!(!leaf.private_key_der.is_empty());
        for invalid in ["", "*.example.test", "127.0.0.1", "api.example.test:443"] {
            assert!(authority.issue_leaf(invalid).is_err(), "{invalid}");
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
        let leaf = authority.issue_leaf("api.example.test").unwrap();
        let server = TlsAcceptor::from(Arc::new(leaf.server_config().unwrap()));
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
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        let server_name = ServerName::try_from("api.example.test").unwrap();
        let mut stream = client.connect(server_name, client_io).await.unwrap();
        stream.write_all(b"x").await.unwrap();
        assert_eq!(server_task.await.unwrap(), [b'x']);

        let wrong_leaf = authority.issue_leaf("api.example.test").unwrap();
        let wrong_server = TlsAcceptor::from(Arc::new(wrong_leaf.server_config().unwrap()));
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
