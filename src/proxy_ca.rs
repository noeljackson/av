//! Deployment CA loading and host-specific leaf issuance for AV's private
//! transparent proxy. The CA key is mounted from an existing Secret and is
//! never returned, logged, or persisted by AV.

use std::{fs, path::Path, time::SystemTime};

use anyhow::{Context, Result, bail};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

const LEAF_VALIDITY: Duration = Duration::hours(8);

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

    fn write_test_ca(directory: &tempfile::TempDir) -> (std::path::PathBuf, std::path::PathBuf) {
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
        (certificate_path, private_key_path)
    }

    #[test]
    fn loads_a_mounted_ca_and_issues_only_single_dns_host_leaves() {
        let directory = tempfile::tempdir().unwrap();
        let (certificate_path, private_key_path) = write_test_ca(&directory);
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
}
