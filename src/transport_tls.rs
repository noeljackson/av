//! Reloadable TLS configuration for AV's network-exposed transparent-proxy
//! transport. This certificate is separate from the CA used to intercept
//! configured upstream hosts.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result, bail};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

use crate::proxy_ca::install_rustls_provider;

pub struct ReloadingTransportTls {
    certificate_path: PathBuf,
    private_key_path: PathBuf,
    current: RwLock<Arc<ServerConfig>>,
}

impl ReloadingTransportTls {
    pub fn load(certificate_path: &Path, private_key_path: &Path) -> Result<Self> {
        let current = load_server_config(certificate_path, private_key_path)?;
        Ok(Self {
            certificate_path: certificate_path.to_owned(),
            private_key_path: private_key_path.to_owned(),
            current: RwLock::new(current),
        })
    }

    /// Re-read the projected Secret for every new transport connection.
    /// Kubernetes updates Secret volumes atomically. A valid replacement is
    /// used immediately; an incomplete or invalid update retains the last
    /// known-good configuration.
    pub fn acceptor(&self) -> (TlsAcceptor, Option<anyhow::Error>) {
        let reload_error = match load_server_config(&self.certificate_path, &self.private_key_path)
        {
            Ok(next) => match self.current.write() {
                Ok(mut current) => {
                    *current = next;
                    None
                }
                Err(_) => Some(anyhow::anyhow!("transport TLS state lock is poisoned")),
            },
            Err(error) => Some(error),
        };
        let current = self
            .current
            .read()
            .map(|current| current.clone())
            .unwrap_or_else(|poisoned| poisoned.into_inner().clone());
        (TlsAcceptor::from(current), reload_error)
    }
}

fn load_server_config(
    certificate_path: &Path,
    private_key_path: &Path,
) -> Result<Arc<ServerConfig>> {
    install_rustls_provider()?;
    let certificate_pem = fs::read(certificate_path).with_context(|| {
        format!(
            "read transport TLS certificate {}",
            certificate_path.display()
        )
    })?;
    let private_key_pem = Zeroizing::new(fs::read(private_key_path).with_context(|| {
        format!(
            "read transport TLS private key {}",
            private_key_path.display()
        )
    })?);
    let certificates = CertificateDer::pem_slice_iter(&certificate_pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse transport TLS certificate chain")?;
    if certificates.is_empty() {
        bail!("transport TLS certificate chain is empty");
    }
    let private_key = PrivateKeyDer::from_pem_slice(&private_key_pem)
        .context("parse transport TLS private key")?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .context("transport TLS certificate and private key do not match")?;
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};

    fn write_leaf(directory: &Path, name: &str) -> (PathBuf, PathBuf) {
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec![name.to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let certificate_path = directory.join("tls.crt");
        let private_key_path = directory.join("tls.key");
        std::fs::write(&certificate_path, certificate.pem()).unwrap();
        std::fs::write(&private_key_path, key.serialize_pem()).unwrap();
        (certificate_path, private_key_path)
    }

    #[test]
    fn retains_last_valid_configuration_during_invalid_secret_update() {
        let directory = tempfile::tempdir().unwrap();
        let (certificate_path, private_key_path) = write_leaf(directory.path(), "av.example.test");
        let reloader = ReloadingTransportTls::load(&certificate_path, &private_key_path).unwrap();
        assert!(reloader.acceptor().1.is_none());

        std::fs::write(&private_key_path, "not a private key").unwrap();
        assert!(reloader.acceptor().1.is_some());

        let replacement = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec!["av.example.test".to_owned()])
            .unwrap()
            .self_signed(&replacement)
            .unwrap();
        std::fs::write(&certificate_path, certificate.pem()).unwrap();
        std::fs::write(&private_key_path, replacement.serialize_pem()).unwrap();
        assert!(reloader.acceptor().1.is_none());
    }

    #[test]
    fn rejects_mismatched_transport_key() {
        let directory = tempfile::tempdir().unwrap();
        let (certificate_path, private_key_path) = write_leaf(directory.path(), "av.example.test");
        let other_key = KeyPair::generate().unwrap();
        std::fs::write(&private_key_path, other_key.serialize_pem()).unwrap();
        assert!(ReloadingTransportTls::load(&certificate_path, &private_key_path).is_err());
    }
}
