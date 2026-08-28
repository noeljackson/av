//! AV-specific crypto-provider selection around the shared proxy CA.

use std::sync::{Arc, OnceLock};

use anyhow::Result;
pub use av_credential_proxy::ProxyCertificateAuthority;
use rustls::crypto::CryptoProvider;

static RUSTLS_PROVIDER: OnceLock<Result<(), String>> = OnceLock::new();

/// Return AV's explicit AWS-LC Rustls provider for shared proxy TLS issuance.
pub fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// Install AV's process-global Rustls provider for APIs that use default builders.
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
