//! Pinned-TLS transport to the app server. TLS 1.3 only, aws-lc-rs provider,
//! server identity pinned (api.md §1.1). After the handshake the client derives
//! the RFC 5705 exporter and feeds it to the login proof (api.md §1.5/§2).

use std::sync::Arc;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use crate::error::UiError;

/// TLS 1.3-only client config that pins exactly `server_cert` as the sole root.
/// Restricting to TLS 1.3 (the server is 1.3-only) prevents a downgrade that
/// would produce a weaker/mismatched RFC 5705 channel binding. No public-CA
/// roots are added: the pinned cert is the only accepted server identity.
pub fn pinned_client_config(
    server_cert: CertificateDer<'static>,
) -> Result<Arc<ClientConfig>, UiError> {
    let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = RootCertStore::empty();
    roots
        .add(server_cert)
        .map_err(|_| UiError::new("tls", "Invalid pinned certificate."))?;
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
        .map_err(|_| UiError::new("tls", "TLS configuration failed."))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// MUST match the server's exporter parameters exactly (crates/server/src/serve.rs:
/// CHANNEL_BINDING_LABEL / CHANNEL_BINDING_LEN, context = None). If these drift,
/// channel binding fails closed and every login is rejected (RFC 5705 distinguishes
/// no-context from empty-context, so the context MUST stay `None`, not `Some(&[])`).
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-MaxSecu-channel-binding-v1";
pub const EXPORTER_LEN: usize = 32;

pub struct Transport {
    tls: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    addr: String, // host:port
}

impl Transport {
    pub fn new(tls: Arc<ClientConfig>, server_name: ServerName<'static>, addr: String) -> Self {
        Self { tls, server_name, addr }
    }

    /// Connect, returning the live stream + the 32-byte channel-binding exporter.
    pub async fn connect(
        &self,
    ) -> Result<(tokio_rustls::client::TlsStream<tokio::net::TcpStream>, [u8; EXPORTER_LEN]), UiError> {
        let tcp = tokio::net::TcpStream::connect(&self.addr)
            .await
            .map_err(|_| UiError::new("offline", "Could not reach the server."))?;
        let connector = TlsConnector::from(self.tls.clone());
        let tls = connector
            .connect(self.server_name.clone(), tcp)
            .await
            .map_err(|_| UiError::new("tls", "Secure connection failed."))?;
        let mut exporter = [0u8; EXPORTER_LEN];
        tls.get_ref()
            .1
            .export_keying_material(&mut exporter, EXPORTER_LABEL, None)
            .map_err(|_| UiError::new("tls", "Channel binding failed."))?;
        Ok((tls, exporter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exporter_params_are_pinned_to_server_contract() {
        // Guard: these MUST equal crates/server/src/serve.rs CHANNEL_BINDING_LABEL/LEN
        // and the context MUST be None (channel binding fails closed otherwise).
        assert_eq!(EXPORTER_LABEL, b"EXPORTER-MaxSecu-channel-binding-v1");
        assert_eq!(EXPORTER_LEN, 32);
    }

    #[test]
    fn pinned_client_config_accepts_a_self_signed_cert() {
        // Mirrors test_pki() in server/tests/file_e2e.rs: a self-signed leaf is a
        // valid pinned root and the TLS-1.3-only builder accepts it.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        assert!(pinned_client_config(cert_der).is_ok());
    }
}
