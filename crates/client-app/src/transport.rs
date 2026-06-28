//! Pinned-TLS transport to the app server. TLS 1.3 only, aws-lc-rs provider,
//! server identity pinned (api.md §1.1). After the handshake the client derives
//! the RFC 5705 exporter and feeds it to the login proof (api.md §1.5/§2).

use std::sync::Arc;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;

use crate::error::UiError;

/// MUST match the server's exporter parameters exactly (crates/server/src/serve.rs:
/// CHANNEL_BINDING_LABEL / CHANNEL_BINDING_LEN, context = None). If these drift,
/// channel binding fails closed and every login is rejected (RFC 5705 distinguishes
/// no-context from empty-context, so the context MUST stay `None`, not `Some(&[])`).
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-MaxSecu-channel-binding-v1";
pub const EXPORTER_LEN: usize = 32;

pub struct Transport {
    tls: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    addr: String,           // host:port
    pub server_id: String,  // filled after challenge
}

impl Transport {
    pub fn new(tls: Arc<ClientConfig>, server_name: ServerName<'static>, addr: String) -> Self {
        Self { tls, server_name, addr, server_id: String::new() }
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
}
