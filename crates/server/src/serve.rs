//! TLS transport adapter: the live channel-binding wiring (DESIGN §9.2).
//!
//! A `tokio-rustls` accept loop terminates TLS 1.3 per connection, derives that
//! connection's RFC 5705 keying-material exporter, injects it as a
//! [`TlsExporter`](crate::http::TlsExporter) request `Extension`, and serves the
//! axum control-plane router over the stream via hyper-util. Handlers therefore
//! see the exporter the connection was *actually* bound to — the basis for
//! rejecting relayed proofs and lifted session tokens (api.md §1.5).

use std::sync::Arc;

use axum::Extension;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::http::TlsExporter;

/// RFC 5705 exporter label for MaxSecu channel binding. Client and server MUST
/// use byte-identical `(label, context, length)` so both derive the same value
/// from the shared TLS 1.3 secret.
pub const CHANNEL_BINDING_LABEL: &[u8] = b"EXPORTER-MaxSecu-channel-binding-v1";
/// Exporter output length: 32 bytes (matches the proof/token `tls_exporter` field).
pub const CHANNEL_BINDING_LEN: usize = 32;

/// Derive this connection's channel-binding value from a rustls connection
/// (server or client side). Returns `None` before the handshake completes.
pub fn export_channel_binding<D>(
    conn: &tokio_rustls::rustls::ConnectionCommon<D>,
) -> Option<[u8; CHANNEL_BINDING_LEN]> {
    let mut out = [0u8; CHANNEL_BINDING_LEN];
    conn.export_keying_material(&mut out, CHANNEL_BINDING_LABEL, None)
        .ok()?;
    Some(out)
}

/// Accept TLS connections on `listener`, injecting each connection's exporter,
/// and serve `router` over them. Runs until the listener errors. Each accepted
/// connection is handled on its own task; a single connection's handshake or
/// I/O failure never tears down the accept loop.
pub async fn serve(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    router: axum::Router,
) -> std::io::Result<()> {
    let acceptor = TlsAcceptor::from(config);
    loop {
        let (tcp, _peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            serve_connection(acceptor, tcp, router).await;
        });
    }
}

/// Terminate TLS on one accepted socket, bind its exporter into the router, and
/// serve HTTP/1.1 or HTTP/2 over the stream. Errors are swallowed: a malformed
/// handshake or a dropped peer is a per-connection event, not a server fault.
async fn serve_connection(
    acceptor: TlsAcceptor,
    tcp: tokio::net::TcpStream,
    router: axum::Router,
) {
    let tls = match acceptor.accept(tcp).await {
        Ok(tls) => tls,
        Err(_) => return, // handshake failure — drop the connection
    };
    // Derive the per-connection exporter from the *completed* handshake; both
    // peers compute the same bytes (RFC 5705). A connection whose exporter we
    // cannot read is unusable for channel binding, so we refuse to serve it.
    let exporter = match export_channel_binding(tls.get_ref().1) {
        Some(e) => TlsExporter(e),
        None => return,
    };
    let service = TowerToHyperService::new(router.layer(Extension(exporter)));
    let _ = Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(tls), service)
        .await;
}
