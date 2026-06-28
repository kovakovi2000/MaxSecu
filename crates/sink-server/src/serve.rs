//! TLS transport for the sink HTTP surface (`docs/sink-interface.md` §3).
//!
//! A `tokio-rustls` accept loop terminates TLS 1.3 per connection and serves the
//! axum control-log router over the stream via hyper-util — mirroring the app
//! server's `serve` (`crates/server/src/serve.rs`), but WITHOUT channel binding:
//! the sink is a read-mostly attestation surface (its trust rests on the
//! anchor-proof the client re-verifies, §4), not a channel-bound session
//! authority, so it needs no RFC 5705 exporter.

use std::sync::Arc;

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

/// Accept TLS connections on `listener` and serve `router` over them. Runs until
/// the listener errors. Each accepted connection is handled on its own task; a
/// single connection's handshake or I/O failure never tears down the accept loop.
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
            // Handshake failure or a dropped peer is a per-connection event.
            let Ok(tls) = acceptor.accept(tcp).await else {
                return;
            };
            let service = TowerToHyperService::new(router);
            let _ = Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls), service)
                .await;
        });
    }
}
