//! In-process Tor transport for the `TorOnly` download route (Part C).
//!
//! One bootstrapped [`arti_client::TorClient`] is shared for the whole app
//! lifetime — bootstrap (fetching the network consensus) is expensive, and the
//! guard/circuit state is worth reusing. Arti's persistent state + cache live
//! under `<config-dir>/tor`. Dialing yields a Tor-circuit `DataStream` which
//! [`crate::transport::tls_over`] then wraps in the SAME pinned TLS 1.3 + RFC 5705
//! channel binding as the direct route — so the zero-knowledge server contract and
//! the channel-bound login proof are unchanged; only the bytes travel over Tor.
//!
//! The bundled-C SQLite that arti's directory manager uses is transport-only and
//! lives entirely outside the crypto/key TCB (which stays pure-Rust). It is the
//! reason `client-app` is its own cargo workspace (see the crate Cargo.toml).

use std::path::PathBuf;
use std::sync::Arc;

use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient;
use tokio::sync::OnceCell;
use tor_rtcompat::PreferredRuntime;

use crate::error::UiError;
use crate::transport::BoxedStream;

/// A lazily-bootstrapped, shared Tor client. The `OnceCell` guarantees the slow
/// first bootstrap runs at most once; a failed bootstrap is NOT cached, so the
/// next `TorOnly` connect retries cleanly.
pub struct TorState {
    cell: OnceCell<Arc<TorClient<PreferredRuntime>>>,
    /// `<config-dir>/tor` — arti's persistent state dir (cache is a subdir).
    state_dir: PathBuf,
}

impl TorState {
    /// Build the (not-yet-bootstrapped) holder. `config_dir` is the client's
    /// config directory; arti state is confined to its `tor/` subdirectory.
    pub fn new(config_dir: PathBuf) -> Self {
        Self {
            cell: OnceCell::new(),
            state_dir: config_dir.join("tor"),
        }
    }

    /// Get-or-bootstrap the shared client. `on_bootstrap` is invoked exactly once,
    /// immediately before the (potentially slow) first bootstrap, so the caller can
    /// surface a "connecting to Tor" state in the UI. Must be called inside a Tokio
    /// runtime (arti derives `PreferredRuntime::current`), which every Tauri command
    /// already is.
    pub async fn client(
        &self,
        on_bootstrap: impl FnOnce() + Send,
    ) -> Result<Arc<TorClient<PreferredRuntime>>, UiError> {
        let client = self
            .cell
            .get_or_try_init(|| async {
                on_bootstrap();
                let cache_dir = self.state_dir.join("cache");
                let cfg = TorClientConfigBuilder::from_directories(&self.state_dir, &cache_dir)
                    .build()
                    .map_err(|_| {
                        UiError::new("tor_unavailable", "Tor configuration is invalid.")
                    })?;
                TorClient::create_bootstrapped(cfg).await.map_err(|_| {
                    UiError::new("tor_unavailable", "Could not connect to the Tor network.")
                })
            })
            .await?;
        Ok(client.clone())
    }

    /// Dial `host:port` over Tor and return the circuit stream boxed for
    /// [`crate::transport::tls_over`]. Never falls back to a direct connection —
    /// the caller surfaces the error rather than leaking the client IP.
    pub async fn dial(
        &self,
        host: &str,
        port: u16,
        on_bootstrap: impl FnOnce() + Send,
    ) -> Result<BoxedStream, UiError> {
        let client = self.client(on_bootstrap).await?;
        let stream = client
            .connect((host, port))
            .await
            .map_err(|_| UiError::new("offline", "Could not reach the server over Tor."))?;
        Ok(Box::new(stream) as BoxedStream)
    }
}
