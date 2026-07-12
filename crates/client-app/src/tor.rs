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
use std::sync::{Arc, OnceLock};

use arti_client::config::TorClientConfigBuilder;
use arti_client::{DormantMode, TorClient};
use tokio::sync::{Mutex, OnceCell};
use tor_rtcompat::PreferredRuntime;

use crate::error::UiError;
use crate::transport::BoxedStream;

/// The process-wide Tor state. There is only ever one Tor client (one bootstrap,
/// one set of circuits), so it lives as a singleton rather than being threaded
/// through every connection helper. `main` initializes it once; the connection
/// code reads it only on the `TorOnly` path.
static GLOBAL: OnceLock<TorState> = OnceLock::new();

/// Initialize the process-wide Tor state with the client config dir (arti state is
/// confined to its `tor/` subdirectory). Idempotent — first call wins. Call once
/// from `main`.
pub fn init(config_dir: PathBuf) {
    let _ = GLOBAL.set(TorState::new(config_dir));
}

/// The process-wide Tor state, if [`init`] has run. `None` in tests / non-Tauri
/// contexts (which never select `TorOnly`, so they never dial Tor).
pub fn global() -> Option<&'static TorState> {
    GLOBAL.get()
}

/// A lazily-bootstrapped, shared Tor client. The arti client is CREATED at most
/// once (cached in `cell`) and REUSED across every connect attempt, so a failed
/// bootstrap never spawns a *second* client whose background tasks would spin the
/// CPU. `bootstrapped` serializes bootstrap attempts and records success; on a
/// bootstrap timeout the shared client is put dormant so its background dir/channel
/// tasks stop churning (arti abandoning the bootstrap future does not stop them —
/// arti has no hard shutdown, see its TODO #1932).
pub struct TorState {
    /// The arti client, created UNBOOTSTRAPPED at most once, then reused.
    cell: OnceCell<Arc<TorClient<PreferredRuntime>>>,
    /// `false` until a bootstrap has succeeded; the mutex also serializes attempts.
    bootstrapped: Mutex<bool>,
    /// `<config-dir>/tor` — arti's persistent state dir (cache is a subdir).
    state_dir: PathBuf,
}

impl TorState {
    /// Build the (not-yet-bootstrapped) holder. `config_dir` is the client's
    /// config directory; arti state is confined to its `tor/` subdirectory.
    pub fn new(config_dir: PathBuf) -> Self {
        Self {
            cell: OnceCell::new(),
            bootstrapped: Mutex::new(false),
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
        // 1) Create the shared arti client (UNBOOTSTRAPPED) exactly once. Creation is
        //    cheap and does NOT start fetching the consensus; we drive and bound the
        //    bootstrap ourselves below. Reusing one client means a stalled bootstrap
        //    never leaves a *second* client's background tasks spinning the CPU.
        let client = self
            .cell
            .get_or_try_init(|| async {
                let cache_dir = self.state_dir.join("cache");
                let cfg = TorClientConfigBuilder::from_directories(&self.state_dir, &cache_dir)
                    .build()
                    .map_err(|_| {
                        UiError::new("tor_unavailable", "Tor configuration is invalid.")
                    })?;
                TorClient::builder()
                    .config(cfg)
                    .create_unbootstrapped_async()
                    .await
                    .map_err(|_| {
                        UiError::new("tor_unavailable", "Could not initialize the Tor client.")
                    })
            })
            .await?
            .clone();

        // 2) Bootstrap once, serialized. If a previous connect already bootstrapped
        //    the shared client, reuse it immediately.
        let mut done = self.bootstrapped.lock().await;
        if *done {
            return Ok(client);
        }
        on_bootstrap();
        // Wake the client in case a prior failed attempt left it dormant (below).
        client.set_dormant(DormantMode::Normal);
        match crate::timeout::with_deadline(
            crate::timeout::TOR_BOOTSTRAP_TIMEOUT,
            async {
                client.bootstrap().await.map_err(|_| {
                    UiError::new("tor_unavailable", "Could not connect to the Tor network.")
                })
            },
            UiError::new("tor_timeout", "Connecting to the Tor network timed out."),
        )
        .await
        {
            Ok(()) => {
                *done = true;
                Ok(client)
            }
            Err(e) => {
                // Bootstrap stalled — e.g. the network blocks/DPI-filters Tor, so the
                // consensus never downloads. Abandoning the bootstrap future does NOT
                // stop arti's background dir/channel tasks (no hard shutdown — arti's
                // TODO #1932); left running they peg the CPU retrying forever. Put the
                // shared client dormant to pause them until the next connect attempt
                // wakes it (DormantMode::Normal above).
                client.set_dormant(DormantMode::Soft);
                Err(e)
            }
        }
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
        let stream = crate::timeout::with_deadline(
            crate::timeout::TOR_DIAL_TIMEOUT,
            async {
                client
                    .connect((host, port))
                    .await
                    .map_err(|_| UiError::new("offline", "Could not reach the server over Tor."))
            },
            UiError::new("tor_timeout", "Reaching the server over Tor timed out."),
        )
        .await?;
        Ok(Box::new(stream) as BoxedStream)
    }
}
