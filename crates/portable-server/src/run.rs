//! Compose the secret-free server from the portable layout + dev artifacts and
//! serve it over TLS. [`prepare`] is reusable by the smoke test (it returns the
//! bound listener + TLS config + composed router); [`run`] prints the dev
//! bootstrap secret ONCE + the DEV-ONLY warnings, exports the client pins, then
//! serves until killed.

use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_rustls::rustls::ServerConfig;

use maxsecu_server::{
    router, serve, AppState, AuthConfig, AuthService, FsBlobStore, MemoryStore, NullAuditSink,
};

use crate::config::{LauncherConfig, Profile};
use crate::layout::Layout;
use crate::{bootstrap, pki};

/// What [`prepare`] produces: a bound listener + TLS config + the composed
/// (monomorphized) router, plus the freshly-generated bootstrap secret (`Some`
/// only on first run, to print once) and the pinned DEV directory key.
pub struct Prepared {
    pub listener: TcpListener,
    pub server_config: Arc<ServerConfig>,
    pub router: axum::Router,
    pub bootstrap_secret: Option<String>,
    pub directory_pub: [u8; 32],
    pub local_addr: std::net::SocketAddr,
}

/// Lay out the data dir, ensure the dev cert / D5 / bootstrap secret, compose the
/// `AppState` (DEV: `MemoryStore` + persistent `FsBlobStore` + `NullAuditSink`),
/// and bind the listener. Reusable by the smoke test. DEV profile only.
pub async fn prepare(cfg: &LauncherConfig) -> std::io::Result<Prepared> {
    if cfg.profile == Profile::Prod {
        // PROD parity is type-checked but requires Postgres (unavailable in this
        // env): a `PgStore` + an injected (non-self-signed) cert + an external
        // audit sink + a `schema.sql` self-apply. The DEV profile (no
        // `DATABASE_URL`) runs with `MemoryStore` + a self-signed pinned cert.
        return Err(std::io::Error::other(format!(
            "prod profile (DATABASE_URL={}) requires Postgres: set up PgStore + an injected \
             cert/sink + schema.sql; the dev profile (no DATABASE_URL) runs with MemoryStore + \
             a self-signed cert",
            cfg.database_url.as_deref().unwrap_or("<unset>")
        )));
    }
    let layout = Layout::ensure(&cfg.data_dir)?;
    pki::ensure_dev_cert(&layout)?;
    let directory_pub = bootstrap::ensure_dev_d5(&layout)?;
    let bootstrap_secret = bootstrap::ensure_bootstrap_secret(&layout)?;
    let hash = bootstrap::bootstrap_secret_hash(&layout)?
        .ok_or_else(|| std::io::Error::other("bootstrap hash missing after ensure"))?;

    let server_config = pki::load_server_config(&layout)?;
    let store = MemoryStore::new();
    let auth_cfg = AuthConfig::default()
        .with_directory_pub(directory_pub)
        .with_bootstrap_secret_hash(hash);
    let state = AppState {
        auth: Arc::new(AuthService::new(store, auth_cfg)),
        blobs: Arc::new(FsBlobStore::new(layout.blobs_dir())),
        audit: Arc::new(NullAuditSink),
        direct_links_enabled: false,
    };
    let listener = TcpListener::bind(("127.0.0.1", cfg.port)).await?;
    let local_addr = listener.local_addr()?;
    Ok(Prepared {
        router: router(state),
        listener,
        server_config,
        bootstrap_secret,
        directory_pub,
        local_addr,
    })
}

/// Run the dev launcher: prepare, export the client pins (cert + D5 pubkey), print
/// the bootstrap secret ONCE + the DEV-ONLY warnings + the pin locations, then
/// serve until the process is killed.
pub async fn run(cfg: LauncherConfig) -> std::io::Result<()> {
    let prepared = prepare(&cfg).await?;
    let layout = Layout::ensure(&cfg.data_dir)?;
    // Export the client pins (cert + D5 pubkey) into a convenience dir the operator
    // copies into the client's `config/` for the auto-connect scenario.
    let client_pins = cfg.data_dir.join("client-pins");
    pki::export_client_pin(&layout, &client_pins)?;
    bootstrap::export_client_pin_d5(&layout, &client_pins)?;

    eprintln!(
        "maxsecu-portable-server (DEV profile) listening on https://{}",
        prepared.local_addr
    );
    eprintln!(
        "  client pins (copy into the client's config/): {}",
        client_pins.display()
    );
    eprintln!(
        "  pinned D5 (DEV ONLY — replace with the offline ceremony key in production): {}",
        hex(&prepared.directory_pub)
    );
    if let Some(secret) = &prepared.bootstrap_secret {
        eprintln!("  BOOTSTRAP SECRET (shown ONCE — record it now): {secret}");
    } else {
        eprintln!("  (already bootstrapped — the bootstrap secret was shown on first run)");
    }
    serve(prepared.listener, prepared.server_config, prepared.router).await
}

/// Lowercase hex of a byte slice (for printing the pinned D5 key).
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
