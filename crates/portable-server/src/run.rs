//! Compose the secret-free server from the portable layout + dev artifacts and
//! serve it over TLS. [`prepare`] is reusable by the smoke test (it returns the
//! bound listener + TLS config + composed router); [`run`] prints the dev
//! bootstrap secret ONCE + the DEV-ONLY warnings, exports the client pins, then
//! serves until killed.

use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_rustls::rustls::ServerConfig;

use std::time::Duration;

use maxsecu_server::{
    router, serve, AppState, AuthConfig, AuthService, BlobStore, ColdTier, DropboxTier, FsBlobStore,
    FsColdTier, MemoryStore, NullAuditSink, PgStore, WriteBackTier,
};

use crate::config::{ColdTierCfg, LauncherConfig, Profile};
use crate::layout::Layout;
use crate::{bootstrap, pki};

/// How often the background sweep offloads idle chunks to the cold tier. Far finer
/// than the multi-day idle threshold (so offload latency is bounded) yet cheap when
/// nothing is idle.
const IDLE_SWEEP_INTERVAL: Duration = Duration::from_secs(3600);

/// Build the blob store for the configured cold tier. With `ColdTierCfg::Off` this
/// is just the local `FsBlobStore` (today's behavior, no offload). Otherwise it is a
/// write-back [`WriteBackTier`] over that local store + the configured cold tier,
/// and a background idle-offload sweeper task is spawned. Returns the type-erased
/// store either way. The Dropbox OAuth token is never logged.
fn build_blobs(cfg: &LauncherConfig, layout: &Layout) -> std::io::Result<Arc<dyn BlobStore>> {
    let local: Arc<dyn BlobStore> = Arc::new(FsBlobStore::new(layout.blobs_dir()));
    let cold: Arc<dyn ColdTier> = match &cfg.cold_tier {
        ColdTierCfg::Off => return Ok(local),
        ColdTierCfg::Fs(dir) => Arc::new(FsColdTier::new(dir.clone())),
        ColdTierCfg::Dropbox { token, root } => Arc::new(
            DropboxTier::new(token.clone(), root.clone())
                .map_err(|e| std::io::Error::other(format!("dropbox tier init: {e}")))?,
        ),
    };
    let tier = Arc::new(WriteBackTier::new(
        local,
        cold,
        cfg.cache_capacity_bytes,
        Duration::from_secs(cfg.offload_idle_days * 24 * 3600),
    ));
    // Background idle-offload sweep: offloads chunks not requested for longer than
    // the configured span. Detached; the Arc keeps the tier alive alongside AppState.
    let sweeper = tier.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(IDLE_SWEEP_INTERVAL);
        loop {
            ticker.tick().await;
            sweeper.run_idle_sweep().await;
        }
    });
    Ok(tier)
}

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
    // Dev artifacts are identical on BOTH profiles: the persistent profile is a
    // SECURITY-DEGRADED *persistent-DEV* (Postgres persistence + dev cert/D5/
    // bootstrap), NOT the production ceremony profile (which additionally requires
    // an injected non-self-signed cert + an external WORM/audit sink + the offline
    // ceremony key). Only the Store backend differs: MemoryStore vs PgStore.
    let layout = Layout::ensure(&cfg.data_dir)?;
    pki::ensure_dev_cert(&layout)?;
    let directory_pub = bootstrap::ensure_dev_d5(&layout)?;
    let bootstrap_secret = bootstrap::ensure_bootstrap_secret(&layout)?;
    let hash = bootstrap::bootstrap_secret_hash(&layout)?
        .ok_or_else(|| std::io::Error::other("bootstrap hash missing after ensure"))?;

    let server_config = pki::load_server_config(&layout)?;
    let auth_cfg = AuthConfig::default()
        .with_directory_pub(directory_pub)
        .with_bootstrap_secret_hash(hash);
    let blobs = build_blobs(cfg, &layout)?;

    // Compose the router over the profile's Store. Each branch builds a distinct
    // `AppState<S>` and type-erases it via `router(..)` into the shared
    // `axum::Router`, so the differing store type never leaks into `Prepared`.
    let app_router = match cfg.profile {
        Profile::Dev => {
            let state = AppState {
                auth: Arc::new(AuthService::new(MemoryStore::new(), auth_cfg)),
                blobs,
                audit: Arc::new(NullAuditSink),
                direct_links_enabled: false,
                max_file_bytes: None,
            };
            router(state)
        }
        Profile::Prod => {
            let url = cfg.database_url.clone().ok_or_else(|| {
                std::io::Error::other("DATABASE_URL is required for the persistent profile")
            })?;
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(8)
                .acquire_timeout(std::time::Duration::from_secs(10))
                .connect(&url)
                .await
                .map_err(|e| std::io::Error::other(format!("postgres connect: {e}")))?;
            let state = AppState {
                auth: Arc::new(AuthService::new(PgStore::new(pool), auth_cfg)),
                blobs,
                audit: Arc::new(NullAuditSink),
                direct_links_enabled: false,
                max_file_bytes: None,
            };
            router(state)
        }
    };

    let listener = TcpListener::bind(("127.0.0.1", cfg.port)).await?;
    let local_addr = listener.local_addr()?;
    Ok(Prepared {
        router: app_router,
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

    let profile_label = match cfg.profile {
        Profile::Dev => "DEV / ephemeral MemoryStore",
        Profile::Prod => "persistent-DEV / Postgres (SECURITY-DEGRADED dev cert+D5+secret)",
    };
    eprintln!(
        "maxsecu-portable-server ({profile_label}) listening on https://{}",
        prepared.local_addr
    );
    eprintln!(
        "  client pins (copy into the client's config/): {}",
        client_pins.display()
    );
    // Cold-tier offload mode — never prints the Dropbox token, only its root.
    let tier_label = match &cfg.cold_tier {
        ColdTierCfg::Off => "off (local only)".to_owned(),
        ColdTierCfg::Fs(dir) => format!("fs cold tier at {}", dir.display()),
        ColdTierCfg::Dropbox { root, .. } => format!("Dropbox (root {root})"),
    };
    eprintln!(
        "  cold-tier offload: {tier_label} (cache cap {} bytes, idle {} days)",
        cfg.cache_capacity_bytes, cfg.offload_idle_days
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
