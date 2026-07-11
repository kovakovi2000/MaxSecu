//! Compose the secret-free server from the portable layout + dev artifacts and
//! serve it over TLS. [`prepare`] is reusable by the smoke test (it returns the
//! bound listener + TLS config + composed router); [`run`] prints the DEV-ONLY
//! warnings + the new-model enrollment guidance, exports the client pins, then
//! serves until killed. There is NO bootstrap secret — enrollment is
//! registration-key-only (via `maxsecu-setup`), and the first registrant is admin.

use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_rustls::rustls::ServerConfig;

use std::time::Duration;

use maxsecu_server::{
    router, serve, AppState, AuthConfig, AuthService, BlobStore, ColdTier, DropboxTier,
    FsBlobStore, FsColdTier, MemoryStore, NullAuditSink, PgStore, WriteBackTier,
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
        ColdTierCfg::Dropbox {
            app_key,
            app_secret,
            refresh_token,
            access_token,
            root,
        } => Arc::new(
            DropboxTier::with_refresh(
                app_key.clone(),
                app_secret.clone(),
                refresh_token.clone(),
                access_token.clone(),
                root.clone(),
            )
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
/// (monomorphized) router, plus the pinned directory key **if known at startup**.
/// In the Prod delegation model `directory_pub` is `None` while awaiting the
/// admin's delegation (the D5 root originates on the admin PC, spec §6).
pub struct Prepared {
    pub listener: TcpListener,
    pub server_config: Arc<ServerConfig>,
    pub router: axum::Router,
    pub directory_pub: Option<[u8; 32]>,
    pub local_addr: std::net::SocketAddr,
}

/// Lay out the data dir, ensure the dev cert / D5, compose the `AppState` (DEV:
/// `MemoryStore` + persistent `FsBlobStore` + `NullAuditSink`), and bind the
/// listener. Reusable by the smoke test. DEV profile only. There is NO bootstrap
/// secret — enrollment is registration-key-only (the first registrant is admin).
pub async fn prepare(cfg: &LauncherConfig) -> std::io::Result<Prepared> {
    // Profiles differ in BOTH the Store backend AND the directory-authority model:
    //   * Dev  (MemoryStore): SECURITY-DEGRADED dev-D5 — the dev-D5 both signs
    //     bindings AND is the pinned root; enrollment is always open (no ceremony).
    //   * Prod (PgStore): the offline-D5 delegation model — a short-lived
    //     operational key signs bindings, the admin-held D5 root delegates it, and
    //     enrollment is CLOSED until a valid delegation is installed (spec §§5,6).
    let layout = Layout::ensure(&cfg.data_dir)?;
    pki::ensure_dev_cert(&layout, cfg.public_addr.as_deref())?;

    // Per-profile directory-authority wiring (dir_signer + delegation ctx + the
    // pinned D5 if known at startup). Dev self-generates the dev-D5; Prod never
    // generates a D5 (the root is admin-supplied through the ceremony).
    let wiring = match cfg.profile {
        Profile::Dev => crate::delegation_setup::build_dev(&layout)?,
        Profile::Prod => crate::delegation_setup::build_prod(&layout)?,
    };
    let directory_pub = wiring.directory_pub;

    let server_config = pki::load_server_config(&layout)?;
    let mut auth_cfg = AuthConfig::default();
    if let Some(dp) = directory_pub {
        auth_cfg = auth_cfg.with_directory_pub(dp);
    }
    let blobs = build_blobs(cfg, &layout)?;

    // Compose the router over the profile's Store. Each branch builds a distinct
    // `AppState<S>` and type-erases it via `router(..)` into the shared
    // `axum::Router`, so the differing store type never leaks into `Prepared`.
    let app_router = match cfg.profile {
        Profile::Dev => {
            let state = AppState {
                auth: Arc::new(
                    AuthService::new(MemoryStore::new(), auth_cfg)
                        .with_dir_signer(wiring.dir_signer.clone())
                        .with_delegation(wiring.ctx.clone()),
                ),
                blobs,
                audit: Arc::new(NullAuditSink),
                direct_links_enabled: cfg.direct_links_enabled,
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
                auth: Arc::new(
                    AuthService::new(PgStore::new(pool), auth_cfg)
                        .with_dir_signer(wiring.dir_signer.clone())
                        .with_delegation(wiring.ctx.clone()),
                ),
                blobs,
                audit: Arc::new(NullAuditSink),
                direct_links_enabled: cfg.direct_links_enabled,
                max_file_bytes: None,
            };
            router(state)
        }
    };

    // In-band pin bootstrap (design 2026-07-10 §2): serve the PUBLIC pins over
    // `GET /v1/bootstrap/pins`. The cert pin is always present; the directory pin is
    // present once a directory_pub is known (Dev: always; Prod: only once
    // delegated — empty while awaiting, since the D5 originates on the admin PC).
    let client_pins = cfg.data_dir.join("client-pins");
    pki::export_client_pin(&layout, &client_pins)?;
    let cert_bytes = std::fs::read(client_pins.join("server_cert.der"))?;
    let dir_bytes = if directory_pub.is_some() {
        bootstrap::export_client_pin_d5(&layout, &client_pins)?;
        std::fs::read(client_pins.join("directory_pub.der"))?
    } else {
        Vec::new() // awaiting delegation — no directory pin to serve yet
    };
    let app_router = app_router.merge(crate::bootstrap_pins::router(cert_bytes, dir_bytes));

    let listener = TcpListener::bind((cfg.bind.as_str(), cfg.port)).await?;
    let local_addr = listener.local_addr()?;
    Ok(Prepared {
        router: app_router,
        listener,
        server_config,
        directory_pub,
        local_addr,
    })
}

/// Run the dev launcher: prepare, export the client pins (cert + D5 pubkey), print
/// the DEV-ONLY warnings + the pin locations + the new-model enrollment guidance,
/// then serve until the process is killed. No bootstrap secret is generated.
pub async fn run(cfg: LauncherConfig) -> std::io::Result<()> {
    let prepared = prepare(&cfg).await?;
    let layout = Layout::ensure(&cfg.data_dir)?;
    // Export the client cert pin into a convenience dir the operator copies into the
    // client's `config/`. The D5 pin is exported per-profile below (Prod serves it
    // only once delegated).
    let client_pins = cfg.data_dir.join("client-pins");
    pki::export_client_pin(&layout, &client_pins)?;
    let cert_pin = std::fs::read(client_pins.join("server_cert.der"))?;
    let code_addr = cfg.public_addr.as_deref().unwrap_or("127.0.0.1");

    match cfg.profile {
        Profile::Dev => {
            // Dev banner is UNCHANGED (invariant 10): self-generated dev-D5, always
            // open enrollment, no ceremony. Connection code = fp(cert, dev-D5 pub).
            bootstrap::export_client_pin_d5(&layout, &client_pins)?;
            let dir_pin = std::fs::read(client_pins.join("directory_pub.der"))?;
            let fp = maxsecu_crypto::pin_fingerprint(&cert_pin, &dir_pin);
            eprintln!("  connection code: {code_addr}:{}#{fp}", cfg.port);
            eprintln!(
                "maxsecu-portable-server (DEV / ephemeral MemoryStore) listening on https://{}",
                prepared.local_addr
            );
            eprintln!(
                "  client pins (copy into the client's config/): {}",
                client_pins.display()
            );
            if let Some(dp) = prepared.directory_pub {
                eprintln!(
                    "  pinned D5 (DEV ONLY — replace with the offline ceremony key in production): {}",
                    hex(&dp)
                );
            }
        }
        Profile::Prod => {
            // Prod: offline-D5 delegation model. The `dev cert` label becomes
            // `pinned self-signed cert`; the SECURITY-DEGRADED dev+D5 / DEV-ONLY
            // lines are gone (invariant 9).
            eprintln!(
                "maxsecu-portable-server (Postgres / pinned self-signed cert) listening on https://{}",
                prepared.local_addr
            );
            eprintln!(
                "  client pins (copy into the client's config/): {}",
                client_pins.display()
            );
            match prepared.directory_pub {
                // Awaiting: the D5 root originates on the admin PC (spec §6), so we
                // cannot compute the final connection code. Print the cert-only
                // fingerprint (for the ceremony's TLS pinning) + the one-time token.
                None => {
                    let cert_fp = maxsecu_crypto::pin_fingerprint(&cert_pin, &[]);
                    let token =
                        std::fs::read_to_string(layout.bootstrap_token_path()).unwrap_or_default();
                    eprintln!("  directory: AWAITING DELEGATION (enrollment closed)");
                    eprintln!("  server address: {code_addr}:{}", cfg.port);
                    eprintln!("  server-cert fingerprint: {cert_fp}");
                    eprintln!("  one-time delegation token: {}", token.trim());
                    eprintln!(
                        "    run the ceremony from the admin PC (install-client / maxsecu-setup)"
                    );
                    eprintln!(
                        "    with this address + fingerprint + token to install the delegation."
                    );
                }
                // Delegated (loaded across a restart): print the full connection code
                // and the current window's expiry.
                Some(_dp) => {
                    bootstrap::export_client_pin_d5(&layout, &client_pins)?;
                    let dir_pin = std::fs::read(client_pins.join("directory_pub.der"))?;
                    let fp = maxsecu_crypto::pin_fingerprint(&cert_pin, &dir_pin);
                    let until = std::fs::read(layout.d5_delegation_path())
                        .ok()
                        .and_then(|b| maxsecu_crypto::parse_delegation(&b).ok())
                        .map(|d| fmt_utc_date(d.valid_until()))
                        .unwrap_or_else(|| "unknown".to_owned());
                    eprintln!("  directory: delegated (valid until {until})");
                    eprintln!("  connection code: {code_addr}:{}#{fp}", cfg.port);
                }
            }
        }
    }

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
        "  direct-link downloads: {}",
        if cfg.direct_links_enabled {
            "on"
        } else {
            "off"
        }
    );
    // Enrollment model (T4/T14): NO bootstrap secret. Recovery registration is OPEN
    // on a fresh server and CLOSES (409) once used; enrollment is registration-key
    // only — the first account to enroll with a key becomes admin.
    eprintln!("  enrollment: registration-key only (first registrant = admin);");
    eprintln!(
        "    provision the recovery account + the first registration key with `maxsecu-setup`"
    );
    eprintln!(
        "    (once-only: recovery registration is open now, and closes after the first use)."
    );
    serve(prepared.listener, prepared.server_config, prepared.router).await
}

/// Lowercase hex of a byte slice (for printing the pinned D5 key).
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Format a unix-seconds instant as a `YYYY-MM-DD UTC` calendar date for the
/// human-facing banner (no external date crate). Uses Howard Hinnant's
/// `civil_from_days` algorithm.
fn fmt_utc_date(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    // Shift to a March-based year to make leap handling branch-free.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02} UTC")
}
