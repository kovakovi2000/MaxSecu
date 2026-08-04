//! Compose the secret-free server from the portable layout + dev artifacts and
//! serve it over TLS. [`prepare`] is reusable by the smoke test (it returns the
//! bound listener + TLS config + composed router); [`run`] prints the DEV-ONLY
//! warnings + the new-model enrollment guidance, exports the client pins, then
//! serves until killed. There is NO bootstrap secret — enrollment is
//! registration-key-only (via `maxsecu-setup`), and the first registrant is admin.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_rustls::rustls::ServerConfig;

use std::time::Duration;

use maxsecu_server::{
    router, serve, AppState, AuthConfig, AuthService, BlobStore, ColdTier, DropboxTier,
    FsBlobStore, FsColdTier, MemoryStore, NullAuditSink, PgStore, Store, WriteBackTier,
};

use crate::config::{ColdTierCfg, LauncherConfig, Profile};
use crate::layout::Layout;
use crate::{bootstrap, pki};

/// How often the background sweep offloads idle chunks to the cold tier. Far finer
/// than the multi-day idle threshold (so offload latency is bounded) yet cheap when
/// nothing is idle.
const IDLE_SWEEP_INTERVAL: Duration = Duration::from_secs(3600);

/// How often the background prune sweeps long-expired `sessions` / `auth_nonces`
/// rows. Hourly is far more often than it needs to be: with a 7-day grace window
/// nothing is urgent, and the point of the short period is that each pass stays
/// tiny, not that it keeps up.
const AUTH_PRUNE_INTERVAL: Duration = Duration::from_secs(3600);

/// Spawn the background auth-row prune.
///
/// Both `sessions` and `auth_nonces` are append-plus-update-in-place on every
/// request path — a session is *revoked* by an UPDATE and a nonce is *consumed*
/// by an UPDATE, and no request path deletes from either; **this task is the
/// only delete either table has** — so without it the two tables only grow, and
/// so does `auth_nonces_open_idx`, whose `used_at IS NULL` predicate does NOT
/// bound itself (an abandoned challenge stays open forever). `auth_nonces` is
/// the one that matters most on top of that: a challenge is
/// issued even for an unknown username (no user-existence oracle), the issuance
/// cap is per claimed *name* with no per-source cap, and the login path reads the
/// table on every channel mint.
///
/// Deliberately an in-process tokio task rather than a cron entry or a systemd
/// timer: this box is deployed by drag-and-drop with no git and has no timer
/// surface at all today, and a unit that can drift out of sync with the binary
/// that owns the schema is a worse failure mode than the leak it fixes.
///
/// **A prune fault is never fatal and never reaches a request.** The task owns
/// its own errors: it logs them and lets the next tick retry. It shares the same
/// [`AuthService`] — hence the same pool — as the handlers, but a failed DELETE
/// cannot fail a login, because no login ever awaits one.
///
/// Returns a counter the task bumps once per completed pass, faults included.
/// [`prepare`] hands it out as [`Prepared::auth_prune_passes`] for exactly one
/// reason: **without it this wiring is unobservable.** Every prune test drove
/// `Store::prune_expired_auth_rows` directly, so deleting the two calls below —
/// the only thing that makes any of it happen in production — left the whole
/// suite green. `prepare_spawns_the_background_auth_prune` watches this counter
/// advance, so removing the spawn now fails a test instead of silently shipping
/// a server that never prunes.
fn spawn_auth_prune<S: Store + 'static>(auth: Arc<AuthService<S>>) -> Arc<AtomicU64> {
    let passes = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&passes);
    tokio::spawn(async move {
        // `interval`'s FIRST tick completes immediately, so the first pass runs
        // at startup rather than an hour in — a box restarted often would
        // otherwise never prune at all.
        let mut ticker = tokio::time::interval(AUTH_PRUNE_INTERVAL);
        loop {
            ticker.tick().await;
            match auth.prune_expired_auth_rows(now_ms()).await {
                Ok(c) if c.total() > 0 => eprintln!(
                    "  auth prune: removed {} expired session row(s), {} expired nonce row(s)",
                    c.sessions, c.nonces
                ),
                Ok(_) => {}
                Err(e) => eprintln!(
                    "  WARNING: auth prune failed (retrying in {}s; logins are unaffected): {e}",
                    AUTH_PRUNE_INTERVAL.as_secs()
                ),
            }
            // AFTER the match, and on the error arm too: the contract is "a pass
            // happened and the loop is still alive", which is what a fault must
            // not break.
            counter.fetch_add(1, Ordering::Relaxed);
        }
    });
    passes
}

/// Wall clock in epoch-milliseconds — the app clock the auth state machine (and
/// so the prune cutoff) reasons in.
///
/// Deliberately total, unlike the request path's equivalent: a clock before the
/// epoch yields `0`, which the prune's saturating cutoff turns into "delete
/// nothing". Panicking here would kill the detached task for the life of the
/// process, quietly, which is exactly the failure mode this task must not have.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Build the configured cold tier, or `None` for [`ColdTierCfg::Off`]. Shared by
/// the serve path ([`build_blobs`]) and the backup subcommands
/// ([`build_backup_tiers`]). The Dropbox OAuth token is never logged.
fn build_cold(cfg: &LauncherConfig, layout: &Layout) -> std::io::Result<Option<Arc<dyn ColdTier>>> {
    let cold: Arc<dyn ColdTier> = match &cfg.cold_tier {
        ColdTierCfg::Off => return Ok(None),
        ColdTierCfg::Fs(dir) => {
            reject_aliased_fs_cold_tier(dir, layout, &cfg.data_dir)?;
            Arc::new(FsColdTier::new(dir.clone()))
        }
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
    Ok(Some(cold))
}

/// Refuse an `fs` cold tier that resolves to the SAME directory as the local blob
/// store. **This one destroys user ciphertext, silently and permanently.**
///
/// `FsColdTier` and the local `FsBlobStore` use the identical `{base}/{blob_ref}/{index}`
/// layout, so if the two roots are the same directory — set directly, or reached
/// through a symlink or a bind mount — then `WriteBackTier::offload` does
/// `cold.put_chunk(...)` immediately followed by `local.delete_chunk(...)` **on the
/// very file it just wrote**. The chunk is gone from both tiers, and because offload
/// is the idle sweeper it happens quietly, long after the upload, to data the user
/// believes is safely stored. Nothing else in the system notices: the DB row survives
/// and the file simply 404s forever.
///
/// Canonicalize before comparing, so a symlink or bind mount cannot dress the same
/// directory up as two.
///
/// Scoped deliberately to EQUALITY, not containment. A cold root that merely sits
/// inside the data dir cannot collide (a `blob_ref` is `hex(file_id)/version/stream`,
/// 32 hex chars — never `blobs`), so refusing it would be a tightening that could
/// stop an existing server from booting, which is its own kind of lockout. That case
/// gets a loud warning instead: it is a real hazard, but for a different reason (a
/// dead-box rebuild that clears the data dir would take the backup with it), and the
/// runbook already tells the operator to keep the cold tier outside.
fn reject_aliased_fs_cold_tier(
    cold_dir: &Path,
    layout: &Layout,
    data_dir: &Path,
) -> std::io::Result<()> {
    let blobs = layout.blobs_dir();
    std::fs::create_dir_all(cold_dir)?;
    std::fs::create_dir_all(&blobs)?;
    // If either side cannot canonicalize, fall back to the literal paths rather than
    // failing the boot: a comparison we cannot make is not a reason to refuse to run.
    let c = cold_dir
        .canonicalize()
        .unwrap_or_else(|_| cold_dir.to_path_buf());
    let b = blobs.canonicalize().unwrap_or_else(|_| blobs.clone());
    if c == b {
        return Err(std::io::Error::other(format!(
            "cold tier directory {} is the SAME directory as the local blob store {} \
             (they resolve to {}). The two use the identical on-disk layout, so the idle \
             offload sweeper would write each chunk to cold and then delete the very file \
             it just wrote — destroying uploaded ciphertext permanently. Point \
             --cold-tier-fs at a directory OUTSIDE the data dir.",
            cold_dir.display(),
            blobs.display(),
            c.display(),
        )));
    }
    let dd = data_dir
        .canonicalize()
        .unwrap_or_else(|_| data_dir.to_path_buf());
    if c.starts_with(&dd) {
        eprintln!(
            "  WARNING: the fs cold tier ({}) is INSIDE the data dir ({}). A dead-box \
             rebuild clears the data dir and would take every backup bundle with it. \
             Move it outside.",
            c.display(),
            dd.display(),
        );
    }
    Ok(())
}

/// Build the blob store for the configured cold tier. With `ColdTierCfg::Off` this
/// is just the local `FsBlobStore` (today's behavior, no offload). Otherwise it is a
/// write-back [`WriteBackTier`] over that local store + the configured cold tier,
/// and a background idle-offload sweeper task is spawned. Returns the type-erased
/// store either way.
fn build_blobs(cfg: &LauncherConfig, layout: &Layout) -> std::io::Result<Arc<dyn BlobStore>> {
    let local: Arc<dyn BlobStore> = Arc::new(FsBlobStore::new(layout.blobs_dir()));
    let Some(cold) = build_cold(cfg, layout)? else {
        return Ok(local);
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

/// The cold tier + the **concrete** [`WriteBackTier`] the `backup` subcommand needs
/// (`main.rs` / `backup_cli`). The backup engine seals bundle parts straight onto
/// [`cold`](BackupTiers::cold); `WriteBackTier::backup_copy_refs` — an inherent
/// method on the concrete tier, unreachable through the type-erased
/// `Arc<dyn BlobStore>` that [`build_blobs`] hands `AppState` — copies every
/// committed blob onto that same cold tier while keeping the local copy. This is
/// the [`build_blobs`] sweeper pattern (hold the concrete `Arc` alongside the
/// erased one), applied to a one-shot CLI: no sweeper task is spawned, because a
/// subcommand has no long-lived runtime to host it.
pub struct BackupTiers {
    pub cold: Arc<dyn ColdTier>,
    pub tier: Arc<WriteBackTier>,
}

/// Build the [`BackupTiers`] for the backup subcommands, or `None` when no cold
/// tier is configured (`ColdTierCfg::Off`). The caller must **fail closed** on
/// `None` (`BackupError::ColdTierRequired`): a backup you wrongly believe is
/// complete is worse than no backup, and with `Off` there is no cold tier to seal
/// the bundle onto (backup) or to enumerate and unseal it from (restore /
/// list-backups).
pub fn build_backup_tiers(
    cfg: &LauncherConfig,
    layout: &Layout,
) -> std::io::Result<Option<BackupTiers>> {
    let Some(cold) = build_cold(cfg, layout)? else {
        return Ok(None);
    };
    let local: Arc<dyn BlobStore> = Arc::new(FsBlobStore::new(layout.blobs_dir()));
    let tier = Arc::new(WriteBackTier::new(
        local,
        cold.clone(),
        cfg.cache_capacity_bytes,
        Duration::from_secs(cfg.offload_idle_days * 24 * 3600),
    ));
    Ok(Some(BackupTiers { cold, tier }))
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
    /// Completed passes of the background auth-row prune [`prepare`] spawned
    /// (see [`spawn_auth_prune`]). Carried out of `prepare` so the wiring is
    /// testable at all — production ignores it.
    pub auth_prune_passes: Arc<AtomicU64>,
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
    let (app_router, auth_prune_passes) = match cfg.profile {
        Profile::Dev => {
            let auth = Arc::new(
                AuthService::new(MemoryStore::new(), auth_cfg)
                    .with_dir_signer(wiring.dir_signer.clone())
                    .with_delegation(wiring.ctx.clone()),
            );
            let passes = spawn_auth_prune(auth.clone());
            let state = AppState {
                auth,
                blobs,
                audit: Arc::new(NullAuditSink),
                direct_links_enabled: cfg.direct_links_enabled,
                max_file_bytes: None,
            };
            (router(state), passes)
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
            let auth = Arc::new(
                AuthService::new(PgStore::new(pool), auth_cfg)
                    .with_dir_signer(wiring.dir_signer.clone())
                    .with_delegation(wiring.ctx.clone()),
            );
            let passes = spawn_auth_prune(auth.clone());
            let state = AppState {
                auth,
                blobs,
                audit: Arc::new(NullAuditSink),
                direct_links_enabled: cfg.direct_links_enabled,
                max_file_bytes: None,
            };
            (router(state), passes)
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
        auth_prune_passes,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "mxps-cold-{tag}-{}-{}",
            std::process::id(),
            maxsecu_crypto::random_array::<4>()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// THE destructive misconfiguration: an `fs` cold tier pointed at the local blob
    /// store. `WriteBackTier::offload` would put each chunk to cold and then delete
    /// the very file it just wrote. Refuse at construction, before a single byte moves.
    #[test]
    fn an_fs_cold_tier_aliasing_the_blob_store_is_refused() {
        let data_dir = tmp("alias");
        let layout = Layout::ensure(&data_dir).unwrap();
        let err = reject_aliased_fs_cold_tier(&layout.blobs_dir(), &layout, &data_dir)
            .expect_err("aliasing the blob dir must be refused");
        let msg = err.to_string();
        assert!(msg.contains("SAME directory"), "{msg}");
        let _ = std::fs::remove_dir_all(&data_dir);
    }

    /// A separate directory is fine — the ordinary configuration must still build.
    #[test]
    fn a_disjoint_fs_cold_tier_is_accepted() {
        let data_dir = tmp("ok-data");
        let cold = tmp("ok-cold");
        let layout = Layout::ensure(&data_dir).unwrap();
        reject_aliased_fs_cold_tier(&cold, &layout, &data_dir).expect("a disjoint dir is fine");
        let _ = std::fs::remove_dir_all(&data_dir);
        let _ = std::fs::remove_dir_all(&cold);
    }

    /// **The wiring test.** `prepare` must actually start the background auth-row
    /// prune, and starting it must actually make a pass happen.
    ///
    /// This is the one thing the prune's own unit tests could not cover: they all
    /// drive `Store::prune_expired_auth_rows` directly, so deleting
    /// `spawn_auth_prune(auth.clone())` from BOTH profile branches used to leave
    /// the entire suite green — and ship a server whose `sessions` /
    /// `auth_nonces` tables grow forever. Delete either call now and this fails:
    /// the Dev branch stops compiling (nothing binds `passes`), and were it
    /// stubbed out the counter would never leave 0.
    ///
    /// It also pins the two properties of the loop that only exist at runtime:
    /// `tokio::time::interval` fires its FIRST tick immediately (so a box that is
    /// restarted often still prunes), and the pass completes rather than the task
    /// dying somewhere inside it.
    #[tokio::test]
    async fn prepare_spawns_the_background_auth_prune() {
        let data_dir = tmp("prune-wiring");
        let cfg = crate::config::LauncherConfig {
            data_dir: data_dir.clone(),
            port: 0,
            bind: "127.0.0.1".to_owned(),
            public_addr: None,
            profile: crate::config::Profile::Dev,
            database_url: None,
            cold_tier: crate::config::ColdTierCfg::Off,
            cache_capacity_bytes: 200_000_000_000,
            offload_idle_days: 30,
            direct_links_enabled: false,
        };
        let prepared = prepare(&cfg).await.expect("dev prepare");

        // The task is spawned, not awaited, so yield until its first pass lands.
        // Generous ceiling because this asserts "it happens", not "how fast".
        let mut passes = 0;
        for _ in 0..200 {
            passes = prepared.auth_prune_passes.load(Ordering::Relaxed);
            if passes > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            passes > 0,
            "prepare() returned without the background auth prune ever running a \
             pass — sessions/auth_nonces would grow forever"
        );

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    /// Containment is a WARNING, not a refusal: it cannot alias (a `blob_ref` is
    /// 32 hex chars, never `blobs`), and refusing would be a tightening that could
    /// stop an already-deployed server from booting.
    #[test]
    fn an_fs_cold_tier_inside_the_data_dir_is_allowed_with_a_warning() {
        let data_dir = tmp("inside");
        let layout = Layout::ensure(&data_dir).unwrap();
        let cold = data_dir.join("cold");
        reject_aliased_fs_cold_tier(&cold, &layout, &data_dir)
            .expect("inside-the-data-dir must warn, not refuse");
        let _ = std::fs::remove_dir_all(&data_dir);
    }
}
