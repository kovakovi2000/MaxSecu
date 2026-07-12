//! Wiring for the offline-D5 delegation model on the portable launcher (spec
//! §§5,6,8). Builds the server-crate [`DelegationCtx`] for each profile and backs
//! its persistence seam with files under `<data_dir>/config/`.
//!
//! - **Dev** ([`build_dev`]): the dev-D5 key is BOTH the binding signer and the
//!   pinned root, and a self-issued dev delegation makes the client verify-hop
//!   uniform. Enrollment is always open (no ceremony) — SECURITY-DEGRADED, dev
//!   only, exactly as before this change.
//! - **Prod** ([`build_prod`]): a short-lived **operational** key (persisted at
//!   `config/operational_secret.bin`) signs bindings; the admin-held D5 root signs
//!   a delegation authorizing it. While no valid delegation is installed the server
//!   is **awaiting** (enrollment closed) and prints a one-time bootstrap token.

use std::sync::Arc;

use maxsecu_crypto::SigningKey;
use maxsecu_server::{DelegationCtx, DelegationPersist, NullDelegationPersist};

use crate::bootstrap;
use crate::layout::Layout;

/// Year-2100 in unix seconds — the (effectively unbounded) window for the Dev
/// self-issued delegation, so Dev enrollment never window-closes.
const YEAR_2100_SECS: u64 = 4_102_444_800;

/// File-backed persistence for the Prod delegation state. Writes land in
/// `<data_dir>/config/` next to the TLS material.
struct FileDelegationPersist {
    layout: Layout,
}

impl DelegationPersist for FileDelegationPersist {
    fn persist_directory_pub(&self, dir_pub: &[u8; 32]) -> std::io::Result<()> {
        write_atomic(&self.layout.d5_pub_path(), dir_pub)
    }
    fn persist_delegation(&self, bytes: &[u8]) -> std::io::Result<()> {
        write_atomic(&self.layout.d5_delegation_path(), bytes)
    }
    fn burn_token(&self) -> std::io::Result<()> {
        match std::fs::remove_file(self.layout.bootstrap_token_path()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// What [`build_prod`] / [`build_dev`] produce: the binding-signing key (for
/// `AuthService::with_dir_signer`), the delegation ctx (for
/// `AuthService::with_delegation`), and the pinned directory public key if one is
/// known at startup (`None` in Prod while awaiting).
pub struct DelegationWiring {
    pub dir_signer: Arc<SigningKey>,
    pub ctx: Arc<DelegationCtx>,
    /// The pinned D5 public key, if known at startup. Dev: always the dev-D5 pub.
    /// Prod: `Some` iff a delegation was persisted across a restart, else `None`.
    pub directory_pub: Option<[u8; 32]>,
}

/// Ensure the operational (binding-signing) key: load `operational_secret.bin`, or
/// generate + persist a fresh 32-byte seed on first Prod run (spec §5). The seed
/// MAY live on the server — it is the delegated key, not the offline root.
fn ensure_operational_key(layout: &Layout) -> std::io::Result<SigningKey> {
    let seed: [u8; 32] = match std::fs::read(layout.operational_secret_path()) {
        Ok(b) if b.len() == 32 => b.try_into().unwrap(),
        Ok(_) => return Err(std::io::Error::other("operational seed malformed")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let s: [u8; 32] = maxsecu_crypto::random_array();
            // Atomic write: a kill/power-loss mid-write can never leave a TRUNCATED
            // seed (which is a hard error) that would brick the server into a systemd
            // crash loop — the file is always either absent or the full 32 bytes.
            write_atomic(&layout.operational_secret_path(), &s)?;
            s
        }
        Err(e) => return Err(e),
    };
    Ok(SigningKey::from_seed(&seed))
}

/// Write `bytes` to `path` atomically: write a sibling temp file, fsync its data, then
/// rename it over the target. Because the target is only ever swapped by an atomic
/// rename (never written in place), a process kill / systemd restart mid-write can
/// never leave the target truncated — every reader sees either the old bytes or the
/// complete new bytes. The `sync_all` flushes the temp's data before the rename commits
/// so the swap does not expose a zero-length file. (We do not fsync the directory, so a
/// hard power-loss on a filesystem that reorders the rename ahead of the data could in
/// principle lose the *rename*, reverting to the old bytes — but never a truncated
/// target.) Used for the operational seed (a truncated seed is fatal by design) and the
/// persisted delegation/pin (a truncated one would silently revert to awaiting).
fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// Load a persisted `(directory_pub, delegation_bytes)` if BOTH files are present
/// and well-formed (32-byte pub + 113-byte cert); otherwise `None` (awaiting). The
/// cert's cryptographic validity is (re)checked at request time by
/// `DelegationCtx::enrollment_open`, not here — a persisted-but-expired delegation
/// loads fine and simply keeps enrollment closed until renewed.
fn load_installed(layout: &Layout) -> Option<([u8; 32], Vec<u8>)> {
    let dir = std::fs::read(layout.d5_pub_path()).ok()?;
    let cert = std::fs::read(layout.d5_delegation_path()).ok()?;
    if dir.len() != 32 || cert.len() != maxsecu_crypto::DELEGATION_WIRE_LEN {
        return None;
    }
    let mut dir_pub = [0u8; 32];
    dir_pub.copy_from_slice(&dir);
    Some((dir_pub, cert))
}

/// Ensure the one-time bootstrap token file exists; return its `sha256`. Reuses an
/// existing token (so a restart while awaiting keeps the same token the operator
/// already has), else generates a fresh 32-byte random hex token and writes it.
fn ensure_bootstrap_token(layout: &Layout) -> std::io::Result<[u8; 32]> {
    let token = match std::fs::read_to_string(layout.bootstrap_token_path()) {
        Ok(s) if !s.trim().is_empty() => s.trim().to_owned(),
        _ => {
            let raw: [u8; 32] = maxsecu_crypto::random_array();
            let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            std::fs::write(layout.bootstrap_token_path(), &hex)?;
            hex
        }
    };
    Ok(maxsecu_crypto::sha256(token.as_bytes()))
}

/// Dev profile wiring: dev-D5 is the binding signer AND the pinned root; a
/// self-issued dev delegation (dev-D5 → dev-D5) keeps the verify-hop uniform.
/// Enrollment is always open.
pub fn build_dev(layout: &Layout) -> std::io::Result<DelegationWiring> {
    let dev_pub = bootstrap::ensure_dev_d5(layout)?;
    let signer = SigningKey::from_seed(&bootstrap::dev_d5_seed(layout)?);
    let cert = maxsecu_crypto::sign_delegation(&signer, &dev_pub, 0, YEAR_2100_SECS);
    Ok(DelegationWiring {
        dir_signer: Arc::new(signer),
        ctx: Arc::new(DelegationCtx::dev(dev_pub, cert)),
        directory_pub: Some(dev_pub),
    })
}

/// Prod profile wiring: generate/load the operational key; load any persisted
/// delegation; while awaiting, ensure a one-time bootstrap token exists. Does NOT
/// generate a D5 (the root is admin-supplied via the ceremony, spec §4/§5).
pub fn build_prod(layout: &Layout) -> std::io::Result<DelegationWiring> {
    let op = ensure_operational_key(layout)?;
    let op_pub = op.verifying_key().to_bytes();
    let installed = load_installed(layout);
    let token_hash = if installed.is_none() {
        Some(ensure_bootstrap_token(layout)?)
    } else {
        // Already delegated: make sure no stale token file lingers.
        let _ = std::fs::remove_file(layout.bootstrap_token_path());
        None
    };
    let pinned_dir = installed.as_ref().map(|(d, _)| *d);
    let ctx = DelegationCtx::prod(
        op_pub,
        installed,
        token_hash,
        Arc::new(FileDelegationPersist {
            layout: layout.clone(),
        }),
    );
    Ok(DelegationWiring {
        dir_signer: Arc::new(op),
        ctx: Arc::new(ctx),
        directory_pub: pinned_dir,
    })
}

/// A no-op persistence handle — exported for symmetry / potential test use.
pub fn null_persist() -> Arc<dyn DelegationPersist> {
    Arc::new(NullDelegationPersist)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "mxps-deleg-{}-{}",
            std::process::id(),
            maxsecu_crypto::random_array::<4>()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn dev_wiring_is_open_and_self_consistent() {
        let dir = tmp();
        let layout = Layout::ensure(&dir).unwrap();
        let w = build_dev(&layout).unwrap();
        // operational == pinned == dev-D5 pub (byte-identical, invariant 2/10).
        assert_eq!(w.ctx.operational_pub(), w.directory_pub.unwrap());
        assert_eq!(
            w.dir_signer.verifying_key().to_bytes(),
            w.directory_pub.unwrap()
        );
        // Always open, regardless of clock.
        assert!(w.ctx.enrollment_open(0));
        assert!(w.ctx.enrollment_open(9_999_999_999));
        // The self-issued delegation is served.
        assert!(w.ctx.current().is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prod_awaiting_persists_op_key_and_token_then_bootstraps() {
        let dir = tmp();
        let layout = Layout::ensure(&dir).unwrap();
        let w = build_prod(&layout).unwrap();
        // Operational key persisted; awaiting ⇒ closed; NO dev-D5 generated.
        assert!(layout.operational_secret_path().is_file());
        assert!(
            !layout.d5_secret_path().exists(),
            "Prod must NOT generate a D5"
        );
        assert!(layout.bootstrap_token_path().is_file());
        assert!(w.directory_pub.is_none());
        assert!(!w.ctx.enrollment_open(1_700_000_000));

        // The operational key is STABLE across restarts (same seed).
        let op_pub = w.ctx.operational_pub();
        let w2 = build_prod(&layout).unwrap();
        assert_eq!(w2.ctx.operational_pub(), op_pub);

        // Read the printed token, perform the bootstrap ceremony against w2.ctx.
        let token = std::fs::read_to_string(layout.bootstrap_token_path()).unwrap();
        let d5 = SigningKey::from_seed(&[1u8; 32]);
        let d5_pub = d5.verifying_key().to_bytes();
        let now = 1_700_000_000u64;
        let cert = maxsecu_crypto::sign_delegation(&d5, &op_pub, now, now + 90 * 86_400);
        let out = w2.ctx.install_bootstrap(token.trim(), d5_pub, &cert, now);
        assert!(
            matches!(out, maxsecu_server::BootstrapResult::Ok { .. }),
            "valid bootstrap opens enrollment: {out:?}"
        );
        assert!(w2.ctx.enrollment_open(now));
        // Persisted to disk: directory_pub.der + d5_delegation.bin written, token burned.
        assert_eq!(
            std::fs::read(layout.d5_pub_path()).unwrap(),
            d5_pub.to_vec()
        );
        assert_eq!(std::fs::read(layout.d5_delegation_path()).unwrap(), cert);
        assert!(!layout.bootstrap_token_path().exists(), "token burned");

        // A FRESH build after delegation loads it (delegated across restart), no token.
        let w3 = build_prod(&layout).unwrap();
        assert_eq!(w3.directory_pub, Some(d5_pub));
        assert!(w3.ctx.enrollment_open(now));
        // REGRESSION (part 4): a restart must NOT rotate the operational key out from
        // under the installed delegation — the loaded op-key still equals the one the
        // persisted delegation authorizes, so the delegation stays valid across restarts.
        assert_eq!(
            w3.ctx.operational_pub(),
            op_pub,
            "restart kept the op-key that the installed delegation authorizes"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_atomic_round_trips_and_leaves_no_temp_file() {
        let dir = tmp();
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("operational_secret.bin");
        write_atomic(&path, &[9u8; 32]).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), vec![9u8; 32]);
        // Overwrite in place still works and never leaves the sibling temp behind.
        write_atomic(&path, &[7u8; 32]).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), vec![7u8; 32]);
        assert!(
            !path.with_extension("tmp").exists(),
            "the temp file must be renamed away, never left behind"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_operational_seed_is_fatal_and_never_silently_regenerated() {
        // A wrong-length (truncated) operational seed MUST be a hard error — never
        // regenerated. Regenerating would silently rotate the op-key and invalidate an
        // already-installed delegation (the delegation would authorize the OLD key),
        // locking out every client. The atomic write exists to prevent such truncation;
        // this locks in the fail-closed behaviour it protects.
        let dir = tmp();
        let layout = Layout::ensure(&dir).unwrap();
        std::fs::write(layout.operational_secret_path(), [1u8; 5]).unwrap();
        // `DelegationWiring` isn't `Debug`, so match rather than `expect_err`.
        let err = match build_prod(&layout) {
            Err(e) => e,
            Ok(_) => panic!("a malformed seed must be fatal"),
        };
        assert!(
            err.to_string().contains("malformed"),
            "expected a 'malformed' error, got: {err}"
        );
        // The bad file is left UNTOUCHED — not silently rotated to a fresh 32-byte key.
        assert_eq!(
            std::fs::read(layout.operational_secret_path()).unwrap(),
            vec![1u8; 5],
            "a malformed seed must not be overwritten/regenerated"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
