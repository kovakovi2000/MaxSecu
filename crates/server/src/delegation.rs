//! Offline-D5 directory-delegation runtime state (spec §§3,5,6,9).
//!
//! The internet-facing server no longer holds the directory root (D5). Instead it
//! holds a short-lived **operational key** and an admin-signed **delegation cert**
//! (`maxsecu_crypto::sign_delegation`) that authorizes that operational key to
//! sign enrollment bindings within a validity window. Clients still pin the D5
//! public key; they insert one hop (verify the delegation against the pinned D5,
//! extract `operational_pub`, verify the enrollment binding against that) and
//! **fail closed** if the delegation is missing/tampered/expired.
//!
//! [`DelegationCtx`] is the server-side runtime state behind a small persistence
//! seam ([`DelegationPersist`]) so it is testable with an in-memory no-op impl
//! (tests) while `portable-server` backs it with files. It is held by the
//! [`AuthService`](crate::auth::AuthService) (an `Arc`), threaded into every
//! handler through `AppState`.
//!
//! ## Profiles
//! - **Dev** ([`DelegationCtx::dev`]): enrollment is **always open** (no ceremony,
//!   no admin PC). The dev-D5 key is both the binding signer and the pinned root,
//!   so a self-issued dev delegation makes the client verify-hop uniform across
//!   profiles while `operational_pub == directory_pub` byte-for-byte.
//! - **Prod** ([`DelegationCtx::prod`]): enrollment is **closed** until a
//!   currently-valid delegation is installed (re-checked at request time against
//!   the live clock, so it auto-re-closes after `valid_until`).

use std::sync::{Arc, RwLock};

use maxsecu_crypto::{parse_delegation, sha256, verify_delegation, CryptoError};

/// The longest delegation window the server will accept (spec §6 "sane window").
/// A cert whose `valid_until - valid_from` exceeds this is rejected — the whole
/// point of the operational key is that it is *short-lived* (design §2: 90 days).
pub const MAX_DELEGATION_WINDOW_SECS: u64 = 366 * 86_400;

/// Tolerated forward clock skew for a delegation's `valid_from` (spec §6). A
/// `valid_from` more than this far in the future is rejected. Single source of truth
/// lives in `maxsecu_crypto` — the client signers back-date `valid_from` by the same
/// amount so a server clock behind the signer still accepts the cert.
pub const DELEGATION_CLOCK_SKEW_SECS: u64 = maxsecu_crypto::DELEGATION_CLOCK_SKEW_SECS;

/// The durable side of the delegation state. `portable-server` implements this
/// over files under `<data_dir>/config/`; tests use [`NullDelegationPersist`].
/// Every method is fallible so a persistence fault surfaces as a `500` (never a
/// silent "installed in RAM but not on disk" that a restart would lose).
pub trait DelegationPersist: Send + Sync {
    /// Persist the pinned D5 public key (`config/directory_pub.der`).
    fn persist_directory_pub(&self, dir_pub: &[u8; 32]) -> std::io::Result<()>;
    /// Persist the delegation cert wire bytes (`config/d5_delegation.bin`).
    fn persist_delegation(&self, bytes: &[u8]) -> std::io::Result<()>;
    /// Burn the one-time bootstrap token: delete its plaintext file so the token
    /// can never be reused after a successful bootstrap.
    fn burn_token(&self) -> std::io::Result<()>;
}

/// A no-op persistence sink (Dev + unit tests): nothing is written to disk.
pub struct NullDelegationPersist;

impl DelegationPersist for NullDelegationPersist {
    fn persist_directory_pub(&self, _dir_pub: &[u8; 32]) -> std::io::Result<()> {
        Ok(())
    }
    fn persist_delegation(&self, _bytes: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    fn burn_token(&self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The installed directory-authority material: the pinned D5 public key and the
/// current delegation cert it signed.
#[derive(Clone)]
struct Installed {
    directory_pub: [u8; 32],
    delegation_bytes: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Dev,
    Prod,
}

/// Outcome of a one-time bootstrap install (`POST /v1/bootstrap/delegation`).
#[derive(Debug)]
pub enum BootstrapResult {
    /// Delegation installed, enrollment opened, token burned. Carries `valid_until`.
    Ok { valid_until: u64 },
    /// The server is not awaiting a bootstrap (already delegated / token burned).
    NotAwaiting,
    /// The one-time token was missing or did not match.
    BadToken,
    /// The delegation's Ed25519 signature (or certificate format) did not verify
    /// against the posted D5 key. Surfaced to the operator as `bad_signature`.
    BadSignature,
    /// The delegation authorizes a different `operational_pub` than this server holds
    /// (e.g. the server was reinstalled/reset since the token was issued). Surfaced
    /// as `op_key_mismatch`.
    OpKeyMismatch,
    /// The delegation's validity window is not acceptable for the server's current
    /// clock (out of window — almost always CLOCK SKEW) or violates the sane-window
    /// bounds. Surfaced as `bad_window`.
    BadWindow,
    /// Persisting the new state to disk failed.
    Persist(std::io::Error),
}

/// Outcome of an admin-authenticated renewal (`POST /v1/admin/delegation`).
#[derive(Debug)]
pub enum RenewResult {
    /// Delegation replaced (renewed). Carries the new `valid_until`.
    Ok { valid_until: u64 },
    /// No delegation is installed yet — renewal requires an existing pinned D5.
    NotDelegated,
    /// The replacement's signature/format did not verify against the pinned D5.
    /// Surfaced as `bad_signature`.
    BadSignature,
    /// The replacement authorizes a different `operational_pub` than the current one
    /// (op-key rotation is out of scope). Surfaced as `op_key_mismatch`.
    OpKeyMismatch,
    /// The replacement's window is out of range / insane. Surfaced as `bad_window`.
    BadWindow,
    /// Persisting the replacement failed.
    Persist(std::io::Error),
}

// `std::io::Error` is not `PartialEq`, so the outcome enums implement it by hand:
// two `Persist` outcomes are considered equal (tests never assert on the inner
// error), and every other variant compares by value.
impl PartialEq for BootstrapResult {
    fn eq(&self, other: &Self) -> bool {
        use BootstrapResult::*;
        match (self, other) {
            (Ok { valid_until: a }, Ok { valid_until: b }) => a == b,
            (NotAwaiting, NotAwaiting) => true,
            (BadToken, BadToken) => true,
            (BadSignature, BadSignature) => true,
            (OpKeyMismatch, OpKeyMismatch) => true,
            (BadWindow, BadWindow) => true,
            (Persist(_), Persist(_)) => true,
            _ => false,
        }
    }
}

impl PartialEq for RenewResult {
    fn eq(&self, other: &Self) -> bool {
        use RenewResult::*;
        match (self, other) {
            (Ok { valid_until: a }, Ok { valid_until: b }) => a == b,
            (NotDelegated, NotDelegated) => true,
            (BadSignature, BadSignature) => true,
            (OpKeyMismatch, OpKeyMismatch) => true,
            (BadWindow, BadWindow) => true,
            (Persist(_), Persist(_)) => true,
            _ => false,
        }
    }
}

/// Server-side delegation runtime state (see module docs). Cheap to share via
/// `Arc`; interior mutability guards the installed material and the token hash.
pub struct DelegationCtx {
    mode: Mode,
    /// The public half of the server's operational (binding-signing) key. In Dev
    /// this equals the pinned dev-D5 public key.
    operational_pub: [u8; 32],
    installed: RwLock<Option<Installed>>,
    /// `Some(sha256(token))` while awaiting the one-time bootstrap; `None` once
    /// burned or in Dev.
    bootstrap_token_hash: RwLock<Option<[u8; 32]>>,
    persist: Arc<dyn DelegationPersist>,
}

impl DelegationCtx {
    /// Dev profile: enrollment always open, no ceremony. `directory_pub` is the
    /// dev-D5 pub and `operational_pub` MUST equal it (the dev-D5 signs bindings
    /// AND is the pinned root). `delegation_bytes` is a self-issued dev cert so the
    /// client verify-hop and the `GET /v1/bootstrap/delegation` fetch are uniform
    /// across profiles.
    pub fn dev(directory_pub: [u8; 32], delegation_bytes: Vec<u8>) -> Self {
        DelegationCtx {
            mode: Mode::Dev,
            operational_pub: directory_pub,
            installed: RwLock::new(Some(Installed {
                directory_pub,
                delegation_bytes,
            })),
            bootstrap_token_hash: RwLock::new(None),
            persist: Arc::new(NullDelegationPersist),
        }
    }

    /// Prod profile. `installed` is `Some((directory_pub, delegation_bytes))` when
    /// a delegation was persisted across a restart, else `None` (awaiting).
    /// `bootstrap_token_hash` is `Some(sha256(token))` while awaiting the one-time
    /// ceremony (ignored once `installed` is `Some`).
    pub fn prod(
        operational_pub: [u8; 32],
        installed: Option<([u8; 32], Vec<u8>)>,
        bootstrap_token_hash: Option<[u8; 32]>,
        persist: Arc<dyn DelegationPersist>,
    ) -> Self {
        DelegationCtx {
            mode: Mode::Prod,
            operational_pub,
            installed: RwLock::new(
                installed.map(|(directory_pub, delegation_bytes)| Installed {
                    directory_pub,
                    delegation_bytes,
                }),
            ),
            bootstrap_token_hash: RwLock::new(bootstrap_token_hash),
            persist,
        }
    }

    /// The public half of the operational (binding-signing) key.
    pub fn operational_pub(&self) -> [u8; 32] {
        self.operational_pub
    }

    /// Is registration-key enrollment currently open? Dev: always. Prod: only when
    /// a delegation is installed AND currently valid for `now_secs` (re-checked
    /// every request so it auto-re-closes after `valid_until`).
    pub fn enrollment_open(&self, now_secs: u64) -> bool {
        match self.mode {
            Mode::Dev => true,
            Mode::Prod => match &*self.installed.read().unwrap() {
                Some(i) => {
                    verify_delegation(&i.directory_pub, &i.delegation_bytes, now_secs).is_ok()
                }
                None => false,
            },
        }
    }

    /// The currently-installed `(directory_pub, delegation_bytes)`, if any — served
    /// to clients at `GET /v1/bootstrap/delegation`.
    pub fn current(&self) -> Option<([u8; 32], Vec<u8>)> {
        self.installed
            .read()
            .unwrap()
            .as_ref()
            .map(|i| (i.directory_pub, i.delegation_bytes.clone()))
    }

    /// One-time bootstrap install (`POST /v1/bootstrap/delegation`). Atomically:
    /// checks the token, verifies the cert against the *posted* D5 pub (TOFU),
    /// requires the extracted `operational_pub` to equal our own and a sane window,
    /// then pins the D5 + installs the delegation + burns the token. A verification
    /// failure leaves the server **awaiting** (token NOT burned).
    pub fn install_bootstrap(
        &self,
        token: &str,
        directory_pub: [u8; 32],
        cert: &[u8],
        now_secs: u64,
    ) -> BootstrapResult {
        // Hold the token-hash write lock across the whole operation so two
        // concurrent bootstraps cannot both succeed (single-use).
        let mut hash_guard = self.bootstrap_token_hash.write().unwrap();
        // Already delegated? (defensive: awaiting implies not-yet-installed.)
        if self.installed.read().unwrap().is_some() {
            return BootstrapResult::NotAwaiting;
        }
        let Some(expected) = *hash_guard else {
            return BootstrapResult::NotAwaiting;
        };
        if sha256(token.as_bytes()) != expected {
            return BootstrapResult::BadToken;
        }
        // Verify the cert against the POSTED directory pub (TOFU) and the window. A
        // signature/format failure, an op-key mismatch, and an out-of-window cert map
        // to DISTINCT outcomes (and journalctl lines) so the operator can tell CLOCK
        // SKEW apart from a wrong build or a reinstalled server. These lines are only
        // reachable AFTER the one-time token check above, so they are not an oracle.
        let op_pub = match verify_delegation(&directory_pub, cert, now_secs) {
            Ok(p) => p,
            Err(CryptoError::DelegationExpired) => {
                log_delegation_reject("bootstrap", "bad_window", cert, now_secs);
                return BootstrapResult::BadWindow;
            }
            Err(e) => {
                log_delegation_reject(
                    "bootstrap",
                    &format!("bad_signature ({e:?})"),
                    cert,
                    now_secs,
                );
                return BootstrapResult::BadSignature;
            }
        };
        if op_pub != self.operational_pub {
            log_delegation_reject("bootstrap", "op_key_mismatch", cert, now_secs);
            return BootstrapResult::OpKeyMismatch;
        }
        if !sane_window(cert, now_secs) {
            log_delegation_reject("bootstrap", "bad_window (insane window)", cert, now_secs);
            return BootstrapResult::BadWindow;
        }
        // Persist BEFORE flipping in-RAM state so a disk fault fails closed.
        if let Err(e) = self.persist.persist_directory_pub(&directory_pub) {
            return BootstrapResult::Persist(e);
        }
        if let Err(e) = self.persist.persist_delegation(cert) {
            return BootstrapResult::Persist(e);
        }
        if let Err(e) = self.persist.burn_token() {
            return BootstrapResult::Persist(e);
        }
        let valid_until = parse_delegation(cert)
            .expect("verify_delegation succeeded ⇒ parse succeeds")
            .valid_until();
        *self.installed.write().unwrap() = Some(Installed {
            directory_pub,
            delegation_bytes: cert.to_vec(),
        });
        *hash_guard = None; // burn: token can never be presented again
        BootstrapResult::Ok { valid_until }
    }

    /// Admin renewal (`POST /v1/admin/delegation`): verify a fresh cert against the
    /// ALREADY-pinned D5, require the extracted `operational_pub` to equal the
    /// current one (op-key rotation is out of scope), then replace + persist the
    /// stored delegation. Does NOT change the pinned D5.
    pub fn install_renewal(&self, cert: &[u8], now_secs: u64) -> RenewResult {
        let mut installed = self.installed.write().unwrap();
        let Some(cur) = installed.clone() else {
            return RenewResult::NotDelegated;
        };
        let op_pub = match verify_delegation(&cur.directory_pub, cert, now_secs) {
            Ok(p) => p,
            Err(CryptoError::DelegationExpired) => {
                log_delegation_reject("renewal", "bad_window", cert, now_secs);
                return RenewResult::BadWindow;
            }
            Err(e) => {
                log_delegation_reject("renewal", &format!("bad_signature ({e:?})"), cert, now_secs);
                return RenewResult::BadSignature;
            }
        };
        // Op-key rotation to a NEW operational_pub is out of scope (deferred,
        // design §12) — a delegation for a different op-key is rejected.
        if op_pub != self.operational_pub {
            log_delegation_reject("renewal", "op_key_mismatch", cert, now_secs);
            return RenewResult::OpKeyMismatch;
        }
        if !sane_window(cert, now_secs) {
            log_delegation_reject("renewal", "bad_window (insane window)", cert, now_secs);
            return RenewResult::BadWindow;
        }
        if let Err(e) = self.persist.persist_delegation(cert) {
            return RenewResult::Persist(e);
        }
        let valid_until = parse_delegation(cert)
            .expect("verify_delegation succeeded ⇒ parse succeeds")
            .valid_until();
        // Pinned D5 is UNCHANGED — only the delegation bytes are replaced.
        *installed = Some(Installed {
            directory_pub: cur.directory_pub,
            delegation_bytes: cert.to_vec(),
        });
        RenewResult::Ok { valid_until }
    }
}

/// Emit a non-secret diagnostic line to stderr (→ journalctl under systemd) naming
/// WHICH delegation check failed, so an operator can tell CLOCK SKEW (`bad_window`)
/// apart from a reinstalled server (`op_key_mismatch`) or a wrong build
/// (`bad_signature`). Deliberately logs ONLY non-secret values — the reason, the
/// server clock, and the cert's public window + operational-key prefix. It NEVER
/// receives or logs the one-time bootstrap token or any seed material.
fn log_delegation_reject(phase: &str, reason: &str, cert: &[u8], now_secs: u64) {
    match parse_delegation(cert) {
        Ok(d) => {
            let op = d.operational_pub();
            eprintln!(
                "maxsecu: {phase} delegation rejected [{reason}]: server_now={now_secs} \
                 cert_window=[{},{}] cert_op_pub={:02x}{:02x}{:02x}{:02x}",
                d.valid_from(),
                d.valid_until(),
                op[0],
                op[1],
                op[2],
                op[3]
            );
        }
        Err(e) => eprintln!(
            "maxsecu: {phase} delegation rejected [{reason}]: server_now={now_secs} \
             unparseable_cert={e:?}"
        ),
    }
}

/// The extra "sane window" checks applied on top of `verify_delegation` (spec §6):
/// the window must end in the future, be non-empty, no longer than
/// [`MAX_DELEGATION_WINDOW_SECS`], and not start further than
/// [`DELEGATION_CLOCK_SKEW_SECS`] in the future.
fn sane_window(cert: &[u8], now_secs: u64) -> bool {
    let Ok(d) = parse_delegation(cert) else {
        return false;
    };
    let (vf, vu) = (d.valid_from(), d.valid_until());
    vu > now_secs
        && vu >= vf
        && vu.saturating_sub(vf) <= MAX_DELEGATION_WINDOW_SECS
        && vf <= now_secs.saturating_add(DELEGATION_CLOCK_SKEW_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_crypto::{sign_delegation, SigningKey};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const DAY: u64 = 86_400;

    fn d5() -> SigningKey {
        SigningKey::from_seed(&[1u8; 32])
    }
    fn op() -> SigningKey {
        SigningKey::from_seed(&[7u8; 32])
    }

    /// A recording persistence impl so tests can assert the disk side fired.
    #[derive(Default)]
    struct RecPersist {
        dir: AtomicUsize,
        del: AtomicUsize,
        burn: AtomicUsize,
    }
    impl DelegationPersist for Arc<RecPersist> {
        fn persist_directory_pub(&self, _d: &[u8; 32]) -> std::io::Result<()> {
            self.dir.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn persist_delegation(&self, _b: &[u8]) -> std::io::Result<()> {
            self.del.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn burn_token(&self) -> std::io::Result<()> {
            self.burn.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn dev_ctx_is_always_open_regardless_of_clock() {
        let d5 = d5();
        let d5_pub = d5.verifying_key().to_bytes();
        // self-issued dev delegation (dev-D5 → dev-D5), far window.
        let cert = sign_delegation(&d5, &d5_pub, 0, 4_102_444_800);
        let ctx = DelegationCtx::dev(d5_pub, cert);
        assert!(ctx.enrollment_open(0));
        assert!(ctx.enrollment_open(9_999_999_999));
        assert_eq!(ctx.operational_pub(), d5_pub);
        assert!(ctx.current().is_some());
    }

    #[test]
    fn prod_awaiting_is_closed_and_opens_on_valid_bootstrap() {
        let d5 = d5();
        let d5_pub = d5.verifying_key().to_bytes();
        let op = op();
        let op_pub = op.verifying_key().to_bytes();
        let now = 1_700_000_000u64;
        let cert = sign_delegation(&op /*wrong signer!*/, &op_pub, now, now + 90 * DAY);
        // Build awaiting ctx with a known token.
        let rec = Arc::new(RecPersist::default());
        let ctx = DelegationCtx::prod(
            op_pub,
            None,
            Some(sha256(b"tok-123")),
            Arc::new(rec.clone()),
        );
        assert!(!ctx.enrollment_open(now), "awaiting ⇒ closed");

        // Wrong signer (op signed instead of d5) ⇒ BadSignature, still awaiting.
        assert_eq!(
            ctx.install_bootstrap("tok-123", d5_pub, &cert, now),
            BootstrapResult::BadSignature
        );
        assert!(!ctx.enrollment_open(now));

        // A correctly D5-signed cert opens enrollment and burns the token.
        let good = sign_delegation(&d5, &op_pub, now, now + 90 * DAY);
        assert_eq!(
            ctx.install_bootstrap("tok-123", d5_pub, &good, now),
            BootstrapResult::Ok {
                valid_until: now + 90 * DAY
            }
        );
        assert!(ctx.enrollment_open(now));
        assert_eq!(rec.dir.load(Ordering::SeqCst), 1);
        assert_eq!(rec.del.load(Ordering::SeqCst), 1);
        assert_eq!(rec.burn.load(Ordering::SeqCst), 1);

        // Second attempt ⇒ NotAwaiting (token burned / already delegated).
        assert_eq!(
            ctx.install_bootstrap("tok-123", d5_pub, &good, now),
            BootstrapResult::NotAwaiting
        );
    }

    #[test]
    fn bootstrap_rejects_bad_token_and_wrong_op_pub_and_stays_awaiting() {
        let d5 = d5();
        let d5_pub = d5.verifying_key().to_bytes();
        let op_pub = op().verifying_key().to_bytes();
        let now = 1_700_000_000u64;
        let ctx = DelegationCtx::prod(
            op_pub,
            None,
            Some(sha256(b"secret")),
            Arc::new(NullDelegationPersist),
        );
        // Wrong token.
        let good = sign_delegation(&d5, &op_pub, now, now + DAY);
        assert_eq!(
            ctx.install_bootstrap("WRONG", d5_pub, &good, now),
            BootstrapResult::BadToken
        );
        assert!(!ctx.enrollment_open(now));
        // Right token, but cert authorizes a DIFFERENT op-key ⇒ OpKeyMismatch.
        let other_op = SigningKey::from_seed(&[9u8; 32]).verifying_key().to_bytes();
        let wrong = sign_delegation(&d5, &other_op, now, now + DAY);
        assert_eq!(
            ctx.install_bootstrap("secret", d5_pub, &wrong, now),
            BootstrapResult::OpKeyMismatch
        );
        assert!(!ctx.enrollment_open(now));
        // Token still usable afterwards (not burned by a failed attempt).
        assert!(matches!(
            ctx.install_bootstrap("secret", d5_pub, &good, now),
            BootstrapResult::Ok { .. }
        ));
    }

    #[test]
    fn bootstrap_rejects_insane_window() {
        let d5 = d5();
        let d5_pub = d5.verifying_key().to_bytes();
        let op_pub = op().verifying_key().to_bytes();
        let now = 1_700_000_000u64;
        let ctx = DelegationCtx::prod(
            op_pub,
            None,
            Some(sha256(b"t")),
            Arc::new(NullDelegationPersist),
        );
        // Window longer than the cap (2 years) ⇒ BadWindow even though it verifies.
        let toolong = sign_delegation(&d5, &op_pub, now, now + 2 * 366 * DAY);
        assert_eq!(
            ctx.install_bootstrap("t", d5_pub, &toolong, now),
            BootstrapResult::BadWindow
        );
    }

    #[test]
    fn bootstrap_distinguishes_out_of_window_from_signature_and_op_key() {
        let d5 = d5();
        let d5_pub = d5.verifying_key().to_bytes();
        let op_pub = op().verifying_key().to_bytes();
        let now = 1_700_000_000u64;
        let fresh_ctx = || {
            DelegationCtx::prod(
                op_pub,
                None,
                Some(sha256(b"tk")),
                Arc::new(NullDelegationPersist),
            )
        };

        // The ACTUAL field bug: a validly-D5-signed cert whose window has not opened
        // yet at the server clock (valid_from in the server's future — exactly what a
        // server clock BEHIND the signer sees) ⇒ BadWindow, NOT BadSignature.
        let not_yet = sign_delegation(&d5, &op_pub, now + 100, now + 90 * DAY);
        assert_eq!(
            fresh_ctx().install_bootstrap("tk", d5_pub, &not_yet, now),
            BootstrapResult::BadWindow,
            "valid signature + future valid_from must be BadWindow (the clock-skew case)"
        );

        // A BACK-DATED cert (valid_from before the server clock, as the fixed client
        // now signs) with the right op-key and a sane window ⇒ Ok.
        let back_dated = sign_delegation(&d5, &op_pub, now - 50, now + 90 * DAY);
        assert_eq!(
            fresh_ctx().install_bootstrap("tk", d5_pub, &back_dated, now),
            BootstrapResult::Ok {
                valid_until: now + 90 * DAY
            },
            "a back-dated, correctly-signed cert installs"
        );
    }

    #[test]
    fn enrollment_recloses_after_valid_until() {
        let d5 = d5();
        let d5_pub = d5.verifying_key().to_bytes();
        let op_pub = op().verifying_key().to_bytes();
        let now = 1_700_000_000u64;
        let vu = now + 30 * DAY;
        let ctx = DelegationCtx::prod(
            op_pub,
            Some((d5_pub, sign_delegation(&d5, &op_pub, now, vu))),
            None,
            Arc::new(NullDelegationPersist),
        );
        assert!(ctx.enrollment_open(now));
        assert!(ctx.enrollment_open(vu)); // inclusive
        assert!(!ctx.enrollment_open(vu + 1), "closes after valid_until");
    }

    #[test]
    fn renewal_replaces_window_but_not_pinned_d5_and_rejects_op_rotation() {
        let d5 = d5();
        let d5_pub = d5.verifying_key().to_bytes();
        let op = op();
        let op_pub = op.verifying_key().to_bytes();
        let now = 1_700_000_000u64;
        let vu1 = now + 10 * DAY;
        let ctx = DelegationCtx::prod(
            op_pub,
            Some((d5_pub, sign_delegation(&d5, &op_pub, now, vu1))),
            None,
            Arc::new(NullDelegationPersist),
        );
        // Renew with a fresh 90-day window for the SAME op-key.
        let vu2 = now + 90 * DAY;
        assert_eq!(
            ctx.install_renewal(&sign_delegation(&d5, &op_pub, now, vu2), now),
            RenewResult::Ok { valid_until: vu2 }
        );
        assert!(ctx.enrollment_open(vu1 + 1), "renewal extended the window");
        // Pinned D5 unchanged.
        assert_eq!(ctx.current().unwrap().0, d5_pub);

        // A delegation for a DIFFERENT op-key is rejected (rotation out of scope).
        let other_op = SigningKey::from_seed(&[3u8; 32]).verifying_key().to_bytes();
        assert_eq!(
            ctx.install_renewal(&sign_delegation(&d5, &other_op, now, vu2), now),
            RenewResult::OpKeyMismatch
        );

        // A renewal signed by a NON-pinned key is rejected (must chain to pinned D5).
        let evil = SigningKey::from_seed(&[42u8; 32]);
        assert_eq!(
            ctx.install_renewal(&sign_delegation(&evil, &op_pub, now, vu2), now),
            RenewResult::BadSignature
        );

        // A renewal with an over-cap (insane) window ⇒ BadWindow (exercises the
        // renewal side of the split, mirroring the bootstrap path).
        assert_eq!(
            ctx.install_renewal(
                &sign_delegation(&d5, &op_pub, now, now + 2 * 366 * DAY),
                now
            ),
            RenewResult::BadWindow
        );
    }

    #[test]
    fn renewal_on_awaiting_is_rejected() {
        let op_pub = op().verifying_key().to_bytes();
        let now = 1_700_000_000u64;
        let ctx = DelegationCtx::prod(
            op_pub,
            None,
            Some(sha256(b"t")),
            Arc::new(NullDelegationPersist),
        );
        let d5 = d5();
        assert_eq!(
            ctx.install_renewal(&sign_delegation(&d5, &op_pub, now, now + DAY), now),
            RenewResult::NotDelegated
        );
    }
}
