//! Client-side directory **key-transparency** (KT) verification (DESIGN §7.4) —
//! the CLIENT half of the split-view exit gate.
//!
//! The directory KT log is an RFC 6962 append-only log whose leaves are the
//! canonical `DirBinding` bytes the directory publishes (§7.2). A client accepts
//! a directory binding at first contact only if it is provably *included* in the
//! KT log under a checkpoint signed by a **pinned** log key, and it *gossips* its
//! latest checkpoint forward so a later checkpoint that is NOT a consistent
//! (append-only) extension of the persisted one is rejected as **equivocation**
//! (a split-view).
//!
//! This mirrors [`crate::sink`]'s transparency-log proof verification
//! (`AnchorProof::TransparencyInclusion`) but under a DISTINCT domain-separation
//! label ([`maxsecu_encoding::labels::KT_CHECKPOINT`]) — the directory KT log and
//! the sink-head control-log are separate trust domains, so a checkpoint of one
//! can never be replayed as a checkpoint of the other.
//!
//! It also mirrors [`crate::directory::TrustStore`]'s trust-on-first-use (TOFU)
//! discipline: the first verified checkpoint is pinned; every subsequent one must
//! be a consistency-proven extension of it.

use crate::util::any_key_verifies;
use maxsecu_crypto::merkle;
use maxsecu_encoding::kt_checkpoint_signing_input;

/// A directory KT log **checkpoint**: the log's commitment to its current state
/// (`tree_size` leaves, Merkle `root`) plus the log's Ed25519 signature over the
/// domain-framed `tree_size(8 BE) ‖ root(32)` (see [`checkpoint_signing_bytes`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KtCheckpoint {
    pub tree_size: u64,
    pub root: [u8; 32],
    pub sig: [u8; 64],
}

/// An RFC 6962 **inclusion proof**: that a leaf is the `index`-th of a `tree_size`
/// -leaf tree. `tree_size` must equal the checkpoint's `tree_size` (the proof is
/// against the checkpoint root) — a mismatch fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    pub index: u64,
    pub tree_size: u64,
    pub path: Vec<[u8; 32]>,
}

/// Why a KT verification failed. Every variant is fail-closed (treat the binding
/// as absent / equivocal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KtError {
    /// No pinned log key verifies the checkpoint signature (a forged/foreign
    /// checkpoint, or an empty pin set ⇒ nothing can validate, fail closed).
    BadCheckpoint,
    /// The binding is not provably included under the checkpoint root, or the
    /// inclusion proof's `tree_size` does not match the checkpoint.
    NotIncluded,
    /// A later checkpoint is NOT a consistent (append-only) extension of the
    /// persisted one — equivocation / a fork served to this client.
    SplitView,
    /// A checkpoint with a `tree_size` lower than the persisted one — a rollback.
    Regression,
}

/// Persisted gossip state: the latest KT checkpoint the client has accepted
/// (mirrors [`crate::directory::TrustStore`]). The client owns the durable
/// backing; the core reads the prior checkpoint and writes an accepted one.
pub trait KtCheckpointStore {
    fn latest(&self) -> Option<KtCheckpoint>;
    fn update(&mut self, cp: KtCheckpoint);
}

/// In-memory [`KtCheckpointStore`] for tests/dev (the real client persists this).
#[derive(Debug, Default, Clone)]
pub struct MemoryKtCheckpointStore {
    latest: Option<KtCheckpoint>,
}

impl MemoryKtCheckpointStore {
    pub fn new() -> MemoryKtCheckpointStore {
        MemoryKtCheckpointStore::default()
    }
}

impl KtCheckpointStore for MemoryKtCheckpointStore {
    fn latest(&self) -> Option<KtCheckpoint> {
        self.latest
    }
    fn update(&mut self, cp: KtCheckpoint) {
        self.latest = Some(cp);
    }
}

/// The exact bytes the KT log signs for a checkpoint: the domain-framed,
/// fixed-width `tree_size(8 BE) ‖ root(32)` under
/// [`maxsecu_encoding::labels::KT_CHECKPOINT`]. Delegates to the single source of
/// truth in `maxsecu-encoding` so the log that PRODUCES checkpoints and this
/// verifier construct identical bytes (mirrors [`crate::sink`]).
fn checkpoint_signing_bytes(tree_size: u64, root: &[u8; 32]) -> Vec<u8> {
    kt_checkpoint_signing_input(tree_size, root)
}

/// Accept `binding_bytes` (the canonical `DirBinding` leaf) only if it is provably
/// included in the directory KT log under a checkpoint signed by a pinned log key,
/// and that checkpoint is a consistent (non-equivocating) advance of the gossip
/// state in `store`. Fail-closed at every step (DESIGN §7.4):
///
/// 1. **Checkpoint signature.** Some key in `log_pubs` must verify `checkpoint.sig`
///    over [`checkpoint_signing_bytes`]. Empty `log_pubs` or a forged/foreign sig
///    ⇒ [`KtError::BadCheckpoint`].
/// 2. **Consistency vs. the persisted checkpoint** (`store.latest()`):
///    - `checkpoint.tree_size < prev.tree_size` ⇒ [`KtError::Regression`] (rollback).
///    - `checkpoint.tree_size == prev.tree_size` ⇒ require `root == prev.root`
///      (the same checkpoint) else [`KtError::SplitView`].
///    - otherwise require [`merkle::verify_consistency`] over the supplied
///      `consistency` proof (prev → new) else [`KtError::SplitView`].
///    - **no persisted checkpoint (first use)** ⇒ skip this step (TOFU pin below).
/// 3. **Inclusion.** `inclusion.tree_size == checkpoint.tree_size` AND
///    [`merkle::verify_inclusion`] under `checkpoint.root` else [`KtError::NotIncluded`].
/// 4. On success, advance the gossip state (`store.update`) and return `Ok(())`.
///
/// The consistency proof is an explicit input (`consistency`): the caller obtains
/// it from the log (`prev.tree_size → checkpoint.tree_size`); it is empty when
/// there is no prev or when `tree_size` is unchanged.
/// Verify ONLY a checkpoint's signature under the pinned KT log keys — step (1) of
/// [`verify_binding_in_log`], factored out as a standalone fast guard.
///
/// Returns `true` iff some key in `log_pubs` signs the checkpoint's domain-framed
/// `tree_size ‖ root` ([`checkpoint_signing_bytes`]). An empty `log_pubs` (nothing
/// pinned) ⇒ `false` (fail closed). A caller runs this BEFORE trusting any
/// sink-controlled field of a served checkpoint (notably `tree_size`) to bound
/// further work: a forged checkpoint is rejected without first doing inclusion /
/// consistency fetches whose count an attacker's `tree_size` would otherwise
/// dictate. The authoritative [`verify_binding_in_log`] still runs afterward.
pub fn verify_checkpoint_sig(checkpoint: &KtCheckpoint, log_pubs: &[[u8; 32]]) -> bool {
    any_key_verifies(
        log_pubs,
        &checkpoint_signing_bytes(checkpoint.tree_size, &checkpoint.root),
        &checkpoint.sig,
    )
}

pub fn verify_binding_in_log(
    binding_bytes: &[u8],
    inclusion: &InclusionProof,
    checkpoint: &KtCheckpoint,
    consistency: &[[u8; 32]],
    log_pubs: &[[u8; 32]],
    store: &mut dyn KtCheckpointStore,
) -> Result<(), KtError> {
    // (1) A pinned log key must sign this checkpoint. Empty pin set ⇒ fail closed.
    if !verify_checkpoint_sig(checkpoint, log_pubs) {
        return Err(KtError::BadCheckpoint);
    }

    // (2) Consistency / split-view / rollback against the persisted gossip state.
    if let Some(prev) = store.latest() {
        if checkpoint.tree_size < prev.tree_size {
            return Err(KtError::Regression);
        }
        if checkpoint.tree_size == prev.tree_size {
            if checkpoint.root != prev.root {
                return Err(KtError::SplitView);
            }
        } else if !merkle::verify_consistency(
            prev.tree_size,
            prev.root,
            checkpoint.tree_size,
            checkpoint.root,
            consistency,
        ) {
            return Err(KtError::SplitView);
        }
    }

    // (3) The binding leaf must be included under the checkpoint root, against the
    // checkpoint's own tree size.
    if inclusion.tree_size != checkpoint.tree_size
        || !merkle::verify_inclusion(
            binding_bytes,
            inclusion.index,
            inclusion.tree_size,
            &inclusion.path,
            checkpoint.root,
        )
    {
        return Err(KtError::NotIncluded);
    }

    // (4) Advance the gossip state (TOFU on first use; a proven extension after).
    store.update(*checkpoint);
    Ok(())
}

/// The issuer-side **"the binding is in the KT log" confirm** (DESIGN §7.4,
/// `docs/sink-interface.md` §8) — the directory-KT analogue of
/// [`crate::sink::confirm_anchored`] (the §6 control-log issuer-side *anchoring*
/// confirm). After the D5 enrollment ceremony signs a `DirBinding` and the
/// directory publishes its canonical bytes to the KT log
/// (`POST /v1/dir-log/bindings`), the enrollment is **not done** until the issuer
/// confirms the binding is provably *included* under a checkpoint signed by the
/// pinned KT log key — so a first-contact client (P7.10
/// [`verify_binding_in_log`]) can pass its KT exit gate for the enrolled user.
///
/// This DELEGATES to [`verify_binding_in_log`] (the single verified path — it does
/// NOT re-implement any verification) with an **empty consistency proof**: an
/// issuer confirm is a fresh, one-shot establishment against the *current*
/// checkpoint (run it with a fresh `store`), not long-lived client gossip, so TOFU
/// pins the current checkpoint and the freshly-fetched inclusion must hold under
/// it. Returns `Ok(())` iff the binding is provably logged; every failure is
/// fail-closed ([`KtError`]) and means the enrollment is **not** complete.
///
/// If the issuer instead holds a *prior* persisted checkpoint and wants the
/// consistency-proven advance too, call [`verify_binding_in_log`] directly with
/// the proper `consistency` proof; this helper is the common fresh-confirm case
/// the enrollment runbook invokes.
pub fn confirm_binding_logged(
    binding_bytes: &[u8],
    inclusion: &InclusionProof,
    checkpoint: &KtCheckpoint,
    log_pubs: &[[u8; 32]],
    store: &mut dyn KtCheckpointStore,
) -> Result<(), KtError> {
    verify_binding_in_log(binding_bytes, inclusion, checkpoint, &[], log_pubs, store)
}

/// The first-contact KT gate the caller passes to
/// [`crate::directory::DirectoryVerifier::verify_binding_with_kt`]: the inclusion
/// proof + signed checkpoint + consistency proof + pinned log keys + the persisted
/// gossip store. The directory verifier supplies the leaf bytes itself
/// (`canonical(DirBinding)`) so they cannot be mismatched against the binding.
pub struct KtContext<'a> {
    pub inclusion: &'a InclusionProof,
    pub checkpoint: &'a KtCheckpoint,
    pub consistency: &'a [[u8; 32]],
    pub log_pubs: &'a [[u8; 32]],
    pub store: &'a mut dyn KtCheckpointStore,
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_crypto::SigningKey;

    /// Build a KT log over `leaves`, sign a checkpoint at `tree_size == leaves.len()`
    /// with `log`, and return the checkpoint (the prover side a P7.11 log emits).
    fn checkpoint(log: &SigningKey, leaves: &[Vec<u8>]) -> KtCheckpoint {
        let tree_size = leaves.len() as u64;
        let root = merkle::merkle_root(leaves);
        let sig = log.sign_raw(&checkpoint_signing_bytes(tree_size, &root));
        KtCheckpoint {
            tree_size,
            root,
            sig,
        }
    }

    /// An inclusion proof for the `index`-th leaf of `leaves`.
    fn inclusion(index: usize, leaves: &[Vec<u8>]) -> InclusionProof {
        InclusionProof {
            index: index as u64,
            tree_size: leaves.len() as u64,
            path: merkle::inclusion_path(index, leaves),
        }
    }

    fn leaf(b: u8) -> Vec<u8> {
        vec![b; 48]
    }

    #[test]
    fn binding_with_valid_inclusion_and_consistency_accepts() {
        let log = SigningKey::generate();
        let pin = [log.verifying_key().to_bytes()];
        let mut store = MemoryKtCheckpointStore::new();

        // A small log; pin its first checkpoint (TOFU) by verifying a leaf in it.
        let small: Vec<Vec<u8>> = (0..3).map(leaf).collect();
        let cp1 = checkpoint(&log, &small);
        verify_binding_in_log(
            &small[0],
            &inclusion(0, &small),
            &cp1,
            &[],
            &pin,
            &mut store,
        )
        .expect("first checkpoint pins on first use");
        assert_eq!(store.latest(), Some(cp1));

        // The log grows; a consistent later checkpoint + a valid inclusion accepts.
        let big: Vec<Vec<u8>> = (0..6).map(leaf).collect();
        let cp2 = checkpoint(&log, &big);
        let consistency = merkle::consistency_path(&big, cp1.tree_size, cp2.tree_size);
        verify_binding_in_log(
            &big[4],
            &inclusion(4, &big),
            &cp2,
            &consistency,
            &pin,
            &mut store,
        )
        .expect("consistent extension + valid inclusion accepts");
        assert_eq!(store.latest(), Some(cp2));
    }

    #[test]
    fn split_view_inconsistent_checkpoint_detected() {
        let log = SigningKey::generate();
        let pin = [log.verifying_key().to_bytes()];
        let mut store = MemoryKtCheckpointStore::new();

        // Pin checkpoint over one history.
        let view_a: Vec<Vec<u8>> = (0..3).map(leaf).collect();
        let cp1 = checkpoint(&log, &view_a);
        verify_binding_in_log(
            &view_a[0],
            &inclusion(0, &view_a),
            &cp1,
            &[],
            &pin,
            &mut store,
        )
        .unwrap();

        // A FORK: a different, larger history that does NOT extend view_a. Even with
        // its own valid inclusion + a (forged-from-the-fork) consistency proof, the
        // consistency check against the pinned root fails ⇒ SplitView.
        let fork: Vec<Vec<u8>> = (0..6).map(|i| leaf(0x80 + i)).collect();
        let cp2 = checkpoint(&log, &fork);
        let consistency = merkle::consistency_path(&fork, cp1.tree_size, cp2.tree_size);
        assert_eq!(
            verify_binding_in_log(
                &fork[4],
                &inclusion(4, &fork),
                &cp2,
                &consistency,
                &pin,
                &mut store
            ),
            Err(KtError::SplitView)
        );
        // The gossip state is unchanged (the equivocal checkpoint is not adopted).
        assert_eq!(store.latest(), Some(cp1));
    }

    #[test]
    fn regression_lower_tree_size_rejected() {
        let log = SigningKey::generate();
        let pin = [log.verifying_key().to_bytes()];
        let mut store = MemoryKtCheckpointStore::new();

        let big: Vec<Vec<u8>> = (0..6).map(leaf).collect();
        let cp_big = checkpoint(&log, &big);
        verify_binding_in_log(&big[0], &inclusion(0, &big), &cp_big, &[], &pin, &mut store)
            .unwrap();

        // A validly-signed but SHORTER checkpoint is a rollback.
        let small: Vec<Vec<u8>> = (0..3).map(leaf).collect();
        let cp_small = checkpoint(&log, &small);
        assert_eq!(
            verify_binding_in_log(
                &small[0],
                &inclusion(0, &small),
                &cp_small,
                &[],
                &pin,
                &mut store
            ),
            Err(KtError::Regression)
        );
    }

    #[test]
    fn forged_checkpoint_sig_rejected() {
        let log = SigningKey::generate();
        let attacker = SigningKey::generate();
        let pin = [log.verifying_key().to_bytes()];

        let leaves: Vec<Vec<u8>> = (0..3).map(leaf).collect();
        let tree_size = leaves.len() as u64;
        let root = merkle::merkle_root(&leaves);

        // Signed by a NON-pinned key ⇒ BadCheckpoint.
        let forged = KtCheckpoint {
            tree_size,
            root,
            sig: attacker.sign_raw(&checkpoint_signing_bytes(tree_size, &root)),
        };
        assert_eq!(
            verify_binding_in_log(
                &leaves[0],
                &inclusion(0, &leaves),
                &forged,
                &[],
                &pin,
                &mut MemoryKtCheckpointStore::new(),
            ),
            Err(KtError::BadCheckpoint)
        );

        // EMPTY pin set ⇒ even a genuine checkpoint never validates (fail closed).
        let genuine = checkpoint(&log, &leaves);
        assert_eq!(
            verify_binding_in_log(
                &leaves[0],
                &inclusion(0, &leaves),
                &genuine,
                &[],
                &[],
                &mut MemoryKtCheckpointStore::new(),
            ),
            Err(KtError::BadCheckpoint)
        );
    }

    #[test]
    fn binding_not_in_log_rejected() {
        let log = SigningKey::generate();
        let pin = [log.verifying_key().to_bytes()];
        let leaves: Vec<Vec<u8>> = (0..4).map(leaf).collect();
        let cp = checkpoint(&log, &leaves);

        // A leaf that is not in the log (bad inclusion of an absent value).
        assert_eq!(
            verify_binding_in_log(
                &leaf(0xFF),
                &inclusion(0, &leaves),
                &cp,
                &[],
                &pin,
                &mut MemoryKtCheckpointStore::new(),
            ),
            Err(KtError::NotIncluded)
        );

        // A valid leaf+path but inclusion.tree_size != checkpoint.tree_size.
        let mut bad = inclusion(1, &leaves);
        bad.tree_size = cp.tree_size + 1;
        assert_eq!(
            verify_binding_in_log(
                &leaves[1],
                &bad,
                &cp,
                &[],
                &pin,
                &mut MemoryKtCheckpointStore::new(),
            ),
            Err(KtError::NotIncluded)
        );
    }

    #[test]
    fn confirm_binding_logged_accepts_included_and_rejects_absent() {
        let log = SigningKey::generate();
        let pin = [log.verifying_key().to_bytes()];
        let leaves: Vec<Vec<u8>> = (0..4).map(leaf).collect();
        let cp = checkpoint(&log, &leaves);

        // The issuer-side confirm: a published binding (leaf 2) is provably logged
        // under the pinned-KT checkpoint (fresh store ⇒ TOFU pins it).
        let mut store = MemoryKtCheckpointStore::new();
        confirm_binding_logged(&leaves[2], &inclusion(2, &leaves), &cp, &pin, &mut store)
            .expect("a logged binding is confirmed included");
        assert_eq!(store.latest(), Some(cp));

        // A NOT-published binding fails the confirm (fail closed).
        assert_eq!(
            confirm_binding_logged(
                &leaf(0xFF),
                &inclusion(0, &leaves),
                &cp,
                &pin,
                &mut MemoryKtCheckpointStore::new(),
            ),
            Err(KtError::NotIncluded)
        );

        // An empty KT pin set never validates the checkpoint (fail closed).
        assert_eq!(
            confirm_binding_logged(
                &leaves[2],
                &inclusion(2, &leaves),
                &cp,
                &[],
                &mut MemoryKtCheckpointStore::new(),
            ),
            Err(KtError::BadCheckpoint)
        );
    }

    #[test]
    fn checkpoint_sig_guard_rejects_forged_head_even_with_huge_tree_size() {
        // The standalone guard a caller runs BEFORE bounding any work by the
        // sink-controlled `tree_size`. A checkpoint NOT signed by a pinned key is
        // rejected regardless of how large `tree_size` claims to be — so a forged
        // `tree_size = u64::MAX` cannot drive an unbounded index-discovery scan.
        let log = SigningKey::generate();
        let attacker = SigningKey::generate();
        let pin = [log.verifying_key().to_bytes()];

        let root = [0x11u8; 32];
        let forged = KtCheckpoint {
            tree_size: u64::MAX,
            root,
            sig: attacker.sign_raw(&checkpoint_signing_bytes(u64::MAX, &root)),
        };
        assert!(!verify_checkpoint_sig(&forged, &pin), "forged sig rejected");
        assert!(
            !verify_checkpoint_sig(&forged, &[]),
            "empty pin set fails closed"
        );

        // A genuinely pinned-key checkpoint verifies (even at a huge tree_size).
        let genuine = KtCheckpoint {
            tree_size: u64::MAX,
            root,
            sig: log.sign_raw(&checkpoint_signing_bytes(u64::MAX, &root)),
        };
        assert!(verify_checkpoint_sig(&genuine, &pin));
    }

    #[test]
    fn first_checkpoint_is_trusted_on_first_use() {
        let log = SigningKey::generate();
        let pin = [log.verifying_key().to_bytes()];
        let mut store = MemoryKtCheckpointStore::new();

        // No prev ⇒ the first verified checkpoint is pinned (TOFU).
        let leaves: Vec<Vec<u8>> = (0..3).map(leaf).collect();
        let cp1 = checkpoint(&log, &leaves);
        assert!(store.latest().is_none());
        verify_binding_in_log(
            &leaves[2],
            &inclusion(2, &leaves),
            &cp1,
            &[],
            &pin,
            &mut store,
        )
        .unwrap();
        assert_eq!(store.latest(), Some(cp1));

        // A subsequent inconsistent checkpoint (a fork) is then caught.
        let fork: Vec<Vec<u8>> = (0..5).map(|i| leaf(0x40 + i)).collect();
        let cp2 = checkpoint(&log, &fork);
        let consistency = merkle::consistency_path(&fork, cp1.tree_size, cp2.tree_size);
        assert_eq!(
            verify_binding_in_log(
                &fork[0],
                &inclusion(0, &fork),
                &cp2,
                &consistency,
                &pin,
                &mut store
            ),
            Err(KtError::SplitView)
        );
    }
}
