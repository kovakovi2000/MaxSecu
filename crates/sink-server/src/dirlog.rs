//! In-repo **directory key-transparency (KT) log** producer (DESIGN §7.4,
//! `docs/sink-interface.md` §8) — the SERVER half of the split-view exit gate.
//!
//! An RFC 6962 append-only Merkle log whose leaves are the canonical `DirBinding`
//! bytes the directory publishes (§7.2). It serves a log-signed checkpoint
//! `{tree_size, root}`, per-leaf inclusion proofs, and prev→current consistency
//! proofs — all in the EXACT shapes the P7.10 client verifier
//! (`client-core::transparency::verify_binding_in_log`) accepts, so a client can
//! prove a binding is included under a pinned KT key and catch a forked/equivocal
//! checkpoint as `KtError::SplitView`.
//!
//! This is the directory-KT counterpart to [`crate::anchor::Anchorer`] (the
//! sink-head control-log's transparency anchor): a SEPARATE Merkle tree and a
//! SEPARATE Ed25519 log key, but served by the SAME `sink-server` process over
//! the same TLS listener. The checkpoint signing bytes come from the single
//! source of truth in `maxsecu-encoding` (under the DISTINCT
//! [`maxsecu_encoding::labels::KT_CHECKPOINT`] label), so a sink-head checkpoint
//! can never be replayed as a KT checkpoint and prover/verifier agree byte-for-byte.
//!
//! **Append-only-grow:** leaves only ever grow; appending the same binding bytes
//! twice records two leaves (each gets its own index) — exactly how a real CT log
//! behaves; the directory dedups upstream. The in-repo log generates a fresh log
//! key per process; the real deployment PINS a long-lived KT key (and gossips its
//! checkpoints to an independent witness/notary — the ops swap-in).

use maxsecu_crypto::merkle::{consistency_path, inclusion_path, merkle_root};
use maxsecu_crypto::SigningKey;
use maxsecu_encoding::kt_checkpoint_signing_input;

/// A directory KT log **checkpoint** in wire/serialization form — mirrors the
/// client's `transparency::KtCheckpoint`: the log's commitment to its current
/// state (`tree_size` leaves, Merkle `root`) plus the log's Ed25519 signature
/// over [`kt_checkpoint_signing_input`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KtCheckpointOut {
    pub tree_size: u64,
    pub root: [u8; 32],
    pub sig: [u8; 64],
}

/// An RFC 6962 **inclusion proof** in wire form — mirrors the client's
/// `transparency::InclusionProof`. `tree_size` equals the checkpoint's
/// `tree_size` (the proof is against the checkpoint root).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionOut {
    pub index: u64,
    pub tree_size: u64,
    pub path: Vec<[u8; 32]>,
}

/// An append-only directory key-transparency log: the log's Ed25519 signing key
/// plus the growing vector of canonical `DirBinding` leaf bytes. The Merkle tree
/// and signing key are SEPARATE from the sink-head control-log's
/// [`crate::anchor::Anchorer`].
pub struct DirLog {
    /// The KT log's Ed25519 key — its public half is PINNED by clients.
    log_key: SigningKey,
    /// The canonical `DirBinding` leaf bytes, in append order.
    leaves: Vec<Vec<u8>>,
}

impl DirLog {
    /// A fresh, empty directory KT log signed by `log_key`.
    pub fn new(log_key: SigningKey) -> Self {
        DirLog {
            log_key,
            leaves: Vec::new(),
        }
    }

    /// Append `binding_bytes` (canonical `DirBinding` leaf) and return its new
    /// leaf index. Append-only-grow: duplicates are allowed and each gets a fresh
    /// index (a real CT log records every append; the directory dedups upstream).
    pub fn append(&mut self, binding_bytes: Vec<u8>) -> u64 {
        let index = self.leaves.len() as u64;
        self.leaves.push(binding_bytes);
        index
    }

    /// The current number of leaves (the checkpoint `tree_size`).
    pub fn tree_size(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// The current log-signed checkpoint over `tree_size ‖ root` under the KT
    /// checkpoint label — exactly what `verify_binding_in_log` checks.
    pub fn checkpoint(&self) -> KtCheckpointOut {
        let tree_size = self.leaves.len() as u64;
        let root = merkle_root(&self.leaves);
        let sig = self
            .log_key
            .sign_raw(&kt_checkpoint_signing_input(tree_size, &root));
        KtCheckpointOut {
            tree_size,
            root,
            sig,
        }
    }

    /// An inclusion proof for the `index`-th leaf against the current tree, or
    /// `None` when `index` is out of range (≥ current `tree_size`).
    pub fn inclusion(&self, index: u64) -> Option<InclusionOut> {
        if index >= self.leaves.len() as u64 {
            return None;
        }
        Some(InclusionOut {
            index,
            tree_size: self.leaves.len() as u64,
            path: inclusion_path(index as usize, &self.leaves),
        })
    }

    /// A consistency proof `from_size → current` (RFC 6962 §2.1.3). Empty when
    /// `from_size` is 0, equals the current size, or exceeds it (the route guards
    /// `from > size`); a caller holding a persisted size-`from_size` checkpoint
    /// drives `merkle::verify_consistency` with this against the current root.
    pub fn consistency(&self, from_size: u64) -> Vec<[u8; 32]> {
        consistency_path(&self.leaves, from_size, self.leaves.len() as u64)
    }

    /// The pinned KT log public key — clients pin this in their KT log allowlist.
    pub fn log_public(&self) -> [u8; 32] {
        self.log_key.verifying_key().to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_crypto::merkle::{verify_consistency, verify_inclusion};
    use maxsecu_crypto::VerifyingKey;

    fn leaf(b: u8) -> Vec<u8> {
        vec![b; 48]
    }

    /// Append several leaves and prove `checkpoint()`/`inclusion(i)`/
    /// `consistency(m)` are mutually self-consistent under the log's own key.
    #[test]
    fn append_emits_checkpoint_inclusion_consistency() {
        let mut log = DirLog::new(SigningKey::generate());
        let vk = VerifyingKey::from_bytes(&log.log_public()).unwrap();

        // Append three leaves; indices are sequential and append-only.
        assert_eq!(log.append(leaf(0)), 0);
        assert_eq!(log.append(leaf(1)), 1);
        assert_eq!(log.append(leaf(2)), 2);

        // The checkpoint signature verifies under the pinned KT key.
        let cp = log.checkpoint();
        assert_eq!(cp.tree_size, 3);
        assert!(vk
            .verify_raw(
                &kt_checkpoint_signing_input(cp.tree_size, &cp.root),
                &cp.sig
            )
            .is_ok());

        // Every leaf's inclusion proof verifies under the checkpoint root.
        for i in 0..3u64 {
            let inc = log.inclusion(i).expect("index in range");
            assert_eq!(inc.tree_size, cp.tree_size);
            assert!(verify_inclusion(
                &leaf(i as u8),
                inc.index,
                inc.tree_size,
                &inc.path,
                cp.root
            ));
        }
        // Out-of-range index yields None.
        assert!(log.inclusion(3).is_none());

        // Grow the log; a consistency proof prev→current verifies against the
        // earlier and current roots.
        let cp_prev = log.checkpoint();
        log.append(leaf(3));
        log.append(leaf(4));
        let cp_now = log.checkpoint();
        let proof = log.consistency(cp_prev.tree_size);
        assert!(verify_consistency(
            cp_prev.tree_size,
            cp_prev.root,
            cp_now.tree_size,
            cp_now.root,
            &proof,
        ));
        // Duplicate append is allowed and grows the tree (append-only-grow).
        let before = log.tree_size();
        let dup = log.append(leaf(0));
        assert_eq!(dup, before);
        assert_eq!(log.tree_size(), before + 1);
    }

    // ---- Cross-crate acceptance: the produced shapes drive the REAL P7.10
    // client verifier (`client_core::transparency::verify_binding_in_log`). ----

    use maxsecu_client_core::transparency::{
        verify_binding_in_log, InclusionProof, KtCheckpoint, KtCheckpointStore, KtError,
        MemoryKtCheckpointStore,
    };
    use maxsecu_encoding::structs::DirBinding;
    use maxsecu_encoding::types::{Bytes32, Id, Role, RoleSet, Text, Timestamp};

    /// A canonical `DirBinding` leaf for user `uid`.
    fn binding_bytes(uid: u8) -> Vec<u8> {
        let b = DirBinding {
            username: Text::new("alice").unwrap(),
            user_id: Id([uid; 16]),
            enc_pub: Bytes32([uid; 32]),
            sig_pub: Bytes32([uid ^ 0xFF; 32]),
            key_version: 1,
            roles: RoleSet::new([Role::User]),
            not_before: Timestamp(1_000),
            not_after: Timestamp(9_000_000_000_000),
            mlkem_pub: None,
        };
        maxsecu_encoding::encode(&b)
    }

    fn to_client_cp(cp: &KtCheckpointOut) -> KtCheckpoint {
        KtCheckpoint {
            tree_size: cp.tree_size,
            root: cp.root,
            sig: cp.sig,
        }
    }

    fn to_client_inc(inc: &InclusionOut) -> InclusionProof {
        InclusionProof {
            index: inc.index,
            tree_size: inc.tree_size,
            path: inc.path.clone(),
        }
    }

    /// The end-to-end producer↔verifier proof: a real `DirBinding` appended to the
    /// log is accepted by the client verifier at first contact and across a
    /// consistent extension, pinned to `DirLog::log_public()`.
    #[test]
    fn client_accepts_produced_binding_and_consistent_extension() {
        let mut log = DirLog::new(SigningKey::generate());
        let pin = [log.log_public()];
        let mut store = MemoryKtCheckpointStore::new();

        // Append three real bindings.
        let b0 = binding_bytes(0x11);
        log.append(b0.clone());
        log.append(binding_bytes(0x22));
        log.append(binding_bytes(0x33));

        // First contact (TOFU): the client accepts b0's inclusion under the
        // produced, KT-signed checkpoint.
        let cp1 = log.checkpoint();
        let inc0 = log.inclusion(0).unwrap();
        verify_binding_in_log(
            &b0,
            &to_client_inc(&inc0),
            &to_client_cp(&cp1),
            &[],
            &pin,
            &mut store,
        )
        .expect("client accepts produced binding at first contact");

        // The log grows; a consistent later checkpoint + a fresh inclusion +
        // a prev→new consistency proof are all accepted.
        let b3 = binding_bytes(0x44);
        log.append(b3.clone());
        log.append(binding_bytes(0x55));
        let cp2 = log.checkpoint();
        let inc3 = log.inclusion(3).unwrap();
        let consistency = log.consistency(cp1.tree_size);
        verify_binding_in_log(
            &b3,
            &to_client_inc(&inc3),
            &to_client_cp(&cp2),
            &consistency,
            &pin,
            &mut store,
        )
        .expect("client accepts a consistent extension");
    }

    /// SPLIT-VIEW: a second, forked log produces a checkpoint that is NOT a
    /// consistent extension of the first — the client catches it as
    /// `KtError::SplitView`.
    #[test]
    fn client_detects_split_view_fork() {
        let key = SigningKey::generate();
        let pin = [key.verifying_key().to_bytes()];
        let mut store = MemoryKtCheckpointStore::new();

        // Log A: the honest history the client pins on first use.
        let mut log_a = DirLog::new(SigningKey::from_seed(&key.to_seed()));
        let b0 = binding_bytes(0xA0);
        log_a.append(b0.clone());
        log_a.append(binding_bytes(0xA1));
        log_a.append(binding_bytes(0xA2));
        let cp_a = log_a.checkpoint();
        verify_binding_in_log(
            &b0,
            &to_client_inc(&log_a.inclusion(0).unwrap()),
            &to_client_cp(&cp_a),
            &[],
            &pin,
            &mut store,
        )
        .expect("pin the honest checkpoint");

        // Log B: a FORK under the SAME log key — different leaves, larger size.
        // Its own (internally valid) consistency proof cannot reconcile with the
        // pinned root_m ⇒ the client returns SplitView.
        let mut log_b = DirLog::new(SigningKey::from_seed(&key.to_seed()));
        let f0 = binding_bytes(0xB0);
        log_b.append(f0.clone());
        log_b.append(binding_bytes(0xB1));
        log_b.append(binding_bytes(0xB2));
        log_b.append(binding_bytes(0xB3));
        log_b.append(binding_bytes(0xB4));
        let cp_b = log_b.checkpoint();
        let consistency = log_b.consistency(cp_a.tree_size);
        assert_eq!(
            verify_binding_in_log(
                &f0,
                &to_client_inc(&log_b.inclusion(0).unwrap()),
                &to_client_cp(&cp_b),
                &consistency,
                &pin,
                &mut store,
            ),
            Err(KtError::SplitView),
        );
        // The gossip state is unchanged (the equivocal checkpoint is not adopted).
        assert_eq!(store.latest(), Some(to_client_cp(&cp_a)));
    }
}
