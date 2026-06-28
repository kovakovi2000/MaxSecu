//! RFC 6962 Merkle **inclusion** verification (DESIGN §7.6 transparency-log
//! anchor form). A transparency log publishes a signed checkpoint
//! `{tree_size, root}`; an inclusion proof shows that a given leaf is the
//! `index`-th of `tree_size` leaves under `root`.
//!
//! Hashing is RFC 6962 §2.1: `leaf_hash(x) = SHA256(0x00 ‖ x)` and
//! `node_hash(l, r) = SHA256(0x01 ‖ l ‖ r)`. The domain-separating `0x00`/`0x01`
//! prefixes prevent second-preimage attacks that confuse a leaf for an internal
//! node. This primitive is consumed by the sink anchor-proof check and reused by
//! update verification.

use crate::hash::sha256;

/// RFC 6962 leaf hash: `SHA256(0x00 ‖ x)`.
fn leaf_hash(x: &[u8]) -> [u8; 32] {
    let mut m = Vec::with_capacity(1 + x.len());
    m.push(0x00);
    m.extend_from_slice(x);
    sha256(&m)
}

/// RFC 6962 interior-node hash: `SHA256(0x01 ‖ l ‖ r)`.
fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut m = [0u8; 1 + 32 + 32];
    m[0] = 0x01;
    m[1..33].copy_from_slice(l);
    m[33..].copy_from_slice(r);
    sha256(&m)
}

/// RFC 6962 §2.1 **Merkle Tree Hash** over the raw leaf values `leaves`. The
/// empty tree hashes to `SHA256(&[])`; a one-leaf tree to that leaf's
/// [`leaf_hash`]; otherwise the tree splits at the largest power of two strictly
/// below `n` and combines the two subtree roots with [`node_hash`]. This is the
/// prover-side counterpart to [`verify_inclusion`] (a generated `root`/path
/// round-trips through it).
pub fn merkle_root(leaves: &[Vec<u8>]) -> [u8; 32] {
    match leaves.len() {
        0 => sha256(&[]),
        1 => leaf_hash(&leaves[0]),
        n => {
            let k = largest_pow2_below(n);
            node_hash(&merkle_root(&leaves[..k]), &merkle_root(&leaves[k..]))
        }
    }
}

/// RFC 6962 §2.1.1 **audit path** (inclusion proof) for the `index`-th leaf of
/// the `leaves.len()`-leaf tree, bottom-up — exactly the `path` that
/// [`verify_inclusion`] consumes. A single-leaf (or empty) tree yields an empty
/// path. Panics on `index >= leaves.len()` (a caller bug, never network input).
pub fn inclusion_path(index: usize, leaves: &[Vec<u8>]) -> Vec<[u8; 32]> {
    assert!(index < leaves.len(), "leaf index out of range");
    let n = leaves.len();
    if n <= 1 {
        return vec![];
    }
    let k = largest_pow2_below(n);
    if index < k {
        let mut p = inclusion_path(index, &leaves[..k]);
        p.push(merkle_root(&leaves[k..]));
        p
    } else {
        let mut p = inclusion_path(index - k, &leaves[k..]);
        p.push(merkle_root(&leaves[..k]));
        p
    }
}

/// Largest power of two strictly less than `n` (RFC 6962 split point; `n > 1`).
fn largest_pow2_below(n: usize) -> usize {
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// Verify an RFC 6962 inclusion proof: that `leaf` (raw leaf value, hashed here)
/// is the `index`-th leaf of a tree of `tree_size` leaves whose Merkle root is
/// `root`, given the audit `path`. Returns `true` only on an exact root match.
///
/// Fail-closed: rejects `index >= tree_size` and any path length that does not
/// match the tree's structure (per RFC 6962 §2.1.1). No `unsafe`.
pub fn verify_inclusion(
    leaf: &[u8],
    index: u64,
    tree_size: u64,
    path: &[[u8; 32]],
    root: [u8; 32],
) -> bool {
    // RFC 6962 §2.1.1 inclusion-proof verification.
    if index >= tree_size {
        return false;
    }
    let mut fnode = index;
    let mut snode = tree_size - 1;
    let mut r = leaf_hash(leaf);
    for p in path {
        if snode == 0 {
            // Path is longer than the tree's depth admits — reject.
            return false;
        }
        if (fnode & 1) == 1 || fnode == snode {
            r = node_hash(p, &r);
            if (fnode & 1) == 0 {
                // Right-shift both until LSB(fnode) is set or fnode is 0.
                while (fnode & 1) == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && r == root
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- The prover side (`merkle_root`/`inclusion_path`) is the single
    // implementation; tests check the verifier against proofs it generates. ----

    fn leaves(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| format!("leaf-{i}").into_bytes()).collect()
    }

    #[test]
    fn generated_proof_round_trips() {
        // Every leaf of a 5-leaf tree (an unbalanced size that exercises the
        // odd-node split): the `root`/`path` the prover emits verify.
        let d = leaves(5);
        let root = merkle_root(&d);
        for (i, leaf) in d.iter().enumerate() {
            let path = inclusion_path(i, &d);
            assert!(
                verify_inclusion(leaf, i as u64, d.len() as u64, &path, root),
                "leaf {i} should verify"
            );
        }
    }

    #[test]
    fn empty_tree_root_is_sha256_of_nothing() {
        assert_eq!(merkle_root(&[]), sha256(&[]));
    }

    #[test]
    fn inclusion_verifies() {
        // A 5-leaf tree (an unbalanced size that exercises the odd-node split).
        let d = leaves(5);
        let root = merkle_root(&d);
        for (i, leaf) in d.iter().enumerate() {
            let path = inclusion_path(i, &d);
            assert!(
                verify_inclusion(leaf, i as u64, d.len() as u64, &path, root),
                "leaf {i} should verify"
            );
        }
    }

    #[test]
    fn single_leaf_tree_has_empty_path() {
        let d = leaves(1);
        let root = merkle_root(&d);
        assert!(verify_inclusion(&d[0], 0, 1, &[], root));
    }

    #[test]
    fn tampered_leaf_or_path_rejected() {
        let d = leaves(5);
        let root = merkle_root(&d);
        let idx = 2usize;
        let path = inclusion_path(idx, &d);

        // Baseline: the honest proof verifies.
        assert!(verify_inclusion(&d[idx], idx as u64, 5, &path, root));

        // Flip a leaf byte → false.
        let mut bad_leaf = d[idx].clone();
        bad_leaf[0] ^= 0x01;
        assert!(!verify_inclusion(&bad_leaf, idx as u64, 5, &path, root));

        // Flip an audit-path byte → false.
        let mut bad_path = path.clone();
        bad_path[0][0] ^= 0x01;
        assert!(!verify_inclusion(&d[idx], idx as u64, 5, &bad_path, root));

        // Wrong index → false.
        assert!(!verify_inclusion(&d[idx], 1, 5, &path, root));

        // index >= tree_size → false.
        assert!(!verify_inclusion(&d[idx], 5, 5, &path, root));

        // Flip a root byte → false.
        let mut bad_root = root;
        bad_root[0] ^= 0x01;
        assert!(!verify_inclusion(&d[idx], idx as u64, 5, &path, bad_root));
    }
}
