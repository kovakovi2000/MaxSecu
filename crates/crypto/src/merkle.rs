//! RFC 6962 Merkle **inclusion** and **consistency** verification (DESIGN §7.6
//! transparency-log anchor form). A transparency log publishes a signed
//! checkpoint `{tree_size, root}`; an inclusion proof shows that a given leaf is
//! the `index`-th of `tree_size` leaves under `root`, and a consistency proof
//! (§2.1.2/§2.1.3, [`verify_consistency`]/[`consistency_path`]) shows that a
//! later checkpoint is an append-only extension of an earlier one — the
//! split-view / equivocation detector for the directory key-transparency log.
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

/// Verify an RFC 6962 §2.1.2 consistency proof that the size-`m` tree (root
/// `root_m`) is a prefix of the size-`n` tree (root `root_n`) — i.e. that the
/// size-`n` log is an append-only extension of the size-`m` log. Returns `true`
/// only when BOTH `root_m` and `root_n` are exactly reconstructed from the proof.
///
/// This is the split-view / equivocation detector for the directory
/// key-transparency log: a client that persisted a signed size-`m` checkpoint
/// rejects (gets `false`) any later size-`n` checkpoint that is not a genuine
/// extension of it (a fork, rollback, or two inconsistent served views).
///
/// Fail-closed: rejects `m > n`; rejects a non-empty proof for the degenerate
/// `m == 0` / `m == n` cases; rejects `m == n` unless `root_m == root_n`; rejects
/// any malformed, short, or over-long proof without panicking (no out-of-bounds).
/// No `unsafe`.
pub fn verify_consistency(
    m: u64,
    root_m: [u8; 32],
    n: u64,
    root_n: [u8; 32],
    proof: &[[u8; 32]],
) -> bool {
    if m > n {
        return false;
    }
    if m == n {
        // Identical trees: the proof is empty and the roots must coincide.
        return proof.is_empty() && root_m == root_n;
    }
    if m == 0 {
        // Every tree is an append-only extension of the empty tree; per RFC the
        // proof is empty. (We do not — cannot — check root_m here.)
        return proof.is_empty();
    }
    // 0 < m < n: the general case (RFC 6962 §2.1.2 reconstruction).
    if proof.is_empty() {
        return false;
    }

    let mut node = m - 1;
    let mut last_node = n - 1;

    // Climb past the right-edge of the size-`m` subtree.
    while (node & 1) == 1 {
        node >>= 1;
        last_node >>= 1;
    }

    let mut idx = 0usize;
    // Seed both reconstructions. When `node > 0` the first proof element is the
    // shared starting hash; when `node == 0` (m is an exact power of two) the
    // first element is omitted and `root_m` itself is the seed.
    let (mut hash_m, mut hash_n) = if node > 0 {
        let seed = proof[idx];
        idx += 1;
        (seed, seed)
    } else {
        (root_m, root_m)
    };

    while node > 0 {
        if (node & 1) == 1 {
            // Right child: fold in the left sibling for both trees.
            if idx >= proof.len() {
                return false;
            }
            let h = proof[idx];
            idx += 1;
            hash_m = node_hash(&h, &hash_m);
            hash_n = node_hash(&h, &hash_n);
        } else if node < last_node {
            // Left child that has a right sibling in the larger tree: that
            // sibling extends only the size-`n` reconstruction.
            if idx >= proof.len() {
                return false;
            }
            let h = proof[idx];
            idx += 1;
            hash_n = node_hash(&hash_n, &h);
        }
        // else: left child at the right edge of both trees — no sibling yet.
        node >>= 1;
        last_node >>= 1;
    }

    // Finish climbing the size-`n` tree to its root.
    while last_node > 0 {
        if idx >= proof.len() {
            return false;
        }
        let h = proof[idx];
        idx += 1;
        hash_n = node_hash(&hash_n, &h);
        last_node >>= 1;
    }

    hash_m == root_m && hash_n == root_n && idx == proof.len()
}

/// RFC 6962 §2.1.3 consistency proof between sizes `m` and `n` (`m <= n`) over
/// `leaves` (the size-`n` leaf set) — the prover counterpart to
/// [`verify_consistency`]. `m == n` (or `m == 0`) yields the empty proof. Like
/// [`inclusion_path`] this is a caller-side (never network) routine; it panics on
/// `n > leaves.len()`.
pub fn consistency_path(leaves: &[Vec<u8>], m: u64, n: u64) -> Vec<[u8; 32]> {
    if m == 0 || m > n {
        return vec![];
    }
    consistency_subproof(m, &leaves[..n as usize], true)
}

/// RFC 6962 §2.1.3 `SUBPROOF(m, D, b)`. The flag `b` records whether the subtree
/// of the first `m` leaves coincides with the whole subtree `D`: when it does and
/// `b` is true the proof is empty (the verifier already holds that root); when `b`
/// is false the committed subtree root is emitted. Mirrors [`inclusion_path`]'s
/// `largest_pow2_below` split, using [`merkle_root`] for committed subtree hashes.
fn consistency_subproof(m: u64, d: &[Vec<u8>], b: bool) -> Vec<[u8; 32]> {
    let n = d.len() as u64;
    if m == n {
        return if b { vec![] } else { vec![merkle_root(d)] };
    }
    let k = largest_pow2_below(n as usize) as u64;
    if m <= k {
        let mut p = consistency_subproof(m, &d[..k as usize], b);
        p.push(merkle_root(&d[k as usize..]));
        p
    } else {
        let mut p = consistency_subproof(m - k, &d[k as usize..], false);
        p.push(merkle_root(&d[..k as usize]));
        p
    }
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

    // ---- RFC 6962 §2.1.2/§2.1.3 consistency (split-view detection). ----

    #[test]
    fn consistency_verifies_for_append_only_extension() {
        // Mix of power-of-two and unbalanced `m`.
        for &(m, n) in &[(1u64, 5u64), (2, 5), (3, 5), (4, 8), (5, 8), (3, 9)] {
            let d = leaves(n as usize);
            let root_m = merkle_root(&d[..m as usize]);
            let root_n = merkle_root(&d[..n as usize]);
            let proof = consistency_path(&d, m, n);
            assert!(
                verify_consistency(m, root_m, n, root_n, &proof),
                "consistency ({m},{n}) should verify"
            );
        }
    }

    #[test]
    fn consistency_rejects_forked_history() {
        let (m, n) = (3u64, 8u64);
        let d = leaves(n as usize);
        let honest_root_m = merkle_root(&d[..m as usize]);
        let honest_root_n = merkle_root(&d);
        let proof = consistency_path(&d, m, n);

        // A server equivocates: it serves a size-`n` view built on a DIFFERENT
        // size-`m` prefix (leaf 1 changed). Its root_n cannot reconcile with the
        // honestly-persisted root_m under the honest proof → split view detected.
        let mut forked = d.clone();
        forked[1] = b"forked-leaf".to_vec();
        let forked_root_n = merkle_root(&forked);
        assert_ne!(forked_root_n, honest_root_n);
        assert!(!verify_consistency(
            m,
            honest_root_m,
            n,
            forked_root_n,
            &proof
        ));

        // Symmetric view: the client persisted a forked size-`m` checkpoint; the
        // honest later root_n no longer extends it.
        let forked_root_m = merkle_root(&forked[..m as usize]);
        assert_ne!(forked_root_m, honest_root_m);
        assert!(!verify_consistency(
            m,
            forked_root_m,
            n,
            honest_root_n,
            &proof
        ));
    }

    #[test]
    fn consistency_rejects_tampered_proof() {
        let (m, n) = (3u64, 9u64);
        let d = leaves(n as usize);
        let root_m = merkle_root(&d[..m as usize]);
        let root_n = merkle_root(&d);
        let proof = consistency_path(&d, m, n);
        assert!(verify_consistency(m, root_m, n, root_n, &proof));

        // Flip any proof node byte → false.
        let mut bad = proof.clone();
        bad[0][0] ^= 0x01;
        assert!(!verify_consistency(m, root_m, n, root_n, &bad));

        // Flip root_m → false.
        let mut bad_m = root_m;
        bad_m[0] ^= 0x01;
        assert!(!verify_consistency(m, bad_m, n, root_n, &proof));

        // Flip root_n → false.
        let mut bad_n = root_n;
        bad_n[0] ^= 0x01;
        assert!(!verify_consistency(m, root_m, n, bad_n, &proof));

        // A truncated proof must not panic and must reject.
        assert!(!verify_consistency(
            m,
            root_m,
            n,
            root_n,
            &proof[..proof.len() - 1]
        ));

        // An over-long proof rejects (trailing element unconsumed).
        let mut longer = proof.clone();
        longer.push([0u8; 32]);
        assert!(!verify_consistency(m, root_m, n, root_n, &longer));
    }

    #[test]
    fn consistency_m_equals_n_requires_equal_roots() {
        let d = leaves(6);
        let root = merkle_root(&d);
        let proof = consistency_path(&d, 6, 6);
        assert!(proof.is_empty());
        assert!(verify_consistency(6, root, 6, root, &proof));

        let mut other = root;
        other[0] ^= 0x01;
        assert!(!verify_consistency(6, root, 6, other, &proof));

        // A non-empty proof when m == n is rejected (fail-closed).
        assert!(!verify_consistency(6, root, 6, root, &[[0u8; 32]]));
    }

    #[test]
    fn consistency_rejects_m_greater_than_n() {
        let d = leaves(8);
        let root_big = merkle_root(&d);
        let root_small = merkle_root(&d[..5]);
        let proof = consistency_path(&d, 5, 8);
        // m=8 > n=5 → fail-closed regardless of proof contents.
        assert!(!verify_consistency(8, root_big, 5, root_small, &proof));
    }

    #[test]
    fn consistency_power_of_two_m() {
        // m an exact power of two: the first proof element is omitted, root_m is
        // the seed.
        for &(m, n) in &[(1u64, 3u64), (2, 7), (4, 7), (4, 8), (8, 13)] {
            let d = leaves(n as usize);
            let root_m = merkle_root(&d[..m as usize]);
            let root_n = merkle_root(&d);
            let proof = consistency_path(&d, m, n);
            assert!(
                verify_consistency(m, root_m, n, root_n, &proof),
                "power-of-two consistency ({m},{n}) should verify"
            );
        }
    }

    #[test]
    fn consistency_m_zero_is_vacuous() {
        let d = leaves(5);
        let root_n = merkle_root(&d);
        let proof = consistency_path(&d, 0, 5);
        assert!(proof.is_empty());
        // m == 0 is consistent with any tree (empty proof only).
        assert!(verify_consistency(0, [0u8; 32], 5, root_n, &proof));
        assert!(!verify_consistency(0, [0u8; 32], 5, root_n, &[[0u8; 32]]));
    }

    #[test]
    fn generated_consistency_round_trips() {
        // Every prover-emitted proof verifies, across all balanced/unbalanced
        // splits up to a tree of 17 leaves.
        for n in 1..=17u64 {
            let d = leaves(n as usize);
            let root_n = merkle_root(&d);
            for m in 1..=n {
                let root_m = merkle_root(&d[..m as usize]);
                let proof = consistency_path(&d, m, n);
                assert!(
                    verify_consistency(m, root_m, n, root_n, &proof),
                    "round-trip ({m},{n})"
                );
            }
        }
    }
}
