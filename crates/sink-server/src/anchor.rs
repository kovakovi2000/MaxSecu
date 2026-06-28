//! Digest **anchoring** (DESIGN §7.6/§3.3, `docs/sink-interface.md` §4).
//!
//! On each control-log append the sink re-publishes its head and emits an
//! `anchor_proof` so a client can trust `{chain_seq, head}` over a channel the
//! app operator does not control. The [`Anchorer`] produces BOTH accepted forms
//! for every anchored head:
//!
//! * **CustodianCoSig** — a separate-custodian Ed25519 signature over the head's
//!   signing bytes ([`encoding::sink_head_signing_input`]).
//! * **TransparencyInclusion** — the head's signing bytes are appended as the
//!   next leaf of an RFC 6962 transparency log; the proof is the log-signed
//!   checkpoint `{tree_size, root}` plus the leaf's inclusion path.
//!
//! Both are exactly what `client-core::sink::verify_anchor_proof` accepts (the
//! leaf value and signing bytes come from the shared `maxsecu-encoding`
//! constructors, so prover and verifier agree byte-for-byte). The lib keeps its
//! non-dev deps to encoding + crypto; tests map [`AnchorProofParts`] into the
//! client's `AnchorProof` to drive the real verifier.

use crate::chain::AnchoredHead;
use maxsecu_crypto::merkle::{inclusion_path, merkle_root};
use maxsecu_crypto::SigningKey;
use maxsecu_encoding::{sink_checkpoint_signing_input, sink_head_signing_input};

/// One produced anchor-proof, in plain lib form (mirrors the variants of
/// `client-core::sink::AnchorProof`). A caller maps these onto the client type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorProofParts {
    /// A separate-custodian Ed25519 signature over the head's signing bytes.
    CustodianCoSig { sig: [u8; 64] },
    /// An RFC 6962 transparency-log inclusion proof: the log-signed checkpoint
    /// plus the leaf's audit path under the checkpoint root.
    TransparencyInclusion {
        checkpoint_sig: [u8; 64],
        tree_size: u64,
        root: [u8; 32],
        index: u64,
        path: Vec<[u8; 32]>,
    },
}

/// Both anchor-proof forms for a single anchored head — handed to a client so it
/// can validate the head under whichever form its allowlist pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorBundle {
    /// The separate-custodian co-signature form.
    pub cosig: AnchorProofParts,
    /// The transparency-log inclusion form.
    pub transparency: AnchorProofParts,
}

/// Anchors control-log heads: holds the custodian signing key, the transparency
/// log's signing key, the growing transparency-log leaves, and the published
/// anchor history (for §3.3 reconciliation).
pub struct Anchorer {
    custodian: SigningKey,
    log: SigningKey,
    leaves: Vec<Vec<u8>>,
    history: Vec<(AnchoredHead, AnchorBundle)>,
}

impl Anchorer {
    /// A fresh anchorer with an empty transparency log and no anchored heads.
    pub fn new(custodian: SigningKey, log: SigningKey) -> Anchorer {
        Anchorer {
            custodian,
            log,
            leaves: Vec::new(),
            history: Vec::new(),
        }
    }

    /// The custodian's public key — pinned in clients' custodian allowlist.
    pub fn custodian_pub(&self) -> [u8; 32] {
        self.custodian.verifying_key().to_bytes()
    }

    /// The transparency log's public key — pinned in clients' log allowlist.
    pub fn log_pub(&self) -> [u8; 32] {
        self.log.verifying_key().to_bytes()
    }

    /// Anchor `head`: append its signing bytes as the next transparency-log leaf,
    /// re-root, and emit BOTH proof forms (custodian co-signature + transparency
    /// inclusion). The bundle is recorded in the history and returned.
    pub fn anchor(&mut self, head: AnchoredHead) -> AnchorBundle {
        // The leaf value is EXACTLY the head's signing bytes the verifier hashes.
        let leaf = sink_head_signing_input(head.chain_seq, &head.head);
        self.leaves.push(leaf);

        let tree_size = self.leaves.len() as u64;
        let index = self.leaves.len() - 1;
        let root = merkle_root(&self.leaves);
        let path = inclusion_path(index, &self.leaves);
        let checkpoint_sig = self
            .log
            .sign_raw(&sink_checkpoint_signing_input(tree_size, &root));

        let cosig_sig = self
            .custodian
            .sign_raw(&sink_head_signing_input(head.chain_seq, &head.head));

        let bundle = AnchorBundle {
            cosig: AnchorProofParts::CustodianCoSig { sig: cosig_sig },
            transparency: AnchorProofParts::TransparencyInclusion {
                checkpoint_sig,
                tree_size,
                root,
                index: index as u64,
                path,
            },
        };
        self.history.push((head, bundle.clone()));
        bundle
    }

    /// The full anchor history — each anchored head and its bundle (§3.3
    /// reconciliation: a client can replay/verify every published head).
    pub fn anchor_log(&self) -> Vec<(AnchoredHead, AnchorBundle)> {
        self.history.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_client_core::sink::{verify_anchor_proof, AnchorProof, AnchoredHead as CHead};

    fn a_head(chain_seq: u64, b: u8) -> AnchoredHead {
        AnchoredHead {
            chain_seq,
            head: [b; 32],
        }
    }

    /// Map a lib [`AnchorProofParts`] onto the client verifier's `AnchorProof`.
    fn to_client(parts: &AnchorProofParts) -> AnchorProof {
        match parts {
            AnchorProofParts::CustodianCoSig { sig } => AnchorProof::CustodianCoSig { sig: *sig },
            AnchorProofParts::TransparencyInclusion {
                checkpoint_sig,
                tree_size,
                root,
                index,
                path,
            } => AnchorProof::TransparencyInclusion {
                checkpoint_sig: *checkpoint_sig,
                tree_size: *tree_size,
                root: *root,
                index: *index,
                path: path.clone(),
            },
        }
    }

    fn chead(h: &AnchoredHead) -> CHead {
        CHead {
            chain_seq: h.chain_seq,
            head: h.head,
        }
    }

    #[test]
    fn anchor_emits_cosig_and_checkpoint() {
        let mut anchorer = Anchorer::new(SigningKey::generate(), SigningKey::generate());
        let head = a_head(3, 0xAB);
        let bundle = anchor_head_via(&mut anchorer, head);

        let ch = chead(&head);
        // The custodian co-signature form verifies against the custodian pin.
        assert!(verify_anchor_proof(
            &ch,
            &to_client(&bundle.cosig),
            &[anchorer.custodian_pub()],
            &[],
        )
        .is_ok());
        // The transparency-inclusion form verifies against the log pin.
        assert!(verify_anchor_proof(
            &ch,
            &to_client(&bundle.transparency),
            &[],
            &[anchorer.log_pub()],
        )
        .is_ok());
    }

    /// Anchor and return the bundle (borrow dance so we can still query pubs).
    fn anchor_head_via(anchorer: &mut Anchorer, head: AnchoredHead) -> AnchorBundle {
        anchorer.anchor(head)
    }

    #[test]
    fn anchor_log_records_each_head() {
        let mut anchorer = Anchorer::new(SigningKey::generate(), SigningKey::generate());
        let h1 = a_head(1, 0x11);
        let h2 = a_head(2, 0x22);
        let h3 = a_head(3, 0x33);
        for h in [h1, h2, h3] {
            anchorer.anchor(h);
        }

        let log = anchorer.anchor_log();
        assert_eq!(log.len(), 3);
        assert_eq!(log[0].0, h1);
        assert_eq!(log[1].0, h2);
        assert_eq!(log[2].0, h3);

        // Every recorded head — under the GROWING tree — still verifies (the
        // earlier leaves' inclusion paths were captured at their tree size).
        let log_pub = anchorer.log_pub();
        let cust_pub = anchorer.custodian_pub();
        for (head, bundle) in &log {
            let ch = chead(head);
            assert!(verify_anchor_proof(&ch, &to_client(&bundle.cosig), &[cust_pub], &[]).is_ok());
            assert!(
                verify_anchor_proof(&ch, &to_client(&bundle.transparency), &[], &[log_pub]).is_ok()
            );
        }
    }
}
