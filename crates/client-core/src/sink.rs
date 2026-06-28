//! The external append-only **sink** — the anchored control-log head (DESIGN
//! §7.6/§16.5, `docs/sink-interface.md`).
//!
//! The app server serves the tombstone *records* (api.md §7.1); the sink
//! independently attests *what the current head is*, over a channel the app
//! operator does not control. A client that holds a trusted [`AnchoredHead`]
//! rejects any server-served chain that is shorter (withholding → a `Gap`),
//! forked, or rolled back (handled by [`crate::revocation::TombstoneSet`]).
//!
//! Posture (Phase 5): an abstract [`SinkClient`] seam + **real** head-proof
//! verification ([`verify_anchor_proof`]) + an in-memory [`FakeSink`]. The real
//! WORM / transparency-log deployment and the transparency-log `anchor_proof`
//! form are a Phase-6 ops item; the proof allowlist is built to admit them.

use maxsecu_crypto::{SigningKey, VerifyingKey};
use maxsecu_encoding::{labels, signing_input};

/// The tuple the sink attests (`sink-interface.md` §2): the chain length and its
/// head. `chain_seq` pins an exact length (so a withheld tail is a short chain →
/// `Gap`); `head` pins the content. `anchored_at` is advisory and omitted — it
/// is never a freshness basis (§7.5, clock-independent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchoredHead {
    pub chain_seq: u64,
    pub head: [u8; 32],
}

/// An accepted anchor-proof form (the client ships an allowlist, like the `alg`
/// registry; `sink-interface.md` §4). v1 ships the **separate-custodian Ed25519
/// co-signature** form; the transparency-log form is a Phase-6 addition.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AnchorProof {
    /// An Ed25519 signature over `{chain_seq, head}` by a key held by a separate
    /// custodian (not the app operator, not D5/D6), pinned in the build.
    CustodianCoSig { sig: [u8; 64] },
}

/// Why a sink interaction failed. Both are fail-closed: a completeness-requiring
/// op blocks (reads of already-verified content continue, §7.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SinkError {
    /// No allowlisted custodian validated the head's `anchor_proof` (§4) — the
    /// head is untrusted, so the op fails closed.
    BadProof,
    /// The sink could not be reached over its pinned channel.
    Unreachable,
}

/// The exact bytes a custodian signs for a head: the domain-framed, fixed-width
/// `chain_seq (8, big-endian) ‖ head (32)`. Both fields are fixed width, so the
/// concatenation is unambiguous; [`signing_input`] length-frames the label.
fn head_signing_bytes(h: &AnchoredHead) -> Vec<u8> {
    let mut m = [0u8; 40];
    m[..8].copy_from_slice(&h.chain_seq.to_be_bytes());
    m[8..].copy_from_slice(&h.head);
    signing_input(labels::SINK_HEAD, &m)
}

/// Verify a head's `anchor_proof` against the **pinned custodian allowlist** (a
/// separate trust domain from D5/D6 and the app server). At least one allowlisted
/// key must validate, else the head is rejected — fail closed (`sink-interface`
/// §4/§5 step 1).
pub fn verify_anchor_proof(
    head: &AnchoredHead,
    proof: &AnchorProof,
    custodian_pubs: &[[u8; 32]],
) -> Result<(), SinkError> {
    let AnchorProof::CustodianCoSig { sig } = proof;
    let msg = head_signing_bytes(head);
    let ok = custodian_pubs.iter().any(|pk| {
        VerifyingKey::from_bytes(pk)
            .and_then(|vk| vk.verify_raw(&msg, sig))
            .is_ok()
    });
    if ok {
        Ok(())
    } else {
        Err(SinkError::BadProof)
    }
}

/// The client's pinned-channel read interface to the sink (`sink-interface.md`
/// §3). The hot path needs only the head; the client verifies the app server's
/// records up to it. The returned proof is validated by [`verify_anchor_proof`].
pub trait SinkClient {
    /// `GET {sink}/v1/control-log/head` — the current anchored head + its proof.
    fn fetch_head(&self) -> Result<(AnchoredHead, AnchorProof), SinkError>;
}

/// An in-memory sink for tests/dev: holds the custodian key and the current
/// `(chain_seq, head)`, and co-signs the head on demand. The real sink is WORM /
/// independent infrastructure (Phase 6).
pub struct FakeSink {
    custodian: SigningKey,
    head: AnchoredHead,
}

impl FakeSink {
    /// A fresh fake sink anchored at the empty chain (`GENESIS_HEAD`, seq 0).
    pub fn new(custodian: SigningKey) -> FakeSink {
        FakeSink {
            custodian,
            head: AnchoredHead {
                chain_seq: 0,
                head: maxsecu_encoding::GENESIS_HEAD.0,
            },
        }
    }

    /// The custodian's public key — the value pinned in clients' allowlists.
    pub fn custodian_pub(&self) -> [u8; 32] {
        self.custodian.verifying_key().to_bytes()
    }

    /// Anchor a new head (the sink re-publishes on each control-log append, §6).
    pub fn anchor(&mut self, chain_seq: u64, head: [u8; 32]) {
        self.head = AnchoredHead { chain_seq, head };
    }
}

impl SinkClient for FakeSink {
    fn fetch_head(&self) -> Result<(AnchoredHead, AnchorProof), SinkError> {
        let sig = self.custodian.sign_raw(&head_signing_bytes(&self.head));
        Ok((self.head, AnchorProof::CustodianCoSig { sig }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::revocation::{ControlRecordIn, IssuerInfo, TombstoneError, TombstoneSet};
    use maxsecu_admin_core::{ControlChain, RevokeParams, SignedControlRecord};
    use maxsecu_encoding::types::{FileScope, Id, Role, Timestamp};

    const NOW: Timestamp = Timestamp(1_719_500_000_000);
    const ADMIN_ID: Id = Id([1; 16]);

    fn a_head() -> AnchoredHead {
        AnchoredHead {
            chain_seq: 3,
            head: [0xAB; 32],
        }
    }

    #[test]
    fn valid_anchor_proof_accepts() {
        let custodian = SigningKey::generate();
        let head = a_head();
        let sig = custodian.sign_raw(&head_signing_bytes(&head));
        assert!(verify_anchor_proof(
            &head,
            &AnchorProof::CustodianCoSig { sig },
            &[custodian.verifying_key().to_bytes()]
        )
        .is_ok());
    }

    #[test]
    fn forged_anchor_proof_is_rejected() {
        let custodian = SigningKey::generate();
        let head = a_head();
        let mut sig = custodian.sign_raw(&head_signing_bytes(&head));
        sig[0] ^= 0x01;
        assert_eq!(
            verify_anchor_proof(
                &head,
                &AnchorProof::CustodianCoSig { sig },
                &[custodian.verifying_key().to_bytes()]
            ),
            Err(SinkError::BadProof)
        );
    }

    #[test]
    fn wrong_custodian_key_is_rejected() {
        let custodian = SigningKey::generate();
        let other = SigningKey::generate();
        let head = a_head();
        let sig = custodian.sign_raw(&head_signing_bytes(&head));
        // Pinned allowlist holds only `other` — the real signer is not trusted.
        assert_eq!(
            verify_anchor_proof(
                &head,
                &AnchorProof::CustodianCoSig { sig },
                &[other.verifying_key().to_bytes()]
            ),
            Err(SinkError::BadProof)
        );
    }

    #[test]
    fn tampered_head_breaks_the_proof() {
        let custodian = SigningKey::generate();
        let head = a_head();
        let sig = custodian.sign_raw(&head_signing_bytes(&head));
        // Server lies about the head while replaying the custodian's signature.
        let mut lied = head;
        lied.head[0] ^= 0x01;
        assert_eq!(
            verify_anchor_proof(
                &lied,
                &AnchorProof::CustodianCoSig { sig },
                &[custodian.verifying_key().to_bytes()]
            ),
            Err(SinkError::BadProof)
        );
    }

    #[test]
    fn fake_sink_fetch_head_is_verifiable() {
        let mut sink = FakeSink::new(SigningKey::generate());
        sink.anchor(7, [0x5A; 32]);
        let (head, proof) = sink.fetch_head().unwrap();
        assert_eq!(head, AnchoredHead { chain_seq: 7, head: [0x5A; 32] });
        assert!(verify_anchor_proof(&head, &proof, &[sink.custodian_pub()]).is_ok());
    }

    // ---- Cross-seam: the sink head + the server-served records compose into a
    // withholding-resistant completeness check (the headline P5.2 gate). ----

    fn rp(scope: FileScope, victim: u8) -> RevokeParams {
        RevokeParams {
            scope,
            revoked_user_id: Id([victim; 16]),
            revoked_capability: None,
            from_version: 1,
            issued_by: ADMIN_ID,
            created_at: NOW,
        }
    }

    fn rec_in(r: &SignedControlRecord) -> ControlRecordIn {
        ControlRecordIn {
            bytes: r.bytes.clone(),
            sig: r.sig,
            co_sig: r.co_sig,
        }
    }

    #[test]
    fn head_and_records_compose_and_withholding_is_a_gap() {
        let admin = SigningKey::generate();
        let admin_pub = admin.verifying_key().to_bytes();
        let issuer = |id: Id| {
            (id == ADMIN_ID).then_some(IssuerInfo {
                sig_pub: admin_pub,
                roles: vec![Role::Admin],
                key_version: 1,
            })
        };

        let mut chain = ControlChain::new();
        let file = FileScope::Specific(Id([0x0A; 16]));
        let r1 = chain.revoke(&admin, rp(file, 0x99), None).unwrap();
        let r2 = chain.revoke(&admin, rp(file, 0x98), None).unwrap();

        // The sink anchors the head AFTER both records (chain_seq = 2).
        let mut sink = FakeSink::new(SigningKey::generate());
        sink.anchor(2, chain.head());
        let (head, proof) = sink.fetch_head().unwrap();
        verify_anchor_proof(&head, &proof, &[sink.custodian_pub()]).expect("head trusted");

        // Full set up to the anchored head verifies.
        let full = [rec_in(&r1), rec_in(&r2)];
        assert!(TombstoneSet::verify_authenticated(&full, head.head, &issuer).is_ok());

        // A server that WITHHOLDS the last record (serves only r1) is caught as a
        // Gap against the sink-anchored head — fail closed (D22).
        let withheld = [rec_in(&r1)];
        assert_eq!(
            TombstoneSet::verify_authenticated(&withheld, head.head, &issuer).unwrap_err(),
            TombstoneError::Gap
        );
    }
}
