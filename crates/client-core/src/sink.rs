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
use maxsecu_encoding::{sink_checkpoint_signing_input, sink_head_signing_input};

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
/// registry; `sink-interface.md` §4). v1 shipped the **separate-custodian
/// Ed25519 co-signature** form; Phase 6 adds the stronger **transparency-log
/// inclusion** form.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AnchorProof {
    /// An Ed25519 signature over `{chain_seq, head}` by a key held by a separate
    /// custodian (not the app operator, not D5/D6), pinned in the build.
    CustodianCoSig { sig: [u8; 64] },
    /// An RFC 6962 transparency-log proof: a log-signed checkpoint
    /// `{tree_size, root}` plus a Merkle inclusion proof that the head's signing
    /// bytes ([`head_signing_bytes`]) are the `index`-th leaf under `root`. Both
    /// the pinned-log checkpoint signature and the inclusion must hold.
    TransparencyInclusion {
        /// The log's Ed25519 signature over
        /// `signing_input(SINK_CHECKPOINT, tree_size(8 BE) ‖ root(32))`.
        checkpoint_sig: [u8; 64],
        tree_size: u64,
        root: [u8; 32],
        index: u64,
        path: Vec<[u8; 32]>,
    },
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
/// `chain_seq (8, big-endian) ‖ head (32)`. Delegates to the single source of
/// truth in `maxsecu-encoding` so the sink that PRODUCES proofs and this verifier
/// construct identical bytes.
fn head_signing_bytes(h: &AnchoredHead) -> Vec<u8> {
    sink_head_signing_input(h.chain_seq, &h.head)
}

/// The exact bytes a transparency log signs for a checkpoint: the domain-framed,
/// fixed-width `tree_size (8, big-endian) ‖ root (32)`. Delegates to the single
/// source of truth in `maxsecu-encoding` (mirrors [`head_signing_bytes`]).
fn checkpoint_signing_bytes(tree_size: u64, root: &[u8; 32]) -> Vec<u8> {
    sink_checkpoint_signing_input(tree_size, root)
}

/// Does any allowlisted key strictly verify `sig` over `msg`?
fn any_key_verifies(pubs: &[[u8; 32]], msg: &[u8], sig: &[u8; 64]) -> bool {
    pubs.iter().any(|pk| {
        VerifyingKey::from_bytes(pk)
            .and_then(|vk| vk.verify_raw(msg, sig))
            .is_ok()
    })
}

/// Verify a head's `anchor_proof` against the pinned trust anchors (separate
/// domains from D5/D6 and the app server): a **custodian allowlist** for the
/// co-signature form and a **transparency-log allowlist** for the inclusion
/// form. The proof must validate under its form, else the head is rejected —
/// fail closed (`sink-interface` §4/§5 step 1). An empty allowlist makes the
/// corresponding form unvalidatable.
pub fn verify_anchor_proof(
    head: &AnchoredHead,
    proof: &AnchorProof,
    custodian_pubs: &[[u8; 32]],
    transparency_log_pubs: &[[u8; 32]],
) -> Result<(), SinkError> {
    let ok = match proof {
        AnchorProof::CustodianCoSig { sig } => {
            any_key_verifies(custodian_pubs, &head_signing_bytes(head), sig)
        }
        AnchorProof::TransparencyInclusion {
            checkpoint_sig,
            tree_size,
            root,
            index,
            path,
        } => {
            // (a) a pinned log key signs the checkpoint AND (b) the head's
            // signing bytes are included under the checkpoint root.
            any_key_verifies(
                transparency_log_pubs,
                &checkpoint_signing_bytes(*tree_size, root),
                checkpoint_sig,
            ) && maxsecu_crypto::merkle::verify_inclusion(
                &head_signing_bytes(head),
                *index,
                *tree_size,
                path,
                *root,
            )
        }
    };
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

/// A real, pinned-TLS [`SinkClient`] over the sink's HTTP control-log surface
/// (`sink-interface.md` §3), behind the `net` feature.
///
/// It fetches `GET /v1/control-log/head` over the sink's OWN pinned TLS identity
/// (independent of the app server, §3) and parses the head + its anchor proofs.
/// It does NOT trust the bytes — the caller validates the returned proof with
/// [`verify_anchor_proof`]. Any transport/parse failure is [`SinkError::Unreachable`]
/// (fail closed). The [`SinkClient`] trait is sync; the async HTTP request runs on
/// a tiny per-call current-thread `tokio` runtime so the rest of the client stays
/// runtime-agnostic.
#[cfg(feature = "net")]
pub struct HttpSinkClient {
    addr: std::net::SocketAddr,
    server_name: String,
    tls: std::sync::Arc<tokio_rustls::rustls::ClientConfig>,
}

#[cfg(feature = "net")]
impl HttpSinkClient {
    /// Build a client targeting the sink at `addr`, presenting `server_name` for
    /// TLS verification against the pinned `tls` config (which holds the sink's
    /// pinned root). `addr` and `server_name` are split so a loopback test can dial
    /// an ephemeral port while still validating the cert's `localhost` SAN.
    pub fn new(
        addr: std::net::SocketAddr,
        server_name: impl Into<String>,
        tls: std::sync::Arc<tokio_rustls::rustls::ClientConfig>,
    ) -> HttpSinkClient {
        HttpSinkClient {
            addr,
            server_name: server_name.into(),
            tls,
        }
    }

    /// `GET /v1/control-log/head`, returning the parsed head and BOTH anchor-proof
    /// forms (custodian co-signature + transparency inclusion) so a caller can
    /// validate the head under whichever form its allowlist pins. The bytes are
    /// untrusted until [`verify_anchor_proof`] passes.
    pub fn fetch_head_all_proofs(&self) -> Result<(AnchoredHead, Vec<AnchorProof>), SinkError> {
        let body = self.get("/v1/control-log/head")?;
        let v: serde_json::Value = serde_json::from_slice(&body).map_err(|_| SinkError::Unreachable)?;
        parse_head_all_proofs(&v).ok_or(SinkError::Unreachable)
    }

    /// Run the blocking GET on a tiny current-thread runtime and return the raw
    /// response body. Any failure collapses to [`SinkError::Unreachable`].
    fn get(&self, path: &str) -> Result<Vec<u8>, SinkError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| SinkError::Unreachable)?;
        rt.block_on(self.get_async(path))
    }

    async fn get_async(&self, path: &str) -> Result<Vec<u8>, SinkError> {
        use http_body_util::{BodyExt, Empty};
        use hyper::body::Bytes;
        use hyper_util::rt::TokioIo;
        use tokio_rustls::rustls::pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        let tcp = tokio::net::TcpStream::connect(self.addr)
            .await
            .map_err(|_| SinkError::Unreachable)?;
        let connector = TlsConnector::from(self.tls.clone());
        let server_name = ServerName::try_from(self.server_name.clone())
            .map_err(|_| SinkError::Unreachable)?;
        let tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|_| SinkError::Unreachable)?;

        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|_| SinkError::Unreachable)?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = hyper::Request::builder()
            .method("GET")
            .uri(path)
            .header("host", self.server_name.as_str())
            .body(Empty::<Bytes>::new())
            .map_err(|_| SinkError::Unreachable)?;
        let resp = sender
            .send_request(req)
            .await
            .map_err(|_| SinkError::Unreachable)?;
        if !resp.status().is_success() {
            return Err(SinkError::Unreachable);
        }
        let bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|_| SinkError::Unreachable)?
            .to_bytes();
        Ok(bytes.to_vec())
    }
}

/// Decode a base64 string into a fixed-width byte array, or `None` on bad
/// base64 / wrong length.
#[cfg(feature = "net")]
fn b64_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    use base64::Engine;
    let v = base64::engine::general_purpose::STANDARD.decode(s).ok()?;
    v.try_into().ok()
}

/// Parse the §3.1 head JSON into an [`AnchoredHead`] and BOTH anchor-proof forms.
/// Returns `None` on any missing/ill-formed field — the caller maps that to
/// [`SinkError::Unreachable`] (fail closed; an untrustworthy head is unusable).
#[cfg(feature = "net")]
fn parse_head_all_proofs(v: &serde_json::Value) -> Option<(AnchoredHead, Vec<AnchorProof>)> {
    let chain_seq = v.get("chain_seq")?.as_u64()?;
    let head = b64_fixed::<32>(v.get("head_b64")?.as_str()?)?;
    let anchored = AnchoredHead { chain_seq, head };

    let cosig = b64_fixed::<64>(v.get("cosig_b64")?.as_str()?)?;

    let t = v.get("transparency")?;
    let checkpoint_sig = b64_fixed::<64>(t.get("checkpoint_sig_b64")?.as_str()?)?;
    let tree_size = t.get("tree_size")?.as_u64()?;
    let root = b64_fixed::<32>(t.get("root_b64")?.as_str()?)?;
    let index = t.get("index")?.as_u64()?;
    let path = t
        .get("path_b64")?
        .as_array()?
        .iter()
        .map(|h| b64_fixed::<32>(h.as_str()?))
        .collect::<Option<Vec<[u8; 32]>>>()?;

    let proofs = vec![
        AnchorProof::CustodianCoSig { sig: cosig },
        AnchorProof::TransparencyInclusion {
            checkpoint_sig,
            tree_size,
            root,
            index,
            path,
        },
    ];
    Some((anchored, proofs))
}

#[cfg(feature = "net")]
impl SinkClient for HttpSinkClient {
    fn fetch_head(&self) -> Result<(AnchoredHead, AnchorProof), SinkError> {
        // Parity with `FakeSink`: return the head + its custodian co-signature
        // form. The caller validates it via `verify_anchor_proof`.
        let (head, proofs) = self.fetch_head_all_proofs()?;
        let cosig = proofs
            .into_iter()
            .find(|p| matches!(p, AnchorProof::CustodianCoSig { .. }))
            .ok_or(SinkError::Unreachable)?;
        Ok((head, cosig))
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
            &[custodian.verifying_key().to_bytes()],
            &[],
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
                &[custodian.verifying_key().to_bytes()],
                &[],
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
                &[other.verifying_key().to_bytes()],
                &[],
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
                &[custodian.verifying_key().to_bytes()],
                &[],
            ),
            Err(SinkError::BadProof)
        );
    }

    // ---- Transparency-log inclusion form (RFC 6962). ----

    /// Build a single-leaf transparency-log tree whose only leaf is `leaf`, and
    /// return its `(tree_size, index, root, path)`. RFC 6962: for a one-leaf tree
    /// the root is the leaf hash `SHA256(0x00 ‖ leaf)` and the audit path is empty.
    fn single_leaf_tree(leaf: &[u8]) -> (u64, u64, [u8; 32], Vec<[u8; 32]>) {
        let mut m = Vec::with_capacity(1 + leaf.len());
        m.push(0x00);
        m.extend_from_slice(leaf);
        (1, 0, maxsecu_crypto::sha256(&m), vec![])
    }

    #[test]
    fn transparency_inclusion_anchor_proof_accepts() {
        let log = SigningKey::generate();
        let head = a_head();
        let (tree_size, index, root, path) = single_leaf_tree(&head_signing_bytes(&head));
        let checkpoint_sig = log.sign_raw(&checkpoint_signing_bytes(tree_size, &root));
        assert!(verify_anchor_proof(
            &head,
            &AnchorProof::TransparencyInclusion {
                checkpoint_sig,
                tree_size,
                root,
                index,
                path,
            },
            &[],
            &[log.verifying_key().to_bytes()],
        )
        .is_ok());
    }

    #[test]
    fn forged_checkpoint_rejected() {
        let log = SigningKey::generate();
        let head = a_head();
        let (tree_size, index, root, path) = single_leaf_tree(&head_signing_bytes(&head));
        let mut checkpoint_sig = log.sign_raw(&checkpoint_signing_bytes(tree_size, &root));
        checkpoint_sig[0] ^= 0x01;
        assert_eq!(
            verify_anchor_proof(
                &head,
                &AnchorProof::TransparencyInclusion {
                    checkpoint_sig,
                    tree_size,
                    root,
                    index,
                    path,
                },
                &[],
                &[log.verifying_key().to_bytes()],
            ),
            Err(SinkError::BadProof)
        );
    }

    #[test]
    fn transparency_proof_rejected_when_no_log_key_pinned() {
        let log = SigningKey::generate();
        let head = a_head();
        let (tree_size, index, root, path) = single_leaf_tree(&head_signing_bytes(&head));
        let checkpoint_sig = log.sign_raw(&checkpoint_signing_bytes(tree_size, &root));
        // Even a perfectly valid proof is rejected when no log key is pinned.
        assert_eq!(
            verify_anchor_proof(
                &head,
                &AnchorProof::TransparencyInclusion {
                    checkpoint_sig,
                    tree_size,
                    root,
                    index,
                    path,
                },
                &[],
                &[],
            ),
            Err(SinkError::BadProof)
        );
    }

    #[test]
    fn transparency_proof_rejected_on_tampered_head() {
        let log = SigningKey::generate();
        let head = a_head();
        let (tree_size, index, root, path) = single_leaf_tree(&head_signing_bytes(&head));
        let checkpoint_sig = log.sign_raw(&checkpoint_signing_bytes(tree_size, &root));
        // Server lies about the head; the inclusion no longer holds under root.
        let mut lied = head;
        lied.head[0] ^= 0x01;
        assert_eq!(
            verify_anchor_proof(
                &lied,
                &AnchorProof::TransparencyInclusion {
                    checkpoint_sig,
                    tree_size,
                    root,
                    index,
                    path,
                },
                &[],
                &[log.verifying_key().to_bytes()],
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
        assert!(verify_anchor_proof(&head, &proof, &[sink.custodian_pub()], &[]).is_ok());
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
        verify_anchor_proof(&head, &proof, &[sink.custodian_pub()], &[]).expect("head trusted");

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
