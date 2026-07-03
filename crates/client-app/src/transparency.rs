//! Directory **key-transparency (KT)** enforcement at the browse/open resolve
//! boundary — trust-alarm C (spec §0-C/§7). This is the CLIENT half of the
//! split-view exit gate: Task 6 publishes every server-signed enrollment binding
//! to the KT log the out-of-band sink produces; this module POLICES that log so a
//! server that equivocates about keys — serves a binding it never logged, or forks
//! the log — is detected and the browse/open fails closed.
//!
//! At the resolve boundary (`commands::feed`/viewer) where a served directory
//! binding is D5-verified for browse/open of ANOTHER user's content, the client
//! ALSO fetches three proofs from the pinned SINK (not the app server): the current
//! KT `checkpoint` (`{tree_size, root, sig}`), an `inclusion` proof for that
//! binding's leaf, and — when a prior checkpoint is persisted — a `consistency`
//! proof. It then runs the shipped
//! [`maxsecu_client_core::transparency::verify_binding_in_log`] gate under the
//! PINNED KT log key(s) + the PERSISTED gossip store. On any [`KtError`] the open
//! is BLOCKED with a `server_untrusted`-class [`UiError`]; on success the gate
//! advances (TOFU-pins) the checkpoint and it is persisted so a later split-view /
//! rollback is detectable across sessions.
//!
//! The KT log key and sink endpoint are PINNED offline ([`crate::config`]) — never
//! trusted from the server. The gossip checkpoint is sealed on disk with an
//! identity-derived key, mirroring [`crate::tofu`]/[`crate::index`].

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use maxsecu_client_core::sink::HttpSinkClient;
use maxsecu_client_core::transparency::{
    verify_binding_in_log, verify_checkpoint_sig, InclusionProof, KtCheckpoint, KtCheckpointStore,
    KtError,
};
use maxsecu_client_core::Identity;
use maxsecu_crypto::merkle::verify_inclusion;

use crate::config::SinkPins;
use crate::error::UiError;

/// Domain-separation label for the KT gossip-store sealing key + AEAD aad. Distinct
/// from the TOFU / search-index labels so the sealed stores use unrelated keys.
const KT_LABEL: &[u8] = b"MaxSecu-kt-checkpoint-v1";

/// A large-but-finite defense-in-depth cap on the KT tree size the index-discovery
/// scan will walk. The primary guard is the checkpoint-signature check (a forged
/// `tree_size` never gets this far); this is a second belt so even a pinned-key
/// checkpoint claiming an absurd size is refused rather than scanned. 2^24 (~16.7M)
/// leaves is far beyond any realistic directory yet bounds the scan.
const MAX_KT_TREE_SIZE: u64 = 1 << 24;

/// The persisted KT **gossip** store: the latest KT checkpoint the client has
/// accepted, sealed on disk under an identity-derived key at
/// `<dir>/kt/checkpoint.kt`. Persisting it across sessions is what makes a
/// cross-session split-view / rollback detectable (the core reads the prior
/// checkpoint and writes an accepted one; this owns the durable backing, mirroring
/// [`crate::tofu::TofuStore`]).
pub struct DiskKtCheckpointStore {
    path: PathBuf,
    /// The identity-derived AEAD sealing key (zeroized on drop).
    key: Zeroizing<[u8; 32]>,
    /// The latest accepted checkpoint (in-RAM; flushed by [`Self::persist`]).
    latest: Option<KtCheckpoint>,
}

/// On-disk (pre-seal) shape: the checkpoint fields, hex-encoded for a stable,
/// debuggable serialization (mirrors [`crate::tofu`]'s hex form).
#[derive(Debug, Serialize, Deserialize)]
struct CheckpointOnDisk {
    tree_size: u64,
    root_hex: String,
    sig_hex: String,
}

impl DiskKtCheckpointStore {
    /// Open (load + decrypt) the sealed gossip store under `<dir>/kt/checkpoint.kt`,
    /// or an empty store (no pinned checkpoint yet) if absent. Fails closed
    /// (`server_untrusted`) on a decrypt/parse error (corrupt, or written by a
    /// foreign identity) — never silently discards a pinned checkpoint.
    pub fn open(dir: &Path, identity: &Identity) -> Result<Self, UiError> {
        let key = seal_key(identity);
        let path = dir.join("kt").join("checkpoint.kt");
        let latest = match std::fs::read(&path) {
            Ok(sealed) => Some(decrypt_checkpoint(&key, &sealed)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => {
                return Err(UiError::new(
                    "server_untrusted",
                    "The key-transparency store could not be read.",
                ))
            }
        };
        Ok(DiskKtCheckpointStore { path, key, latest })
    }

    /// Persist the current accepted checkpoint to disk (a no-op when none is
    /// pinned). **Atomic replace** (mirrors [`crate::tofu`]/`keystore`): seal into a
    /// sibling `.tmp`, `sync_all`, then `rename` over the live path, so a crash
    /// mid-write leaves the OLD sealed checkpoint intact — never a torn file that
    /// would fail-closed on the next `open`.
    pub fn persist(&self) -> Result<(), UiError> {
        let cp = match self.latest {
            Some(cp) => cp,
            None => return Ok(()),
        };
        let dir = self.path.parent().ok_or_else(untrusted_write)?;
        std::fs::create_dir_all(dir).map_err(|_| untrusted_write())?;
        let on_disk = CheckpointOnDisk {
            tree_size: cp.tree_size,
            root_hex: hex(&cp.root),
            sig_hex: hex(&cp.sig),
        };
        let plain = serde_json::to_vec(&on_disk).map_err(|_| untrusted_write())?;
        let nonce = maxsecu_crypto::random_array::<12>();
        let ct = maxsecu_crypto::seal(&self.key, &nonce, KT_LABEL, &plain);
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);

        let tmp = self.path.with_extension("kt.tmp");
        {
            let mut f = std::fs::File::create(&tmp).map_err(|_| untrusted_write())?;
            std::io::Write::write_all(&mut f, &out).map_err(|_| untrusted_write())?;
            f.sync_all().map_err(|_| untrusted_write())?;
        }
        std::fs::rename(&tmp, &self.path).map_err(|_| untrusted_write())
    }
}

impl KtCheckpointStore for DiskKtCheckpointStore {
    fn latest(&self) -> Option<KtCheckpoint> {
        self.latest
    }
    /// Advance the in-RAM gossip state. The durable flush is an explicit
    /// [`Self::persist`] the caller runs ONLY after the full verify succeeds — so a
    /// checkpoint that passed its own signature/consistency checks but failed the
    /// inclusion check is never written (and the trait's fallible-free `update`
    /// signature is respected).
    fn update(&mut self, cp: KtCheckpoint) {
        self.latest = Some(cp);
    }
}

/// Enforce trust-alarm C for a served `binding_bytes` (the canonical `DirBinding`
/// leaf) against the directory KT log the pinned `pins` sink produces, under the
/// pinned `log_pubs` KT key(s) and the persisted gossip `store` (spec §0-C/§7).
///
/// Fetches the current checkpoint + (if a prior checkpoint is persisted) a
/// consistency proof, DISCOVERS the binding's leaf index by scanning inclusion
/// proofs against the checkpoint root, then runs the authoritative
/// [`verify_binding_in_log`] gate (which re-checks the checkpoint signature under
/// the pinned key, consistency/split-view/rollback vs. the persisted gossip, AND
/// inclusion — the scan only locates the index; nothing is trusted from it). On
/// success the gossip store advances and is persisted; on ANY [`KtError`] the
/// action is BLOCKED with a `server_untrusted` [`UiError`].
///
/// **Blocking.** [`HttpSinkClient`] runs each request on its own current-thread
/// runtime, so call this from a sync/blocking context (e.g. `spawn_blocking`) —
/// never directly inside an async task, else the nested runtime panics.
pub fn verify_binding_transparency(
    pins: &SinkPins,
    log_pubs: &[[u8; 32]],
    store: &mut DiskKtCheckpointStore,
    binding_bytes: &[u8],
) -> Result<(), UiError> {
    let client = HttpSinkClient::new(pins.addr, pins.server_name.clone(), pins.tls.clone());
    let checkpoint = client.fetch_kt_checkpoint().map_err(|_| sink_unreachable())?;

    // GUARD: verify the checkpoint signature under the PINNED KT key BEFORE trusting
    // any of its sink-controlled fields — notably `tree_size`, which bounds the
    // index-discovery scan below. A checkpoint not signed by a pinned key is a
    // forged/equivocating head (exactly the actor KT defends against): reject it
    // immediately as `server_untrusted`, with NO scan, so a forged `tree_size` can
    // never drive an unbounded sequence of inclusion fetches (a DoS). The
    // authoritative `verify_binding_in_log` still runs afterward as the real gate.
    if !verify_checkpoint_sig(&checkpoint, log_pubs) {
        return Err(block_transparency(KtError::BadCheckpoint));
    }
    // Defense-in-depth: refuse even a validly-signed checkpoint whose tree size
    // exceeds a sane finite cap (the scan is O(tree_size) sink round-trips).
    if checkpoint.tree_size > MAX_KT_TREE_SIZE {
        return Err(block_transparency(KtError::NotIncluded));
    }

    // The consistency proof is prev→current; empty when there is no prior pinned
    // checkpoint (first use) or the tree size is not strictly larger (§7.4). When
    // `prev.tree_size > checkpoint.tree_size` (a ROLLBACK) we must NOT ask the sink
    // for a `from` it cannot answer — that would surface as `sink_unreachable` and
    // shadow the real `Regression` verdict; pass an EMPTY proof through so
    // `verify_binding_in_log` reaches its rollback branch and blocks as
    // `server_untrusted`.
    let from = store.latest().map(|c| c.tree_size).unwrap_or(0);
    let consistency = if from != 0 && from < checkpoint.tree_size {
        client.fetch_kt_consistency(from).map_err(|_| sink_unreachable())?
    } else {
        Vec::new()
    };

    // Discover the binding's leaf index (the log exposes proofs by index, not by
    // binding). A non-match yields a placeholder inclusion so the authoritative
    // gate below still runs the checkpoint-signature + consistency checks and then
    // fails closed as `NotIncluded` for an absent binding.
    let inclusion = discover_inclusion(&client, &checkpoint, binding_bytes).unwrap_or(
        InclusionProof {
            index: 0,
            tree_size: checkpoint.tree_size,
            path: Vec::new(),
        },
    );

    verify_binding_in_log(
        binding_bytes,
        &inclusion,
        &checkpoint,
        &consistency,
        log_pubs,
        store,
    )
    .map_err(block_transparency)?;

    // Success: TOFU-pin/advance the gossip checkpoint durably.
    store.persist()
}

/// Locate the leaf index whose inclusion proof binds `binding_bytes` under the
/// checkpoint root, by scanning the (bounded) tree. The proof itself is verified
/// with the REAL `merkle::verify_inclusion` (client-core), so a wrong index / bad
/// path never matches. Returns `None` if no leaf in the tree matches (the binding
/// is absent). O(tree_size) sink round-trips — acceptable for the in-repo log; a
/// production deployment would carry an (untrusted, inclusion-checked) index hint.
fn discover_inclusion(
    client: &HttpSinkClient,
    checkpoint: &KtCheckpoint,
    binding_bytes: &[u8],
) -> Option<InclusionProof> {
    for index in 0..checkpoint.tree_size {
        if let Ok(inc) = client.fetch_kt_inclusion(index) {
            if inc.tree_size == checkpoint.tree_size
                && verify_inclusion(
                    binding_bytes,
                    inc.index,
                    inc.tree_size,
                    &inc.path,
                    checkpoint.root,
                )
            {
                return Some(inc);
            }
        }
    }
    None
}

/// Map any [`KtError`] to the fail-closed trust-alarm-C surface. Every KT failure
/// (bad checkpoint / split-view / rollback / not-included) means the server
/// equivocated about keys, so all render as one `server_untrusted` block — the
/// stable code T13's shared trust-alarm modal keys off (alarm-C,
/// [`crate::recovery_pin::TrustAlarm::TransparencyFailure`]), exactly as alarms A/B
/// surface via their own `server_untrusted` codes.
fn block_transparency(_e: KtError) -> UiError {
    UiError::new(
        "server_untrusted",
        "This server failed key-transparency verification; the item was blocked.",
    )
}

fn sink_unreachable() -> UiError {
    UiError::new(
        "sink_unreachable",
        "The key-transparency log could not be fetched.",
    )
}

/// Derive the 32-byte KT-store sealing key from the unlocked identity (a stable TCB
/// secret), domain-separated so it is unrelated to any wrap / index / TOFU key.
fn seal_key(identity: &Identity) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(maxsecu_crypto::hkdf_sha256_32(
        &identity.enc_secret().expose_bytes(),
        KT_LABEL,
    ))
}

/// Decrypt + decode a sealed `nonce ‖ ct` blob into the in-RAM checkpoint.
fn decrypt_checkpoint(key: &[u8; 32], sealed: &[u8]) -> Result<KtCheckpoint, UiError> {
    let untrusted = || {
        UiError::new(
            "server_untrusted",
            "The key-transparency store is corrupt.",
        )
    };
    if sealed.len() < 12 {
        return Err(untrusted());
    }
    let (nonce_bytes, ct) = sealed.split_at(12);
    let nonce: [u8; 12] = nonce_bytes.try_into().map_err(|_| untrusted())?;
    let plain = maxsecu_crypto::open(key, &nonce, KT_LABEL, ct).map_err(|_| untrusted())?;
    let on_disk: CheckpointOnDisk = serde_json::from_slice(&plain).map_err(|_| untrusted())?;
    Ok(KtCheckpoint {
        tree_size: on_disk.tree_size,
        root: unhex::<32>(&on_disk.root_hex).ok_or_else(untrusted)?,
        sig: unhex::<64>(&on_disk.sig_hex).ok_or_else(untrusted)?,
    })
}

fn untrusted_write() -> UiError {
    UiError::new(
        "server_untrusted",
        "The key-transparency store could not be written.",
    )
}

/// Lowercase hex of a byte slice (on-disk form).
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Parse `2*N` lowercase-hex chars into an `N`-byte array (`None` if malformed).
fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "mxktstore_{}_{}",
            std::process::id(),
            hex(&maxsecu_crypto::random_array::<8>())
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    fn cp(tree_size: u64, seed: u8) -> KtCheckpoint {
        KtCheckpoint {
            tree_size,
            root: [seed; 32],
            sig: [seed ^ 0xFF; 64],
        }
    }

    #[test]
    fn store_persists_checkpoint_across_reopen_and_is_sealed() {
        let dir = tmp_dir();
        let id = Identity::generate();
        {
            let mut store = DiskKtCheckpointStore::open(&dir, &id).unwrap();
            assert!(store.latest().is_none(), "empty on first open");
            store.update(cp(3, 0xAB));
            store.persist().unwrap();
        }
        // On-disk bytes must not contain the plaintext hex (it is sealed).
        let raw = std::fs::read(dir.join("kt").join("checkpoint.kt")).unwrap();
        let hex_root = hex(&[0xABu8; 32]);
        assert!(
            !raw.windows(hex_root.len()).any(|w| w == hex_root.as_bytes()),
            "checkpoint is sealed (no plaintext root)"
        );

        // Reopen with the SAME identity sees the persisted checkpoint.
        let reopened = DiskKtCheckpointStore::open(&dir, &id).unwrap();
        assert_eq!(reopened.latest(), Some(cp(3, 0xAB)));

        // A DIFFERENT identity cannot read the sealed store (fails closed).
        let other = Identity::generate();
        assert_eq!(
            DiskKtCheckpointStore::open(&dir, &other).err().unwrap().code,
            "server_untrusted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_store_fails_closed_on_open() {
        let dir = tmp_dir();
        let id = Identity::generate();
        let kt = dir.join("kt");
        std::fs::create_dir_all(&kt).unwrap();
        std::fs::write(kt.join("checkpoint.kt"), b"not-a-sealed-blob").unwrap();
        assert_eq!(
            DiskKtCheckpointStore::open(&dir, &id).err().unwrap().code,
            "server_untrusted"
        );
        // Too short for even the nonce → also fail-closed.
        std::fs::write(kt.join("checkpoint.kt"), b"short").unwrap();
        assert_eq!(
            DiskKtCheckpointStore::open(&dir, &id).err().unwrap().code,
            "server_untrusted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kt_errors_all_block_as_server_untrusted() {
        for e in [
            KtError::BadCheckpoint,
            KtError::NotIncluded,
            KtError::SplitView,
            KtError::Regression,
        ] {
            assert_eq!(block_transparency(e).code, "server_untrusted");
        }
    }
}
