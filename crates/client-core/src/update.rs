//! Client-side verification of **signed + transparency-logged software updates**
//! (DESIGN §8 / D1, stack §1.5).
//!
//! Before a client applies an update it must establish, fail-closed at each step,
//! that the update is: (1) **not a downgrade** (it advances the version and its
//! `min_version` admits the running build), (2) the **artifact it downloaded**
//! hashes to the manifest's pinned `artifact_sha256`, (3) **signed by a pinned
//! release key**, and (4) **included in an append-only transparency log** (a
//! log-signed checkpoint plus a Merkle inclusion proof of the manifest leaf), so a
//! targeted/backdoored build cannot be served to a single victim without also
//! appearing in the public log.
//!
//! This is the pure VERIFICATION logic only — no I/O. The actual download/apply
//! and the OS Authenticode check live in the runbook layer (a later increment).
//! The transparency proof reuses the RFC 6962 [`merkle`](maxsecu_crypto::merkle)
//! primitive (P6.2) and the checkpoint signing bytes of the sink (P6.3).

use maxsecu_crypto::VerifyingKey;
use maxsecu_encoding::{labels, signing_input, sink_checkpoint_signing_input};

/// A software-update descriptor (DESIGN §8): the target `version`, the minimum
/// prior version permitted to take this update (`min_version`), and the SHA-256 of
/// the update artifact the manifest authorizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdateManifest {
    pub version: u64,
    pub min_version: u64,
    pub artifact_sha256: [u8; 32],
}

/// The transparency-log inclusion proof for a manifest: a log-signed checkpoint
/// `{tree_size, root}` plus the RFC 6962 audit `path` showing the manifest's
/// signing bytes are the `index`-th leaf under `root`.
#[derive(Debug, Clone)]
pub struct LogInclusion {
    /// The log's Ed25519 signature over the checkpoint bytes
    /// (`sink_checkpoint_signing_input(tree_size, root)`).
    pub checkpoint_sig: [u8; 64],
    pub tree_size: u64,
    pub root: [u8; 32],
    pub index: u64,
    pub path: Vec<[u8; 32]>,
}

/// Why an update was refused. Each variant corresponds to one fail-closed check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateError {
    /// The manifest does not advance the version, or its `min_version` excludes
    /// the currently running build.
    Downgrade,
    /// No pinned release key verifies the manifest signature.
    BadSignature,
    /// The transparency-log proof failed (bad checkpoint signature or the manifest
    /// leaf is not included under the checkpoint root) — the update is not logged.
    NotLogged,
    /// The downloaded artifact's hash does not match the manifest.
    ArtifactMismatch,
}

/// A successfully verified update — carries the version a caller may now apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    pub version: u64,
}

/// The exact bytes a release key signs for a manifest: the domain-framed,
/// fixed-width `version (8 BE) ‖ min_version (8 BE) ‖ artifact_sha256 (32)` under
/// [`labels::UPDATE_MANIFEST`]. This is ALSO the transparency-log leaf value, so
/// the release signer, the log, and this verifier all construct identical bytes.
fn manifest_signing_bytes(m: &UpdateManifest) -> Vec<u8> {
    let mut body = [0u8; 48];
    body[..8].copy_from_slice(&m.version.to_be_bytes());
    body[8..16].copy_from_slice(&m.min_version.to_be_bytes());
    body[16..].copy_from_slice(&m.artifact_sha256);
    signing_input(labels::UPDATE_MANIFEST, &body)
}

/// Does any pinned key strictly verify `sig` over `msg`? An empty allowlist never
/// validates (mirrors the sink's `any_key_verifies`).
fn any_key_verifies(pubs: &[[u8; 32]], msg: &[u8], sig: &[u8; 64]) -> bool {
    pubs.iter().any(|pk| {
        VerifyingKey::from_bytes(pk)
            .and_then(|vk| vk.verify_raw(msg, sig))
            .is_ok()
    })
}

/// Verify a software update before it is applied (DESIGN §8). Fail-closed at each
/// step, in order:
///
/// 1. **Downgrade:** require `manifest.version > current_version` AND
///    `current_version >= manifest.min_version`, else [`UpdateError::Downgrade`].
/// 2. **ArtifactMismatch:** the downloaded `artifact_sha256` must equal the
///    manifest's, else [`UpdateError::ArtifactMismatch`].
/// 3. **BadSignature:** some pinned `release_pubs` key must verify `manifest_sig`
///    over [`manifest_signing_bytes`], else [`UpdateError::BadSignature`]
///    (empty `release_pubs` ⇒ never validates).
/// 4. **NotLogged:** some pinned `log_pubs` key must verify the checkpoint
///    signature AND the manifest leaf must be Merkle-included under the checkpoint
///    root, else [`UpdateError::NotLogged`] (empty `log_pubs` ⇒ never validates).
///
/// The transparency-log key is pinned INDEPENDENTLY of the sink's control-log key:
/// the checkpoint *structure* is shared (so we reuse
/// [`sink_checkpoint_signing_input`]), but the update log is a distinct trust
/// domain. On success returns the version the caller may apply.
#[allow(clippy::too_many_arguments)]
pub fn verify_update(
    manifest: &UpdateManifest,
    manifest_sig: [u8; 64],
    inclusion: &LogInclusion,
    release_pubs: &[[u8; 32]],
    log_pubs: &[[u8; 32]],
    current_version: u64,
    artifact_sha256: [u8; 32],
) -> Result<Verified, UpdateError> {
    // 1. Downgrade: must advance the version and admit the running build.
    if manifest.version <= current_version || current_version < manifest.min_version {
        return Err(UpdateError::Downgrade);
    }

    // 2. ArtifactMismatch: the bytes we actually downloaded must match the manifest.
    if artifact_sha256 != manifest.artifact_sha256 {
        return Err(UpdateError::ArtifactMismatch);
    }

    let leaf = manifest_signing_bytes(manifest);

    // 3. BadSignature: a pinned release key signs the manifest.
    if !any_key_verifies(release_pubs, &leaf, &manifest_sig) {
        return Err(UpdateError::BadSignature);
    }

    // 4. NotLogged: a pinned log key signs the checkpoint AND the manifest leaf is
    // included under the checkpoint root. The update log key is pinned separately
    // from the sink's control-log key (distinct trust domain, shared structure).
    let logged = any_key_verifies(
        log_pubs,
        &sink_checkpoint_signing_input(inclusion.tree_size, &inclusion.root),
        &inclusion.checkpoint_sig,
    ) && maxsecu_crypto::merkle::verify_inclusion(
        &leaf,
        inclusion.index,
        inclusion.tree_size,
        &inclusion.path,
        inclusion.root,
    );
    if !logged {
        return Err(UpdateError::NotLogged);
    }

    Ok(Verified {
        version: manifest.version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_crypto::merkle::{inclusion_path, merkle_root};
    use maxsecu_crypto::SigningKey;

    const ART: [u8; 32] = [0x11; 32];

    fn manifest() -> UpdateManifest {
        UpdateManifest {
            version: 5,
            min_version: 3,
            artifact_sha256: ART,
        }
    }

    /// Build a transparency tree with `manifest_signing_bytes(m)` placed at `index`
    /// among `n_leaves` total, returning a signed-and-included [`LogInclusion`].
    fn log_inclusion(log: &SigningKey, m: &UpdateManifest, index: usize, n_leaves: usize) -> LogInclusion {
        let leaf = manifest_signing_bytes(m);
        let mut leaves: Vec<Vec<u8>> = (0..n_leaves)
            .map(|i| format!("other-leaf-{i}").into_bytes())
            .collect();
        leaves[index] = leaf;
        let root = merkle_root(&leaves);
        let path = inclusion_path(index, &leaves);
        let checkpoint_sig = log.sign_raw(&sink_checkpoint_signing_input(n_leaves as u64, &root));
        LogInclusion {
            checkpoint_sig,
            tree_size: n_leaves as u64,
            root,
            index: index as u64,
            path,
        }
    }

    #[test]
    fn valid_signed_logged_update_accepts() {
        let release = SigningKey::generate();
        let log = SigningKey::generate();
        let m = manifest();
        let manifest_sig = release.sign_raw(&manifest_signing_bytes(&m));
        // A multi-leaf tree exercises a non-empty audit path.
        let incl = log_inclusion(&log, &m, 2, 5);
        assert_eq!(
            verify_update(
                &m,
                manifest_sig,
                &incl,
                &[release.verifying_key().to_bytes()],
                &[log.verifying_key().to_bytes()],
                4,
                ART,
            ),
            Ok(Verified { version: 5 })
        );
    }

    #[test]
    fn downgrade_rejected() {
        let release = SigningKey::generate();
        let log = SigningKey::generate();
        let m = manifest();
        let manifest_sig = release.sign_raw(&manifest_signing_bytes(&m));
        let incl = log_inclusion(&log, &m, 0, 1);
        let rp = [release.verifying_key().to_bytes()];
        let lp = [log.verifying_key().to_bytes()];

        // version (5) <= current (5): not advancing → Downgrade.
        assert_eq!(
            verify_update(&m, manifest_sig, &incl, &rp, &lp, 5, ART),
            Err(UpdateError::Downgrade)
        );
        // version (5) < current (6): a rollback → Downgrade.
        assert_eq!(
            verify_update(&m, manifest_sig, &incl, &rp, &lp, 6, ART),
            Err(UpdateError::Downgrade)
        );
        // current (2) < min_version (3): the running build is excluded → Downgrade.
        assert_eq!(
            verify_update(&m, manifest_sig, &incl, &rp, &lp, 2, ART),
            Err(UpdateError::Downgrade)
        );
    }

    #[test]
    fn unsigned_or_forged_update_rejected() {
        let release = SigningKey::generate();
        let other = SigningKey::generate();
        let log = SigningKey::generate();
        let m = manifest();
        let incl = log_inclusion(&log, &m, 0, 1);
        let lp = [log.verifying_key().to_bytes()];

        // Flip a manifest-sig byte → BadSignature.
        let mut bad_sig = release.sign_raw(&manifest_signing_bytes(&m));
        bad_sig[0] ^= 0x01;
        assert_eq!(
            verify_update(&m, bad_sig, &incl, &[release.verifying_key().to_bytes()], &lp, 4, ART),
            Err(UpdateError::BadSignature)
        );

        // A valid signature but a different pinned release key → BadSignature.
        let good_sig = release.sign_raw(&manifest_signing_bytes(&m));
        assert_eq!(
            verify_update(&m, good_sig, &incl, &[other.verifying_key().to_bytes()], &lp, 4, ART),
            Err(UpdateError::BadSignature)
        );

        // Empty release allowlist → BadSignature.
        assert_eq!(
            verify_update(&m, good_sig, &incl, &[], &lp, 4, ART),
            Err(UpdateError::BadSignature)
        );
    }

    #[test]
    fn update_without_transparency_inclusion_rejected() {
        let release = SigningKey::generate();
        let log = SigningKey::generate();
        let m = manifest();
        let manifest_sig = release.sign_raw(&manifest_signing_bytes(&m));
        let rp = [release.verifying_key().to_bytes()];
        let lp = [log.verifying_key().to_bytes()];

        // Flip a checkpoint-sig byte → NotLogged.
        let mut incl = log_inclusion(&log, &m, 2, 5);
        incl.checkpoint_sig[0] ^= 0x01;
        assert_eq!(
            verify_update(&m, manifest_sig, &incl, &rp, &lp, 4, ART),
            Err(UpdateError::NotLogged)
        );

        // Tamper an inclusion-path entry → NotLogged.
        let mut incl = log_inclusion(&log, &m, 2, 5);
        incl.path[0][0] ^= 0x01;
        assert_eq!(
            verify_update(&m, manifest_sig, &incl, &rp, &lp, 4, ART),
            Err(UpdateError::NotLogged)
        );

        // Empty log allowlist → NotLogged, even with an otherwise valid proof.
        let incl = log_inclusion(&log, &m, 2, 5);
        assert_eq!(
            verify_update(&m, manifest_sig, &incl, &rp, &[], 4, ART),
            Err(UpdateError::NotLogged)
        );
    }

    #[test]
    fn artifact_hash_mismatch_rejected() {
        let release = SigningKey::generate();
        let log = SigningKey::generate();
        let m = manifest();
        let manifest_sig = release.sign_raw(&manifest_signing_bytes(&m));
        let incl = log_inclusion(&log, &m, 0, 1);
        // The bytes actually downloaded hash to something other than the manifest.
        let downloaded = [0x22; 32];
        assert_eq!(
            verify_update(
                &m,
                manifest_sig,
                &incl,
                &[release.verifying_key().to_bytes()],
                &[log.verifying_key().to_bytes()],
                4,
                downloaded,
            ),
            Err(UpdateError::ArtifactMismatch)
        );
    }
}
