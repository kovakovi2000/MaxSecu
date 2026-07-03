//! Offline recovery-key grant issuance (DESIGN §12.7) — the fallback used only
//! when **no current recipient remains** to perform an online re-share (§12.4b).
//!
//! On the air-gapped recovery device the admin unwraps the current DEK with
//! `recovery_priv`, checks it against the manifest `dek_commit`, then re-wraps it
//! to the new recipient's directory-verified `enc_pub` and signs a **recovery-
//! operator grant** with the admin's *own* `sig` key (`granted_by = admin_id`).
//! Only the resulting ciphertext + grant cross the air gap; `recovery_priv` never
//! touches a networked machine. The grant is honored for **this** version on
//! download but is **not** carry-forward-eligible (R24, §12.3a/§12.9) — that
//! exclusion lives in the rotation carry-forward selection, not here.

use maxsecu_crypto::{unwrap_dek, wrap_dek, Dek, EncPublicKey, EncSecretKey, SigningKey, WrappedDek};
use maxsecu_encoding::labels;
use maxsecu_encoding::structs::{Grant, WrapContext};
use maxsecu_encoding::types::{Bytes32, Id, RecipientType, Timestamp};
use maxsecu_encoding::RECOVERY_ID;

/// Inputs for a recovery-operator grant (§12.7 steps 3–5). The admin has already
/// unwrapped `dek` with `recovery_priv` on the air-gapped device.
pub struct RecoveryGrantParams<'a> {
    /// The admin's own signing key (signs the grant; `granted_by = admin_id`).
    pub admin_sig: &'a SigningKey,
    pub admin_id: Id,
    pub file_id: Id,
    pub version: u64,
    /// The manifest key commitment — the DEK is re-checked against it (§12.3).
    pub dek_commit: [u8; 32],
    pub recipient_id: Id,
    pub recipient_enc_pub: EncPublicKey,
    pub created_at: Timestamp,
}

/// The wrap + signed grant the recovery ceremony emits for the new recipient.
pub struct RecoveryGrantOut {
    pub recipient_id: Id,
    pub wrapped_dek: WrappedDek,
    pub grant: Grant,
    pub grant_sig: [u8; 64],
}

/// A recovery-key grant could not be issued — a refusal, fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryError {
    /// The unwrapped DEK does not match the manifest `dek_commit` (§12.7 step 3)
    /// — the recovery operator does not actually hold this version's key.
    DekCommitMismatch,
    /// The HPKE wrap to the recipient failed (malformed recipient key).
    WrapFailed,
}

/// Issue a recovery-operator read grant for `dek` (already unwrapped with
/// `recovery_priv`). Re-checks the DEK against `dek_commit`, re-wraps it to the
/// recipient's `enc_pub` with the context-bound `info` (§5), and signs the grant
/// under the admin's `sig` key. The recipient gets a *real, openable* wrap, so
/// its access is self-validating on download (§12.5 step 6).
pub fn build_recovery_grant(
    params: &RecoveryGrantParams,
    dek: &Dek,
) -> Result<RecoveryGrantOut, RecoveryError> {
    use RecoveryError::*;

    // (3) Possession: the admin must hold the committed DEK, else the wrap would
    // not open to the value downloaders expect.
    if dek.commit() != params.dek_commit {
        return Err(DekCommitMismatch);
    }

    // (4) Re-wrap the DEK to the new recipient's directory-verified `enc_pub`.
    let ctx = WrapContext {
        file_id: params.file_id,
        version: params.version,
        recipient_id: params.recipient_id,
    };
    let wrapped_dek = wrap_dek(&params.recipient_enc_pub, dek, &ctx).map_err(|_| WrapFailed)?;

    // (5) Sign a recovery-operator grant rooted at the admin (granted_by = admin).
    let grant = Grant {
        file_id: params.file_id,
        file_version: params.version,
        recipient_id: params.recipient_id,
        recipient_type: RecipientType::User,
        dek_commit: Bytes32(params.dek_commit),
        granted_by: params.admin_id,
        created_at: params.created_at,
    };
    let grant_sig = params.admin_sig.sign_canonical(labels::GRANT, &grant);

    Ok(RecoveryGrantOut {
        recipient_id: params.recipient_id,
        wrapped_dek,
        grant,
        grant_sig,
    })
}

// ---- Offline recovery-wrap validation sweep (DESIGN §16.1 / D27 / R26) ----
//
// The downloader-side recovery check only proves the author *signed a grant*
// over the right `dek_commit` (§12.5) — it cannot prove the recovery *wrap
// ciphertext* actually opens to that DEK, because only `recovery_priv` can open
// it. A malicious writer could therefore sign a valid grant yet upload a bad
// wrap, silently breaking recoverability. This offline check, run on the
// air-gapped recovery device, confirms each wrap really decrypts to its
// committed DEK.

/// Identifies the file-version whose recovery wrap is under test (carried into
/// the [`SweepReport`] for any failing sample).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryWrapCtx {
    pub file_id: Id,
    pub version: u64,
}

/// A recovery wrap failed offline validation — a fail-closed finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SweepError {
    /// HPKE-open with `recovery_priv` failed — wrong/corrupt ciphertext or a
    /// wrap that is not bound to this file-version's recovery context.
    WrapUndecryptable,
    /// The wrap opened, but the recovered DEK does not match the committed
    /// `dek_commit` — the writer wrapped a DEK other than the manifest's.
    WrapMismatch,
}

/// Offline-validate one recovery wrap with the recovery private key.
///
/// HPKE-opens `wrap` (the wire form `enc(32) ‖ ct`) under the SAME context the
/// upload path bound it to — `(file_id, version, recipient_id = RECOVERY_ID)`
/// (§5 / `upload::wrap_and_grant`) — then re-derives `dek_commit'` from the
/// recovered DEK and checks it against the committed value. An open failure maps
/// to [`SweepError::WrapUndecryptable`]; a commitment mismatch to
/// [`SweepError::WrapMismatch`].
pub fn validate_recovery_wrap(
    recovery_priv: &EncSecretKey,
    wrap: &[u8],
    dek_commit: [u8; 32],
    ctx: &RecoveryWrapCtx,
) -> Result<(), SweepError> {
    use SweepError::*;

    // Split the wire wrap `enc(32) ‖ ct`; a runt that cannot carry the 32-byte
    // encapsulated key is unopenable by definition.
    if wrap.len() < 32 {
        return Err(WrapUndecryptable);
    }
    let mut enc = [0u8; 32];
    enc.copy_from_slice(&wrap[..32]);
    let wrapped = WrappedDek {
        enc,
        ct: wrap[32..].to_vec(),
    };

    // The recovery wrap is bound to RECOVERY_ID, exactly as the upload/rotate
    // path wrapped it — a different context here would itself fail the open.
    let wrap_ctx = WrapContext {
        file_id: ctx.file_id,
        version: ctx.version,
        recipient_id: RECOVERY_ID,
    };
    let dek = unwrap_dek(recovery_priv, &wrapped, &wrap_ctx).map_err(|_| WrapUndecryptable)?;

    // Recompute the commitment from the recovered DEK and compare. The commit is
    // a public value, so a plain byte compare suffices (mirrors §12.7 step 3).
    if dek.commit() != dek_commit {
        return Err(WrapMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_crypto::{generate_enc_keypair, unwrap_dek};

    /// Build the wire recovery wrap `enc(32) ‖ ct` exactly as the upload path
    /// does: `wrap_dek` to the recovery key under the RECOVERY_ID-bound context.
    fn recovery_wire_wrap(rpk: &EncPublicKey, dek: &Dek, file_id: Id, version: u64) -> Vec<u8> {
        let ctx = WrapContext {
            file_id,
            version,
            recipient_id: RECOVERY_ID,
        };
        let w = wrap_dek(rpk, dek, &ctx).unwrap();
        let mut wire = w.enc.to_vec();
        wire.extend_from_slice(&w.ct);
        wire
    }

    #[test]
    fn good_recovery_wrap_passes() {
        let (rsk, rpk) = generate_enc_keypair();
        let dek = Dek::generate();
        let wire = recovery_wire_wrap(&rpk, &dek, FILE, 3);
        assert_eq!(
            validate_recovery_wrap(&rsk, &wire, dek.commit(), &RecoveryWrapCtx { file_id: FILE, version: 3 }),
            Ok(())
        );
    }

    #[test]
    fn bad_recovery_wrap_is_caught() {
        let (rsk, rpk) = generate_enc_keypair();
        let dek = Dek::generate();
        let other = Dek::generate();

        // A valid HPKE wrap of a DIFFERENT DEK against the committed value: the
        // wrap opens, but the recovered DEK does not match → WrapMismatch.
        let wrong = recovery_wire_wrap(&rpk, &other, FILE, 3);
        assert_eq!(
            validate_recovery_wrap(&rsk, &wrong, dek.commit(), &RecoveryWrapCtx { file_id: FILE, version: 3 }),
            Err(SweepError::WrapMismatch)
        );

        // A corrupted ciphertext cannot open at all → WrapUndecryptable.
        let mut corrupt = recovery_wire_wrap(&rpk, &dek, FILE, 3);
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0x01;
        assert_eq!(
            validate_recovery_wrap(&rsk, &corrupt, dek.commit(), &RecoveryWrapCtx { file_id: FILE, version: 3 }),
            Err(SweepError::WrapUndecryptable)
        );
    }

    const ADMIN_ID: Id = Id([0xAD; 16]);
    const FILE: Id = Id([0xF1; 16]);
    const RECIP: Id = Id([0x55; 16]);
    const NOW: Timestamp = Timestamp(1_719_500_000_000);

    fn params<'a>(admin: &'a SigningKey, enc_pub: EncPublicKey, commit: [u8; 32]) -> RecoveryGrantParams<'a> {
        RecoveryGrantParams {
            admin_sig: admin,
            admin_id: ADMIN_ID,
            file_id: FILE,
            version: 3,
            dek_commit: commit,
            recipient_id: RECIP,
            recipient_enc_pub: enc_pub,
            created_at: NOW,
        }
    }

    #[test]
    fn recovery_grant_round_trips() {
        let admin = SigningKey::generate();
        let dek = Dek::generate();
        let (rsk, rpk) = generate_enc_keypair();

        let out = build_recovery_grant(&params(&admin, rpk, dek.commit()), &dek).unwrap();

        // The produced wrap re-opens to the same DEK under the bound context.
        let ctx = WrapContext { file_id: FILE, version: 3, recipient_id: RECIP };
        let opened = unwrap_dek(&rsk, &out.wrapped_dek, &ctx).unwrap();
        assert_eq!(opened.commit(), dek.commit());

        // The grant verifies under the admin's sig key and is admin-rooted.
        assert!(admin
            .verifying_key()
            .verify_canonical(labels::GRANT, &out.grant, &out.grant_sig)
            .is_ok());
        assert_eq!(out.grant.granted_by, ADMIN_ID);
        assert_eq!(out.grant.recipient_type, RecipientType::User);
        assert_eq!(out.grant.dek_commit, Bytes32(dek.commit()));
    }

    #[test]
    fn recovery_grant_rejects_a_dek_mismatch() {
        let admin = SigningKey::generate();
        let dek = Dek::generate();
        let other = Dek::generate();
        let (_rsk, rpk) = generate_enc_keypair();
        // The manifest commits to `other`, but the admin holds `dek` → refuse.
        assert!(matches!(
            build_recovery_grant(&params(&admin, rpk, other.commit()), &dek),
            Err(RecoveryError::DekCommitMismatch)
        ));
    }
}
