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

use maxsecu_crypto::{wrap_dek, Dek, EncPublicKey, SigningKey, WrappedDek};
use maxsecu_encoding::labels;
use maxsecu_encoding::structs::{Grant, WrapContext};
use maxsecu_encoding::types::{Bytes32, Id, RecipientType, Timestamp};

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

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_crypto::{generate_enc_keypair, unwrap_dek};

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
