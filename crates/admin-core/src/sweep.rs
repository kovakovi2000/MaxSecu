//! Offline recovery-wrap validation sweep driver (DESIGN §16.1 / D27 / R26).
//!
//! A thin, pure loop over [`validate_recovery_wrap`]: it runs the offline check
//! across a batch of recovery-wrap samples (gathered for the air-gapped recovery
//! device) and reports every file-version whose wrap does not open to its
//! committed DEK. No I/O — a ceremony tool feeds it the samples and consumes the
//! report.

use maxsecu_crypto::EncSecretKey;
use maxsecu_encoding::types::Id;

use crate::recovery::{validate_recovery_wrap, RecoveryWrapCtx};

/// One file-version's recovery wrap to validate, as collected from storage.
pub struct RecoverySample {
    pub file_id: Id,
    pub version: u64,
    /// The wire recovery wrap `enc(32) ‖ ct`.
    pub wrap: Vec<u8>,
    /// The manifest's committed DEK value for this version.
    pub dek_commit: [u8; 32],
}

/// The outcome of a sweep: how many were checked and which ones failed.
pub struct SweepReport {
    pub checked: usize,
    /// Every sample that failed validation (undecryptable or mismatched).
    pub bad: Vec<RecoveryWrapCtx>,
}

/// Validate every sample with `recovery_priv`, collecting the failures. Pure.
pub fn run_sweep(recovery_priv: &EncSecretKey, samples: &[RecoverySample]) -> SweepReport {
    let mut bad = Vec::new();
    for s in samples {
        let ctx = RecoveryWrapCtx {
            file_id: s.file_id,
            version: s.version,
        };
        if validate_recovery_wrap(recovery_priv, &s.wrap, s.dek_commit, &ctx).is_err() {
            bad.push(ctx);
        }
    }
    SweepReport {
        checked: samples.len(),
        bad,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_crypto::{generate_enc_keypair, wrap_dek, Dek};
    use maxsecu_encoding::structs::WrapContext;
    use maxsecu_encoding::RECOVERY_ID;

    const F_GOOD1: Id = Id([0x01; 16]);
    const F_BAD: Id = Id([0x02; 16]);
    const F_GOOD2: Id = Id([0x03; 16]);

    /// Build a wire recovery wrap `enc(32) ‖ ct` the way the upload path does.
    fn wire(rpk: &maxsecu_crypto::EncPublicKey, dek: &Dek, file_id: Id, version: u64) -> Vec<u8> {
        let ctx = WrapContext {
            file_id,
            version,
            recipient_id: RECOVERY_ID,
        };
        let w = wrap_dek(rpk, dek, &ctx).unwrap();
        let mut v = w.enc.to_vec();
        v.extend_from_slice(&w.ct);
        v
    }

    #[test]
    fn sweep_reports_only_bad_versions() {
        let (rsk, rpk) = generate_enc_keypair();
        let dek1 = Dek::generate();
        let dek2 = Dek::generate();
        let dek_bad = Dek::generate();
        let other = Dek::generate();

        let samples = vec![
            // Good: wrap opens to its committed DEK.
            RecoverySample {
                file_id: F_GOOD1,
                version: 1,
                wrap: wire(&rpk, &dek1, F_GOOD1, 1),
                dek_commit: dek1.commit(),
            },
            // Bad: a valid wrap of a DIFFERENT DEK than the committed one.
            RecoverySample {
                file_id: F_BAD,
                version: 7,
                wrap: wire(&rpk, &other, F_BAD, 7),
                dek_commit: dek_bad.commit(),
            },
            // Good: another sound wrap.
            RecoverySample {
                file_id: F_GOOD2,
                version: 2,
                wrap: wire(&rpk, &dek2, F_GOOD2, 2),
                dek_commit: dek2.commit(),
            },
        ];

        let report = run_sweep(&rsk, &samples);
        assert_eq!(report.checked, 3);
        assert_eq!(
            report.bad,
            vec![RecoveryWrapCtx {
                file_id: F_BAD,
                version: 7
            }]
        );
    }
}
