//! RAM-budget policy for opening a file (DESIGN §8.1 line 360 / D12).
//!
//! Decrypted plaintext lives in memory only (§8.1); large files exceed RAM by
//! design, so the user sets a budget and the client chooses how to open:
//!
//! 1. **Stream** — preferred whenever the consumer can decrypt-while-use
//!    (progressive playback / chunked processing): nothing whole is ever
//!    materialized, so size is irrelevant (the [`crate::download`] streaming
//!    path, §8.1 line 361).
//! 2. **Whole-in-memory** — when the consumer cannot stream but the plaintext
//!    fits the budget: download and decode from RAM.
//! 3. **Disk-unlock** — the one sanctioned plaintext-on-disk path (§8.1): the
//!    plaintext exceeds the budget and cannot stream, so the client **warns,
//!    requires confirmation, writes only to the user-chosen path, and audits**
//!    the export (§16.5). This is the sole exception to in-memory-only.

/// An audited, plaintext-touching action (DESIGN §16.5). Surfaced to the user
/// and written to the audit log; never carries decrypted bytes or keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEvent {
    /// Oversized open fell through to disk (the §8.1 exception). Records the
    /// sizes that forced it — the user is warned and confirms before this.
    DiskUnlock {
        plaintext_size: u64,
        ram_budget: u64,
    },
    /// An explicit "save decrypted to disk" export (§8.1) — the copy leaves
    /// MaxSecu's protection. `to` is the sanitized, in-export-dir path string.
    PlaintextExport { to: String },
}

/// How the client will open a file given its plaintext size, the user's RAM
/// budget, and whether the consumer can decrypt-while-use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnlockPlan {
    /// Decrypt-while-use; nothing whole in RAM (§8.1 line 361). Size-independent.
    Stream,
    /// Fits the budget — decode from memory.
    WholeInMemory,
    /// Exceeds the budget and cannot stream → the warned, audited disk path.
    DiskUnlock { audit: AuditEvent },
}

/// Choose the open strategy (§8.1 line 360). Streaming is always preferred when
/// available; otherwise the plaintext must fit the RAM budget, or it falls to
/// the audited disk-unlock path. A zero budget forces non-streamable opens to
/// disk (nothing fits).
pub fn plan_unlock(plaintext_size: u64, ram_budget: u64, streamable: bool) -> UnlockPlan {
    if streamable {
        UnlockPlan::Stream
    } else if plaintext_size <= ram_budget {
        UnlockPlan::WholeInMemory
    } else {
        UnlockPlan::DiskUnlock {
            audit: AuditEvent::DiskUnlock {
                plaintext_size,
                ram_budget,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streamable_always_streams_regardless_of_size() {
        // Even a file far larger than the budget streams (nothing whole in RAM).
        assert_eq!(plan_unlock(u64::MAX, 1024, true), UnlockPlan::Stream);
        assert_eq!(plan_unlock(0, 0, true), UnlockPlan::Stream);
    }

    #[test]
    fn fits_budget_decodes_in_memory() {
        assert_eq!(plan_unlock(1000, 4096, false), UnlockPlan::WholeInMemory);
        // Exactly at the budget still fits.
        assert_eq!(plan_unlock(4096, 4096, false), UnlockPlan::WholeInMemory);
    }

    #[test]
    fn oversized_non_streamable_unlocks_to_disk_and_audits() {
        let plan = plan_unlock(10_000_000_000, 256 * 1024 * 1024, false);
        assert_eq!(
            plan,
            UnlockPlan::DiskUnlock {
                audit: AuditEvent::DiskUnlock {
                    plaintext_size: 10_000_000_000,
                    ram_budget: 256 * 1024 * 1024,
                },
            },
            "an oversized, non-streamable open must produce an audited disk-unlock"
        );
    }

    #[test]
    fn zero_budget_forces_non_streamable_to_disk() {
        assert!(matches!(
            plan_unlock(1, 0, false),
            UnlockPlan::DiskUnlock { .. }
        ));
    }
}
