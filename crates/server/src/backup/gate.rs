//! The pure DB-merge gate — decides, from [`LiveFacts`](super::LiveFacts) alone,
//! what a merge is allowed to re-insert.
//!
//! Deliberately sqlx-free (it is not behind the `postgres` feature): the gate is
//! a pure function over the facts read from the live database, so it is unit-
//! testable with hand-built `LiveFacts` and no Postgres. Its two rules are the
//! whole reason the file family can be merged safely — a hard delete is
//! absence-is-meaningful (`skip_subtree = tombstoned(fid) && !live_files(fid)`)
//! and a revocation is the absence of a wrap (a `(file_id, version, recipient)`
//! must not be re-inserted if a `wrap_revocations` row exists). [`merge::run`] reads
//! the rows and the live facts; this module decides.
//!
//! Two corrections the spec paid for in blood are baked in here:
//!
//!   * **The tombstone alone is NOT the gate.** `stage_version` re-creates a
//!     deleted `file_id` freely (client-generated ids, `ON CONFLICT DO NOTHING`,
//!     no tombstone check), so a live, current file can carry an old tombstone
//!     from a previous incarnation. A bare tombstone filter would refuse to merge
//!     that live file's lost subtree — permanently un-protecting it. The live row
//!     wins: `skip ⟺ tombstoned && !live_files`.
//!   * **The wrap gate is `files.current_version`, not version existence.**
//!     `finalize_version` retains the prior `file_versions` row forever, so
//!     "version exists in live" is a no-op gate that would resurrect wraps
//!     revoked by rotation. Streams and wraps are gated on the survivor's `cur`.
//!
//! [`merge::run`]: super::merge::run

use std::collections::HashMap;

use super::LiveFacts;

/// The per-wrap decision, kept explicit so the SQL builder can both filter and
/// feed the two distinct [`MergePreview`](super::MergePreview) skip counters from
/// one pass. Superseded and revoked are disjoint in practice — a revocation is
/// only ever recorded against the current finalized version — but classifying
/// superseded first keeps the counters from double-counting regardless.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapVerdict {
    /// `file_version == cur` and no `wrap_revocations` row — re-insert it.
    Keep,
    /// `file_version != cur`: a superseded version's wrap, whose ciphertext was
    /// purged at finalize. Re-inserting it resurrects a wrap the owner removed by
    /// rotation (correction #2).
    SkipSuperseded,
    /// A `wrap_revocations` row exists for `(file_id, file_version, recipient)`:
    /// this recipient's read access was deliberately taken away.
    SkipRevoked,
}

/// The decision a file-family merge makes over the backup's files, computed
/// purely from [`LiveFacts`]. Streams and wraps are then gated per-row against
/// [`survivor_cur`](FileGate::survivor_cur) via [`keep_stream`] / [`wrap_verdict`].
#[derive(Debug, Clone, Default)]
pub struct FileGate {
    /// Surviving `file_id` → the `current_version` its streams and wraps are
    /// gated on. A file live already has is gated on *live's* `current_version`
    /// (the operator's newer state wins); a file live has lost is restored at the
    /// backup's own `cur`, since live has no `current_version` to gate on.
    survivors: HashMap<[u8; 16], i64>,
    /// Files skipped because the owner destroyed them (`tombstoned && !live_files`).
    skipped_tombstoned: u64,
    /// Surviving files live had lost entirely — restored whole.
    restored_whole: u64,
}

impl FileGate {
    /// The `current_version` a surviving file's streams/wraps are gated on, or
    /// `None` if the file is skipped (its owner destroyed it).
    pub fn survivor_cur(&self, file_id: &[u8; 16]) -> Option<i64> {
        self.survivors.get(file_id).copied()
    }

    /// Files skipped because the owner destroyed them (a `file_tombstones` row
    /// and no live `files` row).
    pub fn skipped_tombstoned(&self) -> u64 {
        self.skipped_tombstoned
    }

    /// Surviving files live had lost entirely, restored whole at the backup's own
    /// `cur`.
    pub fn restored_whole(&self) -> u64 {
        self.restored_whole
    }
}

/// Decide, for every `(file_id, staged_current_version)` the backup holds, which
/// survive the merge and at what `cur` their streams and wraps are gated:
///
///   * `tombstoned && !live_files` → **skip the whole subtree** (owner destroyed it).
///   * otherwise **survive**, gated on `live.current_version[fid]` when live has
///     the file (the operator's newer state wins) or on the backup's own
///     `staged_cur` when live has lost it (restored whole).
pub fn plan_file_gate(staged_files: &[([u8; 16], i64)], live: &LiveFacts) -> FileGate {
    let mut gate = FileGate::default();
    for &(fid, staged_cur) in staged_files {
        // The owner destroyed it — unless a live row (a re-created id) overrides,
        // in which case the tombstone describes a previous incarnation and the
        // live file's lost subtree must still be protected.
        if live.tombstoned.contains(&fid) && !live.live_files.contains(&fid) {
            gate.skipped_tombstoned += 1;
            continue;
        }
        // Live's current_version wins; a lost file restores at the backup's cur.
        let cur = live
            .current_version
            .get(&fid)
            .copied()
            .unwrap_or(staged_cur);
        gate.survivors.insert(fid, cur);
        if !live.live_files.contains(&fid) {
            gate.restored_whole += 1;
        }
    }
    gate
}

/// A `file_streams` row survives iff it belongs to the survivor's gated version.
/// A superseded version's streams were pruned at finalize and their blobs are
/// gone; re-inserting them creates zombie rows that 404 on download.
pub fn keep_stream(survivor_cur: i64, version: i64) -> bool {
    version == survivor_cur
}

/// Classify a `file_key_wraps` row of a *surviving* file: keep only the current
/// version's wraps whose recipient was not revoked.
pub fn wrap_verdict(
    live: &LiveFacts,
    file_id: [u8; 16],
    survivor_cur: i64,
    file_version: i64,
    recipient_id: [u8; 16],
) -> WrapVerdict {
    if file_version != survivor_cur {
        WrapVerdict::SkipSuperseded
    } else if live
        .revoked
        .contains(&(file_id, file_version, recipient_id))
    {
        WrapVerdict::SkipRevoked
    } else {
        WrapVerdict::Keep
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 16] = [0xA1; 16];
    const B: [u8; 16] = [0xB2; 16];
    const R: [u8; 16] = [0x0C; 16];

    /// A hard-deleted file (tombstone, no live row) has its whole subtree skipped.
    #[test]
    fn tombstone_without_a_live_row_skips_the_subtree() {
        let mut live = LiveFacts::default();
        live.tombstoned.insert(A);
        let gate = plan_file_gate(&[(A, 3)], &live);
        assert_eq!(gate.survivor_cur(&A), None);
        assert_eq!(gate.skipped_tombstoned(), 1);
        assert_eq!(gate.restored_whole(), 0);
    }

    /// The live row WINS: a re-created id carries an old tombstone, so a live,
    /// current file's lost subtree must still merge (gated on live's cur).
    #[test]
    fn a_recreated_file_id_with_an_old_tombstone_still_survives() {
        let mut live = LiveFacts::default();
        live.tombstoned.insert(A);
        live.live_files.insert(A);
        live.current_version.insert(A, 5);
        let gate = plan_file_gate(&[(A, 2)], &live);
        assert_eq!(
            gate.survivor_cur(&A),
            Some(5),
            "gated on live's cur, not staged"
        );
        assert_eq!(gate.skipped_tombstoned(), 0);
        assert_eq!(gate.restored_whole(), 0);
    }

    /// A file live has lost entirely (no live row, no tombstone) is restored whole
    /// at the backup's own cur.
    #[test]
    fn a_lost_file_is_restored_whole_at_the_backup_cur() {
        let live = LiveFacts::default();
        let gate = plan_file_gate(&[(A, 4)], &live);
        assert_eq!(gate.survivor_cur(&A), Some(4));
        assert_eq!(gate.restored_whole(), 1);
        assert_eq!(gate.skipped_tombstoned(), 0);
    }

    /// A live file ahead of the backup is gated on live's cur — the backup's older
    /// version cannot strand live's newer state.
    #[test]
    fn a_live_file_ahead_is_gated_on_lives_current_version() {
        let mut live = LiveFacts::default();
        live.live_files.insert(A);
        live.current_version.insert(A, 5);
        let gate = plan_file_gate(&[(A, 3)], &live);
        assert_eq!(gate.survivor_cur(&A), Some(5));
        assert_eq!(gate.restored_whole(), 0);
    }

    #[test]
    fn stream_gate_keeps_only_the_survivor_version() {
        assert!(keep_stream(5, 5));
        assert!(!keep_stream(5, 4));
        assert!(!keep_stream(5, 6));
    }

    #[test]
    fn wrap_gate_drops_superseded_then_revoked_then_keeps() {
        let mut live = LiveFacts::default();
        live.revoked.insert((A, 4, R));
        // Superseded: a wrap at a version other than the survivor's cur.
        assert_eq!(wrap_verdict(&live, A, 4, 3, R), WrapVerdict::SkipSuperseded);
        // At cur, but the recipient was revoked.
        assert_eq!(wrap_verdict(&live, A, 4, 4, R), WrapVerdict::SkipRevoked);
        // At cur, not revoked — keep.
        assert_eq!(wrap_verdict(&live, A, 4, 4, B), WrapVerdict::Keep);
        // The revocation is keyed per (file, version, recipient): a different
        // file's wrap at the same version/recipient is not revoked.
        assert_eq!(wrap_verdict(&live, B, 4, 4, R), WrapVerdict::Keep);
    }

    /// A mixed batch tallies each bucket independently.
    #[test]
    fn a_mixed_batch_tallies_each_bucket() {
        let mut live = LiveFacts::default();
        // A: live-ahead survivor. B: hard-deleted. (a lost file follows.)
        live.live_files.insert(A);
        live.current_version.insert(A, 9);
        live.tombstoned.insert(B);
        let lost = [0xEE; 16];
        let gate = plan_file_gate(&[(A, 2), (B, 1), (lost, 7)], &live);
        assert_eq!(gate.survivor_cur(&A), Some(9));
        assert_eq!(gate.survivor_cur(&B), None);
        assert_eq!(gate.survivor_cur(&lost), Some(7));
        assert_eq!(gate.skipped_tombstoned(), 1);
        assert_eq!(gate.restored_whole(), 1);
    }
}
