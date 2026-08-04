-- migrations/0002_delete_tombstones.sql — record the two absences that mean something.
--
-- Everywhere else in this schema a row IS the fact. In the file family the
-- opposite is also true, and until now nothing wrote it down:
--
--   * A delete is a HARD delete. `delete_file` sets `maxsecu.allow_owner_delete`
--     and physically removes files/file_genesis/file_versions (cascading to
--     file_streams + file_key_wraps), and the blobs are purged from BOTH tiers.
--     The only trace left is the missing row.
--   * A revocation is the ABSENCE of a wrap. `delete_wrap` deletes one
--     file_key_wraps row; nothing records that it was ever there.
--
-- That is fine while the database only moves forward. It stops being fine the
-- moment a backup can be restored into it: a merge re-inserts whatever the
-- bundle still holds, so it would resurrect a file its owner destroyed — as a
-- zombie feed entry pointing at ciphertext that no longer exists anywhere — and
-- hand a de-authorized recipient their wrapped DEK back, silently, on a file
-- that was never deleted. These two tables are what the merge reads to tell
-- "this is missing because it was lost" from "this is missing because a user
-- removed it on purpose".
--
-- No FK to `files` on either table: the parent row is gone by design, which is
-- the entire point. (An FK would also mean `DELETE FROM files` either raised or
-- silently swept the tombstone away with it.)
--
-- Both tables carry the SHARED `maxsecu_forbid_update_delete` guard, not one of
-- the dedicated per-table guards. That matters: the shared guard raises
-- unconditionally and never reads `maxsecu.allow_owner_delete`, so a tombstone
-- stays immutable even inside `delete_file`'s own GUC-enabled transaction — the
-- one place where the rest of the file family is deletable. The guard is
-- BEFORE UPDATE OR DELETE only, so it never fires on INSERT.
--
-- Tombstones only exist going forward: a file deleted by pre-0002 code left no
-- record, so a merge from a bundle predating this migration can still resurrect
-- it. Bundle retention is 10, so that window closes on its own.
--
-- Written in the baseline's idempotent style (IF NOT EXISTS / DROP TRIGGER IF
-- EXISTS) and with no BEGIN;/COMMIT; of its own — migrations/apply.sh wraps this
-- file in ONE transaction together with its schema_migrations row, so applying
-- and recording commit together and a power cut mid-upgrade leaves a working
-- server. Mirrored verbatim into docs/schema.sql (minus the DROP TRIGGER lines,
-- which are catalog-invisible); crates/compat/tests/schema_equivalence.rs proves
-- against a live Postgres that a fresh install and an upgraded install end up
-- with the identical catalog.

-- ============================================================================
-- 11.2a  file_tombstones  — the owner destroyed this file (delete is forever)
-- ============================================================================

CREATE TABLE IF NOT EXISTS file_tombstones (
  file_id     BYTEA PRIMARY KEY CHECK (octet_length(file_id) = 16),  -- the deleted file; no FK — its `files` row is gone
  deleted_at  TIMESTAMPTZ NOT NULL DEFAULT now()                     -- advisory (§7.5); the row's existence is the fact, not its time
);
-- Append-only: a delete cannot be un-recorded. See the shared-guard note above —
-- this holds even under `maxsecu.allow_owner_delete`.
DROP TRIGGER IF EXISTS file_tombstones_immutable ON file_tombstones;
CREATE TRIGGER file_tombstones_immutable BEFORE UPDATE OR DELETE ON file_tombstones
  FOR EACH ROW EXECUTE FUNCTION maxsecu_forbid_update_delete();

-- ============================================================================
-- 11.3a  wrap_revocations  — this recipient's read access was taken away
-- ============================================================================
-- Written ONLY by the recipient-scoped soft-revoke (`delete_wrap`), never by
-- `finalize_version`. Finalize drops the PRIOR version's wraps, but that is
-- version supersession, not revocation: it is recipient-blind and every
-- recipient keeps access through the new version's own wrap. Recording it here
-- would make every rotation look like a revocation and permanently block the
-- merge of wraps nobody ever revoked.
--
-- Keyed per version, matching file_key_wraps' own PK: revocation is a fact about
-- (file, version, recipient), and `delete_wrap` only ever acts on the current
-- finalized version.

CREATE TABLE IF NOT EXISTS wrap_revocations (
  file_id       BYTEA NOT NULL CHECK (octet_length(file_id) = 16),
  file_version  BIGINT NOT NULL,
  recipient_id  BYTEA NOT NULL CHECK (octet_length(recipient_id) = 16),  -- a user_id, or RECOVERY_ID (00..00)
  revoked_at    TIMESTAMPTZ NOT NULL DEFAULT now(),                      -- advisory (§7.5)
  PRIMARY KEY (file_id, file_version, recipient_id)                      -- mirrors file_key_wraps' PK
);
-- Append-only: a revocation cannot be un-recorded.
DROP TRIGGER IF EXISTS wrap_revocations_immutable ON wrap_revocations;
CREATE TRIGGER wrap_revocations_immutable BEFORE UPDATE OR DELETE ON wrap_revocations
  FOR EACH ROW EXECUTE FUNCTION maxsecu_forbid_update_delete();
