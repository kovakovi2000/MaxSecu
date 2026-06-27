-- MaxSecu — PostgreSQL schema (v1)
-- Status: Spec (implement Phase 1+). Companion to DESIGN.md §11, docs/api.md, docs/encoding-spec.md.
--
-- PRINCIPLES (DESIGN.md §4.3 / §11):
--   * The server is SECRET-FREE. Every row here is inert: ciphertext, a public key, a
--     signature, a wrapped DEK, or an opaque signed record. No salts, no KDF params, no
--     private keys, no plaintext DEKs (D4 — see the users table note).
--   * Signed/hashed records are stored as their EXACT canonical(...) bytes in BYTEA columns
--     (suffixed _bytes). The server MUST NOT decode/re-encode them; clients verify signatures
--     over these bytes (docs/api.md §1.3). Columns NOT suffixed _bytes are ADVISORY PROJECTIONS
--     the server reads only for routing/indexing/coarse-authz — never a security boundary.
--   * Append-only / monotonic invariants (tombstones, genesis, audit, control-log) are enforced
--     here with triggers so even a buggy app cannot silently rewrite history (stack.md §2.1).
--     The HASH-CHAIN HEAD itself is verified by clients against the EXTERNAL SINK
--     (docs/sink-interface.md), not trusted from these rows.
--
-- Conventions: 16-byte ids and 32-byte keys/hashes as BYTEA with length CHECKs; timestamps as
-- TIMESTAMPTZ (advisory — never a freshness basis, DESIGN.md §7.5). Values (TTLs, sizes) live in
-- docs/parameters.md, not here.

BEGIN;

-- ============================================================================
-- Reusable append-only / immutability guards
-- ============================================================================

CREATE OR REPLACE FUNCTION maxsecu_forbid_update_delete() RETURNS trigger
  LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'append-only table %, % not permitted', TG_TABLE_NAME, TG_OP;
END $$;

CREATE OR REPLACE FUNCTION maxsecu_forbid_delete() RETURNS trigger
  LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'table % is delete-protected', TG_TABLE_NAME;
END $$;

-- ============================================================================
-- 11.1  users  +  directory_bindings (history)
-- ============================================================================
-- NOTE (D4): there is deliberately NO salt / kdf_params / encrypted_private_key column.
-- Those live only on the user's device (§9.1). Their absence is what removes the
-- server-side offline-guessing target (§3.2). Do not add them.

CREATE TABLE users (
  user_id        BYTEA PRIMARY KEY CHECK (octet_length(user_id) = 16),  -- server-assigned (api.md §1.4)
  username       TEXT NOT NULL UNIQUE,
  -- current identity material (the authoritative copy is the latest signed directory_bindings row):
  enc_pub        BYTEA NOT NULL CHECK (octet_length(enc_pub) = 32),     -- X25519
  sig_pub        BYTEA NOT NULL CHECK (octet_length(sig_pub) = 32),     -- Ed25519
  key_version    BIGINT NOT NULL DEFAULT 1 CHECK (key_version >= 1),    -- monotonic (rotation/re-enroll)
  roles          TEXT[] NOT NULL DEFAULT '{user}',                      -- advisory CEILING projection; effective = ceiling - tombstones (§7.6)
  status         TEXT NOT NULL DEFAULT 'active'                         -- advisory coarse serving flag; authoritative state is the sink-anchored control-log (§11.5)
                   CHECK (status IN ('active','revoked','suspended')),
  enrolled_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  signed_at      TIMESTAMPTZ                                            -- NULL until the ceremony signs the binding (§12.1); until then NOT a valid recipient
);
COMMENT ON COLUMN users.roles IS 'Advisory ceiling; effective roles = ceiling minus role-narrowing tombstones (DESIGN.md §7.6/§10.1).';
COMMENT ON COLUMN users.status IS 'Advisory only. Authoritative revocation/role state = sink-anchored control_log (DESIGN.md §11.5/§7.6).';

-- Superseded bindings are RETAINED forever, indexed by (user_id, key_version), solely to verify
-- signatures over DURABLE records (genesis) signed under an older key (DESIGN.md §11.7 addendum / D28).
CREATE TABLE directory_bindings (
  user_id              BYTEA NOT NULL CHECK (octet_length(user_id) = 16),
  key_version          BIGINT NOT NULL CHECK (key_version >= 1),
  enc_pub              BYTEA NOT NULL CHECK (octet_length(enc_pub) = 32),
  sig_pub              BYTEA NOT NULL CHECK (octet_length(sig_pub) = 32),
  roles                TEXT[] NOT NULL DEFAULT '{user}',
  not_before           TIMESTAMPTZ NOT NULL,
  not_after            TIMESTAMPTZ NOT NULL,
  binding_bytes        BYTEA NOT NULL,   -- canonical(dirbinding) — the signed message (encoding-spec §4)
  directory_signature  BYTEA NOT NULL CHECK (octet_length(directory_signature) = 64),  -- Ed25519 by offline D5
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, key_version)
);
-- Bindings are immutable once published (a new key_version is a new row, never an edit).
CREATE TRIGGER directory_bindings_immutable BEFORE UPDATE OR DELETE ON directory_bindings
  FOR EACH ROW EXECUTE FUNCTION maxsecu_forbid_update_delete();

-- ============================================================================
-- Phase-1 ephemeral auth state (the only "live" server state; no long-term secret)
-- ============================================================================

CREATE TABLE auth_nonces (                       -- single-use login challenges (§9.2; TTL in parameters.md §2)
  nonce        BYTEA PRIMARY KEY CHECK (octet_length(nonce) = 32),
  username     TEXT NOT NULL,                     -- claimed name (challenge issued even if unknown — no oracle, §9.3)
  issued_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ NOT NULL,
  used_at      TIMESTAMPTZ                        -- set on first successful proof; reuse rejected
);

CREATE TABLE sessions (                           -- channel-bound tokens (§9.2 / api.md §1.5)
  token_hash    BYTEA PRIMARY KEY CHECK (octet_length(token_hash) = 32),  -- store only a hash of the token
  user_id       BYTEA NOT NULL REFERENCES users(user_id),
  tls_exporter  BYTEA NOT NULL CHECK (octet_length(tls_exporter) = 32),   -- bound connection's exporter; checked per request
  issued_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at    TIMESTAMPTZ NOT NULL,
  revoked_at    TIMESTAMPTZ
);
CREATE INDEX sessions_user_idx ON sessions(user_id);

CREATE TABLE enrollment_vouchers (                -- one-time in-person anti-spam gate for POST /v1/users (api.md §5.1)
  voucher_hash  BYTEA PRIMARY KEY CHECK (octet_length(voucher_hash) = 32),
  issued_by     BYTEA NOT NULL REFERENCES users(user_id),  -- admin who handed it out in person
  issued_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at    TIMESTAMPTZ NOT NULL,
  used_at       TIMESTAMPTZ,
  used_by_user  BYTEA REFERENCES users(user_id)
);

-- ============================================================================
-- 11.2 / 11.7  files  +  immutable genesis
-- ============================================================================

CREATE TABLE files (
  file_id        BYTEA PRIMARY KEY CHECK (octet_length(file_id) = 16),  -- CLIENT-generated random; PK enforces uniqueness (api.md §1.4)
  owner_id       BYTEA NOT NULL REFERENCES users(user_id),              -- advisory; authority is the signed genesis (§11.7)
  file_type      SMALLINT NOT NULL CHECK (file_type IN (1,2,3)),        -- 1=video 2=image 3=blog (encoding-spec FileType); advisory mirror of signed manifest (D35)
  current_version BIGINT NOT NULL DEFAULT 0 CHECK (current_version >= 0), -- 0 while only-staged; set to N on finalize
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX files_owner_idx ON files(owner_id);
CREATE INDEX files_listing_idx ON files(file_type, updated_at DESC);  -- D35 listing: sort/filter on type/time only

CREATE TABLE file_genesis (                       -- created once, never modified (§11.7)
  file_id            BYTEA PRIMARY KEY REFERENCES files(file_id),       -- one-genesis-per-file
  owner_id           BYTEA NOT NULL,
  owner_key_version  BIGINT NOT NULL CHECK (owner_key_version >= 1),    -- selects the (possibly historical) binding that verifies genesis_sig
  genesis_bytes      BYTEA NOT NULL,                                    -- canonical(genesis)
  genesis_sig        BYTEA NOT NULL CHECK (octet_length(genesis_sig) = 64),
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER file_genesis_immutable BEFORE UPDATE OR DELETE ON file_genesis
  FOR EACH ROW EXECUTE FUNCTION maxsecu_forbid_update_delete();

-- ============================================================================
-- 11.2  file_versions  +  per-stream rows  (multi-stream, D33)
-- ============================================================================

CREATE TABLE file_versions (
  file_id          BYTEA NOT NULL REFERENCES files(file_id),
  version          BIGINT NOT NULL CHECK (version >= 1),               -- strict +1 per write (§7.5/D23) — see finalize trigger
  manifest_bytes   BYTEA NOT NULL,                                     -- canonical(manifest); commits file_type, dek_commit, per-stream digests, recovery_present
  manifest_sig     BYTEA NOT NULL CHECK (octet_length(manifest_sig) = 64),
  author_id        BYTEA NOT NULL,                                     -- advisory; downloader checks author_id == genesis.owner_id (owner-only, D29)
  alg              INTEGER NOT NULL DEFAULT 1,                         -- Suite codepoint (encoding-spec §3)
  finalized        BOOLEAN NOT NULL DEFAULT FALSE,                     -- false while chunks upload; true = visible (api.md §8.4)
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (file_id, version)
);
-- A finalized version is immutable; only the finalized flag may flip false->true (the commit).
CREATE OR REPLACE FUNCTION file_versions_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.finalized THEN RAISE EXCEPTION 'cannot delete a finalized version'; END IF;  -- staged versions may be GC'd; finalized are pruned only by rotation logic via a privileged path
    RETURN OLD;
  END IF;
  IF OLD.finalized THEN RAISE EXCEPTION 'finalized version is immutable'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER file_versions_guard_trg BEFORE UPDATE OR DELETE ON file_versions
  FOR EACH ROW EXECUTE FUNCTION file_versions_guard();

CREATE TABLE file_streams (
  file_id      BYTEA NOT NULL,
  version      BIGINT NOT NULL,
  stream_type  SMALLINT NOT NULL CHECK (stream_type IN (1,2,3,4)),     -- 1=content 2=metadata 3=thumbnail 4=preview (encoding-spec StreamType)
  compression  SMALLINT NOT NULL DEFAULT 0 CHECK (compression IN (0,1)),-- 0=none 1=zstd (authoritative copy in manifest)
  chunk_size   INTEGER NOT NULL CHECK (chunk_size BETWEEN 4096 AND 8388608),  -- [4 KiB, 8 MiB] bound (parameters.md §1.2)
  chunk_count  BIGINT NOT NULL CHECK (chunk_count >= 0),
  total_bytes  BIGINT NOT NULL CHECK (total_bytes >= 0),
  digest       BYTEA NOT NULL CHECK (octet_length(digest) = 32),       -- SHA-256 over ordered per-chunk tags (committed in manifest)
  blob_ref     TEXT NOT NULL,                                          -- logical id -> cache path or Dropbox path (D31)
  PRIMARY KEY (file_id, version, stream_type),
  FOREIGN KEY (file_id, version) REFERENCES file_versions(file_id, version) ON DELETE CASCADE
);

-- ============================================================================
-- 11.3  file_key_wraps  — where READ access lives (per-version key custody)
-- ============================================================================
-- Server may DELETE wraps (deny/soft-revoke) but cannot CREATE a usable one (needs the plaintext
-- DEK) nor forge a grant_sig. RECOVERY_ID (16 zero bytes) is the standing recovery recipient.

CREATE TABLE file_key_wraps (
  file_id        BYTEA NOT NULL,
  file_version   BIGINT NOT NULL,
  recipient_id   BYTEA NOT NULL CHECK (octet_length(recipient_id) = 16), -- a user_id, or RECOVERY_ID (00..00)
  recipient_type SMALLINT NOT NULL CHECK (recipient_type IN (1,2)),      -- 1=user 2=recovery
  wrapped_dek    BYTEA NOT NULL,                                         -- HPKE wrap to recipient enc_pub
  wrap_alg       INTEGER NOT NULL DEFAULT 1,
  granted_by     BYTEA NOT NULL CHECK (octet_length(granted_by) = 16),   -- author | re-sharer | recovery-operator (chain type drives carry-forward, §12.3a)
  grant_bytes    BYTEA NOT NULL,                                         -- canonical(grant)
  grant_sig      BYTEA NOT NULL CHECK (octet_length(grant_sig) = 64),    -- granter Ed25519; a wrap whose grant_sig fails verify is treated as ABSENT (client-side)
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (file_id, file_version, recipient_id),                     -- unique (file,version,recipient) (stack.md §2.1)
  FOREIGN KEY (file_id, file_version) REFERENCES file_versions(file_id, version) ON DELETE CASCADE,
  CHECK ( (recipient_type = 2) = (recipient_id = decode('00000000000000000000000000000000','hex')) )  -- recovery <=> RECOVERY_ID (encoding-spec V-11)
);
CREATE INDEX wraps_recipient_idx ON file_key_wraps(recipient_id);        -- "files I can read" + sharing-graph projection

-- ============================================================================
-- 11.5 / 11.5a / 11.7(D28)  control_log — ONE append-only hash chain
-- ============================================================================
-- revocation + reinstatement + key_compromise interleave into a single chain (encoding-spec §4).
-- chain_seq = global order; prev_head/head = the hash chain whose head the EXTERNAL SINK anchors
-- (docs/sink-interface.md). scope_epoch = the per-scope monotonic counter (revocation/reinstatement).
-- Projection columns are advisory; clients verify the opaque record_bytes + sig.

CREATE TABLE control_log (
  chain_seq       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,       -- global append order
  kind            SMALLINT NOT NULL CHECK (kind IN (6,7,8)),             -- 6=revocation 7=reinstatement 8=key_compromise (encoding-spec type_ids)
  prev_head       BYTEA NOT NULL CHECK (octet_length(prev_head) = 32),   -- SHA-256 of previous record (GENESIS_HEAD=00..00 for the first)
  head            BYTEA NOT NULL UNIQUE CHECK (octet_length(head) = 32), -- SHA-256(canonical(this record))
  record_bytes    BYTEA NOT NULL,                                        -- canonical(revocation|reinstatement|key_compromise)
  sig             BYTEA NOT NULL CHECK (octet_length(sig) = 64),         -- issuer admin Ed25519
  co_sig          BYTEA CHECK (co_sig IS NULL OR octet_length(co_sig) = 64), -- second admin (dual control)
  issued_by       BYTEA NOT NULL REFERENCES users(user_id),
  co_signed_by    BYTEA REFERENCES users(user_id),
  -- ---- advisory projections for serving/querying ----
  is_account_wide BOOLEAN NOT NULL DEFAULT FALSE,                        -- the '*' scope (FileScope 0x02)
  scope_file_id   BYTEA CHECK (scope_file_id IS NULL OR octet_length(scope_file_id) = 16),
  subject_user_id BYTEA NOT NULL CHECK (octet_length(subject_user_id) = 16), -- revoked/reinstated/compromised user
  revoked_capability SMALLINT CHECK (revoked_capability IS NULL OR revoked_capability IN (1,2)), -- role-narrowing (null = full access revoke)
  from_version    BIGINT,                                                -- revocation: applies to this version onward
  scope_epoch     BIGINT,                                                -- revocation/reinstatement: per-scope monotonic
  supersedes_epoch BIGINT,                                               -- reinstatement: the revocation_epoch it clears (by explicit reference, R28)
  compromised_key_version BIGINT,                                        -- key_compromise
  effective_from  TIMESTAMPTZ,                                           -- key_compromise (advisory; authoritative cutoff is sink position, §11.7)
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- scope consistency: account-wide xor a specific file (key_compromise is neither)
  CHECK ( (kind = 8) OR (is_account_wide <> (scope_file_id IS NOT NULL)) ),
  -- per-kind required fields:
  CHECK ( kind <> 6 OR (from_version IS NOT NULL AND scope_epoch IS NOT NULL) ),
  CHECK ( kind <> 7 OR (scope_epoch IS NOT NULL AND supersedes_epoch IS NOT NULL AND co_sig IS NOT NULL) ), -- reinstatement always dual-controlled (§11.5a)
  CHECK ( kind <> 8 OR (compromised_key_version IS NOT NULL) )
);
-- monotonic per-scope epoch (separate sequences for '*' and each file), per kind family
CREATE UNIQUE INDEX control_log_revoke_epoch_uq
  ON control_log (COALESCE(scope_file_id, decode('ffffffffffffffffffffffffffffffff','hex')), scope_epoch)
  WHERE kind = 6;
CREATE UNIQUE INDEX control_log_reinstate_epoch_uq
  ON control_log (COALESCE(scope_file_id, decode('ffffffffffffffffffffffffffffffff','hex')), scope_epoch)
  WHERE kind = 7;
CREATE INDEX control_log_subject_idx ON control_log (subject_user_id);
CREATE INDEX control_log_scope_idx   ON control_log (scope_file_id);

-- Append-only + hash-chain linkage: each new row's prev_head must equal the prior row's head.
CREATE OR REPLACE FUNCTION control_log_append_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE last_head BYTEA;
BEGIN
  SELECT head INTO last_head FROM control_log ORDER BY chain_seq DESC LIMIT 1;
  IF last_head IS NULL THEN
    IF NEW.prev_head <> decode('0000000000000000000000000000000000000000000000000000000000000000','hex') THEN
      RAISE EXCEPTION 'first control_log record must chain to GENESIS_HEAD';
    END IF;
  ELSIF NEW.prev_head <> last_head THEN
    RAISE EXCEPTION 'control_log prev_head does not match current chain head (gap/fork rejected)';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER control_log_append_guard_trg BEFORE INSERT ON control_log
  FOR EACH ROW EXECUTE FUNCTION control_log_append_guard();
CREATE TRIGGER control_log_immutable BEFORE UPDATE OR DELETE ON control_log
  FOR EACH ROW EXECUTE FUNCTION maxsecu_forbid_update_delete();

-- ============================================================================
-- 11.4  auth_events  — LOCAL MIRROR ONLY (forgeable; NOT evidence)
-- ============================================================================
-- The AUTHORITATIVE audit trail is the external append-only sink (DESIGN.md §16.5 /
-- docs/sink-interface.md). This table is a fast local mirror; never relied on for detection.

CREATE TABLE auth_events (
  event_id    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  actor       BYTEA,                                  -- user_id or NULL (pre-auth)
  action      TEXT NOT NULL,                          -- 'login','grant','revoke','rotate','export','ceremony',...
  target      BYTEA,                                  -- file_id / user_id as applicable
  result      TEXT NOT NULL CHECK (result IN ('ok','deny','error')),
  detail      TEXT,                                   -- sanitized; never secrets/plaintext (§16.5)
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX auth_events_actor_idx ON auth_events(actor, created_at DESC);
-- delete-protected locally (it is still only a mirror; the sink is authoritative)
CREATE TRIGGER auth_events_no_delete BEFORE DELETE ON auth_events
  FOR EACH ROW EXECUTE FUNCTION maxsecu_forbid_delete();

-- ============================================================================
-- NOT PRESENT BY DESIGN
-- ============================================================================
--   * write_grants  — owner-only write (D29); no write delegation. Do not add in v1.
--   * any salt / kdf / private-key column on users (D4).
--   * any plaintext, thumbnail, or DEK column anywhere (§4.3).

COMMIT;
