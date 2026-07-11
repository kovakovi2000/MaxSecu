# Prod sharing & feed-visibility fixes — design

**Date:** 2026-07-11
**Status:** Approved (brainstorm) — ready for implementation plan
**Ships as:** an upgrade (rebuild server binary + client, redistribute — same as prior upgrade flows)

## Problem

A real prod deployment surfaced three defects in the browse + share path:

1. **Non-shared posts appear in the feed.** A second profile saw a post it was never
   shared, then got *"This item is not available."* on open. The feed must not show
   items a user cannot open.
2. **Sharing is dead on arrival.** The share picker verifies a username
   (*"… ✓ Verified"*), but pressing **Share** fails with *"The sink endpoint is not
   pinned."* — no user can share anything.
3. **(User request during brainstorm)** On first share to someone, pin their public
   key; if it later changes, warn and let the user confirm rather than silently
   proceeding — or (as today) silently hard-blocking.

## Root causes

1. **`GET /v1/files` (`list_files`) ignores the caller.** Both store backends
   (`MemoryStore` in `crates/server/src/store.rs`, Postgres in `crates/server/src/pg.rs`)
   return *every* finalized + `listed` file to *any* authenticated user. The HTTP
   handler (`crates/server/src/http.rs::list_files`) even binds the session as
   `_session` — the caller id is resolved but discarded. Consequence: the feed lists
   posts the caller holds no wrap for (open then fails closed), and every authenticated
   user learns the existence/type/size/timestamp of every post (metadata leak).
2. **`reshare_file` hard-requires an out-of-band sink.** `reshare_inner`
   (`crates/client-app/src/commands/share.rs`) calls `load_sink_pins(&dir.0)?` as a
   batch-wide prerequisite. The sink is a *separate* revocation-anchor service (T4
   design); the single-server beginner/prod install (`install-server.sh` /
   `install-client.ps1`) never stands one up or pins it, so `config/sink.json` is absent
   and `load_sink_pins` fails closed *before any recipient is processed*. The
   *"✓ Verified"* the user saw is the earlier unauthenticated `resolve_recipient` picker
   check, which does not touch the sink.
3. **First-share pinning already exists; the change path is a dead end.**
   `run_reshare_batch` calls `TofuStore::check_or_pin`, which pins a recipient's key on
   first sighting and returns `Changed` on a later differing key. Today `Changed` maps to
   a fail-closed `server_untrusted` per-recipient outcome with **no way to proceed** and
   no fingerprints surfaced to the user.

## Decisions (from brainstorm)

- **Feed scope:** private — `GET /v1/files` returns only files the caller holds a wrap
  for (their own posts + anything explicitly shared to them). No public discovery feed;
  content is discovered when an owner shares it by username.
- **Revocation anchor:** make the sink **opt-in** (mirroring the existing opt-in KT /
  sink-transparency pattern). No sink pinned ⇒ sharing still fetches server-served
  revocations and enforces D5-verified issuer authority + chain contiguity, but skips
  out-of-band anchoring. A pinned sink keeps full rollback/withholding protection.
- **Key change:** keep fail-closed by default; add an explicit **warn + confirm**
  override that re-pins only on user confirmation.

---

## Part 1 — Feed shows only files you can open (server)

### Interface change
`ListFilter` (`crates/server/src/files.rs`) gains:

```rust
pub struct ListFilter {
    pub file_type: Option<i16>,
    pub limit: usize,
    pub caller_id: [u8; 16], // NEW: the authenticated session principal
}
```

### Handler
`http.rs::list_files` binds `session: AuthedSession` (drop the `_`) and passes
`caller_id: session.user_id` into `ListFilter`.

### Store backends
Both `list_files` implementations add a caller-wrap gate on top of the existing
`current_version >= 1` + `listed` filters:

- **MemoryStore:** keep a file only if its current version's `wraps` contains a row with
  `recipient_id == filter.caller_id`.
- **Postgres:** add to the `WHERE`:
  ```sql
  AND EXISTS (
    SELECT 1 FROM file_key_wraps w
    WHERE w.file_id = files.file_id
      AND w.file_version = files.current_version
      AND w.recipient_id = $caller
  )
  ```

### Semantics / invariants
- Owners still see their own posts (they always hold a self-wrap).
- Recipients see a post as soon as a wrap for them exists (same row the open path checks —
  consistent visibility: if it lists, it opens; if it doesn't list, it also won't open).
- The recovery principal never reaches this endpoint (`AuthedSession` bars it) and a
  recovery wrap (`recipient_id == RECOVERY_ID`) never matches a real caller id, so it
  cannot leak listings.
- No new oracle: absence from the listing is indistinguishable from "no such file."

### Tests
- Store unit test (both backends via the existing `pg_store.rs` / `file_records.rs`
  harnesses): a non-recipient's listing omits a finalized post; the owner's includes it;
  a third user's includes it only after a wrap is added.
- Update existing `list_files(ListFilter { … })` call sites to pass `caller_id`.
- HTTP/e2e (`sharing_e2e.rs` or `file_e2e.rs`): user B's `GET /v1/files` does not list a
  post owned by A until A shares it to B; after sharing, it lists and opens.

---

## Part 2 — Sharing works without a separate sink (client)

### client-core: unanchored tombstone constructor
Add to `crates/client-core/src/revocation.rs`:

```rust
impl TombstoneSet {
    /// Like `verify_authenticated`, but with NO external anchor: the target head is
    /// derived from the served record chain itself. Chain contiguity (`BrokenChain`),
    /// record well-formedness (`Malformed`), and D5 issuer authority are still enforced;
    /// only the out-of-band anchoring (gap/withhold detection) is skipped. Used when no
    /// sink is pinned (opt-in), matching the opt-in KT/transparency pattern.
    pub fn verify_authenticated_unanchored(
        records: &[ControlRecordIn],
        issuer: &dyn Fn(Id) -> Option<IssuerInfo>,
    ) -> Result<TombstoneSet, TombstoneError>;
}
```

Implementation folds the chain head from `records` (reusing the same per-record hash-chain
step `verify_authenticated` already performs) and runs the identical authority/contiguity
checks against that derived head — so `Gap` structurally cannot fire, but every other
fail-closed check remains.

### client-app: optional sink pins
Add to `crates/client-app/src/config.rs`:

```rust
/// Load sink pins if configured. `Ok(None)` when `sink.json` is ABSENT (opt-in — the
/// caller runs the unanchored revocation path); `Err` when present-but-malformed (fail
/// closed); `Ok(Some(pins))` when fully pinned. Mirrors `load_kt_log_pubs`' opt-in shape.
pub fn load_sink_pins_opt(dir: &Path) -> Result<Option<SinkPins>, UiError>;
```

Absence is detected by the missing `sink.json` (the endpoint file). A present `sink.json`
with any missing/malformed sibling pin (`sink_root.der`, `sink_custodians.der`) stays
fail-closed — a half-configured sink is a misconfiguration, not an opt-out.

### client-app: revocation build
`crates/client-app/src/revocations.rs` — `build_tombstones` gains an unanchored path.
Cleanest shape: take `anchored_head: Option<[u8; 32]>`:
- `Some(head)` → `TombstoneSet::verify_authenticated(records, head, issuer)` (unchanged).
- `None` → `TombstoneSet::verify_authenticated_unanchored(records, issuer)`.

### client-app: reshare
`share.rs::reshare_inner` replaces the mandatory sink block:

```rust
let anchored_head = match load_sink_pins_opt(&dir.0)? {
    Some(pins) => Some(fetch_anchored_head(&pins)?), // pinned ⇒ fail closed on bad anchor
    None => None,                                     // opt-in ⇒ unanchored
};
let tombstones = build_tombstones(&mut sender, &host, anchored_head, &verifier, &mut trust, now).await?;
```

`reshare_bundle` inherits this via `reshare_inner`. `enforce_author_transparency`
(`feed.rs`) is unchanged: it only reads the sink when a KT key is pinned (absent by
default), and a KT-pinned-but-sink-absent deployment is an intentional misconfig that stays
fail-closed.

### Tradeoff (documented in code + this spec)
Without a pinned sink, a reshare cannot detect a *withheld/rolled-back* revocation tail —
i.e. it trusts that the (single, admin-operated) server is not hiding its own revocations.
It still refuses to reshare to a recipient named in any *served* revocation with valid D5
issuer authority. Pinning a sink restores full anchoring with no code change.

### Tests
- client-core: `verify_authenticated_unanchored` accepts a valid served chain, still
  rejects a broken link / malformed record / unknown-issuer record.
- client-app: `build_tombstones` with `None` builds against a served chain; a share
  integration test with **no sink pinned** completes (recipient gets `ok:true`), and one
  **with** a sink still exercises the anchored path.

---

## Part 3 — Recipient key-change warn + confirm (client)

### TofuStore
Add `repin` to `crates/client-app/src/tofu.rs`:

```rust
/// Overwrite the pinned fingerprint for `username` (persisted atomically). Used ONLY on
/// an explicit user-confirmed key change — never on the silent path.
pub fn repin(&mut self, username: &str, enc_pub: &[u8; 32], sig_pub: &[u8; 32]) -> Result<(), UiError>;
```

### Request + outcome DTOs
- `ReshareRequest` (`dto.rs`) gains `#[serde(default)] accepted_key_changes: Vec<String>`
  (usernames the user has explicitly confirmed trusting a new key for). Back-compat: absent
  ⇒ empty.
- `ReshareOutcomeDto` gains optional `old_fingerprint: Option<String>` /
  `new_fingerprint: Option<String>` (short display form), populated only for the
  `key_changed` outcome.

### Batch behavior (`run_reshare_batch`)
On `TofuOutcome::Changed` for `uname`:
- if `uname ∈ accepted_key_changes` → `tofu.repin(uname, &author.enc_pub, &author.sig_pub)`
  then proceed with the wrap/POST as normal;
- else → per-recipient outcome `code: "key_changed"` with `old_fingerprint`
  (`tofu.pinned_fingerprint(uname)` → `short_fingerprint`) and `new_fingerprint`
  (`key_fingerprint(&author.enc_pub, &author.sig_pub)` → `short_fingerprint`); no wrap,
  no POST, batch continues (per-recipient isolation preserved).

The pre-existing `server_untrusted` code is retired for the user-key-change case in favor of
`key_changed`; any other trust-alarm reuse (if present) is unaffected.

### UI
When a recipient outcome is `key_changed`, surface a warning dialog:

> ⚠ **[name]'s security key has changed** since you last shared with them. This can happen
> if they reinstalled the app — but it can also mean someone is impersonating them.
> Previously: `<old fp>` · Now: `<new fp>`. Only continue if you trust this change.
> **[Cancel] [Share anyway]**

**Share anyway** re-invokes the share command with that username appended to
`accepted_key_changes` (idempotent server-side, so retrying just that recipient is safe).
Default remains fail-closed; only the explicit confirm re-pins.

### Tests
- `tofu.rs`: `repin` overwrites and persists; a subsequent `check_or_pin` with the new key
  now `Match`es.
- `share.rs` batch: a pre-pinned username whose served key changed yields `key_changed`
  (with both fingerprints) and does NOT POST; the same batch with that username in
  `accepted_key_changes` re-pins and succeeds; a first-sighting peer in the same batch is
  unaffected.
- UI unit/e2e: a `key_changed` outcome renders the confirm dialog; confirming re-invokes
  with the accepted username.

---

## Out of scope
- Deploying a real sink or a server-as-sink-D5-signed head (opt-in path remains available
  for deployments that pin one).
- Any change to the open/download verify ladder (unchanged; the feed now simply matches
  what the open path already enforces).
- Pagination/cursor for the listing (still single-page `limit`).

## Rollout
1. Rebuild + redeploy the server binary (Part 1). Existing feeds immediately scope to the
   caller; no schema migration (the `file_key_wraps` join uses existing columns).
2. Rebuild + redistribute the client (Parts 2–3). Sharing works with no sink pinned; the
   key-change confirm appears when relevant.
3. No data migration; no config changes required for the default (no-sink) deployment.
