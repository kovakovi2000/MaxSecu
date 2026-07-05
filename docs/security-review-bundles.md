# Bundles, Generic type, Download, Delete & Parallel decode — Security Review & Sign-off

**Scope:** the *bundles* feature change set on `main` — commit range `bdb17ff..8c4d275`
(WS1–WS9). It adds: `FileType::Generic`/`Bundle` + the `BundleBody` ordered member-list
codec; a server `listed`/`bundle_id` membership model + a **new destructive owner-only
finalized-delete endpoint** with bundle cascade + cold-tier blob purge; client bundle
build/open (`open_bundle`), generic streaming upload, `download_content`, `delete_content`,
`reshare_bundle`; and a parallel feed-decode **authed connection pool** with three new
performance settings.

**Method:** independent code read of every security-sensitive surface (server delete +
append-only carve-out, bundle content-verify / substitution defense, the concurrency pool,
reshare fan-out, download, generic upload, seam/privacy), cross-checked against the design
(`docs/superpowers/specs/2026-07-04-bundles-generic-download-delete-design.md`) and the
per-task reviews. Verification artifacts: the per-file unit tests; the server cascade tests
(`crates/server/src/store.rs` `delete_file_owner_only_and_cascades_bundle`,
`delete_bundle_never_touches_a_foreign_owned_member`) and the live-PG regression
(`crates/server/tests/pg_store.rs` `delete_finalized_file_cascades_in_postgres`); the
requested-id GATE-5 (`crates/client-e2e/tests/browse_view_e2e.rs`); and the two bundle e2e
suites over real TLS (`bundle_e2e.rs`, `generic_download_parallel_e2e.rs`) — **all green**
this session (`bundle_lifecycle_over_real_tls`, `generic_upload_download_byte_identical`,
`parallel_feed_decode_over_the_pool`).

**Verdict:** **PASS** — no Critical, High, or Medium findings. The feature preserves the
TCB: the untrusted server still cannot read content, cannot add/drop/reorder/substitute a
bundle's members (membership is inside the author-signed content), and cannot delete or
mutate another owner's data. The one deliberate weakening — a transaction-local carve-out
over the append-only triggers so an owner can permanently delete their **own content** — is
minimally scoped and leaves the tamper-evidence logs (`directory_bindings`, `control_log`)
fully immutable. Documented residuals (§4) are Low/Informational and security-neutral.

---

## 1. Surface-by-surface analysis

### 1.1 Destructive delete endpoint + append-only carve-out

**Threat.** A new permanent-delete path must not (a) become an ownership oracle, (b) delete
another user's data, (c) weaken the append-only tamper-evidence logs, or (d) leak blobs
(local or cold-tier) after the DB rows go away.

**Owner-auth, no oracle — OK.** `DELETE /v1/files/{id}` (`crates/server/src/http.rs:1621`
`discard_file`) first tries `discard_unfinalized`; a non-owner of a finalized file already
returns `NotFound`→404 there, so it never reaches `delete_file`
(`http.rs:1639–1643`). `Store::delete_file` itself re-checks ownership under a row lock and
collapses **both** "absent" and "not-owner" to `DeleteError::NotFound`
(pg `crates/server/src/pg.rs:1321–1327`; memory `crates/server/src/store.rs:1277–1282`),
which the handler maps to 404 (`http.rs:1653`). The client mirrors this: 404 → sanitized
`not_found`, and any non-204/404 → `delete_failed` — never surfacing 403/FORBIDDEN, which
`delete_cmd.rs:24–30` explicitly notes "would be an ownership oracle if surfaced"
(tested `other_statuses_are_delete_failed`).

**No cross-owner deletion — OK.** The bundle cascade is owner-scoped in **both** stores:
pg `SELECT file_id FROM files WHERE bundle_id = $1 AND owner_id = $2`
(`pg.rs:1341–1343`); memory `f.bundle_id == Some(file_id) && f.owner_id == owner_id`
(`store.rs:1291`). A `bundle_id` is a member-declared field, so any user can point their own
file at a foreign bundle; the `owner_id` predicate guarantees such a foreign member is never
in the delete set. Directly asserted by
`delete_bundle_never_touches_a_foreign_owned_member` (`store.rs:1673`) and the live-PG
`delete_finalized_file_cascades_in_postgres` (`pg_store.rs:971` — `refs.len()==6` = 2 streams
× 3 owned files, foreign member survives, its blob_ref absent from the purge set).

**GUC carve-out — sound, minimally scoped — OK.** `delete_file` runs a single transaction
that first issues `SET LOCAL maxsecu.allow_owner_delete = 'on'` (`pg.rs:1308`). `SET LOCAL`
is transaction-scoped and auto-resets at COMMIT/ROLLBACK, so no other connection or later
statement is ever affected; every early-return owner-check path rolls back before any DELETE
(`pg.rs:1321–1327`). Only two dedicated guards read this GUC:
`file_genesis_guard` (`docs/schema.sql:157–168`) permits a genesis DELETE **iff** the GUC is
`'on'` and forbids UPDATE unconditionally; `file_versions_guard` (`schema.sql:186–203`)
permits a *finalized* version DELETE only under the GUC (staged rows were always GC-able) and
forbids any finalized-row UPDATE. `current_setting(name, true)` returns NULL on every other
path, so removal stays impossible everywhere but `delete_file`. Critically the **shared**
`maxsecu_forbid_update_delete()` — still bound to `directory_bindings`
(`schema.sql:78–79`) and `control_log` (`schema.sql:305–306`) — is untouched, so the
key-transparency / tamper-evidence chain remains fully immutable even inside the delete
transaction. No non-DELETE statement runs under the GUC (the txn does one owner-check SELECT,
a member SELECT, then three DELETEs), and there is no SQL-injection surface (all queries are
parameterized), so the GUC cannot be turned on from any other code path. Assessment: a
deliberate, correctly-bounded relaxation of append-only for owner-initiated **content**
deletion — the immutability that backs tamper-evidence is preserved.

**Cold-tier purge — OK.** `delete_file` collects every stream's `blob_ref` across all
versions of all targets **before** deleting the rows (`pg.rs:1355–1361`;
`store.rs:1296–1306`) and returns them; the handler purges each via
`st.blobs.delete_stream(r)` (`http.rs:1646–1648`), which cascades to the cold tier
(`WriteBackTier`/`dropbox_tier` `delete_stream`). Purge is best-effort *after* the DB commit
(a purge error is logged, not fatal) — a defensible ordering: the authoritative removal is
the DB row; a stranded cold blob is unreachable ciphertext, not a disclosure.

### 1.2 Bundle content-verify / content-substitution

**Threat.** The untrusted server must not be able to tamper with a bundle's membership or
order, nor substitute any other validly-signed record the viewer can decrypt in place of a
requested member.

**Membership/order are signed — OK.** A bundle's authoritative member list is the decrypted
`StreamType::Content` bytes decoded as `BundleBody`
(`crates/client-app/src/commands/bundle.rs:178–184`), which is sealed + digested + covered by
the author-signed `Manifest` exactly like any content stream. `BundleBody`
(`crates/encoding/src/structs.rs:485–508`) preserves order verbatim ("neither sorts nor
de-duplicates"). `open_bundle_members` sources members **only** from this signed body and
comments the invariant explicitly ("NEVER read members from a server-served listing";
`bundle.rs:176–177`).

**Requested-id discipline, single guard — OK.** The bundle is opened by the **requested** id:
`hex16(req_file_id)` (`bundle.rs:67`) → `run_open(identity, file_id, …)` (`bundle.rs:150`) →
`build_verify_ctx(file_id, …)` (`crates/client-app/src/directory.rs:51`) →
`verify_header` enforces `manifest.file_id != ctx.file_id ⇒ FileIdMismatch`
(`crates/client-core/src/download.rs:214`, and again on genesis `:226`). The consolidation to
a single `build_verify_ctx` is real: all five open paths (viewer content `viewer.rs:469`,
video header `viewer.rs:454`/`video.rs:103`, feed card `feed.rs:208`, bundle `viewer.rs:469`
via `run_open`, download `download_cmd.rs:404,425`) call the one builder — no drifted copy
sourcing `file_id` from the served manifest (which would make the check a tautology). Each
member is then fetched by its **signed** id and run through the identical per-file ladder.
GATE-5 (`browse_view_e2e.rs:598`) exercises the substituted-record rejection.

**Server `listed`/`bundle_id` are untrusted metadata — OK.** They are set once at v1 genesis
(`pg.rs:640–647`; `store.rs:562–563,908–909`) and drive only feed-hiding
(`GET /v1/files … WHERE … listed = true`, `pg.rs:946`; memory `.filter(|f| f.listed)`
`store.rs:1049`) and the delete/reshare cascade. They are never part of a signed manifest and
never feed a verification/auth decision — a malicious flip is an availability issue only,
consistent with the untrusted-server model.

### 1.3 Concurrency / the authed connection pool

**Threat.** Parallel feed-card decodes must not introduce an identity/DEK race, must keep
channel-bound tokens from crossing channels, and must fail closed on a stale token — without
leaking key material across the seam.

**No identity/DEK race — OK.** The pool (`crates/client-app/src/commands/pool.rs`) caches
whole authed channels as one unit `{sender, host, token}` and hands each concurrent borrower a
**different** cached channel, so the hot path never re-auths, never takes the `ConnectLock`,
and never takes the identity. A cold mint calls the existing `reauth` under an internal async
**auth gate** (`acquire` §3, `pool.rs:124–132`) so `reauth` is never concurrent and its
`ConnectLock` `try_lock` (`connection.rs:232`) never races itself. The identity/DEK borrow
discipline in `reauth` is reused verbatim. `decrypt_card` borrows the unlocked identity only
across the synchronous verify.

**Channel-bound token, fail-closed — OK.** A token never leaves its channel. A pooled channel
older than `REUSE_WINDOW_MS` (20 min, one-third of the 60-min server TTL) is discarded and
re-minted (`take_fresh_idle`, `pool.rs:156–166`). On a 401, `decrypt_card` both
`drain_idle()`s the whole pool (every same-era sibling is stale) and `mark_bad()`s its channel
so it is discarded on drop, then re-acquires once, forcing a genuinely-fresh mint; a second
401 is classified as session-expired (`feed.rs:299–315`; `pool.rs:140–152,191–197,214–227`).
A failing mint releases its permit (`authed_pool_releases_permit_on_mint_error`). The pool's
idle set uses a `std::Mutex` held only for a trivial push/pop, never across `.await`.

**Seam stays DTO-only — OK.** A workspace grep of every `#[tauri::command]` return type found
no `Identity`/`Dek`/`DownloadBundle`/`UploadBundle`/`plaintext`/`secret` crossing the seam.
Pooled channels live in Tauri managed state (TCB) and never cross it.

**Client decodePool cancellation — OK (by design).** Queued (not-yet-started) jobs reject with
`CancelledError` on feed teardown; in-flight jobs run to completion (or are abandoned by the
caller) — no shared decode state is corrupted (the backend content cache is mutex-guarded).

### 1.4 `reshare_bundle` fan-out

**Threat.** A partial share (bundle file shared but a member failed) must never be reported as
a full success; the fan-out set must be tamper-proof.

**OK.** `reshare_bundle` (`crates/client-app/src/commands/share.rs:293`) sources the target
set from the **verified signed** `BundleBody` via `open_bundle_members`
(`share.rs:308–310`) — a bundle that cannot be verified is a whole-command `Err` (we refuse to
fan out on unauthenticated membership). Each target reuses the reviewed per-recipient
`reshare_inner` crypto; `aggregate_bundle_outcomes` (`share.rs:251–281`) marks a recipient
`ok` **only if every target** (bundle + all members) shared to them — the first failing (or
missing) target's sanitized code wins, so a partial share is reported as a per-recipient
failure, never full success. Per-recipient fail-isolation is preserved.

### 1.5 `download_content`

**Threat.** Download must be content-substitution safe, bounded in RAM, atomic (no partial
output), and authorize any legitimate wrap-holder without an oracle.

**OK.** `download_content` (`crates/client-app/src/commands/download_cmd.rs:181`) validates and
binds the **requested** id (`hex16` → `build_verify_ctx`, `:190,404,425`). Streaming types
(video/generic) decrypt chunk-by-chunk with the **absolute** index via
`decryptor.open_range(i, …)` — a substituted/mis-positioned chunk fails the AEAD AAD and
fails closed (`:463–484`); RAM is O(one chunk) and each `plaintext` is `Zeroizing`
(`:486`). Output is atomic: an `AtomicFile` writes a unique `.part` sibling on the same volume
and `commit()`s with a rename; any early return drops the sink (RAII `Drop` removes the temp,
`download_cmd.rs:150–156`), so no partial file is left at `save_path`
(`:441–444,488`). Authorization is "open success == authorized" — any wrap-holder who can
decrypt is allowed. A bundle id is rejected as `bad_request` ("Download members individually",
`:223–228`). Byte-identity is asserted by `generic_upload_download_byte_identical`.

### 1.6 Generic streaming upload (`stage_streaming_content`)

**Threat.** Uploading an arbitrary file must not delete or move the user's source, must stay
bounded in RAM, and must preserve the original filename privately.

**OK.** The generic arm calls `stage_streaming_content(… move_input=false …)`
(`crates/client-app/src/commands/upload.rs:517–520`), which **copies** the source into staging
and "never move/delete it" (`upload.rs:858–862`; `move_input=true` is used only for the
transcode-generated temp). Sealing streams from a disk reader (`seal_from_reader`) keeps RAM
at O(one chunk) and discards ciphertext during the digest pass (`:828–839`). The original
filename rides in the encrypted metadata JSON `{title, tags, filename}`
(`prepare_generic_metadata`, `upload.rs:38–41`), not in any server-visible field. The seal +
finish sequence runs under the session lock with no `.await` while the identity is borrowed
(`:806–843`).

### 1.7 Seam & privacy

**Threat.** Member order leaking to the server.

**OK.** Order lives only inside the encrypted, signed `BundleBody` content stream; the server
observes only the flat, **unordered** `listed`/`bundle_id` grouping (a member row carries a
`bundle_id` but no position). This unordered-grouping leak is an accepted metadata disclosure
per the design (§2 of the spec) — order and exact membership semantics stay private.

---

## 2. Threat-model coverage (bundles-relevant)

- **Server tampers with bundle membership/order:** closed — membership is the author-signed
  `BundleBody` content; the server flags are untrusted (§1.2).
- **Server substitutes a member with another signed record:** closed — requested-id binding in
  the single `build_verify_ctx` → `FileIdMismatch` (§1.2; GATE-5).
- **Owner-delete becomes an ownership oracle:** closed — absent and not-owner both → 404, and
  403/FORBIDDEN is never surfaced client-side (§1.1).
- **Delete removes another user's data:** closed — owner-scoped cascade predicate, two unit
  tests + a live-PG regression (§1.1).
- **Append-only tamper-evidence weakened by the delete carve-out:** closed — the GUC is
  transaction-local and only two content-table guards read it; `directory_bindings` /
  `control_log` keep the untouched shared guard (§1.1).
- **Blob leak after delete (incl. cold tier):** mitigated — refs collected pre-delete, purged
  via `delete_stream` which cascades to the cold tier (§1.1).
- **Identity/DEK race under parallel decode; token reuse across channels:** closed —
  channel-bound units, auth-gated cold mint, fail-closed 401 handling (§1.3).
- **Key/plaintext leak across the seam:** closed — DTO-only; grep-verified no command returns
  Identity/DEK/bundle/plaintext (§1.3).
- **Partial bundle share reported as success:** closed — aggregate requires every target (§1.4).
- **Partial download leaves a corrupt/partial file:** closed — atomic temp-then-rename, RAII
  cleanup (§1.5).
- **Generic upload destroys the user's source:** closed — copy, never move/delete (§1.6).

---

## 3. Findings

| # | Severity | Area | Finding | Disposition |
|---|----------|------|---------|-------------|
| — | **Critical / High / Medium** | — | **None.** No surface diverged from its claimed mitigation. | — |
| 1 | Low | Concurrency | **Pool cold-mint vs. `serial` reauth race.** Only `decrypt_card` uses the backend pool; a pool **cold mint** (or expiry re-mint) calls `reauth`, which `try_lock`s the single `ConnectLock`. If another `serial` command holds it, the mint returns a sanitized `busy` (`connection.rs:232`). Fail-closed and retriable — a transient UI error, not a security defect. | Accepted; documented. |
| 2 | Informational | Settings | **`decode_threads` has no runtime consumer.** `feed_concurrency` drives the pool cap (`main.rs:34`) and `transcode_threads` drives the upload transcode (`upload.rs:373–390`), but `decode_threads` is only loaded/clamped/persisted (`config.rs:267,387`) — playback moved to the native WebView2 decoder, so there is no confined-rav1d thread count to wire. Harmless dead setting. | Accepted; note for a later cleanup or re-wire if a confined decoder returns. |
| 3 | Informational | Sharing | **V2/PQ-hybrid bundle reshare is unit-covered, not e2e.** `reshare_bundle` reuses the already-reviewed per-recipient reshare crypto (which handles Suite::V2); the bundle fan-out's PQ path is exercised by unit/aggregate tests, not a dedicated hybrid e2e. Low residual risk (the crypto is unchanged and separately reviewed). | Accepted; optional future e2e. |
| 4 | Informational | Upload | **Abandoned partial-confirm orphan.** If a bundle upload fails after some members finalize, those members are `listed=false` (invisible) and are cleaned up by retry or by `cancel_bundle`'s cascade-delete. A hard-abandoned session (no retry, no cancel) could leave invisible orphaned member files server-side — a storage/availability nit, not a disclosure. | Accepted per design (§5.4 of the spec). |
| 5 | Informational | Server | **Cascade SELECT is not `FOR UPDATE`.** `delete_file`'s member enumeration (`pg.rs:1341`) does not row-lock members; a concurrent member-insert could race. Benign — a bundle and its members are created atomically by the single owner, and the enclosing transaction prevents a partial cascade. Documented in-code. | Accepted. |
| 6 | Informational | Privacy | **Unordered grouping metadata leak.** The server learns the (unordered) `bundle_id` grouping of members; order and content stay private in the signed body. | Accepted per design (§2 of the spec). |

---

## 4. Conclusion

**PASS.** The bundles feature adds a new destructive server endpoint and a new concurrency
path without weakening the TCB. The delete is owner-only with no oracle, its cascade is
owner-scoped (a foreign-owned member always survives — two unit tests + a live-PG
regression), and its append-only carve-out is a transaction-local `SET LOCAL` read by exactly
two content-table guards, leaving `directory_bindings`/`control_log` immutability intact; blob
purge cascades to the cold tier. Bundle membership and order are the author-signed content and
are opened by the requested id through the single consolidated `build_verify_ctx`
substitution guard; the server's `listed`/`bundle_id` flags are untrusted and drive only
feed-hiding and the owner-scoped cascade. The authed pool serializes cold mints behind an auth
gate, binds tokens to their channels, and fails closed on a stale token, with no
Identity/DEK/plaintext crossing the Tauri seam. Reshare never reports a partial share as full
success; download is content-substitution safe with per-chunk AEAD, O(one chunk) RAM, and
atomic temp-then-rename; generic upload copies (never deletes) the user's source. No
Critical/High/Medium findings; the six Low/Informational residuals are documented and
security-neutral. The two bundle e2e suites, the requested-id GATE-5, and the server
delete/cascade tests all pass.
