# Post-Upload Multi-Recipient Sharing — UI Design

**Status:** APPROVED — all open questions resolved (2026-07-02), ready for implementation. No code in this document.
**Branch context:** local `main` (unpushed). Additive to the media-app UI stack (Phases 1–7, all merged).

## 0. Locked decisions (2026-07-02) — these OVERRIDE any hedging in later sections

- **D-OQ1 — Revocation anchor = SECURE SINK ANCHOR.** The reshare command sources the
  anchored control-log head from the out-of-band sink via the Phase-7
  `HttpSinkClient::fetch_control_pos` client (a client-app→sink call that bypasses the
  untrusted app server for the anchor), NOT the server's advisory `chain_head`. This
  makes reshare the **first real authenticated-`TombstoneSet` path in client-app** —
  today the viewer ships `tombstones: None` (§2.4.4). The `TombstoneSet` MUST be built
  via `TombstoneSet::verify_authenticated` against that sink-anchored head. (Retrofitting
  the viewer's `tombstones: None` is a *possible follow-up*, not required by this feature.)
- **D-OQ3 — Share surface = ANY WRAP-HOLDER, not owner-only.** The Share affordance is
  shown to anyone who can open the file (i.e. holds a wrap), matching `build_reshare`'s
  generic `granter`. Consequence: **the `mine`-gating in §2.4.6 / §3 is NO LONGER a
  restriction** — Share is available to any viewer, and the DEK is recovered from the
  *caller's own* served wrap (`recipient_id == Id(my_id)`), which any wrap-holder has.
  Gap 6 (`OpenedContentDto.mine`) is downgraded to optional display metadata, not a gate.
  The sharing-DAG UX (a non-owner reshare produces a normal `GrantAction::Reshare` edge
  whose `granted_by` is the resharer, already subtree-walk-visible per §7) needs no new
  plumbing.
- **D-OQ5 — No batch-size cap.** `recipient_usernames.len()` is unbounded; large batches
  are sequential idempotent POSTs on one connection (slow, not unsafe). Revisit only if
  usage justifies it.
- **D-OQ2 — UI chrome:** build a NEW `<share-dialog>` (modal picker + immediate results)
  AND a NEW `<share-tray>` (passive `EVT_RESHARE` surface). Do not overload `<upload-tray>`.
- **D-OQ4 — `VerifiedAuthor.mlkem_pub`:** add the field to the shared `VerifiedAuthor`
  struct (forwarding the `v.mlkem_pub` the verifier already returns) as its OWN small,
  independently-reviewable step landed before the reshare command.

## 1. Goal & scope

Let the **owner** of an already-uploaded file extend **read** access to N additional
directory-verified recipients, after the fact, from the running app — no offline
ceremony, no re-upload, no new file version.

**In scope:**
- A recipient picker + "Share" flow reachable from an owned item.
- Wrapping the file's DEK to each new recipient's directory-verified key and posting
  the resulting grant to the server, one recipient at a time, with per-recipient
  progress/failure and safe retry.
- Fail-closed directory verification and tombstone-gating of every recipient before
  any wrap is produced.
- Tray-style feedback mirroring the upload tray.
- Interaction with the existing revocation/audit machinery (already built).

**Out of scope (explicitly):**
- Granting **write** — re-share never confers write; owner-only write is D29 and is
  unconditional (`crates/client-core/src/reshare.rs` doc comment, line 12).
- A **non-owner** re-sharing further (any current wrap-holder *can*, cryptographically
  — `build_reshare`'s `granter` is generic — but this spec's UI surface only exposes
  the flow to the owner, matching "post-upload sharing" as scoped by the caller. A
  recipient-initiated re-share is a possible future UI surface, not built here).
- Revoking access (soft- or strong-revoke) — those UIs are separate work; this spec
  only describes how a reshared grant *interacts* with revocation that already exists.
- Cross-version re-share semantics beyond what the current single-version file model
  needs (the file model here is version 1, no rotation UI yet).
- The K-of-N recovery / PQ re-enrollment ceremonies (Phase 7 add-ons) — orthogonal.

## 2. What already exists (grounding) — and one central surprise

The **crypto core and server endpoint for re-sharing are already built, tested, and
wired end-to-end.** The gap is entirely in the client-app command/UI layer, which has
never called them. Concretely:

### 2.1 The reshare primitive — `crates/client-core/src/reshare.rs`

`pub fn build_reshare(params: &ReshareParams, dek: &Dek, tombstones: &TombstoneSet) -> Result<WrapOut, ReshareError>`

- `ReshareParams<'a>` carries: `granter: &'a Identity`, `granter_id`, `file_id`,
  `version`, `dek_commit: [u8;32]`, `recipient_id`, `recipient_enc_pub: EncPublicKey`,
  `suite: Suite`, `recipient_mlkem_pub: Option<[u8;1184]>`, `created_at: Timestamp`.
- Enforces, in order: (1) possession — `dek.commit() == params.dek_commit` or
  `ReshareError::DekCommitMismatch`; (2) never targets the recovery sentinel
  (`ReshareError::RecipientIsRecovery`); (3) tombstone gate — refuses an
  account-wide- or per-file-revoked recipient via `tombstones.is_account_revoked` /
  `is_revoked` (`ReshareError::RecipientRevoked`); (4) wraps the DEK under the
  **file's own suite** (`Suite::V1` classical or `Suite::V2` hybrid via
  `wrap_dek_hybrid` + `pack_hybrid_wrap`, failing closed with
  `ReshareError::ResharePqKeyMissing` if a V2 file targets a non-PQ recipient); (5)
  signs a possession-entailing `Grant{granted_by: granter_id, …}` with the granter's
  signing key.
- Returns a `WrapOut` — exactly the shape `POST /v1/files/{id}/wraps` expects
  (`crates/client-app/src/upload.rs::wrap_wire` already knows how to serialize a
  `WrapOut` for the wire; `stage_body` builds the JSON `wraps[]` shape this endpoint
  also uses).
- Already unit-tested for: a successful re-share + openable wrap, DEK-commitment
  mismatch, recovery-recipient rejection, account-wide revoke rejection, per-file
  revoke rejection, V2 hybrid round-trip, V2-to-classical-recipient rejection.

### 2.2 The server side — `crates/server/src/files.rs` + `crates/server/src/http.rs`

- `POST /v1/files/{file_id}/wraps` → `add_wrap` (`http.rs:1338`). Body is one
  `WrapReq` (recipient_id, recipient_type, wrapped_dek_b64, wrap_alg, granted_by,
  grant_b64, grant_sig_b64) — the same shape `stage_body`'s `wraps[]` entries use.
  `201` on success; `400` on a malformed/inconsistent wrap (`granted_by` not the
  caller, or recipient is recovery/non-user — `AddWrapError::BadRequest`); `404` if
  the file is absent, unfinalized, or **the caller holds no wrap for the current
  version** (`AddWrapError::NoAccess`, deliberately indistinguishable — no access
  oracle).
- `Store::add_wrap` (`crates/server/src/store.rs:336`) is **idempotent by
  recipient — "a re-share replaces an existing row."** This is load-bearing for §4
  below: re-sharing to someone who already has a wrap is a no-op-equivalent success,
  not an error.
- `GET /v1/files/{file_id}/recipients` → `list_recipients` (`http.rs:1460`),
  owner-only, `404` on a missing file or non-owner caller (no oracle). Returns each
  recipient's `recipient_id`, `granted_by`, `grant_b64`/`grant_sig_b64`, and
  `ancestor_grants`. This is the existing endpoint to read "who already has this
  file" for idempotency/duplicate detection in the picker.
- `DELETE /v1/files/{file_id}/wraps/{recipient_id}` → `delete_wrap`, soft-revoke,
  owner-or-granter gate — the interaction point covered in §6.
- **Audit sink wiring is already complete and tested.** `crates/server/src/audit.rs`
  defines `GrantAction::{Author, Reshare, SoftRevoke}` and `GrantEdge`; `add_wrap`
  and `delete_wrap` already emit `GrantAction::Reshare` / `GrantAction::SoftRevoke`
  edges to the injected `Arc<dyn AuditSink>` on success (proven in
  `crates/server/src/http.rs` tests around line 3118–3131: re-share → a `Reshare`
  edge with the correct `granted_by`/`recipient_id`; soft-revoke → a `SoftRevoke`
  edge). **Nothing new is needed server-side or in the audit path.**

### 2.3 What client-app has today (upload, as the pattern to mirror)

- `crates/client-app/src/commands/upload.rs::{stage_upload, confirm_upload,
  cancel_upload, upload_jobs}` — the **preview-then-confirm** two-command pattern:
  `stage_upload` does all local work (no network write) and returns a DTO preview;
  `confirm_upload` runs the network pipeline and emits phase events; the staged
  content lives in `crates/client-app/src/jobs.rs::UploadJobs` (an
  `Arc`-managed `Mutex<HashMap<job_id, StagedUpload>>`) so it never crosses the seam
  as a value.
- `crate::commands::connection::{reauth, server_of, open_conn}` — every authed call
  re-authenticates on a **fresh channel** via `reauth(dir, server, session,
  connect_lock)`, which `try_lock`s the single `ConnectLock` (returns
  `UiError{code:"busy"}` if one is already in flight) and transiently borrows the
  **non-`Clone` `Identity`** out of `Session` for exactly the synchronous signing
  step, restoring it before returning. This is why the UI serializes authed calls
  through one FIFO queue (below) — two authed commands cannot run concurrently.
- `crates/client-app/ui/src/core/serial.ts::{serial, serialPriority}` — the
  single-flight async queue every reauth-bound UI call is routed through
  (`upload-tray.ts`'s retry button: `serial(() => call("confirm_upload", …))`).
- `crates/client-app/src/state.rs` — the `EVT_<NAME>` + kebab-tagged phase-enum
  convention: `EVT_UPLOAD = "maxsecu://upload-state"` /
  `UploadPhase{Encrypting,Staging,Uploading{done,total,bytes_per_s},Finalizing,Done,Failed}`;
  `EVT_FETCH` / `FetchPhase`; `EVT_VIDEO_PREPARE` / `PreparePhase`. A new share flow
  should add a fourth: `EVT_RESHARE` / `SharePhase`.
- `crates/client-app/ui/src/components/upload-tray.ts` — the tray UI to mirror:
  one `<section aria-label="…" aria-live="polite">`, one `<li data-job="…">` per
  job holding a `<state-badge>` + `<progress-meter>`, a bounded ETA calc, a Retry
  button that re-invokes the confirm command through `serial()`, auto-clear on
  success after 4s.
- `crates/client-app/src/directory.rs` — the D5-verification primitives:
  `verify_author_binding`/`resolve_and_verify_author` (by `user_id`, via `GET
  /v1/directory/by-id/{hex}`) and `verify_recovery_binding`/`resolve_recovery_recipient`
  (by username, via `GET /v1/directory/{username}`). **Gap** (see §2.4):
  `VerifiedAuthor` does not carry `mlkem_pub`; only `RecoveryRecipient` does.
- `crates/client-app/ui/src/components/media-card.ts` — `card.mine` (from
  `CardDto.mine`, `crates/client-app/src/dto.rs:137`) already gates the
  "only my uploads" filter (`mine-only` attribute → `this.remove()` if not mine).
  This is the natural gate for a "Share" affordance too.

### 2.4 Gaps this design must close (new work, called out explicitly)

These are real, verified gaps — not hypothetical — found by reading the code, and
each is scoped as "new" below rather than invented as if it already existed:

1. **No client-app reshare command exists.** `grep -r reshare crates/client-app` and
   `grep -r Reshare crates/client-app` both return nothing (checked in both `src/`
   and `ui/`). `build_reshare` has zero callers outside its own test module.
2. **`VerifiedAuthor` (directory.rs) has no `mlkem_pub` field.** `ReshareParams`
   needs `recipient_mlkem_pub: Option<[u8;1184]>` for a `Suite::V2` file. Only
   `RecoveryRecipient` (recovery-specific) carries it today, via the same
   `verifier.verify_binding(...)` call that already returns `v.mlkem_pub` — the
   plumbing exists one layer down, it is just not forwarded into `VerifiedAuthor`.
3. **No client-app path resolves an arbitrary third-party recipient by username** for
   a non-recovery, non-self purpose. `resolve_my_binding`/`resolve_recovery_recipient`
   are semantically "me" / "the recovery sentinel"; a reshare needs the equivalent
   for "some other user the owner names."
4. **No client-app TombstoneSet construction anywhere in production code.**
   `grep -r TombstoneSet crates/client-app/src` matches nothing (only the e2e test
   `bootstrap_admin_e2e.rs` touches the control log, and not via `TombstoneSet`).
   The existing viewer path (`commands/viewer.rs::run_open`) passes
   `tombstones: None` into `VerifyContext` — revocation enforcement is **not yet
   wired into the shipped app's download ladder at all.** `build_reshare`, by
   contrast, takes `tombstones: &TombstoneSet` as a **mandatory, non-optional**
   argument — there is no way to call it without one. This makes fetching the
   control log and building a verified `TombstoneSet` (via
   `TombstoneSet::verify_authenticated`, `crates/client-core/src/revocation.rs:190`)
   a **hard prerequisite** for this feature, not an optional hardening step. `GET
   /v1/revocations` exists server-side (`docs/api.md` §7.1) but has no client-app
   caller today.
5. **No client-app path recovers the owner's own DEK outside the upload
   pipeline.** The viewer's `verify_and_open`/`verify_and_open_headers` unwrap the
   DEK internally (`crates/client-core/src/download.rs:304-318`) but `OpenedFile`
   /`OpenedHeader` never expose it (by design — the viewer only needs plaintext
   streams). The reshare flow needs the **raw DEK** to call `build_reshare`. The
   closest existing pattern is `crates/client-app/src/commands/upload.rs`'s
   `streaming_confirm`, which recovers the DEK from a **persisted self-wrap**
   (`WrappedDek` bytes on disk) via `unwrap_dek`/`unwrap_dek_hybrid` +
   `WrapContext`. A reshare has no persisted self-wrap lying around — it must fetch
   the file's own view (`GET /v1/files/{id}?version=latest`, the same call
   `open_content_inner` makes) and unwrap the **served self-wrap** for the current
   owner, mirroring `verify_header`'s unwrap step (`download.rs:304-318`) but
   **without discarding the DEK afterward.**
6. **`OpenedContentDto` has no `mine` field.** `open_content_inner`
   (`crates/client-app/src/commands/viewer.rs`) already computes `my_id ==
   author.user_id` for the content-cache's `mine` field (line 334) but never
   returns it to the UI. The viewer is the most natural "Share" entry point (the
   user is already looking at the item) and needs this to gate the button, mirroring
   `CardDto.mine`.
7. **No client-app wrapper for `GET /v1/files/{id}/recipients`.** Needed for
   duplicate/idempotency awareness in the picker (§4).

None of these are large — each is a small, additive extension of an existing
pattern — but all seven must land before the "Share" button can do anything real.

## 3. Recipient picker UX

**Entry point.** A "Share…" action on an item the owner owns:
- On `<media-viewer>` (`crates/client-app/ui/src/components/media-viewer.ts`), next
  to the back-link, **gated on a new `mine: bool` on `OpenedContentDto`** (§2.4.6).
  Not shown for an item the current user does not own (view-only for everyone else
  — matches D29 owner-only-write; sharing is an owner privilege by this spec's scope).
- Opens a **new `<share-dialog>`** component (modal, `role="dialog"`,
  `aria-modal="true"`, labelled by its heading, first focusable element focused on
  open, `Escape` closes, focus trapped and returned to the invoking button on close —
  matching the a11y bar already enforced elsewhere: `:focus-visible` rings
  (`styles.css:756`), `[data-reduced-motion]`/`prefers-reduced-motion`
  (`styles.css:760-768`), `[data-high-contrast]` (`styles.css:94-100`)).

**Recipient entry.** A text input, "Add a recipient by username," plus an "Add"
button (Enter also submits). Rationale for **username, not raw user_id**: every
existing directory lookup the app performs from the UI keys on username
(`resolve_recovery_recipient`, `resolve_my_binding`, the connect screen's own
username) — `resolve_and_verify_author` (by `user_id` hex) exists only because the
*manifest* names an author by id; a human never types a `user_id` hex string. The
new resolver (§2.4.3) is `GET /v1/directory/{username}` — the same unauthenticated
endpoint `resolve_recovery_recipient`/`resolve_my_binding` already use, so no new
server route is needed.

**Resolution + verification, per entry, BEFORE it is added to the share list:**
1. `GET /v1/directory/{username}` (unauthenticated, like today's directory calls).
2. `404` → "This username is not published." (mirrors
   `resolve_recovery_recipient`'s `"The recovery recipient is not published."`) —
   entry rejected, not added.
3. `200` → decode `(binding_bytes, signature)` via the existing `parse_binding`
   helper, then verify under the **pinned D5** exactly as `verify_author_binding`
   does (`DirectoryVerifier::verify_binding`) — any failure (bad signature, expired
   `not_before`/`not_after`, malformed bytes) → `"untrusted"` → "This user's identity
   could not be verified." Entry rejected, not added. **No partial trust**: a
   verification failure never adds a "trust me later" placeholder row.
4. Resolve **self** — reject "You are already the owner" if the entered username is
   the caller's own (self-share is meaningless, not an error state the user needs
   surfaced as a failure; see §7).
5. Reject the recovery-sentinel username if configured/knowable client-side (defense
   in depth; `build_reshare` already rejects `RECOVERY_ID` server-independently, so
   this is a nicer error message, not a security boundary).
6. On success, the row shows: display name, a short fingerprint (first 8 bytes hex,
   matching `author_fp` elsewhere in the UI), and a state chip: **"Verified"**
   (green, non-color-only per the existing `<state-badge>` convention) or a pending
   spinner while step 1–3 run.
7. **Duplicate/already-has-access awareness (not a hard block):** the dialog also
   calls the new `list_recipients` wrapper (§2.4.7) once, on open, and cross-checks
   each entered username's resolved `user_id` against the returned recipient set. A
   match shows an inline **"Already has access"** note next to that row but does
   **not** disable "Share" for it — re-sharing to an existing recipient is a
   harmless idempotent no-op server-side (`Store::add_wrap` "replaces an existing
   row"), so blocking it would only be UX polish, not a correctness requirement; see
   §4.

**Fail-closed, no partial share, by construction — not merely by convention:** the
picker performs directory resolution/verification for **every** entered recipient
before "Share" is enabled at all. "Share" only becomes clickable once at least one
row is in the `Verified` state; each row's crypto wrap only happens after its own
verification succeeded, so a row that failed verification is never fed to
`build_reshare` — there is no code path that produces a wrap from an unverified
binding.

## 4. The reshare command/DTO seam

Mirrors `stage_upload`/`confirm_upload` — a **single-shot pattern is sufficient
here** (no long transcode step to preview), but the *shape* still separates
"resolve everything, hold it" from "confirm and run the network calls," so a partial
failure can be retried without re-verifying already-verified recipients.

### New DTOs (`crates/client-app/src/dto.rs`)

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct ResolveRecipientRequest {
    pub username: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ResolvedRecipientDto {
    pub username: String,
    pub user_id: String,      // hex16, opaque to the UI
    pub fingerprint: String,  // first 8 bytes hex, display-only
    pub already_shared: bool, // cross-checked against list_recipients
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReshareRequest {
    pub file_id: String,
    /// Already-resolved user_ids (hex16) from ResolvedRecipientDto — the dialog
    /// resolves first, THEN this command re-verifies + wraps. Re-verifying here
    /// (not trusting the earlier resolve) closes a TOCTOU window where a binding
    /// could be re-signed/rotated between picker-open and Share-click.
    pub recipient_usernames: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReshareOutcomeDto {
    pub username: String,
    pub ok: bool,
    /// Sanitized code on failure (e.g. "untrusted", "revoked", "pq_key_missing"),
    /// None on success.
    pub code: Option<String>,
}
```

Only these DTOs cross the seam — never a `WrapOut`, never a `Dek`, never an
`Identity`. This matches the file-level comment already at the top of `dto.rs`:
*"No key material, no signed-record interiors, no whole-plaintext buffers ever
appear here."*

### The command (`crates/client-app/src/commands/share.rs`, new)

```rust
#[tauri::command]
pub async fn reshare_file(
    req: ReshareRequest,
    app: tauri::AppHandle,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
) -> Result<Vec<ReshareOutcomeDto>, UiError>
```

Single command, no `stage_*`/`confirm_*` split, because unlike upload there is no
expensive local transcode to preview before committing network — the "preview" *is*
the picker's per-recipient verification (§3), which already ran before the user
clicked Share. Flow, one `reauth` per whole call (not per recipient — see §4
rationale below):

1. `let (mut sender, host, token) = reauth(&dir.0, &server, &session,
   &connect_lock).await?;` — one fresh channel, one borrow of the identity's
   signing key for the whole batch's grant-signing (all synchronous, no `.await`
   while borrowed — mirrors `run_open`/`streaming_confirm`'s borrow discipline).
2. **Fetch the file's own view** (`GET /v1/files/{file_id}?version=latest`,
   `parse_file_view`, same call `open_content_inner` makes) to get the manifest +
   the owner's own served wrap.
3. **Recover the DEK** from the owner's self-wrap: `unwrap_dek` (V1) or
   `unwrap_dek_hybrid` + `crate::download::unpack_hybrid_wrap`-equivalent (V2, new
   client-app-side helper mirroring `client-core::upload::unpack_hybrid_wrap`'s
   already-proven logic) under the identity borrow, using
   `WrapContext{file_id, version: manifest.version, recipient_id: Id(my_id)}`.
   Assert `dek.commit() == manifest.dek_commit.0` — self-validating, exactly as
   `verify_header` does; a mismatch is `UiError::new("verify_failed", …)`, never
   silently proceeds.
4. **Fetch + verify the control log** into a `TombstoneSet`:
   `GET /v1/revocations?scope=account` and `?file_id=<hex>` (or a combined fetch —
   an implementation detail), then `TombstoneSet::verify_authenticated(records,
   anchored_head, issuer_resolver)`. The `anchored_head` source mirrors the
   Phase-7 R27 add-on's `HttpSinkClient::fetch_control_pos` pattern (memory:
   "sink `GET /v1/control-log/position?chain_seq`") — **this is new integration
   work, not a one-line call**; see §10 open question OQ-1.
5. For each `recipient_usernames` entry, **re-resolve + re-verify** (§3 step 1–3,
   not trusting the picker's earlier resolve — TOCTOU closure) under the pinned D5,
   this time via the extended resolver that also returns `mlkem_pub` (§2.4.2/§2.4.3).
6. For each successfully re-verified recipient, call `build_reshare(&params, &dek,
   &tombstones)`. `ReshareError::RecipientRevoked` → `ReshareOutcomeDto{ok:false,
   code:"revoked"}`; `ReshareError::ResharePqKeyMissing` →
   `code:"pq_key_missing"`; others map similarly. **Never abort the batch on one
   recipient's failure** — see §5 all-or-nothing-vs-per-recipient decision.
7. `POST` the resulting `WrapOut` to `/v1/files/{file_id}/wraps` per recipient
   (§4's batching, next section) using the SAME `sender`/`token` from step 1 — no
   re-`reauth` per recipient.
8. Emit `SharePhase` events per recipient over a new `EVT_RESHARE`
   (`"maxsecu://reshare-state"`), mirroring `UploadPhase`'s tag-per-variant style.
9. Return `Vec<ReshareOutcomeDto>` — the UI renders success/failure per row.

**Why one `reauth` for the whole batch, not one per recipient:** `reauth`
`try_lock`s the single process-wide `ConnectLock`; a second concurrent `reauth`
(e.g. from another tab/action) gets `busy`. Sharing to N recipients inside one
command holding one channel avoids N lock acquisitions and N TLS handshakes, and
matches `run_pipeline`'s one-`reauth`-covers-many-PUTs pattern in
`crates/client-app/src/upload.rs`. The identity is borrowed only for the brief
synchronous DEK-unwrap + per-recipient grant-signing steps (3 and 6), never held
across an `.await` — same discipline as every existing command.

**Owner-only enforcement — where it actually lives:** the crypto path does not
special-case "owner" at all (`build_reshare`'s `granter` is any current wrap
holder); the *server* enforces it structurally via `AddWrapError::NoAccess` (the
caller must hold a wrap for the current version — an owner always does, from their
self-wrap at upload) and the DEK-recovery step above only succeeds because this
command specifically fetches the OWNER'S OWN self-wrap (`recipient_id ==
Id(my_id)`, the authed session's own id). The UI-level restriction (§3, gating the
Share button on `mine`) is advisory/UX only; the real boundary is that a non-owner
calling this command would fail at step 3 (no self-wrap for a file they don't own —
unless they too were a recipient with their own wrap, in which case they
*cryptographically can* reshare their own copy, which is correct per §12.4b's design
and simply out of this feature's UI surface, not a bug).

## 5. Multi-recipient batching

**Per-recipient, not all-or-nothing.** One recipient's failure (revoked, unverifiable
binding, PQ key missing, transient network error on the POST) must not roll back or
block the others — each `POST /v1/files/{id}/wraps` call is independent, and
`Store::add_wrap`'s per-recipient idempotency means retrying just the failed rows is
always safe. This also matches the picker's own per-row verification model (§3): the
user already saw which rows were "Verified" before clicking Share, so a downstream
failure (e.g. the control log revealed a mid-flight revoke, or the POST hit a
transient 500) is surfaced per-row, not as one opaque batch error.

**Idempotency.** Re-sharing to a recipient who already holds a wrap for this version
is **not an error** — `Store::add_wrap` replaces the existing row (grounded in
§2.2). The picker best-effort flags this in advance (§3 step 7,
`already_shared: true`) as a UX nicety, but the command does not skip or special-case
it: calling `build_reshare` + POST again for an already-shared recipient is safe,
produces the same semantic grant (freshly re-signed with a new `created_at`), and
returns `ok: true`. This means **retrying a partially-failed batch is simply
re-running `reshare_file` with the same recipient list** — the successes are
harmless no-ops, only the previously-failed rows do new work. No separate "retry just
the failed ones" bookkeeping is needed client-side (unlike the upload tray's
checkpointed `progress` counter, which exists because chunk PUTs are NOT
individually cheap to redo — here each recipient op is cheap and idempotent).

**Retry UX:** the `<share-dialog>` (or a follow-up toast, if the dialog has already
been dismissed) keeps the per-row outcome list; a row marked failed gets a "Retry"
button that re-invokes `reshare_file` with **only that one username** (a
single-element `recipient_usernames`) — cheaper than replaying the whole batch, and
avoids re-touching already-succeeded rows even though doing so would also be safe.

## 6. Tray/feedback UX

New `<share-dialog>` (modal, in-context) covers the interactive picker + immediate
per-row result. A companion **passive** surface mirrors the upload tray for the case
where the user dismisses the dialog before all rows finish (or shares in the
background while browsing):

- New `<share-tray>` custom element (or an extension of the existing
  `<upload-tray>` — a design choice for the implementation plan; functionally
  distinct data, same visual language), subscribing to `EVT_RESHARE`
  (`"maxsecu://reshare-state"`), one `<li>` per **file being shared**, nested rows
  or a summary count per recipient outcome (`"3 of 5 shared · 2 failed"`), a
  `<state-badge>` per recipient echoing `ReshareOutcomeDto.code`.
- `SharePhase` (new enum in `state.rs`, kebab-tagged like its siblings):
  ```rust
  pub enum SharePhase {
      Resolving { file_id: String, username: String },
      Verifying { file_id: String, username: String },
      Wrapping  { file_id: String, username: String },
      Recipient { file_id: String, username: String, ok: bool, code: Option<String> },
      Done      { file_id: String, shared: u32, failed: u32 },
  }
  ```
  No `bytes_per_s`/ETA field — wrapping a DEK and POSTing one JSON body per
  recipient is sub-second; a progress **count** ("2 of 5") is the right granularity,
  not a byte-rate meter (the upload tray's ETA math does not apply here — there is
  no large-payload streaming component to a reshare).
- Non-color-only status: every `<state-badge>` carries a text `label`
  (`"Verified"`, `"Failed: revoked"`, `"Shared"`) alongside its `state` attribute,
  matching the existing convention (`upload-tray.ts`'s `phaseLabel` map, never
  color alone).
- `aria-live="polite"` region for the running count, `role="alert"` (assertive) only
  for the terminal all-failed case — matching `admin-screen.ts`'s
  `role="status"`/`role="alert"` split for success vs. failure feedback.

## 7. Revocation interplay

**A reshared grant's place in the `granted_by` graph.** `build_reshare` signs
`Grant{granted_by: granter_id, recipient_id, dek_commit, file_id, file_version,
created_at}` — the owner (or whoever holds a wrap and re-shares) is the parent of
the new recipient in the sharing DAG. The server's audit sink already records this
as `GrantAction::Reshare{file_id, granted_by, recipient_id, at_ms}` (§2.2,
proven by the existing server test at `http.rs:3118-3125`). **This spec adds no new
audit-sink code** — it is a pure consumer of the already-complete Phase-4
`AuditSink`/`GrantEdge` machinery.

**Soft-revoke of a reshared recipient.** `DELETE
/v1/files/{file_id}/wraps/{recipient_id}` — the owner OR the original re-sharer
(`granted_by`) can soft-revoke (`http.rs`'s `delete_wrap`, owner-or-granter coarse
gate). This is a **server-side denial only** (`crates/server/src/files.rs:197-200`
doc comment: "not a cryptographic boundary"). A soft-revoked recipient who kept a
local copy of the ciphertext + their already-unwrapped DEK from before the revoke
retains cryptographic access to that content forever — soft-revoke only stops the
*server* from continuing to serve them.

**Strong-revoke (tombstone) of a reshared recipient.** An admin issues an
account-wide or per-file `revocation` record via `POST /v1/revocations` (dual-
control for account-wide, api.md §7.2). This is the real cryptographic boundary:
- `TombstoneSet::is_account_revoked`/`is_revoked` (§2.1) then refuses **any future
  re-share** to that recipient — `build_reshare` returns `RecipientRevoked` and this
  command's step 6 (§4) surfaces `code:"revoked"` for that row.
- It does **not** retroactively invalidate a wrap the recipient already holds from
  before the tombstone (that requires a version **rotation** with the recipient
  excluded — out of scope here; see `DESIGN.md` §12.9b's subtree-walk revoke flow,
  which is a separate, larger feature).
- The subtree walk for a strong-revoke (§12.9b step 4, "revoking a user also revokes
  everyone they re-shared to, transitively") is computed from the **audit sink's**
  `GrantEdge` graph, *not* the server-served wrap rows (R25, `audit.rs`'s module
  doc: "otherwise a malicious server colluding with a descendant could withhold that
  descendant's edge"). **This spec's re-share, by emitting a normal
  `GrantAction::Reshare` edge through the existing `add_wrap` handler, is
  automatically subtree-walk-visible** — no new plumbing needed for that guarantee;
  it falls out of using the existing endpoint rather than inventing a new one.

**Security note — the server cannot forge a share.** Every wrap the server stores
is inert bytes to it; `add_wrap`'s server-side checks (`parse_stage`-adjacent logic
in `files.rs`) are coarse and non-authoritative (`AddWrapError::BadRequest` only
catches an inconsistent `granted_by`/recipient-type — it never validates the
signature or the wrap opens to anything). The recipient (or anyone re-verifying the
grant chain on download, `crates/client-core/src/download.rs::verify_grant_chain`)
independently re-verifies: the grant is Ed25519-signed by `granted_by`'s
directory-verified `sig_pub`, `dek_commit` matches the manifest, and the chain
walks back to the author. A malicious server can **withhold** a share (deny
service) but cannot **fabricate** one that survives client-side verification — this
is the same trust model the whole download ladder already assumes, unchanged by
this feature.

## 8. Edge cases

| Case | Behavior |
|---|---|
| Recipient username not in directory | `404` from `GET /v1/directory/{username}` → row rejected before Share is even enabled for it ("This username is not published."); never silently skipped. |
| Recipient's `key_version` stale (rotated since last known) | Re-resolved fresh at Share-time (§4 step 5, TOCTOU closure) — the CURRENT binding is what gets wrapped to; no stale-key risk. If the recipient rotated to a suite the file can't reshare into (e.g. lost their ML-KEM key on a V2 file), `ReshareError::ResharePqKeyMissing` → `code:"pq_key_missing"`, surfaced per-row, "prompt them to re-enroll" per the existing doc comment on that variant. |
| Owner offline / connection drops mid-batch | `reauth` fails before step 1 completes → `Err` for the whole command (no partial network state to reconcile — nothing was POSTed yet). If the connection drops mid-batch (between recipients), already-POSTed rows are done (idempotent, safe); remaining rows are `Err`'d as a batch tail failure, retryable per §5. |
| File rotated to a new version between "open the picker" and "click Share" | `reshare_file` re-fetches the file view fresh at Share-time (§4 step 2) — it always wraps against the CURRENT `manifest.version`/`dek_commit`, never a version captured when the dialog opened. A rotation mid-dialog is invisible to the user except that the share lands on the newer version — acceptable (matches "share the file," not "share this exact stale snapshot"). |
| Sharing to self | Rejected client-side at picker-add time (§3 step 4) with a clear, non-alarming message — not routed to the server at all (the server would likely accept it as a harmless idempotent re-wrap of the existing self-wrap, but there is no product reason to allow it, and rejecting early avoids a confusing "Shared to yourself" row). |
| Duplicate username entered twice in one picker session | The picker dedupes by resolved `user_id` (not raw username string) before enabling Share — two different usernames that somehow resolved to the same `user_id` (shouldn't happen, but directory data is server-served) collapse to one row. |
| Re-sharing to someone who already has a wrap | Not an error — idempotent replace (§4/§5). Flagged informationally in the picker, not blocked. |
| Recipient is the recovery sentinel | Rejected both client-side (§3 step 5, nicer message) and server/crypto-side (`ReshareError::RecipientIsRecovery`, unconditional — defense in depth even if the UI-level check is ever bypassed). |
| File has no recipients yet beyond owner+recovery (fresh upload) | No special case — the picker's `list_recipients` call returns just the owner; every entered username is a fresh share. |
| Account-wide or per-file revoked recipient entered | Directory verification succeeds (revocation doesn't unpublish a binding) but `build_reshare` refuses at the tombstone gate → `code:"revoked"`, surfaced per-row with a message distinct from "not verified" (so the owner understands *why*, not just *that*, it failed). |

## 9. Security review checklist

Before this ships, a reviewer must independently confirm:

- [ ] **Only DTOs cross the Tauri seam** for this feature — no `WrapOut`, `Dek`,
      `Identity`, `TombstoneSet`, or raw grant bytes ever appear in a `#[tauri::command]`
      signature or a `dto.rs` struct (`ReshareRequest`/`ResolvedRecipientDto`/
      `ReshareOutcomeDto` carry only usernames, hex ids, booleans, and sanitized codes).
- [ ] **Every recipient's binding is D5-verified before any wrap is produced** —
      trace that `build_reshare` is only ever called with a `recipient_enc_pub`/
      `recipient_mlkem_pub` sourced from a successful `DirectoryVerifier::verify_binding`
      call in THIS SAME command invocation (not a cached/stale value from picker-open
      time — the TOCTOU re-verify at Share-time, §4 step 5, is not skippable).
- [ ] **The TombstoneSet passed to `build_reshare` is a real, chain-verified one**
      (`TombstoneSet::verify_authenticated`, never a synthesized/empty one used as a
      shortcut) and its `anchored_head` is fetched from the real out-of-band sink
      source (§10 OQ-1), not merely the server's advisory `chain_head`.
- [ ] **Owner-only in practice**: confirm the DEK-recovery step (§4 step 3) can only
      succeed for the caller's OWN self-wrap (`recipient_id == Id(my_id)` from the
      AUTHENTICATED session, never a client-supplied id) — this is what actually
      confines the command to "someone who holds their own wrap," including but not
      exclusively the owner.
- [ ] **No plaintext, DEK, or wrap ever appears in a `SharePhase` event or a log
      line** — event payloads carry only `file_id`, `username`, `ok`, and a sanitized
      `code` (mirrors `UiError`'s no-detail-leak convention throughout the codebase).
- [ ] **Fail-closed on every verification step** — a directory `404`, a bad
      signature, a decode failure, or a `TombstoneSet::verify_authenticated` error
      (`Gap`/`BrokenChain`/`Malformed`/`UnknownIssuer`/`BadAuthority`/`NotAdmin`/
      `DualControlMissing`) all reject that recipient (or the whole batch, for a
      log-fetch failure) rather than proceeding with a degraded/partial trust
      assumption.
- [ ] **A batch failure is per-recipient, never silently drops a row** — every
      entered recipient produces exactly one `ReshareOutcomeDto` in the response
      (no recipient can vanish from the result without an explicit `ok:false`).
- [ ] **Idempotent re-share is verified genuinely idempotent** end-to-end (not just
      assumed from the store doc comment) — a test re-shares to an already-wrapped
      recipient and confirms no error, no duplicate grant-edge side effect beyond
      what `Store::add_wrap`'s replace-semantics already produce.
- [ ] **The V2/PQ suite path is exercised**, not just V1 — a file uploaded under
      `Suite::V2` reshared to a PQ-enrolled recipient succeeds; reshared to a
      non-PQ recipient fails closed with `pq_key_missing`, never silently downgrades
      to a classical wrap (`build_reshare` already has no such downgrade path —
      confirm the UI layer doesn't add one).
- [ ] **`reauth`/`ConnectLock` discipline matches every other command** — no new
      code path holds the identity borrow across an `.await`, no code path skips
      `reauth`'s single-flight `try_lock`.

## 10. Testing plan

Mirror `crates/client-app/tests/upload_e2e.rs`'s style: a real TLS server, real
directory ceremony, real control-log, no mocked crypto. New `reshare_e2e.rs`:

1. **Owner shares to a fresh, directory-verified recipient** → `POST
   /v1/files/{id}/wraps` returns `201`; the new recipient's `GET
   /v1/files/{id}?version=latest` (a normal download) now succeeds and the content
   verifies (proves the wrap is genuinely openable — not just accepted).
2. **Idempotent re-share** — share to the same recipient twice; both calls return
   `ok:true`; `GET /v1/files/{id}/recipients` still lists exactly one row for that
   recipient (proves the store's replace-semantics, not an accumulating duplicate).
3. **Unverified/unpublished recipient rejected** — a username with no published
   binding never reaches `build_reshare`; the command returns `ok:false,
   code:"untrusted"` for that row and does not touch the network for a wrap POST.
4. **Tombstoned recipient rejected** — admin account-wide-revokes a user (dual-
   controlled, real `ControlChain`), then a reshare attempt to them returns
   `ok:false, code:"revoked"`; a *different*, non-revoked recipient in the SAME
   batch still succeeds (proves per-recipient isolation, §5).
5. **Batch partial failure + targeted retry** — a batch of 3 (one unpublished, two
   valid) returns 1 failure + 2 successes in one call; retrying with only the
   failed username (after publishing it) succeeds without re-touching the first two.
6. **V2/hybrid suite round-trip** — a `Suite::V2` file reshared to a PQ-enrolled
   recipient; the recipient's download unwraps via the hybrid path and verifies.
   A V2 file reshared to a non-PQ recipient fails closed with `pq_key_missing`.
7. **Non-owner cannot reshare a file they don't hold a wrap for** — a user with no
   wrap on the file gets a DEK-recovery failure (their own "self-wrap" fetch finds
   nothing addressed to them) before any wrap POST is attempted — proves the
   owner-only-in-practice boundary from §9's checklist, not just an assertion.
8. **Grant-edge/audit assertions** — confirm (reusing the existing
   `MemoryAuditSink` test harness already proven in `http.rs`'s own tests) that a
   successful reshare produces exactly one `GrantAction::Reshare` edge with the
   correct `granted_by`/`recipient_id`/`file_id`.
9. **UI-level a11y lint** — extend `crates/client-app/ui/src/a11y.test.ts`'s
   structural checks to cover `<share-dialog>`/`<share-tray>`: labelled dialog,
   `aria-live` region present, no color-only status, focus trap/return, all
   interactive elements keyboard-reachable — matching the existing 22-check
   dependency-free `node:test` pattern (no new axe/jsdom dependency, consistent
   with the P5 sign-off's stated deferral of full axe-in-jsdom).

## 11. Open questions / deferred — ALL RESOLVED, see §0

> **Resolved 2026-07-02 (see §0 for the binding decisions):** OQ-1 → secure sink anchor
> (D-OQ1); OQ-2 → new `<share-dialog>` + `<share-tray>` (D-OQ2); OQ-3 → any wrap-holder,
> not owner-only (D-OQ3); OQ-4 → extend `VerifiedAuthor` as its own step (D-OQ4); OQ-5 →
> no batch cap (D-OQ5). The original analysis is retained below for context.

- **OQ-1 — Where does the reshare command source the anchored control-log head?**
  The Phase-7 R27 add-on already built `HttpSinkClient::fetch_control_pos` /
  `fetch_genesis_pos` against the real sink for a DIFFERENT purpose (the R27
  version-freshness cutoff, server-side/e2e-only per the memory notes — "client-side
  R27-comparison over the REAL sink"). Does this feature reuse that same sink
  client from client-app (a new client-app→sink HTTP call, bypassing the untrusted
  app server for the anchor specifically, matching the sink-interface security
  model), or does it accept the server's advisory `chain_head` from `GET
  /v1/revocations` as a *pragmatic, explicitly-weaker* interim (documented as a
  known gap, matching the fact that `run_open`'s `tombstones: None` already ships
  today without full revocation enforcement)? This has real security-posture
  consequences (a malicious server could otherwise under-serve the control log and
  this feature would falsely treat a revoked user as clean) and should not be
  decided implicitly during implementation.
- **OQ-2 — `<share-dialog>` vs. reusing/extending `<upload-tray>`'s visual chrome
  for `<share-tray>`.** Purely a UI-architecture call for the implementation plan,
  not a security question — noted so the plan doesn't have to re-litigate it.
- **OQ-3 — Should a non-owner recipient who holds a wrap also get a UI entry point
  to re-share their own copy** (cryptographically already supported by
  `build_reshare`'s generic `granter`), or does that stay owner-only at the UI layer
  indefinitely? This spec assumes owner-only per the task's framing ("the owner
  does it") but the crypto does not require it — worth an explicit product decision
  before or shortly after this ships, since building the owner-only UI first does
  not foreclose adding it later (the command's `granted_by` semantics already
  generalize).
- **OQ-4 — Extending `VerifiedAuthor` with `mlkem_pub` (§2.4.2) vs. a parallel
  struct.** The minimal-diff choice is adding the field to `VerifiedAuthor` (used
  by `resolve_and_verify_author` too, which currently drops it needlessly) — but
  that changes a shared struct's shape, which the implementation plan should treat
  as its own small, reviewable step rather than folding into the reshare command's
  diff.
- **OQ-5 — Batch size / rate limiting.** No cap is proposed on
  `recipient_usernames.len()` in this design; large batches (dozens+) are
  sequential POSTs on one connection and would be slow but not unsafe. Worth
  a UX cap (e.g. "share to up to 20 at once") if real usage patterns justify it —
  deferred, not a blocking decision.
