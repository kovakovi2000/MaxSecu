# Share checklist picker — design

**Date:** 2026-07-04
**Status:** approved for planning
**Area:** `crates/client-app` (T4 multi-recipient sharing, `<share-dialog>`)

## 1. Problem

Today's `<share-dialog>` (T4) is an **add-by-username** flow: the user types one
username at a time, the backend resolves + D5-verifies it, and it becomes a
shareable row. To share with several known people the user must remember and
re-type each name.

**Goal:** when opening Share, show the people the user already knows as a
**scrollable, tickable checklist**; the user ticks the recipients and clicks
**Share**. The manual type-a-username input is **kept** as a complement for
anyone not yet in the list.

## 2. Constraints & key findings

- **No server change.** There is no "list all users" endpoint (the directory
  only serves single-username / by-id lookups), and exposing a full user
  directory is an enumeration/privacy surface we deliberately avoid. The roster
  is built entirely from local, already-encountered users.
- **Roster source = people you've shared with.** The only clean, enumerable
  username source the client holds is share-time state. Browsing the feed does
  **not** contribute names (feed resolves authors by id via a throwaway trust
  store; the card DTO carries only a fingerprint). This is accepted: the roster
  starts empty and grows as the user shares.
- **Already-has-access requires `username → user_id`.** Greying out a contact who
  already has the file means comparing against `list_file_recipients` (which
  returns `user_id`s). The TOFU pin store is keyed by username but stores only a
  *fingerprint*, and it is security-critical — so it is **not** changed. A
  separate address-book store provides the `user_id` mapping.
- **The share security path is unchanged.** `reshare_file` already re-resolves,
  D5-verifies, TOFU-checks, and fail-isolates **every** recipient at share time
  (TOCTOU closure). The checklist is only a faster way to feed usernames into
  that same verified path.

## 3. Decisions (confirmed)

| Decision | Choice |
| --- | --- |
| Roster storage | **New `ContactStore`**, separate from the TOFU pin store |
| Roster growth | Record a contact **only on a successful share** (`ok:true` POST) |
| Manual input | **Kept**; a typed+verified name is injected as a **ticked row** in the same checklist |
| Already-shared contact | Row shown but **checkbox disabled/greyed** with an "Already has access" note |
| Contact verification on tick | **Deferred** — ticking is free (no network); `reshare_file` verifies at share time |

## 4. Architecture

### 4.1 `ContactStore` (new) — `crates/client-app/src/contacts.rs`

An identity-sealed local address book, built exactly like `tofu.rs` / `index.rs`:

- **Location:** `<dir>/contacts/contacts.bin`.
- **Sealing:** AEAD key derived HKDF-SHA256 from the unlocked identity, with its
  own domain-separation label (`MaxSecu-contacts-v1`) — confidential + integrity
  protected at rest, unreadable by any other identity.
- **Shape:** `BTreeMap<String /*username*/, ContactRecord { user_id: [u8;16], fingerprint: [u8;32] }>`.
- **Atomic write:** seal → temp file → `sync_all` → `rename` (same discipline as
  `tofu.rs`; a UX store, but atomic-replace is cheap and avoids a torn file
  failing closed).
- **Fail-closed on corrupt / foreign-identity:** `open` returns `Err` on a
  decrypt/parse failure (never silently discards). *(A read failure at dialog-open
  is surfaced as an empty roster by the command wrapper — see §4.3 — never blocks
  sharing.)*
- **API:**
  - `open(dir, identity) -> Result<Self, UiError>`
  - `list(&self) -> Vec<Contact>` (username + user_id + fingerprint), sorted by username
  - `upsert(&mut self, username, user_id, fingerprint) -> Result<(), UiError>`
    (persists atomically; idempotent replace)

### 4.2 Wiring the write path — `share.rs`

- `reshare_inner` opens the `ContactStore` in the **same identity-borrow block**
  that already opens the TOFU store (borrow confined, no await while held).
- `run_reshare_batch` takes an extra `contacts: &mut ContactStore` parameter. On
  each recipient whose wrap POST returns `201` (the `ok:true` path), it
  `upsert`s `(username, author.user_id, key_fingerprint(enc,sig))`. A contact
  upsert failure is **best-effort**: it must never turn a successful share into a
  failure (log/swallow, mirroring the index-write best-effort pattern in
  `feed.rs`). Failed / rejected recipients are **not** recorded.

### 4.3 Read path — `list_contacts` command (new)

```
list_contacts(dir, session) -> Vec<ContactDto>
```

- Requires an unlocked identity (borrowed under the session lock to open the
  store, released before returning).
- **Fails open to an empty roster:** any store-open error degrades to `Ok(vec![])`
  so a first-ever user (no store yet) or a transient read error still gets a
  working dialog (manual input remains available). *(A genuinely corrupt store is
  the one case worth surfacing; for v1 we treat all open failures as "empty
  roster" to guarantee the dialog is never blocked — consistent with
  `list_file_recipients`'s fail-open contract.)*
- `ContactDto { username: String, user_id: String /*hex*/, fingerprint: String /*hex, first 8 bytes*/ }`.

### 4.4 UI — `share-dialog.ts` rework

On `openFor(fileId, invoker)`:

1. Fetch `list_contacts` and `list_file_recipients` (both through the shared
   `serial()` FIFO queue).
2. Build the checklist rows from contacts. A contact whose `user_id` is in the
   already-access set is rendered **disabled + greyed** with the existing
   "Already has access" note.
3. Render a **scrollable container** (`max-height`, `overflow-y:auto`) holding
   the checkbox rows; each checkbox has an accessible label (the username).

Interactions:

- **Tick / untick** a contact → toggles it in the selection set (no network).
- **Manual input** (kept): type a username → `resolve_recipient` (D5-verify, as
  today). On success, if the username is not already a row, inject a new
  **ticked, verified** row into the same list; if it already exists, just tick
  it. On failure, show the inline rejected row (unchanged).
- **Share** enabled when ≥1 row is ticked. Click → `reshare_file` with the ticked
  usernames → render per-row outcomes (shared / failed + Retry), reusing today's
  `applyOutcomes` / retry logic.

Row model gains: `selected: boolean`, a `"contact"` status (known, not-yet-
verified-this-session, tickable), and an `alreadyShared`/disabled flag. Existing
statuses (`pending`/`verified`/`rejected`/`sharing`/`shared`/`share-failed`) and
their badges/retry are retained.

### 4.5 Seam safety

No secrets cross the Tauri boundary: only usernames, hex `user_id`s,
fingerprints, booleans, and sanitized codes — the same DTO discipline the dialog
and `dto.rs` already enforce. The `ContactStore` holds only its derived sealing
key and the in-RAM map; the `Identity` is never stored and never crosses the seam.

## 5. Testing

- **`contacts.rs` unit tests** (mirror `tofu.rs`): upsert-then-list, seal round-
  trip across reopen, plaintext username not present in the sealed bytes, corrupt
  / too-short store fails closed on `open`, a foreign identity cannot read the
  store.
- **`share.rs` tests:** update `run_reshare_batch` call sites for the new
  `contacts` parameter; add a test that a **successful** recipient records a
  contact (correct `user_id`) and a **failed / unresolvable** recipient records
  **nothing**. Existing batch-isolation / TOFU-alarm / POST-failure tests keep
  passing.
- **UI a11y lint** (`a11y.test.ts`): the checklist checkboxes are labelled;
  already-shared rows are disabled.

## 6. Out of scope (YAGNI)

- No server directory-listing endpoint.
- No feed-author seeding of the roster (browse path untouched).
- No contact removal/editing UI (address book is append-on-share only for v1).
- No re-verification of ticked contacts before Share (the share path already
  verifies every recipient).

## 7. Rollout / risk

- Purely additive on the client: a new store file, one new read command, one new
  parameter through the share batch, and a UI rework. No server, no client-core
  (TCB), no crypto change.
- Backward compatible: an absent contacts store = empty roster; the dialog still
  works via manual input exactly as before.
