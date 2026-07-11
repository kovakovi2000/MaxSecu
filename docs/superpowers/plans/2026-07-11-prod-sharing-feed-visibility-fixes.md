# Prod Sharing & Feed-Visibility Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Scope the feed to files a caller can actually open, make sharing work in a single-server deployment with no separate sink, and turn a recipient's key change into a warn+confirm instead of a silent dead-end.

**Architecture:** Three independent parts. Part 1 is server-only (`crates/server`): add a caller-wrap gate to `GET /v1/files`. Part 2 is client-only (`crates/client-core` + `crates/client-app`): make the revocation sink opt-in so `reshare` degrades to an unanchored-but-authenticated tombstone build when no sink is pinned. Part 3 is client-only (`crates/client-app` + UI): add a re-pin path and a `key_changed` per-recipient outcome that the share dialog surfaces as a confirm.

**Tech Stack:** Rust (axum server, hyper client, tokio), TypeScript vanilla-TS UI (Tauri v2, `node --test`).

**Design spec:** `docs/superpowers/specs/2026-07-11-prod-sharing-feed-visibility-fixes-design.md`

---

## Environment / tooling notes (read once)

- **cargo is not on PATH.** Prefix every cargo command (bash):
  `export PATH="$HOME/.cargo/bin:$PATH";`
- **NEVER run `cargo fmt --all`** (pre-existing rustfmt drift in client-core/server/media-launcher). Format only files you touched with `cargo fmt -p <crate> -- <file>` if needed, or leave formatting to the existing style.
- **`client-app` is its OWN cargo workspace.** Build/test it with `--manifest-path crates/client-app/Cargo.toml`, NOT `-p maxsecu-client-app` from the repo root.
- **Server tests:** `cargo test -p maxsecu-server`. Postgres integration tests (`tests/pg_store.rs`) are gated on a live PG test DB and are skipped when unavailable — the MemoryStore unit tests and the axum e2e tests (which use MemoryStore) are the primary gate.
- **client-core tests:** `cargo test -p maxsecu-client-core`.
- **UI:** `npm --prefix crates/client-app/ui run typecheck` and `npm --prefix crates/client-app/ui run test`. Component/DOM tests run under `node --test`; DOM-touching code is exercised structurally (see `confirm.test.ts`), pure logic is unit-tested directly.
- **Work branch:** `fix/prod-sharing-feed-visibility` (already created; the spec is committed there).

---

# Part 1 — Feed shows only files you can open (server)

### Task 1: Add `caller_id` to `ListFilter` + gate the MemoryStore listing

**Files:**
- Modify: `crates/server/src/files.rs` (the `ListFilter` struct, ~line 282-289)
- Modify: `crates/server/src/store.rs` (`MemoryStore::list_files`, ~line 1041; test module additions)
- Modify call sites that construct `ListFilter`: `crates/server/src/http.rs` (~1944, 3548), `crates/server/src/store.rs` (test ~1743), `crates/server/tests/file_records.rs` (~283, 297), `crates/server/tests/pg_store.rs` (~1049, 1061, 1115, 1352), `crates/server/tests/sanitized_errors.rs` (call site if any)

- [ ] **Step 1: Add the field to `ListFilter`**

In `crates/server/src/files.rs`, replace the struct:

```rust
/// Filter/limit for `GET /v1/files` listing (api.md §8.6 / D35).
#[derive(Debug, Clone)]
pub struct ListFilter {
    /// Restrict to one `file_type` (1=video 2=image 3=blog), or all if `None`.
    pub file_type: Option<i16>,
    /// Max entries to return.
    pub limit: usize,
    /// The authenticated session principal. The listing returns ONLY files this
    /// caller holds a wrap for (their own posts + anything shared to them) — a file
    /// with no wrap for the caller is omitted (no oracle; matches the open path).
    pub caller_id: [u8; 16],
}
```

- [ ] **Step 2: Give the shared `v1_parsed` helper an owner self-wrap**

The store.rs test helper `v1_parsed` (~line 1524) stages `wraps: vec![]`. After caller-scoping, a file with no wrap is invisible to everyone — which would break the existing `listing_excludes_bundle_members` test. Add an owner self-wrap. `WrapInput` is already imported at the top of store.rs (`use crate::files::{… WrapInput}`), in scope via the test module's `use super::*`. Replace the `wraps: vec![],` line inside `v1_parsed`:

```rust
            streams: vec![],
            // An owner self-wrap so the owner can SEE this file under the
            // caller-scoped listing (mirrors the real self-wrap every upload posts).
            wraps: vec![WrapInput {
                recipient_id: owner,
                recipient_type: 1,
                wrapped_dek: vec![0xAA; 48],
                wrap_alg: 1,
                granted_by: owner,
                grant_bytes: vec![],
                grant_sig: [0u8; 64],
            }],
            recovery_present: true,
```

(Also apply the SAME `wraps` change to `v1_parsed_typed` (~line 1585) if it likewise stages `wraps: vec![]` and is used by any `list_files` test — check and match.)

- [ ] **Step 3: Write the failing MemoryStore unit test + a recipient-wrap helper**

In the store.rs test module (near `listing_excludes_bundle_members`, ~line 1720), add:

```rust
/// A user-type wrap for `recipient`, granted by `granter`. `granted_by` MUST be the
/// granter: the coarse `add_wrap` gate rejects a wrap whose `granted_by != caller_id`.
fn other_user_wrap(recipient: [u8; 16], granter: [u8; 16]) -> WrapInput {
    WrapInput {
        recipient_id: recipient,
        recipient_type: 1,
        wrapped_dek: vec![0xAA; 48],
        wrap_alg: 1,
        granted_by: granter,
        grant_bytes: vec![],
        grant_sig: [0u8; 64],
    }
}

#[tokio::test]
async fn list_files_returns_only_files_the_caller_holds_a_wrap_for() {
    let store = MemoryStore::new();
    let owner = [0x11u8; 16];
    let other = [0x22u8; 16];
    let file = [0xA1u8; 16];

    // Stage + finalize one listed file owned by `owner` (v1_parsed now includes an
    // owner self-wrap). list_files only returns finalized files.
    store.stage_version(v1_parsed(file, owner, true, None), 1_000).await.unwrap();
    store.finalize_version(file, 1, owner, 1_000).await.unwrap();

    // The owner sees it (holds a self-wrap).
    let mine = store
        .list_files(ListFilter { file_type: None, limit: 50, caller_id: owner })
        .await
        .unwrap();
    assert_eq!(mine.len(), 1, "owner sees their own post");
    assert_eq!(mine[0].file_id, file);

    // A stranger with no wrap does NOT see it.
    let theirs = store
        .list_files(ListFilter { file_type: None, limit: 50, caller_id: other })
        .await
        .unwrap();
    assert!(theirs.is_empty(), "a non-recipient's feed omits the post");

    // After adding a wrap for `other` (granted by owner), they now see it. NOTE the
    // real add_wrap signature: (file_id, wrap, caller_id, now_ms) — NO explicit version.
    store.add_wrap(file, other_user_wrap(other, owner), owner, 1_000).await.unwrap();
    let now_theirs = store
        .list_files(ListFilter { file_type: None, limit: 50, caller_id: other })
        .await
        .unwrap();
    assert_eq!(now_theirs.len(), 1, "a recipient sees a post once shared to them");
}
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test -p maxsecu-server --lib list_files_returns_only_files_the_caller_holds_a_wrap_for`
Expected: FAIL to compile first (missing `caller_id` in other `ListFilter` sites — fix in Step 5), then FAIL the assertion (stranger currently sees the post).

- [ ] **Step 5: Update all other `ListFilter` construction sites to pass `caller_id`**

Every `ListFilter { … }` literal must now set `caller_id`. These tests stage files under a specific owner and assert the listing contains them; because `v1_parsed` now grants an owner self-wrap, passing that owner as `caller_id` keeps them green:

- `crates/server/src/http.rs` ~1944 (the handler): done in Task 3 — for THIS task, set `caller_id: session.user_id` there right away and drop the `_` (Task 3 only adds the e2e test). This keeps the crate compiling.
- `crates/server/src/store.rs` `listing_excludes_bundle_members` (~1743): add `caller_id: owner` (the test's `owner` is `[7u8; 16]`; the bundle carries an owner self-wrap via `v1_parsed`, so it still lists).
- `crates/server/src/http.rs` ~3548 (a delete test's listing check): pass `caller_id: <the owner used in that test>`.
- `crates/server/tests/file_records.rs` (~283, 297): pass `caller_id: <owner id used in that test>`. If that test stages via a helper that omits wraps, ensure the staged files carry an owner self-wrap (mirror the `v1_parsed` change), else the owner-scoped listing returns empty.
- `crates/server/tests/pg_store.rs` (~1049, 1061, 1115, 1352): pass `caller_id: <the owner id in each test>` (Postgres gate — Task 2 also touches this file; coordinate).
- `crates/server/tests/sanitized_errors.rs`: if it constructs a `ListFilter`, pass `caller_id: [0u8; 16]` (the faulty store errors regardless).

> For any test that stages files through a path OTHER than `v1_parsed` and then lists them, the staged file must carry a wrap for the `caller_id` you pass, or the assertion will see an empty list. Prefer the minimal change that preserves each test's intent (add an owner self-wrap to its staging, and pass that owner as `caller_id`).

- [ ] **Step 6: Gate the MemoryStore listing by caller wrap**

In `crates/server/src/store.rs`, `MemoryStore::list_files` (~1041), add one filter line after the `listed` filter:

```rust
        let mut out: Vec<FileListEntry> = inner
            .files
            .iter()
            .filter(|(_, f)| f.current_version >= 1) // finalized only
            .filter(|(_, f)| f.listed) // hide bundle members (Task 1.4)
            // Caller-visibility gate: only files the caller holds a wrap for in the
            // current version (their own self-wrap or a share) — omit everything else
            // (no oracle; matches the open path's wrap check).
            .filter(|(_, f)| {
                f.versions
                    .get(&f.current_version)
                    .is_some_and(|v| v.wraps.iter().any(|w| w.recipient_id == filter.caller_id))
            })
            .filter(|(_, f)| filter.file_type.is_none_or(|t| t == f.file_type))
            .filter_map(|(id, f)| {
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test -p maxsecu-server --lib list_files`
Expected: PASS (new test + existing `list_files` bundle test).

- [ ] **Step 8: Run the full server lib test suite**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test -p maxsecu-server --lib`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add crates/server/src/files.rs crates/server/src/store.rs
git commit -m "feat(server): scope /v1/files listing to caller wraps (MemoryStore)"
```

---

### Task 2: Gate the Postgres listing by caller wrap

**Files:**
- Modify: `crates/server/src/pg.rs` (`PgStore::list_files`, ~line 970-982)
- Test: `crates/server/tests/pg_store.rs` (~line 1040-1120)

- [ ] **Step 1: Add the caller-wrap `EXISTS` clause to the SQL**

In `crates/server/src/pg.rs`, `list_files`, replace the query:

```rust
        let rows = sqlx::query(
            "SELECT file_id, file_type, current_version, updated_at FROM files \
             WHERE current_version >= 1 AND listed = true \
             AND ($1::smallint IS NULL OR file_type = $1) \
             AND EXISTS ( \
                 SELECT 1 FROM file_key_wraps w \
                 WHERE w.file_id = files.file_id \
                   AND w.file_version = files.current_version \
                   AND w.recipient_id = $3 \
             ) \
             ORDER BY updated_at DESC, file_id LIMIT $2",
        )
        .bind(filter.file_type)
        .bind(filter.limit as i64)
        .bind(&filter.caller_id[..])
        .fetch_all(&self.pool)
        .await
        .map_err(store_err(op))?;
```

> Verify the wraps table/column names against the schema the other pg.rs queries use: `file_key_wraps (file_id, file_version, recipient_id, …)` — confirmed by the `add_wrap` INSERT (~line 1133) and the `get_file` SELECT (~line 888). Keep the `$3` bind order consistent (type=$1, limit=$2, caller=$3).

- [ ] **Step 2: Update the pg_store test to assert caller scoping**

In `crates/server/tests/pg_store.rs`, in the listing test (~line 1040-1120): the test already stages files under an owner and lists them. Pass `caller_id: <owner>` in each `ListFilter`. Then ADD an assertion that a different caller id sees an empty listing for a file not wrapped to them:

```rust
    // A caller with no wrap for these files sees nothing (caller-scoped listing).
    let stranger = fresh
        .list_files(ListFilter { file_type: None, limit: 50, caller_id: [0x77u8; 16] })
        .await
        .unwrap();
    assert!(stranger.is_empty(), "pg listing is caller-scoped");
```

- [ ] **Step 3: Run the pg test (if a PG test DB is configured)**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test -p maxsecu-server --test pg_store list_files`
Expected: PASS if a PG test DB is available; SKIPPED/ignored otherwise. If skipped, verify compilation with:
`export PATH="$HOME/.cargo/bin:$PATH"; cargo test -p maxsecu-server --test pg_store --no-run`
Expected: builds.

- [ ] **Step 4: Commit**

```bash
git add crates/server/src/pg.rs crates/server/tests/pg_store.rs
git commit -m "feat(server): scope /v1/files listing to caller wraps (Postgres)"
```

---

### Task 3: Wire the session caller id into the handler + e2e proof

**Files:**
- Modify: `crates/server/src/http.rs` (`list_files` handler, ~line 1921-1975)
- Test: `crates/server/tests/file_e2e.rs` (or `sharing_e2e.rs` — whichever already has a two-user enroll+upload+share harness)

- [ ] **Step 1: Bind the session and pass its user id**

In `crates/server/src/http.rs`, `list_files` handler: change `_session: AuthedSession` to `session: AuthedSession` and pass the id:

```rust
async fn list_files<S: Store + 'static>(
    State(st): State<AppState<S>>,
    session: AuthedSession,
    Query(q): Query<ListQuery>,
) -> Response {
    // … unchanged file_type / limit parsing …
    match st
        .auth
        .store()
        .list_files(ListFilter { file_type, limit, caller_id: session.user_id })
        .await
    {
```

- [ ] **Step 2: Write the failing e2e test**

In the e2e test file that already stands up an axum app with two enrolled users (mirror an existing test's setup — e.g. `sharing_e2e.rs`), add a test:

```rust
#[tokio::test]
async fn feed_lists_a_post_only_after_it_is_shared() {
    // Stand up the app + enroll admin (A) and a second user (B) — reuse the existing
    // enroll/upload/share helpers in this test module.
    let (router, a, b) = app_with_two_users().await;

    // A uploads + finalizes a listed post (self + recovery wraps only).
    let file = upload_finalized_post(&router, &a).await;

    // B's feed does NOT list A's post (no wrap for B).
    let before = get_files(&router, &b).await; // GET /v1/files with B's session token
    assert!(!before.iter().any(|id| *id == file), "unshared post is hidden from B");

    // A's own feed DOES list it.
    let a_feed = get_files(&router, &a).await;
    assert!(a_feed.iter().any(|id| *id == file), "owner sees their post");

    // A shares to B (POST /v1/files/{id}/wraps with a B-recipient wrap).
    share_to(&router, &a, file, &b).await;

    // Now B's feed lists it.
    let after = get_files(&router, &b).await;
    assert!(after.iter().any(|id| *id == file), "shared post appears for B");
}
```

> Use the helpers already present in that test file (enroll, session token, upload chunks, finalize, POST wraps). If a `get_files` helper that parses `GET /v1/files` → `Vec<file_id>` doesn't exist, add a small one that sends the GET with the user's session token and collects `json["files"][*]["file_id"]`. Do not add new server endpoints.

- [ ] **Step 3: Run to verify it fails, then passes**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test -p maxsecu-server --test <that_file> feed_lists_a_post_only_after_it_is_shared`
Expected: FAIL before Step 1's handler change is effective / PASS after.

- [ ] **Step 4: Run the whole server test suite**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test -p maxsecu-server`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/server/src/http.rs crates/server/tests/
git commit -m "feat(server): pass session caller id into /v1/files; e2e proves feed scoping"
```

---

# Part 2 — Sharing works without a separate sink (client)

### Task 4: `TombstoneSet::verify_authenticated_unanchored` (client-core)

**Files:**
- Modify: `crates/client-core/src/revocation.rs` (impl block ~line 192-212; tests ~line 700+)

- [ ] **Step 1: Write the failing test**

In `crates/client-core/src/revocation.rs` test module, add a test that reuses the existing `signed_revocation` / `multi_issuer` / `account_revoke` test helpers already in the module:

```rust
#[test]
fn unanchored_accepts_a_valid_served_chain_and_still_rejects_a_broken_link() {
    let admin = SigningKey::generate();
    // A single valid revocation record chaining from GENESIS, issued by an admin.
    let (_head, rec) =
        signed_revocation(account_revoke(U, 1, GENESIS_HEAD.0, None), &admin, None);
    let issuer = |id: Id| {
        (id == ADMIN_ID).then(|| IssuerInfo {
            sig_pub: admin.verifying_key().to_bytes(),
            roles: vec![Role::Admin],
            key_version: 1,
        })
    };
    // Unanchored: no external head — derived from the record chain. Accepts it.
    let set = TombstoneSet::verify_authenticated_unanchored(&[rec.clone()], &issuer).unwrap();
    assert!(set.is_account_revoked(&[U; 16]));

    // A record that does NOT chain from GENESIS still fails closed (BrokenChain),
    // proving the unanchored variant did not drop the contiguity check.
    let (_h2, bad) =
        signed_revocation(account_revoke(U, 1, [9u8; 32], None), &admin, None);
    assert_eq!(
        TombstoneSet::verify_authenticated_unanchored(&[bad], &issuer).unwrap_err(),
        TombstoneError::BrokenChain
    );
}
```

> Match the exact signatures of `signed_revocation`, `account_revoke`, `IssuerInfo`, `ADMIN_ID`, `U` as used elsewhere in this test module (see ~line 516-575). `account_revoke(U, 1, GENESIS_HEAD.0, None)` is the shape already used there.

- [ ] **Step 2: Run to verify it fails**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test -p maxsecu-client-core unanchored_accepts_a_valid_served_chain`
Expected: FAIL ("no function `verify_authenticated_unanchored`").

- [ ] **Step 3: Implement the constructor**

In `crates/client-core/src/revocation.rs`, add to `impl TombstoneSet` (right after `verify_authenticated`, ~line 212):

```rust
    /// Like [`TombstoneSet::verify_authenticated`], but with NO external anchor:
    /// the target head is DERIVED from the served record chain itself. Chain
    /// contiguity (`BrokenChain`), record well-formedness (`Malformed`), and full
    /// D5 issuer-authority (`UnknownIssuer`/`BadAuthority`/`NotAdmin`/dual-control)
    /// are still enforced — ONLY the out-of-band gap/withhold detection is skipped.
    ///
    /// Used when no revocation sink is pinned (opt-in, mirroring the opt-in KT /
    /// sink-transparency gates): a single-server deployment can still enforce
    /// D5-authenticated revocations without standing up a separate sink. The
    /// tradeoff — trusting that the server is not withholding its own revocation
    /// tail — is accepted by the caller (`client-app` reshare) only when no sink is
    /// pinned; a pinned sink restores anchoring via `verify_authenticated`.
    pub fn verify_authenticated_unanchored(
        records: &[ControlRecordIn],
        issuer: &dyn Fn(Id) -> Option<IssuerInfo>,
    ) -> Result<TombstoneSet, TombstoneError> {
        let mut head = GENESIS_HEAD.0;
        let mut decoded: Vec<Decoded> = Vec::with_capacity(records.len());
        for rec in records {
            let d = Decoded::from_bytes(&rec.bytes)?;
            if d.prev_head() != head {
                return Err(TombstoneError::BrokenChain);
            }
            authenticate_authority(&d, rec, &decoded, issuer)?;
            head = sha256(&rec.bytes);
            decoded.push(d);
        }
        // No `head != anchored_head` gap check: the derived head IS the tip. Every
        // other fail-closed check above still ran.
        Ok(TombstoneSet { records: decoded })
    }
```

- [ ] **Step 4: Run to verify it passes**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test -p maxsecu-client-core unanchored_accepts_a_valid_served_chain`
Expected: PASS.

- [ ] **Step 5: Run the client-core revocation suite**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test -p maxsecu-client-core revocation`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/client-core/src/revocation.rs
git commit -m "feat(client-core): TombstoneSet::verify_authenticated_unanchored for opt-in sink"
```

---

### Task 5: `load_sink_pins_opt` (client-app config)

**Files:**
- Modify: `crates/client-app/src/config.rs` (add function near `load_sink_pins`, ~line 134; tests ~line 665)

- [ ] **Step 1: Write the failing test**

In `crates/client-app/src/config.rs` test module, add (mirror the existing `load_sink_pins_reads_pins_and_fails_closed` test's setup):

```rust
#[test]
fn load_sink_pins_opt_absent_is_none_present_is_some_malformed_is_err() {
    let dir = std::env::temp_dir().join(format!("mxsinkopt-{}", n()));
    let cfg = dir.join("config");
    std::fs::create_dir_all(&cfg).unwrap();

    // Absent sink.json → Ok(None) (opt-in; caller runs the unanchored path).
    assert!(load_sink_pins_opt(&dir).unwrap().is_none());

    // Fully pinned → Ok(Some).
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    std::fs::write(cfg.join("sink_root.der"), cert.cert.der()).unwrap();
    std::fs::write(
        cfg.join("sink.json"),
        br#"{"addr":"127.0.0.1:9443","server_name":"localhost"}"#,
    )
    .unwrap();
    std::fs::write(cfg.join("sink_custodians.der"), [0x11u8; 32]).unwrap();
    assert!(load_sink_pins_opt(&dir).unwrap().is_some());

    // Present sink.json but a malformed sibling pin → Err (fail closed, NOT opt-out).
    std::fs::write(cfg.join("sink_custodians.der"), [0u8; 31]).unwrap();
    assert_eq!(load_sink_pins_opt(&dir).unwrap_err().code, "sink_unpinned");

    let _ = std::fs::remove_dir_all(&dir);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --manifest-path crates/client-app/Cargo.toml --lib load_sink_pins_opt_absent`
Expected: FAIL ("no function `load_sink_pins_opt`").

- [ ] **Step 3: Implement `load_sink_pins_opt`**

In `crates/client-app/src/config.rs`, add right after `load_sink_pins` (~line 163):

```rust
/// Load [`SinkPins`] if a sink is CONFIGURED, else `Ok(None)` (opt-in). Absence is
/// detected by a missing `sink.json` (the endpoint file): a deployment that never
/// pinned a sink runs the unanchored revocation path (mirrors `load_kt_log_pubs`'
/// opt-in shape). A PRESENT `sink.json` with any missing/malformed sibling pin is a
/// half-configured sink — that FAILS CLOSED via [`load_sink_pins`], never silently
/// treated as opt-out.
pub fn load_sink_pins_opt(dir: &Path) -> Result<Option<SinkPins>, UiError> {
    if !dir.join("config").join("sink.json").exists() {
        return Ok(None); // no sink pinned → opt-in (unanchored reshare)
    }
    load_sink_pins(dir).map(Some)
}
```

- [ ] **Step 4: Run to verify it passes, then the config suite**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --manifest-path crates/client-app/Cargo.toml --lib config`
Expected: PASS (new test + existing `load_sink_pins` test).

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/src/config.rs
git commit -m "feat(client-app): load_sink_pins_opt — sink pinning is opt-in"
```

---

### Task 6: `build_tombstones` takes `Option<anchored_head>`

**Files:**
- Modify: `crates/client-app/src/revocations.rs` (`build_tombstones` signature + step 4, ~line 57-100)
- Modify callers: `crates/client-app/src/commands/share.rs` (~line 194 — updated fully in Task 7)

- [ ] **Step 1: Change the signature + branch on the anchor**

In `crates/client-app/src/revocations.rs`, change `build_tombstones` to take `Option<[u8; 32]>` and branch the final verify:

```rust
pub(crate) async fn build_tombstones(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    anchored_head: Option<[u8; 32]>,
    verifier: &DirectoryVerifier,
    trust: &mut (dyn TrustStore + Send),
    now_ms: u64,
) -> Result<TombstoneSet, UiError> {
    // 1. Fetch the untrusted served record set.
    let records = fetch_control_records(sender, host).await?;

    // 2–3. (unchanged) collect distinct issuer ids and pre-resolve each to its
    //      D5-verified IssuerInfo …
    // … keep the existing `ids` collection and `resolved` map building verbatim …

    // 4. Synchronous chain + authority verify. With a pinned sink the served set
    //    must reach the sink-anchored head (full anti-rollback); without one (opt-in)
    //    the head is derived from the chain — D5 issuer authority + contiguity still
    //    enforced, only out-of-band anchoring skipped.
    match anchored_head {
        Some(head) => TombstoneSet::verify_authenticated(&records, head, &|id: Id| {
            resolved.get(&id.0).cloned()
        }),
        None => TombstoneSet::verify_authenticated_unanchored(&records, &|id: Id| {
            resolved.get(&id.0).cloned()
        }),
    }
    .map_err(map_tombstone_err)
}
```

> Keep steps 2 and 3 (the `ids` loop and `resolved` HashMap) exactly as they are today — only the parameter type and the final `match` change. Update the module-doc note at the top of the file to say the anchored head is now optional (opt-in sink).

- [ ] **Step 2: Add a unit test for the unanchored path**

`build_tombstones` needs a live `SendRequest` + an in-process `/v1/revocations` stub. There is an existing router-stub pattern in `revocations.rs` tests (a `spawn_router` mirroring share.rs). If `revocations.rs` has no test module, add one modeled on `share.rs`'s `spawn_router` + `connect` helpers (copy those two helpers). Test:

```rust
#[tokio::test]
async fn build_tombstones_unanchored_accepts_empty_served_set() {
    // A server that returns an EMPTY revocation set (the common fresh-deploy case).
    let mut routes = std::collections::HashMap::new();
    routes.insert(
        "/v1/revocations".to_owned(),
        (hyper::StatusCode::OK, r#"{"records":[]}"#.to_owned()),
    );
    let addr = spawn_router(routes).await;
    let mut sender = connect(&addr).await;

    let d5 = maxsecu_crypto::SigningKey::generate();
    let verifier = DirectoryVerifier::new(d5.verifying_key().to_bytes());
    let mut trust = MemoryTrustStore::new();

    // No anchor (opt-in): an empty served set builds an empty tombstone set.
    let set = build_tombstones(&mut sender, "localhost", None, &verifier, &mut trust, 0)
        .await
        .unwrap();
    assert!(!set.is_account_revoked(&[0xABu8; 16]), "empty set revokes nobody");
}
```

- [ ] **Step 3: Run to verify it fails, then passes after Step 1**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --manifest-path crates/client-app/Cargo.toml --lib build_tombstones_unanchored`
Expected: FAIL to compile until callers (Task 7) are updated. To isolate, this task and Task 7 land together — run the combined build at the end of Task 7. For now verify the crate compiles with the share.rs caller updated (do Task 7 Step 1 before running).

- [ ] **Step 4: Commit (with Task 7, since the caller must change together)**

Defer the commit to the end of Task 7 so the crate compiles.

---

### Task 7: `reshare_inner` uses the opt-in sink path

**Files:**
- Modify: `crates/client-app/src/commands/share.rs` (`reshare_inner`, ~line 118-202; imports ~line 56, 67; tests ~line 793)

- [ ] **Step 1: Swap the mandatory sink for the optional path**

In `crates/client-app/src/commands/share.rs`:

Update the import (~line 56):
```rust
use crate::config::{load_directory_pub, load_sink_pins_opt};
```

Remove the now-unused `load_sink_pins` import and the eager `let sink_pins = load_sink_pins(&dir.0)?;` line (~line 123). Replace the batch-prerequisite sink block (~line 190-202) — the `fetch_anchored_head` + `build_tombstones` steps — with:

```rust
    // Step 4: fetch the sink-anchored head IF a sink is pinned, then build the
    // authenticated TombstoneSet. The sink is OPT-IN (spec §Part 2): pinned ⇒ fetch
    // the out-of-band anchor and fail closed on a bad one (full anti-rollback);
    // absent ⇒ unanchored build (D5 issuer authority + contiguity still enforced).
    let anchored_head = match load_sink_pins_opt(&dir.0)? {
        Some(pins) => Some(fetch_anchored_head(&pins)?),
        None => None,
    };
    let tombstones = build_tombstones(
        &mut sender,
        &host,
        anchored_head,
        &verifier,
        &mut trust,
        now,
    )
    .await?;
```

The `use crate::sink::fetch_anchored_head;` import (~line 67) stays (still used on the pinned path).

- [ ] **Step 2: Add an integration test — sharing works with NO sink pinned**

In `crates/client-app/src/commands/share.rs` test module: the existing tests exercise `run_reshare_batch` directly (bypassing the sink). Add a test at the `reshare_inner` level is heavy (needs directory + reauth + file-view stubs). Instead, assert the KEY new behavior at the unit boundary already covered by Task 6's `build_tombstones(None)` test. Add here a focused test that `load_sink_pins_opt` returning `None` is the reshare path by asserting the module compiles and the existing batch tests still pass. (No new share.rs test needed beyond confirming the suite is green — the unanchored build is proven in Task 6, and `run_reshare_batch` isolation is already covered.)

> Rationale: `reshare_inner` requires an authenticated channel + directory delegation + a served file view — the existing suite deliberately tests the isolated `run_reshare_batch` instead. The behavioral change (no-sink ⇒ unanchored, still works) is fully covered by Task 6's test plus the untouched batch tests. Do not build a full `reshare_inner` harness for this.

- [ ] **Step 3: Build + test the client-app crate**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --manifest-path crates/client-app/Cargo.toml --lib share revocations config`
Expected: PASS (share batch tests, the new `build_tombstones_unanchored`, config).

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo build --manifest-path crates/client-app/Cargo.toml`
Expected: builds (no unused-import warnings for the removed `load_sink_pins`).

- [ ] **Step 4: Commit Tasks 6 + 7 together**

```bash
git add crates/client-app/src/revocations.rs crates/client-app/src/commands/share.rs
git commit -m "feat(client-app): opt-in sink — reshare builds unanchored tombstones when no sink pinned"
```

---

# Part 3 — Recipient key-change warn + confirm (client)

### Task 8: `TofuStore::repin`

**Files:**
- Modify: `crates/client-app/src/tofu.rs` (add method ~line 139; test ~line 264)

- [ ] **Step 1: Write the failing test**

In `crates/client-app/src/tofu.rs` test module, add:

```rust
#[test]
fn repin_overwrites_and_persists() {
    let dir = tmp_dir();
    let id = Identity::generate();
    let mut store = TofuStore::open(&dir, &id).unwrap();

    // First-sighting pin of key A.
    assert_eq!(store.check_or_pin("alice", &ENC_A, &SIG_A).unwrap(), TofuOutcome::Pinned);
    // Key B would normally be a Changed (blocked) result.
    assert_eq!(store.check_or_pin("alice", &ENC_B, &SIG_B).unwrap(), TofuOutcome::Changed);

    // An explicit repin to B overwrites the pin (user-confirmed key change).
    store.repin("alice", &ENC_B, &SIG_B).unwrap();
    // Now B Matches and A would be the Changed one.
    assert_eq!(store.check_or_pin("alice", &ENC_B, &SIG_B).unwrap(), TofuOutcome::Match);
    assert_eq!(store.check_or_pin("alice", &ENC_A, &SIG_A).unwrap(), TofuOutcome::Changed);

    // Persisted across reopen.
    let mut reopened = TofuStore::open(&dir, &id).unwrap();
    assert_eq!(reopened.check_or_pin("alice", &ENC_B, &SIG_B).unwrap(), TofuOutcome::Match);

    let _ = std::fs::remove_dir_all(&dir);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --manifest-path crates/client-app/Cargo.toml --lib repin_overwrites_and_persists`
Expected: FAIL ("no method `repin`").

- [ ] **Step 3: Implement `repin`**

In `crates/client-app/src/tofu.rs`, add to `impl TofuStore` (after `check_or_pin`, ~line 139):

```rust
    /// Overwrite the pinned fingerprint for `username` (persisted atomically).
    /// Used ONLY on an EXPLICIT user-confirmed key change — never on the silent
    /// `check_or_pin` path (which retains the old pin on a `Changed`). After this,
    /// the new key `Match`es and the old key would itself trip the alarm.
    pub fn repin(
        &mut self,
        username: &str,
        enc_pub: &[u8; 32],
        sig_pub: &[u8; 32],
    ) -> Result<(), UiError> {
        let fp = key_fingerprint(enc_pub, sig_pub);
        let mut candidate = self.map.clone();
        candidate.insert(username.to_owned(), fp);
        self.persist(&candidate)?; // atomic write first; commit RAM only on success
        self.map = candidate;
        Ok(())
    }
```

- [ ] **Step 4: Run to verify it passes, then the tofu suite**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --manifest-path crates/client-app/Cargo.toml --lib tofu`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/src/tofu.rs
git commit -m "feat(client-app): TofuStore::repin for user-confirmed key changes"
```

---

### Task 9: `key_changed` outcome + `accepted_key_changes` in the batch

**Files:**
- Modify: `crates/client-app/src/dto.rs` (`ReshareRequest` ~line 382, `ReshareOutcomeDto` ~line 424)
- Modify: `crates/client-app/src/commands/share.rs` (`run_reshare_batch` Changed arm ~line 410-427; `push_outcome` ~line 514; both `reshare_inner`/`reshare_bundle` pass-through of the new request field; tests)

- [ ] **Step 1: Extend the DTOs**

In `crates/client-app/src/dto.rs`:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct ReshareRequest {
    pub file_id: String,
    pub recipient_usernames: Vec<String>,
    /// Usernames the user has EXPLICITLY confirmed trusting a new key for (a
    /// user-confirmed key change). A recipient here whose key changed is re-pinned
    /// and shared to; anyone NOT here whose key changed yields a `key_changed`
    /// outcome instead (warn + confirm). Absent ⇒ empty (default fail-closed).
    #[serde(default)]
    pub accepted_key_changes: Vec<String>,
}
```

```rust
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReshareOutcomeDto {
    pub username: String,
    pub ok: bool,
    pub code: Option<String>, // sanitized failure code, None on success
    /// For a `key_changed` outcome only: the previously-pinned short fingerprint
    /// and the newly-served one, so the UI can show a warn+confirm. `None` otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_fingerprint: Option<String>,
}
```

> Every existing `ReshareOutcomeDto { … }` literal (in `share.rs` and its tests, and `push_outcome`) must now set the two new fields. Prefer adding them in `push_outcome` (the single constructor) and using `..Default::default()`-free explicit `None` at the literal sites. Since the struct derives no `Default`, update each literal. To minimize churn, give `push_outcome` an extended signature (Step 3) and route ALL rows through it.

- [ ] **Step 2: Update `run_reshare_batch` signature to receive the accepted set**

In `share.rs`, thread `accepted_key_changes: &[String]` into `run_reshare_batch` (add the parameter; pass `&req.recipient_usernames`'s sibling `&req.accepted_key_changes` from `reshare_inner`). At the call site (~line 205) add the argument; in `reshare_bundle`'s per-target `ReshareRequest` construction (~line 322), propagate `accepted_key_changes: req.accepted_key_changes.clone()`.

- [ ] **Step 3: Rewrite the `Changed` arm + centralize fingerprints in `push_outcome`**

Replace the `check_or_pin` match's `Changed` arm (~line 412-421) in `run_reshare_batch`:

```rust
        match tofu.check_or_pin(uname, &author.enc_pub, &author.sig_pub) {
            Ok(TofuOutcome::Pinned) | Ok(TofuOutcome::Match) => {}
            Ok(TofuOutcome::Changed) => {
                if accepted_key_changes.iter().any(|u| u == uname) {
                    // User explicitly confirmed this key change → re-pin and proceed.
                    if let Err(e) = tofu.repin(uname, &author.enc_pub, &author.sig_pub) {
                        push_outcome(&mut outcomes, emit, file_id_hex, uname, false, Some(e.code), None, None);
                        continue;
                    }
                    // fall through to the wrap/POST below (no `continue`).
                } else {
                    // Not confirmed → surface a warn+confirm outcome with both prints.
                    let old_fp = tofu.pinned_fingerprint(uname).map(|fp| crate::tofu::short_fingerprint(&fp));
                    let new_fp = crate::tofu::short_fingerprint(&crate::tofu::key_fingerprint(
                        &author.enc_pub,
                        &author.sig_pub,
                    ));
                    push_outcome(
                        &mut outcomes, emit, file_id_hex, uname, false,
                        Some("key_changed".to_owned()), old_fp, Some(new_fp),
                    );
                    continue;
                }
            }
            Err(e) => {
                push_outcome(&mut outcomes, emit, file_id_hex, uname, false, Some(e.code), None, None);
                continue;
            }
        }
```

Extend `push_outcome` (~line 514) to carry the fingerprints:

```rust
#[allow(clippy::too_many_arguments)]
fn push_outcome(
    outcomes: &mut Vec<ReshareOutcomeDto>,
    emit: &impl Fn(SharePhase),
    file_id_hex: &str,
    username: &str,
    ok: bool,
    code: Option<String>,
    old_fingerprint: Option<String>,
    new_fingerprint: Option<String>,
) {
    emit(SharePhase::Recipient {
        file_id: file_id_hex.to_owned(),
        username: username.to_owned(),
        ok,
        code: code.clone(),
    });
    outcomes.push(ReshareOutcomeDto {
        username: username.to_owned(),
        ok,
        code,
        old_fingerprint,
        new_fingerprint,
    });
}
```

Update EVERY other `push_outcome(...)` call in `run_reshare_batch` (the resolve-fail, wrap-fail, POST arms, and the success arm) to pass the two trailing `None, None`.

- [ ] **Step 4: Update existing share.rs tests for the new arities**

The batch tests call `run_reshare_batch(...)` — add the `accepted_key_changes` argument (pass `&[]` for the existing tests). The `changed_pinned_key_blocks_the_share_but_first_sighting_proceeds` test currently asserts `code == "server_untrusted"`; change that expectation to `"key_changed"` and assert `old_fingerprint`/`new_fingerprint` are `Some`. Add a new test:

```rust
#[tokio::test]
async fn accepted_key_change_repins_and_shares() {
    // Same setup as changed_pinned_key_blocks_the_share_but_first_sighting_proceeds,
    // but pass accepted_key_changes = ["alice"] and assert alice now shares (ok:true)
    // and no longer yields key_changed. carol (first sighting) still succeeds.
    // … reuse that test's d5/verifier/tofu-prepin setup verbatim …
    let outcomes = run_reshare_batch(
        &mut sender, "localhost", "tok", &file_id_hex, FILE_ID, 1,
        dek.commit(), Suite::V1, GRANTER_ID, &dek, &tombstones, &session,
        &mut tofu, Some(&mut empty_contacts()), &recipients,
        &["alice".to_owned()],      // accepted_key_changes
        &verifier, &mut trust, NOW, &|_| {},
    ).await;
    assert!(outcomes[0].ok, "an accepted key change re-pins and shares");
    assert_eq!(outcomes[0].code, None);
}
```

> Match `run_reshare_batch`'s exact parameter ORDER when inserting `accepted_key_changes` — place it consistently (e.g. right after `recipients`) in the signature AND every call site. Update the `mixed_batch…`, `post_failure…`, `successful_share…`, `post_failure_records_no_contact` tests' calls with `&[]`.

- [ ] **Step 5: Update the DTO round-trip test (if present)**

If `dto.rs` has a `reshare_dto_tests` module asserting the outcome shape, update it to include the new optional fields (they should be absent from JSON when `None` due to `skip_serializing_if`).

- [ ] **Step 6: Run the client-app tests**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --manifest-path crates/client-app/Cargo.toml --lib share dto tofu`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/client-app/src/dto.rs crates/client-app/src/commands/share.rs
git commit -m "feat(client-app): key_changed outcome + accepted_key_changes re-pin path"
```

---

### Task 10: Share dialog surfaces `key_changed` as a confirm

**Files:**
- Modify: `crates/client-app/ui/src/core/types.ts` (`ReshareOutcome` ~line 81)
- Modify: `crates/client-app/ui/src/components/share-dialog.ts` (`share`, `retryRow`, `applyOutcomes`)
- Create: `crates/client-app/ui/src/components/share-keychange.ts` (pure helper) + `crates/client-app/ui/src/components/share-keychange.test.ts`
- Modify: `crates/client-app/ui/package.json` (add the new test file to the `test` script)

- [ ] **Step 1: Extend the `ReshareOutcome` type**

In `types.ts`:

```ts
// The per-recipient outcome of a reshare_file call, in request order.
export interface ReshareOutcome {
  username: string;
  ok: boolean;
  code: string | null; // sanitized failure code, null on success
  // For a "key_changed" outcome only: previously-pinned vs newly-served short
  // fingerprints, so the UI can warn + confirm. Absent otherwise.
  old_fingerprint?: string;
  new_fingerprint?: string;
}
```

- [ ] **Step 2: Write the failing pure-helper test**

Create `crates/client-app/ui/src/components/share-keychange.test.ts`:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { keyChangeMessage, isKeyChange } from "./share-keychange.ts";

test("isKeyChange detects the key_changed code", () => {
  assert.equal(isKeyChange({ username: "a", ok: false, code: "key_changed" }), true);
  assert.equal(isKeyChange({ username: "a", ok: false, code: "share_failed" }), false);
  assert.equal(isKeyChange({ username: "a", ok: true, code: null }), false);
});

test("keyChangeMessage includes both fingerprints and the username", () => {
  const msg = keyChangeMessage({
    username: "flesman",
    ok: false,
    code: "key_changed",
    old_fingerprint: "A1B2 C3D4 E5F6 0718",
    new_fingerprint: "99AA BBCC DDEE FF00",
  });
  assert.match(msg, /flesman/);
  assert.match(msg, /A1B2 C3D4 E5F6 0718/);
  assert.match(msg, /99AA BBCC DDEE FF00/);
});
```

- [ ] **Step 3: Run to verify it fails**

Run: `node --experimental-strip-types --test crates/client-app/ui/src/components/share-keychange.test.ts`
Expected: FAIL (module not found).

- [ ] **Step 4: Implement the pure helper**

Create `crates/client-app/ui/src/components/share-keychange.ts`:

```ts
import type { ReshareOutcome } from "../core/types.ts";

// A recipient outcome whose key changed since we last shared: warn + confirm.
export function isKeyChange(o: ReshareOutcome): boolean {
  return !o.ok && o.code === "key_changed";
}

// The human warning for a changed recipient key. Pure so it is unit-testable.
export function keyChangeMessage(o: ReshareOutcome): string {
  const oldFp = o.old_fingerprint ?? "unknown";
  const newFp = o.new_fingerprint ?? "unknown";
  return (
    `${o.username}'s security key has changed since you last shared with them. ` +
    `This can happen if they reinstalled the app — but it can also mean someone ` +
    `is impersonating them.\n\nPreviously: ${oldFp}\nNow: ${newFp}\n\n` +
    `Only continue if you trust this change.`
  );
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `node --experimental-strip-types --test crates/client-app/ui/src/components/share-keychange.test.ts`
Expected: PASS.

- [ ] **Step 6: Wire the confirm into the dialog**

In `share-dialog.ts`:

Add imports at the top:
```ts
import { confirmModal } from "../core/confirm.ts";
import { isKeyChange, keyChangeMessage } from "./share-keychange.ts";
```

Add a `Set<string>` field to remember confirmed usernames for this dialog session:
```ts
  private acceptedKeyChanges = new Set<string>();
```
Reset it in `openFor` (next to `this.rows = [];`):
```ts
    this.acceptedKeyChanges = new Set();
```

In both `share()` and `retryRow()`, include the accepted set in the request payload:
```ts
        call<ReshareOutcome[]>(this.shareCommand(), {
          req: {
            file_id: this.fileId,
            recipient_usernames: usernames, // or [row.username] in retryRow
            accepted_key_changes: Array.from(this.acceptedKeyChanges),
          },
        }),
```

After `this.applyOutcomes(outcomes);` in `share()` (and after it in `retryRow`), handle key-change outcomes by prompting and, on confirm, re-sharing just those usernames. Add a new method and call it:

```ts
  /** For any key_changed outcomes, prompt one at a time; a confirmed change is
   * remembered and that recipient is re-shared (now accepted → server re-pins). */
  private async handleKeyChanges(outcomes: ReshareOutcome[]) {
    const changes = outcomes.filter(isKeyChange);
    for (const o of changes) {
      const ok = await confirmModal({
        title: "Security key changed",
        message: keyChangeMessage(o),
        confirmLabel: "Share anyway",
      });
      if (!ok) continue;
      this.acceptedKeyChanges.add(o.username);
      const row = this.rows.find((r) => r.username === o.username);
      if (row) await this.retryRow(row.key);
    }
  }
```

Call it at the end of `share()` (after `this.renderRows(); this.updateShareEnabled();`) and at the end of `retryRow()` — but guard against infinite recursion: `retryRow` should NOT itself call `handleKeyChanges` (only `share()` kicks off the confirm loop, and `retryRow` re-runs with the username already in `acceptedKeyChanges`, so a second `key_changed` cannot recur). So: call `await this.handleKeyChanges(outcomes);` only from `share()`.

Also update `applyOutcomes` so a `key_changed` row renders informatively rather than as a generic failure:
```ts
      } else if (o.code === "key_changed") {
        row.status = "share-failed";
        row.code = "key_changed";
        row.message = "Security key changed — confirm to continue.";
      } else {
        row.status = "share-failed";
        row.code = o.code ?? null;
        row.message = o.code ? `Failed: ${o.code}` : "Sharing failed.";
      }
```

- [ ] **Step 7: Register the new test file**

In `crates/client-app/ui/package.json`, append `src/components/share-keychange.test.ts` to the space-separated file list in the `"test"` script.

- [ ] **Step 8: Typecheck + run the UI test suite**

Run: `npm --prefix crates/client-app/ui run typecheck`
Expected: no errors.

Run: `npm --prefix crates/client-app/ui run test`
Expected: PASS (including the new `share-keychange.test.ts`).

- [ ] **Step 9: Commit**

```bash
git add crates/client-app/ui/src/core/types.ts \
        crates/client-app/ui/src/components/share-dialog.ts \
        crates/client-app/ui/src/components/share-keychange.ts \
        crates/client-app/ui/src/components/share-keychange.test.ts \
        crates/client-app/ui/package.json
git commit -m "feat(ui): warn + confirm on a recipient's changed security key"
```

---

## Final verification

- [ ] **Server:** `export PATH="$HOME/.cargo/bin:$PATH"; cargo test -p maxsecu-server` → PASS
- [ ] **client-core:** `export PATH="$HOME/.cargo/bin:$PATH"; cargo test -p maxsecu-client-core` → PASS
- [ ] **client-app:** `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --manifest-path crates/client-app/Cargo.toml --lib` → PASS
- [ ] **UI:** `npm --prefix crates/client-app/ui run typecheck && npm --prefix crates/client-app/ui run test` → PASS
- [ ] **Clippy (touched crates):** `export PATH="$HOME/.cargo/bin:$PATH"; cargo clippy -p maxsecu-server -p maxsecu-client-core -- -D warnings` and `cargo clippy --manifest-path crates/client-app/Cargo.toml -- -D warnings` → clean (do NOT run `cargo fmt --all`)
- [ ] **Manual smoke (documented, user-run):** deploy the rebuilt server + client; verify (a) a second profile's feed does NOT list an unshared post, (b) sharing to a username succeeds with no sink pinned, (c) sharing again after the recipient's key changed prompts a confirm.

## Self-review notes (author)

- **Spec coverage:** Part 1 → Tasks 1-3; Part 2 → Tasks 4-7; Part 3 → Tasks 8-10. All spec sections mapped.
- **Type consistency:** `caller_id: [u8;16]` used identically in `ListFilter`, both stores, and the handler. `verify_authenticated_unanchored(records, issuer)` signature matches its client-app caller. `key_changed` code + `old_fingerprint`/`new_fingerprint` fields consistent across Rust DTO, TS type, and helper. `accepted_key_changes` snake_case on both the Rust `#[serde(default)]` field and the JS `req` payload (matches the repo's "req struct fields stay snake_case" convention).
- **Known follow-ups:** the pinned-sink `reshare_inner` path is unchanged and remains covered by existing tests; no full `reshare_inner` harness is added (documented rationale in Task 7 Step 2).
