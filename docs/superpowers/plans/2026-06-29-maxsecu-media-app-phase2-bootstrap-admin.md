# MaxSecu Media App — Phase 2: Bootstrap + Admin — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the glass-break + first-admin bootstrap, voucher enrollment, status-only pending screen, and admin approval queue on top of the existing MaxSecu backend, with a scripted test ceremony — so a full `bootstrap → first-admin → voucher-enroll a user → pending → ceremony-sign (approve) → user is a valid recipient` flow runs end-to-end over real TLS.

**Architecture:** The existing secret-free server gains a small set of **additive** HTTP endpoints (bootstrap registration, D5-binding publish, admin pending-list, admin voucher-issuance) and one new authorization model: **admin is authorized only by a D5-signed binding** (the server pins the D5 public key and verifies the caller's stored binding carries `Role::Admin`), never by a server-held flag — honoring D-K (the server cannot confer admin). The crypto/protocol/TCB and the zero-knowledge model are untouched: the server still stores opaque, client-verified bytes and forges nothing (it only verifies signatures against the pinned D5 *public* key, which it cannot use to sign). A new test-only `tools/ceremony-harness` crate scripts the air-gapped `admin-core` D5 ceremony in-process so the e2e can sign and publish bindings.

**Tech Stack:** Rust (axum, sqlx/Postgres, tokio-rustls + `aws-lc-rs`), `maxsecu-admin-core` (offline `DirectorySigner`/`ControlChain`), `maxsecu-client-core` (`DirectoryVerifier`), `maxsecu-encoding`/`maxsecu-crypto`, Tauri 2 + vanilla-TS Web Components, the existing `MemoryStore`/`MemoryBlobStore` e2e harness (no Postgres).

---

## Backend facts this plan is grounded in (read before coding)

- **Offline ceremony (the trust root):** `crates/admin-core/src/directory.rs` — `DirectorySigner::{generate, public_key, sign_binding(&b, mlkem), sign_enrollment(&b, &fingerprint)}` → `SignedBinding { binding: DirBinding, signature: [u8;64] }`. `crates/admin-core/src/control.rs` — `ControlChain::{new, revoke(...)}`, `RevokeParams`, `CoSign`, `SignedControlRecord { bytes, head, sig, co_sig }`.
- **The binding type:** `crates/encoding/src/structs.rs:25` `DirBinding { username: Text, user_id: Id, enc_pub, sig_pub, key_version: u64, roles: RoleSet, not_before: Timestamp, not_after: Timestamp, mlkem_pub: Option<MlKemPub> }`; `crates/encoding/src/types.rs:244` `enum Role { User=1, Admin=2 }`, `RoleSet::new([..])` / `.roles()`. Signed under `labels::DIRBINDING`.
- **Store (server persistence seam):** `crates/server/src/store.rs` — trait `Store` + `MemoryStore` + (cfg-test) `FaultyStore`; `crates/server/src/pg.rs` is the Postgres adapter. Existing: `create_user`, `consume_voucher`, `user_by_name`, `put_binding(user_id, key_version, bytes, sig)`, `binding_by_username`, `binding_by_user_id`, `append_control`, `control_records`, `user_roles`. `MemoryStore` has inherent (non-trait) `add_user`, `add_voucher`, `set_roles` test seeders — **do not remove or rename these** (existing tests call them).
- **HTTP layer:** `crates/server/src/http.rs` — `router(state)`, `AppState<S> { auth, blobs, audit, direct_links_enabled }`, the `AuthedSession` extractor (channel-bound session → `user_id`), `post_control` (currently admin-gated via advisory `user_roles`), `directory_by_username`/`directory_by_id` handlers, helpers `b64_fixed`/`b64_vec`/`b64encode`/`hex_fixed`/`hex_encode`/`now_ms`/`internal_error`/`rate_limited`.
- **Auth config/service:** `crates/server/src/auth.rs` — `AuthConfig { server_id, nonce_ttl_ms, session_ttl_ms, rate_limit }` (has `Default`), `AuthService::{new, store, server_id, challenge, prove, validate_session, logout}`.
- **Client verification:** `crates/client-core/src/directory.rs` — `DirectoryVerifier::{new(pinned_dir_pub), verify_binding, authorize_recipient}`, `VerifyError`, `MemoryTrustStore`; `crates/client-core/src/revocation.rs` — `TombstoneSet::verify(&records, anchored_head)`.
- **Canonical e2e templates:** `crates/server/tests/directory_e2e.rs` (offline ceremony → store → serve → client verify, TLS harness `test_pki`/`connect`/`get`), `crates/client-app/tests/connect_login_e2e.rs` (the real client-app `transport`/`session` modules driving connect+login; `post`/`open`/`register` helpers, `spawn_server`).
- **Existing client-app modules to reuse (do not reimplement):** `crates/client-app/src/transport.rs` (`pinned_client_config`, `Transport::{new,connect}`), `crates/client-app/src/session.rs` (`make_proof`, `login_exchange`), `error.rs` (`UiError`), `dto.rs`, `state.rs`, `keystore.rs`, `config.rs`, `commands/` (`connect`, `unlock_keystore`, stubs).

## Environment (tell every subagent)

- **cargo is NOT on the tool PATH.** Prefix every shell command: PowerShell `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; ` / bash `export PATH="$HOME/.cargo/bin:$PATH"; `. Rust 1.96 MSVC.
- **No PostgreSQL on the host.** Run the workspace test gate with `MAXSECU_PG_OPTIONAL=1` (sanctioned skip in `pg_store.rs`). e2e tests use `MemoryStore`/`MemoryBlobStore`.
- **Tauri CLI / GUI is not available** — verify the client via `cargo build`, `tsc`, and the e2e; never launch the window.
- **`cargo fmt --all --check` fails on pre-existing Phase 0–7 drift** — keep only the files you touch fmt-clean (`cargo fmt -p <crate>`), do not mass-reformat.
- **deny.toml:** `ring`/`openssl` are HARD-banned (keep). Add only narrow, justified entries if a genuinely new dep requires it (none expected — all crates here are already in-tree).

## Security-review note for the additive endpoints (honor exactly)

The server stays **secret-free and zero-knowledge**. Every new endpoint preserves that:

- **`POST /v1/bootstrap`** — creates a user during the first-run window only (no published binding exists yet), gated by a bootstrap secret whose **hash** is configured (the server never stores the plaintext). It **does not confer admin** — it only creates the user record (exactly like `create_user`). Admin authority arrives only when the offline ceremony D5-signs that user's binding with `Role::Admin`. The window closes the moment any binding is published, so the secret stops working after the ceremony.
- **`POST /v1/directory` (publish)** — accepts a binding only if it **verifies against the pinned D5 public key**. The server holds D5's *public* half only; it can verify but cannot forge a binding. This is an anti-pollution gate, **not** the security boundary — the client still re-verifies every served binding (`DirectoryVerifier`). Unauthenticated by design: the D5 signature *is* the authority, and the bootstrap admins' bindings must be publishable before any admin session exists.
- **Admin authz (`AdminSession`)** — admin-gated endpoints (`POST /v1/pending` listing read, `POST /v1/vouchers`, `post_control`) authorize by resolving the caller's session → `user_id` → stored binding, verifying it under the pinned D5 key, checking the validity window, and requiring `Role::Admin`. This replaces the advisory `users.roles` gate with the stronger D5-verified one (D-K). The server still can't *grant* admin — it can only *recognize* a D5-signed Admin binding.
- **Deferred (documented, not a hole):** the server's coarse admin gate does **not** yet honor a role-narrowing de-admin tombstone (a de-admined admin keeps *server-side coarse* powers until their binding is re-signed/expires). This is acceptable per DESIGN §4.2/§10 ("coarse authorization … not the security boundary"): the de-admin tombstone's *authoritative* effect is client-side and sink-anchored — clients reject a de-admined admin's signed actions regardless. Server-side tombstone honoring is a follow-up.
- **Sanitized errors:** every new endpoint returns the existing uniform shapes (`400`/`401`/`403`/`404`/`409`/`429`/`500`) with no oracle and no internal detail, mirroring `crates/server/tests/sanitized_errors.rs`.

---

## File structure

```
crates/server/src/
  auth.rs        MODIFY — AuthConfig gains directory_pub + bootstrap_secret_hash (+ builders);
                          AuthService exposes them.
  store.rs       MODIFY — Store trait + MemoryStore: has_any_binding, list_pending_users
                          (+ PendingUser), issue_voucher; FaultyStore impls; creation-time tracking.
  pg.rs          MODIFY — Postgres impls of the three new Store methods.
  http.rs        MODIFY — POST /v1/bootstrap, POST /v1/directory, GET /v1/pending,
                          POST /v1/vouchers; AdminSession extractor; migrate post_control to it;
                          update the post_control admin-gate test + helpers.
crates/server/tests/
  sanitized_errors.rs   MODIFY — add the new endpoints' sanitized-error cases.
tools/ceremony-harness/
  Cargo.toml     NEW — test/dev lib over admin-core (D5 signing).
  src/lib.rs     NEW — Ceremony: generate D5, sign user/admin bindings, account-wide revoke.
crates/client-app/
  Cargo.toml     MODIFY — dev-dep on ceremony-harness; (deps already cover hyper/base64).
  src/dto.rs     MODIFY — bootstrap/admin DTOs.
  src/state.rs   MODIFY — AccountState (pending/active) + EVT_ACCOUNT.
  src/bootstrap.rs   NEW — glass-break credential generation + encrypted save.
  src/admin.rs       NEW — pending-list + voucher + ceremony-request request/response shaping.
  src/http_client.rs NEW — small typed HTTP helpers over an open Transport connection
                            (POST json / GET json), reused by the new commands.
  src/commands/bootstrap.rs  NEW — register_glassbreak, create_first_admin, register_user,
                                   account_status commands.
  src/commands/admin.rs      NEW — list_pending, issue_voucher, request_approval commands.
  src/commands/mod.rs        MODIFY — re-export the new modules.
  src/main.rs    MODIFY — declare modules; register the new commands.
  ui/src/core/types.ts       MODIFY — AccountState + admin DTO TS types.
  ui/src/components/bootstrap-screen.ts  NEW — <bootstrap-screen> glass-break + first-admin.
  ui/src/components/pending-screen.ts    NEW — <pending-screen> status-only + adaptive poll.
  ui/src/components/admin-screen.ts      NEW — <admin-screen> approval queue + voucher issuance.
  ui/src/components/app-shell.ts         MODIFY — route the three new screens; subscribe AccountState.
crates/client-app/tests/
  bootstrap_admin_e2e.rs   NEW — the Phase-2 exit-gate e2e over real TLS.
```

---

## Task 1: Server pins the D5 key + bootstrap secret in `AuthConfig`

**Files:**
- Modify: `crates/server/src/auth.rs`

The two new authz inputs live in `AuthConfig` (flows to `AuthService`, reachable from handlers via `st.auth`). Both default to `None` so every existing `AuthConfig::default()` caller is unaffected.

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` in `crates/server/src/auth.rs`:

```rust
#[test]
fn config_carries_pinned_d5_and_bootstrap_secret() {
    let cfg = AuthConfig::default()
        .with_directory_pub([0x7D; 32])
        .with_bootstrap_secret_hash([0xB5; 32]);
    let svc = AuthService::new(MemoryStore::new(), cfg);
    assert_eq!(svc.directory_pub(), Some([0x7D; 32]));
    assert_eq!(svc.bootstrap_secret_hash(), Some([0xB5; 32]));
    // Defaults are absent (admin endpoints fail closed until configured).
    let bare = AuthService::new(MemoryStore::new(), AuthConfig::default());
    assert_eq!(bare.directory_pub(), None);
    assert_eq!(bare.bootstrap_secret_hash(), None);
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p maxsecu-server auth::tests::config_carries_pinned_d5_and_bootstrap_secret`
Expected: FAIL (no such methods).

- [ ] **Step 3: Add the fields + builders + accessors**

In `AuthConfig` add two fields:

```rust
    /// The pinned offline **directory-signing (D5) public key** (DESIGN §7.3).
    /// `Some` enables D5-verified admin authz + the binding-publish gate; `None`
    /// fails those closed. The server holds only the *public* half — it verifies
    /// bindings, it cannot forge them.
    pub directory_pub: Option<[u8; 32]>,
    /// `SHA-256(bootstrap_secret)` for the first-run bootstrap window (§4.2). The
    /// plaintext is printed once by the operator/launcher and never stored.
    pub bootstrap_secret_hash: Option<[u8; 32]>,
```

In the `Default` impl add `directory_pub: None,` and `bootstrap_secret_hash: None,`.

Add builders + accessors:

```rust
impl AuthConfig {
    /// Pin the offline D5 directory-signing public key (enables admin authz).
    pub fn with_directory_pub(mut self, dir_pub: [u8; 32]) -> Self {
        self.directory_pub = Some(dir_pub);
        self
    }
    /// Configure the first-run bootstrap secret by its `SHA-256` hash.
    pub fn with_bootstrap_secret_hash(mut self, h: [u8; 32]) -> Self {
        self.bootstrap_secret_hash = Some(h);
        self
    }
}
```

In `impl<S: Store> AuthService<S>` add:

```rust
    /// The pinned D5 directory-signing public key, if configured (§7.3).
    pub fn directory_pub(&self) -> Option<[u8; 32]> {
        self.cfg.directory_pub
    }
    /// The configured bootstrap-secret hash, if the bootstrap window is enabled.
    pub fn bootstrap_secret_hash(&self) -> Option<[u8; 32]> {
        self.cfg.bootstrap_secret_hash
    }
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cargo test -p maxsecu-server auth::tests::config_carries_pinned_d5_and_bootstrap_secret`
Expected: PASS.

- [ ] **Step 5: Confirm no literal `AuthConfig { .. }` constructions broke**

Run: `cargo build -p maxsecu-server --all-targets`
Expected: builds. If a literal `AuthConfig { server_id, .. }` exists anywhere (grep `AuthConfig {`), add `directory_pub: None, bootstrap_secret_hash: None,` to it. (`..Default::default()` is also acceptable.)

- [ ] **Step 6: Commit**

```bash
git add crates/server/src/auth.rs
git commit -m "feat(server): AuthConfig pins D5 pubkey + bootstrap secret hash"
```

---

## Task 2: `Store::has_any_binding` (bootstrap-window gate)

**Files:**
- Modify: `crates/server/src/store.rs`, `crates/server/src/pg.rs`

The bootstrap window is **open ⟺ no binding has been published** (the bootstrap admins' bindings are the first ones published, at the ceremony). `has_any_binding` answers that.

- [ ] **Step 1: Write the failing test**

Add to `crates/server/src/store.rs` (create a `#[cfg(test)] mod store_tests` near the bottom, or extend an existing test module if present):

```rust
#[cfg(test)]
mod phase2_store_tests {
    use super::*;
    use maxsecu_encoding::types::{Bytes32, Id, Role, RoleSet, Text, Timestamp};
    use maxsecu_encoding::{encode, structs::DirBinding};

    fn binding_bytes(uid: u8) -> Vec<u8> {
        encode(&DirBinding {
            username: Text::new("u").unwrap(),
            user_id: Id([uid; 16]),
            enc_pub: Bytes32([uid; 32]),
            sig_pub: Bytes32([uid; 32]),
            key_version: 1,
            roles: RoleSet::new([Role::User]),
            not_before: Timestamp(0),
            not_after: Timestamp(4_102_444_800_000),
            mlkem_pub: None,
        })
    }

    #[tokio::test]
    async fn has_any_binding_flips_after_first_publish() {
        let s = MemoryStore::new();
        assert!(!s.has_any_binding().await.unwrap(), "window open with no bindings");
        s.put_binding([0x0A; 16], 1, binding_bytes(0x0A), [0u8; 64]).await.unwrap();
        assert!(s.has_any_binding().await.unwrap(), "window closes after first publish");
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p maxsecu-server phase2_store_tests::has_any_binding_flips_after_first_publish`
Expected: FAIL (no method `has_any_binding`).

- [ ] **Step 3: Add the trait method + impls**

In the `Store` trait (after the binding methods) add:

```rust
    /// `true` iff at least one signed binding has been published — the first-run
    /// bootstrap window is **open** only while this is `false` (§4.2).
    async fn has_any_binding(&self) -> Result<bool, StoreError>;
```

`MemoryStore` impl:

```rust
    async fn has_any_binding(&self) -> Result<bool, StoreError> {
        Ok(!self.inner.lock().unwrap().bindings.is_empty())
    }
```

`FaultyStore` impl (in the `#[cfg(test)]` block):

```rust
    async fn has_any_binding(&self) -> Result<bool, StoreError> {
        Err(Self::fault("has_any_binding"))
    }
```

`PgStore` impl in `crates/server/src/pg.rs`:

```rust
    async fn has_any_binding(&self) -> Result<bool, StoreError> {
        let row = sqlx::query("SELECT EXISTS(SELECT 1 FROM directory_bindings) AS present")
            .fetch_one(&self.pool)
            .await
            .map_err(store_err("has_any_binding"))?;
        row.try_get::<bool, _>("present")
            .map_err(store_err("has_any_binding"))
    }
```

(If `Row::try_get` is not already imported in `pg.rs`, it is — `user_roles` uses it. Keep the same import.)

- [ ] **Step 4: Run it to verify it passes**

Run: `cargo test -p maxsecu-server phase2_store_tests::has_any_binding_flips_after_first_publish`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/server/src/store.rs crates/server/src/pg.rs
git commit -m "feat(server): Store::has_any_binding for the bootstrap window"
```

---

## Task 3: `Store::list_pending_users` (+ `PendingUser`)

**Files:**
- Modify: `crates/server/src/store.rs`, `crates/server/src/lib.rs` (re-export `PendingUser`), `crates/server/src/pg.rs`

A **pending** user is one with a user record but **no published binding** (D-G). The admin approval queue reads this list.

- [ ] **Step 1: Write the failing test**

Add to `phase2_store_tests` in `store.rs`:

```rust
    #[tokio::test]
    async fn list_pending_excludes_users_with_a_binding() {
        let s = MemoryStore::new();
        s.add_user("alice", UserRecord { user_id: [0x0A; 16], enc_pub: [1; 32], sig_pub: [1; 32] });
        s.add_user("bob",   UserRecord { user_id: [0x0B; 16], enc_pub: [2; 32], sig_pub: [2; 32] });
        // alice gets a binding (approved); bob stays pending.
        s.put_binding([0x0A; 16], 1, binding_bytes(0x0A), [0u8; 64]).await.unwrap();

        let pending = s.list_pending_users().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].user_id, [0x0B; 16]);
        assert_eq!(pending[0].username, "bob");
    }
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p maxsecu-server phase2_store_tests::list_pending_excludes_users_with_a_binding`
Expected: FAIL (no `list_pending_users` / `PendingUser`).

- [ ] **Step 3: Add `PendingUser`, the trait method, and impls**

Near the other public view structs in `store.rs`:

```rust
/// One un-approved account for the admin queue (`GET /v1/pending`, D-G): a user
/// record with **no** published binding yet. `created_at_ms` is the request time
/// the pending screen surfaces (0 if unknown for a seeded test user).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingUser {
    pub user_id: [u8; 16],
    pub username: String,
    pub created_at_ms: u64,
}
```

In `Store` trait:

```rust
    /// Users with a record but no published binding — the admin approval queue
    /// (§4.2 / D-G). Newest-first by `created_at_ms`.
    async fn list_pending_users(&self) -> Result<Vec<PendingUser>, StoreError>;
```

Track creation time in `MemoryStore`. In `struct Inner` add:

```rust
    // Wall-clock creation time per username (best-effort; dev store only).
    created_ms: HashMap<String, u64>,
```

In `MemoryStore::create_user`, after inserting the user, record the time (use a local helper):

```rust
        let now = now_ms_wall();
        inner.created_ms.insert(username.to_owned(), now);
```

In `MemoryStore::add_user` (the test seeder), also stamp it:

```rust
        let now = now_ms_wall();
        let mut inner = self.inner.lock().unwrap();
        inner.created_ms.entry(username.to_owned()).or_insert(now);
        inner.users.insert(username.to_owned(), rec);
```

Add a private wall-clock helper at module scope (the store is otherwise clock-injected, but a dev-only creation timestamp is acceptable here):

```rust
fn now_ms_wall() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
```

`MemoryStore::list_pending_users`:

```rust
    async fn list_pending_users(&self) -> Result<Vec<PendingUser>, StoreError> {
        let inner = self.inner.lock().unwrap();
        let mut out: Vec<PendingUser> = inner
            .users
            .iter()
            .filter(|(_, u)| !inner.bindings.contains_key(&u.user_id))
            .map(|(name, u)| PendingUser {
                user_id: u.user_id,
                username: name.clone(),
                created_at_ms: inner.created_ms.get(name).copied().unwrap_or(0),
            })
            .collect();
        out.sort_by(|a, b| b.created_at_ms.cmp(&a.created_at_ms).then(a.user_id.cmp(&b.user_id)));
        Ok(out)
    }
```

`FaultyStore`:

```rust
    async fn list_pending_users(&self) -> Result<Vec<PendingUser>, StoreError> {
        Err(Self::fault("list_pending_users"))
    }
```

`PgStore` (`pg.rs`) — `users` left-joined against the latest binding; `created_at` exists on `users` (the INSERT relies on its DEFAULT):

```rust
    async fn list_pending_users(&self) -> Result<Vec<PendingUser>, StoreError> {
        let rows = sqlx::query(
            "SELECT u.user_id, u.username, \
                    (EXTRACT(EPOCH FROM u.created_at) * 1000)::bigint AS created_ms \
             FROM users u \
             WHERE NOT EXISTS (SELECT 1 FROM directory_bindings b WHERE b.user_id = u.user_id) \
             ORDER BY u.created_at DESC, u.user_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(store_err("list_pending_users"))?;
        rows.iter()
            .map(|r| {
                Ok(PendingUser {
                    user_id: col_fixed(r, "list_pending_users", "user_id")?,
                    username: r.try_get("username").map_err(store_err("list_pending_users"))?,
                    created_at_ms: r
                        .try_get::<i64, _>("created_ms")
                        .map_err(store_err("list_pending_users"))? as u64,
                })
            })
            .collect()
    }
```

> If `users` has no `created_at` column, the implementer must add it via the schema (`schema.sql`) with `DEFAULT now()`; verify against `crates/server/src/pg.rs` `create_user` and `docs/schema.sql`. The MemoryStore path is the one the e2e exercises (no Postgres), so a `created_ms` of 0 is acceptable if the column is absent — but prefer adding the column for prod parity.

Re-export `PendingUser` from `crates/server/src/lib.rs` in the `pub use store::{...}` list.

- [ ] **Step 4: Run it to verify it passes**

Run: `cargo test -p maxsecu-server phase2_store_tests::list_pending_excludes_users_with_a_binding`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/server/src/store.rs crates/server/src/lib.rs crates/server/src/pg.rs
git commit -m "feat(server): Store::list_pending_users + PendingUser"
```

---

## Task 4: `Store::issue_voucher` (admin voucher issuance backing)

**Files:**
- Modify: `crates/server/src/store.rs`, `crates/server/src/pg.rs`

The admin issue-voucher endpoint needs to *persist* a voucher hash with a TTL. The existing `consume_voucher` (Task: register path) checks `used_at IS NULL AND expires_at > now()` in pg. The new trait method is named `issue_voucher` (NOT `add_voucher`, which is the inherent MemoryStore test seeder — keep that intact).

- [ ] **Step 1: Write the failing test**

Add to `phase2_store_tests` in `store.rs`:

```rust
    #[tokio::test]
    async fn issued_voucher_is_consumable_once() {
        let s = MemoryStore::new();
        let h = maxsecu_crypto::sha256(b"invite-code-xyz");
        s.issue_voucher(h, 4_102_444_800_000).await.unwrap();
        assert!(s.consume_voucher(&h).await.unwrap(), "fresh issued voucher consumes");
        assert!(!s.consume_voucher(&h).await.unwrap(), "second consume fails (single-use)");
    }
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p maxsecu-server phase2_store_tests::issued_voucher_is_consumable_once`
Expected: FAIL (no `issue_voucher`).

- [ ] **Step 3: Add the trait method + impls**

`Store` trait:

```rust
    /// Persist a fresh single-use enrollment voucher by its `SHA-256` hash, with
    /// an absolute expiry (`POST /v1/vouchers`, admin-issued). Idempotent re-issue
    /// of the same hash is allowed.
    async fn issue_voucher(&self, voucher_hash: [u8; 32], expires_at_ms: u64) -> Result<(), StoreError>;
```

`MemoryStore` (the dev set has no per-entry TTL; the expiry is honored by pg — the MemoryStore `consume_voucher` is unconditional remove, which is fine for tests):

```rust
    async fn issue_voucher(&self, voucher_hash: [u8; 32], _expires_at_ms: u64) -> Result<(), StoreError> {
        self.inner.lock().unwrap().vouchers.insert(voucher_hash);
        Ok(())
    }
```

`FaultyStore`:

```rust
    async fn issue_voucher(&self, _voucher_hash: [u8; 32], _expires_at_ms: u64) -> Result<(), StoreError> {
        Err(Self::fault("issue_voucher"))
    }
```

`PgStore` (`pg.rs`):

```rust
    async fn issue_voucher(&self, voucher_hash: [u8; 32], expires_at_ms: u64) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO enrollment_vouchers (voucher_hash, expires_at) VALUES ($1, $2) \
             ON CONFLICT (voucher_hash) DO NOTHING",
        )
        .bind(&voucher_hash[..])
        .bind(try_ms_to_ts(expires_at_ms, "issue_voucher")?)
        .execute(&self.pool)
        .await
        .map_err(store_err("issue_voucher"))?;
        Ok(())
    }
```

> Confirm the `enrollment_vouchers` columns against `docs/schema.sql` + the `consume_voucher` query in `pg.rs` (it reads `voucher_hash`, `used_at`, `expires_at`). Use `try_ms_to_ts` (already used by `put_binding`/`append_control`).

- [ ] **Step 4: Run it to verify it passes**

Run: `cargo test -p maxsecu-server phase2_store_tests::issued_voucher_is_consumable_once`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/server/src/store.rs crates/server/src/pg.rs
git commit -m "feat(server): Store::issue_voucher (admin voucher issuance backing)"
```

---

## Task 5: `POST /v1/bootstrap` — first-run glass-break / first-admin registration

**Files:**
- Modify: `crates/server/src/http.rs`

Gated by (1) the bootstrap window being open (`!has_any_binding`) and (2) the bootstrap secret. Creates the user; **does not** confer admin.

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` in `http.rs` (mirror the existing handler-test style — find how the suite builds a test `Router` + sends requests; reuse those helpers, e.g. `app()` / `send`/`post_json`). Add:

```rust
    #[tokio::test]
    async fn bootstrap_creates_user_only_during_the_window_with_the_secret() {
        let store = MemoryStore::new();
        let cfg = AuthConfig::default().with_bootstrap_secret_hash(maxsecu_crypto::sha256(b"S3CRET"));
        let app = app_with(store, cfg); // helper: AppState{auth:AuthService::new(store,cfg),..} + router + exporter layer

        // Wrong secret → 401 (no oracle).
        let (st, _) = post_json(&app, "/v1/bootstrap", serde_json::json!({
            "username": "glassbreak",
            "enc_pub_b64": B64.encode([1u8; 32]),
            "sig_pub_b64": B64.encode([2u8; 32]),
            "bootstrap_secret": "WRONG",
        })).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);

        // Right secret → 201 user_id.
        let (st, body) = post_json(&app, "/v1/bootstrap", serde_json::json!({
            "username": "glassbreak",
            "enc_pub_b64": B64.encode([1u8; 32]),
            "sig_pub_b64": B64.encode([2u8; 32]),
            "bootstrap_secret": "S3CRET",
        })).await;
        assert_eq!(st, StatusCode::CREATED);
        assert_eq!(body["user_id"].as_str().unwrap().len(), 32); // hex-16
    }
```

> Use the existing test helper names from `http.rs`'s test module. If the module exposes `admin_app()`/a `Router` + a raw `oneshot` send, replicate that shape; `app_with`/`post_json` above are illustrative — adapt to the module's real helpers (read them first). The behavioral assertions (401 wrong secret, 201 right secret, hex-16 user_id) are the contract.

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p maxsecu-server bootstrap_creates_user_only_during_the_window_with_the_secret`
Expected: FAIL (route not mounted).

- [ ] **Step 3: Add the handler + route**

Add the request/response types + handler near `register`:

```rust
#[derive(Deserialize)]
struct BootstrapReq {
    username: String,
    enc_pub_b64: String,
    sig_pub_b64: String,
    bootstrap_secret: String,
}

/// `POST /v1/bootstrap` — first-run glass-break / first-admin registration (§4.2).
/// Valid ONLY while the bootstrap window is open (no published binding) and the
/// bootstrap secret matches. Creates the user; **never** confers admin — admin
/// arrives only when the offline ceremony D5-signs the binding (D-K).
async fn bootstrap_register<S: Store>(
    State(st): State<AppState<S>>,
    Json(req): Json<BootstrapReq>,
) -> Response {
    // The window is disabled unless a bootstrap secret is configured.
    let Some(want) = st.auth.bootstrap_secret_hash() else {
        return StatusCode::FORBIDDEN.into_response(); // bootstrap disabled
    };
    // Window closed once any binding is published.
    match st.auth.store().has_any_binding().await {
        Ok(true) => return StatusCode::CONFLICT.into_response(), // bootstrap_closed
        Ok(false) => {}
        Err(e) => return internal_error(e),
    }
    // Constant-shape secret check (no oracle): a mismatch is the same 401 as a bad login.
    if maxsecu_crypto::sha256(req.bootstrap_secret.as_bytes()) != want {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let (Some(enc_pub), Some(sig_pub)) =
        (b64_fixed::<32>(&req.enc_pub_b64), b64_fixed::<32>(&req.sig_pub_b64))
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match st.auth.store().create_user(&req.username, enc_pub, sig_pub).await {
        Ok(Some(user_id)) => (
            StatusCode::CREATED,
            Json(RegisterRes { user_id: hex_encode(&user_id) }),
        )
            .into_response(),
        Ok(None) => StatusCode::CONFLICT.into_response(), // username taken
        Err(e) => internal_error(e),
    }
}
```

Mount it in `router`:

```rust
        .route("/v1/bootstrap", post(bootstrap_register::<S>))
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cargo test -p maxsecu-server bootstrap_creates_user_only_during_the_window_with_the_secret`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/server/src/http.rs
git commit -m "feat(server): POST /v1/bootstrap (window+secret-gated first-run register)"
```

---

## Task 6: `POST /v1/directory` — publish a D5-signed binding

**Files:**
- Modify: `crates/server/src/http.rs`

Accepts a binding only if it verifies under the pinned D5 public key (anti-pollution gate); stores it via `put_binding`. Unauthenticated — the D5 signature is the authority, and bootstrap admins' bindings must be publishable before any admin session exists.

- [ ] **Step 1: Write the failing test**

Add to `http.rs` tests:

```rust
    #[tokio::test]
    async fn publish_binding_requires_a_valid_d5_signature() {
        use maxsecu_admin_core::DirectorySigner;
        use maxsecu_encoding::encode;
        use maxsecu_encoding::structs::DirBinding;
        use maxsecu_encoding::types::{Bytes32, Id, Role, RoleSet, Text, Timestamp};

        let d5 = DirectorySigner::generate();
        let store = MemoryStore::new();
        let cfg = AuthConfig::default().with_directory_pub(d5.public_key());
        let app = app_with(store, cfg);

        let b = DirBinding {
            username: Text::new("alice").unwrap(),
            user_id: Id([0x0A; 16]),
            enc_pub: Bytes32([0xE1; 32]),
            sig_pub: Bytes32([0x51; 32]),
            key_version: 1,
            roles: RoleSet::new([Role::User]),
            not_before: Timestamp(0),
            not_after: Timestamp(4_102_444_800_000),
            mlkem_pub: None,
        };
        let signed = d5.sign_binding(&b, None);

        // Forged signature → rejected.
        let (st, _) = post_json(&app, "/v1/directory", serde_json::json!({
            "binding_b64": B64.encode(encode(&b)),
            "directory_signature_b64": B64.encode([0u8; 64]),
        })).await;
        assert_eq!(st, StatusCode::FORBIDDEN);

        // Genuine D5 signature → 201, and now served by GET /v1/directory/alice.
        let (st, _) = post_json(&app, "/v1/directory", serde_json::json!({
            "binding_b64": B64.encode(encode(&signed.binding)),
            "directory_signature_b64": B64.encode(signed.signature),
        })).await;
        assert_eq!(st, StatusCode::CREATED);
        let (st, body) = get_json(&app, "/v1/directory/alice").await;
        assert_eq!(st, StatusCode::OK);
        assert!(body["binding_b64"].as_str().is_some());
    }
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p maxsecu-server publish_binding_requires_a_valid_d5_signature`
Expected: FAIL (route not mounted).

- [ ] **Step 3: Add the handler + route**

```rust
use maxsecu_crypto::VerifyingKey;
use maxsecu_encoding::labels::DIRBINDING;
use maxsecu_encoding::structs::DirBinding;

#[derive(Deserialize)]
struct PublishBindingReq {
    binding_b64: String,
    directory_signature_b64: String,
}

/// `POST /v1/directory` — publish a ceremony-signed identity binding (§7.1). The
/// server verifies it against the **pinned D5 public key** (anti-pollution) and
/// stores the opaque bytes; it cannot forge a binding (it lacks D5's private key)
/// and the client re-verifies everything served. Unauthenticated by design — the
/// D5 signature is the authority, and bootstrap admins' bindings publish before
/// any admin session exists.
async fn publish_binding<S: Store>(
    State(st): State<AppState<S>>,
    Json(req): Json<PublishBindingReq>,
) -> Response {
    let Some(dir_pub) = st.auth.directory_pub() else {
        return StatusCode::FORBIDDEN.into_response(); // publishing disabled (no pinned D5)
    };
    let (Some(bytes), Some(sig)) =
        (b64_vec(&req.binding_b64), b64_fixed::<64>(&req.directory_signature_b64))
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(binding) = maxsecu_encoding::decode::<DirBinding>(&bytes) else {
        return StatusCode::BAD_REQUEST.into_response(); // non-canonical
    };
    // Verify under the pinned D5 key. A bad/forged signature is refused (403) —
    // the server stores only genuinely ceremony-signed bindings.
    let verified = VerifyingKey::from_bytes(&dir_pub)
        .and_then(|vk| vk.verify_canonical(DIRBINDING, &binding, &sig))
        .is_ok();
    if !verified {
        return StatusCode::FORBIDDEN.into_response();
    }
    match st
        .auth
        .store()
        .put_binding(binding.user_id.0, binding.key_version, bytes, sig)
        .await
    {
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(e) => internal_error(e),
    }
}
```

Mount it (note `/v1/directory/{username}` already exists for GET; add a distinct POST collection route):

```rust
        .route("/v1/directory", post(publish_binding::<S>))
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cargo test -p maxsecu-server publish_binding_requires_a_valid_d5_signature`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/server/src/http.rs
git commit -m "feat(server): POST /v1/directory publishes a D5-verified binding"
```

---

## Task 7: `AdminSession` (D5-verified admin) + `GET /v1/pending` + `POST /v1/vouchers` + migrate `post_control`

**Files:**
- Modify: `crates/server/src/http.rs`

Introduce the unified admin gate and the two admin endpoints; migrate `post_control` (and its test) to the new gate.

- [ ] **Step 1: Write the failing tests**

Add to `http.rs` tests. First a reusable helper that builds an admin-configured app and returns a logged-in admin token + the D5 signer (read the existing `admin_app`/login helpers and adapt):

```rust
    // Build an app whose pinned D5 has signed an ADMIN binding for `admin_id`,
    // plus a channel-bound session token for that admin. Returns (app, d5, token).
    async fn admin_app_d5() -> (/* app */ _, maxsecu_admin_core::DirectorySigner, String) {
        // 1. d5 = DirectorySigner::generate(); cfg = AuthConfig::default().with_directory_pub(d5.public_key())
        // 2. store: add_user("root", UserRecord{user_id:[0xAD;16],..}); enroll keys so login works
        // 3. publish a D5 admin binding for [0xAD;16] (roles {User,Admin}) via store.put_binding
        // 4. perform challenge+proof to mint a session token bound to the test exporter
        // (mirror the existing admin_app + login flow already in this test module)
        unimplemented!("compose from the existing admin_app + login helpers")
    }

    #[tokio::test]
    async fn pending_list_is_admin_gated_and_lists_unsigned_users() {
        let (app, _d5, admin_token) = admin_app_d5().await;
        // Seed a pending user (registered, no binding).
        // ... store.add_user("newbie", UserRecord{user_id:[0x0C;16],..}) via the app's store handle ...

        // No token → 401.
        let (st, _) = get_json(&app, "/v1/pending").await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        // Admin token → 200, lists newbie.
        let (st, body) = get_json_auth(&app, "/v1/pending", &admin_token).await;
        assert_eq!(st, StatusCode::OK);
        let users = body["pending"].as_array().unwrap();
        assert!(users.iter().any(|u| u["username"] == "newbie"));
    }

    #[tokio::test]
    async fn issue_voucher_is_admin_gated_and_enables_registration() {
        let (app, _d5, admin_token) = admin_app_d5().await;
        let h = maxsecu_crypto::sha256(b"in-person-code");
        // Non-admin (no token) → 401.
        let (st, _) = post_json(&app, "/v1/vouchers", serde_json::json!({ "voucher_hash_b64": B64.encode(h) })).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        // Admin → 201; the voucher then works on POST /v1/users.
        let (st, _) = post_json_auth(&app, "/v1/vouchers", serde_json::json!({ "voucher_hash_b64": B64.encode(h) }), &admin_token).await;
        assert_eq!(st, StatusCode::CREATED);
        let (st, _) = post_json(&app, "/v1/users", serde_json::json!({
            "username": "viaadmin",
            "enc_pub_b64": B64.encode([3u8; 32]),
            "sig_pub_b64": B64.encode([4u8; 32]),
            "enrollment_voucher": "in-person-code",
        })).await;
        assert_eq!(st, StatusCode::CREATED);
    }
```

Then **update the existing** `control_log_append_serve_and_admin_gate` test (and the `admin_app`/`admin_app_audited` helpers): the admin caller must now be authorized via a D5-signed Admin binding + a pinned `directory_pub` in `AuthConfig`, instead of `store.set_roles([0xAD;16], [User,Admin])`. A non-admin caller (no binding, or a User-only binding) must still receive `403`.

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p maxsecu-server pending_list_is_admin_gated_and_lists_unsigned_users issue_voucher_is_admin_gated_and_enables_registration`
Expected: FAIL (routes/extractor missing).

- [ ] **Step 3: Implement `AdminSession`, the endpoints, and migrate `post_control`**

`AdminSession` extractor (place after `AuthedSession`):

```rust
/// A channel-bound session whose caller is a **D5-verified admin** (DESIGN
/// §4.2/§10.1, D-K): the session resolves to a `user_id` whose stored binding
/// verifies under the pinned D5 key, is within its validity window, and carries
/// `Role::Admin`. The coarse server gate only — the client re-verifies every
/// control-log record's authenticity independently. Rejects `401` (not a session)
/// or `403` (authenticated but not a verified admin).
pub struct AdminSession {
    pub user_id: [u8; 16],
    pub token: [u8; 32],
}

impl<S: Store + 'static> FromRequestParts<AppState<S>> for AdminSession {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &AppState<S>) -> Result<Self, StatusCode> {
        let session = AuthedSession::from_request_parts(parts, state).await?;
        let Some(dir_pub) = state.auth.directory_pub() else {
            return Err(StatusCode::FORBIDDEN); // admin authz disabled
        };
        let stored = state
            .auth
            .store()
            .binding_by_user_id(&session.user_id)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .ok_or(StatusCode::FORBIDDEN)?; // no binding ⇒ not an admin
        let binding = maxsecu_encoding::decode::<DirBinding>(&stored.binding_bytes)
            .map_err(|_| StatusCode::FORBIDDEN)?;
        // Verify under the pinned D5 key.
        let ok = VerifyingKey::from_bytes(&dir_pub)
            .and_then(|vk| vk.verify_canonical(DIRBINDING, &binding, &stored.signature))
            .is_ok();
        if !ok {
            return Err(StatusCode::FORBIDDEN);
        }
        // Validity window + Admin role.
        let now = now_ms();
        if now < binding.not_before.0 || now > binding.not_after.0 {
            return Err(StatusCode::FORBIDDEN);
        }
        if !binding.roles.roles().contains(&Role::Admin) {
            return Err(StatusCode::FORBIDDEN);
        }
        Ok(AdminSession { user_id: session.user_id, token: session.token })
    }
}
```

`GET /v1/pending`:

```rust
#[derive(Serialize)]
struct PendingOut {
    user_id: String,
    username: String,
    created_at: u64,
}

#[derive(Serialize)]
struct PendingRes {
    pending: Vec<PendingOut>,
}

/// `GET /v1/pending` — the admin approval queue (D-G). Admin-gated; lists users
/// with no published binding. Status only — no key material.
async fn list_pending<S: Store + 'static>(
    State(st): State<AppState<S>>,
    _admin: AdminSession,
) -> Response {
    match st.auth.store().list_pending_users().await {
        Ok(list) => Json(PendingRes {
            pending: list
                .iter()
                .map(|p| PendingOut {
                    user_id: hex_encode(&p.user_id),
                    username: p.username.clone(),
                    created_at: p.created_at_ms,
                })
                .collect(),
        })
        .into_response(),
        Err(e) => internal_error(e),
    }
}
```

`POST /v1/vouchers`:

```rust
/// Admin-issued voucher TTL (operational anti-spam window).
const VOUCHER_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1000;

#[derive(Deserialize)]
struct IssueVoucherReq {
    voucher_hash_b64: String,
}

/// `POST /v1/vouchers` — admin issues a one-time enrollment voucher (§4.2). The
/// admin client generates the code and posts only its `SHA-256` (the server never
/// sees the code). Admin-gated.
async fn issue_voucher<S: Store + 'static>(
    State(st): State<AppState<S>>,
    _admin: AdminSession,
    Json(req): Json<IssueVoucherReq>,
) -> Response {
    let Some(hash) = b64_fixed::<32>(&req.voucher_hash_b64) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match st.auth.store().issue_voucher(hash, now_ms() + VOUCHER_TTL_MS).await {
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(e) => internal_error(e),
    }
}
```

Migrate `post_control`: change its signature from `session: AuthedSession` + the manual `user_roles`/`Role::Admin` block to `_admin: AdminSession` and delete the role-lookup block. Keep the rest (decode/append/publish) unchanged.

Mount the routes in `router`:

```rust
        .route("/v1/pending", get(list_pending::<S>))
        .route("/v1/vouchers", post(issue_voucher::<S>))
```

- [ ] **Step 4: Run the new + migrated tests**

Run: `cargo test -p maxsecu-server pending_list_is_admin_gated_and_lists_unsigned_users issue_voucher_is_admin_gated_and_enables_registration control_log_append_serve_and_admin_gate`
Expected: PASS (all three).

- [ ] **Step 5: Full server test pass**

Run: `cargo test -p maxsecu-server`
Expected: PASS. (Fix any other test that relied on the old advisory `post_control` gate by giving its admin caller a D5-signed Admin binding + a pinned `directory_pub`.)

- [ ] **Step 6: Commit**

```bash
git add crates/server/src/http.rs
git commit -m "feat(server): D5-verified AdminSession; GET /v1/pending; POST /v1/vouchers; migrate post_control"
```

---

## Task 8: Sanitized-error coverage for the new endpoints

**Files:**
- Modify: `crates/server/tests/sanitized_errors.rs`

Prove the new endpoints leak no oracle and surface a backend fault as a bare `500` (reuse the `FaultyStore` pattern already in that file).

- [ ] **Step 1: Write the failing tests**

Read `crates/server/tests/sanitized_errors.rs` for its harness (it builds a router over a chosen `Store`, including `FaultyStore`, and asserts statuses with no body detail). Add:

```rust
#[tokio::test]
async fn bootstrap_backend_fault_is_bare_500() {
    // FaultyStore + a configured bootstrap secret → has_any_binding faults → 500,
    // never a misleading 401/201, and no detail in the body.
    // (compose like the existing faulty-store cases in this file)
}

#[tokio::test]
async fn pending_requires_admin_no_oracle() {
    // No session → 401; an authenticated non-admin (no D5 admin binding) → 403;
    // bodies are empty (no reason string).
}

#[tokio::test]
async fn publish_binding_rejects_forged_without_detail() {
    // directory_pub configured; a forged signature → 403 with an empty body.
}
```

Flesh each out with the file's real helpers (router builder, request sender, status+body asserts). The contract: `bootstrap` over a `FaultyStore` → `500` (bare); `/v1/pending` without admin → `401`/`403` (bare); `/v1/directory` forged → `403` (bare).

- [ ] **Step 2: Run them to verify they fail, then implement/adjust until they pass**

Run: `cargo test -p maxsecu-server --test sanitized_errors`
Expected: FAIL first, then PASS after wiring the cases to the real harness (the endpoints already behave correctly from Tasks 5–7; this task only adds coverage).

- [ ] **Step 3: Commit**

```bash
git add crates/server/tests/sanitized_errors.rs
git commit -m "test(server): sanitized-error coverage for bootstrap/publish/pending"
```

---

## Task 9: `tools/ceremony-harness` — scripted offline D5 ceremony (test/dev)

**Files:**
- Create: `tools/ceremony-harness/Cargo.toml`, `tools/ceremony-harness/src/lib.rs`
- Modify: root `Cargo.toml` (workspace members)

A thin, **test-only** library over `admin-core` that scripts the air-gapped ceremony in-process (spec §3, §4.5 — security-degraded, never a prod path). It produces the `(binding_bytes, signature)` the publish endpoint accepts.

- [ ] **Step 1: Add the crate to the workspace**

In root `Cargo.toml` `[workspace] members`, add `"tools/ceremony-harness",`.

- [ ] **Step 2: Write `tools/ceremony-harness/Cargo.toml`**

```toml
[package]
name = "maxsecu-ceremony-harness"
version = "0.0.0"
edition.workspace = true
rust-version.workspace = true
publish = false
description = "TEST-ONLY scripted offline D5 ceremony over admin-core (not a prod path)."

[dependencies]
maxsecu-admin-core = { path = "../../crates/admin-core" }
maxsecu-crypto = { path = "../../crates/crypto" }
maxsecu-encoding = { path = "../../crates/encoding" }

[lints.rust]
unsafe_code = "forbid"
```

- [ ] **Step 3: Write the failing test + the lib body**

`tools/ceremony-harness/src/lib.rs`:

```rust
//! TEST-ONLY scripted offline ceremony (spec §4.5). Wraps the air-gapped
//! `admin-core` D5 key so a test can D5-sign + revoke without a real air-gap.
//! NEVER a production path — the real ceremony runs the CLIs offline.

#![forbid(unsafe_code)]

use maxsecu_admin_core::{ControlChain, CoSign, DirectorySigner, RevokeParams, SignedControlRecord};
use maxsecu_crypto::{fingerprint, SigningKey};
use maxsecu_encoding::encode;
use maxsecu_encoding::structs::DirBinding;
use maxsecu_encoding::types::{Bytes32, FileScope, Id, Role, RoleSet, Text, Timestamp};

/// Far-future validity bound for test bindings (year 2100).
pub const FAR_FUTURE_MS: u64 = 4_102_444_800_000;

/// The scripted ceremony: holds the D5 key (and dual-control admin keys for
/// account-wide revokes) the way the offline ceremony would.
pub struct Ceremony {
    d5: DirectorySigner,
}

/// What the publish endpoint consumes: the canonical binding bytes + D5 signature.
pub struct PublishedBinding {
    pub binding_bytes: Vec<u8>,
    pub signature: [u8; 64],
}

impl Ceremony {
    /// Generate a fresh D5 key (key-generation ceremony).
    pub fn generate() -> Ceremony {
        Ceremony { d5: DirectorySigner::generate() }
    }

    /// The pinned D5 public key clients + the server are configured with.
    pub fn directory_pub(&self) -> [u8; 32] {
        self.d5.public_key()
    }

    /// Sign an identity binding with the given roles, enforcing the in-person
    /// fingerprint confirmation (the MITM defense). `user_id`/`enc_pub`/`sig_pub`
    /// are the values the server returned at registration.
    pub fn sign_binding(
        &self,
        username: &str,
        user_id: [u8; 16],
        enc_pub: [u8; 32],
        sig_pub: [u8; 32],
        roles: &[Role],
        key_version: u64,
    ) -> PublishedBinding {
        let binding = DirBinding {
            username: Text::new(username).expect("valid username"),
            user_id: Id(user_id),
            enc_pub: Bytes32(enc_pub),
            sig_pub: Bytes32(sig_pub),
            key_version,
            roles: RoleSet::new(roles.iter().copied()),
            not_before: Timestamp(0),
            not_after: Timestamp(FAR_FUTURE_MS),
            mlkem_pub: None,
        };
        let confirmed = fingerprint(&enc_pub, &sig_pub); // the admin confirms this in person
        let signed = self
            .d5
            .sign_enrollment(&binding, &confirmed)
            .expect("fingerprint matches (scripted)");
        PublishedBinding {
            binding_bytes: encode(&signed.binding),
            signature: signed.signature,
        }
    }

    /// A dual-controlled account-wide revocation tombstone (for de-admin/revoke
    /// flows). Returns the signed record + the new anchored head.
    pub fn account_revoke(&self, revoked: [u8; 16], at_ms: u64) -> (SignedControlRecord, [u8; 32]) {
        let mut chain = ControlChain::new();
        let admin = SigningKey::generate();
        let co = SigningKey::generate();
        let rec = chain
            .revoke(
                &admin,
                RevokeParams {
                    scope: FileScope::AccountWide,
                    revoked_user_id: Id(revoked),
                    revoked_capability: None,
                    from_version: 1,
                    issued_by: Id([0xAD; 16]),
                    created_at: Timestamp(at_ms),
                },
                Some(CoSign { admin_id: Id([0xC0; 16]), key: &co }),
            )
            .expect("account-wide revoke is dual-controlled");
        let head = chain.head();
        (rec, head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_crypto::VerifyingKey;
    use maxsecu_encoding::decode;
    use maxsecu_encoding::labels::DIRBINDING;

    #[test]
    fn signed_binding_verifies_under_the_pinned_d5() {
        let cer = Ceremony::generate();
        let pb = cer.sign_binding("alice", [0x0A; 16], [0xE1; 32], [0x51; 32], &[Role::User], 1);
        let binding: DirBinding = decode(&pb.binding_bytes).unwrap();
        VerifyingKey::from_bytes(&cer.directory_pub())
            .unwrap()
            .verify_canonical(DIRBINDING, &binding, &pb.signature)
            .expect("a scripted-ceremony binding verifies under the pinned D5");
        assert_eq!(binding.roles.roles(), &[Role::User]);
    }
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cargo test -p maxsecu-ceremony-harness`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml tools/ceremony-harness
git commit -m "feat(ceremony-harness): test-only scripted offline D5 ceremony"
```

---

## Task 10: client-app typed HTTP helpers over an open `Transport`

**Files:**
- Create: `crates/client-app/src/http_client.rs`
- Modify: `crates/client-app/src/main.rs` (`mod http_client;`)

The new commands POST/GET JSON over a pinned-TLS connection. Factor the hyper request/response plumbing (already proven in `connect_login_e2e.rs`) into one reusable module so each command stays thin.

- [ ] **Step 1: Write the failing test**

`crates/client-app/src/http_client.rs`:

```rust
//! Thin typed JSON-over-HTTP/1.1 helpers used by the Phase-2 commands on top of
//! an already-established pinned-TLS connection (transport.rs). Only DTOs cross —
//! never key material.

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, StatusCode};

use crate::error::UiError;

/// POST a JSON body; return `(status, json)`. `bearer` adds the channel-bound
/// `Authorization: MaxSecu-Session <hex>` header when `Some`.
pub async fn post_json(
    sender: &mut SendRequest<Full<Bytes>>,
    uri: &str,
    body: &serde_json::Value,
    bearer: Option<&str>,
) -> Result<(StatusCode, serde_json::Value), UiError> {
    send(sender, "POST", uri, Some(body), bearer).await
}

/// GET and return `(status, json)`.
pub async fn get_json(
    sender: &mut SendRequest<Full<Bytes>>,
    uri: &str,
    bearer: Option<&str>,
) -> Result<(StatusCode, serde_json::Value), UiError> {
    send(sender, "GET", uri, None, bearer).await
}

async fn send(
    sender: &mut SendRequest<Full<Bytes>>,
    method: &str,
    uri: &str,
    body: Option<&serde_json::Value>,
    bearer: Option<&str>,
) -> Result<(StatusCode, serde_json::Value), UiError> {
    sender.ready().await.map_err(|_| UiError::new("offline", "Lost connection to the server."))?;
    let mut builder = Request::builder().method(method).uri(uri).header("host", "localhost");
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    if let Some(tok) = bearer {
        builder = builder.header("authorization", format!("MaxSecu-Session {tok}"));
    }
    let payload = body.map(|b| Bytes::from(b.to_string())).unwrap_or_default();
    let req = builder
        .body(Full::new(payload))
        .map_err(|_| UiError::new("internal", "Could not build the request."))?;
    let resp = sender
        .send_request(req)
        .await
        .map_err(|_| UiError::new("offline", "The server did not respond."))?;
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|_| UiError::new("offline", "The response was interrupted."))?
        .to_bytes();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    Ok((status, json))
}

#[cfg(test)]
mod tests {
    #[test]
    fn module_compiles() {
        // Behavior is exercised by the e2e (live TLS); this guards the surface.
        assert_eq!(2 + 2, 4);
    }
}
```

- [ ] **Step 2: Wire the module + verify it builds**

Add `mod http_client;` to `crates/client-app/src/main.rs`.

Run: `cargo test -p maxsecu-client-app http_client::tests::module_compiles`
Expected: PASS (after `mod http_client;` is declared).

- [ ] **Step 3: Commit**

```bash
git add crates/client-app/src/http_client.rs crates/client-app/src/main.rs
git commit -m "feat(client-app): typed JSON HTTP helpers over the pinned transport"
```

---

## Task 11: Glass-break credentials + bootstrap commands

**Files:**
- Create: `crates/client-app/src/bootstrap.rs`, `crates/client-app/src/commands/bootstrap.rs`
- Modify: `crates/client-app/src/dto.rs`, `crates/client-app/src/commands/mod.rs`, `crates/client-app/src/main.rs`

Glass-break generates a random username + password locally, seals an identity into a portable keystore blob (reusing `keystore`/`keyblob`), and optionally writes an **encrypted** creds file; it does **not** log in. First-admin uses a user-chosen username+password. Both register via `POST /v1/bootstrap`.

- [ ] **Step 1: Write the failing test for credential generation**

`crates/client-app/src/bootstrap.rs`:

```rust
//! Glass-break emergency-credential generation (spec §4.1/§4.2). Random local
//! creds, sealed like any portable keystore; never auto-logged-in; the optional
//! creds file is ciphertext (the keystore blob itself is the encrypted artifact).

use maxsecu_client_core::Identity;
use maxsecu_crypto::random_array;

use crate::error::UiError;

/// A freshly generated emergency credential set. The password is high-entropy and
/// shown once; the identity is sealed by the caller into the keystore.
pub struct GlassbreakCreds {
    pub username: String,
    pub password: String,
    pub identity: Identity,
}

/// Generate a random username (`gb-<hex>`) + a high-entropy password + a fresh
/// identity. Pure/local — no network, no login.
pub fn generate_glassbreak() -> GlassbreakCreds {
    let uname_suffix: [u8; 6] = random_array();
    let pw_bytes: [u8; 24] = random_array();
    GlassbreakCreds {
        username: format!("gb-{}", hex_lower(&uname_suffix)),
        password: base64_url(&pw_bytes),
        identity: Identity::generate(),
    }
}

fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// URL-safe base64 without padding — a copy-pasteable password alphabet.
fn base64_url(b: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(b)
}

/// Validate that a generated password is non-trivial (length floor).
pub fn ensure_strong(password: &str) -> Result<(), UiError> {
    if password.len() < 16 {
        return Err(UiError::new("weak_password", "Generated password too short."));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glassbreak_creds_are_random_and_well_formed() {
        let a = generate_glassbreak();
        let b = generate_glassbreak();
        assert!(a.username.starts_with("gb-"));
        assert_ne!(a.username, b.username, "usernames are random");
        assert_ne!(a.password, b.password, "passwords are random");
        ensure_strong(&a.password).unwrap();
        // Distinct identities.
        assert_ne!(a.identity.sig_pub_bytes(), b.identity.sig_pub_bytes());
    }
}
```

- [ ] **Step 2: Run it to verify it fails, then passes**

Add `mod bootstrap;` to `main.rs`.
Run: `cargo test -p maxsecu-client-app bootstrap::tests::glassbreak_creds_are_random_and_well_formed`
Expected: PASS (after the module is declared).

- [ ] **Step 3: Add DTOs**

In `crates/client-app/src/dto.rs` add:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapRequest {
    pub bootstrap_secret: String,
    /// Optional path to write the encrypted glass-break creds file.
    pub save_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GlassbreakResponse {
    /// The generated username, shown once so the operator can record it.
    pub username: String,
    /// The generated password, shown once (never persisted in cleartext).
    pub password: String,
    pub user_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FirstAdminRequest {
    pub username: String,
    pub password: String,
    pub bootstrap_secret: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegisterUserRequest {
    pub username: String,
    pub password: String,
    pub voucher: String,
}
```

- [ ] **Step 4: Add the bootstrap commands**

`crates/client-app/src/commands/bootstrap.rs` — read the existing `commands/connection.rs` `connect` to reuse how it builds a `Transport` + opens a connection (managed `Session`/`AppDir` state, `pinned_client_config`, `ConnectionConfig`). Each command opens one pinned-TLS connection, performs its single exchange, returns a DTO.

```rust
use hyper::StatusCode;
use hyper_util::rt::TokioIo;
use tauri::State;

use crate::commands::auth::AppDir;
use crate::dto::{BootstrapRequest, FirstAdminRequest, GlassbreakResponse, RegisterUserRequest};
use crate::error::UiError;
use crate::http_client::post_json;
use crate::{bootstrap, keystore};

// Reuse the transport-building helper used by `connect` (factor it into a shared
// fn `open_connection(dir) -> SendRequest<...>` in commands/connection.rs if not
// already present; mirror connect_login_e2e.rs `open`). Shown here as `open_conn`.

/// `register_glassbreak` — generate emergency creds, register via /v1/bootstrap,
/// seal the keystore for them, optionally write the encrypted creds file. NOT a
/// login (spec §4.1).
#[tauri::command]
pub async fn register_glassbreak(
    req: BootstrapRequest,
    dir: State<'_, AppDir>,
) -> Result<GlassbreakResponse, UiError> {
    let creds = bootstrap::generate_glassbreak();
    bootstrap::ensure_strong(&creds.password)?;
    let mut sender = open_conn(&dir.0).await?;
    let body = serde_json::json!({
        "username": creds.username,
        "enc_pub_b64": b64(creds.identity.enc_pub_bytes()),
        "sig_pub_b64": b64(creds.identity.sig_pub_bytes()),
        "bootstrap_secret": req.bootstrap_secret,
    });
    let (status, json) = post_json(&mut sender, "/v1/bootstrap", &body, None).await?;
    let user_id = bootstrap_user_id(status, &json)?;
    // Seal a portable keystore at a glass-break-specific sub-path so it does not
    // collide with the operator's own keystore (kept offline; never auto-loaded).
    keystore::seal_identity(&dir.0.join("glassbreak"), &creds.password, &creds.identity)?;
    if let Some(path) = req.save_path {
        keystore::seal_identity(std::path::Path::new(&path), &creds.password, &creds.identity)?;
    }
    Ok(GlassbreakResponse {
        username: creds.username,
        password: creds.password,
        user_id,
    })
}

/// `create_first_admin` — register the operator's chosen admin account via
/// /v1/bootstrap and seal its keystore. Admin role is conferred later, by the
/// ceremony (D-K) — this only creates the account.
#[tauri::command]
pub async fn create_first_admin(
    req: FirstAdminRequest,
    dir: State<'_, AppDir>,
) -> Result<String, UiError> {
    let id = keystore::create(&dir.0, &req.password)?; // seals a fresh identity for the admin
    let mut sender = open_conn(&dir.0).await?;
    let body = serde_json::json!({
        "username": req.username,
        "enc_pub_b64": b64(id.enc_pub_bytes()),
        "sig_pub_b64": b64(id.sig_pub_bytes()),
        "bootstrap_secret": req.bootstrap_secret,
    });
    let (status, json) = post_json(&mut sender, "/v1/bootstrap", &body, None).await?;
    bootstrap_user_id(status, &json)
}

/// `register_user` — voucher-gated enrollment via /v1/users (the post-bootstrap
/// path). Seals the new user's keystore; they then sit in `pending` until the
/// ceremony signs their binding.
#[tauri::command]
pub async fn register_user(
    req: RegisterUserRequest,
    dir: State<'_, AppDir>,
) -> Result<String, UiError> {
    let id = keystore::create(&dir.0, &req.password)?;
    let mut sender = open_conn(&dir.0).await?;
    let body = serde_json::json!({
        "username": req.username,
        "enc_pub_b64": b64(id.enc_pub_bytes()),
        "sig_pub_b64": b64(id.sig_pub_bytes()),
        "enrollment_voucher": req.voucher,
    });
    let (status, json) = post_json(&mut sender, "/v1/users", &body, None).await?;
    match status {
        StatusCode::CREATED => json["user_id"]
            .as_str()
            .map(|s| s.to_owned())
            .ok_or_else(|| UiError::new("internal", "Malformed server response.")),
        StatusCode::CONFLICT => Err(UiError::new("username_taken", "That username is taken.")),
        StatusCode::FORBIDDEN => Err(UiError::new("bad_voucher", "That invite code is invalid or used.")),
        _ => Err(UiError::new("register_failed", "Registration failed.")),
    }
}

fn bootstrap_user_id(status: StatusCode, json: &serde_json::Value) -> Result<String, UiError> {
    match status {
        StatusCode::CREATED => json["user_id"]
            .as_str()
            .map(|s| s.to_owned())
            .ok_or_else(|| UiError::new("internal", "Malformed server response.")),
        StatusCode::CONFLICT => Err(UiError::new("bootstrap_closed", "Bootstrap is no longer available.")),
        StatusCode::UNAUTHORIZED => Err(UiError::new("bad_secret", "The bootstrap secret is incorrect.")),
        _ => Err(UiError::new("bootstrap_failed", "Bootstrap failed.")),
    }
}

fn b64(bytes: impl AsRef<[u8]>) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.encode(bytes.as_ref())
}
```

Two supporting items the implementer must wire:

1. **`open_conn(dir) -> SendRequest<Full<Bytes>>`** — factor the connection setup from `commands/connection.rs::connect` (build `ConnectionConfig::load`, `pinned_client_config`, `Transport::new`, `Transport::connect`, then `hyper::client::conn::http1::handshake` + spawn the conn task — exactly `connect_login_e2e.rs::open`). Put it in `commands/connection.rs` as `pub(crate) async fn open_conn(...)` and import it. (If `connect` already establishes a stored connection, expose a reusable opener instead of duplicating.)
2. **`keystore::seal_identity(dir, password, identity)`** — add to `crates/client-app/src/keystore.rs` a function that seals a *given* identity (the existing `create` generates one): `pub fn seal_identity(dir: &Path, password: &str, id: &Identity) -> Result<(), UiError>` doing `keyblob::seal` + write (refactor `create` to call it). Add a unit test mirroring the existing keystore tests.

`commands/mod.rs`: add `pub mod bootstrap;`.
`main.rs`: register `commands::bootstrap::{register_glassbreak, create_first_admin, register_user}` in `invoke_handler!`. Replace the matching `not_implemented` stubs.

- [ ] **Step 5: Build + test**

Run: `cargo test -p maxsecu-client-app keystore:: bootstrap::` then `cargo build -p maxsecu-client-app`
Expected: PASS / builds.

- [ ] **Step 6: Commit**

```bash
git add crates/client-app/src/bootstrap.rs crates/client-app/src/commands crates/client-app/src/dto.rs crates/client-app/src/keystore.rs crates/client-app/src/main.rs
git commit -m "feat(client-app): glass-break + first-admin + user bootstrap commands"
```

---

## Task 12: `account_status` command + `AccountState`

**Files:**
- Modify: `crates/client-app/src/state.rs`, `crates/client-app/src/commands/bootstrap.rs`, `crates/client-app/src/main.rs`

A pending user (record exists, no published binding) gets `404` from `GET /v1/directory/{username}`; once the ceremony publishes their binding it returns `200`. `account_status` maps that to a typed state the pending screen polls — **no new server endpoint**.

- [ ] **Step 1: Write the failing test for the state shape**

Add to `crates/client-app/src/state.rs`:

```rust
pub const EVT_ACCOUNT: &str = "maxsecu://account-state";

/// Approval status for the signed-in account (D-G). `Pending` shows the
/// status-only screen; `Active` unlocks the app.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "state")]
pub enum AccountState {
    Unknown,
    Pending,
    Active,
}

#[cfg(test)]
mod account_tests {
    use super::*;
    #[test]
    fn account_state_serializes_kebab_tagged() {
        assert_eq!(
            serde_json::to_string(&AccountState::Pending).unwrap(),
            "{\"state\":\"pending\"}"
        );
    }
}
```

- [ ] **Step 2: Run it to verify it passes**

Run: `cargo test -p maxsecu-client-app state::account_tests`
Expected: PASS.

- [ ] **Step 3: Add the command**

In `commands/bootstrap.rs`:

```rust
use crate::dto::AccountStatusRequest;
use crate::http_client::get_json;
use crate::state::AccountState;

/// `account_status` — poll whether the signed-in account has been approved (its
/// binding published). `404` → Pending; `200` → Active. Status only — the
/// directory body is opaque here (the client TCB re-verifies it elsewhere).
#[tauri::command]
pub async fn account_status(
    req: AccountStatusRequest,
    dir: State<'_, AppDir>,
) -> Result<AccountState, UiError> {
    let mut sender = open_conn(&dir.0).await?;
    let (status, _json) =
        get_json(&mut sender, &format!("/v1/directory/{}", req.username), None).await?;
    match status {
        StatusCode::OK => Ok(AccountState::Active),
        StatusCode::NOT_FOUND => Ok(AccountState::Pending),
        _ => Err(UiError::new("status_failed", "Could not check account status.")),
    }
}
```

Add the DTO to `dto.rs`:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct AccountStatusRequest {
    pub username: String,
}
```

Register `commands::bootstrap::account_status` in `main.rs`.

- [ ] **Step 4: Build + test**

Run: `cargo build -p maxsecu-client-app` and `cargo test -p maxsecu-client-app state::`
Expected: builds / PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/src/state.rs crates/client-app/src/commands/bootstrap.rs crates/client-app/src/dto.rs crates/client-app/src/main.rs
git commit -m "feat(client-app): account_status command + AccountState (pending/active)"
```

---

## Task 13: Admin commands — `list_pending`, `issue_voucher`, `request_approval`

**Files:**
- Create: `crates/client-app/src/admin.rs`, `crates/client-app/src/commands/admin.rs`
- Modify: `crates/client-app/src/dto.rs`, `crates/client-app/src/commands/mod.rs`, `crates/client-app/src/main.rs`

The admin uses a channel-bound session (its token threaded as `Authorization`). `issue_voucher` generates the code client-side and posts only its hash, returning the code to display. `request_approval` produces a **ceremony work-item** (D-K) — it does not (and cannot) sign; the actual D5 signing is offline (or the ceremony-harness in tests).

- [ ] **Step 1: Write the failing test for voucher-code generation**

`crates/client-app/src/admin.rs`:

```rust
//! Admin-side helpers: voucher-code generation and ceremony-request shaping. No
//! key material here — the D5 key is offline; "approve" emits a work-item, not a
//! signature (D-K).

use maxsecu_crypto::{random_array, sha256};

/// A freshly generated invite: the human-shareable `code` and the `hash` posted
/// to the server (the server never sees the code).
pub struct Voucher {
    pub code: String,
    pub hash: [u8; 32],
}

/// Generate a random invite code + its SHA-256.
pub fn generate_voucher() -> Voucher {
    let raw: [u8; 18] = random_array();
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let code = URL_SAFE_NO_PAD.encode(raw);
    let hash = sha256(code.as_bytes());
    Voucher { code, hash }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn voucher_hash_matches_code() {
        let v = generate_voucher();
        assert_eq!(v.hash, sha256(v.code.as_bytes()));
        assert_ne!(generate_voucher().code, generate_voucher().code);
    }
}
```

- [ ] **Step 2: Run it to verify it passes**

Add `mod admin;` to `main.rs`.
Run: `cargo test -p maxsecu-client-app admin::tests::voucher_hash_matches_code`
Expected: PASS.

- [ ] **Step 3: Add DTOs + commands**

`dto.rs`:

```rust
#[derive(Debug, Clone, Serialize)]
pub struct PendingUserDto {
    pub user_id: String,
    pub username: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct IssueVoucherResponse {
    /// The invite code to hand to the new user in person (shown once).
    pub code: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApprovalRequest {
    pub user_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CeremonyWorkItem {
    /// What the offline ceremony needs: the candidate to D5-sign with `roles`.
    pub user_id: String,
    pub roles: Vec<String>,
    pub note: String,
}
```

`commands/admin.rs` (the admin session token is read from managed `Session` state set at login — mirror how `connect`/login stored it; thread it as the bearer):

```rust
use tauri::State;

use crate::admin;
use crate::commands::auth::AppDir;
use crate::dto::{ApprovalRequest, CeremonyWorkItem, IssueVoucherResponse, PendingUserDto};
use crate::error::UiError;
use crate::http_client::{get_json, post_json};
use crate::session::Session; // managed state holding the channel-bound token (set at login)

/// `list_pending` — the admin approval queue (D-G). Requires an admin session.
#[tauri::command]
pub async fn list_pending(
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
) -> Result<Vec<PendingUserDto>, UiError> {
    let token = session.token().ok_or_else(|| UiError::new("unauthorized", "Sign in as an admin."))?;
    let mut sender = open_conn(&dir.0).await?;
    let (status, json) = get_json(&mut sender, "/v1/pending", Some(&token)).await?;
    match status.as_u16() {
        200 => Ok(json["pending"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|u| PendingUserDto {
                        user_id: u["user_id"].as_str().unwrap_or_default().to_owned(),
                        username: u["username"].as_str().unwrap_or_default().to_owned(),
                        created_at: u["created_at"].as_u64().unwrap_or(0),
                    })
                    .collect()
            })
            .unwrap_or_default()),
        401 | 403 => Err(UiError::new("forbidden", "Admin access required.")),
        _ => Err(UiError::new("pending_failed", "Could not load the approval queue.")),
    }
}

/// `issue_voucher` — generate an invite, post its hash, return the code to show.
#[tauri::command]
pub async fn issue_voucher(
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
) -> Result<IssueVoucherResponse, UiError> {
    let token = session.token().ok_or_else(|| UiError::new("unauthorized", "Sign in as an admin."))?;
    let voucher = admin::generate_voucher();
    let mut sender = open_conn(&dir.0).await?;
    let body = serde_json::json!({ "voucher_hash_b64": b64(voucher.hash) });
    let (status, _json) = post_json(&mut sender, "/v1/vouchers", &body, Some(&token)).await?;
    match status.as_u16() {
        201 => Ok(IssueVoucherResponse { code: voucher.code }),
        401 | 403 => Err(UiError::new("forbidden", "Admin access required.")),
        _ => Err(UiError::new("voucher_failed", "Could not issue an invite.")),
    }
}

/// `request_approval` — produce a ceremony work-item for a pending user (D-K).
/// The running app cannot sign (the D5 key is offline); this hands the operator
/// the data the air-gapped ceremony needs.
#[tauri::command]
pub fn request_approval(req: ApprovalRequest) -> Result<CeremonyWorkItem, UiError> {
    Ok(CeremonyWorkItem {
        user_id: req.user_id,
        roles: vec!["user".to_owned()],
        note: "Confirm the candidate's fingerprint in person, then D5-sign at the ceremony.".to_owned(),
    })
}

fn b64(bytes: impl AsRef<[u8]>) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.encode(bytes.as_ref())
}
```

> If the existing `session` module does not expose a managed `Session` with a `token()` accessor, add a minimal one (a `Mutex<Option<String>>` set by the login flow in `connect`). Read `commands/connection.rs` + `session.rs` first and reuse what login already stores; do not introduce a second session store.

`commands/mod.rs`: add `pub mod admin;`. `main.rs`: register `commands::admin::{list_pending, issue_voucher, request_approval}` and replace any matching stubs.

- [ ] **Step 4: Build + test**

Run: `cargo test -p maxsecu-client-app admin::` then `cargo build -p maxsecu-client-app`
Expected: PASS / builds.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/src/admin.rs crates/client-app/src/commands crates/client-app/src/dto.rs crates/client-app/src/main.rs
git commit -m "feat(client-app): admin commands (pending list, voucher, ceremony-request)"
```

---

## Task 14: UI — `<bootstrap-screen>` (glass-break + first-admin)

**Files:**
- Create: `crates/client-app/ui/src/components/bootstrap-screen.ts`
- Modify: `crates/client-app/ui/src/core/types.ts`, `crates/client-app/ui/src/components/app-shell.ts`

Accessible (WCAG 2.1 AA) two-step bootstrap. Mirror the Phase-1 `connect-screen.ts` patterns (landmarks, labelled inputs, `role="alert"` errors, the `call()` rpc wrapper).

- [ ] **Step 1: Add TS DTO types**

In `crates/client-app/ui/src/core/types.ts` add:

```ts
export interface GlassbreakResponse { username: string; password: string; user_id: string }
export interface PendingUserDto { user_id: string; username: string; created_at: number }
export interface IssueVoucherResponse { code: string }
export interface AccountStateMsg { state: "unknown" | "pending" | "active" }
```

- [ ] **Step 2: Write `bootstrap-screen.ts`**

```ts
import { call } from "../core/rpc.ts";
import type { GlassbreakResponse } from "../core/types.ts";

// Two-step first-run bootstrap (spec §4.2): ① generate the emergency glass-break
// account, ② create the first admin. Accessible: landmark, labelled controls,
// role="alert" errors, focus moved to the heading on step change.
export class BootstrapScreen extends HTMLElement {
  connectedCallback() {
    this.renderGlassbreak();
  }

  private renderGlassbreak() {
    this.innerHTML = `
      <main id="main" aria-labelledby="bs-h">
        <h1 id="bs-h" tabindex="-1">First-run setup — Step 1 of 2: Emergency account</h1>
        <p>This creates a one-time <strong>glass-break</strong> account. Record its
           credentials offline; it is your backstop if all admins are lost. It will
           <strong>not</strong> sign you in.</p>
        <form id="gb">
          <label>Bootstrap secret
            <input name="secret" required autocomplete="off"
                   aria-describedby="gb-help" /></label>
          <p id="gb-help">Printed in the server console on first run.</p>
          <label><input type="checkbox" name="save" /> Also save an encrypted creds file</label>
          <label id="path-wrap" hidden>File path
            <input name="path" autocomplete="off" /></label>
          <button type="submit">Generate emergency account</button>
          <p id="gb-err" role="alert"></p>
        </form>
      </main>`;
    const form = this.querySelector("#gb") as HTMLFormElement;
    const saveBox = form.querySelector('input[name="save"]') as HTMLInputElement;
    const pathWrap = this.querySelector("#path-wrap") as HTMLElement;
    saveBox.addEventListener("change", () => { pathWrap.hidden = !saveBox.checked; });
    (this.querySelector("#bs-h") as HTMLElement).focus();
    form.addEventListener("submit", (e) => this.onGlassbreak(e, form));
  }

  private async onGlassbreak(e: Event, form: HTMLFormElement) {
    e.preventDefault();
    const err = this.querySelector("#gb-err")!;
    err.textContent = "";
    const d = new FormData(form);
    try {
      const res = await call<GlassbreakResponse>("register_glassbreak", {
        req: {
          bootstrap_secret: d.get("secret"),
          save_path: d.get("save") ? d.get("path") || null : null,
        },
      });
      this.renderCredsThenAdmin(res);
    } catch (x: any) {
      err.textContent = x?.message ?? "Could not create the emergency account.";
    }
  }

  private renderCredsThenAdmin(creds: GlassbreakResponse) {
    this.innerHTML = `
      <main id="main" aria-labelledby="cr-h">
        <h1 id="cr-h" tabindex="-1">Save these emergency credentials now</h1>
        <p role="alert">Shown once. Store them offline and encrypted.</p>
        <dl>
          <dt>Username</dt><dd><code>${escape(creds.username)}</code></dd>
          <dt>Password</dt><dd><code>${escape(creds.password)}</code></dd>
        </dl>
        <button id="next">I have saved them — continue to create the first admin</button>
      </main>`;
    (this.querySelector("#cr-h") as HTMLElement).focus();
    (this.querySelector("#next") as HTMLButtonElement)
      .addEventListener("click", () => this.renderAdmin());
  }

  private renderAdmin() {
    this.innerHTML = `
      <main id="main" aria-labelledby="ad-h">
        <h1 id="ad-h" tabindex="-1">First-run setup — Step 2 of 2: First admin</h1>
        <form id="ad">
          <label>Username <input name="username" required autocomplete="username" /></label>
          <label>Password <input name="password" type="password" required
                 autocomplete="new-password" /></label>
          <label>Bootstrap secret <input name="secret" required autocomplete="off" /></label>
          <button type="submit">Create first admin</button>
          <p id="ad-err" role="alert"></p>
        </form>
      </main>`;
    const form = this.querySelector("#ad") as HTMLFormElement;
    (this.querySelector("#ad-h") as HTMLElement).focus();
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const err = this.querySelector("#ad-err")!;
      err.textContent = "";
      const d = new FormData(form);
      try {
        await call<string>("create_first_admin", {
          req: { username: d.get("username"), password: d.get("password"), bootstrap_secret: d.get("secret") },
        });
        location.hash = "#/connect"; // admin then signs in normally (after the ceremony)
      } catch (x: any) {
        err.textContent = x?.message ?? "Could not create the first admin.";
      }
    });
  }
}

function escape(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
}

customElements.define("bootstrap-screen", BootstrapScreen);
```

- [ ] **Step 3: Route it**

In `app-shell.ts`, import `"./bootstrap-screen.ts";` and add a `bootstrap` route case to the router switch (render `<bootstrap-screen></bootstrap-screen>`). Add a `"bootstrap"` value to the `Route` union in `core/router.ts`.

- [ ] **Step 4: Build the UI (typecheck)**

Run: `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cd crates/client-app/ui; npm run build`
Expected: esbuild bundles with no TS error. (If `npm install` was never run in this clone, run it first; `node_modules` is gitignored.)

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/ui/src/components/bootstrap-screen.ts crates/client-app/ui/src/core/types.ts crates/client-app/ui/src/core/router.ts crates/client-app/ui/src/components/app-shell.ts
git commit -m "feat(ui): accessible first-run bootstrap screen (glass-break + first-admin)"
```

---

## Task 15: UI — `<pending-screen>` (status-only, adaptive poll)

**Files:**
- Create: `crates/client-app/ui/src/components/pending-screen.ts`
- Modify: `crates/client-app/ui/src/components/app-shell.ts`, `crates/client-app/ui/src/core/router.ts`

Status-only (D-G): no feed, no upload. Smart adaptive polling (D-I): poll faster while focused, slower when hidden; flips to the app when `active`.

- [ ] **Step 1: Write `pending-screen.ts`**

```ts
import { call } from "../core/rpc.ts";
import type { AccountStateMsg } from "../core/types.ts";

// Status-only pending screen (D-G) with adaptive polling (D-I). The username is
// passed via the `username` attribute set by the shell after login.
export class PendingScreen extends HTMLElement {
  private timer: number | null = null;
  private fast = 5000;
  private slow = 30000;

  connectedCallback() {
    this.innerHTML = `
      <main id="main" aria-labelledby="pd-h">
        <h1 id="pd-h" tabindex="-1">Awaiting approval</h1>
        <p>Your account has been created and is waiting for an administrator to
           approve it at the next signing ceremony.</p>
        <dl>
          <dt>Account</dt><dd><code id="pd-user"></code></dd>
        </dl>
        <p id="pd-status" role="status" aria-live="polite">Checking status…</p>
      </main>`;
    const user = this.getAttribute("username") ?? "";
    (this.querySelector("#pd-user") as HTMLElement).textContent = user;
    (this.querySelector("#pd-h") as HTMLElement).focus();
    document.addEventListener("visibilitychange", this.reschedule);
    this.poll();
  }

  disconnectedCallback() {
    if (this.timer !== null) clearTimeout(this.timer);
    document.removeEventListener("visibilitychange", this.reschedule);
  }

  private reschedule = () => { /* next poll() picks the new interval */ };

  private async poll() {
    const status = this.querySelector("#pd-status")!;
    const user = this.getAttribute("username") ?? "";
    try {
      const res = await call<AccountStateMsg>("account_status", { req: { username: user } });
      if (res.state === "active") {
        status.textContent = "Approved — opening the app…";
        location.hash = "#/feed";
        return;
      }
      status.textContent = "Still pending. We'll keep checking.";
    } catch {
      status.textContent = "Couldn't reach the server; retrying…";
    }
    const interval = document.hidden ? this.slow : this.fast;
    this.timer = window.setTimeout(() => this.poll(), interval);
  }
}

customElements.define("pending-screen", PendingScreen);
```

- [ ] **Step 2: Route it**

In `app-shell.ts` import `"./pending-screen.ts";`, add a `pending` route that renders `<pending-screen>` with the signed-in `username` attribute, and subscribe to `EVT_ACCOUNT` (`maxsecu://account-state`) to route to `pending`/`feed` accordingly. Add `"pending"` to the `Route` union.

- [ ] **Step 3: Typecheck**

Run: `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cd crates/client-app/ui; npm run build`
Expected: no TS error.

- [ ] **Step 4: Commit**

```bash
git add crates/client-app/ui/src/components/pending-screen.ts crates/client-app/ui/src/components/app-shell.ts crates/client-app/ui/src/core/router.ts
git commit -m "feat(ui): status-only pending screen with adaptive polling"
```

---

## Task 16: UI — `<admin-screen>` (approval queue + voucher issuance)

**Files:**
- Create: `crates/client-app/ui/src/components/admin-screen.ts`
- Modify: `crates/client-app/ui/src/components/app-shell.ts`, `crates/client-app/ui/src/core/router.ts`

- [ ] **Step 1: Write `admin-screen.ts`**

```ts
import { call } from "../core/rpc.ts";
import type { PendingUserDto, IssueVoucherResponse } from "../core/types.ts";

// Admin operations (spec §5 Admin row): approval queue + voucher issuance.
// "Approve" is a ceremony-request (D-K), not an in-app grant.
export class AdminScreen extends HTMLElement {
  connectedCallback() {
    this.innerHTML = `
      <main id="main" aria-labelledby="ad-h">
        <h1 id="ad-h" tabindex="-1">Admin</h1>
        <section aria-labelledby="iv-h">
          <h2 id="iv-h">Invite a new user</h2>
          <button id="iv-btn">Issue invite code</button>
          <p id="iv-out" role="status" aria-live="polite"></p>
        </section>
        <section aria-labelledby="pq-h">
          <h2 id="pq-h">Approval queue</h2>
          <p id="pq-status" role="status" aria-live="polite">Loading…</p>
          <ul id="pq-list"></ul>
        </section>
      </main>`;
    (this.querySelector("#ad-h") as HTMLElement).focus();
    (this.querySelector("#iv-btn") as HTMLButtonElement)
      .addEventListener("click", () => this.issue());
    this.loadQueue();
  }

  private async issue() {
    const out = this.querySelector("#iv-out")!;
    out.textContent = "Issuing…";
    try {
      const res = await call<IssueVoucherResponse>("issue_voucher", {});
      out.textContent = `Invite code (hand to the new user in person): ${res.code}`;
    } catch (x: any) {
      out.textContent = x?.message ?? "Could not issue an invite.";
    }
  }

  private async loadQueue() {
    const status = this.querySelector("#pq-status")!;
    const list = this.querySelector("#pq-list") as HTMLUListElement;
    try {
      const pending = await call<PendingUserDto[]>("list_pending", {});
      list.innerHTML = "";
      if (pending.length === 0) {
        status.textContent = "No accounts awaiting approval.";
        return;
      }
      status.textContent = `${pending.length} awaiting approval.`;
      for (const u of pending) {
        const li = document.createElement("li");
        li.textContent = `${u.username} `;
        const btn = document.createElement("button");
        btn.textContent = "Prepare approval (ceremony)";
        btn.addEventListener("click", () => this.requestApproval(u.user_id, li));
        li.appendChild(btn);
        list.appendChild(li);
      }
    } catch (x: any) {
      status.textContent = x?.message ?? "Could not load the queue.";
    }
  }

  private async requestApproval(userId: string, li: HTMLElement) {
    try {
      const item = await call<{ note: string }>("request_approval", { req: { user_id: userId } });
      const note = document.createElement("span");
      note.setAttribute("role", "status");
      note.textContent = ` — ${item.note}`;
      li.appendChild(note);
    } catch (x: any) {
      const note = document.createElement("span");
      note.setAttribute("role", "alert");
      note.textContent = ` — ${x?.message ?? "Could not prepare the ceremony request."}`;
      li.appendChild(note);
    }
  }
}

customElements.define("admin-screen", AdminScreen);
```

- [ ] **Step 2: Route it**

In `app-shell.ts` import `"./admin-screen.ts";` and make the existing "Admin" nav item a real link (`href="#/admin"`) that renders `<admin-screen>`. Add `"admin"` to the `Route` union.

- [ ] **Step 3: Typecheck**

Run: `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cd crates/client-app/ui; npm run build`
Expected: no TS error.

- [ ] **Step 4: Commit**

```bash
git add crates/client-app/ui/src/components/admin-screen.ts crates/client-app/ui/src/components/app-shell.ts crates/client-app/ui/src/core/router.ts
git commit -m "feat(ui): admin screen (approval queue + voucher issuance)"
```

---

## Task 17: End-to-end — full bootstrap → approve → recipient over real TLS

**Files:**
- Create: `crates/client-app/tests/bootstrap_admin_e2e.rs`
- Modify: `crates/client-app/Cargo.toml` (dev-deps)

The Phase-2 exit gate. Drives the **real** stack over loopback TLS, mirroring `connect_login_e2e.rs` (client-app `transport`/`session`) and `directory_e2e.rs` (ceremony → publish → `DirectoryVerifier`).

- [ ] **Step 1: Add dev-deps**

In `crates/client-app/Cargo.toml` `[dev-dependencies]` add:

```toml
maxsecu-ceremony-harness = { path = "../../tools/ceremony-harness" }
maxsecu-admin-core = { path = "../admin-core" }
maxsecu-client-core = { path = "../client-core" }
maxsecu-encoding = { path = "../encoding" }
serde_json = "1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

(`maxsecu-server`, `rcgen`, `base64`, `hyper`, `hyper-util`, `http-body-util` are already deps/dev-deps.)

- [ ] **Step 2: Write the failing e2e**

```rust
//! Phase-2 exit gate: full bootstrap → first-admin → voucher-enroll → pending →
//! ceremony-sign (approve) → valid recipient, over REAL loopback TLS 1.3. Drives
//! the real client-app transport/session + the secret-free server + the scripted
//! offline ceremony, mirroring connect_login_e2e.rs + directory_e2e.rs.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::ServerConfig;

use maxsecu_ceremony_harness::Ceremony;
use maxsecu_client_app::session::login_exchange;
use maxsecu_client_app::transport::{pinned_client_config, Transport};
use maxsecu_client_core::{DirectoryVerifier, MemoryTrustStore, TombstoneSet};
use maxsecu_crypto::sha256;
use maxsecu_encoding::structs::DirBinding;
use maxsecu_encoding::types::Role;
use maxsecu_encoding::{decode, GENESIS_HEAD};
use maxsecu_server::{serve, AppState, AuthConfig, AuthService, MemoryStore};

const BOOTSTRAP_SECRET: &str = "operator-console-secret";
const TS: u64 = 1_719_500_000_000;

struct TestPki { server_config: Arc<ServerConfig>, cert_der: CertificateDer<'static> }

fn test_pki() -> TestPki {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
    let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
    let server_config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions().unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der).unwrap();
    TestPki { server_config: Arc::new(server_config), cert_der }
}

async fn open(t: &Transport) -> (SendRequest<Full<Bytes>>, [u8; 32]) {
    let (tls, exporter) = t.connect().await.unwrap();
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.unwrap();
    tokio::spawn(async move { let _ = conn.await; });
    (sender, exporter)
}

async fn post(s: &mut SendRequest<Full<Bytes>>, uri: &str, body: serde_json::Value, bearer: Option<&str>)
    -> (StatusCode, serde_json::Value) {
    s.ready().await.unwrap();
    let mut b = Request::builder().method("POST").uri(uri)
        .header("host", "localhost").header("content-type", "application/json");
    if let Some(t) = bearer { b = b.header("authorization", format!("MaxSecu-Session {t}")); }
    let resp = s.send_request(b.body(Full::new(Bytes::from(body.to_string()))).unwrap()).await.unwrap();
    let st = resp.status();
    let by = resp.into_body().collect().await.unwrap().to_bytes();
    (st, if by.is_empty() { serde_json::Value::Null } else { serde_json::from_slice(&by).unwrap_or(serde_json::Value::Null) })
}

async fn get(s: &mut SendRequest<Full<Bytes>>, uri: &str, bearer: Option<&str>)
    -> (StatusCode, serde_json::Value) {
    s.ready().await.unwrap();
    let mut b = Request::builder().method("GET").uri(uri).header("host", "localhost");
    if let Some(t) = bearer { b = b.header("authorization", format!("MaxSecu-Session {t}")); }
    let resp = s.send_request(b.body(Full::new(Bytes::new())).unwrap()).await.unwrap();
    let st = resp.status();
    let by = resp.into_body().collect().await.unwrap().to_bytes();
    (st, if by.is_empty() { serde_json::Value::Null } else { serde_json::from_slice(&by).unwrap_or(serde_json::Value::Null) })
}

#[tokio::test]
async fn full_bootstrap_to_valid_recipient() {
    // ---- Offline ceremony decides the pinned D5; the server pins its public key.
    let ceremony = Ceremony::generate();
    let pinned = ceremony.directory_pub();

    let store = MemoryStore::new();
    let cfg = AuthConfig::default()
        .with_directory_pub(pinned)
        .with_bootstrap_secret_hash(sha256(BOOTSTRAP_SECRET.as_bytes()));
    let pki = test_pki();
    let state = AppState {
        auth: Arc::new(AuthService::new(store, cfg)),
        blobs: Arc::new(maxsecu_server::MemoryBlobStore::new()),
        audit: Arc::new(maxsecu_server::NullAuditSink),
        direct_links_enabled: false,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, pki.server_config.clone(), maxsecu_server::router(state)));

    let transport = Transport::new(
        pinned_client_config(pki.cert_der.clone()).unwrap(),
        ServerName::try_from("localhost").unwrap(),
        addr.to_string(),
    );

    // ---- Bootstrap: glass-break + first-admin register (no binding yet) --------
    // Use real identities so login + ceremony fingerprints line up.
    let admin_id = maxsecu_client_core::Identity::generate();
    let (mut c, _e) = open(&transport).await;

    let (st, gb) = post(&mut c, "/v1/bootstrap", serde_json::json!({
        "username": "gb-emergency",
        "enc_pub_b64": B64.encode([0xE9; 32]),
        "sig_pub_b64": B64.encode([0x59; 32]),
        "bootstrap_secret": BOOTSTRAP_SECRET,
    }), None).await;
    assert_eq!(st, StatusCode::CREATED);
    let gb_uid = hex16(gb["user_id"].as_str().unwrap());

    let (st, ad) = post(&mut c, "/v1/bootstrap", serde_json::json!({
        "username": "root",
        "enc_pub_b64": B64.encode(admin_id.enc_pub_bytes()),
        "sig_pub_b64": B64.encode(admin_id.sig_pub_bytes()),
        "bootstrap_secret": BOOTSTRAP_SECRET,
    }), None).await;
    assert_eq!(st, StatusCode::CREATED);
    let admin_uid = hex16(ad["user_id"].as_str().unwrap());

    // ---- Ceremony signs BOTH bootstrap bindings with admin role, then publishes.
    for (name, uid, enc, sig) in [
        ("gb-emergency", gb_uid, [0xE9; 32], [0x59; 32]),
        ("root", admin_uid, admin_id.enc_pub_bytes(), admin_id.sig_pub_bytes()),
    ] {
        let pb = ceremony.sign_binding(name, uid, enc, sig, &[Role::User, Role::Admin], 1);
        let (st, _) = post(&mut c, "/v1/directory", serde_json::json!({
            "binding_b64": B64.encode(&pb.binding_bytes),
            "directory_signature_b64": B64.encode(pb.signature),
        }), None).await;
        assert_eq!(st, StatusCode::CREATED, "publish {name}'s admin binding");
    }

    // Window is now closed.
    let (st, _) = post(&mut c, "/v1/bootstrap", serde_json::json!({
        "username": "late", "enc_pub_b64": B64.encode([1u8; 32]),
        "sig_pub_b64": B64.encode([2u8; 32]), "bootstrap_secret": BOOTSTRAP_SECRET,
    }), None).await;
    assert_eq!(st, StatusCode::CONFLICT, "bootstrap closes after the first publish");

    // ---- First admin logs in (channel-bound) over a fresh connection ----------
    let (mut admin_conn, exporter) = open(&transport).await;
    let login = login_exchange(&mut admin_conn, &admin_id, "root", "localhost", &exporter, TS)
        .await.expect("admin login");
    let admin_token = login.token;

    // ---- Admin issues a voucher; a new user enrolls (pending) -----------------
    let voucher_code = "in-person-invite-001";
    let (st, _) = post(&mut admin_conn, "/v1/vouchers", serde_json::json!({
        "voucher_hash_b64": B64.encode(sha256(voucher_code.as_bytes())),
    }), Some(&admin_token)).await;
    assert_eq!(st, StatusCode::CREATED, "admin issues a voucher");

    let user_id = maxsecu_client_core::Identity::generate();
    let (mut user_conn, _e) = open(&transport).await;
    let (st, ru) = post(&mut user_conn, "/v1/users", serde_json::json!({
        "username": "newbie",
        "enc_pub_b64": B64.encode(user_id.enc_pub_bytes()),
        "sig_pub_b64": B64.encode(user_id.sig_pub_bytes()),
        "enrollment_voucher": voucher_code,
    }), None).await;
    assert_eq!(st, StatusCode::CREATED);
    let newbie_uid = hex16(ru["user_id"].as_str().unwrap());

    // ---- Pending: newbie has no binding yet -----------------------------------
    let (st, _) = get(&mut user_conn, "/v1/directory/newbie", None).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "unsigned ⇒ pending ⇒ not a recipient");

    // newbie appears in the admin approval queue.
    let (st, pend) = get(&mut admin_conn, "/v1/pending", Some(&admin_token)).await;
    assert_eq!(st, StatusCode::OK);
    assert!(pend["pending"].as_array().unwrap().iter().any(|u| u["username"] == "newbie"));

    // ---- Approve: the ceremony signs newbie's USER binding and publishes ------
    let pb = ceremony.sign_binding(
        "newbie", newbie_uid, user_id.enc_pub_bytes(), user_id.sig_pub_bytes(), &[Role::User], 1);
    let (st, _) = post(&mut admin_conn, "/v1/directory", serde_json::json!({
        "binding_b64": B64.encode(&pb.binding_bytes),
        "directory_signature_b64": B64.encode(pb.signature),
    }), Some(&admin_token)).await;
    assert_eq!(st, StatusCode::CREATED);

    // ---- newbie is now a valid recipient: served binding authorizes under the
    //      PINNED D5 (the whole point) -----------------------------------------
    let (st, body) = get(&mut user_conn, "/v1/directory/newbie", None).await;
    assert_eq!(st, StatusCode::OK, "approved ⇒ served ⇒ recipient");
    let binding: DirBinding =
        decode(&B64.decode(body["binding_b64"].as_str().unwrap()).unwrap()).unwrap();
    let sig: [u8; 64] =
        B64.decode(body["directory_signature_b64"].as_str().unwrap()).unwrap().try_into().unwrap();
    let verifier = DirectoryVerifier::new(pinned);
    let none = TombstoneSet::verify(&[], GENESIS_HEAD.0).unwrap();
    let authorized = verifier
        .authorize_recipient(&binding, &sig, TS, &mut MemoryTrustStore::new(), &none)
        .expect("newbie is a valid recipient after the ceremony");
    assert_eq!(authorized.enc_pub, user_id.enc_pub_bytes());
    assert_eq!(authorized.effective_roles, vec![Role::User]);
}

fn hex16(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}
```

- [ ] **Step 3: Run it to verify it fails, then passes**

Run: `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cargo test -p maxsecu-client-app --test bootstrap_admin_e2e`
Expected: compiles and PASSES end-to-end. Debug against the server handlers from Tasks 5–7 if any status mismatches (use `systematic-debugging`; do not weaken an assertion to make it pass).

- [ ] **Step 4: Commit**

```bash
git add crates/client-app/Cargo.toml crates/client-app/tests/bootstrap_admin_e2e.rs
git commit -m "test(client-app): e2e bootstrap -> first-admin -> approve -> valid recipient"
```

---

## Task 18: Phase-2 gates green + security-review note

**Files:**
- Modify: `docs/security-review-phase2-mediaapp.md` (NEW), any files needing fmt/clippy fixes.

- [ ] **Step 1: Format only the touched crates**

Run: `cargo fmt -p maxsecu-server -p maxsecu-client-app -p maxsecu-ceremony-harness`
Then: `cargo fmt -p maxsecu-server -p maxsecu-client-app -p maxsecu-ceremony-harness -- --check`
Expected: clean. (Do not run `cargo fmt --all` — pre-existing Phase 0–7 drift would dirty unrelated files.)

- [ ] **Step 2: Clippy (warnings are errors) on the touched crates**

Run: `cargo clippy -p maxsecu-server -p maxsecu-client-app -p maxsecu-ceremony-harness --all-targets -- -D warnings`
Expected: no warnings. Fix in place; no blanket `#[allow]`.

- [ ] **Step 3: UI typecheck**

Run: `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cd crates/client-app/ui; npm run build`
Expected: clean bundle.

- [ ] **Step 4: Supply-chain gates**

Run: `cargo deny check` then `cargo audit`
Expected: pass (no new external deps were introduced — `ceremony-harness` is in-tree over admin-core/crypto/encoding). If `deny.toml` flags the new in-tree crate's path dep, no change should be needed; only add a narrow, justified entry if genuinely required.

- [ ] **Step 5: Full workspace test (PG optional)**

Run: `$env:MAXSECU_PG_OPTIONAL=1; cargo test --workspace`
Expected: all pass (existing + new; the PG suite runs as the sanctioned skip).

- [ ] **Step 6: Write the security-review note**

Create `docs/security-review-phase2-mediaapp.md` summarizing: the additive endpoints, why each preserves the secret-free/zero-knowledge model (the server only verifies under the pinned D5 *public* key; the client re-verifies everything), the bootstrap-window + secret design and its first-run-race mitigation (§4.5), the D5-verified `AdminSession` model (D-K), and the one **documented deferral** (server coarse gate does not yet honor de-admin tombstones — client-side/sink-anchored is authoritative). Conclude PASS with no Critical/High/Medium if the gates are green.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "chore(phase2): gates green (fmt/clippy/deny/audit/test) + security-review note"
```

---

## Self-review checklist (done while writing)

- **Spec coverage (Phase 2 row of §10 + §4.2/§4.6/§5/§6/§7):** glass-break + first-admin bootstrap (Tasks 5, 11, 14) ✓; voucher enrollment (Tasks 4, 7, 11, 16) ✓; status-only pending (Tasks 3, 12, 15) ✓; admin approval queue (Tasks 3, 7, 13, 16) ✓; ceremony harness (Task 9) ✓; D5-only admin promotion / no server grant — D-K (Tasks 7, 13 `request_approval` work-item) ✓; e2e full bootstrap → approve (Task 17) ✓; WCAG-AA screens (Tasks 14–16: landmarks, labelled controls, `role="alert"`/`status`, focus management, non-color-only) ✓; smart adaptive polling — D-I (Task 15) ✓; sanitized errors (Task 8) ✓; UI strictly outside the TCB — only DTOs cross (all client-app tasks) ✓.
- **Additive-only / zero-knowledge:** crypto/protocol/TCB untouched; the server gains only coarse-authz + opaque-storage endpoints, verifying solely against the pinned D5 *public* key; client re-verifies (security-review note + Task 17 `authorize_recipient`) ✓.
- **Type consistency:** `AuthConfig::{with_directory_pub, with_bootstrap_secret_hash}` + `AuthService::{directory_pub, bootstrap_secret_hash}` (Task 1) used by Tasks 5–7, 17; `Store::{has_any_binding (T2), list_pending_users+PendingUser (T3), issue_voucher (T4)}` impl'd in MemoryStore + pg + FaultyStore and consumed by handlers; `AdminSession` (T7) gates `/v1/pending`, `/v1/vouchers`, `post_control`; client `http_client::{post_json,get_json}` (T10) used by all new commands; `AccountState`/`EVT_ACCOUNT` (T12) consumed by `<pending-screen>` (T15); `Ceremony::{generate, directory_pub, sign_binding, account_revoke}` (T9) used by the e2e (T17). Endpoint paths consistent: `POST /v1/bootstrap`, `POST /v1/directory`, `GET /v1/pending`, `POST /v1/vouchers`.
- **Known fill-ins flagged for the engineer (real-codebase confirmations, not placeholders):** the `http.rs` test-module helper names (T5–T7 — read & reuse `admin_app`/login helpers); whether `users.created_at` exists in `schema.sql` (T3); the `enrollment_vouchers` columns (T4); the client `open_conn` opener + managed `Session` token accessor (T11, T13 — reuse what `connect`/login already establish). Each names the exact file to read.

## Next phases (separate plan docs, written when reached)

Phase 3 (browse + view) · 4 (upload) · 5 (settings + a11y) · 6 (packaging) · 7 (video, gated). Each follows this same TDD/bite-sized structure and reuses the command-boundary, state-machine, and ceremony patterns established here.
