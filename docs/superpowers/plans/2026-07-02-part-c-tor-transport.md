# Part C — Real Tor Transport (arti-client) via Client-Workspace Split — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the client's `TorOnly` route actually route through Tor (in-process, via `arti-client`) instead of failing closed with `tor_unavailable`.

**Architecture:** `arti-client` needs `libsqlite3-sys 0.37`; the server's `sqlx` pins `libsqlite3-sys 0.30`; Cargo's `links = "sqlite3"` uniqueness rule forbids both in one lockfile. The client genuinely has **no SQL**, so we split `client-app` into its **own Cargo workspace** (own `Cargo.lock`), removing `sqlx` from its graph entirely. Because no single lockfile may contain both `arti-client` and `sqlx`, the client-side e2e tests (which boot a real `maxsecu-server`) must link the server **without** its Postgres/`sqlx` code — so `sqlx`/`PgStore` become an additive, default-on `postgres` feature on the server crate, and the relocated e2e crate depends on the server with `default-features = false` (MemoryStore only). Arti is wired at the single connection choke point (`open_conn`): dial via arti → box the stream → the existing pinned-TLS + RFC 5705 channel-binding + hyper handshake path is reused verbatim.

**Tech Stack:** Rust, `arti-client` 0.44, `tokio-rustls` (aws-lc-rs), `hyper` 1, Tauri 2. Two Cargo workspaces sharing the same repo via path deps.

**Proven pre-work (spike 2026-07-02):** the split resolves cleanly (`sqlx` → 0 occurrences in the client lock; `arti-client 0.44.0` + `rusqlite 0.39` + `libsqlite3-sys 0.37` resolve) and `cargo build -p arti-client` compiles on Windows MSVC (exit 0, 57s).

**Known deviations to keep visible (call out in the sign-off):**
1. **Bundled-C SQLite enters the client** via arti's `tor-dirmgr` → `rusqlite` (bundled). This is a deliberate deviation from the client's pure-Rust/zero-C VIEW-path ethos; accepted because arti is the documented preferred Tor design and the C is transport-only (outside the crypto/key TCB).
2. **`cargo deny` scope expands** (~400 new crates) in the new client workspace; licenses/advisories/duplicates handled in Task 7.
3. **"Zero server change" becomes "one additive feature gate"** — `sqlx`/`PgStore` behind default-on `postgres`. The real server + `portable-server` build **identically** (feature on by default); only the client-side e2e crate turns it off.

---

## File Structure

**Server workspace (root `Cargo.toml`, unchanged members minus client-app):**
- `crates/server/Cargo.toml` — `sqlx` + `time` moved under a new default-on `postgres` feature.
- `crates/server/src/lib.rs` — `pub mod pg;` and `pub use pg::PgStore;` gated `#[cfg(feature = "postgres")]`.
- `Cargo.toml` (root) — drop `crates/client-app` from `members`, add `exclude = ["crates/client-app"]`.
- `tools/ceremony-harness/Cargo.toml` — its `maxsecu-server` dep becomes `default-features = false` (no postgres), so it can be reused from the client workspace.

**Client workspace (rooted at `crates/client-app`, own lock):**
- `crates/client-app/Cargo.toml` — new `[workspace]`/`[workspace.package]`; add `arti-client`, `tor-rtcompat`; drop the `maxsecu-server`/`maxsecu-ceremony-harness` dev-deps (they move to the e2e crate).
- `crates/client-app/src/transport.rs` — add `ConnStream` boxing trait + `tls_over()` helper; `Transport::connect` reuses it.
- `crates/client-app/src/tor.rs` (new) — `TorState` shared bootstrapped `TorClient` holder + `dial(host, port) -> Box<dyn ConnStream>`.
- `crates/client-app/src/commands/connection.rs` — `open_conn` gains a Tor branch; `connect` stops failing closed; bootstrap UX events.
- `crates/client-app/src/state.rs` — register `TorState`; new `ConnectionState::TorBootstrapping` variant.
- `crates/client-app/src/main.rs` — manage `TorState`.
- `crates/client-e2e/` (new crate, **member of the client workspace**) — the 7 relocated e2e tests; deps `maxsecu-client-app` (path) + `maxsecu-server` (path, `default-features = false`) + `maxsecu-ceremony-harness` (path) + `image`.
- `crates/client-app/deny.toml` (new) — client-workspace cargo-deny policy covering the arti tree.

**Build/packaging:**
- `packaging/package.ps1` / `package.sh` — build the two workspaces separately.
- `dist/` restage — client bin now from the client workspace target.

---

## Task 0: Baseline

- [ ] **Step 1: Confirm clean baseline builds on `main` HEAD**

Run (PS prefix): `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cargo build --workspace --tests`
Expected: builds, 0 errors (pre-existing rustfmt drift is out of scope; NEVER `cargo fmt --all`).

- [ ] **Step 2: Record the exact e2e test inventory to relocate**

The 7 files under `crates/client-app/tests/`: `bootstrap_admin_e2e.rs`, `connect_login_e2e.rs`, `streaming_upload_e2e.rs`, `upload_e2e.rs`, `video_upload_e2e.rs`, `browse_view_e2e.rs`, `video_e2e.rs`. All boot a `MemoryStore` server (none need Postgres) — verified: `connect_login_e2e.rs` imports `maxsecu_server::{serve, AppState, AuthConfig, AuthService, MemoryStore}` only.

---

## Task 1: Feature-gate `sqlx`/`PgStore` behind default-on `postgres` (server crate)

**Files:**
- Modify: `crates/server/Cargo.toml`
- Modify: `crates/server/src/lib.rs:23,43`

- [ ] **Step 1: Add the feature + gate the deps in `crates/server/Cargo.toml`**

Add a `[features]` section and move `sqlx` (line 37) + `time` (line 38) to `optional = true`, pulled in by the feature:

```toml
[features]
default = ["postgres"]
# The production Postgres Store (`pg::PgStore`). Default-on so the real server and
# `portable-server` build unchanged. Turned OFF by the client-side e2e crate
# (`maxsecu-client-e2e`) so the server can be linked WITHOUT `sqlx` — that lets it
# coexist in the client workspace's lockfile with `arti-client` (whose
# `libsqlite3-sys 0.37` conflicts with sqlx's `0.30` under the `links` rule).
postgres = ["dep:sqlx", "dep:time"]
```

Change the two dep lines to optional:

```toml
sqlx = { version = "0.8", default-features = false, features = ["runtime-tokio", "postgres", "time"], optional = true }
time = { version = "0.3", optional = true }
```

- [ ] **Step 2: Gate the `pg` module + `PgStore` re-export in `crates/server/src/lib.rs`**

```rust
#[cfg(feature = "postgres")]
pub mod pg;
```
```rust
#[cfg(feature = "postgres")]
pub use pg::PgStore;
```

- [ ] **Step 3: Find and gate any other `sqlx`/`time` uses**

Run: `rg -n "sqlx|use time|time::" crates/server/src` — gate any remaining references with `#[cfg(feature = "postgres")]` (expected: only `pg.rs`, which is entirely gated by the module attribute above). If `time` is used outside `pg.rs`, either keep `time` non-optional or gate those uses.

- [ ] **Step 4: Verify BOTH feature states compile**

Run: `cargo build -p maxsecu-server` (postgres on — unchanged) → PASS.
Run: `cargo build -p maxsecu-server --no-default-features` (no sqlx) → PASS.
Run: `cargo build -p maxsecu-portable-server` (depends on server default features) → PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/server/Cargo.toml crates/server/src/lib.rs
git commit -m "feat(server): gate sqlx/PgStore behind default-on postgres feature"
```

---

## Task 2: Make `ceremony-harness` server-dep postgres-free (so the client workspace can reuse it)

**Files:**
- Modify: `tools/ceremony-harness/Cargo.toml`

- [ ] **Step 1: Set its `maxsecu-server` dep to `default-features = false`**

```toml
maxsecu-server = { path = "../../crates/server", default-features = false }
```

- [ ] **Step 2: Verify ceremony-harness still compiles (it uses MemoryStore-based ceremony flows, no PgStore)**

Run: `cargo build -p maxsecu-ceremony-harness` → PASS. If it references `PgStore`, it doesn't — fix by using MemoryStore if any breakage.

- [ ] **Step 3: Commit**

```bash
git add tools/ceremony-harness/Cargo.toml
git commit -m "chore(ceremony-harness): link server without postgres (portable to client workspace)"
```

---

## Task 3: Split `client-app` into its own workspace

**Files:**
- Modify: `Cargo.toml` (root)
- Modify: `crates/client-app/Cargo.toml`

- [ ] **Step 1: Exclude client-app from the root workspace**

In root `Cargo.toml`, remove `"crates/client-app",` from `members` and add after the members array:
```toml
exclude = ["crates/client-app"]
```

- [ ] **Step 2: Promote client-app to its own workspace**

At the TOP of `crates/client-app/Cargo.toml`, before `[package]`:
```toml
[workspace]
resolver = "2"

[workspace.package]
edition = "2021"
rust-version = "1.96"
```
(The package keeps `edition.workspace = true` / `rust-version.workspace = true`, now referring to its own workspace.)

- [ ] **Step 3: Move the server/ceremony dev-deps OUT (they go to the e2e crate in Task 4)**

Delete these two lines from `[dev-dependencies]` in `crates/client-app/Cargo.toml`:
```toml
maxsecu-server = { path = "../server" }
maxsecu-ceremony-harness = { path = "../../tools/ceremony-harness" }
```
Keep `image`, `rcgen`, `hyper` (server feature) dev-deps for `direct_link.rs`'s in-process stub tests (those need only `hyper` server, not `maxsecu-server`).

- [ ] **Step 4: Verify the client workspace resolves + builds standalone (no arti yet)**

Run from `crates/client-app`: `cargo build` → PASS. `cargo test --lib` → PASS (unit tests; e2e temporarily absent — they move in Task 4). The root workspace: `cargo build --workspace` (now without client-app) → PASS.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/client-app/Cargo.toml
git commit -m "refactor: split client-app into its own cargo workspace"
```

---

## Task 4: Relocate the 7 e2e tests into a new client-workspace crate `maxsecu-client-e2e`

**Files:**
- Create: `crates/client-e2e/Cargo.toml`
- Create: `crates/client-e2e/src/lib.rs` (empty marker: `//! e2e-only crate.`)
- Move: `crates/client-app/tests/*.rs` → `crates/client-e2e/tests/*.rs`

- [ ] **Step 1: Create the e2e crate as a member of the CLIENT workspace**

`crates/client-e2e/Cargo.toml`:
```toml
[package]
name = "maxsecu-client-e2e"
version = "0.0.0"
edition.workspace = true
rust-version.workspace = true
publish = false
description = "Client↔server end-to-end tests (server linked WITHOUT postgres/sqlx so it coexists with arti in the client workspace lock)."

[dependencies]

[dev-dependencies]
maxsecu-client-app = { path = "../client-app" }
maxsecu-client-core = { path = "../client-core", features = ["net"] }
maxsecu-crypto = { path = "../crypto" }
maxsecu-encoding = { path = "../encoding" }
maxsecu-admin-core = { path = "../admin-core" }
# CRITICAL: default-features = false → no `postgres` → no `sqlx` → no
# libsqlite3-sys 0.30 → coexists with arti's 0.37 in the client workspace lock.
maxsecu-server = { path = "../server", default-features = false }
maxsecu-ceremony-harness = { path = "../../tools/ceremony-harness" }
# same test deps the tests used inside client-app:
base64 = "0.22"
serde_json = "1"
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "io-util", "sync", "time"] }
tokio-rustls = { version = "0.26", default-features = false, features = ["aws_lc_rs"] }
hyper = { version = "1", features = ["client", "http1", "server"] }
hyper-util = { version = "0.1", features = ["tokio"] }
http-body-util = "0.1"
rcgen = { version = "0.13", default-features = false, features = ["crypto", "aws_lc_rs", "pem"] }
image = { version = "0.25", default-features = false, features = ["png", "jpeg"] }
```

Add `"crates/client-e2e"` to the client workspace `members` (add a `members = ["crates/client-e2e"]`? No — the client workspace root IS `crates/client-app`. A sibling crate can't be a member of a workspace rooted at a sibling dir.) **Resolution:** the client workspace root must move UP so it can hold both `client-app` and `client-e2e`. See Step 1a.

- [ ] **Step 1a: Root the client workspace at a shared parent, not at `client-app`**

A workspace rooted at `crates/client-app` cannot contain `crates/client-e2e` (a sibling). Instead, create `crates/_client-ws/Cargo.toml` as a **virtual manifest** workspace root? That's awkward with the existing tree. **Chosen approach:** keep the client workspace rooted at `crates/client-app` and make `client-e2e` a **path-dep-only** arrangement is impossible for integration tests. Therefore root the client workspace via a dedicated virtual manifest:

Create `client.Cargo.toml`? Cargo requires the file be named `Cargo.toml`. **Final chosen approach:** place a virtual workspace manifest at repo path `client-workspace/Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = ["../crates/client-app", "../crates/client-e2e"]

[workspace.package]
edition = "2021"
rust-version = "1.96"
```
and REMOVE the `[workspace]` table added to `crates/client-app/Cargo.toml` in Task 3 Step 2 (client-app becomes a normal member again, of the client-workspace virtual root). The root `Cargo.toml` keeps `exclude = ["crates/client-app", "crates/client-e2e"]`.

> NOTE for executor: verify Cargo accepts members outside the workspace-root dir via `..` paths (it does; members may be any path). If tooling dislikes the `..`, alternatively move both crates under `client/` (`client/app`, `client/e2e`) with the workspace root at `client/` — a larger move; prefer the `..`-members virtual root first and fall back to the move only if Cargo rejects it.

- [ ] **Step 2: `git mv` the 7 test files**

```bash
mkdir -p crates/client-e2e/tests
git mv crates/client-app/tests/bootstrap_admin_e2e.rs crates/client-e2e/tests/
git mv crates/client-app/tests/connect_login_e2e.rs crates/client-e2e/tests/
git mv crates/client-app/tests/streaming_upload_e2e.rs crates/client-e2e/tests/
git mv crates/client-app/tests/upload_e2e.rs crates/client-e2e/tests/
git mv crates/client-app/tests/video_upload_e2e.rs crates/client-e2e/tests/
git mv crates/client-app/tests/browse_view_e2e.rs crates/client-e2e/tests/
git mv crates/client-app/tests/video_e2e.rs crates/client-e2e/tests/
```

- [ ] **Step 3: Fix imports** — the tests already use `maxsecu_client_app::…` and `maxsecu_server::…` public paths, so no code changes expected. If any test referenced a `#[path]` helper local to `client-app/tests`, move that helper too.

- [ ] **Step 4: Verify the whole client workspace builds + e2e passes**

Run from `client-workspace/`: `cargo test --workspace` → all 7 e2e PASS over real TLS, client-app unit tests PASS. Confirm the client-workspace lock contains **no `sqlx`**: `rg -c 'name = "sqlx' Cargo.lock` → 0.

- [ ] **Step 5: Commit**

```bash
git add client-workspace/Cargo.toml crates/client-e2e crates/client-app/Cargo.toml Cargo.toml
git commit -m "refactor: relocate client↔server e2e tests to maxsecu-client-e2e (postgres-free server link)"
```

---

## Task 5: Add arti + the boxing transport seam

**Files:**
- Modify: `crates/client-app/Cargo.toml` — add arti deps
- Modify: `crates/client-app/src/transport.rs`

- [ ] **Step 1: Add arti deps to client-app**

```toml
# In-process Tor client for the TorOnly download route (Part C). Brings a
# transport-only bundled-C SQLite via tor-dirmgr→rusqlite (outside the crypto
# TCB); isolated in this workspace's lock (no sqlx here). See deny.toml.
arti-client = { version = "0.44", default-features = false, features = ["tokio", "rustls", "onion-service-client"] }
tor-rtcompat = { version = "0.44", default-features = false, features = ["tokio", "rustls"] }
```
> Executor: start from `arti-client = "0.44"` (default features, proven to compile) and only trim features if deny/build stays green. Do NOT enable `native-tls` (keep the graph on rustls/aws-lc-rs to match the pinned transport; avoid OpenSSL C).

- [ ] **Step 2: Add the `ConnStream` boxing trait + `tls_over` helper to `transport.rs`**

```rust
use tokio::io::{AsyncRead, AsyncWrite};

/// Object-safe union of the stream traits a TLS session needs, so the direct
/// (`TcpStream`) and Tor (`arti_client::DataStream`) paths can be unified behind
/// one boxed type and share the SAME TLS + exporter code.
pub trait ConnStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ConnStream for T {}

/// Boxed transport-layer stream (TCP for direct, Tor circuit for TorOnly).
pub type BoxedStream = Box<dyn ConnStream>;

/// Run the pinned TLS 1.3 handshake over an already-dialed boxed stream and
/// derive the RFC 5705 exporter. Identical for direct and Tor — only the dialing
/// differs. Preserves channel binding regardless of the underlying transport.
pub async fn tls_over(
    tls: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    stream: BoxedStream,
) -> Result<
    (
        tokio_rustls::client::TlsStream<BoxedStream>,
        [u8; EXPORTER_LEN],
    ),
    UiError,
> {
    let connector = TlsConnector::from(tls);
    let tls = connector
        .connect(server_name, stream)
        .await
        .map_err(|_| UiError::new("tls", "Secure connection failed."))?;
    let mut exporter = [0u8; EXPORTER_LEN];
    tls.get_ref()
        .1
        .export_keying_material(&mut exporter, EXPORTER_LABEL, None)
        .map_err(|_| UiError::new("tls", "Channel binding failed."))?;
    Ok((tls, exporter))
}
```

Refactor `Transport::connect` to dial TCP then delegate:
```rust
pub async fn connect(
    &self,
) -> Result<(tokio_rustls::client::TlsStream<BoxedStream>, [u8; EXPORTER_LEN]), UiError> {
    let tcp = tokio::net::TcpStream::connect(&self.addr)
        .await
        .map_err(|_| UiError::new("offline", "Could not reach the server."))?;
    tls_over(self.tls.clone(), self.server_name.clone(), Box::new(tcp)).await
}
```

- [ ] **Step 3: Add a unit test that `tls_over` works over a boxed loopback stream**

```rust
#[tokio::test]
async fn tls_over_boxes_a_tcp_stream_and_exports_binding() {
    // Stand up a one-shot self-signed TLS server on loopback, connect via a BOXED
    // TcpStream through `tls_over`, assert a non-zero 32-byte exporter is derived.
    // (Mirrors the existing pinned_client_config self-signed test; full behavior
    // is covered by connect_login_e2e over the real server.)
}
```

- [ ] **Step 4: Verify build + test**

Run from `client-workspace/`: `cargo build` → PASS (arti now compiles into client-app's graph). `cargo test -p maxsecu-client-app --lib` → PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/Cargo.toml crates/client-app/src/transport.rs
git commit -m "feat(client): add arti dep + boxed-stream TLS seam (tls_over)"
```

---

## Task 6: `TorState` — a shared, lazily-bootstrapped `TorClient`

**Files:**
- Create: `crates/client-app/src/tor.rs`
- Modify: `crates/client-app/src/lib.rs` (add `pub mod tor;`)
- Modify: `crates/client-app/src/main.rs` (manage `TorState`)
- Modify: `crates/client-app/src/state.rs` (add `ConnectionState::TorBootstrapping`)

- [ ] **Step 1: `tor.rs` — holder + dial**

```rust
//! In-process Tor transport for the TorOnly route. One bootstrapped `TorClient`
//! is shared for the app lifetime (bootstrap is expensive; reuse the circuits).
//! Arti's state/cache dirs live under the client config dir. Dialing yields a
//! `DataStream` that `transport::tls_over` then wraps in pinned TLS — so channel
//! binding and the zero-knowledge server contract are unchanged; only the
//! underlying bytes travel over Tor.

use std::path::PathBuf;
use std::sync::Arc;

use arti_client::{TorClient, TorClientConfig};
use tor_rtcompat::PreferredRuntime;
use tokio::sync::OnceCell;

use crate::error::UiError;
use crate::transport::BoxedStream;

/// Lazily-bootstrapped shared Tor client. `OnceCell` so the (slow) first
/// bootstrap runs once; later connects reuse it.
pub struct TorState {
    cell: OnceCell<TorClient<PreferredRuntime>>,
    state_dir: PathBuf,
}

impl TorState {
    pub fn new(config_dir: PathBuf) -> Self {
        Self { cell: OnceCell::new(), state_dir: config_dir.join("tor") }
    }

    /// Get-or-bootstrap the shared client. `on_bootstrap` is invoked (once) right
    /// before the potentially-slow bootstrap so the UI can show progress.
    pub async fn client(
        &self,
        on_bootstrap: impl FnOnce(),
    ) -> Result<&TorClient<PreferredRuntime>, UiError> {
        self.cell
            .get_or_try_init(|| async {
                on_bootstrap();
                let mut builder = TorClientConfig::builder();
                builder
                    .storage()
                    .state_dir(self.state_dir.clone().try_into().map_err(|_| ())?)
                    .cache_dir(self.state_dir.join("cache").try_into().map_err(|_| ())?);
                let cfg = builder.build().map_err(|_| ())?;
                TorClient::create_bootstrapped(cfg).await.map_err(|_| ())
            })
            .await
            .map_err(|_| UiError::new("tor_unavailable", "Could not connect to the Tor network."))
    }

    /// Dial `host:port` over Tor, returning a boxed stream for `tls_over`.
    pub async fn dial(
        &self,
        host: &str,
        port: u16,
        on_bootstrap: impl FnOnce(),
    ) -> Result<BoxedStream, UiError> {
        let client = self.client(on_bootstrap).await?;
        let stream = client
            .connect((host, port))
            .await
            .map_err(|_| UiError::new("offline", "Could not reach the server over Tor."))?;
        Ok(Box::new(stream) as BoxedStream)
    }
}
```
> Executor: the exact `TorClientConfig` builder API (state/cache dir setters, error types) may differ slightly in 0.44 — adjust to the real API; the shape (build config with a state dir under `config_dir/tor`, `create_bootstrapped`, `connect((host,port))`) is the contract. `DataStream` implements tokio `AsyncRead+AsyncWrite+Unpin+Send`, satisfying `ConnStream`.

- [ ] **Step 2: Register `pub mod tor;` in `lib.rs`; add `ConnectionState::TorBootstrapping` in `state.rs`.**

- [ ] **Step 3: Manage `TorState` in `main.rs`** — `.manage(TorState::new(app_config_dir))` alongside the other managed state, keyed so `open_conn` can retrieve it.

- [ ] **Step 4: Verify build**

Run from `client-workspace/`: `cargo build` → PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/src/tor.rs crates/client-app/src/lib.rs crates/client-app/src/main.rs crates/client-app/src/state.rs
git commit -m "feat(client): shared lazily-bootstrapped TorState + Tor dialing"
```

---

## Task 7: Route `open_conn` through Tor when `TorOnly`; stop failing closed

**Files:**
- Modify: `crates/client-app/src/commands/connection.rs`

- [ ] **Step 1: Thread the effective `RouteMode` + `TorState` into `open_conn`**

`open_conn` currently always dials TCP (`Transport::connect`). Change it to take the effective `RouteMode` and (for the Tor path) a `&TorState` + a bootstrap-progress callback. When `TorOnly`: split `server` into `host:port`, `tor.dial(host, port, on_bootstrap)`, then `transport::tls_over(config, server_name, boxed)`; otherwise `Transport::connect` as today. Both feed the same hyper handshake:

```rust
let (tls, exporter) = match mode {
    RouteMode::TorOnly => {
        let port = server.rsplit_once(':').and_then(|(_, p)| p.parse().ok())
            .ok_or_else(|| UiError::new("tls", "Invalid server name."))?;
        let boxed = tor.dial(host, port, on_bootstrap).await?;
        transport::tls_over(config, server_name, boxed).await?
    }
    _ => Transport::new(config, server_name, server.to_owned()).connect().await?,
};
```

- [ ] **Step 2: Remove the fail-closed early-return in `connect`**

Delete the `if mode == RouteMode::TorOnly { return Err("tor_unavailable") }` block (connection.rs:63-68). Emit `ConnectionState::TorBootstrapping` from the `on_bootstrap` callback so the UI shows the (slow) first-bootstrap. Keep the invariant that `TorOnly` NEVER falls back to clearnet — on Tor failure, surface the error; do not retry direct.

- [ ] **Step 3: Also thread the mode into `reauth`** (it calls `open_conn`) so post-login authenticated commands keep using Tor when selected. Load the persisted `route_mode` in `reauth` (it has `dir`) and pass it through.

- [ ] **Step 4: Keep the "never direct-link under Tor" invariant** — `direct_link::direct_allowed` already returns true only for `PreferDropbox`, so `TorOnly` never brokers a cloud link. No change needed; add a test asserting it.

- [ ] **Step 5: Verify build + existing e2e still pass (direct path unchanged)**

Run from `client-workspace/`: `cargo test --workspace` → all e2e PASS (they use direct mode; the Tor branch is only taken under TorOnly). `cargo build` → PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/client-app/src/commands/connection.rs
git commit -m "feat(client): route connect/reauth through Tor for TorOnly (no clearnet fallback)"
```

---

## Task 8: cargo-deny for the client workspace

**Files:**
- Create: `crates/client-app/deny.toml` (or `client-workspace/deny.toml`)

- [ ] **Step 1: Copy the root `deny.toml` as the base; run against the client workspace**

Run from `client-workspace/`: `cargo deny check` → triage the arti tree: new licenses (MPL-2.0, ISC, etc. common in the tor crates), duplicate versions, and any RUSTSEC advisories. Add **narrow, justified** allowances (per-crate where possible), never a blanket `licenses.allow = ["*"]`. Document each addition with a comment (mirrors the CDLA-Permissive-2.0 justification style already in the repo).

- [ ] **Step 2: Record any unavoidable advisories** in the sign-off doc (Task 10) rather than silently ignoring.

- [ ] **Step 3: Commit**

```bash
git add client-workspace/deny.toml
git commit -m "chore(client): cargo-deny policy for the arti dependency tree"
```

---

## Task 9: Build/packaging for two workspaces

**Files:**
- Modify: `packaging/package.ps1`, `packaging/package.sh`
- Modify: any `dist/` build/run scripts that assume one workspace

- [ ] **Step 1: Build server workspace and client workspace separately**

Server bits: `cargo build --release -p maxsecu-portable-server` (root workspace). Client bit: `cargo build --release -p maxsecu-client-app` (from `client-workspace/`). Update the packaging scripts to invoke both and collect the two target dirs.

- [ ] **Step 2: Rebuild + restage `dist/`** with the new client binary; smoke-launch the GUI once.

- [ ] **Step 3: Commit**

```bash
git add packaging dist
git commit -m "build: package the split server + client workspaces"
```

---

## Task 10: Live Tor test, verification, security review, sign-off

**Files:**
- Create: `crates/client-e2e/tests/tor_route_e2e.rs` (`#[ignore]` live test)
- Create: `docs/security-review-part-c-tor-transport.md`

- [ ] **Step 1: `#[ignore]` live Tor test** (mirrors the Dropbox `#[ignore]` pattern — real network, opt-in). Gated on an env flag (e.g. `MAXSECU_TOR_LIVE=1`): bootstrap a `TorClient`, dial a known reachable host over Tor, assert a stream opens. Do NOT make CI depend on the Tor network.

- [ ] **Step 2: Full verification matrix**
  - Root workspace: `cargo build --workspace --tests` (0 warnings), `cargo test --workspace` green, `cargo deny check`.
  - Client workspace: `cargo build`, `cargo test --workspace` green (7 e2e + units), `cargo deny check`.
  - Assert client lock has **no `sqlx`**; server + portable-server build with postgres ON (unchanged).
  - UI unchanged (route setting already shipped in Part A) — `npm run typecheck && npm test && npm run build` in `crates/client-app/ui`.

- [ ] **Step 3: Two-stage security review** (spec + security) focused on: (a) `TorOnly` NEVER falls back to clearnet (no IP leak); (b) channel binding still derived over the Tor-tunneled TLS (exporter unchanged); (c) direct-link stays disabled under Tor; (d) the bundled-C SQLite is transport-only, outside the crypto/key TCB; (e) arti state dir under the client config dir, no secrets written. Write `docs/security-review-part-c-tor-transport.md` (PASS/CONCERNS).

- [ ] **Step 4: Update memory** (`download-route-setting.md`: Part C DONE; note the split + server postgres-feature + deviations). Update `MEMORY.md` hook.

- [ ] **Step 5: Final commit + finish the branch** (`superpowers:finishing-a-development-branch` — merge to local `main`, do NOT push).

---

## Self-Review Notes

- **Spec coverage:** split (T3), test coexistence via server feature-gate (T1/T2/T4), arti wiring at the single choke point (T5/T6/T7), deny (T8), packaging (T9), verify+review (T10). ✔
- **The one genuinely uncertain mechanic** is the client-workspace **root location** (T4 Step 1a): a workspace rooted at `crates/client-app` cannot include the sibling `crates/client-e2e`. The plan's primary approach is a virtual manifest at `client-workspace/Cargo.toml` with `..`-path members; fallback is relocating both crates under a `client/` parent. Executor must confirm which Cargo accepts before proceeding past T4.
- **Type consistency:** `ConnStream`/`BoxedStream`/`tls_over` (T5) are used verbatim by `TorState::dial` (T6) and `open_conn` (T7). `ConnectionState::TorBootstrapping` (T6) emitted in T7.
- **Deviations** (C-SQLite, deny scope, server feature-gate) are surfaced in the header and re-checked in the T10 sign-off.
