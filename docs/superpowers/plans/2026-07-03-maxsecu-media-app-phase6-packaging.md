# MaxSecu Media App — Phase 6: Packaging — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the system "just run" for testing while preserving prod parity: a new **`portable-server`** launcher binary that lays out a portable folder, generates a self-signed pinned TLS cert + a one-time bootstrap secret + a dev directory-signing (D5) key, self-applies the schema (prod/Postgres path), and serves the existing secret-free server over real TLS — verified by a smoke test where a real client **bootstraps** against the launched server over loopback TLS. Formalize the **client portable folder layout**, and add **packaging scripts** that build the release artifacts. Real PostgreSQL-binary bundling, Authenticode signing, and the Tauri GUI bundle are environment-blocked here and are wired as **documented deferred-ops hooks**, not stubs that pretend.

**Architecture:** The server is currently a **library only** (no binary). `portable-server` is the first runnable server: it composes `maxsecu_server::{serve, router, AppState, AuthConfig, AuthService, MemoryStore, FsBlobStore, NullAuditSink}` + `rcgen` (self-signed cert) + a dev D5 key (`maxsecu_admin_core::DirectorySigner`) into a process that boots from an empty data dir, prints the bootstrap secret once, and serves. The **dev profile** uses `MemoryStore` + `FsBlobStore` so it runs with zero external dependencies (the smoke test exercises this end-to-end). The **prod profile** is wired behind a config flag/DSN: `PgStore` + an injected real cert + an external sink + `schema.sql` self-apply — present and type-checked, exercised only when a `DATABASE_URL` is supplied (so CI without PG still passes via the dev profile, `MAXSECU_PG_OPTIONAL` discipline). The launcher writes the dev D5 public key + the self-signed cert to where a client pins them (`directory_pub.der`, `server_cert.der`), so the auto-connect test scenario (spec §9) can stand the whole stack up.

**Tech Stack:** Rust (a new `crates/portable-server` bin over `maxsecu-server` + `rcgen` + `maxsecu-admin-core` + `tokio`/`tokio-rustls`), the existing in-process TLS e2e harness for the smoke test, PowerShell/bash packaging scripts. No new external Rust deps beyond what the workspace already pins (`rcgen`, `tokio`, `tokio-rustls`, `maxsecu-crypto` are all in-tree).

---

## Backend facts this plan is grounded in (read before coding)

- **The server is a LIBRARY** (`crates/server/src/lib.rs`) with NO binary. Exports used here: `serve(listener: TcpListener, server_config: Arc<ServerConfig>, router) -> impl Future` (`serve.rs`); `router(state) -> Router`; `AppState<S> { auth: Arc<AuthService<S>>, blobs: Arc<dyn BlobStore>, audit: Arc<dyn AuditSink>, direct_links_enabled: bool }`; `AuthService::new(store, AuthConfig)`; `AuthConfig::default().with_directory_pub([u8;32]).with_bootstrap_secret_hash([u8;32])`; `MemoryStore::new()` (+ inherent `add_voucher(hash)`); `FsBlobStore::new(&dir)`; `NullAuditSink`; `PgStore` (prod); `export_channel_binding`. (Confirm exact `AppState` field names + `serve` signature in `crates/server/src/{lib.rs,serve.rs,http.rs}` and how the e2e tests build `AppState` — `crates/client-app/tests/bootstrap_admin_e2e.rs` + `crates/server/tests/file_e2e.rs` are the canonical examples; MIRROR their `AppState`/`serve` wiring exactly.)
- **D5 key (dev):** `maxsecu_admin_core::DirectorySigner::{generate, public_key() -> [u8;32]}` (and `tools/ceremony-harness::Ceremony` wraps it). The dev launcher generates a D5 on first run, persists it, and writes its public key for the client to pin. (PROD: the D5 private key is offline; the launcher only ever needs the public key pinned — for dev convenience it generates one and prints a clear "DEV ONLY — not a production ceremony key" warning.)
- **Self-signed cert:** `rcgen::generate_simple_self_signed(vec!["localhost".into()])` → `cert.cert.der()` + `cert.key_pair.serialize_der()`; build a `tokio_rustls::rustls::ServerConfig` with `aws_lc_rs` provider + `with_single_cert` (see `test_pki()` in the e2e tests — reuse that exact construction). The DER cert is also written to `<client>/config/server_cert.der` for pinning.
- **Bootstrap secret:** the server's `AuthConfig.with_bootstrap_secret_hash(sha256(secret))` (Phase 2). The launcher generates a random secret on first run, prints it once to the console, stores ONLY its `sha256` (and a "bootstrapped" marker so it isn't reprinted). `maxsecu_crypto::{random_array, sha256}`.
- **Schema:** `docs/schema.sql` (the Postgres schema). The prod path applies it via `PgStore`/`sqlx` against `DATABASE_URL`. (Confirm whether `PgStore` already has a migrate/apply entrypoint; if not, the launcher reads `schema.sql` and executes it once — behind the prod flag, not exercised without PG.)
- **Client portable layout:** `crates/client-app/src/main.rs` resolves `AppDir` beside the exe; `keystore`/`config`/`index` dirs are created on demand by their writers. Phase 6 formalizes the full layout (`config/ keystore/ index/ cache/ logs/`) and ensures the dirs exist.
- **Env constraints baked into this repo (honor):** Tauri CLI is NOT installed (only `tauri-build`); no PostgreSQL on the host; no Authenticode cert. These make a *real* GUI bundle, *real* PG bundling, and *real* signing un-buildable here — Phase 6 builds the launcher + layout + scripts + smoke test, and documents those three as deferred-ops with the wiring hook in place.

## Environment (tell every subagent)

- **cargo is NOT on the tool PATH.** Prefix: bash `export PATH="$HOME/.cargo/bin:$PATH"; ` / PowerShell `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; `. Rust 1.96 MSVC.
- **No PostgreSQL** — the dev launcher + smoke test use `MemoryStore` + `FsBlobStore`; the prod/PG path is type-checked but only runs with a `DATABASE_URL`. Workspace test gate: `MAXSECU_PG_OPTIONAL=1`.
- **Tauri CLI / GUI / real PG / Authenticode unavailable** — verify via `cargo build`/`cargo test`/the smoke test only; never launch a GUI; never require a live PG.
- **fmt:** the NEW `portable-server` crate is kept fmt-clean (`cargo fmt -p maxsecu-portable-server -- --check`); client-app stays clean; client-core/server pre-existing drift OUT OF SCOPE (never `cargo fmt --all`).
- **clippy:** `cargo clippy -p maxsecu-portable-server -- -D warnings`, no blanket `#[allow]`.
- **deny/audit:** `ring`/`openssl` banned. `rcgen`/`tokio-rustls`/`tokio` are already in-tree; if `portable-server` needs a dep already pinned in `[workspace.dependencies]`, use the workspace version. No NEW external dep expected; add a narrow justified entry only if required.

## Security model for Phase 6 (honor exactly)

- **The dev D5 key + dev bootstrap secret are SECURITY-DEGRADED, dev-only.** The launcher must loudly label the generated D5 as "DEV ONLY — replace with the offline ceremony key in production" and never present the dev profile as production. Prod injects the real (offline-signed) D5 public key + a real cert + external sink — the launcher reads those from config and does NOT generate them.
- **The bootstrap secret is printed ONCE** to the operator console and stored only as `sha256` (never in cleartext on disk) — matching the Phase-2 design. A "bootstrapped" marker prevents reprinting.
- **No secret is baked into the binary** (cert key, D5 key, bootstrap secret are all generated at runtime into the data dir, dev profile; injected at runtime, prod profile). `stack.md §5.1`/`DESIGN §16.6`.
- **The server it serves is unchanged** — the secret-free, zero-knowledge core; `portable-server` only composes + supervises it. No new endpoint, no new crypto.

---

## File structure

```
Cargo.toml          MODIFY — add "crates/portable-server" to [workspace] members.
crates/portable-server/
  Cargo.toml        NEW — bin crate over maxsecu-server + admin-core + crypto + rcgen + tokio + tokio-rustls.
  src/main.rs       NEW — the launcher entrypoint (parse profile/config, run).
  src/layout.rs     NEW — portable folder layout (create/locate the data dirs).
  src/pki.rs        NEW — self-signed cert gen/load (dev) + ServerConfig build; write client-pin cert.
  src/bootstrap.rs  NEW — dev D5 gen/load + pubkey export; bootstrap-secret gen/print/hash + marker.
  src/config.rs     NEW — LauncherConfig (port, data_dir, profile dev|prod, optional database_url, paths).
  src/run.rs        NEW — compose AppState (dev: Memory+Fs+Null; prod hook: Pg) + serve over TLS.
crates/portable-server/tests/
  boot_smoke.rs     NEW — launch the dev server in a temp dir + a client bootstraps over real TLS.
crates/client-app/src/
  layout.rs         NEW — ensure_portable_layout(dir): create config/keystore/index/cache/logs; layout doc.
  main.rs           MODIFY — call ensure_portable_layout on startup.
packaging/
  package.ps1       NEW — build release artifacts (cargo build --release -p maxsecu-portable-server +
                          client-app); Tauri-bundle + Authenticode steps present-but-gated (deferred-ops).
  package.sh        NEW — POSIX equivalent.
  README.md         NEW — portable layouts (client + server), how to run, the deferred-ops (PG bundle,
                          Authenticode cert, Tauri CLI), reproducibility notes.
docs/
  security-review-phase6-mediaapp.md  NEW — Phase-6 sign-off.
```

---

## Task 1: `portable-server` crate skeleton + workspace member

**Files:** Modify root `Cargo.toml`; Create `crates/portable-server/Cargo.toml`, `crates/portable-server/src/main.rs`.

- [ ] **Step 1:** add `"crates/portable-server",` to `[workspace] members` in root `Cargo.toml`.
- [ ] **Step 2:** `crates/portable-server/Cargo.toml`:

```toml
[package]
name = "maxsecu-portable-server"
version = "0.0.0"
edition.workspace = true
rust-version.workspace = true
publish = false
description = "Portable launcher for the MaxSecu server: lays out a portable folder, generates a dev self-signed pinned cert + bootstrap secret + dev D5 key, and serves the secret-free server over TLS. Prod parity behind a DATABASE_URL/profile flag."

[[bin]]
name = "maxsecu-portable-server"
path = "src/main.rs"

[dependencies]
maxsecu-server = { path = "../server" }
maxsecu-admin-core = { path = "../admin-core" }
maxsecu-crypto = { path = "../crypto" }
tokio = { workspace = true }            # confirm the workspace pin/features; need rt-multi-thread + macros + net
tokio-rustls = { workspace = true }
rcgen = { workspace = true }            # if not in [workspace.dependencies], use the version the e2e dev-deps use
serde = { workspace = true }
serde_json = { workspace = true }

[lints.rust]
unsafe_code = "forbid"
```
> Confirm each dep is in `[workspace.dependencies]` (read root Cargo.toml); if `rcgen`/`tokio-rustls` are only dev-deps elsewhere, add a pinned `[workspace.dependencies]` entry matching the version the tests already use (do NOT introduce a new version). Adjust features as the build requires.

- [ ] **Step 3:** minimal `src/main.rs` that compiles + a placeholder:

```rust
//! MaxSecu portable server launcher (DESIGN spec §8.2). Lays out a portable
//! folder, generates a DEV self-signed pinned cert + bootstrap secret + DEV D5
//! key, and serves the secret-free server over TLS. The DEV profile runs with no
//! external deps (MemoryStore + FsBlobStore); PROD parity (Postgres + injected
//! cert/sink) is behind a config flag. The DEV D5/secret are SECURITY-DEGRADED —
//! never a production ceremony.
#![forbid(unsafe_code)]

fn main() {
    eprintln!("maxsecu-portable-server: starting…");
    // Wired up across Tasks 2–7.
}
```

- [ ] **Step 4:** `cargo build -p maxsecu-portable-server` (builds) ; `cargo fmt -p maxsecu-portable-server -- --check` (clean) ; `cargo clippy -p maxsecu-portable-server -- -D warnings` (clean — `main` is a placeholder; that's fine). Commit `feat(portable-server): crate skeleton + workspace member`.

---

## Task 2: `LauncherConfig` + portable folder layout

**Files:** Create `crates/portable-server/src/config.rs`, `crates/portable-server/src/layout.rs`; wire `mod`s in `main.rs`.

- [ ] **Step 1 (config, TDD):** `LauncherConfig { data_dir: PathBuf, port: u16, profile: Profile (Dev|Prod), database_url: Option<String> }` with `from_env_and_args()` (read `MAXSECU_DATA_DIR`, `MAXSECU_PORT` [default e.g. 8443], `DATABASE_URL` → Prod if set else Dev). Unit test: defaults to Dev + the default port when env is empty; Prod when `DATABASE_URL` is set. (Use a pure `from_parts(env_map)` helper so it's testable without touching the real environment.)
- [ ] **Step 2 (layout, TDD):** `Layout` rooted at `data_dir` with the server sub-dirs: `tls/`, `blobs/`, `config/`, `logs/`. `Layout::ensure(data_dir) -> io::Result<Layout>` creates them; accessors `tls_dir()`/`blobs_dir()`/`config_dir()`/`logs_dir()`/`cert_der_path()`/`cert_key_path()`/`d5_pub_path()`/`bootstrap_marker_path()`. Test: `ensure` on a temp dir creates all sub-dirs and the accessors return paths under `data_dir`.
- [ ] **Step 3:** `cargo test -p maxsecu-portable-server` ; build ; fmt/clippy clean. Commit `feat(portable-server): launcher config + portable folder layout`.

---

## Task 3: PKI — self-signed pinned cert (dev)

**Files:** Create `crates/portable-server/src/pki.rs`.

- [ ] **Step 1 (TDD):** `ensure_dev_cert(layout) -> io::Result<()>` — if `cert_der_path`/`cert_key_path` are absent, generate a self-signed cert for `localhost` (rcgen), write the DER cert + DER key; idempotent (reuse on restart). `load_server_config(layout) -> Arc<ServerConfig>` builds the `tokio_rustls::rustls::ServerConfig` (aws_lc_rs provider, TLS 1.3 defaults, `with_single_cert`) from the stored cert/key — MIRROR the e2e `test_pki()` construction. `export_client_pin(layout, client_config_dir)` copies the DER cert to `<client_config_dir>/server_cert.der` (where `client-app` pins it). Test: `ensure_dev_cert` twice → the cert bytes are stable across calls (idempotent); the written cert parses as a `CertificateDer`; `load_server_config` returns a config without panicking.
- [ ] **Step 2:** build/test ; fmt/clippy clean. Commit `feat(portable-server): dev self-signed pinned cert + ServerConfig`.

---

## Task 4: Bootstrap secret + dev D5 key

**Files:** Create `crates/portable-server/src/bootstrap.rs`.

- [ ] **Step 1 (TDD):**
  - `ensure_bootstrap_secret(layout) -> io::Result<Option<String>>`: on first run (no `bootstrap_marker_path`), generate a random secret, write `sha256(secret)` to the marker (binary or hex), and return `Some(secret)` (so `main` prints it once); on a subsequent run return `None` (already bootstrapped). `bootstrap_secret_hash(layout) -> io::Result<Option<[u8;32]>>` reads the stored hash for `AuthConfig.with_bootstrap_secret_hash`.
  - `ensure_dev_d5(layout) -> io::Result<[u8;32]>`: on first run generate a `DirectorySigner`, persist its key material to `d5_*` paths (so admins can run the dev ceremony), and write its **public key** to `d5_pub_path`; return the pubkey. Idempotent (reuse on restart). `export_client_pin_d5(layout, client_config_dir)` copies the pubkey to `<client_config_dir>/directory_pub.der`.
  - Tests: first call returns `Some(secret)` and stores a 32-byte hash that equals `sha256(secret)`; second call returns `None` but the stored hash is unchanged; `ensure_dev_d5` returns a stable 32-byte pubkey across calls and writes `directory_pub.der` on export.
- [ ] **Step 2:** build/test ; fmt/clippy clean. Commit `feat(portable-server): one-time bootstrap secret + dev D5 key (security-degraded)`.

---

## Task 5: `run` — compose AppState + serve over TLS (dev)

**Files:** Create `crates/portable-server/src/run.rs`; wire `main.rs` to call it.

- [ ] **Step 1:** `pub async fn run(cfg: LauncherConfig) -> anyhow-free Result` (use `std::io::Result`/a small error enum, no anyhow unless already a workspace dep): ensure layout → ensure dev cert → ensure dev D5 → ensure bootstrap secret (print it ONCE with the DEV-ONLY warning + the pinned D5 fingerprint) → build `AppState` (DEV: `MemoryStore::new()` + `FsBlobStore::new(layout.blobs_dir())` + `NullAuditSink`, `AuthConfig::default().with_directory_pub(d5_pub).with_bootstrap_secret_hash(hash)`, `direct_links_enabled: false`) → bind `TcpListener` on `cfg.port` → `serve(listener, server_config, router(state))`. For PROD (`cfg.profile == Prod`, `database_url` set): the SAME composition but `PgStore` + an injected cert (from a configured path) + schema self-apply — implement the PROD branch as a clearly-marked `prod_app(...)` that is type-checked; it may `unimplemented!()`/return a "prod profile requires …" error for the parts that need PG (since PG isn't available here), OR fully wire `PgStore` if its constructor is callable without a live connection at compile time. State which.
- [ ] **Step 2:** `main.rs`: parse `LauncherConfig::from_env_and_args()`, `tokio::runtime` block_on `run(cfg)`; on the dev profile it serves until killed. Build (`cargo build -p maxsecu-portable-server`).
- [ ] **Step 3:** fmt/clippy clean. Commit `feat(portable-server): compose AppState + serve over TLS (dev profile)`.

> Note: `run` serves forever, so it's not unit-tested directly; the smoke test (Task 6) factors the *setup* (layout+cert+d5+secret+AppState+listener) into a testable `prepare(cfg) -> (listener, server_config, router, bootstrap_secret)` that both `run` and the test call, then the test drives a client against it. Structure `run` so `prepare` is reusable (return the pieces; `run` just `serve`s them).

---

## Task 6: Smoke test — dev server boots + a client bootstraps over real TLS

**Files:** Create `crates/portable-server/tests/boot_smoke.rs`; (`[dev-dependencies]` in the crate's Cargo.toml: hyper/hyper-util/http-body-util/base64/maxsecu-crypto/maxsecu-client-core or just raw hyper like the other e2es).

- [ ] **Step 1:** the test: `prepare(LauncherConfig { data_dir: temp, port: 0, profile: Dev, .. })` → bind on an ephemeral port, `tokio::spawn(serve(...))`; build a pinned client `ClientConfig` from the launcher's exported `server_cert.der`; connect; `POST /v1/bootstrap` with the smoke test's bootstrap secret (the one `prepare` returned) → assert `201`; then a second `POST /v1/bootstrap` after publishing a binding would close the window — but to keep it focused, assert: (a) the data dir got laid out (tls/blobs/config/logs exist + server_cert.der + directory_pub.der), (b) the bootstrap secret is returned once and its sha256 is stored, (c) a client over the pinned cert can `POST /v1/bootstrap` with the right secret → 201 and with a wrong secret → 401. Mirror `bootstrap_admin_e2e.rs`'s TLS/hyper helpers (copy them).
- [ ] **Step 2:** run `export PATH="$HOME/.cargo/bin:$PATH"; cargo test -p maxsecu-portable-server --test boot_smoke` until PASS (real debugging; no weakened asserts). fmt/clippy clean. Commit `test(portable-server): dev boot + client bootstrap over real TLS smoke test`.

---

## Task 7: Client portable folder layout

**Files:** Create `crates/client-app/src/layout.rs`; Modify `crates/client-app/src/main.rs`, `lib.rs`.

- [ ] **Step 1 (TDD):** `ensure_portable_layout(dir) -> io::Result<()>` creates `config/`, `keystore/`, `index/`, `cache/`, `logs/` beside the exe (idempotent). Test: on a temp dir all five exist after the call; a second call is a no-op. Add a module doc describing the portable layout (matches spec §8.1).
- [ ] **Step 2:** `main.rs` calls `ensure_portable_layout(&app_dir)` at startup (best-effort; log on failure, don't crash). `lib.rs` `pub mod layout;`.
- [ ] **Step 3:** `cargo test -p maxsecu-client-app layout::` ; build ; fmt/clippy clean. Commit `feat(client-app): ensure portable folder layout on startup`.

---

## Task 8: Packaging scripts + README

**Files:** Create `packaging/package.ps1`, `packaging/package.sh`, `packaging/README.md`.

- [ ] **Step 1:** `package.ps1` (and the bash twin): build the release artifacts — `cargo build --release -p maxsecu-portable-server` and `cargo build --release -p maxsecu-client-app`; copy the binaries + the UI `dist/` into a `dist/MaxSecuServer/` and `dist/MaxSecuClient/` portable-folder skeleton (the layouts from spec §8.1/§8.2); echo the deferred steps clearly. The **Tauri GUI bundle** (`tauri build`), **Authenticode signing** (`signtool`), and **PostgreSQL bundling** are present as clearly-commented, **guarded** steps that run only if the tool/cert is available (Tauri CLI / signtool / a PG dist) and otherwise print a "DEFERRED (not available in this environment): …" notice — they must NOT fail the script. Do not fabricate a signed exe.
- [ ] **Step 2:** `packaging/README.md`: document the client + server portable layouts; how to run the dev server (`maxsecu-portable-server` → prints the bootstrap secret) + point the client at it; the deferred-ops (real PG bundling, Authenticode cert + signing, Tauri CLI GUI bundle, reproducible-build flags) and where each is wired; the security note that dev D5/secret are dev-only.
- [ ] **Step 3:** Verify the scripts are syntactically valid (`bash -n packaging/package.sh`; `pwsh -NoProfile -Command "$null = [scriptblock]::Create((Get-Content -Raw packaging/package.ps1))"` if pwsh is available, else a manual read) and that the cargo-build commands they invoke are correct. Do NOT necessarily run a full release build in CI if it's slow — at minimum confirm `cargo build --release -p maxsecu-portable-server` compiles (it's the new crate). Commit `chore(packaging): portable build scripts + README (deferred-ops documented)`.

---

## Task 9: Phase-6 gates green + security-review note

**Files:** Create `docs/security-review-phase6-mediaapp.md`.

- [ ] fmt (`portable-server` + client-app clean), clippy `-D warnings` (`portable-server` + client-app), `cargo deny`, `cargo audit`, `MAXSECU_PG_OPTIONAL=1 cargo test --workspace` (incl. the new `boot_smoke` + client-app `layout` tests).
- [ ] Write the note: `portable-server` only composes/supervises the unchanged secret-free server (no new crypto/endpoint); the DEV D5 + bootstrap secret are runtime-generated, security-degraded, dev-only, and loudly labeled; no secret is baked into the binary; the bootstrap secret is printed once and stored only as sha256; the prod profile injects the real cert/D5/sink/PG and self-applies schema (wired, exercised with a DATABASE_URL). Conclude PASS if green. Document the deferred-ops (real PG bundling, Authenticode cert + signing, Tauri GUI bundle) as environment-blocked with the hooks in place — NOT security gaps.
- [ ] Commit `chore(phase6): gates green + security-review note`.

---

## Self-review checklist (done while writing)

- **Spec coverage (Phase 6 row of §10 + §8 packaging):** server self-extracting launcher that lays out the folder, gens dev cert + prints the bootstrap secret on first run, serves (Tasks 1–5) ✓; bundles+supervises PostgreSQL — **prod hook wired, real bundling deferred-ops** (Tasks 5, 8, 9 — documented) ✓; self-applies schema.sql — prod path (Task 5) ✓; in-process dev sink — `NullAuditSink` for dev, external injected for prod (Task 5; the in-process `sink-server` is an optional wire — noted) ✓; client portable folder layout (Task 7) ✓; portability + smoke tests — the boot smoke test (Task 6) proves the dev stack stands up + a client bootstraps over real TLS (the spec §9 auto-connect foundation) ✓; packaging scripts + reproducibility/Authenticode notes (Task 8) ✓; secrets injected at runtime not baked in (Tasks 3–5, security note) ✓.
- **No core change:** `portable-server` composes the existing `maxsecu-server` library unchanged; the only client-app change is the additive `layout` module ✓.
- **Type consistency:** `LauncherConfig`/`Layout` (T2) consumed by pki/bootstrap/run (T3–T5) + the smoke test (T6); `ensure_dev_cert`/`load_server_config`/`export_client_pin` (T3), `ensure_bootstrap_secret`/`bootstrap_secret_hash`/`ensure_dev_d5` (T4) composed by `run`/`prepare` (T5) + asserted by `boot_smoke` (T6); `ensure_portable_layout` (T7) called by client `main.rs`.
- **Known fill-ins flagged:** the exact `AppState` field names + `serve` signature + `test_pki()` ServerConfig construction (read `server/src/{lib,serve,http}.rs` + the e2e tests — T1/T3/T5); whether `[workspace.dependencies]` pins `rcgen`/`tokio-rustls` (T1); whether `PgStore` has a no-live-connection constructor + a schema-apply entrypoint (T5 — if not, the prod branch returns a clear "requires PG" error, type-checked); `DirectorySigner` key-persistence shape (T4 — persist what `admin-core` exposes; at minimum the public key + enough to re-load, else regenerate-and-rewrite-pubkey with a warning).

## Deferred (documented, environment-blocked — NOT security gaps)

- **Real PostgreSQL binary bundling + supervision** — needs PG binaries + a bundler; the prod profile wires `PgStore`/schema-apply behind `DATABASE_URL`, and the dev profile runs on `MemoryStore`. The bundling is a CI/ops packaging step.
- **Authenticode signing** (client + server exe) — needs a code-signing cert; `package.*` has the guarded `signtool` step. (Existing MaxSecu deferral.)
- **Tauri GUI bundle** (`tauri build`) — the Tauri CLI is not installed here; `package.*` has the guarded `tauri build` step; `cargo build` already builds the `client-app` binary (sans the bundled WebView2 installer).
- **Reproducible-build flags + transparency-logged release** — documented in the README; the offline signing key + release transparency are the existing Phase-7 ops deferrals.
- **In-process dev sink** (`sink-server`) wired into the dev launcher — optional; dev uses `NullAuditSink`. Note the injection point.
- **P7 video** remains the separate, gated, security-reviewed effort (spec §10.7 / D-B).
