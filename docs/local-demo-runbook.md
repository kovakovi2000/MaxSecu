# MaxSecu — Local Working-Demo Runbook (2026-06-30)

> **Audience:** the operator (you) running MaxSecu as a usable local demo on this
> Windows 11 host. This runbook is both the plan and the executed record. Steps
> marked **[DONE in this session]** were performed by the assistant during the
> assembly run; steps marked **[YOU]** are the hands-on GUI click-through.

**Goal.** Take MaxSecu from code-complete to a usable local demo:
1. a runnable client `.exe` you launch,
2. a **persistent** test server already running (Postgres-backed, survives restart),
3. ready-to-use accounts + correct instructions to sign in / create accounts.

---

## 0. Decisions taken (from the up-front Q&A)

| Axis | Choice | Consequence |
|------|--------|-------------|
| Demo depth | **Full demo + 2nd user** | Pre-seed a working admin (`root`) + a second user (`bob`), both with published directory bindings; verify upload + sandboxed-video playback through the GUI. |
| Persistence | **Postgres (persistent)** | Accounts/sessions/directory survive server restarts. Uses the WSL `Ubuntu-22.04` PG14 (`maxsecu` DB). |
| Server lifecycle | **Start now + script** | The assistant starts the server in this session and leaves a start script. (No bootstrap secret to capture — enrollment is registration-key-only; provision with `maxsecu-setup`.) |
| First GUI launch | **Assistant smokes it, then hands to you** | The assistant confirms the window opens / UI loads, then you do the account click-through. |

## 0.1 The enrollment model (updated — registration-key-only, no bootstrap secret)

> **UPDATE (T4/T14/T15):** the old bootstrap-secret + voucher + pending flow is
> **gone**. There is no `POST /v1/bootstrap`, no `/v1/vouchers`, no `/v1/pending`,
> and the server prints **no bootstrap secret**. The `tools/demo-seed` tool is
> **retired**; provisioning is now done by **`tools/maxsecu-setup`** + the
> registration-key enrollment panel.

The current model:
- **Enrollment is registration-key-only.** A new account POSTs `/v1/users` with a
  single-use **registration key**. The **server itself signs** the account's
  directory binding (with its DEV D5 key) and stores it atomically — no separate
  offline ceremony step, no "pending" wait. **The first account to enroll becomes
  admin**; everyone after is a plain user.
- **Admins mint more keys** in-app via `POST /v1/registration-keys` (the GUI
  Admin screen's "mint a key" button); the server returns the plaintext key once.
- **The recovery account is provisioned once** by `maxsecu-setup`, which also
  emits the **first registration key** and a **`recovery_pin.bin`** that must be
  embedded into the client build (the client fails closed without it). Recovery
  registration (`POST /v1/recovery/register`) is **open on a fresh server and
  closes (409) after the first use**.

➡️ Therefore the usable-demo path is: **run the server → run `maxsecu-setup`
(creates the recovery account + first registration key + `recovery_pin.bin`) →
copy `recovery_pin.bin` into `crates/client-app/` and REBUILD the client → launch
the client and enroll the first admin with the first registration key.**

---

## 1. Components & paths

- Server launcher: `crates/portable-server` → `maxsecu-portable-server.exe`.
- Client: `crates/client-app` (Tauri 2) → `maxsecu-client-app.exe` (embeds `ui/dist`, needs WebView2 — standard on Win11).
- Setup tool: `tools/maxsecu-setup` → provisions the recovery account + first
  registration key + `recovery_pin.bin` (replaces the retired `tools/demo-seed`).
- Staged output: `dist/`
  - `dist/MaxSecuServer/` — server exe + `run-server.ps1`.
  - `dist/MaxSecuClient-root/` — admin client (exe + `ui/` + `config/` pins + sealed `keystore/`).
  - `dist/MaxSecuClient-bob/` — second-user client (same shape).
- Server data dir (persistent crypto artifacts + blobs): `maxsecu-server-data/`.

**Dev credentials (SECURITY-DEGRADED — local demo only):**
- Postgres: `postgres://maxsecu:maxsecu-dev@127.0.0.1:5432/maxsecu?sslmode=disable`
- `root` keystore password: `root-demo-pass-9!`
- `bob` keystore password: `bob-demo-pass-9!`
- Server SAN is `localhost` ⇒ clients MUST connect to `localhost:8443` (never `127.0.0.1:8443`).

---

## 2. Steps

### S1 — Add a persistent (Postgres) profile to the launcher **[DONE]**
`crates/portable-server`: when `DATABASE_URL` is set, compose `AppState` over
`PgStore` instead of `MemoryStore`, **keeping the dev self-signed cert + dev D5 +
dev bootstrap** (a clearly-labelled *persistent-DEV* profile — NOT the production
ceremony profile, which additionally requires an injected non-self-signed cert +
external sink). Emit a loud SECURITY-DEGRADED notice.
- Verify: `cargo build -p maxsecu-portable-server` compiles; unit tests pass.

### S2 — `Ceremony::from_seed` in the test-only ceremony harness **[DONE]**
Add `Ceremony::from_seed(&[u8;32])` so the seeding tool signs bindings under the
server's persisted dev D5 seed (reusing `sign_binding`, exactly like
`bootstrap_admin_e2e.rs`).
- Verify: `cargo test -p maxsecu-ceremony-harness` passes.

### S3 — `tools/maxsecu-setup` provisioning tool **[UPDATED — replaces demo-seed]**
Run **once** against the freshly-started server (reads the pinned
`server_cert.der` from `<data_dir>/client-pins/`). It:
1. registers the **recovery account** (`POST /v1/recovery/register`, once-only);
2. mints the **first registration key** (`--first-key-out register.key`);
3. writes the canonical **`recovery_pin.bin`** (`--pin-out`) and the sealed
   recovery private-key blob (`--out`, move to cold storage).

Example:
```
maxsecu-setup \
  --data-dir ./maxsecu-server-data \
  --out ./recovery_key.blob \
  --pin-out ./recovery_pin.bin \
  --first-key-out ./register.key \
  --passphrase 'recovery-demo-pass-9!'
```
- Verify: exits 0 and prints the three artifact paths. Re-running against the same
  server exits **3** ("already registered", once-only).

### S4 — Build the WebView UI **[DONE]**
`cd crates/client-app/ui && npm run build` → `ui/dist/{index.html,main.js,styles.css}`.
- Verify: `ui/dist/main.js` present and non-empty.

### S5 — Build release binaries **[UPDATED]**
Server (root workspace): `cargo build --release -p maxsecu-portable-server`.
Client + setup tool (client workspace): from `crates/client-app`,
`cargo build --release` and `cargo build --release -p maxsecu-setup`.
- Verify: `maxsecu-portable-server.exe`, `maxsecu-client-app.exe`, and
  `maxsecu-setup.exe` exist. NOTE: the client is **rebuilt again in S9** after
  `recovery_pin.bin` is dropped into `crates/client-app/` (the pin is embedded at
  build time).

### S6 — Prepare Postgres **[DONE]**
Start WSL `Ubuntu-22.04`; ensure PG14 online; `ALTER ROLE maxsecu PASSWORD
'maxsecu-dev'`; apply `docs/schema.sql` into the `maxsecu` DB (idempotent reset:
drop+recreate the public schema first).
- Verify: `\dt` lists the Phase-1 tables (`users`, `directory_bindings`, `sessions`, …).

### S7 — Stage `dist/` **[DONE]**
Copy exes + `ui/` + scripts into the three folders; write each client's
`config/connection.json` = `{"server":"localhost:8443","use_tor":false,"auto_connect":true}`;
write `config/recovery_recipient.txt` (`root`→`bob`, `bob`→`root`); pins are
copied in S9 after the server prints them.

### S8 — Start the persistent server **[UPDATED]**
`DATABASE_URL=… MAXSECU_DATA_DIR=…/maxsecu-server-data maxsecu-portable-server.exe`,
backgrounded. Capture from its console: the **pinned dev D5** and the
**client-pins dir**. There is **no bootstrap secret** to capture anymore.
- Verify: TLS `GET https://localhost:8443/...` responds (pinned).

### S9 — Provision recovery + first key, then REBUILD the client **[UPDATED]**
1. Run `maxsecu-setup` (see S3) against the live server → produces
   `recovery_pin.bin` + `register.key` + the sealed recovery blob.
2. **Copy `recovery_pin.bin` → `crates/client-app/recovery_pin.bin` and REBUILD /
   repackage the client** so the pin is embedded (the client fails closed without
   it). Re-stage the rebuilt `maxsecu-client-app.exe` into `dist/`.
3. Copy `maxsecu-server-data/client-pins/{server_cert.der,directory_pub.der}` into
   the client's `config/`.
- Verify: `GET /v1/recovery/pubkey` returns `200`; a second `maxsecu-setup` run
  exits `3` (recovery already registered).

### S10 — Verify backend pipeline **[DONE]**
Run the existing e2e gates headlessly (`bootstrap_admin_e2e`, `upload_e2e`,
`video_upload_e2e`, `browse_view_e2e`) to confirm the upload→view→video paths are
green, since the live GUI demo of those is yours to drive.

### S11 — Smoke-launch the GUI **[DONE]**
Launch `dist/MaxSecuClient-root/maxsecu-client-app.exe`; confirm the window/process
starts and the WebView loads `ui/dist` (watch for WebView2/CSP/`invoke` errors).
This is the first time the app runs as a *window*, so this is the highest-risk step.

### S12 — Hand-off **[YOU]** — see §3.

---

## 3. Create / use your first account (the click-through) **[YOU]** **[UPDATED]**

The window opens on **"Connect to a MaxSecu server"** (default route). Under the
new model you **enroll** the first admin with the registration key — there are no
pre-seeded `root`/`bob` accounts.

### 3a. Enrol the first admin (registration-key)
1. Open the **enrollment panel** (register a new account).
2. **Server**: `localhost:8443`  *(must be `localhost`, not `127.0.0.1` — the pinned cert's SAN is `localhost`)*
3. **Username** + **password** of your choice.
4. **Registration key**: paste the contents of `register.key` (from `maxsecu-setup`).
5. Click **Register / Enrol**.
   - Under the hood: `POST /v1/users` with the single-use key; the **server signs**
     the `[User, Admin]` binding (first registrant = admin) and stores it
     atomically. You are immediately an admin — no "pending" wait, no ceremony.
6. Connect/unlock → you land on **#/feed**; the top nav exposes
   **Feed · Upload · Admin · Settings**.

### 3b. Verify upload + sandboxed-video playback (the GUI e2e)
1. Click **Upload**. Pick the sample video `dist/sample/sample.mp4` (or any small MP4/AV1).
2. The upload tray shows progress; on completion the item appears in **Feed**.
3. Open it from the feed → the **media-viewer**/`<video-player>` decodes in the
   confined worker (codec runs out-of-process; main process holds no decoder).
4. Your upload is wrapped to yourself (self) + the recovery recipient.

### 3c. Enrol a second user
As the admin, open **Admin → mint a registration key** (`POST /v1/registration-keys`;
the server returns the plaintext key once). Hand that key to the second user, who
enrols exactly as in 3a — this time as a plain **User** (only the first registrant
is admin). Launch a second client instance → Server `localhost:8443` → enrol with
the new key → **#/feed**.

---

## 4. Caveats (honest list)

- **SECURITY-DEGRADED dev profile.** The D5 signing key and the TLS cert are dev
  artifacts generated into `maxsecu-server-data/`. The dev D5 **private** seed
  (`config/d5_secret.bin`) is cleartext on disk — and because the server signs
  enrollment bindings with it, anyone with the data dir can forge bindings. Never
  share/commit the data dir. This is NOT the production ceremony key. (There is no
  bootstrap secret in this model.)
- **Persistent-DEV ≠ Prod profile.** We get Postgres persistence while keeping the
  dev cert/D5. The real Prod profile additionally needs an injected (non-self-signed)
  cert + an external WORM/audit sink + the offline ceremony key (so the server no
  longer holds the signing key).
- **Unsigned exe.** No code-signing cert was provided → Windows SmartScreen may warn
  ("More info → Run anyway"). The Tauri NSIS installer is a deferred-op (Tauri CLI
  not installed); the raw cargo exe runs directly.
- **Recovery is registered** on this server (once-only). To re-run `maxsecu-setup`
  from scratch, reset the data dir + DB (see §5) first — a second run against the
  same server exits `3`.
- Demo passwords are placeholders — rotate for anything real.

## 5. Reset / re-run

- **Full reset**: stop the server; in WSL `psql -d maxsecu -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;'` then re-apply `docs/schema.sql`; delete `maxsecu-server-data/`; restart server (new dev cert/D5) and re-stage pins; re-run `maxsecu-setup` to re-provision the recovery account + a fresh first registration key, then **rebuild the client** with the new `recovery_pin.bin`.
- Registration keys are single-use: mint a fresh one (`POST /v1/registration-keys`, admin) for each new enrollment.
- Keystores refuse to overwrite (`keystore_exists`): delete the client folder's `keystore/` before re-sealing.

## 6. Appendix — the enrollment flows (reference)

- **First-admin enrollment** (`POST /v1/users`, registration-key): a new account
  posts its keys + the single-use registration key; the **server signs** the
  binding and stores it atomically. The **first-ever registrant becomes admin**
  (`[User, Admin]`); everyone after is `[User]`. No "pending" wait, no separate
  ceremony — the server is the enrollment authority in the DEV profile.
- **Minting more keys** (`POST /v1/registration-keys`, admin-gated): an admin mints
  a fresh single-use key (the GUI Admin screen's "mint a key" button); the server
  returns the plaintext once. Hand it to the enrollee.
- **Recovery account** (`POST /v1/recovery/register`, once-only): provisioned by
  `maxsecu-setup`, which also emits the first registration key + `recovery_pin.bin`.

## 7. Remaining manual / deferred (not done here)

- Authenticode signing (no cert), Tauri NSIS installer (no Tauri CLI).
- Real Prod profile (injected cert + external sink + offline ceremony key).
- Real ffmpeg/AAC author-side ingest (off-by-default `ffmpeg` feature; host has only unsupported FFmpeg 8.0).

---

## 8. Verification results (this assembly run — HISTORICAL, pre-redesign)

> **SUPERSEDED (T4/T14/T15):** the run below predates the registration-key
> redesign. It used the now-retired `demo-seed` tool, the `enrollment_vouchers`
> table, and a one-time bootstrap secret — **all removed**. It is kept only as a
> historical record of the original `dist/` assembly; the current flow is §0.1 +
> §2 + §3 above. Re-verify against the new model when you next assemble `dist/`.

All checks below **PASSED** during the (pre-redesign) assembly run that produced
the original `dist/`.

**Build (release, `target/release/`):**
- [x] `maxsecu-portable-server.exe` built (exit 0)
- [x] `maxsecu-client-app.exe` built (exit 0)
- [x] `maxsecu-demo-seed.exe` built (exit 0)

**Postgres schema applied — 12 tables in DB `maxsecu`:**
- [x] `users`, `directory_bindings`, `sessions`, `auth_nonces`, `enrollment_vouchers`,
  `files`, `file_versions`, `file_streams`, `file_genesis`, `file_key_wraps`,
  `control_log`, `auth_events`

**Server (persistent-DEV / Postgres over TLS on `https://localhost:8443`):**
- [x] `curl -k GET /v1/directory/root` → **200**
- [x] `curl -k GET /v1/directory/bob` → **200**
- [x] `curl -k GET /v1/directory/nobody` → **404**

**Seeding (offline D5 ceremony; seeder D5 matched the server's pinned D5):**
- [x] `root` provisioned with a published `[User,Admin]` binding + sealed keystore —
  `user_id = 3fda727348811d52ef0a3e7370052b98`
- [x] `bob` provisioned with a published `[User]` binding + sealed keystore —
  `user_id = d9dbcb2b0d05c1a2f0e7a98bad562f35`
- [x] Spare voucher issued: `spare-voucher-389980da86e8`
- [x] Pinned dev D5 public key:
  `60895e67ae084e5f491dc1449c6747c8e9f84f5aedba2b33ace934e2927ed7cc`
- [x] One-time bootstrap secret for the current data dir: `EE3xnkpn15hEabDkYxLqmlJoVAFtHEMg`
  (**already consumed**; a new secret prints only on a fresh data dir — see §5)

**GUI smoke (`dist/MaxSecuClient-root/maxsecu-client-app.exe`):**
- [x] Process alive (~37 MB) and **34** `msedgewebview2` child processes spawned ⇒
  WebView2 loaded the embedded `ui/dist` successfully (first-ever windowed launch
  works). The smoke instance was then closed.

**Backend e2e gates (`cargo test -p maxsecu-client-app`) — each "1 passed":**
- [x] `bootstrap_admin_e2e`
- [x] `upload_e2e`
- [x] `browse_view_e2e`
- [x] `video_upload_e2e`
- [x] `video_e2e`
