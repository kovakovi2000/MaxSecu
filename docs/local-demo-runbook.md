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
| Server lifecycle | **Start now + script** | The assistant starts the server in this session, captures the one-time bootstrap secret, and leaves a start script. |
| First GUI launch | **Assistant smokes it, then hands to you** | The assistant confirms the window opens / UI loads, then you do the account click-through. |

## 0.1 The one non-obvious design fact that shapes everything

`POST /v1/bootstrap` (what the GUI's "create first admin" screen calls) **creates
an account but never confers admin and never publishes a directory binding.** A
bootstrapped account can *log in* but cannot issue vouchers, browse the feed, or
upload until an **offline D5 directory ceremony** signs its binding and publishes
it to `POST /v1/directory` (authority = the D5 signature, not a session). In this
dev build the "ceremony" is a scripted tool that uses the server's on-disk dev D5
seed (`<data_dir>/config/d5_secret.bin`).

Two further constraints from the code:
- **Bootstrap closes permanently after the first published binding** (`bootstrap_closes_after_first_binding`). Once we seed `root`'s binding, the GUI bootstrap screen returns `409`.
- The shell's **default route is `#/connect`** and there is **no link to `#/bootstrap`** in the GUI. Account provisioning is by design an out-of-band ceremony; the GUI's everyday entry point is **unlock + connect**.

➡️ Therefore the usable-demo path is: **pre-seed `root`+`bob` (sealed keystores +
published bindings) over the persistent server, then you unlock + connect.** The
GUI bootstrap/voucher screens are documented in the appendix for completeness.

---

## 1. Components & paths

- Server launcher: `crates/portable-server` → `maxsecu-portable-server.exe`.
- Client: `crates/client-app` (Tauri 2) → `maxsecu-client-app.exe` (embeds `ui/dist`, needs WebView2 — standard on Win11).
- Seeding tool (added this session): `tools/demo-seed` → provisions `root`+`bob`.
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

### S3 — `tools/demo-seed` provisioning tool **[DONE]**
Mirrors `bootstrap_admin_e2e.rs` against the live server:
1. read pins (`server_cert.der`) + dev D5 seed from the server data dir;
2. bootstrap a glass-break account + `root` (with the live bootstrap secret);
3. publish `root`'s `[User,Admin]` binding under the dev D5 → bootstrap closes;
4. log in as `root`, issue a voucher; register `bob` via `/v1/users`;
5. publish `bob`'s `[User]` binding;
6. issue one **spare voucher** (printed, for the appendix voucher demo);
7. seal `root`/`bob` identities into their client folders' `keystore/`.
- Verify: tool exits 0 and prints both `user_id`s + the spare voucher.

### S4 — Build the WebView UI **[DONE]**
`cd crates/client-app/ui && npm run build` → `ui/dist/{index.html,main.js,styles.css}`.
- Verify: `ui/dist/main.js` present and non-empty.

### S5 — Build release binaries **[DONE]**
`cargo build --release -p maxsecu-portable-server -p maxsecu-client-app -p maxsecu-demo-seed`.
- Verify: the three exes exist under `target/release/`.

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

### S8 — Start the persistent server **[DONE]**
`DATABASE_URL=… MAXSECU_DATA_DIR=…/maxsecu-server-data maxsecu-portable-server.exe`,
backgrounded. Capture from its console: the **one-time bootstrap secret**, the
**pinned dev D5**, and the **client-pins dir**.
- Verify: TLS `GET https://localhost:8443/...` responds (pinned).

### S9 — Seed accounts + wire pins **[DONE]**
Run `demo-seed` against the live server; then copy
`maxsecu-server-data/client-pins/{server_cert.der,directory_pub.der}` into both
clients' `config/`.
- Verify: `GET /v1/directory/root` and `/v1/directory/bob` return `200`.

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

## 3. Create / use your first account (the click-through) **[YOU]**

The window opens on **"Connect to a MaxSecu server"** (default route).

### 3a. Sign in as the ready-made admin (`root`)
1. **Server**: `localhost:8443`  *(must be `localhost`, not `127.0.0.1` — the pinned cert's SAN is `localhost`)*
2. **Username**: `root`
3. **Password**: `root-demo-pass-9!`
4. Leave **Use Tor** unchecked. Click **Connect**.
   - Under the hood: `unlock_keystore(password)` opens the sealed keystore beside
     the exe, then `connect` does pinned-TLS + channel-bound login, then
     `account_status` routes you. Because `root` has a published binding you land
     on **#/feed** (an unseeded account would land on **#/pending**).
5. You're now an **admin**: the top nav exposes **Feed · Upload · Admin · Settings**.

### 3b. Verify upload + sandboxed-video playback (the GUI e2e)
1. Click **Upload**. Pick the sample video `dist/sample/sample.mp4` (or any small MP4/AV1).
2. The upload tray shows progress; on completion the item appears in **Feed**.
3. Open it from the feed → the **media-viewer**/`<video-player>` decodes in the
   confined worker (codec runs out-of-process; main process holds no decoder).
4. `root`'s upload is wrapped to `root` (self) + the recovery recipient (`bob`), so
   `bob` can also see/share it.

### 3c. Sign in as the second user (`bob`)
Launch `dist/MaxSecuClient-bob/maxsecu-client-app.exe` → Server `localhost:8443`,
Username `bob`, Password `bob-demo-pass-9!` → **Connect** → **#/feed**.

---

## 4. Caveats (honest list)

- **SECURITY-DEGRADED dev profile.** The D5 signing key, the bootstrap secret, and
  the TLS cert are dev artifacts generated into `maxsecu-server-data/`. The dev D5
  **private** seed (`config/d5_secret.bin`) is cleartext on disk — anyone with the
  data dir can forge bindings. Never share/commit the data dir. This is NOT the
  production ceremony key.
- **Persistent-DEV ≠ Prod profile.** We get Postgres persistence while keeping the
  dev cert/D5/bootstrap. The real Prod profile additionally needs an injected
  (non-self-signed) cert + an external WORM/audit sink + the offline ceremony key.
- **Unsigned exe.** No code-signing cert was provided → Windows SmartScreen may warn
  ("More info → Run anyway"). The Tauri NSIS installer is a deferred-op (Tauri CLI
  not installed); the raw cargo exe runs directly.
- **Bootstrap is closed** on this server (we published `root`'s binding). To exercise
  the GUI bootstrap screen from scratch, reset the DB (see §5) before seeding.
- Demo passwords are placeholders — rotate for anything real.

## 5. Reset / re-run

- **Re-seed only** (DB kept): drop+recreate schema, restart server, re-run `demo-seed`.
- **Full reset**: stop the server; in WSL `psql -d maxsecu -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;'` then re-apply `docs/schema.sql`; delete `maxsecu-server-data/`; restart server (new dev cert/D5/secret) and re-stage pins; re-run `demo-seed`.
- Keystores refuse to overwrite (`keystore_exists`): delete the client folder's `keystore/` before re-sealing.

## 6. Appendix — the designed bootstrap/voucher flows (reference)

- **GUI first-run bootstrap** (`#/bootstrap`, only on a fresh DB; not linked from
  connect): Step 1 generates a glass-break emergency account (needs the bootstrap
  secret), Step 2 creates the first admin (username/password/secret). The new admin
  is then **pending** until a ceremony publishes its `[User,Admin]` binding.
- **Voucher enrolment** (`register_user`): an admin issues an invite; a new user
  registers with it; the user is **pending** until the ceremony publishes a `[User]`
  binding. A spare voucher code is printed by `demo-seed` for this.

## 7. Remaining manual / deferred (not done here)

- Authenticode signing (no cert), Tauri NSIS installer (no Tauri CLI).
- Real Prod profile (injected cert + external sink + offline ceremony key).
- Real ffmpeg/AAC author-side ingest (off-by-default `ffmpeg` feature; host has only unsupported FFmpeg 8.0).

---

## 8. Verification results (this assembly run)

All checks below **PASSED** during the assembly run that produced this `dist/`.

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
