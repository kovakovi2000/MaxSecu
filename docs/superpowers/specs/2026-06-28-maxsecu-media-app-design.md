# MaxSecu Media App — Client + Server Application Layer

**Status:** Design (approved in brainstorming 2026-06-28). Next step: implementation plan (writing-plans).
**Scope:** A portable desktop **client GUI** and a portable **server artifact** for posting, browsing, and managing **image, video, and text/blog** content, built **on top of** the existing MaxSecu zero-knowledge backend (`DESIGN.md`, `docs/api.md`, `docs/stack.md`, `docs/media-sandbox.md`, `docs/schema.sql`).
**Companion to:** `DESIGN.md` (authoritative threat model + protocol), `docs/stack.md` (locked stack decisions), `docs/api.md` (RPC contract), `docs/media-sandbox.md` (decode isolation), `docs/parameters.md` (all numeric values).

> This document specifies the **application layer only**. Every confidentiality/integrity guarantee continues to rest on the existing core (`client-core`, `crypto`, `encoding`) and is re-verified client-side. Nothing here is a new security boundary; the new UI is explicitly **outside the TCB** (`stack.md §1.2`).

---

## 1. Context & what already exists

MaxSecu is a mature, tested zero-knowledge file-storage system (Phases 0–7 complete). The application this spec describes is **not a greenfield build** — most of the hard backend already exists:

| Capability the prompt asks for | Already provided by MaxSecu | New work here |
|---|---|---|
| Image / video / text posts | Files of `file_type: image \| video \| blog` + title/thumbnail/preview/content streams (`api.md §8`) | UI + client orchestration |
| Content feed / library, filter by type | `GET /v1/files?type=…` listing index (D35) | Feed UI, "my uploads" filter, client-side search/sort |
| Upload management | Two-phase resumable chunked upload (`api.md §8–9`) | Upload tray + pipeline UX |
| Auth / session | Channel-bound Ed25519 challenge-response (`api.md §2`) | Connection + keystore-unlock UX |
| Enrollment / admin / approval | Voucher-gated enrollment, coarse admin role, dual control (`api.md §4–5,§7`) | Glass-break/first-admin bootstrap + approval UI |
| Image + text rendering | Pure-Rust PNG + sanitized blog path (`media-sandbox §4`, `stack.md §1.7`) | Viewer UI |
| Crypto / encoding / transport | `crypto`, `encoding`, rustls TLS 1.3, PQ-hybrid, key-transparency, recovery | (reuse unchanged) |

**Locked by existing specs — not re-decided here:** client shell = **Tauri (Rust core + WebView2)**; client packaging = **portable signed `.exe`, password-derived at-rest state**; crypto/transport/error-model/rate-limiting; the **media decode-isolation** model; reproducible + Authenticode-signed builds.

**Existing crates:** `encoding`, `crypto`, `client-core`, `server`, `sink-server`, `admin-core`, `media-worker`.

---

## 2. Decisions taken in this brainstorm

| # | Decision | Choice |
|---|---|---|
| D-A | Project basis | **Build on MaxSecu** (application layer over the existing backend) |
| D-B | Video in v1 | **Images + text now; video player UI built but codec gated** behind the existing `Transcoder`/decode seam (lights up when the sandboxed ffmpeg/dav1d worker is ratified) |
| D-C | Trust / deployment mode | **Full high-assurance ceremony** (offline D5 directory key, voucher enrollment, in-person fingerprint); test uses a **scripted local ceremony** |
| D-D | Server packaging | **Self-extracting exe that bundles & supervises PostgreSQL**, auto self-signed cert + in-process sink for dev, self-applies `schema.sql`. Prod keeps the documented static-binary/compose path |
| D-E | Identity on a device with no keystore | **Portable encrypted keystore + recovery** (no password-derived keys); username+password unlocks the portable keystore |
| D-F | Search | **Client-side over decrypted titles + user tags**, kept in a local encrypted index |
| D-G | Pending (un-approved) user | **Status-only screen** — no feed, no upload; shows just the approval status |
| D-H | Accessibility | **WCAG 2.1 AA** + the full requested checklist |
| D-I | Background state changes | **Smart adaptive polling** (faster when focused, slower when idle, immediate on action) |
| D-J | WebView2 UI stack | **Vanilla TypeScript + Web Components**, pinned/vendored, no framework runtime |
| D-K | Admin promotion | **Ceremony-based only** — admin role is conferred by the offline D5-signed identity binding; no in-app/server "promote" path (`DESIGN.md:457`) |

---

## 3. Architecture & crate layout

```
crates/
  client-app/            NEW — Tauri backend (Rust). Depends on client-core (TCB).
    src/                   Tauri command catalog, event/progress bus, session+connection mgr,
                           feed/upload/admin orchestration, local encrypted search index.
    ui/                    NEW — WebView2 frontend: vanilla TS + Web Components, pinned/vendored.
      components/          <feed-grid> <media-viewer> <video-player> <upload-tray>
                           <status-pill> <progress-meter> <conn-banner> <quick-settings> …
      core/                Router, Store (observable state), Rpc (invoke wrapper + event bus)
  portable-server/       NEW — launcher wrapping maxsecu-server: self-extract, bundle+supervise
                           PostgreSQL, gen self-signed pinned cert + in-process sink (dev),
                           self-apply schema.sql, print bootstrap secret on first run.
  (existing: encoding, crypto, client-core, server, sink-server, admin-core, media-worker)
tools/
  ceremony-harness/      NEW (test-only) — scripts the existing air-gapped ceremony CLIs locally
                           to D5-sign bootstrap bindings for the auto-connect test scenario.
```

### 3.1 The Tauri command boundary (the single integration seam)

The UI can do **only** what a command allows. Each command takes a typed request, returns already-verified render-ready data or a typed error, and may emit a stream of `progress`/`state` events. The UI **never** receives a private key, a signed record's interior, or a whole-plaintext buffer — only decoded-on-demand bytes streamed through the core (`stack.md §1.2`, `DESIGN.md §8.1`).

Representative catalog (not exhaustive):

- **Connection/auth:** `connect(server, opts)`, `unlock_keystore(password)`, `login(username)`, `logout()`, `connection_state()` (stream).
- **Bootstrap:** `register_glassbreak(bootstrap_secret, save_path?)`, `create_first_admin(username, password, bootstrap_secret)`, `register_user(username, voucher)`, `account_status()`.
- **Feed/search:** `list_feed(filter, sort, cursor)`, `decrypt_card(file_id)` (title+thumbnail), `search_local(query)`, `reindex()`.
- **Viewer:** `open_content(file_id)` → streamed decode events; `save_unlocked(file_id, path)` (warned + audited).
- **Upload:** `stage_upload(meta, paths, recipients)`, `confirm_preview(job_id)`, `pause/resume/cancel(job_id)`, `upload_state()` (stream).
- **Admin:** `list_pending()`, `approve(user_id)`, `deny(user_id)`, `issue_voucher()`, `revoke(...)`/`tombstone(...)` (with co-sign), `control_log_state()`.
- **Settings:** `get/set_settings(...)`, `set_ram_cap(...)`, `export_keystore(path)`, `recovery_*`.

### 3.2 Rejected alternatives

- Folding the shell into `client-core` — muddies the library/TCB boundary.
- A separate UI process over hand-rolled IPC — Tauri already provides the audited IPC seam.
- Password-derived identity keys (D-E) — a real security downgrade; rejected in favor of portable keystore + recovery.

---

## 4. Bootstrap, identity, connection & recovery

### 4.1 Trust roots (full high-assurance mode, D-C)

- **D5 directory-signing key** — created **offline** in the existing ceremony *before* the server is exposed; the server pins its public key. D5 signs identity bindings → it alone decides who is a **valid recipient**. The cryptographic trust root.
- **Glass-break account** — first registration: an **emergency** identity with a **locally-generated random username + password**, **not auto-logged-in**, creds optionally written to an **encrypted file** at a user-chosen location, kept offline. Its binding is D5-signed with an **admin/recovery role** at bootstrap, so it is a *backstop* admin (emergency co-signer / re-establish authority if all operational admins are lost) — not the routine way to add admins.
- **First admin** — *second* registration with a user-chosen username+password. Its binding is **D5-signed with the `admin` role at bootstrap**; the server cannot confer admin itself (`DESIGN.md:457`). Day-to-day operational authority (approvals, vouchers, dual-control revocations).
- **Subsequent users** — voucher-gated registration → **pending** → admin approval → active; becomes a valid recipient once D5 signs the binding at the next ceremony.

### 4.2 First-run bootstrap flow

1. Server starts with an empty DB and prints a **one-time bootstrap secret** to its console/log.
2. First client with no account → **glass-break** screen: generates random creds locally, requires the bootstrap secret, optionally saves an **encrypted** creds file. Does **not** log in.
3. **First-admin** screen: user types desired username+password + the bootstrap secret → admin created.
4. Bootstrap window **auto-closes** after first-admin is set; thereafter registration is voucher-gated + approval-gated.
5. Ceremony (offline in prod; scripted locally for test) D5-signs the bindings **with their roles** (glass-break + first-admin get `admin`/recovery; users get `user`) so accounts become valid recipients.

### 4.6 Admin role conferral & promotion (D-K)

- **Granting admin = a D5 ceremony**, never an in-app button or a server grant. The offline D5 key signs the target user's binding with `roles` including `admin` (`DESIGN.md:457`, `schema.sql:53`). Offline in prod; scripted via the `ceremony-harness` in tests.
- The Admin screen's "add admin" affordance is therefore a **guided ceremony-request flow** (collect the candidate's directory-verified fingerprint, produce a ceremony work-item), not a privilege grant the running system can perform.
- **De-admining is lighter and in-band:** an admin posts a **role-narrowing tombstone** to the control-log; it takes effect as soon as it is sink-anchored — no ceremony, no re-sign (`DESIGN.md:76`/§7.6). Tombstones may *narrow* a role, never *widen* it.
- **Reaching two admins does not depend on the glass-break account:** the routine path is a promotion ceremony; glass-break is only the emergency backstop. Mass/account-wide revocations and all reinstatements still require dual control (a second admin's co-signature, `api.md §7.2`).

### 4.3 Identity & login (portable keystore + recovery, D-E)

- The Ed25519 key lives in a **portable encrypted keystore** beside the client exe; **password unlocks it (Argon2id)**, then channel-bound challenge-response (`api.md §2`).
- On a device with **no keystore**, username+password alone **cannot** reconstruct the key (true zero-knowledge). The user runs **recovery**: import an exported keystore blob, or use the Phase-7 recovery-recipient / Shamir path (`admin-core::recovery`).

### 4.4 Connection evolution (the testing scenario)

- **Now (test):** client reads a bundled config and **auto-connects** to the already-running server.
- **Later:** remove that config; the **connection screen** (server domain/IP, username, password, optional Tor) becomes the entry point. Both code paths exist from the start; auto-connect is just a config-driven default we delete.

### 4.5 Security risks, recovery & alternatives (bootstrap)

- **First-run race** (attacker reaches the open server first): mitigated by the **bootstrap secret** printed only to the operator's console; alternatives = loopback-only first-run, or in-person setup before exposure. Naïve "first-connection-wins" is documented as the weakest option and not chosen.
- **Glass-break creds file** is a high-value secret → stored **encrypted**, offline, with an explicit warning; never written to the repo or an indexed path.
- **Lost all admins** → use glass-break to mint a new admin. **Lost glass-break** → D5 ceremony + recovery recipient. **Lost keystore/device** → §4.3 recovery.
- **Residual:** the operator in full mode still runs the offline ceremony; the test ceremony harness is security-degraded and **test-only** (clearly labelled, never a prod path).

---

## 5. Screen-by-screen UI & navigation

**Shell (Layout B — top navigation rail):** top tab bar (Feed · My Content · Upload · Admin · Settings) + ⚡ quick-settings popover; a thin **status strip** (connection · sync · active tasks) below it; content region beneath. All regions are ARIA landmarks with a logical focus order.

| Screen | Purpose | Key elements | States |
|---|---|---|---|
| **Connection** | Enter a server (later version) | domain/IP, username, password, Tor toggle, "remember server", Bootstrap entry | resolving → TLS-pin → channel-bind → keystore-unlock → authenticating → connected; sanitized failure + Retry |
| **First-run bootstrap** | Establish glass-break + first admin | ① glass-break (gen creds, bootstrap secret, save encrypted, "won't log in") ② first admin ③ pending status-only | success/already-bootstrapped/secret-mismatch |
| **Pending** | Un-approved user (D-G) | "awaiting admin approval", account + request time only | polled re-check; approved → unlock app |
| **Feed / Library** | Browse all accessible content | search (titles+tags), Type/Sort filters, "Only my uploads" toggle, media grid with per-item state badges | empty / skeleton-loading / inline error+retry |
| **My Content** | Current user's uploads | same grid pre-filtered to owner | empty → "Upload your first post" |
| **Viewer (image/blog)** | View one post | decrypted-from-RAM render, metadata, verification ticks, Share, warned "Save unlocked" | decrypting / cold-fetching / verify-fail / ready |
| **Video player** | Play video (chrome now, codec later, D-B) | buffering %/readiness, **played vs. loaded-segment** scrubber, captions/CC, volume, fullscreen, "decode worker pending" badge | buffering / playing / stalled / error / codec-unavailable |
| **Upload** | Create posts | choose+describe (title/tags/type/recipients) → **preview-before-upload confirm** → encrypt → resumable upload; **active-uploads tray** | per-stage: transcoding/thumbnail/compress/encrypt/stage/upload %·speed·ETA/finalize/done/retry |
| **Admin** | Operate the service | approval queue (approve/deny + fingerprint), voucher issuance, revocation/tombstone (dual-control for mass), **"add admin" = guided ceremony-request** (not a server grant), de-admin via role-narrowing tombstone | sink-anchored confirmation; mass-revoke/reinstate blocked until a co-signing admin is available; 403 if not admin |
| **Settings** | Full configuration | Account (export keystore, recovery, change password, approval+ceremony status), Connection (Tor, direct links), **Performance/memory (RAM cache cap, decrypt-window, disk-unlock warning)**, **Behavior defaults (confirmations / "always do X")**, **Accessibility**, Privacy | inline validation; instant apply |
| **Quick-settings (⚡)** | Most-used toggles | Tor, reduced motion, high contrast, confirmations, RAM cap, theme | instant apply |

**Empty / loading / error** are first-class for every data view: skeletons while loading, explicit empty copy with the primary next action, and inline sanitized error banners with Retry (never a raw error string — matches the server's sanitized model, `api.md §3`).

---

## 6. Real-time feedback & state-visibility system

A single, consistent feedback layer rather than ad-hoc spinners. **Every long-running or external operation is a typed state machine** in the `client-app` backend that emits `progress`/`state` events over the Tauri event bus; the UI binds them to shared components.

**Shared components:** `<status-pill>` (connection/sync), `<progress-meter>` (%, speed, ETA, retry), `<task-tray>` (all background tasks), `<conn-banner>` (degraded/reconnecting), per-item `state-badge`.

**Tracked state machines & what they surface:**

- **Connection:** connected · reconnecting · disconnected · degraded; sub-states during connect (§5).
- **Authentication:** unlocking keystore · authenticating · session-expired · re-authenticating.
- **Upload:** queued · transcoding · thumbnail/preview · compressing · encrypting · staging · uploading (% · speed · ETA) · finalizing · done · failed (+ retry attempt/backoff). Resumable: re-PUT missing indices only.
- **Download/cold-fetch:** cache-hit · cold-fetching (% · speed · ETA, from `…/chunks/{i}/status`) · cold-ready · paused/resumed.
- **Media processing:** transcoding · thumbnailing · indexing; **video → codec-unavailable** stub.
- **Player:** buffering · loaded-segments · playback-ready · stalled · error.
- **Sync (smart polling, D-I):** idle · syncing · synced (with "last synced") · failed; faster when focused, immediate after a user action.
- **Background:** caching · cleanup · reindex.

**Behavior under load:** normal = subtle inline progress; **slow** = the meter shows speed/ETA and the operation stays cancellable/pausable; **failure** = a sanitized message + automatic retry with visible backoff, then a manual Retry. All feedback is **non-color-only** (icon + text + ARIA live region), screen-reader announced, and consistent across screens.

---

## 7. Accessibility plan (WCAG 2.1 AA + checklist, D-H)

- **Keyboard:** full operability, visible focus, logical tab order, skip-to-content, no keyboard traps; shortcuts documented and remappable-safe.
- **Screen readers:** semantic landmarks, labelled controls, ARIA **live regions** for the feedback layer (so progress/connection/auth changes are announced), Narrator/NVDA tested.
- **Contrast & color:** AA contrast; **status never by color alone** (icon + text always).
- **Text & layout:** scalable text (browser/zoom + in-app size control), reflow without loss, simple layouts, **large click/touch targets**.
- **Motion:** **reduced-motion** option (and respects OS setting) disabling non-essential animation/auto-play.
- **Media:** captions/CC and metadata surfaced where available; player controls fully keyboard/SR accessible.
- **Errors:** clear, plain-language, actionable messages (within the server's sanitized constraints).
- **Verification:** automated a11y checks (axe-style) in CI over the component set + manual NVDA/keyboard passes per release.

---

## 8. Packaging, folder structure, data, logs, updates, reset

### 8.1 Client — portable single signed `.exe` (`stack.md §5.2`)

Self-extracts a portable folder beside the exe on first run; no installer, no registry writes. **At-rest state is ciphertext-only**; the at-rest key is **password-derived (Argon2id)** so the folder travels.

```
MaxSecuClient/
  MaxSecuClient.exe         Authenticode-signed launcher (Tauri app + embedded UI assets)
  config/
    connection.json         server pin, Tor, defaults  (NO secrets; auto-connect config in test build)
    settings.json           UI/a11y/behavior/RAM-cap preferences
  keystore/
    local_key_blob          encrypted Ed25519 identity (Argon2id-wrapped)
    trust_store             trust-on-last-use (directory TOFU, sink head)
  index/
    search.idx              local ENCRYPTED title+tag search index (D-F)
  cache/                    ciphertext-only LRU/LFU blob cache (FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
  logs/                     sanitized, no secrets/plaintext; rotated
  glassbreak/               (optional) ENCRYPTED emergency creds file, user-placed
```

- **Generated credentials** (glass-break) → encrypted file at a user-chosen path (default `glassbreak/`), warned + offline.
- **Plaintext never on disk** except the explicit, warned **"Save unlocked"** export (`§8.1`/`DESIGN.md`). Large media via **decrypt-while-play** bounded RAM window.
- **Updates:** replace the signed exe (transparency-logged, offline signing key), fits in-person delivery; settings/keystore preserved.
- **Reset/recover:** delete `cache/`+`index/` to reclaim space (rebuilt on demand); keystore recovery via §4.3; "factory reset" clears `config/`/`settings` but warns before touching `keystore/`.

### 8.2 Server — self-extracting exe with bundled PostgreSQL (D-D)

A single launcher that unfolds a portable folder and supervises its dependencies, so it "just runs" for testing while preserving prod parity (real Postgres + schema).

```
MaxSecuServer/
  MaxSecuServer.exe         launcher: extracts, supervises, prints bootstrap secret on first run
  postgres/                 bundled PostgreSQL binaries + data dir (auto-initialized)
  server/                   maxsecu-server binary + embedded schema.sql (self-applied)
  tls/                      dev self-signed pinned cert (prod: real cert injected)
  sink/                     in-process dev sink (prod: external WORM/SIEM injected)
  config/                   ports, paths, runtime knobs (NO secrets)
  logs/                     server logs (sanitized to clients; full detail local)
```

- **Secrets injected at runtime, never baked in** (Dropbox token, sink creds) — `stack.md §5.1`, `DESIGN.md §16.6`.
- **Prod path unchanged:** static `x86_64-unknown-linux-musl` binary or `docker-compose.yml` against external Postgres + external sink + real TLS cert.
- **Reset/recover:** stop launcher, remove `postgres/data` + blob cache for a clean slate; first run re-bootstraps (new bootstrap secret).

---

## 9. Testing strategy

- **Unit / property:** new `client-app` orchestration + `ui` component logic; reuse existing core test suites unchanged.
- **Command-boundary tests:** every Tauri command's typed contract + event stream (the one integration seam).
- **The auto-connect scenario (e2e):** `portable-server` boots → **`ceremony-harness` scripts the local D5 ceremony** → client auto-connects → glass-break + first-admin bootstrap → user enrollment → approval → upload (image/blog) → browse/search → view → share, all over **real TLS** against the real server, mirroring the existing `server/tests/*_e2e.rs` style.
- **Feedback/state machines:** assert each state machine emits the documented transitions under **normal / slow / failure** (injected latency + faults), including resumable upload (drop+resume), cold-fetch progress, reconnect, session-expiry re-auth.
- **Accessibility:** automated axe-style checks in CI + manual NVDA/keyboard passes.
- **Packaging:** smoke-test that both self-extracting exes unfold, run, and tear down cleanly on a fresh Windows profile; client runs from a removable drive (portable check).
- **Security regressions:** reuse `sanitized_errors`, channel-binding, sink-anchor, and media-sandbox containment tests; add a check that the **UI never receives keys/whole-plaintext** across the command boundary.

---

## 10. Phased roadmap (vertical slices)

Each phase is independently runnable and tested before the next.

1. **Shell + connection + auth slice** — `client-app` + UI shell (Layout B), connection screen + auto-connect, keystore unlock, login, empty feed. e2e: connect+login against `portable-server`.
2. **Bootstrap + admin slice** — glass-break, first-admin, voucher enrollment, pending status, approval queue, ceremony harness. e2e: full bootstrap → approve.
3. **Browse + view slice** — feed/library, "my uploads", client-side title+tag search/sort, image + blog viewer, the full feedback layer for fetch/decrypt.
4. **Upload slice** — image/blog upload pipeline with preview-before-upload, active-uploads tray, resumable progress/ETA/retry.
5. **Settings + accessibility slice** — Settings + Quick-settings, RAM-cache controls, behavior toggles, a11y options; CI a11y checks.
6. **Packaging slice** — client portable exe + server self-extracting exe with bundled Postgres; portability + smoke tests.
7. **Video (later, gated by D-B)** — ratify the ffmpeg/dav1d C carve-out, build the AppContainer sandbox decode/transcode worker, light up the already-built player chrome and upload stub. Security-reviewed.

---

## 11. Restart prompt (paste into a fresh session after `/clear`)

> **Continue building the MaxSecu Media App from the approved design spec at `docs/superpowers/specs/2026-06-28-maxsecu-media-app-design.md`.** This is the user-facing client+server application layer built **on top of the existing MaxSecu zero-knowledge backend** in this repo (do not re-architect the backend; reuse `client-core`, `crypto`, `encoding`, `server`, `admin-core`, `sink-server`, `media-worker`).
>
> Implement the phased roadmap (spec §10) in order: (1) shell + connection + auth, (2) bootstrap + admin, (3) browse + view, (4) upload, (5) settings + accessibility, (6) packaging, (7) video is deferred behind the existing decode seam. Honor the locked decisions in spec §2: Tauri + WebView2 client with **vanilla TS + Web Components**; portable signed client `.exe` with password-derived at-rest state; **portable server exe bundling PostgreSQL**; **full high-assurance ceremony** trust model (script the existing air-gapped ceremony CLIs for tests); **portable keystore + recovery** identity (no password-derived keys); images+text now with the **video player UI built but codec gated**; client-side **title+tag** search; **status-only** pending users; **WCAG 2.1 AA**; **smart adaptive polling**. Keep the UI strictly outside the TCB across the Tauri command boundary — it must never receive private keys, signed-record interiors, or whole-plaintext buffers.
>
> Build the real-time feedback layer (spec §6) as typed state machines emitting progress/state events. Maintain MaxSecu's discipline: pinned/vendored deps, `cargo deny`/`cargo audit`, no new C dependency beyond the sanctioned `aws-lc-rs` (video's ffmpeg/dav1d carve-out is a separate, later, security-reviewed decision), reproducible + Authenticode-signed builds, sanitized errors, and the existing e2e test style over real TLS.
>
> **Work continuously through implementation, integration, testing, debugging, and validation without pausing for further questions.** Resolve issues independently; iterate with tests until each phase's e2e scenario (spec §9) passes, including the auto-connect bootstrap end-to-end. Only stop for a genuinely blocking external problem (out of disk, an unobtainable critical dependency, or a system-level constraint). Treat the task as complete only when all in-scope phases (1–6) are fully functional, integrated, tested, and verified, and the auto-connect scenario passes end-to-end.

---

## 12. Open items deliberately deferred

- Real **video** codec + sandbox worker (D-B, §10.7) — separate security-reviewed effort.
- Real **Dropbox** cold-tier adapter, real third-party **WORM/SIEM sink**, real **CI + Authenticode cert** — existing MaxSecu deferrals (`MEMORY`/`stack.md §3`); the portable dev profile uses in-process/self-signed stand-ins.
- **zstd** compression stays `none` until a vetted pure-Rust encoder exists (`stack.md §2.5`).
- **Server-push** sync (rejected in favor of smart polling, D-I) — revisit if near-instant updates become a requirement.
