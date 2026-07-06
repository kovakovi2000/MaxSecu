# MaxSecu Client — Frontend Guide (for a UI rework)

This document is a handoff for reworking the **look & feel** of the MaxSecu desktop
client's UI. The frontend is the WebView layer of a **Tauri 2** app: a vanilla
**TypeScript + Web Components** SPA that talks to a Rust backend over the Tauri
command/event bridge.

You may freely redesign **layout, styling, components, interactions, and motion**.
You may **not** change the **backend contract** (the command names, argument shapes,
return shapes, and event payloads in §3) or the **security invariants** (§5) — those
are enforced by a Rust trusted core and by tests. Break the contract and the app
stops working or stops being safe.

> **Context you don't need to fully understand, but should respect:** MaxSecu is a
> zero‑knowledge, end‑to‑end‑encrypted media app. All cryptography, key handling,
> verification, and network I/O happen in the **Rust backend** (the "TCB" — Trusted
> Computing Base). The UI is deliberately **outside** the TCB: it only ever receives
> already‑decrypted, render‑ready data (an image's PNG bytes, a blog's sanitized
> text) and never sees keys, tokens, or ciphertext. Keep it that way.

---

## 1. Tech stack & build

| Thing | Value |
|---|---|
| Shell | Tauri 2 (Rust) + system WebView (WebView2 on Windows) |
| UI framework | **None** — vanilla TS + native Web Components (Custom Elements) |
| Language | TypeScript 5.4 (type‑checked; runtime is plain ESM via stripping) |
| Bundler | **esbuild 0.21.5** (`src/main.ts` → `dist/main.js`, one ESM bundle) |
| Tests | `node --test` (node's built‑in runner; no Jest/Vitest), `--experimental-strip-types` |
| Tauri API | `@tauri-apps/api` 2.1.1 (`invoke`, `listen`) |

Commands (run from this `ui/` directory):

```bash
npm install            # restore dev deps (node_modules is gitignored)
npm run build          # esbuild bundle → dist/main.js + copy index.html, styles.css
npm run typecheck      # tsc --noEmit (must stay clean)
npm test               # unit tests (node:test)
npm run test:a11y      # accessibility structural lint (must stay green — see §6)
```

**Important build fact:** the Tauri executable **embeds `ui/dist/` at compile time**.
After changing the UI you must `npm run build`, then rebuild the Rust app, for the
change to appear in the running `.exe`. (During pure‑UI iteration you can serve
`dist/` standalone with a mocked bridge — see §8.)

### Why no framework?
The project ships **reproducible, auditable builds** and keeps the UI dependency
surface tiny on purpose (one runtime dep: `@tauri-apps/api`). If you want to
introduce a framework (React/Svelte/Vue/etc.), that is a **product decision for the
owner**, not a given — it changes the build, the bundle size, the audit story, and
the CSP. Default assumption: **stay vanilla TS + Web Components**. If you do switch,
you must preserve everything in §3, §5, and §6.

---

## 2. App structure

```
ui/
├── index.html              # shell HTML: <app-shell>, skip link, base inline CSS, CSP-safe
├── styles.css              # design system: tokens, theme, a11y, layout (~1980 lines)
├── package.json            # scripts + pinned dev deps
├── tsconfig.json
└── src/
    ├── main.ts             # entry: imports <app-shell> (that's all)
    ├── core/               # framework-free logic (no DOM in most; unit-tested)
    │   ├── rpc.ts          # call() / on()  — the ONLY Tauri bridge wrapper (§3)
    │   ├── router.ts       # hash router (#/route?query) → Route enum
    │   ├── serial.ts       # single-flight queue for backend calls (§4) — CRITICAL
    │   ├── busy.ts         # global "backend busy / nav-locked" flag (transcode/upload guard)
    │   ├── viewer-open.ts  # viewer open orchestration (see §7 cautionary tale)
    │   ├── card-view.ts, card-retry.ts # media-card decode state + bounded retry
    │   ├── pool.ts         # bounded worker pool for parallel feed card decode
    │   ├── bundle-view.ts  # bundle Gallery/Stacked view-mode state (remember-last)
    │   ├── composer.ts     # bundle composer model (add/reorder/remove items)
    │   ├── download.ts, download-name.ts # download orchestration + safe filename derivation
    │   ├── confirm.ts      # promise-based confirm-dialog primitive
    │   ├── transcode-opts.ts # resolution/bitrate menu model (mirrors Rust TranscodeOptions)
    │   ├── gauge.ts        # RAM/cache gauge math (used/total → %, colour band)
    │   ├── format.ts       # byte/duration/number formatting helpers
    │   ├── trust-alarm.ts  # directory trust-alarm (split-view / first-contact) banner state
    │   ├── settings.ts     # settingsStore + applySettings + load/update (§5 theming)
    │   ├── settings-store.ts # reactive store backing settings
    │   ├── store.ts        # tiny reactive store primitive
    │   ├── session.ts      # current-username singleton
    │   ├── toast.ts        # toast pub/sub (success/info/error)
    │   ├── tasks.ts        # active-tasks counter (binds upload + fetch events)
    │   └── types.ts        # TS mirrors of every backend DTO (KEEP IN SYNC — §3)
    │   # NB: video is now native <video> — the old player.ts / webgl-yuv.ts
    │   #     (WebGL YUV→RGB sandbox surface) were retired with the decode sandbox.
    └── components/         # Web Components (one custom element each)
        ├── app-shell.ts        # top-level shell: header, nav rail, router, outlet
        ├── status-pill.ts      # connection-state indicator
        ├── connect-screen.ts   # unlock keystore + connect
        ├── register-screen.ts  # registration-key enrollment panel
        ├── recovery-login-screen.ts # cold recovery challenge-response login
        ├── admin-screen.ts     # registration-key minting (admin only)
        ├── feed-screen.ts      # the feed / library grid (also #/mine variant)
        ├── media-card.ts       # one feed item (self-decrypting card → View/Download/Delete; bundle badge)
        ├── media-viewer.ts     # one opened post (image / blog text / native video)
        ├── video-player.ts     # native <video> playback chrome (Media Chrome controls)
        ├── video-src.ts        # builds the stream:// source URL for the native player
        ├── bundle-screen.ts    # opened bundle: Gallery ⇄ Stacked toggle + Download-all
        ├── bundle-composer.ts  # compose a bundle (add/reorder/remove/preview/post)
        ├── upload-screen.ts    # compose + preview + confirm an upload (image/blog/video)
        ├── upload-tray.ts      # persistent active-uploads tray (progress/retry)
        ├── share-dialog.ts     # reshare modal: tickable contacts checklist + manual input
        ├── share-tray.ts       # persistent active-reshare tray
        ├── trust-alarm.ts      # directory trust-alarm banner (split-view / first-contact)
        ├── settings-screen.ts  # full settings (appearance, a11y, account, privacy, RAM/cache, concurrency)
        ├── ram-gauge.ts        # header RAM-usage meter
        ├── toast-host.ts       # renders toasts (assertive/polite live regions)
        ├── skeleton-card.ts    # shimmer placeholder while loading
        ├── state-badge.ts      # non-color-only status chip
        └── progress-meter.ts   # accessible progress bar
```

`*.test.ts` files sit next to their module and run under `node:test`.

---

## 3. The backend contract (DO NOT BREAK)

The UI calls the backend with **`call(command, args)`** and subscribes to pushed
state with **`on(eventName, cb)`** — both from `src/core/rpc.ts`:

```ts
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
export async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  return invoke<T>(cmd, args);          // REJECTS with a UiError on failure (§3.3)
}
export function on<T>(event: string, cb: (p: T) => void): Promise<() => void> {
  return listen<T>(event, (e) => cb(e.payload));   // resolves to an unlisten fn
}
```

**Tauri arg convention (IMPORTANT — two different casings):**
- **Top-level scalar params are camelCase in JS.** Tauri v2 auto-converts the JS key
  to the snake_case Rust parameter, so a Rust signature `(file_id: String, pts_ms: u64)`
  is invoked as `call("cmd", { fileId, ptsMs })` — **not** `{ file_id, pts_ms }` (that
  silently fails to bind and the call rejects). Real examples: `open_video` → `{ fileId }`,
  `cache_stats` → `{ mediaCapBytes, thumbCapBytes }`, `save_file` → `{ defaultName }`.
- **Struct params keep snake_case fields.** A signature `(req: SomeRequest, …)` is invoked
  as `call("cmd", { req: { …fields… } })`; the wrapper key (`req` / `settings`) is one word,
  and the struct's fields are serde-serialized under their **snake_case** Rust names.
- Enum string values are **kebab-case**.

> In the tables below, scalar keys are written in snake_case for readability, but at the
> call site a scalar key must be **camelCased** (per the first bullet). `req: {…}` field
> names stay snake_case as shown.

### 3.1 Commands

> This table is the authoritative **list** of commands (matches `main.rs`'s
> `generate_handler!`). For the exact field shapes of every `req: …` payload and
> return DTO, the **single source of truth is `src/core/types.ts`** (and, behind it,
> each command's Rust signature). A UI rework does **not** change any of these.

**Session / connection**

| Command | Invoke args | Returns | Used by |
|---|---|---|---|
| `connect` | `{ req: { server, username, use_tor } }` | `{ server_id }` | connect-screen |
| `unlock_keystore` | `{ password }` | `void` | connect-screen |
| `logout` | `{}` | `void` | header / settings |
| `startup_mode` | `{}` | `StartupMode` (`normal\|register\|recovery`) | app-shell boot |

**Enrollment / recovery / admin**

| Command | Invoke args | Returns | Used by |
|---|---|---|---|
| `register_with_key` | `{ req: RegisterRequest }` | `RegisteredDto` | register-screen |
| `request_recovery_challenge` | `{ passphrase }` | `RecoveryChallengeDto` | recovery-login-screen |
| `answer_recovery_challenge` | `{}` | `RecoveryLoginDto` | recovery-login-screen |
| `mint_registration_key` | `{ destPath }` | `string` (saved path; the key is written to that file, never returned) | admin-screen |

**Browse / view**

| Command | Invoke args | Returns | Used by |
|---|---|---|---|
| `list_feed` | `{ req: { filter, sort, limit? } }` | `FeedEntry[]` | feed-screen |
| `decrypt_card` | `{ req: { file_id, version? } }` | `Card` | media-card |
| `open_content` | `{ req: { file_id, version? } }` | `OpenedContent` | media-viewer |
| `open_bundle` | `{ req: { file_id, version? } }` | `BundleView` | bundle-screen |
| `search_local` | `{ req: { query } }` | `SearchHit[]` | feed-screen |

**Download / delete / share**

| Command | Invoke args | Returns | Used by |
|---|---|---|---|
| `download_content` | `{ req: DownloadRequest }` | `string` (saved path) | media-card / viewer / bundle |
| `delete_content` | `{ req: DeleteRequest }` | `void` | media-card (owner-only) |
| `reshare_file` | `{ req: ReshareRequest }` | `ReshareOutcomeDto[]` | share-dialog |
| `reshare_bundle` | `{ req: ReshareRequest }` | `ReshareOutcomeDto[]` | share-dialog |
| `resolve_recipient` | `{ req: ResolveRecipientRequest }` | `ResolvedRecipientDto` | share-dialog |
| `list_file_recipients` | `{ file_id }` | `string[]` | share-dialog |
| `list_contacts` | `{}` | `ContactDto[]` | share-dialog |

**File pickers**

| Command | Invoke args | Returns | Used by |
|---|---|---|---|
| `pick_file` | `{ extensions: string[] }` | `string \| null` | upload-screen (image **and** video picks) |
| `pick_files` | `{ extensions: string[] }` | `string[]` | bundle-composer |
| `save_file` | `{ default_name }` | `string \| null` | download flows |
| `pick_folder` | `{}` | `string \| null` | dest picking |

**Upload (single + bundle)**

| Command | Invoke args | Returns | Used by |
|---|---|---|---|
| `stage_upload` | `{ req: StageUploadRequest }` | `UploadPreview` | upload-screen |
| `stage_bundle` | `{ req: StageBundleRequest }` | `BundlePreview` | bundle-composer |
| `confirm_upload` | `{ req: { job_id } }` | `void` (emits `upload-state`) | upload-screen |
| `confirm_bundle` | `{ req: { job_id } }` | `string` (bundle id) | bundle-composer |
| `retry_confirm` | `{ req: { job_id } }` | `void` | upload-tray |
| `cancel_upload` | `{ req: { job_id } }` | `void` | upload-tray |
| `cancel_bundle` | `{ req: { job_id } }` | `void` | bundle-composer |
| `cancel_video_prepare` | `{ req: { job_id } }` | `void` | upload-screen |
| `resume_upload` | `{ req: { job_id } }` | `void` | upload-tray |
| `upload_jobs` | `{}` | `UploadJobView[]` | upload-tray |
| `list_pending_uploads` | `{}` | `PendingUploadDto[]` | upload-tray |
| `dismiss_pending_upload` | `{ req: { job_id } }` | `void` | upload-tray |

**Settings / account**

| Command | Invoke args | Returns | Used by |
|---|---|---|---|
| `get_settings` | `{}` | `Settings` | settings, boot |
| `set_settings` | `{ settings: Settings }` | `Settings` (normalized) | settings-screen |
| `change_password` | `{ req: { old_password, new_password } }` | `void` | settings-screen |
| `export_keystore` | `{ req: { dest_path } }` | `void` | settings-screen |
| `system_cores` | `{}` | `number` | settings-screen (concurrency) |

**RAM / cache**

| Command | Invoke args | Returns | Used by |
|---|---|---|---|
| `ram_limits` | `{}` | `{ default_mb, min_mb, max_mb }` | settings |
| `memory_stats` | `{}` | `MemoryStats` | ram-gauge |
| `cache_stats` | `{ media_cap_bytes, thumb_cap_bytes }` | `CacheStats` | settings (gauges) |
| `clear_media_cache` | `{}` | `void` | settings |
| `clear_thumb_cache` | `{}` | `void` | settings |

**Video (native `<video>`)**

| Command | Invoke args | Returns | Used by |
|---|---|---|---|
| `open_video` | `{ file_id }` | `void` (starts the stream; native element then seeks/plays) | video-player |
| `cancel_video` | `{ file_id }` | `void` | video-player |

> Native `<video>` handles seek/volume/scrubbing itself, so the old
> `video_seek` / `video_set_volume` / `preview_video` commands are **gone**.

`StageUploadRequest = { kind: "image"|"blog"|"video", path?, content?, options?, title, tags? }`
(image → `path`; blog → `content`; video → `path` (a REAL video file path) +
`options: TranscodeOptions`). The video path is picked via `pick_file` with video
extensions (`mp4 mov mkv webm avi m4v mpg mpeg wmv flv ts`) — only the PATH crosses
the seam; the confined ffmpeg ingest reads the bytes. (The old MXRAWV01 raw-frame
`source_b64` video path is GONE.)

`TranscodeOptions = { resolution: Resolution, bitrate: Bitrate }` — built by the
upload screen's resolution/bitrate menu (`core/transcode-opts.ts`). Its JSON shape
mirrors the Rust `media-launcher::TranscodeOptions` enum byte-for-byte (externally
tagged: a unit variant is the bare string; a single-field variant is `{ Variant: value }`):

- `Resolution`: `"Original"` (keep source) · `{ "Height": n }` (height presets 2160/1440/1080/720/480) · `{ "Custom": { "width": W, "height": H } }`.
- `Bitrate`: `"Original"` (keep source) · `{ "Kbps": n }`.

The menu auto-suggests a starting kbps from the target resolution's nominal dims at
30 fps when you pick a non-Original resolution (you can edit it); the Rust side always
re-clamps against the authoritative `VideoBounds`.

### 3.2 Events (backend → UI, via `on(name, cb)`)

Each payload is an **internally‑tagged** union: the discriminator field is shown
first. Subscribe and switch on it.

| Event name | Payload |
|---|---|
| `maxsecu://connection-state` | `{ state }` — `idle\|resolving\|tls-handshake\|channel-binding\|connected\|reconnecting\|disconnected\|degraded` |
| `maxsecu://auth-state` | `{ state }` — `logged-out\|unlocking-keystore\|authenticating\|logged-in\|session-expired\|reauthenticating` |
| `maxsecu://fetch-state` | `{ phase, file_id, … }` — `fetching{fetched,total}\|verifying\|decrypting\|ready\|failed{code}` |
| `maxsecu://upload-state` | `{ phase, job_id, … }` — `encrypting\|staging\|uploading{done,total}\|finalizing\|done{file_id}\|failed{code}` |
| `maxsecu://bundle-stage` | `{ phase, … }` — per-member bundle staging progress |
| `maxsecu://reshare-state` | `{ phase, … }` — per-recipient reshare progress |
| `maxsecu://player-state` | `{ phase, … }` — `buffering\|playing\|gap{skipped}\|stalled\|error{code}\|codec-unavailable` |
| `maxsecu://video-prepare` | `{ phase, … }` — local transcode/prepare progress before an upload |

> Because video is now a **native `<video>`** element, the decoded-frame stream is
> gone: the old `maxsecu://video-frame` / `maxsecu://video-audio` events (raw I420 /
> PCM) and `maxsecu://account-state` are **retired**. Don't reintroduce listeners for them.

These names are defined in the Rust source as constants (`EVT_*`). **Use the exact
strings.** The full TS shapes live in `src/core/types.ts` — keep that file in sync if
the backend ever changes (it won't as part of a UI rework).

### 3.3 Errors

A failed command **rejects** the `call()` promise with a sanitized error object:

```ts
{ code: string, message: string }   // e.g. { code: "offline", message: "The server did not respond." }
```

Callers own rejection handling. Convention in this codebase: show `message` in a
status line and/or an error toast. Never assume a thrown value is an `Error`
instance; read `.message` defensively (see `viewerErr`/`errMsg` helpers).

---

## 4. The serial queue (concurrency — CRITICAL)

The backend re‑authenticates on a fresh channel per authenticated call and can only
run **one such call at a time** (it `try_lock`s a single connect lock and borrows a
single non‑`Clone` identity). If the UI fires two authenticated commands
concurrently, the second fails with `{ code: "busy" }`.

So **all authenticated calls go through `src/core/serial.ts`**, a single‑flight FIFO
queue:

```ts
import { serial, serialPriority, cancelPending } from "../core/serial.ts";

serial(() => call("decrypt_card", { req }));       // normal: FIFO
serialPriority(() => call("open_content", { req })); // jumps ahead of queued normals
cancelPending();   // reject everything still QUEUED (e.g. on leaving a screen)
```

Rules when reworking:
- Any component that calls an **authenticated** backend command must wrap it in
  `serial(...)` (or `serialPriority(...)` for user‑initiated foreground actions like
  opening the viewer over a backlog of card decrypts).
- Call `cancelPending()` from a screen's teardown (`disconnectedCallback`) if it
  enqueued background work (the feed does this), so a backlog can't wedge the lock.
- Unauthenticated commands (`get_settings`, `ram_limits`, `register_with_key`,
  `search_local`) do **not** need the queue.

---

## 5. Security & accessibility invariants (DO NOT BREAK)

1. **Content Security Policy** (from `tauri.conf.json`):
   `default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'`
   - No remote origins. No `script-src` beyond self → **no inline `<script>`, no
     `eval`, no CDN**. Bundle everything.
   - Images/thumbnails render from **`data:` URLs** built from base64 the backend
     returns (`data:image/png;base64,…`). That's why `img-src` allows `data:`.
   - `style-src 'unsafe-inline'` permits inline styles / `<style>`; you may keep
     using them. If you add a new external resource type you must update the CSP
     **and** justify it (security‑reviewed).

2. **No HTML injection.** User/content strings are rendered with **`textContent`**
   or DOM construction — **never** `innerHTML` with interpolated values. Blog bodies
   are shown via `pre.textContent`. The a11y lint (below) **fails** on any `${…}`
   inside an `innerHTML` template literal. Static `innerHTML` (no interpolation) is
   fine for fixed scaffolding.

3. **No secrets in the UI.** The backend never sends keys, tokens, ciphertext, or
   bundle interiors across the bridge. The only sensitive things that legitimately
   cross are passwords **going in** (to `unlock_keystore`/`change_password`) — pass
   them straight to the command and don't retain/log them.

4. **Accessibility — WCAG 2.1 AA.** This is a hard requirement and is **lint‑gated**
   (`npm run test:a11y`, a structural check in `src/a11y.test.ts`). Per routed
   screen the lint requires:
   - a focusable landmark with `id="main"` (`<main id="main" tabindex="-1">`),
   - **focus moved to `#main` on route change** (the shell does this; keep it),
   - a live region (`role="status"`/`aria-live`) for async status,
   - **no unescaped `${}` inside `innerHTML`** (XSS rule #2 above),
   - non‑color‑only status (icon/text + color — see `state-badge`),
   - a working **skip link** and visible **`:focus-visible`** outlines.

   If you restructure components, **keep these or the lint (and the merge) fails.**
   You may extend the lint, not weaken it.

5. **UI stays outside the TCB.** Don't move verification, crypto, or network logic
   into the frontend. Display what the backend gives you.

---

## 6. Theming & design tokens

Theme and accessibility preferences are driven by **attributes on `<html>`**, set by
`applySettings()` in `src/core/settings.ts`, and consumed by `styles.css`:

| Attribute | Values | Meaning |
|---|---|---|
| `data-theme` | `tech` (default) \| `cheese` \| `pottery` | frontend visual theme preset. `tech` is baked into `index.html` to avoid a flash. |
| `data-reduced-motion` | present/absent | when present, motion/animation must be zeroed. `styles.css` also honors `@media (prefers-reduced-motion)`. |
| `data-high-contrast` | present/absent | high‑contrast adjustments |
| `data-text-size` | `normal` \| `large` \| `larger` | scales the **root font size** so the whole UI scales (use `rem`). |

The single source of truth for live settings is the reactive **`settingsStore`**
(`core/settings.ts`). The settings screen, the ⚡ quick‑settings popover, and the
shell theme all read/write that one store via `updateSettings(patch)` (which also
persists to the backend and re‑applies). When you redesign these controls, keep them
bound to the store so they stay in sync and apply live.

`styles.css` currently defines the design system with CSS custom properties (color
tokens, accent, surfaces, motion tokens, spacing). You may replace the visual design
wholesale — just keep keying off the four `data-*` attributes above and keep using
`rem` for text so `data-text-size` works.

A couple of layout facts the current UI relies on (preserve the behavior, restyle
freely):
- The header carries a standalone **`<ram-gauge>`** meter (the old ⚡ quick‑settings
  popover was removed — full appearance/RAM controls now live only on the Settings screen).
- A persistent **upload tray** *and* a **share tray** live in the header (outside the
  routed outlet) so upload/reshare progress survives navigation.
- There is a **status strip** with the connection pill + an active‑tasks count.
- A **trust‑alarm** banner can appear (directory split‑view / first‑contact) — it must
  read as a high‑priority, non‑color‑only alert.

---

## 7. How a screen wires to the backend (and one cautionary tale)

Pattern for a custom element:

```ts
import { call, on } from "../core/rpc.ts";
import { serial } from "../core/serial.ts";

class MyScreen extends HTMLElement {
  private cleanup: (() => void) | null = null;
  connectedCallback() {
    this.innerHTML = `<main id="main" tabindex="-1">…<p id="status" role="status" aria-live="polite"></p></main>`;
    (this.querySelector("#main") as HTMLElement).focus();
    // subscribe to pushed state — FIRE AND FORGET (see below)
    on("maxsecu://some-state", (m) => { /* update DOM */ }).then(u => { this.cleanup = u; });
    // do the actual work
    serial(() => call("some_command", { req: {/*…*/} }))
      .then(data => { /* render */ })
      .catch(err => { /* show err.message */ });
  }
  disconnectedCallback() { this.cleanup?.(); }
}
customElements.define("my-screen", MyScreen);
```

> **Cautionary tale (a real bug fixed here):** the viewer used to **`await` the
> status‑event subscription before calling `open_content`**. If `listen()` didn't
> settle, the content open was never dispatched and the screen hung on "Loading…"
> forever. **A backend call must never be gated behind a status/event subscription.**
> Subscribe fire‑and‑forget; do the real work independently. This orchestration now
> lives in `core/viewer-open.ts` (`runViewerOpen`) and is unit‑tested
> (`viewer-open.test.ts`) precisely against this failure mode. Follow that pattern.

---

## 8. Iterating on the UI without rebuilding the Rust app

The bundle is plain ESM + Web Components, so you can develop the visuals against a
**mock bridge**. The whole backend surface is just `invoke` + `listen`. Provide a
stub before `main.js` loads, e.g. in a dev `index.html`:

```html
<script>
  window.__TAURI_INTERNALS__ = { /* or shim @tauri-apps/api in your dev server */ };
</script>
```

…or, more simply, point `core/rpc.ts` at a mock during dev that returns canned
`Card`/`OpenedContent`/`FeedEntry[]` objects (shapes in `types.ts`) and pushes fake
events. Build the look against those fixtures, then `npm run build` and rebuild the
Rust app to see it live. (The fixtures in `*.test.ts` are good sample data.)

To run the real app end‑to‑end you need the desktop build; the client connects to a
server at **`localhost:8443`** (its TLS cert is for `localhost`, not `127.0.0.1`).

---

## 9. Routes

Hash‑based, parsed by `core/router.ts` (`#/route?query`; the query is preserved in
`location.hash` for the screen to read, e.g. the viewer reads `?id=…&v=…`).

`connect` · `feed` · `mine` (feed filtered to my uploads) · `register` · `recovery` ·
`admin` · `viewer` · `bundle` · `upload` · `settings`. Unknown → `connect`.
(The old `bootstrap` / `pending` routes were retired with the voucher/pending
enrollment flow; enrollment is now `register` + admin `mint_registration_key`.)

The shell (`app-shell.ts`) maps each route to a component in the `#outlet`, sets the
active nav state, moves focus to `#main`, and toggles the ⚡ button's visibility.

---

## 10. Checklist before you call a rework "done"

- [ ] `npm run typecheck` clean
- [ ] `npm test` green (and add tests for new logic — node:test)
- [ ] `npm run test:a11y` green (extend it for new screens; never weaken it)
- [ ] `npm run build` succeeds; app rebuilt and visually verified
- [ ] Every command/event in §3 still called with the exact name/args/shape
- [ ] Authenticated calls go through `serial`/`serialPriority` (§4)
- [ ] No `${}` in `innerHTML`; content via `textContent`/DOM (§5.2)
- [ ] CSP unchanged (or changes justified); images via `data:` URLs (§5.1)
- [ ] WCAG AA preserved: `#main` landmark + focus on route change + live regions +
      visible focus + skip link + non‑color‑only status (§5.4)
- [ ] Theme/a11y still driven by the `data-*` attributes + `settingsStore` (§6)
- [ ] No keys/tokens/ciphertext handled in the UI (§5.3)
```

---

## 11. Multi-frontend architecture (the drop-in contract)

The client hosts **three switchable frontends** over ONE shared component tree and
backend. A frontend is a named visual skin with three parts:

- **Registry entry** `{ id, label }` in `src/core/frontends.ts` (`FRONTENDS`).
- **A complete stylesheet** it owns: `styles.<id>.css`, loaded via a single
  `<link id="frontend-css">` in `index.html`. Exactly one is active at a time.
- **An optional decoration module** `src/frontends/<id>/deco.ts` implementing
  `DecoModule` (below), bundled into `main.js`.

Registered ids: `default` (→ `styles.css`, today's design, verbatim),
`pizza` (→ `styles.pizza.css`, this brief), `slot3` (→ `styles.slot3.css`, empty).

Switching (`src/core/frontends.ts::applyFrontend`) rewrites the `<link>` href, sets
`data-frontend="<id>"` on `<html>`, unmounts the old deco module, mounts the new one,
and persists the id in `localStorage["maxsecu.frontend"]`. An inline bootstrap in
`index.html` applies the persisted frontend before first paint (no flash).

### The `DecoModule` interface

    export interface DecoModule {
      // Idempotent. Called once on apply AND after every route render. Query your slot
      // (e.g. document.querySelector('[data-deco-slot="login"]')) and inject decoration
      // only if you have not already (guard by a data-attr/class you own). Safe no-op if
      // the slot is absent on the current screen.
      mount(doc: Document): void;
      // Remove every node your mount() injected (called when switching away).
      unmount(doc: Document): void;
    }

### Decoration slots (stable mount points in the shared components)

- `data-deco-slot="login"` — on the `<main>` of connect / register / recovery-login.
- `data-deco-slot="app-bg"` — a body-level full-page layer in `app-shell`.
- `data-deco-slot="header"` — inside the app header.

Default/`slot3` leave these empty. Your `pizza` deco fills them. Slots are inert when
empty — do NOT change component markup, layout, or spacing; only add children to slots.

### What the pizza design delivers (drops into the `pizza` slot)

1. `styles.pizza.css` — a COMPLETE standalone stylesheet (replaces the stub, which is
   just `@import url("styles.css");`). **Preserve every spacing/layout/type token and
   the component structure** from `styles.css` — change only colour, texture, imagery,
   borders, shadows, and decorative styling. The spacing of elements must stay identical.
2. `src/frontends/pizza/deco.ts` — the real `DecoModule` (replaces the no-op stub),
   placing `assets/pizza.png` into `data-deco-slot="login"` and any cheese-drip layers.

Do NOT touch `src/core/rpc.ts`, `types.ts`, command/event names, argument shapes, the
serial queue (§4), or the security/a11y invariants (§5). This is look-and-feel only.
