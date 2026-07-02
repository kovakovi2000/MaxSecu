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
├── styles.css              # design system: tokens, theme, a11y, layout (215 lines)
├── package.json            # scripts + pinned dev deps
├── tsconfig.json
└── src/
    ├── main.ts             # entry: imports <app-shell> (that's all)
    ├── core/               # framework-free logic (no DOM in most; unit-tested)
    │   ├── rpc.ts          # call() / on()  — the ONLY Tauri bridge wrapper (§3)
    │   ├── router.ts       # hash router (#/route?query) → Route enum
    │   ├── serial.ts       # single-flight queue for backend calls (§4) — CRITICAL
    │   ├── viewer-open.ts  # viewer open orchestration (see §7 cautionary tale)
    │   ├── settings.ts     # settingsStore + applySettings + load/update (§5 theming)
    │   ├── settings-store.ts # reactive store backing settings
    │   ├── store.ts        # tiny reactive store primitive
    │   ├── session.ts      # current-username singleton
    │   ├── toast.ts        # toast pub/sub (success/info/error)
    │   ├── tasks.ts        # active-tasks counter (binds upload + fetch events)
    │   ├── types.ts        # TS mirrors of every backend DTO (KEEP IN SYNC — §3)
    │   ├── player.ts       # video A/V sync + ring buffer (player chrome logic)
    │   └── webgl-yuv.ts    # WebGL YUV(I420)→RGB shader for the video surface
    └── components/         # Web Components (one custom element each)
        ├── app-shell.ts        # top-level shell: header, nav rail, router, outlet
        ├── status-pill.ts      # connection-state indicator
        ├── connect-screen.ts   # unlock keystore + connect
        ├── bootstrap-screen.ts # first-run glass-break + first-admin provisioning
        ├── pending-screen.ts   # "awaiting approval" status (adaptive polling)
        ├── admin-screen.ts     # approval queue + voucher issuance (admin only)
        ├── feed-screen.ts      # the feed / library grid (also #/mine variant)
        ├── media-card.ts       # one feed item (self-decrypting card → "View")
        ├── media-viewer.ts     # one opened post (image / blog text / video player)
        ├── video-player.ts     # sandboxed-video playback chrome (WebGL canvas)
        ├── upload-screen.ts    # compose + preview + confirm an upload
        ├── upload-tray.ts      # persistent active-uploads tray (progress/retry)
        ├── settings-screen.ts  # full settings (appearance, a11y, account, RAM)
        ├── ram-gauge.ts        # header RAM-usage rainbow meter
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

**Tauri arg convention:** an argument object's keys are the command's Rust parameter
names. Commands whose Rust signature is `(req: SomeRequest, …)` are invoked as
`call("cmd", { req: { …fields… } })`. Commands with scalar params (e.g.
`(file_id: String, pts_ms: u64)`) are invoked as `call("cmd", { file_id, pts_ms })`.
All field names are **snake_case**; all enum string values are **kebab-case**.

### 3.1 Commands

| Command | Invoke args | Returns | Used by |
|---|---|---|---|
| `connect` | `{ req: { server, username, use_tor } }` | `{ server_id }` | connect-screen |
| `unlock_keystore` | `{ password }` | `void` | connect-screen |
| `logout` | `{}` | `void` | (header / settings) |
| `list_feed` | `{ req: { filter, sort, limit? } }` | `FeedEntry[]` | feed-screen |
| `decrypt_card` | `{ req: { file_id, version? } }` | `Card` | media-card |
| `open_content` | `{ req: { file_id, version? } }` | `OpenedContent` | media-viewer |
| `search_local` | `{ req: { query } }` | `SearchHit[]` | feed-screen |
| `pick_file` | `{ extensions: string[] }` | `string \| null` (chosen path, or null if cancelled) | upload-screen (image **and** video file picks) |
| `register_glassbreak` | `{ req: { bootstrap_secret, save_path? } }` | `GlassbreakResponse` | bootstrap-screen |
| `create_first_admin` | `{ req: { username, password, bootstrap_secret } }` | `string` (user_id) | bootstrap-screen |
| `register_user` | `{ req: { username, password, voucher } }` | `string` (user_id) | (enrollment) |
| `account_status` | `{ req: { username } }` | `AccountStateMsg` | connect/pending |
| `list_pending` | `{}` | `PendingUserDto[]` | admin-screen |
| `issue_voucher` | `{}` | `{ code }` | admin-screen |
| `request_approval` | `{ req: { user_id } }` | `CeremonyWorkItem` | admin-screen |
| `stage_upload` | `{ req: StageUploadRequest }` | `UploadPreview` | upload-screen |
| `confirm_upload` | `{ req: { job_id } }` | `void` (emits `upload-state`) | upload-screen |
| `cancel_upload` | `{ req: { job_id } }` | `void` | upload-tray |
| `upload_jobs` | `{}` | `UploadJobView[]` | upload-tray |
| `get_settings` | `{}` | `Settings` | settings, boot |
| `set_settings` | `{ settings: Settings }` | `Settings` (normalized) | settings/quick |
| `change_password` | `{ req: { old_password, new_password } }` | `void` | settings-screen |
| `export_keystore` | `{ req: { dest_path } }` | `void` | settings-screen |
| `ram_limits` | `{}` | `{ default_mb, min_mb, max_mb }` | settings/quick |
| `open_video` | `{ file_id }` | `void` (streams via events) | video-player |
| `video_seek` | `{ file_id, pts_ms }` | `void` | video-player |
| `video_set_volume` | `{ file_id, gain }` | `void` | video-player |
| `cancel_video` | `{ file_id }` | `void` | video-player |
| `preview_video` | `{ job_id }` | `void` (streams via events) | upload-screen |

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
| `maxsecu://account-state` | `{ state }` — `unknown\|pending\|active` |
| `maxsecu://fetch-state` | `{ phase, file_id, … }` — `fetching{fetched,total}\|verifying\|decrypting\|ready\|failed{code}` |
| `maxsecu://upload-state` | `{ phase, job_id, … }` — `encrypting\|staging\|uploading{done,total}\|finalizing\|done{file_id}\|failed{code}` |
| `maxsecu://player-state` | `{ phase, … }` — `buffering\|playing\|gap{skipped}\|stalled\|error{code}\|codec-unavailable` |
| `maxsecu://video-frame` | `I420FrameDto { width, height, pts_ms, y_b64, u_b64, v_b64 }` |
| `maxsecu://video-audio` | `PcmDto { channels, sample_rate, pts_ms, samples_b64 }` |

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
- Unauthenticated commands (`get_settings`, `ram_limits`, `account_status`,
  bootstrap commands, `search_local`) do **not** need the queue.

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
| `data-theme` | `dark` (default) \| `light` | color scheme. `dark` is baked into `index.html` to avoid a flash. |
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
- The ⚡ quick‑settings button is **hidden on the Settings screen** (`r === "settings"`
  toggles `[hidden]` on it). It exposes **Theme + RAM only**.
- A persistent **upload tray** lives in the header (outside the routed outlet) so
  upload progress survives navigation.
- There is a **status strip** with the connection pill + an active‑tasks count.

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

`connect` · `feed` · `mine` (feed filtered to my uploads) · `bootstrap` · `pending` ·
`admin` · `viewer` · `upload` · `settings`. Unknown → `connect`.

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
