# Native `<video>` Streaming Player over a `stream://` Range Protocol

**Date:** 2026-07-01
**Branch:** `feat/universal-video-ingest`
**Status:** Design approved; spec under review.
**Supersedes (view path only):** the hand-rolled canvas decode engine from
`docs/superpowers/specs/2026-07-01-video-player-streaming-and-chrome-design.md`
and its Stage-1 plan `docs/superpowers/plans/2026-07-01-video-player-streaming-engine.md`.

## Problem

The current player renders video by decoding frames in a confined pure-Rust
worker (`media-worker.exe`) and shipping I420 frames + PCM to a canvas + WebAudio,
with a hand-rolled A/V engine (`core/player.ts`) re-deriving the clock, buffering,
seek, and A/V sync that a browser media stack already does. In practice it is
broken: playback rolls back randomly, audio desyncs, fragments drop out, and a
59-second clip could hang. Re-deriving a correct streaming media engine by hand is
the wrong investment.

## Decision

Play video with a **real `<video>` element** whose `src` is a **custom Tauri
`stream://` URI-scheme protocol** that answers HTTP **Range** requests with
**decrypted** bytes. The browser's native media stack owns demux, decode, clock,
buffering, seek, and A/V sync. Controls come from **Media Chrome** (an npm
dependency, bundled locally).

This is an explicit, user-approved **reversal of Phase-7's central decision** for
the **view path only**: native WebView2 codecs (fMP4 demux + AV1 + AAC) now decode
inside the key-holding WebView. The content **key never leaves the Rust process** —
only decrypted plaintext crosses into the WebView, which is the accepted tradeoff.
See "Security posture" for the honest residual-risk accounting.

## Non-goals

- No change to crypto, verify ladder, directory, upload, or the download wire
  format.
- No change to the **author-side confined `media-transcode-worker`** — transcoding
  untrusted *source* video stays sandboxed (still a real RCE surface).
- No metadata/manifest format change.
- The image viewer path is untouched.

## Scope of change

### Stays (untouched)
- All crypto/verify/directory/download; `feed_fragment` / `open_range` / the
  fragment index; `FragmentCache`; the image viewer.
- `media-transcode-worker.exe` + the universal-video-ingest author path.

### Added
1. A Tauri **custom `stream://` protocol** (async, Range-aware) registered on the
   app builder, in the Rust main process.
2. An **open-video session registry** in app state:
   `file_id → OpenVideo { decryptor, chunk_size, content_chunk_count,
   total_plaintext_len, cache handle, authed fetch context }`. Built by the verify
   ladder on open; dropped + zeroized on close.
3. A **real `<video>`-based component** wrapped in **Media Chrome** for
   controls / fullscreen / keyboard / gestures / buffered ("grey") bar.

### Removed — LAST, only after the new path is e2e-green
- `core/player.ts` (hand-rolled A/V engine) and its tests.
- `core/webgl-yuv.ts` + the canvas rendering in `components/video-player.ts`.
- The decode-emit path: `EVT_VIDEO_FRAME`, `EVT_VIDEO_AUDIO`, `EVT_PLAYER`,
  `EVT_VIDEO_INFO`/`VideoInfo`, and `preview_seek` / `video_seek` / windowing +
  `decode_and_emit` in `commands/video.rs`.
- The **`media-worker.exe` playback-decode process** and the `media-launcher`
  decode session (`VideoSessionDecoder` / `VideoSubprocessSession`) — they existed
  *only* to decode for playback and are dead for the view path. (The
  `media-launcher` / `media-worker` crates may remain in the workspace but are no
  longer wired into the shipping view path; final removal vs. dormant is a
  cleanup-task call, not a blocker.)

## Architecture & data flow

```
open_content(file_id)
  → verify ladder builds a ContentDecryptor (stays in the TCB)
  → probe total plaintext length (decrypt ONLY the last chunk once)
  → register OpenVideo{...} in the session registry, keyed by file_id
UI: <video src="stream://media/<file_id>">
  → WebView issues  Range: bytes=a-b
     handler:
       map [a,b) → contiguous chunk range k..=m
       ciphertext for k..=m from FragmentCache (hit)
         or authed GET per absolute chunk index (miss) → cache it
       decryptor.open_range(k, &chunks) → plaintext for k..=m  (Zeroizing)
       slice plaintext to the requested [a,b)
       respond 206 Partial Content (Content-Range, Accept-Ranges: bytes)
  → <video> decodes AV1+AAC natively; owns seek / buffer / clock / A-V sync
close_content(file_id)
  → drop OpenVideo (Zeroizing plaintext buffers + decryptor wiped)
```

### Byte ↔ chunk mapping

Every content chunk holds exactly `chunk_size` bytes of plaintext except the last.
So for plaintext offset `O`: `chunk = O / chunk_size`, `intra = O % chunk_size`. A
range `[a, b)` spans chunks `floor(a/cs) ..= floor((b-1)/cs)`; decrypt that single
contiguous `open_range` and slice `[a − k·cs, b − k·cs)` out of the concatenated
plaintext.

`total_plaintext_len = (content_chunk_count − 1) · chunk_size +
last_chunk_plaintext_len`, where `last_chunk_plaintext_len` is learned by decrypting
the last chunk once at open. `chunk_size` and `content_chunk_count` come from the
already-verified header / decryptor. **No metadata format change.**

### The range-decrypt helper

Factor a helper (working name `decrypt_byte_range`) that, given
`(decryptor, cache, fetch_chunk, file_id, offset, len)`, computes the covering
chunk range, sources ciphertext from cache-or-fetch (reusing the exact
cache-then-fetch-then-`open_range` logic that `feed_fragment` already embodies),
decrypts, and returns the sliced plaintext. `feed_fragment` and the new helper
share the sourcing logic; the fragment-index/PTS machinery is unchanged and simply
unused by the streaming handler.

### Concurrency

The HTTP/1.1 connection is a single `SendRequest`, so cache-**miss** fetches
serialize behind a per-file async mutex; cache **hits** are lock-free. `<video>`
playback issues largely sequential range reads (one buffering read-ahead), so
contention is low.

### Auth / addressing

`stream://media/<file_id>` URLs are minted only by our own trusted, CSP-locked UI.
The handler serves **only** `file_id`s that already have a live `OpenVideo`
session (created by an authenticated `open_content` that ran the verify ladder), so
no token in the URL is needed. Unknown/closed `file_id` → 404.

### CSP / registration

- Register the `stream` scheme on the Tauri builder
  (`register_asynchronous_uri_scheme_protocol`) so the async responder can await
  network fetches.
- Extend the tauri.conf.json CSP with `media-src stream:` (and any
  `img-src`/`connect-src` the scheme needs). No remote content is ever allowed.

## Error handling

Fail-closed and oracle-free:
- unknown / closed `file_id` → **404**
- unsatisfiable / malformed range → **416**
- any fetch / AEAD / decrypt failure → sanitized **500** (no detail)
- no plaintext is ever released on a failed AEAD open (the existing
  `feed_fragment` invariant carries over verbatim).

## Frontend

- New `<video>`-based `components/video-player.ts` (replacing the canvas version):
  sets `src="stream://media/<file_id>"`, wired into `<media-viewer>`.
- **Media Chrome** wraps the `<video>`: play/pause, scrubber with buffered bar,
  time display, fullscreen, keyboard, auto-hide, click/double-click gestures. Speed
  menu remains dropped. Media Chrome is bundled from the local `node_modules` into
  `ui/dist` — no CSP or remote-origin change.
- Native benefits for free: a poster/first frame while paused, correct pause of
  both audio and video, an accurate timer and duration, native seek.
- The `serial.ts` FIFO / reauth serialization for **commands** is unchanged; the
  range handler is out-of-band of the command bus (it's an in-process protocol), so
  it does not go through `serial.ts`.

## Security posture

**The reversal, stated plainly:** native WebView2 codecs (fMP4 demux, AV1, AAC)
now run inside the WebView, which holds Tauri IPC and therefore reach to identity
keys. A codec/demux bug reachable from decoded bytes is an RCE surface that Phase-7
had eliminated by confining decode to a keyless worker.

**Genuine residual-risk narrowings (documented, not hand-waved):**
1. The WebView only ever decodes content that is **AEAD-authenticated +
   manifest-bound + produced by a D5-verified author's own confined transcoder** —
   not arbitrary internet video. The threat shrinks to a *malicious or compromised
   verified author* crafting an adversarial-but-valid AV1/AAC/fMP4 bitstream.
2. CSP stays locked to no remote content; WebView2 is an auto-updating, sandboxed
   runtime.
3. The content **key never leaves the Rust process**; only bounded, per-range
   decrypted plaintext crosses into the WebView, and `OpenVideo` plaintext buffers
   are `Zeroizing` and dropped on close.

A new sign-off doc — `docs/security-review-native-video-mediaapp.md` — records the
reversal, the residual surface, and these mitigations. This is a required
deliverable of the plan, not optional.

## Testing strategy

- **Verify-first (Task 0):** a real AV1+AAC fragmented-MP4 actually plays in the
  WebView2 runtime on this machine. If it cannot, the entire approach is void and we
  stop here. Done with a minimal `<video>` + a known-good local fMP4 before any
  other work.
- **Unit:** byte↔chunk mapping; range slicing across chunk boundaries; the
  last-chunk total-length probe; the 416/404 decision logic.
- **Integration:** the range handler over a **real `ContentDecryptor` + real
  `FragmentCache` + a fake fetch closure** — first range (`bytes=0-`), a mid-file
  seek range, the last partial range, a cache-hit-vs-miss assertion, and the
  416/404 paths.
- **e2e (real TLS):** upload a video → `open_content` → pull a sequence of ranges
  through the handler → assert the concatenated decrypted bytes equal the original
  content plaintext, and that no plaintext reaches disk (only ciphertext in the
  fragment cache).
- **Manual GUI smoke:** the two real clips
  (`D:\Images\00168.mp4` and the 59-second clip) play, seek, and pause with sound in
  the packaged client.

## Build / packaging notes

- After UI changes: `npm run build` in `crates/client-app/ui`, then
  `cargo build --release -p maxsecu-client-app`, then copy the exe to **both**
  `dist\MaxSecuClient-root` and `dist\MaxSecuClient-bob` (close the running client
  first — it locks its dist copy).
- The confined `media-transcode-worker.exe` must still sit beside the client exe.
  `media-worker.exe` is no longer required by the view path (may remain dormant).
- `cargo` is not on the tool PATH — prefix
  `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path";` (PS) /
  `export PATH="$HOME/.cargo/bin:$PATH";` (bash).
- Never `cargo fmt --all` (pre-existing repo-wide drift); match in-file style.

## Open risks

- **WebView2 AV1/AAC support** is the gating unknown — resolved by Task 0.
- **Range-read concurrency** under aggressive browser prefetch — mitigated by the
  per-file fetch mutex; watch for it in the integration test.
- **Large files** (the known ">64 MiB transcode-delivery residual") stream fine
  with per-range fetch, but the fragment-cache byte budget interacts with seek-heavy
  access — cache eviction is already LRU and bounded; no new work expected, but note
  it.
