# RAM cache model rework — shared budgets, persistence, two-knob/two-gauge, ciphertext-in-RAM

**Date:** 2026-07-06
**Status:** DRAFT — awaiting user review
**Area:** `crates/client-app` (client only; NO server / wire / client-core change)
**Supersedes on the cache side:** the post-merge RAM-gauge fix in [fast-remux-gpu-ingest].

## Problem (from live testing)

Three defects in the current RAM-cache behavior:

1. **Gauge exceeds the cap (e.g. `Cache 302 / 256 MB`).** Each open video registers its **own** `FragmentCache`, each capped at the *full* `ram_cache_cap_mb`. `cache_stats` reconciles every per-job cache to that cap and then **sums** them — so N simultaneous videos can total up to N× the cap. Pausing videos does not help: a paused video's `VideoJob` (and its cache) still exists; only `cancel_video` frees it.
2. **Leaving the viewer wipes the cache.** The `FragmentCache` lives *inside* the `VideoJob` (`jobs.rs`), so `cancel_video` destroys it. Re-opening the same video re-fetches everything.
3. **Thumbnails/content not represented, and cache RAM can spill plaintext to disk.** Thumbnails + full image/blog payloads live in a *separate* `ContentCache` (plaintext, LRU, its own copy of the same cap), invisible to the gauge. And any plaintext resident in RAM can be written to disk by the OS (Windows pagefile / hibernation / crash dumps) outside our control.

## Goals

- One **shared, persistent** budget for video fragments — fixes (1) and (2).
- **Two independent, user-tunable caps** with **two stacked gauges** (each ≤ 100% in RAM mode; Disk mode is uncapped and informational).
- **Everything cached in RAM is ciphertext** — so an OS page-out / hibernate spills only ciphertext, and on process close the keys are zeroized (paged copies become unrecoverable).
- **Never write plaintext to disk** — inviolable (already true for the on-disk fragment backend).

## Non-goals

- No server, wire-format, or `client-core` change.
- Not eliminating the webview's *transient* decoded-frame plaintext (the frame currently on screen). That is pre-existing, out of scope, and unavoidable for a native `<video>`/`<img>`.
- Not defeating a privileged local attacker with live process-memory access.

## Decisions locked with the user

- **D1.** Video fragments persist across leaving the viewer; LRU-only eviction. (`cancel_video` still zeroizes the content subkey/decryptor.)
- **D2.** Two caches, **two independent caps**, **two stacked gauges** — not a combined budget.
- **D3.** Partition: **Media cache** holds *video fragments + full images + blog bodies* under one shared 1 GB budget (cross-LRU); **Thumbnails cache** holds feed-card data (incl. thumbnail image) under a separate 256 MB budget.
- **D4.** **Both caches store ciphertext in RAM.** Video fragments are already ciphertext (encrypted under the content DEK). Full content + thumbnails are sealed under a **per-process ephemeral AES-256-GCM key** (random at startup, RAM-only, zeroized on close).
- **D5.** Disk backend, when selected, stores **ciphertext only** — never plaintext. Hard rule.
- **D5a. Disk mode is a distinct mode, not just a backend swap:**
  - **No byte cap** — the on-disk cache grows freely (bounded only by the disk).
  - **Wiped on BOTH app start and app exit** — a disk cache never survives a session boundary (startup wipe already partly exists via `open`; add the exit wipe).
  - **Gauges switch meaning:** numerator = **actual on-disk cache size**; denominator = **estimated free space on that disk**, probed **once at startup** (a growing cache can therefore approach/exceed 100% during a long session — accepted, it is informational; disk has no enforced limit).
  - **Clear button deletes the on-disk cache** (instead of zeroizing RAM).
  - The single location setting governs **both** caches (Media + Thumbnails); in RAM mode both use their caps, in Disk mode both go to disk with no cap.
- **D5b. Default location = RAM (Memory).** (Change `FragmentCacheLocation` default from `Disk` to `Memory`.)
- **D6.** On program close, **all in-RAM caches + the ephemeral key are zeroized** (extend the existing `RunEvent::Exit` hook).
- **D7.** Defaults: **Media = 1024 MB**, **Thumbnails = 256 MB**.
- **D8. Cache data is removed in EXACTLY three cases — nothing else:**
  1. **Cap reached** → evict least-recently-*requested* entries (LRU) until the new data fits.
  2. **App close** → zeroize all in-RAM cache memory before exit (D6).
  3. **Manual "Clear"** → a dedicated **Clear button next to each gauge** clears (and zeroizes) that one cache.

  **Leaving/exiting a post or the video viewer NEVER clears either cache** — both caches are persistent across all in-app navigation. (`cancel_video` still drops the per-session *decryptor*/subkey, but touches no cached bytes.) Explicit post/bundle **deletion** still invalidates that item's own entries via `invalidate_file` — that is deleting the underlying content, not "exiting a post," and is out of scope of D8's normal-eviction rule.

## Architecture

### Component A — `MediaCache` (generalized ciphertext-blob LRU; replaces per-job `FragmentCache`)

Generalize today's `FragmentCache` into a **namespaced opaque-ciphertext LRU**. It stores only opaque bytes and never inspects/transforms them (the existing CIPHERTEXT-ONLY invariant, now covering two namespaces):

- **Key:** `(ns, id_hex, sub)` where `ns ∈ { Frag, Content }`:
  - `Frag`: `id_hex = file_id`, `sub = seq` — a video fragment's ciphertext chunks (as today).
  - `Content`: `id_hex = file_id`, `sub = version` — an ephemeral-sealed full image/blog payload.
- **One cap, one `total_bytes`, one global LRU clock** across both namespaces → the cross-structure LRU is just one LRU over blobs. This is what makes "video + full content share 1 GB" tractable.
- **Backends:** `Memory` (in-process map; ciphertext only; **cap enforced** via LRU) **[default]** or `Disk` (files under `cache/media/`, filename includes `ns`; ciphertext only; **no cap** — grows freely, D5a). `memory_bytes()` reports the Memory-backend fill (0 for Disk); `disk_bytes()` reports the on-disk total (0 for Memory) — the gauge picks the one matching the mode.
- **Managed state:** `Arc<tokio::sync::Mutex<MediaCache>>` created once at startup from settings — **not** per `VideoJob`. `VideoJob` loses its `cache` field and instead borrows the shared cache in `serve_range`.
- **Lifecycle:** `cancel_video` drops the job (zeroizes decryptor) but not the shared cache → **persistence (D1)**. Location toggle change rebuilds the cache (Memory→zeroize; Disk→delete files); RAM cap change applies live via `set_cap`.
- **Startup + exit wipe:** on `open`, any prior `cache/media/` contents are removed (already true); on Disk mode the **exit** hook also deletes them (D5a — disk cache never crosses a session).
- **New:** `clear_and_zeroize()` (Memory: drop/wipe blobs; Disk: remove files) — used by the Exit hook **and** the manual Clear command.

**Lock ordering:** `serve_range` currently holds the `VideoJobs` lock while calling `assemble_range(&mut job.cache, …)`. With a shared cache the order is **`VideoJobs` → `MediaCache`** everywhere (and `cache_stats` locks `MediaCache` alone). No path takes them in the reverse order → no deadlock. The brief `MediaCache` lock covers get/put/evict + the in-TCB decrypt of the covering fragment (unchanged from today, just relocated).

### Component B — `ThumbCache` (sealed card cache; refactor of `ContentCache`)

Today's `ContentCache` holds one entry per `(file_id, version)` carrying **card meta** (title/tags/thumbnail_b64/author_fp/recovery_ok/mine/member_counts) **and** an optional full-content payload. Split by destination:

- **Card meta → `ThumbCache`** (256 MB, its own cap + gauge). The meta struct is **serialized and ephemeral-sealed** (AES-256-GCM under the process key) before it rests in the map; `get_card` unseals + deserializes. Zero-network, zero-re-verify hits preserved (unseal is µs). This is the "thumbnails cache" (a card *is* the thumbnail + its title/tags).
- **Full-content payload → `MediaCache` `Content` namespace** (shares the 1 GB budget with video). `put_content` seals the display-final bytes (image PNG / blog UTF-8) and stores them there; `get_content` reads + unseals.
- The current **card-put/content-put enrichment** (feed→view→feed) is preserved across the two stores: a card-put touches `ThumbCache`; a content-put touches both `ThumbCache` (meta) and `MediaCache` (payload). Invalidate/`invalidate_file`/`set_cap`/`clear_and_zeroize` fan out to both.
- **`ThumbCache` follows the same location setting** (D5a): RAM mode → sealed blobs in-process, 256 MB cap; Disk mode → sealed blobs under `cache/thumb/`, no cap, wiped on start+exit. Its gauge switches meaning identically to the Media gauge. (Both caches share the one `BlobCache` backend engine — Memory/Disk, LRU, `memory_bytes`/`disk_bytes`, `clear_and_zeroize` — differing only in namespaces, cap, and which gauge they feed.)

### Component C — ephemeral seal (`SessionSeal`)

- A 32-byte key from the OS CSPRNG at startup, in managed state, wrapped `Zeroizing`, **never persisted**.
- `seal(plaintext) -> Vec<u8>` = random 96-bit nonce ‖ AES-256-GCM ciphertext‖tag; `open(blob) -> Zeroizing<Vec<u8>>`.
- Used by `ThumbCache` (meta) and `MediaCache` `Content` entries. Video `Frag` entries are **not** re-sealed (already ciphertext under the content DEK).
- Zeroized in the Exit hook → any pagefile/hibernation copy of sealed blobs is unrecoverable afterward.

### Component D — settings (two knobs)

- `PerformanceSettings`: rename `ram_cache_cap_mb` → **`media_cache_cap_mb`** (default 1024) and add **`thumb_cache_cap_mb`** (default 256). Both `#[serde(default)]`; **migration:** an old file with `ram_cache_cap_mb` maps that value into `media_cache_cap_mb`. Both clamp-normalized (reuse the existing RAM-bounds logic; the media cap keeps the total−6 GB ceiling; thumb uses the same bounds, independent value — resolves OQ3). **The two caps apply only in RAM mode** (Disk mode is uncapped, D5a).
- `fragment_cache_location` → **`cache_location`**, `#[serde(default)]` = **`Memory`** (D5b). One setting governs both caches.
- Live-applied: RAM caps → `MediaCache::set_cap` / `ThumbCache::set_cap` on `set_settings` (mirroring today's single-cap wiring). Changing `cache_location` rebuilds both caches (Memory↔Disk).
- Settings UI: the location **select** (default RAM) + the **two cap controls** (shown/relevant in RAM mode).

### Component E — gauges (two stacked bars) + per-cache Clear

- `<ram-gauge>` renders **two bars stacked vertically**: "Media cache" and "Thumbnails".
- **Dual-mode denominator/numerator** (per the live `cache_location`):
  - **RAM mode:** numerator = in-RAM sealed-ciphertext fill; denominator = that cache's cap. Each bar ≤ 100%.
  - **Disk mode:** numerator = on-disk cache size; denominator = **estimated free disk space** probed once at startup (D5a). May exceed 100% on a long session — accepted.
- Each bar has a **"Clear" button beside it** (D8 case 3): RAM mode → zeroize that cache; Disk mode → delete that on-disk cache. Then re-poll so the bar drops to 0. Keyboard-focusable, aria-labeled; confirm-free (clearing a cache only forces re-fetch, no user-data loss).
- `cache_stats(media_cap_bytes, thumb_cap_bytes)` returns `{ media_used, thumb_used, mode, disk_free_estimate }`. In RAM mode it reconciles each cache to its live cap (`set_cap`) and reports `memory_bytes`; in Disk mode it reports `disk_bytes` + the cached startup free-space estimate as the denominator. The UI paints accordingly.
- Reuse `gauge.ts` model per bar.

### Component G — manual clear commands

- `clear_media_cache` and `clear_thumb_cache` Tauri commands each lock the target cache and call `clear_and_zeroize()` (the same routine the Exit hook uses). No effect on any open `VideoJob`'s decryptor — only cached bytes are dropped; an in-flight `serve_range` simply re-fetches on its next miss.

### Component F — Exit-hook zeroize / disk-wipe (D6, D5a)

Extend `main.rs` `RunEvent::Exit` to additionally `MediaCache::clear_and_zeroize()`, `ThumbCache::clear_and_zeroize()` (Memory → zeroize RAM; Disk → delete `cache/media/` + `cache/thumb/`), and zeroize the `SessionSeal` key — alongside today's `ContentCache` wipe (which `ThumbCache` replaces). Disk caches are thus wiped on both start (`open`) and exit.

### Component H — startup free-space probe (Disk-mode gauge denominator, D5a)

At startup, estimate free space on the drive holding the app dir **once** and stash it in managed state (`Arc<u64>` or a field). Used only as the Disk-mode gauge denominator. Mechanism: prefer an existing dependency exposing free space (the client already surfaces system RAM in `ram.rs`; add the analogous disk call — e.g. via `sysinfo` or a tiny `GetDiskFreeSpaceExW`/`statvfs` helper in a module that permits `unsafe`, **never** inside `#![forbid(unsafe_code)]` cache code). Best-effort: on probe failure, fall back to hiding the Disk-mode denominator (show raw size only).

## Security review (required sign-off: `docs/security-review-2026-07-06-ram-cache-model.md`)

Must cover: cross-video isolation under the shared cache (keyed by file_id → no cross-read); persistence posture (only ciphertext resident while idle; subkey zeroized on `cancel_video`); ephemeral-seal construction (unique nonces, AEAD, key never persisted, zeroized on close); Disk backend remains ciphertext-only (D5); Exit-hook zeroize (D6); explicit statement of the residual (32-byte ephemeral key + transient webview frame can still be paged/hibernated).

## Testing

- **`MediaCache`:** namespaced put/get roundtrip; cross-namespace shared LRU eviction; `Frag`+`Content` under one cap; `set_cap` lowering evicts; Disk backend writes ciphertext-only (existing plaintext-marker test extended to `Content`); `memory_bytes` (Memory-only) drives the gauge; path-safe filenames incl. `ns`; `clear_and_zeroize` wipes.
- **`ThumbCache`/content split:** card-put/content-put enrichment still works across the two stores; sealed meta roundtrips; oversize-vs-cap; invalidate/`invalidate_file`; `set_cap`; `clear_and_zeroize`.
- **`SessionSeal`:** seal→open roundtrip; distinct nonces; tampered blob → error; wrong key → error.
- **`cache_stats`:** two-cap reconcile + both `used` values; in RAM mode never > respective cap; in Disk mode reports `disk_bytes` + the startup free-space estimate.
- **Clear commands:** `clear_media_cache`/`clear_thumb_cache` zero the target cache (used→0), zeroize its RAM, and leave the other cache + any open `VideoJob` decryptor untouched.
- **Persistence:** leaving a video (`cancel_video`) drops the decryptor but the Media cache keeps its bytes (a follow-up `serve_range`/re-open is a cache hit, not a refetch).
- **Disk mode:** no cap enforced (grows past the RAM cap); `disk_bytes` tracks on-disk size; `open` wipes prior contents (startup) and `clear_and_zeroize` removes files (exit/manual); on-disk blobs are ciphertext only (plaintext-marker scan); location toggle rebuild moves/wipes correctly. Free-space probe returns a plausible value and degrades gracefully on failure.
- **serde/migration:** old `ram_cache_cap_mb` → `media_cache_cap_mb`; both caps clamp-normalize.
- **UI:** `gauge.ts`/two-bar model unit tests; `tsc` clean; existing suite green. **esbuild rebuild required** before rebuilding the client bin (see [fast-remux-gpu-ingest] build gotcha).
- Existing video e2e (`phase7_video_upload_over_real_tls`, copy-path gate) stays green with the shared cache.

## Resolved decisions (formerly open questions)

- **OQ1 → resolved:** the location toggle governs **both** caches; in Disk mode all namespaces (video `Frag`, `Content`, `Card`) go to disk as ciphertext, no cap (D5a). Disk caches are wiped on start+exit, so sealed-under-ephemeral-key content is never read across a restart.
- **OQ2 → resolved:** the gauge is **dual-mode** — RAM fill ÷ cap, or on-disk size ÷ startup free-space estimate (D5a). Not an empty bar.
- **OQ3 → resolved:** `thumb_cache_cap_mb` uses the same normalization bounds as the media cap, independent value.

## Implementation approach

Subagent-driven (Opus 4.8), per-task two-stage (spec + quality) review, mirroring the fast-ingest build. Tasks are largely sequential (cache core → content split → seal → settings → commands → UI → Exit hook → security sign-off), so a small number of dependent tasks with review checkpoints rather than wide parallelism.
