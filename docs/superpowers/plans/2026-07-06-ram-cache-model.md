# RAM cache model rework — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the per-video-job `FragmentCache` + separate plaintext `ContentCache` with two app-global, persistent, ciphertext-in-RAM caches (Media 1 GB / Thumbnails 256 MB) that each have their own cap, gauge, and Clear button, share one Disk/Memory location toggle (default RAM), zeroize on close, and never write plaintext to disk.

**Architecture:** One reusable `BlobCache` engine (namespaced opaque-ciphertext LRU, Disk **or** Memory backend). Two instances behind managed state: `MediaCache` (namespaces `Frag`=video, `Content`=full image/blog) and `ThumbCache` (namespace `Card`=feed card meta). Full content + card meta are AES-256-GCM–sealed under a per-process ephemeral key (`SessionSeal`) before entering a cache; video fragments are already content-DEK ciphertext. `cancel_video` no longer drops the cache (persistence); the Exit hook zeroizes the seal key + clears caches. Client-only; no server/wire/`client-core` change.

**Tech Stack:** Rust (Tauri 2, tokio, `aes-gcm` or the crate already used by `client-core`/`crypto` for AEAD, `zeroize`, `sysinfo`), TypeScript (vanilla web components + esbuild).

**Spec:** `docs/superpowers/specs/2026-07-06-ram-cache-model-design.md` (read it first).

**Baseline note:** Before Task 1, the 9 pre-existing uncommitted files (the "Preparing preview" progress feature + the superseded live-cap fix) must be committed as a baseline, and a feature branch created (see Task 0). This rework then supersedes the live-cap parts of `fragment_cache.rs`, `commands/video.rs` (`cache_stats`), and `ui/.../ram-gauge.ts`.

---

## Critical environment rules (every task)

- **cargo not on PATH** — prefix each cargo call: `export PATH="$HOME/.cargo/bin:$PATH";` (bash) / `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path";` (PS).
- **NEVER `cargo fmt --all`** and **NEVER `git add -A`** (untracked `.server-fresh/`, `client/`, `recovery_*.bin`, `register.key` must never be staged). Use scoped `git add <path>`.
- **client-app is its own cargo workspace** (`crates/client-app`). Run its tests from there: `cargo test -p maxsecu-client-app`.
- **UI build gotcha:** after ANY `crates/client-app/ui/src/**.ts` edit you MUST `cd crates/client-app/ui && npm run build` (esbuild → `dist/main.js`) before rebuilding the bin. `npm run typecheck`/`npm test` do NOT emit the bundle.
- **Do NOT restart the running demo server** (PID from the session; in-memory accounts) and do NOT run `.server-fresh/rerun-demo.ps1`.
- `#![forbid(unsafe_code)]` holds in `fragment_cache.rs`/`blob_cache.rs` — the disk free-space FFI must live elsewhere (Task 6).

---

## File structure

**New:**
- `crates/client-app/src/blob_cache.rs` — the generalized namespaced ciphertext-blob LRU (renamed/generalized from `fragment_cache.rs`).
- `crates/client-app/src/session_seal.rs` — per-process ephemeral AES-256-GCM seal.
- `crates/client-app/src/media_cache.rs` — `MediaCache` wrapper (managed state) over a `BlobCache` for `Frag`+`Content`.
- `crates/client-app/src/thumb_cache.rs` — `ThumbCache` (replaces `content_cache.rs`) over a `BlobCache` for `Card`, sealed.
- `crates/client-app/src/disk_free.rs` — startup free-space probe (allows `unsafe`/uses `sysinfo`).

**Modified:**
- `crates/client-app/src/config.rs` — split caps, rename location, default Memory, migration, normalization.
- `crates/client-app/src/jobs.rs` — `VideoJob` loses `cache` field.
- `crates/client-app/src/commands/video.rs` — `serve_range`/`open_video` use shared `MediaCache`; `cache_stats` dual-mode; add `clear_media_cache`.
- `crates/client-app/src/commands/feed.rs` — `get_card`/`put_card` → `ThumbCache`.
- `crates/client-app/src/commands/viewer.rs` — `get_content`/`put_content` → `ThumbCache` (meta) + `MediaCache` (payload).
- `crates/client-app/src/commands/delete_cmd.rs` — `invalidate_file` fans out to both.
- `crates/client-app/src/commands/settings.rs` — apply both caps live.
- `crates/client-app/src/main.rs` — manage new states; Exit hook clears caches + zeroizes seal + disk-wipes; add `clear_thumb_cache`.
- `crates/client-app/src/lib.rs` — module list.
- `crates/client-app/ui/src/core/types.ts` — `CacheStats` shape.
- `crates/client-app/ui/src/core/gauge.ts` — model helper (reused per bar).
- `crates/client-app/ui/src/components/ram-gauge.ts` — two stacked bars + Clear buttons + dual-mode.
- `crates/client-app/ui/src/components/settings-screen.ts` — two cap controls + location select default.

**Removed:** `crates/client-app/src/content_cache.rs` (replaced by `thumb_cache.rs` + `media_cache.rs` Content namespace).

---

## Task 0: Baseline commit + feature branch

**Files:** none (git only).

- [ ] **Step 1: Commit the pre-existing UX work as baseline (scoped adds only)**

```bash
git add crates/client-app/src/commands/upload.rs crates/client-app/src/commands/video.rs \
        crates/client-app/src/fragment_cache.rs crates/client-app/src/main.rs \
        crates/client-app/src/state.rs \
        crates/client-app/ui/src/components/bundle-composer.ts \
        crates/client-app/ui/src/components/ram-gauge.ts \
        crates/client-app/ui/src/components/upload-screen.ts \
        crates/client-app/ui/src/core/types.ts
git commit -m "feat(client): preparing-preview progress + interim live-cap gauge fix (baseline)"
```

- [ ] **Step 2: Commit the spec + this plan**

```bash
git add docs/superpowers/specs/2026-07-06-ram-cache-model-design.md docs/superpowers/plans/2026-07-06-ram-cache-model.md
git commit -m "docs: RAM cache model rework spec + plan"
```

- [ ] **Step 3: Create the feature branch**

```bash
git switch -c feat/ram-cache-model
git branch --show-current   # expect: feat/ram-cache-model
```

---

## Task 1: `BlobCache` engine (generalize `FragmentCache`)

Generalize the existing ciphertext cache to a namespaced blob LRU with Disk **or** Memory backend, an optional cap (Memory enforces it; Disk is unlimited), and `memory_bytes()`/`disk_bytes()`/`clear_and_zeroize()`. Preserve every existing security invariant (ciphertext-only, no path traversal, case-normalized key, Windows not-content-indexed).

**Files:**
- Create: `crates/client-app/src/blob_cache.rs` (git-move `fragment_cache.rs`, then edit).
- Modify: `crates/client-app/src/lib.rs` (rename `pub mod fragment_cache;` → `pub mod blob_cache;`).
- Test: inline `#[cfg(test)]` in `blob_cache.rs` (port existing tests + add new).

- [ ] **Step 1: Move the file, keep history**

```bash
git mv crates/client-app/src/fragment_cache.rs crates/client-app/src/blob_cache.rs
```

- [ ] **Step 2: Introduce the namespace + generalized key**

Add near the top of `blob_cache.rs`:

```rust
/// Which logical stream a blob belongs to. Kept as a small fixed set of
/// path-safe tags so the on-disk filename can embed it without traversal risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ns { Frag, Content, Card }

impl Ns {
    fn tag(self) -> &'static str {
        match self { Ns::Frag => "frag", Ns::Content => "content", Ns::Card => "card" }
    }
}
```

Change the index/backend key from `(String, u32)` to `(Ns, String, u32)` (namespace, `id_hex`, `sub`). Update `blob_filename` to `format!("{}_{}_{}.blob", ns.tag(), id_hex, sub)`. `validated_key` still validates the `id_hex` component is hex-only (unchanged rule); `ns.tag()` and the decimal `sub` are inherently path-safe.

- [ ] **Step 3: Cap becomes optional (Disk = unlimited)**

`FragmentCache` → `BlobCache`. Add a `cap: Option<u64>` field (`None` = unlimited). `Memory` backend: `Some(cap)`, LRU-evict as today. `Disk` backend: `None`, never evict. In `put`, `while self.cap.is_some_and(|c| self.total_bytes + size > c) && self.evict_one() {}`; skip the "larger than cap" early-return when `cap` is `None`.

- [ ] **Step 4: Add `memory_bytes` / `disk_bytes` / `clear_and_zeroize`**

```rust
/// Bytes held in RAM (Memory backend) — 0 for Disk. Drives the RAM-mode gauge.
pub fn memory_bytes(&self) -> u64 {
    match &self.backend { Backend::Memory { .. } => self.total_bytes, Backend::Disk { .. } => 0 }
}
/// Bytes held on disk (Disk backend) — 0 for Memory. Drives the Disk-mode gauge.
pub fn disk_bytes(&self) -> u64 {
    match &self.backend { Backend::Disk { .. } => self.total_bytes, Backend::Memory { .. } => 0 }
}
/// Drop every entry: Memory → wipe blobs (they are `Zeroizing`); Disk → remove files.
pub fn clear_and_zeroize(&mut self) {
    let keys: Vec<_> = self.index.keys().cloned().collect();
    for k in keys { self.remove_entry(&k); }
    self.total_bytes = 0;
}
```

Change the Memory backend map value to `Zeroizing<Vec<u8>>` (import `zeroize::Zeroizing`) for defense-in-depth (contents are ciphertext, but wiping on drop is cheap). `get` returns a plain `Vec<u8>` clone as today.

- [ ] **Step 5: Port existing tests to the new key + add new tests**

Update every existing test call from `c.put("aa", 0, …)` to `c.put(Ns::Frag, "aa", 0, …)` etc. Add:

```rust
#[test]
fn namespaces_do_not_collide() {
    let dir = tmp_dir("ns");
    let mut c = BlobCache::open_located(&dir, Some(1 << 20), FragmentCacheLocation::Memory).unwrap();
    c.put(Ns::Frag, "aa", 0, b"frag-bytes").unwrap();
    c.put(Ns::Content, "aa", 0, b"content-bytes").unwrap();
    assert_eq!(c.get(Ns::Frag, "aa", 0).as_deref(), Some(b"frag-bytes".as_slice()));
    assert_eq!(c.get(Ns::Content, "aa", 0).as_deref(), Some(b"content-bytes".as_slice()));
}

#[test]
fn disk_backend_is_uncapped() {
    let dir = tmp_dir("uncap");
    // cap None on disk: three 10-byte blobs under a would-be 20-byte cap all survive.
    let mut c = BlobCache::open_located(&dir, None, FragmentCacheLocation::Disk).unwrap();
    for s in 0..3u32 { c.put(Ns::Frag, "aa", s, &[0u8; 10]).unwrap(); }
    assert_eq!(c.total_bytes(), 30);
    assert_eq!(c.disk_bytes(), 30);
    assert_eq!(c.memory_bytes(), 0);
}

#[test]
fn clear_and_zeroize_empties_both_backends() {
    for loc in [FragmentCacheLocation::Memory, FragmentCacheLocation::Disk] {
        let dir = tmp_dir("clr");
        let cap = if loc == FragmentCacheLocation::Memory { Some(1 << 20) } else { None };
        let mut c = BlobCache::open_located(&dir, cap, loc).unwrap();
        c.put(Ns::Card, "aa", 0, b"x").unwrap();
        c.clear_and_zeroize();
        assert_eq!(c.total_bytes(), 0);
        assert!(c.get(Ns::Card, "aa", 0).is_none());
    }
}
```

- [ ] **Step 6: Keep the ciphertext-only + traversal + case tests green (extend the plaintext-marker test to `Ns::Content`).**

- [ ] **Step 7: Update `lib.rs`, compile & test**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd crates/client-app && cargo test -p maxsecu-client-app blob_cache`
Expected: PASS. (`commands/video.rs` still references the old type — it will not compile app-wide yet; that is fixed in Task 5. Scope this run to the `blob_cache` tests, which compile the lib module in isolation via `--lib` if needed: `cargo test -p maxsecu-client-app --lib blob_cache` may still require the crate to build. If app-wide build breaks, temporarily keep a `pub use blob_cache as fragment_cache` alias + a thin `FragmentCache` type alias so Task 1 lands green, removed in Task 5.)

- [ ] **Step 8: Commit**

```bash
git add crates/client-app/src/blob_cache.rs crates/client-app/src/lib.rs
git commit -m "feat(cache): generalize FragmentCache into namespaced BlobCache (Disk uncapped, memory/disk bytes, clear_and_zeroize)"
```

---

## Task 2: `SessionSeal` (per-process ephemeral AEAD)

**Files:**
- Create: `crates/client-app/src/session_seal.rs`
- Modify: `crates/client-app/src/lib.rs` (`pub mod session_seal;`)
- Test: inline.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn seal_open_round_trips() {
        let s = SessionSeal::generate();
        let pt = b"card-meta-or-content-bytes".to_vec();
        let blob = s.seal(&pt);
        assert_ne!(blob, pt);                     // not plaintext
        assert_eq!(&*s.open(&blob).unwrap(), &pt[..]);
    }
    #[test]
    fn distinct_nonces_per_seal() {
        let s = SessionSeal::generate();
        assert_ne!(s.seal(b"x"), s.seal(b"x"));    // random nonce → different ciphertext
    }
    #[test]
    fn tampered_blob_fails() {
        let s = SessionSeal::generate();
        let mut blob = s.seal(b"hello");
        *blob.last_mut().unwrap() ^= 0xff;
        assert!(s.open(&blob).is_none());
    }
    #[test]
    fn wrong_key_fails() {
        let a = SessionSeal::generate();
        let b = SessionSeal::generate();
        assert!(b.open(&a.seal(b"hello")).is_none());
    }
    #[test]
    fn truncated_blob_is_none() {
        let s = SessionSeal::generate();
        assert!(s.open(&[0u8; 4]).is_none());       // shorter than nonce
    }
}
```

- [ ] **Step 2: Run — expect FAIL (type missing).**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd crates/client-app && cargo test -p maxsecu-client-app session_seal`

- [ ] **Step 3: Implement**

Use the same AEAD crate the workspace already depends on (check `client-core`/`crypto` for `aes-gcm` / `aead`; reuse it — do NOT add a new crypto dependency without confirming). Sketch:

```rust
//! Per-process ephemeral seal: a random AES-256-GCM key, RAM-only, never persisted.
//! Full image/blog payloads and feed-card meta are sealed under it before resting in
//! a RAM/disk cache, so any OS page-out / hibernation of the cache spills only
//! ciphertext, and zeroizing this key on close makes even a spilled copy unrecoverable.
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use zeroize::Zeroizing;

pub struct SessionSeal { key: Zeroizing<[u8; 32]> }

impl SessionSeal {
    pub fn generate() -> Self {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).expect("OS CSPRNG"); // or the workspace RNG helper
        Self { key: Zeroizing::new(k) }
    }
    pub fn seal(&self, pt: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).expect("OS CSPRNG");
        let cipher = Aes256Gcm::new((&*self.key).into());
        let mut out = nonce.to_vec();
        out.extend(cipher.encrypt(Nonce::from_slice(&nonce), pt).expect("seal"));
        out
    }
    pub fn open(&self, blob: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        if blob.len() < 12 { return None; }
        let (nonce, ct) = blob.split_at(12);
        let cipher = Aes256Gcm::new((&*self.key).into());
        cipher.decrypt(Nonce::from_slice(nonce), ct).ok().map(Zeroizing::new)
    }
}
```

(If the workspace exposes a preferred RNG/AEAD wrapper in `maxsecu_crypto`, use that instead of `getrandom`/`aes-gcm` directly — confirm by reading `crates/crypto`.)

- [ ] **Step 4: Run — expect PASS.** Same command as Step 2.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/src/session_seal.rs crates/client-app/src/lib.rs crates/client-app/Cargo.toml
git commit -m "feat(cache): per-process ephemeral SessionSeal (AES-256-GCM, RAM-only key)"
```

---

## Task 3: Config — two caps, renamed location, default Memory, migration

**Files:**
- Modify: `crates/client-app/src/config.rs` (`PerformanceSettings`, defaults, `normalized_with_ram`, migration, tests).
- Test: inline in `config.rs`.

- [ ] **Step 1: Write failing tests**

Add to `config.rs` tests:

```rust
#[test]
fn migrates_legacy_ram_cache_cap_into_media() {
    // Old settings.json with only ram_cache_cap_mb populates media_cache_cap_mb.
    let json = r#"{"media_cache_cap_mb":0,"thumb_cache_cap_mb":0,"ram_cache_cap_mb":512}"#;
    let p: PerformanceSettings = serde_json::from_str(json).unwrap();
    assert_eq!(p.media_cache_cap_mb, 512);
    assert_eq!(p.thumb_cache_cap_mb, 256); // default when absent/zero
}
#[test]
fn default_location_is_memory() {
    assert_eq!(PerformanceSettings::default().cache_location, FragmentCacheLocation::Memory);
}
#[test]
fn both_caps_clamp_to_ram_bounds() {
    let limits = RamLimits { default_mb: 1024, min_mb: 64, max_mb: 2048 };
    let mut s = SettingsConfig::default();
    s.performance.media_cache_cap_mb = 99_999;
    s.performance.thumb_cache_cap_mb = 1;
    let n = s.normalized_with_ram(&limits).performance;
    assert!(n.media_cache_cap_mb <= 2048 && n.media_cache_cap_mb >= 64);
    assert!(n.thumb_cache_cap_mb <= 2048 && n.thumb_cache_cap_mb >= 64);
}
```

- [ ] **Step 2: Run — expect FAIL.**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd crates/client-app && cargo test -p maxsecu-client-app config`

- [ ] **Step 3: Implement**

In `PerformanceSettings`: remove `ram_cache_cap_mb` as a live field; add
```rust
pub media_cache_cap_mb: u32,
#[serde(default = "default_thumb_cap")] pub thumb_cache_cap_mb: u32,
#[serde(default)] pub cache_location: FragmentCacheLocation, // renamed from fragment_cache_location
// legacy migration shim: accept an old file's key, fold into media on load.
#[serde(default, skip_serializing)] ram_cache_cap_mb: Option<u32>,
```
`fn default_thumb_cap() -> u32 { 256 }`. Change `FragmentCacheLocation::default()` to `Memory` (was `Disk`). In `Default for PerformanceSettings`, set `media_cache_cap_mb: 1024, thumb_cache_cap_mb: 256, cache_location: FragmentCacheLocation::Memory, ram_cache_cap_mb: None`. In `SettingsConfig::load` (or a `post_deserialize`), if `media_cache_cap_mb == 0` and `ram_cache_cap_mb` is `Some(v>0)`, set `media_cache_cap_mb = v`; if `thumb_cache_cap_mb == 0`, set it to 256. In `normalized_with_ram`, clamp BOTH caps with the existing `limits.min_mb..=limits.max_mb` logic. Update the existing single-cap tests (`d.performance.ram_cache_cap_mb`) to the new field names.

- [ ] **Step 4: Run — expect PASS.** Same command.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/src/config.rs
git commit -m "feat(config): split media/thumb cache caps, rename cache_location (default Memory), migrate legacy ram_cache_cap_mb"
```

---

## Task 4: `MediaCache` + move cache out of `VideoJob` + wire `serve_range`

**Files:**
- Create: `crates/client-app/src/media_cache.rs`
- Modify: `crates/client-app/src/jobs.rs` (drop `VideoJob.cache`), `crates/client-app/src/commands/video.rs` (open/serve/cancel/probe), `crates/client-app/src/lib.rs`.
- Test: inline in `media_cache.rs` + adjust `commands/video.rs` tests (`build_job`).

- [ ] **Step 1: Implement `MediaCache` wrapper**

```rust
//! App-global shared video+content cache. One `BlobCache` behind an async mutex,
//! holding `Frag` (content-DEK ciphertext) and `Content` (SessionSeal-sealed
//! image/blog) blobs under one budget. Persistent across `cancel_video`.
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::blob_cache::{BlobCache, Ns};
use crate::config::FragmentCacheLocation;

pub struct MediaCache(pub Arc<Mutex<BlobCache>>);

impl MediaCache {
    /// cap_mb None-ify on Disk (uncapped); Some(bytes) on Memory.
    pub fn open(app_dir: &std::path::Path, cap_mb: u32, loc: FragmentCacheLocation) -> Self {
        let cap = match loc { FragmentCacheLocation::Memory => Some(cap_mb as u64 * 1024 * 1024), FragmentCacheLocation::Disk => None };
        let bc = BlobCache::open_located(app_dir, cap, loc).expect("open media cache");
        MediaCache(Arc::new(Mutex::new(bc)))
    }
}
```

- [ ] **Step 2: Drop `VideoJob.cache`**

In `jobs.rs`, remove the `pub cache: crate::fragment_cache::FragmentCache,` field and its doc line. Fix the constructor in `commands/video.rs` (`open_video_inner`) and the test `build_job` accordingly.

- [ ] **Step 3: Rewire `serve_range` / `cached_fragment_valid` / `probe_total_len` to the shared cache**

`serve_range(jobs, media: &MediaCache, …)`: Phase A now locks the `VideoJobs` for index/decryptor/channel, and separately locks `media.0` for the cache read (`cached_fragment_valid(&mut *media_guard, Ns::Frag, …)`) and Phase-C assemble. Keep lock order **VideoJobs → MediaCache**. `assemble_range` and `feed_fragment` signatures change from `&mut FragmentCache` to `(&mut BlobCache, Ns::Frag)` — update `crate::stream::assemble_range` and `crate::video::feed_fragment` to take the `Ns` (thread `Ns::Frag` through). `cached_fragment_valid(cache, ns, id, seq, chunk_len)`. The Phase-D evict loop uses `media_guard.evict(Ns::Frag, id, seq)`.

- [ ] **Step 4: `open_video` uses the shared cache; `cancel_video` keeps it**

`open_video_inner`: delete the per-job `FragmentCache::open_located(...)` block; the `VideoJob` no longer carries a cache. `stream_media`/`serve_range` receive the `MediaCache` managed state (`app.state::<MediaCache>()`). `cancel_video` is unchanged in effect (drops the job/decryptor) — it must NOT touch `MediaCache` (persistence).

- [ ] **Step 5: Update `commands/video.rs` unit tests**

`build_job` drops the `cache` field. Tests that fed the per-job cache (`cached_fragment_valid_mirrors_the_feeder_hit_condition`) build a standalone `BlobCache` and pass `Ns::Frag`.

- [ ] **Step 6: Compile & test**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd crates/client-app && cargo test -p maxsecu-client-app media_cache video::`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/client-app/src/media_cache.rs crates/client-app/src/jobs.rs crates/client-app/src/commands/video.rs crates/client-app/src/video.rs crates/client-app/src/stream.rs crates/client-app/src/lib.rs
git commit -m "feat(cache): app-global shared MediaCache; VideoJob no longer owns the cache (persist across cancel; fixes over-cap sum)"
```

---

## Task 5: `ThumbCache` (replace `ContentCache`) + call-site migration

**Files:**
- Create: `crates/client-app/src/thumb_cache.rs`
- Remove: `crates/client-app/src/content_cache.rs`
- Modify: `crates/client-app/src/commands/feed.rs`, `viewer.rs`, `delete_cmd.rs`, `settings.rs`, `lib.rs`, `main.rs` (import swap).

- [ ] **Step 1: Implement `ThumbCache`**

A struct holding `Arc<Mutex<BlobCache>>` (namespace `Ns::Card`) + a `SessionSeal` handle (shared `Arc<SessionSeal>`), plus a small in-struct serialization of `CachedMeta`. `put_card(key, meta)`: `bincode`/`serde_json`-serialize `CachedMeta` (move the struct here from `content_cache.rs`), `seal`, `blob_cache.put(Ns::Card, hex(file_id), version, &sealed)`. `get_card(key, file_id_hex) -> Option<CardDto>`: `get` → `seal.open` → deserialize → build `CardDto` (port the existing reconstruction from `content_cache.rs`). Add `invalidate_file` (evict all `Card` entries whose `id_hex` matches — `BlobCache` needs an `evict_prefix(ns, id_hex)` helper: add it, iterating keys with that `(ns, id_hex)`), `set_cap`, `clear_and_zeroize`. **Full-content payloads do NOT live here** — they go to `MediaCache` `Ns::Content` (Step 2).

- [ ] **Step 2: Move full content into `MediaCache` `Content`**

`viewer.rs` `open_content`: today it calls `content_cache.get_content(...)` / `put_content(...)`. Replace with: on read, `media.get(Ns::Content, file_id_hex, version)` → `seal.open` → shape into `OpenedContentDto` (port `get_content`'s image/blog shaping); on write, `seal(display_final_bytes)` → `media.put(Ns::Content, …)`, and separately `thumb.put_card(...)` for the meta. Preserve the card/content enrichment: a `get_card` hit still works from `ThumbCache`; a content hit needs BOTH a `ThumbCache` meta entry (for title/type) and the `MediaCache` payload — store meta on every content-put.

- [ ] **Step 3: Update `feed.rs`**

Swap the `cache: State<ContentCache>` param to `thumb: State<ThumbCache>`; `get_card`/`put_card` now hit `ThumbCache`. Signature/param name changes only; logic identical.

- [ ] **Step 4: Update `delete_cmd.rs`**

`invalidate_file` fans out: `thumb.invalidate_file(file_id)` + `media.invalidate_file(file_id)` (add `MediaCache::invalidate_file` = evict `Frag` + `Content` for that id via `evict_prefix`).

- [ ] **Step 5: Update `settings.rs`**

`set_settings` applies BOTH caps live: `media.set_cap(norm.performance.media_cache_cap_mb …)` (only meaningful in Memory mode) + `thumb.set_cap(norm.performance.thumb_cache_cap_mb …)`. If `cache_location` changed vs the persisted value, rebuild both caches (swap the `Arc<Mutex<BlobCache>>` contents under lock). Take `media: State<MediaCache>, thumb: State<ThumbCache>` params.

- [ ] **Step 6: Port + adapt the `content_cache.rs` tests into `thumb_cache.rs`**

Card-put/content-put enrichment, oversize-vs-cap, invalidate/`invalidate_file`, `set_cap`, `clear_and_zeroize`, image base64 round-trip — but content payload assertions now go through `MediaCache`. Add a sealed-roundtrip test (meta survives seal→store→open).

- [ ] **Step 7: Remove `content_cache.rs`, update `lib.rs`/imports, compile & test**

```bash
git rm crates/client-app/src/content_cache.rs
export PATH="$HOME/.cargo/bin:$PATH"; cd crates/client-app && cargo test -p maxsecu-client-app
```
Expected: PASS (whole client-app suite).

- [ ] **Step 8: Commit**

```bash
git add -u crates/client-app/src
git add crates/client-app/src/thumb_cache.rs
git commit -m "feat(cache): replace plaintext ContentCache with sealed ThumbCache (card meta) + MediaCache Content (full payloads)"
```

---

## Task 6: Startup disk free-space probe

**Files:**
- Create: `crates/client-app/src/disk_free.rs` (NO `forbid(unsafe_code)`; may use `sysinfo` `Disks` or a Win32 call).
- Modify: `crates/client-app/src/lib.rs`.
- Test: inline (pure fallback path).

- [ ] **Step 1: Implement**

Prefer `sysinfo::Disks` (already a dependency — confirm the version exposes `available_space()` per mount) to find the disk containing `app_dir` and return its available bytes; fall back to `None` on any failure.

```rust
/// Best-effort free bytes on the volume holding `app_dir`, probed ONCE at startup.
pub fn free_bytes_for(app_dir: &std::path::Path) -> Option<u64> {
    use sysinfo::Disks;
    let disks = Disks::new_with_refreshed_list();
    // Longest mount-point prefix match wins (handles nested mounts).
    disks.iter()
        .filter(|d| app_dir.starts_with(d.mount_point()))
        .max_by_key(|d| d.mount_point().as_os_str().len())
        .map(|d| d.available_space())
}
```

- [ ] **Step 2: Test the fallback (a bogus path yields `None` or a plausible value; never panics).**

```rust
#[test]
fn free_bytes_never_panics() {
    let _ = super::free_bytes_for(std::path::Path::new("Z:/definitely/not/mounted/here"));
    let some = super::free_bytes_for(&std::env::temp_dir());
    assert!(some.map_or(true, |b| b > 0));
}
```

- [ ] **Step 3: Run — expect PASS.**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd crates/client-app && cargo test -p maxsecu-client-app disk_free`

- [ ] **Step 4: Commit**

```bash
git add crates/client-app/src/disk_free.rs crates/client-app/src/lib.rs
git commit -m "feat(cache): startup disk free-space probe for the Disk-mode gauge denominator"
```

---

## Task 7: Commands — dual-mode `cache_stats` + `clear_*` + main.rs wiring

**Files:**
- Modify: `crates/client-app/src/commands/video.rs` (`cache_stats`, `clear_media_cache`), `crates/client-app/src/commands/settings.rs` or a new `commands/cache.rs` (`clear_thumb_cache`), `crates/client-app/src/main.rs` (manage states, handlers, Exit hook, startup free-space).
- Test: `cache_stats`/clear unit tests in `video.rs`.

- [ ] **Step 1: `cache_stats` returns dual-mode struct**

```rust
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct CacheStats {
    pub media_used: u64,
    pub thumb_used: u64,
    pub disk_mode: bool,
    pub disk_free_estimate: u64, // 0 when unknown / RAM mode
}
```
`cache_stats(media_cap_bytes, thumb_cap_bytes, media, thumb, disk_free)`: lock each; in Memory mode `set_cap` to the passed caps + report `memory_bytes()`; in Disk mode report `disk_bytes()` + the stashed `disk_free`. `disk_mode` from the live `cache_location` (read via `AppDir` settings or a managed flag).

- [ ] **Step 2: Clear commands**

```rust
#[tauri::command]
pub async fn clear_media_cache(media: State<'_, MediaCache>) -> Result<(), UiError> {
    media.0.lock().await.clear_and_zeroize(); Ok(())
}
#[tauri::command]
pub async fn clear_thumb_cache(thumb: State<'_, ThumbCache>) -> Result<(), UiError> {
    thumb.clear_and_zeroize().await; Ok(())
}
```

- [ ] **Step 3: `main.rs` wiring**

Build `MediaCache::open(app_dir, media_cap, loc)`, `SessionSeal::generate()` (wrap `Arc`), `ThumbCache::new(app_dir, thumb_cap, loc, seal.clone())`, and stash `disk_free::free_bytes_for(&app_dir)`; `.manage(...)` all. Register `cache_stats`, `clear_media_cache`, `clear_thumb_cache`; remove the old `ContentCache` manage + import. Extend `RunEvent::Exit`: `media.clear_and_zeroize()`, `thumb.clear_and_zeroize()`, drop/zeroize the `SessionSeal` (its `Zeroizing` key wipes on drop; ensure the managed `Arc` is the last ref or add an explicit zeroize). Because Exit runs in a sync callback, use `try_state` + `blocking_lock()` (tokio) or a `std::sync::Mutex` for the caches' clear path — mirror how `VideoPrepareCancel` handles the sync hook.

- [ ] **Step 4: Tests**

`clear_media_cache`/`clear_thumb_cache` zero their target and leave the other + any open job untouched; `cache_stats` never exceeds caps in Memory mode.

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd crates/client-app && cargo test -p maxsecu-client-app`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/src/commands/video.rs crates/client-app/src/commands/cache.rs crates/client-app/src/commands/settings.rs crates/client-app/src/main.rs crates/client-app/src/lib.rs
git commit -m "feat(cache): dual-mode cache_stats + clear_media/clear_thumb commands + Exit-hook zeroize & disk-wipe"
```

---

## Task 8: UI — two stacked gauges + Clear buttons + two settings knobs

**Files:**
- Modify: `crates/client-app/ui/src/core/types.ts`, `core/gauge.ts`, `components/ram-gauge.ts`, `components/settings-screen.ts`.
- Test: `crates/client-app/ui/src/**/*.test.ts` (gauge model, settings).

- [ ] **Step 1: `types.ts` — new `CacheStats`**

```ts
export interface CacheStats {
  media_used: number; thumb_used: number; disk_mode: boolean; disk_free_estimate: number;
}
```

- [ ] **Step 2: `gauge.ts` — model already takes (used, cap); reuse per bar.** Add a Disk-mode variant that allows `fillFraction > 1` (clamp the bar width to 100% but show the true % in the label).

- [ ] **Step 3: `ram-gauge.ts` — two bars + Clear**

Render two `.ram-gauge-row` blocks ("Media" / "Thumbnails"), each = bar + read-out + a `<button class="cache-clear">Clear</button>`. Poll `cache_stats` with both caps; in RAM mode denominator = each cap, in Disk mode denominator = `disk_free_estimate` and label suffix "(disk)". Clear button → `call("clear_media_cache")` / `call("clear_thumb_cache")` then immediate re-poll. Keep `role="meter"` + aria on each bar; buttons get `aria-label="Clear media cache"` / `"Clear thumbnails cache"`.

- [ ] **Step 4: `settings-screen.ts` — two cap controls + location select**

Replace the single RAM-cap control with **Media cache (MB)** and **Thumbnails cache (MB)** number inputs (both bounded by `ram_limits`), and ensure the location `<select>` shows RAM (Memory) as the default. Wire to `media_cache_cap_mb` / `thumb_cache_cap_mb` / `cache_location`.

- [ ] **Step 5: Typecheck + tests + esbuild build**

```bash
cd crates/client-app/ui && npm run typecheck && npm test && npm run build
```
Expected: tsc clean, all tests pass, `dist/main.js` regenerated.

- [ ] **Step 6: Commit**

```bash
git add crates/client-app/ui/src/core/types.ts crates/client-app/ui/src/core/gauge.ts crates/client-app/ui/src/components/ram-gauge.ts crates/client-app/ui/src/components/settings-screen.ts crates/client-app/ui/dist/main.js
git commit -m "feat(ui): two stacked cache gauges (Media/Thumbnails) with per-cache Clear + dual cap settings"
```

---

## Task 9: Security sign-off + holistic verification

**Files:**
- Create: `docs/security-review-2026-07-06-ram-cache-model.md`

- [ ] **Step 1: Write the sign-off** covering (from the spec's Security section): cross-video isolation (keyed by `(ns,file_id,seq/version)` → no cross-read); persistence posture (only ciphertext at rest in RAM; subkey zeroized on `cancel_video`); ephemeral-seal (unique nonces, AEAD auth, key never persisted, zeroized on close); Disk backend ciphertext-only + wiped on start & exit; Exit-hook zeroize; explicit residual (32-byte ephemeral key + transient webview frame can be paged/hibernated). Verdict PASS or list findings.

- [ ] **Step 2: Full build + test (both workspaces as relevant) + tsc**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd crates/client-app && cargo test -p maxsecu-client-app
cd ui && npm run typecheck && npm test && npm run build
```
Expected: all green.

- [ ] **Step 3: Rebuild the client bin + restage (manual smoke)**

```bash
export PATH="$HOME/.cargo/bin:$PATH"; cd crates/client-app && cargo build --bin maxsecu-client-app
```
Then (per the build gotcha) copy `crates/client-app/target/debug/maxsecu-client-app.exe` → `client/maxsecu-client-app.exe`, kill the old client PID, relaunch. **Do NOT restart the server.** Smoke: play a bundle's 3 videos at once → the Media gauge stays ≤100% and never sums past the cap; leave + re-open a video → instant (cache hit); lower the Media cap → evicts down; toggle to Disk → gauge shows on-disk/free-space; Clear buttons drop each bar to 0; close the app → (verify via logs/behavior) caches cleared.

- [ ] **Step 4: Commit the sign-off**

```bash
git add docs/security-review-2026-07-06-ram-cache-model.md
git commit -m "docs(security): sign-off for the RAM cache model rework"
```

- [ ] **Step 5:** Hand back to the user for the merge decision (superpowers:finishing-a-development-branch) — do NOT merge to `main` without explicit approval.

---

## Self-review checklist (run before dispatch)

- Spec §Component A→H all have a task: A=T1/T4, B=T5, C=T2, D=T3, E=T8, F=T7, G=T7, H=T6. ✓
- D8 (three-case eviction + persistence): T4 (persistence), T7 (clear/exit), LRU in T1. ✓
- Disk-mode (D5a): T1 (uncapped), T6 (free-space), T7 (dual-mode stats), T8 (gauge). ✓
- Migration (D3/D7): T3. ✓ Default RAM (D5b): T3. ✓
- Type consistency: `BlobCache`/`Ns`/`MediaCache`/`ThumbCache`/`SessionSeal`/`CacheStats{media_used,thumb_used,disk_mode,disk_free_estimate}` used consistently across T1–T8. ✓
- No `cargo fmt --all`, no `git add -A`: all adds scoped. ✓
