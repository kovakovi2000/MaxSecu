# MaxSecu Media App — UI Overhaul + Caching Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the MaxSecu media client match its approved design — a token-driven dark+flashy themeable look (light toggle), a real "My Content" route + status strip, a reactive settings store, skeletons/toasts/visible upload progress, and a Rust-side in-memory **decrypted-content cache** (Zeroizing, LRU by bytes, sized from system RAM) — while the TCB/backend stay byte-for-byte unchanged.

**Architecture:** Application layer only (`crates/client-app` + its `ui/`). The Rust side gains a `ContentCache` managed-state (LRU, Zeroizing, zeroized on evict + on app close) consulted by `decrypt_card`/`open_content`; a `ram.rs` module reads physical RAM via the one new dep `sysinfo` to bound the cache cap; `SettingsConfig` gains `appearance.theme`. The UI keeps vanilla TS + Web Components: one shared reactive settings store drives theme/text-size/reduced-motion live, a toast host + skeletons + a hardened serial queue fix the feedback and viewer-stuck bugs, and `styles.css` is rewritten as a hand-rolled CSS-token design system.

**Tech Stack:** Rust (Tauri 2, `tokio`, `zeroize`, new pinned `sysinfo`), TypeScript (esbuild 0.21.5, tsc 5.4.5, `@tauri-apps/api` 2.1.1), `node:test`, hand-rolled CSS custom properties.

---

## Ground rules (read once, apply to every task)

- **cargo is NOT on PATH.** Prefix every shell:
  - bash: `export PATH="$HOME/.cargo/bin:$PATH";`
  - PowerShell: `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path";`
- **TCB/backend are OFF-LIMITS:** do not touch `client-core`, `crypto`, `encoding`, `server`, `admin-core`, `sink-server`, `media-worker`, `media-launcher`, `media-transcode-worker`. Only `crates/client-app/src/**` and `crates/client-app/ui/**`.
- **NEVER run `cargo fmt --all`** (repo-wide pre-existing rustfmt drift). New `client-app` + `ui` lines stay fmt-clean by matching in-file style.
- **Only new dependency allowed:** `sysinfo` (Task 1). Flag it in the commit body for `cargo deny`/`cargo audit`. No other new deps.
- **No secrets/keys/whole-plaintext cross the Tauri seam** beyond the image/blog bytes that already cross today (the viewer's `image_png_b64`/`blog_text` and the card `thumbnail_b64`). The cache holds decrypted bytes **in the Rust process only**; it never widens what the UI receives.
- **Do NOT git push or merge.** Commit locally only. (Each task ends in a local commit.)
- **Per-task verification (run after every task that touches the named layer):**
  - UI: `cd crates/client-app/ui && npm run build && npm test && npm run test:a11y && npm run typecheck`
  - Rust unit: `cargo test -p maxsecu-client-app --lib`
  - Rust e2e (must STAY green): `cargo test -p maxsecu-client-app --test browse_view_e2e --test upload_e2e`
    (video e2e `video_e2e`/`video_upload_e2e` run single-threaded: `cargo test -p maxsecu-client-app --test video_e2e -- --test-threads=1` — only if a task could affect them; this plan does not change the video path.)
  - Lint (Rust tasks): `cargo clippy -p maxsecu-client-app -- -D warnings`
- **Known host flake:** a full `cargo test -p maxsecu-client-app --lib` may occasionally abort in pre-existing `keystore::tests` (argon2 host resource flake, unrelated). If that single module aborts, re-run the new module's tests targeted (e.g. `cargo test -p maxsecu-client-app --lib content_cache::`) to confirm green.

## Design decisions locked for this plan (resolve ambiguities once)

1. **Cache shape.** One `ContentCache` keyed by `(file_id:[u8;16], version:u64)`. Each entry carries small render `meta` (title, tags, file_type, author_fp, recovery_ok, mine, optional `thumbnail_b64`) **plus** an optional `Zeroizing<Vec<u8>>` of the **content** payload (raw image PNG bytes or raw blog UTF-8). `decrypt_card` fills/reads `meta` (header-only); `open_content` fills/reads `meta + content`. LRU eviction by **resident bytes** (content + thumbnail + meta string lengths). An entry whose content exceeds the whole cap is served through, never stored.
2. **Version plumbing.** `CardRequest`/`OpenContentRequest` gain an optional `version: Option<u64>`. The feed knows each entry's `version` (D35 listing), so cards/viewer pass it → a cache hit needs **zero network**. When absent, the command fetches the cheap §8.5 view (no content chunks), learns `view.version`, then checks the cache before the expensive chunk download + decrypt.
3. **Theme.** `appearance.theme: "dark" | "light"`, default `"dark"`, applied via `<html data-theme>`. Persisted in `settings.json`.
4. **My Content.** New route `#/mine` → `<feed-screen mine>` (owner-filtered, the "only my uploads" control preset + hidden). Nav link "My Content" replaces the dead `<span>`.
5. **Status strip / active-tasks.** A small JS counter store subscribes to `EVT_UPLOAD` + `EVT_FETCH` and renders an active-tasks count in the status strip; no backend change.

---

## Task 1: RAM sizing — `sysinfo` dep + `ram_limits()` command

**Files:**
- Modify: `crates/client-app/Cargo.toml`
- Create: `crates/client-app/src/ram.rs`
- Modify: `crates/client-app/src/lib.rs`

- [ ] **Step 1: Add the dep.** In `crates/client-app/Cargo.toml`, under `[dependencies]` (after `base64 = "0.22"`), add:

```toml
# Physical-RAM read for the in-memory decrypted-content cache sizing (the cap is
# bounded to total-RAM − 6 GB). The ONLY new dependency in the UI-overhaul work;
# flagged for `cargo deny`/`cargo audit`. Pure-Rust on Windows (no new C).
sysinfo = { version = "0.33", default-features = false, features = ["system"] }
```

- [ ] **Step 2: Write the failing test.** Create `crates/client-app/src/ram.rs`:

```rust
//! Physical-RAM sizing for the in-memory decrypted-content cache (spec §6.1).
//! The cap defaults to 10% of system RAM, floored at 64 MiB, and is never allowed
//! above (total − 6 GB) so the OS + app keep working room on small machines.

use serde::Serialize;

use crate::error::UiError;

const MIN_MB: u32 = 64;
const HEADROOM_MB: u64 = 6144; // 6 GiB reserved for the OS + the rest of the app.

/// The slider/number bounds the UI uses for the RAM-cache control, plus the
/// first-run default. All in whole MiB.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct RamLimits {
    pub default_mb: u32,
    pub min_mb: u32,
    pub max_mb: u32,
}

/// Pure RAM-cap math (unit-tested without touching the OS): max = max(min,
/// total − 6 GB); default = clamp(total / 10, min, max).
pub fn compute_ram_limits(total_mb: u64) -> RamLimits {
    let min_mb = MIN_MB;
    let ceiling = total_mb.saturating_sub(HEADROOM_MB) as u32;
    let max_mb = ceiling.max(min_mb);
    let ten_pct = (total_mb / 10) as u32;
    let default_mb = ten_pct.clamp(min_mb, max_mb);
    RamLimits {
        default_mb,
        min_mb,
        max_mb,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn big_machine_uses_ten_percent_under_a_total_minus_6gb_ceiling() {
        // 16 GiB total → max = 16384-6144 = 10240; default = 1638 (10%).
        let l = compute_ram_limits(16384);
        assert_eq!(l.min_mb, 64);
        assert_eq!(l.max_mb, 10240);
        assert_eq!(l.default_mb, 1638);
    }

    #[test]
    fn small_machine_floors_at_64mb() {
        // 4 GiB total → total-6GB saturates to 0 → max floored to 64; default
        // clamps up to 64.
        let l = compute_ram_limits(4096);
        assert_eq!(l.max_mb, 64);
        assert_eq!(l.default_mb, 64);
    }

    #[test]
    fn mid_machine_ceiling_and_default() {
        // 8 GiB total → max = 2048; default = 819 (10%).
        let l = compute_ram_limits(8192);
        assert_eq!(l.max_mb, 2048);
        assert_eq!(l.default_mb, 819);
    }
}
```

- [ ] **Step 3: Run the test to verify it fails (module not yet in lib).**

Run: `cargo test -p maxsecu-client-app --lib ram::` (bash: prefix PATH).
Expected: FAIL — `ram` is not a module of the crate yet (or `error[E0583]`/unresolved). 

- [ ] **Step 4: Register the module + add the OS read and command.** Append to `crates/client-app/src/ram.rs`:

```rust
/// Total physical RAM in whole MiB, via `sysinfo`. Only this function touches
/// the OS; `compute_ram_limits` stays pure for testing.
fn system_total_mb() -> u64 {
    use sysinfo::System;
    let mut sys = System::new();
    sys.refresh_memory();
    // `total_memory()` is BYTES on sysinfo 0.30+. Convert to MiB.
    sys.total_memory() / (1024 * 1024)
}

/// `ram_limits` — the slider/number bounds + first-run default for the RAM-cache
/// control. Read by the Settings screen + quick-settings so the UI cannot select
/// a cap above (total − 6 GB).
#[tauri::command]
pub async fn ram_limits() -> Result<RamLimits, UiError> {
    Ok(compute_ram_limits(system_total_mb()))
}
```

In `crates/client-app/src/lib.rs`, add `pub mod ram;` in alphabetical position (after `pub mod nothing`… i.e. between `pub mod layout;` and `pub mod session;` is not alphabetical — place it after `pub mod layout;`? The list is `keystore, layout, session…`; insert `pub mod ram;` between `layout` and `session`):

```rust
pub mod layout;
pub mod ram;
pub mod session;
```

- [ ] **Step 5: Run the tests + build.**

Run: `cargo test -p maxsecu-client-app --lib ram::` then `cargo build -p maxsecu-client-app`.
Expected: 3 ram tests PASS; build succeeds (sysinfo resolves). If `0.33` fails to resolve, run `cargo add sysinfo --no-default-features --features system -p maxsecu-client-app` to get the resolvable version, then **pin the exact resolved version** in `Cargo.toml` (e.g. `sysinfo = { version = "=0.33.1", … }`) to match repo pinning discipline.

- [ ] **Step 6: Verify deny/audit still pass with the new dep.**

Run: `cargo deny check 2>&1 | tail -20` and `cargo audit 2>&1 | tail -20` (from repo root).
Expected: no NEW denials/advisories attributable to `sysinfo`. If `cargo deny` reports a new transitive license needing an allow, add the minimal `allow` entry to `deny.toml` with a one-line justification comment (do not broaden bans; keep `ring`/`openssl` banned).

- [ ] **Step 7: Commit.**

```bash
git add crates/client-app/Cargo.toml crates/client-app/src/ram.rs crates/client-app/src/lib.rs deny.toml Cargo.lock
git commit -m "feat(client-app): add sysinfo-backed ram_limits() for cache sizing"
```

---

## Task 2: Settings model — `appearance.theme` + RAM-bounded normalize

**Files:**
- Modify: `crates/client-app/src/config.rs`
- Modify: `crates/client-app/ui/src/core/types.ts`

- [ ] **Step 1: Write the failing test.** In `crates/client-app/src/config.rs`, inside `mod tests`, add:

```rust
    #[test]
    fn appearance_theme_defaults_dark_and_normalizes() {
        let s = SettingsConfig::default();
        assert_eq!(s.appearance.theme, "dark");
        // An unknown theme normalizes back to dark.
        let mut bad = SettingsConfig::default();
        bad.appearance.theme = "neon".into();
        assert_eq!(bad.normalized().appearance.theme, "dark");
    }

    #[test]
    fn ram_cap_clamps_into_computed_bounds() {
        use crate::ram::compute_ram_limits;
        let limits = compute_ram_limits(16384); // min 64, max 10240
        let mut s = SettingsConfig::default();
        s.performance.ram_cache_cap_mb = 99_999;
        assert_eq!(
            s.normalized_with_ram(&limits).performance.ram_cache_cap_mb,
            10240
        );
        s.performance.ram_cache_cap_mb = 1;
        assert_eq!(
            s.normalized_with_ram(&limits).performance.ram_cache_cap_mb,
            64
        );
    }
```

- [ ] **Step 2: Run it to confirm it fails.**

Run: `cargo test -p maxsecu-client-app --lib config::tests::appearance_theme`
Expected: FAIL — no field `appearance`, no `normalized_with_ram`.

- [ ] **Step 3: Implement the model changes.** In `crates/client-app/src/config.rs`:

Add the appearance struct (after `ConnectionSettings`):

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppearanceSettings {
    /// "dark" (default) | "light". Applied via `<html data-theme>` in the UI.
    pub theme: String,
}
impl Default for AppearanceSettings {
    fn default() -> Self {
        Self {
            theme: "dark".into(),
        }
    }
}
```

Add the field to `SettingsConfig` (with `#[serde(default)]` so older files still load):

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SettingsConfig {
    #[serde(default)]
    pub a11y: A11ySettings,
    #[serde(default)]
    pub behavior: BehaviorSettings,
    #[serde(default)]
    pub performance: PerformanceSettings,
    #[serde(default)]
    pub connection: ConnectionSettings,
    #[serde(default)]
    pub appearance: AppearanceSettings,
}
```

Replace `normalized()` with a RAM-bounded version + a pure helper:

```rust
    /// Clamp/normalize untrusted values using the live RAM bounds. Convenience
    /// wrapper that reads the system RAM; the pure work is `normalized_with_ram`.
    pub fn normalized(&self) -> SettingsConfig {
        let limits = crate::ram::compute_ram_limits(crate::ram::system_total_mb_public());
        self.normalized_with_ram(&limits)
    }

    /// Pure normalization against explicit RAM bounds (unit-testable): clamp the
    /// RAM cache cap into [min,max], constrain text_size + theme to known sets.
    pub fn normalized_with_ram(&self, limits: &crate::ram::RamLimits) -> SettingsConfig {
        let mut s = self.clone();
        s.performance.ram_cache_cap_mb = s
            .performance
            .ram_cache_cap_mb
            .clamp(limits.min_mb, limits.max_mb);
        if !matches!(s.a11y.text_size.as_str(), "normal" | "large" | "larger") {
            s.a11y.text_size = "normal".into();
        }
        if !matches!(s.appearance.theme.as_str(), "dark" | "light") {
            s.appearance.theme = "dark".into();
        }
        s
    }
```

In `crates/client-app/src/ram.rs`, expose the OS read for `config`:

```rust
/// Public shim so `config::SettingsConfig::normalized()` can source the live total
/// without duplicating the sysinfo read. (Tests use `compute_ram_limits` directly.)
pub fn system_total_mb_public() -> u64 {
    system_total_mb()
}
```

Update the existing `settings_roundtrip_and_defaults_and_clamp` test's clamp assertion: replace `assert!(norm.performance.ram_cache_cap_mb <= 4096);` with a bounds-driven check:

```rust
        let limits = crate::ram::compute_ram_limits(crate::ram::system_total_mb_public());
        let norm = bad.normalized();
        assert!(norm.performance.ram_cache_cap_mb <= limits.max_mb);
        assert!(norm.performance.ram_cache_cap_mb >= limits.min_mb);
        assert_eq!(norm.a11y.text_size, "normal");
```

- [ ] **Step 4: Mirror the type in the UI.** In `crates/client-app/ui/src/core/types.ts`, extend `Settings`:

```ts
export interface Settings {
  a11y: { reduced_motion: boolean; high_contrast: boolean; text_size: "normal" | "large" | "larger" };
  behavior: { confirm_destructive: boolean };
  performance: { ram_cache_cap_mb: number };
  connection: { use_tor: boolean };
  appearance: { theme: "dark" | "light" };
}

// The RAM-cache slider/number bounds from the `ram_limits` command (Task 1).
export interface RamLimits { default_mb: number; min_mb: number; max_mb: number }
```

- [ ] **Step 5: Run Rust tests + UI typecheck.**

Run: `cargo test -p maxsecu-client-app --lib config::` then `cd crates/client-app/ui && npm run typecheck`.
Expected: config tests PASS. Typecheck will FAIL until the `defaults()`/`DEFAULTS` literals that build `Settings` include `appearance` — that is fixed in Tasks 11–12 which own those files. **For this task**, also patch the two existing literals so typecheck stays green now: in `quick-settings.ts` `defaults()` and `settings-screen.ts` `DEFAULTS`, add `appearance: { theme: "dark" }` to each object. (Their full redesign lands in Tasks 11–12.)

- [ ] **Step 6: Re-run typecheck + build.**

Run: `cd crates/client-app/ui && npm run typecheck && npm run build`. Expected: PASS.

- [ ] **Step 7: Commit.**

```bash
git add crates/client-app/src/config.rs crates/client-app/src/ram.rs crates/client-app/ui/src/core/types.ts crates/client-app/ui/src/components/quick-settings.ts crates/client-app/ui/src/components/settings-screen.ts
git commit -m "feat(client-app): settings appearance.theme + RAM-bounded normalize"
```

---

## Task 3: The in-memory decrypted-content cache (`content_cache.rs`)

**Files:**
- Create: `crates/client-app/src/content_cache.rs`
- Modify: `crates/client-app/src/lib.rs`

- [ ] **Step 1: Write the module + failing tests.** Create `crates/client-app/src/content_cache.rs`:

```rust
//! In-memory decrypted-content cache (spec §6). Holds image/blog decrypted
//! payloads — which already cross to the WebView today — resident in RAM so the
//! feed + viewer are instant on return. LRU-evicted by total resident bytes;
//! every payload is `Zeroizing`, so eviction/replace/clear wipes the plaintext.
//! Keyed by `(file_id, version)`. Video is intentionally OUT (frames live in the
//! confined worker). No key material is ever stored here.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use zeroize::Zeroizing;

use crate::dto::{CardDto, OpenedContentDto};

/// The cache key: a content id is unique per (file, version).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub file_id: [u8; 16],
    pub version: u64,
}

/// Small, render-ready metadata shared by the card + the content DTOs. No key
/// material; this is exactly what already crosses to the UI.
#[derive(Debug, Clone)]
pub struct CachedMeta {
    pub file_type: String,
    pub title: String,
    pub tags: Vec<String>,
    pub thumbnail_b64: Option<String>,
    pub author_fp: String,
    pub recovery_ok: bool,
    pub mine: bool,
}

impl CachedMeta {
    fn approx_bytes(&self) -> usize {
        self.file_type.len()
            + self.title.len()
            + self.tags.iter().map(|t| t.len()).sum::<usize>()
            + self.thumbnail_b64.as_ref().map_or(0, |t| t.len())
            + self.author_fp.len()
    }
}

struct Entry {
    meta: CachedMeta,
    /// Raw content payload (image PNG bytes or blog UTF-8). `None` for a card-only
    /// entry (header-only decrypt fetched no content). `Zeroizing`: wiped on drop.
    content: Option<Zeroizing<Vec<u8>>>,
    bytes: usize,
    last_used: u64,
}

impl Entry {
    fn recompute_bytes(&mut self) {
        self.bytes =
            self.meta.approx_bytes() + self.content.as_ref().map_or(0, |c| c.len());
    }
}

struct CacheInner {
    map: HashMap<CacheKey, Entry>,
    total: usize,
    cap: usize,
    clock: u64,
}

/// Managed-state handle. `Mutex` (sync — the cache ops are fast, no await held).
pub struct ContentCache(Mutex<CacheInner>);

impl ContentCache {
    pub fn new(cap_bytes: usize) -> Self {
        ContentCache(Mutex::new(CacheInner {
            map: HashMap::new(),
            total: 0,
            cap: cap_bytes,
            clock: 0,
        }))
    }

    fn tick(inner: &mut CacheInner) -> u64 {
        inner.clock += 1;
        inner.clock
    }

    /// Reconstruct a `CardDto` from a cached entry's meta (header-only data).
    pub fn get_card(&self, key: CacheKey, file_id_hex: &str) -> Option<CardDto> {
        let mut inner = self.0.lock().unwrap();
        let t = Self::tick(&mut inner);
        let e = inner.map.get_mut(&key)?;
        e.last_used = t;
        let m = &e.meta;
        Some(CardDto {
            file_id: file_id_hex.to_owned(),
            file_type: m.file_type.clone(),
            version: key.version,
            title: m.title.clone(),
            tags: m.tags.clone(),
            thumbnail_b64: m.thumbnail_b64.clone(),
            mine: m.mine,
            author_fp: m.author_fp.clone(),
            recovery_ok: m.recovery_ok,
        })
    }

    /// Reconstruct an `OpenedContentDto` — only a hit if the content payload is
    /// resident (a card-only entry returns `None` so the caller fetches content).
    pub fn get_content(&self, key: CacheKey, file_id_hex: &str) -> Option<OpenedContentDto> {
        let mut inner = self.0.lock().unwrap();
        let t = Self::tick(&mut inner);
        let e = inner.map.get_mut(&key)?;
        let content = e.content.as_ref()?;
        e.last_used = t;
        let (image_png_b64, blog_text) = if e.meta.file_type == "image" {
            (Some(B64.encode(content.as_slice())), None)
        } else {
            (None, Some(String::from_utf8_lossy(content).into_owned()))
        };
        Some(OpenedContentDto {
            file_id: file_id_hex.to_owned(),
            file_type: e.meta.file_type.clone(),
            version: key.version,
            title: e.meta.title.clone(),
            tags: e.meta.tags.clone(),
            image_png_b64,
            blog_text,
            author_fp: e.meta.author_fp.clone(),
            recovery_ok: e.meta.recovery_ok,
        })
    }

    /// Insert/update the header-only meta for a card (no content).
    pub fn put_card(&self, key: CacheKey, meta: CachedMeta) {
        let mut inner = self.0.lock().unwrap();
        let t = Self::tick(&mut inner);
        Self::upsert(&mut inner, key, meta, None, t);
        Self::evict_to_fit(&mut inner);
    }

    /// Insert/update with the decrypted content payload resident.
    pub fn put_content(&self, key: CacheKey, meta: CachedMeta, content: Vec<u8>) {
        let mut inner = self.0.lock().unwrap();
        // Oversize-vs-cap: serve through, never store (and never evict everything
        // for one giant item).
        let projected = meta.approx_bytes() + content.len();
        if projected > inner.cap {
            // Drop any stale smaller entry under this key, then bail.
            if let Some(old) = inner.map.remove(&key) {
                inner.total -= old.bytes;
            }
            return;
        }
        let t = Self::tick(&mut inner);
        Self::upsert(&mut inner, key, meta, Some(Zeroizing::new(content)), t);
        Self::evict_to_fit(&mut inner);
    }

    fn upsert(
        inner: &mut CacheInner,
        key: CacheKey,
        meta: CachedMeta,
        content: Option<Zeroizing<Vec<u8>>>,
        now: u64,
    ) {
        if let Some(old) = inner.map.remove(&key) {
            inner.total -= old.bytes;
        }
        let mut e = Entry {
            meta,
            content,
            bytes: 0,
            last_used: now,
        };
        e.recompute_bytes();
        inner.total += e.bytes;
        inner.map.insert(key, e);
    }

    fn evict_to_fit(inner: &mut CacheInner) {
        while inner.total > inner.cap {
            // Find the least-recently-used key.
            let Some((&victim, _)) = inner
                .map
                .iter()
                .min_by_key(|(_, e)| e.last_used)
            else {
                break;
            };
            if let Some(e) = inner.map.remove(&victim) {
                inner.total -= e.bytes; // e drops here → Zeroizing wipes content.
            }
        }
    }

    /// Drop a specific entry (e.g. a newer version supersedes it).
    pub fn invalidate(&self, key: CacheKey) {
        let mut inner = self.0.lock().unwrap();
        if let Some(e) = inner.map.remove(&key) {
            inner.total -= e.bytes;
        }
    }

    /// Live cap change (Settings RAM control). Shrinks → evicts to fit immediately.
    pub fn set_cap(&self, cap_bytes: usize) {
        let mut inner = self.0.lock().unwrap();
        inner.cap = cap_bytes;
        Self::evict_to_fit(&mut inner);
    }

    /// Wipe everything (app close). Every content payload is `Zeroizing`, so the
    /// plaintext is zeroed as each entry drops.
    pub fn clear_and_zeroize(&self) {
        let mut inner = self.0.lock().unwrap();
        inner.map.clear(); // each Entry drops → Zeroizing<Vec<u8>> wiped.
        inner.total = 0;
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.0.lock().unwrap().map.len()
    }
    #[cfg(test)]
    fn total(&self) -> usize {
        self.0.lock().unwrap().total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(title: &str) -> CachedMeta {
        CachedMeta {
            file_type: "blog".into(),
            title: title.into(),
            tags: vec![],
            thumbnail_b64: None,
            author_fp: "ab".into(),
            recovery_ok: true,
            mine: false,
        }
    }
    fn key(b: u8, v: u64) -> CacheKey {
        CacheKey {
            file_id: [b; 16],
            version: v,
        }
    }

    #[test]
    fn put_then_get_content_round_trips_bytes() {
        let c = ContentCache::new(1024);
        c.put_content(key(1, 1), meta("hi"), b"hello world".to_vec());
        let got = c.get_content(key(1, 1), "01".repeat(16).as_str()).unwrap();
        assert_eq!(got.blog_text.unwrap(), "hello world");
        assert_eq!(got.title, "hi");
    }

    #[test]
    fn lru_evicts_least_recently_used_by_bytes() {
        // cap fits ~2 small entries; a 3rd evicts the oldest-touched.
        let c = ContentCache::new(60);
        c.put_content(key(1, 1), meta("a"), vec![0u8; 20]);
        c.put_content(key(2, 1), meta("b"), vec![0u8; 20]);
        // Touch #1 so #2 is now the LRU.
        let _ = c.get_content(key(1, 1), "x");
        c.put_content(key(3, 1), meta("c"), vec![0u8; 20]);
        assert!(c.get_content(key(2, 1), "x").is_none(), "LRU #2 evicted");
        assert!(c.get_content(key(1, 1), "x").is_some());
        assert!(c.get_content(key(3, 1), "x").is_some());
    }

    #[test]
    fn oversize_content_is_not_stored() {
        let c = ContentCache::new(50);
        c.put_content(key(1, 1), meta("big"), vec![0u8; 1000]);
        assert!(c.get_content(key(1, 1), "x").is_none());
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn set_cap_shrink_evicts() {
        let c = ContentCache::new(1000);
        c.put_content(key(1, 1), meta("a"), vec![0u8; 200]);
        c.put_content(key(2, 1), meta("b"), vec![0u8; 200]);
        c.set_cap(150); // both now over → evict until ≤150
        assert!(c.total() <= 150);
    }

    #[test]
    fn clear_and_zeroize_empties() {
        let c = ContentCache::new(1000);
        c.put_content(key(1, 1), meta("a"), vec![0u8; 200]);
        c.clear_and_zeroize();
        assert_eq!(c.len(), 0);
        assert_eq!(c.total(), 0);
    }

    #[test]
    fn card_only_entry_has_no_content_hit() {
        let c = ContentCache::new(1000);
        c.put_card(key(1, 1), meta("card"));
        assert!(c.get_card(key(1, 1), "x").is_some());
        assert!(c.get_content(key(1, 1), "x").is_none());
    }
}
```

- [ ] **Step 2: Register the module.** In `crates/client-app/src/lib.rs`, add `pub mod content_cache;` after `pub mod config;`:

```rust
pub mod config;
pub mod content_cache;
pub mod directory;
```

- [ ] **Step 3: Run the tests.**

Run: `cargo test -p maxsecu-client-app --lib content_cache::`
Expected: 6 tests PASS.

- [ ] **Step 4: Clippy + build.**

Run: `cargo clippy -p maxsecu-client-app -- -D warnings`
Expected: clean.

- [ ] **Step 5: Commit.**

```bash
git add crates/client-app/src/content_cache.rs crates/client-app/src/lib.rs
git commit -m "feat(client-app): Zeroizing LRU in-memory decrypted-content cache"
```

---

## Task 4: Wire the cache as managed state + exit-zeroize + register `ram_limits`

**Files:**
- Modify: `crates/client-app/src/main.rs`

- [ ] **Step 1: Edit `main.rs`.** Replace the body of `fn main()` so the cache is managed state (cap sourced from persisted settings), `ram_limits` is registered, and `RunEvent::Exit` zeroizes the cache:

```rust
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use maxsecu_client_app::commands::auth::{AppDir, ConnectLock, Session};
use maxsecu_client_app::config::SettingsConfig;
use maxsecu_client_app::content_cache::ContentCache;

fn main() {
    let app_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    let _ = maxsecu_client_app::layout::ensure_portable_layout(&app_dir);

    // Initial cache cap from persisted settings (normalized to the live RAM
    // bounds). MiB → bytes.
    let cap_bytes =
        SettingsConfig::load(&app_dir).performance.ram_cache_cap_mb as usize * 1024 * 1024;

    let app = tauri::Builder::default()
        .manage(AppDir(app_dir))
        .manage(Session::new())
        .manage(ConnectLock::new())
        .manage(maxsecu_client_app::jobs::UploadJobs::new())
        .manage(maxsecu_client_app::jobs::VideoJobs::new())
        .manage(ContentCache::new(cap_bytes))
        .invoke_handler(tauri::generate_handler![
            maxsecu_client_app::commands::connection::connect,
            maxsecu_client_app::commands::auth::unlock_keystore,
            maxsecu_client_app::commands::auth::logout,
            maxsecu_client_app::commands::feed::list_feed,
            maxsecu_client_app::commands::feed::decrypt_card,
            maxsecu_client_app::commands::viewer::open_content,
            maxsecu_client_app::commands::search::search_local,
            maxsecu_client_app::commands::bootstrap::register_glassbreak,
            maxsecu_client_app::commands::bootstrap::create_first_admin,
            maxsecu_client_app::commands::bootstrap::register_user,
            maxsecu_client_app::commands::bootstrap::account_status,
            maxsecu_client_app::commands::admin::list_pending,
            maxsecu_client_app::commands::admin::issue_voucher,
            maxsecu_client_app::commands::admin::request_approval,
            maxsecu_client_app::commands::upload::stage_upload,
            maxsecu_client_app::commands::upload::confirm_upload,
            maxsecu_client_app::commands::upload::cancel_upload,
            maxsecu_client_app::commands::upload::upload_jobs,
            maxsecu_client_app::commands::video::preview_video,
            maxsecu_client_app::commands::settings::get_settings,
            maxsecu_client_app::commands::settings::set_settings,
            maxsecu_client_app::commands::settings::change_password,
            maxsecu_client_app::commands::settings::export_keystore,
            maxsecu_client_app::ram::ram_limits,
            maxsecu_client_app::commands::video::open_video,
            maxsecu_client_app::commands::video::video_seek,
            maxsecu_client_app::commands::video::video_set_volume,
            maxsecu_client_app::commands::video::cancel_video,
        ])
        .build(tauri::generate_context!())
        .expect("error while running MaxSecu client");

    // Zeroize the decrypted-content cache on shutdown so no plaintext survives the
    // process (spec §6 — zeroized on app close, in addition to on-evict).
    app.run(|app_handle, event| {
        if let tauri::RunEvent::Exit = event {
            if let Some(cache) = app_handle.try_state::<ContentCache>() {
                cache.clear_and_zeroize();
            }
        }
    });
}
```

- [ ] **Step 2: Build.**

Run: `cargo build -p maxsecu-client-app`
Expected: compiles. (If `try_state` is not found, it is `tauri::Manager::try_state`; add `use tauri::Manager;` at the top.)

- [ ] **Step 3: Confirm e2e still green (no behavior change yet).**

Run: `cargo test -p maxsecu-client-app --test browse_view_e2e --test upload_e2e`
Expected: PASS.

- [ ] **Step 4: Commit.**

```bash
git add crates/client-app/src/main.rs
git commit -m "feat(client-app): manage ContentCache + zeroize on exit + register ram_limits"
```

---

## Task 5: Integrate the cache + version into `decrypt_card` / `open_content` + live `set_cap`

**Files:**
- Modify: `crates/client-app/src/dto.rs`
- Modify: `crates/client-app/src/commands/feed.rs`
- Modify: `crates/client-app/src/commands/viewer.rs`
- Modify: `crates/client-app/src/commands/settings.rs`
- Modify: `crates/client-app/ui/src/core/types.ts`

- [ ] **Step 1: Add optional `version` to the request DTOs.** In `crates/client-app/src/dto.rs`, edit both requests:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct CardRequest {
    pub file_id: String,
    /// The version the feed already knows (D35 listing). When present, a cache hit
    /// needs zero network. Absent → the command learns it from the §8.5 view.
    #[serde(default)]
    pub version: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpenContentRequest {
    pub file_id: String,
    #[serde(default)]
    pub version: Option<u64>,
}
```

- [ ] **Step 2: Build a `CachedMeta` from a decoded card/content + insert the cache reads/writes in `feed.rs`.** In `crates/client-app/src/commands/feed.rs`:

Add to the `decrypt_card` signature a cache param and short-circuit. Replace the function head + add the pre-check and the populate. Concretely, change the signature to include:

```rust
    cache: State<'_, crate::content_cache::ContentCache>,
```

Right after `let file_id = hex16(&req.file_id)?;` add the zero-network pre-check:

```rust
    use crate::content_cache::{CacheKey, CachedMeta};
    // Zero-network hit when the caller passed the version it already knows.
    if let Some(v) = req.version {
        if let Some(card) = cache.get_card(CacheKey { file_id, version: v }, &req.file_id) {
            return Ok(card);
        }
    }
```

After the `view` is parsed (`let view = crate::download::parse_file_view(&view_json)?;`), add a post-view pre-check (covers the no-version-supplied case, saving the header decrypt):

```rust
    if req.version.is_none() {
        if let Some(card) =
            cache.get_card(CacheKey { file_id, version: view.version }, &req.file_id)
        {
            return Ok(card);
        }
    }
```

Then, just before `Ok(card)` at the end (after the best-effort index upsert block), populate the cache:

```rust
    cache.put_card(
        CacheKey {
            file_id,
            version: opened.version,
        },
        CachedMeta {
            file_type: card.file_type.clone(),
            title: card.title.clone(),
            tags: card.tags.clone(),
            thumbnail_b64: card.thumbnail_b64.clone(),
            author_fp: card.author_fp.clone(),
            recovery_ok: card.recovery_ok,
            mine: card.mine,
        },
    );
```

- [ ] **Step 3: Insert the cache into `open_content` in `viewer.rs`.** In `crates/client-app/src/commands/viewer.rs`:

Add a cache param to `open_content` (the outer command) and thread it into `open_content_inner`:

```rust
pub async fn open_content(
    req: OpenContentRequest,
    app: tauri::AppHandle,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
    cache: State<'_, crate::content_cache::ContentCache>,
) -> Result<OpenedContentDto, UiError> {
    let emit = |p: FetchPhase| {
        let _ = app.emit(EVT_FETCH, p);
    };
    let out = open_content_inner(&req, &dir, &session, &connect_lock, &cache, &emit).await;
    if let Err(e) = &out {
        emit(FetchPhase::Failed {
            file_id: req.file_id.clone(),
            code: e.code.clone(),
        });
    }
    out
}
```

In `open_content_inner`, add the `cache` param and the pre-checks. Signature:

```rust
async fn open_content_inner(
    req: &OpenContentRequest,
    dir: &State<'_, AppDir>,
    session: &State<'_, Session>,
    connect_lock: &State<'_, ConnectLock>,
    cache: &State<'_, crate::content_cache::ContentCache>,
    emit: &impl Fn(FetchPhase),
) -> Result<OpenedContentDto, UiError> {
```

Right after `let file_id = hex16(&req.file_id)?;` add the zero-network pre-check:

```rust
    use crate::content_cache::{CacheKey, CachedMeta};
    if let Some(v) = req.version {
        if let Some(dto) = cache.get_content(CacheKey { file_id, version: v }, &req.file_id) {
            emit(FetchPhase::Ready {
                file_id: req.file_id.clone(),
            });
            return Ok(dto);
        }
    }
```

After `let view = parse_file_view(&view_json)?;` add the post-view pre-check (saves the big chunk download + decrypt):

```rust
    if req.version.is_none() {
        if let Some(dto) =
            cache.get_content(CacheKey { file_id, version: view.version }, &req.file_id)
        {
            emit(FetchPhase::Ready {
                file_id: req.file_id.clone(),
            });
            return Ok(dto);
        }
    }
```

After `let (image_png_b64, blog_text) = shape_content(manifest.file_type, &opened.streams)?;` capture the RAW content bytes for caching (the cache stores raw, reconstructs on read):

```rust
    // Raw content payload for the cache (image PNG bytes / blog UTF-8). The DTO
    // carries the shaped form; the cache stores raw + reconstructs identically.
    let raw_content: Vec<u8> = opened
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Content)
        .map(|s| s.plaintext.clone())
        .unwrap_or_default();
```

Then, right before the final `Ok(OpenedContentDto { … })`, populate the cache (video file_type is never cached — shape_content already errored for video, so this branch only runs for image/blog):

```rust
    cache.put_content(
        CacheKey {
            file_id,
            version: opened.version,
        },
        CachedMeta {
            file_type: file_type_name(manifest.file_type),
            title: title.clone(),
            tags: tags.clone(),
            thumbnail_b64: None,
            author_fp: hex(&author.fingerprint[..8]),
            recovery_ok: opened.recovery_grant_ok,
            mine: my_id == author.user_id,
        },
        raw_content,
    );
```

Note: `file_type_name`, `hex`, `StreamType` are already imported in `viewer.rs`.

- [ ] **Step 4: Live cap on `set_settings`.** In `crates/client-app/src/commands/settings.rs`, give `set_settings` the cache and apply the new cap:

```rust
#[tauri::command]
pub async fn set_settings(
    settings: SettingsConfig,
    dir: State<'_, AppDir>,
    cache: State<'_, crate::content_cache::ContentCache>,
) -> Result<SettingsConfig, UiError> {
    let norm = settings.normalized();
    norm.save(&dir.0)
        .map_err(|_| UiError::new("settings_failed", "Could not save settings."))?;
    // Apply the (normalized) RAM-cache cap live: a smaller cap evicts now.
    cache.set_cap(norm.performance.ram_cache_cap_mb as usize * 1024 * 1024);
    Ok(norm)
}
```

- [ ] **Step 5: Mirror `version` in the UI request types.** In `crates/client-app/ui/src/core/types.ts`, the `decrypt_card`/`open_content` callers pass `version` inline (no dedicated interface), so no type change is strictly required — but add a note comment near `Card`/`OpenedContent` that `version` may be passed in the request. (No code change; the UI plumbing lands in Tasks 13–14.)

- [ ] **Step 6: Build + unit + e2e.**

Run:
```
cargo clippy -p maxsecu-client-app -- -D warnings
cargo test -p maxsecu-client-app --lib
cargo test -p maxsecu-client-app --test browse_view_e2e --test upload_e2e
```
Expected: clippy clean; lib tests PASS; **both e2e PASS** (the commands aren't exercised by e2e, which drives the lower-level modules — so identical verified bytes are guaranteed; the cache only short-circuits the command wrappers).

- [ ] **Step 7: Commit.**

```bash
git add crates/client-app/src/dto.rs crates/client-app/src/commands/feed.rs crates/client-app/src/commands/viewer.rs crates/client-app/src/commands/settings.rs crates/client-app/ui/src/core/types.ts
git commit -m "feat(client-app): consult the content cache in card/content opens + live cap"
```

---

## Task 6: Shared reactive settings store (UI)

**Files:**
- Modify: `crates/client-app/ui/src/core/settings.ts`
- Create: `crates/client-app/ui/src/core/settings-store.test.ts`
- Modify: `crates/client-app/ui/package.json` (add the new test file to the `test` script)

- [ ] **Step 1: Write the failing test.** Create `crates/client-app/ui/src/core/settings-store.test.ts`:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { SettingsStore } from "./settings-store.ts";
import type { Settings } from "./types.ts";

function base(): Settings {
  return {
    a11y: { reduced_motion: false, high_contrast: false, text_size: "normal" },
    behavior: { confirm_destructive: false },
    performance: { ram_cache_cap_mb: 256 },
    connection: { use_tor: false },
    appearance: { theme: "dark" },
  };
}

test("subscribe is called immediately with current state", () => {
  const s = new SettingsStore(base());
  let seen: Settings | null = null;
  s.subscribe((v) => (seen = v));
  assert.equal(seen!.appearance.theme, "dark");
});

test("patch merges a nested section and notifies", () => {
  const s = new SettingsStore(base());
  let seen: Settings | null = null;
  s.subscribe((v) => (seen = v));
  s.patchLocal({ appearance: { theme: "light" } });
  assert.equal(seen!.appearance.theme, "light");
  assert.equal(seen!.a11y.text_size, "normal", "other sections preserved");
});

test("unsubscribe stops notifications", () => {
  const s = new SettingsStore(base());
  let count = 0;
  const off = s.subscribe(() => count++);
  off();
  s.patchLocal({ appearance: { theme: "light" } });
  assert.equal(count, 1, "only the immediate call fired");
});
```

> The store is split into a **pure** core (`SettingsStore`, no Tauri import — testable in node) and the Tauri-aware glue in `settings.ts`. This keeps `node:test` runnable without mocking `@tauri-apps/api`.

- [ ] **Step 2: Create the pure store.** Create `crates/client-app/ui/src/core/settings-store.ts`:

```ts
import type { Settings } from "./types.ts";

export type SettingsListener = (s: Settings) => void;

// A small reactive store: single source of truth for the current Settings. Pure
// (no Tauri import) so it is unit-testable. `patchLocal` does a one-level-deep
// merge of section objects and notifies subscribers; persistence lives in the
// Tauri-aware wrapper in settings.ts.
export class SettingsStore {
  private state: Settings;
  private listeners = new Set<SettingsListener>();
  constructor(initial: Settings) {
    this.state = initial;
  }
  get(): Settings {
    return this.state;
  }
  set(next: Settings): void {
    this.state = next;
    this.notify();
  }
  // Deep-merge one or more section patches (e.g. { appearance: { theme } }).
  patchLocal(patch: Partial<Settings>): void {
    const cur = this.state as Record<string, Record<string, unknown>>;
    const merged: Record<string, Record<string, unknown>> = { ...cur };
    for (const [section, vals] of Object.entries(patch)) {
      merged[section] = { ...(cur[section] ?? {}), ...(vals as Record<string, unknown>) };
    }
    this.state = merged as unknown as Settings;
    this.notify();
  }
  subscribe(l: SettingsListener): () => void {
    this.listeners.add(l);
    l(this.state);
    return () => this.listeners.delete(l);
  }
  private notify(): void {
    for (const l of [...this.listeners]) l(this.state);
  }
}
```

- [ ] **Step 3: Run the test (fails — file just created but package script not updated).**

Add the test to the script first: in `crates/client-app/ui/package.json`, extend `test`:

```json
    "test": "node --experimental-strip-types --test src/core/store.test.ts src/core/settings-store.test.ts src/core/webgl-yuv.test.ts src/core/player.test.ts",
```

Run: `cd crates/client-app/ui && npm test`
Expected: the 3 settings-store tests PASS (and existing tests stay green).

- [ ] **Step 4: Rewrite `settings.ts` to expose the singleton + theme apply + persistence.** Replace `crates/client-app/ui/src/core/settings.ts`:

```ts
import { call } from "./rpc.ts";
import type { Settings } from "./types.ts";
import { SettingsStore } from "./settings-store.ts";

const DEFAULTS: Settings = {
  a11y: { reduced_motion: false, high_contrast: false, text_size: "normal" },
  behavior: { confirm_destructive: false },
  performance: { ram_cache_cap_mb: 256 },
  connection: { use_tor: false },
  appearance: { theme: "dark" },
};

// The single shared settings store (spec §7). Settings screen, quick-settings,
// and the shell theme all read/write THIS instance, so they always agree and
// apply live.
export const settingsStore = new SettingsStore(DEFAULTS);

// Apply settings to the document: theme + a11y data-attrs. styles.css keys on
// them. Reduced-motion ALSO respects the OS via a media query in styles.css.
export function applySettings(s: Settings): void {
  const root = document.documentElement;
  root.setAttribute("data-theme", s.appearance.theme);
  root.toggleAttribute("data-reduced-motion", s.a11y.reduced_motion);
  root.toggleAttribute("data-high-contrast", s.a11y.high_contrast);
  root.setAttribute("data-text-size", s.a11y.text_size);
}

// Load persisted settings into the store and apply them. Safe on boot. Returns
// the loaded settings, or null on failure (defaults stay).
export async function loadAndApplySettings(): Promise<Settings | null> {
  try {
    const s = await call<Settings>("get_settings");
    settingsStore.set(s);
    applySettings(s);
    return s;
  } catch {
    return null;
  }
}

// Persist a patch: merge into the store, push to the backend, reflect any
// normalization (clamping) the backend returns, and apply live. Throws the
// sanitized UiError on failure (callers surface it).
export async function updateSettings(patch: Partial<Settings>): Promise<Settings> {
  settingsStore.patchLocal(patch);
  const norm = await call<Settings>("set_settings", { settings: settingsStore.get() });
  settingsStore.set(norm);
  applySettings(norm);
  return norm;
}

// Subscribe the document theme/a11y attrs to every store change (call once on
// boot, after loadAndApplySettings, so live edits from any screen apply).
export function bindDocumentToSettings(): () => void {
  return settingsStore.subscribe((s) => applySettings(s));
}
```

- [ ] **Step 5: Typecheck + build.** (Callers in quick-settings/settings-screen still use the old `applySettings(norm)` shape — still exported, so they compile. Their refactor to the store is Tasks 11–12.)

Run: `cd crates/client-app/ui && npm run typecheck && npm run build && npm test`
Expected: PASS.

- [ ] **Step 6: Commit.**

```bash
git add crates/client-app/ui/src/core/settings.ts crates/client-app/ui/src/core/settings-store.ts crates/client-app/ui/src/core/settings-store.test.ts crates/client-app/ui/package.json
git commit -m "feat(ui): shared reactive settings store + theme apply"
```

---

## Task 7: Harden the serial queue (priority + cancel + guaranteed lock release)

**Files:**
- Modify: `crates/client-app/ui/src/core/serial.ts`
- Create: `crates/client-app/ui/src/core/serial.test.ts`
- Modify: `crates/client-app/ui/package.json` (add the test file)

- [ ] **Step 1: Write the failing test.** Create `crates/client-app/ui/src/core/serial.test.ts`:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { serial, serialPriority, cancelPending } from "./serial.ts";

const tick = () => new Promise((r) => setTimeout(r, 5));

test("tasks run one at a time, in FIFO order", async () => {
  const order: number[] = [];
  const a = serial(async () => { await tick(); order.push(1); });
  const b = serial(async () => { order.push(2); });
  await Promise.all([a, b]);
  assert.deepEqual(order, [1, 2]);
});

test("a failing task does not stall the queue", async () => {
  const ran: number[] = [];
  const a = serial(async () => { throw new Error("boom"); }).catch(() => {});
  const b = serial(async () => { ran.push(2); });
  await Promise.all([a, b]);
  assert.deepEqual(ran, [2]);
});

test("priority task jumps ahead of queued tasks", async () => {
  const order: string[] = [];
  // Occupy the queue with a slow task, then enqueue normal + priority.
  const slow = serial(async () => { await tick(); order.push("slow"); });
  const normal = serial(async () => { order.push("normal"); });
  const prio = serialPriority(async () => { order.push("prio"); });
  await Promise.all([slow, normal, prio]);
  // slow runs first (already started); among the waiters, prio precedes normal.
  assert.equal(order[0], "slow");
  assert.ok(order.indexOf("prio") < order.indexOf("normal"));
});

test("cancelPending rejects queued (not-yet-started) tasks", async () => {
  let started = false;
  const slow = serial(async () => { await tick(); });
  const queued = serial(async () => { started = true; }).catch((e) => (e as Error).message);
  cancelPending();
  const res = await queued;
  await slow;
  assert.equal(started, false, "queued task never ran");
  assert.equal(res, "cancelled");
});
```

- [ ] **Step 2: Run it (fails — new API not present).**

Add the file to the script: in `package.json` `test`, append ` src/core/serial.test.ts`.
Run: `cd crates/client-app/ui && npm test`
Expected: FAIL — `serialPriority`/`cancelPending` not exported.

- [ ] **Step 3: Reimplement `serial.ts` as a real queue.** Replace `crates/client-app/ui/src/core/serial.ts`:

```ts
// A single-flight async queue. The backend re-authenticates on a fresh channel
// and `try_lock`s ONE connect lock + borrows ONE non-Clone identity, so two
// authed commands cannot run at once — this queue serializes them. Hardened:
// every task releases the runner on success/error/cancel; a priority task jumps
// ahead of queued (not-yet-started) tasks (so opening the viewer is not stuck
// behind a backlog of card decrypts); `cancelPending` rejects everything still
// queued (used when leaving the feed) so a stalled backlog can't wedge the lock.

type Job<T = unknown> = {
  task: () => Promise<T>;
  resolve: (v: T) => void;
  reject: (e: unknown) => void;
  priority: boolean;
};

const queue: Job[] = [];
let running = false;

function pump(): void {
  if (running) return;
  const job = queue.shift();
  if (!job) return;
  running = true;
  // Run, then ALWAYS release and pump the next — success or failure.
  job
    .task()
    .then(
      (v) => job.resolve(v),
      (e) => job.reject(e),
    )
    .finally(() => {
      running = false;
      pump();
    });
}

function enqueue<T>(task: () => Promise<T>, priority: boolean): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const job: Job<T> = { task, resolve, reject, priority };
    if (priority) {
      // Insert ahead of the first non-priority job (after any queued priorities).
      let i = 0;
      while (i < queue.length && queue[i].priority) i++;
      queue.splice(i, 0, job as Job);
    } else {
      queue.push(job as Job);
    }
    pump();
  });
}

export function serial<T>(task: () => Promise<T>): Promise<T> {
  return enqueue(task, false);
}

// High-priority: jumps ahead of queued normal tasks (e.g. viewer open over a
// backlog of card decrypts). Does NOT preempt the already-running task.
export function serialPriority<T>(task: () => Promise<T>): Promise<T> {
  return enqueue(task, true);
}

// Reject everything still queued (not the running task). Used when navigating
// away from the feed so a backlog of card decrypts cannot wedge the lock.
export function cancelPending(): void {
  while (queue.length) {
    const job = queue.shift()!;
    job.reject(new Error("cancelled"));
  }
}
```

- [ ] **Step 4: Run the tests.**

Run: `cd crates/client-app/ui && npm test`
Expected: 4 serial tests PASS (+ existing green).

- [ ] **Step 5: Typecheck + build.**

Run: `cd crates/client-app/ui && npm run typecheck && npm run build`
Expected: PASS. (Existing callers of `serial()` are unaffected — same signature.)

- [ ] **Step 6: Commit.**

```bash
git add crates/client-app/ui/src/core/serial.ts crates/client-app/ui/src/core/serial.test.ts crates/client-app/ui/package.json
git commit -m "feat(ui): harden serial queue with priority + cancel + guaranteed release"
```

---

## Task 8: Toast system (`core/toast.ts` + `<toast-host>`)

**Files:**
- Create: `crates/client-app/ui/src/core/toast.ts`
- Create: `crates/client-app/ui/src/components/toast-host.ts`
- Create: `crates/client-app/ui/src/core/toast.test.ts`
- Modify: `crates/client-app/ui/package.json` (add the test file)

- [ ] **Step 1: Write the failing test.** Create `crates/client-app/ui/src/core/toast.test.ts`:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { toast, subscribeToasts, type ToastEvent } from "./toast.ts";

test("toast() notifies subscribers with kind + message", () => {
  const seen: ToastEvent[] = [];
  const off = subscribeToasts((e) => seen.push(e));
  toast("success", "Uploaded");
  toast("error", "Nope");
  off();
  toast("info", "ignored after unsubscribe");
  assert.equal(seen.length, 2);
  assert.deepEqual(
    seen.map((e) => [e.kind, e.message]),
    [["success", "Uploaded"], ["error", "Nope"]],
  );
});
```

- [ ] **Step 2: Run it (fails — module absent).**

Add ` src/core/toast.test.ts` to `package.json` `test`.
Run: `cd crates/client-app/ui && npm test` → FAIL (no `./toast.ts`).

- [ ] **Step 3: Implement the pub/sub core.** Create `crates/client-app/ui/src/core/toast.ts`:

```ts
// A tiny toast pub/sub (spec §5). Pure (no DOM/Tauri import) so it is unit-
// testable; <toast-host> subscribes and renders. Errors are assertive (announced
// immediately by screen readers); everything else is polite.
export type ToastKind = "success" | "info" | "error";
export interface ToastEvent { kind: ToastKind; message: string }

type ToastListener = (e: ToastEvent) => void;
const listeners = new Set<ToastListener>();

export function toast(kind: ToastKind, message: string): void {
  const e: ToastEvent = { kind, message };
  for (const l of [...listeners]) l(e);
}
export function subscribeToasts(l: ToastListener): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}
```

- [ ] **Step 4: Implement the host component.** Create `crates/client-app/ui/src/components/toast-host.ts`:

```ts
import { subscribeToasts, type ToastEvent } from "../core/toast.ts";

// Singleton toast surface mounted once in the shell. Two ARIA-live regions:
// assertive for errors, polite for success/info. Each toast is a node built via
// textContent (never innerHTML) and auto-dismisses; errors linger longer.
export class ToastHost extends HTMLElement {
  private off: (() => void) | null = null;

  connectedCallback() {
    this.innerHTML = `
      <div class="toast-stack">
        <div id="toast-assertive" role="alert" aria-live="assertive" aria-atomic="true"></div>
        <div id="toast-polite" role="status" aria-live="polite" aria-atomic="true"></div>
      </div>`;
    this.off = subscribeToasts((e) => this.show(e));
  }
  disconnectedCallback() {
    this.off?.();
  }
  private show(e: ToastEvent) {
    const region = this.querySelector(
      e.kind === "error" ? "#toast-assertive" : "#toast-polite",
    ) as HTMLElement;
    const item = document.createElement("div");
    item.className = `toast toast-${e.kind}`;
    item.textContent = e.message; // textContent: never HTML.
    region.appendChild(item);
    const ttl = e.kind === "error" ? 7000 : 4000;
    window.setTimeout(() => item.remove(), ttl);
  }
}
customElements.define("toast-host", ToastHost);
```

- [ ] **Step 5: Run the test + typecheck + build.**

Run: `cd crates/client-app/ui && npm test && npm run typecheck && npm run build`
Expected: PASS.

- [ ] **Step 6: Commit.**

```bash
git add crates/client-app/ui/src/core/toast.ts crates/client-app/ui/src/components/toast-host.ts crates/client-app/ui/src/core/toast.test.ts crates/client-app/ui/package.json
git commit -m "feat(ui): toast system (pub/sub core + <toast-host>)"
```

---

## Task 9: Skeleton loader component

**Files:**
- Create: `crates/client-app/ui/src/components/skeleton-card.ts`

- [ ] **Step 1: Implement.** Create `crates/client-app/ui/src/components/skeleton-card.ts`:

```ts
// A shimmer placeholder used while the feed/viewer load (spec §5/§6). Pure
// presentational; the shimmer is driven by motion tokens in styles.css and is
// stilled under reduced-motion. aria-hidden so screen readers ignore the
// placeholder (the live status region announces "Loading…").
export class SkeletonCard extends HTMLElement {
  connectedCallback() {
    this.setAttribute("aria-hidden", "true");
    this.innerHTML = `
      <div class="skeleton-card">
        <div class="sk sk-thumb"></div>
        <div class="sk sk-line sk-line-lg"></div>
        <div class="sk sk-line sk-line-sm"></div>
      </div>`;
  }
}
customElements.define("skeleton-card", SkeletonCard);
```

- [ ] **Step 2: Typecheck + build.**

Run: `cd crates/client-app/ui && npm run typecheck && npm run build`
Expected: PASS. (Styling lands in Task 16; the element renders unstyled until then.)

- [ ] **Step 3: Commit.**

```bash
git add crates/client-app/ui/src/components/skeleton-card.ts
git commit -m "feat(ui): <skeleton-card> shimmer placeholder"
```

---

## Task 10: Router `mine` route + shell rewrite (My Content, status strip, quick-settings hide, toast-host)

**Files:**
- Modify: `crates/client-app/ui/src/core/router.ts`
- Create: `crates/client-app/ui/src/core/router.test.ts`
- Modify: `crates/client-app/ui/src/components/app-shell.ts`
- Modify: `crates/client-app/ui/package.json` (add the router test file)

- [ ] **Step 1: Write the failing router test.** Create `crates/client-app/ui/src/core/router.test.ts`:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { ROUTES } from "./router.ts";

test("router knows the mine route", () => {
  assert.ok(ROUTES.includes("mine"), "#/mine is a known route");
  assert.ok(ROUTES.includes("feed"));
});
```

- [ ] **Step 2: Run it (fails — `ROUTES` not exported, `mine` absent).**

Add ` src/core/router.test.ts` to `package.json` `test`.
Run: `cd crates/client-app/ui && npm test` → FAIL.

- [ ] **Step 3: Add the route + export the list.** Replace `crates/client-app/ui/src/core/router.ts`:

```ts
export const ROUTES = [
  "connect", "feed", "mine", "bootstrap", "pending", "admin", "viewer", "upload", "settings",
] as const;
export type Route = (typeof ROUTES)[number];
export class Router {
  constructor(private onChange: (r: Route) => void) {
    window.addEventListener("hashchange", () => this.emit());
    this.emit();
  }
  private emit() {
    const raw = location.hash.replace(/^#\//, "").split("?")[0];
    const r: Route = (ROUTES as readonly string[]).includes(raw) ? (raw as Route) : "connect";
    this.onChange(r);
  }
  go(r: Route) { location.hash = `#/${r}`; }
}
```

- [ ] **Step 4: Rewrite the shell.** Replace `crates/client-app/ui/src/components/app-shell.ts`:

```ts
import { Router, type Route } from "../core/router.ts";
import { on } from "../core/rpc.ts";
import { getUsername } from "../core/session.ts";
import "./status-pill.ts";
import "./connect-screen.ts";
import "./bootstrap-screen.ts";
import "./pending-screen.ts";
import "./admin-screen.ts";
import "./feed-screen.ts";
import "./media-viewer.ts";
import "./upload-screen.ts";
import "./upload-tray.ts";
import "./settings-screen.ts";
import "./quick-settings.ts";
import "./toast-host.ts";
import "./skeleton-card.ts";
import { loadAndApplySettings, bindDocumentToSettings } from "../core/settings.ts";
import { activeTasks } from "../core/tasks.ts";
import type { StatusPill } from "./status-pill.ts";
import type { ConnState } from "../core/types.ts";

const NAV: Array<{ route: Route; label: string }> = [
  { route: "feed", label: "Feed" },
  { route: "mine", label: "My Content" },
  { route: "upload", label: "Upload" },
  { route: "admin", label: "Admin" },
  { route: "settings", label: "Settings" },
];

export class AppShell extends HTMLElement {
  connectedCallback() {
    const links = NAV.map(
      (n) => `<a href="#/${n.route}" data-route="${n.route}">${n.label}</a>`,
    ).join("");
    this.innerHTML = `
      <header role="banner" class="app-header">
        <nav role="navigation" aria-label="Primary" class="nav-rail">${links}</nav>
        <div class="header-actions">
          <quick-settings id="qs"></quick-settings>
        </div>
        <div class="status-strip" role="region" aria-label="Status">
          <status-pill id="pill"></status-pill>
          <span id="sync-ind" class="sync-ind" role="status" aria-live="polite"></span>
          <span id="tasks-ind" class="tasks-ind" role="status" aria-live="polite">No active tasks</span>
        </div>
        <upload-tray></upload-tray>
      </header>
      <toast-host></toast-host>
      <div id="outlet"></div>`;

    // Boot: load + apply persisted settings, then keep the document bound to the
    // shared store so live edits from any screen apply instantly.
    void loadAndApplySettings();
    bindDocumentToSettings();

    const outlet = this.querySelector("#outlet")!;
    const pill = this.querySelector("#pill") as StatusPill;
    const qs = this.querySelector("#qs") as HTMLElement;

    new Router((r) => {
      // Quick-settings is hidden on the Settings screen (spec §4).
      qs.toggleAttribute("hidden", r === "settings");
      // Active-nav state.
      this.querySelectorAll<HTMLAnchorElement>(".nav-rail a").forEach((a) => {
        const isActive = a.getAttribute("data-route") === r
          || (r === "mine" && a.getAttribute("data-route") === "mine");
        a.toggleAttribute("aria-current", isActive);
        a.classList.toggle("active", isActive);
      });

      if (r === "pending") {
        const el = document.createElement("pending-screen");
        el.setAttribute("username", getUsername());
        outlet.replaceChildren(el);
      } else if (r === "mine") {
        const el = document.createElement("feed-screen");
        el.setAttribute("mine", "");
        outlet.replaceChildren(el);
      } else {
        outlet.innerHTML = r === "feed"
          ? "<feed-screen></feed-screen>"
          : r === "viewer"
          ? "<media-viewer></media-viewer>"
          : r === "upload"
          ? "<upload-screen></upload-screen>"
          : r === "settings"
          ? "<settings-screen></settings-screen>"
          : r === "admin"
          ? "<admin-screen></admin-screen>"
          : r === "bootstrap"
          ? "<bootstrap-screen></bootstrap-screen>"
          : "<connect-screen></connect-screen>";
      }
      const main = outlet.querySelector<HTMLElement>("#main");
      main?.focus();
    });

    on<ConnState>("maxsecu://connection-state", (s) => { pill.state = s.state; });

    // Active-tasks indicator (uploads + fetches in flight).
    const tasksInd = this.querySelector("#tasks-ind") as HTMLElement;
    activeTasks.subscribe((n) => {
      tasksInd.textContent = n === 0 ? "No active tasks" : `${n} active task${n === 1 ? "" : "s"}`;
    });
  }
}
customElements.define("app-shell", AppShell);
```

- [ ] **Step 5: Create the active-tasks store.** Create `crates/client-app/ui/src/core/tasks.ts`:

```ts
import { on } from "./rpc.ts";
import type { UploadMsg, FetchMsg } from "./types.ts";

// Tracks in-flight long-running tasks for the status strip's active-tasks count
// (spec §4/§6). Counts uploads (between first event and done/failed) + viewer
// fetches (between fetching and ready/failed), keyed by id so duplicates don't
// double-count. No backend change — it binds the existing event channels.
type Listener = (n: number) => void;

class ActiveTasks {
  private uploads = new Set<string>();
  private fetches = new Set<string>();
  private listeners = new Set<Listener>();
  private wired = false;

  private ensureWired() {
    if (this.wired) return;
    this.wired = true;
    void on<UploadMsg>("maxsecu://upload-state", (m) => {
      if (m.phase === "done" || m.phase === "failed") this.uploads.delete(m.job_id);
      else this.uploads.add(m.job_id);
      this.notify();
    });
    void on<FetchMsg>("maxsecu://fetch-state", (m) => {
      if (m.phase === "ready" || m.phase === "failed") this.fetches.delete(m.file_id);
      else this.fetches.add(m.file_id);
      this.notify();
    });
  }
  private count(): number {
    return this.uploads.size + this.fetches.size;
  }
  private notify() {
    for (const l of [...this.listeners]) l(this.count());
  }
  subscribe(l: Listener): () => void {
    this.ensureWired();
    this.listeners.add(l);
    l(this.count());
    return () => this.listeners.delete(l);
  }
}

export const activeTasks = new ActiveTasks();
```

- [ ] **Step 6: Run tests + a11y + typecheck + build.**

Run: `cd crates/client-app/ui && npm test && npm run test:a11y && npm run typecheck && npm run build`
Expected: PASS. (The a11y lint over screens is unaffected; the shell isn't in the `screens` list.)

- [ ] **Step 7: Commit.**

```bash
git add crates/client-app/ui/src/core/router.ts crates/client-app/ui/src/core/router.test.ts crates/client-app/ui/src/components/app-shell.ts crates/client-app/ui/src/core/tasks.ts crates/client-app/ui/package.json
git commit -m "feat(ui): Layout-B shell — My Content route, status strip, quick-settings hide, toasts"
```

---

## Task 11: Quick-settings reduced to Theme + RAM

**Files:**
- Modify: `crates/client-app/ui/src/components/quick-settings.ts`

- [ ] **Step 1: Rewrite the component.** Replace `crates/client-app/ui/src/components/quick-settings.ts`:

```ts
import { call } from "../core/rpc.ts";
import { settingsStore, updateSettings } from "../core/settings.ts";
import type { Settings, RamLimits } from "../core/types.ts";

// ⚡ Quick-settings popover (spec §4): reduced to the two most-used controls —
// Theme toggle + RAM cache cap (slider bound to a number input, both clamped to
// the live `ram_limits`). Reads/writes the SHARED settings store so it stays in
// sync with the full Settings screen and applies live. Accessible: aria-expanded/
// -controls on the trigger, Esc-dismiss + focus return, all controls labelled.
export class QuickSettings extends HTMLElement {
  private open = false;
  private limits: RamLimits | null = null;
  private unsub: (() => void) | null = null;

  connectedCallback() {
    this.innerHTML = `
      <div class="qs">
        <button id="qs-btn" aria-expanded="false" aria-controls="qs-pop" aria-haspopup="true" title="Quick settings">⚡</button>
        <div id="qs-pop" role="group" aria-label="Quick settings" hidden></div>
      </div>`;
    const btn = this.querySelector("#qs-btn") as HTMLButtonElement;
    btn.addEventListener("click", () => this.toggle());
    this.addEventListener("keydown", (e) => {
      if ((e as KeyboardEvent).key === "Escape" && this.open) {
        this.close();
        btn.focus();
      }
    });
  }
  disconnectedCallback() {
    this.unsub?.();
  }

  private async toggle() {
    if (this.open) { this.close(); return; }
    if (!this.limits) {
      try { this.limits = await call<RamLimits>("ram_limits"); } catch { this.limits = { default_mb: 256, min_mb: 64, max_mb: 4096 }; }
    }
    this.renderPopover();
    this.open = true;
    const pop = this.querySelector("#qs-pop") as HTMLElement;
    const btn = this.querySelector("#qs-btn") as HTMLButtonElement;
    pop.hidden = false;
    btn.setAttribute("aria-expanded", "true");
    (pop.querySelector("input,select,button") as HTMLElement | null)?.focus();
  }
  private close() {
    this.open = false;
    (this.querySelector("#qs-pop") as HTMLElement).hidden = true;
    (this.querySelector("#qs-btn") as HTMLButtonElement).setAttribute("aria-expanded", "false");
  }

  private renderPopover() {
    const s = settingsStore.get();
    const limits = this.limits!;
    const pop = this.querySelector("#qs-pop") as HTMLElement;
    pop.replaceChildren();

    // Theme toggle.
    const themeLabel = document.createElement("label");
    themeLabel.textContent = "Theme ";
    const themeSel = document.createElement("select");
    for (const opt of ["dark", "light"] as const) {
      const o = document.createElement("option");
      o.value = opt; o.textContent = opt;
      if (s.appearance.theme === opt) o.selected = true;
      themeSel.appendChild(o);
    }
    themeSel.addEventListener("change", () => {
      const theme = themeSel.value === "light" ? "light" : "dark";
      void this.save({ appearance: { theme } });
    });
    themeLabel.appendChild(themeSel);
    pop.appendChild(themeLabel);

    // RAM cap: range + number, both clamped to [min,max].
    const ramLabel = document.createElement("label");
    ramLabel.textContent = "RAM cache cap (MB) ";
    const range = document.createElement("input");
    range.type = "range";
    range.min = String(limits.min_mb); range.max = String(limits.max_mb); range.step = "16";
    range.value = String(s.performance.ram_cache_cap_mb);
    range.setAttribute("aria-label", "RAM cache cap (MB)");
    const num = document.createElement("input");
    num.type = "number";
    num.min = String(limits.min_mb); num.max = String(limits.max_mb); num.step = "1";
    num.value = String(s.performance.ram_cache_cap_mb);
    num.setAttribute("aria-label", "RAM cache cap (MB), exact");
    const syncFrom = (v: number) => {
      const clamped = Math.min(Math.max(v, limits.min_mb), limits.max_mb);
      range.value = String(clamped); num.value = String(clamped);
      void this.save({ performance: { ram_cache_cap_mb: clamped } });
    };
    range.addEventListener("change", () => syncFrom(Number(range.value)));
    num.addEventListener("change", () => syncFrom(Number(num.value)));
    ramLabel.append(range, num);
    pop.appendChild(ramLabel);

    pop.appendChild(this.status());
  }

  private status(): HTMLParagraphElement {
    const p = document.createElement("p");
    p.id = "qs-status"; p.setAttribute("role", "status"); p.setAttribute("aria-live", "polite");
    return p;
  }

  private async save(patch: Partial<Settings>) {
    const status = this.querySelector("#qs-status");
    try {
      await updateSettings(patch);
      if (status) status.textContent = "Saved.";
    } catch (x) {
      if (status) status.textContent = errMsg(x, "Could not save.");
    }
  }
}

function errMsg(x: unknown, fallback: string): string {
  if (x && typeof x === "object" && "message" in x) {
    const m = (x as { message?: unknown }).message;
    if (typeof m === "string") return m;
  }
  return fallback;
}

customElements.define("quick-settings", QuickSettings);
```

- [ ] **Step 2: Typecheck + build + a11y.**

Run: `cd crates/client-app/ui && npm run typecheck && npm run build && npm run test:a11y`
Expected: PASS.

- [ ] **Step 3: Commit.**

```bash
git add crates/client-app/ui/src/components/quick-settings.ts
git commit -m "feat(ui): quick-settings reduced to Theme + RAM, bound to shared store"
```

---

## Task 12: Settings screen — Appearance(theme) + RAM(ram_limits) + shared store

**Files:**
- Modify: `crates/client-app/ui/src/components/settings-screen.ts`

- [ ] **Step 1: Rewrite the screen.** Replace `crates/client-app/ui/src/components/settings-screen.ts`:

```ts
import { call } from "../core/rpc.ts";
import { settingsStore, updateSettings, loadAndApplySettings } from "../core/settings.ts";
import type { Settings, RamLimits } from "../core/types.ts";

// Settings (spec §5/§7): appearance / accessibility / performance / behavior /
// connection / account / privacy. Preference controls write through the SHARED
// settings store (so quick-settings + the shell theme stay in sync and apply
// live); the RAM control is bounded to the live `ram_limits`. Account actions
// are explicit submits. Accessible: focused landmark on mount, labelled controls
// in fieldsets, role=status live regions.
const DEFAULTS: Settings = {
  a11y: { reduced_motion: false, high_contrast: false, text_size: "normal" },
  behavior: { confirm_destructive: false },
  performance: { ram_cache_cap_mb: 256 },
  connection: { use_tor: false },
  appearance: { theme: "dark" },
};

export class SettingsScreen extends HTMLElement {
  private limits: RamLimits = { default_mb: 256, min_mb: 64, max_mb: 4096 };
  private unsub: (() => void) | null = null;

  connectedCallback() {
    this.innerHTML = `
      <main id="main" tabindex="-1" aria-labelledby="set-h">
        <h1 id="set-h">Settings</h1>
        <p id="set-status" role="status" aria-live="polite"></p>

        <form id="set-form">
          <fieldset>
            <legend>Appearance</legend>
            <label>Theme
              <select name="theme">
                <option value="dark">Dark</option>
                <option value="light">Light</option>
              </select></label>
          </fieldset>

          <fieldset>
            <legend>Accessibility</legend>
            <label><input type="checkbox" name="reduced_motion" /> Reduce motion</label>
            <label><input type="checkbox" name="high_contrast" /> High contrast</label>
            <label>Text size
              <select name="text_size">
                <option value="normal">Normal</option>
                <option value="large">Large</option>
                <option value="larger">Larger</option>
              </select></label>
          </fieldset>

          <fieldset>
            <legend>Performance</legend>
            <label>RAM cache cap (MB)
              <input type="range" name="ram_range" step="16" />
              <input type="number" name="ram_cache_cap_mb" step="1" /></label>
            <p id="ram-hint" class="hint"></p>
          </fieldset>

          <fieldset>
            <legend>Behavior</legend>
            <label><input type="checkbox" name="confirm_destructive" /> Confirm destructive actions</label>
          </fieldset>

          <fieldset>
            <legend>Connection</legend>
            <label><input type="checkbox" name="use_tor" disabled /> Route over Tor
              <span> (arrives in a later phase)</span></label>
          </fieldset>
        </form>

        <fieldset>
          <legend>Account</legend>
          <p id="acct-status" role="status" aria-live="polite"></p>
          <form id="pw-form">
            <label>Current password
              <input type="password" name="oldpw" autocomplete="current-password" /></label>
            <label>New password
              <input type="password" name="newpw" autocomplete="new-password" /></label>
            <button type="submit">Change password</button>
          </form>
          <form id="exp-form">
            <p id="exp-warn" role="note">Back up the keystore file securely — it is only as safe as your password.</p>
            <label>Export keystore to path
              <input type="text" name="dest" autocomplete="off" /></label>
            <button type="submit">Export keystore</button>
          </form>
        </fieldset>

        <fieldset>
          <legend>Privacy</legend>
          <p>MaxSecu stores and encrypts your content locally before it ever leaves this
            device. Settings are kept on this device only; no analytics or telemetry are
            collected.</p>
        </fieldset>
      </main>`;
    (this.querySelector("#main") as HTMLElement).focus();

    const prefForm = this.querySelector("#set-form") as HTMLFormElement;
    prefForm.addEventListener("change", (e) => this.onPrefChange(e));

    (this.querySelector("#pw-form") as HTMLFormElement)
      .addEventListener("submit", (e) => { e.preventDefault(); this.onChangePassword(); });
    (this.querySelector("#exp-form") as HTMLFormElement)
      .addEventListener("submit", (e) => { e.preventDefault(); this.onExportKeystore(); });

    // Keep the form mirrored to the shared store (so a quick-settings edit shows
    // up here live, and vice-versa).
    this.unsub = settingsStore.subscribe((s) => this.writeControls(s));

    this.init();
  }
  disconnectedCallback() {
    this.unsub?.();
  }

  private async init() {
    try { this.limits = await call<RamLimits>("ram_limits"); } catch { /* keep defaults */ }
    const range = this.input("ram_range");
    const num = this.input("ram_cache_cap_mb");
    range.min = String(this.limits.min_mb); range.max = String(this.limits.max_mb);
    num.min = String(this.limits.min_mb); num.max = String(this.limits.max_mb);
    (this.querySelector("#ram-hint") as HTMLElement).textContent =
      `Allowed ${this.limits.min_mb}–${this.limits.max_mb} MB (cap = total RAM − 6 GB).`;
    const loaded = await loadAndApplySettings();
    this.writeControls(loaded ?? DEFAULTS);
  }

  private input(name: string): HTMLInputElement {
    return this.querySelector(`#set-form [name="${name}"]`) as HTMLInputElement;
  }
  private sel(name: string): HTMLSelectElement {
    return this.querySelector(`#set-form [name="${name}"]`) as HTMLSelectElement;
  }

  private async onPrefChange(e: Event) {
    const status = this.querySelector("#set-status")!;
    const target = e.target as HTMLElement;
    // Keep range + number in lockstep before reading.
    if (target?.getAttribute("name") === "ram_range") {
      this.input("ram_cache_cap_mb").value = this.input("ram_range").value;
    } else if (target?.getAttribute("name") === "ram_cache_cap_mb") {
      this.input("ram_range").value = this.input("ram_cache_cap_mb").value;
    }
    const ram = Number(this.input("ram_cache_cap_mb").value);
    const text = this.sel("text_size").value;
    const patch: Partial<Settings> = {
      appearance: { theme: this.sel("theme").value === "light" ? "light" : "dark" },
      a11y: {
        reduced_motion: this.input("reduced_motion").checked,
        high_contrast: this.input("high_contrast").checked,
        text_size: text === "large" || text === "larger" ? text : "normal",
      },
      performance: { ram_cache_cap_mb: Number.isFinite(ram) ? ram : DEFAULTS.performance.ram_cache_cap_mb },
      behavior: { confirm_destructive: this.input("confirm_destructive").checked },
    };
    try {
      await updateSettings(patch); // normalizes + applies + notifies the store
      status.textContent = "Saved.";
    } catch (x) {
      status.textContent = errMsg(x, "Could not save settings.");
    }
  }

  private writeControls(s: Settings): void {
    this.sel("theme").value = s.appearance.theme;
    this.input("reduced_motion").checked = s.a11y.reduced_motion;
    this.input("high_contrast").checked = s.a11y.high_contrast;
    this.sel("text_size").value = s.a11y.text_size;
    this.input("ram_cache_cap_mb").value = String(s.performance.ram_cache_cap_mb);
    this.input("ram_range").value = String(s.performance.ram_cache_cap_mb);
    this.input("confirm_destructive").checked = s.behavior.confirm_destructive;
    this.input("use_tor").checked = s.connection.use_tor;
  }

  private async onChangePassword() {
    const status = this.querySelector("#acct-status")!;
    const oldp = (this.querySelector('input[name="oldpw"]') as HTMLInputElement).value;
    const newp = (this.querySelector('input[name="newpw"]') as HTMLInputElement).value;
    try {
      await call<void>("change_password", { req: { old_password: oldp, new_password: newp } });
      status.textContent = "Password changed.";
      (this.querySelector('input[name="oldpw"]') as HTMLInputElement).value = "";
      (this.querySelector('input[name="newpw"]') as HTMLInputElement).value = "";
    } catch (x) {
      status.textContent = errMsg(x, "Could not change the password.");
    }
  }
  private async onExportKeystore() {
    const status = this.querySelector("#acct-status")!;
    const dest = (this.querySelector('input[name="dest"]') as HTMLInputElement).value;
    try {
      await call<void>("export_keystore", { req: { dest_path: dest } });
      status.textContent = "Keystore exported.";
    } catch (x) {
      status.textContent = errMsg(x, "Could not export the keystore.");
    }
  }
}

function errMsg(x: unknown, fallback: string): string {
  if (x && typeof x === "object" && "message" in x) {
    const m = (x as { message?: unknown }).message;
    if (typeof m === "string") return m;
  }
  return fallback;
}

customElements.define("settings-screen", SettingsScreen);
```

- [ ] **Step 2: Typecheck + build + a11y.**

Run: `cd crates/client-app/ui && npm run typecheck && npm run build && npm run test:a11y`
Expected: PASS (settings-screen still has a focusable `#main`, focus on mount, live region).

- [ ] **Step 3: Commit.**

```bash
git add crates/client-app/ui/src/components/settings-screen.ts
git commit -m "feat(ui): settings screen — Appearance/RAM controls via shared store"
```

---

## Task 13: Feed screen — mine-preset, view-state retention, skeletons, version plumbing

**Files:**
- Modify: `crates/client-app/ui/src/components/feed-screen.ts`

- [ ] **Step 1: Rewrite the feed screen.** Replace `crates/client-app/ui/src/components/feed-screen.ts`:

```ts
import { call } from "../core/rpc.ts";
import { serial, cancelPending } from "../core/serial.ts";
import { toast } from "../core/toast.ts";
import type { FeedEntry, FeedFilter, FeedSort, SearchHit } from "../core/types.ts";
import "./media-card.ts";
import "./state-badge.ts";
import "./skeleton-card.ts";

// Module-level retained view-state so returning to the feed restores instantly
// (spec §8) instead of visibly rebuilding. Keyed by mine-vs-all so the two
// routes don't clobber each other.
interface FeedView { entries: FeedEntry[]; filter: FeedFilter; sort: FeedSort; scrollY: number }
const retained: Record<"all" | "mine", FeedView | null> = { all: null, mine: null };

export class FeedScreen extends HTMLElement {
  private filter: FeedFilter = "all";
  private sort: FeedSort = "newest-first";
  private mineOnly = false;

  private get key(): "all" | "mine" { return this.mineOnly ? "mine" : "all"; }

  connectedCallback() {
    this.mineOnly = this.hasAttribute("mine");
    const r = retained[this.key];
    if (r) { this.filter = r.filter; this.sort = r.sort; }

    this.innerHTML = `
      <main id="main" tabindex="-1" aria-labelledby="fd-h">
        <h1 id="fd-h">${this.mineOnly ? "My Content" : "Feed"}</h1>
        <form id="controls" role="search">
          <label>Search <input name="q" type="search" autocomplete="off"
            aria-describedby="fd-status" /></label>
          <label>Type
            <select name="type">
              <option value="all">All</option>
              <option value="image">Images</option>
              <option value="blog">Blogs</option>
              <option value="video">Video</option>
            </select></label>
          <label>Sort
            <select name="sort">
              <option value="newest-first">Newest first</option>
              <option value="oldest-first">Oldest first</option>
            </select></label>
          ${this.mineOnly ? "" : `<label><input type="checkbox" name="mine" /> Only my uploads</label>`}
        </form>
        <p id="fd-status" role="status" aria-live="polite"></p>
        <div id="grid" role="list"></div>
      </main>`;
    (this.querySelector("#main") as HTMLElement).focus();

    // Reflect retained control values.
    (this.querySelector('[name="type"]') as HTMLSelectElement).value = this.filter;
    (this.querySelector('[name="sort"]') as HTMLSelectElement).value = this.sort;

    const form = this.querySelector("#controls") as HTMLFormElement;
    form.addEventListener("change", (e) => {
      if ((e.target as HTMLElement)?.getAttribute("name") === "q") return;
      const d = new FormData(form);
      this.filter = (d.get("type") as FeedFilter) ?? "all";
      this.sort = (d.get("sort") as FeedSort) ?? "newest-first";
      if (!this.mineOnly) this.mineOnly = !!d.get("mine");
      this.load();
    });
    const q = form.querySelector('input[name="q"]') as HTMLInputElement;
    q.addEventListener("input", () => this.runSearch(q.value));

    // Instant restore if we have a retained view; else load.
    if (r && r.entries.length) {
      this.renderEntries(r.entries);
      (this.querySelector("#fd-status") as HTMLElement).textContent = `${r.entries.length} item(s).`;
      window.requestAnimationFrame(() => window.scrollTo(0, r.scrollY));
    } else {
      this.load();
    }
  }

  disconnectedCallback() {
    // Cancel any queued card decrypts so a backlog can't wedge the shared lock
    // after we leave (spec §8), and remember the scroll position.
    cancelPending();
    const r = retained[this.key];
    if (r) r.scrollY = window.scrollY;
  }

  private showSkeletons(n: number) {
    const grid = this.querySelector("#grid") as HTMLElement;
    grid.replaceChildren();
    for (let i = 0; i < n; i++) grid.appendChild(document.createElement("skeleton-card"));
  }

  private async load() {
    const status = this.querySelector("#fd-status")!;
    status.textContent = "Loading…";
    this.showSkeletons(6);
    try {
      const entries = await serial(() => call<FeedEntry[]>("list_feed", {
        req: { filter: this.filter, sort: this.sort },
      }));
      retained[this.key] = { entries, filter: this.filter, sort: this.sort, scrollY: 0 };
      this.renderEntries(entries);
      status.textContent = entries.length === 0 ? "No content yet." : `${entries.length} item(s).`;
    } catch (x) {
      (this.querySelector("#grid") as HTMLElement).replaceChildren();
      status.textContent = errMsg(x, "Could not load the feed.");
      toast("error", errMsg(x, "Could not load the feed."));
    }
  }

  private renderEntries(entries: FeedEntry[]) {
    const grid = this.querySelector("#grid") as HTMLElement;
    grid.replaceChildren();
    for (const e of entries) {
      const card = document.createElement("media-card");
      card.setAttribute("file-id", e.file_id);
      card.setAttribute("file-type", e.file_type);
      card.setAttribute("version", String(e.version)); // enables zero-network cache hits
      card.setAttribute("role", "listitem");
      if (this.mineOnly) card.setAttribute("mine-only", "");
      grid.appendChild(card);
    }
  }

  private async runSearch(query: string) {
    const status = this.querySelector("#fd-status")!;
    if (query.trim() === "") { this.load(); return; }
    try {
      const hits = await call<SearchHit[]>("search_local", { req: { query } });
      const grid = this.querySelector("#grid") as HTMLElement;
      grid.replaceChildren();
      status.textContent = `${hits.length} match(es).`;
      for (const h of hits) {
        const card = document.createElement("media-card");
        card.setAttribute("file-id", h.file_id);
        card.setAttribute("file-type", h.file_type);
        card.setAttribute("role", "listitem");
        if (this.mineOnly) card.setAttribute("mine-only", "");
        grid.appendChild(card);
      }
    } catch (x) {
      status.textContent = errMsg(x, "Search failed.");
    }
  }
}

function errMsg(x: unknown, fallback: string): string {
  if (x && typeof x === "object" && "message" in x) {
    const m = (x as { message?: unknown }).message;
    if (typeof m === "string") return m;
  }
  return fallback;
}

customElements.define("feed-screen", FeedScreen);
```

- [ ] **Step 2: Typecheck + build + a11y.**

Run: `cd crates/client-app/ui && npm run typecheck && npm run build && npm run test:a11y`
Expected: PASS.

- [ ] **Step 3: Commit.**

```bash
git add crates/client-app/ui/src/components/feed-screen.ts
git commit -m "feat(ui): feed mine-preset + retained view-state + skeletons + version plumbing"
```

---

## Task 14: Media card version pass-through + viewer version + skeleton + error toast

**Files:**
- Modify: `crates/client-app/ui/src/components/media-card.ts`
- Modify: `crates/client-app/ui/src/components/media-viewer.ts`

- [ ] **Step 1: Card — pass version to `decrypt_card` + carry it in the viewer link.** In `crates/client-app/ui/src/components/media-card.ts`:

In `connectedCallback`, read the version attr and pass it to `decrypt`:

```ts
  connectedCallback() {
    const id = this.getAttribute("file-id") ?? "";
    const versionAttr = this.getAttribute("version");
    const version = versionAttr !== null ? Number(versionAttr) : undefined;
    this.innerHTML = `
      <article aria-busy="true">
        <state-badge state="decrypting" label="Decrypting…"></state-badge>
        <h3 class="title">…</h3>
      </article>`;
    void this.decrypt(id, version);
  }
```

Change `decrypt` to accept + send version, and to build the viewer link with `&v=`:

```ts
  private async decrypt(id: string, version: number | undefined) {
    const article = this.querySelector("article")!;
    try {
      const card = await serial(() =>
        call<Card>("decrypt_card", { req: { file_id: id, version } }),
      );
      // ... unchanged badge/thumbnail/title/tags rendering ...
      const open = document.createElement("a");
      open.href = version !== undefined
        ? `#/viewer?id=${encodeURIComponent(id)}&v=${version}`
        : `#/viewer?id=${encodeURIComponent(id)}`;
      open.textContent = "View";
      article.appendChild(open);
    } catch (x) {
      // ... unchanged error rendering ...
    }
  }
```

(Keep all the existing badge/img/h3/tags lines between the `try {` open and the `const open` line exactly as they are today — only the `decrypt` signature, the `call` args, and the `open.href` change.)

- [ ] **Step 2: Viewer — read `v` from the hash, pass it, show a skeleton, toast on error.** In `crates/client-app/ui/src/components/media-viewer.ts`:

Add the skeleton import at the top:

```ts
import "./skeleton-card.ts";
import { toast } from "../core/toast.ts";
import { serialPriority } from "../core/serial.ts";
```

In `connectedCallback`, parse the version and render a skeleton in the body before the call; use `serialPriority` so the viewer jumps the card-decrypt backlog:

```ts
    const params = new URLSearchParams(location.hash.split("?")[1] ?? "");
    const id = params.get("id") ?? "";
    const vParam = params.get("v");
    const version = vParam !== null ? Number(vParam) : undefined;
    this.reqId = id;
```

Right after `(this.querySelector("#main") as HTMLElement).focus();`, seed a skeleton:

```ts
    (this.querySelector("#vw-body") as HTMLElement).appendChild(
      document.createElement("skeleton-card"),
    );
```

Replace the `open_content` call + catch:

```ts
    try {
      const c = await serialPriority(() =>
        call<OpenedContent>("open_content", { req: { file_id: id, version } }),
      );
      this.render(c);
    } catch (x) {
      (this.querySelector("#vw-h") as HTMLElement).textContent = "Could not open this item";
      const msg = viewerErr(x);
      (this.querySelector("#vw-status") as HTMLElement).textContent = msg;
      (this.querySelector("#vw-body") as HTMLElement).replaceChildren();
      toast("error", msg);
    }
```

In `render`, clear the skeleton first — it already does `body.replaceChildren()`, so no change needed beyond ensuring that runs (it does).

- [ ] **Step 3: Typecheck + build + a11y.**

Run: `cd crates/client-app/ui && npm run typecheck && npm run build && npm run test:a11y`
Expected: PASS.

- [ ] **Step 4: Commit.**

```bash
git add crates/client-app/ui/src/components/media-card.ts crates/client-app/ui/src/components/media-viewer.ts
git commit -m "feat(ui): card/viewer version plumbing + viewer skeleton + priority open + error toast"
```

---

## Task 15: Upload tray — prominent + success toast

**Files:**
- Modify: `crates/client-app/ui/src/components/upload-tray.ts`

- [ ] **Step 1: Add a heading/visibility + fire a success toast on done.** In `crates/client-app/ui/src/components/upload-tray.ts`:

Import the toast helper:

```ts
import { toast } from "../core/toast.ts";
```

Give the tray a visible header + a class hook (so Task 16 styles it prominently). Replace the `connectedCallback` innerHTML:

```ts
    this.innerHTML = `
      <section class="upload-tray" aria-label="Active uploads">
        <h2 class="ut-title">Uploads</h2>
        <ul id="ut-list" aria-live="polite"></ul>
      </section>`;
```

In `onMsg`, fire a success toast in the `done` branch:

```ts
    } else if (m.phase === "done") {
      meter.hidden = true;
      this.starts.delete(m.job_id);
      toast("success", "Upload complete.");
      this.clearRowLater(m.job_id);
    } else if (m.phase === "failed") {
```

- [ ] **Step 2: Typecheck + build + a11y.**

Run: `cd crates/client-app/ui && npm run typecheck && npm run build && npm run test:a11y`
Expected: PASS.

- [ ] **Step 3: Commit.**

```bash
git add crates/client-app/ui/src/components/upload-tray.ts
git commit -m "feat(ui): prominent upload tray + success toast on completion"
```

---

## Task 16: Token-driven CSS design system (dark + light, motion, surfaces)

**Files:**
- Modify: `crates/client-app/ui/styles.css`

- [ ] **Step 1: Rewrite `styles.css` as a token system.** Replace the entire file `crates/client-app/ui/styles.css`:

```css
/* MaxSecu media client — token-driven design system (spec §3).
   Dark is the default; <html data-theme="light"> swaps the token block. Text
   scaling lives on :root font-size so every rem grows. Motion tokens gate all
   transitions/shimmer so reduced-motion (attr + OS media query) actually stills
   motion. AA contrast; status is never color-only (handled in components). */

/* ---------- Tokens: dark (default) ---------- */
:root {
  --mx-accent-1: #3b82f6; /* electric blue */
  --mx-accent-2: #8b5cf6; /* violet */
  --mx-accent: linear-gradient(135deg, var(--mx-accent-1), var(--mx-accent-2));

  --mx-base: #0b0f1a;
  --mx-surface-1: #121829;
  --mx-surface-2: #1a2236;
  --mx-surface-3: #232d45;
  --mx-text: #eef2fb;
  --mx-muted: #9aa6c2;
  --mx-border: #2b3754;

  --mx-glow: 0 0 0 1px rgba(139, 92, 246, 0.35), 0 8px 30px rgba(59, 130, 246, 0.18);
  --mx-elev-1: 0 1px 2px rgba(0, 0, 0, 0.5);
  --mx-elev-2: 0 8px 24px rgba(0, 0, 0, 0.45);

  --mx-radius: 12px;
  --mx-radius-sm: 8px;
  --mx-space-1: 0.25rem;
  --mx-space-2: 0.5rem;
  --mx-space-3: 0.75rem;
  --mx-space-4: 1rem;
  --mx-space-6: 1.5rem;

  --mx-fs-1: 0.85rem;
  --mx-fs-2: 1rem;
  --mx-fs-3: 1.25rem;
  --mx-fs-4: 1.6rem;

  --mx-dur-fast: 120ms;
  --mx-dur: 220ms;
  --mx-ease: cubic-bezier(0.2, 0.7, 0.2, 1);

  --mx-text-scale: 1;
}

/* ---------- Tokens: light ---------- */
:root[data-theme="light"] {
  --mx-base: #f5f7fc;
  --mx-surface-1: #ffffff;
  --mx-surface-2: #eef2fb;
  --mx-surface-3: #e2e8f6;
  --mx-text: #131a2b;
  --mx-muted: #4d5872;
  --mx-border: #cbd5ea;
  --mx-glow: 0 0 0 1px rgba(139, 92, 246, 0.25), 0 8px 30px rgba(59, 130, 246, 0.12);
  --mx-elev-1: 0 1px 2px rgba(20, 30, 60, 0.12);
  --mx-elev-2: 0 8px 24px rgba(20, 30, 60, 0.14);
}

/* ---------- Text scaling on :root so every rem grows ---------- */
:root[data-text-size="large"]  { --mx-text-scale: 1.25; }
:root[data-text-size="larger"] { --mx-text-scale: 1.5; }
html { font-size: calc(100% * var(--mx-text-scale)); }

/* ---------- Base ---------- */
body {
  margin: 0;
  background: var(--mx-base);
  color: var(--mx-text);
  font-family: "Segoe UI", system-ui, sans-serif;
  font-size: var(--mx-fs-2);
  line-height: 1.5;
}
a { color: var(--mx-accent-1); }
:root[data-theme="dark"] a { color: #9ec1ff; }

/* ---------- Shell: header / nav rail / status strip ---------- */
.app-header {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--mx-space-4);
  padding: var(--mx-space-3) var(--mx-space-4);
  background: var(--mx-surface-1);
  border-bottom: 1px solid var(--mx-border);
  box-shadow: var(--mx-elev-1);
}
.nav-rail { display: flex; gap: var(--mx-space-3); align-items: center; flex-wrap: wrap; }
.nav-rail a {
  text-decoration: none;
  color: var(--mx-muted);
  padding: var(--mx-space-2) var(--mx-space-3);
  border-radius: var(--mx-radius-sm);
  transition: color var(--mx-dur) var(--mx-ease), background var(--mx-dur) var(--mx-ease);
}
.nav-rail a:hover { color: var(--mx-text); background: var(--mx-surface-2); }
.nav-rail a.active, .nav-rail a[aria-current] {
  color: #fff;
  background: var(--mx-accent);
  box-shadow: var(--mx-glow);
}
.header-actions { margin-left: auto; }
.status-strip {
  display: flex; align-items: center; gap: var(--mx-space-3);
  flex-basis: 100%; color: var(--mx-muted); font-size: var(--mx-fs-1);
}
.tasks-ind, .sync-ind { font-variant-numeric: tabular-nums; }

/* ---------- Glassy surfaces (cards, popovers, viewer, tray, toasts) ---------- */
.qs #qs-pop, .upload-tray, video-player, #vw-body, .toast {
  background: color-mix(in srgb, var(--mx-surface-2) 92%, transparent);
  border: 1px solid var(--mx-border);
  border-radius: var(--mx-radius);
  box-shadow: var(--mx-elev-2);
  backdrop-filter: blur(8px);
}

/* Feed grid + cards */
#grid {
  display: grid; gap: var(--mx-space-4);
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  padding: var(--mx-space-4);
}
media-card article {
  display: block;
  background: var(--mx-surface-2);
  border: 1px solid var(--mx-border);
  border-radius: var(--mx-radius);
  padding: var(--mx-space-3);
  box-shadow: var(--mx-elev-1);
  transition: transform var(--mx-dur) var(--mx-ease), box-shadow var(--mx-dur) var(--mx-ease);
}
media-card article:hover { transform: translateY(-2px); box-shadow: var(--mx-glow); }
media-card img { max-width: 100%; height: auto; border-radius: var(--mx-radius-sm); display: block; }
media-card .title { font-size: var(--mx-fs-3); margin: var(--mx-space-2) 0 0; }
media-card .tags { color: var(--mx-muted); font-size: var(--mx-fs-1); }

/* Controls */
input, select, button, textarea { font: inherit; color: inherit; }
select, input[type="text"], input[type="search"], input[type="number"],
input[type="password"], textarea {
  background: var(--mx-surface-1);
  border: 1px solid var(--mx-border);
  border-radius: var(--mx-radius-sm);
  padding: var(--mx-space-2) var(--mx-space-3);
}
button {
  background: var(--mx-accent); color: #fff; border: 0;
  border-radius: var(--mx-radius-sm);
  padding: var(--mx-space-2) var(--mx-space-4); cursor: pointer;
  transition: filter var(--mx-dur) var(--mx-ease), box-shadow var(--mx-dur) var(--mx-ease);
}
button:hover { filter: brightness(1.1); box-shadow: var(--mx-glow); }
button:disabled { filter: grayscale(0.6) opacity(0.6); cursor: not-allowed; }

/* Quick-settings + upload tray */
.qs { position: relative; }
.qs #qs-btn { background: var(--mx-surface-2); }
.qs #qs-pop {
  position: absolute; right: 0; z-index: 20; min-width: 260px;
  display: grid; gap: var(--mx-space-3); padding: var(--mx-space-4);
}
.qs #qs-pop label { display: grid; gap: var(--mx-space-1); }
.upload-tray { padding: var(--mx-space-3); min-width: 220px; }
.upload-tray .ut-title { font-size: var(--mx-fs-2); margin: 0 0 var(--mx-space-2); }
.upload-tray ul { list-style: none; margin: 0; padding: 0; display: grid; gap: var(--mx-space-2); }
.upload-tray li { display: flex; gap: var(--mx-space-2); align-items: center; flex-wrap: wrap; }

/* Toasts */
.toast-stack { position: fixed; right: var(--mx-space-4); bottom: var(--mx-space-4); z-index: 50; display: grid; gap: var(--mx-space-2); }
.toast {
  padding: var(--mx-space-3) var(--mx-space-4); min-width: 220px; max-width: 360px;
  animation: mx-toast-in var(--mx-dur) var(--mx-ease);
}
.toast-success { border-left: 4px solid #22c55e; }
.toast-info { border-left: 4px solid var(--mx-accent-1); }
.toast-error { border-left: 4px solid #ef4444; }
@keyframes mx-toast-in { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }

/* Skeletons (shimmer driven by motion tokens) */
.skeleton-card { display: grid; gap: var(--mx-space-2); padding: var(--mx-space-3);
  background: var(--mx-surface-2); border: 1px solid var(--mx-border); border-radius: var(--mx-radius); }
.sk { background: linear-gradient(90deg, var(--mx-surface-2), var(--mx-surface-3), var(--mx-surface-2));
  background-size: 200% 100%; border-radius: var(--mx-radius-sm); animation: mx-shimmer 1.2s infinite linear; }
.sk-thumb { height: 120px; }
.sk-line { height: 0.9rem; }
.sk-line-lg { width: 80%; }
.sk-line-sm { width: 50%; }
@keyframes mx-shimmer { from { background-position: 200% 0; } to { background-position: -200% 0; } }

/* High contrast */
:root[data-high-contrast] { filter: contrast(1.25); }
:root[data-high-contrast] a { text-decoration: underline; }

/* Reduced motion: explicit user setting … */
:root[data-reduced-motion] * {
  animation-duration: 0.001ms !important;
  animation-iteration-count: 1 !important;
  transition-duration: 0.001ms !important;
  scroll-behavior: auto !important;
}
/* … and respect the OS preference too. */
@media (prefers-reduced-motion: reduce) {
  * {
    animation-duration: 0.001ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.001ms !important;
    scroll-behavior: auto !important;
  }
}

/* Always-visible focus for keyboard users (WCAG 2.4.7). */
:focus-visible { outline: 2px solid var(--mx-accent-1); outline-offset: 2px; }

/* --- Sandboxed video player chrome (unchanged from Phase 7) --- */
video-player .vp-stage canvas { max-width: 100%; height: auto; background: #000; display: block; }
video-player .vp-controls { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; margin-top: 0.5rem; }
video-player .vp-field { display: inline-flex; gap: 0.25rem; align-items: center; }
video-player .vp-time { font-variant-numeric: tabular-nums; }
video-player .vp-badge { display: inline-block; padding: 0.1rem 0.4rem; border: 1px solid currentColor; border-radius: 0.25rem; font-size: 0.85em; }
video-player .vp-badge[hidden] { display: none; }
video-player .vp-warn { border: 2px solid currentColor; padding: 0.5rem 0.75rem; margin: 0.5rem 0; font-weight: 700; background: rgba(255, 0, 0, 0.08); flex-basis: 100%; }
video-player .vp-warn[hidden] { display: none; }
```

- [ ] **Step 2: Build (copies styles.css into dist) + verify the bundle exists.**

Run: `cd crates/client-app/ui && npm run build`
Expected: PASS; `dist/styles.css` updated.

- [ ] **Step 3: Sanity-check no stray `px` type sizing regressed text scaling.** The token type scale uses `rem`; confirm the build copied the file:

Run (bash): `grep -c "var(--mx-" crates/client-app/ui/dist/styles.css`
Expected: a non-zero count (tokens present in the built file).

- [ ] **Step 4: Commit.**

```bash
git add crates/client-app/ui/styles.css
git commit -m "feat(ui): token-driven dark+light design system with motion + glass surfaces"
```

---

## Task 17: Extend the a11y structural lint + run the full UI test suite

**Files:**
- Modify: `crates/client-app/ui/src/a11y.test.ts`

- [ ] **Step 1: Add checks for the new affordances.** In `crates/client-app/ui/src/a11y.test.ts`, append a new block at the end of the file:

```ts
// --- UI-overhaul affordances (this plan) -----------------------------------
{
  const shell = readFileSync("src/components/app-shell.ts", "utf8");
  const toastHost = readFileSync("src/components/toast-host.ts", "utf8");

  test("shell exposes a real My Content link (not a dead span)", () => {
    assert.match(shell, /#\/mine/, "shell must link to #/mine");
    assert.match(shell, /My Content/, "My Content label present");
    assert.doesNotMatch(
      shell,
      /<span>\s*My Content\s*<\/span>/,
      "My Content must be a link, not a span",
    );
  });

  test("shell status strip + active-tasks live region", () => {
    assert.match(shell, /status-strip/, "status strip present");
    assert.match(shell, /tasks-ind/, "active-tasks indicator present");
    assert.match(shell, /aria-live/, "status strip uses a live region");
  });

  test("toast host has assertive + polite live regions, no raw innerHTML interpolation", () => {
    assert.match(toastHost, /aria-live="assertive"/, "errors are assertive");
    assert.match(toastHost, /aria-live="polite"/, "non-errors are polite");
    assert.match(toastHost, /textContent/, "toast text via textContent");
    assert.doesNotMatch(
      toastHost,
      /\.innerHTML\s*=\s*`[^`]*\$\{(?!esc\()/,
      "toast-host must not interpolate unescaped data into innerHTML",
    );
  });

  test("quick-settings + settings expose a labelled Theme + RAM control", () => {
    const qs = readFileSync("src/components/quick-settings.ts", "utf8");
    const set = readFileSync("src/components/settings-screen.ts", "utf8");
    for (const src of [qs, set]) {
      assert.match(src, /Theme/, "Theme control present");
      assert.match(src, /aria-label|<label|name="theme"/, "controls labelled");
    }
    assert.match(qs, /type="range"/, "quick-settings RAM uses a range slider");
  });
}
```

- [ ] **Step 2: Run the full UI suite.**

Run: `cd crates/client-app/ui && npm run build && npm test && npm run test:a11y && npm run typecheck`
Expected: ALL PASS.

- [ ] **Step 3: Commit.**

```bash
git add crates/client-app/ui/src/a11y.test.ts
git commit -m "test(ui): a11y lint for My Content link, status strip, toasts, theme/RAM controls"
```

---

## Task 18: Full-stack verification + GUI smoke + handoff checklist

**Files:** none (verification + packaging only).

- [ ] **Step 1: Rust gates.**

Run (bash, PATH-prefixed):
```
cargo clippy -p maxsecu-client-app -- -D warnings
cargo test -p maxsecu-client-app --lib
cargo test -p maxsecu-client-app --test browse_view_e2e --test upload_e2e
```
Expected: clippy clean; lib green (if `keystore::tests` flakes, re-run `content_cache::`/`ram::`/`config::` targeted to confirm); **both e2e PASS** (identical verified bytes — the cache returns the same content).

- [ ] **Step 2: deny/audit.**

Run: `cargo deny check 2>&1 | tail -20 && cargo audit 2>&1 | tail -20`
Expected: pass (only the intended `sysinfo` addition).

- [ ] **Step 3: Build the release exes.**

Run: `cd crates/client-app/ui && npm run build` then
`cargo build --release -p maxsecu-portable-server -p maxsecu-client-app -p maxsecu-demo-seed`
Expected: all build (the Tauri exe embeds the freshly built `ui/dist`).

- [ ] **Step 4: Stage the new client exe into the demo client folder(s).**

Copy the rebuilt exe into BOTH client folders so the GUI runs the new build:
```
cp target/release/maxsecu-client-app.exe dist/MaxSecuClient-root/maxsecu-client-app.exe
cp target/release/maxsecu-client-app.exe dist/MaxSecuClient-bob/maxsecu-client-app.exe
```
(Use `Copy-Item` in PowerShell if preferred.)

- [ ] **Step 5: Start the demo server (with the WSL keepalive) — see `docs/local-demo-runbook.md`.**

Run (PowerShell): `dist\MaxSecuServer\run-server.ps1`
Expected: the script spawns the hidden WSL keepalive, then the server serves on `https://localhost:8443`. (Clients MUST use `localhost`, not `127.0.0.1` — cert SAN.) If the DB connect times out, confirm the keepalive is up before retrying.

- [ ] **Step 6: GUI smoke launch.**

Run (PowerShell): `Start-Process dist\MaxSecuClient-root\maxsecu-client-app.exe`
Then confirm the process is alive with WebView2 children:
`Get-Process maxsecu-client-app, msedgewebview2 -ErrorAction SilentlyContinue | Select-Object Name, Id`
Expected: `maxsecu-client-app` plus one or more `msedgewebview2` children → the window opened and WebView2 loaded `ui/dist`.

- [ ] **Step 7: Hand the user the eyeball checklist** (these need a human; list them in the final message):
  - Dark theme by default; the ⚡ Theme toggle → light flips the whole shell instantly and persists across relaunch.
  - Settings → Text size = Larger visibly scales ALL text (not just body); reduced-motion stills the shimmer/hover motion.
  - "My Content" nav link opens `#/mine` (owner-filtered; no "only my uploads" checkbox there); active nav item is highlighted.
  - Feed shows skeletons while loading, then cards; leaving and returning to the feed is instant (no visible rebuild); the viewer never hangs on "loading" and a second open of the same item is instant.
  - Upload shows tray progress + ETA and a green "Upload complete." toast on success; a failure shows an error toast + Retry.
  - ⚡ quick-settings shows ONLY Theme + RAM, and the ⚡ trigger disappears while on the Settings screen.
  - RAM slider/number is capped at (total RAM − 6 GB) and cannot exceed it.

- [ ] **Step 8: Final commit (if any staging artifacts changed) + STOP (do not push).**

```bash
git add -A
git commit -m "chore(demo): stage UI-overhaul client build into demo client folders" || echo "nothing to stage"
```

Report the verification evidence (test output) to the user and present the eyeball checklist. **Do not push or merge.**

---

## Self-review (performed against the spec)

- **§3 design system** → Task 16 (tokens, dark+light, motion tokens, glass surfaces, root-font-size text scaling, AA, focus-visible).
- **§4 shell/nav** → Task 10 (nav rail with active state, real My Content `#/mine` link, status strip with connection pill + sync + active-tasks, quick-settings hidden on `#/settings`); route added Task 10 (`router.ts` + test).
- **§5 feedback/loading** → skeletons (Tasks 9/13/14), toasts (Task 8 + wired in 13/14/15), upload tray prominence + success toast (Task 15).
- **§6 cache** → Tasks 3 (module), 4 (managed state + exit-zeroize), 5 (decrypt_card/open_content integration + version), 5 (live set_cap). Zeroizing on evict/replace (Drop) + on close (RunEvent::Exit). Video excluded. Oversize served-through.
- **§6.1 RAM sizing** → Task 1 (`sysinfo`, `ram_limits`, 10%/min-64/total−6GB math) + Task 2 (normalized clamps into computed bounds; first-run default).
- **§7 settings + shared store** → Task 2 (`appearance.theme`), Task 6 (shared reactive store + theme apply), Tasks 11–12 (quick-settings + settings screen both read/write the store; live apply).
- **§8 bug fixes** → My Content (Task 10), viewer-stuck/serial hardening + priority + cancel-on-leave (Tasks 7/13/14), feed reload (retained view-state, Task 13 + cache Task 5), text-size scaling (Task 16), reduced-motion (Task 16), upload feedback (Tasks 8/15).
- **§9 file change map** → every named file is touched in a task; `core/toast.ts`, `components/toast-host.ts`, `components/skeleton-card.ts` created (Tasks 8/9).
- **§10 testing** → settings store test (Task 6), serial priority/cancel/release (Task 7), router includes mine (Task 10), content_cache LRU/oversize/set_cap/clear (Task 3), ram math + normalized bounds (Tasks 1/2), a11y lint extensions (Task 17), e2e stays green (Tasks 4/5/18).
- **Constraints** → only `sysinfo` added (Task 1); no TCB/backend edits (every task is `client-app`/`ui`); no `cargo fmt --all`; sanitized errors preserved (cache returns the same DTOs); no new plaintext crosses the seam (cache is Rust-process-only).

**Type-consistency check:** `ContentCache::{new,get_card,get_content,put_card,put_content,set_cap,clear_and_zeroize,invalidate}` used identically in Tasks 3/4/5. `CacheKey{file_id,version}` and `CachedMeta{file_type,title,tags,thumbnail_b64,author_fp,recovery_ok,mine}` consistent across feed/viewer. `RamLimits{default_mb,min_mb,max_mb}` consistent (Rust + types.ts). `settingsStore`/`updateSettings`/`applySettings`/`bindDocumentToSettings` consistent across settings.ts, quick-settings, settings-screen, app-shell. `serial`/`serialPriority`/`cancelPending` consistent across serial.ts, feed, viewer. `toast`/`subscribeToasts` consistent across toast.ts, toast-host, feed, viewer, upload-tray. `ROUTES`/`Route` includes `mine` (router + shell). `version` optional field added to `CardRequest`/`OpenContentRequest` and passed by media-card/media-viewer.
```