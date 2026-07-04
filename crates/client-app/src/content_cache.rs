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
        const ENTRY_OVERHEAD: usize = 128; // fixed accounting floor per entry (key+headers+bucket)
        self.bytes = ENTRY_OVERHEAD
            + self.meta.approx_bytes()
            + self.content.as_ref().map_or(0, |c| c.len());
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

    /// Poison-safe lock: a panic while holding the guard must not brick the cache
    /// (it stores no key material), so recover the inner state instead of `unwrap`.
    fn guard(&self) -> std::sync::MutexGuard<'_, CacheInner> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn tick(inner: &mut CacheInner) -> u64 {
        inner.clock += 1;
        inner.clock
    }

    /// Reconstruct a `CardDto` from a cached entry's meta (header-only data).
    pub fn get_card(&self, key: CacheKey, file_id_hex: &str) -> Option<CardDto> {
        let mut inner = self.guard();
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
            member_counts: crate::dto::MemberCounts::default(),
        })
    }

    /// Reconstruct an `OpenedContentDto` — only a hit if the content payload is
    /// resident (a card-only entry returns `None` so the caller fetches content).
    /// The stored bytes are DISPLAY-FINAL (see `put_content`): an image is
    /// re-encoded back to base64 into `image_png_b64`; a blog's already-sanitized
    /// UTF-8 bytes are returned verbatim via `from_utf8_lossy`. So a cache hit is
    /// byte-identical to a fresh decrypt+shape — the cache applies no shaping itself.
    pub fn get_content(&self, key: CacheKey, file_id_hex: &str) -> Option<OpenedContentDto> {
        let mut inner = self.guard();
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
            // A cache hit only exists because THIS wrap-holder already opened the
            // item successfully once (see `put_content`'s callers) — same D-OQ3
            // display-metadata semantics as a fresh open, not ownership-gated.
            can_share: true,
        })
    }

    /// Insert/update the header-only meta for a card (no content).
    pub fn put_card(&self, key: CacheKey, meta: CachedMeta) {
        let mut inner = self.guard();
        let t = Self::tick(&mut inner);
        Self::upsert(&mut inner, key, meta, None, t);
        Self::evict_to_fit(&mut inner);
    }

    /// Insert/update with the decrypted content payload resident.
    ///
    /// Stores the caller's FINAL display bytes for this content: for an IMAGE the
    /// raw canonical-PNG content bytes (read back base64-encoded into
    /// `image_png_b64`); for a BLOG the already-sanitized UTF-8 text bytes (read
    /// back verbatim). The caller is responsible for passing display-final bytes so
    /// a cache hit is byte-identical to a fresh decrypt+shape.
    pub fn put_content(&self, key: CacheKey, meta: CachedMeta, content: Vec<u8>) {
        let content = Zeroizing::new(content); // wiped on every exit, incl. oversize return
        let mut inner = self.guard();
        // Oversize-vs-cap: serve through, never store (and never evict everything
        // for one giant item).
        let projected = meta.approx_bytes() + content.len();
        if projected > inner.cap {
            // Drop any stale smaller entry under this key, then bail.
            if let Some(old) = inner.map.remove(&key) {
                inner.total -= old.bytes;
            }
            return; // content drops here → zeroized
        }
        let t = Self::tick(&mut inner);
        Self::upsert(&mut inner, key, meta, Some(content), t);
        Self::evict_to_fit(&mut inner);
    }

    fn upsert(
        inner: &mut CacheInner,
        key: CacheKey,
        mut meta: CachedMeta,
        mut content: Option<Zeroizing<Vec<u8>>>,
        now: u64,
    ) {
        if let Some(old) = inner.map.remove(&key) {
            inner.total -= old.bytes;
            // Carry forward fields the new writer didn't supply, so a card-put
            // (thumbnail, no content) and a content-put (content, no thumbnail) for
            // the same (file, version) ENRICH one unified entry instead of clobbering
            // each other on the feed→view→feed flow the cache exists to accelerate.
            if meta.thumbnail_b64.is_none() {
                meta.thumbnail_b64 = old.meta.thumbnail_b64;
            }
            if content.is_none() {
                content = old.content;
            }
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
        let mut inner = self.guard();
        if let Some(e) = inner.map.remove(&key) {
            inner.total -= e.bytes;
        }
    }

    /// Live cap change (Settings RAM control). Shrinks → evicts to fit immediately.
    pub fn set_cap(&self, cap_bytes: usize) {
        let mut inner = self.guard();
        inner.cap = cap_bytes;
        Self::evict_to_fit(&mut inner);
    }

    /// Wipe everything (app close). Every content payload is `Zeroizing`, so the
    /// plaintext is zeroed as each entry drops.
    pub fn clear_and_zeroize(&self) {
        let mut inner = self.guard();
        inner.map.clear(); // each Entry drops → Zeroizing<Vec<u8>> wiped.
        inner.total = 0;
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.guard().map.len()
    }
    #[cfg(test)]
    fn total(&self) -> usize {
        self.guard().total
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
        // Each entry ≈ 128 overhead + 7 meta ("blog"+1-char title+"ab") + 20 content
        // = 155B. Cap 360 fits 2 (310) but not 3 (465), so the 3rd evicts the LRU.
        let c = ContentCache::new(360);
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

    #[test]
    fn image_content_round_trips_as_base64() {
        let c = ContentCache::new(1024);
        let mut m = meta("pic");
        m.file_type = "image".into();
        let png = vec![0x89u8, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3];
        c.put_content(key(7, 2), m, png.clone());
        let got = c.get_content(key(7, 2), "07".repeat(16).as_str()).unwrap();
        assert_eq!(got.image_png_b64.unwrap(), B64.encode(&png));
        assert!(got.blog_text.is_none());
    }

    #[test]
    fn card_and_content_puts_merge_not_clobber() {
        let c = ContentCache::new(10_000);
        // 1) card first: thumbnail present, no content.
        let mut m = meta("t");
        m.thumbnail_b64 = Some("THUMB".into());
        c.put_card(key(1, 1), m);
        // 2) content next: no thumbnail in this meta — must NOT drop the thumbnail.
        c.put_content(key(1, 1), meta("t"), b"body".to_vec());
        assert_eq!(c.get_content(key(1, 1), "x").unwrap().blog_text.unwrap(), "body");
        assert_eq!(
            c.get_card(key(1, 1), "x").unwrap().thumbnail_b64,
            Some("THUMB".into()),
            "thumbnail survives a later content-put"
        );
        // 3) a later card-put (feed re-mount) must NOT evict the cached content.
        c.put_card(key(1, 1), meta("t"));
        assert!(
            c.get_content(key(1, 1), "x").is_some(),
            "content survives a later card-put"
        );
    }

    #[test]
    fn invalidate_drops_entry_and_byte_accounting() {
        let c = ContentCache::new(1000);
        c.put_content(key(1, 1), meta("a"), vec![0u8; 200]);
        assert!(c.get_content(key(1, 1), "x").is_some());
        c.invalidate(key(1, 1));
        assert!(c.get_content(key(1, 1), "x").is_none());
        assert_eq!(c.total(), 0);
    }
}
