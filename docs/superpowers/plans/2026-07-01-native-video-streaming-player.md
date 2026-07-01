# Native `<video>` Streaming Player Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the hand-rolled canvas decode engine with a real `<video>` element fed by a custom Tauri `stream://` URI-scheme protocol that answers HTTP Range requests with per-range-decrypted bytes, so the browser's native media stack owns demux/decode/clock/buffering/seek/A-V-sync.

**Architecture:** A new pure Rust core (`plan_range` + `assemble_range` in `crate::stream`) maps a requested plaintext byte range to the covering CMAF fragments, reuses `feed_fragment` (cache-or-fetch + AEAD decrypt) to materialize their plaintext, and slices out the exact range. The download command layer prefetches missing ciphertext over the network between the two sync halves (mirroring `play_window_command`). A thin async Tauri protocol responder parses the `Range` header, calls the core, and builds a `206 Partial Content` response. The frontend points a real `<video src="stream://media/<file_id>">` wrapped in Media Chrome. The content key never leaves the Rust process; only decrypted plaintext crosses into the WebView.

**Tech Stack:** Rust (Tauri v2, hyper, tokio, zeroize), `maxsecu-client-core` (`ContentDecryptor`), vanilla TypeScript + Web Components, Media Chrome (npm), esbuild, `node:test`.

**Spec:** `docs/superpowers/specs/2026-07-01-native-video-streaming-player-design.md`

---

## Notes for the implementer (read once)

- `cargo` is NOT on the tool PATH. Prefix every cargo command:
  - PowerShell: `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cargo ...`
  - bash: `export PATH="$HOME/.cargo/bin:$PATH"; cargo ...`
- **NEVER** run `cargo fmt --all` (pre-existing repo-wide rustfmt drift). Match the style of the file you edit.
- UI commands run from `crates/client-app/ui`: `npm run typecheck`, `npm run build`, `npm run test`, `npm run test:a11y`. Single UI test file: `node --experimental-strip-types --test src/core/<file>.test.ts`.
- Rust crate under test is `maxsecu-client-app` (`-p maxsecu-client-app`).
- The canonical content is AV1 video + AAC audio in fragmented MP4 (CMAF). Each content chunk holds exactly `chunk_size` bytes of plaintext except the last.
- The `hex(&[u8]) -> String` and `hex16(&str) -> Result<[u8;16], UiError>` helpers live in `crate::commands::feed`.
- Removal of the old engine + `media-worker` playback path happens LAST (Task 11), only after the new path is e2e-green (Task 6) and smoke-green (Task 10).

---

## Task 0: Verify AV1+AAC fMP4 actually plays in WebView2 (GATE — spike)

**This gates the entire plan.** If WebView2 on the target machine cannot natively decode AV1 video + AAC audio in fragmented MP4, the native-`<video>` approach is void and we stop here and reconsider.

**Files:**
- Create (throwaway): `crates/client-app/ui/webview-codec-probe.html`

- [ ] **Step 1: Produce a known-good canonical AV1+AAC fMP4 sample**

The repo already transcodes to canonical AV1/AAC CMAF. Reuse the vendored ffmpeg to make a tiny sample from an existing clip:

Run (bash):
```bash
export PATH="$HOME/.cargo/bin:$PATH"
"vendor/ffmpeg/ffmpeg.exe" -y -i "D:/Images/00168.mp4" \
  -t 3 -c:v libaom-av1 -crf 34 -b:v 0 -c:a aac -movflags +frag_keyframe+empty_moov+default_base_moof \
  "C:/Users/gecim/AppData/Local/Temp/claude/D--scrs-programs-MaxSecu/3248e1a8-3781-45e1-823d-9259b7c73d67/scratchpad/probe-av1-aac.mp4"
```
Expected: a small `.mp4` is written. (If `libaom-av1` is unavailable in the vendored build, substitute the exact encoder the transcode worker uses — grep `crates/media-transcode-worker` for the codec/muxer flags and mirror them, so the probe matches production output.)

- [ ] **Step 2: Write a minimal probe page**

`crates/client-app/ui/webview-codec-probe.html`:
```html
<!doctype html>
<html>
  <body style="background:#111;color:#eee;font-family:sans-serif">
    <h3 id="support"></h3>
    <video id="v" controls autoplay muted style="max-width:640px"></video>
    <pre id="log"></pre>
    <script>
      const S = 'video/mp4; codecs="av01.0.05M.08,mp4a.40.2"';
      document.getElementById('support').textContent =
        'MediaSource.isTypeSupported: ' + (window.MediaSource ? MediaSource.isTypeSupported(S) : 'no MSE') +
        ' | canPlayType: ' + document.createElement('video').canPlayType(S);
      const v = document.getElementById('v');
      v.src = 'probe-av1-aac.mp4';
      const log = (m) => (document.getElementById('log').textContent += m + '\n');
      ['loadedmetadata','canplay','playing','timeupdate','error','stalled'].forEach(e =>
        v.addEventListener(e, () => log(e + (e === 'error' ? ' code=' + (v.error && v.error.code) : ' t=' + v.currentTime.toFixed(2)))));
    </script>
  </body>
</html>
```

- [ ] **Step 3: Load it in the actual WebView2 runtime**

Copy `probe-av1-aac.mp4` next to the html, then open the page inside a Tauri window (the WebView2 engine — NOT a system browser, which has different codec licensing). Fastest path: temporarily set `tauri.conf.json` `build.frontendDist` is not needed — instead run the existing packaged client and, in its window, use the devtools console to `window.location.href = <file url to the probe>` is blocked by CSP; simplest is to temporarily point `"frontendDist"` at a folder containing the probe as `index.html`. Document whichever method you use in the task's commit message.

Expected PASS: `canPlayType` returns `"probably"` or `"maybe"`, the `<video>` fires `playing` and `timeupdate` advances, and you SEE the frames + hear nothing (muted). PASS means AV1+AAC decode works in WebView2.

Expected FAIL: `canPlayType` empty, `error code=4` (SRC_NOT_SUPPORTED). If FAIL, **STOP** — record the result and escalate to the controller; the plan cannot proceed.

- [ ] **Step 4: Record the result and clean up**

Delete `webview-codec-probe.html` and the sample. Commit a one-line note of the outcome:
```bash
git commit --allow-empty -m "chore(video): WebView2 AV1+AAC fMP4 playback verified (Task 0 gate)"
```

---

## Task 1: Capture the content stream's `chunk_size` in the parsed file view

The byte↔chunk mapping needs the plaintext `chunk_size`. The §8.5 file view already carries it per stream (`"chunk_size"`), but `parse_file_view` currently drops it.

**Files:**
- Modify: `crates/client-app/src/download.rs` (`StreamSpec`, `parse_file_view`)
- Test: `crates/client-app/src/download.rs` (existing `#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing test**

Add to the tests module in `crates/client-app/src/download.rs`:
```rust
    #[test]
    fn parses_content_chunk_size() {
        let p = parse_file_view(&view_json()).unwrap();
        let content = p
            .streams
            .iter()
            .find(|s| s.stream_type == StreamType::Content)
            .unwrap();
        assert_eq!(content.chunk_size, 4096);
    }
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cargo test -p maxsecu-client-app --lib download::tests::parses_content_chunk_size`
Expected: FAIL — `no field `chunk_size` on type `&StreamSpec``.

- [ ] **Step 3: Add the field and populate it**

In `StreamSpec`:
```rust
pub struct StreamSpec {
    pub stream_type: StreamType,
    pub chunk_count: u64,
    pub chunk_size: u64,
}
```
In `parse_file_view`, inside the streams loop, replace the `streams.push(StreamSpec { ... })` with:
```rust
        streams.push(StreamSpec {
            stream_type: st,
            chunk_count: s["chunk_count"].as_u64().ok_or_else(bad)?,
            chunk_size: s["chunk_size"].as_u64().ok_or_else(bad)?,
        });
```

- [ ] **Step 4: Run the test to confirm it passes**

Run: `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cargo test -p maxsecu-client-app --lib download::`
Expected: PASS (all download tests, including `parses_a_well_formed_view`).

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/src/download.rs
git commit -m "feat(video): capture content chunk_size in the parsed file view"
```

---

## Task 2: Pure byte-range → fragment-range mapping + slicing (`crate::stream`)

The heart of range serving, with zero Tauri/network coupling: given the fragment index, `chunk_size`, and `total_len`, compute (a) which contiguous fragments cover a requested plaintext byte range, (b) the byte offset of that fragment span's start, and (c) how to slice the assembled plaintext back to the exact range.

**Files:**
- Create: `crates/client-app/src/stream.rs`
- Modify: `crates/client-app/src/lib.rs` (add `pub mod stream;`)
- Test: `crates/client-app/src/stream.rs` (`#[cfg(test)] mod tests`)

- [ ] **Step 1: Register the module**

In `crates/client-app/src/lib.rs`, add alongside the other `pub mod` lines (e.g. near `pub mod video;`):
```rust
pub mod stream;
```

- [ ] **Step 2: Write the failing tests (pure mapping)**

Create `crates/client-app/src/stream.rs`:
```rust
//! Byte-range video streaming core (native-<video> player). Maps a requested
//! plaintext byte range to the covering CMAF fragments, reuses the fragment
//! feeder to materialize their plaintext, and slices out the exact range. No
//! Tauri, no network here — the command layer prefetches ciphertext between the
//! two sync halves (`plan_range` then `assemble_range`), mirroring the
//! decrypt-while-play discipline: only ciphertext is cached, plaintext is
//! bounded + zeroized, the decryptor never crosses the seam.

use crate::error::UiError;
use crate::video::FragmentEntry;

/// A sanitized range-layer error (no oracle / internal detail crosses the seam).
fn range_err() -> UiError {
    UiError::new("video_failed", "The video could not be streamed.")
}

/// A resolved, satisfiable request for plaintext bytes `[start, start+len)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeReq {
    pub start: u64,
    pub len: u64,
}

/// Clamp a parsed `(first, last_inclusive_or_none)` HTTP byte range against
/// `total_len`, capping the served length to `max_body` so an open-ended
/// `bytes=N-` streams in bounded pieces instead of returning the whole file.
/// Returns `None` (⇒ 416) for an unsatisfiable range (`first >= total_len`).
pub fn resolve_range(
    first: u64,
    last_inclusive: Option<u64>,
    total_len: u64,
    max_body: u64,
) -> Option<RangeReq> {
    if total_len == 0 || first >= total_len {
        return None;
    }
    let last = last_inclusive.unwrap_or(total_len - 1).min(total_len - 1);
    if last < first {
        return None;
    }
    let want = last - first + 1;
    let len = want.min(max_body.max(1));
    Some(RangeReq { start: first, len })
}

/// The fragment span `[f0, f1]` (inclusive `seq`s) whose chunk ranges cover the
/// plaintext byte range `[start, start+len)`, plus `base` = the plaintext byte
/// offset of fragment `f0`'s first chunk (`f0.chunk_start * chunk_size`). The
/// caller feeds fragments `f0..=f1`, concatenates their plaintext, and slices
/// `[start - base, start - base + len)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangePlan {
    pub f0: u32,
    pub f1: u32,
    pub base: u64,
}

/// Map a satisfiable byte range to its covering fragment span. `chunk_size > 0`
/// and a non-empty, contiguous-from-0 index (as `parse_fragment_index`
/// guarantees) are required. Fail-closed on any arithmetic/coverage violation.
pub fn plan_range(
    index: &[FragmentEntry],
    chunk_size: u64,
    req: &RangeReq,
) -> Result<RangePlan, UiError> {
    if index.is_empty() || chunk_size == 0 || req.len == 0 {
        return Err(range_err());
    }
    let last_byte = req.start.checked_add(req.len - 1).ok_or_else(range_err)?;
    let first_chunk = req.start / chunk_size;
    let last_chunk = last_byte / chunk_size;

    let mut f0: Option<u32> = None;
    let mut f1: Option<u32> = None;
    for e in index {
        let cstart = e.chunk_start;
        let cend = e.chunk_start.checked_add(e.chunk_len).ok_or_else(range_err)?; // exclusive
        if first_chunk >= cstart && first_chunk < cend {
            f0 = Some(e.seq);
        }
        if last_chunk >= cstart && last_chunk < cend {
            f1 = Some(e.seq);
        }
    }
    let (f0, f1) = (f0.ok_or_else(range_err)?, f1.ok_or_else(range_err)?);
    let base = index
        .iter()
        .find(|e| e.seq == f0)
        .ok_or_else(range_err)?
        .chunk_start
        .checked_mul(chunk_size)
        .ok_or_else(range_err)?;
    Ok(RangePlan { f0, f1, base })
}

/// Slice the exact requested range out of the concatenated fragment-span
/// plaintext. `assembled` is the plaintext of fragments `[f0, f1]` in order;
/// `base` is `plan.base`. Fail-closed if the slice is out of bounds.
pub fn slice_range(assembled: &[u8], base: u64, req: &RangeReq) -> Result<Vec<u8>, UiError> {
    let lo = req.start.checked_sub(base).ok_or_else(range_err)? as usize;
    let hi = lo
        .checked_add(req.len as usize)
        .filter(|hi| *hi <= assembled.len())
        .ok_or_else(range_err)?;
    Ok(assembled[lo..hi].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::video::parse_fragment_index;

    fn idx() -> Vec<FragmentEntry> {
        // 3 fragments: chunks [0,2), [2,5), [5,6) — 6 chunks total.
        parse_fragment_index(&serde_json::json!({
            "title": "v", "tags": [],
            "fragments": [
                { "seq": 0, "pts_ms": 0,    "chunk_start": 0, "chunk_len": 2 },
                { "seq": 1, "pts_ms": 1000, "chunk_start": 2, "chunk_len": 3 },
                { "seq": 2, "pts_ms": 2000, "chunk_start": 5, "chunk_len": 1 },
            ]
        }))
        .unwrap()
    }

    #[test]
    fn resolve_open_ended_caps_to_max_body() {
        // total 100, bytes=0- , cap 40 → [0,40)
        let r = resolve_range(0, None, 100, 40).unwrap();
        assert_eq!(r, RangeReq { start: 0, len: 40 });
    }

    #[test]
    fn resolve_bounded_clamps_to_total_and_cap() {
        // bytes=90-999 over total 100 → last clamps to 99 → want 10, cap 40 → 10
        let r = resolve_range(90, Some(999), 100, 40).unwrap();
        assert_eq!(r, RangeReq { start: 90, len: 10 });
    }

    #[test]
    fn resolve_unsatisfiable_is_none() {
        assert!(resolve_range(100, None, 100, 40).is_none()); // first == total
        assert!(resolve_range(0, None, 0, 40).is_none()); // empty resource
    }

    #[test]
    fn plan_single_fragment() {
        // chunk_size 4096: bytes [0, 100) live entirely in chunk 0 ⇒ fragment 0.
        let p = plan_range(&idx(), 4096, &RangeReq { start: 0, len: 100 }).unwrap();
        assert_eq!(p, RangePlan { f0: 0, f1: 0, base: 0 });
    }

    #[test]
    fn plan_spans_fragments() {
        // start in chunk 1 (frag 0), end in chunk 5 (frag 2). base = frag0.chunk_start*cs = 0.
        let p = plan_range(&idx(), 4096, &RangeReq { start: 4096, len: 4096 * 5 }).unwrap();
        assert_eq!(p, RangePlan { f0: 0, f1: 2, base: 0 });
    }

    #[test]
    fn plan_mid_start_base_is_fragment_start() {
        // start in chunk 2 (frag 1) → f0 = 1, base = 2*4096.
        let p = plan_range(&idx(), 4096, &RangeReq { start: 2 * 4096, len: 10 }).unwrap();
        assert_eq!(p, RangePlan { f0: 1, f1: 1, base: 2 * 4096 });
    }

    #[test]
    fn slice_extracts_exact_range() {
        let assembled: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
        // base = 100 means assembled[0] is plaintext byte 100.
        let got = slice_range(&assembled, 100, &RangeReq { start: 150, len: 10 }).unwrap();
        assert_eq!(got, (50..60u32).map(|i| i as u8).collect::<Vec<u8>>());
    }

    #[test]
    fn slice_out_of_bounds_fails_closed() {
        let assembled = vec![0u8; 10];
        assert!(slice_range(&assembled, 0, &RangeReq { start: 5, len: 100 }).is_err());
        // base greater than start underflows → err
        assert!(slice_range(&assembled, 50, &RangeReq { start: 0, len: 1 }).is_err());
    }
}
```

- [ ] **Step 3: Run the tests and confirm they fail**

Run: `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cargo test -p maxsecu-client-app --lib stream::`
Expected: FAIL to compile / assertion failures until the module compiles clean (it is written above, so on first compile the tests should PASS — if a test fails, fix the code above, not the test).

- [ ] **Step 4: Run again to confirm PASS**

Run: `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cargo test -p maxsecu-client-app --lib stream::`
Expected: PASS (8 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/src/stream.rs crates/client-app/src/lib.rs
git commit -m "feat(video): pure byte-range->fragment-range mapping + slicing (stream core)"
```

---

## Task 3: `assemble_range` — feed the fragment span + slice (integration over a real decryptor)

Materialize the plaintext for a `RangePlan`'s fragment span by reusing `feed_fragment` (cache-or-fetch + AEAD decrypt), then slice to the exact range. The ciphertext source is an injected sync `fetch_chunk` (the command prefetches into a map; tests use an in-memory map) — identical to `decrypt_window`.

**Files:**
- Modify: `crates/client-app/src/stream.rs`
- Test: `crates/client-app/src/stream.rs`

- [ ] **Step 1: Write the failing integration test**

Add to `crates/client-app/src/stream.rs` (below `slice_range`, before `#[cfg(test)]` the fn; add the test inside the tests module). First the function signature the test drives — add this ABOVE the tests module:
```rust
use crate::fragment_cache::FragmentCache;
use maxsecu_client_core::ContentDecryptor;

/// Materialize plaintext for the fragment span `[plan.f0, plan.f1]` (via
/// `feed_fragment`: cache-hit ⇒ no fetch, miss ⇒ `fetch_chunk` + cache the
/// CIPHERTEXT), then slice out exactly `req`. The assembled plaintext is a
/// transient `Vec` dropped on return (never cached, returned only as the sliced
/// bytes). Fail-closed on any feed/slice error. `fetch_chunk(i)` returns the
/// opaque ciphertext for ABSOLUTE content chunk `i`.
pub fn assemble_range<F>(
    index: &[FragmentEntry],
    cache: &mut FragmentCache,
    decryptor: &ContentDecryptor,
    file_id_hex: &str,
    plan: &RangePlan,
    req: &RangeReq,
    mut fetch_chunk: F,
) -> Result<Vec<u8>, UiError>
where
    F: FnMut(u64) -> Result<Vec<u8>, UiError>,
{
    let mut assembled: Vec<u8> = Vec::new();
    for seq in plan.f0..=plan.f1 {
        crate::video::feed_fragment(
            index,
            cache,
            decryptor,
            file_id_hex,
            seq,
            &mut fetch_chunk,
            |pt| {
                assembled.extend_from_slice(pt);
                Ok(())
            },
        )?;
    }
    slice_range(&assembled, plan.base, req)
}
```
Then add the test inside `mod tests` (it needs the same test-support imports `crate::video::tests` uses; replicate a minimal builder here rather than reaching into another module's private test helpers):
```rust
    use maxsecu_client_core::{
        build_upload, open_content_decryptor, Identity, PlaintextStreams, StreamChunks,
        StreamHeader, UploadBundle, UploadParams, VerifyContext, NO_ADMINS, NO_GRANTERS,
    };
    use maxsecu_crypto::generate_enc_keypair;
    use maxsecu_encoding::encode;
    use maxsecu_encoding::types::{FileType, Id, RecipientType, StreamType, Timestamp};
    use std::path::PathBuf;

    const OWNER_ID: Id = Id([0x11; 16]);
    const FILE_ID: Id = Id([0xF1; 16]);
    const NOW: Timestamp = Timestamp(1_719_500_000_000);

    fn tmp_cache(tag: &str) -> FragmentCache {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("mxstream-{tag}-{}-{nanos}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        FragmentCache::open(&dir, 1 << 20).unwrap()
    }

    /// Build a 6-chunk video-shaped upload; return (decryptor-ready header + owner,
    /// the ciphertext content chunks, the whole content plaintext, chunk_size).
    fn build() -> (Identity, StreamHeader, Vec<Vec<u8>>, Vec<u8>, u64) {
        let owner = Identity::generate();
        let (_rsk, rpk) = generate_enc_keypair();
        let chunk_size = 4096u64;
        let params = UploadParams {
            owner: &owner,
            owner_id: OWNER_ID,
            owner_key_version: 1,
            file_id: FILE_ID,
            file_type: FileType::Video,
            chunk_size: chunk_size as u32,
            recovery_pub: rpk,
            recovery_mlkem_pub: None,
            created_at: NOW,
        };
        let content: Vec<u8> = (0..(4096 * 5 + 123)).map(|i| (i % 251) as u8).collect(); // 6 chunks
        let streams = PlaintextStreams {
            content: content.clone(),
            metadata: Some(b"title=clip".to_vec()),
            thumbnail: None,
            preview: None,
        };
        let b: UploadBundle = build_upload(&params, &streams).unwrap();
        let sw = b.wraps.iter().find(|w| w.recipient_type == RecipientType::User).unwrap();
        let rw = b.wraps.iter().find(|w| w.recipient_type == RecipientType::Recovery).unwrap();
        let content_s = b.streams.iter().find(|s| s.stream_type == StreamType::Content).unwrap();
        let small = b
            .streams
            .iter()
            .filter(|s| s.stream_type != StreamType::Content)
            .map(|s| StreamChunks { stream_type: s.stream_type, chunks: s.chunks.clone() })
            .collect();
        let header = StreamHeader {
            manifest_bytes: encode(&b.manifest),
            manifest_sig: b.manifest_sig,
            genesis_bytes: encode(&b.genesis),
            genesis_sig: b.genesis_sig,
            wrapped_dek: sw.wrapped_dek.clone(),
            grant_bytes: encode(&sw.grant),
            grant_sig: sw.grant_sig,
            ancestor_grants: vec![],
            recovery_grant_bytes: encode(&rw.grant),
            recovery_grant_sig: rw.grant_sig,
            small_streams: small,
        };
        (owner, header, content_s.chunks.clone(), content, chunk_size)
    }

    fn decryptor_of(owner: &Identity, header: &StreamHeader) -> ContentDecryptor {
        let pk = owner.sig_pub_bytes();
        let ctx = VerifyContext {
            file_id: FILE_ID,
            author_sig_pub: pk,
            owner_sig_pub: pk,
            recipient_id: OWNER_ID,
            recipient_type: RecipientType::User,
            recipient_secret: owner.enc_secret(),
            recipient_mlkem_seed: None,
            seen_max_version: None,
            granter_sig_pub: &NO_GRANTERS,
            admin_sig_pub: &NO_ADMINS,
            tombstones: None,
            compromise: None,
        };
        open_content_decryptor(&ctx, header).unwrap()
    }

    fn file_id_hex() -> String {
        FILE_ID.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn assemble_returns_exact_plaintext_range_across_fragments() {
        let (owner, header, ct, content, cs) = build();
        let dec = decryptor_of(&owner, &header);
        let index = idx(); // 3 frags over 6 chunks — matches this 6-chunk content
        let mut cache = tmp_cache("asm");
        let id = file_id_hex();

        // Request bytes [4096, 4096+9000) — spans chunk 1 (frag 0) .. chunk 3 (frag 1).
        let req = RangeReq { start: 4096, len: 9000 };
        let plan = plan_range(&index, cs, &req).unwrap();
        let mut fetches = 0u32;
        let got = assemble_range(&index, &mut cache, &dec, &id, &plan, &req, |i| {
            fetches += 1;
            Ok(ct[i as usize].clone())
        })
        .unwrap();
        assert_eq!(got, content[4096..4096 + 9000].to_vec());
        assert!(fetches > 0, "cold range fetched ciphertext");

        // Second identical request is a cache hit: no fetch, same bytes.
        let mut fetches2 = 0u32;
        let got2 = assemble_range(&index, &mut cache, &dec, &id, &plan, &req, |_i| {
            fetches2 += 1;
            Ok(Vec::new())
        })
        .unwrap();
        assert_eq!(fetches2, 0, "warm range performed no fetch");
        assert_eq!(got2, got);
    }
```
Note: `idx()` (3 fragments over 6 chunks) already matches this 6-chunk `content`.

- [ ] **Step 2: Run it and confirm it fails, then passes**

Run: `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cargo test -p maxsecu-client-app --lib stream::`
Expected: the code above compiles and PASSES. If a signature mismatch appears (e.g. `feed_fragment` visibility), confirm `feed_fragment`, `FragmentEntry`, and `parse_fragment_index` are `pub` in `crate::video` (they are) and adjust imports only — never weaken a test assertion.

- [ ] **Step 3: Commit**

```bash
git add crates/client-app/src/stream.rs
git commit -m "feat(video): assemble_range — feed the covering fragment span + slice to the exact byte range"
```

---

## Task 4: Total-plaintext-length probe + extend `VideoJob` (register-only open)

`open_video` currently registers the session AND decodes window 0. Rework it to register-only, and compute the two facts the range handler needs: the content `chunk_size` (from the view) and `total_plaintext_len` (from the signed chunk count + the last chunk's plaintext length, learned by decrypting the last fragment once).

**Files:**
- Modify: `crates/client-app/src/jobs.rs` (`VideoJob`)
- Modify: `crates/client-app/src/stream.rs` (add `total_len` helper)
- Test: `crates/client-app/src/stream.rs`

- [ ] **Step 1: Write the failing total-length test**

Add to `stream.rs` above the tests module:
```rust
/// Total plaintext byte length of the content: `(n-1) * chunk_size +
/// last_chunk_plaintext_len`, where `n = content_chunk_count`. The last chunk's
/// plaintext length is supplied by the caller (learned once by decrypting the
/// final fragment at open). `chunk_size > 0` and `n >= 1` required.
pub fn total_len(content_chunk_count: u64, chunk_size: u64, last_chunk_plaintext_len: u64) -> Result<u64, UiError> {
    if content_chunk_count == 0 || chunk_size == 0 {
        return Err(range_err());
    }
    (content_chunk_count - 1)
        .checked_mul(chunk_size)
        .and_then(|x| x.checked_add(last_chunk_plaintext_len))
        .ok_or_else(range_err)
}
```
And the test inside `mod tests`:
```rust
    #[test]
    fn total_len_sums_full_chunks_plus_last() {
        // 6 chunks of 4096, last chunk 123 bytes → 5*4096 + 123.
        assert_eq!(total_len(6, 4096, 123).unwrap(), 5 * 4096 + 123);
        assert!(total_len(0, 4096, 1).is_err());
        assert!(total_len(6, 0, 1).is_err());
    }

    #[test]
    fn total_len_matches_real_content() {
        let (owner, header, ct, content, cs) = build();
        let dec = decryptor_of(&owner, &header);
        let n = dec.content_chunk_count();
        // Decrypt the last chunk to learn its plaintext length.
        let last = dec.open_range(n - 1, &[ct[(n - 1) as usize].clone()]).unwrap();
        assert_eq!(total_len(n, cs, last.len() as u64).unwrap(), content.len() as u64);
    }
```

- [ ] **Step 2: Run it (fail → pass)**

Run: `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cargo test -p maxsecu-client-app --lib stream::total_len`
Expected: PASS after the helper compiles.

- [ ] **Step 3: Extend `VideoJob` with `chunk_size` + `total_len`**

In `crates/client-app/src/jobs.rs`, add two fields to `VideoJob` (keep `gain` for now; it is removed in Task 11 with the old commands):
```rust
pub struct VideoJob {
    pub decryptor: maxsecu_client_core::ContentDecryptor,
    pub index: Vec<crate::video::FragmentEntry>,
    pub cache: crate::fragment_cache::FragmentCache,
    pub file_id_hex: String,
    pub version: u64,
    /// Plaintext content chunk size (bytes) — the byte↔chunk unit for range serving.
    pub chunk_size: u64,
    /// Total plaintext content length (bytes) — the `Content-Range` denominator.
    pub total_len: u64,
    pub gain: f32,
}
```

- [ ] **Step 4: Populate the new fields in `open_video_inner`**

In `crates/client-app/src/commands/video.rs`, in `open_video_inner`, after `open_video_job_core` returns `(decryptor, index)` and before registering the job, add the probe. Replace the existing registration block (the `let cap = ...; let cache = ...; jobs.0.lock()...insert(...)` block plus the trailing `play_window_command(...)`) with:
```rust
    let version = decryptor.version();

    // Content chunk size from the (authenticated-envelope) view — the byte↔chunk
    // unit for range serving.
    let chunk_size = view
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Content)
        .map(|s| s.chunk_size)
        .ok_or_else(player_err)?;

    // Register the session first (so the fragment cache exists), then probe the
    // total plaintext length by decrypting ONLY the last fragment once — its
    // ciphertext is cached as a side effect (a back-seek to the end is warm).
    let cap = SettingsConfig::load(&dir.0).performance.ram_cache_cap_mb as u64 * 1024 * 1024;
    let cache = FragmentCache::open(&dir.0, cap).map_err(|_| player_err())?;
    jobs.0.lock().await.insert(
        file_id_hex.clone(),
        VideoJob {
            decryptor,
            index,
            cache,
            file_id_hex: file_id_hex.clone(),
            version,
            chunk_size,
            total_len: 0, // set below
            gain: 1.0,
        },
    );

    // Probe total_len via the last fragment (reuses the streaming plan/prefetch/
    // assemble path against the real server — mirrors play_window_command Phase B).
    let total = probe_total_len(&mut sender, &host, &token, &jobs, &file_id_hex, chunk_size).await?;
    if let Some(job) = jobs.0.lock().await.get_mut(&file_id_hex) {
        job.total_len = total;
    }
    Ok(())
```
Then add this helper in `crates/client-app/src/commands/video.rs` (near `play_window_command`). It reuses the exact plan/prefetch loop but for the last fragment's chunks, then decrypts to learn the last chunk's plaintext length:
```rust
/// Probe the total plaintext content length by decrypting the LAST fragment once
/// over the real server (prefetch its ciphertext, then `open_range`), caching the
/// ciphertext as a side effect. Returns `(n-1)*chunk_size + last_chunk_plaintext`.
async fn probe_total_len(
    sender: &mut hyper::client::conn::http1::SendRequest<http_body_util::Full<hyper::body::Bytes>>,
    host: &str,
    token: &str,
    jobs: &VideoJobs,
    file_id_hex: &str,
    chunk_size: u64,
) -> Result<u64, UiError> {
    // Plan: the last chunk's absolute index + the content chunk count, under the lock.
    let (n, last_idx) = {
        let guard = jobs.0.lock().await;
        let job = guard.get(file_id_hex).ok_or_else(player_err)?;
        let n = job.decryptor.content_chunk_count();
        if n == 0 {
            return Err(player_err());
        }
        (n, n - 1)
    };
    // Fetch the last ciphertext chunk (no lock).
    let uri = format!("/v1/files/{file_id_hex}/versions/{}/streams/content/chunks/{last_idx}", {
        let guard = jobs.0.lock().await;
        guard.get(file_id_hex).ok_or_else(player_err)?.version
    });
    let (status, ct) = get_bytes(sender, &uri, Some(token), host).await?;
    if status != hyper::StatusCode::OK {
        return Err(player_err());
    }
    // Decrypt just that chunk under the lock to learn its plaintext length.
    let last_len = {
        let guard = jobs.0.lock().await;
        let job = guard.get(file_id_hex).ok_or_else(player_err)?;
        job.decryptor
            .open_range(last_idx, &[ct])
            .map_err(|_| player_err())?
            .len() as u64
    };
    crate::stream::total_len(n, chunk_size, last_len)
}
```
Remove the now-unused `on_frame`/`on_audio`/`on_info`/`emit` plumbing from `open_video`/`open_video_inner` **only** in Task 11 (the old player events are still emitted by the not-yet-removed seek path); for now leave the closures in place but unused by the new body. If the compiler warns about unused `emit`/`on_*` params, prefix them with `_` at the call site to keep this task compiling without touching the seek commands.

- [ ] **Step 5: Run the crate tests**

Run: `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cargo test -p maxsecu-client-app --lib`
Expected: PASS. (Existing `commands::video` unit tests that construct `VideoJob` directly must be updated to include `chunk_size`/`total_len` — set `chunk_size: 4096, total_len: 0` in those test constructors. Find them with the compiler errors and fix each.)

- [ ] **Step 6: Commit**

```bash
git add crates/client-app/src/jobs.rs crates/client-app/src/stream.rs crates/client-app/src/commands/video.rs
git commit -m "feat(video): register-only open_video + total-length probe; VideoJob carries chunk_size/total_len"
```

---

## Task 5: `serve_range` command core + register the `stream://` protocol

Wire the three-phase (plan → async prefetch → assemble) range service and expose it through a Tauri async URI-scheme protocol. Keep the Tauri coupling thin: a `serve_range` async fn does all the work; the protocol responder just parses the `Range` header and builds the HTTP response.

**Files:**
- Modify: `crates/client-app/src/commands/video.rs` (add `serve_range`)
- Modify: `crates/client-app/src/main.rs` (register the protocol; CSP is Task 5b)
- Modify: `crates/client-app/tauri.conf.json` (CSP — media-src)

- [ ] **Step 1: Add `serve_range` (three-phase, mirrors `play_window_command`)**

In `crates/client-app/src/commands/video.rs`, add:
```rust
/// The body + metadata of one satisfied range response (206). `total_len` is the
/// Content-Range denominator; `start`/`len` describe the returned slice.
pub struct RangeResponse {
    pub start: u64,
    pub len: u64,
    pub total_len: u64,
    pub body: Vec<u8>,
}

/// Cap on a single range response body (open-ended `bytes=N-` streams in pieces).
const MAX_RANGE_BODY: u64 = 4 * 1024 * 1024;

/// Serve one plaintext byte range for an OPEN video session over the real server:
/// (A) plan the covering fragment span + which ciphertext chunks are missing, under
/// the jobs lock; (B) prefetch the missing ciphertext with NO lock held; (C) assemble
/// + slice under the lock. Fail-closed. The content key never leaves this process;
/// only the sliced plaintext is returned. `first`/`last_inclusive` are the parsed
/// HTTP byte-range bounds.
async fn serve_range(
    sender: &mut hyper::client::conn::http1::SendRequest<http_body_util::Full<hyper::body::Bytes>>,
    host: &str,
    token: &str,
    jobs: &VideoJobs,
    file_id_hex: &str,
    first: u64,
    last_inclusive: Option<u64>,
) -> Result<RangeResponse, UiError> {
    use crate::stream::{assemble_range, plan_range, resolve_range};

    // Phase A — resolve the request + plan the fragment span + fetch list, under the lock.
    let (req, plan, total_len, version, fetch_indices) = {
        let mut guard = jobs.0.lock().await;
        let job = guard.get_mut(file_id_hex).ok_or_else(player_err)?;
        let req = resolve_range(first, last_inclusive, job.total_len, MAX_RANGE_BODY)
            .ok_or_else(|| UiError::new("range_not_satisfiable", "range"))?;
        let plan = plan_range(&job.index, job.chunk_size, &req)?;
        let mut fetch_indices = Vec::new();
        for seq in plan.f0..=plan.f1 {
            let (cs, cl) = chunks_for_fragment(&job.index, seq).ok_or_else(player_err)?;
            if !cached_fragment_valid(&mut job.cache, &job.file_id_hex, seq, cl) {
                let end = cs.checked_add(cl).ok_or_else(player_err)?;
                fetch_indices.extend(cs..end);
            }
        }
        (req, plan, job.total_len, job.version, fetch_indices)
    };

    // Phase B — prefetch missing ciphertext with NO lock held.
    let mut prefetched: HashMap<u64, Vec<u8>> = HashMap::new();
    for i in fetch_indices {
        let uri = format!("/v1/files/{file_id_hex}/versions/{version}/streams/content/chunks/{i}");
        let (status, bytes) = get_bytes(sender, &uri, Some(token), host).await?;
        if status != hyper::StatusCode::OK {
            return Err(player_err());
        }
        prefetched.insert(i, bytes);
    }

    // Phase C — assemble + slice under the lock (sync decrypt in the TCB).
    let body = {
        let mut guard = jobs.0.lock().await;
        let job = guard.get_mut(file_id_hex).ok_or_else(player_err)?;
        // Split borrows: index/decryptor are read-only, cache is &mut.
        let VideoJob { index, cache, decryptor, file_id_hex: fid, .. } = job;
        assemble_range(index, cache, decryptor, fid, &plan, &req, |i| {
            prefetched.remove(&i).ok_or_else(player_err)
        })?
    };

    Ok(RangeResponse { start: req.start, len: req.len, total_len, body })
}
```
Note the `range_not_satisfiable` code — the protocol responder (Step 3) maps it to HTTP 416; every other error maps to 500.

- [ ] **Step 2: Update the CSP to allow the media scheme**

In `crates/client-app/tauri.conf.json`, replace the `security.csp` string with:
```json
    "security": { "csp": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; media-src 'self' stream: http://stream.localhost https://stream.localhost" }
```
(The exact host form is what Tauri rewrites `stream://` to on Windows WebView2; the Task-0/Task-10 smoke pins it — if playback is CSP-blocked, check the devtools console for the blocked URL and add its exact origin here.)

- [ ] **Step 3: Register the `stream://` protocol in `main.rs`**

In `crates/client-app/src/main.rs`, chain `.register_asynchronous_uri_scheme_protocol` onto the `tauri::Builder` (before `.build(...)`). Add the needed imports at the top (`use maxsecu_client_app::commands::auth::{...}` already present; add `Session`, `ConnectLock`, `AppDir` are already imported). Insert:
```rust
        .register_asynchronous_uri_scheme_protocol("stream", |ctx, request, responder| {
            let app = ctx.app_handle().clone();
            // Parse "…/media/<file_id_hex>" and the Range header up front (cheap, sync).
            let path = request.uri().path().to_string();
            let range_header = request
                .headers()
                .get(hyper::header::RANGE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            tauri::async_runtime::spawn(async move {
                let resp = maxsecu_client_app::commands::video::stream_media(&app, &path, range_header.as_deref())
                    .await;
                responder.respond(resp);
            });
        })
```
Then implement `stream_media` in `crates/client-app/src/commands/video.rs` — the ONLY place Tauri HTTP types are touched. It resolves state, calls `serve_range`, and builds the `http::Response`:
```rust
/// The `stream://media/<file_id_hex>` protocol entry point. Resolves the open
/// session, mints a fresh authed channel (Phase-3 reauth), serves the requested
/// byte range, and builds a `206 Partial Content` response. Errors map to 416
/// (unsatisfiable range) or 500 (everything else) with an empty body — no oracle.
/// Returns the concrete `http::Response<Vec<u8>>` the Tauri responder wants.
pub async fn stream_media(
    app: &tauri::AppHandle,
    path: &str,
    range_header: Option<&str>,
) -> http::Response<Vec<u8>> {
    match stream_media_inner(app, path, range_header).await {
        Ok(r) => http::Response::builder()
            .status(206)
            .header(http::header::CONTENT_TYPE, "video/mp4")
            .header(http::header::ACCEPT_RANGES, "bytes")
            .header(
                http::header::CONTENT_RANGE,
                format!("bytes {}-{}/{}", r.start, r.start + r.len - 1, r.total_len),
            )
            .header(http::header::CONTENT_LENGTH, r.len.to_string())
            .body(r.body)
            .unwrap_or_else(|_| http::Response::builder().status(500).body(Vec::new()).unwrap()),
        Err(code) => {
            let status = if code == 416 { 416 } else { 500 };
            http::Response::builder().status(status).body(Vec::new()).unwrap()
        }
    }
}

/// Inner: resolve `file_id` from the path, mint an authed channel, parse the Range
/// header, and call `serve_range`. Returns an HTTP status code (`u16`) on error.
async fn stream_media_inner(
    app: &tauri::AppHandle,
    path: &str,
    range_header: Option<&str>,
) -> Result<RangeResponse, u16> {
    use tauri::Manager;
    // Path is "/media/<file_id_hex>" (leading slash). Extract + validate the id.
    let file_id_hex = path
        .strip_prefix("/media/")
        .map(str::to_string)
        .ok_or(404u16)?;
    let _ = hex16(&file_id_hex).map_err(|_| 404u16)?; // reject non-hex ids

    let dir = app.state::<AppDir>();
    let session = app.state::<Session>();
    let connect_lock = app.state::<ConnectLock>();
    let jobs = app.state::<VideoJobs>();

    // The session must already be open (open_video registered it).
    {
        let guard = jobs.0.lock().await;
        if !guard.contains_key(&file_id_hex) {
            return Err(404);
        }
    }

    // Parse "bytes=first-[last]" (default first=0 when absent).
    let (first, last_inclusive) = parse_byte_range(range_header);

    let server = server_of(&dir.0).map_err(|_| 500u16)?;
    let (mut sender, host, token) = reauth(&dir.0, &server, &session, &connect_lock)
        .await
        .map_err(|_| 500u16)?;
    serve_range(&mut sender, &host, &token, &jobs, &file_id_hex, first, last_inclusive)
        .await
        .map_err(|e| if e.code == "range_not_satisfiable" { 416 } else { 500 })
}

/// Parse an HTTP `Range: bytes=first-[last]` value into `(first, last_inclusive)`.
/// A missing/garbled header defaults to `(0, None)` (whole resource from the start,
/// capped by `MAX_RANGE_BODY` in `resolve_range`). Only a single range is honored.
fn parse_byte_range(h: Option<&str>) -> (u64, Option<u64>) {
    let Some(h) = h else { return (0, None) };
    let Some(spec) = h.trim().strip_prefix("bytes=") else { return (0, None) };
    let spec = spec.split(',').next().unwrap_or("").trim();
    let mut parts = spec.splitn(2, '-');
    let first = parts.next().and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0);
    let last = parts
        .next()
        .and_then(|s| { let s = s.trim(); if s.is_empty() { None } else { s.parse::<u64>().ok() } });
    (first, last)
}
```
Add `http` to `crates/client-app/Cargo.toml` dependencies if not already present (Tauri re-exports it, but depend on it directly for clarity):
Run: `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cargo add http -p maxsecu-client-app`

- [ ] **Step 4: Unit-test `parse_byte_range`**

Add to the `commands::video` tests module:
```rust
    #[test]
    fn parse_byte_range_forms() {
        assert_eq!(super::parse_byte_range(None), (0, None));
        assert_eq!(super::parse_byte_range(Some("bytes=0-")), (0, None));
        assert_eq!(super::parse_byte_range(Some("bytes=100-199")), (100, Some(199)));
        assert_eq!(super::parse_byte_range(Some("bytes=500-")), (500, None));
        assert_eq!(super::parse_byte_range(Some("garbage")), (0, None));
        // multi-range: only the first is honored
        assert_eq!(super::parse_byte_range(Some("bytes=0-99,200-299")), (0, Some(99)));
    }
```

- [ ] **Step 5: Build + run tests**

Run: `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cargo build -p maxsecu-client-app && cargo test -p maxsecu-client-app --lib`
Expected: PASS. Fix any borrow/import errors (e.g. the `VideoJob` destructure in `serve_range` may need `let job = &mut *job;` first — resolve with the compiler's guidance without changing behavior).

- [ ] **Step 6: Commit**

```bash
git add crates/client-app/src/commands/video.rs crates/client-app/src/main.rs crates/client-app/tauri.conf.json crates/client-app/Cargo.toml
git commit -m "feat(video): serve_range core + stream:// async protocol responder + media-src CSP"
```

---

## Task 6: End-to-end range streaming over real TLS

Prove the whole path — upload a video, open it, pull a sequence of ranges through `serve_range`, and assert the concatenated decrypted bytes equal the original content plaintext, with only ciphertext ever on disk. Reuse the existing video e2e harness.

**Files:**
- Modify: `crates/client-app/tests/video_e2e.rs` (add a range-streaming test)

- [ ] **Step 1: Read the existing harness**

Open `crates/client-app/tests/video_e2e.rs` and note how it boots the server over TLS, uploads a canonical video, and drives `open_video`. Reuse its setup helpers verbatim (server boot, upload, `AppDir`, session unlock).

- [ ] **Step 2: Write the failing e2e test**

Add a test that, after `open_video` has registered the session, calls `serve_range` directly (it is `async` and takes an authed `sender` — mint one via the same `reauth`/`server_of` the harness uses) for a walk of ranges covering the whole clip, concatenates the bodies, and compares to the known plaintext. If `serve_range` is private, add `#[cfg(test)] pub` visibility via a `pub(crate)` and a thin re-export, OR make `serve_range` `pub(crate)` and call it through a tiny `#[cfg(test)]` helper in the crate. Prefer marking `serve_range` and `RangeResponse` `pub(crate)` and adding a crate-level test shim:
```rust
// In the test: walk the clip in 64 KiB windows and reassemble.
let mut assembled = Vec::new();
let mut off = 0u64;
loop {
    let (mut sender, host, token) = reauth(&app_dir, &server, &session, &connect_lock).await.unwrap();
    let r = maxsecu_client_app::commands::video::serve_range(
        &mut sender, &host, &token, &jobs, &file_id_hex, off, Some(off + 64 * 1024 - 1),
    ).await.unwrap();
    assembled.extend_from_slice(&r.body);
    off += r.len;
    if off >= r.total_len { break; }
}
assert_eq!(assembled, original_content_plaintext);
```
(Expose `serve_range` as `pub(crate)` won't reach an integration test in `tests/`; integration tests only see the public API. So make `serve_range`, `RangeResponse`, and a `reauth`-based caller reachable: add a **public** thin command-free helper `pub async fn stream_range_for_test(...)` behind `#[cfg(any(test, feature = "test-hooks"))]`, or simpler — add the range-walk assertion as a `#[test]` INSIDE `crates/client-app/src/commands/video.rs` unit tests using an in-memory fake fetch instead of TLS, and keep the TLS e2e limited to `open_video` + one `stream_media`-shaped call via a public wrapper. Choose the smallest public surface: expose `pub async fn serve_range(...)` (drop the privacy) with a doc note that it is the protocol core.)

Decision for the implementer: **make `serve_range` and `RangeResponse` `pub`** (they carry no secrets across the seam — only sliced plaintext the protocol already exposes), so the integration test can call them. Document them as "the stream:// protocol core."

- [ ] **Step 3: Run the e2e (fail → pass)**

Run: `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cargo test -p maxsecu-client-app --test video_e2e`
Expected: PASS — reassembled bytes equal the plaintext; the fragment cache dir contains only `.frag` ciphertext (assert no plaintext marker appears on disk, mirroring `fragment_cache.rs`'s ciphertext-only test).

- [ ] **Step 4: Commit**

```bash
git add crates/client-app/tests/video_e2e.rs crates/client-app/src/commands/video.rs
git commit -m "test(video): e2e range streaming over real TLS reassembles the exact plaintext"
```

---

## Task 7: Add Media Chrome and bundle it locally

Media Chrome provides the overlaid controls (play/pause, scrubber + buffered bar, time, fullscreen, keyboard, auto-hide, gestures) for a real `<video>`. Bundle it into `ui/dist` via esbuild — no CDN, no CSP change.

**Files:**
- Modify: `crates/client-app/ui/package.json`

- [ ] **Step 1: Add the dependency**

Run (from `crates/client-app/ui`):
```bash
npm install media-chrome@^4
```
Expected: `media-chrome` added to `dependencies` and `node_modules`.

- [ ] **Step 2: Confirm esbuild bundles it (no runtime CDN)**

The `build` script already runs esbuild with `--bundle`, so a top-level `import 'media-chrome'` in a component will be inlined into `dist/main.js`. No script change needed. Verify by adding a temporary `import 'media-chrome';` to `src/main.ts`, then:
```bash
npm run build
```
Expected: `dist/main.js` grows and contains Media Chrome (grep `media-controller` in `dist/main.js`). Then REMOVE the temporary import (Task 8 adds the real one in the component).

- [ ] **Step 3: Commit**

```bash
git add crates/client-app/ui/package.json crates/client-app/ui/package-lock.json
git commit -m "build(ui): add media-chrome, bundled locally via esbuild"
```

---

## Task 8: New `<video>`-based player component wired to `stream://` + Media Chrome

Replace the canvas `<video-player>` with a real `<video>` inside a Media Chrome controller, pointed at `stream://media/<file_id>`. The component opens the session (invoke `open_video`), sets `src`, and closes the session (invoke `cancel_video`) on teardown.

**Files:**
- Rewrite: `crates/client-app/ui/src/components/video-player.ts`
- Modify: `crates/client-app/ui/src/components/media-viewer.ts` (mount the new component for videos)

- [ ] **Step 1: Rewrite the component**

Replace the contents of `crates/client-app/ui/src/components/video-player.ts` with a real-`<video>` implementation. Keep the same custom-element tag name and the same public attribute/property the viewer uses to pass the `file_id` (check `media-viewer.ts` for the current contract and preserve it). Skeleton:
```ts
import 'media-chrome';
import { invoke } from '@tauri-apps/api/core';

/// A native-<video> player: opens the decrypt-while-stream session in the backend,
/// points a real <video> at the stream:// range protocol, and lets the browser own
/// decode/seek/buffer/sync. Media Chrome supplies the overlaid controls.
export class VideoPlayer extends HTMLElement {
  private fileId = '';
  private videoEl!: HTMLVideoElement;
  private opened = false;

  static get observedAttributes() { return ['file-id']; }

  connectedCallback() {
    this.innerHTML = `
      <media-controller style="width:100%;aspect-ratio:16/9;background:#000">
        <video slot="media" playsinline preload="metadata"></video>
        <media-control-bar>
          <media-play-button></media-play-button>
          <media-time-range></media-time-range>
          <media-time-display showduration></media-time-display>
          <media-mute-button></media-mute-button>
          <media-volume-range></media-volume-range>
          <media-fullscreen-button></media-fullscreen-button>
        </media-control-bar>
      </media-controller>`;
    this.videoEl = this.querySelector('video')!;
    this.videoEl.addEventListener('error', () => this.dispatchEvent(new CustomEvent('player-error', { bubbles: true })));
    if (this.fileId) void this.open();
  }

  attributeChangedCallback(name: string, _old: string, val: string) {
    if (name === 'file-id') { this.fileId = val ?? ''; if (this.isConnected && this.fileId) void this.open(); }
  }

  private async open() {
    if (this.opened) return;
    this.opened = true;
    try {
      await invoke('open_video', { fileId: this.fileId });
      // stream://media/<id> — Tauri maps this to the registered async protocol.
      this.videoEl.src = `stream://media/${this.fileId}`;
    } catch (e) {
      this.dispatchEvent(new CustomEvent('player-error', { bubbles: true, detail: e }));
    }
  }

  disconnectedCallback() {
    this.videoEl?.removeAttribute('src');
    if (this.opened && this.fileId) void invoke('cancel_video', { fileId: this.fileId }).catch(() => {});
    this.opened = false;
  }
}

customElements.define('video-player', VideoPlayer);
```
Adjust the tag name / attribute name to match the existing contract exactly (do NOT rename the element if `media-viewer.ts` references `video-player`). Confirm the `open_video`/`cancel_video` argument key casing matches Tauri's expectation (Tauri converts `file_id` ↔ `fileId`; the existing UI already invokes these — copy its exact call shape from the current `video-player.ts` before deleting it).

- [ ] **Step 2: Point `media-viewer.ts` at the new component for videos**

In `crates/client-app/ui/src/components/media-viewer.ts`, ensure the video branch renders `<video-player file-id="...">` (or sets the property the component reads). Remove any wiring to the old frame/PlayerPhase events (`maxsecu://video-frame`, `maxsecu://player-state`, etc.) from the viewer — the native element handles playback state now. Leave image/blog branches untouched.

- [ ] **Step 3: Typecheck + build**

Run (from `crates/client-app/ui`):
```bash
npm run typecheck && npm run build
```
Expected: no type errors; `dist/main.js` rebuilt with Media Chrome + the new component.

- [ ] **Step 4: Commit**

```bash
git add crates/client-app/ui/src/components/video-player.ts crates/client-app/ui/src/components/media-viewer.ts
git commit -m "feat(ui): native <video> player over stream:// wrapped in Media Chrome"
```

---

## Task 9: Frontend unit test for the new component's contract

Cover the non-DOM logic: the `src` URL is built from the file id, and open/close invoke the right commands. Use `node:test` with a stubbed `invoke` (the repo already tests components this way via injected fakes — mirror `viewer-open.test.ts`).

**Files:**
- Create: `crates/client-app/ui/src/components/video-player.test.ts`
- Modify: `crates/client-app/ui/package.json` (add the file to the `test` script)

- [ ] **Step 1: Factor the pure bit if needed**

If the component embeds the URL inline, export a tiny pure helper so it is testable without a DOM:
```ts
export function streamSrc(fileId: string): string {
  return `stream://media/${fileId}`;
}
```
Use `streamSrc(this.fileId)` in the component.

- [ ] **Step 2: Write the test**

`crates/client-app/ui/src/components/video-player.test.ts`:
```ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { streamSrc } from './video-player.ts';

test('streamSrc builds the protocol URL from the file id', () => {
  assert.equal(streamSrc('abc123'), 'stream://media/abc123');
});
```
(If importing the component module pulls in `media-chrome`/`@tauri-apps` and breaks under `node:test`, keep `streamSrc` in a tiny sibling module `video-src.ts` with NO side-effect imports, import it from both the component and the test.)

- [ ] **Step 3: Wire it into the test script**

In `crates/client-app/ui/package.json`, append the new test file to the `test` script's file list.

- [ ] **Step 4: Run**

Run (from `crates/client-app/ui`): `npm test`
Expected: PASS (existing tests + the new one). Note: `player.test.ts` and `webgl-yuv.test.ts` are removed in Task 11 — until then they still run and should still pass.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/ui/src/components/video-player.test.ts crates/client-app/ui/src/components/video-src.ts crates/client-app/ui/package.json
git commit -m "test(ui): stream:// src URL contract for the native video player"
```

---

## Task 10: GUI smoke (manual — controller + user)

Build the release exe, stage it, and confirm real playback in the packaged client.

**Files:** none (build + manual verification)

- [ ] **Step 1: Build UI + exe**

Run:
```bash
export PATH="$HOME/.cargo/bin:$PATH"
( cd crates/client-app/ui && npm run build )
cargo build --release -p maxsecu-client-app
```
Expected: clean build; `dist/main.js` current.

- [ ] **Step 2: Stage the exe to both dist dirs (client must be closed)**

Copy the freshly built `maxsecu-client-app.exe` (release) to BOTH `dist\MaxSecuClient-root` and `dist\MaxSecuClient-bob`, keeping the confined `media-transcode-worker.exe` beside it. (The running client locks its copy — close it first.)

- [ ] **Step 3: Hand off to the user for the smoke test**

Ask the user to relaunch and play both clips:
- `D:\Images\00168.mp4` (short)
- `D:\Images\Car crash call #skit #funny #comedy.mp4` (59 s)

Confirm, for each: press-Play-to-start, smooth playback WITH sound (no freeze/rollback/desync), Pause stops both audio+video, the timer advances and shows the right duration, the scrubber seeks and re-watches, and the 59 s clip streams without hanging. If the console shows a CSP `media-src` block, add the exact blocked origin to `tauri.conf.json` (Task 5 Step 2 note) and rebuild.

- [ ] **Step 4: Record the outcome**

On success, commit an empty marker or proceed to Task 11. On failure, invoke `superpowers:systematic-debugging` before continuing (likely suspects: the `stream://` host form / CSP, the Range parsing, or `serve_range` bounds).

---

## Task 11: Remove the hand-rolled engine + decode-worker view path (cleanup)

Only after Tasks 6 and 10 are green. Delete the now-dead playback machinery so the codebase has ONE video path.

**Files:**
- Delete: `crates/client-app/ui/src/core/player.ts`, `crates/client-app/ui/src/core/player.test.ts`, `crates/client-app/ui/src/core/webgl-yuv.ts`, `crates/client-app/ui/src/core/webgl-yuv.test.ts`
- Modify: `crates/client-app/ui/package.json` (drop the deleted tests from the `test` script)
- Modify: `crates/client-app/src/commands/video.rs` (remove `video_seek`, `video_set_volume`, `play_window_command`, `decrypt_window`, `decode_and_emit`, `window_offset_ms`, `push_bounded`, frame/PCM DTOs, and the preview decode commands `preview_video`/`preview_seek` if the author preview also moves to native — see Step 4)
- Modify: `crates/client-app/src/state.rs` (remove `EVT_VIDEO_FRAME/AUDIO/PLAYER/INFO`, `PlayerPhase`, `VideoInfo`, and their tests)
- Modify: `crates/client-app/src/main.rs` (drop the removed commands from `generate_handler!`)
- Modify: `crates/client-app/src/jobs.rs` (drop `VideoJob.gain`)

- [ ] **Step 1: Decide the author-preview path**

The author's preview-before-upload (`preview_video`) also uses the confined decode + canvas. It can switch to the SAME native `<video>` by serving the STAGED plaintext through a second protocol path (`stream://preview/<job_id>` backed by `UploadJobs`' `StagedVideoPreview.cmaf`, sliced by byte range with NO decrypt). **If time-boxed, keep `preview_video` as-is in this task and file a follow-up** — do not block the download-path cleanup on it. Record the decision in the commit message.

- [ ] **Step 2: Remove the frontend engine**

Delete `player.ts`, `player.test.ts`, `webgl-yuv.ts`, `webgl-yuv.test.ts`. Remove any imports of them (grep the UI for `core/player`, `core/webgl-yuv`). Update the `test` script in `package.json` to drop `player.test.ts` and `webgl-yuv.test.ts`.

- [ ] **Step 3: Remove the backend decode commands + events**

In `commands/video.rs`, delete `video_seek`, `video_set_volume`, `cancel_video`'s player-event emit (keep `cancel_video` itself but simplify it to just drop the job — rename intent to "close session"), `play_window_command`, `decrypt_window`, `decode_and_emit`, `window_offset_ms`, `push_bounded`, `frame_dto`, `pcm_dto`, `I420FrameDto`, `PcmDto`, `ScriptGuard`, `make_decoder`/`SessionDecoder`/`worker_path`, and their tests. In `state.rs`, delete `EVT_VIDEO_FRAME/AUDIO/PLAYER/INFO`, `PlayerPhase`, `VideoInfo` + tests. In `main.rs`, remove `video_seek`, `video_set_volume`, `preview_seek` (if preview went native), and any handler entries for deleted commands. Drop `VideoJob.gain` and its uses.

- [ ] **Step 4: Build + full test sweep**

Run:
```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo test -p maxsecu-client-app
( cd crates/client-app/ui && npm run typecheck && npm test && npm run test:a11y )
```
Expected: all green. Resolve dead-code warnings by deletion, not `#[allow]`.

- [ ] **Step 5: Rebuild + re-stage + quick re-smoke**

Rebuild the exe (Task 10 Steps 1–2) and confirm a video still plays (no regression from the deletions).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor(video): remove hand-rolled canvas engine + decode-worker view path (native <video> is the one path)"
```

---

## Task 12: Security review doc (reversal sign-off)

Record the Phase-7 reversal for the view path honestly, with the residual-risk narrowing and mitigations.

**Files:**
- Create: `docs/security-review-native-video-mediaapp.md`

- [ ] **Step 1: Write the review**

Cover: (1) what changed — native WebView2 codecs (fMP4 demux, AV1, AAC) now decode in the WebView, which holds Tauri IPC; the confined `media-worker` decode path is retired for viewing. (2) The residual surface — a codec/demux bug reachable from decoded bytes is RCE in the key-holding WebView. (3) The narrowings — content is AEAD-authenticated + manifest-bound + produced by a D5-verified author's own confined transcoder (not arbitrary internet video), so the threat is a malicious/compromised *verified author* crafting an adversarial-but-valid bitstream; CSP is locked to no remote content; WebView2 is auto-updating + sandboxed; the content key never leaves the Rust process; per-range plaintext is bounded + `Zeroizing`. (4) What was verified — Task 0 (codec support), Task 6 (bytes equal plaintext, ciphertext-only on disk), Task 10 (real playback). (5) Explicit residual/accepted risk + any follow-ups (author-preview native migration if deferred; per-range reauth cost). Mirror the structure of `docs/security-review-phase7-mediaapp.md`.

- [ ] **Step 2: Self-review the doc**

Confirm no claim overstates the security (this is a REDUCTION of the Phase-7 posture for the view path — say so plainly). No "PASS" theater; state the accepted risk.

- [ ] **Step 3: Commit**

```bash
git add docs/security-review-native-video-mediaapp.md
git commit -m "docs(security): native-video view-path reversal sign-off (residual-risk narrowing + mitigations)"
```

---

## Self-Review (controller)

**Spec coverage:**
- `stream://` protocol + Range → Tasks 2,3,5. ✓
- Per-range streaming (plan/prefetch/assemble, cache-or-fetch) → Tasks 3,5. ✓
- Byte↔chunk mapping + total length → Tasks 2,4. ✓
- Open-video session registry (register-only) → Task 4. ✓
- Real `<video>` + Media Chrome → Tasks 7,8. ✓
- CSP / registration → Task 5. ✓
- Error handling (404/416/500, fail-closed) → Tasks 3,5. ✓
- Verify-first codec gate → Task 0. ✓
- Unit/integration/e2e/smoke tests → Tasks 2,3,6,9,10. ✓
- Removal of the old engine → Task 11. ✓
- Security-review doc → Task 12. ✓

**Placeholder scan:** No "TBD"/"handle edge cases"/"similar to". Author-preview migration in Task 11 is an explicit, bounded decision, not a placeholder. ✓

**Type consistency:** `RangeReq`/`RangePlan`/`RangeResponse` defined in Task 2/5 and used consistently; `resolve_range`/`plan_range`/`slice_range`/`assemble_range`/`total_len` signatures match across tasks; `VideoJob` gains `chunk_size`/`total_len` (Task 4) used by `serve_range` (Task 5). ✓

**Known risk carried forward:** the exact `stream://` host origin on WebView2/Windows is pinned empirically in Task 0/Task 10 (CSP note in Task 5). Per-range `reauth` cost is acceptable for v1 (noted for later optimization).
