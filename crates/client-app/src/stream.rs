//! Byte-range video streaming core (native-<video> player). Maps a requested
//! plaintext byte range to the covering CMAF fragments, reuses the fragment
//! feeder to materialize their plaintext, and slices out the exact range. No
//! Tauri, no network here — the command layer prefetches ciphertext between the
//! two sync halves (`plan_range` then `assemble_range`), mirroring the
//! decrypt-while-play discipline: only ciphertext is cached, plaintext is
//! bounded + zeroized, the decryptor never crosses the seam.

use crate::error::UiError;
use crate::fragment_cache::FragmentCache;
use crate::video::FragmentEntry;
use maxsecu_client_core::ContentDecryptor;

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
    use maxsecu_client_core::{
        build_upload, open_content_decryptor, Identity, PlaintextStreams, StreamChunks,
        StreamHeader, UploadBundle, UploadParams, VerifyContext, NO_ADMINS, NO_GRANTERS,
    };
    use maxsecu_crypto::generate_enc_keypair;
    use maxsecu_encoding::encode;
    use maxsecu_encoding::types::{FileType, Id, RecipientType, StreamType, Timestamp};

    const OWNER_ID: Id = Id([0x11; 16]);
    const FILE_ID: Id = Id([0xF1; 16]);
    const NOW: Timestamp = Timestamp(1_719_500_000_000);

    fn tmp_cache(tag: &str) -> FragmentCache {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir()
            .join(format!("mxstream-{tag}-{}-{nanos}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        FragmentCache::open(&dir, 1 << 20).unwrap()
    }

    /// Build a 6-chunk video-shaped upload; return (owner, header, ciphertext
    /// content chunks, the whole content plaintext, chunk_size as u64).
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
        let content: Vec<u8> = (0..(4096 * 5 + 123)).map(|i| (i % 251) as u8).collect();
        let streams = PlaintextStreams {
            content: content.clone(),
            metadata: Some(b"title=clip".to_vec()),
            thumbnail: None,
            preview: None,
        };
        let b: UploadBundle = build_upload(&params, &streams).unwrap();
        let sw = b
            .wraps
            .iter()
            .find(|w| w.recipient_type == RecipientType::User)
            .unwrap();
        let rw = b
            .wraps
            .iter()
            .find(|w| w.recipient_type == RecipientType::Recovery)
            .unwrap();
        let content_s = b
            .streams
            .iter()
            .find(|s| s.stream_type == StreamType::Content)
            .unwrap();
        let small = b
            .streams
            .iter()
            .filter(|s| s.stream_type != StreamType::Content)
            .map(|s| StreamChunks {
                stream_type: s.stream_type,
                chunks: s.chunks.clone(),
            })
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
}
