//! Sandboxed-video client orchestration (Phase 7, Gate 4): the **fragment index**
//! (seek map) + the **decrypt-while-play feeder** that drives one CMAF fragment at
//! a time from the ciphertext [`BlobCache`](crate::blob_cache) and
//! the in-TCB [`ContentDecryptor`](maxsecu_client_core::ContentDecryptor) to a
//! decoder sink.
//!
//! # Security model (the dedicated review checks these)
//! * **Only ciphertext is cached.** The blob handed to [`BlobCache::put`] is
//!   the *length-prefixed framing of the fetched ciphertext chunks* — never the
//!   decrypted plaintext. The decrypt happens AFTER the cache write, into a
//!   `Zeroizing` buffer that never touches the cache or disk.
//! * **Plaintext is bounded + discarded.** Exactly one fragment's plaintext is
//!   live at a time. It is handed to the `sink` by reference and dropped (zeroized)
//!   at the end of [`feed_fragment`]; it is never returned across any seam, never
//!   cached, never logged.
//! * **The `ContentDecryptor` stays in the TCB.** [`feed_fragment`] only *borrows*
//!   it. It is non-`Clone`, holds the content subkey, and never crosses the Tauri
//!   boundary (Task 4.3 wires the sink to the sandboxed `media-worker`; this layer
//!   is decoder-agnostic).
//! * **Fail-closed.** Unknown/out-of-range fragment, a fetch error, a corrupt
//!   cache blob, or an AEAD decrypt failure all yield a sanitized [`UiError`] with
//!   no panic and no partial-plaintext leak.
//!
//! The fragment index itself arrives inside the **authenticated** `metadata`
//! stream (AEAD-opened + manifest-bound by `verify_and_open_headers`), so a
//! malicious server cannot steer the player to an attacker-chosen chunk range.
//! It is nonetheless re-validated here (contiguity / ordering / coverage) as
//! defense in depth.

use serde_json::Value;

use maxsecu_client_core::ContentDecryptor;

use crate::blob_cache::{BlobCache, Ns};
use crate::error::UiError;

/// One CMAF fragment's seek + storage mapping: presentation time `pts_ms` and the
/// half-open absolute `content`-chunk range `[chunk_start, chunk_start + chunk_len)`
/// it occupies. Parsed (and validated) out of the authenticated `metadata` stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentEntry {
    pub seq: u32,
    pub pts_ms: u64,
    pub chunk_start: u64,
    pub chunk_len: u64,
}

/// A sanitized fragment-layer error (no internal detail crosses the seam).
fn video_err() -> UiError {
    UiError::new("video_failed", "The video could not be played.")
}

/// Parse + **validate** the `"fragments"` array out of the (authenticated)
/// `metadata` JSON into an ordered [`FragmentEntry`] list.
///
/// Validation (fail-closed; any violation ⇒ [`UiError`]):
/// * the array is present and non-empty;
/// * `seq` is `0..N` contiguous (entry `k` has `seq == k`) — strictly ordered and
///   unique;
/// * `pts_ms` is non-decreasing;
/// * every `chunk_len >= 1`;
/// * the ranges are **contiguous and non-overlapping starting at 0**
///   (`entry[0].chunk_start == 0` and `entry[k].chunk_start == entry[k-1].chunk_start
///   + entry[k-1].chunk_len`), so the whole `content` is covered exactly once.
///
/// The index is authenticated upstream, but a malformed/overlapping/out-of-order
/// index is still rejected here (defense in depth) before it can drive a fetch.
pub fn parse_fragment_index(metadata_json: &Value) -> Result<Vec<FragmentEntry>, UiError> {
    let arr = metadata_json
        .get("fragments")
        .and_then(Value::as_array)
        .ok_or_else(video_err)?;
    if arr.is_empty() {
        return Err(video_err());
    }

    let mut out: Vec<FragmentEntry> = Vec::with_capacity(arr.len());
    let mut expected_start: u64 = 0;
    let mut last_pts: u64 = 0;
    for (k, item) in arr.iter().enumerate() {
        let seq = item
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or_else(video_err)?;
        let pts_ms = item
            .get("pts_ms")
            .and_then(Value::as_u64)
            .ok_or_else(video_err)?;
        let chunk_start = item
            .get("chunk_start")
            .and_then(Value::as_u64)
            .ok_or_else(video_err)?;
        let chunk_len = item
            .get("chunk_len")
            .and_then(Value::as_u64)
            .ok_or_else(video_err)?;

        // seq is 0..N contiguous (so it equals the slot index and fits a u32).
        if seq != k as u64 {
            return Err(video_err());
        }
        // pts non-decreasing.
        if pts_ms < last_pts {
            return Err(video_err());
        }
        // each fragment covers at least one chunk.
        if chunk_len < 1 {
            return Err(video_err());
        }
        // contiguous, non-overlapping, starting at 0 (covers content exactly once).
        if chunk_start != expected_start {
            return Err(video_err());
        }
        // advance the running end with no overflow.
        expected_start = chunk_start.checked_add(chunk_len).ok_or_else(video_err)?;
        last_pts = pts_ms;

        out.push(FragmentEntry {
            seq: seq as u32,
            pts_ms,
            chunk_start,
            chunk_len,
        });
    }
    Ok(out)
}

/// Map a presentation time to the `seq` of the fragment whose
/// `[pts_ms, next.pts_ms)` window contains it; the last fragment covers to
/// infinity. Returns `None` for an empty index or a time before the first
/// fragment's `pts_ms`.
pub fn fragment_for_time(index: &[FragmentEntry], pts_ms: u64) -> Option<u32> {
    let mut hit: Option<u32> = None;
    for e in index {
        if e.pts_ms <= pts_ms {
            // The latest fragment whose window has opened by `pts_ms` wins; the
            // next iteration overrides it iff its window has also opened.
            hit = Some(e.seq);
        } else {
            break;
        }
    }
    hit
}

/// The absolute `content`-chunk range `(chunk_start, chunk_len)` for `seq`, or
/// `None` if no fragment carries that `seq`.
pub fn chunks_for_fragment(index: &[FragmentEntry], seq: u32) -> Option<(u64, u64)> {
    index
        .iter()
        .find(|e| e.seq == seq)
        .map(|e| (e.chunk_start, e.chunk_len))
}

/// Decrypt ONE fragment and hand its plaintext to `sink`, sourcing the fragment's
/// **ciphertext** chunks from the cache (hit ⇒ no network) or the injected
/// `fetch_chunk` (miss ⇒ per-chunk GET), caching the fetched ciphertext.
///
/// * `fetch_chunk(i)` returns the opaque ciphertext for ABSOLUTE `content` chunk
///   index `i`. Injected so the real command supplies a network GET and tests can
///   assert it is called on a miss and NOT on a hit.
/// * `sink(&plaintext)` consumes the decoded canonical-fragment plaintext exactly
///   once. The range-serving path (`stream::assemble_range`) appends it into the
///   buffer returned over `stream://` for the native `<video>` element to play;
///   here it is decoder-agnostic.
///
/// The decrypted plaintext is a `Zeroizing` buffer that is dropped (wiped) when
/// this function returns — it is never cached, returned, or logged. The cache
/// only ever stores the **serialized ciphertext** (`frame_chunks`). Fail-closed
/// throughout: an unknown/out-of-range `seq`, a corrupt cached blob, a fetch
/// error, or an AEAD failure all return an `Err` with no plaintext released.
pub fn feed_fragment<F, S>(
    index: &[FragmentEntry],
    cache: &mut BlobCache,
    ns: Ns,
    decryptor: &ContentDecryptor,
    file_id_hex: &str,
    seq: u32,
    mut fetch_chunk: F,
    mut sink: S,
) -> Result<(), UiError>
where
    F: FnMut(u64) -> Result<Vec<u8>, UiError>,
    S: FnMut(&[u8]) -> Result<(), UiError>,
{
    let (chunk_start, chunk_len) = chunks_for_fragment(index, seq).ok_or_else(video_err)?;

    // Bound the range against the SIGNED content_chunk_count before any fetch, so a
    // bogus index cannot drive an unbounded fetch loop (open_range re-checks too).
    let end = chunk_start
        .checked_add(chunk_len)
        .filter(|e| *e <= decryptor.content_chunk_count())
        .ok_or_else(video_err)?;

    // Cache hit: re-read the stored CIPHERTEXT framing. A corrupt blob, or one
    // whose chunk count does not match this fragment, is treated as a miss
    // (fail-closed) — never a panic.
    let cached: Option<Vec<Vec<u8>>> = cache
        .get(ns, file_id_hex, seq)
        .and_then(|blob| deframe_chunks(&blob))
        .filter(|chunks| chunks.len() as u64 == chunk_len);

    let chunks: Vec<Vec<u8>> = match cached {
        Some(chunks) => chunks,
        None => {
            // Miss: fetch each ciphertext chunk by ABSOLUTE index, then cache the
            // serialized CIPHERTEXT (best-effort; the in-memory chunks are still
            // used even if the cache write fails).
            let mut chunks: Vec<Vec<u8>> = Vec::with_capacity(chunk_len as usize);
            for i in chunk_start..end {
                chunks.push(fetch_chunk(i)?);
            }
            let blob = frame_chunks(&chunks);
            let _ = cache.put(ns, file_id_hex, seq, &blob);
            chunks
        }
    };

    // TCB decrypt: AEAD-open the contiguous range bound to its absolute indices.
    // The plaintext is held only here, in a Zeroizing buffer.
    let plaintext = decryptor
        .open_range(chunk_start, &chunks)
        .map_err(|_| video_err())?;

    // Hand it to the decoder sink, then drop (zeroize) it on return. It is never
    // cached, returned, or logged.
    sink(&plaintext)?;
    Ok(())
}

/// Length-prefixed framing of a fragment's **ciphertext** chunks for the cache
/// blob: `u32 count` (LE) then, per chunk, `u32 len` (LE) `+ bytes`. The bytes are
/// the opaque fetched ciphertext — never plaintext.
fn frame_chunks(chunks: &[Vec<u8>]) -> Vec<u8> {
    let total: usize = 4 + chunks.iter().map(|c| 4 + c.len()).sum::<usize>();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(chunks.len() as u32).to_le_bytes());
    for c in chunks {
        out.extend_from_slice(&(c.len() as u32).to_le_bytes());
        out.extend_from_slice(c);
    }
    out
}

/// Inverse of [`frame_chunks`], bounds-safe: a truncated, over-long, or
/// trailing-garbage blob yields `None` (the caller treats it as a cache miss).
/// Never panics, and the capacity reservation is bounded by the blob length: an
/// impossible `count` is rejected up front, so a tampered blob cannot drive an
/// allocation larger than the structurally possible number of chunks.
fn deframe_chunks(blob: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut pos = 0usize;
    let count = read_u32(blob, &mut pos)? as usize;
    // Each chunk costs at least its own 4-byte length header on the wire, so the
    // true maximum possible count is `(blob.len() - 4) / 4` (the count prefix
    // itself consumes the first 4 bytes). Reject anything above that BEFORE the
    // `with_capacity` reservation, so a tampered blob cannot amplify the
    // allocation past the bytes actually present.
    let max_count = (blob.len().saturating_sub(4)) / 4;
    if count > max_count {
        return None;
    }
    let mut chunks: Vec<Vec<u8>> = Vec::with_capacity(count);
    for _ in 0..count {
        let len = read_u32(blob, &mut pos)? as usize;
        let next = pos.checked_add(len)?;
        if next > blob.len() {
            return None;
        }
        chunks.push(blob[pos..next].to_vec());
        pos = next;
    }
    // Reject trailing garbage (the blob must deframe exactly).
    if pos != blob.len() {
        return None;
    }
    Some(chunks)
}

/// Read a little-endian `u32` at `*pos`, advancing it; `None` if out of bounds.
fn read_u32(blob: &[u8], pos: &mut usize) -> Option<u32> {
    let next = pos.checked_add(4)?;
    let bytes: [u8; 4] = blob.get(*pos..next)?.try_into().ok()?;
    *pos = next;
    Some(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

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

    fn file_id_hex() -> String {
        FILE_ID.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("mxvid-{tag}-{}-{nanos}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    // ---- fragment-index parse / mapping ----

    fn frag(seq: u32, pts_ms: u64, chunk_start: u64, chunk_len: u64) -> serde_json::Value {
        serde_json::json!({
            "seq": seq, "pts_ms": pts_ms, "chunk_start": chunk_start, "chunk_len": chunk_len
        })
    }

    fn meta(frags: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({ "title": "v", "tags": [], "fragments": frags })
    }

    #[test]
    fn parses_a_well_formed_index() {
        let j = meta(vec![
            frag(0, 0, 0, 2),
            frag(1, 1000, 2, 3),
            frag(2, 2000, 5, 1),
        ]);
        let idx = parse_fragment_index(&j).unwrap();
        assert_eq!(idx.len(), 3);
        assert_eq!(
            idx[1],
            FragmentEntry {
                seq: 1,
                pts_ms: 1000,
                chunk_start: 2,
                chunk_len: 3
            }
        );
    }

    #[test]
    fn rejects_missing_or_empty_fragments() {
        assert!(parse_fragment_index(&serde_json::json!({ "title": "v" })).is_err());
        assert!(parse_fragment_index(&meta(vec![])).is_err());
    }

    #[test]
    fn rejects_non_contiguous_seq() {
        let j = meta(vec![frag(0, 0, 0, 1), frag(2, 1000, 1, 1)]); // seq jumps 0 -> 2
        assert!(parse_fragment_index(&j).is_err());
    }

    #[test]
    fn rejects_decreasing_pts() {
        let j = meta(vec![frag(0, 5000, 0, 1), frag(1, 1000, 1, 1)]);
        assert!(parse_fragment_index(&j).is_err());
    }

    #[test]
    fn rejects_zero_chunk_len() {
        let j = meta(vec![frag(0, 0, 0, 0)]);
        assert!(parse_fragment_index(&j).is_err());
    }

    #[test]
    fn rejects_overlapping_or_gapped_ranges() {
        // overlap: second starts at 1 but first covered [0,2)
        assert!(parse_fragment_index(&meta(vec![frag(0, 0, 0, 2), frag(1, 1, 1, 2)])).is_err());
        // gap: second starts at 3 but first covered [0,2)
        assert!(parse_fragment_index(&meta(vec![frag(0, 0, 0, 2), frag(1, 1, 3, 1)])).is_err());
        // does not start at 0
        assert!(parse_fragment_index(&meta(vec![frag(0, 0, 1, 1)])).is_err());
    }

    #[test]
    fn fragment_for_time_windows() {
        let idx = parse_fragment_index(&meta(vec![
            frag(0, 0, 0, 1),
            frag(1, 1000, 1, 1),
            frag(2, 2000, 2, 1),
        ]))
        .unwrap();
        assert_eq!(fragment_for_time(&idx, 0), Some(0));
        assert_eq!(fragment_for_time(&idx, 999), Some(0));
        assert_eq!(fragment_for_time(&idx, 1000), Some(1));
        assert_eq!(fragment_for_time(&idx, 1500), Some(1));
        assert_eq!(fragment_for_time(&idx, 2000), Some(2));
        assert_eq!(fragment_for_time(&idx, u64::MAX), Some(2)); // last covers to infinity
        assert_eq!(fragment_for_time(&[], 10), None); // empty index
    }

    #[test]
    fn fragment_for_time_before_first_is_none() {
        let idx = vec![FragmentEntry {
            seq: 0,
            pts_ms: 500,
            chunk_start: 0,
            chunk_len: 1,
        }];
        assert_eq!(fragment_for_time(&idx, 100), None);
        assert_eq!(fragment_for_time(&idx, 500), Some(0));
    }

    #[test]
    fn chunks_for_fragment_lookup() {
        let idx = parse_fragment_index(&meta(vec![frag(0, 0, 0, 2), frag(1, 1, 2, 3)])).unwrap();
        assert_eq!(chunks_for_fragment(&idx, 0), Some((0, 2)));
        assert_eq!(chunks_for_fragment(&idx, 1), Some((2, 3)));
        assert_eq!(chunks_for_fragment(&idx, 7), None);
    }

    // ---- framing round-trip ----

    #[test]
    fn framing_round_trips_and_rejects_corruption() {
        let chunks = vec![b"\x00\x01".to_vec(), b"".to_vec(), b"\xff\xfe\xfd".to_vec()];
        let blob = frame_chunks(&chunks);
        assert_eq!(deframe_chunks(&blob).unwrap(), chunks);
        // Truncated header.
        assert_eq!(deframe_chunks(&blob[..2]), None);
        // Trailing garbage.
        let mut extra = blob.clone();
        extra.push(0x00);
        assert_eq!(deframe_chunks(&extra), None);
        // Over-long declared length.
        let mut bad = Vec::new();
        bad.extend_from_slice(&1u32.to_le_bytes()); // count = 1
        bad.extend_from_slice(&99u32.to_le_bytes()); // len = 99 (but no bytes follow)
        assert_eq!(deframe_chunks(&bad), None);
        // Absurd count is rejected without huge allocation.
        let mut huge = Vec::new();
        huge.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(deframe_chunks(&huge), None);
        // An impossible-but-modest count (more chunks than 4-byte headers could
        // fit in the remaining bytes) is rejected up front by the capacity guard,
        // before any large reservation: a 12-byte blob can hold at most
        // (12 - 4) / 4 = 2 chunk headers, so count = 1000 must be rejected.
        let mut impossible = Vec::new();
        impossible.extend_from_slice(&1000u32.to_le_bytes()); // count = 1000
        impossible.extend_from_slice(&[0u8; 8]); // only room for <=2 headers
        assert_eq!(deframe_chunks(&impossible), None);
    }

    // ---- the feeder over a REAL ContentDecryptor + REAL BlobCache ----

    /// Build a multi-chunk video-shaped upload, returning the bundle + the whole
    /// content plaintext (content spans several 4 KiB chunks).
    fn build_large() -> (Identity, UploadBundle, Vec<u8>) {
        let owner = Identity::generate();
        let (_recovery_sk, recovery_pk) = generate_enc_keypair();
        let params = UploadParams {
            owner: &owner,
            owner_id: OWNER_ID,
            owner_key_version: 1,
            file_id: FILE_ID,
            file_type: FileType::Video,
            chunk_size: 4096,
            recovery_pub: recovery_pk,
            recovery_mlkem_pub: None,
            created_at: NOW,
        };
        let content: Vec<u8> = (0..(4096 * 4 + 100)).map(|i| (i % 251) as u8).collect();
        let streams = PlaintextStreams {
            content: content.clone(),
            metadata: Some(b"title=clip".to_vec()),
            thumbnail: None,
            preview: None,
        };
        let bundle = build_upload(&params, &streams).unwrap();
        (owner, bundle, content)
    }

    /// Split a bundle into a StreamHeader (small streams) + the content ciphertext
    /// chunks fetched lazily by the test.
    fn split(b: &UploadBundle) -> (StreamHeader, Vec<Vec<u8>>) {
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
        let content = b
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
        (header, content.chunks.clone())
    }

    fn ctx<'a>(owner: &'a Identity) -> VerifyContext<'a> {
        let pk = owner.sig_pub_bytes();
        VerifyContext {
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
        }
    }

    /// Build a two-fragment index over the staged content: [0,2) then [2,N).
    fn two_fragment_index(n_chunks: u64) -> Vec<FragmentEntry> {
        parse_fragment_index(&meta(vec![
            frag(0, 0, 0, 2),
            frag(1, 1000, 2, n_chunks - 2),
        ]))
        .unwrap()
    }

    #[test]
    fn feeder_fetches_on_miss_caches_ciphertext_then_serves_from_cache_on_hit() {
        let (owner, bundle, content) = build_large();
        let (header, chunks) = split(&bundle);
        assert!(chunks.len() >= 4);
        let dec = open_content_decryptor(&ctx(&owner), &header).expect("decryptor");
        let index = two_fragment_index(chunks.len() as u64);
        let id_hex = file_id_hex();

        let dir = tmp_dir("feed");
        let mut cache = BlobCache::open(&dir, 1 << 20).unwrap();

        // Fragment 0 = content chunks [0,2) = plaintext bytes [0, 2*4096).
        let mut fetch_calls = 0u32;
        let mut got: Vec<u8> = Vec::new();
        feed_fragment(
            &index,
            &mut cache,
            Ns::Frag,
            &dec,
            &id_hex,
            0,
            |i| {
                fetch_calls += 1;
                Ok(chunks[i as usize].clone())
            },
            |pt| {
                got.extend_from_slice(pt);
                Ok(())
            },
        )
        .expect("miss feeds");
        assert_eq!(fetch_calls, 2, "miss fetched both chunks of fragment 0");
        assert_eq!(got, content[0..2 * 4096], "decoded plaintext matches");

        // The cache now holds CIPHERTEXT, not the plaintext we just decoded.
        let blob = cache.get(Ns::Frag, &id_hex, 0).expect("cached after miss");
        assert_ne!(blob, got, "cache blob is not the decoded plaintext");
        assert!(
            !blob.windows(got.len()).any(|w| w == got.as_slice()),
            "the decoded plaintext does not appear in the cached ciphertext blob"
        );
        // And it deframes back to exactly the fetched ciphertext chunks.
        assert_eq!(deframe_chunks(&blob).unwrap(), chunks[0..2].to_vec());

        // Second feed of the SAME fragment is a cache hit: the fetcher is NOT called.
        let mut fetch_calls2 = 0u32;
        let mut got2: Vec<u8> = Vec::new();
        feed_fragment(
            &index,
            &mut cache,
            Ns::Frag,
            &dec,
            &id_hex,
            0,
            |_i| {
                fetch_calls2 += 1;
                Ok(Vec::new())
            },
            |pt| {
                got2.extend_from_slice(pt);
                Ok(())
            },
        )
        .expect("hit feeds");
        assert_eq!(fetch_calls2, 0, "cache hit performed NO fetch");
        assert_eq!(got2, got, "cache hit decrypts to the same plaintext");
    }

    #[test]
    fn feeder_reconstructs_whole_content_across_fragments() {
        let (owner, bundle, content) = build_large();
        let (header, chunks) = split(&bundle);
        let dec = open_content_decryptor(&ctx(&owner), &header).expect("decryptor");
        let index = two_fragment_index(chunks.len() as u64);
        let id_hex = file_id_hex();
        let dir = tmp_dir("whole");
        let mut cache = BlobCache::open(&dir, 1 << 20).unwrap();

        let mut joined: Vec<u8> = Vec::new();
        for seq in 0..2u32 {
            feed_fragment(
                &index,
                &mut cache,
                Ns::Frag,
                &dec,
                &id_hex,
                seq,
                |i| Ok(chunks[i as usize].clone()),
                |pt| {
                    joined.extend_from_slice(pt);
                    Ok(())
                },
            )
            .expect("feeds");
        }
        assert_eq!(joined, content, "fragments reconstruct the whole content");
    }

    #[test]
    fn corrupt_cache_blob_is_treated_as_a_miss() {
        let (owner, bundle, _content) = build_large();
        let (header, chunks) = split(&bundle);
        let dec = open_content_decryptor(&ctx(&owner), &header).expect("decryptor");
        let index = two_fragment_index(chunks.len() as u64);
        let id_hex = file_id_hex();
        let dir = tmp_dir("corrupt");
        let mut cache = BlobCache::open(&dir, 1 << 20).unwrap();

        // Pre-seed a GARBAGE (undeframeable) blob under fragment 0's key.
        cache
            .put(Ns::Frag, &id_hex, 0, b"\xff\xff\xff\xff not a frame")
            .unwrap();

        let mut fetch_calls = 0u32;
        feed_fragment(
            &index,
            &mut cache,
            Ns::Frag,
            &dec,
            &id_hex,
            0,
            |i| {
                fetch_calls += 1;
                Ok(chunks[i as usize].clone())
            },
            |_pt| Ok(()),
        )
        .expect("refetches over corrupt cache");
        assert_eq!(fetch_calls, 2, "corrupt cache blob forced a refetch");
        // The cache was repaired with valid ciphertext framing.
        assert_eq!(
            deframe_chunks(&cache.get(Ns::Frag, &id_hex, 0).unwrap()).unwrap(),
            chunks[0..2].to_vec()
        );
    }

    #[test]
    fn unknown_seq_fails_closed() {
        let (owner, bundle, _content) = build_large();
        let (header, chunks) = split(&bundle);
        let dec = open_content_decryptor(&ctx(&owner), &header).expect("decryptor");
        let index = two_fragment_index(chunks.len() as u64);
        let dir = tmp_dir("unknown");
        let mut cache = BlobCache::open(&dir, 1 << 20).unwrap();
        let err = feed_fragment(
            &index,
            &mut cache,
            Ns::Frag,
            &dec,
            &file_id_hex(),
            99,
            |_i| panic!("must not fetch"),
            |_pt| panic!("must not sink"),
        )
        .unwrap_err();
        assert_eq!(err.code, "video_failed");
    }

    #[test]
    fn fetch_error_propagates_without_release() {
        let (owner, bundle, _content) = build_large();
        let (header, chunks) = split(&bundle);
        let dec = open_content_decryptor(&ctx(&owner), &header).expect("decryptor");
        let index = two_fragment_index(chunks.len() as u64);
        let dir = tmp_dir("fetcherr");
        let mut cache = BlobCache::open(&dir, 1 << 20).unwrap();
        let mut sink_calls = 0u32;
        let err = feed_fragment(
            &index,
            &mut cache,
            Ns::Frag,
            &dec,
            &file_id_hex(),
            0,
            |_i| Err(UiError::new("offline", "no net")),
            |_pt| {
                sink_calls += 1;
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(err.code, "offline");
        assert_eq!(sink_calls, 0, "no plaintext released on a fetch error");
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let (owner, bundle, _content) = build_large();
        let (header, mut chunks) = split(&bundle);
        chunks[0][0] ^= 0x01; // flip a ciphertext byte the fetcher will return
        let dec = open_content_decryptor(&ctx(&owner), &header).expect("decryptor");
        let index = two_fragment_index(chunks.len() as u64);
        let dir = tmp_dir("tamper");
        let mut cache = BlobCache::open(&dir, 1 << 20).unwrap();
        let mut sink_calls = 0u32;
        let err = feed_fragment(
            &index,
            &mut cache,
            Ns::Frag,
            &dec,
            &file_id_hex(),
            0,
            |i| Ok(chunks[i as usize].clone()),
            |_pt| {
                sink_calls += 1;
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(err.code, "video_failed");
        assert_eq!(sink_calls, 0, "no plaintext released on an AEAD failure");
    }

    /// The direct-link download route's Phase-D retry (`commands::video::serve_range`)
    /// depends on a specific mechanism this pins directly, without any network: a
    /// failed `feed_fragment` (tampered ciphertext) still writes that TAMPERED blob
    /// to the cache — `cache.put` happens BEFORE the AEAD check — so a naive retry
    /// that just re-supplies genuine bytes to `feed_fragment` would read the
    /// poisoned cache entry back as a "hit" and fail again FOREVER. Evicting the
    /// entry first (`BlobCache::evict`, what `serve_range` does before its
    /// forced-proxy retry) breaks that trap: the next `feed_fragment` call is a
    /// genuine miss, re-fetches (here: the caller now supplies genuine bytes,
    /// standing in for the forced-proxy refetch), and succeeds.
    #[test]
    fn evicting_a_poisoned_cache_entry_lets_a_retry_with_genuine_bytes_succeed() {
        let (owner, bundle, content) = build_large();
        let (header, mut chunks) = split(&bundle);
        let genuine = chunks.clone();
        chunks[0][0] ^= 0x01; // tamper the bytes the FIRST feed will return
        let dec = open_content_decryptor(&ctx(&owner), &header).expect("decryptor");
        let index = two_fragment_index(chunks.len() as u64);
        let id_hex = file_id_hex();
        let dir = tmp_dir("poison-then-evict");
        let mut cache = BlobCache::open(&dir, 1 << 20).unwrap();

        // First feed: tampered bytes. Fails AEAD, but the cache was already
        // written with the tampered blob (the trap this test pins).
        let err = feed_fragment(
            &index,
            &mut cache,
            Ns::Frag,
            &dec,
            &id_hex,
            0,
            |i| Ok(chunks[i as usize].clone()),
            |_pt| Ok(()),
        )
        .unwrap_err();
        assert_eq!(err.code, "video_failed");
        assert!(cache.contains(Ns::Frag, &id_hex, 0), "the failed attempt still poisoned the cache");

        // Without eviction, a retry with GENUINE bytes still fails — the poisoned
        // cache is read back as a "hit" and the genuine bytes never get used.
        let mut fetch_calls = 0u32;
        let still_fails = feed_fragment(
            &index,
            &mut cache,
            Ns::Frag,
            &dec,
            &id_hex,
            0,
            |i| {
                fetch_calls += 1;
                Ok(genuine[i as usize].clone())
            },
            |_pt| Ok(()),
        );
        assert!(still_fails.is_err(), "poisoned cache shadows even genuine bytes");
        assert_eq!(fetch_calls, 0, "the cache hit prevented any fetch at all");

        // Evict (what serve_range's Phase D does before its forced-proxy retry),
        // then retry with genuine bytes: now a real miss, refetches, and succeeds.
        cache.evict(Ns::Frag, &id_hex, 0);
        assert!(!cache.contains(Ns::Frag, &id_hex, 0));
        let mut fetch_calls2 = 0u32;
        let mut got: Vec<u8> = Vec::new();
        feed_fragment(
            &index,
            &mut cache,
            Ns::Frag,
            &dec,
            &id_hex,
            0,
            |i| {
                fetch_calls2 += 1;
                Ok(genuine[i as usize].clone())
            },
            |pt| {
                got.extend_from_slice(pt);
                Ok(())
            },
        )
        .expect("succeeds once the poisoned entry is evicted and genuine bytes are supplied");
        assert_eq!(fetch_calls2, 2, "the eviction forced a real refetch");
        assert_eq!(got, content[0..2 * 4096], "recovers the exact genuine plaintext");
    }
}
