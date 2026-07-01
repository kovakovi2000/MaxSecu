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
