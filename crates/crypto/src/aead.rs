//! Chunked / framed AES-256-GCM (DESIGN §12.10 / D33).
//!
//! Each chunk is `AES-256-GCM(ck, nonce_i, chunk_i, AAD_i)` where:
//!   * `ck` is the per-stream subkey `HKDF(DEK, "MaxSecu-<stream>-v1")` — the
//!     raw DEK is never an AEAD key (L-5);
//!   * `nonce_i` is the 96-bit big-endian chunk counter `i` (unique because
//!     `ck` is unique per file-version);
//!   * `AAD_i = canonical(chunk_aad)` = `{file_id, version, stream_type,
//!     chunk_index=i, is_last}`.
//!
//! The framing prevents truncation, reordering, and cross-file/version/stream
//! splicing: a missing final chunk (no `is_last`), an out-of-range index, or a
//! replay into another stream all fail the AEAD `AAD` check.

use crate::hash::sha256;
use crate::CryptoError;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use maxsecu_encoding::encode;
use maxsecu_encoding::structs::ChunkAad;
use maxsecu_encoding::types::{Id, StreamType};
use std::io::Read;

const TAG_LEN: usize = 16;

/// 96-bit big-endian counter nonce equal to the chunk index (§12.10).
fn nonce_for(chunk_index: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&chunk_index.to_be_bytes());
    n
}

/// Seal one chunk under `ck` with the given `aad` (its nonce is `aad.chunk_index`).
pub fn seal_chunk(ck: &[u8; 32], aad: &ChunkAad, plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(ck));
    let nonce = nonce_for(aad.chunk_index);
    let aad_bytes = encode(aad);
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad_bytes,
            },
        )
        .expect("AES-256-GCM encryption is infallible for in-bounds inputs")
}

/// Open one chunk; any tamper / wrong key / wrong AAD fails closed.
pub fn open_chunk(
    ck: &[u8; 32],
    aad: &ChunkAad,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(ck));
    let nonce = nonce_for(aad.chunk_index);
    let aad_bytes = encode(aad);
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| CryptoError::Aead)
}

/// A sealed stream: its ordered ciphertext chunks, the chunk count, and the
/// per-stream digest committed in the signed manifest (`SHA-256` over the
/// ordered per-chunk AEAD tags, DESIGN §12.3 / D33).
pub struct SealedStream {
    pub chunks: Vec<Vec<u8>>,
    pub chunk_count: u64,
    pub digest: [u8; 32],
}

/// Seal a whole stream into `chunk_size`-byte frames. A zero-length stream
/// yields exactly one empty, `is_last` chunk (so `chunk_count >= 1` always and
/// truncation-to-empty is still detectable).
pub fn seal_stream(
    ck: &[u8; 32],
    file_id: Id,
    version: u64,
    stream_type: StreamType,
    chunk_size: usize,
    plaintext: &[u8],
) -> SealedStream {
    assert!(chunk_size > 0, "chunk_size must be positive");
    let mut frames: Vec<&[u8]> = plaintext.chunks(chunk_size).collect();
    if frames.is_empty() {
        frames.push(&[]);
    }
    let n = frames.len();
    let mut chunks = Vec::with_capacity(n);
    for (i, frame) in frames.iter().enumerate() {
        let aad = ChunkAad {
            file_id,
            version,
            stream_type,
            chunk_index: i as u64,
            is_last: i == n - 1,
        };
        chunks.push(seal_chunk(ck, &aad, frame));
    }
    let digest = stream_digest(&chunks);
    SealedStream {
        chunks,
        chunk_count: n as u64,
        digest,
    }
}

/// Open and concatenate a stream's chunks, enforcing the framing: index `i`
/// for position `i`, `is_last` only on the final chunk. Any truncation,
/// reorder, splice, or tamper fails closed.
pub fn open_stream(
    ck: &[u8; 32],
    file_id: Id,
    version: u64,
    stream_type: StreamType,
    chunks: &[Vec<u8>],
) -> Result<Vec<u8>, CryptoError> {
    if chunks.is_empty() {
        return Err(CryptoError::Framing("empty stream"));
    }
    let n = chunks.len();
    let mut out = Vec::new();
    for (i, ct) in chunks.iter().enumerate() {
        let aad = ChunkAad {
            file_id,
            version,
            stream_type,
            chunk_index: i as u64,
            is_last: i == n - 1,
        };
        out.extend_from_slice(&open_chunk(ck, &aad, ct)?);
    }
    Ok(out)
}

/// Read up to `cap` bytes, looping over partial reads, so a short result
/// reliably means end-of-input (not a small `read`).
fn read_upto<R: Read>(r: &mut R, cap: usize) -> Result<Vec<u8>, CryptoError> {
    let mut buf = Vec::with_capacity(cap.min(1 << 16));
    let mut tmp = [0u8; 8192];
    while buf.len() < cap {
        let want = (cap - buf.len()).min(tmp.len());
        let n = r
            .read(&mut tmp[..want])
            .map_err(|_| CryptoError::Framing("stream read"))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    Ok(buf)
}

/// Seal a stream **chunk-at-a-time** from a reader (DESIGN §8.1 / §12.10): reads
/// one `chunk_size` frame, seals it, and hands the ciphertext to `emit(index,
/// ct)` — never holding more than one frame + its ciphertext in memory, so an
/// arbitrarily large source is processed within an O(chunk_size) budget. Returns
/// the `(chunk_count, digest)` to commit in the manifest (identical to
/// [`seal_stream`] for the same input). An empty source yields one empty
/// `is_last` chunk.
pub fn seal_stream_streaming<R, E>(
    ck: &[u8; 32],
    file_id: Id,
    version: u64,
    stream_type: StreamType,
    chunk_size: usize,
    reader: &mut R,
    mut emit: E,
) -> Result<(u64, [u8; 32]), CryptoError>
where
    R: Read,
    E: FnMut(u64, &[u8]) -> Result<(), CryptoError>,
{
    assert!(chunk_size > 0, "chunk_size must be positive");
    let mut tags: Vec<u8> = Vec::new();
    let mut index = 0u64;
    let mut cur = read_upto(reader, chunk_size)?;
    loop {
        // A short read already signalled EOF, so there is no following frame.
        let next = if cur.len() < chunk_size {
            Vec::new()
        } else {
            read_upto(reader, chunk_size)?
        };
        let is_last = next.is_empty();
        let aad = ChunkAad {
            file_id,
            version,
            stream_type,
            chunk_index: index,
            is_last,
        };
        let ct = seal_chunk(ck, &aad, &cur);
        tags.extend_from_slice(&ct[ct.len().saturating_sub(TAG_LEN)..]);
        emit(index, &ct)?;
        index += 1;
        if is_last {
            break;
        }
        cur = next;
    }
    Ok((index, sha256(&tags)))
}

/// Open a stream **chunk-at-a-time** (DESIGN §8.1 line 361 — decrypt-while-play):
/// for each index in `0..chunk_count`, `fetch(i)` supplies the ciphertext chunk
/// (e.g. a lazy network GET), its AEAD tag is verified **before** the plaintext
/// is handed to `sink`, and only one chunk of plaintext is ever in memory. The
/// signed `chunk_count` + the `is_last` AAD catch truncation/extension; any
/// tamper/reorder fails closed. No whole-stream plaintext is materialized.
pub fn open_stream_streaming<Fetch, Sink>(
    ck: &[u8; 32],
    file_id: Id,
    version: u64,
    stream_type: StreamType,
    chunk_count: u64,
    mut fetch: Fetch,
    mut sink: Sink,
) -> Result<(), CryptoError>
where
    Fetch: FnMut(u64) -> Result<Vec<u8>, CryptoError>,
    Sink: FnMut(&[u8]) -> Result<(), CryptoError>,
{
    if chunk_count == 0 {
        return Err(CryptoError::Framing("empty stream"));
    }
    for i in 0..chunk_count {
        let ct = fetch(i)?;
        let aad = ChunkAad {
            file_id,
            version,
            stream_type,
            chunk_index: i,
            is_last: i == chunk_count - 1,
        };
        let pt = open_chunk(ck, &aad, &ct)?; // verified before release to the sink
        sink(&pt)?;
    }
    Ok(())
}

/// Single-shot AES-256-GCM (not chunk-framed): the on-device `local_key_blob`
/// and any other one-shot sealed record (DESIGN §8.1). `nonce` must be unique
/// per `key`; the blob uses a fresh random nonce stored beside the ciphertext.
pub fn seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AES-256-GCM encryption is infallible for in-bounds inputs")
}

/// Open a [`seal`]ed ciphertext; any tamper / wrong key / wrong AAD fails closed.
pub fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)
}

/// The per-stream manifest digest: `SHA-256` over the ordered per-chunk AEAD
/// tags (DESIGN §12.3 / D33). Equals [`SealedStream::digest`]; a downloader
/// recomputes it over the served chunks and rejects a manifest-mismatch. Robust
/// against an undersized (untrusted-server) chunk — it never indexes out of
/// bounds, so a short chunk simply yields a non-matching digest.
pub fn stream_digest(chunks: &[Vec<u8>]) -> [u8; 32] {
    let mut tags = Vec::with_capacity(chunks.len() * TAG_LEN);
    for ct in chunks {
        tags.extend_from_slice(&ct[ct.len().saturating_sub(TAG_LEN)..]);
    }
    sha256(&tags)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CK: [u8; 32] = [0x11; 32];
    const FID: Id = Id([0x22; 16]);

    #[test]
    fn single_shot_seal_open_round_trips() {
        let key = [0x33; 32];
        let nonce = [0x44; 12];
        let aad = b"local-key-blob-header";
        let pt = b"enc_sk||enc_pk||sig_seed";
        let ct = seal(&key, &nonce, aad, pt);
        assert_eq!(open(&key, &nonce, aad, &ct).unwrap(), pt);
    }

    #[test]
    fn single_shot_rejects_wrong_key_aad_or_tamper() {
        let key = [0x33; 32];
        let nonce = [0x44; 12];
        let ct = seal(&key, &nonce, b"aad", b"secret");
        assert_eq!(
            open(&[0x99; 32], &nonce, b"aad", &ct),
            Err(CryptoError::Aead)
        );
        assert_eq!(
            open(&key, &nonce, b"other-aad", &ct),
            Err(CryptoError::Aead)
        );
        let mut bad = ct.clone();
        let n = bad.len() - 1;
        bad[n] ^= 0x01;
        assert_eq!(open(&key, &nonce, b"aad", &bad), Err(CryptoError::Aead));
    }

    fn body() -> Vec<u8> {
        (0..(1024 * 5 + 7)).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn stream_digest_matches_seal_and_detects_tamper() {
        let pt = body();
        let sealed = seal_stream(&CK, FID, 1, StreamType::Content, 1024, &pt);
        // Recomputing over the served chunks equals the manifest-committed digest.
        assert_eq!(stream_digest(&sealed.chunks), sealed.digest);
        // Flipping a tag byte changes the digest (manifest mismatch on download).
        let mut tampered = sealed.chunks.clone();
        let last = tampered.last_mut().unwrap();
        let i = last.len() - 1;
        last[i] ^= 0x01;
        assert_ne!(stream_digest(&tampered), sealed.digest);
        // A truncated/undersized chunk does not panic (untrusted input).
        let short = vec![vec![0u8; 3]];
        let _ = stream_digest(&short);
    }

    #[test]
    fn stream_round_trips() {
        let pt = body();
        let sealed = seal_stream(&CK, FID, 1, StreamType::Content, 1024, &pt);
        assert!(sealed.chunk_count >= 6);
        let out = open_stream(&CK, FID, 1, StreamType::Content, &sealed.chunks).unwrap();
        assert_eq!(out, pt);
    }

    #[test]
    fn empty_stream_is_one_last_chunk() {
        let sealed = seal_stream(&CK, FID, 1, StreamType::Preview, 1024, &[]);
        assert_eq!(sealed.chunk_count, 1);
        let out = open_stream(&CK, FID, 1, StreamType::Preview, &sealed.chunks).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn tampered_chunk_byte_rejects() {
        let pt = body();
        let mut sealed = seal_stream(&CK, FID, 1, StreamType::Content, 1024, &pt);
        sealed.chunks[2][0] ^= 0x01;
        assert_eq!(
            open_stream(&CK, FID, 1, StreamType::Content, &sealed.chunks),
            Err(CryptoError::Aead)
        );
    }

    #[test]
    fn truncating_final_chunk_rejects() {
        // Dropping the last chunk makes the new last frame's AAD claim is_last,
        // which it was not sealed with → fails (truncation detection).
        let pt = body();
        let sealed = seal_stream(&CK, FID, 1, StreamType::Content, 1024, &pt);
        let truncated = &sealed.chunks[..sealed.chunks.len() - 1];
        assert_eq!(
            open_stream(&CK, FID, 1, StreamType::Content, truncated),
            Err(CryptoError::Aead)
        );
    }

    #[test]
    fn reordering_chunks_rejects() {
        let pt = body();
        let mut sealed = seal_stream(&CK, FID, 1, StreamType::Content, 1024, &pt);
        sealed.chunks.swap(0, 1); // chunk_index in the AAD no longer matches position
        assert_eq!(
            open_stream(&CK, FID, 1, StreamType::Content, &sealed.chunks),
            Err(CryptoError::Aead)
        );
    }

    #[test]
    fn cross_stream_replay_rejects() {
        // A content chunk cannot be opened as a thumbnail chunk: stream_type is
        // bound in the AAD (D33), so the streams never share a (key,nonce) space.
        let pt = body();
        let sealed = seal_stream(&CK, FID, 1, StreamType::Content, 1024, &pt);
        assert_eq!(
            open_stream(&CK, FID, 1, StreamType::Thumbnail, &sealed.chunks),
            Err(CryptoError::Aead)
        );
    }

    #[test]
    fn wrong_file_or_version_rejects() {
        let pt = body();
        let sealed = seal_stream(&CK, FID, 1, StreamType::Content, 1024, &pt);
        assert_eq!(
            open_stream(&CK, Id([0x23; 16]), 1, StreamType::Content, &sealed.chunks),
            Err(CryptoError::Aead)
        );
        assert_eq!(
            open_stream(&CK, FID, 2, StreamType::Content, &sealed.chunks),
            Err(CryptoError::Aead)
        );
    }

    #[test]
    fn streaming_seal_matches_whole_buffer() {
        let pt = body();
        let whole = seal_stream(&CK, FID, 1, StreamType::Content, 1024, &pt);
        let mut emitted: Vec<Vec<u8>> = Vec::new();
        let mut cursor = std::io::Cursor::new(pt.clone());
        let (count, digest) = seal_stream_streaming(
            &CK,
            FID,
            1,
            StreamType::Content,
            1024,
            &mut cursor,
            |i, ct| {
                assert_eq!(i as usize, emitted.len());
                emitted.push(ct.to_vec());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(count, whole.chunk_count);
        assert_eq!(digest, whole.digest);
        assert_eq!(emitted, whole.chunks); // deterministic counter nonce
    }

    #[test]
    fn streaming_seal_empty_is_one_last_chunk() {
        let whole = seal_stream(&CK, FID, 1, StreamType::Preview, 1024, &[]);
        let mut emitted = Vec::new();
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        let (count, digest) = seal_stream_streaming(
            &CK,
            FID,
            1,
            StreamType::Preview,
            1024,
            &mut cursor,
            |_, ct| {
                emitted.push(ct.to_vec());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(count, 1);
        assert_eq!(digest, whole.digest);
        assert_eq!(emitted, whole.chunks);
    }

    #[test]
    fn streaming_open_round_trips_without_a_whole_plaintext_buffer() {
        let pt = body();
        let sealed = seal_stream(&CK, FID, 1, StreamType::Content, 1024, &pt);
        // The sink only folds each frame into a running hash + a max-window check;
        // it never concatenates the plaintext, proving streaming needs no whole buffer.
        let mut acc_tags = Vec::new();
        let mut max_window = 0usize;
        open_stream_streaming(
            &CK,
            FID,
            1,
            StreamType::Content,
            sealed.chunk_count,
            |i| Ok(sealed.chunks[i as usize].clone()),
            |frame| {
                max_window = max_window.max(frame.len());
                acc_tags.extend_from_slice(&sha256(frame));
                Ok(())
            },
        )
        .unwrap();
        // No single observed frame ever exceeded the chunk size (O(chunk_size) RAM).
        assert!(max_window <= 1024);
        // The streamed bytes reconstruct the same plaintext (verified via the
        // whole-buffer opener as an independent oracle).
        let whole = open_stream(&CK, FID, 1, StreamType::Content, &sealed.chunks).unwrap();
        let expected: Vec<u8> = whole.chunks(1024).flat_map(sha256).collect();
        assert_eq!(acc_tags, expected);
    }

    #[test]
    fn streaming_open_detects_truncation_via_chunk_count() {
        let pt = body();
        let sealed = seal_stream(&CK, FID, 1, StreamType::Content, 1024, &pt);
        // Claim one fewer chunk: the chunk now at the "last" position was sealed
        // with is_last=false, so its AAD mismatches and the open fails closed.
        let short = sealed.chunk_count - 1;
        let err = open_stream_streaming(
            &CK,
            FID,
            1,
            StreamType::Content,
            short,
            |i| Ok(sealed.chunks[i as usize].clone()),
            |_| Ok(()),
        )
        .unwrap_err();
        assert_eq!(err, CryptoError::Aead);
    }

    #[test]
    fn streaming_open_rejects_a_tampered_chunk_before_release() {
        let pt = body();
        let sealed = seal_stream(&CK, FID, 1, StreamType::Content, 1024, &pt);
        let mut released = 0usize;
        let err = open_stream_streaming(
            &CK,
            FID,
            1,
            StreamType::Content,
            sealed.chunk_count,
            |i| {
                let mut ct = sealed.chunks[i as usize].clone();
                if i == 2 {
                    ct[0] ^= 0x01; // tamper chunk 2's ciphertext
                }
                Ok(ct)
            },
            |_| {
                released += 1;
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(err, CryptoError::Aead);
        // Chunks 0 and 1 released; the tampered chunk 2 was NOT released to the sink.
        assert_eq!(released, 2);
    }

    #[test]
    fn digest_commits_to_ciphertext_tags() {
        // The stream digest changes if any chunk's tag changes (manifest binding).
        let pt = body();
        let a = seal_stream(&CK, FID, 1, StreamType::Content, 1024, &pt);
        let b = seal_stream(&CK, FID, 1, StreamType::Content, 1024, &pt);
        assert_eq!(
            a.digest, b.digest,
            "deterministic counter nonce ⇒ stable digest"
        );
        let mut pt2 = pt.clone();
        pt2[0] ^= 0xFF;
        let c = seal_stream(&CK, FID, 1, StreamType::Content, 1024, &pt2);
        assert_ne!(a.digest, c.digest);
    }
}
