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
    let mut tags = Vec::with_capacity(n * TAG_LEN);
    for (i, frame) in frames.iter().enumerate() {
        let aad = ChunkAad {
            file_id,
            version,
            stream_type,
            chunk_index: i as u64,
            is_last: i == n - 1,
        };
        let ct = seal_chunk(ck, &aad, frame);
        tags.extend_from_slice(&ct[ct.len() - TAG_LEN..]);
        chunks.push(ct);
    }
    SealedStream {
        chunks,
        chunk_count: n as u64,
        digest: sha256(&tags),
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

#[cfg(test)]
mod tests {
    use super::*;

    const CK: [u8; 32] = [0x11; 32];
    const FID: Id = Id([0x22; 16]);

    fn body() -> Vec<u8> {
        (0..(1024 * 5 + 7)).map(|i| (i % 251) as u8).collect()
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
