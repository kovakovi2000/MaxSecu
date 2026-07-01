//! In-process registry of staged-but-not-yet-confirmed uploads (preview-before-
//! upload). `stage_upload` builds the encrypted `UploadBundle`, stores it here keyed
//! by a random `job_id`, and returns a preview; `confirm_upload` takes it and runs
//! the network pipeline; `cancel_upload` drops it. The bundle stays in the TCB —
//! it never crosses the Tauri seam.

use std::collections::HashMap;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use maxsecu_client_core::UploadBundle;

/// One persistent authed HTTP/1.1 channel for an open video session: the live
/// `SendRequest` plus the host + bearer token bound to it. All range fetches for a
/// session reuse this ONE connection (serialized via the tokio Mutex around it),
/// instead of re-authing per range (which contended the ConnectLock → spurious 500s).
pub struct AuthedChannel {
    pub sender: SendRequest<Full<Bytes>>,
    pub host: String,
    pub token: String,
}

/// The canonical (already-plaintext) video held for the **preview-before-upload**
/// local decode (Phase 7, Gate 6). `cmaf` is the transcoded AV1/CMAF content stream
/// the bundle ALSO carries in encrypted form; the author's own plaintext is bounded
/// here only so `preview_video` can drive the confined decode session over it
/// without a server fetch or a decrypt. It is dropped when the job leaves the
/// registry (confirm/cancel) — and, being `Zeroizing`, the full-file plaintext is
/// WIPED on that drop (matching the per-window `ScriptGuard` discipline). `index` is
/// the authenticated fragment seek-map (in VIDEO_CHUNK_SIZE units), used to slice
/// `cmaf` into per-fragment decode inputs.
pub struct StagedVideoPreview {
    pub cmaf: Zeroizing<Vec<u8>>,
    pub index: Vec<crate::video::FragmentEntry>,
}

/// One staged upload held pending the user's confirm. `bundle` carries the signed,
/// encrypted records + ciphertext chunks (never sent to the UI). For a video,
/// `preview` additionally holds the canonical plaintext + fragment index so the
/// author can WYSIWYG-preview the transcoded result before confirming.
pub struct StagedUpload {
    pub bundle: UploadBundle,
    pub file_type: String,
    pub title: String,
    pub total_chunks: u64,
    pub byte_size: u64,
    pub preview: Option<StagedVideoPreview>,
}

/// Managed state: `job_id -> StagedUpload`. Async mutex (commands are async).
pub struct UploadJobs(pub Mutex<HashMap<String, StagedUpload>>);

impl UploadJobs {
    pub fn new() -> Self {
        UploadJobs(Mutex::new(HashMap::new()))
    }
}

impl Default for UploadJobs {
    fn default() -> Self {
        Self::new()
    }
}

/// One live video-player session (Phase 7, Gate 4). Holds the in-TCB
/// [`ContentDecryptor`] (the content subkey — NEVER crosses the Tauri seam), the
/// authenticated fragment index (seek map), and the bounded on-disk **ciphertext**
/// [`FragmentCache`]. Dropping the job (on `cancel_video`) drops the decryptor,
/// which zeroizes the subkey. Non-`Clone` by construction (the decryptor is).
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
    /// UI playback gain preference (0.0..=4.0). Has NO decode effect — the UI
    /// applies it via WebAudio (Gate 5); stored here so it survives across windows.
    pub gain: f32,
    /// The persistent authed connection for range serving. `Option` only so pure
    /// `commands::video` unit tests (which never serve ranges) can build a job with
    /// `None`; the real open path + the e2e always populate `Some`. Behind an `Arc<Mutex>`
    /// so overlapping range requests serialize over the one HTTP/1.1 connection.
    pub channel: Option<Arc<tokio::sync::Mutex<AuthedChannel>>>,
}

/// Managed state: `file_id_hex -> VideoJob`. Async mutex (commands are async).
/// Keyed by the canonical lowercase `hex16(file_id)` so seek/volume/cancel find
/// the session `open_video` created.
pub struct VideoJobs(pub Mutex<HashMap<String, VideoJob>>);

impl VideoJobs {
    pub fn new() -> Self {
        VideoJobs(Mutex::new(HashMap::new()))
    }
}

impl Default for VideoJobs {
    fn default() -> Self {
        Self::new()
    }
}

/// Managed state holding the cancel token for the CURRENTLY in-flight video
/// `stage_upload` transcode (there is at most one — the UI stages one video at a
/// time). `stage_upload` installs a fresh `Arc<AtomicBool>` before the confined
/// transcode and clears it on completion/cancel; `cancel_video_prepare` (and the app
/// shutdown hook) set the bool to tear the confined ffmpeg/re-mux children down.
///
/// A **`std::sync::Mutex`** (not the async `tokio::sync::Mutex`): the lock is held
/// only for the trivial `Option` swap/read (never across an `.await`), and the
/// shutdown hook runs in Tauri's synchronous `RunEvent` callback where an async lock
/// is unavailable — a std mutex lets the command AND the shutdown hook share it.
pub struct VideoPrepareCancel(
    pub std::sync::Mutex<Option<std::sync::Arc<std::sync::atomic::AtomicBool>>>,
);

impl VideoPrepareCancel {
    pub fn new() -> Self {
        VideoPrepareCancel(std::sync::Mutex::new(None))
    }
}

impl Default for VideoPrepareCancel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn staged() -> StagedUpload {
        // A real bundle via build_upload (UploadBundle is not Default/Clone).
        use maxsecu_client_core::{build_upload, Identity, PlaintextStreams, UploadParams};
        use maxsecu_crypto::generate_enc_keypair;
        use maxsecu_encoding::types::{FileType, Id, Timestamp};
        let owner = Identity::generate();
        let (_rsk, rpk) = generate_enc_keypair();
        let params = UploadParams {
            owner: &owner,
            owner_id: Id([0x11; 16]),
            owner_key_version: 1,
            file_id: Id([0xF1; 16]),
            file_type: FileType::Blog,
            chunk_size: 4096,
            recovery_pub: rpk,
            recovery_mlkem_pub: None,
            created_at: Timestamp(1_719_500_000_000),
        };
        let streams = PlaintextStreams {
            content: b"hi".to_vec(),
            metadata: None,
            thumbnail: None,
            preview: None,
        };
        let bundle = build_upload(&params, &streams).unwrap();
        StagedUpload {
            bundle,
            file_type: "blog".into(),
            title: "T".into(),
            total_chunks: 1,
            byte_size: 2,
            preview: None,
        }
    }

    #[tokio::test]
    async fn insert_then_take_round_trips() {
        let jobs = UploadJobs::new();
        jobs.0.lock().await.insert("job-1".into(), staged());
        assert!(jobs.0.lock().await.contains_key("job-1"));
        let taken = jobs.0.lock().await.remove("job-1");
        assert!(taken.is_some());
        assert_eq!(taken.unwrap().title, "T");
        assert!(jobs.0.lock().await.remove("job-1").is_none()); // gone
    }
}
