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
use maxsecu_client_core::UploadBundle;
use crate::upload_staging::StagingRecord;

/// One persistent authed HTTP/1.1 channel for an open video session: the live
/// `SendRequest` plus the host + bearer token bound to it. All range fetches for a
/// session reuse this ONE connection (serialized via the tokio Mutex around it),
/// instead of re-authing per range (which contended the ConnectLock → spurious 500s).
pub struct AuthedChannel {
    pub sender: SendRequest<Full<Bytes>>,
    pub host: String,
    pub token: String,
}

/// The upload content variant — held in the in-process job registry. Image/blog
/// uploads keep their fully-encrypted `UploadBundle` in RAM. Video uploads use the
/// disk-backed `StagingRecord` (no content ciphertext in RAM, only small streams).
pub enum StagedContent {
    /// Image or blog: the complete encrypted bundle (small enough to hold in RAM).
    InRam(UploadBundle),
    /// Video: disk-backed staging record with no content ciphertext. The content is
    /// re-sealed on demand during `confirm_upload` via `resume_content_sealer`.
    Streaming(StagingRecord),
}

/// File-backed author preview for the **preview-before-upload** local decode (Phase 7,
/// Gate 6). Holds the on-disk path of the transcoded fMP4 (`out.mp4` in the per-job
/// temp dir) instead of an in-RAM plaintext buffer — range requests from the native
/// `<video>` element are served by reading bounded slices from disk
/// (`serve_preview_range` / `preview_slice_file`). `index` is the authenticated
/// fragment seek-map (in VIDEO_CHUNK_SIZE units), used to locate per-fragment byte
/// ranges in the file. Dropped when the job leaves the registry (confirm/cancel); the
/// on-disk file is then also deleted via `StagedUpload.job_dir` cleanup.
#[derive(Clone)]
pub struct StagedVideoPreview {
    /// On-disk path of the transcoded fMP4 (`out.mp4` in the per-job temp dir). Byte
    /// ranges are served by seek+read — no full-file plaintext in RAM.
    pub out_mp4_path: std::path::PathBuf,
    pub index: Vec<crate::video::FragmentEntry>,
}

/// One staged upload held pending the user's confirm. `content` is either an
/// in-RAM `UploadBundle` (image/blog) or a disk-backed `StagingRecord` (video).
/// Neither the bundle's DEK nor the content ciphertext ever crosses the Tauri seam.
/// For a video, `preview` holds the on-disk fMP4 path + fragment index so the author
/// can WYSIWYG-preview the transcoded result before confirming. `job_dir` is the
/// staging dir (video) or None (image/blog); deleted on confirm-success or cancel.
pub struct StagedUpload {
    pub content: StagedContent,
    pub file_type: String,
    pub title: String,
    pub total_chunks: u64,
    pub byte_size: u64,
    pub preview: Option<StagedVideoPreview>,
    /// Per-job temp dir (video only; `None` for image/blog). Deleted on
    /// confirm-success or cancel. Retained on failed-confirm so the retry can still
    /// serve preview ranges from the on-disk fMP4.
    pub job_dir: Option<std::path::PathBuf>,
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

/// The identity of one bundle member: its `file_id` and `FileType`. Stored
/// parallel to `BundleJob.members` (same index = same member), in the
/// AUTHORITATIVE bundle member order. Kept in the TCB — it never crosses the
/// Tauri seam.
pub struct MemberMeta {
    pub file_id: [u8; 16],
    pub file_type: maxsecu_encoding::types::FileType,
}

/// One staged-but-not-yet-confirmed BUNDLE: the bundle's own `bundle_id`
/// (generated at stage time), its title/tags, and its ordered members. Each
/// member is a fully-staged [`StagedUpload`] (image/blog in-RAM, video/generic
/// disk-backed) — exactly as a single-post `stage_upload` would produce. The
/// `member_meta` vector is parallel to `members` (same index = same member) and
/// its order IS the authoritative bundle member order. Like [`StagedUpload`],
/// this holds `UploadBundle`/`StagingRecord` material and NEVER crosses the
/// Tauri seam; only the [`crate::dto::BundlePreview`] DTO does.
pub struct BundleJob {
    pub bundle_id: [u8; 16],
    pub title: String,
    pub tags: Vec<String>,
    /// Parallel to `member_meta`, same order.
    pub members: Vec<StagedUpload>,
    /// `(file_id, file_type)` per member, in order (authoritative bundle order).
    pub member_meta: Vec<MemberMeta>,
    /// Raw PNG thumbnail bytes of the chosen cover member (from the stage request's
    /// `cover_index`), sealed into the bundle file's Thumbnail stream so the bundle's
    /// feed card shows a cover image. `None` ⇒ no cover (card falls back to members).
    pub cover_thumbnail: Option<Vec<u8>>,
}

/// Managed state: `job_id -> BundleJob`. Async mutex (commands are async).
pub struct BundleJobs(pub Mutex<HashMap<String, BundleJob>>);

impl BundleJobs {
    pub fn new() -> Self {
        BundleJobs(Mutex::new(HashMap::new()))
    }
}

impl Default for BundleJobs {
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
    /// The persistent authed connection for range serving. `Option` only so pure
    /// `commands::video` unit tests (which never serve ranges) can build a job with
    /// `None`; the real open path + the e2e always populate `Some`. Behind an `Arc<Mutex>`
    /// so overlapping range requests serialize over the one HTTP/1.1 connection.
    pub channel: Option<Arc<tokio::sync::Mutex<AuthedChannel>>>,
    /// The download route (`crate::config::RouteMode`) captured once when
    /// `open_video` registered this session — reused by every `serve_range` call
    /// for the session's lifetime (a mid-session settings edit takes effect on the
    /// NEXT `open_video`, not retroactively). Drives the direct-link download
    /// route (`crate::direct_link`): `PreferDropbox` prefers a server-brokered
    /// direct cloud fetch for `content` chunks, falling back to the proxy on any
    /// problem; `TorOnly` never attempts direct.
    pub route_mode: crate::config::RouteMode,
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
            content: StagedContent::InRam(bundle),
            file_type: "blog".into(),
            title: "T".into(),
            total_chunks: 1,
            byte_size: 2,
            preview: None,
            job_dir: None,
        }
    }

    #[tokio::test]
    async fn insert_then_take_round_trips() {
        let jobs = UploadJobs::new();
        jobs.0.lock().await.insert("job-1".into(), staged());
        assert!(jobs.0.lock().await.contains_key("job-1"));
        let taken = jobs.0.lock().await.remove("job-1");
        assert!(taken.is_some());
        let taken = taken.unwrap();
        assert_eq!(taken.title, "T");
        assert!(matches!(taken.content, StagedContent::InRam(_)));
        assert!(jobs.0.lock().await.remove("job-1").is_none()); // gone
    }

    #[tokio::test]
    async fn bundle_job_insert_take_round_trips() {
        let jobs = BundleJobs::new();
        let job = BundleJob {
            bundle_id: [0xB1; 16],
            title: "Trip".into(),
            tags: vec!["a".into()],
            members: vec![staged(), staged()],
            member_meta: vec![
                MemberMeta {
                    file_id: [0x01; 16],
                    file_type: maxsecu_encoding::types::FileType::Blog,
                },
                MemberMeta {
                    file_id: [0x02; 16],
                    file_type: maxsecu_encoding::types::FileType::Blog,
                },
            ],
            cover_thumbnail: None,
        };
        jobs.0.lock().await.insert("b-1".into(), job);
        let taken = jobs.0.lock().await.remove("b-1").unwrap();
        assert_eq!(taken.members.len(), 2);
        assert_eq!(taken.member_meta.len(), 2);
        assert_eq!(taken.bundle_id.len(), 16);
        assert!(jobs.0.lock().await.remove("b-1").is_none());
    }
}
