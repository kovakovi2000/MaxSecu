//! Plain data crossing the Tauri command boundary. No key material, no
//! signed-record interiors, no whole-plaintext buffers ever appear here.

use serde::{Deserialize, Serialize};

pub use maxsecu_media_launcher::TranscodeOptions;

#[derive(Debug, Clone, Deserialize)]
pub struct ConnectRequest {
    pub server: String, // host:port or domain
    pub username: String,
    pub use_tor: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectResponse {
    pub server_id: String, // from the challenge response
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExportKeystoreRequest {
    pub dest_path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapRequest {
    pub bootstrap_secret: String,
    /// Optional directory to ALSO write the encrypted glass-break keystore into.
    pub save_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GlassbreakResponse {
    pub username: String,
    pub password: String,
    pub user_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FirstAdminRequest {
    pub username: String,
    pub password: String,
    pub bootstrap_secret: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegisterUserRequest {
    pub username: String,
    pub password: String,
    pub voucher: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccountStatusRequest {
    pub username: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PendingUserDto {
    pub user_id: String,
    pub username: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct IssueVoucherResponse {
    pub code: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApprovalRequest {
    pub user_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CeremonyWorkItem {
    pub user_id: String,
    pub roles: Vec<String>,
    pub note: String,
}

/// Feed type filter (D35). `All` omits the server `type` param.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FeedFilter {
    All,
    Image,
    Video,
    Blog,
}

/// Client-side sort over the listing.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FeedSort {
    NewestFirst,
    OldestFirst,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListFeedRequest {
    pub filter: FeedFilter,
    pub sort: FeedSort,
    #[serde(default)]
    pub limit: Option<usize>,
}

/// One feed entry — listing metadata only (no decrypted values). The card is
/// decrypted separately by `decrypt_card`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FeedEntryDto {
    pub file_id: String,
    pub file_type: String,
    pub version: u64,
    pub updated_at: u64,
    pub has_thumbnail: bool,
}

/// A decrypted, verified feed card — render-ready, no key material.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CardDto {
    pub file_id: String,
    pub file_type: String,
    pub version: u64,
    pub title: String,
    pub tags: Vec<String>,
    /// A small canonical-PNG thumbnail as standard base64, or `None` if the item
    /// has no thumbnail stream (e.g. a blog). The UI renders it via a `data:` URL.
    pub thumbnail_b64: Option<String>,
    /// `true` if this user authored the file (drives the "only my uploads" filter).
    pub mine: bool,
    /// A short fingerprint hex (first 8 bytes) of the verified author identity —
    /// a non-secret verification tick for the UI.
    pub author_fp: String,
    /// Whether a valid author recovery grant was present (anomaly flag, not fatal).
    pub recovery_ok: bool,
}

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

/// The verified, decrypted content to display. Exactly one of `image_png_b64` /
/// `blog_text` is set per `file_type`. No key material; the content shown is the
/// product, not a TCB leak.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OpenedContentDto {
    pub file_id: String,
    pub file_type: String,
    pub version: u64,
    pub title: String,
    pub tags: Vec<String>,
    /// For an image: the canonical PNG as standard base64 (UI → `data:image/png`).
    pub image_png_b64: Option<String>,
    /// For a blog: the sanitized UTF-8 text.
    pub blog_text: Option<String>,
    pub author_fp: String,
    pub recovery_ok: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SearchHit {
    pub file_id: String,
    pub title: String,
    pub file_type: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SearchRequest {
    pub query: String,
}

/// What kind of content the user is staging for upload.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UploadKind {
    Image,
    Blog,
    Video,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StageUploadRequest {
    pub kind: UploadKind,
    /// For an image OR a video: a filesystem path to the chosen source file (the
    /// Browse picker returns it via `commands::dialog::pick_file`). The video source
    /// is now an ARBITRARY file decoded by the confined ffmpeg, so it is carried as a
    /// path (no in-memory bytes, no 64 MiB seam limit on the source). Ignored for
    /// blogs.
    #[serde(default)]
    pub path: Option<String>,
    /// For a blog: the post body text. Ignored for images/videos.
    #[serde(default)]
    pub content: Option<String>,
    /// For a video: the author's transcode shaping (resolution + bitrate) that feeds
    /// the confined ffmpeg argv. Absent → [`TranscodeOptions::default`] (preserve the
    /// source). Ignored for other kinds.
    #[serde(default)]
    pub options: Option<TranscodeOptions>,
    pub title: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// A preview of a staged-but-not-uploaded post. No key material, no bundle —
/// only what the UI renders before the user confirms.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UploadPreview {
    pub job_id: String,
    pub file_type: String,
    pub title: String,
    pub tags: Vec<String>,
    pub byte_size: u64,
    pub total_chunks: u64,
    /// A small canonical-PNG thumbnail (base64) for an image preview, else None.
    pub thumbnail_b64: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConfirmUploadRequest {
    pub job_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CancelUploadRequest {
    pub job_id: String,
}

/// One staged/retained upload job, for the active-uploads tray. No bundle, no keys.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UploadJobView {
    pub job_id: String,
    pub title: String,
    pub file_type: String,
    pub total_chunks: u64,
}

/// One pending (interrupted) upload returned by `list_pending_uploads` for the
/// cross-restart resume prompt. No bundle, no key material — only the information
/// the UI needs to label the entry and show a progress fraction.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PendingUploadView {
    pub file_id_hex: String,
    pub title: String,
    pub progress: u64,
    pub total: u64,
}
