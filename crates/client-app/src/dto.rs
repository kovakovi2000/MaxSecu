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

/// Registration-key enrollment (spec §5). The single-use key itself is NOT on the
/// seam — it is read from the local `register.key` file entirely in Rust — so only
/// the chosen username + the keystore passphrase cross the boundary.
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterWithKeyRequest {
    pub username: String,
    pub passphrase: String,
}

/// The outcome of a successful `register_with_key`: the enrolled username + the
/// server-assigned opaque `user_id` (hex16). NO key material, NO registration key.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RegisteredDto {
    pub username: String,
    pub user_id: String,
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
    /// For a bundle card: how many members of each kind it groups (order-private —
    /// counts only, never the member order). Zeros for a non-bundle card.
    #[serde(default)]
    pub member_counts: MemberCounts,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CardRequest {
    pub file_id: String,
    /// The version the feed already knows (D35 listing). When present, a cache hit
    /// needs zero network. Absent → the command learns it from the §8.5 view.
    #[serde(default)]
    pub version: Option<u64>,
}

/// A request to download+decrypt a post's original to disk. `save_path` is the
/// OS path the user chose (via the `save_file` native dialog); the command writes
/// the verified plaintext there. Plain data only — no key material.
#[derive(Debug, Clone, Deserialize)]
pub struct DownloadRequest {
    pub file_id: String,
    pub save_path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpenContentRequest {
    pub file_id: String,
    #[serde(default)]
    pub version: Option<u64>,
}

/// A request to permanently delete an owned post/bundle (spec: bundles Task 6.1).
/// Carries only the target `file_id` (hex16). The command validates + parses it,
/// then issues `DELETE /v1/files/{file_id}`; no key material crosses the seam.
#[derive(Debug, Clone, Deserialize)]
pub struct DeleteRequest {
    pub file_id: String,
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
    /// Display metadata for the Share affordance (T4, D-OQ3): `true` whenever
    /// this open succeeded, i.e. the caller holds a wrap for this item. Per the
    /// locked decision, Share is available to ANY wrap-holder who can open the
    /// content — NOT gated on `my_id == author.user_id` (ownership). This is
    /// therefore always `true` on a successful `OpenedContentDto`; there is no
    /// partial-open path that would set it `false`.
    pub can_share: bool,
    /// `true` iff THIS user authored the item (`my_id == author.user_id`). Gates
    /// the owner-only permanent-Delete affordance (bundles Task 6.2) — distinct
    /// from `can_share`, which any current wrap-holder gets.
    pub mine: bool,
}

/// One member of an opened bundle, in the bundle's authoritative order. A seam
/// DTO (Serialize — it crosses the boundary TO the UI): plain data only, no key
/// material. `title` / `thumbnail_b64` are filled lazily by the UI (empty here);
/// `file_id` comes from the SIGNED bundle body, never a server-served listing.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BundleMemberView {
    pub file_id: String,
    pub file_type: String,
    pub title: String,
    pub thumbnail_b64: Option<String>,
}

/// A verified, opened bundle: its own id/type/version plus the ordered member
/// list. A seam DTO (Serialize — crosses TO the UI): no key material. The member
/// ORDER is authoritative and comes verbatim from the signed `BundleBody`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BundleView {
    pub file_id: String,
    pub file_type: String,
    pub version: u64,
    pub members: Vec<BundleMemberView>,
    /// `true` iff THIS user authored the bundle (`my_id == author.user_id`).
    /// Gates the owner-only "Delete bundle" affordance (bundles Task 6.2); the
    /// server cascades member deletion.
    pub mine: bool,
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
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UploadKind {
    Image,
    Blog,
    Video,
    Generic,
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

/// A tally of a bundle's members by kind. Order-private: this carries only how
/// many members of each kind a bundle groups — never the member order itself.
/// A seam DTO: plain counts, no key material. Defaults to all-zeros.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemberCounts {
    pub video: u32,
    pub image: u32,
    pub blog: u32,
    pub generic: u32,
}

/// One member of a bundle being staged, mirroring [`StageUploadRequest`]'s
/// per-item fields. A seam DTO: plain data only, no key material, no identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleMemberInput {
    pub kind: UploadKind,
    /// For an image / video / generic member: a filesystem path to the source
    /// file. Ignored for blogs.
    #[serde(default)]
    pub path: Option<String>,
    /// For a blog member: the post body text. Ignored for other kinds.
    #[serde(default)]
    pub content: Option<String>,
    /// For a video member: the transcode shaping. Absent → default. Ignored
    /// otherwise.
    #[serde(default)]
    pub options: Option<TranscodeOptions>,
    pub title: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// A request to stage (but not yet upload) a bundle — its own title/tags plus an
/// ordered list of members. A seam DTO: plain data only, no key material.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StageBundleRequest {
    pub title: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub members: Vec<BundleMemberInput>,
    /// Index (into `members`) of the member whose thumbnail becomes the bundle's
    /// own cover/index preview (rendered on the bundle's feed card). Must point at
    /// a member that produces a thumbnail (image/video); otherwise the bundle gets
    /// no cover. `None` ⇒ no cover (the card falls back to the member previews).
    #[serde(default)]
    pub cover_index: Option<usize>,
}

/// A preview of a staged-but-not-uploaded bundle: a per-member preview list plus
/// the order-private [`MemberCounts`] tally. A seam DTO: no key material, only
/// what the UI renders before the user confirms.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundlePreview {
    pub job_id: String,
    pub member_previews: Vec<UploadPreview>,
    pub counts: MemberCounts,
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

#[derive(Debug, Clone, Deserialize)]
pub struct ResolveRecipientRequest {
    pub username: String,
}

/// A resolved potential share recipient — display-only, no key material. The
/// UI shows `fingerprint` as a non-secret verification tick and disables the
/// "add" affordance when `already_shared` is true.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ResolvedRecipientDto {
    pub username: String,
    pub user_id: String,      // hex16, opaque to the UI
    pub fingerprint: String,  // first 8 bytes hex, display-only
    pub already_shared: bool, // cross-checked against list_recipients
}

/// A known contact (roster row) for the share checklist — display-only, no key
/// material. This roster carries no `already_shared` flag; the dialog computes
/// access itself by cross-checking `user_id` against `list_file_recipients`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ContactDto {
    pub username: String,
    pub user_id: String,     // hex16, opaque to the UI
    pub fingerprint: String, // first 8 bytes hex, display-only
}

/// A request to share an already-uploaded file with more recipients. Carries
/// only the requested usernames; the command re-resolves and re-verifies each
/// one under the pinned D5 at share-time rather than trusting the picker's
/// earlier resolve — this closes a TOCTOU window where a binding could be
/// re-signed/rotated between picker-open and Share-click.
#[derive(Debug, Clone, Deserialize)]
pub struct ReshareRequest {
    pub file_id: String,
    pub recipient_usernames: Vec<String>,
}

/// The outcome of `request_recovery_challenge` — an opaque status handle plus the
/// server's public self-asserted id. Carries NO nonce and NO key material: the
/// unwrapped challenge nonce and the cold recovery Identity stay entirely in
/// Rust-managed state.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RecoveryChallengeDto {
    pub status: String,
    pub server_id: String,
}

/// The outcome of `answer_recovery_challenge` — success establishes an ADMIN
/// session (stored where normal sessions live). No key material; the recovery
/// private key never crosses this boundary.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RecoveryLoginDto {
    pub status: String,
    pub server_id: String,
}

/// The startup screen the client should open, chosen by file-presence precedence
/// (spec §5 / §0-D7): a cold recovery keyblob → `Recovery` (WINS even if a register
/// key is also present), else a single-use registration key → `Register`, else
/// `Normal` (keystore-unlock + connect). Serializes to a bare lowercase string
/// (`"recovery"` / `"register"` / `"normal"`) — the ONLY thing that crosses the
/// seam. No key material, no file contents.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StartupMode {
    Recovery,
    Register,
    Normal,
}

/// The per-recipient outcome of a `reshare` call — one entry per requested
/// username, in request order. No key material; `code` is a sanitized failure
/// code (no oracle), `None` on success.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReshareOutcomeDto {
    pub username: String,
    pub ok: bool,
    pub code: Option<String>, // sanitized failure code, None on success
}

#[cfg(test)]
mod reshare_dto_tests {
    use super::*;

    #[test]
    fn resolve_recipient_request_roundtrips() {
        let j = r#"{"username":"bob"}"#;
        let req: ResolveRecipientRequest = serde_json::from_str(j).unwrap();
        assert_eq!(req.username, "bob");
    }

    #[test]
    fn resolved_recipient_dto_serializes_all_fields() {
        let dto = ResolvedRecipientDto {
            username: "bob".into(),
            user_id: "ab".repeat(8),
            fingerprint: "deadbeefcafebabe".into(),
            already_shared: false,
        };
        let s = serde_json::to_string(&dto).unwrap();
        // Round-trip through serde_json::Value since the DTO is UI-bound
        // (Serialize-only, like its CardDto/FeedEntryDto siblings).
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["username"], "bob");
        assert_eq!(v["user_id"], "ab".repeat(8));
        assert_eq!(v["fingerprint"], "deadbeefcafebabe");
        assert_eq!(v["already_shared"], false);
    }

    #[test]
    fn opened_content_dto_can_share_is_not_ownership_gated() {
        // Per D-OQ3: `can_share` is set on ANY successful open (the caller holds
        // a wrap), regardless of `mine`/ownership — there is no separate
        // ownership field on this DTO at all, so a `true` value here must not be
        // read as "I am the author". This test just pins the serialized shape.
        let dto = OpenedContentDto {
            file_id: "ab".repeat(8),
            file_type: "blog".into(),
            version: 1,
            title: "hello".into(),
            tags: vec![],
            image_png_b64: None,
            blog_text: Some("hi".into()),
            author_fp: "deadbeef".into(),
            recovery_ok: true,
            can_share: true,
            mine: false,
        };
        let s = serde_json::to_string(&dto).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["can_share"], true);
        // `mine` is a distinct, independent flag from `can_share` (D-OQ3): a
        // non-owner wrap-holder still gets `can_share: true` but `mine: false`.
        assert_eq!(v["mine"], false);
    }

    #[test]
    fn recovery_dtos_serialize_without_key_material() {
        let ch = RecoveryChallengeDto {
            status: "challenge-ready".into(),
            server_id: "maxsecu-1".into(),
        };
        let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&ch).unwrap()).unwrap();
        assert_eq!(v["status"], "challenge-ready");
        assert_eq!(v["server_id"], "maxsecu-1");
        // Exactly two fields — no nonce/token/key ever leaks onto the DTO.
        assert_eq!(v.as_object().unwrap().len(), 2);

        let login = RecoveryLoginDto {
            status: "admin-session".into(),
            server_id: "maxsecu-1".into(),
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&login).unwrap()).unwrap();
        assert_eq!(v["status"], "admin-session");
        assert_eq!(v.as_object().unwrap().len(), 2);
    }

    #[test]
    fn contact_dto_serializes_all_fields() {
        let dto = ContactDto {
            username: "bob".into(),
            user_id: "ab".repeat(8),
            fingerprint: "deadbeefcafebabe".into(),
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&dto).unwrap()).unwrap();
        assert_eq!(v["username"], "bob");
        assert_eq!(v["user_id"], "ab".repeat(8));
        assert_eq!(v["fingerprint"], "deadbeefcafebabe");
    }

    #[test]
    fn bundle_dtos_serde_round_trip() {
        let req = StageBundleRequest {
            title: "Trip".into(),
            tags: vec!["a".into()],
            members: vec![
                BundleMemberInput {
                    kind: UploadKind::Image,
                    path: Some("p.png".into()),
                    content: None,
                    options: None,
                    title: "m1".into(),
                    tags: vec![],
                },
                BundleMemberInput {
                    kind: UploadKind::Generic,
                    path: Some("it.pdf".into()),
                    content: None,
                    options: None,
                    title: "m2".into(),
                    tags: vec![],
                },
            ],
            cover_index: Some(0),
        };
        let back: StageBundleRequest =
            serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(back, req);

        let prev = BundlePreview {
            job_id: "j".into(),
            member_previews: vec![],
            counts: MemberCounts {
                video: 1,
                image: 2,
                blog: 0,
                generic: 3,
            },
        };
        let back2: BundlePreview =
            serde_json::from_str(&serde_json::to_string(&prev).unwrap()).unwrap();
        assert_eq!(back2, prev);
    }

    #[test]
    fn reshare_request_roundtrips() {
        let j = r#"{"file_id":"ab","recipient_usernames":["bob","carol"]}"#;
        let req: ReshareRequest = serde_json::from_str(j).unwrap();
        assert_eq!(req.file_id, "ab");
        assert_eq!(req.recipient_usernames, vec!["bob", "carol"]);
    }

    #[test]
    fn reshare_outcome_dto_serializes_all_fields() {
        let ok = ReshareOutcomeDto {
            username: "bob".into(),
            ok: true,
            code: None,
        };
        let s = serde_json::to_string(&ok).unwrap();
        assert!(s.contains("\"code\":null"), "got {s}");
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["username"], "bob");
        assert_eq!(v["ok"], true);
        assert!(v["code"].is_null());

        let failed = ReshareOutcomeDto {
            username: "carol".into(),
            ok: false,
            code: Some("not_found".into()),
        };
        let s = serde_json::to_string(&failed).unwrap();
        assert!(s.contains("\"code\":\"not_found\""), "got {s}");
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["username"], "carol");
        assert_eq!(v["ok"], false);
        assert_eq!(v["code"], "not_found");
    }
}
