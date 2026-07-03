//! Plain data crossing the Tauri command boundary. No key material, no
//! signed-record interiors, no whole-plaintext buffers ever appear here.

use serde::{Deserialize, Serialize};
use std::fmt;

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
    /// Display metadata for the Share affordance (T4, D-OQ3): `true` whenever
    /// this open succeeded, i.e. the caller holds a wrap for this item. Per the
    /// locked decision, Share is available to ANY wrap-holder who can open the
    /// content — NOT gated on `my_id == author.user_id` (ownership). This is
    /// therefore always `true` on a successful `OpenedContentDto`; there is no
    /// partial-open path that would set it `false`.
    pub can_share: bool,
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

/// The per-recipient outcome of a `reshare` call — one entry per requested
/// username, in request order. No key material; `code` is a sanitized failure
/// code (no oracle), `None` on success.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReshareOutcomeDto {
    pub username: String,
    pub ok: bool,
    pub code: Option<String>, // sanitized failure code, None on success
}

// --- T6 Shamir recovery-key ceremony DTOs (spec §8) ---------------------
//
// DTO rule for this feature (extends the file-level rule above): individual
// MSHARE1 share-text strings ARE allowed to cross the seam (§2.1 — any single
// share below `k` is information-theoretically indistinguishable from random),
// as is the initial-secret unseal passphrase (loaded/zeroized inside the
// command, per D-B). The **reconstructed whole key never crosses the seam** —
// `reconstruct_recovery_key` returns only an opaque `ceremony_handle` into the
// server-side `CeremonySession`.
//
// `SplitRecoveryKeyRequest`/`AddShareRequest` carry secret-ish text
// (passphrase / share text) but must never have a `Debug` that could dump it
// into a panic/log, so — unlike the spec's own listing, which shows `Debug`
// on both — they get a manual redacting `Debug` here instead of the derive.

/// Split an existing sealed recovery secret into `n` MSHARE1 shares, any `k`
/// of which later reconstruct it. `recovery_secret_path` + `passphrase` are
/// loaded/unsealed and zeroized entirely inside the command — neither the raw
/// scalar nor (after this DTO is consumed) the passphrase persists anywhere.
#[derive(Clone, Deserialize)]
pub struct SplitRecoveryKeyRequest {
    pub recovery_secret_path: String, // local file path; loaded + zeroized inside the command
    pub passphrase: String, // D-B: unseals the sealed recovery-secret file; zeroized in the command
    pub label: String,      // non-secret, operator-chosen (§5)
    pub k: u8,
    pub n: u8,
}

impl fmt::Debug for SplitRecoveryKeyRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SplitRecoveryKeyRequest")
            .field("recovery_secret_path", &self.recovery_secret_path)
            .field("passphrase", &"<redacted>")
            .field("label", &self.label)
            .field("k", &self.k)
            .field("n", &self.n)
            .finish()
    }
}

#[derive(Clone, Serialize)]
pub struct SplitRecoveryKeyResponse {
    pub shares: Vec<String>, // §5 wire-encoded MSHARE1 strings — the interchange unit, not raw Share bytes
    pub label: String,
    pub k: u8,
    pub n: u8,
}

impl fmt::Debug for SplitRecoveryKeyResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `shares` are MSHARE1 share text — the same sensitive class as
        // `AddShareRequest.share_text` — so elide them (count only), per the
        // spec §8 prose rule + §11 checklist ("never derive/implement Debug in
        // a way that would dump share bytes"). Non-secret label/k/n are shown.
        f.debug_struct("SplitRecoveryKeyResponse")
            .field("shares", &format!("<{} shares>", self.shares.len()))
            .field("label", &self.label)
            .field("k", &self.k)
            .field("n", &self.n)
            .finish()
    }
}

/// One MSHARE1 share pasted/loaded by the reconstructing custodian.
#[derive(Clone, Deserialize)]
pub struct AddShareRequest {
    pub share_text: String, // one §5 MSHARE1 string
}

impl fmt::Debug for AddShareRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddShareRequest")
            .field("share_text", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AddShareResponse {
    pub have: u8,
    pub need: u8,
    pub label: String,
}

/// The outcome of a successful reconstruct. Carries only an opaque handle
/// into `CeremonySession` — never the reconstructed key bytes (§8 DTO rule).
#[derive(Debug, Clone, Serialize)]
pub struct ReconstructResponse {
    pub ceremony_handle: String, // opaque id into CeremonySession — NEVER the key bytes
    pub label: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProveRequest {
    /// Which in-session reconstruction to prove — the opaque handle minted by
    /// `reconstruct_recovery_key` (`ReconstructResponse.ceremony_handle`). Spec
    /// §8's DTO listing omits this, but the proof MUST know WHICH reconstructed
    /// `EncSecretKey` to test (the session holds a `HashMap<handle, key>`), so
    /// it is carried here. It is an opaque, non-secret id — plain `Debug` is fine.
    pub ceremony_handle: String,
    pub file_id_hex: String,
    pub version: u64,
    pub dek_commit_hex: String,
    pub recovery_wrap_b64: String, // the wire wrap `enc(32) ‖ ct` (recovery.rs:151-162 wire form)
}

#[derive(Debug, Clone, Serialize)]
pub struct ProveResponse {
    pub verified: bool,
}

/// A non-secret record of an operator's EXPLICIT completion of a split
/// ceremony (spec §4 step 5): who/when, `k`/`n`, which custodian indices were
/// issued, and the label. Every field here is ordinary metadata — there is NO
/// share body / secret field on this DTO by construction (the wizard never
/// passes share bytes into `record_split_ceremony`), so plain derived `Debug`
/// is fine, unlike `SplitRecoveryKeyRequest`/`AddShareRequest` above.
#[derive(Debug, Clone, Deserialize)]
pub struct SplitCeremonyLogRequest {
    pub log_path: String, // operator-chosen local file to append to
    pub label: String,    // the §5 non-secret label
    pub k: u8,
    pub n: u8,
    pub custodian_indices: Vec<u8>, // which share indices were issued (non-secret)
    pub operator: Option<String>,   // who (operator-entered; offline, no server identity)
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
        };
        let s = serde_json::to_string(&dto).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["can_share"], true);
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

#[cfg(test)]
mod recovery_ceremony_dto_tests {
    use super::*;

    #[test]
    fn split_recovery_key_request_roundtrips() {
        let j = r#"{"recovery_secret_path":"/tmp/recovery.sealed","passphrase":"hunter2","label":"MaxSecu recovery key, 2026-07","k":3,"n":5}"#;
        let req: SplitRecoveryKeyRequest = serde_json::from_str(j).unwrap();
        assert_eq!(req.recovery_secret_path, "/tmp/recovery.sealed");
        assert_eq!(req.passphrase, "hunter2");
        assert_eq!(req.label, "MaxSecu recovery key, 2026-07");
        assert_eq!(req.k, 3);
        assert_eq!(req.n, 5);
    }

    #[test]
    fn split_recovery_key_request_debug_redacts_passphrase() {
        let req = SplitRecoveryKeyRequest {
            recovery_secret_path: "/tmp/recovery.sealed".into(),
            passphrase: "hunter2".into(),
            label: "label".into(),
            k: 3,
            n: 5,
        };
        let d = format!("{req:?}");
        assert!(!d.contains("hunter2"), "passphrase leaked into Debug: {d}");
        assert!(d.contains("<redacted>"), "got {d}");
        // Non-secret fields still show up (helps debugging without leaking).
        assert!(d.contains("/tmp/recovery.sealed"));
    }

    #[test]
    fn split_recovery_key_response_serializes_all_fields() {
        let resp = SplitRecoveryKeyResponse {
            shares: vec!["MSHARE1:...".into(), "MSHARE1:...".into()],
            label: "label".into(),
            k: 3,
            n: 5,
        };
        let s = serde_json::to_string(&resp).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["shares"].as_array().unwrap().len(), 2);
        assert_eq!(v["label"], "label");
        assert_eq!(v["k"], 3);
        assert_eq!(v["n"], 5);
    }

    #[test]
    fn split_recovery_key_response_debug_redacts_share_text() {
        let resp = SplitRecoveryKeyResponse {
            shares: vec![
                "MSHARE1:bGFiZWw:3:5:1:c2VjcmV0Ym9keQ:deadbeef".into(),
                "MSHARE1:bGFiZWw:3:5:2:YW5vdGhlcmJvZHk:cafebabe".into(),
            ],
            label: "label".into(),
            k: 3,
            n: 5,
        };
        let d = format!("{resp:?}");
        assert!(!d.contains("MSHARE1"), "share text leaked into Debug: {d}");
        assert!(!d.contains("c2VjcmV0Ym9keQ"), "share body leaked: {d}");
        assert!(d.contains("<2 shares>"), "got {d}");
        // Non-secret fields still show up.
        assert!(d.contains("label"));
    }

    #[test]
    fn add_share_request_roundtrips_and_redacts_debug() {
        let j = r#"{"share_text":"MSHARE1:bGFiZWw:3:5:1:Ym9keQ:deadbeef"}"#;
        let req: AddShareRequest = serde_json::from_str(j).unwrap();
        assert_eq!(req.share_text, "MSHARE1:bGFiZWw:3:5:1:Ym9keQ:deadbeef");
        let d = format!("{req:?}");
        assert!(!d.contains("MSHARE1"), "share text leaked into Debug: {d}");
        assert!(d.contains("<redacted>"), "got {d}");
    }

    #[test]
    fn add_share_response_serializes_all_fields() {
        let resp = AddShareResponse {
            have: 2,
            need: 3,
            label: "label".into(),
        };
        let s = serde_json::to_string(&resp).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["have"], 2);
        assert_eq!(v["need"], 3);
        assert_eq!(v["label"], "label");
    }

    #[test]
    fn reconstruct_response_serializes_all_fields_no_key_bytes() {
        let resp = ReconstructResponse {
            ceremony_handle: "a1b2c3".into(),
            label: "label".into(),
        };
        let s = serde_json::to_string(&resp).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["ceremony_handle"], "a1b2c3");
        assert_eq!(v["label"], "label");
        // Only the two documented fields — no room for a smuggled key field.
        assert_eq!(v.as_object().unwrap().len(), 2);
    }

    #[test]
    fn prove_request_roundtrips() {
        let j = r#"{"ceremony_handle":"a1b2c3","file_id_hex":"ab","version":7,"dek_commit_hex":"cd","recovery_wrap_b64":"ZWY"}"#;
        let req: ProveRequest = serde_json::from_str(j).unwrap();
        assert_eq!(req.ceremony_handle, "a1b2c3");
        assert_eq!(req.file_id_hex, "ab");
        assert_eq!(req.version, 7);
        assert_eq!(req.dek_commit_hex, "cd");
        assert_eq!(req.recovery_wrap_b64, "ZWY");
    }

    #[test]
    fn prove_response_serializes() {
        let resp = ProveResponse { verified: true };
        let s = serde_json::to_string(&resp).unwrap();
        assert_eq!(s, r#"{"verified":true}"#);
    }

    #[test]
    fn split_ceremony_log_request_roundtrips() {
        let j = r#"{"log_path":"/tmp/ceremony.log","label":"MaxSecu recovery key, 2026-07","k":3,"n":5,"custodian_indices":[1,2,3,4,5],"operator":"alice"}"#;
        let req: SplitCeremonyLogRequest = serde_json::from_str(j).unwrap();
        assert_eq!(req.log_path, "/tmp/ceremony.log");
        assert_eq!(req.label, "MaxSecu recovery key, 2026-07");
        assert_eq!(req.k, 3);
        assert_eq!(req.n, 5);
        assert_eq!(req.custodian_indices, vec![1, 2, 3, 4, 5]);
        assert_eq!(req.operator.as_deref(), Some("alice"));
    }

    #[test]
    fn split_ceremony_log_request_operator_is_optional() {
        let j = r#"{"log_path":"/tmp/ceremony.log","label":"label","k":2,"n":3,"custodian_indices":[1,2],"operator":null}"#;
        let req: SplitCeremonyLogRequest = serde_json::from_str(j).unwrap();
        assert_eq!(req.operator, None);
    }
}
