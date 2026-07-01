//! Typed connection/auth states streamed to the UI as events. The UI binds them
//! to <status-pill>/<conn-banner>; every transition is serializable and
//! non-color-only (the UI adds icon+text).

use serde::Serialize;

pub const EVT_CONNECTION: &str = "maxsecu://connection-state";
pub const EVT_AUTH: &str = "maxsecu://auth-state";
pub const EVT_ACCOUNT: &str = "maxsecu://account-state";

/// The fetch/decrypt feedback channel (spec §6) — per-file progress for the
/// viewer. Emitted over the Tauri event bus; the UI binds a progress meter +
/// per-item badge. Non-color-only: each variant carries a stable phase code.
pub const EVT_FETCH: &str = "maxsecu://fetch-state";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "phase")]
pub enum FetchPhase {
    /// Fetching ciphertext (optionally with cold-fetch progress).
    Fetching {
        file_id: String,
        fetched: u64,
        total: u64,
    },
    /// Running the §12.5 verify ladder.
    Verifying { file_id: String },
    /// Shaping the verified+decrypted content for display.
    Decrypting { file_id: String },
    /// Done — the content is ready to render.
    Ready { file_id: String },
    /// Failed with a sanitized code (no oracle).
    Failed { file_id: String, code: String },
}

/// The upload feedback channel (spec §6) — per-job progress for the active-uploads
/// tray. Emitted over the Tauri event bus; the UI binds a progress meter + badge.
/// Non-color-only: each variant carries a stable `phase` code.
pub const EVT_UPLOAD: &str = "maxsecu://upload-state";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "phase")]
pub enum UploadPhase {
    /// Transcoding/encrypting locally (before any network write).
    Encrypting { job_id: String },
    /// Staging the version (POST /v1/files).
    Staging { job_id: String },
    /// Uploading ciphertext chunks (resumable). `bytes_per_s` is a rolling
    /// throughput estimate (0 for the small image/blog path; live MB/s for video).
    Uploading {
        job_id: String,
        done: u64,
        total: u64,
        bytes_per_s: u64,
    },
    /// Finalizing the version.
    Finalizing { job_id: String },
    /// Done — the file is committed.
    Done { job_id: String, file_id: String },
    /// Failed with a sanitized code (no oracle).
    Failed { job_id: String, code: String },
}

/// The video **prepare** (author-side transcode) feedback channel — per-job progress
/// for the confined ffmpeg ingest + re-mux that runs inside `stage_upload` for a
/// video (before any bundle exists). Emitted over the Tauri event bus so the upload
/// UI can show a live progress bar + a Cancel affordance during the slow confined
/// transcode. Non-color-only: each variant carries a stable `phase` code.
///
/// # Contract (consumed by the UI task)
/// * Event name: [`EVT_VIDEO_PREPARE`] = `"maxsecu://video-prepare"`.
/// * Payload: this [`PreparePhase`], kebab-tagged on `"phase"` — exactly:
///   - `{"phase":"transcoding","percent":<0..=100|null>}` (percent is `null` until
///     ffmpeg reports the source duration),
///   - `{"phase":"remuxing"}`,
///   - `{"phase":"finalizing"}`,
///   - `{"phase":"cancelled"}` (benign terminal after a cancel),
///   - `{"phase":"failed","code":"<code>"}` (sanitized terminal).
/// * Cancel: the `cancel_video_prepare` command (no args) cancels the in-flight
///   transcode; `stage_upload` then returns `UiError{code:"cancelled"}` (benign — the
///   UI returns to idle), while a real failure returns `UiError{code:"video_failed"}`.
pub const EVT_VIDEO_PREPARE: &str = "maxsecu://video-prepare";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "phase")]
pub enum PreparePhase {
    /// Confined ffmpeg transcode in progress; `percent` is `None` until the source
    /// duration is known (then `0..=100`).
    Transcoding { percent: Option<u8> },
    /// Re-muxing ffmpeg's output into canonical AV1/CMAF fragments (second confined
    /// spawn).
    Remuxing,
    /// Deriving thumbnail/preview + validating the fragment index (final local step).
    Finalizing,
    /// Benign terminal: the user (or app shutdown) cancelled the transcode.
    Cancelled,
    /// Sanitized terminal failure (no decode oracle) — carries a stable code.
    Failed { code: String },
}

/// The sandboxed-video player feedback channel (Phase 7, Gate 4) — per-file
/// playback state for the `<media-viewer>` video surface. Emitted over the Tauri
/// event bus alongside the decoded frame/PCM DTOs (`EVT_VIDEO_FRAME`/
/// `EVT_VIDEO_AUDIO`). Non-color-only: each variant carries a stable `phase` code.
pub const EVT_PLAYER: &str = "maxsecu://player-state";

/// Decoded-frame channel: one [`crate::commands::video::I420FrameDto`] per
/// re-validated frame the confined worker produced (the UI uploads its planes to
/// a WebGL texture in Gate 5). Carries NO key material — only RAM-only pixels.
pub const EVT_VIDEO_FRAME: &str = "maxsecu://video-frame";

/// Decoded-audio channel: one [`crate::commands::video::PcmDto`] per re-validated
/// PCM chunk (the UI feeds it to WebAudio in Gate 5).
pub const EVT_VIDEO_AUDIO: &str = "maxsecu://video-audio";

/// One-shot per-open metadata for the player UI (scrubber max + timer denominator).
pub const EVT_VIDEO_INFO: &str = "maxsecu://video-info";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VideoInfo {
    pub duration_ms: u64,
    pub fragment_count: u32,
}

/// The video player's state machine (spec §6/§7). Emitted over [`EVT_PLAYER`];
/// the UI binds a buffering spinner / play state / error banner. `Error` carries a
/// sanitized code (no decode oracle); `CodecUnavailable` is the honest
/// player-gated terminal when the confined worker is not present.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "phase")]
pub enum PlayerPhase {
    /// Decrypting + decoding the current bounded window before frames flow.
    Buffering,
    /// Frames are flowing (the window decoded + re-validated).
    Playing,
    /// A BENIGN, non-terminal notice that the per-fragment resilient decode dropped
    /// `skipped` fragment(s) whose confined worker aborted (the F1 rav1d panic / F2
    /// stsz-OOM Job-kill): the rest of the window still decoded, so playback is a
    /// brief gap (the surviving frames pace by their `pts_ms`), not a failure. Carries
    /// only the COUNT — no decode oracle / per-fragment detail.
    Gap { skipped: u32 },
    /// Awaiting the next window / data underrun (non-terminal).
    Stalled,
    /// Failed with a sanitized code (no oracle). Also the benign terminal for a
    /// user cancel (`code = "cancelled"`).
    Error { code: String },
    /// The confined video worker is unavailable (player gated, D-B).
    CodecUnavailable,
}

// The complete connection-state vocabulary streamed to the UI. `connect` emits
// the connect-flow subset (Resolving/TlsHandshake/ChannelBinding/Connected/
// Disconnected); Idle/Reconnecting/Degraded are emitted by the reconnect +
// health logic added in a later phase.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "state")]
pub enum ConnectionState {
    Idle,
    Resolving,
    TlsHandshake,
    ChannelBinding,
    Connected,
    Reconnecting,
    Disconnected,
    Degraded,
}

// The complete auth-state vocabulary. `connect` emits Authenticating/LoggedIn/
// LoggedOut; UnlockingKeystore/SessionExpired/Reauthenticating are emitted by
// the unlock UI + session-expiry/re-auth logic added in a later phase.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "state")]
pub enum AuthState {
    LoggedOut,
    UnlockingKeystore,
    Authenticating,
    LoggedIn,
    SessionExpired,
    Reauthenticating,
}

/// Approval status for the signed-in account (D-G). `Pending` shows the
/// status-only screen; `Active` unlocks the app. `Unknown` is the pre-poll
/// default.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "state")]
pub enum AccountState {
    Unknown,
    Pending,
    Active,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_serialize_kebab_tagged() {
        let j = serde_json::to_string(&ConnectionState::TlsHandshake).unwrap();
        assert_eq!(j, "{\"state\":\"tls-handshake\"}");
        let j = serde_json::to_string(&AuthState::UnlockingKeystore).unwrap();
        assert_eq!(j, "{\"state\":\"unlocking-keystore\"}");
    }

    #[test]
    fn account_state_serializes_kebab_tagged() {
        assert_eq!(
            serde_json::to_string(&AccountState::Pending).unwrap(),
            "{\"state\":\"pending\"}"
        );
    }
}

#[cfg(test)]
mod fetch_tests {
    use super::*;

    #[test]
    fn fetch_phase_serializes_kebab_tagged() {
        let v = FetchPhase::Verifying {
            file_id: "aa".into(),
        };
        let s = serde_json::to_string(&v).unwrap();
        assert!(s.contains("\"phase\":\"verifying\""));
        assert!(s.contains("\"file_id\":\"aa\""));
    }
}

#[cfg(test)]
mod player_phase_tests {
    use super::*;

    #[test]
    fn player_phase_serializes_kebab_tagged() {
        assert_eq!(
            serde_json::to_string(&PlayerPhase::Buffering).unwrap(),
            "{\"phase\":\"buffering\"}"
        );
        assert_eq!(
            serde_json::to_string(&PlayerPhase::Playing).unwrap(),
            "{\"phase\":\"playing\"}"
        );
        assert_eq!(
            serde_json::to_string(&PlayerPhase::CodecUnavailable).unwrap(),
            "{\"phase\":\"codec-unavailable\"}"
        );
        let e = serde_json::to_string(&PlayerPhase::Error {
            code: "cancelled".into(),
        })
        .unwrap();
        assert!(e.contains("\"phase\":\"error\"") && e.contains("\"code\":\"cancelled\""));
    }
}

#[cfg(test)]
mod prepare_phase_tests {
    use super::*;

    #[test]
    fn prepare_phase_serializes_kebab_tagged() {
        // percent present.
        let s = serde_json::to_string(&PreparePhase::Transcoding { percent: Some(42) }).unwrap();
        assert!(s.contains("\"phase\":\"transcoding\""), "got {s}");
        assert!(s.contains("\"percent\":42"), "got {s}");
        // percent unknown → null.
        let s = serde_json::to_string(&PreparePhase::Transcoding { percent: None }).unwrap();
        assert!(s.contains("\"percent\":null"), "got {s}");
        assert_eq!(
            serde_json::to_string(&PreparePhase::Remuxing).unwrap(),
            "{\"phase\":\"remuxing\"}"
        );
        assert_eq!(
            serde_json::to_string(&PreparePhase::Finalizing).unwrap(),
            "{\"phase\":\"finalizing\"}"
        );
        assert_eq!(
            serde_json::to_string(&PreparePhase::Cancelled).unwrap(),
            "{\"phase\":\"cancelled\"}"
        );
        let f = serde_json::to_string(&PreparePhase::Failed {
            code: "video_failed".into(),
        })
        .unwrap();
        assert!(f.contains("\"phase\":\"failed\"") && f.contains("\"code\":\"video_failed\""));
    }
}

#[cfg(test)]
mod upload_phase_tests {
    use super::*;

    #[test]
    fn upload_phase_serializes_kebab_tagged() {
        let s = serde_json::to_string(&UploadPhase::Uploading {
            job_id: "j".into(),
            done: 2,
            total: 5,
            bytes_per_s: 3_000_000,
        })
        .unwrap();
        assert!(s.contains("\"phase\":\"uploading\""), "got {s}");
        assert!(s.contains("\"done\":2") && s.contains("\"total\":5"));
        assert!(s.contains("\"bytes_per_s\":3000000"), "got {s}");
        let d = serde_json::to_string(&UploadPhase::Done {
            job_id: "j".into(),
            file_id: "ab".into(),
        })
        .unwrap();
        assert!(d.contains("\"phase\":\"done\"") && d.contains("\"file_id\":\"ab\""));
    }
}

#[cfg(test)]
mod video_info_tests {
    use super::*;
    #[test]
    fn video_info_serializes() {
        let s = serde_json::to_string(&VideoInfo { duration_ms: 59000, fragment_count: 5 }).unwrap();
        assert!(s.contains("\"duration_ms\":59000"));
        assert!(s.contains("\"fragment_count\":5"));
    }
}
