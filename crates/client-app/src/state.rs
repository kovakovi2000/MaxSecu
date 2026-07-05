//! Typed connection/auth states streamed to the UI as events. The UI binds them
//! to <status-pill>/<conn-banner>; every transition is serializable and
//! non-color-only (the UI adds icon+text).

use serde::Serialize;

/// The H.264 encoder the runtime ladder settled on (probed once per session so later
/// uploads skip dead GPU rungs). `None` until the first re-encode probes it. Held in an
/// `Arc<Mutex<_>>` so it can be cloned into any `spawn_blocking` context.
#[derive(Clone, Default)]
pub struct H264EncoderCache(
    pub std::sync::Arc<std::sync::Mutex<Option<maxsecu_media_launcher::H264Encoder>>>,
);

pub const EVT_CONNECTION: &str = "maxsecu://connection-state";
pub const EVT_AUTH: &str = "maxsecu://auth-state";

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

pub const EVT_BUNDLE_STAGE: &str = "maxsecu://bundle-stage";

/// Per-member progress for the bundle composer's staging pass (the "Preparing
/// preview…" / "Preparing bundle…" step in `stage_bundle`), which stages members
/// sequentially and can be slow when a member is a video (confined transcode).
/// Emitted over [`EVT_BUNDLE_STAGE`] so the composer can show which member of how
/// many is currently being prepared instead of a static spinner. For a video
/// member, the finer transcode progress still arrives over [`EVT_VIDEO_PREPARE`].
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "phase")]
pub enum BundleStagePhase {
    /// Now staging member `index` of `total` (both 1-based). `title` is the
    /// member's user-supplied title (no secret) for the progress read-out.
    Member {
        index: usize,
        total: usize,
        title: String,
    },
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
/// event bus. Non-color-only: each variant carries a stable `phase` code.
pub const EVT_PLAYER: &str = "maxsecu://player-state";

/// The video player's state machine (spec §6/§7). Emitted over [`EVT_PLAYER`];
/// the UI binds an error banner. `Error` carries a sanitized code (no decode
/// oracle).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "phase")]
pub enum PlayerPhase {
    /// Failed with a sanitized code (no oracle). Also the benign terminal for a
    /// user cancel (`code = "cancelled"`).
    Error { code: String },
}

/// The post-upload multi-recipient reshare feedback channel (spec §6) — per-file,
/// per-recipient progress for the share UI. Emitted over the Tauri event bus; the
/// UI binds a progress meter + per-recipient badge. Non-color-only: each variant
/// carries a stable `phase` code.
pub const EVT_RESHARE: &str = "maxsecu://reshare-state";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "phase")]
pub enum SharePhase {
    /// Resolving a recipient username to a directory binding.
    Resolving { file_id: String, username: String },
    /// Verifying the resolved recipient's binding under the pinned D5.
    Verifying { file_id: String, username: String },
    /// Wrapping the DEK to the verified recipient's public key.
    Wrapping { file_id: String, username: String },
    /// One recipient's outcome — `ok` with a sanitized `code` on failure (no oracle).
    Recipient {
        file_id: String,
        username: String,
        ok: bool,
        code: Option<String>,
    },
    /// Done — the reshare call has finished; `shared`/`failed` tally the recipients.
    Done {
        file_id: String,
        shared: u32,
        failed: u32,
    },
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
    /// Bootstrapping the in-process Tor client (TorOnly route, first connect only —
    /// the client is then reused). Slow; the UI shows a distinct "connecting to Tor"
    /// state. Emitted before TlsHandshake when the route is TorOnly.
    TorBootstrapping,
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

    #[test]
    fn bundle_stage_phase_serializes_kebab_tagged() {
        let s = serde_json::to_string(&BundleStagePhase::Member {
            index: 2,
            total: 5,
            title: "My Video".into(),
        })
        .unwrap();
        assert!(s.contains("\"phase\":\"member\""), "got {s}");
        assert!(s.contains("\"index\":2") && s.contains("\"total\":5"), "got {s}");
        assert!(s.contains("\"title\":\"My Video\""), "got {s}");
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
mod share_phase_tests {
    use super::*;

    #[test]
    fn share_phase_serializes_kebab_tagged() {
        let s = serde_json::to_string(&SharePhase::Resolving {
            file_id: "ab".into(),
            username: "bob".into(),
        })
        .unwrap();
        assert!(s.contains("\"phase\":\"resolving\""), "got {s}");
        assert!(s.contains("\"file_id\":\"ab\"") && s.contains("\"username\":\"bob\""));

        let s = serde_json::to_string(&SharePhase::Verifying {
            file_id: "ab".into(),
            username: "bob".into(),
        })
        .unwrap();
        assert!(s.contains("\"phase\":\"verifying\""), "got {s}");

        let s = serde_json::to_string(&SharePhase::Wrapping {
            file_id: "ab".into(),
            username: "bob".into(),
        })
        .unwrap();
        assert!(s.contains("\"phase\":\"wrapping\""), "got {s}");

        let ok = serde_json::to_string(&SharePhase::Recipient {
            file_id: "ab".into(),
            username: "bob".into(),
            ok: true,
            code: None,
        })
        .unwrap();
        assert!(ok.contains("\"phase\":\"recipient\""), "got {ok}");
        assert!(ok.contains("\"ok\":true") && ok.contains("\"code\":null"));

        let failed = serde_json::to_string(&SharePhase::Recipient {
            file_id: "ab".into(),
            username: "carol".into(),
            ok: false,
            code: Some("not_found".into()),
        })
        .unwrap();
        assert!(failed.contains("\"ok\":false") && failed.contains("\"code\":\"not_found\""));

        let d = serde_json::to_string(&SharePhase::Done {
            file_id: "ab".into(),
            shared: 2,
            failed: 1,
        })
        .unwrap();
        assert!(d.contains("\"phase\":\"done\""), "got {d}");
        assert!(d.contains("\"shared\":2") && d.contains("\"failed\":1"));
    }
}
