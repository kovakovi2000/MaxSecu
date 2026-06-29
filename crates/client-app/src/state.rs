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
    /// Uploading ciphertext chunks (resumable).
    Uploading {
        job_id: String,
        done: u64,
        total: u64,
    },
    /// Finalizing the version.
    Finalizing { job_id: String },
    /// Done — the file is committed.
    Done { job_id: String, file_id: String },
    /// Failed with a sanitized code (no oracle).
    Failed { job_id: String, code: String },
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
mod upload_phase_tests {
    use super::*;

    #[test]
    fn upload_phase_serializes_kebab_tagged() {
        let s = serde_json::to_string(&UploadPhase::Uploading {
            job_id: "j".into(),
            done: 2,
            total: 5,
        })
        .unwrap();
        assert!(s.contains("\"phase\":\"uploading\""), "got {s}");
        assert!(s.contains("\"done\":2") && s.contains("\"total\":5"));
        let d = serde_json::to_string(&UploadPhase::Done {
            job_id: "j".into(),
            file_id: "ab".into(),
        })
        .unwrap();
        assert!(d.contains("\"phase\":\"done\"") && d.contains("\"file_id\":\"ab\""));
    }
}
