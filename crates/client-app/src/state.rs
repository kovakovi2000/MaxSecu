//! Typed connection/auth states streamed to the UI as events. The UI binds them
//! to <status-pill>/<conn-banner>; every transition is serializable and
//! non-color-only (the UI adds icon+text).

use serde::Serialize;

pub const EVT_CONNECTION: &str = "maxsecu://connection-state";
pub const EVT_AUTH: &str = "maxsecu://auth-state";

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
