//! Sanitized error surface for the command boundary. The UI must never receive
//! internal detail (paths, crypto internals) — only a stable machine code +
//! short message, mirroring the server's sanitized model (api.md §3).

use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UiError {
    pub code: String,
    pub message: String,
}

impl UiError {
    pub fn new(code: &str, message: &str) -> Self {
        Self { code: code.into(), message: message.into() }
    }
}

impl From<maxsecu_client_core::ClientError> for UiError {
    fn from(_e: maxsecu_client_core::ClientError) -> Self {
        // Fallback `?` converter: any unmapped core error collapses to the
        // generic fail-closed unauthorized shape, leaking no detail. There is
        // deliberately no per-kind branching here. Call sites that need a
        // specific code (e.g. weak_password, no_keystore, offline) must map
        // explicitly via `UiError::new` instead of relying on `?` — otherwise a
        // non-login error would surface to the user as "Sign-in failed."
        UiError::new("unauthorized", "Sign-in failed.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uierror_is_stable_shape() {
        let e = UiError::new("offline", "No connection.");
        assert_eq!(e.code, "offline");
        let j = serde_json::to_string(&e).unwrap();
        assert!(j.contains("\"code\":\"offline\""));
        assert!(j.contains("\"message\""));
    }
}
