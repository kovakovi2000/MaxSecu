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
        // Collapse every core error to a single non-oracle shape per kind.
        // Phase 1 only distinguishes the two the UI must act on; everything
        // else is a generic failure (no detail leaks).
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
