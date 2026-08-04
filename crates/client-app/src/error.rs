//! Sanitized error surface for the command boundary. The UI must never receive
//! internal detail (paths, crypto internals) — only a stable machine code +
//! short message, mirroring the server's sanitized model (api.md §3).

use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UiError {
    pub code: String,
    pub message: String,
    /// Seconds the SERVER asked us to wait (its `Retry-After` header), carried
    /// only by the `rate_limited` (HTTP 429) shape so the caller can back off for
    /// the real interval instead of guessing — and so the UI can tell the user
    /// how long to wait. `None` for every other error, and then `skip`ped, so an
    /// existing error's JSON across the Tauri seam stays byte-identical
    /// (`{"code":…,"message":…}`) for any already-shipped `ui/dist`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_s: Option<u64>,
}

impl UiError {
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retry_after_s: None,
        }
    }

    /// Attach the server's `Retry-After` seconds (see [`UiError::retry_after_s`]).
    /// `None` leaves the error's wire shape untouched.
    pub fn with_retry_after(mut self, retry_after_s: Option<u64>) -> Self {
        self.retry_after_s = retry_after_s;
        self
    }
}

// NB: there is deliberately NO blanket `impl From<maxsecu_client_core::ClientError>
// for UiError`. One used to exist and collapsed every unmapped core error to
// `unauthorized`/"Sign-in failed." — its own comment warned that a non-login error
// would then be reported to the user as a credential failure, and that is exactly
// the misdiagnosis it caused (a throttled read looked like a wrong password). It had
// no call sites. Every site must map its core error EXPLICITLY via `UiError::new`
// with the code that actually describes the failure (`offline`, `rate_limited`,
// `verify_failed`, …).

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

    /// The new `retry_after_s` field must be INVISIBLE unless it is set, so an
    /// already-shipped `ui/dist` sees exactly the two keys it has always seen.
    #[test]
    fn retry_after_is_omitted_unless_set_and_present_when_set() {
        let plain = serde_json::to_value(UiError::new("offline", "No connection.")).unwrap();
        assert_eq!(
            plain.as_object().unwrap().len(),
            2,
            "an ordinary error must still serialize as exactly {{code, message}}"
        );
        let throttled = serde_json::to_value(
            UiError::new("rate_limited", "Too many attempts.").with_retry_after(Some(37)),
        )
        .unwrap();
        assert_eq!(throttled["retry_after_s"], 37);
        assert_eq!(throttled["code"], "rate_limited");
    }
}
