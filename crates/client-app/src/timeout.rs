//! A tiny timeout wrapper for the connect path. arti's bootstrap, the Tor dial,
//! and the TLS handshake have no natural short timeout of their own — a slow or
//! exit-policy-blocked circuit would otherwise hang `connect()` forever and leave
//! the login screen on a dead spinner. `with_deadline` bounds each so a stall
//! surfaces as a prompt, sanitized `UiError` instead.

use std::future::Future;
use std::time::Duration;

use crate::error::UiError;

/// Max time to bootstrap the shared Tor client (cold consensus fetch). Generous:
/// a first arti bootstrap genuinely can take 30–60s.
pub(crate) const TOR_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(60);
/// Max time to open a Tor circuit stream to the server once bootstrapped.
pub(crate) const TOR_DIAL_TIMEOUT: Duration = Duration::from_secs(30);
/// Max time for the pinned TLS 1.3 handshake over an already-dialed stream.
pub(crate) const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Await `fut` but give up after `dur`, returning `on_timeout` if it elapses.
/// `fut` already yields the domain `Result<T, UiError>`; a timeout replaces it
/// with the caller's sanitized timeout error so the UI shows a clear message.
pub(crate) async fn with_deadline<T>(
    dur: Duration,
    fut: impl Future<Output = Result<T, UiError>>,
    on_timeout: UiError,
) -> Result<T, UiError> {
    match tokio::time::timeout(dur, fut).await {
        Ok(res) => res,
        Err(_) => Err(on_timeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn returns_the_inner_value_when_it_resolves_in_time() {
        let out = with_deadline(
            Duration::from_secs(5),
            async { Ok::<u32, UiError>(7) },
            UiError::new("tor_timeout", "should not fire"),
        )
        .await;
        assert_eq!(out.unwrap(), 7);
    }

    #[tokio::test]
    async fn returns_the_timeout_error_when_the_future_stalls() {
        let out = with_deadline::<u32>(
            Duration::from_millis(20),
            std::future::pending(),
            UiError::new("tor_timeout", "Connecting to the Tor network timed out."),
        )
        .await;
        let err = out.expect_err("a pending future must time out");
        assert_eq!(err.code, "tor_timeout");
    }

    #[tokio::test]
    async fn propagates_an_inner_error_unchanged() {
        let out = with_deadline::<u32>(
            Duration::from_secs(5),
            async { Err(UiError::new("offline", "inner")) },
            UiError::new("tor_timeout", "should not fire"),
        )
        .await;
        assert_eq!(out.unwrap_err().code, "offline");
    }
}
