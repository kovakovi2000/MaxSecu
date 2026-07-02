//! `GET /v1/files/{file_id}/recipients` — read a file's current recipient set,
//! used by the share picker for duplicate/idempotency awareness (spec
//! `2026-07-02-multi-recipient-sharing-design.md` §2.2, §2.4 gap 7): before
//! offering "Share" against an already-verified username, the picker cross-checks
//! the resolved `user_id` against this list and shows an inline "Already has
//! access" note (never a hard block — re-sharing is an idempotent no-op
//! server-side, `Store::add_wrap` "replaces an existing row").
//!
//! # Fail-open by design (for this ONE purpose only)
//! The server endpoint is owner-only and returns `404` — deliberately
//! indistinguishable — for both a missing file and a non-owner caller (no access
//! oracle, mirrors `AddWrapError::NoAccess`). This wrapper treats that `404`, any
//! other non-`200` status, a transport failure, and a malformed body identically:
//! an empty result. Duplicate-awareness is a UX nicety, not a correctness
//! requirement, so a caller here must NEVER be blocked from sharing by this call
//! failing — it degrades to "unknown who already has access" and lets every
//! entered recipient proceed as a fresh (or harmlessly idempotent) share.

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;

use crate::commands::feed::hex16;
use crate::http_client::get_json;

/// One recipient row from the server's response. Only `user_id` is needed for
/// duplicate-awareness today; the server also returns `granted_by`/grant bytes/
/// `ancestor_grants` (used elsewhere, e.g. rotation carry-forward) but those are
/// not parsed here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientRow {
    pub user_id: [u8; 16],
}

/// Fetch the file's current recipients. Returns an empty `Vec` — never an
/// `Err` — for a `404` (no oracle: missing file or non-owner caller), any other
/// non-`200`, a transport error, or a malformed body. See the module doc for why
/// this must fail open.
pub async fn list_recipients(
    sender: &mut SendRequest<Full<Bytes>>,
    file_id_hex: &str,
    bearer: &str,
    host: &str,
) -> Vec<RecipientRow> {
    let uri = format!("/v1/files/{file_id_hex}/recipients");
    let Ok((status, json)) = get_json(sender, &uri, Some(bearer), host).await else {
        return Vec::new();
    };
    if status != hyper::StatusCode::OK {
        return Vec::new();
    }
    let Some(entries) = json.get("recipients").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|r| {
            let id_hex = r.get("recipient_id")?.as_str()?;
            let user_id = hex16(id_hex).ok()?;
            Some(RecipientRow { user_id })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use hyper::server::conn::http1 as server_http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use tokio::net::TcpListener;

    /// A tiny in-process HTTP/1.1 stub returning a fixed `(status, json body)` to
    /// every request, standing in for the pinned server connection (mirrors
    /// `direct_link.rs`'s `StubServer`/`spawn_stub`/`connect` test harness).
    async fn spawn_stub(status: hyper::StatusCode, body: serde_json::Value) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (socket, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let status = status;
                let body = body.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                        let body = body.clone();
                        async move {
                            // Drain the body (never inspected — a bare GET has none anyway).
                            let _ = req.into_body().collect().await;
                            let resp = Response::builder()
                                .status(status)
                                .body(Full::<Bytes>::from(body.to_string()))
                                .unwrap();
                            Ok::<_, Infallible>(resp)
                        }
                    });
                    let _ = server_http1::Builder::new()
                        .serve_connection(TokioIo::new(socket), svc)
                        .await;
                });
            }
        });
        format!("127.0.0.1:{}", addr.port())
    }

    async fn connect(addr: &str) -> SendRequest<Full<Bytes>> {
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        sender
    }

    #[tokio::test]
    async fn ok_response_yields_parsed_recipient_user_ids() {
        let body = serde_json::json!({
            "recipients": [
                {
                    "recipient_id": "0a".repeat(16),
                    "granted_by": "0b".repeat(16),
                    "grant_b64": "AA==",
                    "grant_sig_b64": "AA==",
                    "ancestor_grants": [],
                },
                {
                    "recipient_id": "0c".repeat(16),
                    "granted_by": "0b".repeat(16),
                    "grant_b64": "AA==",
                    "grant_sig_b64": "AA==",
                    "ancestor_grants": [],
                },
            ]
        });
        let addr = spawn_stub(hyper::StatusCode::OK, body).await;
        let mut sender = connect(&addr).await;

        let rows = list_recipients(&mut sender, &"ff".repeat(16), "tok", "localhost").await;

        assert_eq!(rows.len(), 2, "both recipient rows are parsed");
        assert_eq!(rows[0].user_id, [0x0a; 16]);
        assert_eq!(rows[1].user_id, [0x0c; 16]);
    }

    #[tokio::test]
    async fn not_found_degrades_to_empty_never_a_hard_error() {
        // Owner-only, no-oracle 404 — could mean "missing file" or "not the
        // owner"; either way this must never surface as an error the picker has
        // to handle, only an empty "unknown" result.
        let addr = spawn_stub(hyper::StatusCode::NOT_FOUND, serde_json::Value::Null).await;
        let mut sender = connect(&addr).await;

        let rows = list_recipients(&mut sender, &"ff".repeat(16), "tok", "localhost").await;

        assert!(rows.is_empty());
    }

    #[tokio::test]
    async fn malformed_body_degrades_to_empty() {
        // A 200 with a body that isn't the expected {"recipients": [...]} shape
        // (e.g. a proxy/misconfiguration) must not panic or bubble an error.
        let addr = spawn_stub(hyper::StatusCode::OK, serde_json::json!({ "unexpected": true })).await;
        let mut sender = connect(&addr).await;

        let rows = list_recipients(&mut sender, &"ff".repeat(16), "tok", "localhost").await;

        assert!(rows.is_empty());
    }
}
