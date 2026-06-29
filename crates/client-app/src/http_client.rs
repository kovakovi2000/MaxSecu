//! Thin typed JSON-over-HTTP/1.1 helpers used by the Phase-2 commands on top of
//! an already-established pinned-TLS connection (transport.rs). Only DTOs cross —
//! never key material.

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, StatusCode};

use crate::error::UiError;

/// POST a JSON body; return `(status, json)`. `bearer` adds the channel-bound
/// `Authorization: MaxSecu-Session <hex>` header when `Some`. `host` is the
/// connect host (cert-SAN/SNI name) threaded into the `Host` header so the
/// future manual-connect screen can target a real server domain.
pub async fn post_json(
    sender: &mut SendRequest<Full<Bytes>>,
    uri: &str,
    body: &serde_json::Value,
    bearer: Option<&str>,
    host: &str,
) -> Result<(StatusCode, serde_json::Value), UiError> {
    send(sender, "POST", uri, Some(body), bearer, host).await
}

/// GET and return `(status, json)`. `host` is the connect host threaded into the
/// `Host` header (see [`post_json`]).
pub async fn get_json(
    sender: &mut SendRequest<Full<Bytes>>,
    uri: &str,
    bearer: Option<&str>,
    host: &str,
) -> Result<(StatusCode, serde_json::Value), UiError> {
    send(sender, "GET", uri, None, bearer, host).await
}

/// GET a raw `application/octet-stream` body (a ciphertext chunk); return
/// `(status, bytes)`. `bearer` adds the channel-bound `Authorization` header.
/// `host` is the connect host threaded into the `Host` header (see [`post_json`]).
pub async fn get_bytes(
    sender: &mut SendRequest<Full<Bytes>>,
    uri: &str,
    bearer: Option<&str>,
    host: &str,
) -> Result<(StatusCode, Vec<u8>), UiError> {
    sender
        .ready()
        .await
        .map_err(|_| UiError::new("offline", "Lost connection to the server."))?;
    let mut builder = Request::builder()
        .method("GET")
        .uri(uri)
        .header("host", host);
    if let Some(tok) = bearer {
        builder = builder.header("authorization", format!("MaxSecu-Session {tok}"));
    }
    let req = builder
        .body(Full::new(Bytes::new()))
        .map_err(|_| UiError::new("internal", "Could not build the request."))?;
    let resp = sender
        .send_request(req)
        .await
        .map_err(|_| UiError::new("offline", "The server did not respond."))?;
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|_| UiError::new("offline", "The response was interrupted."))?
        .to_bytes()
        .to_vec();
    Ok((status, bytes))
}

async fn send(
    sender: &mut SendRequest<Full<Bytes>>,
    method: &str,
    uri: &str,
    body: Option<&serde_json::Value>,
    bearer: Option<&str>,
    host: &str,
) -> Result<(StatusCode, serde_json::Value), UiError> {
    sender
        .ready()
        .await
        .map_err(|_| UiError::new("offline", "Lost connection to the server."))?;
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", host);
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    if let Some(tok) = bearer {
        builder = builder.header("authorization", format!("MaxSecu-Session {tok}"));
    }
    let payload = body.map(|b| Bytes::from(b.to_string())).unwrap_or_default();
    let req = builder
        .body(Full::new(payload))
        .map_err(|_| UiError::new("internal", "Could not build the request."))?;
    let resp = sender
        .send_request(req)
        .await
        .map_err(|_| UiError::new("offline", "The server did not respond."))?;
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|_| UiError::new("offline", "The response was interrupted."))?
        .to_bytes();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    Ok((status, json))
}

#[cfg(test)]
mod tests {
    #[test]
    fn module_compiles() {
        // Behavior is exercised by the e2e (live TLS); this guards the surface.
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn get_bytes_is_exposed() {
        // Compile-time guard that the raw-bytes accessor exists with the expected
        // signature (mirrors get_json: sender, uri, bearer, host -> (status,
        // bytes)); behavior is exercised over live TLS by the Phase-3 e2e.
        // Returning (not binding) the future avoids clippy::let_underscore_future.
        fn _assert_sig(
            s: &mut hyper::client::conn::http1::SendRequest<
                http_body_util::Full<hyper::body::Bytes>,
            >,
        ) -> impl std::future::Future<
            Output = Result<(hyper::StatusCode, Vec<u8>), crate::error::UiError>,
        > + '_ {
            super::get_bytes(s, "/x", None, "localhost")
        }
        assert_eq!(2 + 2, 4);
    }
}
