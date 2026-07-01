//! Download orchestration: turn the server's opaque §8.5 file view + a D5-verified
//! author into the `client-core` `DownloadBundle`/`StreamHeader` + `VerifyContext`
//! the verify ladder consumes. Pure parsing/assembly here; the verify ladder lives
//! in client-core. Only verified, render-ready results ever reach a command.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;

use maxsecu_client_core::{DownloadBundle, StreamChunks, StreamHeader};
use maxsecu_crypto::WrappedDek;
use maxsecu_encoding::types::StreamType;

use crate::error::UiError;
use crate::http_client::get_bytes;

/// One stream's wire descriptor from a §8.5 file view (no values).
#[derive(Debug)]
pub struct StreamSpec {
    pub stream_type: StreamType,
    pub chunk_count: u64,
    pub chunk_size: u64,
}

/// The parsed, non-secret framing of a file view: which streams exist + the
/// verification records, ready to drive header/content fetches. The wrap and
/// grant bytes are inert (the recipient re-verifies them); they never reach the UI.
#[derive(Debug)]
pub struct ParsedView {
    pub version: u64,
    pub manifest_bytes: Vec<u8>,
    pub manifest_sig: [u8; 64],
    pub genesis_bytes: Vec<u8>,
    pub genesis_sig: [u8; 64],
    pub wrapped_dek: WrappedDek,
    pub grant_bytes: Vec<u8>,
    pub grant_sig: [u8; 64],
    pub ancestor_grants: Vec<(Vec<u8>, [u8; 64])>,
    pub recovery_grant_bytes: Vec<u8>,
    pub recovery_grant_sig: [u8; 64],
    pub streams: Vec<StreamSpec>,
}

fn stream_type_from_name(s: &str) -> Option<StreamType> {
    match s {
        "content" => Some(StreamType::Content),
        "metadata" => Some(StreamType::Metadata),
        "thumbnail" => Some(StreamType::Thumbnail),
        "preview" => Some(StreamType::Preview),
        _ => None,
    }
}

fn dec(json: &serde_json::Value, key: &str) -> Result<Vec<u8>, UiError> {
    B64.decode(json[key].as_str().ok_or_else(bad)?)
        .map_err(|_| bad())
}
fn dec64(json: &serde_json::Value, key: &str) -> Result<[u8; 64], UiError> {
    dec(json, key)?.try_into().map_err(|_| bad())
}
fn bad() -> UiError {
    UiError::new("fetch_failed", "The server sent a malformed file record.")
}

/// Rebuild the `enc(32) ‖ ct` wire wrap into a `WrappedDek`.
fn wrap_from_bytes(b: &[u8]) -> Result<WrappedDek, UiError> {
    if b.len() < 32 {
        return Err(bad());
    }
    Ok(WrappedDek {
        enc: b[..32].try_into().map_err(|_| bad())?,
        ct: b[32..].to_vec(),
    })
}

/// Parse a §8.5 `FileRes` JSON body into a `ParsedView` (no network, no decrypt).
pub fn parse_file_view(json: &serde_json::Value) -> Result<ParsedView, UiError> {
    let mw = &json["my_wrap"];
    let ancestor_grants = mw["ancestor_grants"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|g| Ok((dec(g, "grant_b64")?, dec64(g, "grant_sig_b64")?)))
                .collect::<Result<Vec<_>, UiError>>()
        })
        .transpose()?
        .unwrap_or_default();
    let (recovery_grant_bytes, recovery_grant_sig) = match json.get("recovery_grant") {
        Some(rg) if !rg.is_null() => (dec(rg, "grant_b64")?, dec64(rg, "grant_sig_b64")?),
        _ => (Vec::new(), [0u8; 64]),
    };
    let mut streams = Vec::new();
    for s in json["streams"].as_array().ok_or_else(bad)? {
        let name = s["stream_type"].as_str().ok_or_else(bad)?;
        let st = stream_type_from_name(name).ok_or_else(bad)?;
        streams.push(StreamSpec {
            stream_type: st,
            chunk_count: s["chunk_count"].as_u64().ok_or_else(bad)?,
            chunk_size: s["chunk_size"].as_u64().ok_or_else(bad)?,
        });
    }
    Ok(ParsedView {
        version: json["version"].as_u64().ok_or_else(bad)?,
        manifest_bytes: dec(json, "manifest_b64")?,
        manifest_sig: dec64(json, "manifest_sig_b64")?,
        genesis_bytes: dec(json, "genesis_b64")?,
        genesis_sig: dec64(json, "genesis_sig_b64")?,
        wrapped_dek: wrap_from_bytes(&dec(mw, "wrapped_dek_b64")?)?,
        grant_bytes: dec(mw, "grant_b64")?,
        grant_sig: dec64(mw, "grant_sig_b64")?,
        ancestor_grants,
        recovery_grant_bytes,
        recovery_grant_sig,
        streams,
    })
}

fn stream_name(st: StreamType) -> &'static str {
    match st {
        StreamType::Content => "content",
        StreamType::Metadata => "metadata",
        StreamType::Thumbnail => "thumbnail",
        StreamType::Preview => "preview",
    }
}

/// GET every ciphertext chunk of one stream (authed) for `file_id_hex`/`version`.
/// `host` is threaded into the Host header (see http_client::get_bytes).
pub async fn fetch_stream_chunks(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    token: &str,
    file_id_hex: &str,
    version: u64,
    spec: &StreamSpec,
) -> Result<StreamChunks, UiError> {
    // No eager capacity hint: `chunk_count` is the UNSIGNED §8.5 listing value
    // (attacker-controlled, read before verification) — a huge value would panic
    // (capacity overflow) or OOM. The loop self-bounds: the first out-of-range
    // chunk GET returns non-OK and errors out.
    let mut chunks = Vec::new();
    for i in 0..spec.chunk_count {
        let uri = format!(
            "/v1/files/{file_id_hex}/versions/{version}/streams/{}/chunks/{i}",
            stream_name(spec.stream_type)
        );
        let (status, bytes) = get_bytes(sender, &uri, Some(token), host).await?;
        if status != hyper::StatusCode::OK {
            return Err(UiError::new(
                "fetch_failed",
                "A content chunk could not be fetched.",
            ));
        }
        chunks.push(bytes);
    }
    Ok(StreamChunks {
        stream_type: spec.stream_type,
        chunks,
    })
}

/// Build a header-only `StreamHeader` (NON-content streams only) from a parsed
/// view — for `decrypt_card`. Fetches only `metadata`/`thumbnail`/`preview`.
pub async fn build_stream_header(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    token: &str,
    file_id_hex: &str,
    view: &ParsedView,
) -> Result<StreamHeader, UiError> {
    let mut small = Vec::new();
    for spec in view
        .streams
        .iter()
        .filter(|s| s.stream_type != StreamType::Content)
    {
        small
            .push(fetch_stream_chunks(sender, host, token, file_id_hex, view.version, spec).await?);
    }
    Ok(StreamHeader {
        manifest_bytes: view.manifest_bytes.clone(),
        manifest_sig: view.manifest_sig,
        genesis_bytes: view.genesis_bytes.clone(),
        genesis_sig: view.genesis_sig,
        wrapped_dek: view.wrapped_dek.clone(),
        grant_bytes: view.grant_bytes.clone(),
        grant_sig: view.grant_sig,
        ancestor_grants: view.ancestor_grants.clone(),
        recovery_grant_bytes: view.recovery_grant_bytes.clone(),
        recovery_grant_sig: view.recovery_grant_sig,
        small_streams: small,
    })
}

/// Build a full `DownloadBundle` (ALL streams) from a parsed view — for the viewer.
pub async fn build_download_bundle(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    token: &str,
    file_id_hex: &str,
    view: &ParsedView,
) -> Result<DownloadBundle, UiError> {
    let mut streams = Vec::new();
    for spec in &view.streams {
        streams
            .push(fetch_stream_chunks(sender, host, token, file_id_hex, view.version, spec).await?);
    }
    Ok(DownloadBundle {
        manifest_bytes: view.manifest_bytes.clone(),
        manifest_sig: view.manifest_sig,
        genesis_bytes: view.genesis_bytes.clone(),
        genesis_sig: view.genesis_sig,
        wrapped_dek: view.wrapped_dek.clone(),
        grant_bytes: view.grant_bytes.clone(),
        grant_sig: view.grant_sig,
        ancestor_grants: view.ancestor_grants.clone(),
        recovery_grant_bytes: view.recovery_grant_bytes.clone(),
        recovery_grant_sig: view.recovery_grant_sig,
        streams,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view_json() -> serde_json::Value {
        serde_json::json!({
            "version": 1,
            "manifest_b64": B64.encode([1u8; 8]),
            "manifest_sig_b64": B64.encode([2u8; 64]),
            "genesis_b64": B64.encode([3u8; 8]),
            "genesis_sig_b64": B64.encode([4u8; 64]),
            "my_wrap": {
                "wrapped_dek_b64": B64.encode([9u8; 64]), // 32 enc + 32 ct
                "grant_b64": B64.encode([5u8; 8]),
                "grant_sig_b64": B64.encode([6u8; 64]),
                "ancestor_grants": []
            },
            "recovery_grant": { "grant_b64": B64.encode([7u8; 8]), "grant_sig_b64": B64.encode([8u8; 64]) },
            "streams": [
                { "stream_type": "content", "chunk_count": 3, "chunk_size": 4096, "blob_ref": "x" },
                { "stream_type": "metadata", "chunk_count": 1, "chunk_size": 4096, "blob_ref": "y" }
            ]
        })
    }

    #[test]
    fn parses_a_well_formed_view() {
        let p = parse_file_view(&view_json()).unwrap();
        assert_eq!(p.version, 1);
        assert_eq!(p.wrapped_dek.enc, [9u8; 32]);
        assert_eq!(p.wrapped_dek.ct, vec![9u8; 32]);
        assert_eq!(p.streams.len(), 2);
        assert_eq!(p.streams[0].stream_type, StreamType::Content);
        assert_eq!(p.streams[0].chunk_count, 3);
    }

    #[test]
    fn missing_recovery_grant_is_tolerated() {
        let mut j = view_json();
        j["recovery_grant"] = serde_json::Value::Null;
        let p = parse_file_view(&j).unwrap();
        assert!(p.recovery_grant_bytes.is_empty());
    }

    #[test]
    fn malformed_view_is_a_sanitized_error() {
        let bad = serde_json::json!({ "version": "nope" });
        assert_eq!(parse_file_view(&bad).unwrap_err().code, "fetch_failed");
    }

    #[test]
    fn parses_content_chunk_size() {
        let p = parse_file_view(&view_json()).unwrap();
        let content = p
            .streams
            .iter()
            .find(|s| s.stream_type == StreamType::Content)
            .unwrap();
        assert_eq!(content.chunk_size, 4096);
    }
}
