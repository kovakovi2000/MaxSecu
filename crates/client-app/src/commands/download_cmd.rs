//! The `download_content` command: verify + decrypt any post's ORIGINAL and write
//! the plaintext to disk. Image/blog write the whole content plaintext in one go;
//! video/generic stream chunk-by-chunk (O(one content chunk) RAM) reusing the same
//! verify ladder + in-TCB `ContentDecryptor` the player uses. Opened by the
//! REQUESTED id (content-substitution safe). Only DTOs/primitives cross the seam —
//! the `ContentDecryptor`/`Identity`/plaintext-DEK never do.

use std::io::Write;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;
use tauri::State;

use maxsecu_client_core::{open_content_decryptor, DirectoryVerifier, MemoryTrustStore};
use maxsecu_encoding::decode;
use maxsecu_encoding::structs::Manifest;
use maxsecu_encoding::types::{FileType, StreamType};

use crate::commands::auth::{AppDir, ConnectLock, Session};
use crate::commands::connection::{reauth, server_of};
use crate::commands::feed::{hex, hex16, now_ms};
use crate::commands::viewer::run_open;
use crate::config::{load_directory_pub, RouteMode, SettingsConfig};
use crate::directory::{
    resolve_and_verify_author_logged, resolve_my_user_id, VerifiedAuthor,
};
use crate::download::{build_download_bundle, build_stream_header, parse_file_view};
use crate::dto::DownloadRequest;
use crate::error::UiError;
use crate::http_client::get_json;

/// Suggest a save-as filename for a downloaded post from its authenticated
/// metadata JSON (`{"title","tags"}` for image/blog/video, `{"title","tags",
/// "filename"}` for generic). Image→`<title>.png`, video→`<title>.mp4`,
/// blog→`<title>.txt`, generic→the original `filename` (fallback `<title>` else
/// `download.bin`), bundle→`"bundle"` (bundles download per-member, not directly).
/// The title/filename are sanitized into a safe, non-path-traversing name.
pub fn suggested_filename(file_type: FileType, metadata_json: &[u8]) -> String {
    let v: serde_json::Value =
        serde_json::from_slice(metadata_json).unwrap_or(serde_json::Value::Null);
    let title = sanitize_name(v.get("title").and_then(|t| t.as_str()).unwrap_or(""));
    match file_type {
        FileType::Image => with_ext(&title, "png"),
        FileType::Video => with_ext(&title, "mp4"),
        FileType::Blog => with_ext(&title, "txt"),
        FileType::Generic => {
            let filename = v
                .get("filename")
                .and_then(|f| f.as_str())
                .map(sanitize_name)
                .unwrap_or_default();
            if !filename.is_empty() {
                filename
            } else if !title.is_empty() {
                title
            } else {
                "download.bin".to_owned()
            }
        }
        // A bundle is a container — its members download individually.
        FileType::Bundle => "bundle".to_owned(),
    }
}

/// `<title>.<ext>`, or `download.<ext>` when the (sanitized) title is blank.
fn with_ext(title: &str, ext: &str) -> String {
    if title.is_empty() {
        format!("download.{ext}")
    } else {
        format!("{title}.{ext}")
    }
}

/// Strip anything that could make `raw` a path-traversing / illegal filename:
/// path separators, drive/stream colons, the Windows-reserved glob chars, and any
/// control chars; then trim surrounding whitespace and dots (so a name can never
/// be `.`/`..` or a hidden dotfile). Keeps the interior extension dot intact.
fn sanitize_name(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| {
            !c.is_control() && !matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
        })
        .collect();
    cleaned.trim().trim_matches('.').trim().to_owned()
}

fn write_failed() -> UiError {
    UiError::new("write_failed", "Could not write the file to disk.")
}

/// `download_content` — verify + decrypt the REQUESTED post's original and write
/// the plaintext to `req.save_path`. Image/blog write the whole content plaintext;
/// video/generic stream the content chunk-by-chunk (O(one chunk) RAM). Any
/// wrap-holder who can open the content is authorized (open success == authorized).
/// Returns the written `save_path`. Sanitized errors (no decode/verify oracle).
#[tauri::command]
pub async fn download_content(
    req: DownloadRequest,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
) -> Result<String, UiError> {
    // Validate the REQUESTED id up front: it is the id the served record must bind
    // to (via `build_verify_ctx`) and it is interpolated into the request URL.
    let file_id = hex16(&req.file_id)?;
    let file_id_hex = hex(&file_id);

    let pinned = load_directory_pub(&dir.0)?;
    let verifier = DirectoryVerifier::new(pinned);
    let mut trust = MemoryTrustStore::new();
    let now = now_ms();

    let username = {
        let s = session.0.lock().await;
        s.username.clone()
    }
    .ok_or_else(|| UiError::new("locked", "Sign in first."))?;

    let server = server_of(&dir.0)?;
    let (mut sender, host, token) = reauth(&dir.0, &server, &session, &connect_lock).await?;

    let (status, view_json) = get_json(
        &mut sender,
        &format!("/v1/files/{file_id_hex}?version=latest"),
        Some(&token),
        &host,
    )
    .await?;
    if status != hyper::StatusCode::OK {
        return Err(UiError::new("fetch_failed", "That item is not available."));
    }
    let view = parse_file_view(&view_json)?;
    let manifest: Manifest =
        decode(&view.manifest_bytes).map_err(|_| UiError::new("untrusted", "Malformed record."))?;

    // Bundles are containers — nothing to download directly; the UI downloads each
    // member by its own id instead.
    if manifest.file_type == FileType::Bundle {
        return Err(UiError::new(
            "bad_request",
            "Download members individually.",
        ));
    }

    // D5-verify the author binding (fail-closed) BEFORE any decode/decrypt, then
    // enforce key-transparency (opt-in) exactly as the viewer/player do.
    let (author, author_binding) = resolve_and_verify_author_logged(
        &mut sender,
        &host,
        &hex(&manifest.author_id.0),
        &verifier,
        &mut trust,
        now,
    )
    .await?;
    crate::commands::feed::enforce_author_transparency(&dir.0, session.inner(), author_binding)
        .await?;
    let my_id =
        resolve_my_user_id(&mut sender, &host, &username, &verifier, &mut trust, now).await?;

    let route_mode = SettingsConfig::load(&dir.0).connection.route_mode;

    match manifest.file_type {
        // Whole-content types: reuse the viewer's verify ladder, take the Content
        // stream plaintext, and write it whole.
        FileType::Image | FileType::Blog => {
            download_whole(
                &mut sender,
                &host,
                &token,
                &req,
                file_id,
                &view,
                &author,
                my_id,
                &session,
                route_mode,
            )
            .await
        }
        // Streaming types (video AND generic store their original as the content
        // stream): derive the in-TCB `ContentDecryptor` and stream every content
        // chunk to disk, one chunk in RAM.
        FileType::Video | FileType::Generic => {
            download_streaming(
                &mut sender,
                &host,
                &token,
                &req,
                file_id,
                &file_id_hex,
                &view,
                &author,
                my_id,
                &session,
                route_mode,
            )
            .await
        }
        FileType::Bundle => unreachable!("bundle handled above"),
    }
}

/// Image/blog: fetch the whole download bundle, verify+decrypt via the SHARED
/// `run_open` (identical verify ladder + content-substitution binding the viewer
/// uses), and write the Content stream plaintext whole to `save_path`. A direct-
/// sourced bundle that fails verification is refetched forced-proxy and retried
/// once (fail-closed fallback — the link source is untrusted).
#[allow(clippy::too_many_arguments)]
async fn download_whole(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    token: &str,
    req: &DownloadRequest,
    file_id: [u8; 16],
    view: &crate::download::ParsedView,
    author: &VerifiedAuthor,
    my_id: [u8; 16],
    session: &State<'_, Session>,
    route_mode: RouteMode,
) -> Result<String, UiError> {
    let direct_http = crate::direct_link::shared_direct_http();
    let (bundle, bundle_used_direct) = build_download_bundle(
        sender,
        host,
        token,
        &req.file_id,
        view,
        route_mode,
        direct_http,
    )
    .await?;

    // Borrow the unlocked identity UNDER the session lock across the SYNCHRONOUS
    // verify (no await) — the identity never crosses the seam and its borrow never
    // spans an await.
    let attempt = {
        let guard = session.0.lock().await;
        let identity = guard
            .identity
            .as_ref()
            .ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?;
        run_open(identity, file_id, author, my_id, &bundle)
    };
    let opened = match attempt {
        Ok(o) => o,
        Err(e) if bundle_used_direct => {
            let (bundle, _) = build_download_bundle(
                sender,
                host,
                token,
                &req.file_id,
                view,
                RouteMode::PreferServer,
                None,
            )
            .await?;
            let guard = session.0.lock().await;
            let identity = guard
                .identity
                .as_ref()
                .ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?;
            run_open(identity, file_id, author, my_id, &bundle).map_err(|_| e)?
        }
        Err(e) => return Err(e),
    };

    let content = opened
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Content)
        .ok_or_else(|| UiError::new("verify_failed", "Missing content."))?;

    let mut file = std::fs::File::create(&req.save_path).map_err(|_| write_failed())?;
    file.write_all(&content.plaintext).map_err(|_| write_failed())?;
    file.flush().map_err(|_| write_failed())?;
    Ok(req.save_path.clone())
}

/// Video/generic: derive the in-TCB `ContentDecryptor` (the SAME header ladder the
/// player uses, minus the fragment index — a linear download needs no seek index)
/// and stream every content chunk to disk. Fetches each chunk's CIPHERTEXT
/// (direct-link-preferring, forced-proxy fallback on AEAD failure), decrypts it in
/// the TCB with the per-chunk AEAD, and appends the plaintext — O(one chunk) RAM.
#[allow(clippy::too_many_arguments)]
async fn download_streaming(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    token: &str,
    req: &DownloadRequest,
    file_id: [u8; 16],
    file_id_hex: &str,
    view: &crate::download::ParsedView,
    author: &VerifiedAuthor,
    my_id: [u8; 16],
    session: &State<'_, Session>,
    route_mode: RouteMode,
) -> Result<String, UiError> {
    let direct_http = crate::direct_link::shared_direct_http();

    // Header (small streams only — no content fetched). Prefer the direct route.
    let (header, header_used_direct) =
        build_stream_header(sender, host, token, &req.file_id, view, route_mode, direct_http)
            .await?;

    // Derive the decryptor under the session lock (sync verify; the identity borrow
    // never spans an await). A direct-sourced header that fails verification is
    // refetched forced-proxy and retried once (fail-closed fallback). The decryptor
    // OWNS the content subkey — it, not the identity, is used across the fetch loop.
    let decryptor = {
        let attempt = {
            let guard = session.0.lock().await;
            let identity = guard
                .identity
                .as_ref()
                .ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?;
            let ctx = crate::directory::build_verify_ctx(file_id, author, my_id, identity);
            open_content_decryptor(&ctx, &header)
        };
        match attempt {
            Ok(d) => d,
            Err(_) if header_used_direct => {
                let (header, _) = build_stream_header(
                    sender,
                    host,
                    token,
                    &req.file_id,
                    view,
                    RouteMode::PreferServer,
                    None,
                )
                .await?;
                let guard = session.0.lock().await;
                let identity = guard
                    .identity
                    .as_ref()
                    .ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?;
                let ctx = crate::directory::build_verify_ctx(file_id, author, my_id, identity);
                open_content_decryptor(&ctx, &header)
                    .map_err(|_| UiError::new("verify_failed", "This item failed verification."))?
            }
            Err(_) => {
                return Err(UiError::new(
                    "verify_failed",
                    "This item failed verification.",
                ))
            }
        }
    };

    let n = decryptor.content_chunk_count();
    let version = decryptor.version();

    let mut file = std::fs::File::create(&req.save_path).map_err(|_| write_failed())?;
    for i in 0..n {
        // Fetch this chunk's ciphertext, preferring the direct route. The real
        // per-chunk AEAD check is the `open_range` decrypt below; a direct-sourced
        // chunk that fails it is refetched forced-proxy and retried exactly once.
        let (mut ct, mut used_direct) = crate::direct_link::fetch_chunk_routed(
            sender,
            host,
            token,
            file_id_hex,
            version,
            "content",
            i,
            route_mode,
            direct_http,
            |_| true,
        )
        .await?;

        let plaintext = loop {
            // Decrypt the single chunk in the TCB with its ABSOLUTE index (the
            // decryptor derives is_last from the signed count — a substituted /
            // mis-positioned chunk fails the AAD and we fail closed).
            match decryptor.open_range(i, std::slice::from_ref(&ct)) {
                Ok(pt) => break pt,
                Err(_) if used_direct => {
                    ct = crate::direct_link::fetch_chunk_proxy(
                        sender,
                        host,
                        token,
                        file_id_hex,
                        version,
                        "content",
                        i,
                    )
                    .await?;
                    used_direct = false; // exactly one retry
                }
                Err(_) => return Err(UiError::new("verify_failed", "This item failed verification.")),
            }
        };
        file.write_all(&plaintext).map_err(|_| write_failed())?;
        // `plaintext` (Zeroizing) drops here → the chunk plaintext is zeroized.
    }
    file.flush().map_err(|_| write_failed())?;
    Ok(req.save_path.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_encoding::types::FileType;

    #[test]
    fn suggested_filename_by_type() {
        let meta = br#"{"title":"My Trip","tags":[],"filename":"itinerary.pdf"}"#;
        assert_eq!(suggested_filename(FileType::Generic, meta), "itinerary.pdf"); // original filename
        assert_eq!(suggested_filename(FileType::Image, meta), "My Trip.png");
        assert_eq!(suggested_filename(FileType::Video, meta), "My Trip.mp4");
        assert_eq!(suggested_filename(FileType::Blog, meta), "My Trip.txt");
        // Missing/blank title falls back to a safe default (e.g. "download.png").
        let bare = br#"{"title":"","tags":[]}"#;
        assert_eq!(suggested_filename(FileType::Image, bare), "download.png");
    }

    #[test]
    fn generic_falls_back_to_title_then_default() {
        // Generic with no filename → sanitized title (no forced extension).
        let no_name = br#"{"title":"Report 2026","tags":[]}"#;
        assert_eq!(suggested_filename(FileType::Generic, no_name), "Report 2026");
        // Generic with neither → the safe default.
        let bare = br#"{"title":"","tags":[]}"#;
        assert_eq!(suggested_filename(FileType::Generic, bare), "download.bin");
    }

    #[test]
    fn bundle_is_not_directly_downloadable() {
        assert_eq!(suggested_filename(FileType::Bundle, b"{}"), "bundle");
    }

    #[test]
    fn title_is_sanitized_against_path_traversal() {
        // Path separators / traversal / control chars are stripped; the interior
        // extension dot on a generic filename survives.
        let evil = br#"{"title":"../../etc/passwd","tags":[],"filename":"a/b\\c:d.pdf"}"#;
        let gen = suggested_filename(FileType::Generic, evil);
        assert!(!gen.contains('/') && !gen.contains('\\') && !gen.contains(':'));
        assert_eq!(gen, "abcd.pdf");
        let img = suggested_filename(FileType::Image, evil);
        assert!(!img.contains('/') && !img.contains('\\'));
        assert_eq!(img, "etcpasswd.png"); // leading ".." trimmed, separators removed
    }

    #[test]
    fn malformed_metadata_yields_a_safe_default() {
        assert_eq!(suggested_filename(FileType::Video, b"not json"), "download.mp4");
    }
}
