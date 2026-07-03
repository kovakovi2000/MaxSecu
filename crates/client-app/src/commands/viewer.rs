//! The viewer command: verify + decrypt a file's content and return it render-
//! ready (image PNG to display, or sanitized blog text). Drives the FetchPhase
//! feedback machine. The content shown is the product; no keys/grants cross.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use maxsecu_client_core::OpenedStream;
use maxsecu_encoding::types::{FileType, StreamType};

use crate::error::UiError;

/// Shape the decrypted streams into the content body for `file_type`. Image →
/// the canonical PNG content stream (base64). Blog → sanitized UTF-8 text.
/// Video → `codec_unavailable` (player gated, D-B). Pure — unit-tested.
pub(crate) fn shape_content(
    file_type: FileType,
    streams: &[OpenedStream],
) -> Result<(Option<String>, Option<String>), UiError> {
    let content = streams
        .iter()
        .find(|s| s.stream_type == StreamType::Content)
        .ok_or_else(|| UiError::new("verify_failed", "Missing content."))?;
    match file_type {
        FileType::Image => Ok((Some(B64.encode(&content.plaintext)), None)),
        FileType::Blog => {
            let text = String::from_utf8(content.plaintext.clone())
                .map_err(|_| UiError::new("verify_failed", "Unreadable blog content."))?;
            Ok((None, Some(sanitize_blog(&text))))
        }
        FileType::Video => Err(UiError::new(
            "codec_unavailable",
            "Video playback is not enabled yet.",
        )),
    }
}

/// Minimal blog sanitization for display: strip control chars except newlines/
/// tabs. The viewer renders this as TEXT (textContent), never HTML — that is the
/// real XSS defense; this is defense-in-depth.
fn sanitize_blog(s: &str) -> String {
    s.chars()
        .filter(|c| *c == '\n' || *c == '\t' || !c.is_control())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(t: StreamType, p: &[u8]) -> OpenedStream {
        OpenedStream {
            stream_type: t,
            plaintext: p.to_vec(),
        }
    }

    #[test]
    fn image_content_is_base64_png() {
        let png = [0x89, 0x50, 0x4E, 0x47, 1, 2, 3];
        let (img, blog) =
            shape_content(FileType::Image, &[stream(StreamType::Content, &png)]).unwrap();
        assert_eq!(img.unwrap(), B64.encode(png));
        assert!(blog.is_none());
    }

    #[test]
    fn blog_content_is_sanitized_text() {
        let (img, blog) = shape_content(
            FileType::Blog,
            &[stream(StreamType::Content, b"Hello\x07 world\n")],
        )
        .unwrap();
        assert!(img.is_none());
        assert_eq!(blog.unwrap(), "Hello world\n"); // the BEL control char stripped
    }

    #[test]
    fn video_is_codec_unavailable() {
        let err = shape_content(FileType::Video, &[stream(StreamType::Content, b"x")]).unwrap_err();
        assert_eq!(err.code, "codec_unavailable");
    }

    #[test]
    fn missing_content_is_verify_failed() {
        let err = shape_content(FileType::Blog, &[stream(StreamType::Metadata, b"x")]).unwrap_err();
        assert_eq!(err.code, "verify_failed");
    }
}

use tauri::{Emitter, State};

use maxsecu_client_core::{
    verify_and_open, verify_and_open_headers, DirectoryVerifier, Identity, MemoryTrustStore,
    VerifyContext, NO_ADMINS, NO_GRANTERS,
};
use maxsecu_encoding::decode;
use maxsecu_encoding::structs::Manifest;
use maxsecu_encoding::types::{Id, RecipientType};

use crate::commands::auth::{AppDir, ConnectLock, Session};
use crate::commands::connection::{reauth, server_of};
use crate::commands::feed::{file_type_name, hex, hex16, now_ms, parse_title_tags};
use crate::config::load_directory_pub;
use crate::download::{build_download_bundle, build_stream_header, parse_file_view};
use crate::dto::{OpenContentRequest, OpenedContentDto};
use crate::http_client::get_json;
use crate::state::{FetchPhase, EVT_FETCH};

/// `open_content` — the viewer: fetch, verify, decrypt one file and return the
/// content to display. Emits FetchPhase over EVT_FETCH. Sanitized errors.
#[tauri::command]
pub async fn open_content(
    req: OpenContentRequest,
    app: tauri::AppHandle,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
    cache: State<'_, crate::content_cache::ContentCache>,
) -> Result<OpenedContentDto, UiError> {
    let emit = |p: FetchPhase| {
        let _ = app.emit(EVT_FETCH, p);
    };
    let out = open_content_inner(&req, &dir, &session, &connect_lock, &cache, &emit).await;
    if let Err(e) = &out {
        emit(FetchPhase::Failed {
            file_id: req.file_id.clone(),
            code: e.code.clone(),
        });
    }
    out
}

async fn open_content_inner(
    req: &OpenContentRequest,
    dir: &State<'_, AppDir>,
    session: &State<'_, Session>,
    connect_lock: &State<'_, ConnectLock>,
    cache: &State<'_, crate::content_cache::ContentCache>,
    emit: &impl Fn(FetchPhase),
) -> Result<OpenedContentDto, UiError> {
    // Validate the REQUESTED id up front: this is the id the served record must
    // bind to (see `run_open`), and it also rejects a malformed id before it is
    // interpolated into the request URL.
    let file_id = hex16(&req.file_id)?;
    use crate::content_cache::{CacheKey, CachedMeta};
    if let Some(v) = req.version {
        if let Some(dto) = cache.get_content(CacheKey { file_id, version: v }, &req.file_id) {
            emit(FetchPhase::Ready {
                file_id: req.file_id.clone(),
            });
            return Ok(dto);
        }
    }
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
    let (mut sender, host, token) = reauth(&dir.0, &server, session, connect_lock).await?;

    emit(FetchPhase::Fetching {
        file_id: req.file_id.clone(),
        fetched: 0,
        total: 0,
    });
    let (status, view_json) = get_json(
        &mut sender,
        &format!("/v1/files/{}?version=latest", req.file_id),
        Some(&token),
        &host,
    )
    .await?;
    if status != hyper::StatusCode::OK {
        return Err(UiError::new("fetch_failed", "That item is not available."));
    }
    let view = parse_file_view(&view_json)?;
    if req.version.is_none() {
        // NB: keyed on the UNVERIFIED envelope `view.version`; if it diverges from the
        // signed manifest version this is a benign cache miss (the put keys on the
        // verified `opened.version`).
        if let Some(dto) =
            cache.get_content(CacheKey { file_id, version: view.version }, &req.file_id)
        {
            emit(FetchPhase::Ready {
                file_id: req.file_id.clone(),
            });
            return Ok(dto);
        }
    }
    let manifest: Manifest =
        decode(&view.manifest_bytes).map_err(|_| UiError::new("untrusted", "Malformed record."))?;
    let (author, author_binding) = crate::directory::resolve_and_verify_author_logged(
        &mut sender,
        &host,
        &hex(&manifest.author_id.0),
        &verifier,
        &mut trust,
        now,
    )
    .await?;
    // Trust-alarm C (spec §0-C/§7): block the OPEN unless the served author binding
    // is provably present in the directory key-transparency log under a pinned,
    // non-equivocating checkpoint (opt-in; see `enforce_author_transparency`).
    crate::commands::feed::enforce_author_transparency(&dir.0, session.inner(), author_binding)
        .await?;
    let my_id = crate::directory::resolve_my_user_id(
        &mut sender,
        &host,
        &username,
        &verifier,
        &mut trust,
        now,
    )
    .await?;

    // The download route setting, read once and reused for every fetch below.
    let route_mode = crate::config::SettingsConfig::load(&dir.0).connection.route_mode;
    let direct_http = crate::direct_link::shared_direct_http();

    // VIDEO: return metadata via a HEADER-ONLY open (no whole-file download, no
    // gate error) so the viewer mounts the native <video-player>, which streams the
    // content itself via open_video + the stream:// Range protocol. Image/blog keep
    // the full verify+decrypt path below.
    if manifest.file_type == FileType::Video {
        let (header, header_used_direct) = build_stream_header(
            &mut sender,
            &host,
            &token,
            &req.file_id,
            &view,
            route_mode,
            direct_http,
        )
        .await?;
        emit(FetchPhase::Verifying {
            file_id: req.file_id.clone(),
        });
        // Borrow the unlocked identity UNDER the lock across the SYNCHRONOUS header
        // verify (no await), mirroring run_open — no transient None window. If a
        // direct-sourced header chunk failed verification, refetch the WHOLE
        // header forced-proxy and retry exactly once (fail-closed: never denies
        // the view, just falls back — the link source is untrusted).
        let attempt = {
            let guard = session.0.lock().await;
            let identity = guard
                .identity
                .as_ref()
                .ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?;
            verify_and_open_headers(&video_verify_ctx(file_id, &author, my_id, identity), &header)
        };
        let opened = match attempt {
            Ok(o) => o,
            Err(_) if header_used_direct => {
                let (header, _) = build_stream_header(
                    &mut sender,
                    &host,
                    &token,
                    &req.file_id,
                    &view,
                    crate::config::RouteMode::PreferServer,
                    None,
                )
                .await?;
                let guard = session.0.lock().await;
                let identity = guard
                    .identity
                    .as_ref()
                    .ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?;
                verify_and_open_headers(
                    &video_verify_ctx(file_id, &author, my_id, identity),
                    &header,
                )
                .map_err(|_| UiError::new("verify_failed", "This item failed verification."))?
            }
            Err(_) => {
                return Err(UiError::new(
                    "verify_failed",
                    "This item failed verification.",
                ))
            }
        };
        let (title, tags) = opened
            .small_streams
            .iter()
            .find(|s| s.stream_type == StreamType::Metadata)
            .map(|s| parse_title_tags(&s.plaintext))
            .unwrap_or_else(|| ("(untitled)".to_owned(), Vec::new()));
        emit(FetchPhase::Ready {
            file_id: req.file_id.clone(),
        });
        return Ok(OpenedContentDto {
            file_id: req.file_id.clone(),
            file_type: file_type_name(FileType::Video),
            version: opened.version,
            title,
            tags,
            image_png_b64: None,
            blog_text: None,
            author_fp: hex(&author.fingerprint[..8]),
            recovery_ok: opened.recovery_grant_ok,
            // Display metadata only (D-OQ3): this open succeeded, so the caller
            // holds a wrap — Share is available to ANY wrap-holder, not just the
            // author/owner. NOT gated on `my_id == author.user_id`.
            can_share: true,
        });
    }

    let (bundle, bundle_used_direct) = build_download_bundle(
        &mut sender,
        &host,
        &token,
        &req.file_id,
        &view,
        route_mode,
        direct_http,
    )
    .await?;

    emit(FetchPhase::Verifying {
        file_id: req.file_id.clone(),
    });
    // Borrow the unlocked identity UNDER the lock across the SYNCHRONOUS verify
    // (`run_open` has no await), so the borrow never spans an await and the
    // identity is never taken out — no transient `None` window for a concurrent
    // command to observe, and nothing to restore on any path. If a direct-
    // sourced chunk failed verification, refetch the WHOLE bundle forced-proxy
    // and retry exactly once (fail-closed: never denies the view, just falls
    // back — the link source is untrusted).
    let attempt = {
        let guard = session.0.lock().await;
        let identity = guard
            .identity
            .as_ref()
            .ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?;
        run_open(identity, file_id, &author, my_id, &bundle)
    };
    let opened = match attempt {
        Ok(o) => o,
        Err(e) if bundle_used_direct => {
            let (bundle, _) = build_download_bundle(
                &mut sender,
                &host,
                &token,
                &req.file_id,
                &view,
                crate::config::RouteMode::PreferServer,
                None,
            )
            .await?;
            let guard = session.0.lock().await;
            let identity = guard
                .identity
                .as_ref()
                .ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?;
            run_open(identity, file_id, &author, my_id, &bundle).map_err(|_| e)?
        }
        Err(e) => return Err(e),
    };

    emit(FetchPhase::Decrypting {
        file_id: req.file_id.clone(),
    });
    let (image_png_b64, blog_text) = shape_content(manifest.file_type, &opened.streams)?;
    // Display-final content bytes for the cache (so a hit == a fresh decrypt):
    // image → the raw canonical-PNG content plaintext (cache re-base64s it);
    // blog → the already-sanitized `blog_text` bytes (NOT the raw plaintext).
    let cache_content: Option<Vec<u8>> = match manifest.file_type {
        FileType::Image => opened
            .streams
            .iter()
            .find(|s| s.stream_type == StreamType::Content)
            .map(|s| s.plaintext.clone()),
        FileType::Blog => blog_text.as_ref().map(|t| t.clone().into_bytes()),
        FileType::Video => None,
    };
    let (title, tags) = opened
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Metadata)
        .map(|s| parse_title_tags(&s.plaintext))
        .unwrap_or_else(|| ("(untitled)".to_owned(), Vec::new()));

    emit(FetchPhase::Ready {
        file_id: req.file_id.clone(),
    });

    if let Some(content) = cache_content {
        cache.put_content(
            CacheKey {
                file_id,
                version: opened.version,
            },
            CachedMeta {
                file_type: file_type_name(manifest.file_type),
                title: title.clone(),
                tags: tags.clone(),
                thumbnail_b64: None,
                author_fp: hex(&author.fingerprint[..8]),
                recovery_ok: opened.recovery_grant_ok,
                mine: my_id == author.user_id,
            },
            content,
        );
    }

    Ok(OpenedContentDto {
        file_id: req.file_id.clone(),
        file_type: file_type_name(manifest.file_type),
        version: opened.version,
        title,
        tags,
        image_png_b64,
        blog_text,
        author_fp: hex(&author.fingerprint[..8]),
        recovery_ok: opened.recovery_grant_ok,
        // Display metadata only (D-OQ3): this open succeeded, so the caller
        // holds a wrap — Share is available to ANY wrap-holder, not just the
        // author/owner. NOT gated on `my_id == author.user_id`.
        can_share: true,
    })
}

/// Build the header-only `VerifyContext` for the VIDEO branch (metadata-only
/// open — no content fetched here). A free `fn` (not a closure) so its return
/// type's lifetime is provably tied to `identity`'s borrow (a closure here
/// fails lifetime inference: the compiler cannot generalize a closure's return
/// type over an implicit higher-ranked input lifetime the way a `fn` can).
fn video_verify_ctx<'a>(
    file_id: [u8; 16],
    author: &crate::directory::VerifiedAuthor,
    my_id: [u8; 16],
    identity: &'a Identity,
) -> VerifyContext<'a> {
    VerifyContext {
        file_id: Id(file_id),
        author_sig_pub: author.sig_pub,
        owner_sig_pub: author.sig_pub,
        recipient_id: Id(my_id),
        recipient_type: RecipientType::User,
        recipient_secret: identity.enc_secret(),
        recipient_mlkem_seed: None,
        seen_max_version: None,
        granter_sig_pub: &NO_GRANTERS,
        admin_sig_pub: &NO_ADMINS,
        tombstones: None,
        compromise: None,
    }
}

/// Build the VerifyContext and run the whole-buffer verify+decrypt. Synchronous —
/// the caller holds the session lock across this so the identity borrow is safe.
fn run_open(
    identity: &Identity,
    file_id: [u8; 16],
    author: &crate::directory::VerifiedAuthor,
    my_id: [u8; 16],
    bundle: &maxsecu_client_core::DownloadBundle,
) -> Result<maxsecu_client_core::OpenedFile, UiError> {
    // `file_id` MUST be the REQUESTED id, NOT `manifest.file_id`: `verify_header`
    // binds the served record to the request via `manifest.file_id != ctx.file_id
    // => FileIdMismatch`. Sourcing it from the manifest would make that check a
    // tautology, letting an untrusted server substitute any other validly-signed
    // record the user can decrypt.
    let ctx = VerifyContext {
        file_id: Id(file_id),
        author_sig_pub: author.sig_pub,
        owner_sig_pub: author.sig_pub,
        recipient_id: Id(my_id),
        recipient_type: RecipientType::User,
        recipient_secret: identity.enc_secret(),
        recipient_mlkem_seed: None,
        seen_max_version: None,
        granter_sig_pub: &NO_GRANTERS,
        admin_sig_pub: &NO_ADMINS,
        tombstones: None,
        compromise: None,
    };
    verify_and_open(&ctx, bundle)
        .map_err(|_| UiError::new("verify_failed", "This item failed verification."))
}
