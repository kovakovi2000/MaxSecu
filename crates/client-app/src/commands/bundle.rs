//! The `open_bundle` command: verify + decrypt a bundle file and return its
//! ordered member list. The member ids come from the SIGNED `BundleBody`
//! content — never from any server-served listing/metadata — so the returned
//! order and membership are tamper-proof. Mirrors the viewer's verify ladder
//! (`open_content_inner`) using the same shared primitives; the viewer path is
//! untouched.

use crate::dto::{BundleMemberView, BundleView};

/// Map a verified [`BundleBody`]'s members to seam DTOs, in the bundle's
/// authoritative order. Pure — the order/membership are exactly the signed
/// content. `title` / `thumbnail_b64` are left empty (the UI fills them lazily).
pub(crate) fn member_views_from_body(
    body: &maxsecu_encoding::structs::BundleBody,
) -> Vec<BundleMemberView> {
    body.members
        .iter()
        .map(|m| BundleMemberView {
            file_id: hex(&m.file_id.0),
            file_type: file_type_name(m.file_type),
            title: String::new(),
            thumbnail_b64: None,
        })
        .collect()
}

use crate::commands::feed::{file_type_name, hex};

use tauri::State;

use maxsecu_client_core::{DirectoryVerifier, MemoryTrustStore};
use maxsecu_encoding::decode;
use maxsecu_encoding::structs::{BundleBody, Manifest};
use maxsecu_encoding::types::{FileType, StreamType};

use crate::commands::auth::{AppDir, ConnectLock, Session};
use crate::commands::connection::{reauth, server_of};
use crate::commands::feed::{hex16, now_ms};
use crate::config::load_directory_pub;
use crate::download::{build_download_bundle, parse_file_view};
use crate::dto::OpenContentRequest;
use crate::error::UiError;
use crate::http_client::get_json;

/// Verify + decrypt a bundle file and return its authoritative member list plus
/// the verified version. Reusable by other commands (e.g. member-count reads):
/// the returned `BundleBody` is the SIGNED content — its member ids/order are
/// tamper-proof, sourced from the decrypted `StreamType::Content`, NOT from any
/// server-served listing.
///
/// Mirrors the viewer's verify ladder (`open_content_inner`) by orchestrating the
/// SAME shared primitives — `resolve_and_verify_author_logged`,
/// `enforce_author_transparency`, `resolve_my_user_id`, `build_download_bundle`,
/// `viewer::run_open` — including the direct-link retry-once-forced-proxy
/// fallback. The bundle is bound to the REQUESTED `req_file_id` inside `run_open`
/// (via `build_verify_ctx`). Intentionally UNCACHED: the `ContentCache` stores
/// `OpenedContentDto` (image/blog bytes), not a `BundleBody`, so every open does a
/// fresh verify — bundles are small (an ordered id list) so this is cheap.
pub(crate) async fn open_bundle_members(
    req_file_id: &str,
    dir: &State<'_, AppDir>,
    session: &State<'_, Session>,
    connect_lock: &State<'_, ConnectLock>,
) -> Result<(BundleBody, u64, bool), UiError> {
    // Validate the REQUESTED id up front: `run_open` binds the served record to
    // it, and it rejects a malformed id before it is interpolated into the URL.
    let file_id = hex16(req_file_id)?;
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

    let (status, view_json) = get_json(
        &mut sender,
        &format!("/v1/files/{req_file_id}?version=latest"),
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
    // A bundle only: reject any other served record type up front (defense in
    // depth — `run_open` also binds the requested id).
    if manifest.file_type != FileType::Bundle {
        // A wrong requested record type is a request problem, not a verify
        // failure — mirrors the viewer's symmetric `bad_request` for bundles.
        return Err(UiError::new("bad_request", "Not a bundle."));
    }
    let (author, author_binding) = crate::directory::resolve_and_verify_author_logged(
        &mut sender,
        &host,
        &hex(&manifest.author_id.0),
        &verifier,
        &mut trust,
        now,
    )
    .await?;
    // Trust-alarm C: block the OPEN unless the served author binding is provably
    // present in the directory KT log (opt-in; see the viewer's use of this).
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

    let route_mode = crate::config::SettingsConfig::load(&dir.0).connection.route_mode;
    let direct_http = crate::direct_link::shared_direct_http();

    let (bundle, used_direct) = build_download_bundle(
        &mut sender,
        &host,
        &token,
        req_file_id,
        &view,
        route_mode,
        direct_http,
    )
    .await?;

    // Borrow the unlocked identity UNDER the lock across the SYNCHRONOUS verify
    // (`run_open` has no await), so the borrow never spans an await and there is
    // no transient `None` window. If a direct-sourced chunk failed verification,
    // refetch the WHOLE bundle forced-proxy and retry exactly once (fail-closed:
    // the link source is untrusted, so fall back to the server rather than deny).
    let attempt = {
        let guard = session.0.lock().await;
        let identity = guard
            .identity
            .as_ref()
            .ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?;
        crate::commands::viewer::run_open(identity, file_id, &author, my_id, &bundle)
    };
    let opened = match attempt {
        Ok(o) => o,
        Err(e) if used_direct => {
            let (bundle, _) = build_download_bundle(
                &mut sender,
                &host,
                &token,
                req_file_id,
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
            crate::commands::viewer::run_open(identity, file_id, &author, my_id, &bundle)
                .map_err(|_| e)?
        }
        Err(e) => return Err(e),
    };

    // The member list is the SIGNED content stream — authoritative and tamper-
    // proof. NEVER read members from a server-served listing/metadata.
    let content = opened
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Content)
        .ok_or_else(|| UiError::new("verify_failed", "Missing content."))?;
    let body: BundleBody =
        decode(&content.plaintext).map_err(|_| UiError::new("untrusted", "Malformed bundle."))?;
    // Ownership (bundles Task 6.2): the caller authored this bundle iff their id
    // matches the verified author. Gates the owner-only "Delete bundle" action.
    let mine = my_id == author.user_id;
    Ok((body, opened.version, mine))
}

/// `open_bundle` — verify + decrypt a bundle file and return its ordered member
/// list to the UI. The member ids/order come from the SIGNED bundle body, never
/// a server-served listing. No FetchPhase events (the UI shows its own spinner);
/// errors are sanitized `UiError`s.
#[tauri::command]
pub async fn open_bundle(
    req: OpenContentRequest,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
) -> Result<BundleView, UiError> {
    let (body, version, mine) =
        open_bundle_members(&req.file_id, &dir, &session, &connect_lock).await?;
    Ok(BundleView {
        file_id: req.file_id,
        file_type: file_type_name(FileType::Bundle),
        version,
        members: member_views_from_body(&body),
        mine,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_views_map_in_order_with_types() {
        use maxsecu_encoding::structs::{BundleBody, BundleMember};
        use maxsecu_encoding::types::{FileType, Id};
        let body = BundleBody {
            members: vec![
                BundleMember {
                    file_id: Id([0x0A; 16]),
                    file_type: FileType::Video,
                },
                BundleMember {
                    file_id: Id([0x0B; 16]),
                    file_type: FileType::Generic,
                },
            ],
        };
        let views = member_views_from_body(&body);
        assert_eq!(views.len(), 2);
        assert_eq!(views[0].file_type, "video");
        assert_eq!(views[0].file_id, "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"); // hex of member id
        assert_eq!(views[1].file_type, "generic");
        assert!(views[0].title.is_empty() && views[0].thumbnail_b64.is_none());
    }
}
