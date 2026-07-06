//! The `delete_content` command: permanently delete an OWNED post/bundle
//! (bundles Task 6.1). A thin client wrapper over the server's owner-only
//! `DELETE /v1/files/{file_id}` (204 on success; the server cascades bundle
//! members + purges blobs). Sanitized, no-oracle errors — a non-owner is
//! indistinguishable from a missing file (both surface `not_found`). On success
//! the local content-cache entries for the id are invalidated. Only the target
//! id (a primitive) crosses the seam; no key material.

use hyper::StatusCode;
use tauri::State;

use crate::commands::auth::{AppDir, ConnectLock, Session};
use crate::commands::connection::{reauth, server_of};
use crate::commands::feed::{hex, hex16};
use crate::media_cache::MediaCache;
use crate::thumb_cache::ThumbCache;
use crate::dto::DeleteRequest;
use crate::error::UiError;
use crate::http_client::delete_req;

/// Map the server's `DELETE /v1/files/{id}` status to the command result.
/// **204 → Ok** (deleted); **404 → `not_found`** (sanitized: the server returns
/// 404 for BOTH "missing" and "not yours" so this carries no ownership oracle);
/// anything else / a transport-level surprise → `delete_failed`. Pure — unit-tested.
fn map_delete_status(status: StatusCode) -> Result<(), UiError> {
    match status {
        StatusCode::NO_CONTENT => Ok(()),
        StatusCode::NOT_FOUND => Err(UiError::new("not_found", "That item is no longer available.")),
        _ => Err(UiError::new("delete_failed", "Could not delete that item.")),
    }
}

/// `delete_content` — permanently delete the REQUESTED owned post/bundle. Validates
/// the id up front (malformed → sanitized error, NO network), reauths on a fresh
/// channel, issues the owner-only DELETE, and on success invalidates the local
/// content-cache entries for the id. Sanitized errors (no ownership oracle).
#[tauri::command]
pub async fn delete_content(
    req: DeleteRequest,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
    thumb: State<'_, ThumbCache>,
    media: State<'_, MediaCache>,
) -> Result<(), UiError> {
    // Validate the REQUESTED id BEFORE any network: a malformed id short-circuits
    // here (and is never interpolated into the request URL).
    let file_id = hex16(&req.file_id)?;
    let file_id_hex = hex(&file_id);

    let server = server_of(&dir.0)?;
    let (mut sender, host, token) = reauth(&dir.0, &server, &session, &connect_lock).await?;

    let (status, _body) = delete_req(
        &mut sender,
        &format!("/v1/files/{file_id_hex}"),
        Some(&token),
        &host,
    )
    .await?;
    map_delete_status(status)?;

    // Deleted server-side (204). Drop the local content-cache entries for this id
    // (any version). The server already cascaded bundle members, but the client
    // only knows the bundle id here — invalidating it is enough for the immediate
    // view; the feed refresh (Task 6.2) drops the members from the listing. Both
    // sealed caches are cleared: card meta (ThumbCache) and any full content +
    // video fragments (MediaCache) for the id.
    thumb.invalidate_file(file_id).await;
    media.invalidate_file(file_id).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_204_is_ok() {
        assert!(map_delete_status(StatusCode::NO_CONTENT).is_ok());
    }

    #[test]
    fn status_404_is_not_found_no_oracle() {
        let e = map_delete_status(StatusCode::NOT_FOUND).unwrap_err();
        assert_eq!(e.code, "not_found");
    }

    #[test]
    fn other_statuses_are_delete_failed() {
        for s in [
            StatusCode::OK,             // unexpected 200
            StatusCode::FORBIDDEN,      // would be an ownership oracle if surfaced
            StatusCode::UNAUTHORIZED,
            StatusCode::CONFLICT,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            let e = map_delete_status(s).unwrap_err();
            assert_eq!(e.code, "delete_failed", "status {s} must map to delete_failed");
        }
    }

    #[test]
    fn malformed_id_is_rejected_before_network() {
        // `delete_content` validates `hex16(&req.file_id)?` first, so a malformed
        // id short-circuits with a sanitized error and never reaches the network.
        assert!(hex16("nothex").is_err());
        assert!(hex16(&"z".repeat(32)).is_err()); // right length, not hex
        assert!(hex16(&"ab".repeat(16)).is_ok()); // a well-formed id parses
    }
}
