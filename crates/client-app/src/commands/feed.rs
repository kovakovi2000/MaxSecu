//! Feed/browse commands: the D35 listing (`list_feed`) and per-item card
//! decryption (`decrypt_card`, added in a later task). Listing carries no values;
//! card decryption runs the verify ladder in the TCB and returns only render-ready
//! metadata + a thumbnail. The UI never sees keys, grants, or the content stream.

use hyper::StatusCode;
use tauri::State;

use crate::commands::auth::{AppDir, ConnectLock, Session};
use crate::commands::connection::{reauth, server_of};
use crate::dto::{FeedEntryDto, FeedFilter, FeedSort, ListFeedRequest};
use crate::error::UiError;
use crate::http_client::get_json;

/// Map one `ListEntryRes` JSON object to a `FeedEntryDto`. Pure — unit-tested.
fn entry_from_json(j: &serde_json::Value) -> Option<FeedEntryDto> {
    let streams = j.get("streams")?;
    Some(FeedEntryDto {
        file_id: j["file_id"].as_str()?.to_owned(),
        file_type: j["file_type"].as_str()?.to_owned(),
        version: j["version"].as_u64()?,
        updated_at: j["updated_at"].as_u64()?,
        has_thumbnail: streams.get("thumbnail").is_some(),
    })
}

/// Apply the client-side sort (the server returns listing order).
fn sort_entries(entries: &mut [FeedEntryDto], sort: FeedSort) {
    match sort {
        FeedSort::NewestFirst => entries.sort_by_key(|e| std::cmp::Reverse(e.updated_at)),
        FeedSort::OldestFirst => entries.sort_by_key(|e| e.updated_at),
    }
}

/// The server `type` query value for a filter, or `None` for `All`.
fn filter_param(filter: FeedFilter) -> Option<&'static str> {
    match filter {
        FeedFilter::All => None,
        FeedFilter::Image => Some("image"),
        FeedFilter::Video => Some("video"),
        FeedFilter::Blog => Some("blog"),
    }
}

/// `list_feed` — the D35 listing (api.md §8.6). Authed (re-authed on a fresh
/// channel); carries no values. The type filter is applied server-side; sort is
/// client-side.
#[tauri::command]
pub async fn list_feed(
    req: ListFeedRequest,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
) -> Result<Vec<FeedEntryDto>, UiError> {
    let server = server_of(&dir.0)?;
    let (mut sender, host, token) = reauth(&dir.0, &server, &session, &connect_lock).await?;
    let limit = req.limit.unwrap_or(50).min(200);
    let uri = match filter_param(req.filter) {
        Some(t) => format!("/v1/files?type={t}&limit={limit}"),
        None => format!("/v1/files?limit={limit}"),
    };
    let (status, json) = get_json(&mut sender, &uri, Some(&token), &host).await?;
    if status != StatusCode::OK {
        return Err(UiError::new("feed_failed", "Could not load the feed."));
    }
    let mut entries: Vec<FeedEntryDto> = json["files"]
        .as_array()
        .map(|a| a.iter().filter_map(entry_from_json).collect())
        .unwrap_or_default();
    sort_entries(&mut entries, req.sort);
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn j(id: &str, ty: &str, ver: u64, upd: u64, thumb: bool) -> serde_json::Value {
        let mut streams = serde_json::Map::new();
        streams.insert("metadata".into(), serde_json::json!({ "size": 10 }));
        if thumb {
            streams.insert("thumbnail".into(), serde_json::json!({ "size": 20 }));
        }
        serde_json::json!({ "file_id": id, "file_type": ty, "version": ver, "updated_at": upd, "streams": streams })
    }

    #[test]
    fn maps_and_sorts_entries() {
        let raw = [
            j("aa", "image", 1, 100, true),
            j("bb", "blog", 2, 300, false),
            j("cc", "image", 1, 200, true),
        ];
        let mut entries: Vec<FeedEntryDto> = raw.iter().filter_map(entry_from_json).collect();
        assert_eq!(entries.len(), 3);
        assert!(entries[0].has_thumbnail && !entries[1].has_thumbnail);
        sort_entries(&mut entries, FeedSort::NewestFirst);
        assert_eq!(
            entries.iter().map(|e| e.updated_at).collect::<Vec<_>>(),
            vec![300, 200, 100]
        );
        sort_entries(&mut entries, FeedSort::OldestFirst);
        assert_eq!(
            entries.iter().map(|e| e.updated_at).collect::<Vec<_>>(),
            vec![100, 200, 300]
        );
    }

    #[test]
    fn filter_param_maps_types() {
        assert_eq!(filter_param(FeedFilter::All), None);
        assert_eq!(filter_param(FeedFilter::Image), Some("image"));
        assert_eq!(filter_param(FeedFilter::Blog), Some("blog"));
    }
}
