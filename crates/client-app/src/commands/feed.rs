//! Feed/browse commands: the D35 listing (`list_feed`) and per-item card
//! decryption (`decrypt_card`, added in a later task). Listing carries no values;
//! card decryption runs the verify ladder in the TCB and returns only render-ready
//! metadata + a thumbnail. The UI never sees keys, grants, or the content stream.

use hyper::StatusCode;
use tauri::State;

use crate::commands::auth::{AppDir, ConnectLock, Session};
use crate::commands::connection::{reauth, server_of};
use crate::commands::pool::AppPool;
use crate::jobs::AuthedChannel;
use crate::dto::{FeedEntryDto, FeedFilter, FeedSort, ListFeedRequest};
use crate::error::UiError;
use crate::http_client::get_json;

use maxsecu_encoding::types::FileType;

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

/// Parse the metadata plaintext into `(title, tags)`. Tolerant: JSON
/// `{title,tags}` preferred; any other UTF-8 ⇒ that string is the title; non-UTF-8
/// ⇒ `(untitled)`. (Phase 4 uploads write the JSON form.) `pub(crate)` so the
/// viewer command reuses it.
pub(crate) fn parse_title_tags(meta: &[u8]) -> (String, Vec<String>) {
    #[derive(serde::Deserialize)]
    struct Meta {
        title: Option<String>,
        #[serde(default)]
        tags: Vec<String>,
    }
    match std::str::from_utf8(meta) {
        Ok(s) => match serde_json::from_str::<Meta>(s) {
            Ok(m) if m.title.is_some() => (m.title.unwrap(), m.tags),
            _ => (s.to_owned(), Vec::new()),
        },
        Err(_) => ("(untitled)".to_owned(), Vec::new()),
    }
}

/// Tally a bundle's members by kind into a [`crate::dto::MemberCounts`]
/// (order-private — counts only, never the member order). `FileType::Bundle`
/// can't be a member, so it is ignored. `pub(crate)` so it is unit-testable.
pub(crate) fn histogram(members: &[FileType]) -> crate::dto::MemberCounts {
    let mut c = crate::dto::MemberCounts::default();
    for t in members {
        match t {
            FileType::Video => c.video += 1,
            FileType::Image => c.image += 1,
            FileType::Blog => c.blog += 1,
            FileType::Generic => c.generic += 1,
            FileType::Bundle => {} // a member can't be a bundle — count nowhere.
        }
    }
    c
}

/// The UI-facing file-type string. `pub(crate)` so the viewer command reuses it.
pub(crate) fn file_type_name(t: FileType) -> String {
    match t {
        FileType::Image => "image",
        FileType::Video => "video",
        FileType::Blog => "blog",
        FileType::Generic => "generic",
        FileType::Bundle => "bundle",
    }
    .to_owned()
}

/// Milliseconds since the Unix epoch. `pub(crate)` so the viewer command reuses
/// it instead of redefining the same clock read.
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Parse a 32-char hex `file_id` into 16 bytes. `pub(crate)` so the viewer
/// command validates the REQUESTED id with the same rule.
pub(crate) fn hex16(s: &str) -> Result<[u8; 16], UiError> {
    let bad = || UiError::new("fetch_failed", "Malformed file id.");
    if s.len() != 32 {
        return Err(bad());
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
    }
    Ok(out)
}

/// Lowercase hex of a byte slice. `pub(crate)` so the viewer command reuses it.
pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Trust-alarm C (spec §0-C/§7): police the directory key-transparency (KT) log
/// for a served, D5-verified author binding at the browse/open resolve boundary.
///
/// **Opt-in.** If no KT log key is pinned (`config::load_kt_log_pubs` empty), or the
/// sink is not pinned, this is a no-op and the caller runs today's D5-only
/// verification — so a deployment without a pinned KT key still browses. When a KT
/// key IS pinned, fetch the checkpoint / inclusion / consistency proofs from the
/// pinned SINK (never the app server) and verify `binding_bytes` is provably logged
/// under a pinned, non-equivocating checkpoint via
/// [`crate::transparency::verify_binding_transparency`]; ANY failure BLOCKS the
/// open with a `server_untrusted` error (no content shown). The persisted gossip
/// checkpoint advances on success (TOFU-pins), making cross-session split-view /
/// rollback detectable. `HttpSinkClient` is blocking, so the verify runs on a
/// `spawn_blocking` worker (never inside this async task's runtime).
pub(crate) async fn enforce_author_transparency(
    dir: &std::path::Path,
    session: &Session,
    binding_bytes: Vec<u8>,
) -> Result<(), UiError> {
    let kt_pubs = crate::config::load_kt_log_pubs(dir)?;
    if kt_pubs.is_empty() {
        return Ok(()); // KT gate not configured (opt-in) — D5-only, as today.
    }
    let pins = crate::config::load_sink_pins(dir)?;
    // Open the persisted gossip store under the unlocked identity (sealed at rest);
    // the borrow is confined to this block, released before the blocking verify.
    let mut store = {
        let guard = session.0.lock().await;
        let identity = guard
            .identity
            .as_ref()
            .ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?;
        crate::transparency::DiskKtCheckpointStore::open(dir, identity)?
    };
    tokio::task::spawn_blocking(move || {
        crate::transparency::verify_binding_transparency(&pins, &kt_pubs, &mut store, &binding_bytes)
    })
    .await
    .map_err(|_| UiError::new("server_untrusted", "The key-transparency check could not run."))?
}

/// Run the §12.5 header ladder for MY wrap with a transiently-borrowed identity.
/// Factored out so the `&identity` borrow (the `ctx` holds `enc_secret()`) is
/// confined to this call — the caller restores the identity into the session on
/// every path, borrow already released.
fn open_my_header(
    identity: &maxsecu_client_core::Identity,
    file_id: [u8; 16],
    author: &crate::directory::VerifiedAuthor,
    my_id: [u8; 16],
    header: &maxsecu_client_core::StreamHeader,
) -> Result<maxsecu_client_core::OpenedHeader, UiError> {
    use maxsecu_client_core::verify_and_open_headers;
    let ctx = crate::directory::build_verify_ctx(file_id, author, my_id, identity);
    verify_and_open_headers(&ctx, header)
        .map_err(|_| UiError::new("verify_failed", "This item failed verification."))
}

/// Mint a fresh authed channel for the pool by reusing the EXISTING `reauth`
/// VERBATIM and wrapping its `(sender, host, token)` into an [`AuthedChannel`] — the
/// three parts stay bound together as one channel-bound unit. The pool only calls
/// this under its internal auth gate, so `reauth`'s `ConnectLock` `try_lock` is never
/// contended.
async fn reauth_channel(
    dir: &std::path::Path,
    server: &str,
    session: &Session,
    connect_lock: &ConnectLock,
) -> Result<AuthedChannel, UiError> {
    let (sender, host, token) = reauth(dir, server, session, connect_lock).await?;
    Ok(AuthedChannel {
        sender,
        host,
        token,
    })
}

/// `decrypt_card` — fetch + verify one item's card (title/tags/thumbnail), header-
/// only (no content fetch). Verifies the author binding under the pinned D5, runs
/// the §12.5 header ladder, returns render-ready metadata. Sanitized errors.
#[tauri::command]
pub async fn decrypt_card(
    req: crate::dto::CardRequest,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
    thumb: State<'_, crate::thumb_cache::ThumbCache>,
    pool: State<'_, AppPool>,
) -> Result<crate::dto::CardDto, UiError> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use maxsecu_client_core::{DirectoryVerifier, MemoryTrustStore};
    use maxsecu_encoding::decode;
    use maxsecu_encoding::structs::Manifest;
    use maxsecu_encoding::types::StreamType;

    let file_id = hex16(&req.file_id)?;
    use crate::thumb_cache::{CacheKey, CachedMeta};
    // Zero-network hit when the caller passed the version it already knows.
    if let Some(v) = req.version {
        if let Some(card) = thumb.get_card(CacheKey { file_id, version: v }, &req.file_id).await {
            return Ok(card);
        }
    }
    let pinned = crate::config::load_directory_pub(&dir.0)?;
    let verifier = DirectoryVerifier::new(pinned);
    let mut trust = MemoryTrustStore::new();
    let now = now_ms();

    let username = {
        let s = session.0.lock().await;
        s.username.clone()
    }
    .ok_or_else(|| UiError::new("locked", "Sign in first."))?;

    let server = server_of(&dir.0)?;

    // Borrow a channel from the pool instead of re-authing per call. Concurrent
    // `decrypt_card` calls take DIFFERENT cached channels (no ConnectLock contention,
    // no identity-take on the hot path); only a cold-start / expired channel mints a
    // fresh one via `reauth` (under the pool's auth gate). The §8.5 view GET is the
    // FIRST use of the (possibly reused) channel, so it is the fail-closed check:
    //   * 401 — the SESSION token was rejected (expired mid-life, or the server
    //     restarted / invalidated the session), which makes EVERY pooled sibling
    //     channel (same-era token) stale, not just this one. So `drain_idle()` the
    //     whole pool AND `mark_bad()` this channel, then re-acquire ONCE: with idle
    //     empty the pool is FORCED to mint a genuinely-fresh channel via `reauth`
    //     (it can't hand back a stale sibling). A SECOND 401 after that fresh mint is a
    //     genuinely-expired session — surface it as an auth error (`locked`,
    //     "reconnect"), NOT `fetch_failed` (which would mislabel it "item unavailable").
    //   * transport error — a stale pooled connection went dead; discard THIS one
    //     channel and retry once (not session-wide — the token may still be valid).
    // A 200 validates the channel+token for the rest of this call's fetches (all within
    // the same instant), so the sequence can't 401 downstream; a downstream transport
    // failure returns the channel to the pool and is caught by the next reuse's view GET
    // (self-healing within one decode, never a persistent poison).
    let mut chan;
    let view_json;
    {
        let view_uri = format!("/v1/files/{}?version=latest", req.file_id);
        let mut attempt = 0u8;
        loop {
            attempt += 1;
            let first = attempt == 1;
            let mut c = pool
                .acquire(|| reauth_channel(&dir.0, &server, &session, &connect_lock))
                .await?;
            let host = c.host.clone();
            let token = c.token.clone();
            match get_json(&mut c.sender, &view_uri, Some(&token), &host).await {
                Ok((StatusCode::UNAUTHORIZED, _)) if first => {
                    // Session-wide auth failure: drain every stale sibling + discard this
                    // channel, forcing the retry to mint a fresh one via reauth.
                    pool.drain_idle();
                    c.mark_bad();
                    continue;
                }
                Ok((StatusCode::UNAUTHORIZED, _)) => {
                    // Still 401 after a fresh reauth ⇒ the session is genuinely expired.
                    c.mark_bad();
                    return Err(UiError::new("locked", "Your session expired. Reconnect."));
                }
                Ok((StatusCode::OK, vj)) => {
                    chan = c;
                    view_json = vj;
                    break;
                }
                Ok(_) => return Err(UiError::new("fetch_failed", "That item is not available.")),
                Err(e) if first => {
                    c.mark_bad(); // dead pooled connection — discard + retry once.
                    let _ = e;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
    // The channel-bound host + token for this call's remaining authed fetches (owned
    // clones so `&mut chan.sender` can be borrowed alongside them). The pooled channel
    // returns to the pool on `chan` drop at the end of the command.
    let host = chan.host.clone();
    let token = chan.token.clone();
    let view = crate::download::parse_file_view(&view_json)?;
    if req.version.is_none() {
        // NB: keyed on the UNVERIFIED envelope `view.version`; if it diverges from the
        // signed manifest version this is a benign cache miss (the put keys on the
        // verified `opened.version`).
        if let Some(card) = thumb
            .get_card(CacheKey { file_id, version: view.version }, &req.file_id)
            .await
        {
            return Ok(card);
        }
    }
    let manifest: Manifest =
        decode(&view.manifest_bytes).map_err(|_| UiError::new("untrusted", "Malformed record."))?;

    // Resolve the author (Phase 3: author == owner) + my own id, under the pinned D5.
    let (author, author_binding) = crate::directory::resolve_and_verify_author_logged(
        &mut chan.sender,
        &host,
        &hex(&manifest.author_id.0),
        &verifier,
        &mut trust,
        now,
    )
    .await?;
    // Trust-alarm C (spec §0-C/§7): the D5-verified author binding must ALSO be
    // provably present in the directory key-transparency log under a pinned,
    // non-equivocating checkpoint. Opt-in (see `enforce_author_transparency`); when
    // a KT key is pinned, ANY failure blocks the card as `server_untrusted`.
    enforce_author_transparency(&dir.0, session.inner(), author_binding).await?;
    let my_id = crate::directory::resolve_my_user_id(
        &mut chan.sender,
        &host,
        &username,
        &verifier,
        &mut trust,
        now,
    )
    .await?;

    // Header-only fetch (metadata/thumbnail/preview — never content). Prefers
    // the direct-link download route (`crate::direct_link`) per the effective
    // route setting.
    let route_mode = crate::config::SettingsConfig::load(&dir.0).connection.route_mode;
    let direct_http = crate::direct_link::shared_direct_http();
    let (header, header_used_direct) = crate::download::build_stream_header(
        &mut chan.sender,
        &host,
        &token,
        &req.file_id,
        &view,
        route_mode,
        direct_http,
    )
    .await?;

    // Borrow the unlocked identity UNDER the lock to unwrap MY wrap. The guard is
    // held only across `open_my_header`, which is SYNCHRONOUS (no await), so this
    // never takes the identity out (no transient `None` window for a concurrent
    // command to observe) and is panic-safe (nothing to restore). If a direct-
    // sourced header chunk failed verification, refetch the WHOLE header
    // forced-proxy and retry exactly once — fail-closed: a tampered/substituted
    // direct link never denies browsing, it falls back (the link source is
    // untrusted; a genuinely-invalid record still fails on the retry).
    let opened = match {
        let guard = session.0.lock().await;
        let identity = guard
            .identity
            .as_ref()
            .ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?;
        open_my_header(identity, file_id, &author, my_id, &header)
    } {
        Ok(opened) => opened,
        Err(e) if header_used_direct => {
            let (header, _) = crate::download::build_stream_header(
                &mut chan.sender,
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
            open_my_header(identity, file_id, &author, my_id, &header).map_err(|_| e)?
        }
        Err(e) => return Err(e),
    };

    let (title, tags) = opened
        .small_streams
        .iter()
        .find(|s| s.stream_type == StreamType::Metadata)
        .map(|s| parse_title_tags(&s.plaintext))
        .unwrap_or_else(|| ("(untitled)".to_owned(), Vec::new()));
    let thumbnail_b64 = opened
        .small_streams
        .iter()
        .find(|s| s.stream_type == StreamType::Thumbnail)
        .map(|s| B64.encode(&s.plaintext));
    let mine = my_id == author.user_id;

    // For a bundle card, compute the order-private member tally (VID/IMG/TXT/FILE)
    // from the VERIFIED signed member list. Best-effort: if the member list can't
    // be opened, the card still renders (with a bundle badge) at zero counts —
    // a member-list failure must NOT fail the whole card. Non-bundle cards stay
    // at the default zeros. This extra fetch only happens for bundles (small list)
    // and its result is cached below.
    let member_counts = if manifest.file_type == FileType::Bundle {
        match crate::commands::bundle::open_bundle_members(
            &req.file_id,
            &dir,
            &session,
            &connect_lock,
        )
        .await
        {
            Ok((body, _version, _mine)) => {
                histogram(&body.members.iter().map(|m| m.file_type).collect::<Vec<_>>())
            }
            Err(_) => crate::dto::MemberCounts::default(),
        }
    } else {
        crate::dto::MemberCounts::default()
    };

    let card = crate::dto::CardDto {
        file_id: req.file_id,
        file_type: file_type_name(manifest.file_type),
        version: opened.version,
        title,
        tags,
        thumbnail_b64,
        mine,
        author_fp: hex(&author.fingerprint[..8]),
        recovery_ok: opened.recovery_grant_ok,
        member_counts: member_counts.clone(),
    };

    // Best-effort: index the decoded card for local search (D-F). An index failure
    // must never fail the browse — swallow it.
    {
        let guard = session.0.lock().await;
        if let Some(identity) = guard.identity.as_ref() {
            if let Ok(mut idx) = crate::index::load(&dir.0, identity) {
                idx.upsert(crate::index::IndexEntry {
                    file_id: card.file_id.clone(),
                    file_type: card.file_type.clone(),
                    title: card.title.clone(),
                    tags: card.tags.clone(),
                });
                let _ = crate::index::save(&dir.0, identity, &idx);
            }
        }
    }

    thumb
        .put_card(
            CacheKey {
                file_id,
                version: opened.version,
            },
            CachedMeta {
                file_type: card.file_type.clone(),
                title: card.title.clone(),
                tags: card.tags.clone(),
                thumbnail_b64: card.thumbnail_b64.clone(),
                author_fp: card.author_fp.clone(),
                recovery_ok: card.recovery_ok,
                mine: card.mine,
                member_counts: card.member_counts.clone(),
            },
        )
        .await;
    Ok(card)
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
    fn histogram_tallies_member_file_types() {
        use maxsecu_encoding::types::FileType;
        let h = histogram(&[FileType::Video, FileType::Image, FileType::Image, FileType::Generic]);
        assert_eq!(h, crate::dto::MemberCounts { video: 1, image: 2, blog: 0, generic: 1 });
    }

    #[test]
    fn filter_param_maps_types() {
        assert_eq!(filter_param(FeedFilter::All), None);
        assert_eq!(filter_param(FeedFilter::Image), Some("image"));
        assert_eq!(filter_param(FeedFilter::Blog), Some("blog"));
    }

    #[test]
    fn parses_metadata_json_then_falls_back() {
        let (t, tags) = super::parse_title_tags(br#"{"title":"Sunset","tags":["beach","2026"]}"#);
        assert_eq!(t, "Sunset");
        assert_eq!(tags, vec!["beach".to_owned(), "2026".to_owned()]);
        // Non-JSON ⇒ whole string is the title, no tags.
        let (t2, tags2) = super::parse_title_tags(b"title=fox");
        assert_eq!(t2, "title=fox");
        assert!(tags2.is_empty());
        // Invalid UTF-8 ⇒ a safe placeholder title.
        let (t3, tags3) = super::parse_title_tags(&[0xff, 0xfe]);
        assert_eq!(t3, "(untitled)");
        assert!(tags3.is_empty());
    }
}
