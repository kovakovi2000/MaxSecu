//! Feed/browse commands: the D35 listing (`list_feed`) and per-item card
//! decryption (`decrypt_card`, added in a later task). Listing carries no values;
//! card decryption runs the verify ladder in the TCB and returns only render-ready
//! metadata + a thumbnail. The UI never sees keys, grants, or the content stream.

use tauri::State;

use crate::commands::auth::{AppDir, ConnectLock, Session};
use crate::commands::connection::{reauth, server_of};
use crate::commands::pool::{get_on_pooled_channel, AppPool};
use crate::directory::Recipient;
use crate::dto::{FeedEntryDto, FeedFilter, FeedPageDto, FeedSort, ListFeedRequest};
use crate::error::UiError;
use crate::jobs::AuthedChannel;

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

/// Apply the sort client-side. **Legacy path ONLY** — used exclusively when the
/// response carried no `total`, i.e. the server did not paginate and therefore
/// also ignored the `sort` query param (an un-upgraded server, prod `41912da`).
/// On that path the whole visible result set IS this one page, so sorting it is
/// complete and correct — exactly today's behaviour. A paginating server sorts
/// server-side and its page order is passed through UNTOUCHED (re-sorting one
/// page of a multi-page listing would silently reorder a window).
fn sort_entries_legacy(entries: &mut [FeedEntryDto], sort: FeedSort) {
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

/// The server `sort` query value. `newest` is the server's default and today's
/// listing order (`updated_at DESC, file_id ASC`); `oldest` reverses the
/// `updated_at` key only.
fn sort_param(sort: FeedSort) -> &'static str {
    match sort {
        FeedSort::NewestFirst => "newest",
        FeedSort::OldestFirst => "oldest",
    }
}

/// Build the `GET /v1/files` request URI. Pure — unit-tested.
///
/// Every parameter beyond `type`/`limit` is NEW, so an un-upgraded server simply
/// ignores it (`ListQuery` has no `deny_unknown_fields` and axum parses the query
/// with `serde_urlencoded`) — the request stays a valid page-1 request there.
/// `cursor` SUPERSEDES `offset` (the server's rule), so the two are never sent
/// together; `offset=0` is omitted entirely so a page-1 URI stays as close to
/// today's as possible.
fn build_list_uri(
    filter: FeedFilter,
    sort: FeedSort,
    owner_me: bool,
    limit: usize,
    offset: u32,
    cursor: Option<&str>,
) -> String {
    let mut uri = String::from("/v1/files?");
    if let Some(t) = filter_param(filter) {
        uri.push_str("type=");
        uri.push_str(t);
        uri.push('&');
    }
    uri.push_str("limit=");
    uri.push_str(&limit.to_string());
    uri.push_str("&sort=");
    uri.push_str(sort_param(sort));
    if owner_me {
        uri.push_str("&owner=me");
    }
    match cursor {
        // A cursor is opaque and already URL-safe (base64url, unpadded) — pass it
        // through verbatim; it fully determines the offset server-side.
        Some(c) if !c.is_empty() => {
            uri.push_str("&cursor=");
            uri.push_str(c);
        }
        _ => {
            if offset > 0 {
                uri.push_str("&offset=");
                uri.push_str(&offset.to_string());
            }
        }
    }
    uri
}

/// Parse one `GET /v1/files` response body into the [`FeedPageDto`] envelope.
/// Pure — unit-tested, including against a synthetic OLD-server body.
///
/// * `total` absent ⇒ the server does NOT paginate (it ignored `offset`/`cursor`
///   and `sort`): report `total: None` so the UI renders no pager, and apply the
///   legacy client-side sort so that single page still honours the user's choice.
/// * `total` present ⇒ a paginating server: pass its order through untouched and
///   surface `next_cursor` (JSON `null` ⇒ `None` ⇒ last page).
fn page_from_json(json: &serde_json::Value, sort: FeedSort) -> FeedPageDto {
    let mut entries: Vec<FeedEntryDto> = json
        .get("files")
        .and_then(|f| f.as_array())
        .map(|a| a.iter().filter_map(entry_from_json).collect())
        .unwrap_or_default();
    let total = json.get("total").and_then(|t| t.as_u64());
    if total.is_none() {
        sort_entries_legacy(&mut entries, sort);
    }
    let next_cursor = json
        .get("next_cursor")
        .and_then(|c| c.as_str())
        .filter(|c| !c.is_empty())
        .map(|c| c.to_owned());
    FeedPageDto {
        entries,
        next_cursor,
        total,
    }
}

/// `list_feed` — the D35 listing (api.md §8.6). Authed over a POOLED channel;
/// carries no values. Type filter, owner filter, sort and paging are all applied
/// SERVER-side; the client only passes them through and reads the envelope back.
///
/// The listing GET is itself the pool's channel-health check (see
/// [`get_on_pooled_channel`]): paging the feed used to mint a whole fresh login per
/// page, which — together with a card decode per item — is what walked the account
/// into the server's 30-challenges-per-minute cap.
///
/// **Old-server safety.** An upgraded client talking to an un-upgraded server has
/// its `offset`/`cursor`/`sort`/`owner` silently ignored and gets page 1 forever.
/// That server's body carries no `total`, so the envelope reports `total: None`
/// and the UI renders NO pager and never asks for `offset > 0` — the whole flow
/// then behaves exactly as it does today (one page, up to 50 items, client-sorted).
#[tauri::command]
pub async fn list_feed(
    req: ListFeedRequest,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
    pool: State<'_, AppPool>,
) -> Result<FeedPageDto, UiError> {
    let server = server_of(&dir.0)?;
    // WHO we are right now — the pool never hands a channel across principals.
    // Same error `reauth` itself raised when the session had no principal.
    let principal = { session.0.lock().await.principal.clone() }
        .ok_or_else(|| UiError::new("locked", "Sign in first."))?;
    // UNCHANGED clamp: default 50, cap 200. Lowering either would be a tightening
    // that breaks a shipped caller asking for limit=200.
    let limit = req.limit.unwrap_or(50).min(200);
    let uri = build_list_uri(
        req.filter,
        req.sort,
        req.owner_me.unwrap_or(false),
        limit,
        req.offset.unwrap_or(0),
        req.cursor.as_deref(),
    );
    let (_chan, json) = get_on_pooled_channel(
        &pool,
        &principal,
        &uri,
        UiError::new("feed_failed", "Could not load the feed."),
        || reauth_channel(&dir.0, &server, &session, &connect_lock),
    )
    .await?;
    Ok(page_from_json(&json, req.sort))
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
        let principal = guard
            .principal
            .as_ref()
            .ok_or_else(|| UiError::new("locked", "Sign in first."))?;
        crate::transparency::DiskKtCheckpointStore::open_for(dir, identity, principal)?
    };
    tokio::task::spawn_blocking(move || {
        crate::transparency::verify_binding_transparency(
            &pins,
            &kt_pubs,
            &mut store,
            &binding_bytes,
        )
    })
    .await
    .map_err(|_| {
        UiError::new(
            "server_untrusted",
            "The key-transparency check could not run.",
        )
    })?
}

/// Run the §12.5 header ladder for MY wrap with a transiently-borrowed identity.
/// Factored out so the `&identity` borrow (the `ctx` holds `enc_secret()`) is
/// confined to this call — the caller restores the identity into the session on
/// every path, borrow already released.
fn open_my_header(
    identity: &maxsecu_client_core::Identity,
    file_id: [u8; 16],
    author: &crate::directory::VerifiedAuthor,
    me: Recipient,
    header: &maxsecu_client_core::StreamHeader,
) -> Result<maxsecu_client_core::OpenedHeader, UiError> {
    use maxsecu_client_core::verify_and_open_headers;
    let ctx = crate::directory::build_verify_ctx(file_id, author, me, identity);
    verify_and_open_headers(&ctx, header)
        .map_err(|_| UiError::new("verify_failed", "This item failed verification."))
}

/// Mint a fresh authed channel for the pool by reusing the EXISTING `reauth`
/// VERBATIM and wrapping its `(sender, host, token)` into an [`AuthedChannel`] — the
/// three parts stay bound together as one channel-bound unit. The pool only calls
/// this under its internal auth gate, so `reauth`'s `ConnectLock` `try_lock` is never
/// contended.
///
/// `pub(crate)` because it is now the ONE mint closure every authed read command
/// hands to the pool (viewer, bundle, download, video, feed) — a single place where
/// a login is actually spent.
pub(crate) async fn reauth_channel(
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
    use maxsecu_client_core::MemoryTrustStore;
    use maxsecu_encoding::decode;
    use maxsecu_encoding::structs::Manifest;
    use maxsecu_encoding::types::StreamType;

    let file_id = hex16(&req.file_id)?;
    use crate::thumb_cache::{CacheKey, CachedMeta};
    // Zero-network hit when the caller passed the version it already knows.
    if let Some(v) = req.version {
        if let Some(card) = thumb
            .get_card(
                CacheKey {
                    file_id,
                    version: v,
                },
                &req.file_id,
            )
            .await
        {
            return Ok(card);
        }
    }
    let pinned = crate::config::load_directory_pub(&dir.0)?;
    let mut trust = MemoryTrustStore::new();
    let now = now_ms();

    let principal = {
        let s = session.0.lock().await;
        s.principal.clone()
    }
    .ok_or_else(|| UiError::new("locked", "Sign in first."))?;

    let server = server_of(&dir.0)?;

    // Borrow a channel from the pool instead of re-authing per call. Concurrent
    // `decrypt_card` calls take DIFFERENT cached channels (no ConnectLock contention,
    // no identity-take on the hot path); only a cold-start / expired channel mints a
    // fresh one via `reauth` (under the pool's auth gate). The §8.5 view GET is the
    // FIRST use of the (possibly reused) channel and therefore the fail-closed
    // channel-health check — that whole discipline (401 ⇒ drain + one forced fresh
    // mint; transport error ⇒ discard this channel + retry once) now lives ONCE in
    // `get_on_pooled_channel`, shared with every other authed read.
    let (mut chan, view_json) = get_on_pooled_channel(
        &pool,
        &principal,
        &format!("/v1/files/{}?version=latest", req.file_id),
        UiError::new("fetch_failed", "That item is not available."),
        || reauth_channel(&dir.0, &server, &session, &connect_lock),
    )
    .await?;
    // The channel-bound host + token for this call's remaining authed fetches (owned
    // clones so `&mut chan.sender` can be borrowed alongside them). The pooled channel
    // returns to the pool on `chan` drop at the end of the command.
    let host = chan.host.clone();
    let token = chan.token.clone();
    // Offline-D5 hop (spec §3/§7): resolve the effective directory verifier over the
    // pooled pinned channel; fail closed on a bad delegation before any author verify.
    let verifier =
        crate::directory::build_delegated_verifier(&mut chan.sender, &host, pinned, now).await?;
    let view = crate::download::parse_file_view(&view_json)?;
    if req.version.is_none() {
        // NB: keyed on the UNVERIFIED envelope `view.version`; if it diverges from the
        // signed manifest version this is a benign cache miss (the put keys on the
        // verified `opened.version`).
        if let Some(card) = thumb
            .get_card(
                CacheKey {
                    file_id,
                    version: view.version,
                },
                &req.file_id,
            )
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
    let me = crate::directory::resolve_me(
        &mut chan.sender,
        &host,
        &principal,
        &verifier,
        &mut trust,
        now,
    )
    .await?;

    // Header-only fetch (metadata/thumbnail/preview — never content). Prefers
    // the direct-link download route (`crate::direct_link`) per the effective
    // route setting.
    let route_mode = crate::config::SettingsConfig::load(&dir.0)
        .connection
        .route_mode;
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
        open_my_header(identity, file_id, &author, me, &header)
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
            open_my_header(identity, file_id, &author, me, &header).map_err(|_| e)?
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
    let mine = me.id().0 == author.user_id;

    // For a bundle card, compute the order-private member tally (VID/IMG/TXT/FILE)
    // from the VERIFIED signed member list — REUSING THIS CALL'S already-warm
    // pooled channel (`chan`) AND its already-fetched `view` (same file id, same
    // instant — one §8.5 GET, not two) via `open_bundle_members_on`, NOT a fresh
    // `reauth`.
    // That keeps the nested member fetch off the single global `ConnectLock`, so a
    // concurrent feed decode no longer loses the lock and silently falls back to
    // zero counts. Best-effort: on any failure the card still renders (bundle
    // badge, zero counts) but we record `member_ok = false` and DON'T cache it
    // below, so a transient failure self-heals on reload instead of sticking as a
    // cached blank. Non-bundle cards stay at the default zeros (and cache).
    let (member_counts, member_ok) = if manifest.file_type == FileType::Bundle {
        match crate::commands::bundle::open_bundle_members_on(
            &mut chan.sender,
            &host,
            &token,
            &req.file_id,
            &view,
            &dir,
            &session,
        )
        .await
        {
            Ok((body, _version, _mine)) => (
                histogram(&body.members.iter().map(|m| m.file_type).collect::<Vec<_>>()),
                true,
            ),
            Err(_) => (crate::dto::MemberCounts::default(), false),
        }
    } else {
        (crate::dto::MemberCounts::default(), true)
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
        if let (Some(identity), Some(who)) = (guard.identity.as_ref(), guard.principal.as_ref()) {
            if let Ok(mut idx) = crate::index::load_for(&dir.0, identity, who) {
                idx.upsert(crate::index::IndexEntry {
                    file_id: card.file_id.clone(),
                    file_type: card.file_type.clone(),
                    title: card.title.clone(),
                    tags: card.tags.clone(),
                });
                let _ = crate::index::save_for(&dir.0, identity, who, &idx);
            }
        }
    }

    // Skip caching a bundle card whose member tally failed to load (`member_ok`
    // is false only for a bundle whose `open_bundle_members_on` errored): caching
    // it would make the empty summary sticky. Everything else (all non-bundles,
    // and bundles with a good tally) caches normally.
    if member_ok {
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
    }
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
        sort_entries_legacy(&mut entries, FeedSort::NewestFirst);
        assert_eq!(
            entries.iter().map(|e| e.updated_at).collect::<Vec<_>>(),
            vec![300, 200, 100]
        );
        sort_entries_legacy(&mut entries, FeedSort::OldestFirst);
        assert_eq!(
            entries.iter().map(|e| e.updated_at).collect::<Vec<_>>(),
            vec![100, 200, 300]
        );
    }

    // ---- F3 paging: URI construction (frozen surface #10, widening only) ----

    #[test]
    fn page_one_uri_keeps_todays_type_and_limit_params() {
        // The default page-1 request must stay a superset of today's URI: same
        // `type`/`limit`, plus the new (old-server-ignored) `sort`. No `offset`.
        let u = build_list_uri(FeedFilter::All, FeedSort::NewestFirst, false, 50, 0, None);
        assert_eq!(u, "/v1/files?limit=50&sort=newest");
        let u = build_list_uri(
            FeedFilter::Image,
            FeedSort::NewestFirst,
            false,
            200,
            0,
            None,
        );
        assert_eq!(u, "/v1/files?type=image&limit=200&sort=newest");
        assert!(!u.contains("offset"), "offset=0 must not be sent");
        assert!(
            !u.contains("owner"),
            "owner must be absent unless asked for"
        );
    }

    #[test]
    fn uri_carries_offset_sort_and_owner() {
        let u = build_list_uri(
            FeedFilter::Video,
            FeedSort::OldestFirst,
            true,
            50,
            100,
            None,
        );
        assert_eq!(
            u,
            "/v1/files?type=video&limit=50&sort=oldest&owner=me&offset=100"
        );
    }

    #[test]
    fn cursor_supersedes_offset_in_the_uri() {
        // The server treats a valid cursor as authoritative; sending both would be
        // ambiguous, so the client never does.
        let u = build_list_uri(
            FeedFilter::All,
            FeedSort::NewestFirst,
            false,
            50,
            150,
            Some("MXwxNTB8YWJjZA"),
        );
        assert_eq!(u, "/v1/files?limit=50&sort=newest&cursor=MXwxNTB8YWJjZA");
        assert!(!u.contains("offset="), "a cursor must suppress offset");
        // An empty cursor is treated as absent (falls back to offset).
        let u = build_list_uri(
            FeedFilter::All,
            FeedSort::NewestFirst,
            false,
            50,
            150,
            Some(""),
        );
        assert_eq!(u, "/v1/files?limit=50&sort=newest&offset=150");
    }

    #[test]
    fn sort_param_maps_both_orders() {
        assert_eq!(sort_param(FeedSort::NewestFirst), "newest");
        assert_eq!(sort_param(FeedSort::OldestFirst), "oldest");
    }

    // ---- F3 paging: response-envelope parsing --------------------------------

    #[test]
    fn parses_the_paginated_envelope_and_preserves_server_order() {
        // A NEW server: `total` present ⇒ the page order is authoritative and must
        // NOT be re-sorted client-side, even though these entries are not in
        // `updated_at` order (a re-share bumps `updated_at`, so a page really can
        // look unordered by that key while still being the server's page).
        let body = serde_json::json!({
            "files": [j("aa", "image", 1, 100, true), j("bb", "blog", 2, 300, false)],
            "next_cursor": "MXw1MHxkZWFkYmVlZg",
            "total": 137,
        });
        let page = page_from_json(&body, FeedSort::NewestFirst);
        assert_eq!(page.total, Some(137));
        assert_eq!(page.next_cursor.as_deref(), Some("MXw1MHxkZWFkYmVlZg"));
        assert_eq!(
            page.entries
                .iter()
                .map(|e| e.file_id.as_str())
                .collect::<Vec<_>>(),
            vec!["aa", "bb"],
            "a paginating server's page order must pass through untouched"
        );
    }

    #[test]
    fn last_page_reports_a_null_cursor_as_none() {
        let body = serde_json::json!({
            "files": [j("aa", "image", 1, 100, true)],
            "next_cursor": serde_json::Value::Null,
            "total": 1,
        });
        let page = page_from_json(&body, FeedSort::NewestFirst);
        assert_eq!(page.total, Some(1));
        assert_eq!(page.next_cursor, None, "a null next_cursor means last page");
    }

    #[test]
    fn old_server_body_without_total_is_reported_as_unpaginated() {
        // THE OLD-SERVER HAZARD. prod `41912da` returns exactly this body shape:
        // `files` + a hard-coded `next_cursor: null`, and NO `total` key. The
        // envelope must say `total: None` so the UI renders no pager and never
        // asks for offset > 0 — and the legacy client-side sort must still run,
        // because that server ignored the `sort` param too.
        let body = serde_json::json!({
            "files": [
                j("aa", "image", 1, 100, true),
                j("bb", "blog", 2, 300, false),
                j("cc", "image", 1, 200, true),
            ],
            "next_cursor": serde_json::Value::Null,
        });
        let page = page_from_json(&body, FeedSort::NewestFirst);
        assert_eq!(
            page.total, None,
            "no `total` ⇒ this server does not paginate"
        );
        assert_eq!(page.next_cursor, None);
        assert_eq!(
            page.entries
                .iter()
                .map(|e| e.updated_at)
                .collect::<Vec<_>>(),
            vec![300, 200, 100],
            "the legacy single page must still honour the requested sort"
        );
        let page = page_from_json(&body, FeedSort::OldestFirst);
        assert_eq!(
            page.entries
                .iter()
                .map(|e| e.updated_at)
                .collect::<Vec<_>>(),
            vec![100, 200, 300]
        );
    }

    #[test]
    fn unknown_type_early_return_parses_as_an_empty_first_page() {
        // The server's unknown-`type` early return: empty files, null cursor,
        // total 0. It must NOT be mistaken for an old server (total IS present).
        let body =
            serde_json::json!({ "files": [], "next_cursor": serde_json::Value::Null, "total": 0 });
        let page = page_from_json(&body, FeedSort::NewestFirst);
        assert!(page.entries.is_empty());
        assert_eq!(page.total, Some(0));
        assert_eq!(page.next_cursor, None);
    }

    #[test]
    fn envelope_serializes_the_three_ui_fields() {
        let page = page_from_json(
            &serde_json::json!({ "files": [j("aa", "image", 1, 100, true)], "total": 9 }),
            FeedSort::NewestFirst,
        );
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&page).unwrap()).unwrap();
        assert_eq!(v.as_object().unwrap().len(), 3);
        assert_eq!(v["entries"].as_array().unwrap().len(), 1);
        assert_eq!(v["total"], 9);
        assert!(v["next_cursor"].is_null());
    }

    #[test]
    fn list_feed_request_binds_an_old_ui_dist_payload() {
        // An exe upgraded WITHOUT its ui/dist rebuild still sends only
        // {filter, sort} — every new paging field must default.
        let req: ListFeedRequest =
            serde_json::from_str(r#"{"filter":"all","sort":"newest-first"}"#).unwrap();
        assert_eq!(req.limit, None);
        assert_eq!(req.offset, None);
        assert_eq!(req.cursor, None);
        assert_eq!(req.owner_me, None);
        // …and the new UI's full payload binds too.
        let req: ListFeedRequest = serde_json::from_str(
            r#"{"filter":"image","sort":"oldest-first","limit":50,"offset":100,"cursor":"abc","owner_me":true}"#,
        )
        .unwrap();
        assert_eq!(req.offset, Some(100));
        assert_eq!(req.cursor.as_deref(), Some("abc"));
        assert_eq!(req.owner_me, Some(true));
    }

    #[test]
    fn histogram_tallies_member_file_types() {
        use maxsecu_encoding::types::FileType;
        let h = histogram(&[
            FileType::Video,
            FileType::Image,
            FileType::Image,
            FileType::Generic,
        ]);
        assert_eq!(
            h,
            crate::dto::MemberCounts {
                video: 1,
                image: 2,
                blog: 0,
                generic: 1
            }
        );
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
