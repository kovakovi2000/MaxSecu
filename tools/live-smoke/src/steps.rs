//! The individual smoke assertions. Filled in across Tasks 3-6.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use maxsecu_client_app::commands::register::register_with_key_exchange;
use maxsecu_client_app::config::RouteMode;
use maxsecu_client_app::directory::resolve_recovery_pin;
use maxsecu_client_app::download::{build_download_bundle, parse_file_view};
use maxsecu_client_app::keystore;
use maxsecu_client_app::session::login_exchange;
use maxsecu_client_core::{
    build_upload, verify_and_open, Identity, UploadParams, VerifyContext, NO_ADMINS, NO_GRANTERS,
};
use maxsecu_crypto::EncPublicKey;
use maxsecu_encoding::decode;
use maxsecu_encoding::structs::DirBinding;
use maxsecu_encoding::types::{FileType, Id, RecipientType, Role, StreamType, Timestamp};

use crate::net::{self, Conn};

const PASSPHRASE: &str = "live-smoke enrol passphrase battery 9!";
const TS: u64 = 1_719_500_000_000;
const BLOG_BODY: &[u8] = b"live-smoke blog body: prove the full upload + view-back round-trips.";

/// Create `dir` and drop `register.key = key` into it — the on-disk shape a fresh
/// client install has before its first enroll. Split out of `app_dir_with_key` so
/// the backup-E2E `seed` phase can put the app-dir wherever it needs it (a state-file
/// sibling that survives the run) rather than in a throwaway temp dir.
fn seed_app_dir(dir: &Path, key: &str) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    std::fs::write(dir.join("register.key"), key.as_bytes())
        .map_err(|e| format!("write register.key: {e}"))?;
    Ok(())
}

/// A fresh temp app-dir seeded with `register.key = key`.
fn app_dir_with_key(tag: &str, key: &str) -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join(format!(
        "livesmoke_{tag}_{}",
        net::hex(&maxsecu_crypto::random_array::<8>())
    ));
    seed_app_dir(&dir, key)?;
    Ok(dir)
}

/// Enroll `username` with `key` over `c`; returns (app_dir, user_id_hex).
async fn enroll(
    c: &mut Conn,
    host: &str,
    tag: &str,
    username: &str,
    key: &str,
) -> Result<(PathBuf, String), String> {
    let dir = app_dir_with_key(tag, key)?;
    let reg = register_with_key_exchange(&mut c.sender, host, &dir, username, PASSPHRASE)
        .await
        .map_err(|e| format!("enroll {username}: {}", e.message))?;
    Ok((dir, reg.user_id))
}

/// Channel-bound login for an already-enrolled identity sealed in `dir`.
async fn login(c: &mut Conn, host: &str, dir: &Path, username: &str) -> Result<(Identity, String), String> {
    let id = keystore::unlock(dir, PASSPHRASE).map_err(|e| format!("unlock {username}: {}", e.message))?;
    let ok = login_exchange(&mut c.sender, &id, username, host, &c.exporter, TS)
        .await
        .map_err(|e| format!("login {username}: {}", e.message))?;
    if ok.token.is_empty() { return Err(format!("empty token for {username}")); }
    Ok((id, ok.token))
}

/// Upload a blog as `owner` (already logged in with `token`); returns the file_id.
/// Exercises the recovery-pin gate (`resolve_recovery_pin`): the server's served
/// recovery pubkey must match this app's embedded pin before any DEK wrap happens.
async fn upload_blog(
    c: &mut Conn,
    host: &str,
    owner: &Identity,
    owner_uid_hex: &str,
    token: &str,
    body: &[u8],
    title: &str,
) -> Result<[u8; 16], String> {
    let recovery = resolve_recovery_pin(&mut c.sender, host)
        .await
        .map_err(|e| format!("resolve_recovery_pin (recovery gate): {}", e.message))?;

    let streams = maxsecu_client_app::upload::prepare_blog_streams(body.to_vec(), title, &[]);
    let file_id = Id(maxsecu_crypto::random_array::<16>());
    let bundle = build_upload(
        &UploadParams {
            owner,
            owner_id: Id(net::hex16(owner_uid_hex)?),
            owner_key_version: 1,
            file_id,
            file_type: FileType::Blog,
            chunk_size: 4096,
            recovery_pub: EncPublicKey::from_bytes(recovery.enc_pub),
            recovery_mlkem_pub: recovery.mlkem_pub,
            created_at: Timestamp(TS),
        },
        &streams,
    )
    .map_err(|e| format!("build_upload: {e:?}"))?;

    maxsecu_client_app::upload::run_pipeline(
        &mut c.sender,
        host,
        token,
        &bundle,
        |_, _| {},
        maxsecu_client_app::upload::StageFlags::default(),
    )
    .await
    .map_err(|e| format!("run_pipeline: {}", e.message))?;

    Ok(file_id.0)
}

/// Fetch the owner's own file view, download every stream, verify + decrypt, and
/// return the plaintext `content` stream bytes.
async fn view_own_blog(
    c: &mut Conn,
    host: &str,
    owner: &Identity,
    owner_uid_hex: &str,
    token: &str,
    file_id: [u8; 16],
) -> Result<Vec<u8>, String> {
    let fid_hex = net::hex(&file_id);
    let (st, json) = net::get(c, &format!("/v1/files/{fid_hex}?version=latest"), host, Some(token)).await?;
    if st != hyper::StatusCode::OK {
        return Err(format!("file view GET status {st}"));
    }
    let view = parse_file_view(&json).map_err(|e| format!("parse_file_view: {}", e.message))?;
    let (bundle, _direct) =
        build_download_bundle(&mut c.sender, host, token, &fid_hex, &view, RouteMode::PreferServer, None)
            .await
            .map_err(|e| format!("build_download_bundle: {}", e.message))?;

    let ctx = VerifyContext {
        file_id: Id(file_id),
        author_sig_pub: owner.sig_pub_bytes(),
        owner_sig_pub: owner.sig_pub_bytes(),
        recipient_id: Id(net::hex16(owner_uid_hex)?),
        recipient_type: RecipientType::User,
        recipient_secret: owner.enc_secret(),
        // Suite::V2 upload (PQ owner + PQ recovery) ⇒ the ML-KEM seed is required.
        recipient_mlkem_seed: owner.mlkem_seed(),
        seen_max_version: None,
        granter_sig_pub: &NO_GRANTERS,
        admin_sig_pub: &NO_ADMINS,
        tombstones: None,
        compromise: None,
    };
    let opened = verify_and_open(&ctx, &bundle).map_err(|e| format!("verify_and_open: {e:?}"))?;
    let content = opened
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Content)
        .ok_or("no content stream in opened file")?;
    Ok(content.plaintext.clone())
}

/// Admin mints a fresh single-use registration key over `c` with `admin_token`.
async fn mint_key(c: &mut Conn, host: &str, admin_token: &str) -> Result<String, String> {
    let (st, res) = net::post(c, "/v1/registration-keys", host, Some(admin_token), serde_json::json!({})).await?;
    if st != hyper::StatusCode::CREATED {
        return Err(format!("mint registration key status {st}"));
    }
    res["registration_key"]
        .as_str()
        .map(|s| s.to_owned())
        .ok_or_else(|| "no registration_key in mint response".to_owned())
}

/// As the logged-in caller (`token`), list the feed and assert `want_fid_hex` appears.
async fn assert_feed_contains(c: &mut Conn, host: &str, token: &str, want_fid_hex: &str) -> Result<(), String> {
    let (st, json) = net::get(c, "/v1/files?limit=200", host, Some(token)).await?;
    if st != hyper::StatusCode::OK {
        return Err(format!("feed GET status {st}"));
    }
    let found = json["files"].as_array().map(|a| {
        a.iter().any(|f| f["file_id"].as_str() == Some(want_fid_hex))
    }).unwrap_or(false);
    if !found {
        return Err(format!("user2 feed does not contain admin file {want_fid_hex}"));
    }
    Ok(())
}

// =========================================================================
// F3 -- THE PAGINATED LISTING (`GET /v1/files`)
//
// F3 is the only fix in this upgrade that is user-visible on prod today, and it
// had ZERO coverage in the rehearsal lap: a grep of the 196 KB lap log found 0
// occurrences of `/v1/files` and 0 of `cursor`. `assert_feed_contains` below
// touches the route, but it lives in `Phase::All`, and the lap runs only
// `--phase seed` and `--phase verify`.
//
// So the two halves of the contract are asserted here, in the two phases the lap
// actually runs, against a LIVE server over the pinned transport as the seeded
// user with real seeded rows:
//   * `seed`   -- pre-upgrade, PROD-era server: no `total`, and it does NOT page.
//   * `verify` -- post-upgrade (and again post-restore): the full paging contract.
// The client code is byte-identical between the two calls; only the server differs.
// =========================================================================

/// One `GET /v1/files<query>` as the logged-in caller. `query` includes its own `?`.
async fn list_page(
    c: &mut Conn,
    host: &str,
    token: &str,
    query: &str,
) -> Result<(hyper::StatusCode, serde_json::Value), String> {
    net::get(c, &format!("/v1/files{query}"), host, Some(token)).await
}

/// The `file_id`s of a listing page, in served order.
fn page_ids(json: &serde_json::Value) -> Result<Vec<String>, String> {
    let arr = json["files"]
        .as_array()
        .ok_or("listing response has no 'files' array")?;
    arr.iter()
        .map(|f| {
            f["file_id"]
                .as_str()
                .map(|s| s.to_owned())
                .ok_or_else(|| "listing entry has no file_id".to_owned())
        })
        .collect()
}

/// One listing page as `(file_id, file_type)` pairs, in served order.
///
/// `file_type` is the AUTHENTICATED type the server records from the signed manifest
/// (api.md §8.6, `store.rs::FileListEntry`) — the same column `?type=` filters on — so
/// comparing a filtered page against it is a real check rather than a tautology.
fn page_entries(json: &serde_json::Value) -> Result<Vec<(String, String)>, String> {
    let arr = json["files"]
        .as_array()
        .ok_or("listing response has no 'files' array")?;
    arr.iter()
        .map(|f| {
            let id = f["file_id"]
                .as_str()
                .ok_or_else(|| "listing entry has no file_id".to_owned())?;
            let ty = f["file_type"].as_str().ok_or_else(|| {
                format!(
                    "listing entry {id} carries no file_type -- the exclusion check \
                     below cannot judge a filter without it"
                )
            })?;
            Ok((id.to_owned(), ty.to_owned()))
        })
        .collect()
}

/// Decide whether a `?type=<want>` page is a REAL filter of `wide` (the unfiltered
/// listing). Returns the one-line summary the caller prints, or the diagnosis.
///
/// Split out of [`assert_paginated_listing`] on purpose: it is a pure function over two
/// already-fetched pages, so the tests at the bottom of this file can pin the exact
/// regression it exists to catch without a live server.
///
/// THE HOLE THIS CLOSES. The previous form asserted only three things:
///
/// ```text
///     typed.total == typed_ids.len()
///     !typed_ids.is_empty()
///     typed_ids.len() as u64 <= total
/// ```
///
/// A server that had DROPPED the `type` parameter entirely serves the WHOLE feed back
/// and satisfies all three IDENTICALLY — on the lap's box, 4 of 4 rows instead of 3 of
/// 4. And `type` is a PROD-ERA parameter: 41912da's `ListQuery` already carries
/// `file_type`, and 41912da's `feed.rs` already sends `/v1/files?type=…`. So a paging
/// rewrite that silently dropped the filter would show every existing user's filtered
/// feed as unfiltered, and the lap would still have recorded PASS. The fix is to assert
/// what a filter is FOR: that it EXCLUDES.
fn check_type_filter(
    wide: &[(String, String)],
    typed: &[(String, String)],
    want: &str,
) -> Result<String, String> {
    let expect: Vec<String> = wide
        .iter()
        .filter(|(_, t)| t == want)
        .map(|(i, _)| i.clone())
        .collect();
    let excluded: Vec<(String, String)> = wide.iter().filter(|(_, t)| t != want).cloned().collect();

    // NON-VACUITY, LOUDLY. An EXCLUSION assertion needs something to exclude: on a
    // corpus of one single file_type, "the filter kept everything" and "the filter is
    // gone" are the SAME observation, and anything written here would be a tautology
    // again. The seed uploads a blog AND an image precisely so a strict subset exists,
    // so a one-type corpus is a broken box, not an expected state — fail rather than
    // quietly assert something weaker under the same name.
    if expect.is_empty() {
        return Err(format!(
            "no file in the unfiltered listing has type '{want}' ({} row(s), types: {:?}) \
             -- the type-filter assertion would have nothing to keep",
            wide.len(),
            wide.iter().map(|(_, t)| t.as_str()).collect::<Vec<_>>()
        ));
    }
    if excluded.is_empty() {
        return Err(format!(
            "every one of the {} visible file(s) has type '{want}', so there is NOTHING \
             for the filter to exclude -- a server that ignored `type` entirely would be \
             indistinguishable from one that honoured it. The seed uploads a blog AND an \
             image so this cannot normally happen; the corpus on this box is wrong.",
            wide.len()
        ));
    }

    // (1) Every served entry really carries the requested type.
    if let Some((id, t)) = typed.iter().find(|(_, t)| t != want) {
        return Err(format!(
            "type={want} served {id}, whose authenticated file_type is '{t}' -- the \
             filter is not filtering"
        ));
    }
    // (2) The served set is EXACTLY the unfiltered entries of that type: nothing
    //     missing (over-filtering hides a user's own posts) and nothing extra.
    let got = sorted_unique(&typed.iter().map(|(i, _)| i.clone()).collect::<Vec<_>>());
    let want_set = sorted_unique(&expect);
    if got != want_set {
        return Err(format!(
            "type={want} served {got:?} but the unfiltered listing says the '{want}' \
             files are {want_set:?}"
        ));
    }
    // (3) A PROPER subset: strictly fewer entries than the unfiltered listing. This is
    //     the assertion the old three could not make, and the one that fails when the
    //     parameter is dropped.
    if typed.len() >= wide.len() {
        return Err(format!(
            "type={want} served {} of {} entries -- a filtered listing must be a PROPER \
             subset (the {} non-'{want}' file(s) must be gone)",
            typed.len(),
            wide.len(),
            excluded.len()
        ));
    }
    // (4) Say the exclusion out loud, per excluded id, so a failure names the file that
    //     leaked rather than only the counts.
    for (id, t) in &excluded {
        if got.binary_search(id).is_ok() {
            return Err(format!(
                "type={want} served {id}, which is a '{t}' -- it must have been excluded"
            ));
        }
    }
    Ok(format!(
        "type={want} is a REAL filter: {} of {} entries, and the {} non-'{want}' \
         file(s) ({}) are absent",
        typed.len(),
        wide.len(),
        excluded.len(),
        excluded
            .iter()
            .map(|(i, t)| format!("{i} [{t}]"))
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

/// The `updated_at` values of a listing page, in served order.
fn page_updated_at(json: &serde_json::Value) -> Result<Vec<u64>, String> {
    let arr = json["files"]
        .as_array()
        .ok_or("listing response has no 'files' array")?;
    arr.iter()
        .map(|f| {
            f["updated_at"]
                .as_u64()
                .ok_or_else(|| "listing entry has no numeric updated_at".to_owned())
        })
        .collect()
}

fn sorted_unique(ids: &[String]) -> Vec<String> {
    let mut v = ids.to_vec();
    v.sort();
    v.dedup();
    v
}

/// F3 against the PRE-UPGRADE (prod-era) server. It must look exactly like the
/// pre-paging contract, because that is what the shipped client is written against:
/// `total`'s ABSENCE is the version signal that tells the feed to render no pager at
/// all. A server that leaked a `total` here while still ignoring `offset` would make
/// the client draw `<< 1 2 3 >>` and then serve page 1 forever.
async fn assert_listing_is_pre_paging(c: &mut Conn, host: &str, token: &str) -> Result<(), String> {
    let (st, base) = list_page(c, host, token, "?limit=200").await?;
    if st != hyper::StatusCode::OK {
        return Err(format!("pre-upgrade GET /v1/files status {st}"));
    }
    let base_ids = page_ids(&base)?;
    // NON-VACUITY: an empty feed would satisfy every check below without proving one.
    if base_ids.is_empty() {
        return Err(
            "pre-upgrade GET /v1/files returned an EMPTY feed -- the seeded uploads \
             are not listed, so every assertion here would be vacuous"
                .to_owned(),
        );
    }
    if base.get("total").is_some() {
        return Err(format!(
            "the PRE-UPGRADE server already reports `total` ({}) -- it is not a prod-era \
             server, so the old-server half of the F3 proof is void",
            base["total"]
        ));
    }
    if !base["next_cursor"].is_null() {
        return Err(format!(
            "the PRE-UPGRADE server returned a next_cursor ({}) -- it was always null \
             before paging landed",
            base["next_cursor"]
        ));
    }
    // ...and it must NOT page. `offset` is not a field on the prod-era `ListQuery`,
    // so `serde_urlencoded` drops it and the identical first page comes back.
    let (sto, off) = list_page(c, host, token, "?limit=200&offset=1").await?;
    if sto != hyper::StatusCode::OK {
        return Err(format!("pre-upgrade GET /v1/files?offset=1 status {sto}"));
    }
    if page_ids(&off)? != base_ids {
        return Err(
            "the PRE-UPGRADE server honoured `offset` -- it is not the prod-era listing".into(),
        );
    }
    if off.get("total").is_some() {
        return Err("the PRE-UPGRADE server reported `total` on the offset request".into());
    }
    eprintln!(
        "live-smoke seed: PRE-UPGRADE listing is pre-paging as expected \
         ({} file(s), no `total`, next_cursor null, `offset` ignored)",
        base_ids.len()
    );
    Ok(())
}

/// F3 against the UPGRADED server: the whole paging surface.
///
/// WHAT THIS PROVES: a default listing still works; `limit` is honoured; `offset`
/// serves a DISJOINT page; `total` is present and equals the real row count; walking
/// the feed by `cursor` reproduces exactly the unpaged set with no repeats; `sort`
/// is parsed and `oldest` mirrors `newest`; `owner=me` is a real filter-bearing
/// parameter; `type=blog` EXCLUDES (it serves a proper subset that is exactly the
/// blogs, and the seeded image is absent); and a cursor replayed under a CHANGED
/// filter is refused with a 400 carrying a machine code, rather than silently serving
/// the wrong page of a different result set.
///
/// WHAT THIS DOES NOT PROVE — two things, both stated rather than papered over:
///
///   * that `owner=me` EXCLUDES a file the caller can see but does not own. Since
///     736bd2c the feed is scoped to the caller's own wraps, and the seed/verify path
///     enrolls exactly ONE account -- so no such file exists on this box, and
///     manufacturing one would need a second account that has RESHARED to this one.
///     See the two indirect checks in step 7 (`bad_owner` 400 + the cursor
///     fingerprint) for what is asserted instead.
///   * that `type=` is correct for the types this box never holds. The seed uploads a
///     blog and an image, so the exclusion is proven for exactly that pair; `video`,
///     `generic` and `bundle` are never seeded here and are covered only by the
///     server's own unit tests. What IS proven is the property that actually breaks a
///     user's feed -- that the parameter is honoured at all rather than dropped -- and
///     `check_type_filter` FAILS LOUDLY rather than weakening itself if the corpus
///     ever stops carrying two distinct types.
async fn assert_paginated_listing(c: &mut Conn, host: &str, token: &str) -> Result<(), String> {
    // ---- 1. a DEFAULT listing (no new parameter at all) still works ----
    // The pre-paging client sends exactly this. If widening the query broke it, every
    // existing user's feed would be empty after the upgrade.
    let (st, dflt) = list_page(c, host, token, "").await?;
    if st != hyper::StatusCode::OK {
        return Err(format!("default GET /v1/files status {st}"));
    }
    if page_ids(&dflt)?.is_empty() {
        return Err(
            "default GET /v1/files returned an EMPTY feed on the upgraded server -- \
             every assertion below would be vacuous"
                .to_owned(),
        );
    }

    // ---- 2. `total` is PRESENT and CORRECT ----
    let total = dflt
        .get("total")
        .and_then(|t| t.as_u64())
        .ok_or("upgraded server: GET /v1/files carries no numeric `total` -- a numbered pager cannot render")?;
    let (_, wide) = list_page(c, host, token, "?limit=200").await?;
    let wide_ids = page_ids(&wide)?;
    if wide_ids.len() as u64 != total {
        return Err(format!(
            "`total` is {total} but an unpaged (limit=200) listing serves {} entries -- \
             the pager would render the wrong number of pages",
            wide_ids.len()
        ));
    }
    if total < 2 {
        return Err(format!(
            "only {total} file(s) are visible -- the paging assertions below need at least 2"
        ));
    }

    // ---- 3. `limit` is HONOURED ----
    let (_, p0) = list_page(c, host, token, "?limit=1").await?;
    let p0_ids = page_ids(&p0)?;
    if p0_ids.len() != 1 {
        return Err(format!("limit=1 served {} entries, not 1", p0_ids.len()));
    }

    // ---- 4. `offset` serves a DISJOINT page ----
    let (_, p1) = list_page(c, host, token, "?limit=1&offset=1").await?;
    let p1_ids = page_ids(&p1)?;
    if p1_ids.len() != 1 {
        return Err(format!(
            "limit=1&offset=1 served {} entries, not 1",
            p1_ids.len()
        ));
    }
    if p1_ids[0] == p0_ids[0] {
        return Err(format!(
            "offset=1 served the SAME entry as offset=0 ({}) -- the server is not paging",
            p0_ids[0]
        ));
    }

    // ---- 5. a `cursor` ROUND-TRIPS, and the walk reproduces the whole feed ----
    let c0 = p0["next_cursor"]
        .as_str()
        .ok_or("limit=1 page 1 carries no next_cursor even though total > 1")?
        .to_owned();
    let (stc, via_cursor) = list_page(c, host, token, &format!("?limit=1&cursor={c0}")).await?;
    if stc != hyper::StatusCode::OK {
        return Err(format!("replaying our own next_cursor gave status {stc}"));
    }
    if page_ids(&via_cursor)? != p1_ids {
        return Err(format!(
            "the cursor page and the offset=1 page disagree: {:?} vs {:?}",
            page_ids(&via_cursor)?,
            p1_ids
        ));
    }
    // Walk the feed a page at a time. This is what pins `total` to reality: it is the
    // number a numbered pager divides by `limit`, so a `total` that does not match the
    // number of rows actually reachable is a page count that lies.
    let mut walked: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut hops: u64 = 0;
    loop {
        // Bounded: `next_cursor` is null-checked below, but a server that never
        // advanced would otherwise spin forever inside the oracle.
        if hops > total + 2 {
            return Err(format!(
                "the cursor walk did not terminate within {} hops for total={total}",
                total + 2
            ));
        }
        hops += 1;
        let q = match &cursor {
            None => "?limit=1".to_owned(),
            Some(cur) => format!("?limit=1&cursor={cur}"),
        };
        let (stw, page) = list_page(c, host, token, &q).await?;
        if stw != hyper::StatusCode::OK {
            return Err(format!("cursor walk hop {hops} status {stw}"));
        }
        walked.extend(page_ids(&page)?);
        match page["next_cursor"].as_str() {
            Some(nc) => cursor = Some(nc.to_owned()),
            None => break,
        }
    }
    if walked.len() as u64 != total {
        return Err(format!(
            "walking limit=1 pages by cursor yielded {} entries but `total` says {total}",
            walked.len()
        ));
    }
    let walked_set = sorted_unique(&walked);
    if walked_set.len() != walked.len() {
        return Err("the cursor walk served the same file twice -- pages are not disjoint".into());
    }
    if walked_set != sorted_unique(&wide_ids) {
        return Err("the cursor walk did not reproduce the unpaged listing".into());
    }

    // ---- 6. `sort=oldest` mirrors `sort=newest` ----
    let (_, newest) = list_page(c, host, token, "?limit=200&sort=newest").await?;
    let (_, oldest) = list_page(c, host, token, "?limit=200&sort=oldest").await?;
    let newest_ids = page_ids(&newest)?;
    let oldest_ids = page_ids(&oldest)?;
    if sorted_unique(&newest_ids) != sorted_unique(&oldest_ids) {
        return Err("sort=newest and sort=oldest serve DIFFERENT sets of files".into());
    }
    let nu = page_updated_at(&newest)?;
    let ou = page_updated_at(&oldest)?;
    if nu.windows(2).any(|w| w[0] < w[1]) {
        return Err(format!(
            "sort=newest is not non-increasing in updated_at: {nu:?}"
        ));
    }
    if ou.windows(2).any(|w| w[0] > w[1]) {
        return Err(format!(
            "sort=oldest is not non-decreasing in updated_at: {ou:?}"
        ));
    }
    // EXACT reversal is only well-defined when no two rows share an `updated_at`:
    // the SQL tiebreak is `file_id ASC` in BOTH directions (crates/server/src/pg.rs,
    // `ORDER BY updated_at {}, file_id`), so rows at an equal timestamp deliberately
    // do NOT mirror. Assert it when the timestamps are distinct; say so plainly when
    // they are not, rather than quietly asserting something weaker under the same name.
    let mut ts = nu.clone();
    ts.sort_unstable();
    ts.dedup();
    if ts.len() == nu.len() {
        let mut mirrored = oldest_ids.clone();
        mirrored.reverse();
        if mirrored != newest_ids {
            return Err(format!(
                "sort=oldest is not the reverse of sort=newest: {oldest_ids:?} vs {newest_ids:?}"
            ));
        }
        eprintln!("live-smoke verify: sort=oldest is the exact reverse of sort=newest");
    } else {
        eprintln!(
            "live-smoke verify: {} of {} rows share an updated_at ms, so only \
             monotonicity was asserted for sort (the file_id tiebreak is ASC both ways)",
            nu.len() - ts.len(),
            nu.len()
        );
    }
    // A bad `sort` is a loud 400, not a silently-ignored parameter.
    let (sts, sbody) = list_page(c, host, token, "?limit=200&sort=sideways").await?;
    if sts != hyper::StatusCode::BAD_REQUEST || sbody["code"].as_str() != Some("bad_sort") {
        return Err(format!(
            "sort=sideways gave {sts} / {:?}, expected 400 bad_sort",
            sbody["code"]
        ));
    }

    // ---- 7. `owner=me` is a real, filter-bearing parameter ----
    let (sto, mine) = list_page(c, host, token, "?limit=200&owner=me").await?;
    if sto != hyper::StatusCode::OK {
        return Err(format!("owner=me status {sto}"));
    }
    let mine_ids = page_ids(&mine)?;
    // On THIS box the seeded account owns every file it can see, so the owner=me set
    // MUST equal the unfiltered set. That check alone would also pass on a server that
    // dropped the parameter, hence the two that follow.
    if sorted_unique(&mine_ids) != sorted_unique(&wide_ids) {
        return Err(format!(
            "owner=me served {} entries but the caller owns all {} visible files",
            mine_ids.len(),
            wide_ids.len()
        ));
    }
    if mine.get("total").and_then(|t| t.as_u64()) != Some(total) {
        return Err(format!(
            "owner=me `total` is {:?}, expected {total}",
            mine.get("total")
        ));
    }
    // (a) the parameter is PARSED, not ignored: a bogus value is a loud 400.
    let (stb, obody) = list_page(c, host, token, "?limit=200&owner=someone-else").await?;
    if stb != hyper::StatusCode::BAD_REQUEST || obody["code"].as_str() != Some("bad_owner") {
        return Err(format!(
            "owner=someone-else gave {stb} / {:?}, expected 400 bad_owner",
            obody["code"]
        ));
    }
    // (b) `owner` participates in the cursor's filter fingerprint, i.e. the server
    //     treats it as a real filter dimension: a cursor minted UNDER owner=me is
    //     refused when replayed WITHOUT it.
    let (_, mine_p0) = list_page(c, host, token, "?limit=1&owner=me").await?;
    let mine_cursor = mine_p0["next_cursor"]
        .as_str()
        .ok_or("owner=me limit=1 carries no next_cursor even though total > 1")?
        .to_owned();
    let (stm, mbody) = list_page(c, host, token, &format!("?limit=1&cursor={mine_cursor}")).await?;
    if stm != hyper::StatusCode::BAD_REQUEST
        || mbody["code"].as_str() != Some("cursor_query_mismatch")
    {
        return Err(format!(
            "an owner=me cursor replayed WITHOUT owner gave {stm} / {:?}, expected 400 \
             cursor_query_mismatch -- `owner` is not bound into the cursor",
            mbody["code"]
        ));
    }

    // ---- 8. a cursor replayed under a CHANGED `type` is REJECTED with 400 ----
    // The failure this prevents: silently serving page 2 OF A DIFFERENT RESULT SET.
    let (stt, tbody) =
        list_page(c, host, token, &format!("?limit=1&type=blog&cursor={c0}")).await?;
    if stt != hyper::StatusCode::BAD_REQUEST
        || tbody["code"].as_str() != Some("cursor_query_mismatch")
    {
        return Err(format!(
            "a cursor minted for the UNFILTERED feed was accepted under type=blog \
             ({stt} / {:?}), expected 400 cursor_query_mismatch",
            tbody["code"]
        ));
    }
    // ...while the same `type` filter WITHOUT a stale cursor still works and still
    // reports its own `total` (proving the 400 above is about the cursor, not the type).
    let (stf, typed) = list_page(c, host, token, "?limit=200&type=blog").await?;
    if stf != hyper::StatusCode::OK {
        return Err(format!("type=blog status {stf}"));
    }
    let typed_entries = page_entries(&typed)?;
    if typed.get("total").and_then(|t| t.as_u64()) != Some(typed_entries.len() as u64) {
        return Err(format!(
            "type=blog `total` is {:?} but it served {} entries",
            typed.get("total"),
            typed_entries.len()
        ));
    }
    // THE assertion: the filter EXCLUDES. See `check_type_filter` for what the three
    // checks that used to stand here could not fail on.
    let type_summary = check_type_filter(&page_entries(&wide)?, &typed_entries, "blog")?;
    eprintln!("live-smoke verify: {type_summary}");

    eprintln!(
        "live-smoke verify: paginated feed OK (total={total}: default listing, limit, \
         disjoint offset, {hops}-hop cursor walk, sort both ways, owner=me, \
         type filter EXCLUDES a proper subset, and 400 on a cursor replayed under a \
         changed filter)"
    );
    Ok(())
}

/// Assert `username`'s published binding has User but NOT Admin (i.e. an ordinary user).
async fn assert_user_not_admin(c: &mut Conn, host: &str, username: &str) -> Result<(), String> {
    let (st, body) = net::get(c, &format!("/v1/directory/{username}"), host, None).await?;
    if st != hyper::StatusCode::OK {
        return Err(format!("directory GET {username} status {st}"));
    }
    let bytes = B64
        .decode(body["binding_b64"].as_str().ok_or("no binding_b64")?)
        .map_err(|e| format!("b64: {e}"))?;
    let binding: DirBinding = decode(&bytes).map_err(|e| format!("decode binding: {e}"))?;
    if !binding.roles.roles().contains(&Role::User) {
        return Err(format!("{username} is missing the User role"));
    }
    if binding.roles.roles().contains(&Role::Admin) {
        return Err(format!("{username} unexpectedly has the Admin role"));
    }
    Ok(())
}

pub async fn run(server: &str, host: &str, client_dir: &Path) -> Result<(), String> {
    let admin_key = std::fs::read_to_string(client_dir.join("register.key"))
        .map_err(|e| format!("read admin register.key: {e}"))?
        .trim()
        .to_owned();

    let t = net::transport(client_dir, host, server)?;

    // ---- Admin enroll (first registrant → admin) + login ----
    let mut c = net::open(&t).await?;
    let (admin_dir, admin_uid) = enroll(&mut c, host, "admin", "smokeadmin", &admin_key).await?;
    let mut c2 = net::open(&t).await?; // fresh channel for the channel-bound login
    let login_res = login(&mut c2, host, &admin_dir, "smokeadmin").await;
    if login_res.is_err() {
        let _ = std::fs::remove_dir_all(&admin_dir);
    }
    let (admin_id, admin_token) = login_res?;
    eprintln!("live-smoke: admin enrolled + logged in");

    // ---- Admin uploads a blog and views it back (full round-trip) ----
    let round_trip = async {
        let file_id = upload_blog(&mut c2, host, &admin_id, &admin_uid, &admin_token, BLOG_BODY, "SmokeDiary").await?;
        let got = view_own_blog(&mut c2, host, &admin_id, &admin_uid, &admin_token, file_id).await?;
        if got != BLOG_BODY {
            return Err(format!("view-back mismatch: {} bytes decrypted, expected {}", got.len(), BLOG_BODY.len()));
        }
        eprintln!("live-smoke: admin upload + view-back OK ({} bytes)", got.len());
        Ok::<[u8; 16], String>(file_id)
    }
    .await;
    let _ = std::fs::remove_dir_all(&admin_dir);
    let admin_file_id = round_trip?;

    // ---- Admin mints a key; user2 enrolls with it → User role, not Admin ----
    let minted = mint_key(&mut c2, host, &admin_token).await?;
    let mut c3 = net::open(&t).await?;
    let (user_dir, user_uid) = enroll(&mut c3, host, "user", "smokeuser", &minted).await?;
    assert_user_not_admin(&mut c3, host, "smokeuser").await?;
    eprintln!("live-smoke: admin-mint + user2 enroll (User role) OK");

    // ---- user2 logs in, sees the admin's card in the feed (cross-user visibility),
    // then uploads its OWN blog and views it back (a second independent user works) ----
    let user2_flow = async {
        let mut c4 = net::open(&t).await?;
        let (user_id, user_token) = login(&mut c4, host, &user_dir, "smokeuser").await?;
        assert_feed_contains(&mut c4, host, &user_token, &net::hex(&admin_file_id)).await?;
        eprintln!("live-smoke: cross-user feed visibility OK");

        const USER_BODY: &[u8] = b"live-smoke user2 post: a second independent account round-trips too.";
        let user_fid = upload_blog(&mut c4, host, &user_id, &user_uid, &user_token, USER_BODY, "User2Diary").await?;
        let got2 = view_own_blog(&mut c4, host, &user_id, &user_uid, &user_token, user_fid).await?;
        if got2 != USER_BODY {
            return Err(format!("user2 view-back mismatch: {} bytes", got2.len()));
        }
        eprintln!("live-smoke: user2 upload + view-back OK ({} bytes)", got2.len());
        Ok::<(), String>(())
    }
    .await;
    let _ = std::fs::remove_dir_all(&user_dir);
    user2_flow?;

    Ok(())
}

// ===========================================================================
//  Backup / rollback E2E — the `--phase seed|verify` split.
//
//  `seed` enrolls + uploads into an app-dir that PERSISTS (a state-file sibling),
//  records everything needed to re-open it, and returns. The harness then backs
//  up, DESTROYS, and restores the server. `verify` re-opens the SAME sealed
//  app-dir — no re-enroll, no re-pin — and proves the restored server still serves
//  the recorded identity, directory binding and file content, then that the WRITE
//  path works again. That is the executable form of the CLAUDE.md rule.
// ===========================================================================

/// State-file schema version (JSON, binary fields as lowercase hex).
const STATE_VERSION: u64 = 1;
/// The account `seed` enrolls (distinct name; the backup E2E runs its own server).
const SEED_USER: &str = "bkupadmin";

/// A small, valid 16×16 RGBA PNG (pure bytes — no `image` crate needed to embed
/// it). `seed` transcodes THIS through `prepare_image_streams`, which derives a
/// Thumbnail + Preview. Those two are PINNED streams (`is_pinned_stream`), never
/// idle-offloaded, so this is the ONLY thing that round-trips a pinned blob through
/// the cold tier — correction #1's headline failure. A blog alone cannot cover it
/// (`prepare_blog_streams` sets thumbnail/preview: None).
#[rustfmt::skip]
const SEED_IMAGE_PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0xf3, 0xff,
    0x61, 0x00, 0x00, 0x01, 0x2a, 0x49, 0x44, 0x41, 0x54, 0x78, 0xda, 0x15, 0xcc, 0xc1, 0xa0, 0x6d,
    0x21, 0x00, 0x00, 0xc0, 0x63, 0x70, 0x0d, 0x32, 0xc8, 0x20, 0x83, 0x36, 0x7f, 0x9d, 0x41, 0x06,
    0x19, 0x64, 0x90, 0x41, 0x06, 0x19, 0x64, 0x90, 0x41, 0x24, 0xef, 0x4f, 0x8b, 0xd9, 0xce, 0xf7,
    0x7d, 0xff, 0xfe, 0x7e, 0x04, 0x22, 0x89, 0x4c, 0xa1, 0xd2, 0xe8, 0x0c, 0x26, 0x8b, 0xcd, 0xe1,
    0xf2, 0x7d, 0x3f, 0x01, 0x81, 0x48, 0x22, 0x53, 0xa8, 0x34, 0x3a, 0x83, 0xc9, 0x62, 0x73, 0xb8,
    0xbf, 0x17, 0x04, 0x01, 0x81, 0x48, 0x22, 0x53, 0xa8, 0x34, 0x3a, 0x83, 0xc9, 0x62, 0x73, 0xb8,
    0xe1, 0x05, 0x51, 0x40, 0x20, 0x92, 0xc8, 0x14, 0x2a, 0x8d, 0xce, 0x60, 0xb2, 0xd8, 0x1c, 0x6e,
    0x7c, 0x41, 0x12, 0x10, 0x88, 0x24, 0x32, 0x85, 0x4a, 0xa3, 0x33, 0x98, 0x2c, 0x36, 0x87, 0x9b,
    0x5e, 0x90, 0x05, 0x04, 0x22, 0x89, 0x4c, 0xa1, 0xd2, 0xe8, 0x0c, 0x26, 0x8b, 0xcd, 0xe1, 0xe6,
    0x17, 0x14, 0x01, 0x81, 0x48, 0x22, 0x53, 0xa8, 0x34, 0x3a, 0x83, 0xc9, 0x62, 0x73, 0xb8, 0xe1,
    0x05, 0x51, 0x40, 0x20, 0x92, 0xc8, 0x14, 0x2a, 0x8d, 0xce, 0x60, 0xb2, 0xd8, 0x1c, 0x6e, 0x7c,
    0x41, 0x12, 0x10, 0x88, 0x24, 0x32, 0x85, 0x4a, 0xa3, 0x33, 0x98, 0x2c, 0x36, 0x87, 0x9b, 0x5e,
    0x90, 0x05, 0x04, 0x22, 0x89, 0x4c, 0xa1, 0xd2, 0xe8, 0x0c, 0x26, 0x8b, 0xcd, 0xe1, 0xe6, 0x17,
    0x14, 0x01, 0x81, 0x48, 0x22, 0x53, 0xa8, 0x34, 0x3a, 0x83, 0xc9, 0x62, 0x73, 0xb8, 0xe1, 0x05,
    0x51, 0x40, 0x20, 0x92, 0xc8, 0x14, 0x2a, 0x8d, 0xce, 0x60, 0xb2, 0xd8, 0x1c, 0x6e, 0x7c, 0x41,
    0x12, 0x10, 0x88, 0x24, 0x32, 0x85, 0x4a, 0xa3, 0x33, 0x98, 0x2c, 0x36, 0x87, 0x9b, 0x5e, 0x90,
    0x05, 0x04, 0x22, 0x89, 0x4c, 0xa1, 0xd2, 0xe8, 0x0c, 0x26, 0x8b, 0xcd, 0xe1, 0xe6, 0x17, 0x14,
    0x01, 0x81, 0x48, 0x22, 0x53, 0xa8, 0x34, 0x3a, 0x83, 0xc9, 0x62, 0x73, 0xb8, 0xe1, 0x05, 0x51,
    0x40, 0x20, 0x92, 0xc8, 0x14, 0x2a, 0x8d, 0xce, 0x60, 0xb2, 0xd8, 0x1c, 0x2e, 0xff, 0x01, 0x1b,
    0xf9, 0xf7, 0x1c, 0x5e, 0x9a, 0x67, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
    0x42, 0x60, 0x82,
];

/// Enroll `username` over `c` into an ALREADY-seeded `dir` (register.key present);
/// returns the server-assigned `user_id` (hex16). The dir is the caller's — this is
/// the explicit-dir counterpart of `enroll`, which makes its own throwaway temp dir.
async fn enroll_at(
    c: &mut Conn,
    host: &str,
    dir: &Path,
    username: &str,
) -> Result<String, String> {
    let reg = register_with_key_exchange(&mut c.sender, host, dir, username, PASSPHRASE)
        .await
        .map_err(|e| format!("enroll {username}: {}", e.message))?;
    Ok(reg.user_id)
}

/// Upload an image as `owner` via the real `prepare_image_streams` (pure-Rust
/// `RustImageCodec`, so it works under `default-features = false`). Returns the
/// file_id. Unlike `upload_blog` this produces Thumbnail + Preview streams, the
/// PINNED path the blog cannot exercise. Returns the file_id.
async fn upload_image(
    c: &mut Conn,
    host: &str,
    owner: &Identity,
    owner_uid_hex: &str,
    token: &str,
    src_png: &[u8],
    title: &str,
) -> Result<[u8; 16], String> {
    let recovery = resolve_recovery_pin(&mut c.sender, host)
        .await
        .map_err(|e| format!("resolve_recovery_pin (recovery gate): {}", e.message))?;

    let (file_type, streams) = maxsecu_client_app::upload::prepare_image_streams(src_png, title, &[])
        .map_err(|e| format!("prepare_image_streams: {}", e.message))?;
    let file_id = Id(maxsecu_crypto::random_array::<16>());
    let bundle = build_upload(
        &UploadParams {
            owner,
            owner_id: Id(net::hex16(owner_uid_hex)?),
            owner_key_version: 1,
            file_id,
            file_type,
            chunk_size: 4096,
            recovery_pub: EncPublicKey::from_bytes(recovery.enc_pub),
            recovery_mlkem_pub: recovery.mlkem_pub,
            created_at: Timestamp(TS),
        },
        &streams,
    )
    .map_err(|e| format!("build_upload(image): {e:?}"))?;

    maxsecu_client_app::upload::run_pipeline(
        &mut c.sender,
        host,
        token,
        &bundle,
        |_, _| {},
        maxsecu_client_app::upload::StageFlags::default(),
    )
    .await
    .map_err(|e| format!("run_pipeline(image): {}", e.message))?;

    Ok(file_id.0)
}

/// Where `seed` puts the app-dir: a sibling of the state file (`<state>.appdir`), so
/// it survives the run and `verify` re-opens the very same sealed keystore. NOT a
/// temp dir — the spec is explicit that the sealed app-dir is the recorded artifact.
fn seed_app_dir_path(state_path: &Path) -> PathBuf {
    let name = state_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("state");
    state_path.with_file_name(format!("{name}.appdir"))
}

/// One `files[]` entry: `content_sha256` is over the PLAINTEXT `view_own_blog`
/// returns (the Content stream), so `verify` recomputes it the identical way.
fn file_record(tag: &str, file_id: &[u8; 16], plaintext: &[u8], file_type: &str) -> serde_json::Value {
    serde_json::json!({
        "tag": tag,
        "file_id": net::hex(file_id),
        "content_sha256": net::hex(&maxsecu_crypto::sha256(plaintext)),
        "file_type": file_type,
    })
}

#[allow(clippy::too_many_arguments)]
fn write_state(
    path: &Path,
    server: &str,
    host: &str,
    app_dir: &Path,
    username: &str,
    user_id: &str,
    sig_pub: &str,
    enc_pub: &str,
    files: &[serde_json::Value],
) -> Result<(), String> {
    let v = serde_json::json!({
        "version": STATE_VERSION,
        "server": server,
        "host": host,
        "app_dir": app_dir.to_string_lossy(),
        "username": username,
        "user_id": user_id,
        "sig_pub": sig_pub,
        "enc_pub": enc_pub,
        "files": files,
    });
    let bytes = serde_json::to_vec_pretty(&v).map_err(|e| format!("serialize state: {e}"))?;
    std::fs::write(path, bytes).map_err(|e| format!("write state {}: {e}", path.display()))
}

fn read_state(path: &Path) -> Result<serde_json::Value, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read state {}: {e}", path.display()))?;
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse state {}: {e}", path.display()))?;
    let ver = v.get("version").and_then(|x| x.as_u64());
    if ver != Some(STATE_VERSION) {
        return Err(format!("state version mismatch: got {ver:?}, want {STATE_VERSION}"));
    }
    Ok(v)
}

fn state_str(v: &serde_json::Value, k: &str) -> Result<String, String> {
    v.get(k)
        .and_then(|x| x.as_str())
        .map(|s| s.to_owned())
        .ok_or_else(|| format!("state: missing/invalid string field '{k}'"))
}

/// PHASE `seed`: enroll + upload (blog AND image) into a PERSISTENT app-dir beside
/// the state file, record everything `verify` needs, and return WITHOUT tearing the
/// app-dir down.
pub async fn seed(
    server: &str,
    host: &str,
    client_dir: &Path,
    state_path: &Path,
) -> Result<(), String> {
    let admin_key = std::fs::read_to_string(client_dir.join("register.key"))
        .map_err(|e| format!("read admin register.key: {e}"))?
        .trim()
        .to_owned();

    let app_dir = seed_app_dir_path(state_path);
    // Start from a clean app-dir (a stale one from a prior seed would have no
    // register.key and enroll would fail "not in registration mode").
    let _ = std::fs::remove_dir_all(&app_dir);
    seed_app_dir(&app_dir, &admin_key)?;

    let t = net::transport(client_dir, host, server)?;

    let mut c = net::open(&t).await?;
    let user_id = enroll_at(&mut c, host, &app_dir, SEED_USER).await?;
    eprintln!(
        "live-smoke seed: enrolled {SEED_USER} into {}",
        app_dir.display()
    );

    // Record the identity's public keys straight from the real at-rest path so
    // `verify` can assert they survived the restore unchanged.
    let id = keystore::unlock(&app_dir, PASSPHRASE)
        .map_err(|e| format!("unlock after enroll: {}", e.message))?;
    let sig_pub = net::hex(&id.sig_pub_bytes());
    let enc_pub = net::hex(&id.enc_pub_bytes());

    let mut c2 = net::open(&t).await?; // fresh channel for the channel-bound login
    let (_login_id, token) = login(&mut c2, host, &app_dir, SEED_USER).await?;

    let mut files = Vec::new();

    // Blog upload + view-back to confirm it landed; record the content digest.
    let blog_fid = upload_blog(&mut c2, host, &id, &user_id, &token, BLOG_BODY, "BackupDiary").await?;
    let blog_pt = view_own_blog(&mut c2, host, &id, &user_id, &token, blog_fid).await?;
    files.push(file_record("blog", &blog_fid, &blog_pt, "blog"));
    eprintln!("live-smoke seed: blog uploaded + viewed ({} bytes)", blog_pt.len());

    // Image upload — the PINNED Thumbnail/Preview streams round-trip the cold tier.
    let img_fid = upload_image(&mut c2, host, &id, &user_id, &token, SEED_IMAGE_PNG, "BackupPhoto").await?;
    let img_pt = view_own_blog(&mut c2, host, &id, &user_id, &token, img_fid).await?;
    files.push(file_record("image", &img_fid, &img_pt, "image"));
    eprintln!(
        "live-smoke seed: image uploaded + viewed ({} bytes content)",
        img_pt.len()
    );

    // F3, OLD-SERVER HALF. Same client code the `verify` phase runs, against the
    // PRE-upgrade server: it must see no `total` and must not page. Runs here, after
    // the uploads, so there is something in the feed to page over.
    assert_listing_is_pre_paging(&mut c2, host, &token).await?;

    write_state(
        state_path, server, host, &app_dir, SEED_USER, &user_id, &sig_pub, &enc_pub, &files,
    )?;
    eprintln!("live-smoke seed: wrote state {}", state_path.display());
    // Intentionally do NOT remove the app-dir: `verify` unlocks the SAME sealed
    // keystore (the whole point — a real "no re-enroll").
    Ok(())
}

/// PHASE `verify`: re-open the sealed app-dir the restored server was rolled back
/// under. No re-enroll, no re-pin. Assert identity, directory binding and every
/// recorded file's content all survived, then that the WRITE path works again.
pub async fn verify(
    server: &str,
    host: &str,
    client_dir: &Path,
    state_path: &Path,
) -> Result<(), String> {
    let st = read_state(state_path)?;
    let rec_server = state_str(&st, "server")?;
    let rec_host = state_str(&st, "host")?;
    if rec_server != server {
        return Err(format!(
            "state server mismatch: recorded {rec_server}, got {server}"
        ));
    }
    if rec_host != host {
        return Err(format!("state host mismatch: recorded {rec_host}, got {host}"));
    }
    let app_dir = PathBuf::from(state_str(&st, "app_dir")?);
    let username = state_str(&st, "username")?;
    let user_id = state_str(&st, "user_id")?;
    let rec_sig = state_str(&st, "sig_pub")?;
    let rec_enc = state_str(&st, "enc_pub")?;

    // NO re-enroll: the single-use register.key was consumed at seed time and must
    // still be gone (its absence is the proof this app-dir was never re-enrolled).
    if app_dir.join("register.key").exists() {
        return Err(format!(
            "register.key still present in {} — verify must NOT re-enroll",
            app_dir.display()
        ));
    }
    // The real at-rest path: keystore::unlock → keyblob::unlock. If the restore
    // damaged the keyblob this fails here.
    let id = keystore::unlock(&app_dir, PASSPHRASE)
        .map_err(|e| format!("keystore::unlock({}): {}", app_dir.display(), e.message))?;
    if net::hex(&id.sig_pub_bytes()) != rec_sig {
        return Err("sig_pub changed after restore (identity not preserved)".into());
    }
    if net::hex(&id.enc_pub_bytes()) != rec_enc {
        return Err("enc_pub changed after restore (identity not preserved)".into());
    }
    eprintln!("live-smoke verify: unlocked restored identity; sig/enc pub keys match");

    let t = net::transport(client_dir, host, server)?;
    let mut c = net::open(&t).await?;
    let (_login_id, token) = login(&mut c, host, &app_dir, &username).await?;
    eprintln!("live-smoke verify: login OK (no re-enroll, no re-pin)");

    // The sharpest assertion: `user_id` is the recipient_id inside every DEK wrap,
    // so a merge that stranded this user would change what the directory serves.
    let (dst, body) = net::get(&mut c, &format!("/v1/directory/{username}"), host, None).await?;
    if dst != hyper::StatusCode::OK {
        return Err(format!("directory GET {username} status {dst}"));
    }
    let bytes = B64
        .decode(body["binding_b64"].as_str().ok_or("no binding_b64")?)
        .map_err(|e| format!("b64: {e}"))?;
    let binding: DirBinding = decode(&bytes).map_err(|e| format!("decode binding: {e}"))?;
    if net::hex(&binding.user_id.0) != user_id {
        return Err(format!(
            "binding user_id mismatch: recorded {user_id}, served {}",
            net::hex(&binding.user_id.0)
        ));
    }
    eprintln!("live-smoke verify: directory binding user_id matches ({user_id})");

    // Every recorded file must view-back byte-identically (digest compare) — this is
    // where the PINNED image streams are actually pulled back off the restored cold
    // tier (build_download_bundle fetches ALL streams).
    let files = st
        .get("files")
        .and_then(|f| f.as_array())
        .ok_or("state: missing 'files' array")?;
    for f in files {
        let tag = f.get("tag").and_then(|x| x.as_str()).unwrap_or("?");
        let fid_hex = f
            .get("file_id")
            .and_then(|x| x.as_str())
            .ok_or("file: missing file_id")?;
        let want_sha = f
            .get("content_sha256")
            .and_then(|x| x.as_str())
            .ok_or("file: missing content_sha256")?;
        let fid = net::hex16(fid_hex)?;
        let pt = view_own_blog(&mut c, host, &id, &user_id, &token, fid).await?;
        let got_sha = net::hex(&maxsecu_crypto::sha256(&pt));
        if got_sha != want_sha {
            return Err(format!(
                "file '{tag}' {fid_hex}: content digest mismatch after restore (got {got_sha}, want {want_sha})"
            ));
        }
        eprintln!(
            "live-smoke verify: file '{tag}' {fid_hex} round-trips ({} bytes)",
            pt.len()
        );
    }

    // The WRITE path must survive too — a fresh upload needs the restored delegation
    // triple + recovery_account + operational_secret to wrap and to pass the pin gate.
    const POST_BODY: &[u8] =
        b"live-smoke verify: a fresh post AFTER restore proves the write path survived.";
    let new_fid = upload_blog(&mut c, host, &id, &user_id, &token, POST_BODY, "PostRestore").await?;
    let got = view_own_blog(&mut c, host, &id, &user_id, &token, new_fid).await?;
    if got != POST_BODY {
        return Err(format!(
            "post-restore write/view mismatch: {} bytes decrypted",
            got.len()
        ));
    }
    eprintln!(
        "live-smoke verify: post-restore upload + view-back OK ({} bytes)",
        got.len()
    );

    // F3, NEW-SERVER HALF. Runs LAST so the fresh post above is already in the feed
    // (the paging assertions need at least two rows, and more rows make the cursor
    // walk a real walk rather than a single hop).
    assert_paginated_listing(&mut c, host, &token).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{check_type_filter, page_entries, SEED_IMAGE_PNG};

    /// The lap's real corpus at `verify` time: three blogs and one image, all owned by
    /// the seeded account. `wide` is what `?limit=200` (no filter) serves.
    fn wide_corpus() -> serde_json::Value {
        serde_json::json!({
            "files": [
                { "file_id": "aa00", "file_type": "blog",  "updated_at": 4u64 },
                { "file_id": "bb01", "file_type": "blog",  "updated_at": 3u64 },
                { "file_id": "cc02", "file_type": "image", "updated_at": 2u64 },
                { "file_id": "dd03", "file_type": "blog",  "updated_at": 1u64 },
            ],
            "total": 4u64,
        })
    }

    /// What a CORRECT `?type=blog` serves: 3 of 4, the image gone.
    fn filtered_page() -> serde_json::Value {
        serde_json::json!({
            "files": [
                { "file_id": "aa00", "file_type": "blog", "updated_at": 4u64 },
                { "file_id": "bb01", "file_type": "blog", "updated_at": 3u64 },
                { "file_id": "dd03", "file_type": "blog", "updated_at": 1u64 },
            ],
            "total": 3u64,
        })
    }

    /// THE NEGATIVE CONTROL, half 1 — the OLD assertion on input it should have
    /// rejected.
    ///
    /// This test does NOT call the product code; it re-implements, verbatim, the three
    /// predicates that used to stand at `assert_paginated_listing` step 8:
    ///
    /// ```text
    ///     typed.total == typed_ids.len()
    ///     !typed_ids.is_empty()
    ///     typed_ids.len() as u64 <= total
    /// ```
    ///
    /// and drives them with the response a server that DROPPED the `type` parameter
    /// returns: the whole unfiltered feed, 4 of 4. All three hold. That is the defect —
    /// the gate could not fail, so `type` (a PROD-ERA parameter) could have been lost in
    /// the paging rewrite and this oracle would still have said PASS.
    ///
    /// Kept as a test rather than deleted so the claim "the old check was vacuous" is
    /// executable instead of asserted in prose, and so a future edit that reverts to the
    /// weak form has this sitting next to it.
    #[test]
    fn the_old_type_assertions_could_not_fail_on_an_unfiltered_page() {
        let wide = wide_corpus();
        // The server ignored `?type=blog` and served the unfiltered feed back.
        let typed = wide_corpus();

        let total = wide["total"].as_u64().unwrap();
        let typed_ids: Vec<String> = typed["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["file_id"].as_str().unwrap().to_owned())
            .collect();

        assert_eq!(
            typed["total"].as_u64(),
            Some(typed_ids.len() as u64),
            "OLD check 1 (total == served) held"
        );
        assert!(!typed_ids.is_empty(), "OLD check 2 (non-empty) held");
        assert!(
            typed_ids.len() as u64 <= total,
            "OLD check 3 (subset by count) held"
        );
        assert_eq!(
            typed_ids.len() as u64,
            total,
            "and it served ALL {total} rows while claiming to filter"
        );
    }

    /// THE NEGATIVE CONTROL, half 2 — the NEW check on the SAME input.
    #[test]
    fn check_type_filter_rejects_a_page_that_was_not_filtered() {
        let wide = page_entries(&wide_corpus()).unwrap();
        let typed = page_entries(&wide_corpus()).unwrap(); // filter dropped: 4 of 4
        let err = check_type_filter(&wide, &typed, "blog")
            .expect_err("an unfiltered page MUST be rejected -- this is the whole point");
        assert!(
            err.contains("cc02") || err.contains("PROPER subset"),
            "the diagnosis must name the leak or the missing exclusion, got: {err}"
        );
    }

    /// The positive half: a genuinely filtered page passes, and the summary names the
    /// file that was excluded.
    #[test]
    fn check_type_filter_accepts_a_real_proper_subset() {
        let wide = page_entries(&wide_corpus()).unwrap();
        let typed = page_entries(&filtered_page()).unwrap();
        let ok = check_type_filter(&wide, &typed, "blog").expect("a real 3-of-4 filter");
        assert!(
            ok.contains("cc02"),
            "summary must name the excluded id: {ok}"
        );
        assert!(ok.contains("3 of 4"), "summary must state the counts: {ok}");
    }

    /// Over-filtering is a defect too: a `type=blog` that hid one of the caller's blogs
    /// is a user staring at a feed missing their own post.
    #[test]
    fn check_type_filter_rejects_an_over_filtered_page() {
        let wide = page_entries(&wide_corpus()).unwrap();
        let mut typed = page_entries(&filtered_page()).unwrap();
        typed.pop(); // drop dd03
        let err = check_type_filter(&wide, &typed, "blog")
            .expect_err("a page missing one of the caller's blogs must be rejected");
        assert!(err.contains("dd03"), "must name the missing blog: {err}");
    }

    /// The non-vacuity guard: with only one file_type on the box, "the filter kept
    /// everything" and "the filter is gone" are the same observation, so the checker
    /// must FAIL LOUDLY rather than pass on a tautology.
    #[test]
    fn check_type_filter_fails_loudly_on_a_single_type_corpus() {
        let only_blogs = serde_json::json!({
            "files": [
                { "file_id": "aa00", "file_type": "blog", "updated_at": 2u64 },
                { "file_id": "bb01", "file_type": "blog", "updated_at": 1u64 },
            ],
            "total": 2u64,
        });
        let wide = page_entries(&only_blogs).unwrap();
        let typed = wide.clone();
        let err = check_type_filter(&wide, &typed, "blog")
            .expect_err("a one-type corpus must be reported, never silently accepted");
        assert!(
            err.contains("NOTHING for the filter to exclude"),
            "must say why it is vacuous, got: {err}"
        );
    }

    /// A listing entry with no `file_type` must be a hard error, not a default: the
    /// exclusion check cannot judge a filter it cannot read the types of.
    #[test]
    fn page_entries_refuses_an_entry_with_no_file_type() {
        let bad = serde_json::json!({ "files": [ { "file_id": "aa00" } ] });
        let err = page_entries(&bad).expect_err("missing file_type must fail");
        assert!(err.contains("carries no file_type"), "got: {err}");
    }

    /// `SEED_IMAGE_PNG` is a hand-assembled byte literal, and a byte literal is
    /// exactly the kind of constant that rots silently: the `seed` phase is the
    /// only consumer, it lives behind a tens-of-minutes WSL E2E, and a bad image
    /// surfaces there as a generic `bad_image` several thousand lines into a run.
    ///
    /// It shipped WRONG once: the IDAT chunk's CRC-32 and the zlib stream's
    /// Adler-32 were both stale (the pixel data was fine), so `png`'s critical-chunk
    /// CRC check rejected it and `seed` could never reach `backup-server.sh` —
    /// meaning the pinned Thumbnail/Preview cold-tier round-trip the design calls
    /// the E2E's whole point (correction R2-19) never ran.
    ///
    /// This drives the SAME entry point `upload_image` does, so it fails in
    /// milliseconds, in the normal `cargo test`, instead of mid-E2E.
    #[test]
    fn the_seed_image_actually_decodes() {
        let r = maxsecu_client_app::upload::prepare_image_streams(SEED_IMAGE_PNG, "t", &[]);
        assert!(
            r.is_ok(),
            "SEED_IMAGE_PNG no longer decodes ({:?}) — `live-smoke --phase seed` \
             would fail at upload_image and the backup E2E would never reach backup-server.sh",
            r.err().map(|e| e.message)
        );
    }
}
