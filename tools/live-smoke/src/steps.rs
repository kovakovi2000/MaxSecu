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
async fn login(
    c: &mut Conn,
    host: &str,
    dir: &Path,
    username: &str,
) -> Result<(Identity, String), String> {
    let id = keystore::unlock(dir, PASSPHRASE)
        .map_err(|e| format!("unlock {username}: {}", e.message))?;
    let ok = login_exchange(&mut c.sender, &id, username, host, &c.exporter, TS)
        .await
        .map_err(|e| format!("login {username}: {}", e.message))?;
    if ok.token.is_empty() {
        return Err(format!("empty token for {username}"));
    }
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
    let (st, json) = net::get(
        c,
        &format!("/v1/files/{fid_hex}?version=latest"),
        host,
        Some(token),
    )
    .await?;
    if st != hyper::StatusCode::OK {
        return Err(format!("file view GET status {st}"));
    }
    let view = parse_file_view(&json).map_err(|e| format!("parse_file_view: {}", e.message))?;
    let (bundle, _direct) = build_download_bundle(
        &mut c.sender,
        host,
        token,
        &fid_hex,
        &view,
        RouteMode::PreferServer,
        None,
    )
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
    let (st, res) = net::post(
        c,
        "/v1/registration-keys",
        host,
        Some(admin_token),
        serde_json::json!({}),
    )
    .await?;
    if st != hyper::StatusCode::CREATED {
        return Err(format!("mint registration key status {st}"));
    }
    res["registration_key"]
        .as_str()
        .map(|s| s.to_owned())
        .ok_or_else(|| "no registration_key in mint response".to_owned())
}

/// As the logged-in caller (`token`), list the feed and assert `want_fid_hex` appears.
async fn assert_feed_contains(
    c: &mut Conn,
    host: &str,
    token: &str,
    want_fid_hex: &str,
) -> Result<(), String> {
    let (st, json) = net::get(c, "/v1/files?limit=200", host, Some(token)).await?;
    if st != hyper::StatusCode::OK {
        return Err(format!("feed GET status {st}"));
    }
    let found = json["files"]
        .as_array()
        .map(|a| {
            a.iter()
                .any(|f| f["file_id"].as_str() == Some(want_fid_hex))
        })
        .unwrap_or(false);
    if !found {
        return Err(format!(
            "user2 feed does not contain admin file {want_fid_hex}"
        ));
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
        let file_id = upload_blog(
            &mut c2,
            host,
            &admin_id,
            &admin_uid,
            &admin_token,
            BLOG_BODY,
            "SmokeDiary",
        )
        .await?;
        let got =
            view_own_blog(&mut c2, host, &admin_id, &admin_uid, &admin_token, file_id).await?;
        if got != BLOG_BODY {
            return Err(format!(
                "view-back mismatch: {} bytes decrypted, expected {}",
                got.len(),
                BLOG_BODY.len()
            ));
        }
        eprintln!(
            "live-smoke: admin upload + view-back OK ({} bytes)",
            got.len()
        );
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

        const USER_BODY: &[u8] =
            b"live-smoke user2 post: a second independent account round-trips too.";
        let user_fid = upload_blog(
            &mut c4,
            host,
            &user_id,
            &user_uid,
            &user_token,
            USER_BODY,
            "User2Diary",
        )
        .await?;
        let got2 = view_own_blog(&mut c4, host, &user_id, &user_uid, &user_token, user_fid).await?;
        if got2 != USER_BODY {
            return Err(format!("user2 view-back mismatch: {} bytes", got2.len()));
        }
        eprintln!(
            "live-smoke: user2 upload + view-back OK ({} bytes)",
            got2.len()
        );
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
async fn enroll_at(c: &mut Conn, host: &str, dir: &Path, username: &str) -> Result<String, String> {
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

    let (file_type, streams) =
        maxsecu_client_app::upload::prepare_image_streams(src_png, title, &[])
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
fn file_record(
    tag: &str,
    file_id: &[u8; 16],
    plaintext: &[u8],
    file_type: &str,
) -> serde_json::Value {
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
    let v: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parse state {}: {e}", path.display()))?;
    let ver = v.get("version").and_then(|x| x.as_u64());
    if ver != Some(STATE_VERSION) {
        return Err(format!(
            "state version mismatch: got {ver:?}, want {STATE_VERSION}"
        ));
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
    let blog_fid = upload_blog(
        &mut c2,
        host,
        &id,
        &user_id,
        &token,
        BLOG_BODY,
        "BackupDiary",
    )
    .await?;
    let blog_pt = view_own_blog(&mut c2, host, &id, &user_id, &token, blog_fid).await?;
    files.push(file_record("blog", &blog_fid, &blog_pt, "blog"));
    eprintln!(
        "live-smoke seed: blog uploaded + viewed ({} bytes)",
        blog_pt.len()
    );

    // Image upload — the PINNED Thumbnail/Preview streams round-trip the cold tier.
    let img_fid = upload_image(
        &mut c2,
        host,
        &id,
        &user_id,
        &token,
        SEED_IMAGE_PNG,
        "BackupPhoto",
    )
    .await?;
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
        return Err(format!(
            "state host mismatch: recorded {rec_host}, got {host}"
        ));
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
    let new_fid = upload_blog(
        &mut c,
        host,
        &id,
        &user_id,
        &token,
        POST_BODY,
        "PostRestore",
    )
    .await?;
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

// ===========================================================================
//  PROD-UPGRADE FILE-FIDELITY oracle — the `--phase upload-files|download-files`
//  pair.
//
//  `upload-files` reads REAL files off disk, uploads each one through the REAL
//  prepare path for its kind, downloads it straight back, writes the recovered
//  plaintext to --out-dir, and records a digest for EVERY stream in --state.
//  `download-files` then reopens the SAME sealed app-dir after the upgrade — no
//  re-enroll, no re-pin, no upload of the recorded files — re-downloads each one,
//  and fails on any digest that moved.
//
//  Honesty rule baked into the design: source-byte identity is MEASURED at upload
//  time, never assumed. Thumbnail/Preview are derived by the client and have no
//  source counterpart at all; a non-PNG image source is re-encoded to PNG
//  (client-core/src/media.rs) so its original bytes are irrecoverable. For any
//  stream where the client transformed the input, the ONLY sound assertion is
//  pre-upgrade recovered bytes == post-upgrade recovered bytes, and that is what
//  is asserted — the source comparison is skipped and the skip is PRINTED.
//
//  FileType::Video is deliberately unreachable here: this oracle is built with
//  `default-features = false`, so `embed-ffmpeg` is OFF and ffmpeg is compiled
//  OUT (ffmpeg_bin::ensure_ffmpeg is the fail-closed `video_unavailable` stub);
//  and even with ffmpeg present prepare_video_streams always re-muxes to
//  fragmented MP4, so a Video Content stream can never equal the source file.
//  An .mp4 is uploaded as Generic — byte-preserving, multi-chunk, and honest
//  about what it does and does not prove.
// ===========================================================================

/// The account these two phases own. Distinct from `run`'s (`smokeadmin`) and
/// `seed`'s (`bkupadmin`) so the three oracles never share an app-dir or identity.
pub const FILES_USER: &str = "upgradeuser";

/// Chunk size for the fidelity uploads: the PRODUCT's own value (1 MiB —
/// `commands/upload.rs` seals every in-RAM upload at `VIDEO_CHUNK_SIZE`). The
/// 4 KiB `steps.rs` uses elsewhere is fine for a 70-byte blog but would turn a
/// 6 MiB MP4 into ~1500 sequential PUTs. Inside the server's [4 KiB, 8 MiB]
/// framing bounds and under its 8 MiB + 64 KiB body limit.
const FILES_CHUNK_SIZE: u32 = maxsecu_client_app::upload::VIDEO_CHUNK_SIZE;

/// Build identity of THIS oracle binary: the lowercase-hex SHA-256 of the file
/// behind `std::env::current_exe()`, computed at RUN time.
///
/// `download-files` refuses to run against a state file written by a DIFFERENT
/// build unless `--allow-client-upgrade`: the post-upgrade lap must use the
/// PRE-upgrade client, or it proves nothing about existing users' installs.
///
/// This used to be `option_env!("MAXSECU_ORACLE_BUILD")` stamped in at compile
/// time, which was wrong in the way that matters: nothing in the tree ever set
/// that variable, so it was permanently `"unset"`, the comparison was always
/// `"unset" == "unset"`, and the guard could never fire — while both phases
/// printed a WARNING that read, to a log skimmer, like covered ground. Hashing
/// the running executable needs no build plumbing, is always available, and is
/// exactly the property the guard wants to assert: same bytes on both laps.
///
/// Fails CLOSED. If the executable cannot be located or read there is no honest
/// identity to compare, so both phases abort rather than degrade to a guard that
/// passes by default.
fn oracle_build_id() -> Result<String, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("cannot locate this oracle binary (current_exe): {e}"))?;
    let bytes = std::fs::read(&exe)
        .map_err(|e| format!("cannot read this oracle binary {}: {e}", exe.display()))?;
    Ok(sha_hex(&bytes))
}

/// First 12 hex chars of a build id — enough to eyeball in a log, short enough to
/// sit on one line. Length-guarded so it can never panic on a truncated value.
fn short_build(b: &str) -> &str {
    &b[..b.len().min(12)]
}

/// Everything both file-fidelity phases need. A struct rather than nine positional
/// parameters so `main.rs` stays readable and clippy stays quiet.
pub struct FilesArgs<'a> {
    pub server: &'a str,
    pub host: &'a str,
    pub client_dir: &'a Path,
    pub state: &'a Path,
    pub app_dir: Option<&'a Path>,
    pub out_dir: &'a Path,
    pub files: &'a [String],
    pub allow_client_upgrade: bool,
    pub allow_server_id_change: bool,
}

/// Which prepare path a `--file` argument takes. Deliberately EXPLICIT (the caller
/// writes `image:`/`generic:`/`blog:`) rather than inferred from the extension. The
/// GUI infers (`ui/src/core/composer.ts::detectKind`), but inference would route a
/// `.mp4` down the VIDEO path, whose Content stream is a re-muxed fMP4 and can never
/// be byte-identical to the source — and a green run would then be misread as
/// "video upload verified". Naming the path is the honesty gate.
#[derive(Clone, Copy, PartialEq)]
enum FileKind {
    Image,
    Generic,
    Blog,
}

impl FileKind {
    fn parse(s: &str) -> Result<FileKind, String> {
        match s {
            "image" => Ok(FileKind::Image),
            "generic" => Ok(FileKind::Generic),
            "blog" => Ok(FileKind::Blog),
            "video" => Err(
                "--file kind 'video' is NOT supported by this oracle: ffmpeg is COMPILED OUT of \
                 this build (default-features = false ⇒ embed-ffmpeg off ⇒ ensure_ffmpeg is the \
                 fail-closed `video_unavailable` stub), and prepare_video_streams always re-muxes \
                 to fragmented MP4 anyway, so a Video Content stream can never equal the source \
                 bytes. Upload the file as 'generic:' instead — byte-preserving and multi-chunk — \
                 and cover the transcode path with the manual GUI smoke."
                    .to_owned(),
            ),
            other => Err(format!(
                "unknown --file kind '{other}' (want image|generic|blog; 'video' is rejected on \
                 purpose — ffmpeg is compiled out of this oracle)"
            )),
        }
    }

    fn name(self) -> &'static str {
        match self {
            FileKind::Image => "image",
            FileKind::Generic => "generic",
            FileKind::Blog => "blog",
        }
    }
}

/// `<kind>:<path>`. Split on the FIRST colon only, so a Windows path keeps its
/// drive letter (`image:D:\shots\a.png` -> ("image", "D:\\shots\\a.png")).
fn parse_file_arg(spec: &str) -> Result<(FileKind, PathBuf), String> {
    let (kind, path) = spec.split_once(':').ok_or_else(|| {
        format!("--file '{spec}' must be '<kind>:<path>', e.g. image:D:\\fixtures\\shot.png")
    })?;
    if path.is_empty() {
        return Err(format!("--file '{spec}' has an empty path"));
    }
    Ok((FileKind::parse(kind)?, PathBuf::from(path)))
}

fn base_name(p: &Path) -> Result<String, String> {
    p.file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_owned())
        .ok_or_else(|| format!("source path {} has no usable file name", p.display()))
}

fn sha_hex(bytes: &[u8]) -> String {
    net::hex(&maxsecu_crypto::sha256(bytes))
}

fn stream_name_of(t: StreamType) -> &'static str {
    match t {
        StreamType::Content => "content",
        StreamType::Metadata => "metadata",
        StreamType::Thumbnail => "thumbnail",
        StreamType::Preview => "preview",
    }
}

fn file_type_name(t: FileType) -> &'static str {
    match t {
        FileType::Video => "video",
        FileType::Image => "image",
        FileType::Blog => "blog",
        FileType::Generic => "generic",
        FileType::Bundle => "bundle",
    }
}

/// Refuse to write recovered bytes into a directory that holds one of the SOURCES.
/// Overwriting a source with the bytes we just recovered would make any external
/// `sha256sum src out` comparison vacuously green.
fn assert_out_dir_disjoint(out_dir: &Path, sources: &[PathBuf]) -> Result<(), String> {
    let out = std::fs::canonicalize(out_dir)
        .map_err(|e| format!("canonicalize --out-dir {}: {e}", out_dir.display()))?;
    for p in sources {
        let parent = p.parent().unwrap_or_else(|| Path::new("."));
        let par = match std::fs::canonicalize(parent) {
            Ok(x) => x,
            Err(_) => continue, // source dir is gone; nothing to clobber
        };
        if par == out {
            return Err(format!(
                "--out-dir {} is the SAME directory as source {} — the recovered bytes would \
                 overwrite the source and make the SHA-256 comparison meaningless",
                out_dir.display(),
                p.display()
            ));
        }
    }
    Ok(())
}

/// Read a REAL file off disk and run it through the REAL prepare path for its kind.
/// Returns (file_type, streams, the source bytes as read).
fn prepare_from_disk(
    kind: FileKind,
    path: &Path,
) -> Result<(FileType, maxsecu_client_core::PlaintextStreams, Vec<u8>), String> {
    let source = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let name = base_name(path)?;
    match kind {
        // The real GUI image path. Content is stream-copied verbatim when the source
        // is already PNG, RE-ENCODED otherwise; Thumbnail + Preview are always
        // derived. `upload_files` measures which happened.
        FileKind::Image => {
            let (ft, streams) =
                maxsecu_client_app::upload::prepare_image_streams(&source, &name, &[]).map_err(
                    |e| format!("prepare_image_streams({}): {}", path.display(), e.message),
                )?;
            Ok((ft, streams, source))
        }
        // The real GUI generic path: raw bytes, no transcode, original filename in
        // the metadata (commands/upload.rs UploadKind::Generic does exactly this).
        FileKind::Generic => {
            let streams = maxsecu_client_core::PlaintextStreams {
                content: source.clone(),
                metadata: Some(maxsecu_client_app::upload::prepare_generic_metadata(
                    &name,
                    &name,
                    &[],
                )),
                thumbnail: None,
                preview: None,
            };
            Ok((FileType::Generic, streams, source))
        }
        // Blog: content passes through untouched.
        FileKind::Blog => {
            let streams =
                maxsecu_client_app::upload::prepare_blog_streams(source.clone(), &name, &[]);
            Ok((FileType::Blog, streams, source))
        }
    }
}

/// Upload already-prepared streams as `owner`. Structurally identical to
/// `upload_blog`/`upload_image` (same recovery-pin gate, same `build_upload`, same
/// `run_pipeline`), differing only in taking the file_type + streams from the caller
/// and sealing at the product's 1 MiB chunk size.
async fn upload_prepared(
    c: &mut Conn,
    host: &str,
    owner: &Identity,
    owner_uid_hex: &str,
    token: &str,
    file_type: FileType,
    streams: &maxsecu_client_core::PlaintextStreams,
) -> Result<[u8; 16], String> {
    let recovery = resolve_recovery_pin(&mut c.sender, host)
        .await
        .map_err(|e| format!("resolve_recovery_pin (recovery gate): {}", e.message))?;

    let file_id = Id(maxsecu_crypto::random_array::<16>());
    let bundle = build_upload(
        &UploadParams {
            owner,
            owner_id: Id(net::hex16(owner_uid_hex)?),
            owner_key_version: 1,
            file_id,
            file_type,
            chunk_size: FILES_CHUNK_SIZE,
            recovery_pub: EncPublicKey::from_bytes(recovery.enc_pub),
            recovery_mlkem_pub: recovery.mlkem_pub,
            created_at: Timestamp(TS),
        },
        streams,
    )
    .map_err(|e| format!("build_upload({}): {e:?}", file_type_name(file_type)))?;

    maxsecu_client_app::upload::run_pipeline(
        &mut c.sender,
        host,
        token,
        &bundle,
        |_, _| {},
        maxsecu_client_app::upload::StageFlags::default(),
    )
    .await
    .map_err(|e| format!("run_pipeline({}): {}", file_type_name(file_type), e.message))?;

    Ok(file_id.0)
}

/// Like `view_own_blog`, but returns EVERY decrypted stream, not just Content.
/// Thumbnail/Preview have no source counterpart, so their pre/post digests are the
/// only evidence the pinned-blob path survived the upgrade.
async fn open_all_streams(
    c: &mut Conn,
    host: &str,
    owner: &Identity,
    owner_uid_hex: &str,
    token: &str,
    file_id: [u8; 16],
) -> Result<Vec<maxsecu_client_core::OpenedStream>, String> {
    let fid_hex = net::hex(&file_id);
    let (st, json) = net::get(
        c,
        &format!("/v1/files/{fid_hex}?version=latest"),
        host,
        Some(token),
    )
    .await?;
    if st != hyper::StatusCode::OK {
        return Err(format!("file view GET {fid_hex} status {st}"));
    }
    let view = parse_file_view(&json).map_err(|e| format!("parse_file_view: {}", e.message))?;
    let (bundle, _direct) = build_download_bundle(
        &mut c.sender,
        host,
        token,
        &fid_hex,
        &view,
        RouteMode::PreferServer,
        None,
    )
    .await
    .map_err(|e| format!("build_download_bundle({fid_hex}): {}", e.message))?;

    let ctx = VerifyContext {
        file_id: Id(file_id),
        author_sig_pub: owner.sig_pub_bytes(),
        owner_sig_pub: owner.sig_pub_bytes(),
        recipient_id: Id(net::hex16(owner_uid_hex)?),
        recipient_type: RecipientType::User,
        recipient_secret: owner.enc_secret(),
        recipient_mlkem_seed: owner.mlkem_seed(),
        seen_max_version: None,
        granter_sig_pub: &NO_GRANTERS,
        admin_sig_pub: &NO_ADMINS,
        tombstones: None,
        compromise: None,
    };
    let opened =
        verify_and_open(&ctx, &bundle).map_err(|e| format!("verify_and_open({fid_hex}): {e:?}"))?;
    Ok(opened.streams)
}

fn content_bytes(streams: &[maxsecu_client_core::OpenedStream]) -> Result<&[u8], String> {
    streams
        .iter()
        .find(|s| s.stream_type == StreamType::Content)
        .map(|s| s.plaintext.as_slice())
        .ok_or_else(|| "no content stream in opened file".to_owned())
}

/// One JSON record per decrypted stream, in the manifest's ascending order (which
/// `verify_and_open` preserves), so the pre/post comparison is a plain value compare.
fn stream_records(streams: &[maxsecu_client_core::OpenedStream]) -> Vec<serde_json::Value> {
    streams
        .iter()
        .map(|s| {
            serde_json::json!({
                "stream": stream_name_of(s.stream_type),
                "bytes": s.plaintext.len() as u64,
                "sha256": sha_hex(&s.plaintext),
            })
        })
        .collect()
}

/// The app-dir these phases use: `--app-dir` when given, else `<state>.appdir` (the
/// same convention `seed` uses, so the sealed keystore is a durable artifact).
fn files_app_dir(a: &FilesArgs<'_>) -> PathBuf {
    match a.app_dir {
        Some(p) => p.to_path_buf(),
        None => seed_app_dir_path(a.state),
    }
}

/// The server's own view of who this account is. Doubles as an assertion: a restore
/// or migration that stranded the account changes what the directory serves.
async fn binding_user_id(c: &mut Conn, host: &str, username: &str) -> Result<String, String> {
    let (st, body) = net::get(c, &format!("/v1/directory/{username}"), host, None).await?;
    if st != hyper::StatusCode::OK {
        return Err(format!("directory GET {username} status {st}"));
    }
    let bytes = B64
        .decode(body["binding_b64"].as_str().ok_or("no binding_b64")?)
        .map_err(|e| format!("b64: {e}"))?;
    let binding: DirBinding = decode(&bytes).map_err(|e| format!("decode binding: {e}"))?;
    Ok(net::hex(&binding.user_id.0))
}

#[allow(clippy::too_many_arguments)]
fn write_files_state(
    a: &FilesArgs<'_>,
    app_dir: &Path,
    user_id: &str,
    sig_pub: &str,
    enc_pub: &str,
    server_id: &str,
    oracle_build: &str,
    files: &[serde_json::Value],
) -> Result<(), String> {
    // Absolute, canonical: `download-files` compares against it to refuse writing
    // the post-upgrade recovery on top of the pre-upgrade one.
    let out_abs = std::fs::canonicalize(a.out_dir)
        .map_err(|e| format!("canonicalize --out-dir {}: {e}", a.out_dir.display()))?;
    // STATE_VERSION stays 1 on purpose: `read_state` hard-rejects any other value,
    // and the envelope is a strict SUPERSET of `write_state`'s, so the backup-E2E
    // `verify()` can still consume a file written here.
    let v = serde_json::json!({
        "version": STATE_VERSION,
        "server": a.server,
        "host": a.host,
        "app_dir": app_dir.to_string_lossy(),
        "username": FILES_USER,
        "user_id": user_id,
        "sig_pub": sig_pub,
        "enc_pub": enc_pub,
        "server_id": server_id,
        "oracle_build": oracle_build,
        "out_dir": out_abs.to_string_lossy(),
        "files": files,
    });
    let bytes = serde_json::to_vec_pretty(&v).map_err(|e| format!("serialize state: {e}"))?;
    std::fs::write(a.state, bytes).map_err(|e| format!("write state {}: {e}", a.state.display()))
}

/// PHASE `upload-files`: upload every `--file` through its real prepare path,
/// download each straight back, write the recovered plaintext to `--out-dir`, and
/// record a digest for EVERY stream in `--state`.
///
/// Enrolls ONLY when the app-dir has no keystore. If a keystore exists it is
/// unlocked and reused (no re-enroll, `register.key` untouched), which makes this
/// phase safe to run a SECOND time after the upgrade to prove the write path.
pub async fn upload_files(a: &FilesArgs<'_>) -> Result<(), String> {
    if a.files.is_empty() {
        return Err("--phase upload-files needs at least one --file <kind>:<path>".into());
    }
    // Computed FIRST: if this binary cannot identify itself the whole run is
    // unverifiable, and that must surface in a second rather than after a live upload.
    let build = oracle_build_id()?;

    // Validate every source BEFORE touching the network, so a typo fails in a
    // second rather than half-way through a live upload.
    let mut specs: Vec<(FileKind, PathBuf)> = Vec::with_capacity(a.files.len());
    for spec in a.files {
        specs.push(parse_file_arg(spec)?);
    }
    let mut names: Vec<String> = Vec::with_capacity(specs.len());
    for (_, p) in &specs {
        let md = std::fs::metadata(p).map_err(|e| format!("source {}: {e}", p.display()))?;
        if !md.is_file() {
            return Err(format!("source {} is not a file", p.display()));
        }
        let n = base_name(p)?;
        if names.contains(&n) {
            return Err(format!(
                "two --file arguments share the basename '{n}' — the recovered copies would \
                 overwrite each other in --out-dir"
            ));
        }
        names.push(n);
    }
    std::fs::create_dir_all(a.out_dir)
        .map_err(|e| format!("mkdir --out-dir {}: {e}", a.out_dir.display()))?;
    let src_paths: Vec<PathBuf> = specs.iter().map(|(_, p)| p.clone()).collect();
    assert_out_dir_disjoint(a.out_dir, &src_paths)?;

    let app_dir = files_app_dir(a);
    let t = net::transport(a.client_dir, a.host, a.server)?;

    // Enroll ONLY on a virgin app-dir. A keystore that exists but will not unlock is
    // a HARD failure below — never re-enroll over it, because that would mint a brand
    // new identity and hide the exact damage this test hunts for.
    let mut enrolled_uid: Option<String> = None;
    if keystore::exists(&app_dir) {
        if app_dir.join("register.key").exists() {
            return Err(format!(
                "register.key is present in {} alongside an existing keystore — refusing to run \
                 (this state is ambiguous and could re-enroll)",
                app_dir.display()
            ));
        }
        eprintln!(
            "live-smoke files: reusing the sealed identity in {} (NO re-enroll)",
            app_dir.display()
        );
    } else {
        let admin_key = std::fs::read_to_string(a.client_dir.join("register.key"))
            .map_err(|e| format!("read admin register.key: {e}"))?
            .trim()
            .to_owned();
        let _ = std::fs::remove_dir_all(&app_dir);
        seed_app_dir(&app_dir, &admin_key)?;
        let mut c0 = net::open(&t).await?;
        let uid = enroll_at(&mut c0, a.host, &app_dir, FILES_USER).await?;
        if app_dir.join("register.key").exists() {
            return Err(
                "register.key survived enroll — the single-use registration key was not consumed"
                    .into(),
            );
        }
        eprintln!(
            "live-smoke files: enrolled {FILES_USER} ({uid}) into {}",
            app_dir.display()
        );
        enrolled_uid = Some(uid);
    }

    let id = keystore::unlock(&app_dir, PASSPHRASE)
        .map_err(|e| format!("keystore::unlock({}): {}", app_dir.display(), e.message))?;
    let sig_pub = net::hex(&id.sig_pub_bytes());
    let enc_pub = net::hex(&id.enc_pub_bytes());

    let mut c = net::open(&t).await?; // fresh channel for the channel-bound login
    let ok = login_exchange(&mut c.sender, &id, FILES_USER, a.host, &c.exporter, TS)
        .await
        .map_err(|e| format!("login {FILES_USER}: {}", e.message))?;
    if ok.token.is_empty() {
        return Err(format!("empty token for {FILES_USER}"));
    }
    let token = ok.token.clone();
    let server_id = ok.server_id.clone();

    let user_id = binding_user_id(&mut c, a.host, FILES_USER).await?;
    if let Some(uid) = enrolled_uid {
        if uid != user_id {
            return Err(format!(
                "enroll returned user_id {uid} but the directory binding serves {user_id}"
            ));
        }
    }
    eprintln!("live-smoke files: logged in as {FILES_USER} ({user_id}), server_id={server_id}");
    eprintln!(
        "live-smoke files: oracle binary sha256={}… — recorded in --state as the build \
         download-files must match",
        short_build(&build)
    );

    let mut records: Vec<serde_json::Value> = Vec::with_capacity(specs.len());
    for ((kind, path), name) in specs.iter().zip(names.iter()) {
        let (file_type, streams, source) = prepare_from_disk(*kind, path)?;
        let source_sha = sha_hex(&source);

        let fid =
            upload_prepared(&mut c, a.host, &id, &user_id, &token, file_type, &streams).await?;
        let fid_hex = net::hex(&fid);

        // Read it straight back through the real verify ladder: this run's own
        // recovered bytes are the PRE-upgrade reference the post-upgrade lap uses.
        let opened = open_all_streams(&mut c, a.host, &id, &user_id, &token, fid).await?;
        let content = content_bytes(&opened)?;
        let content_sha = sha_hex(content);

        let dest = a.out_dir.join(name);
        std::fs::write(&dest, content).map_err(|e| format!("write {}: {e}", dest.display()))?;

        // MEASURED, not assumed. A .png under `image:` comes back verbatim; a .jpg
        // under `image:` does not, and that is recorded truthfully.
        let content_is_source = content_sha == source_sha;

        eprintln!(
            "live-smoke files: {name} kind={} file_type={} fid={fid_hex} src={}B content={}B \
             streams={} {} -> {}",
            kind.name(),
            file_type_name(file_type),
            source.len(),
            content.len(),
            opened.len(),
            if content_is_source {
                "SOURCE-IDENTICAL"
            } else {
                "TRANSFORMED(cross-run-only)"
            },
            dest.display()
        );

        records.push(serde_json::json!({
            "tag": name,
            "kind": kind.name(),
            "file_id": fid_hex,
            "file_type": file_type_name(file_type),
            "source_path": path.to_string_lossy(),
            "source_sha256": source_sha,
            "source_bytes": source.len() as u64,
            "content_sha256": content_sha,
            "content_bytes": content.len() as u64,
            "content_is_source": content_is_source,
            "streams": stream_records(&opened),
        }));
    }

    write_files_state(
        a, &app_dir, &user_id, &sig_pub, &enc_pub, &server_id, &build, &records,
    )?;
    eprintln!(
        "live-smoke files: uploaded + read back {}/{} file(s); state {}",
        records.len(),
        specs.len(),
        a.state.display()
    );
    // The sealed app-dir is deliberately LEFT IN PLACE: `download-files` reopens
    // this exact keystore, which is what "no re-enroll" actually means.
    Ok(())
}

/// PHASE `download-files`: reopen the SAME sealed app-dir after the upgrade and
/// re-download every recorded file. This phase NEVER re-enrolls and NEVER re-uploads
/// a recorded file — if the server lost a blob it must fail, not silently re-create.
pub async fn download_files(a: &FilesArgs<'_>) -> Result<(), String> {
    if !a.files.is_empty() {
        return Err(
            "--file is not valid with --phase download-files (the file set comes from --state)"
                .into(),
        );
    }
    let st = read_state(a.state)?;
    let rec_server = state_str(&st, "server")?;
    let rec_host = state_str(&st, "host")?;
    if rec_server != a.server {
        return Err(format!(
            "state server mismatch: recorded {rec_server}, got {}",
            a.server
        ));
    }
    if rec_host != a.host {
        return Err(format!(
            "state host mismatch: recorded {rec_host}, got {}",
            a.host
        ));
    }

    // The post-upgrade lap must run the SAME (pre-upgrade) client binary, or it
    // proves nothing about the installs real users already have.
    let rec_build = state_str(&st, "oracle_build")?;
    let build = oracle_build_id()?;
    if rec_build != build && !a.allow_client_upgrade {
        return Err(format!(
            "oracle build changed: --state was written by '{rec_build}', this binary is \
             '{build}'. The post-upgrade lap must use the PRE-upgrade client. Pass \
             --allow-client-upgrade to run the NEW client deliberately."
        ));
    }
    eprintln!(
        "live-smoke files: oracle binary sha256={}… — {}",
        short_build(&build),
        if rec_build == build {
            "SAME binary that wrote --state"
        } else {
            "DIFFERENT from --state, allowed by --allow-client-upgrade"
        }
    );

    let app_dir = PathBuf::from(state_str(&st, "app_dir")?);
    // NO re-enroll: the single-use key was consumed at upload time and must still be
    // gone. Its absence is the proof this app-dir was never re-enrolled.
    if app_dir.join("register.key").exists() {
        return Err(format!(
            "register.key is present in {} — download-files must NOT re-enroll",
            app_dir.display()
        ));
    }
    if !keystore::exists(&app_dir) {
        return Err(format!(
            "no keystore in {} — the sealed identity is gone; a re-enroll here would hide the \
             very break this test hunts",
            app_dir.display()
        ));
    }
    let id = keystore::unlock(&app_dir, PASSPHRASE)
        .map_err(|e| format!("keystore::unlock({}): {}", app_dir.display(), e.message))?;
    if net::hex(&id.sig_pub_bytes()) != state_str(&st, "sig_pub")? {
        return Err("sig_pub changed after the upgrade (identity not preserved)".into());
    }
    if net::hex(&id.enc_pub_bytes()) != state_str(&st, "enc_pub")? {
        return Err("enc_pub changed after the upgrade (identity not preserved)".into());
    }
    eprintln!("live-smoke files: unlocked the SAME sealed identity; sig/enc pub keys match");

    std::fs::create_dir_all(a.out_dir)
        .map_err(|e| format!("mkdir --out-dir {}: {e}", a.out_dir.display()))?;
    let out_abs = std::fs::canonicalize(a.out_dir)
        .map_err(|e| format!("canonicalize --out-dir {}: {e}", a.out_dir.display()))?;
    if out_abs.to_string_lossy() == state_str(&st, "out_dir")? {
        return Err(format!(
            "--out-dir {} is the SAME directory the upload phase wrote to — a failed write here \
             would leave the PRE-upgrade copy in place and read as green. Use a distinct directory.",
            out_abs.display()
        ));
    }

    let files = st
        .get("files")
        .and_then(|f| f.as_array())
        .ok_or("state: missing 'files' array")?;
    if files.is_empty() {
        return Err("state records ZERO files — this run would verify nothing".into());
    }
    let sources: Vec<PathBuf> = files
        .iter()
        .filter_map(|f| f.get("source_path").and_then(|x| x.as_str()))
        .map(PathBuf::from)
        .collect();
    assert_out_dir_disjoint(a.out_dir, &sources)?;

    let username = state_str(&st, "username")?;
    let user_id = state_str(&st, "user_id")?;

    let t = net::transport(a.client_dir, a.host, a.server)?;
    let mut c = net::open(&t).await?;
    let ok = login_exchange(&mut c.sender, &id, &username, a.host, &c.exporter, TS)
        .await
        .map_err(|e| format!("login {username}: {}", e.message))?;
    if ok.token.is_empty() {
        return Err(format!("empty token for {username}"));
    }
    let token = ok.token.clone();
    eprintln!("live-smoke files: login OK (no re-enroll, no re-pin)");

    let rec_server_id = state_str(&st, "server_id")?;
    if ok.server_id != rec_server_id {
        if a.allow_server_id_change {
            eprintln!(
                "live-smoke files: WARNING server_id changed ({rec_server_id} -> {}) — allowed by \
                 --allow-server-id-change",
                ok.server_id
            );
        } else {
            return Err(format!(
                "server_id changed across the upgrade: recorded {rec_server_id}, now {}. Every \
                 login proof is bound to it. Pass --allow-server-id-change only if this rotation \
                 is intended and recorded in docs/compat/LEDGER.md.",
                ok.server_id
            ));
        }
    }

    // user_id is the recipient_id inside every DEK wrap — a migration that stranded
    // this account changes what the directory serves.
    let served_uid = binding_user_id(&mut c, a.host, &username).await?;
    if served_uid != user_id {
        return Err(format!(
            "binding user_id mismatch: recorded {user_id}, served {served_uid}"
        ));
    }

    // The recovery pin the server serves must still match this app's EMBEDDED pin,
    // or no future upload from this install can ever wrap a DEK.
    resolve_recovery_pin(&mut c.sender, a.host)
        .await
        .map_err(|e| format!("recovery pin gate after the upgrade: {}", e.message))?;
    eprintln!("live-smoke files: directory binding + recovery pin both unchanged");

    let total = files.len();
    let mut done = 0usize;
    for f in files {
        let tag = f
            .get("tag")
            .and_then(|x| x.as_str())
            .ok_or("file record: missing 'tag'")?;
        let fid_hex = f
            .get("file_id")
            .and_then(|x| x.as_str())
            .ok_or("file record: missing 'file_id'")?;
        let fid = net::hex16(fid_hex)?;

        let opened = open_all_streams(&mut c, a.host, &id, &user_id, &token, fid).await?;

        // EVERY stream, not just content. Thumbnail/Preview are derived and have no
        // source counterpart, so this cross-run compare is their ONLY evidence.
        let want = f
            .get("streams")
            .and_then(|x| x.as_array())
            .ok_or("file record: missing 'streams'")?;
        let got = stream_records(&opened);
        if got.len() != want.len() {
            return Err(format!(
                "file '{tag}' {fid_hex}: stream COUNT changed after the upgrade (recorded {}, got {})",
                want.len(),
                got.len()
            ));
        }
        for (w, g) in want.iter().zip(got.iter()) {
            if w != g {
                return Err(format!(
                    "file '{tag}' {fid_hex}: stream record changed after the upgrade\n  recorded {w}\n  got      {g}"
                ));
            }
        }

        let content = content_bytes(&opened)?;
        let content_sha = sha_hex(content);
        let want_content = f
            .get("content_sha256")
            .and_then(|x| x.as_str())
            .ok_or("file record: missing 'content_sha256'")?;
        if content_sha != want_content {
            return Err(format!(
                "file '{tag}' {fid_hex}: CONTENT digest changed after the upgrade (got \
                 {content_sha}, recorded {want_content})"
            ));
        }

        let dest = a.out_dir.join(tag);
        std::fs::write(&dest, content).map_err(|e| format!("write {}: {e}", dest.display()))?;

        let is_src = f
            .get("content_is_source")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);
        let src_sha = f
            .get("source_sha256")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let src_path = f.get("source_path").and_then(|x| x.as_str()).unwrap_or("");

        if is_src {
            if content_sha != src_sha {
                return Err(format!(
                    "file '{tag}' {fid_hex}: recovered content != SOURCE bytes (got {content_sha}, \
                     source {src_sha})"
                ));
            }
            // Re-hash the source ON DISK when it is still there: proves the state
            // file was not regenerated or edited between the two laps.
            if !src_path.is_empty() {
                if let Ok(bytes) = std::fs::read(src_path) {
                    let now = sha_hex(&bytes);
                    if now != src_sha {
                        return Err(format!(
                            "file '{tag}': the SOURCE at {src_path} changed since the upload phase \
                             (now {now}, recorded {src_sha}) — the comparison would be meaningless"
                        ));
                    }
                }
            }
            eprintln!(
                "live-smoke files: {tag} {fid_hex} OK {} bytes SOURCE-IDENTICAL -> {}",
                content.len(),
                dest.display()
            );
        } else {
            eprintln!(
                "live-smoke files: {tag} {fid_hex} OK {} bytes CROSS-RUN-IDENTICAL (the client \
                 transformed this source at upload time, so source-byte identity is impossible by \
                 design and is NOT asserted) -> {}",
                content.len(),
                dest.display()
            );
        }
        done += 1;
    }
    if done != total {
        return Err(format!("verified {done} of {total} recorded files"));
    }
    eprintln!("live-smoke files: {done}/{total} recorded file(s) verified after the upgrade");

    // The WRITE path must survive too: a fresh post from the SAME pre-upgrade
    // identity needs the delegation triple + recovery account + operational key to
    // still wrap and to still pass the pin gate. Uses the existing helpers verbatim.
    const POST_BODY: &[u8] =
        b"live-smoke files: a fresh post AFTER the upgrade proves an EXISTING identity can still write.";
    let new_fid = upload_blog(
        &mut c,
        a.host,
        &id,
        &user_id,
        &token,
        POST_BODY,
        "PostUpgrade",
    )
    .await?;
    let got = view_own_blog(&mut c, a.host, &id, &user_id, &token, new_fid).await?;
    if got != POST_BODY {
        return Err(format!(
            "post-upgrade write/view mismatch: {} bytes decrypted",
            got.len()
        ));
    }
    eprintln!(
        "live-smoke files: post-upgrade upload + view-back OK ({} bytes)",
        got.len()
    );

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
