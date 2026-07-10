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

/// A fresh temp app-dir seeded with `register.key = key`.
fn app_dir_with_key(tag: &str, key: &str) -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join(format!(
        "livesmoke_{tag}_{}",
        net::hex(&maxsecu_crypto::random_array::<8>())
    ));
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    std::fs::write(dir.join("register.key"), key.as_bytes())
        .map_err(|e| format!("write register.key: {e}"))?;
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
