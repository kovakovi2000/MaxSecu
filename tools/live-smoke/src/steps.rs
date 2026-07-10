//! The individual smoke assertions. Filled in across Tasks 3-6.

use std::path::{Path, PathBuf};

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
use maxsecu_encoding::types::{FileType, Id, RecipientType, StreamType, Timestamp};

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
        Ok::<(), String>(())
    }
    .await;
    let _ = std::fs::remove_dir_all(&admin_dir);
    round_trip?;
    Ok(())
}
