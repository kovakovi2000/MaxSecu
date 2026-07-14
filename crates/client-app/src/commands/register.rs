//! **Registration-key enrollment** on the client side (spec §5): startup mode #2.
//! When a single-use `register.key` file is present beside the exe, the operator
//! (or an admin-minted enrollee) turns it into a real account. The client:
//!
//!   1. reads the single-use registration key from `<app-dir>/register.key`,
//!   2. generates a fresh hybrid [`Identity`] (X25519 + ML-KEM + Ed25519) ENTIRELY
//!      in Rust,
//!   3. `POST /v1/users` with the key + the identity's PUBLIC keys + username — the
//!      server consumes the key, creates the user, signs the binding (the first-ever
//!      registrant becomes admin; everyone else is User-role), and returns 201,
//!   4. on success SEALS the new identity into the local keystore (passphrase-
//!      protected) AND DELETES the local `register.key` file — the server has
//!      consumed its copy, so the client destroys its plaintext copy so the single-
//!      use secret can never be reused.
//!
//! The generated `Identity` and the passphrase-derived key stay entirely in Rust;
//! only DTOs (username + opaque `user_id`) cross the Tauri seam; the registration
//! key value is never returned and never logged. A consumed/invalid key → 403 → the
//! flow fails CLOSED (no account, no keystore, no key deletion).

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;
use hyper::StatusCode;
use zeroize::Zeroizing;

use maxsecu_client_core::Identity;

use crate::config::ConnectionConfig;
use crate::dto::{RegisterWithKeyRequest, RegisteredDto};
use crate::error::UiError;
use crate::http_client::post_json;
use crate::keystore;

use super::auth::AppDir;
use super::connection::open_conn;

/// Where the single-use registration key file lives in the portable layout:
/// `<app-dir>/register.key`, beside the exe (a sibling of the recovery keyblob at
/// `<app-dir>/recovery/recovery_key_blob`). Written out of band by `maxsecu-setup`.
pub fn register_key_path(dir: &Path) -> PathBuf {
    dir.join("register.key")
}

/// Read + trim the single-use registration key from `path`. A missing file →
/// `no_registration_key` (this device is not in registration mode). The returned
/// key is zeroize-on-drop; it is never returned to the UI or logged.
pub fn read_registration_key(path: &Path) -> Result<Zeroizing<String>, UiError> {
    let raw = std::fs::read_to_string(path).map_err(|_| {
        UiError::new(
            "no_registration_key",
            "No registration key file on this device.",
        )
    })?;
    let key = raw.trim().to_owned();
    if key.is_empty() {
        return Err(UiError::new(
            "no_registration_key",
            "The registration key file is empty.",
        ));
    }
    Ok(Zeroizing::new(key))
}

fn b64(bytes: impl AsRef<[u8]>) -> String {
    B64.encode(bytes.as_ref())
}

/// Build the `POST /v1/users` enrollment body — a PURE function so the wire shape
/// is testable without a network (see `tests/compat.rs`; this is the exact seam
/// where `mlkem_pub_b64` once went missing and forced every recipient to
/// re-enroll).
///
/// Every emitted key is read by the server's `RegisterReq`; DROPPING one is a
/// backward-compatibility break, not a refactor. `mlkem_pub_b64` in particular is
/// what makes the server publish a PQ-hybrid directory binding — without it every
/// `Suite::V2` re-share (or rotation) to this user fails closed with
/// `pq_key_missing` (P7.4, `docs/runbooks/pq-reenrollment.md`). A fresh identity is
/// always PQ-capable; a legacy v1-blob identity carries no ML-KEM key and enrols
/// classical (the `None` arm is a forward-compat guard).
pub fn build_register_body(
    username: &str,
    id: &Identity,
    registration_key: &str,
) -> serde_json::Value {
    let mut body = serde_json::json!({
        "username": username,
        "enc_pub_b64": b64(id.enc_pub_bytes()),
        "sig_pub_b64": b64(id.sig_pub_bytes()),
        "registration_key": registration_key,
    });
    if let Some(mlkem) = id.mlkem_pub_bytes() {
        body["mlkem_pub_b64"] = serde_json::Value::String(b64(mlkem));
    }
    body
}

/// `POST /v1/users` with the registration key + the new identity's PUBLIC keys +
/// `username`, over an already-connected, pinned-TLS sender. Returns the server-
/// assigned `user_id` (hex16) on 201. A consumed/invalid key (403) → the single
/// sanitized `registration_failed` shape (fail closed); a taken username (409) →
/// `username_taken`; anything else → `register_failed`. Only PUBLIC key bytes and
/// the (already-known-to-the-server) key ever leave; no private material.
pub async fn enroll_exchange(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    username: &str,
    id: &Identity,
    registration_key: &str,
) -> Result<String, UiError> {
    let body = build_register_body(username, id, registration_key);
    let (status, json) = post_json(sender, "/v1/users", &body, None, host).await?;
    match status {
        StatusCode::CREATED => json["user_id"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| UiError::new("internal", "Malformed server response.")),
        // A reused/expired/unknown single-use key: fail closed with one sanitized
        // shape so the UI cannot tell "consumed" from "never existed" (no oracle).
        StatusCode::FORBIDDEN => Err(UiError::new(
            "registration_failed",
            "The registration key is invalid or already used.",
        )),
        StatusCode::CONFLICT => Err(UiError::new("username_taken", "That username is taken.")),
        _ => Err(UiError::new("register_failed", "Registration failed.")),
    }
}

/// The full client-side enrollment flow, over an already-connected pinned-TLS
/// sender (the Tauri command opens the connection; the e2e drives this directly).
///
/// Ordering is fail-safe: the local checks (key present, keystore not-yet-created,
/// strong passphrase) run BEFORE the network call so a server rejection never
/// leaves an orphaned sealed blob or a burned key with no account. Only AFTER the
/// server has accepted (201) is the new identity sealed and the local `register.key`
/// destroyed — so a failure at any step leaves the single-use key reusable.
pub async fn register_with_key_exchange(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    dir: &Path,
    username: &str,
    passphrase: &str,
) -> Result<RegisteredDto, UiError> {
    // Read the single-use key first (missing → not in registration mode).
    let key = read_registration_key(&register_key_path(dir))?;
    // Fail fast BEFORE the network call: a pre-existing keystore or a weak
    // passphrase must not consume the server-side key.
    keystore::precheck(dir, passphrase)?;

    // Generate the fresh hybrid identity entirely in Rust.
    let id = Identity::generate();
    let user_id = enroll_exchange(sender, host, username, &id, key.as_str()).await?;

    // Only now, after the server has accepted, persist the identity locally...
    keystore::seal_identity(dir, passphrase, &id)?;
    // ...and destroy the local plaintext copy of the now-consumed single-use key.
    // Best-effort: the account already exists and the key is sealed, so a failed
    // unlink must not fail the enrollment — but it should be visible if it happens.
    let _ = std::fs::remove_file(register_key_path(dir));

    Ok(RegisteredDto {
        username: username.to_owned(),
        user_id,
    })
}

/// Persist the address the user just enrolled against into `<dir>/config/connection.json`
/// so their SUBSEQUENT logins default to it (`connection::server_of` reads
/// `ConnectionConfig::server`). Load-then-patch so any pre-existing preference on the
/// file (e.g. `use_tor`) is preserved; only `server` is (re)set and `auto_connect` is
/// forced off (registration never implies auto-connect). The connect `server_name` is
/// derived from the host part of `server` at dial time by `open_conn` (host before the
/// last `:`), so it is not stored separately here. Best-effort by design: the account
/// already exists and the identity is sealed, so a failed write must not fail the
/// enrollment (the caller ignores the result).
fn persist_registered_server(dir: &Path, server: &str) -> std::io::Result<()> {
    let mut cfg = ConnectionConfig::load(dir);
    cfg.server = server.to_owned();
    cfg.auto_connect = false;
    cfg.save(dir)
}

/// `register_with_key` — startup mode #2 (spec §5). Read the local `register.key`,
/// generate a fresh identity, enrol via `POST /v1/users`, seal the identity into the
/// keystore, and delete the consumed key file. Only DTOs cross the seam; the
/// generated identity + passphrase-derived key never leave Rust.
#[tauri::command]
pub async fn register_with_key(
    req: RegisterWithKeyRequest,
    dir: tauri::State<'_, AppDir>,
) -> Result<RegisteredDto, UiError> {
    // Scrub the passphrase on every exit path (success, failure, panic).
    let passphrase = Zeroizing::new(req.passphrase);
    // Mirror `login`/`connect`: bind to the server the USER typed on the register
    // screen (`req.server`), NOT the saved/default `connection.json` (`server_of`).
    // A fresh device has no saved server yet, so reading it here was the bug.
    let (mut sender, host, _exp) = open_conn(&dir.0, &req.server).await?;
    let dto =
        register_with_key_exchange(&mut sender, &host, &dir.0, &req.username, passphrase.as_str())
            .await?;
    // Only after a fully successful enrollment (201 + sealed identity + consumed
    // key) persist the entered address so later logins default to it. Best-effort:
    // the account already exists, so a failed write must not fail registration.
    let _ = persist_registered_server(&dir.0, &req.server);
    Ok(dto)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "mxreg-ut-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn register_key_path_is_beside_the_exe() {
        let p = register_key_path(Path::new("/app"));
        assert!(p.ends_with("register.key"));
    }

    #[test]
    fn register_with_key_request_carries_server() {
        // The register screen now sends the typed server on the seam (mirroring
        // `login`/`connect`), so the request must deserialize a `server` field.
        let req: RegisterWithKeyRequest = serde_json::from_str(
            r#"{"server":"123.123.123.123:8443","username":"alice","passphrase":"hunter2hunter2"}"#,
        )
        .unwrap();
        assert_eq!(req.server, "123.123.123.123:8443");
        assert_eq!(req.username, "alice");
        assert_eq!(req.passphrase, "hunter2hunter2");
    }

    #[test]
    fn persist_registered_server_writes_entered_address() {
        // After a successful enrollment the entered address is written to
        // connection.json so `connection::server_of` (which reads
        // `ConnectionConfig::server`) defaults later logins to it.
        let dir = tempdir();
        persist_registered_server(&dir, "123.123.123.123:8443").unwrap();
        let cfg = ConnectionConfig::load(&dir);
        assert_eq!(cfg.server, "123.123.123.123:8443");
        assert!(!cfg.auto_connect);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persist_registered_server_preserves_prior_prefs_and_forces_manual() {
        // Load-then-patch: a pre-existing preference on the file survives, only
        // `server` is (re)set and `auto_connect` is forced off.
        let dir = tempdir();
        ConnectionConfig {
            server: "old:1".into(),
            use_tor: true,
            auto_connect: true,
        }
        .save(&dir)
        .unwrap();
        persist_registered_server(&dir, "new-host:8443").unwrap();
        let cfg = ConnectionConfig::load(&dir);
        assert_eq!(cfg.server, "new-host:8443");
        assert!(cfg.use_tor, "prior use_tor preference preserved");
        assert!(!cfg.auto_connect, "registration never implies auto-connect");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_registration_key_trims_and_rejects_missing_or_empty() {
        let dir = tempdir();
        let path = register_key_path(&dir);
        // Missing file → clear, sanitized error.
        assert_eq!(
            read_registration_key(&path).unwrap_err().code,
            "no_registration_key"
        );
        // Trailing newline/whitespace from an operator paste is trimmed off.
        std::fs::write(&path, "  deadbeef\n").unwrap();
        assert_eq!(read_registration_key(&path).unwrap().as_str(), "deadbeef");
        // A whitespace-only file is treated as absent (fail closed).
        std::fs::write(&path, "   \n").unwrap();
        assert_eq!(
            read_registration_key(&path).unwrap_err().code,
            "no_registration_key"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
