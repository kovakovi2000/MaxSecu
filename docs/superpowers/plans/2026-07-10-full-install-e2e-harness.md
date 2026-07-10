# Full-Install / Reinstall E2E Test Harness — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One committed PowerShell orchestrator that, fully unattended, provisions a throwaway WSL server, installs server + client via their real scripts, proves the live pair works at the protocol layer with a headless Rust oracle, exercises the reset+reinstall path, proves it again, then deletes everything — with one pristine pass requiring zero mid-run fixes.

**Architecture:** Three pieces. (1) `tools/live-smoke/` — a new headless binary in the **client** cargo workspace that reuses the production `client-core` + `client-app` library functions over the pinned TLS transport against the *live installed* server; it is the functional oracle and exits non-zero on any failure. (2) `scripts/test-full-install.ps1` — a phased, fail-fast orchestrator with `try/finally` teardown. (3) A one-line non-interactive tweak to `install-client.ps1` (accept the recovery passphrase from a param / env var). The smoke deliberately covers only what the *stock* single-server install actually ships: enroll → upload → view-back → admin-mint → second-user enroll → cross-user feed visibility → second-user own upload round-trip. **User-to-user `reshare` is intentionally out of scope** — it hard-requires an out-of-band sink server that neither installer deploys (decision recorded 2026-07-10).

**Tech Stack:** PowerShell 5.1 (orchestrator), WSL2 + Ubuntu 22.04 + systemd (throwaway server), Rust 1.96 MSVC (smoke binary + client build), the existing `install-server.sh` / `install-client.ps1`, `maxsecu-setup`, and the `maxsecu-client-app` / `maxsecu-client-core` crates.

---

## Key facts established during design (do not re-derive)

- **The smoke is a SEPARATE crate**, so every client-app/client-core symbol it calls must be `pub` (not `pub(crate)`). `download::recover_own_dek` is `pub(crate)` — **do not use it**. Use the `pub` top-level `maxsecu_client_core::verify_and_open` instead.
- **The smoke must embed the REAL recovery pin.** `build_upload`'s recovery gate (`directory::resolve_recovery_pin` → `compare_served`) matches the server's recovery account only if the pin compiled into the binary equals the one `maxsecu-setup` used. So the smoke links `maxsecu-client-app` with `default-features = false` (drops `embed-ffmpeg`, so no vendored `ffmpeg.exe` is needed) and **WITHOUT `unpinned-dev`** (so `build.rs` embeds the real `crates/client-app/recovery_pin.bin` that `install-client.ps1` staged). Therefore the smoke can only be built **after** `install-client.ps1` has run.
- **Feature-unification discipline (gotcha):** `client-e2e` pulls `client-app` with `unpinned-dev` as a *dev-dependency*; the smoke pulls it as a *normal* dependency without that feature. Under resolver v2 these do NOT collide as long as you build the smoke **by name**: `cargo build -p maxsecu-live-smoke`. Never build it via a bare workspace `cargo build`.
- **Server identity for a `--public` install** is an IP-SAN cert whose SAN is the WSL IP. So the smoke's rustls `ServerName` and the `host` header must be that **IP string**, and `pinned_client_config` pins the exact `server_cert.der`. This mirrors how the real client dials a public server.
- **Uploads are Suite::V2** (PQ owner + PQ recovery), so `verify_and_open`'s `VerifyContext.recipient_mlkem_seed` must be `Some(owner.mlkem_seed()...)`, not `None`.
- **Reset wipes the DB**, so the second (reinstall) smoke run starts from an empty server — the fixed usernames `smokeadmin` / `smokeuser` are free again each pass; no timestamping needed.

## Reference files to mirror (known-compiling production/e2e code)

- `crates/client-e2e/tests/connect_login_e2e.rs:99-152` — the `open()` (TLS+hyper sender+exporter) and raw `post()` JSON helpers, and `register()`.
- `crates/client-e2e/tests/full_flow_e2e.rs:316-465` — the full enroll→resolve-recovery→upload→view story against a server, using the exact `client-app` functions the smoke needs.
- `crates/client-e2e/tests/browse_view_e2e.rs:496-564` — the exact `VerifyContext { .. }` literal + `verify_and_open(&ctx, &bundle)` call for decrypting an owned blog.

---

## File Structure

- **Create** `tools/live-smoke/Cargo.toml` — bin crate manifest; member of the client workspace.
- **Create** `tools/live-smoke/src/main.rs` — arg parsing, orchestration of the smoke steps, process exit code.
- **Create** `tools/live-smoke/src/net.rs` — pinned-transport connection + raw JSON GET/POST helpers (mirrors the e2e `open`/`post`/`get`).
- **Create** `tools/live-smoke/src/steps.rs` — the individual assertions (enroll, login, upload, view-back, mint, role-check, feed-visibility).
- **Modify** `crates/client-app/Cargo.toml:` `[workspace] members` — add `"../../tools/live-smoke"`.
- **Modify** `scripts/install-client.ps1:279` region — accept `-RecoveryPassphrase` / `$env:SETUP_RECOVERY_PW` and skip the interactive `Read-Host` when supplied.
- **Create** `scripts/test-full-install.ps1` — the orchestrator.
- **Modify** `README.md` — a "Full-install E2E harness" section + document the `install-client.ps1` non-interactive passphrase change.

---

## Task 1: `install-client.ps1` — non-interactive recovery passphrase

**Files:**
- Modify: `scripts/install-client.ps1:39-65` (params) and `scripts/install-client.ps1:274-289` (passphrase prompt)

The ONLY interactive blocker to unattended client install is the `Read-Host -AsSecureString 'Recovery passphrase'`. Accept the passphrase from a new `-RecoveryPassphrase` parameter or the `SETUP_RECOVERY_PW` env var; only prompt when neither is supplied.

- [ ] **Step 1: Add the `-RecoveryPassphrase` parameter to the `Install` set**

In the `param(...)` block, after the `$Fingerprint` parameter (around line 56), add:

```powershell
    # Unattended recovery passphrase. When supplied (or via $env:SETUP_RECOVERY_PW),
    # the interactive Read-Host prompt is skipped so the client can be installed
    # non-interactively (e.g. by scripts\test-full-install.ps1). Leave empty for the
    # normal interactive install, which prompts without echoing.
    [Parameter(ParameterSetName = 'Install')]
    [string] $RecoveryPassphrase = '',
```

- [ ] **Step 2: Use the supplied passphrase instead of prompting**

Replace the prompt block (currently lines ~277-288, from `Write-Host 'Choose a RECOVERY passphrase...` through the `if ([string]::IsNullOrEmpty($PlainPw)) { Fail ... }`) with:

```powershell
    # Prefer a non-interactively supplied passphrase (param or env var); fall back to
    # an interactive, non-echoed prompt. The plaintext is handed to the child process
    # ONLY via the SETUP_RECOVERY_PW env var below (never printed, never persisted).
    $PlainPw = $RecoveryPassphrase
    if ([string]::IsNullOrEmpty($PlainPw)) { $PlainPw = $env:SETUP_RECOVERY_PW }
    if ([string]::IsNullOrEmpty($PlainPw)) {
        Write-Host 'Choose a RECOVERY passphrase. Write it down and keep it offline with'
        Write-Host 'recovery_key.blob -- together they are the ONLY way to recover the account.'
        $SecurePw = Read-Host -AsSecureString 'Recovery passphrase'
        $Bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePw)
        try {
            $PlainPw = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($Bstr)
        } finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr)
        }
    } else {
        Write-Host 'Using a non-interactively supplied recovery passphrase.' -ForegroundColor DarkYellow
    }
    if ([string]::IsNullOrEmpty($PlainPw)) {
        Fail 'Recovery passphrase cannot be empty.'
    }
```

Leave the existing `$env:SETUP_RECOVERY_PW = $PlainPw` / `finally { Remove-Item Env:\SETUP_RECOVERY_PW ... }` block that follows unchanged — it already scrubs the env var after the child exits.

- [ ] **Step 3: Verify the script still parses and the reset path is unaffected**

Run: `powershell -NoProfile -Command "& { . { param() } ; $null = [ScriptBlock]::Create((Get-Content -Raw scripts\install-client.ps1)); 'parsed ok' }"`
Expected: prints `parsed ok` with no parser error. (A full run is exercised end-to-end by Task 7.)

- [ ] **Step 4: Commit**

```bash
git add scripts/install-client.ps1
git commit -m "feat(install-client): accept -RecoveryPassphrase/SETUP_RECOVERY_PW for unattended install"
```

---

## Task 2: `live-smoke` crate skeleton (compiles, parses args)

**Files:**
- Create: `tools/live-smoke/Cargo.toml`
- Create: `tools/live-smoke/src/main.rs`
- Modify: `crates/client-app/Cargo.toml` (`[workspace] members`)

- [ ] **Step 1: Add the crate to the client workspace members**

In `crates/client-app/Cargo.toml`, change:

```toml
members = [".", "../client-e2e", "../../tools/maxsecu-setup"]
```
to:
```toml
members = [".", "../client-e2e", "../../tools/maxsecu-setup", "../../tools/live-smoke"]
```

- [ ] **Step 2: Write `tools/live-smoke/Cargo.toml`**

```toml
[package]
name = "maxsecu-live-smoke"
version = "0.0.0"
edition.workspace = true
rust-version.workspace = true
publish = false
description = "Headless functional oracle: drives client-core/client-app against a LIVE installed MaxSecu server over the pinned transport. Exits non-zero on any failure."
# Sits outside the client-workspace root dir (crates/client-app), so name the
# owning workspace explicitly (Cargo's ancestor walk would otherwise bind it to
# the top-level server workspace — same reason client-e2e does this).
workspace = "../../crates/client-app"

[[bin]]
name = "maxsecu-live-smoke"
path = "src/main.rs"

[dependencies]
# default-features = false drops embed-ffmpeg (no vendored ffmpeg.exe needed) but
# KEEPS the real embedded recovery pin (NO unpinned-dev), so build_upload's recovery
# gate matches the live server's recovery account. Build ONLY as `-p maxsecu-live-smoke`
# (never a bare workspace build) so client-e2e's dev-only `unpinned-dev` never unifies in.
maxsecu-client-app = { path = "../../crates/client-app", default-features = false }
maxsecu-client-core = { path = "../../crates/client-core", features = ["net"] }
maxsecu-crypto = { path = "../../crates/crypto" }
maxsecu-encoding = { path = "../../crates/encoding" }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "io-util", "sync", "time"] }
tokio-rustls = { version = "0.26", default-features = false, features = ["aws_lc_rs"] }
hyper = { version = "1", features = ["client", "http1"] }
hyper-util = { version = "0.1", features = ["tokio"] }
http-body-util = "0.1"
base64 = "0.22"
serde_json = "1"

[lints.rust]
unsafe_code = "forbid"
```

- [ ] **Step 3: Write a minimal `tools/live-smoke/src/main.rs` that parses args and prints them**

```rust
//! Headless functional oracle for the full-install E2E harness. Drives the REAL
//! client-core/client-app code paths against a LIVE installed MaxSecu server over
//! the pinned TLS transport. Any failed assertion returns Err → process exit 1.
//!
//! Usage:
//!   maxsecu-live-smoke --server <ip:port> --host <ip> --client-dir <dist/MaxSecuClient>
//!
//! --server      dial target ip:port (the WSL server's --public address)
//! --host        the cert-SAN name to verify against == the public IP (same as --server host)
//! --client-dir  the built admin client dir: reads config/server_cert.der,
//!               config/directory_pub.der, and register.key (the admin's first key)

mod net;
mod steps;

use std::process::ExitCode;

struct Args {
    server: String,
    host: String,
    client_dir: std::path::PathBuf,
}

fn parse_args() -> Result<Args, String> {
    let mut server = None;
    let mut host = None;
    let mut client_dir = None;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--server" => server = it.next(),
            "--host" => host = it.next(),
            "--client-dir" => client_dir = it.next(),
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Args {
        server: server.ok_or("missing --server")?,
        host: host.ok_or("missing --host")?,
        client_dir: client_dir.ok_or("missing --client-dir")?.into(),
    })
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("live-smoke: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!(
        "live-smoke: server={} host={} client_dir={}",
        args.server,
        args.host,
        args.client_dir.display()
    );
    match steps::run(&args.server, &args.host, &args.client_dir).await {
        Ok(()) => {
            println!("LIVE-SMOKE OK");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("LIVE-SMOKE FAIL: {e}");
            ExitCode::FAILURE
        }
    }
}
```

- [ ] **Step 4: Write a stub `tools/live-smoke/src/steps.rs` so it compiles**

```rust
//! The individual smoke assertions. Filled in across Tasks 3-6.

use std::path::Path;

pub async fn run(_server: &str, _host: &str, _client_dir: &Path) -> Result<(), String> {
    Err("not yet implemented".into())
}
```

- [ ] **Step 5: Write a stub `tools/live-smoke/src/net.rs` so it compiles**

```rust
//! Pinned-transport connection + raw JSON helpers. Filled in in Task 3.
```

- [ ] **Step 6: Compile the crate BY NAME (never a bare workspace build)**

Run (PowerShell): `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cargo build -p maxsecu-live-smoke --manifest-path crates\client-app\Cargo.toml`

Expected: it FAILS at the `maxsecu-client-app` build script with a missing-recovery-pin error **if no `crates/client-app/recovery_pin.bin` is present** — that is expected and correct (the smoke is only ever built after `install-client.ps1` stages the pin). To compile-check in isolation during development, temporarily stage a pin with `Copy-Item recovery_pin.bin crates\client-app\recovery_pin.bin` if you have one from a prior `maxsecu-setup` run, OR defer this compile-check to Task 7 where the harness stages it. Do NOT add `unpinned-dev` to make it compile — that would break the recovery gate against the live server.

- [ ] **Step 7: Commit**

```bash
git add tools/live-smoke/Cargo.toml tools/live-smoke/src/main.rs tools/live-smoke/src/steps.rs tools/live-smoke/src/net.rs crates/client-app/Cargo.toml
git commit -m "feat(live-smoke): scaffold headless live-server oracle crate"
```

---

## Task 3: `live-smoke` — pinned connection + enroll + login + recovery-pin

**Files:**
- Modify: `tools/live-smoke/src/net.rs`
- Modify: `tools/live-smoke/src/steps.rs`

- [ ] **Step 1: Write `net.rs` — a `Conn` over the production `Transport`, plus raw JSON helpers**

Mirror `connect_login_e2e.rs:99-134`. Note the `ServerName` is built from the **IP host** (public IP-SAN cert), not `"localhost"`.

```rust
//! Pinned-transport connection + raw JSON GET/POST helpers over a live server.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use std::path::Path;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};

use maxsecu_client_app::transport::{pinned_client_config, Transport};

pub struct Conn {
    pub sender: SendRequest<Full<Bytes>>,
    pub exporter: [u8; 32],
}

/// Read the pinned `server_cert.der` from `<client_dir>/config/` and build a
/// Transport that pins it and verifies the SAN against `host` (the public IP).
pub fn transport(client_dir: &Path, host: &str, server: &str) -> Result<Transport, String> {
    let cert_path = client_dir.join("config").join("server_cert.der");
    let der = std::fs::read(&cert_path)
        .map_err(|e| format!("read {}: {e}", cert_path.display()))?;
    let cfg = pinned_client_config(CertificateDer::from(der))
        .map_err(|e| format!("pin cert: {}", e.message))?;
    let name = ServerName::try_from(host.to_owned())
        .map_err(|_| format!("invalid server_name '{host}'"))?;
    Ok(Transport::new(cfg, name, server.to_owned()))
}

/// Open one pinned-TLS connection and drive an http1 client over it.
pub async fn open(t: &Transport) -> Result<Conn, String> {
    let (tls, exporter) = t.connect().await.map_err(|e| format!("connect: {}", e.message))?;
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(|e| format!("http handshake: {e}"))?;
    tokio::spawn(async move { let _ = conn.await; });
    Ok(Conn { sender, exporter })
}

pub async fn post(
    c: &mut Conn,
    uri: &str,
    host: &str,
    auth: Option<&str>,
    body: serde_json::Value,
) -> Result<(StatusCode, serde_json::Value), String> {
    c.sender.ready().await.map_err(|e| format!("ready: {e}"))?;
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("host", host)
        .header("content-type", "application/json");
    if let Some(tk) = auth {
        req = req.header("authorization", format!("MaxSecu-Session {tk}"));
    }
    let req = req
        .body(Full::new(Bytes::from(body.to_string())))
        .map_err(|e| format!("build req: {e}"))?;
    let resp = c.sender.send_request(req).await.map_err(|e| format!("send: {e}"))?;
    let status = resp.status();
    let bytes = resp.into_body().collect().await.map_err(|e| format!("body: {e}"))?.to_bytes();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    Ok((status, json))
}

pub async fn get(
    c: &mut Conn,
    uri: &str,
    host: &str,
    auth: Option<&str>,
) -> Result<(StatusCode, serde_json::Value), String> {
    c.sender.ready().await.map_err(|e| format!("ready: {e}"))?;
    let mut req = Request::builder().method("GET").uri(uri).header("host", host);
    if let Some(tk) = auth {
        req = req.header("authorization", format!("MaxSecu-Session {tk}"));
    }
    let req = req.body(Full::new(Bytes::new())).map_err(|e| format!("build req: {e}"))?;
    let resp = c.sender.send_request(req).await.map_err(|e| format!("send: {e}"))?;
    let status = resp.status();
    let bytes = resp.into_body().collect().await.map_err(|e| format!("body: {e}"))?.to_bytes();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    Ok((status, json))
}

pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b { s.push_str(&format!("{x:02x}")); }
    s
}

pub fn hex16(s: &str) -> Result<[u8; 16], String> {
    if s.len() != 32 { return Err(format!("bad user_id hex len: {}", s.len())); }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| format!("hex: {e}"))?;
    }
    Ok(out)
}

pub fn b64(bytes: &[u8]) -> String { B64.encode(bytes) }
```

- [ ] **Step 2: In `steps.rs`, add an `enroll` helper that seeds a temp app-dir with a key and enrolls**

Mirror `full_flow_e2e.rs:263-271` (`app_dir_with_key`) and its `register_with_key_exchange` calls.

```rust
use std::path::{Path, PathBuf};

use maxsecu_client_app::commands::register::register_with_key_exchange;
use maxsecu_client_app::keystore;
use maxsecu_client_app::session::login_exchange;
use maxsecu_client_core::Identity;

use crate::net::{self, Conn};

const PASSPHRASE: &str = "live-smoke enrol passphrase battery 9!";
const TS: u64 = 1_719_500_000_000;

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
```

- [ ] **Step 3: Wire a first end-to-end `run()` that enrolls the admin and logs in**

Replace the stub `run` with:

```rust
pub async fn run(server: &str, host: &str, client_dir: &Path) -> Result<(), String> {
    let admin_key = std::fs::read_to_string(client_dir.join("register.key"))
        .map_err(|e| format!("read admin register.key: {e}"))?
        .trim()
        .to_owned();

    let t = net::transport(client_dir, host, server)?;

    // ---- Admin enroll (first registrant → admin) + login ----
    let mut c = net::open(&t).await?;
    let (admin_dir, _admin_uid) = enroll(&mut c, host, "admin", "smokeadmin", &admin_key).await?;
    let mut c2 = net::open(&t).await?; // fresh channel for the channel-bound login
    let (_admin_id, _admin_token) = login(&mut c2, host, &admin_dir, "smokeadmin").await?;
    eprintln!("live-smoke: admin enrolled + logged in");

    let _ = std::fs::remove_dir_all(&admin_dir);
    Ok(())
}
```

- [ ] **Step 4: Compile-check (requires a staged `crates/client-app/recovery_pin.bin`; see Task 2 Step 6)**

Run: `cargo build -p maxsecu-live-smoke --manifest-path crates\client-app\Cargo.toml`
Expected: PASS. If it fails only at `client-app`'s build script for a missing pin, stage a pin first or defer to Task 7.

- [ ] **Step 5: Commit**

```bash
git add tools/live-smoke/src/net.rs tools/live-smoke/src/steps.rs
git commit -m "feat(live-smoke): pinned connection + admin enroll + login"
```

---

## Task 4: `live-smoke` — upload a blog and view it back (owner round-trip)

**Files:**
- Modify: `tools/live-smoke/src/steps.rs`

- [ ] **Step 1: Add the upload helper**

Mirror `full_flow_e2e.rs:364-402`. Add imports at the top of `steps.rs`:

```rust
use maxsecu_client_app::directory::resolve_recovery_pin;
use maxsecu_client_core::{build_upload, UploadParams};
use maxsecu_crypto::EncPublicKey;
use maxsecu_encoding::types::{FileType, Id, Timestamp};
```

Add:

```rust
const BLOG_BODY: &[u8] = b"live-smoke blog body: prove the full upload + view-back round-trips.";

/// Upload a blog as `owner` (already logged in with `token`); returns the file_id.
async fn upload_blog(
    c: &mut Conn,
    host: &str,
    owner: &Identity,
    owner_uid_hex: &str,
    token: &str,
    body: &[u8],
    title: &str,
) -> Result<[u8; 16], String> {
    // The recovery gate: resolve_recovery_pin MATCHES the embedded pin against the
    // server's recovery account (fails closed / trust-alarm A on mismatch).
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
```

- [ ] **Step 2: Add the view-back helper (verify + decrypt the OWNED blog)**

Mirror `browse_view_e2e.rs:550-564` for the `VerifyContext` literal. Add imports:

```rust
use maxsecu_client_app::download::{build_download_bundle, parse_file_view};
use maxsecu_client_core::{verify_and_open, VerifyContext, NO_ADMINS, NO_GRANTERS};
use maxsecu_encoding::types::{RecipientType, StreamType};
use maxsecu_client_app::config::RouteMode;
```

Add:

```rust
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
    };
    let opened = verify_and_open(&ctx, &bundle).map_err(|e| format!("verify_and_open: {e:?}"))?;
    let content = opened
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Content)
        .ok_or("no content stream in opened file")?;
    Ok(content.plaintext.clone())
}
```

> **Implementer note:** `OpenedStream`'s plaintext accessor may be named `plaintext`, `bytes`, or `data` — confirm the field against `crates/client-core/src/download.rs` `pub struct OpenedStream` and adjust the `.plaintext` above. Same for `RouteMode` variant names (`PreferServer` etc.) in `crates/client-app/src/config.rs`. These are the only two names not verified verbatim during planning.

- [ ] **Step 3: Extend `run()` to upload + view-back and assert equality**

After the admin login block in `run()`, before the `remove_dir_all`, insert:

```rust
    // ---- Admin uploads a blog and views it back (full round-trip) ----
    let file_id = upload_blog(&mut c2, host, &_admin_id, &_admin_uid, &_admin_token, BLOG_BODY, "SmokeDiary").await?;
    let got = view_own_blog(&mut c2, host, &_admin_id, &_admin_uid, &_admin_token, file_id).await?;
    if got != BLOG_BODY {
        return Err(format!("view-back mismatch: {} bytes decrypted, expected {}", got.len(), BLOG_BODY.len()));
    }
    eprintln!("live-smoke: admin upload + view-back OK ({} bytes)", got.len());
```

(You will need the admin's `user_id` and `Identity` — change the earlier `let (_admin_id, _admin_token)` binding to keep them, and capture `_admin_uid` from `enroll`'s return: `let (admin_dir, admin_uid) = enroll(...)`.)

- [ ] **Step 4: Compile-check**

Run: `cargo build -p maxsecu-live-smoke --manifest-path crates\client-app\Cargo.toml`
Expected: PASS (after resolving the two flagged accessor names).

- [ ] **Step 5: Commit**

```bash
git add tools/live-smoke/src/steps.rs
git commit -m "feat(live-smoke): upload a blog and verify the view-back round-trip"
```

---

## Task 5: `live-smoke` — admin mints a key, user2 enrolls (role assertion)

**Files:**
- Modify: `tools/live-smoke/src/steps.rs`

- [ ] **Step 1: Add the admin-mint helper**

Mirror `full_flow_e2e.rs:492-501`.

```rust
/// Admin mints a fresh single-use registration key over `c` with `admin_token`.
async fn mint_key(c: &mut Conn, host: &str, admin_token: &str) -> Result<String, String> {
    let (st, res) = net::post(c, "/v1/registration-keys", host, Some(admin_token), serde_json::json!({})).await?;
    if st != hyper::StatusCode::CREATED {
        return Err(format!("mint registration key status {st}"));
    }
    res["registration_key"].as_str().map(|s| s.to_owned()).ok_or("no registration_key in mint response".into())
}
```

- [ ] **Step 2: Add a directory role assertion helper**

Mirror `full_flow_e2e.rs:510-517` + `parse_binding` (`full_flow_e2e.rs:197-200`).

```rust
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use maxsecu_encoding::decode;
use maxsecu_encoding::structs::DirBinding;
use maxsecu_encoding::types::Role;

/// Assert `username`'s published binding has User but NOT Admin (i.e. an ordinary user).
async fn assert_user_not_admin(c: &mut Conn, host: &str, username: &str) -> Result<(), String> {
    let (st, body) = net::get(c, &format!("/v1/directory/{username}"), host, None).await?;
    if st != hyper::StatusCode::OK {
        return Err(format!("directory GET {username} status {st}"));
    }
    let bytes = B64.decode(body["binding_b64"].as_str().ok_or("no binding_b64")?)
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
```

- [ ] **Step 3: Extend `run()` — mint + user2 enroll + role check**

After the admin round-trip block:

```rust
    // ---- Admin mints a key; user2 enrolls with it → User role, not Admin ----
    let minted = mint_key(&mut c2, host, &_admin_token).await?;
    let mut c3 = net::open(&t).await?;
    let (user_dir, user_uid) = enroll(&mut c3, host, "user", "smokeuser", &minted).await?;
    assert_user_not_admin(&mut c3, host, "smokeuser").await?;
    eprintln!("live-smoke: admin-mint + user2 enroll (User role) OK");
```

- [ ] **Step 4: Compile-check**

Run: `cargo build -p maxsecu-live-smoke --manifest-path crates\client-app\Cargo.toml`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tools/live-smoke/src/steps.rs
git commit -m "feat(live-smoke): admin mints a key and user2 enrolls with User role"
```

---

## Task 6: `live-smoke` — cross-user feed visibility + user2 own round-trip

**Files:**
- Modify: `tools/live-smoke/src/steps.rs`

- [ ] **Step 1: Add a feed-visibility helper**

Mirror the internals of `feed::list_feed` (`crates/client-app/src/commands/feed.rs:53-76`): a raw authed `GET /v1/files` and scan for the admin's `file_id`.

```rust
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
```

> **Implementer note:** confirm the feed row's id field name is `file_id` against `entry_from_json` in `crates/client-app/src/commands/feed.rs` (it may be `id`); adjust the JSON key if so.

- [ ] **Step 2: Extend `run()` — user2 login, sees admin's card, does its own round-trip**

```rust
    // ---- user2 logs in, sees the admin's card in the feed (cross-user visibility) ----
    let mut c4 = net::open(&t).await?;
    let (user_id, user_token) = login(&mut c4, host, &user_dir, "smokeuser").await?;
    assert_feed_contains(&mut c4, host, &user_token, &net::hex(&file_id)).await?;
    eprintln!("live-smoke: cross-user feed visibility OK");

    // ---- user2 uploads its OWN blog and views it back (a second independent user works) ----
    const USER_BODY: &[u8] = b"live-smoke user2 post: a second independent account round-trips too.";
    let user_fid = upload_blog(&mut c4, host, &user_id, &user_uid, &user_token, USER_BODY, "User2Diary").await?;
    let got2 = view_own_blog(&mut c4, host, &user_id, &user_uid, &user_token, user_fid).await?;
    if got2 != USER_BODY {
        return Err(format!("user2 view-back mismatch: {} bytes", got2.len()));
    }
    eprintln!("live-smoke: user2 upload + view-back OK ({} bytes)", got2.len());

    let _ = std::fs::remove_dir_all(&user_dir);
```

Ensure `admin_dir`'s `remove_dir_all` stays at the end and `run()` returns `Ok(())`.

- [ ] **Step 3: Compile-check + clippy**

Run: `cargo build -p maxsecu-live-smoke --manifest-path crates\client-app\Cargo.toml`
Then: `cargo clippy -p maxsecu-live-smoke --manifest-path crates\client-app\Cargo.toml`
Expected: PASS, no warnings. (Do NOT run `cargo fmt --all` — see repo gotchas.)

- [ ] **Step 4: Commit**

```bash
git add tools/live-smoke/src/steps.rs
git commit -m "feat(live-smoke): cross-user feed visibility + user2 own upload round-trip"
```

---

## Task 7: `scripts/test-full-install.ps1` — the orchestrator

**Files:**
- Create: `scripts/test-full-install.ps1`

**Params:** `-Port` (default 8443), `-KeepOnFailure` (skip teardown for debugging), `-Iterations` (default 1, back-to-back clean passes).

The orchestrator is phased and fail-fast, with a `try/finally` that guarantees `wsl --unregister` + folder cleanup and a client `-Reset` even on failure (unless `-KeepOnFailure`). Because `Get-Date`-derived unique names are needed, the distro is `maxsecu-test-<yyyyMMddHHmmss>`.

- [ ] **Step 1: Write the script header, params, and helpers**

```powershell
<#
.SYNOPSIS
    Unattended full-install / reinstall E2E test for MaxSecu.
.DESCRIPTION
    Provisions a throwaway WSL Ubuntu-22.04 distro, installs the server via the real
    install-server.sh, builds the client via install-client.ps1, runs the headless
    live-smoke oracle against the live pair, then exercises the reset+reinstall path
    and re-runs the oracle, and finally tears everything down. Fail-fast with a
    try/finally that always unregisters the distro and resets the client.
.PARAMETER Port         Server listen port (default 8443).
.PARAMETER KeepOnFailure  Skip teardown on failure (for debugging).
.PARAMETER Iterations   Number of back-to-back clean passes (default 1).
#>
[CmdletBinding()]
param(
    [int]    $Port = 8443,
    [switch] $KeepOnFailure,
    [int]    $Iterations = 1
)
$ErrorActionPreference = 'Stop'

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Stamp = Get-Date -Format 'yyyyMMddHHmmss'
$Distro = "maxsecu-test-$Stamp"
$WorkDir = Join-Path $env:TEMP "maxsecu-test-$Stamp"
$RootFsCache = Join-Path $env:LOCALAPPDATA 'maxsecu-test\ubuntu-22.04-rootfs.tar.gz'
$RecoveryPw = "livesmoke-recovery-$Stamp!"

function Phase($t) { Write-Host "`n==== $t ====" -ForegroundColor Cyan }
function Die($t)   { Write-Host "FAIL: $t" -ForegroundColor Red; throw $t }

# Run a command inside the distro as the default user; throws on non-zero.
function Wsl($cmd) {
    $out = wsl -d $Distro -- bash -lc $cmd 2>&1
    $code = $LASTEXITCODE
    $out | ForEach-Object { Write-Host "  [wsl] $_" }
    if ($code -ne 0) { Die "wsl command failed ($code): $cmd" }
    return $out
}
```

- [ ] **Step 2: Add the WSL provisioning function**

Downloads the Ubuntu 22.04 cloud rootfs once (cached), imports a fresh distro, enables systemd, and waits for boot. Do NOT export/reuse the dev `Ubuntu-22.04` distro (avoid polluting the test with dev state).

```powershell
function Provision-Wsl {
    Phase "Provision WSL distro $Distro"
    New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
    $installDir = Join-Path $WorkDir 'distro'
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null

    if (-not (Test-Path $RootFsCache)) {
        Write-Host "  Downloading Ubuntu 22.04 rootfs (one-time cache)..."
        New-Item -ItemType Directory -Path (Split-Path $RootFsCache) -Force | Out-Null
        $url = 'https://cloud-images.ubuntu.com/wsl/jammy/current/ubuntu-jammy-wsl-amd64-wsl.rootfs.tar.gz'
        Invoke-WebRequest -Uri $url -OutFile $RootFsCache -UseBasicParsing
    }

    wsl --import $Distro $installDir $RootFsCache --version 2
    if ($LASTEXITCODE -ne 0) { Die "wsl --import failed" }

    # Enable systemd (needed for the maxsecu-server systemd unit + postgresql).
    wsl -d $Distro -- bash -lc "printf '[boot]\nsystemd=true\n' | tee /etc/wsl.conf >/dev/null"
    wsl --terminate $Distro
    Start-Sleep -Seconds 2

    # Wait for systemd to reach running/degraded (degraded is fine — some units may be inactive).
    $ok = $false
    for ($i = 0; $i -lt 60; $i++) {
        $state = (wsl -d $Distro -- bash -lc 'systemctl is-system-running 2>/dev/null') 2>$null
        if ($state -match 'running|degraded') { $ok = $true; break }
        Start-Sleep -Seconds 2
    }
    if (-not $ok) { Die "systemd did not come up in the distro" }
    Write-Host "  distro up (systemd: $state)"
}
```

- [ ] **Step 3: Add source-copy + server-install functions**

Copy the working tree (including uncommitted changes) into the distro's native fs, minus heavy caches, then run the real installer and parse the connection code.

```powershell
function Copy-Source {
    Phase "Copy source into the distro"
    # Stage a clean copy on Windows (exclude caches), then move it into the distro fs.
    $stage = Join-Path $WorkDir 'src'
    $exclude = @('target', 'node_modules', 'dist', '.git', 'webview', 'tmp')
    robocopy $Root $stage /MIR /XD @exclude /NFL /NDL /NJH /NJS /NP | Out-Null
    # robocopy exit codes < 8 are success.
    if ($LASTEXITCODE -ge 8) { Die "robocopy of source failed ($LASTEXITCODE)" }
    $wslStage = (wsl -d $Distro -- wslpath -a ($stage -replace '\\','/')) 2>$null
    Wsl "rm -rf ~/maxsecu && cp -r '$wslStage' ~/maxsecu && chmod +x ~/maxsecu/scripts/*.sh"
}

function Install-Server([string]$mode) {
    Phase "Install server ($mode)"
    if ($mode -eq 'reset') {
        Wsl "cd ~/maxsecu && ./scripts/install-server.sh --reset --port $Port"
        return $null
    }
    $wslIp = (Wsl "hostname -I | awk '{print `$1}'").Trim()
    if (-not $wslIp) { Die "could not determine WSL IP" }
    Write-Host "  WSL IP: $wslIp"
    # Non-interactive: no TTY ⇒ install-server.sh auto-skips the Dropbox prompt.
    $log = Wsl "cd ~/maxsecu && ./scripts/install-server.sh --public $wslIp --port $Port --no-dropbox"
    # Parse the connection code (addr:port#fingerprint) from the summary.
    $code = ($log | Select-String -Pattern '^\s*([0-9.]+:[0-9]+#\S+)\s*$' | Select-Object -First 1).Matches.Groups[1].Value
    if (-not $code) { Die "could not parse the connection code from install-server output" }
    Write-Host "  connection code: $code"
    return $code
}
```

- [ ] **Step 4: Add client-build + smoke-run functions**

```powershell
function Build-Client([string]$code) {
    Phase "Build client"
    & powershell -ExecutionPolicy Bypass -File (Join-Path $Root 'scripts\install-client.ps1') `
        -ConnectionCode $code -RecoveryPassphrase $RecoveryPw
    if ($LASTEXITCODE -ne 0) { Die "install-client.ps1 failed ($LASTEXITCODE)" }
}

function Run-Smoke([string]$code) {
    Phase "Run live-smoke oracle"
    # server = ip:port, host = ip (cert SAN), client-dir = the built admin client.
    $addr = ($code -split '#')[0]
    $ip = ($addr -split ':')[0]
    $clientDir = Join-Path $Root 'dist\MaxSecuClient'
    $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
    & cargo run --release -p maxsecu-live-smoke --manifest-path (Join-Path $Root 'crates\client-app\Cargo.toml') -- `
        --server $addr --host $ip --client-dir $clientDir
    if ($LASTEXITCODE -ne 0) { Die "live-smoke failed ($LASTEXITCODE)" }
}
```

- [ ] **Step 5: Add the teardown function**

```powershell
function Teardown {
    Phase "Teardown"
    try { wsl --terminate $Distro 2>$null } catch {}
    try { wsl --unregister $Distro 2>$null } catch {}
    try {
        & powershell -ExecutionPolicy Bypass -File (Join-Path $Root 'scripts\install-client.ps1') -Reset | Out-Null
    } catch { Write-Host "  client reset warning: $_" -ForegroundColor DarkYellow }
    if (Test-Path $WorkDir) { Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue }
    Write-Host "  teardown complete"
}
```

- [ ] **Step 6: Add the main flow (install → smoke → reset+reinstall → smoke → teardown), honoring `-Iterations`**

```powershell
$failed = $false
try {
    for ($iter = 1; $iter -le $Iterations; $iter++) {
        Phase "PASS $iter of $Iterations"
        Provision-Wsl
        Copy-Source
        $code = Install-Server 'install'
        Build-Client $code
        Run-Smoke $code

        Phase "Reset + reinstall path"
        Install-Server 'reset' | Out-Null
        & powershell -ExecutionPolicy Bypass -File (Join-Path $Root 'scripts\install-client.ps1') -Reset | Out-Null
        $code2 = Install-Server 'install'   # fresh cert ⇒ new fingerprint ⇒ new code
        Build-Client $code2
        Run-Smoke $code2

        Teardown
    }
    Write-Host "`nALL PASSES GREEN ($Iterations)" -ForegroundColor Green
}
catch {
    $failed = $true
    Write-Host "`nHARNESS FAILED: $_" -ForegroundColor Red
    if ($KeepOnFailure) {
        Write-Host "-KeepOnFailure set: leaving distro '$Distro' and '$WorkDir' for debugging." -ForegroundColor Yellow
        Write-Host "  Server logs:  wsl -d $Distro -- journalctl -u maxsecu-server -e" -ForegroundColor Yellow
    } else {
        Teardown
    }
    exit 1
}
```

- [ ] **Step 7: Parser check**

Run: `powershell -NoProfile -Command "$null=[ScriptBlock]::Create((Get-Content -Raw scripts\test-full-install.ps1)); 'parsed ok'"`
Expected: `parsed ok`.

- [ ] **Step 8: FIRST real end-to-end run (the acceptance gate begins here)**

Run: `powershell -ExecutionPolicy Bypass -File scripts\test-full-install.ps1`
Expected: reaches `ALL PASSES GREEN (1)`. **If anything fails or needs a mid-run fix** (installer, source, smoke, or harness), fix it, then discard and re-run from a fresh WSL (`wsl --unregister maxsecu-test-*` first if a distro leaked) until a single run completes install → smoke → reset+reinstall → smoke → teardown with no interruption. See Task 8 for the loop discipline.

- [ ] **Step 9: Commit**

```bash
git add scripts/test-full-install.ps1
git commit -m "feat(harness): unattended full-install/reinstall E2E orchestrator"
```

---

## Task 8: README + the acceptance loop

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Document the harness and the installer change in README**

Add a section (place near the existing install docs) covering:

```markdown
## Full-install E2E test harness

`scripts/test-full-install.ps1` provisions a throwaway WSL Ubuntu-22.04 server,
installs the server (`install-server.sh --public`) and client (`install-client.ps1`)
via their real scripts, runs the headless `maxsecu-live-smoke` oracle against the
live pair, exercises the reset+reinstall path, re-runs the oracle, then unregisters
the distro and resets the client.

    powershell -ExecutionPolicy Bypass -File scripts\test-full-install.ps1
    # options: -Port 8443  -KeepOnFailure  -Iterations 3

Requirements: WSL2 with virtualization enabled; the Rust MSVC + Node toolchains
(the same the normal client install needs). The Ubuntu rootfs is downloaded once
and cached under %LOCALAPPDATA%\maxsecu-test.

What the oracle asserts (the stock single-server surface): admin enroll → blog
upload → view-back → admin mints a key → second user enrolls (User role, not Admin)
→ the second user sees the admin's card in the feed → the second user uploads and
views back its own blog. User-to-user `reshare` is intentionally NOT covered: it
requires an out-of-band sink server that the single-server install does not deploy.

### Non-interactive client install

`install-client.ps1` now accepts `-RecoveryPassphrase <pw>` (or the
`SETUP_RECOVERY_PW` env var). When supplied it skips the interactive passphrase
prompt so the harness (or any automation) can install unattended. The normal
interactive install is unchanged — omit the flag and it prompts without echo.
```

- [ ] **Step 2: THE ACCEPTANCE LOOP (implementation-time gate — not a committed test)**

This is a gate the implementing agent runs, not code. Do not consider the feature done until it passes.

1. From a state with NO leftover test distro (`wsl -l -v` shows none matching `maxsecu-test-*`; unregister any that leaked), run `scripts\test-full-install.ps1` with no args.
2. If it fails or you had to touch ANY file to get further (installer, Rust source, or the harness), commit the fix, then **discard the environment** (`wsl --unregister <leftover>`, delete the temp dir) and run again from scratch.
3. Repeat until ONE run goes install → smoke → reset+reinstall → smoke → teardown with **zero interruptions and zero mid-run fixes**.
4. Then run `scripts\test-full-install.ps1 -Iterations 2` once to confirm back-to-back passes are clean.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs(harness): document the full-install E2E harness + non-interactive client install"
```

---

## Self-Review (completed against the design spec)

- **Orchestrator (`test-full-install.ps1`, committed, phased, fail-fast, try/finally, `-Port`/`-KeepOnFailure`/`-Iterations`)** → Task 7. ✓
- **`tools/live-smoke` headless binary, client workspace, mirrors client-e2e deps, reuses client-core over the pinned transport, exits non-zero on failure** → Tasks 2-6. ✓
- **`install-client.ps1` non-interactive passphrase** → Task 1. ✓
- **`install-server.sh` already non-interactive under non-TTY (Dropbox auto-No); harness greps the connection code** → used in Task 7 Step 3; no server-script change needed (confirmed: lines 407-411 auto-skip Dropbox with no TTY). ✓
- **Provision (unique distro, cached rootfs, `wsl --import`, wsl.conf systemd, wait for `systemctl is-system-running`)** → Task 7 Step 2. ✓
- **Server install (copy tree incl. uncommitted, minus target/node_modules/dist; discover WSL IP; `--public <ip>`; parse code)** → Task 7 Steps 3. ✓
- **Client build (`install-client.ps1 -ConnectionCode -RecoveryPassphrase`)** → Task 7 Step 4. ✓
- **Headless smoke unit checks (admin enroll→upload→view; mint+user2; user2 views)** → Tasks 4-6, adapted per the recorded decision (feed-visibility + user2 own round-trip replace the sink-dependent reshare). ✓
- **Reinstall path (`--reset` → `--public` again → `-Reset` → rebuild → re-smoke)** → Task 7 Step 6. ✓
- **Teardown (`wsl --unregister`, client `-Reset`, delete temp) even on failure unless `-KeepOnFailure`** → Task 7 Steps 5-6. ✓
- **Addressing (bind 0.0.0.0, dial WSL IP, IP-SAN pinned cert)** → net.rs ServerName=IP + install `--public <ip>`. ✓
- **Errors (per-phase logs, timeboxed waits, `journalctl` hint)** → Task 7 helpers + `-KeepOnFailure` message. ✓
- **Acceptance loop + `-Iterations`** → Task 8 Step 2 + Task 7 param. ✓

**Two names to confirm at implementation time** (flagged inline, both in known reference files, neither is a placeholder): `OpenedStream`'s plaintext field and the `RouteMode` variant (Task 4 Step 2), and the feed row id key (Task 6 Step 1).
