# Tor Login Connection — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Tasks A1–A4 (Track A, Rust transport) and B1 (Track B, frontend) touch disjoint files and may run as two parallel agents. Task 0/3/5/6 are operator-driven and sequential.

**Goal:** Make the MaxSecu client log in over Tor to the self-hosted server on `176.63.161.224:8443`, and turn the "stuck on the login page" hang into a bounded, diagnosable, visible flow.

**Architecture:** Clearnet-over-Tor (client dials the server's clearnet `host:port` through a Tor exit relay; no onion service, no server-side Tor). Two code defects are fixed: (1) the Tor path (bootstrap/dial/TLS handshake) has no timeout, so any stall hangs `connect()` forever — we add a small `with_deadline` wrapper at each hang point; (2) the login screen never subscribes to `EVT_CONNECTION`, so progress is invisible — we wire it to show live transport status. A new env-gated headless smoke drives the real challenge→proof login over a Tor circuit against the running server, giving an automatable reproduction/repair harness.

**Tech Stack:** Rust (arti-client / tokio / tokio-rustls / hyper), TypeScript custom-element UI (Tauri event bus + vitest), WSL2 Ubuntu server, Windows `netsh` portproxy.

---

## File Structure

**Track A — Rust transport (client-app workspace):**
- Create `crates/client-app/src/timeout.rs` — `with_deadline` helper + the three duration constants + unit tests. One responsibility: bounding a connect-path future.
- Modify `crates/client-app/src/lib.rs` — declare `mod timeout;`.
- Modify `crates/client-app/src/tor.rs` — wrap bootstrap + dial in `with_deadline`.
- Modify `crates/client-app/src/transport.rs` — wrap the TLS handshake in `with_deadline` (via a test-injectable inner fn) + a timeout test.
- Create `crates/client-e2e/tests/tor_login_e2e.rs` — the live headless Tor login smoke.

**Track B — Frontend:**
- Create `crates/client-app/ui/src/core/connection-status.ts` — pure state→text mapping (no DOM side effects, so it's unit-testable in isolation).
- Create `crates/client-app/ui/src/core/connection-status.test.ts` — vitest unit tests for the mapping.
- Modify `crates/client-app/ui/src/components/connect-screen.ts` — subscribe to `EVT_CONNECTION`, render live status while busy, clean up on disconnect.

**Operator-driven (no code):** Task 0 (environment bring-up + reachability gate), Task 3 (diagnose/fix), Task 5 (GUI confirm), Task 6 (CI gate).

---

## Task 0: Environment bring-up + reachability gate (operator runbook — driver: me, not TDD)

**Goal:** Stand up a publicly-reachable server bound `0.0.0.0:8443` with a cert carrying `176.63.161.224` as an IP-SAN, bridge Windows:8443 → WSL:8443, enroll a throwaway identity, and PROVE external reachability before any Tor code runs. **STOP if the reachability gate fails** — no code change helps an unreachable port.

- [ ] **Step 1: Find the WSL server IP and networking mode**

```bash
wsl.exe -d Ubuntu-22.04 -- bash -lc "hostname -I | awk '{print \$1}'"   # WSL eth0 IP
cat "$USERPROFILE/.wslconfig" 2>/dev/null | grep -i networkingMode || echo "NAT (default)"
```
Expected: an IP like `172.31.x.x`. If `networkingMode=mirrored`, a WSL server on `0.0.0.0:8443` is already reachable on the Windows host IP and Steps 3–4 (portproxy) are skipped.

- [ ] **Step 2: Run the server bound public with a public-IP-SAN cert (Dev profile)**

Use the `portable-server` binary. Delete any stale cert first so the IP-SAN regenerates, then run with the bind/public-addr env contract (`MAXSECU_BIND`, `MAXSECU_PORT`, `MAXSECU_PUBLIC_ADDR`). Dev profile keeps enrollment OPEN (self-gen D5) so the smoke can enroll without the delegation ceremony. Exact binary path/flags are read from `portable-server --help` / `scripts/install-server.sh` at run time; the env contract is fixed:

```bash
# in WSL, in the server data dir:
rm -f <data_dir>/tls/cert.der <data_dir>/tls/key.der
MAXSECU_BIND=0.0.0.0 MAXSECU_PORT=8443 MAXSECU_PUBLIC_ADDR=176.63.161.224 \
  <portable-server-run-command>   # Dev profile
```
Verify: `wsl.exe -d Ubuntu-22.04 -- bash -lc "ss -ltnp | grep 8443"` shows `0.0.0.0:8443`.

- [ ] **Step 3: Bridge Windows:8443 → WSL:8443 (NAT mode only; needs admin/UAC)**

Run BOTH elevated commands in a SINGLE `Start-Process -Verb RunAs -Wait` so the user sees **one** UAC prompt, not three. **The invoking tool call MUST use the maximum timeout (600000 ms / 10 min) with `-Wait`** — the user may take a while to click the UAC consent, and the call must not time out while the dialog is open (user guidance, [[uac-prompt-no-timeout]]).

```powershell
$wsl = (wsl.exe -d Ubuntu-22.04 -- bash -lc "hostname -I | awk '{print `$1}'").Trim()
Start-Process powershell -Verb RunAs -Wait -ArgumentList @(
  "-NoProfile","-Command",
  "netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8443 connectaddress=$wsl connectport=8443; " +
  "netsh advfirewall firewall add rule name='MaxSecu 8443' dir=in action=allow protocol=TCP localport=8443"
)
netsh interface portproxy show all   # verify (non-elevated read is fine)
```
Expected: exactly one UAC prompt (wait for the click), then the portproxy rule listed.

- [ ] **Step 4: Enroll a throwaway identity + capture the reg key and pinned cert**

Mint/register a registration key (via `maxsecu-setup` / the server's reg-key path) and copy the server's `server_cert.der` (pinned cert) to a known path for the smoke. Record: `MAXSECU_TOR_LIVE_SERVER=176.63.161.224:8443`, `MAXSECU_TOR_LIVE_CERT=<path to server_cert.der>`, `MAXSECU_TOR_LIVE_REGKEY=<reg key>`.

- [ ] **Step 5: Reachability gate — local, then external (STOP-if-fail)**

```bash
# Local: server answers on WSL loopback (proves the server is up)
wsl.exe -d Ubuntu-22.04 -- bash -lc "curl -k --max-time 5 https://127.0.0.1:8443/v1/bootstrap/pins -o /dev/null -w '%{http_code}\n' || echo DOWN"
# Windows->WSL bridge: Windows can reach the server through the portproxy
curl -k --max-time 5 https://192.168.0.10:8443/v1/bootstrap/pins -o /dev/null -w '%{http_code}\n'
```
External reachability is proven by the Tor smoke itself (Task A4) — a Tor exit is a genuinely external vantage. If the local checks pass but the smoke can't reach the server, the gap is router/ISP inbound (fix the network, do not proceed to code diagnosis of the client).

Expected: HTTP `200`/`404` (a response = reachable). Connection refused/timeout = a broken link in the chain — fix before continuing.

---

## Task A1: `with_deadline` timeout helper (Track A)

**Files:**
- Create: `crates/client-app/src/timeout.rs`
- Modify: `crates/client-app/src/lib.rs` (add `mod timeout;` at line 28)
- Test: inline `#[cfg(test)] mod tests` in `timeout.rs`

- [ ] **Step 1: Write `timeout.rs` with the helper and its failing tests**

```rust
//! A tiny timeout wrapper for the connect path. arti's bootstrap, the Tor dial,
//! and the TLS handshake have no natural short timeout of their own — a slow or
//! exit-policy-blocked circuit would otherwise hang `connect()` forever and leave
//! the login screen on a dead spinner. `with_deadline` bounds each so a stall
//! surfaces as a prompt, sanitized `UiError` instead.

use std::future::Future;
use std::time::Duration;

use crate::error::UiError;

/// Max time to bootstrap the shared Tor client (cold consensus fetch). Generous:
/// a first arti bootstrap genuinely can take 30–60s.
pub(crate) const TOR_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(60);
/// Max time to open a Tor circuit stream to the server once bootstrapped.
pub(crate) const TOR_DIAL_TIMEOUT: Duration = Duration::from_secs(30);
/// Max time for the pinned TLS 1.3 handshake over an already-dialed stream.
pub(crate) const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Await `fut` but give up after `dur`, returning `on_timeout` if it elapses.
/// `fut` already yields the domain `Result<T, UiError>`; a timeout replaces it
/// with the caller's sanitized timeout error so the UI shows a clear message.
pub(crate) async fn with_deadline<T>(
    dur: Duration,
    fut: impl Future<Output = Result<T, UiError>>,
    on_timeout: UiError,
) -> Result<T, UiError> {
    match tokio::time::timeout(dur, fut).await {
        Ok(res) => res,
        Err(_) => Err(on_timeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn returns_the_inner_value_when_it_resolves_in_time() {
        let out = with_deadline(
            Duration::from_secs(5),
            async { Ok::<u32, UiError>(7) },
            UiError::new("tor_timeout", "should not fire"),
        )
        .await;
        assert_eq!(out.unwrap(), 7);
    }

    #[tokio::test]
    async fn returns_the_timeout_error_when_the_future_stalls() {
        let out = with_deadline::<u32>(
            Duration::from_millis(20),
            std::future::pending(),
            UiError::new("tor_timeout", "Connecting to the Tor network timed out."),
        )
        .await;
        let err = out.expect_err("a pending future must time out");
        assert_eq!(err.code, "tor_timeout");
    }

    #[tokio::test]
    async fn propagates_an_inner_error_unchanged() {
        let out = with_deadline::<u32>(
            Duration::from_secs(5),
            async { Err(UiError::new("offline", "inner")) },
            UiError::new("tor_timeout", "should not fire"),
        )
        .await;
        assert_eq!(out.unwrap_err().code, "offline");
    }
}
```

In `crates/client-app/src/lib.rs`, after the line `pub mod thumb_cache;` (line 28), add:
```rust
mod timeout;
```

- [ ] **Step 2: Run the tests to verify they pass**

Run: `cargo test --manifest-path crates/client-app/Cargo.toml -p maxsecu-client-app timeout::`
Expected: 3 tests pass (`returns_the_inner_value_...`, `returns_the_timeout_error_...`, `propagates_an_inner_error_...`). The stalled-future test completes in ~20ms.

- [ ] **Step 3: Commit**

```bash
git add crates/client-app/src/timeout.rs crates/client-app/src/lib.rs
git commit -m "feat(client-tor): add with_deadline timeout helper for the connect path"
```

---

## Task A2: Bound the Tor bootstrap + dial (Track A)

**Files:**
- Modify: `crates/client-app/src/tor.rs:69-89` (bootstrap in `client`) and `:94-106` (`dial`)

- [ ] **Step 1: Wrap the bootstrap in `client()`**

Replace the body of `client` (`tor.rs:69-89`) so the `create_bootstrapped` call is bounded:

```rust
    pub async fn client(
        &self,
        on_bootstrap: impl FnOnce() + Send,
    ) -> Result<Arc<TorClient<PreferredRuntime>>, UiError> {
        let client = self
            .cell
            .get_or_try_init(|| async {
                on_bootstrap();
                let cache_dir = self.state_dir.join("cache");
                let cfg = TorClientConfigBuilder::from_directories(&self.state_dir, &cache_dir)
                    .build()
                    .map_err(|_| {
                        UiError::new("tor_unavailable", "Tor configuration is invalid.")
                    })?;
                crate::timeout::with_deadline(
                    crate::timeout::TOR_BOOTSTRAP_TIMEOUT,
                    async {
                        TorClient::create_bootstrapped(cfg).await.map_err(|_| {
                            UiError::new("tor_unavailable", "Could not connect to the Tor network.")
                        })
                    },
                    UiError::new("tor_timeout", "Connecting to the Tor network timed out."),
                )
                .await
            })
            .await?;
        Ok(client.clone())
    }
```

- [ ] **Step 2: Wrap the dial in `dial()`**

Replace the body of `dial` (`tor.rs:94-106`):

```rust
    pub async fn dial(
        &self,
        host: &str,
        port: u16,
        on_bootstrap: impl FnOnce() + Send,
    ) -> Result<BoxedStream, UiError> {
        let client = self.client(on_bootstrap).await?;
        let stream = crate::timeout::with_deadline(
            crate::timeout::TOR_DIAL_TIMEOUT,
            async {
                client
                    .connect((host, port))
                    .await
                    .map_err(|_| UiError::new("offline", "Could not reach the server over Tor."))
            },
            UiError::new("tor_timeout", "Reaching the server over Tor timed out."),
        )
        .await?;
        Ok(Box::new(stream) as BoxedStream)
    }
```

- [ ] **Step 3: Build and run the client-app tests to verify no regression**

Run: `cargo test --manifest-path crates/client-app/Cargo.toml -p maxsecu-client-app`
Expected: the crate compiles and all existing tests pass. (The timeout *mechanism* is covered by A1; real Tor bootstrap/dial timeouts are exercised by the live smoke in A4 — no network-dependent unit test is added here.)

- [ ] **Step 4: Commit**

```bash
git add crates/client-app/src/tor.rs
git commit -m "fix(client-tor): bound Tor bootstrap + dial so a blocked circuit errors instead of hanging"
```

---

## Task A3: Bound the TLS handshake (Track A)

**Files:**
- Modify: `crates/client-app/src/transport.rs:27-49` (`tls_over`) + tests block

- [ ] **Step 1: Write the failing timeout test**

Add to the `#[cfg(test)] mod tests` block in `transport.rs` (and add `use std::time::Duration;` near the top imports if not present — it is not, so add it):

```rust
    #[tokio::test]
    async fn tls_handshake_times_out_on_a_silent_peer() {
        // A duplex whose far end never responds: rustls waits for the ServerHello
        // forever. `_server_end` is kept alive (no EOF) so the ONLY way the future
        // completes is the deadline — proving the handshake is bounded.
        let (client_end, _server_end) = tokio::io::duplex(1024);
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let cfg = pinned_client_config(cert_der).unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        let err = tls_over_within(Duration::from_millis(80), cfg, name, Box::new(client_end))
            .await
            .expect_err("silent peer must time out");
        assert_eq!(err.code, "tls");
    }
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --manifest-path crates/client-app/Cargo.toml -p maxsecu-client-app tls_handshake_times_out`
Expected: FAIL to compile — `tls_over_within` does not exist yet.

- [ ] **Step 3: Refactor `tls_over` to delegate to a test-injectable inner fn**

At the top of `transport.rs`, add:
```rust
use std::time::Duration;
```
Replace `tls_over` (`transport.rs:27-49`) with a thin wrapper + a duration-parameterized inner fn:

```rust
pub async fn tls_over(
    tls: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    stream: BoxedStream,
) -> Result<
    (
        tokio_rustls::client::TlsStream<BoxedStream>,
        [u8; EXPORTER_LEN],
    ),
    UiError,
> {
    tls_over_within(
        crate::timeout::TLS_HANDSHAKE_TIMEOUT,
        tls,
        server_name,
        stream,
    )
    .await
}

/// Same as [`tls_over`], with the handshake deadline injected so tests can assert
/// the timeout without a real 15s wait. The pinned TLS 1.3 handshake is bounded by
/// `dur`; on expiry we return the sanitized `tls` timeout error.
async fn tls_over_within(
    dur: Duration,
    tls: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    stream: BoxedStream,
) -> Result<
    (
        tokio_rustls::client::TlsStream<BoxedStream>,
        [u8; EXPORTER_LEN],
    ),
    UiError,
> {
    let connector = TlsConnector::from(tls);
    let tls = crate::timeout::with_deadline(
        dur,
        async {
            connector
                .connect(server_name, stream)
                .await
                .map_err(|_| UiError::new("tls", "Secure connection failed."))
        },
        UiError::new("tls", "Secure connection timed out."),
    )
    .await?;
    let mut exporter = [0u8; EXPORTER_LEN];
    tls.get_ref()
        .1
        .export_keying_material(&mut exporter, EXPORTER_LABEL, None)
        .map_err(|_| UiError::new("tls", "Channel binding failed."))?;
    Ok((tls, exporter))
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --manifest-path crates/client-app/Cargo.toml -p maxsecu-client-app tls_handshake_times_out`
Expected: PASS in ~80ms.

- [ ] **Step 5: Run the whole client-app test suite (no regression)**

Run: `cargo test --manifest-path crates/client-app/Cargo.toml -p maxsecu-client-app`
Expected: all pass, including the existing `exporter_params_are_pinned_...` and `pinned_client_config_accepts_...`.

- [ ] **Step 6: Commit**

```bash
git add crates/client-app/src/transport.rs
git commit -m "fix(client-tor): bound the pinned TLS handshake so a silent peer errors instead of hanging"
```

---

## Task A4: Live headless Tor login smoke (Track A)

**Files:**
- Create: `crates/client-e2e/tests/tor_login_e2e.rs`

- [ ] **Step 1: Write the smoke test**

```rust
//! LIVE end-to-end Tor LOGIN smoke (opt-in, real network + a real running server).
//!
//! Unlike `tor_route_e2e` (which only proves a Tor circuit opens to a public host),
//! this drives the FULL production login — register + channel-bound challenge→proof
//! — over a Tor circuit against a REAL MaxSecu server reachable at its clearnet
//! address. It is the automated reproduction/repair harness for "stuck on the login
//! page over Tor". `#[ignore]` + env-gated so it never runs in CI or a plain test.
//!
//! Run against the port-forwarded server (from the client-app workspace):
//! ```text
//! MAXSECU_TOR_LIVE=1 \
//! MAXSECU_TOR_LIVE_SERVER=176.63.161.224:8443 \
//! MAXSECU_TOR_LIVE_CERT=/path/to/server_cert.der \
//! MAXSECU_TOR_LIVE_REGKEY=<registration-key> \
//! cargo test --manifest-path crates/client-app/Cargo.toml -p maxsecu-client-e2e \
//!   --test tor_login_e2e -- --ignored --nocapture
//! ```

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::ClientConfig;

use maxsecu_client_app::session::login_exchange;
use maxsecu_client_app::tor::TorState;
use maxsecu_client_app::transport::{pinned_client_config, tls_over};
use maxsecu_client_core::Identity;

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Open a fresh Tor circuit → pinned TLS → hyper http1 connection to the server,
/// returning the request sender and this connection's RFC 5705 exporter.
async fn open_tor_conn(
    tor: &TorState,
    host: &str,
    port: u16,
    tls_cfg: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    announce_bootstrap: bool,
) -> (SendRequest<Full<Bytes>>, [u8; 32]) {
    let boxed = tor
        .dial(host, port, move || {
            if announce_bootstrap {
                eprintln!("bootstrapping Tor (first connect can take up to a minute)…");
            }
        })
        .await
        .expect("dial the server over a Tor circuit");
    let (tls, exporter) = tls_over(tls_cfg, server_name, boxed)
        .await
        .expect("pinned TLS 1.3 over the Tor circuit");
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .expect("http1 handshake over Tor");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    (sender, exporter)
}

/// POST a JSON body and return only the status (draining the body).
async fn post_status(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    uri: &str,
    body: serde_json::Value,
) -> StatusCode {
    sender.ready().await.unwrap();
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("host", host)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let _ = resp.into_body().collect().await;
    status
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live Tor + real server; run with MAXSECU_TOR_LIVE=1 and SERVER/CERT/REGKEY env"]
async fn tor_login_against_the_real_server() {
    if env("MAXSECU_TOR_LIVE").as_deref() != Some("1") {
        eprintln!("skipping: set MAXSECU_TOR_LIVE=1 to run the live Tor login test");
        return;
    }
    let server = env("MAXSECU_TOR_LIVE_SERVER").expect("set MAXSECU_TOR_LIVE_SERVER=host:port");
    let cert_path =
        env("MAXSECU_TOR_LIVE_CERT").expect("set MAXSECU_TOR_LIVE_CERT=/path/server_cert.der");
    let reg_key = env("MAXSECU_TOR_LIVE_REGKEY").expect("set MAXSECU_TOR_LIVE_REGKEY=<reg key>");

    let (host, port_s) = server.rsplit_once(':').expect("SERVER must be host:port");
    let host = host.to_owned();
    let port: u16 = port_s.parse().expect("port must be a number");

    let cert_bytes = std::fs::read(&cert_path).expect("read the pinned server_cert.der");
    let tls_cfg = pinned_client_config(CertificateDer::from(cert_bytes)).expect("pin the cert");
    // Host is an IP literal here -> rustls uses an IP ServerName and matches the
    // cert's IP-SAN (176.63.161.224 must be a SAN — set MAXSECU_PUBLIC_ADDR at
    // cert generation, Task 0 Step 2).
    let server_name = ServerName::try_from(host.clone()).expect("server name from host");

    // Arti state under a throwaway dir so the run leaves nothing behind.
    let tmp = std::env::temp_dir().join(format!("mxtor-login-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let tor = TorState::new(tmp.clone());

    // 1) Enroll a throwaway identity over a first Tor connection. Registration is
    //    reg-key-gated (not channel-bound), so any connection works. Mirrors the
    //    direct connect_login_e2e::register — classical binding is fine; login does
    //    not need the ML-KEM key.
    let id = Identity::generate();
    let username = format!("tor-smoke-{}", now_ms());
    let (mut reg, _exp) = open_tor_conn(
        &tor,
        &host,
        port,
        tls_cfg.clone(),
        server_name.clone(),
        true,
    )
    .await;
    let st = post_status(
        &mut reg,
        &host,
        "/v1/users",
        serde_json::json!({
            "username": username,
            "enc_pub_b64": B64.encode(id.enc_pub_bytes()),
            "sig_pub_b64": B64.encode(id.sig_pub_bytes()),
            "registration_key": reg_key,
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "registration over Tor should 201");

    // 2) Fresh Tor connection: full channel-bound login through the production code.
    let (mut sender, exporter) =
        open_tor_conn(&tor, &host, port, tls_cfg, server_name, false).await;
    let login = login_exchange(&mut sender, &id, &username, &host, &exporter, now_ms())
        .await
        .expect("login over the Tor-bound channel");

    assert!(
        !login.token.is_empty(),
        "server minted a session token over Tor"
    );
    eprintln!(
        "OK: logged in over Tor as {username}, server_id={}",
        login.server_id
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
```

- [ ] **Step 2: Confirm it compiles and is skipped by default**

Run: `cargo test --manifest-path crates/client-app/Cargo.toml -p maxsecu-client-e2e --test tor_login_e2e`
Expected: compiles; the test is listed as `ignored` (0 run). This keeps CI/plain-test green.

- [ ] **Step 3: Commit**

```bash
git add crates/client-e2e/tests/tor_login_e2e.rs
git commit -m "test(client-e2e): live headless Tor login smoke against a real server (env-gated)"
```

> **Note:** actually RUNNING this against the live server happens in Task 3, after Task 0 stands up the environment.

---

## Task B1: Live login progress on the connect screen (Track B)

**Files:**
- Create: `crates/client-app/ui/src/core/connection-status.ts`
- Create: `crates/client-app/ui/src/core/connection-status.test.ts`
- Modify: `crates/client-app/ui/src/components/connect-screen.ts`

- [ ] **Step 1: Write the failing mapping test**

Create `crates/client-app/ui/src/core/connection-status.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { connectionStatusText } from "./connection-status.ts";

describe("connectionStatusText", () => {
  it("gives the Tor bootstrap state an expectation-setting line", () => {
    expect(connectionStatusText("tor-bootstrapping")).toMatch(/Tor/i);
  });

  it("maps every known transport state to a non-empty message", () => {
    for (const s of ["resolving", "tor-bootstrapping", "tls-handshake", "channel-binding", "connected"]) {
      expect(connectionStatusText(s).length).toBeGreaterThan(0);
    }
  });

  it("falls back to the generic transport message for unknown states", () => {
    expect(connectionStatusText("idle")).toBe("Opening encrypted transport…");
    expect(connectionStatusText("whatever")).toBe("Opening encrypted transport…");
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

Run (from `crates/client-app/ui`): `npx vitest run src/core/connection-status.test.ts`
Expected: FAIL — cannot resolve `./connection-status.ts`.

- [ ] **Step 3: Implement the pure mapping module**

Create `crates/client-app/ui/src/core/connection-status.ts`:

```ts
// Maps a backend ConnectionState (EVT_CONNECTION, kebab-case `state`) to a short
// human line for the connect screen. Pure + DOM-free so it unit-tests in isolation
// (no customElements side effects). The `tor-bootstrapping` line sets the "this can
// take a moment" expectation that the old static spinner failed to convey.
export function connectionStatusText(state: string): string {
  switch (state) {
    case "resolving":
      return "Resolving server…";
    case "tor-bootstrapping":
      return "Bootstrapping Tor (first connect can take up to a minute)…";
    case "tls-handshake":
      return "Securing connection…";
    case "channel-binding":
      return "Binding secure channel…";
    case "connected":
      return "Connected. Authenticating…";
    default:
      return "Opening encrypted transport…";
  }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run (from `crates/client-app/ui`): `npx vitest run src/core/connection-status.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Wire the connect screen to the event**

In `crates/client-app/ui/src/components/connect-screen.ts`:

(a) Update the imports at the top:
```ts
import { call, on } from "../core/rpc.ts";
import { setUsername } from "../core/session.ts";
import { connectionStatusText } from "../core/connection-status.ts";
import type { ConnState, Settings } from "../core/types.ts";
```

(b) Add an unlisten field + cleanup to the class. Immediately after the class declaration line `export class ConnectScreen extends HTMLElement {`, add:
```ts
  private unlistenConn?: () => void;

  disconnectedCallback() {
    this.unlistenConn?.();
  }
```

(c) Track busy state and reflect live progress. Replace the `setBusy` definition (currently `connect-screen.ts:71-78`) with a version that records `busy`, and subscribe after it:
```ts
    let busy = false;
    const setBusy = (b: boolean, msg: string) => {
      busy = b;
      f.toggleAttribute("aria-busy", b);
      stage.classList.toggle("is-loading", b);
      f.classList.toggle("is-loading", b);
      status.textContent = msg;
      submitLabel.textContent = b ? "Handshake running" : "Connect securely";
      controls.forEach((el) => { el.disabled = b; });
    };

    // Live transport progress: the `connect` backend emits ConnectionState over
    // EVT_CONNECTION (notably the slow first Tor bootstrap). We only override the
    // status line WHILE the form is busy, so idle/disconnected transitions don't
    // stomp the resting message. Without this a Tor stall read as a dead spinner.
    on<ConnState>("maxsecu://connection-state", (s) => {
      if (busy) status.textContent = connectionStatusText(s.state);
    })
      .then((cl) => { this.unlistenConn = cl; })
      .catch(() => { /* progress is best-effort; login still works without it */ });
```

(The submit handler already calls `setBusy(true, …)` / `setBusy(false, …)` and sets its own status strings between awaits; those remain and interleave with the live event updates — both write the same `status` element.)

- [ ] **Step 6: Type-check + run the full UI test suite**

Run (from `crates/client-app/ui`): `npx vitest run` and the project's type-check (e.g. `npx tsc --noEmit` or the configured `npm run check`).
Expected: all vitest tests pass (including the new mapping tests); no TypeScript errors from the new imports/usage.

- [ ] **Step 7: Commit**

```bash
git add crates/client-app/ui/src/core/connection-status.ts \
        crates/client-app/ui/src/core/connection-status.test.ts \
        crates/client-app/ui/src/components/connect-screen.ts
git commit -m "feat(client-ui): show live Tor/TLS progress on the connect screen"
```

---

## Task 3: Run the smoke, diagnose, fix (operator — driver: me, systematic-debugging)

**Goal:** With Task 0's environment up and Track A merged, run the live smoke over Tor and drive it to green.

- [ ] **Step 1: Run the live Tor login smoke**

```bash
MAXSECU_TOR_LIVE=1 \
MAXSECU_TOR_LIVE_SERVER=176.63.161.224:8443 \
MAXSECU_TOR_LIVE_CERT=<path>/server_cert.der \
MAXSECU_TOR_LIVE_REGKEY=<reg key> \
cargo test --manifest-path crates/client-app/Cargo.toml -p maxsecu-client-e2e \
  --test tor_login_e2e -- --ignored --nocapture
```
Expected on success: `OK: logged in over Tor as tor-smoke-…`.

- [ ] **Step 2: If it fails, diagnose from the now-bounded error (invoke systematic-debugging)**

The timeout work means failures are prompt and typed, not hangs. Map the sanitized code to the cause:
- `tor_unavailable` / `tor_timeout` on bootstrap → Tor network not reachable from this host (local firewall/AV blocking arti). 
- `tor_timeout` on dial → the exit relay could not reach `176.63.161.224:8443` → verify external inbound reachability (router forward, ISP inbound, portproxy, server bound `0.0.0.0`). Cross-check server logs: `journalctl`/stderr `listening on … 0.0.0.0:8443`, `ss -ltnp | grep 8443`.
- `tls` → cert SAN mismatch (the pinned cert lacks the `176.63.161.224` IP-SAN — regenerate per Task 0 Step 2) or wrong pinned cert.
- register `!= 201` → enrollment closed (use the Dev profile / install a delegation) or a bad reg key.

Apply the fix at the correct layer (network for reachability, cert for SAN, server config for enrollment), then re-run Step 1 until green.

---

## Task 5: GUI confirmation (operator — driver: user)

- [ ] **Step 1: Build/launch the real client app and log in over Tor**

The user runs the Tauri client, enters `176.63.161.224:8443` as the server, ticks "Route through Tor", and signs in.
Expected: the status line now shows live progress ("Bootstrapping Tor…", "Securing connection…", "Connected. Authenticating…"), and the app reaches `#/feed`. A forced failure (e.g. server down) now surfaces a prompt error instead of an endless spinner.

---

## Task 6: Verify + CI gate + finalize (operator — driver: me)

- [ ] **Step 1: Full local CI gate (per project pre-push discipline)**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
# Root workspace (server etc.)
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
# Client-app workspace (its own lockfile; excluded from root CI, must still be green)
cargo fmt --manifest-path crates/client-app/Cargo.toml --all -- --check
cargo clippy --manifest-path crates/client-app/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path crates/client-app/Cargo.toml
```
Expected: all green. Fix any rustfmt drift per-package with `cargo fmt -p <crate>` (never the blanket write form). The live Tor test stays `ignored` (not run here).

- [ ] **Step 2: UI checks**

Run (from `crates/client-app/ui`): `npx vitest run` and the configured type-check/lint.
Expected: green.

- [ ] **Step 3: Finalize the branch**

Invoke superpowers:finishing-a-development-branch to decide merge/PR. Do not push until the full gate above is green (memory: [[ci-check-before-push]]).

---

## Self-Review (checklist)

**Spec coverage:**
- Root cause 1 (no Tor-path timeout) → Tasks A1/A2/A3. ✅
- Root cause 2 (UI not subscribed to EVT_CONNECTION) → Task B1. ✅
- Reachability chain (bind/SAN/portproxy/firewall/forward) → Task 0. ✅
- Headless Tor login smoke → Task A4; run/diagnose → Task 3. ✅
- GUI confirmation → Task 5. ✅
- CI gate → Task 6. ✅
- Success criteria (bounded error, live progress, real login, green gate) → A1–A3 / B1 / A4+Task3 / Task6. ✅

**Placeholder scan:** Task 0 Steps 2 & 4 defer the exact `portable-server` run command and reg-key mint to execution time — inherent to an interactive ops task on a running server, not a code placeholder. All TDD code tasks (A1–A4, B1) carry complete code. ✅

**Type consistency:** `with_deadline(dur, fut, on_timeout)` signature and `crate::timeout::{TOR_BOOTSTRAP_TIMEOUT, TOR_DIAL_TIMEOUT, TLS_HANDSHAKE_TIMEOUT}` are used identically in A2/A3. `tls_over` keeps its public signature; `tls_over_within(dur, …)` is the injectable inner. `connectionStatusText(state: string): string` matches its import/use in B1. `ConnState { state }`, `on<T>(event, cb): Promise<() => void>`, and `EVT_CONNECTION = "maxsecu://connection-state"` match the existing code. ✅
