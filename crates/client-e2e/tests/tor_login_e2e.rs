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
