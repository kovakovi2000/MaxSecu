//! The `connect` command: the full authenticated connect flow on ONE TLS
//! connection. It pins the server cert, handshakes TLS 1.3, derives the RFC 5705
//! exporter, then runs challenge→proof over that SAME connection (the exporter is
//! per-connection — reconnecting between the two would break channel binding) and
//! returns the server's REAL `server_id`. It never fabricates an id.

use hyper_util::rt::TokioIo;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};

use crate::dto::{ConnectRequest, ConnectResponse};
use crate::error::UiError;
use crate::session;
use crate::state::{AuthState, ConnectionState, EVT_AUTH, EVT_CONNECTION};
use crate::transport::{self, Transport};

use super::auth::{AppDir, ConnectLock, Session};

#[tauri::command]
pub async fn connect(
    req: ConnectRequest,
    app: tauri::AppHandle,
    dir: tauri::State<'_, AppDir>,
    session: tauri::State<'_, Session>,
    connect_lock: tauri::State<'_, ConnectLock>,
) -> Result<ConnectResponse, UiError> {
    use tauri::Emitter;
    let emit_conn = |s: ConnectionState| {
        let _ = app.emit(EVT_CONNECTION, s);
    };
    let emit_auth = |s: AuthState| {
        let _ = app.emit(EVT_AUTH, s);
    };

    // Re-entrancy guard: only one connect runs at a time. Held for the whole
    // command (across awaits, which is exactly what serializes connects). Without
    // it, a concurrent connect would race the take/restore of the Session
    // identity and could clobber the winner's terminal state. Take this BEFORE
    // emitting any state so a rejected concurrent attempt leaves the UI untouched.
    let _guard = connect_lock
        .0
        .try_lock()
        .map_err(|_| UiError::new("busy", "A connection attempt is already in progress."))?;

    // Honest failure: Phase 1 has no Tor; a direct TcpStream cannot route through
    // it, so refuse rather than silently connecting in the clear.
    if req.use_tor {
        return Err(UiError::new(
            "not_implemented",
            "Tor support arrives in a later phase.",
        ));
    }

    // Run the flow; on ANY error emit Disconnected before returning.
    match connect_inner(&req, &dir, &session, &emit_conn, &emit_auth).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            emit_conn(ConnectionState::Disconnected);
            Err(e)
        }
    }
}

async fn connect_inner(
    req: &ConnectRequest,
    dir: &tauri::State<'_, AppDir>,
    session: &tauri::State<'_, Session>,
    emit_conn: &impl Fn(ConnectionState),
    emit_auth: &impl Fn(AuthState),
) -> Result<ConnectResponse, UiError> {
    emit_conn(ConnectionState::Resolving);

    // 1) Pinned server cert (Phase-1 trust source): <dir>/config/server_cert.der.
    let cert_path = dir.0.join("config").join("server_cert.der");
    let cert_bytes = std::fs::read(&cert_path)
        .map_err(|_| UiError::new("untrusted", "This server has not been trusted yet."))?;
    let cert = CertificateDer::from(cert_bytes);
    let config = transport::pinned_client_config(cert)?;

    // 2) ServerName from the host portion of `server` (host:port). The SNI/cert
    //    validation uses the host; the port only matters for the TCP dial.
    //    Phase-1 constraint: `server` must be `hostname:port` (no IPv6 bracket
    //    form, no port-less host — those are not parsed yet), and the host MUST
    //    match a SAN in the pinned cert (e.g. connecting by 127.0.0.1 against a
    //    localhost-SAN cert will not verify).
    let host = req.server.rsplit_once(':').map(|(h, _)| h).unwrap_or(&req.server);
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| UiError::new("tls", "Invalid server name."))?;
    let transport = Transport::new(config, server_name, req.server.clone());

    // 3) TLS handshake + channel binding (same connection used for login).
    emit_conn(ConnectionState::TlsHandshake);
    let (tls, exporter) = transport.connect().await?;
    emit_conn(ConnectionState::ChannelBinding);

    // 4) hyper http1 over the TLS stream; drive the connection in the background.
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(|_| UiError::new("tls", "Secure connection failed."))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // 5) Take the unlocked identity OUT of the session for the duration of the
    //    exchange (Identity is not Clone) so we never hold the mutex across the
    //    HTTP awaits. Invariant: every path below MUST restore it into the session
    //    (the user stays unlocked) — the ConnectLock guarantees no concurrent
    //    connect observes the transient `None`. Take it BEFORE emitting
    //    Authenticating so the `locked` early-return doesn't wedge the UI on
    //    "Authenticating". Bind `ts` before the take so the (effectively
    //    impossible) clock panic can't strike between take and restore.
    let ts = now_ms();
    let id = {
        let mut s = session.0.lock().await;
        s.identity
            .take()
            .ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?
    };
    emit_auth(AuthState::Authenticating);

    let result =
        session::login_exchange(&mut sender, &id, &req.username, host, &exporter, ts).await;

    // 6) Restore the identity regardless of outcome (the user stays unlocked).
    let login = match result {
        Ok(login) => {
            let mut s = session.0.lock().await;
            s.identity = Some(id);
            s.server_id = login.server_id.clone();
            s.token = Some(login.token.clone());
            login
        }
        Err(e) => {
            session.0.lock().await.identity = Some(id);
            emit_auth(AuthState::LoggedOut);
            return Err(e);
        }
    };

    emit_conn(ConnectionState::Connected);
    emit_auth(AuthState::LoggedIn);
    Ok(ConnectResponse {
        server_id: login.server_id,
    })
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
