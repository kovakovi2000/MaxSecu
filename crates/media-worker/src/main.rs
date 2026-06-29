//! The decode **worker** process (DESIGN §8.1/D30, media-sandbox §1).
//!
//! Secret-less and network-less by construction: in normal mode it reads **one**
//! canonical-media request on stdin, runs the bounded pure-Rust decode (no keys,
//! no sockets), writes **one** framed response on stdout, and exits — one worker
//! per file (media-sandbox §2). The launcher ([`SubprocessDecoder`]) and the
//! Windows AppContainer wrapper spawn exactly this binary.
//!
//! In `--selftest-*` mode it performs one containment probe (attempt network /
//! spawn a child) and writes a single verdict byte (`1` = the action SUCCEEDED,
//! `0` = it was DENIED), so the confinement tests can assert denial from inside
//! the sandbox.
//!
//! [`SubprocessDecoder`]: maxsecu_media_worker::SubprocessDecoder

use maxsecu_client_core::sandbox::{DecodeError, DecodedImage};
use maxsecu_client_core::video::{decode_client_msg, encode_worker_msg, ClientMsg, VideoBounds};
use maxsecu_media_worker::{framing, proto, run_decode, VideoSession};
use std::io::{Read, Write};

/// CF-2: rav1d's single-threaded decode overflows Windows' default 1 MiB
/// main-thread stack, so every path that drives a [`VideoSession`] runs on a
/// 64 MiB-stack thread. Shared by `--video-session` and the late-lifetime
/// selftests; `main` spawns it and joins.
const VIDEO_STACK_BYTES: usize = 64 * 1024 * 1024;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(mode) = args.get(1) {
        // Persistent duplex video-decode session (Task 3.3): framed ClientMsg in,
        // framed WorkerMsg out, on a 64 MiB-stack thread (CF-2).
        if mode == "--video-session" {
            run_on_video_stack(video_session_loop);
            return;
        }
        // Late-lifetime containment probes (Task 3.3): decode one real fragment
        // first (so the worker is genuinely mid-session), THEN run the SAME
        // net/spawn probe as the matching `--selftest-*` mode and write the verdict
        // byte. Proves confinement holds across the whole session lifetime, not just
        // at process start.
        if mode == "--selftest-net-late" || mode == "--selftest-spawn-late" {
            run_on_video_stack(decode_one_fragment_from_stdin);
            let base = if mode == "--selftest-net-late" {
                "--selftest-net"
            } else {
                "--selftest-spawn"
            };
            let verdict = run_selftest(base, args.get(2).map(String::as_str));
            let mut out = std::io::stdout();
            let _ = out.write_all(&[verdict as u8]);
            let _ = out.flush();
            return;
        }
        if mode.starts_with("--selftest") {
            let verdict = run_selftest(mode, args.get(2).map(String::as_str));
            let mut out = std::io::stdout();
            let _ = out.write_all(&[verdict as u8]);
            let _ = out.flush();
            return;
        }
    }

    let mut input = Vec::new();
    let resp: Result<DecodedImage, DecodeError> =
        if std::io::stdin().read_to_end(&mut input).is_err() {
            Err(DecodeError::DecodeFailed)
        } else {
            match proto::decode_request(&input) {
                Ok(req) => run_decode(&req),
                Err(_) => Err(DecodeError::DecodeFailed),
            }
        };
    let bytes = proto::encode_response(&resp);
    let mut out = std::io::stdout();
    let _ = out.write_all(&bytes);
    let _ = out.flush();
}

/// Run `f` on a 64 MiB-stack thread and join it (CF-2 — see [`VIDEO_STACK_BYTES`]).
fn run_on_video_stack(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(VIDEO_STACK_BYTES)
        .spawn(f)
        .expect("spawn 64 MiB video-decode thread")
        .join()
        .expect("video-decode thread panicked");
}

/// The `--video-session` duplex streaming loop. Reads length-prefixed `ClientMsg`
/// frames from stdin, feeds each to a persistent [`VideoSession`], and writes each
/// returned `WorkerMsg` back as a length-prefixed frame on stdout (flushing after
/// every input message). Terminates on `ClientMsg::Close` or stdin EOF; on a
/// malformed / over-ceiling / truncated frame or an undecodable body it exits
/// cleanly (the launcher tears the worker down regardless). Holds no keys and
/// opens no sockets.
fn video_session_loop() {
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    let mut session = VideoSession::new();

    loop {
        let body = match framing::read_frame(&mut reader) {
            Ok(Some(body)) => body,
            Ok(None) => break, // clean EOF at a frame boundary — done.
            Err(_) => break,   // over-ceiling / truncated frame — bail out cleanly.
        };
        let msg = match decode_client_msg(&body) {
            Ok(msg) => msg,
            Err(_) => break, // undecodable message body — bail out cleanly.
        };
        let is_close = matches!(msg, ClientMsg::Close);

        for out_msg in session.feed(msg) {
            let out_body = encode_worker_msg(&out_msg);
            if framing::write_frame(&mut writer, &out_body).is_err() {
                return; // launcher hung up — stop.
            }
        }
        if writer.flush().is_err() {
            return;
        }
        if is_close {
            break;
        }
    }
}

/// Read ONE length-prefixed fragment body from stdin and decode it through a real
/// [`VideoSession`] (Open → Fragment → Close), so the worker is genuinely
/// mid-session before a late-lifetime containment probe runs. A missing / malformed
/// fragment is tolerated — the probe still runs (proving denial regardless of input).
fn decode_one_fragment_from_stdin() {
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let frag = match framing::read_frame(&mut reader) {
        Ok(Some(body)) => body,
        _ => return, // no usable fragment — proceed straight to the probe.
    };
    let mut session = VideoSession::new();
    session.feed(ClientMsg::Open {
        bounds: VideoBounds::default(),
    });
    let _ = session.feed(ClientMsg::Fragment { seq: 0, bytes: frag });
    session.feed(ClientMsg::Close);
}

/// One containment probe from inside the (possibly confined) worker. Returns
/// whether the action **succeeded** — the confinement tests assert it does NOT.
fn run_selftest(mode: &str, arg: Option<&str>) -> bool {
    use std::process::{Command, Stdio};
    match mode {
        // Attempt a loopback TCP connect. An AppContainer with no network
        // capability cannot reach the network (loopback included) → false.
        "--selftest-net" => match arg.and_then(|p| p.parse::<u16>().ok()) {
            Some(port) => {
                let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
                std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(2))
                    .is_ok()
            }
            None => false,
        },
        // Attempt to read a user file (a key-blob stand-in). An AppContainer's
        // low-privilege token cannot read the user's files → false.
        "--selftest-read" => arg.map(|p| std::fs::read(p).is_ok()).unwrap_or(false),
        // Attempt to spawn a child process. A Job Object with active-process = 1
        // (and breakaway denied) cannot create a child → false.
        "--selftest-spawn" => std::env::current_exe()
            .ok()
            .and_then(|exe| {
                Command::new(exe)
                    .arg("--selftest-noop")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .ok()
            })
            .map(|mut child| {
                let _ = child.wait();
                true
            })
            .unwrap_or(false),
        // The child spawned by --selftest-spawn; exists only to be spawnable.
        "--selftest-noop" => true,
        _ => false,
    }
}
