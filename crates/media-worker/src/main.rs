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
use maxsecu_media_worker::{proto, run_decode};
use std::io::{Read, Write};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(mode) = args.get(1) {
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
