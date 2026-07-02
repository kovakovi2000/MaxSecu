//! The author-side transcode **worker** process (Universal Video Ingest, Task 3.3;
//! DESIGN §8.1/D30).
//!
//! Secret-less and network-less by construction: it reads **one** framed
//! [`TranscodeRequest`] on stdin, runs the bounded re-mux (no keys, no sockets),
//! writes **one** framed [`TranscodeResult`] on stdout, and exits — one job per
//! process (the same one-shot, confined shape as the decode `media-worker`).
//! `media-launcher::TranscodeLauncher` spawns exactly this binary inside the OS
//! confinement (AppContainer + Job Object on Windows).
//!
//! The transcode body is pure-Rust and links/runs **no codec**: it symphonia-demuxes
//! ffmpeg's output AV1/AAC mp4 (the request `source`) and re-muxes it into the
//! canonical chunk-aligned CMAF fragment layout (see the crate lib). The
//! arbitrary-format decode + AV1/AAC encode happen UPSTREAM in a separate confined
//! `ffmpeg.exe` spawned by `client-app` — that external process, not this crate, is
//! the C carve-out.
//!
//! In `--selftest-*` mode it performs ONE containment probe — attempt a network
//! connect / spawn a child / read a sensitive path — and writes a single verdict byte
//! (`1` = the action SUCCEEDED, `0` = it was DENIED), so the containment tests can
//! assert the AppContainer + Job Object confinement denies each from inside the sandbox
//! (the same probes the decode `media-worker` uses). This bounds the blast radius of
//! the confined worker: even a parser 0-day in it cannot reach the network, shell out,
//! or read the user's keys.
//!
//! [`TranscodeRequest`]: maxsecu_client_core::media::TranscodeRequest
//! [`TranscodeResult`]: maxsecu_client_core::media::TranscodeResult

use std::io::{Read, Write};
use std::process::ExitCode;

use maxsecu_client_core::media::{decode_transcode_request, encode_transcode_result};
use maxsecu_media_transcode_worker::transcode;

/// Hard ceiling on a single framed message body, mirroring
/// `media-launcher::framing::MAX_FRAME_BYTES` (64 MiB). A hostile / corrupt length
/// prefix beyond this is rejected rather than driving a multi-GiB allocation. The
/// framing is duplicated inline (a handful of lines) rather than depending on the
/// codec-free-but-Windows-coupled `media-launcher`, so this worker keeps the
/// minimal dependency set (client-core + the codecs).
const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

fn main() -> ExitCode {
    // Gate-6 containment probe mode: ONE net/spawn/read attempt, then a single verdict
    // byte (`1` = succeeded, `0` = denied) on stdout. Added ALONGSIDE the normal
    // one-shot transcode mode (below), which is untouched. The probe reads no stdin.
    let args: Vec<String> = std::env::args().collect();
    if let Some(mode) = args.get(1) {
        if mode.starts_with("--selftest") {
            let verdict = run_selftest(mode, args.get(2).map(String::as_str));
            let mut out = std::io::stdout();
            let _ = out.write_all(&[verdict as u8]);
            let _ = out.flush();
            return ExitCode::SUCCESS;
        }
    }

    // Read exactly one framed request from stdin. Any framing/decoding failure is
    // fail-closed: write nothing and exit non-zero so the launcher surfaces an error.
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let body = match read_frame(&mut reader) {
        Ok(Some(body)) => body,
        _ => return ExitCode::FAILURE, // EOF / truncated / over-ceiling frame.
    };
    let req = match decode_transcode_request(&body) {
        Ok(req) => req,
        Err(_) => return ExitCode::FAILURE, // undecodable request body.
    };

    let result = match transcode(&req) {
        Ok(result) => result,
        Err(_) => return ExitCode::FAILURE, // fail-closed transcode failure.
    };

    let out_body = encode_transcode_result(&result);
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    if write_frame(&mut writer, &out_body).is_err() || writer.flush().is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Read exactly `buf.len()` bytes, looping over partial reads. `Ok(true)` = filled;
/// `Ok(false)` = clean EOF before ANY byte (a frame boundary); `Err` = truncated
/// mid-buffer / I/O error.
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                return if filled == 0 {
                    Ok(false)
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "truncated frame",
                    ))
                };
            }
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// Read one length-prefixed frame body. `Ok(None)` = clean EOF at a frame boundary;
/// `Err` on an over-ceiling length prefix or a truncated body. Never attempts a
/// `u32::MAX`-sized allocation.
fn read_frame(r: &mut impl Read) -> std::io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    if !read_full(r, &mut len_buf)? {
        return Ok(None);
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame length exceeds ceiling",
        ));
    }
    let mut body = vec![0u8; len];
    if !read_full(r, &mut body)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "truncated frame body",
        ));
    }
    Ok(Some(body))
}

/// Write one length-prefixed frame body (`u32` LE length + bytes).
fn write_frame(w: &mut impl Write, body: &[u8]) -> std::io::Result<()> {
    w.write_all(&(body.len() as u32).to_le_bytes())?;
    w.write_all(body)
}

/// One containment probe (Phase 7 Gate 6) from inside the (possibly confined) worker.
/// Returns whether the action **succeeded** — the containment tests assert it does NOT
/// when the worker is confined (AppContainer + Job Object), yet DOES when unconfined.
/// Mirrors the decode `media-worker`'s `run_selftest` so both workers prove the same
/// net/spawn/read denials. The transcode worker holds NO keys and opens NO sockets in
/// normal operation; these probes are the ONLY such attempts, and they are denied.
fn run_selftest(mode: &str, arg: Option<&str>) -> bool {
    use std::process::{Command, Stdio};
    match mode {
        // Attempt a loopback TCP connect. An AppContainer with no network capability
        // cannot reach the network (loopback included) → false. Unconfined → true.
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
        // Attempt to spawn a child process. A Job Object with active-process = 1 (and
        // breakaway denied) cannot create a child → false.
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
