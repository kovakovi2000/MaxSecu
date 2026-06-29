//! The author-side transcode **worker** process (DESIGN §8.1/D30, Phase 7 Gate 6).
//!
//! Secret-less and network-less by construction: it reads **one** framed
//! [`TranscodeRequest`] on stdin, runs the bounded transcode (no keys, no sockets),
//! writes **one** framed [`TranscodeResult`] on stdout, and exits — one job per
//! process (the same one-shot, confined shape as the decode `media-worker`).
//! `media-launcher::TranscodeLauncher` spawns exactly this binary inside the OS
//! confinement (AppContainer + Job Object on Windows).
//!
//! The transcode body itself is a skeleton placeholder for Gate 6; Task 6.2 fills
//! in the real `rav1e` encode + CMAF mux (and the optional `ac-ffmpeg` ingest).
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
