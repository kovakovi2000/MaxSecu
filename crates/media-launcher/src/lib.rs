//! Sandboxed media-decode **launcher** (DESIGN §8.1/D30, media-sandbox).
//!
//! Decoding shared media runs a decoder on attacker-authored bytes — the system's
//! top RCE surface. The defense is to run that decode in a **secret-less,
//! network-less, OS-isolated process** and treat both its input bounds and its
//! output as untrusted (`client-core::sandbox`). This crate is the **codec-free
//! launcher** side of that seam: it spawns the confined `media-worker` binary and
//! exchanges framed messages with it, but **never links the AV1/CMAF codecs**
//! (`rav1d`/`symphonia` live only in the `media-worker` crate). That separation is
//! structural — a key-holding consumer (`client-app`) depends on this crate, so the
//! decoder cannot be unified into the trusted process by Cargo feature resolution.
//!
//! * [`proto`] — the one-shot wire protocol between the launcher and the worker
//!   (request: bounds + canonical bytes; response: a decoded frame or a decode
//!   error). Length-prefixed, little-endian, fully unit-tested.
//! * [`SubprocessDecoder`] — spawns the worker binary, ships one request, reads
//!   one response, and maps it back to the [`SandboxedDecoder`] contract. This is
//!   **real process isolation** (separate address space, no shared key state) and
//!   is cross-platform.
//! * `#[cfg(windows)]` [`AppContainerDecoder`] (added in 6b-ii) wraps the same
//!   spawn in an AppContainer + Job Object with no network capability — the OS
//!   confinement that makes a decoder 0-day non-exfiltrating.
//!
//! The worker holds **no keys and opens no sockets**; the launcher hands it only
//! the already-decrypted canonical bytes for one file and kills it per job
//! (media-sandbox §2 — one worker per decode).

use maxsecu_client_core::sandbox::{DecodeError, DecodedImage};
use maxsecu_client_core::media::MediaBounds;
use maxsecu_client_core::sandbox::SandboxedDecoder;

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicBool;

pub mod ffmpeg_args;
pub use ffmpeg_args::build_ffmpeg_args;

pub mod transcode_opts;
pub use transcode_opts::{Bitrate, Resolution, TranscodeOptions};

#[cfg(windows)]
mod win32;
#[cfg(windows)]
pub use win32::{
    appcontainer_sid_string, grant_path_to_appcontainer, spawn_confined_exe, ConfinedExeOutput,
    ConfinedOutput, FfmpegProgress, GrantAccess, PathGrant, SpawnError,
};

/// Default per-worker memory cap (decompression-bomb hard kill, media-sandbox §3).
pub const DEFAULT_WORKER_MEMORY_CAP_BYTES: u64 = 512 * 1024 * 1024;

/// Default Job-Object memory cap for the confined **ffmpeg** ingest (Task 2.2).
/// AV1 (SVT-AV1) ENCODE is markedly hungrier than the decode worker — lookahead +
/// reference buffers — so this is larger than [`DEFAULT_WORKER_MEMORY_CAP_BYTES`].
/// 2 GiB is generous headroom for realistic source media while still hard-killing a
/// runaway/bomb; callers tune it via [`FfmpegLauncher::with_memory_cap`].
#[cfg(windows)]
pub const DEFAULT_FFMPEG_MEMORY_CAP_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// **Progress-based stall timeout** for the confined ffmpeg ingest (Task B). The
/// fixed wall-clock kill is replaced by this: the confined ffmpeg is force-killed
/// only if its `-progress` `out_time` fails to advance for this long (reset on every
/// forward advance), so a legitimately-slow but progressing transcode is NEVER
/// wrongly killed. 90 s of ZERO progress is a hang, not slow work.
#[cfg(windows)]
pub const FFMPEG_STALL_TIMEOUT_MS: u32 = 90_000;

/// **Absolute backstop** for the confined ffmpeg ingest (Task B): even if `out_time`
/// keeps advancing (a progress-spammer), the confined process is terminated past
/// this total wall-clock bound. 1 hour is generous headroom for a large legitimate
/// transcode while still guaranteeing termination.
#[cfg(windows)]
pub const FFMPEG_MAX_TOTAL_MS: u32 = 3_600_000;

/// Length-prefixed **framing**, originally for the persistent video-session
/// protocol (Task 3.3; the client-side session driver was retired once native
/// `<video>` became the viewer — see `media-worker`'s own `--video-session` loop,
/// which still speaks this wire format). Each frame is a `u32` little-endian
/// length prefix followed by exactly that many bytes — one `client-core::video`
/// message body (`encode_client_msg` / `encode_worker_msg`) for the video-session
/// wire, or a `client-core::media` transcode-request/-result body for the one-shot
/// transcode wire ([`TranscodeLauncher::parse_framed_result`]). The outer length
/// prefix is this transport's job; the message-body codec lives elsewhere.
pub mod framing {
    use std::io::{Read, Write};

    /// Hard ceiling on a single frame body. A hostile / corrupt length prefix
    /// beyond this is rejected rather than driving a multi-GiB allocation. Sized
    /// well above `VideoBounds::max_fragment_bytes` (16 MiB) plus the small
    /// per-message header — generous headroom without inviting a bomb.
    pub const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

    /// Read exactly `buf.len()` bytes, looping over partial pipe reads.
    /// `Ok(true)` = filled; `Ok(false)` = clean EOF before ANY byte was read (a
    /// frame boundary — the peer closed its end); `Err` = truncated mid-buffer /
    /// I/O error.
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

    /// Read one length-prefixed frame body. `Ok(None)` = clean EOF at a frame
    /// boundary (the peer is done); `Err` on an over-ceiling length prefix or a
    /// truncated body. Never attempts a `u32::MAX`-sized allocation.
    pub fn read_frame(r: &mut impl Read) -> std::io::Result<Option<Vec<u8>>> {
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

    /// Write one length-prefixed frame body (`u32` LE length + bytes). The caller
    /// is responsible for flushing.
    pub fn write_frame(w: &mut impl Write, body: &[u8]) -> std::io::Result<()> {
        w.write_all(&(body.len() as u32).to_le_bytes())?;
        w.write_all(body)
    }
}

pub mod proto {
    //! One-shot length-prefixed little-endian protocol (one request → one
    //! response per worker process). Self-contained so the worker binary and the
    //! launcher agree byte-for-byte.

    use super::{DecodeError, DecodedImage, MediaBounds};

    /// A decode request: the pre-decode bounds + the canonical media bytes.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DecodeRequest {
        pub bounds: MediaBounds,
        pub canonical: Vec<u8>,
    }

    /// Malformed frame on the wire (truncated / bad length).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ProtoError;

    // Error tag bytes (worker → launcher). The worker only ever produces these
    // three; output-validation / worker-failure are launcher-side concerns.
    const ERR_EMPTY: u8 = 1;
    const ERR_DECODE_FAILED: u8 = 2;
    const ERR_TOO_LARGE: u8 = 3;

    fn put_u32(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    fn put_u64(buf: &mut Vec<u8>, v: u64) {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    fn take_u32(b: &[u8], at: &mut usize) -> Result<u32, ProtoError> {
        let end = at.checked_add(4).ok_or(ProtoError)?;
        let slice = b.get(*at..end).ok_or(ProtoError)?;
        *at = end;
        Ok(u32::from_le_bytes(slice.try_into().unwrap()))
    }
    fn take_u64(b: &[u8], at: &mut usize) -> Result<u64, ProtoError> {
        let end = at.checked_add(8).ok_or(ProtoError)?;
        let slice = b.get(*at..end).ok_or(ProtoError)?;
        *at = end;
        Ok(u64::from_le_bytes(slice.try_into().unwrap()))
    }
    fn take_u8(b: &[u8], at: &mut usize) -> Result<u8, ProtoError> {
        let v = *b.get(*at).ok_or(ProtoError)?;
        *at += 1;
        Ok(v)
    }
    fn take_bytes(b: &[u8], at: &mut usize, len: usize) -> Result<Vec<u8>, ProtoError> {
        let end = at.checked_add(len).ok_or(ProtoError)?;
        let slice = b.get(*at..end).ok_or(ProtoError)?;
        *at = end;
        Ok(slice.to_vec())
    }

    pub fn encode_request(req: &DecodeRequest) -> Vec<u8> {
        let mut buf = Vec::with_capacity(20 + req.canonical.len());
        put_u32(&mut buf, req.bounds.max_width);
        put_u32(&mut buf, req.bounds.max_height);
        put_u64(&mut buf, req.bounds.max_pixels);
        put_u32(&mut buf, req.canonical.len() as u32);
        buf.extend_from_slice(&req.canonical);
        buf
    }

    pub fn decode_request(bytes: &[u8]) -> Result<DecodeRequest, ProtoError> {
        let at = &mut 0usize;
        let max_width = take_u32(bytes, at)?;
        let max_height = take_u32(bytes, at)?;
        let max_pixels = take_u64(bytes, at)?;
        let len = take_u32(bytes, at)? as usize;
        let canonical = take_bytes(bytes, at, len)?;
        if *at != bytes.len() {
            return Err(ProtoError); // trailing data — reject (injective frame)
        }
        Ok(DecodeRequest {
            bounds: MediaBounds {
                max_width,
                max_height,
                max_pixels,
            },
            canonical,
        })
    }

    pub fn encode_response(res: &Result<DecodedImage, DecodeError>) -> Vec<u8> {
        let mut buf = Vec::new();
        match res {
            Ok(img) => {
                buf.push(0); // ok tag
                put_u32(&mut buf, img.width);
                put_u32(&mut buf, img.height);
                buf.push(img.channels);
                put_u32(&mut buf, img.pixels.len() as u32);
                buf.extend_from_slice(&img.pixels);
            }
            Err(e) => {
                buf.push(1); // error tag
                match e {
                    DecodeError::Empty => buf.push(ERR_EMPTY),
                    DecodeError::TooLarge { width, height } => {
                        buf.push(ERR_TOO_LARGE);
                        put_u32(&mut buf, *width);
                        put_u32(&mut buf, *height);
                    }
                    // The worker never produces OutputRejected/Worker; anything
                    // else collapses to DecodeFailed.
                    _ => buf.push(ERR_DECODE_FAILED),
                }
            }
        }
        buf
    }

    pub fn decode_response(bytes: &[u8]) -> Result<Result<DecodedImage, DecodeError>, ProtoError> {
        let at = &mut 0usize;
        match take_u8(bytes, at)? {
            0 => {
                let width = take_u32(bytes, at)?;
                let height = take_u32(bytes, at)?;
                let channels = take_u8(bytes, at)?;
                let len = take_u32(bytes, at)? as usize;
                let pixels = take_bytes(bytes, at, len)?;
                if *at != bytes.len() {
                    return Err(ProtoError);
                }
                Ok(Ok(DecodedImage {
                    width,
                    height,
                    channels,
                    pixels,
                }))
            }
            1 => {
                let err = match take_u8(bytes, at)? {
                    ERR_EMPTY => DecodeError::Empty,
                    ERR_TOO_LARGE => {
                        let width = take_u32(bytes, at)?;
                        let height = take_u32(bytes, at)?;
                        DecodeError::TooLarge { width, height }
                    }
                    _ => DecodeError::DecodeFailed,
                };
                Ok(Err(err))
            }
            _ => Err(ProtoError),
        }
    }
}

/// Run the worker's decode in-process — the exact work the spawned `media-worker`
/// binary does. Shared so `main.rs` and tests can call it without a subprocess.
/// Holds no keys and opens no sockets.
pub fn run_decode(req: &proto::DecodeRequest) -> Result<DecodedImage, DecodeError> {
    maxsecu_client_core::sandbox::decode_rgba_bounded(&req.canonical, &req.bounds)
}

/// Decode by spawning the `media-worker` binary and exchanging one request /
/// response over its stdio pipes — **real process isolation** (separate address
/// space; the worker shares none of this process's key state). The Win32
/// AppContainer hardening is layered on in 6b-ii.
pub struct SubprocessDecoder {
    worker_path: PathBuf,
}

impl SubprocessDecoder {
    /// `worker_path` is the absolute path to the built `media-worker` executable.
    pub fn new(worker_path: impl Into<PathBuf>) -> Self {
        SubprocessDecoder {
            worker_path: worker_path.into(),
        }
    }

    /// Build the (unspawned) command — shared with the Windows launcher so the
    /// confinement wraps the same invocation.
    fn base_command(&self) -> Command {
        let mut cmd = Command::new(&self.worker_path);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        cmd
    }
}

impl SandboxedDecoder for SubprocessDecoder {
    fn decode_image(
        &self,
        canonical: &[u8],
        bounds: &MediaBounds,
    ) -> Result<DecodedImage, DecodeError> {
        let request = proto::encode_request(&proto::DecodeRequest {
            bounds: *bounds,
            canonical: canonical.to_vec(),
        });

        let mut child = self
            .base_command()
            .spawn()
            .map_err(|_| DecodeError::Worker)?;

        // Write the request on a thread so a large request can't deadlock against
        // the worker filling its stdout pipe.
        let mut stdin = child.stdin.take().ok_or(DecodeError::Worker)?;
        let writer = std::thread::spawn(move || {
            let _ = stdin.write_all(&request);
            // drop(stdin) closes the pipe → the worker sees EOF.
        });

        let mut response = Vec::new();
        let read_ok = child
            .stdout
            .take()
            .ok_or(DecodeError::Worker)?
            .read_to_end(&mut response)
            .is_ok();
        let _ = writer.join();
        let status = child.wait().map_err(|_| DecodeError::Worker)?;

        if !status.success() || !read_ok {
            return Err(DecodeError::Worker); // worker crashed / killed / I/O error
        }
        match proto::decode_response(&response) {
            Ok(inner) => inner,
            Err(_) => Err(DecodeError::Worker),
        }
    }
}

impl SubprocessDecoder {
    /// Run a worker `--selftest-*` probe **without** OS confinement and return its
    /// verdict (`true` = the action succeeded). The differential against
    /// [`AppContainerDecoder`] is what proves the confinement bites: an unconfined
    /// worker connects / spawns; a confined one is denied.
    pub fn selftest(&self, args: &[&str]) -> std::io::Result<bool> {
        let mut cmd = Command::new(&self.worker_path);
        cmd.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let out = cmd.output()?;
        Ok(out.stdout.first().copied() == Some(1))
    }
}

/// A video-session driver failure (Task 3.4). Carries no secrets.
#[derive(Debug)]
pub enum SessionError {
    /// The framed duplex exchange failed: a pipe I/O error, a truncated /
    /// over-ceiling frame, or an undecodable worker message body.
    Io(std::io::Error),
    /// The Windows AppContainer + Job Object launch itself failed (setup FFI).
    #[cfg(windows)]
    Spawn(SpawnError),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::Io(e) => write!(f, "video session I/O error: {e}"),
            #[cfg(windows)]
            SessionError::Spawn(e) => write!(f, "video session launch failed: {e}"),
        }
    }
}

impl std::error::Error for SessionError {}

/// Decode by spawning the `media-worker` binary inside a **Windows AppContainer +
/// Job Object** (DESIGN §8.1/D30, media-sandbox §2): no network capability, a
/// low-privilege token that cannot read the user's key blob, no child processes,
/// and a hard memory cap. Same `SandboxedDecoder` contract as the cross-platform
/// [`SubprocessDecoder`]; the OS confinement is the only difference.
#[cfg(windows)]
pub struct AppContainerDecoder {
    worker_path: PathBuf,
    memory_cap_bytes: u64,
}

#[cfg(windows)]
impl AppContainerDecoder {
    pub fn new(worker_path: impl Into<PathBuf>) -> Self {
        AppContainerDecoder {
            worker_path: worker_path.into(),
            memory_cap_bytes: DEFAULT_WORKER_MEMORY_CAP_BYTES,
        }
    }

    pub fn with_memory_cap(worker_path: impl Into<PathBuf>, cap: u64) -> Self {
        AppContainerDecoder {
            worker_path: worker_path.into(),
            memory_cap_bytes: cap,
        }
    }

    /// Run a worker `--selftest-*` probe **inside** the AppContainer + Job Object
    /// and return its verdict (`true` = the action succeeded). The containment
    /// tests assert this is `false` (network / child-spawn denied).
    pub fn selftest(&self, args: &[&str]) -> Result<bool, SpawnError> {
        let out = win32::spawn_confined(&self.worker_path, args, &[], self.memory_cap_bytes)?;
        Ok(out.stdout.first().copied() == Some(1))
    }
}

#[cfg(windows)]
impl SandboxedDecoder for AppContainerDecoder {
    fn decode_image(
        &self,
        canonical: &[u8],
        bounds: &MediaBounds,
    ) -> Result<DecodedImage, DecodeError> {
        let request = proto::encode_request(&proto::DecodeRequest {
            bounds: *bounds,
            canonical: canonical.to_vec(),
        });
        let out = win32::spawn_confined(&self.worker_path, &[], &request, self.memory_cap_bytes)
            .map_err(|_| DecodeError::Worker)?;
        if out.exit_code != 0 {
            return Err(DecodeError::Worker);
        }
        match proto::decode_response(&out.stdout) {
            Ok(inner) => inner,
            Err(_) => Err(DecodeError::Worker),
        }
    }
}

// ===========================================================================
// Author-side transcode launcher (Phase 7, Gate 6). The codec-free spawner side of
// the C-confined ingest worker: spawns the `media-transcode-worker` binary
// ONE-SHOT (one request → one response) — NOT the duplex session launcher — and
// exchanges framed messages whose body codec lives in `client-core` (the TCB). On
// Windows the spawn is the same AppContainer + Job Object confinement
// (`win32::spawn_confined`) the decode path uses. This crate links NO codec
// (`rav1e`/`ac-ffmpeg` live ONLY in the worker), so a key-holding consumer
// depending on this launcher can never unify them in.
// ===========================================================================

use maxsecu_client_core::media::{
    decode_transcode_result, encode_transcode_request, TranscodeRequest, TranscodeResult,
};

/// Spawn the confined `media-transcode-worker` for ONE transcode job: write a
/// framed [`TranscodeRequest`] to its stdin, read a single framed
/// [`TranscodeResult`] from its stdout. Real process isolation (separate address
/// space; no key state shared). The codecs (`rav1e` encode, `ac-ffmpeg` ingest)
/// live only in the spawned binary; this launcher is codec-free.
pub struct TranscodeLauncher {
    worker_path: PathBuf,
    memory_cap_bytes: u64,
}

impl TranscodeLauncher {
    /// `worker_path` is the absolute path to the built `media-transcode-worker`.
    pub fn new(worker_path: impl Into<PathBuf>) -> Self {
        TranscodeLauncher {
            worker_path: worker_path.into(),
            memory_cap_bytes: DEFAULT_WORKER_MEMORY_CAP_BYTES,
        }
    }

    pub fn with_memory_cap(worker_path: impl Into<PathBuf>, cap: u64) -> Self {
        TranscodeLauncher {
            worker_path: worker_path.into(),
            memory_cap_bytes: cap,
        }
    }

    /// Run one transcode job to completion and return its [`TranscodeResult`]. The
    /// worker output is untrusted: the response frame length is bounded
    /// ([`framing::MAX_FRAME_BYTES`]) and the body decoded with the bounds-safe
    /// `client-core` codec — a hostile / crashing / non-zero-exit worker yields a
    /// [`SessionError`], never a panic.
    ///
    /// `cancel` (Task C) is polled during the confined re-mux worker's bounded exit
    /// wait, so a user cancel / app shutdown tears a slow re-mux down promptly rather
    /// than waiting out the full DoS bound. Pass a never-set flag for a
    /// non-cancellable call.
    pub fn transcode(
        &self,
        req: &TranscodeRequest,
        cancel: &AtomicBool,
    ) -> Result<TranscodeResult, SessionError> {
        let mut stdin_data = Vec::new();
        // Writing into a Vec is infallible; frame the lone request for the worker.
        let _ = framing::write_frame(&mut stdin_data, &encode_transcode_request(req));
        let stdout = self.run_worker(&stdin_data, cancel)?;
        parse_framed_result(&stdout)
    }

    /// Run a transcode-worker `--selftest-*` probe **inside** the AppContainer + Job
    /// Object and return its verdict (`true` = the probed action SUCCEEDED). The
    /// Gate-6 containment differential asserts this is `false` (network / child-spawn /
    /// key-blob-read denied) while the SAME worker run unconfined is allowed — proving
    /// the confinement is what bounds a (future, deferred) ffmpeg C-decode 0-day. The
    /// probe needs no stdin, so none is written; the lone verdict byte is read off the
    /// confined stdout.
    #[cfg(windows)]
    pub fn selftest(&self, args: &[&str]) -> Result<bool, SpawnError> {
        let out = win32::spawn_confined(&self.worker_path, args, &[], self.memory_cap_bytes)?;
        // Read ONLY the single verdict byte (not the worker exit code): a confined
        // spawn that produced no stdout byte reads as `false` (DENIED) — the SAFE
        // direction (a probe can never silently read as ALLOWED).
        Ok(out.stdout.first().copied() == Some(1))
    }

    /// Spawn the worker inside the Windows AppContainer + Job Object, stream the
    /// framed request on its stdin, and return the captured stdout. `cancel` is polled
    /// during the confined worker's bounded exit wait (Task C).
    #[cfg(windows)]
    fn run_worker(&self, stdin_data: &[u8], cancel: &AtomicBool) -> Result<Vec<u8>, SessionError> {
        let out = win32::spawn_confined_cancellable(
            &self.worker_path,
            &[],
            stdin_data,
            self.memory_cap_bytes,
            cancel,
        )
        .map_err(SessionError::Spawn)?;
        if out.exit_code != 0 {
            return Err(SessionError::Io(std::io::Error::other(
                "transcode worker exited non-zero",
            )));
        }
        Ok(out.stdout)
    }

    /// Cross-platform fallback (no OS confinement off Windows): a plain one-shot
    /// child. Real process isolation still holds (separate address space). The
    /// request is streamed on a writer thread so a large request cannot deadlock
    /// against the worker filling its stdout pipe.
    #[cfg(not(windows))]
    fn run_worker(&self, stdin_data: &[u8], cancel: &AtomicBool) -> Result<Vec<u8>, SessionError> {
        // No OS-confined cancellable wait off Windows; the cross-platform child is
        // reaped normally. (`cancel` is honored on the Windows confined path.)
        let _ = cancel;
        let mut child = Command::new(&self.worker_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(SessionError::Io)?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| SessionError::Io(std::io::Error::other("worker stdin unavailable")))?;
        let data = stdin_data.to_vec();
        let writer = std::thread::spawn(move || {
            let _ = stdin.write_all(&data);
            // drop(stdin) closes the pipe → the worker sees EOF.
        });
        let mut stdout = Vec::new();
        let read_ok = child
            .stdout
            .take()
            .ok_or_else(|| SessionError::Io(std::io::Error::other("worker stdout unavailable")))?
            .read_to_end(&mut stdout)
            .is_ok();
        let _ = writer.join();
        let status = child.wait().map_err(SessionError::Io)?;
        if !status.success() || !read_ok {
            return Err(SessionError::Io(std::io::Error::other(
                "transcode worker failed",
            )));
        }
        Ok(stdout)
    }
}

/// Decode the worker's framed stdout into a [`TranscodeResult`], bounding the
/// response frame length ([`framing::MAX_FRAME_BYTES`]) and rejecting an empty,
/// truncated, over-ceiling, trailing-garbage, or undecodable response. Shared by
/// [`TranscodeLauncher::transcode`] and its unit tests, which exercise it against a
/// synthesized worker stdout with no real spawn (the real spawn round-trip is
/// Task 6.2).
fn parse_framed_result(stdout: &[u8]) -> Result<TranscodeResult, SessionError> {
    let mut cursor = std::io::Cursor::new(stdout);
    let body = framing::read_frame(&mut cursor)
        .map_err(SessionError::Io)?
        .ok_or_else(|| SessionError::Io(std::io::Error::other("worker produced no response")))?;
    // The single frame must be the WHOLE response (no trailing second frame / junk).
    if (cursor.position() as usize) != stdout.len() {
        return Err(SessionError::Io(std::io::Error::other(
            "trailing bytes after worker response frame",
        )));
    }
    decode_transcode_result(&body)
        .map_err(|_| SessionError::Io(std::io::Error::other("undecodable worker response")))
}

/// The outcome of a confined ffmpeg run: ffmpeg's process exit code and a BOUNDED
/// tail of its stderr (diagnostics — its media goes to the granted output file).
/// `exit_code == 0` is success; the CALLER then reads the output file from the
/// per-job dir. `stderr_tail` is capped (head-kept) so a verbose/hostile ffmpeg
/// can't OOM the parent.
#[cfg(windows)]
#[derive(Debug)]
pub struct FfmpegOutcome {
    pub exit_code: u32,
    pub stderr_tail: Vec<u8>,
    /// `true` iff the run was terminated because the caller's `cancel` flag was set
    /// (a user cancel / app shutdown) — a DISTINCT, benign outcome the caller maps to
    /// a `cancelled` error, NOT the sanitized `video_failed` a stall/backstop kill or
    /// a non-zero exit produces.
    pub cancelled: bool,
}

/// Spawn the pinned `ffmpeg.exe` inside the SAME AppContainer + Job Object
/// confinement the decode worker uses (Task 2.2, D-2): NO network capability, a
/// low-IL token that cannot read the user's keys, NO child processes
/// (`ActiveProcessLimit = 1`), a hard memory cap, and kill-on-close +
/// bounded-wait-then-kill (no hang). Filesystem access is scoped to exactly one
/// caller-provided per-job directory via the Task-2.1 path-ACL grant (RAII —
/// revoked after the spawn on every path). ffmpeg reads an input FILE and writes an
/// output FILE in that dir (its MP4 muxer writes `moov` last and cannot stream to a
/// pipe — Phase-0 ratification §2.1); media never crosses stdio (stdin/stdout =
/// NUL), only a bounded stderr tail is captured. This launcher links NO codec — it
/// only spawns the external binary.
#[cfg(windows)]
pub struct FfmpegLauncher {
    ffmpeg_path: PathBuf,
    memory_cap_bytes: u64,
    /// Progress-based stall bound (Task B): kill only after this long with NO
    /// `-progress` advance.
    stall_timeout_ms: u32,
    /// Absolute wall-clock backstop (Task B): kill past this even if progress keeps
    /// advancing (a progress-spammer).
    max_total_ms: u32,
}

#[cfg(windows)]
impl FfmpegLauncher {
    /// `ffmpeg_path` is the absolute path to the pinned `ffmpeg.exe`.
    pub fn new(ffmpeg_path: impl Into<PathBuf>) -> Self {
        FfmpegLauncher {
            ffmpeg_path: ffmpeg_path.into(),
            memory_cap_bytes: DEFAULT_FFMPEG_MEMORY_CAP_BYTES,
            stall_timeout_ms: FFMPEG_STALL_TIMEOUT_MS,
            max_total_ms: FFMPEG_MAX_TOTAL_MS,
        }
    }

    /// As [`new`](Self::new) with an explicit Job-Object memory cap (AV1 encode is
    /// memory-hungry; tune per source/preset).
    pub fn with_memory_cap(ffmpeg_path: impl Into<PathBuf>, cap: u64) -> Self {
        FfmpegLauncher {
            ffmpeg_path: ffmpeg_path.into(),
            memory_cap_bytes: cap,
            stall_timeout_ms: FFMPEG_STALL_TIMEOUT_MS,
            max_total_ms: FFMPEG_MAX_TOTAL_MS,
        }
    }

    /// Override the absolute forced-kill backstop (default [`FFMPEG_MAX_TOTAL_MS`]).
    /// This is a FINITE DoS ceiling, not a soft hint: past it the confined ffmpeg is
    /// terminated regardless of progress. The primary bound is now the progress-based
    /// stall watchdog ([`FFMPEG_STALL_TIMEOUT_MS`], see [`with_stall_timeout`](Self::with_stall_timeout)),
    /// so a legitimately-slow-but-progressing transcode is never wrongly killed.
    pub fn with_timeout(mut self, max_total_ms: u32) -> Self {
        self.max_total_ms = max_total_ms;
        self
    }

    /// Override the progress-based stall timeout (default [`FFMPEG_STALL_TIMEOUT_MS`]):
    /// the confined ffmpeg is killed only after this long with NO `-progress` advance.
    pub fn with_stall_timeout(mut self, stall_timeout_ms: u32) -> Self {
        self.stall_timeout_ms = stall_timeout_ms;
        self
    }

    /// Run ffmpeg confined with `args` (the discrete argv elements — inputs/outputs
    /// are separate elements, not a shell string), granting the AppContainer SID
    /// `ReadWrite` access to `grant_dir` for the spawn only.
    ///
    /// CONTRACT: `grant_dir` MUST be a **fresh, unique, non-symlinked** directory
    /// (the caller creates it under the system temp dir) that already contains the
    /// source as an input file; ffmpeg writes its output file in the SAME dir. The
    /// grant is `ReadWrite` (which also drops the dir to a Low integrity label so the
    /// Low-IL container can write) and is REVOKED when this returns on every path.
    /// The argv must reference only paths inside `grant_dir` — anything outside is
    /// denied by the confinement (proven by the D-2 differential test).
    ///
    /// CLEANUP OBLIGATION (security requirement, not mere hygiene): after this
    /// returns, the CALLER MUST delete the WHOLE `grant_dir`. The dir-grant revoke
    /// restores the directory's prior DACL/label, but the OUTPUT file ffmpeg created
    /// inside it inherited the container-SID allow ACE (and a Low integrity label) at
    /// creation, and that inherited ACE on the child file CANNOT be retroactively
    /// stripped by revoking the dir grant. Wholesale deletion of the per-job dir is
    /// the only correct cleanup — leaving it behind leaves a container-accessible,
    /// Low-IL artifact on disk.
    ///
    /// The run is bounded by a **progress-based stall watchdog** (Task B): the
    /// confined ffmpeg is force-killed only if its `-progress` `out_time` fails to
    /// advance for `stall_timeout_ms` (default [`FFMPEG_STALL_TIMEOUT_MS`]), plus an
    /// absolute `max_total_ms` backstop (default [`FFMPEG_MAX_TOTAL_MS`]).
    /// `on_progress` (Task A) is invoked live per progress tick with a sanitized
    /// [`FfmpegProgress`] (percent + elapsed ms only — no stderr text / paths cross).
    /// `cancel` (Task C) is polled throughout; when set, the child is terminated, the
    /// path grant is revoked (as on every path), and the returned [`FfmpegOutcome`]
    /// has `cancelled == true` (the caller maps that to a distinct `cancelled` error,
    /// NOT the sanitized `video_failed`).
    pub fn run(
        &self,
        args: &[std::ffi::OsString],
        grant_dir: &std::path::Path,
        on_progress: impl Fn(FfmpegProgress) + Send,
        cancel: &AtomicBool,
    ) -> Result<FfmpegOutcome, SpawnError> {
        let out = win32::spawn_confined_exe(
            &self.ffmpeg_path,
            args,
            &[(grant_dir, GrantAccess::ReadWrite)],
            self.memory_cap_bytes,
            self.stall_timeout_ms,
            self.max_total_ms,
            on_progress,
            cancel,
        )?;
        Ok(FfmpegOutcome {
            exit_code: out.exit_code,
            stderr_tail: out.stderr_tail,
            cancelled: out.cancelled,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::proto::*;
    use super::*;

    #[test]
    fn request_roundtrips() {
        let req = DecodeRequest {
            bounds: MediaBounds {
                max_width: 100,
                max_height: 200,
                max_pixels: 50_000,
            },
            canonical: vec![1, 2, 3, 4, 5],
        };
        assert_eq!(decode_request(&encode_request(&req)).unwrap(), req);
    }

    #[test]
    fn request_rejects_truncated_and_trailing() {
        let req = DecodeRequest {
            bounds: MediaBounds::default(),
            canonical: vec![9, 9, 9],
        };
        let mut bytes = encode_request(&req);
        // Trailing junk → rejected (injective frame).
        bytes.push(0xFF);
        assert!(decode_request(&bytes).is_err());
        // Truncated → rejected.
        assert!(decode_request(&bytes[..3]).is_err());
    }

    #[test]
    fn ok_response_roundtrips() {
        let img = DecodedImage {
            width: 3,
            height: 2,
            channels: 4,
            pixels: vec![0u8; 3 * 2 * 4],
        };
        let wire = encode_response(&Ok(img.clone()));
        assert_eq!(decode_response(&wire).unwrap(), Ok(img));
    }

    #[test]
    fn error_responses_roundtrip() {
        for e in [
            DecodeError::Empty,
            DecodeError::DecodeFailed,
            DecodeError::TooLarge {
                width: 64,
                height: 48,
            },
        ] {
            let wire = encode_response(&Err(e.clone()));
            assert_eq!(decode_response(&wire).unwrap(), Err(e));
        }
    }

    // ---- transcode launcher (Gate 6): the framing/parse contract, no spawn ----

    use maxsecu_client_core::media::{encode_transcode_result, FragmentEntry, TranscodeResult};

    fn sample_transcode_result() -> TranscodeResult {
        TranscodeResult {
            cmaf: vec![1, 2, 3],
            thumbnail: vec![9],
            preview: vec![7, 7],
            fragments: vec![FragmentEntry {
                seq: 0,
                pts_ms: 0,
                chunk_start: 0,
                chunk_len: 1,
            }],
            loudness_gain_db: Some(-2.0),
        }
    }

    #[test]
    fn transcode_launcher_parses_a_framed_worker_result() {
        let result = sample_transcode_result();
        // Synthesize exactly what the worker writes: one framed result body.
        let mut worker_stdout = Vec::new();
        framing::write_frame(&mut worker_stdout, &encode_transcode_result(&result)).unwrap();
        assert_eq!(super::parse_framed_result(&worker_stdout).unwrap(), result);
    }

    #[test]
    fn transcode_launcher_rejects_empty_truncated_and_trailing() {
        let result = sample_transcode_result();
        let mut frame = Vec::new();
        framing::write_frame(&mut frame, &encode_transcode_result(&result)).unwrap();
        // Clean parse first.
        assert_eq!(super::parse_framed_result(&frame).unwrap(), result);
        // Empty stdout (worker crashed before any output) → error.
        assert!(super::parse_framed_result(&[]).is_err());
        // Truncated frame body → error.
        assert!(super::parse_framed_result(&frame[..frame.len() - 1]).is_err());
        // Trailing garbage after the single response frame → error.
        let mut trailing = frame.clone();
        trailing.push(0x00);
        assert!(super::parse_framed_result(&trailing).is_err());
    }

    #[test]
    fn transcode_launcher_rejects_over_ceiling_response_length() {
        // A length prefix beyond MAX_FRAME_BYTES is rejected without a huge alloc.
        let mut bad = Vec::new();
        bad.extend_from_slice(&((framing::MAX_FRAME_BYTES as u32) + 1).to_le_bytes());
        assert!(super::parse_framed_result(&bad).is_err());
    }

    #[test]
    fn transcode_launcher_constructs_codec_free() {
        // Construct the launcher (no spawn): proves the type compiles + is usable
        // here without linking any codec.
        let _l = TranscodeLauncher::new(std::path::PathBuf::from("media-transcode-worker"));
        let _l2 = TranscodeLauncher::with_memory_cap(std::path::PathBuf::from("worker"), 256 << 20);
    }

    #[cfg(windows)]
    #[test]
    fn ffmpeg_launcher_bounds_are_stall_watchdog_plus_backstop() {
        // The confined ffmpeg ingest is bounded by the progress-based stall watchdog
        // (primary) + a 1-hour absolute DoS backstop — the old fixed 10-min hard cap
        // (DEFAULT_FFMPEG_TIMEOUT_MS) is gone.
        let launcher = FfmpegLauncher::new("ffmpeg.exe");
        assert_eq!(launcher.stall_timeout_ms, FFMPEG_STALL_TIMEOUT_MS);
        assert_eq!(launcher.max_total_ms, FFMPEG_MAX_TOTAL_MS);
    }
}
