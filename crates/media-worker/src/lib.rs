//! Sandboxed media-decode **worker + launcher** (DESIGN §8.1/D30, media-sandbox).
//!
//! Decoding shared media runs a decoder on attacker-authored bytes — the system's
//! top RCE surface. The defense is to run that decode in a **secret-less,
//! network-less, OS-isolated process** and treat both its input bounds and its
//! output as untrusted (`client-core::sandbox`). This crate is the process side
//! of that seam:
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
use maxsecu_client_core::video::{
    decode_worker_msg, encode_client_msg, ClientMsg, WorkerMsg,
};

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[cfg(windows)]
mod win32;
#[cfg(windows)]
pub use win32::{ConfinedOutput, SpawnError};

/// Persistent video-decode session (Phase 7, Task 3.2): the in-process AV1/CMAF
/// decode state machine over the `client-core` `ClientMsg`/`WorkerMsg` seam. Drive
/// it on a 64 MiB-stack thread (CF-2 — see [`session`] docs).
mod session;
pub use session::VideoSession;

/// Default per-worker memory cap (decompression-bomb hard kill, media-sandbox §3).
pub const DEFAULT_WORKER_MEMORY_CAP_BYTES: u64 = 512 * 1024 * 1024;

/// Length-prefixed duplex **framing** for the persistent video-session protocol
/// (Task 3.3). Each frame on the pipe is a `u32` little-endian length prefix
/// followed by exactly that many bytes = one `client-core::video` message body
/// (`encode_client_msg` / `encode_worker_msg`). The outer length prefix is this
/// transport's job; the message-body codec lives in `client-core`. Shared by the
/// worker's `--video-session` loop (`src/main.rs`) and the cross-platform
/// [`VideoSubprocessSession`] launcher — and reused by the Task-3.4 AppContainer
/// variant, which frames the same duplex over the confined pipe.
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

/// Drive a persistent video-decode **session** to completion: ship every
/// `ClientMsg` in `script` and collect every `WorkerMsg` the worker emits, in
/// order. Implemented by the cross-platform [`VideoSubprocessSession`] and,
/// `#[cfg(windows)]`, by the OS-confined [`AppContainerVideoSession`] — the SAME
/// framed-duplex driver ([`drive_framed_session`]) over either a plain child's
/// stdio or the AppContainer's confined pipes, so the test can drive both.
pub trait VideoSessionDecoder {
    /// Run the full `Open → Fragment* → Close` exchange and return every decoded
    /// `WorkerMsg`, in order.
    fn run_session(&self, script: &[ClientMsg]) -> Result<Vec<WorkerMsg>, SessionError>;
}

/// Defense-in-depth ceiling on the **number** of `WorkerMsg`s the trusted parent
/// will buffer for one session before giving up (Minor #4): each frame is already
/// bounded to [`framing::MAX_FRAME_BYTES`], but without a per-session cap a hostile
/// worker could stream frames indefinitely → parent OOM. A canonical clip emits a
/// handful of messages per fragment; `1 << 20` is far above any legitimate session
/// yet finite. On exceed the driver stops reading and errors; teardown then kills
/// the worker (the confined Job is kill-on-close).
const MAX_SESSION_MSGS: usize = 1 << 20;

/// Defense-in-depth ceiling on the **total bytes** of `WorkerMsg` bodies buffered
/// for one session before giving up (Minor #4) — the byte-sized companion to
/// [`MAX_SESSION_MSGS`], so neither many tiny frames nor a few near-`MAX_FRAME_BYTES`
/// frames can exhaust parent memory.
const MAX_SESSION_BYTES: u64 = 1024 * 1024 * 1024;

/// Shared **framed-duplex driver** for a persistent video session over a pair of
/// pipe ends. Streams every framed `ClientMsg` on a **writer thread** (so a large
/// request can't deadlock against the worker filling its stdout pipe) while
/// reading framed `WorkerMsg`s on the caller's thread until EOF — deadlock-free,
/// bounded buffering. A broken-pipe write (the worker exited early) ends the
/// writer cleanly. The accumulated output is bounded by [`MAX_SESSION_MSGS`] /
/// [`MAX_SESSION_BYTES`]: a worker that streams without end is cut off with an
/// error rather than OOMing the trusted parent. The caller owns process spawn /
/// wait / teardown; this only drives the I/O over the two handle ends, so it is
/// shared verbatim by the cross-platform [`VideoSubprocessSession`] (over `Child`
/// stdio) and the Windows [`AppContainerVideoSession`] (over the confined `File`
/// pipe ends).
fn drive_framed_session<W, R>(
    writer: W,
    mut reader: R,
    script: &[ClientMsg],
) -> std::io::Result<Vec<WorkerMsg>>
where
    W: Write + Send + 'static,
    R: Read,
{
    // Own the script so it can move into the writer thread (the worker reads on
    // its own schedule; the parent must not hold a borrow across the join).
    let script = script.to_vec();
    let writer = std::thread::spawn(move || {
        let mut writer = writer;
        for msg in &script {
            let body = encode_client_msg(msg);
            if framing::write_frame(&mut writer, &body).is_err() {
                break; // worker hung up early (broken pipe) — stop cleanly.
            }
        }
        let _ = writer.flush();
        // drop(writer) closes the pipe → the worker sees EOF.
    });

    let mut out = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut read_err: Option<std::io::Error> = None;
    loop {
        match framing::read_frame(&mut reader) {
            Ok(Some(body)) => {
                // Per-session ceiling (Minor #4): cut a runaway worker off before it
                // can exhaust parent memory; teardown kills it afterwards.
                total_bytes = total_bytes.saturating_add(body.len() as u64);
                if out.len() >= MAX_SESSION_MSGS || total_bytes > MAX_SESSION_BYTES {
                    read_err = Some(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "session output exceeded per-session ceiling",
                    ));
                    break;
                }
                match decode_worker_msg(&body) {
                    Ok(msg) => out.push(msg),
                    Err(_) => {
                        read_err = Some(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "undecodable worker message",
                        ));
                        break;
                    }
                }
            }
            Ok(None) => break, // worker closed stdout — exchange complete.
            Err(e) => {
                read_err = Some(e);
                break;
            }
        }
    }
    // Dropping `reader` (when this fn returns) closes our read end → a still-writing
    // worker gets a broken pipe and stops; the writer thread is joined here.

    let _ = writer.join();
    match read_err {
        Some(e) => Err(e),
        None => Ok(out),
    }
}

/// Drive a persistent video-decode **session** by spawning the `media-worker`
/// binary with `--video-session` and exchanging length-prefixed `ClientMsg` /
/// `WorkerMsg` frames over its stdio pipes — **real process isolation** across a
/// process boundary (separate address space; the worker shares none of this
/// process's key state). Cross-platform (plain `Command`); the Task-3.4
/// AppContainer variant layers OS confinement on this same framed duplex.
pub struct VideoSubprocessSession {
    worker_path: PathBuf,
}

impl VideoSubprocessSession {
    /// `worker_path` is the absolute path to the built `media-worker` executable.
    pub fn new(worker_path: impl Into<PathBuf>) -> Self {
        VideoSubprocessSession {
            worker_path: worker_path.into(),
        }
    }

    /// Run the full framed exchange: ship every `ClientMsg` in `script` (each
    /// length-prefixed) to the worker on a **writer thread** — so a large request
    /// can't deadlock against the worker filling its stdout pipe — while this
    /// thread concurrently reads framed `WorkerMsg`s until the worker closes
    /// stdout (EOF). Returns every decoded `WorkerMsg`, in order.
    ///
    /// `script` should normally end with `ClientMsg::Close` so the worker tears
    /// the session down and exits; dropping stdin afterwards also signals EOF,
    /// which the worker treats identically. Reads apply the same defensive
    /// length-bound ([`framing::MAX_FRAME_BYTES`]) as the worker.
    pub fn run(&self, script: Vec<ClientMsg>) -> std::io::Result<Vec<WorkerMsg>> {
        self.run_framed(&script)
    }

    /// The framed-duplex exchange behind both [`run`](Self::run) and the
    /// [`VideoSessionDecoder`] impl: spawn the `--video-session` worker, then drive
    /// the shared [`drive_framed_session`] over its stdio (writer thread + reader),
    /// and reap the child. Cross-platform; no OS confinement.
    fn run_framed(&self, script: &[ClientMsg]) -> std::io::Result<Vec<WorkerMsg>> {
        let mut child = Command::new(&self.worker_path)
            .arg("--video-session")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("worker stdin unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("worker stdout unavailable"))?;

        let result = drive_framed_session(stdin, stdout, script);
        // On an error/cap cutoff the child may still be running (e.g. a runaway
        // worker); kill it so `wait` can't hang and nothing is left behind. (The
        // confined path relies on the Job's kill-on-close instead.)
        if result.is_err() {
            let _ = child.kill();
        }
        let _ = child.wait();
        result
    }
}

impl VideoSessionDecoder for VideoSubprocessSession {
    fn run_session(&self, script: &[ClientMsg]) -> Result<Vec<WorkerMsg>, SessionError> {
        self.run_framed(script).map_err(SessionError::Io)
    }
}

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

/// Drive a persistent video-decode **session** inside a **Windows AppContainer +
/// Job Object** (DESIGN §8.1/D30, media-sandbox §2; Task 3.4): no network
/// capability, a low-privilege token that cannot read the user's key blob, no
/// child processes, and a hard memory cap. Same [`VideoSessionDecoder`] contract
/// as the cross-platform [`VideoSubprocessSession`]; the OS confinement is the
/// only difference. The duplex framing is the SAME [`drive_framed_session`], run
/// over the confined pipe ends handed back by [`win32::spawn_confined_session`].
#[cfg(windows)]
pub struct AppContainerVideoSession {
    worker_path: PathBuf,
    memory_cap_bytes: u64,
}

#[cfg(windows)]
impl AppContainerVideoSession {
    pub fn new(worker_path: impl Into<PathBuf>) -> Self {
        AppContainerVideoSession {
            worker_path: worker_path.into(),
            memory_cap_bytes: DEFAULT_WORKER_MEMORY_CAP_BYTES,
        }
    }

    pub fn with_memory_cap(worker_path: impl Into<PathBuf>, cap: u64) -> Self {
        AppContainerVideoSession {
            worker_path: worker_path.into(),
            memory_cap_bytes: cap,
        }
    }

    /// Feed ONE framed `Fragment` body on stdin and run a confined worker
    /// `--selftest-*` probe (`--selftest-net-late` / `--selftest-spawn-late` first
    /// decode that fragment so the worker is genuinely mid-session; `--selftest-read`
    /// ignores it) inside the AppContainer + Job Object, returning its verdict
    /// (`true` = the action SUCCEEDED). The session containment differential asserts
    /// this is `false` — the same serial `spawn_confined` path the single-image
    /// containment suite uses, so the duplex setup is exercised by the session
    /// decode test and the late-lifetime denial by this probe.
    pub fn selftest_with_fragment(
        &self,
        args: &[&str],
        fragment: &[u8],
    ) -> Result<bool, SpawnError> {
        let mut stdin_data = Vec::new();
        // Writing into a Vec is infallible; frame the lone fragment for the worker.
        let _ = framing::write_frame(&mut stdin_data, fragment);
        let out = win32::spawn_confined(&self.worker_path, args, &stdin_data, self.memory_cap_bytes)?;
        Ok(out.stdout.first().copied() == Some(1))
    }

    /// Drive a confined worker `--selftest-*` probe over the **duplex**
    /// [`win32::spawn_confined_session`] launcher (NOT the serial `spawn_confined`),
    /// so confinement over the new duplex path is proven directly. A writer thread
    /// streams ONE framed `Fragment` (the `--selftest-*-late` worker decodes it so it
    /// is genuinely mid-session) then drops the pipe (EOF); the parent thread reads
    /// the worker's single verdict byte. Returns `true` if the probed action
    /// SUCCEEDED; the duplex containment differential asserts it is `false`.
    pub fn selftest_duplex(&self, args: &[&str], fragment: &[u8]) -> Result<bool, SpawnError> {
        let frag = fragment.to_vec();
        let (verdict, _exit_code) = win32::spawn_confined_session(
            &self.worker_path,
            args,
            self.memory_cap_bytes,
            move |mut writer, mut reader| {
                // Stream the lone framed fragment on a writer thread (concurrent with
                // the read below — the real duplex shape), then EOF.
                let writer_thread = std::thread::spawn(move || {
                    let mut framed = Vec::new();
                    let _ = framing::write_frame(&mut framed, &frag);
                    let _ = writer.write_all(&framed);
                    let _ = writer.flush();
                    // drop(writer) → the worker sees EOF after its one fragment.
                });
                let mut out = Vec::new();
                let _ = reader.read_to_end(&mut out);
                let _ = writer_thread.join();
                out.first().copied() == Some(1)
            },
        )?;
        Ok(verdict)
    }
}

#[cfg(windows)]
impl VideoSessionDecoder for AppContainerVideoSession {
    fn run_session(&self, script: &[ClientMsg]) -> Result<Vec<WorkerMsg>, SessionError> {
        // `spawn_confined_session` does the SAME AppContainer + Job + pipe setup as
        // `spawn_confined`, then hands back the two parent pipe ends as `File`s and
        // runs our `drive` closure over them (writer thread + reader) — the duplex
        // framing is `drive_framed_session`, identical to the cross-platform path.
        // The closure runs to completion before `spawn_confined_session` returns, so
        // borrowing `script` here is sound (no clone needed at this level).
        let (result, _exit_code) = win32::spawn_confined_session(
            &self.worker_path,
            &["--video-session"],
            self.memory_cap_bytes,
            |writer, reader| drive_framed_session(writer, reader, script),
        )
        .map_err(SessionError::Spawn)?;
        result.map_err(SessionError::Io)
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
}
