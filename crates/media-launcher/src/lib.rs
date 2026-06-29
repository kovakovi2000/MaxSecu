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
use maxsecu_client_core::video::{
    decode_worker_msg, encode_client_msg, encode_worker_msg, ClientMsg, WorkerMsg,
};

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use zeroize::Zeroize;

#[cfg(windows)]
mod win32;
#[cfg(windows)]
pub use win32::{ConfinedOutput, SpawnError};

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

    /// Resilient (respawn-on-abort) variant of [`run_session`](Self::run_session): on
    /// a worker-PROCESS abort mid-window, skip the one culprit fragment and respawn a
    /// FRESH confined worker over the rest, so a single hostile/corrupt fragment drops
    /// a few frames instead of killing the whole window. `budget` caps the respawns
    /// (callers pass [`MAX_RESPAWNS_PER_WINDOW`]).
    ///
    /// The **provided default** does a single non-resilient attempt — it simply wraps
    /// [`run_session`](Self::run_session) and reports `Completed` with no skips/respawns.
    /// Decoders that cannot abort mid-window (e.g. in-process test doubles) get this
    /// for free; the real OS-confined sessions ([`VideoSubprocessSession`] /
    /// `AppContainerVideoSession`) OVERRIDE it with the genuine respawn driver.
    fn run_session_resilient(
        &self,
        script: &[ClientMsg],
        budget: u32,
    ) -> Result<ResilientOutcome, SessionError> {
        let _ = budget; // a single attempt never respawns; budget is unused here.
        Ok(ResilientOutcome {
            msgs: self.run_session(script)?,
            skipped: Vec::new(),
            respawns: 0,
            terminal: TerminalReason::Completed,
        })
    }
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

/// How a single framed-duplex worker attempt ENDED, returned alongside the
/// accumulated `WorkerMsg`s by [`drive_framed_session_partial`]. The resilient
/// driver ([`resilient_session`]) keys its respawn decision off this:
/// * [`DriveEnd::Completed`] — the worker finished the script cleanly (normal end).
/// * [`DriveEnd::WorkerGone`] — the frame stream broke mid-frame (truncated body /
///   pipe I/O error): the worker **process died** (the F1 rav1d `panic_cannot_unwind`
///   → `abort`, or the F2 stsz-OOM Job-memory kill). RESUMABLE — respawn a fresh
///   confined worker over the fragments after the culprit.
/// * [`DriveEnd::Protective`] — the **parent** cut the exchange off defensively
///   (per-session cap exceeded, an undecodable message body, or an over-ceiling
///   frame length). A HOSTILE signal — the resilient driver does NOT respawn into
///   it (respawning into a parent-side defense would amplify a hostile input).
///
/// Note: [`drive_framed_session_partial`] reports a *clean pipe EOF* as `None`
/// (not `Some(Completed)`): a worker closing stdout does not by itself prove it
/// exited cleanly, so the caller upgrades `None` to `Completed`/`WorkerGone` by
/// consulting the worker **process exit code** (`run_attempt`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriveEnd {
    /// The worker finished the script cleanly (normal end).
    Completed,
    /// The worker process died mid-stream — resumable by respawn.
    WorkerGone,
    /// The parent cut the exchange off defensively — terminal, never respawned.
    Protective,
}

/// Shared **framed-duplex driver** for a persistent video session over a pair of
/// pipe ends, returning the accumulated `WorkerMsg`s ALONGSIDE how the exchange
/// ended ([`DriveEnd`]) — the **partial-returning** core behind both the
/// all-or-nothing [`drive_framed_session`] wrapper and the respawn-capable
/// [`VideoSubprocessSession::run_session_resilient`] / `AppContainerVideoSession`
/// resilient paths.
///
/// Streams every framed `ClientMsg` on a **writer thread** (so a large request
/// can't deadlock against the worker filling its stdout pipe) while reading framed
/// `WorkerMsg`s on the caller's thread until EOF — deadlock-free, bounded
/// buffering. A broken-pipe write (the worker exited early) ends the writer
/// cleanly. The accumulated output is bounded by [`MAX_SESSION_MSGS`] /
/// [`MAX_SESSION_BYTES`]: a worker that streams without end is cut off (`Protective`)
/// rather than OOMing the trusted parent — **any decoded frames seen before the cut
/// are still returned**.
///
/// The end classification:
/// * `Ok(None)` from [`framing::read_frame`] (clean pipe EOF) → returns `None`
///   (defer to the process exit code; see [`DriveEnd`]).
/// * the parent's own cutoffs (per-session cap exceeded / undecodable body) →
///   `Some(DriveEnd::Protective)`.
/// * a read error of kind `InvalidData` (an over-ceiling frame length the parent
///   refused) → `Some(DriveEnd::Protective)`.
/// * any other read error (truncated frame body / broken pipe) → the worker died →
///   `Some(DriveEnd::WorkerGone)`.
///
/// The caller owns process spawn / wait / teardown; this only drives the I/O over
/// the two handle ends, so it is shared verbatim by the cross-platform
/// [`VideoSubprocessSession`] (over `Child` stdio) and the Windows
/// [`AppContainerVideoSession`] (over the confined `File` pipe ends).
///
/// Defense in depth: the writer thread **zeroizes** the transient canonical
/// PLAINTEXT (already-decrypted `Fragment` bytes, plus each serialized frame body)
/// once it is on the wire — respawns multiply these decrypted-fragment copies in
/// the trusted parent, so they are not left lingering in freed heap.
fn drive_framed_session_partial<W, R>(
    writer: W,
    mut reader: R,
    script: &[ClientMsg],
) -> (Vec<WorkerMsg>, Option<DriveEnd>)
where
    W: Write + Send + 'static,
    R: Read,
{
    // Own the script so it can move into the writer thread (the worker reads on
    // its own schedule; the parent must not hold a borrow across the join).
    let script = script.to_vec();
    let writer = std::thread::spawn(move || {
        let mut writer = writer;
        let mut script = script;
        for msg in &script {
            let mut body = encode_client_msg(msg);
            let write_ok = framing::write_frame(&mut writer, &body).is_ok();
            // Wipe the serialized PLAINTEXT body now it is on the wire (or failed).
            body.zeroize();
            if !write_ok {
                break; // worker hung up early (broken pipe) — stop cleanly.
            }
        }
        let _ = writer.flush();
        // Defense in depth: wipe the transient canonical-plaintext `Fragment` copies
        // (including any unsent ones after an early break) — respawns multiply these
        // already-decrypted copies in the trusted parent.
        for msg in &mut script {
            if let ClientMsg::Fragment { bytes, .. } = msg {
                bytes.zeroize();
            }
        }
        // drop(writer) closes the pipe → the worker sees EOF.
    });

    let mut out = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut end: Option<DriveEnd> = None;
    loop {
        match framing::read_frame(&mut reader) {
            Ok(Some(body)) => {
                // Per-session ceiling (Minor #4): cut a runaway worker off before it
                // can exhaust parent memory; teardown kills it afterwards. This is a
                // PARENT-side defense → Protective (never respawned into).
                total_bytes = total_bytes.saturating_add(body.len() as u64);
                if out.len() >= MAX_SESSION_MSGS || total_bytes > MAX_SESSION_BYTES {
                    end = Some(DriveEnd::Protective);
                    break;
                }
                match decode_worker_msg(&body) {
                    Ok(msg) => out.push(msg),
                    Err(_) => {
                        end = Some(DriveEnd::Protective);
                        break;
                    }
                }
            }
            Ok(None) => break, // clean pipe EOF — defer to the process exit code.
            Err(e) => {
                // `InvalidData` = an over-ceiling frame length the parent refused
                // (a hostile prefix) → Protective. Anything else (truncated body /
                // broken pipe) = the worker died mid-frame → WorkerGone.
                end = Some(if e.kind() == std::io::ErrorKind::InvalidData {
                    DriveEnd::Protective
                } else {
                    DriveEnd::WorkerGone
                });
                break;
            }
        }
    }
    // Dropping `reader` (when this fn returns) closes our read end → a still-writing
    // worker gets a broken pipe and stops; the writer thread is joined here.

    let _ = writer.join();
    (out, end)
}

/// All-or-nothing wrapper over [`drive_framed_session_partial`]: a clean pipe EOF
/// (`None`) yields `Ok(msgs)`; any abnormal/protective end yields `Err`. Preserves
/// the exact observable behavior of the original driver (the existing
/// [`VideoSubprocessSession`] / [`AppContainerVideoSession`] `run_session` callers
/// rely on it). The respawn-capable callers use the partial driver directly.
fn drive_framed_session<W, R>(
    writer: W,
    reader: R,
    script: &[ClientMsg],
) -> std::io::Result<Vec<WorkerMsg>>
where
    W: Write + Send + 'static,
    R: Read,
{
    let (out, end) = drive_framed_session_partial(writer, reader, script);
    match end {
        // Clean pipe EOF — exchange complete (the all-or-nothing caller reaps the
        // child separately to confirm a clean exit).
        None | Some(DriveEnd::Completed) => Ok(out),
        Some(DriveEnd::WorkerGone) => Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "worker died mid-session (truncated frame stream)",
        )),
        Some(DriveEnd::Protective) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "session output cut off by a parent-side defense",
        )),
    }
}

/// Bounded number of confined-worker **respawns** the resilient driver will perform
/// for a single window before giving up — an explicit DoS ceiling. Each respawn is
/// a fresh AppContainer + Job Object launch, so an attacker who crafts a window in
/// which EVERY fragment aborts the worker must NOT be able to drive unbounded
/// confined-process spawns (a hostile clip would otherwise be a spawn bomb). Windows
/// of play are already small (a handful of fragments), so 8 respawns is generous
/// headroom for the realistic "one or two bad fragments" case while bounding the
/// worst case. (Forward progress also terminates the run independently — the resume
/// cursor strictly advances every respawn — so this is purely the worst-case cap.)
pub const MAX_RESPAWNS_PER_WINDOW: u32 = 8;

/// Why a [`resilient_session`] run stopped (its terminal state).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalReason {
    /// A worker attempt finished its (sub)script cleanly — the whole window decoded
    /// (possibly minus earlier skipped culprits).
    Completed,
    /// A worker attempt was cut off by a PARENT-side defense (per-session cap /
    /// undecodable body / over-ceiling frame). NOT retried — respawning into a
    /// hostile signal would amplify it.
    Protective,
    /// Every respawn up to the budget still died; the DoS cap ([`MAX_RESPAWNS_PER_WINDOW`]
    /// when the caller passes it) stopped the run.
    BudgetExhausted,
    /// The cross-respawn accumulated output hit the per-WINDOW buffering ceiling
    /// ([`MAX_SESSION_MSGS`] / [`MAX_SESSION_BYTES`]) — stopped before parent OOM.
    CapExceeded,
}

/// The result of a resilient (respawn-on-abort) video session: every `WorkerMsg`
/// salvaged across all attempts, the culprit fragments that were skipped, the
/// respawn count, and why the run stopped.
#[derive(Debug)]
pub struct ResilientOutcome {
    /// Every `WorkerMsg` accumulated across all attempts, in order, bounded by the
    /// per-WINDOW [`MAX_SESSION_MSGS`] / [`MAX_SESSION_BYTES`] ceiling (NOT reset per
    /// respawn — N respawns do not buy N× the memory).
    pub msgs: Vec<WorkerMsg>,
    /// The `seq` of each fragment that was SKIPPED (the culprit the worker died on),
    /// in skip order.
    pub skipped: Vec<u32>,
    /// How many times a fresh confined worker was respawned.
    pub respawns: u32,
    /// Why the run stopped.
    pub terminal: TerminalReason,
}

/// Pure, **injectable** resilient session driver: runs `run_attempt` over the full
/// script, and on a `WorkerGone` abort mid-window **skips the one culprit fragment**
/// (the fragment in flight when the worker died) and re-runs `run_attempt` over a
/// rebuilt resume sub-script `[Open, <fragments after the culprit>, Close]`, so a
/// single hostile/corrupt fragment drops a few frames instead of killing playback.
///
/// `run_attempt` runs ONE worker attempt over a (sub)script and reports the decoded
/// `WorkerMsg`s plus how that attempt ended ([`DriveEnd`]); it is injected so the
/// respawn LOGIC is unit-tested with a fake closure (no real abort needed
/// cross-platform), while the real sessions supply a fresh confined-worker spawn.
///
/// Invariants:
/// * **Bounded buffering across the whole run** — the accumulated output honors the
///   SAME [`MAX_SESSION_MSGS`] / [`MAX_SESSION_BYTES`] ceiling spanning ALL attempts
///   (not reset per respawn); on exceed → [`TerminalReason::CapExceeded`].
/// * **Protective is terminal** — a parent-side cutoff is never respawned into.
/// * **Forward progress** — the resume cursor strictly advances every respawn (skip
///   ≥ 1 fragment), so the run terminates by exhausting fragments even before the
///   budget; `budget` is the explicit DoS cap.
pub fn resilient_session<F>(run_attempt: F, full_script: &[ClientMsg], budget: u32) -> ResilientOutcome
where
    F: FnMut(&[ClientMsg]) -> (Vec<WorkerMsg>, DriveEnd),
{
    resilient_session_inner(run_attempt, full_script, budget, MAX_SESSION_MSGS, MAX_SESSION_BYTES)
}

/// Owns the resilient driver's canonical (already-decrypted) `ClientMsg` clones —
/// the master `fragments` list kept for the WHOLE window plus each rebuilt resume
/// sub-script. Its `Drop` **zeroizes** every `Fragment`'s plaintext bytes, so the
/// wipe runs on ALL exit paths (Completed / Protective / BudgetExhausted /
/// CapExceeded / an early return / a panic) — mirroring client-app's `ScriptGuard`
/// and the per-attempt writer-thread wipe in [`drive_framed_session_partial`]. Only
/// the driver's OWN clones are wrapped; the caller's borrowed `full_script` is never
/// touched (the caller owns its own zeroizing guard over that).
struct ResumeMaterial(Vec<ClientMsg>);

/// Zeroize every `Fragment`'s already-decrypted plaintext bytes in a script. Shared
/// by [`ResumeMaterial`]'s `Drop` and its unit test, so the wipe is asserted on
/// still-owned data (the `Drop` frees the heap, so it can't be read back soundly).
fn wipe_fragment_plaintext(msgs: &mut [ClientMsg]) {
    for msg in msgs {
        if let ClientMsg::Fragment { bytes, .. } = msg {
            bytes.zeroize();
        }
    }
}

impl Drop for ResumeMaterial {
    fn drop(&mut self) {
        wipe_fragment_plaintext(&mut self.0);
    }
}

/// [`resilient_session`] with the per-window buffering ceilings injected, so the
/// cross-respawn cap behavior is unit-testable with small bounds (the public entry
/// pins the real [`MAX_SESSION_MSGS`] / [`MAX_SESSION_BYTES`]).
fn resilient_session_inner<F>(
    mut run_attempt: F,
    full_script: &[ClientMsg],
    budget: u32,
    max_msgs: usize,
    max_bytes: u64,
) -> ResilientOutcome
where
    F: FnMut(&[ClientMsg]) -> (Vec<WorkerMsg>, DriveEnd),
{
    // Pre-extract the window structure: the `Open` to replay on each respawn (a fresh
    // worker needs it) and the ordered fragment list (each closed-GOP, independently
    // decodable — so resume needs no worker change, just a fresh script).
    let open_msg: Option<ClientMsg> = full_script
        .iter()
        .find(|m| matches!(m, ClientMsg::Open { .. }))
        .cloned();
    // Wrap the canonical-plaintext clones in a zeroize-on-drop guard so the master
    // resume copy is wiped on EVERY exit path (the per-attempt writer-thread copies
    // are already wiped in `drive_framed_session_partial`).
    let fragments = ResumeMaterial(
        full_script
            .iter()
            .filter(|m| matches!(m, ClientMsg::Fragment { .. }))
            .cloned()
            .collect(),
    );
    let frag_seq = |i: usize| -> u32 {
        match &fragments.0[i] {
            ClientMsg::Fragment { seq, .. } => *seq,
            _ => 0,
        }
    };

    let mut msgs: Vec<WorkerMsg> = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut skipped: Vec<u32> = Vec::new();
    let mut respawns: u32 = 0;
    // Index (into `fragments`) of the first fragment THIS attempt (re)starts from.
    let mut next_idx: usize = 0;

    // First attempt = the full script verbatim; later attempts = rebuilt resume
    // scripts. Also guarded: a reassignment drops (wipes) the previous sub-script,
    // and the final value is wiped when this fn returns.
    let mut script = ResumeMaterial(full_script.to_vec());

    loop {
        let (attempt_msgs, end) = run_attempt(&script.0);

        // Cross-respawn bounded accumulation: the SAME per-window ceiling spans the
        // WHOLE resilient run. Count completed fragments (one EndOfFragment each, even
        // for a SOFT-errored fragment — the worker survived those) to locate the culprit.
        let mut completed_in_attempt: usize = 0;
        let mut cap_hit = false;
        for m in attempt_msgs {
            if let WorkerMsg::EndOfFragment { .. } = m {
                completed_in_attempt += 1;
            }
            total_bytes = total_bytes.saturating_add(encode_worker_msg(&m).len() as u64);
            if msgs.len() >= max_msgs || total_bytes > max_bytes {
                cap_hit = true;
                break;
            }
            msgs.push(m);
        }
        if cap_hit {
            return ResilientOutcome {
                msgs,
                skipped,
                respawns,
                terminal: TerminalReason::CapExceeded,
            };
        }

        match end {
            DriveEnd::Completed => {
                return ResilientOutcome {
                    msgs,
                    skipped,
                    respawns,
                    terminal: TerminalReason::Completed,
                };
            }
            DriveEnd::Protective => {
                return ResilientOutcome {
                    msgs,
                    skipped,
                    respawns,
                    terminal: TerminalReason::Protective,
                };
            }
            DriveEnd::WorkerGone => {
                // The culprit is the fragment IN FLIGHT when the worker died = the one
                // right after the last completed fragment (the last `EndOfFragment`) in
                // THIS attempt. With in-order processing, `completed_in_attempt`
                // EndOfFragments mean fragments `next_idx .. next_idx+k` completed and
                // `next_idx + k` was in flight.
                let culprit_idx = next_idx + completed_in_attempt;
                if culprit_idx >= fragments.0.len() {
                    // No fragment remained to be the culprit: every fragment of this
                    // attempt produced its EndOfFragment, so the abort was in teardown
                    // after all frames were emitted — nothing lost. Treat as complete.
                    return ResilientOutcome {
                        msgs,
                        skipped,
                        respawns,
                        terminal: TerminalReason::Completed,
                    };
                }
                if respawns >= budget {
                    // DoS cap: stop rather than spawn another confined worker.
                    return ResilientOutcome {
                        msgs,
                        skipped,
                        respawns,
                        terminal: TerminalReason::BudgetExhausted,
                    };
                }
                // Record + skip the culprit, then resume strictly AFTER it. `next_idx`
                // advances by at least one every respawn (culprit_idx + 1 > next_idx) —
                // forward progress guarantees termination even before the budget.
                skipped.push(frag_seq(culprit_idx));
                next_idx = culprit_idx + 1;
                respawns += 1;
                // Rebuild the resume sub-script: [Open, <fragments after culprit>, Close].
                let mut resume: Vec<ClientMsg> = Vec::new();
                if let Some(o) = &open_msg {
                    resume.push(o.clone());
                }
                resume.extend_from_slice(&fragments.0[next_idx..]);
                resume.push(ClientMsg::Close);
                // Reassigning drops (zeroizes) the previous sub-script's plaintext.
                script = ResumeMaterial(resume);
            }
        }
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

    /// Run ONE worker attempt over `script` for the resilient driver: spawn a FRESH
    /// `--video-session` worker (so every respawn is independently isolated — the
    /// per-fragment skip must NOT relax isolation), drive the partial duplex, then
    /// classify the end by combining the driver's pipe view with the process exit
    /// status (an abnormal exit / kill ⇒ [`DriveEnd::WorkerGone`]; a clean exit after
    /// a clean pipe EOF ⇒ [`DriveEnd::Completed`]).
    fn run_attempt(&self, script: &[ClientMsg]) -> Result<(Vec<WorkerMsg>, DriveEnd), SessionError> {
        let mut child = Command::new(&self.worker_path)
            .arg("--video-session")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(SessionError::Io)?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| SessionError::Io(std::io::Error::other("worker stdin unavailable")))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| SessionError::Io(std::io::Error::other("worker stdout unavailable")))?;

        let (msgs, end) = drive_framed_session_partial(stdin, stdout, script);
        // A parent-side cutoff (`Some`) may leave the worker running; kill so `wait`
        // can't hang. A clean pipe EOF (`None`) means the worker is exiting — don't
        // kill, so `wait` reads its REAL exit status (clean vs abort/kill).
        if end.is_some() {
            let _ = child.kill();
        }
        let status = child.wait().map_err(SessionError::Io)?;
        let drive_end = match end {
            Some(DriveEnd::Protective) => DriveEnd::Protective,
            Some(DriveEnd::WorkerGone) | Some(DriveEnd::Completed) => DriveEnd::WorkerGone,
            // Clean pipe EOF: a clean exit ⇒ Completed; any abnormal exit ⇒ WorkerGone.
            None => {
                if status.success() {
                    DriveEnd::Completed
                } else {
                    DriveEnd::WorkerGone
                }
            }
        };
        Ok((msgs, drive_end))
    }
}

/// Shared adapter from a fallible per-attempt spawner to [`resilient_session`]: a
/// FIRST-attempt launch failure has nothing to salvage → surface it as `Err`; a
/// later respawn that fails to launch ends the run terminally (no respawn into a
/// broken launcher) but keeps what already decoded. Used by both the cross-platform
/// and the AppContainer resilient paths.
fn run_resilient_over<F>(
    mut run_attempt: F,
    script: &[ClientMsg],
    budget: u32,
) -> Result<ResilientOutcome, SessionError>
where
    F: FnMut(&[ClientMsg]) -> Result<(Vec<WorkerMsg>, DriveEnd), SessionError>,
{
    let mut attempt_no: u32 = 0;
    let mut first_launch_err: Option<SessionError> = None;
    let outcome = resilient_session(
        |s| {
            let this = attempt_no;
            attempt_no += 1;
            match run_attempt(s) {
                Ok(pair) => pair,
                Err(e) => {
                    if this == 0 {
                        first_launch_err = Some(e);
                    }
                    // No worker ran: nothing completed, and a broken launcher is not a
                    // hostile input — end terminally (Protective is never respawned into).
                    (Vec::new(), DriveEnd::Protective)
                }
            }
        },
        script,
        budget,
    );
    if let Some(e) = first_launch_err {
        return Err(e);
    }
    Ok(outcome)
}

impl VideoSessionDecoder for VideoSubprocessSession {
    fn run_session(&self, script: &[ClientMsg]) -> Result<Vec<WorkerMsg>, SessionError> {
        self.run_framed(script).map_err(SessionError::Io)
    }

    /// Resilient (respawn-on-abort) override: a worker-process abort mid-window
    /// **skips the one culprit fragment** and respawns a FRESH `--video-session`
    /// worker over the remaining fragments, so one hostile/corrupt fragment drops a
    /// few frames instead of killing playback. Every respawn spawns a brand-new
    /// isolated worker (the skip never relaxes isolation); the respawn count is capped
    /// at `budget` (pass [`MAX_RESPAWNS_PER_WINDOW`]).
    ///
    /// Returns `Err` only if the FIRST worker could not be launched at all (nothing to
    /// salvage); a worker that started and died is the resilient path → `Ok` with the
    /// salvaged frames + the `skipped` culprits.
    fn run_session_resilient(
        &self,
        script: &[ClientMsg],
        budget: u32,
    ) -> Result<ResilientOutcome, SessionError> {
        run_resilient_over(|s| self.run_attempt(s), script, budget)
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

    /// Run ONE **confined** worker attempt over `script` for the resilient driver:
    /// spawn a FRESH AppContainer + Job worker (every respawn is freshly confined —
    /// the per-fragment skip must NOT relax confinement: no keys, no net, the same
    /// memory cap), drive the partial duplex over the confined pipes, then classify
    /// the end by combining the driver's pipe view with the confined process exit
    /// code (an abnormal exit / Job-kill ⇒ [`DriveEnd::WorkerGone`]; a clean exit
    /// after a clean pipe EOF ⇒ [`DriveEnd::Completed`]).
    fn run_attempt(&self, script: &[ClientMsg]) -> Result<(Vec<WorkerMsg>, DriveEnd), SessionError> {
        let ((msgs, end), exit_code) = win32::spawn_confined_session(
            &self.worker_path,
            &["--video-session"],
            self.memory_cap_bytes,
            |writer, reader| drive_framed_session_partial(writer, reader, script),
        )
        .map_err(SessionError::Spawn)?;
        let drive_end = match end {
            // A parent-side defense — definitive, regardless of how the Job-killed
            // worker then exited; never respawned into.
            Some(DriveEnd::Protective) => DriveEnd::Protective,
            Some(DriveEnd::WorkerGone) | Some(DriveEnd::Completed) => DriveEnd::WorkerGone,
            // Clean pipe EOF: exit 0 ⇒ Completed; abnormal exit / Job-kill ⇒ WorkerGone.
            None => {
                if exit_code == 0 {
                    DriveEnd::Completed
                } else {
                    DriveEnd::WorkerGone
                }
            }
        };
        Ok((msgs, drive_end))
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

    /// Resilient (respawn-on-abort) override inside the AppContainer + Job Object: a
    /// confined-worker abort mid-window (the F1 rav1d `abort` / the F2 stsz-OOM
    /// Job-memory kill) **skips the one culprit fragment** and respawns a FRESH
    /// **confined** worker over the remaining fragments — one hostile/corrupt fragment
    /// drops a few frames instead of killing playback, and every respawn stays freshly
    /// confined (no keys, no net, the same memory cap). The respawn count is capped at
    /// `budget` (pass [`MAX_RESPAWNS_PER_WINDOW`]).
    ///
    /// Returns `Err` only if the FIRST confined worker could not be launched at all.
    fn run_session_resilient(
        &self,
        script: &[ClientMsg],
        budget: u32,
    ) -> Result<ResilientOutcome, SessionError> {
        run_resilient_over(|s| self.run_attempt(s), script, budget)
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
    pub fn transcode(&self, req: &TranscodeRequest) -> Result<TranscodeResult, SessionError> {
        let mut stdin_data = Vec::new();
        // Writing into a Vec is infallible; frame the lone request for the worker.
        let _ = framing::write_frame(&mut stdin_data, &encode_transcode_request(req));
        let stdout = self.run_worker(&stdin_data)?;
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
    /// framed request on its stdin, and return the captured stdout.
    #[cfg(windows)]
    fn run_worker(&self, stdin_data: &[u8]) -> Result<Vec<u8>, SessionError> {
        let out = win32::spawn_confined(&self.worker_path, &[], stdin_data, self.memory_cap_bytes)
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
    fn run_worker(&self, stdin_data: &[u8]) -> Result<Vec<u8>, SessionError> {
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

    // ---- resilient (respawn-on-abort) session driver: the headline correctness ----
    // The respawn LOGIC is proven cross-platform with a FAKE `run_attempt` closure
    // (no real worker / abort needed — that's why `resilient_session` is injectable;
    // the real confined OOM-abort → respawn e2e is Task B's job).

    use maxsecu_client_core::video::{I420Frame, VideoBounds};

    fn t_open() -> ClientMsg {
        ClientMsg::Open {
            bounds: VideoBounds::default(),
        }
    }
    fn t_frag(seq: u32) -> ClientMsg {
        ClientMsg::Fragment {
            seq,
            bytes: vec![seq as u8; 4],
        }
    }
    /// `[Open, Fragment(seqs..), Close]` — the canonical window shape.
    fn t_script(seqs: &[u32]) -> Vec<ClientMsg> {
        let mut s = vec![t_open()];
        s.extend(seqs.iter().map(|&q| t_frag(q)));
        s.push(ClientMsg::Close);
        s
    }
    /// A `Video` frame tagged via `pts_ms` so a test can assert exactly which
    /// fragments' frames survived.
    fn t_vid(tag: u64) -> WorkerMsg {
        WorkerMsg::Video(I420Frame {
            width: 2,
            height: 2,
            pts_ms: tag,
            y: vec![0u8; 4],
            u: vec![0u8; 1],
            v: vec![0u8; 1],
        })
    }
    fn t_eof(seq: u32) -> WorkerMsg {
        WorkerMsg::EndOfFragment { seq }
    }
    fn video_tags(msgs: &[WorkerMsg]) -> Vec<u64> {
        msgs.iter()
            .filter_map(|m| match m {
                WorkerMsg::Video(f) => Some(f.pts_ms),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn resilient_abort_after_k_skips_culprit_and_resumes() {
        // s0,s1 decode; the worker DIES on s2 (no EndOfFragment{2}); the respawn over
        // [Open, s3, s4, Close] then completes. One bad fragment drops only its frames.
        let full = t_script(&[0, 1, 2, 3, 4]);
        let responses = [
            (
                vec![WorkerMsg::Ready, t_vid(0), t_eof(0), t_vid(1), t_eof(1)],
                DriveEnd::WorkerGone,
            ),
            (
                vec![WorkerMsg::Ready, t_vid(3), t_eof(3), t_vid(4), t_eof(4)],
                DriveEnd::Completed,
            ),
        ];
        let mut i = 0usize;
        let out = resilient_session(
            |_s| {
                let r = responses[i].clone();
                i += 1;
                r
            },
            &full,
            MAX_RESPAWNS_PER_WINDOW,
        );
        assert_eq!(out.skipped, vec![2], "the culprit s2 is skipped");
        assert_eq!(out.respawns, 1);
        assert_eq!(out.terminal, TerminalReason::Completed);
        // Surviving frames from s0,s1 AND from the resumed s3,s4 accumulate; s2 dropped.
        assert_eq!(video_tags(&out.msgs), vec![0, 1, 3, 4]);
    }

    #[test]
    fn resilient_budget_cap_terminates() {
        // Every attempt dies with NO progress; the run stops at `budget` respawns
        // (terminates — no infinite loop) with BudgetExhausted.
        let full = t_script(&[0, 1, 2, 3, 4]);
        let budget = 2;
        let out = resilient_session(
            |_s| (vec![WorkerMsg::Ready], DriveEnd::WorkerGone),
            &full,
            budget,
        );
        assert_eq!(out.respawns, budget);
        assert_eq!(out.terminal, TerminalReason::BudgetExhausted);
        assert_eq!(out.skipped, vec![0, 1], "skipped one culprit per respawn");
    }

    #[test]
    fn resilient_protective_is_not_respawned() {
        // A parent-side cutoff is terminal — respawning into a hostile signal would
        // amplify it. No respawn, no skip.
        let full = t_script(&[0, 1, 2]);
        let out = resilient_session(
            |_s| (vec![WorkerMsg::Ready, t_vid(0)], DriveEnd::Protective),
            &full,
            MAX_RESPAWNS_PER_WINDOW,
        );
        assert_eq!(out.respawns, 0);
        assert!(out.skipped.is_empty());
        assert_eq!(out.terminal, TerminalReason::Protective);
        assert_eq!(video_tags(&out.msgs), vec![0], "frames before the cutoff are kept");
    }

    #[test]
    fn resilient_forward_progress_terminates_by_exhaustion() {
        // Abort on the FIRST remaining fragment EVERY time, with a budget far larger
        // than the fragment count: the resume cursor strictly advances (skip >= 1), so
        // the run terminates by exhausting fragments — NOT by spinning or hitting the
        // budget. (If the cursor failed to advance this test would hang.)
        let full = t_script(&[0, 1]);
        let out = resilient_session(
            |_s| (vec![WorkerMsg::Ready], DriveEnd::WorkerGone),
            &full,
            100,
        );
        assert_eq!(out.skipped, vec![0, 1], "cursor advanced past every fragment");
        assert_eq!(out.respawns, 2, "two advances, then no fragment remained");
        assert!(out.respawns < 100, "terminated by exhaustion, not the budget");
        assert_eq!(out.terminal, TerminalReason::Completed);
    }

    #[test]
    fn resilient_buffering_is_bounded_across_respawns() {
        // The per-window ceiling spans the WHOLE run: N respawns do NOT buy N× memory.
        // With max_msgs=5, attempt0 (3 msgs) + attempt1 (would add 3 → 6) trips the cap
        // mid-attempt1 → CapExceeded, output bounded at 5 (NOT 6+).
        let full = t_script(&[0, 1, 2, 3]);
        let responses = [
            (vec![WorkerMsg::Ready, t_vid(0), t_eof(0)], DriveEnd::WorkerGone),
            (vec![WorkerMsg::Ready, t_vid(1), t_eof(1)], DriveEnd::WorkerGone),
        ];
        let mut i = 0usize;
        let out = super::resilient_session_inner(
            |_s| {
                let r = responses[i].clone();
                i += 1;
                r
            },
            &full,
            100,
            /* max_msgs */ 5,
            /* max_bytes */ u64::MAX,
        );
        assert_eq!(out.terminal, TerminalReason::CapExceeded);
        assert_eq!(out.msgs.len(), 5, "accumulation bounded across respawns");
        assert_eq!(out.respawns, 1, "tripped the cap on the first respawn");
    }

    #[test]
    fn resilient_byte_ceiling_also_bounds() {
        // The byte companion to MAX_SESSION_BYTES: a tiny max_bytes trips CapExceeded
        // before unbounded accumulation, on the same accounting path.
        let full = t_script(&[0, 1]);
        let out = super::resilient_session_inner(
            |_s| (vec![WorkerMsg::Ready, t_vid(0), t_vid(0)], DriveEnd::WorkerGone),
            &full,
            100,
            /* max_msgs */ usize::MAX,
            /* max_bytes */ 8,
        );
        assert_eq!(out.terminal, TerminalReason::CapExceeded);
    }

    #[test]
    fn resume_material_wipes_fragment_plaintext() {
        // The exact wipe `ResumeMaterial::drop` runs (factored so it can be asserted on
        // still-owned data — Drop frees the heap, so it can't be read back soundly).
        let mut script = vec![t_open(), t_frag(0), ClientMsg::Close];
        if let ClientMsg::Fragment { bytes, .. } = &mut script[1] {
            *bytes = vec![0xABu8; 16]; // clearly non-zero canonical plaintext.
        }
        super::wipe_fragment_plaintext(&mut script);
        match &script[1] {
            ClientMsg::Fragment { bytes, .. } => {
                assert!(bytes.iter().all(|&b| b == 0), "fragment plaintext zeroized");
            }
            _ => panic!("expected a Fragment"),
        }
    }

    #[test]
    fn drive_framed_partial_classifies_clean_and_protective() {
        // The partial driver reports a clean pipe EOF as `None` (defer to exit code)
        // and a parent-side over-ceiling/undecodable cutoff as `Some(Protective)`.
        // Clean EOF: a well-framed Ready then end-of-stream.
        let mut wire = Vec::new();
        framing::write_frame(&mut wire, &encode_worker_msg(&WorkerMsg::Ready)).unwrap();
        let (msgs, end) = drive_framed_session_partial(Vec::new(), std::io::Cursor::new(wire), &[]);
        assert_eq!(msgs, vec![WorkerMsg::Ready]);
        assert_eq!(end, None, "clean pipe EOF defers to the process exit code");

        // Undecodable worker body → parent-side Protective.
        let mut bad = Vec::new();
        framing::write_frame(&mut bad, &[0xFFu8, 0xFF]).unwrap();
        let (_m, end) = drive_framed_session_partial(Vec::new(), std::io::Cursor::new(bad), &[]);
        assert_eq!(end, Some(DriveEnd::Protective));

        // Over-ceiling frame length prefix → parent refused it → Protective.
        let mut over = Vec::new();
        over.extend_from_slice(&((framing::MAX_FRAME_BYTES as u32) + 1).to_le_bytes());
        let (_m, end) = drive_framed_session_partial(Vec::new(), std::io::Cursor::new(over), &[]);
        assert_eq!(end, Some(DriveEnd::Protective));

        // Truncated frame body (worker died mid-frame) → WorkerGone.
        let mut trunc = Vec::new();
        trunc.extend_from_slice(&100u32.to_le_bytes()); // claims 100 bytes, supplies 2
        trunc.extend_from_slice(&[1u8, 2u8]);
        let (_m, end) = drive_framed_session_partial(Vec::new(), std::io::Cursor::new(trunc), &[]);
        assert_eq!(end, Some(DriveEnd::WorkerGone));
    }
}
