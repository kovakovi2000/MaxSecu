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

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[cfg(windows)]
mod win32;
#[cfg(windows)]
pub use win32::{ConfinedOutput, SpawnError};

/// Default per-worker memory cap (decompression-bomb hard kill, media-sandbox §3).
pub const DEFAULT_WORKER_MEMORY_CAP_BYTES: u64 = 512 * 1024 * 1024;

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
