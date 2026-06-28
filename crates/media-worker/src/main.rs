//! The decode **worker** process (DESIGN §8.1/D30, media-sandbox §1).
//!
//! Secret-less and network-less by construction: it reads **one** canonical-media
//! request on stdin, runs the bounded pure-Rust decode (no keys, no sockets),
//! writes **one** framed response on stdout, and exits — one worker per file
//! (media-sandbox §2). The launcher ([`SubprocessDecoder`]) and the Windows
//! AppContainer wrapper spawn exactly this binary.
//!
//! [`SubprocessDecoder`]: maxsecu_media_worker::SubprocessDecoder

use maxsecu_client_core::sandbox::{DecodeError, DecodedImage};
use maxsecu_media_worker::{proto, run_decode};
use std::io::{Read, Write};

fn main() {
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
