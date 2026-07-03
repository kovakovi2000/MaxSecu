//! `maxsecu-setup` — the operator's one-shot system-bootstrap tool (spec §4).
//!
//! Run ONCE against a freshly-started server. It:
//!   1. generates the ONE system **recovery account** — a hybrid `Identity`
//!      (X25519 + ML-KEM enc key, so every upload's recovery grant stays
//!      `Suite::V2`, plus an Ed25519 sig key);
//!   2. registers the recovery account's PUBLIC keys with the server
//!      (`POST /v1/recovery/register`; 201 first, **409** if already registered);
//!   3. logs in AS the recovery account (channel-bound challenge/response — it
//!      just generated the private key, so it can) to obtain an admin session,
//!      and mints the **first registration key** with it (the first enrollee
//!      becomes admin via the server's atomic first-admin claim);
//!   4. writes THREE cold artifacts — the **sealed** recovery private key
//!      (Argon2id `local_key_blob`, never bare bytes), the canonical
//!      **`recovery_pin.bin`** (the exact bytes the client build embeds), and the
//!      plaintext **first registration key**.
//!
//! The tool NEVER uploads, NEVER logs the private key, and only ever puts PUBLIC
//! keys on the wire. On a 409 (recovery already registered) it writes NOTHING and
//! the caller exits non-zero.

pub mod setup;

pub use setup::{run, SetupError, SetupOpts, SetupReport};
