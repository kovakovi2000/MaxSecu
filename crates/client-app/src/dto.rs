//! Plain data crossing the Tauri command boundary. No key material, no
//! signed-record interiors, no whole-plaintext buffers ever appear here.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct ConnectRequest {
    pub server: String,        // host:port or domain
    pub username: String,
    pub use_tor: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectResponse {
    pub server_id: String,     // from the challenge response
}

// Reserved for the standalone login command surfaced by the UI in a later phase
// (Task 9/10); Phase-1 `connect` folds username into ConnectRequest and returns
// only the public server_id, so these are not yet constructed.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct LoginRequest {
    pub username: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct LoginResponse {
    pub session_expires_in_s: u64,
}
