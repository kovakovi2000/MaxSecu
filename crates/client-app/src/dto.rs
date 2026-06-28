//! Plain data crossing the Tauri command boundary. No key material, no
//! signed-record interiors, no whole-plaintext buffers ever appear here.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct ConnectRequest {
    pub server: String,        // host:port or domain
    pub use_tor: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectResponse {
    pub server_id: String,     // from the challenge response
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginRequest {
    pub username: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoginResponse {
    pub session_expires_in_s: u64,
}
