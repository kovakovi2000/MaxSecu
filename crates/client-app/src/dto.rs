//! Plain data crossing the Tauri command boundary. No key material, no
//! signed-record interiors, no whole-plaintext buffers ever appear here.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct ConnectRequest {
    pub server: String, // host:port or domain
    pub username: String,
    pub use_tor: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectResponse {
    pub server_id: String, // from the challenge response
}

#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapRequest {
    pub bootstrap_secret: String,
    /// Optional directory to ALSO write the encrypted glass-break keystore into.
    pub save_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GlassbreakResponse {
    pub username: String,
    pub password: String,
    pub user_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FirstAdminRequest {
    pub username: String,
    pub password: String,
    pub bootstrap_secret: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegisterUserRequest {
    pub username: String,
    pub password: String,
    pub voucher: String,
}
