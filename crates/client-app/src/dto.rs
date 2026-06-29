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

#[derive(Debug, Clone, Deserialize)]
pub struct AccountStatusRequest {
    pub username: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PendingUserDto {
    pub user_id: String,
    pub username: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct IssueVoucherResponse {
    pub code: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApprovalRequest {
    pub user_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CeremonyWorkItem {
    pub user_id: String,
    pub roles: Vec<String>,
    pub note: String,
}

/// Feed type filter (D35). `All` omits the server `type` param.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FeedFilter {
    All,
    Image,
    Video,
    Blog,
}

/// Client-side sort over the listing.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FeedSort {
    NewestFirst,
    OldestFirst,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListFeedRequest {
    pub filter: FeedFilter,
    pub sort: FeedSort,
    #[serde(default)]
    pub limit: Option<usize>,
}

/// One feed entry — listing metadata only (no decrypted values). The card is
/// decrypted separately by `decrypt_card`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FeedEntryDto {
    pub file_id: String,
    pub file_type: String,
    pub version: u64,
    pub updated_at: u64,
    pub has_thumbnail: bool,
}
