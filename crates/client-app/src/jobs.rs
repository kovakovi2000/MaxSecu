//! In-process registry of staged-but-not-yet-confirmed uploads (preview-before-
//! upload). `stage_upload` builds the encrypted `UploadBundle`, stores it here keyed
//! by a random `job_id`, and returns a preview; `confirm_upload` takes it and runs
//! the network pipeline; `cancel_upload` drops it. The bundle stays in the TCB —
//! it never crosses the Tauri seam.

use std::collections::HashMap;

use tokio::sync::Mutex;

use maxsecu_client_core::UploadBundle;

/// One staged upload held pending the user's confirm. `bundle` carries the signed,
/// encrypted records + ciphertext chunks (never sent to the UI).
pub struct StagedUpload {
    pub bundle: UploadBundle,
    pub file_type: String,
    pub title: String,
    pub total_chunks: u64,
    pub byte_size: u64,
}

/// Managed state: `job_id -> StagedUpload`. Async mutex (commands are async).
pub struct UploadJobs(pub Mutex<HashMap<String, StagedUpload>>);

impl UploadJobs {
    pub fn new() -> Self {
        UploadJobs(Mutex::new(HashMap::new()))
    }
}

impl Default for UploadJobs {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn staged() -> StagedUpload {
        // A real bundle via build_upload (UploadBundle is not Default/Clone).
        use maxsecu_client_core::{build_upload, Identity, PlaintextStreams, UploadParams};
        use maxsecu_crypto::generate_enc_keypair;
        use maxsecu_encoding::types::{FileType, Id, Timestamp};
        let owner = Identity::generate();
        let (_rsk, rpk) = generate_enc_keypair();
        let params = UploadParams {
            owner: &owner,
            owner_id: Id([0x11; 16]),
            owner_key_version: 1,
            file_id: Id([0xF1; 16]),
            file_type: FileType::Blog,
            chunk_size: 4096,
            recovery_pub: rpk,
            recovery_mlkem_pub: None,
            created_at: Timestamp(1_719_500_000_000),
        };
        let streams = PlaintextStreams {
            content: b"hi".to_vec(),
            metadata: None,
            thumbnail: None,
            preview: None,
        };
        let bundle = build_upload(&params, &streams).unwrap();
        StagedUpload {
            bundle,
            file_type: "blog".into(),
            title: "T".into(),
            total_chunks: 1,
            byte_size: 2,
        }
    }

    #[tokio::test]
    async fn insert_then_take_round_trips() {
        let jobs = UploadJobs::new();
        jobs.0.lock().await.insert("job-1".into(), staged());
        assert!(jobs.0.lock().await.contains_key("job-1"));
        let taken = jobs.0.lock().await.remove("job-1");
        assert!(taken.is_some());
        assert_eq!(taken.unwrap().title, "T");
        assert!(jobs.0.lock().await.remove("job-1").is_none()); // gone
    }
}
