//! Video transcode bounds (DESIGN §8.1/D30). Pure type; NO codec dependency
//! (codecs live in the confined author-side transcode worker).

/// Pre-decode bounds for video (media-sandbox §3 + spec §2.1). Hard ceilings,
/// checked before any allocation, in the main process AND each worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoBounds {
    pub max_width: u32,
    pub max_height: u32,
    pub max_pixels: u64,
    pub max_duration_ms: u64,
    pub max_framerate: u32,
    pub max_fragment_bytes: u64,
    pub max_total_bytes: u64,
    pub max_fragments: u32,
    pub max_audio_channels: u8,
    pub max_sample_rate: u32,
}

impl Default for VideoBounds {
    fn default() -> Self {
        // Values mirror docs/parameters.md §11 (set in Task 1.4).
        VideoBounds {
            max_width: 7680,
            max_height: 4320,
            max_pixels: 33_177_600, // 8K
            max_duration_ms: 30 * 60 * 1000,
            max_framerate: 120,
            max_fragment_bytes: 16 * 1024 * 1024,
            max_total_bytes: 4 * 1024 * 1024 * 1024,
            max_fragments: 4096,
            max_audio_channels: 2,
            max_sample_rate: 48_000,
        }
    }
}
