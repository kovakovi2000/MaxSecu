//! Sandboxed media **launcher** (DESIGN §8.1/D30, media-sandbox).
//!
//! The viewer decodes via the native `<video>` element (WebView2), so the
//! confined image/video *decode* worker this crate used to launch
//! (`media-worker`, `SubprocessDecoder`/`AppContainerDecoder`) is retired — it
//! validated no shipping path. What remains is the **author-side** half of this
//! crate: it drives the pinned, embedded `ffmpeg.exe` inside the SAME Windows
//! AppContainer + Job Object confinement (no network capability, a low-IL token
//! that cannot read the user's keys, no child processes, a hard memory cap) that
//! the retired decode worker used, so `ffmpeg` — the top RCE surface on the
//! author side, since it parses arbitrary attacker-authored source media — never
//! runs unconfined. This crate itself links **no codec**; it only spawns the
//! external `ffmpeg.exe` binary and builds/validates its argv
//! ([`ffmpeg_args`]/[`transcode_opts`]).
//!
//! * [`FfmpegLauncher`] — spawns the confined ffmpeg for one transcode job and
//!   returns its exit code + a bounded stderr tail ([`FfmpegOutcome`]), reporting
//!   live progress via [`FfmpegProgress`].
//! * `#[cfg(windows)]` `win32` — the AppContainer + Job Object FFI (the only
//!   `unsafe` in this crate) shared by the ffmpeg confinement.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

pub mod ffmpeg_args;
pub use ffmpeg_args::{
    build_ingest_args, build_probe_args, plan_ingest, H264Encoder, IngestPlan, VideoArg,
};

pub mod probe;
#[cfg(windows)]
pub use probe::probe_source;
pub use probe::{parse_probe, AudioCodec, ProbeResult, VideoCodec};

pub mod transcode_opts;
pub use transcode_opts::{Bitrate, Resolution, TranscodeOptions};

#[cfg(windows)]
mod win32;
#[cfg(windows)]
pub use win32::{
    appcontainer_sid_string, grant_creator_owner_full_control, grant_path_to_appcontainer,
    spawn_confined_exe, ConfinedExeOutput, FfmpegProgress, GrantAccess, PathGrant, SpawnError,
};

/// Default Job-Object memory cap for the confined **ffmpeg** ingest (Task 2.2).
/// AV1 (SVT-AV1) ENCODE is memory-hungry — lookahead + reference buffers — so
/// this is generous. 2 GiB is ample headroom for realistic source media while
/// still hard-killing a runaway/bomb; callers tune it via
/// [`FfmpegLauncher::with_memory_cap`].
#[cfg(windows)]
pub const DEFAULT_FFMPEG_MEMORY_CAP_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// **Progress-based stall timeout** for the confined ffmpeg ingest (Task B). The
/// fixed wall-clock kill is replaced by this: the confined ffmpeg is force-killed
/// only if its `-progress` `out_time` fails to advance for this long (reset on every
/// forward advance), so a legitimately-slow but progressing transcode is NEVER
/// wrongly killed. 90 s of ZERO progress is a hang, not slow work.
#[cfg(windows)]
pub const FFMPEG_STALL_TIMEOUT_MS: u32 = 90_000;

/// **Absolute backstop** for the confined ffmpeg ingest (Task B): even if `out_time`
/// keeps advancing (a progress-spammer), the confined process is terminated past
/// this total wall-clock bound. 1 hour is generous headroom for a large legitimate
/// transcode while still guaranteeing termination.
#[cfg(windows)]
pub const FFMPEG_MAX_TOTAL_MS: u32 = 3_600_000;

/// The outcome of a confined ffmpeg run: ffmpeg's process exit code and a BOUNDED
/// tail of its stderr (diagnostics — its media goes to the granted output file).
/// `exit_code == 0` is success; the CALLER then reads the output file from the
/// per-job dir. `stderr_tail` is capped (head-kept) so a verbose/hostile ffmpeg
/// can't OOM the parent.
#[cfg(windows)]
#[derive(Debug)]
pub struct FfmpegOutcome {
    pub exit_code: u32,
    pub stderr_tail: Vec<u8>,
    /// `true` iff the run was terminated because the caller's `cancel` flag was set
    /// (a user cancel / app shutdown) — a DISTINCT, benign outcome the caller maps to
    /// a `cancelled` error, NOT the sanitized `video_failed` a stall/backstop kill or
    /// a non-zero exit produces.
    pub cancelled: bool,
}

/// Spawn the pinned `ffmpeg.exe` inside the SAME AppContainer + Job Object
/// confinement the decode worker uses (Task 2.2, D-2): NO network capability, a
/// low-IL token that cannot read the user's keys, NO child processes
/// (`ActiveProcessLimit = 1`), a hard memory cap, and kill-on-close +
/// bounded-wait-then-kill (no hang). Filesystem access is scoped to exactly one
/// caller-provided per-job directory via the Task-2.1 path-ACL grant (RAII —
/// revoked after the spawn on every path). ffmpeg reads an input FILE and writes an
/// output FILE in that dir (its MP4 muxer writes `moov` last and cannot stream to a
/// pipe — Phase-0 ratification §2.1); media never crosses stdio (stdin/stdout =
/// NUL), only a bounded stderr tail is captured. This launcher links NO codec — it
/// only spawns the external binary.
#[cfg(windows)]
pub struct FfmpegLauncher {
    ffmpeg_path: PathBuf,
    memory_cap_bytes: u64,
    /// Progress-based stall bound (Task B): kill only after this long with NO
    /// `-progress` advance.
    stall_timeout_ms: u32,
    /// Absolute wall-clock backstop (Task B): kill past this even if progress keeps
    /// advancing (a progress-spammer).
    max_total_ms: u32,
}

#[cfg(windows)]
impl FfmpegLauncher {
    /// `ffmpeg_path` is the absolute path to the pinned `ffmpeg.exe`.
    pub fn new(ffmpeg_path: impl Into<PathBuf>) -> Self {
        FfmpegLauncher {
            ffmpeg_path: ffmpeg_path.into(),
            memory_cap_bytes: DEFAULT_FFMPEG_MEMORY_CAP_BYTES,
            stall_timeout_ms: FFMPEG_STALL_TIMEOUT_MS,
            max_total_ms: FFMPEG_MAX_TOTAL_MS,
        }
    }

    /// As [`new`](Self::new) with an explicit Job-Object memory cap (AV1 encode is
    /// memory-hungry; tune per source/preset).
    pub fn with_memory_cap(ffmpeg_path: impl Into<PathBuf>, cap: u64) -> Self {
        FfmpegLauncher {
            ffmpeg_path: ffmpeg_path.into(),
            memory_cap_bytes: cap,
            stall_timeout_ms: FFMPEG_STALL_TIMEOUT_MS,
            max_total_ms: FFMPEG_MAX_TOTAL_MS,
        }
    }

    /// Override the absolute forced-kill backstop (default [`FFMPEG_MAX_TOTAL_MS`]).
    /// This is a FINITE DoS ceiling, not a soft hint: past it the confined ffmpeg is
    /// terminated regardless of progress. The primary bound is now the progress-based
    /// stall watchdog ([`FFMPEG_STALL_TIMEOUT_MS`], see [`with_stall_timeout`](Self::with_stall_timeout)),
    /// so a legitimately-slow-but-progressing transcode is never wrongly killed.
    pub fn with_timeout(mut self, max_total_ms: u32) -> Self {
        self.max_total_ms = max_total_ms;
        self
    }

    /// Override the progress-based stall timeout (default [`FFMPEG_STALL_TIMEOUT_MS`]):
    /// the confined ffmpeg is killed only after this long with NO `-progress` advance.
    pub fn with_stall_timeout(mut self, stall_timeout_ms: u32) -> Self {
        self.stall_timeout_ms = stall_timeout_ms;
        self
    }

    /// Run ffmpeg confined with `args` (the discrete argv elements — inputs/outputs
    /// are separate elements, not a shell string), granting the AppContainer SID
    /// `ReadWrite` access to `grant_dir` for the spawn only.
    ///
    /// CONTRACT: `grant_dir` MUST be a **fresh, unique, non-symlinked** directory
    /// (the caller creates it under the system temp dir) that already contains the
    /// source as an input file; ffmpeg writes its output file in the SAME dir. The
    /// grant is `ReadWrite` (which also drops the dir to a Low integrity label so the
    /// Low-IL container can write) and is REVOKED when this returns on every path.
    /// The argv must reference only paths inside `grant_dir` — anything outside is
    /// denied by the confinement (proven by the D-2 differential test).
    ///
    /// CLEANUP OBLIGATION (security requirement, not mere hygiene): after this
    /// returns, the CALLER MUST delete the WHOLE `grant_dir`. The dir-grant revoke
    /// restores the directory's prior DACL/label, but the OUTPUT file ffmpeg created
    /// inside it inherited the container-SID allow ACE (and a Low integrity label) at
    /// creation, and that inherited ACE on the child file CANNOT be retroactively
    /// stripped by revoking the dir grant. Wholesale deletion of the per-job dir is
    /// the only correct cleanup — leaving it behind leaves a container-accessible,
    /// Low-IL artifact on disk.
    ///
    /// The run is bounded by a **progress-based stall watchdog** (Task B): the
    /// confined ffmpeg is force-killed only if its `-progress` `out_time` fails to
    /// advance for `stall_timeout_ms` (default [`FFMPEG_STALL_TIMEOUT_MS`]), plus an
    /// absolute `max_total_ms` backstop (default [`FFMPEG_MAX_TOTAL_MS`]).
    /// `on_progress` (Task A) is invoked live per progress tick with a sanitized
    /// [`FfmpegProgress`] (percent + elapsed ms only — no stderr text / paths cross).
    /// `cancel` (Task C) is polled throughout; when set, the child is terminated, the
    /// path grant is revoked (as on every path), and the returned [`FfmpegOutcome`]
    /// has `cancelled == true` (the caller maps that to a distinct `cancelled` error,
    /// NOT the sanitized `video_failed`).
    pub fn run(
        &self,
        args: &[std::ffi::OsString],
        grant_dir: &std::path::Path,
        on_progress: impl Fn(FfmpegProgress) + Send,
        cancel: &AtomicBool,
    ) -> Result<FfmpegOutcome, SpawnError> {
        let out = win32::spawn_confined_exe(
            &self.ffmpeg_path,
            args,
            &[(grant_dir, GrantAccess::ReadWrite)],
            self.memory_cap_bytes,
            self.stall_timeout_ms,
            self.max_total_ms,
            on_progress,
            cancel,
        )?;
        Ok(FfmpegOutcome {
            exit_code: out.exit_code,
            stderr_tail: out.stderr_tail,
            cancelled: out.cancelled,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn ffmpeg_launcher_bounds_are_stall_watchdog_plus_backstop() {
        // The confined ffmpeg ingest is bounded by the progress-based stall watchdog
        // (primary) + a 1-hour absolute DoS backstop — the old fixed 10-min hard cap
        // (DEFAULT_FFMPEG_TIMEOUT_MS) is gone.
        let launcher = FfmpegLauncher::new("ffmpeg.exe");
        assert_eq!(launcher.stall_timeout_ms, FFMPEG_STALL_TIMEOUT_MS);
        assert_eq!(launcher.max_total_ms, FFMPEG_MAX_TOTAL_MS);
    }
}
