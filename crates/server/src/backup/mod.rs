//! Server backup & rollback (`docs/superpowers/specs/2026-07-16-server-backup-rollback-design.md`).
//!
//! Gives the operator a way to undo a failed upgrade and to rebuild a dead VPS
//! without ever costing an existing user their account, keys, or uploaded data.
//! Blobs are not bundled: they ride the existing cold tier, and `WriteBackTier`
//! rehydrates a copy on read-miss, so a rebuild needs only the small sealed
//! bundle and the corpus returns lazily, per file, on demand.
//!
//! Nothing here may read the environment. `compat_server_reads_env_only_through_launcher_config`
//! (`crates/portable-server/tests/env_surface.rs`) walks `crates/server/src` too
//! and fails the build on any `env::var("MAXSECU_*")`, so every knob arrives as a
//! function argument.
//!
//! # The engine
//!
//! A bundle lives at `{root}/_backup/<stamp>/{db,state}/<index>` (parts) plus a
//! plaintext `{root}/_backup/<stamp>/manifest/0` hint, all written through
//! [`ColdTier::put_chunk`], which both adapters realize as `{root}/{ref}/{index}`.
//! The `db` and `state` components are **independently sealed** — one
//! [`MxbuSealer`](format::MxbuSealer) each, with its own fresh salt and
//! `nonce_base` — so a `state` part can never open under the `db` key (nor vice
//! versa), and `restore --only state` never fetches a `db/` part. Part 0 of a
//! component is the sealed [`BackupIndex`] (its authenticated table of contents)
//! and is written **last**: its presence is the commit point. Parts `1..=k` are
//! the payload frames, each ≤ `part_size` (≤ 8 MiB) so RAM stays O(part size) for
//! an arbitrarily large `pg_dump`.
//!
//! The plaintext manifest is an **untrusted hint** — anyone with the Dropbox
//! account can rewrite it — so its per-part digests are over the sealed
//! **ciphertext** (never the plaintext: that would be a confirmation oracle over
//! the dump), and [`plan`] aborts if the manifest's `git_sha` hint disagrees with
//! the authenticated `git_sha` inside the sealed index. A `null` sha (no `.git`
//! in the source copy) is written as an empty string and `null ≡ null` is
//! agreement, not a mismatch.
//!
//! The DB *merge* — the one cross-database step — is [`merge::run`], filled in by
//! phase 2 stage 2; this module owns the container, the state extraction, and the
//! plan / dry-run split, and reaches the merge only through
//! [`restore_db_merge`].

pub mod format;
pub mod gate; // stage 2 fills this
#[cfg(feature = "postgres")]
pub mod merge; // stage 2 fills this

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::io::{self, Cursor, Read, Write};
use std::path::{Component as PathComponent, Path, PathBuf};

use maxsecu_crypto::{sha256, Argon2Params};
use maxsecu_encoding::structs::{BackupEntry, BackupIndex, BackupPart};
use maxsecu_encoding::types::{Bytes32, Text, Timestamp};
use maxsecu_encoding::{decode, encode, DecodeError};
use serde::{Deserialize, Serialize};

use crate::blob::BlobError;
use crate::tier::ColdTier;
use format::{MxbuError, MxbuOpener, MxbuSealer, MXBU_HEADER_LEN};

/// AES-256-GCM tag length appended to every sealed part.
const AEAD_TAG_LEN: usize = 16;

/// The most a stored part exceeds its plaintext frame by: the repeated 45-byte
/// `MXBU` header plus the 16-byte AEAD tag.
pub const PART_OVERHEAD: usize = MXBU_HEADER_LEN + AEAD_TAG_LEN;

/// The largest plaintext frame a payload part may carry (8 MiB). Sidesteps
/// Dropbox's 150 MB single-shot cliff without the upload-session API this repo
/// does not have.
pub const MAX_PART_SIZE: usize = 8 * 1024 * 1024;

/// The stored ceiling for a payload part of `part_size` plaintext bytes.
pub fn max_part_bytes(part_size: usize) -> usize {
    part_size + PART_OVERHEAD
}

/// Part 0 (the sealed [`BackupIndex`]) is never the logical last frame — the
/// payload follows it in `part_index` even though it is written last — so its
/// `is_last` AEAD bit is a fixed `false`. Truncation of the payload is caught by
/// the authenticated part list (a missing part is [`BackupError::MissingPart`]),
/// not by part 0's bit; the final *payload* frame still carries `is_last = true`.
const PART0_IS_LAST: bool = false;

// ---- component / mode / scope ----

/// One independently-sealed half of a bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Component {
    /// `pg_dump -Fc` — one opaque archive, carried as the payload with no
    /// per-file [`BackupEntry`] table (only `pg_restore` reads it).
    Db,
    /// unit, drop-ins, `dropbox.env`, `tls/`, `config/` — several files, each a
    /// [`BackupEntry`] so restore can split the concatenated payload back out.
    State,
}

impl Component {
    /// The lowercase path segment this component occupies under a stamp
    /// (`_backup/<stamp>/db` or `.../state`) and its manifest key.
    pub fn as_str(&self) -> &'static str {
        match self {
            Component::Db => "db",
            Component::State => "state",
        }
    }
}

/// How the DB is restored. `Merge` (the default when a live DB exists) adds back
/// only what is missing and never touches a live row; `Replace` is a wholesale
/// `pg_restore --clean` and — over a live DB — the `2a626d6` failure mode by
/// construction, so it requires `--force`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DbMode {
    Merge,
    Replace,
}

/// Which components a backup writes / a restore touches. `code` and `blobs` have
/// no sealed component: `code` is a `git checkout` of the recorded sha, and
/// `blobs` selects no work at all — nothing pre-pulls them, because `WriteBackTier`
/// rehydrates a missing chunk from cold on read-miss. The token is still accepted
/// so no existing invocation starts erroring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Only {
    pub db: bool,
    pub state: bool,
    pub code: bool,
    pub blobs: bool,
}

impl Only {
    /// The default restore: the two sealed components plus a code checkout, no
    /// blob pre-pull.
    pub const fn default_restore() -> Self {
        Only {
            db: true,
            state: true,
            code: true,
            blobs: false,
        }
    }

    /// Just the two sealed components (what a backup writes).
    pub const fn components() -> Self {
        Only {
            db: true,
            state: true,
            code: false,
            blobs: false,
        }
    }

    /// Whether this scope selects the given sealed component.
    pub fn selects(&self, component: Component) -> bool {
        match component {
            Component::Db => self.db,
            Component::State => self.state,
        }
    }
}

impl Default for Only {
    fn default() -> Self {
        Only::default_restore()
    }
}

// ---- errors ----

/// Why a backup or restore step failed. Fail-closed: there is no best-effort
/// path and no partial bundle.
#[derive(Debug)]
pub enum BackupError {
    /// A cold-tier I/O fault.
    Tier(BlobError),
    /// A local filesystem / serialization I/O fault.
    Io(io::Error),
    /// The sealed `MXBU` layer refused a part (wrong passphrase, tamper, reorder,
    /// truncation, a foreign header).
    Mxbu(MxbuError),
    /// The authenticated [`BackupIndex`] did not decode.
    Decode(DecodeError),
    /// A `<stamp>` outside `[0-9A-Za-z-]{1,32}` — it flows into a `blob_ref`.
    BadStamp(String),
    /// A `git_sha` outside `[0-9A-Fa-f]{1,64}`. Like [`BackupError::BadStamp`],
    /// this guards a value that leaves the binary and is acted on by the shell
    /// driver — `restore --only code` prints it and `restore-server.sh` feeds it
    /// to `git checkout`. The **plaintext manifest** is the untrusted source
    /// (anyone with the cold-tier account can rewrite it), and on `--only code`
    /// no sealed component is opened, so nothing else cross-checks it.
    BadGitSha(String),
    /// A `part_size` of 0 or above [`MAX_PART_SIZE`].
    BadPartSize(usize),
    /// A component overflowed `u32::MAX` parts (~32 EiB at 8 MiB parts).
    TooManyParts,
    /// No bundle with this stamp (no readable manifest).
    NoSuchBundle(String),
    /// A part the authenticated index promised is absent from the tier. Part 0
    /// absent means an incomplete upload (part 0 is the commit point).
    MissingPart { component: Component, index: u32 },
    /// A fetched part's ciphertext digest disagrees with the authenticated index
    /// — caught **before** the part is opened, so a truncated/spliced download is
    /// distinguished from a wrong passphrase.
    PartDigestMismatch { component: Component, index: u32 },
    /// A restored state file's plaintext digest disagrees with its
    /// [`BackupEntry`].
    EntryDigestMismatch { path: String },
    /// A state entry's path escaped the staging root (`..`, absolute, prefix).
    UnsafeEntryPath(String),
    /// The declared entry lengths do not sum to the payload actually sealed.
    PayloadLenMismatch { declared: u64, actual: u64 },
    /// The payload is shorter than its entry table claims (corrupt bundle).
    MalformedPayload,
    /// The manifest's plaintext `git_sha` hint disagrees with the authenticated
    /// sha inside a sealed component (or two components disagree). `null ≡ null`
    /// is agreement, never a mismatch.
    GitShaDisagreement {
        hint: Option<String>,
        sealed: Option<String>,
    },
    /// The manifest's plaintext `created_at` hint disagrees with the authenticated
    /// timestamp inside a sealed component. `list_backups` orders bundles — and so
    /// resolves `--from latest` — on the plaintext value, which anyone holding the
    /// cold-tier account can rewrite; the sealed counterpart is right there and
    /// free to check, so a back-dated manifest cannot quietly hand the operator an
    /// older bundle than the one they asked for.
    CreatedAtDisagreement { hint: u64, sealed: u64 },
    /// A selected component is absent from this bundle.
    ComponentMismatch { component: Component },
    /// The manifest's own `stamp` field disagrees with its path.
    StampMismatch { expected: String, found: String },
    /// The tier cannot enumerate (`list_prefix` → `Ok(None)`). An empty backup
    /// list shown to an operator about to roll back is a trap, so this never
    /// collapses to "no bundles".
    TierCannotList,
    /// A backup was requested with no cold tier configured. A backup you wrongly
    /// believe is complete is worse than no backup.
    ColdTierRequired,
    /// A `merge` was requested with no reachable live DB to merge into.
    LiveDbRequired,
    /// `--db-mode replace` over a reachable live DB without `--force`.
    ReplaceOverLiveDbNeedsForce,
    /// The merge's stopped-server precondition failed: the live database still
    /// has other connections. No isolation level makes the gate safe against a
    /// concurrent `delete_file`/`delete_wrap`, so the server must be stopped
    /// first. The caller's live pool must also be `max_connections(1)`, or its
    /// own idle siblings trip this.
    ServerStillConnected { others: i64 },
    /// A user in the backup has re-registered live under a **different**
    /// `user_id`, so their `files` rows carry an `owner_id` no live `users` row
    /// has.
    ///
    /// `users` is merged before `files`, but the bare `ON CONFLICT DO NOTHING`
    /// suppresses only unique/exclusion violations — the `users.username` index
    /// silently drops the backup's row, and the FK on `files.owner_id` is not
    /// deferrable, so Postgres would abort the whole merge on
    /// `files_owner_id_fkey`. Refuse first and name the accounts: a raw FK
    /// message tells the operator nothing about which account to fix, and this is
    /// a data-integrity decision only they can make.
    OwnerUsernameCollision { usernames: Vec<String> },
    /// A Postgres fault from the DB-merge path (phase 2 stage 2).
    #[cfg(feature = "postgres")]
    Db(Box<sqlx::Error>),
}

impl fmt::Display for BackupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackupError::Tier(e) => write!(f, "cold tier: {e}"),
            BackupError::Io(e) => write!(f, "io: {e}"),
            BackupError::Mxbu(e) => write!(f, "sealed part: {e}"),
            BackupError::Decode(e) => write!(f, "backup index decode: {e}"),
            BackupError::BadStamp(s) => write!(f, "invalid backup stamp {s:?}"),
            BackupError::BadGitSha(s) => write!(f, "invalid git sha {s:?}"),
            BackupError::BadPartSize(n) => write!(f, "invalid part size {n}"),
            BackupError::TooManyParts => write!(f, "component exceeds u32::MAX parts"),
            BackupError::NoSuchBundle(s) => write!(f, "no backup bundle {s:?}"),
            BackupError::MissingPart { component, index } => {
                write!(f, "missing {} part {index}", component.as_str())
            }
            BackupError::PartDigestMismatch { component, index } => {
                write!(
                    f,
                    "{} part {index} ciphertext digest mismatch",
                    component.as_str()
                )
            }
            BackupError::EntryDigestMismatch { path } => {
                write!(f, "restored state file {path:?} digest mismatch")
            }
            BackupError::UnsafeEntryPath(p) => write!(f, "unsafe state entry path {p:?}"),
            BackupError::PayloadLenMismatch { declared, actual } => {
                write!(f, "payload is {actual} bytes, entries declare {declared}")
            }
            BackupError::MalformedPayload => write!(f, "payload shorter than its entry table"),
            BackupError::GitShaDisagreement { hint, sealed } => write!(
                f,
                "git sha disagreement: manifest hint {hint:?} vs sealed {sealed:?}"
            ),
            BackupError::CreatedAtDisagreement { hint, sealed } => write!(
                f,
                "created_at disagreement: manifest hint {hint} vs sealed {sealed}"
            ),
            BackupError::ComponentMismatch { component } => {
                write!(f, "bundle has no {} component", component.as_str())
            }
            BackupError::StampMismatch { expected, found } => {
                write!(f, "manifest stamp {found:?} at path {expected:?}")
            }
            BackupError::TierCannotList => write!(f, "cold tier cannot enumerate backups"),
            BackupError::ColdTierRequired => write!(f, "no cold tier configured"),
            BackupError::LiveDbRequired => write!(f, "merge needs a reachable live database"),
            BackupError::ReplaceOverLiveDbNeedsForce => {
                write!(f, "replace over a live database requires --force")
            }
            BackupError::ServerStillConnected { others } => write!(
                f,
                "the live database has {others} other connection(s); \
                 stop the server before merging"
            ),
            BackupError::OwnerUsernameCollision { usernames } => write!(
                f,
                "the backup's account(s) {usernames:?} exist in the live database under a \
                 DIFFERENT user_id, so the files they own cannot be merged; remove or \
                 rename those re-registered accounts in the live database and re-run \
                 the restore"
            ),
            #[cfg(feature = "postgres")]
            BackupError::Db(e) => write!(f, "database: {e}"),
        }
    }
}

impl std::error::Error for BackupError {}

impl From<BlobError> for BackupError {
    fn from(e: BlobError) -> Self {
        BackupError::Tier(e)
    }
}
impl From<io::Error> for BackupError {
    fn from(e: io::Error) -> Self {
        BackupError::Io(e)
    }
}
impl From<MxbuError> for BackupError {
    fn from(e: MxbuError) -> Self {
        BackupError::Mxbu(e)
    }
}
impl From<DecodeError> for BackupError {
    fn from(e: DecodeError) -> Self {
        BackupError::Decode(e)
    }
}
#[cfg(feature = "postgres")]
impl From<sqlx::Error> for BackupError {
    fn from(e: sqlx::Error) -> Self {
        BackupError::Db(Box::new(e))
    }
}

// ---- the pure merge-gate input ----

/// The facts the DB-merge [`gate`] reads from the **live** database — the pure,
/// append-only truth a merge is gated on. Kept a plain value (not a DB handle) so
/// the gate is unit-testable with no Postgres.
///
/// The tombstone gate is `tombstoned(fid) && !live_files.contains(fid)`:
/// `stage_version` re-creates a deleted `file_id` freely, so a bare tombstone
/// filter would refuse to merge a live, current file's lost subtree. A wrap is
/// gated on the `(file_id, version, recipient_id)` membership of `revoked`.
#[derive(Debug, Clone, Default)]
pub struct LiveFacts {
    /// `file_id`s with a `file_tombstones` row.
    pub tombstoned: HashSet<[u8; 16]>,
    /// `file_id`s with a live `files` row.
    pub live_files: HashSet<[u8; 16]>,
    /// live `files.current_version`, keyed by `file_id`.
    pub current_version: HashMap<[u8; 16], i64>,
    /// `(file_id, file_version, recipient_id)` with a `wrap_revocations` row.
    pub revoked: HashSet<([u8; 16], i64, [u8; 16])>,
}

// ---- plans (the driver contract written to `<staging>/plan.json`) ----

/// What a DB restore will do. The `Merge` preview is populated by the merge stage
/// (via [`restore_db_merge`] with `apply = false`); [`plan`] leaves it
/// [`MergePreview::default`].
#[derive(Debug, Clone, Serialize)]
pub enum DbPlan {
    Merge { preview: MergePreview },
    Replace { over_live_db: bool },
}

/// A row-level account of what a merge inserted (or, in a dry run, would insert).
/// Its fields are public so the merge stage fills them; [`plan`] leaves it empty.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MergePreview {
    /// Rows added back per table, in FK order.
    pub per_table_inserts: BTreeMap<String, u64>,
    /// File subtrees skipped because the owner destroyed the file
    /// (`tombstoned && !live_files`).
    pub subtrees_skipped_tombstoned: u64,
    /// `file_key_wraps` rows skipped because a `wrap_revocations` row exists.
    pub wraps_skipped_revoked: u64,
    /// `file_key_wraps` rows skipped because they belong to a superseded version
    /// (`file_version != current_version`).
    pub wraps_skipped_superseded: u64,
    /// Files present in the backup but lost from live, restored whole.
    pub files_restored_whole: u64,
}

/// The state files a restore will reconstruct.
#[derive(Debug, Clone, Serialize)]
pub struct StatePlan {
    pub entries: Vec<StatePlanEntry>,
}

/// One reconstructed state file.
#[derive(Debug, Clone, Serialize)]
pub struct StatePlanEntry {
    pub path: String,
    pub len: u64,
}

/// The commit a `--only code` rollback checks out.
#[derive(Debug, Clone, Serialize)]
pub struct CodePlan {
    pub git_sha: Option<String>,
}

/// Whether a restore will warm local disk by pulling blobs from cold up front.
/// Currently always `false`: blobs need no restore step at all, because
/// `WriteBackTier` rehydrates a copy on read-miss, and no code path here walks blob
/// refs. The field stays so the plan can state that fact rather than stay silent.
#[derive(Debug, Clone, Serialize)]
pub struct BlobsPlan {
    pub prepull: bool,
}

/// The whole plan a restore will carry out — serialized to `<staging>/plan.json`
/// as the shell driver's contract, and printed for `--dry-run`.
#[derive(Debug, Clone, Serialize)]
pub struct RestorePlan {
    pub stamp: String,
    /// The authenticated sha (cross-checked across selected components), or the
    /// manifest hint when only `code`/`blobs` are selected.
    pub git_sha: Option<String>,
    pub db: Option<DbPlan>,
    pub state: Option<StatePlan>,
    pub code: Option<CodePlan>,
    pub blobs: Option<BlobsPlan>,
    pub dry_run: bool,
}

impl fmt::Display for RestorePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "restore plan for {}{}",
            self.stamp,
            if self.dry_run { " (dry run)" } else { "" }
        )?;
        writeln!(
            f,
            "  git sha: {}",
            self.git_sha.as_deref().unwrap_or("<none>")
        )?;
        match &self.db {
            None => writeln!(f, "  db:      (skipped)")?,
            Some(DbPlan::Merge { preview }) => {
                writeln!(f, "  db:      merge")?;
                writeln!(
                    f,
                    "           files restored whole: {}",
                    preview.files_restored_whole
                )?;
                writeln!(
                    f,
                    "           subtrees skipped (tombstoned): {}",
                    preview.subtrees_skipped_tombstoned
                )?;
                writeln!(
                    f,
                    "           wraps skipped (revoked / superseded): {} / {}",
                    preview.wraps_skipped_revoked, preview.wraps_skipped_superseded
                )?;
                for (table, n) in &preview.per_table_inserts {
                    writeln!(f, "           insert {table}: {n}")?;
                }
            }
            Some(DbPlan::Replace { over_live_db }) => writeln!(
                f,
                "  db:      replace{}",
                if *over_live_db {
                    " (OVER LIVE DB — forced)"
                } else {
                    ""
                }
            )?,
        }
        match &self.state {
            None => writeln!(f, "  state:   (skipped)")?,
            Some(s) => {
                writeln!(f, "  state:   {} file(s)", s.entries.len())?;
                for e in &s.entries {
                    writeln!(f, "           {} ({} bytes)", e.path, e.len)?;
                }
            }
        }
        match &self.code {
            None => writeln!(f, "  code:    (skipped)")?,
            Some(c) => writeln!(
                f,
                "  code:    checkout {}",
                c.git_sha.as_deref().unwrap_or("<none>")
            )?,
        }
        if let Some(b) = &self.blobs {
            writeln!(
                f,
                "  blobs:   {}",
                if b.prepull {
                    "pre-pull"
                } else {
                    "no pre-pull — cold blobs rehydrate lazily on read-miss"
                }
            )?;
        }
        Ok(())
    }
}

// ---- metadata / summaries / requests / reports ----

/// What sealing or opening one component yielded: its authenticated sha, its
/// entry table (empty for `db`), and its payload parts (part 0 excluded — it
/// cannot describe itself).
#[derive(Debug, Clone)]
pub struct BundleMeta {
    pub component: Component,
    pub stamp: String,
    pub git_sha: Option<String>,
    pub created_at: u64,
    pub entries: Vec<BackupEntry>,
    pub parts: Vec<BackupPart>,
}

impl BundleMeta {
    /// Total stored parts, including the sealed-index part 0.
    pub fn part_count(&self) -> usize {
        self.parts.len() + 1
    }
}

/// One backup bundle as seen by `list-backups` (read from the plaintext manifest,
/// no passphrase needed).
#[derive(Debug, Clone, Serialize)]
pub struct BackupSummary {
    pub stamp: String,
    pub git_sha: Option<String>,
    pub created_at: u64,
    /// **Total stored parts** for the component, i.e. exactly what
    /// `ls _backup/<stamp>/db/` shows: the payload parts the manifest hints at
    /// PLUS the sealed-index part 0 (which cannot describe itself, so it is not in
    /// the hint list). Same definition as [`BundleMeta::part_count`], which is what
    /// the seal run prints — the two operator-facing numbers must agree, because
    /// this listing is the only passphrase-free way to check a bundle is whole and
    /// a mismatch reads as "a part went missing".
    ///
    /// `0` means the component is ABSENT from the bundle (e.g. sealed `--only db`),
    /// which is why the `+ 1` lives inside the `map_or` closure and not outside it.
    pub db_parts: usize,
    /// Total stored parts for `state`. See [`BackupSummary::db_parts`].
    pub state_parts: usize,
}

/// One state file to seal: its bundle-relative path and its source on disk.
#[derive(Debug, Clone)]
pub struct StateFile {
    pub path: String,
    pub source: PathBuf,
}

/// Everything [`backup`] needs. The `db` payload is a file (streamed O(part
/// size)); the `state` files are small and read whole. The passphrase, stamp,
/// git sha, argon params, part size, and retention are all arguments — this
/// module never reads the environment.
pub struct BackupRequest<'a> {
    pub cold: &'a dyn ColdTier,
    pub passphrase: &'a str,
    pub stamp: &'a str,
    /// `None` when there is no `.git` in the source copy (written as the empty
    /// string; `null ≡ null` is agreement on restore).
    pub git_sha: Option<&'a str>,
    pub only: Only,
    pub argon: Argon2Params,
    pub part_size: usize,
    pub created_at: u64,
    pub keep: usize,
    /// The `pg_dump -Fc` archive, when `only.db`.
    pub db_dump: Option<&'a Path>,
    /// The files to seal as `state`, when `only.state`.
    pub state_files: &'a [StateFile],
}

/// Everything [`plan`] / [`restore`] need.
pub struct RestoreRequest<'a> {
    pub cold: &'a dyn ColdTier,
    pub passphrase: &'a str,
    /// `"latest"` or an exact `<stamp>`.
    pub from: &'a str,
    pub only: Only,
    pub db_mode: DbMode,
    pub dry_run: bool,
    /// Authorizes `replace` over a reachable live DB.
    pub force: bool,
    /// Whether a live DB is reachable (the driver tells us). Drives the
    /// `merge`/`replace` guards.
    pub live_db_present: bool,
    /// Where `restore` extracts the dump, the state files, and `plan.json`.
    pub staging: &'a Path,
}

/// What [`backup`] sealed. The bundle is not yet discoverable — that is
/// [`commit_bundle`], which the caller runs only once the blob copy has succeeded.
#[derive(Debug, Clone)]
pub struct BackupReport {
    pub stamp: String,
    pub components: Vec<BundleMeta>,
}

/// What [`restore`] extracted to staging. The DB *merge* is a separate driver
/// step ([`restore_db_merge`]) — restore only unseals the dump.
#[derive(Debug, Clone)]
pub struct RestoreReport {
    pub stamp: String,
    pub dry_run: bool,
    pub db_dump: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
    pub plan_json: Option<PathBuf>,
    pub restored_state_files: Vec<String>,
}

// ---- the plaintext manifest hint ----

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Manifest {
    stamp: String,
    #[serde(default)]
    git_sha: Option<String>,
    created_at: u64,
    #[serde(default)]
    components: BTreeMap<String, ComponentHint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ComponentHint {
    parts: Vec<PartHint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PartHint {
    len: u64,
    /// The part's **ciphertext** digest, hex — a world-readable file beside the
    /// bundle, so never the plaintext digest.
    digest: String,
}

// ---- small helpers ----

fn component_ref(stamp: &str, component: Component) -> String {
    format!("_backup/{stamp}/{}", component.as_str())
}

fn manifest_ref(stamp: &str) -> String {
    format!("_backup/{stamp}/manifest")
}

/// `<stamp>` flows into a `blob_ref`, so it is validated before use. The tiers'
/// containment guards only reject non-`Normal` path parts — they are a backstop,
/// not this validation.
fn validate_stamp(stamp: &str) -> Result<(), BackupError> {
    let ok = !stamp.is_empty()
        && stamp.len() <= 32
        && stamp
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(BackupError::BadStamp(stamp.to_owned()))
    }
}

/// `git_sha` leaves the binary and is *acted on* by the shell driver — the plan
/// prints `code: checkout <sha>` and `restore-server.sh` scrapes that line into
/// `git checkout '$CODE_SHA'`. So it is validated for the same reason `<stamp>`
/// is, and it needs it more: on `--only code` **no sealed component is opened**
/// (`backup_cli` does not even read a passphrase), so the value in play is the
/// one from the *plaintext* manifest — a file this design explicitly models as
/// attacker-writable ("anyone with the Dropbox account can rewrite it").
/// Unvalidated, an embedded newline injects an extra line into the plan the
/// driver parses, and a `'` escapes the driver's single-quoting.
///
/// `[0-9A-Fa-f]{1,64}` admits every abbreviated and full SHA-1/SHA-256 object id
/// `git rev-parse HEAD` can emit — the only thing that ever produces this field —
/// so no honest bundle is refused. `None` (no checkout at backup time) is
/// untouched: `null ≡ null` stays agreement.
fn validate_git_sha(git_sha: &Option<String>) -> Result<(), BackupError> {
    let Some(s) = git_sha else { return Ok(()) };
    let ok = !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
    if ok {
        Ok(())
    } else {
        Err(BackupError::BadGitSha(s.clone()))
    }
}

fn check_part_size(part_size: usize) -> Result<(), BackupError> {
    if part_size == 0 || part_size > MAX_PART_SIZE {
        Err(BackupError::BadPartSize(part_size))
    } else {
        Ok(())
    }
}

/// Join a bundle-relative entry path under `base`, rejecting any traversal /
/// absolute / prefix component. Path *policy* is the restorer's job, not the
/// codec's (`BackupEntry`'s doc).
fn safe_relative_join(base: &Path, rel: &str) -> Result<PathBuf, BackupError> {
    let relp = Path::new(rel);
    for c in relp.components() {
        match c {
            PathComponent::Normal(_) => {}
            _ => return Err(BackupError::UnsafeEntryPath(rel.to_owned())),
        }
    }
    Ok(base.join(relp))
}

fn opt_to_text(git_sha: Option<&str>) -> Result<Text, BackupError> {
    Text::new(git_sha.unwrap_or("")).map_err(BackupError::Decode)
}

fn text_to_opt(t: &Text) -> Option<String> {
    let s = t.as_str();
    if s.is_empty() {
        None
    } else {
        Some(s.to_owned())
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn json_io(e: serde_json::Error) -> BackupError {
    BackupError::Io(io::Error::other(e))
}

/// Best-effort mode on something [`restore`] just created under staging (Unix
/// only; a no-op elsewhere, where the concept does not exist).
///
/// Restore materializes the plaintext `pg_dump` — every DEK wrap in the system —
/// plus the run-state secrets: the unit file (the only copy of the DB password),
/// `dropbox.env`'s refresh token, `tls/key.der`, and the operational signing seed.
/// The driver leaves that staging tree in place for the whole restore, so the
/// default umask would publish all of it at 0755/0644 to every other local account
/// for minutes. The seal side already refuses to do that with its transient dump
/// dir; its mirror image must not be the hole that undoes the discipline. The
/// `0700` on the enclosing directories is what actually blocks traversal — the
/// per-file `0600` is the belt to that pair of braces.
#[cfg(unix)]
fn harden(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn harden(_path: &Path, _mode: u32) {}

/// Read up to `part_size` bytes, looping until the buffer is full or EOF. A
/// return shorter than `part_size` (including empty) means EOF was reached.
fn read_frame<R: Read>(r: &mut R, part_size: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; part_size];
    let mut filled = 0;
    while filled < part_size {
        let n = r.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    buf.truncate(filled);
    Ok(buf)
}

// ---- the container engine ----

/// Seal one component into `_backup/<stamp>/<component>/*`: chunk `src` into
/// ≤ `part_size` frames sealed under **one** [`MxbuSealer`] (one Argon2id
/// derivation, a fresh salt + `nonce_base`), write them at parts `1..=k`, then
/// seal the [`BackupIndex`] as part 0 and write it **last** (the commit point).
/// RAM stays O(part size).
///
/// `entries` is the payload's file table — empty for `db` (one opaque archive),
/// one entry per file for `state`. When non-empty it must sum to the payload
/// length, so a corrupt caller cannot ship a mismatched table.
#[allow(clippy::too_many_arguments)]
pub async fn seal_component<R: Read>(
    cold: &dyn ColdTier,
    passphrase: &str,
    stamp: &str,
    git_sha: Option<&str>,
    component: Component,
    entries: Vec<BackupEntry>,
    mut src: R,
    argon: Argon2Params,
    part_size: usize,
    created_at: u64,
) -> Result<BundleMeta, BackupError> {
    validate_stamp(stamp)?;
    check_part_size(part_size)?;
    let bref = component_ref(stamp, component);
    let sealer = MxbuSealer::new(passphrase, argon)?; // one Argon2id per component

    // Stream the payload with a one-frame lookahead so `is_last` is exact without
    // buffering the whole payload.
    let mut parts_meta: Vec<BackupPart> = Vec::new();
    let mut total_payload: u64 = 0;
    let mut pending = read_frame(&mut src, part_size)?;
    let mut idx: u32 = 1;
    while !pending.is_empty() {
        let cur = std::mem::take(&mut pending);
        pending = read_frame(&mut src, part_size)?;
        let is_last = pending.is_empty();
        total_payload += cur.len() as u64;
        let sealed = sealer.seal_part(idx, is_last, &cur);
        parts_meta.push(BackupPart {
            len: sealed.len() as u64,
            digest: Bytes32(sha256(&sealed)),
        });
        cold.put_chunk(&bref, idx as u64, sealed).await?;
        idx = idx.checked_add(1).ok_or(BackupError::TooManyParts)?;
    }

    if !entries.is_empty() {
        let declared: u64 = entries.iter().map(|e| e.len).sum();
        if declared != total_payload {
            return Err(BackupError::PayloadLenMismatch {
                declared,
                actual: total_payload,
            });
        }
    }

    let index = BackupIndex {
        git_sha: opt_to_text(git_sha)?,
        entries,
        parts: parts_meta,
        created_at: Timestamp(created_at),
    };
    let body = encode(&index);
    let part0 = sealer.seal_part(0, PART0_IS_LAST, &body);
    cold.put_chunk(&bref, 0, part0).await?; // written LAST — the commit point

    Ok(BundleMeta {
        component,
        stamp: stamp.to_owned(),
        git_sha: text_to_opt(&index.git_sha),
        created_at,
        entries: index.entries,
        parts: index.parts,
    })
}

/// Fetch part 0, derive the key from its own header, and decode the authenticated
/// [`BackupIndex`]. The returned opener carries that key for the payload parts.
async fn read_index(
    cold: &dyn ColdTier,
    passphrase: &str,
    stamp: &str,
    component: Component,
) -> Result<(MxbuOpener, BundleMeta), BackupError> {
    validate_stamp(stamp)?;
    let bref = component_ref(stamp, component);
    let part0 = cold
        .get_chunk(&bref, 0)
        .await?
        .ok_or(BackupError::MissingPart {
            component,
            index: 0,
        })?;
    let opener = MxbuOpener::from_part(passphrase, &part0)?;
    let body = opener.open_part(0, PART0_IS_LAST, &part0)?;
    let index: BackupIndex = decode(&body)?;
    let meta = BundleMeta {
        component,
        stamp: stamp.to_owned(),
        git_sha: text_to_opt(&index.git_sha),
        created_at: index.created_at.0,
        entries: index.entries,
        parts: index.parts,
    };
    Ok((opener, meta))
}

/// Open every payload part of `meta` in order, verifying each part's **ciphertext
/// digest against the authenticated index before opening it**, and append the
/// plaintext to `sink`. RAM stays O(part size).
async fn open_payload<W: Write>(
    cold: &dyn ColdTier,
    opener: &MxbuOpener,
    meta: &BundleMeta,
    mut sink: W,
) -> Result<(), BackupError> {
    let bref = component_ref(&meta.stamp, meta.component);
    let k = meta.parts.len();
    for (pos, part_meta) in meta.parts.iter().enumerate() {
        let index = (pos + 1) as u32;
        let part = cold
            .get_chunk(&bref, index as u64)
            .await?
            .ok_or(BackupError::MissingPart {
                component: meta.component,
                index,
            })?;
        // Integrity off the untrusted tier, before the AEAD — a truncated or
        // spliced download is caught here, distinctly from a wrong passphrase.
        if part.len() as u64 != part_meta.len || sha256(&part) != part_meta.digest.0 {
            return Err(BackupError::PartDigestMismatch {
                component: meta.component,
                index,
            });
        }
        let is_last = pos + 1 == k;
        let plaintext = opener.open_part(index, is_last, &part)?;
        sink.write_all(&plaintext)?;
    }
    Ok(())
}

/// Unseal one whole component into `sink` (read the index, then the payload).
pub async fn open_component<W: Write>(
    cold: &dyn ColdTier,
    passphrase: &str,
    stamp: &str,
    component: Component,
    sink: W,
) -> Result<BundleMeta, BackupError> {
    let (opener, meta) = read_index(cold, passphrase, stamp, component).await?;
    open_payload(cold, &opener, &meta, sink).await?;
    Ok(meta)
}

async fn write_manifest(
    cold: &dyn ColdTier,
    stamp: &str,
    git_sha: Option<&str>,
    created_at: u64,
    metas: &[&BundleMeta],
) -> Result<(), BackupError> {
    let mut components = BTreeMap::new();
    for m in metas {
        let parts = m
            .parts
            .iter()
            .map(|p| PartHint {
                len: p.len,
                digest: hex(&p.digest.0),
            })
            .collect();
        components.insert(m.component.as_str().to_owned(), ComponentHint { parts });
    }
    let manifest = Manifest {
        stamp: stamp.to_owned(),
        git_sha: git_sha.map(|s| s.to_owned()),
        created_at,
        components,
    };
    let bytes = serde_json::to_vec(&manifest).map_err(json_io)?;
    cold.put_chunk(&manifest_ref(stamp), 0, bytes).await?;
    Ok(())
}

async fn read_manifest(cold: &dyn ColdTier, stamp: &str) -> Result<Manifest, BackupError> {
    let bytes = cold
        .get_chunk(&manifest_ref(stamp), 0)
        .await?
        .ok_or_else(|| BackupError::NoSuchBundle(stamp.to_owned()))?;
    let m: Manifest = serde_json::from_slice(&bytes).map_err(json_io)?;
    if m.stamp != stamp {
        return Err(BackupError::StampMismatch {
            expected: stamp.to_owned(),
            found: m.stamp,
        });
    }
    // The manifest is untrusted (plaintext, world-writable on the tier). Its
    // stamp is already pinned to the path above; its git_sha is the other field
    // that leaves this binary and gets acted on by the driver.
    validate_git_sha(&m.git_sha)?;
    Ok(m)
}

/// Enumerate every backup bundle from the plaintext manifests — **no passphrase**.
/// Fails closed when the tier cannot enumerate (`Ok(None)`): an empty list shown
/// to an operator about to roll back would read as "there is nothing to roll back
/// to". `Ok(Some(vec![]))` ("can list, no bundles") is a real empty list.
pub async fn list_backups(cold: &dyn ColdTier) -> Result<Vec<BackupSummary>, BackupError> {
    let stamps = match cold.list_prefix("_backup").await? {
        None => return Err(BackupError::TierCannotList),
        Some(v) => v,
    };
    let mut out = Vec::new();
    for stamp in stamps {
        // A stamp dir with no manifest is an incomplete upload — skip it, never
        // list it as restorable.
        let Some(bytes) = cold.get_chunk(&manifest_ref(&stamp), 0).await? else {
            continue;
        };
        // One truncated or foreign object under `_backup/<x>/manifest/0` must not
        // take the whole enumeration down with it: an operator mid-incident would
        // then be unable to see — or even name — the healthy bundles sitting beside
        // it. The fail-closed rule above is about "cannot enumerate at all", which
        // is a different fact.
        let Ok(m) = serde_json::from_slice::<Manifest>(&bytes) else {
            eprintln!("warning: unreadable manifest for backup {stamp} — skipping it");
            continue;
        };
        // The manifest is ATTACKER-WRITABLE by this design's own model ("anyone with
        // the Dropbox account can rewrite it"), and `m.stamp` is a *self-declared*
        // field — it is not the directory the manifest was found in. Two checks the
        // per-bundle `read_manifest` already makes and this inline parse used to skip:
        //
        //   * `m.stamp != stamp` — a rewritten manifest could make one bundle
        //     impersonate another, so `--from latest` resolves to a stamp whose parts
        //     live somewhere else entirely.
        //   * `validate_stamp` — the value flows into `resolve_stamp` -> `RestorePlan`
        //     -> the driver's `staging=` line and into every `{root}/_backup/<stamp>/…`
        //     ref. Unvalidated it can carry `/`, `..` or an embedded NEWLINE, which
        //     forges an extra line in the plan the shell driver scrapes. `git_sha` is
        //     validated for exactly this reason (see `validate_git_sha` below); the
        //     stamp reached the same places with no guard at all, and on a scope that
        //     opens no sealed component (`--only code`) nothing downstream caught it.
        //
        // Warn-and-skip, not fail: one poisoned manifest must not hide the healthy
        // bundles beside it from an operator mid-incident (same policy as above).
        if m.stamp != stamp {
            eprintln!(
                "warning: manifest under _backup/{stamp} declares stamp {:?} — skipping it",
                m.stamp
            );
            continue;
        }
        if validate_stamp(&m.stamp).is_err() {
            eprintln!("warning: manifest for backup {stamp} has an invalid stamp — skipping it");
            continue;
        }
        // `+ 1` for the sealed index at part 0: the manifest hints only at the
        // PAYLOAD parts (part 0 cannot describe itself), but the operator counting
        // `_backup/<stamp>/db/*` sees part 0 too, and the seal run already printed
        // `BundleMeta::part_count()`, which includes it. Reporting `parts.len()`
        // here made `--list` under-report by exactly one against both of those.
        // The `+ 1` is INSIDE the closure so an absent component still reports 0.
        out.push(BackupSummary {
            db_parts: m.components.get("db").map_or(0, |c| c.parts.len() + 1),
            state_parts: m.components.get("state").map_or(0, |c| c.parts.len() + 1),
            stamp: m.stamp,
            git_sha: m.git_sha,
            created_at: m.created_at,
        });
    }
    out.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.stamp.cmp(&b.stamp))
    });
    Ok(out)
}

/// Keep the newest `keep` bundle stamps, deleting the rest. **Never** touches a
/// blob ref: it only enumerates under `_backup`, and real refs begin with 32 hex
/// chars. A tier that cannot enumerate cannot prune (best-effort, not fatal).
pub async fn prune(cold: &dyn ColdTier, keep: usize) -> Result<Vec<String>, BackupError> {
    prune_protecting(cold, keep, None).await
}

/// [`prune`], but never deleting `protect` — the stamp the calling run just sealed.
///
/// Retention is ordered lexicographically on the stamp, and the run's own bundle is
/// otherwise protected only by the ASSUMPTION that its stamp sorts last. Nothing
/// enforced that. Any backwards step of the wall clock between two backups (NTP
/// correction, a VM restored from a snapshot, a operator fixing a mis-set timezone)
/// produces a new stamp that sorts BEFORE existing ones — and `commit_bundle` would
/// then delete the bundle it had just finished uploading while `backup` went on to
/// print "backup complete" and exit 0. The operator would be told they had a fresh
/// rollback point and have none.
pub async fn prune_protecting(
    cold: &dyn ColdTier,
    keep: usize,
    protect: Option<&str>,
) -> Result<Vec<String>, BackupError> {
    let mut stamps = match cold.list_prefix("_backup").await? {
        None => return Ok(Vec::new()),
        Some(v) => v,
    };
    stamps.sort(); // lexicographic == chronological for the compact timestamp stamp

    // Retention counts BUNDLES, not directory names. A listed name is only a
    // candidate (`ColdTier::list_prefix`'s own contract), and a run that died
    // between its first payload part and its manifest leaves a stamp dir behind
    // that nothing ever removes. Such an orphan is always NEWER than every good
    // bundle, so counting it would evict a real restore point per failed run —
    // silently reducing the retention the operator asked for. Orphans are left
    // alone rather than deleted: they can never displace a bundle, and a
    // concurrent in-flight upload must not be swept out from under itself.
    let mut bundles = Vec::with_capacity(stamps.len());
    for stamp in stamps {
        if cold.get_chunk(&manifest_ref(&stamp), 0).await?.is_some() {
            bundles.push(stamp);
        }
    }
    if bundles.len() <= keep {
        return Ok(Vec::new());
    }
    let cutoff = bundles.len() - keep;
    let victims: Vec<String> = bundles[..cutoff]
        .iter()
        // Never the bundle this run just sealed, wherever its stamp happens to sort.
        .filter(|s| Some(s.as_str()) != protect)
        .cloned()
        .collect();
    for stamp in &victims {
        // The manifest goes FIRST — it is the marker `list_backups` and
        // `read_manifest` treat as "this bundle exists and is restorable", so a
        // cold-tier fault part-way through (exactly what prune must tolerate over
        // Dropbox) has to leave an unlisted orphan, never a listed bundle whose
        // parts are already gone. This is the delete-side mirror of writing part 0
        // last on the seal side.
        cold.delete_stream(&manifest_ref(stamp)).await?;
        cold.delete_stream(&component_ref(stamp, Component::Db))
            .await?;
        cold.delete_stream(&component_ref(stamp, Component::State))
            .await?;
    }
    Ok(victims)
}

// ---- dead-box `--replace` blob-resolution probe (design "Dead-box `--replace`") ----

/// What [`verify_stream_blobs`] found. Deliberately three buckets, not two: a
/// cold-tier **fault** is not evidence of absence, and conflating the two is how a
/// transient Dropbox error turns into "your file is gone".
#[derive(Debug, Default, Clone)]
pub struct BlobResolution {
    /// Streams whose index-0 chunk is genuinely absent from the cold tier —
    /// `Ok(false)`, an authoritative "not there". Carries the owning `file_id` so
    /// the operator gets a list of FILES to audit, not opaque refs.
    pub missing: Vec<([u8; 16], String)>,
    /// Streams whose presence could not be determined: `has_chunk` returned an
    /// error. A tier fault, **not** a missing file. Counted and reported
    /// separately so "we could not check" never reads as "it is gone".
    pub faults: Vec<(String, String)>,
    /// Streams confirmed present on the cold tier.
    pub present: u64,
}

impl BlobResolution {
    /// Every probed stream resolved, with nothing unverifiable.
    pub fn is_clean(&self) -> bool {
        self.missing.is_empty() && self.faults.is_empty()
    }

    /// The distinct files with at least one missing stream, in first-seen order.
    pub fn missing_file_ids(&self) -> Vec<[u8; 16]> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for (fid, _) in &self.missing {
            if seen.insert(*fid) {
                out.push(*fid);
            }
        }
        out
    }
}

/// Probe whether each restored stream's ciphertext still resolves on the cold
/// tier, for the dead-box `--replace` path (with no live DB there are no
/// tombstones, so a replace resurrects files deleted — or rotated — since the
/// backup, and their chunks were already purged).
///
/// **One `has_chunk(blob_ref, 0)` per STREAM, never per chunk.** A removal purges
/// the whole stream (`delete_stream`), so index 0 absent ⟺ the stream is gone;
/// probing every chunk would multiply cold-tier calls by `chunk_count` for no
/// extra signal.
///
/// Never returns `Err` and **never drops a row**: it is an audit, not a repair.
/// Auto-dropping rows whose blobs are unreachable would conflate "the owner
/// deleted this" with "Dropbox hiccuped during the restore" and would permanently
/// destroy live files — the exact break this whole feature exists to prevent. The
/// caller reports; the operator decides.
pub async fn verify_stream_blobs(
    cold: &dyn ColdTier,
    refs: &[([u8; 16], String)],
) -> BlobResolution {
    let mut out = BlobResolution::default();
    for (file_id, blob_ref) in refs {
        match cold.has_chunk(blob_ref, 0).await {
            Ok(true) => out.present += 1,
            Ok(false) => out.missing.push((*file_id, blob_ref.clone())),
            Err(e) => out.faults.push((blob_ref.clone(), e.to_string())),
        }
    }
    out
}

// ---- orchestration ----

/// Seal the selected components into a new bundle. The bundle is **not** published
/// here: [`commit_bundle`] writes the manifest and prunes, once the caller knows the
/// blob copy succeeded. Blobs are **not** here either — they ride the cold tier
/// (DB-driven `backup_copy_refs`, phase 2 stage 2), never the bundle.
pub async fn backup(req: &BackupRequest<'_>) -> Result<BackupReport, BackupError> {
    validate_stamp(req.stamp)?;
    check_part_size(req.part_size)?;
    let mut components: Vec<BundleMeta> = Vec::new();

    if req.only.db {
        let path = req.db_dump.ok_or_else(|| {
            BackupError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "db component selected but no dump path provided",
            ))
        })?;
        let file = std::fs::File::open(path)?;
        let meta = seal_component(
            req.cold,
            req.passphrase,
            req.stamp,
            req.git_sha,
            Component::Db,
            Vec::new(), // db is one opaque archive: no per-file entry table
            file,
            req.argon,
            req.part_size,
            req.created_at,
        )
        .await?;
        components.push(meta);
    }

    if req.only.state {
        let mut entries = Vec::new();
        let mut payload = Vec::new(); // state is a few KB — read whole
        for sf in req.state_files {
            let bytes = std::fs::read(&sf.source)?;
            entries.push(BackupEntry {
                path: Text::new(&sf.path).map_err(BackupError::Decode)?,
                len: bytes.len() as u64,
                digest: Bytes32(sha256(&bytes)),
            });
            payload.extend_from_slice(&bytes);
        }
        let meta = seal_component(
            req.cold,
            req.passphrase,
            req.stamp,
            req.git_sha,
            Component::State,
            entries,
            Cursor::new(payload),
            req.argon,
            req.part_size,
            req.created_at,
        )
        .await?;
        components.push(meta);
    }

    Ok(BackupReport {
        stamp: req.stamp.to_owned(),
        components,
    })
}

/// Publish the bundle [`backup`] sealed: write the plaintext manifest, then prune
/// to `req.keep`. Returns the pruned stamps.
///
/// This is deliberately **not** part of [`backup`]. The manifest is the marker
/// [`list_backups`] — and therefore `--from latest` — keys on, so writing it is the
/// bundle's commit point, and pruning evicts a good older bundle to make room. But
/// the user corpus does not ride the bundle: blobs are copied to cold by the caller
/// (`WriteBackTier::backup_copy_refs`) *after* the seal returns, and that copy can
/// fail. Committing inside [`backup`] would make a run the operator was told FAILED
/// still resolve as `latest`, and it would already have deleted the last complete
/// bundle to do so. A backup you wrongly believe is complete is worse than no
/// backup, so the caller commits only once the blob copy is known complete.
pub async fn commit_bundle(
    req: &BackupRequest<'_>,
    report: &BackupReport,
) -> Result<Vec<String>, BackupError> {
    let refs: Vec<&BundleMeta> = report.components.iter().collect();
    write_manifest(req.cold, req.stamp, req.git_sha, req.created_at, &refs).await?;
    // Protect the bundle we just published: retention sorts lexicographically, and a
    // backwards clock step would otherwise let this call delete its own fresh restore
    // point while `backup` still exits 0 printing "complete".
    prune_protecting(req.cold, req.keep, Some(req.stamp)).await
}

/// Resolve `"latest"` or an exact stamp to a stamp that exists, then read part 0
/// of each selected sealed component, cross-check its authenticated `git_sha`
/// against the manifest hint and any sibling component, and build the plan.
/// Changes nothing — `--dry-run` calls this and prints the result.
pub async fn plan(req: &RestoreRequest<'_>) -> Result<RestorePlan, BackupError> {
    let stamp = resolve_stamp(req.cold, req.from).await?;
    let manifest = read_manifest(req.cold, &stamp).await?;
    let hint = manifest.git_sha.clone();

    let mut sealed_sha: Option<Option<String>> = None;
    let mut db = None;
    let mut state = None;

    if req.only.db {
        if !manifest.components.contains_key(Component::Db.as_str()) {
            return Err(BackupError::ComponentMismatch {
                component: Component::Db,
            });
        }
        let (_opener, meta) = read_index(req.cold, req.passphrase, &stamp, Component::Db).await?;
        reconcile_sha(&mut sealed_sha, &hint, &meta.git_sha)?;
        reconcile_created_at(manifest.created_at, meta.created_at)?;
        db = Some(build_db_plan(req)?);
    }

    if req.only.state {
        if !manifest.components.contains_key(Component::State.as_str()) {
            return Err(BackupError::ComponentMismatch {
                component: Component::State,
            });
        }
        let (_opener, meta) =
            read_index(req.cold, req.passphrase, &stamp, Component::State).await?;
        reconcile_sha(&mut sealed_sha, &hint, &meta.git_sha)?;
        reconcile_created_at(manifest.created_at, meta.created_at)?;
        state = Some(StatePlan {
            entries: meta
                .entries
                .iter()
                .map(|e| StatePlanEntry {
                    path: e.path.as_str().to_owned(),
                    len: e.len,
                })
                .collect(),
        });
    }

    let effective = match &sealed_sha {
        Some(s) => s.clone(),
        None => hint.clone(),
    };
    // Belt and braces. `read_manifest` already validated the hint, and the sealed
    // value is authenticated — but this is the single point where either can escape
    // into `CodePlan` and, from there, into the driver's `git checkout`. With
    // `--only code` NOTHING above ran: `sealed_sha` is still `None`, so `effective`
    // IS the untrusted hint, and that is the case the spec calls the common one.
    validate_git_sha(&effective)?;
    let code = req.only.code.then(|| CodePlan {
        git_sha: effective.clone(),
    });
    // No pre-pull is performed: nothing in `restore` walks blob refs, and
    // `WriteBackTier` rehydrates a missing chunk on the first read-miss anyway. The
    // plan says exactly that instead of asserting a warm-up that never happens — a
    // plan line the operator (and the shell driver that scrapes it) trusts must
    // never describe work the restore does not do.
    let blobs = req.only.blobs.then_some(BlobsPlan { prepull: false });

    Ok(RestorePlan {
        stamp,
        git_sha: effective,
        db,
        state,
        code,
        blobs,
        dry_run: req.dry_run,
    })
}

/// The manifest hint and every selected component's authenticated sha must agree
/// (`null ≡ null` included). `hint != sealed` (with `Option` equality doing the
/// null match) is a disagreement.
fn reconcile_sha(
    seen: &mut Option<Option<String>>,
    hint: &Option<String>,
    sealed: &Option<String>,
) -> Result<(), BackupError> {
    if hint != sealed {
        return Err(BackupError::GitShaDisagreement {
            hint: hint.clone(),
            sealed: sealed.clone(),
        });
    }
    match seen {
        Some(prev) if prev != sealed => Err(BackupError::GitShaDisagreement {
            hint: prev.clone(),
            sealed: sealed.clone(),
        }),
        _ => {
            *seen = Some(sealed.clone());
            Ok(())
        }
    }
}

/// The manifest's plaintext `created_at` and the opened component's authenticated
/// one must agree. Both are written from the same value at seal time, so this holds
/// for every honest bundle — and it is the only thing standing between a rewritten
/// manifest and `list_backups`, which sorts on the plaintext field and hands the
/// last entry to `--from latest`.
fn reconcile_created_at(hint: u64, sealed: u64) -> Result<(), BackupError> {
    if hint != sealed {
        return Err(BackupError::CreatedAtDisagreement { hint, sealed });
    }
    Ok(())
}

fn build_db_plan(req: &RestoreRequest<'_>) -> Result<DbPlan, BackupError> {
    match req.db_mode {
        DbMode::Merge => {
            if !req.live_db_present {
                return Err(BackupError::LiveDbRequired);
            }
            // The row-level preview is the merge stage's to fill.
            Ok(DbPlan::Merge {
                preview: MergePreview::default(),
            })
        }
        DbMode::Replace => {
            if req.live_db_present && !req.force {
                return Err(BackupError::ReplaceOverLiveDbNeedsForce);
            }
            Ok(DbPlan::Replace {
                over_live_db: req.live_db_present,
            })
        }
    }
}

async fn resolve_stamp(cold: &dyn ColdTier, from: &str) -> Result<String, BackupError> {
    if from == "latest" {
        let summaries = list_backups(cold).await?;
        let stamp = summaries
            .into_iter()
            .next_back()
            .map(|s| s.stamp)
            .ok_or_else(|| BackupError::NoSuchBundle("latest".to_owned()))?;
        // Belt AND braces. `list_backups` now drops invalid stamps, but this is the
        // one line every `--from latest` flows through on its way to the plan and to
        // the shell driver, and the explicit branch below has always validated. Do not
        // leave the guard depending on which helper produced the string.
        validate_stamp(&stamp)?;
        Ok(stamp)
    } else {
        validate_stamp(from)?;
        read_manifest(cold, from).await?; // existence: NoSuchBundle if absent
        Ok(from.to_owned())
    }
}

/// Carry out `plan`: extract the selected state files (verifying each plaintext
/// digest) and unseal the `db` dump to `<staging>/db.dump`, then write
/// `<staging>/plan.json`. A dry run writes **nothing**. The DB *merge* is a
/// separate driver step — restore only unseals the dump; `pg_restore` into a
/// scratch DB and [`restore_db_merge`] come after.
pub async fn restore(
    req: &RestoreRequest<'_>,
    plan: &RestorePlan,
) -> Result<RestoreReport, BackupError> {
    if req.dry_run {
        return Ok(RestoreReport {
            stamp: plan.stamp.clone(),
            dry_run: true,
            db_dump: None,
            state_dir: None,
            plan_json: None,
            restored_state_files: Vec::new(),
        });
    }

    std::fs::create_dir_all(req.staging)?;
    harden(req.staging, 0o700);
    let mut report = RestoreReport {
        stamp: plan.stamp.clone(),
        dry_run: false,
        db_dump: None,
        state_dir: None,
        plan_json: None,
        restored_state_files: Vec::new(),
    };

    if plan.state.is_some() {
        let (opener, meta) =
            read_index(req.cold, req.passphrase, &plan.stamp, Component::State).await?;
        let mut payload = Vec::new(); // state is small
        open_payload(req.cold, &opener, &meta, &mut payload).await?;

        let state_dir = req.staging.join("state");
        std::fs::create_dir_all(&state_dir)?;
        harden(&state_dir, 0o700);
        let mut off: usize = 0;
        for e in &meta.entries {
            let len = e.len as usize;
            let end = off.checked_add(len).ok_or(BackupError::MalformedPayload)?;
            if end > payload.len() {
                return Err(BackupError::MalformedPayload);
            }
            let bytes = &payload[off..end];
            if sha256(bytes) != e.digest.0 {
                return Err(BackupError::EntryDigestMismatch {
                    path: e.path.as_str().to_owned(),
                });
            }
            let dest = safe_relative_join(&state_dir, e.path.as_str())?;
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
                harden(parent, 0o700);
            }
            std::fs::write(&dest, bytes)?;
            harden(&dest, 0o600);
            report.restored_state_files.push(e.path.as_str().to_owned());
            off = end;
        }
        report.state_dir = Some(state_dir);
    }

    if plan.db.is_some() {
        let (opener, meta) =
            read_index(req.cold, req.passphrase, &plan.stamp, Component::Db).await?;
        let dump = req.staging.join("db.dump");
        let mut f = std::fs::File::create(&dump)?;
        open_payload(req.cold, &opener, &meta, &mut f).await?;
        f.flush()?;
        harden(&dump, 0o600);
        report.db_dump = Some(dump);
    }

    let plan_path = req.staging.join("plan.json");
    let json = serde_json::to_vec_pretty(plan).map_err(json_io)?;
    std::fs::write(&plan_path, json)?;
    report.plan_json = Some(plan_path);

    Ok(report)
}

/// The one cross-database step, gated on live's tombstones and `current_version`:
/// the driver has already unsealed the dump (via [`restore`]), created the
/// scratch DB and `pg_restore`d into it. `apply = false` is the `--dry-run` /
/// preview path. Filled in by phase 2 stage 2 — this is the call site into
/// [`merge::run`].
#[cfg(feature = "postgres")]
pub async fn restore_db_merge(
    live: &sqlx::PgPool,
    staged: &sqlx::PgPool,
    apply: bool,
) -> Result<MergePreview, BackupError> {
    merge::run(live, staged, apply).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tier::MemoryColdTier;
    use async_trait::async_trait;
    use maxsecu_crypto::ARGON2_FLOOR;

    const PW: &str = "a-long-enough-backup-passphrase";
    const STAMP: &str = "20260716T0000Z";

    fn payload_of(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let r = maxsecu_crypto::random_array::<8>();
        std::env::temp_dir().join(format!("mxbackup_{tag}_{}", hex(&r)))
    }

    /// Seal an opaque (db-style, entry-less) payload.
    async fn seal_blob(
        cold: &dyn ColdTier,
        stamp: &str,
        git_sha: Option<&str>,
        component: Component,
        payload: &[u8],
        part_size: usize,
    ) -> BundleMeta {
        seal_component(
            cold,
            PW,
            stamp,
            git_sha,
            component,
            Vec::new(),
            Cursor::new(payload.to_vec()),
            ARGON2_FLOOR,
            part_size,
            1000,
        )
        .await
        .unwrap()
    }

    async fn listed_stamps(cold: &dyn ColdTier) -> Vec<String> {
        list_backups(cold)
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.stamp)
            .collect()
    }

    /// How many objects the tier actually holds under `_backup/<stamp>/<component>/`
    /// — the `ls` an operator would run.
    async fn tier_part_count(cold: &dyn ColdTier, stamp: &str, component: Component) -> usize {
        cold.list_prefix(&component_ref(stamp, component))
            .await
            .unwrap()
            .expect("the memory tier enumerates")
            .len()
    }

    async fn open_blob(cold: &dyn ColdTier, stamp: &str, component: Component) -> Vec<u8> {
        let mut out = Vec::new();
        open_component(cold, PW, stamp, component, &mut out)
            .await
            .unwrap();
        out
    }

    #[tokio::test]
    async fn bundle_round_trips_across_part_boundaries() {
        let cold = MemoryColdTier::new();
        let payload = payload_of(1000 * 3 + 137);
        let meta = seal_blob(
            &cold,
            STAMP,
            Some("deadbeef"),
            Component::Db,
            &payload,
            1000,
        )
        .await;
        assert!(meta.parts.len() >= 4, "payload must span several parts");
        assert_eq!(meta.git_sha.as_deref(), Some("deadbeef"));
        assert_eq!(open_blob(&cold, STAMP, Component::Db).await, payload);
    }

    #[tokio::test]
    async fn wrong_passphrase_fails_closed() {
        let cold = MemoryColdTier::new();
        seal_blob(&cold, STAMP, None, Component::Db, &payload_of(500), 1000).await;
        let err = read_index(&cold, "a-different-passphrase", STAMP, Component::Db)
            .await
            .unwrap_err();
        assert!(matches!(err, BackupError::Mxbu(MxbuError::Unauthentic)));
    }

    #[tokio::test]
    async fn truncation_is_rejected() {
        let cold = MemoryColdTier::new();
        seal_blob(&cold, STAMP, None, Component::Db, &payload_of(3500), 1000).await;
        let (opener, meta) = read_index(&cold, PW, STAMP, Component::Db).await.unwrap();
        let last = meta.parts.len() as u64;
        cold.delete_chunk(&component_ref(STAMP, Component::Db), last)
            .await
            .unwrap();
        let err = open_payload(&cold, &opener, &meta, &mut Vec::new())
            .await
            .unwrap_err();
        assert!(matches!(err, BackupError::MissingPart { index, .. } if index as u64 == last));
    }

    #[tokio::test]
    async fn reorder_is_rejected() {
        let cold = MemoryColdTier::new();
        seal_blob(&cold, STAMP, None, Component::Db, &payload_of(3500), 1000).await;
        let bref = component_ref(STAMP, Component::Db);
        let c1 = cold.get_chunk(&bref, 1).await.unwrap().unwrap();
        let c2 = cold.get_chunk(&bref, 2).await.unwrap().unwrap();
        cold.put_chunk(&bref, 1, c2).await.unwrap();
        cold.put_chunk(&bref, 2, c1).await.unwrap();
        let (opener, meta) = read_index(&cold, PW, STAMP, Component::Db).await.unwrap();
        let err = open_payload(&cold, &opener, &meta, &mut Vec::new())
            .await
            .unwrap_err();
        assert!(matches!(err, BackupError::PartDigestMismatch { .. }));
    }

    #[tokio::test]
    async fn cross_bundle_splice_is_rejected() {
        // Two bundles, same passphrase — the two-time-pad guard. Each sealer has a
        // fresh salt/nonce_base, so B's ciphertext can never satisfy A's
        // authenticated index (and could not open under A's key either).
        let cold = MemoryColdTier::new();
        seal_blob(&cold, "aaaa", None, Component::Db, &payload_of(2500), 1000).await;
        seal_blob(&cold, "bbbb", None, Component::Db, &payload_of(2500), 1000).await;
        let from_b = cold
            .get_chunk(&component_ref("bbbb", Component::Db), 1)
            .await
            .unwrap()
            .unwrap();
        cold.put_chunk(&component_ref("aaaa", Component::Db), 1, from_b)
            .await
            .unwrap();
        let err = open_component(&cold, PW, "aaaa", Component::Db, &mut Vec::new())
            .await
            .unwrap_err();
        assert!(matches!(err, BackupError::PartDigestMismatch { .. }));
    }

    #[tokio::test]
    async fn part_digest_mismatch_rejects_before_open() {
        let cold = MemoryColdTier::new();
        seal_blob(&cold, STAMP, None, Component::Db, &payload_of(2500), 1000).await;
        let bref = component_ref(STAMP, Component::Db);
        let mut c1 = cold.get_chunk(&bref, 1).await.unwrap().unwrap();
        c1[MXBU_HEADER_LEN + 1] ^= 0x01; // corrupt the ciphertext body
        cold.put_chunk(&bref, 1, c1).await.unwrap();
        let (opener, meta) = read_index(&cold, PW, STAMP, Component::Db).await.unwrap();
        let err = open_payload(&cold, &opener, &meta, &mut Vec::new())
            .await
            .unwrap_err();
        // The digest gate — NOT the AEAD — is what rejects, proving "before open".
        assert!(matches!(
            err,
            BackupError::PartDigestMismatch { index: 1, .. }
        ));
    }

    /// `--only code` opens NO sealed component, so `reconcile_sha` never runs and
    /// the sha in play is the one from the **plaintext, attacker-writable**
    /// manifest. It then leaves the binary as `code: checkout <sha>` and
    /// `restore-server.sh` scrapes that line into `git checkout '$CODE_SHA'` —
    /// so an embedded newline forges plan lines the driver parses (including the
    /// `staging=` path its root `rm -rf` trap consumes) and a `'` escapes the
    /// driver's quoting. Validation is what stands in for the absent cross-check.
    #[tokio::test]
    async fn only_code_refuses_a_malformed_manifest_git_sha() {
        let staging = temp_dir("codeonly");
        let only_code = Only {
            db: false,
            state: false,
            code: true,
            blobs: false,
        };
        for evil in [
            "deadbeef\nstaging=/etc\ncode:    checkout deadbeef",
            "dead'; rm -rf /; echo '",
            "../../etc/passwd",
            "", // empty is not `null`: the writer records absence as None
        ] {
            let cold = MemoryColdTier::new();
            let db = seal_blob(&cold, STAMP, None, Component::Db, &payload_of(64), 1000).await;
            // Only the plaintext manifest is tampered — the sealed side is untouched
            // and is never consulted on this path, which is the whole point.
            write_manifest(&cold, STAMP, Some(evil), 1000, &[&db])
                .await
                .unwrap();
            let req = RestoreRequest {
                cold: &cold,
                passphrase: PW,
                from: STAMP,
                only: only_code,
                db_mode: DbMode::Merge,
                dry_run: true,
                force: false,
                live_db_present: true,
                staging: &staging,
            };
            let err = plan(&req).await.unwrap_err();
            assert!(
                matches!(err, BackupError::BadGitSha(_)),
                "manifest git_sha {evil:?} was accepted (got {err:?})"
            );
        }

        // A real sha still plans fine — the guard must not reject honest bundles.
        let cold = MemoryColdTier::new();
        let db = seal_blob(&cold, STAMP, None, Component::Db, &payload_of(64), 1000).await;
        let sha = "1f0c4bd1e4a0a5b0c8d9e2f3a4b5c6d7e8f90a1b";
        write_manifest(&cold, STAMP, Some(sha), 1000, &[&db])
            .await
            .unwrap();
        let req = RestoreRequest {
            cold: &cold,
            passphrase: PW,
            from: STAMP,
            only: only_code,
            db_mode: DbMode::Merge,
            dry_run: true,
            force: false,
            live_db_present: true,
            staging: &staging,
        };
        let p = plan(&req).await.unwrap();
        assert_eq!(p.code.unwrap().git_sha.as_deref(), Some(sha));
    }

    #[tokio::test]
    async fn git_sha_mismatch_aborts_in_plan() {
        let cold = MemoryColdTier::new();
        let db = seal_blob(
            &cold,
            STAMP,
            Some("deadbeef"),
            Component::Db,
            &payload_of(500),
            1000,
        )
        .await;
        let state = seal_component(
            &cold,
            PW,
            STAMP,
            Some("cafebabe"), // different sha from db
            Component::State,
            Vec::new(),
            Cursor::new(payload_of(500)),
            ARGON2_FLOOR,
            1000,
            1000,
        )
        .await
        .unwrap();
        // Manifest hint matches db but not state.
        write_manifest(&cold, STAMP, Some("deadbeef"), 1000, &[&db, &state])
            .await
            .unwrap();
        let staging = temp_dir("plan");
        let req = RestoreRequest {
            cold: &cold,
            passphrase: PW,
            from: STAMP,
            only: Only::components(),
            db_mode: DbMode::Merge,
            dry_run: true,
            force: false,
            live_db_present: true,
            staging: &staging,
        };
        let err = plan(&req).await.unwrap_err();
        assert!(matches!(err, BackupError::GitShaDisagreement { .. }));
    }

    #[tokio::test]
    async fn cross_component_and_cross_stamp_substitution_rejects() {
        let cold = MemoryColdTier::new();
        seal_blob(&cold, "aaaa", None, Component::Db, &payload_of(2500), 1000).await;
        seal_blob(
            &cold,
            "aaaa",
            None,
            Component::State,
            &payload_of(2500),
            1000,
        )
        .await;
        seal_blob(&cold, "bbbb", None, Component::Db, &payload_of(2500), 1000).await;

        // cross-component: a state part in a db slot.
        let state_part = cold
            .get_chunk(&component_ref("aaaa", Component::State), 1)
            .await
            .unwrap()
            .unwrap();
        cold.put_chunk(&component_ref("aaaa", Component::Db), 1, state_part)
            .await
            .unwrap();
        assert!(
            open_component(&cold, PW, "aaaa", Component::Db, &mut Vec::new())
                .await
                .is_err()
        );

        // cross-stamp: another stamp's part 0 (index) over ours — the payload it
        // now describes lives under a different path, so the digest check fails.
        let other0 = cold
            .get_chunk(&component_ref("bbbb", Component::Db), 0)
            .await
            .unwrap()
            .unwrap();
        cold.put_chunk(&component_ref("aaaa", Component::Db), 0, other0)
            .await
            .unwrap();
        assert!(
            open_component(&cold, PW, "aaaa", Component::Db, &mut Vec::new())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn no_part_exceeds_max_part_bytes() {
        let cold = MemoryColdTier::new();
        let part_size = 1000;
        let meta = seal_blob(
            &cold,
            STAMP,
            None,
            Component::Db,
            &payload_of(part_size * 5 + 7),
            part_size,
        )
        .await;
        assert!(meta.parts.len() >= 5);
        let bref = component_ref(STAMP, Component::Db);
        for i in 1..=meta.parts.len() as u64 {
            let part = cold.get_chunk(&bref, i).await.unwrap().unwrap();
            assert!(
                part.len() <= max_part_bytes(part_size),
                "part {i} is {} bytes, ceiling {}",
                part.len(),
                max_part_bytes(part_size)
            );
        }
    }

    #[tokio::test]
    async fn backup_is_idempotent_and_resumable() {
        let cold = MemoryColdTier::new();
        let payload = payload_of(3500);
        seal_blob(&cold, STAMP, None, Component::Db, &payload, 1000).await;

        // Simulate a crash before the commit point: drop part 0 and a payload part.
        let bref = component_ref(STAMP, Component::Db);
        cold.delete_chunk(&bref, 0).await.unwrap();
        cold.delete_chunk(&bref, 2).await.unwrap();

        // Re-running completes the bundle (idempotent by index).
        seal_blob(&cold, STAMP, None, Component::Db, &payload, 1000).await;
        assert_eq!(open_blob(&cold, STAMP, Component::Db).await, payload);
    }

    /// A tier that cannot enumerate — takes the trait's default `list_prefix`
    /// (`Ok(None)`).
    struct NoListTier {
        inner: MemoryColdTier,
    }
    #[async_trait]
    impl ColdTier for NoListTier {
        async fn put_chunk(&self, r: &str, i: u64, b: Vec<u8>) -> Result<(), BlobError> {
            self.inner.put_chunk(r, i, b).await
        }
        async fn get_chunk(&self, r: &str, i: u64) -> Result<Option<Vec<u8>>, BlobError> {
            self.inner.get_chunk(r, i).await
        }
        async fn chunk_count(&self, r: &str) -> Result<u64, BlobError> {
            self.inner.chunk_count(r).await
        }
        async fn delete_stream(&self, r: &str) -> Result<(), BlobError> {
            self.inner.delete_stream(r).await
        }
        async fn delete_chunk(&self, r: &str, i: u64) -> Result<(), BlobError> {
            self.inner.delete_chunk(r, i).await
        }
        async fn has_chunk(&self, r: &str, i: u64) -> Result<bool, BlobError> {
            self.inner.has_chunk(r, i).await
        }
    }

    #[tokio::test]
    async fn list_backups_fails_closed_when_tier_cannot_list() {
        let cold = NoListTier {
            inner: MemoryColdTier::new(),
        };
        seal_blob(&cold, STAMP, None, Component::Db, &payload_of(500), 1000).await;
        write_manifest_smoke(&cold).await;
        let err = list_backups(&cold).await.unwrap_err();
        assert!(matches!(err, BackupError::TierCannotList));
    }

    async fn write_manifest_smoke(cold: &dyn ColdTier) {
        let meta = read_index(cold, PW, STAMP, Component::Db).await.unwrap().1;
        write_manifest(cold, STAMP, None, 1000, &[&meta])
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn list_backups_empty_when_listing_tier_has_no_bundles() {
        let cold = MemoryColdTier::new();
        assert!(list_backups(&cold).await.unwrap().is_empty());
    }

    // ---- the manifest is attacker-writable: `--from latest` must not trust it ----

    /// Write a raw, hand-forged `manifest/0` under `_backup/<dir>` whose self-declared
    /// `stamp` field is whatever the caller says. This is what an attacker with the
    /// Dropbox account can do — the manifest is plaintext and unauthenticated.
    async fn forge_manifest(cold: &dyn ColdTier, dir: &str, declared: &str, created_at: u64) {
        let json = serde_json::json!({
            "stamp": declared,
            "git_sha": null,
            "created_at": created_at,
            "components": {},
        });
        cold.put_chunk(&manifest_ref(dir), 0, serde_json::to_vec(&json).unwrap())
            .await
            .unwrap();
    }

    /// A stamp carrying an embedded NEWLINE would forge an extra line in the plan the
    /// shell driver scrapes (`staging=` / `db_dump=` / `code: checkout …`). It must
    /// never survive enumeration, and `--from latest` must not resolve to it.
    ///
    /// NB the DIRECTORY name is the poisoned value here, and the manifest declares it
    /// truthfully. That is deliberate: a stamp that merely disagrees with its
    /// directory is caught by the impersonation check below, so a test that poisoned
    /// only the declared field would pass with `validate_stamp` removed and prove
    /// nothing about it. A directory name really can contain a newline on Linux.
    #[tokio::test]
    async fn a_manifest_declaring_a_newline_stamp_is_not_listed_or_resolved() {
        let cold = MemoryColdTier::new();
        let poisoned = "evil\nstaging=x";
        forge_manifest(&cold, poisoned, poisoned, 9000).await;
        let listed = list_backups(&cold).await.unwrap();
        assert!(
            listed.is_empty(),
            "a forged newline stamp was listed: {listed:?}"
        );
        assert!(matches!(
            resolve_stamp(&cold, "latest").await.unwrap_err(),
            BackupError::NoSuchBundle(_)
        ));
    }

    /// A stamp with characters outside `[0-9A-Za-z-]` flows into every
    /// `{root}/_backup/<stamp>/…` ref; the tiers' containment guards are a backstop,
    /// not the gate. Same self-consistent shape as the newline case, for the same
    /// reason.
    #[tokio::test]
    async fn a_manifest_declaring_an_out_of_charset_stamp_is_not_listed() {
        let cold = MemoryColdTier::new();
        let poisoned = "evil..etc";
        forge_manifest(&cold, poisoned, poisoned, 9000).await;
        assert!(
            list_backups(&cold).await.unwrap().is_empty(),
            "an out-of-charset stamp was listed"
        );
    }

    /// Impersonation: a manifest whose `stamp` names a DIFFERENT bundle would make
    /// `--from latest` resolve to a stamp whose parts live somewhere else.
    #[tokio::test]
    async fn a_manifest_whose_stamp_disagrees_with_its_directory_is_skipped() {
        let cold = MemoryColdTier::new();
        forge_manifest(&cold, "20260101T000000Z", "20991231T235959Z", 9000).await;
        let listed = list_backups(&cold).await.unwrap();
        assert!(
            listed.is_empty(),
            "an impersonating manifest was listed: {listed:?}"
        );
    }

    /// The poisoned manifest must not hide a healthy bundle sitting beside it —
    /// warn-and-skip, never fail the whole enumeration.
    #[tokio::test]
    async fn a_poisoned_manifest_does_not_hide_the_healthy_bundle_beside_it() {
        let cold = MemoryColdTier::new();
        forge_manifest(&cold, "evil", "evil\nstaging=/etc", 9999).await;
        forge_manifest(&cold, "20260101T000000Z", "20260101T000000Z", 1000).await;
        let listed = list_backups(&cold).await.unwrap();
        assert_eq!(listed.len(), 1, "{listed:?}");
        assert_eq!(listed[0].stamp, "20260101T000000Z");
        // ...and `latest` picks the healthy one, not the newer forged one.
        assert_eq!(
            resolve_stamp(&cold, "latest").await.unwrap(),
            "20260101T000000Z"
        );
    }

    // ---- dead-box `--replace` blob-resolution probe ----

    /// A tier whose `has_chunk` always FAULTS — the "Dropbox hiccuped" case that
    /// must never be reported as a missing file.
    struct FaultyHasChunk {
        inner: MemoryColdTier,
    }
    #[async_trait]
    impl ColdTier for FaultyHasChunk {
        async fn put_chunk(&self, r: &str, i: u64, b: Vec<u8>) -> Result<(), BlobError> {
            self.inner.put_chunk(r, i, b).await
        }
        async fn get_chunk(&self, r: &str, i: u64) -> Result<Option<Vec<u8>>, BlobError> {
            self.inner.get_chunk(r, i).await
        }
        async fn chunk_count(&self, r: &str) -> Result<u64, BlobError> {
            self.inner.chunk_count(r).await
        }
        async fn delete_stream(&self, r: &str) -> Result<(), BlobError> {
            self.inner.delete_stream(r).await
        }
        async fn delete_chunk(&self, r: &str, i: u64) -> Result<(), BlobError> {
            self.inner.delete_chunk(r, i).await
        }
        async fn has_chunk(&self, _r: &str, _i: u64) -> Result<bool, BlobError> {
            Err(BlobError::new("cold_fault", "429 rate limited"))
        }
    }

    const FID_A: [u8; 16] = [0xA1; 16];
    const FID_B: [u8; 16] = [0xB2; 16];

    /// A present stream resolves; a purged one is reported missing, attributed to
    /// the file that owns it.
    #[tokio::test]
    async fn probe_separates_present_from_purged_streams() {
        let cold = MemoryColdTier::new();
        cold.put_chunk("aaaa/1/Media", 0, vec![1, 2, 3])
            .await
            .unwrap();
        let refs = vec![
            (FID_A, "aaaa/1/Media".to_owned()),
            (FID_B, "bbbb/1/Media".to_owned()), // never written == purged
        ];
        let r = verify_stream_blobs(&cold, &refs).await;
        assert_eq!(r.present, 1);
        assert_eq!(r.missing, vec![(FID_B, "bbbb/1/Media".to_owned())]);
        assert!(r.faults.is_empty());
        assert!(!r.is_clean());
        assert_eq!(r.missing_file_ids(), vec![FID_B]);
    }

    /// THE correction the spec paid for: a tier FAULT is not absence. A probe that
    /// cannot reach the tier must report zero missing files — reporting them as
    /// missing would tell an operator their users' data is gone because Dropbox
    /// rate-limited the audit.
    #[tokio::test]
    async fn a_tier_fault_is_never_reported_as_a_missing_file() {
        let cold = FaultyHasChunk {
            inner: MemoryColdTier::new(),
        };
        let refs = vec![
            (FID_A, "aaaa/1/Media".to_owned()),
            (FID_B, "bbbb/1/Media".to_owned()),
        ];
        let r = verify_stream_blobs(&cold, &refs).await;
        assert!(
            r.missing.is_empty(),
            "a fault must NOT be counted as a missing file: {:?}",
            r.missing
        );
        assert_eq!(r.faults.len(), 2, "both probes are unverifiable");
        assert_eq!(r.present, 0);
        assert!(!r.is_clean(), "unverifiable is not clean either");
    }

    /// Several streams of the SAME file are reported as one file to audit.
    #[tokio::test]
    async fn missing_streams_collapse_to_distinct_file_ids() {
        let cold = MemoryColdTier::new();
        let refs = vec![
            (FID_A, "aaaa/1/Media".to_owned()),
            (FID_A, "aaaa/1/Thumbnail".to_owned()),
            (FID_B, "bbbb/1/Media".to_owned()),
        ];
        let r = verify_stream_blobs(&cold, &refs).await;
        assert_eq!(r.missing.len(), 3);
        assert_eq!(r.missing_file_ids(), vec![FID_A, FID_B]);
    }

    /// A fully-resolvable corpus is clean — the no-warning case must really mean
    /// "every file is intact", which is the whole reason the probe exists.
    #[tokio::test]
    async fn a_fully_resolvable_corpus_is_clean() {
        let cold = MemoryColdTier::new();
        cold.put_chunk("aaaa/1/Media", 0, vec![1]).await.unwrap();
        cold.put_chunk("bbbb/1/Media", 0, vec![2]).await.unwrap();
        let refs = vec![
            (FID_A, "aaaa/1/Media".to_owned()),
            (FID_B, "bbbb/1/Media".to_owned()),
        ];
        let r = verify_stream_blobs(&cold, &refs).await;
        assert!(r.is_clean());
        assert_eq!(r.present, 2);
        assert!(r.missing_file_ids().is_empty());
    }

    /// Only index 0 is ever probed — one HEAD per stream, not per chunk.
    #[tokio::test]
    async fn probe_touches_only_index_zero() {
        let cold = MemoryColdTier::new();
        // Index 0 present, later indices absent: a per-chunk probe would call this
        // missing; a per-stream probe correctly calls it present.
        cold.put_chunk("aaaa/1/Media", 0, vec![1]).await.unwrap();
        let refs = vec![(FID_A, "aaaa/1/Media".to_owned())];
        let r = verify_stream_blobs(&cold, &refs).await;
        assert!(r.is_clean());
        assert_eq!(r.present, 1);
    }

    /// A tier that panics if any `db` part is fetched — proves a `--only state`
    /// restore never downloads the dump.
    struct PanicOnDbGet {
        inner: MemoryColdTier,
    }
    #[async_trait]
    impl ColdTier for PanicOnDbGet {
        async fn put_chunk(&self, r: &str, i: u64, b: Vec<u8>) -> Result<(), BlobError> {
            self.inner.put_chunk(r, i, b).await
        }
        async fn get_chunk(&self, r: &str, i: u64) -> Result<Option<Vec<u8>>, BlobError> {
            assert!(
                !(r.starts_with("_backup/") && r.ends_with("/db")),
                "restore fetched a db part: {r}"
            );
            self.inner.get_chunk(r, i).await
        }
        async fn chunk_count(&self, r: &str) -> Result<u64, BlobError> {
            self.inner.chunk_count(r).await
        }
        async fn delete_stream(&self, r: &str) -> Result<(), BlobError> {
            self.inner.delete_stream(r).await
        }
        async fn delete_chunk(&self, r: &str, i: u64) -> Result<(), BlobError> {
            self.inner.delete_chunk(r, i).await
        }
        async fn has_chunk(&self, r: &str, i: u64) -> Result<bool, BlobError> {
            self.inner.has_chunk(r, i).await
        }
        async fn list_prefix(&self, p: &str) -> Result<Option<Vec<String>>, BlobError> {
            self.inner.list_prefix(p).await
        }
    }

    #[tokio::test]
    async fn restore_only_state_never_touches_db_parts() {
        let cold = PanicOnDbGet {
            inner: MemoryColdTier::new(),
        };
        // A complete bundle: db + state + manifest.
        let db = seal_blob(&cold, STAMP, None, Component::Db, &payload_of(2000), 1000).await;
        let state_files = [StateFile {
            path: "dropbox.env".to_owned(),
            source: PathBuf::new(),
        }];
        let state_bytes = b"MAXSECU_COLD_TIER=fs\n".to_vec();
        let state = seal_component(
            &cold,
            PW,
            STAMP,
            None,
            Component::State,
            vec![BackupEntry {
                path: Text::new(&state_files[0].path).unwrap(),
                len: state_bytes.len() as u64,
                digest: Bytes32(sha256(&state_bytes)),
            }],
            Cursor::new(state_bytes.clone()),
            ARGON2_FLOOR,
            1000,
            1000,
        )
        .await
        .unwrap();
        write_manifest(&cold, STAMP, None, 1000, &[&db, &state])
            .await
            .unwrap();

        let staging = temp_dir("onlystate");
        let req = RestoreRequest {
            cold: &cold,
            passphrase: PW,
            from: STAMP,
            only: Only {
                db: false,
                state: true,
                code: false,
                blobs: false,
            },
            db_mode: DbMode::Merge,
            dry_run: false,
            force: false,
            live_db_present: true,
            staging: &staging,
        };
        let the_plan = plan(&req).await.unwrap();
        let report = restore(&req, &the_plan).await.unwrap();
        assert!(report.db_dump.is_none());
        let restored = std::fs::read(staging.join("state").join("dropbox.env")).unwrap();
        assert_eq!(restored, state_bytes);
        let _ = std::fs::remove_dir_all(&staging);
    }

    #[tokio::test]
    async fn dry_run_writes_nothing() {
        let cold = MemoryColdTier::new();
        let db = seal_blob(&cold, STAMP, None, Component::Db, &payload_of(500), 1000).await;
        write_manifest(&cold, STAMP, None, 1000, &[&db])
            .await
            .unwrap();
        let staging = temp_dir("dry");
        let req = RestoreRequest {
            cold: &cold,
            passphrase: PW,
            from: STAMP,
            only: Only {
                db: true,
                state: false,
                code: false,
                blobs: false,
            },
            db_mode: DbMode::Merge,
            dry_run: true,
            force: false,
            live_db_present: true,
            staging: &staging,
        };
        let the_plan = plan(&req).await.unwrap();
        let report = restore(&req, &the_plan).await.unwrap();
        assert!(report.dry_run && report.plan_json.is_none());
        assert!(!staging.exists(), "a dry run created the staging dir");
    }

    #[tokio::test]
    async fn stamp_with_a_traversal_component_is_rejected() {
        for bad in [
            "../evil",
            "a/b",
            "",
            "under_score",
            "toolong-toolong-toolong-toolong-x",
        ] {
            assert!(validate_stamp(bad).is_err(), "{bad:?} should be rejected");
        }
        assert!(validate_stamp("20260716T0000Z").is_ok());
        // The seal path validates too, before writing anything.
        let cold = MemoryColdTier::new();
        let err = seal_blob_result(&cold, "../evil").await.unwrap_err();
        assert!(matches!(err, BackupError::BadStamp(_)));
    }

    async fn seal_blob_result(cold: &dyn ColdTier, stamp: &str) -> Result<BundleMeta, BackupError> {
        seal_component(
            cold,
            PW,
            stamp,
            None,
            Component::Db,
            Vec::new(),
            Cursor::new(payload_of(10)),
            ARGON2_FLOOR,
            1000,
            1000,
        )
        .await
    }

    /// A backwards clock step (NTP correction, a VM restored from a snapshot, a
    /// mis-set timezone being fixed) makes the NEW bundle's stamp sort BEFORE the
    /// existing ones. Retention is lexicographic, so without an explicit guard
    /// `commit_bundle` deletes the bundle it has just finished uploading — while
    /// `backup` goes on to print "complete" and exit 0, telling the operator they have
    /// a fresh rollback point they do not have.
    #[tokio::test]
    async fn commit_never_prunes_the_bundle_this_run_just_sealed() {
        let cold = MemoryColdTier::new();
        // Two existing bundles, both stamped LATER than the one we are about to seal.
        for stamp in ["20260601T000000Z", "20260602T000000Z"] {
            let m = seal_blob(&cold, stamp, None, Component::Db, &payload_of(300), 1000).await;
            write_manifest(&cold, stamp, None, 1000, &[&m])
                .await
                .unwrap();
        }
        // The clock stepped back: this run's stamp sorts FIRST of the three.
        let fresh = "20260101T000000Z";
        let m = seal_blob(&cold, fresh, None, Component::Db, &payload_of(300), 1000).await;
        write_manifest(&cold, fresh, None, 1000, &[&m])
            .await
            .unwrap();

        let pruned = prune_protecting(&cold, 2, Some(fresh)).await.unwrap();
        assert!(
            !pruned.contains(&fresh.to_owned()),
            "retention deleted the bundle this run just sealed: {pruned:?}"
        );
        assert!(
            cold.get_chunk(&manifest_ref(fresh), 0)
                .await
                .unwrap()
                .is_some(),
            "the fresh bundle's manifest was deleted — `--from latest` has no restore point"
        );
    }

    #[tokio::test]
    async fn retention_prunes_oldest_and_never_touches_blobs() {
        let cold = MemoryColdTier::new();
        // A real blob ref — 32 hex chars, never under `_backup`.
        let blob = "aabbccddeeff00112233445566778899/1/1";
        cold.put_chunk(blob, 0, vec![0xAB; 8]).await.unwrap();

        for stamp in ["20260101T000000Z", "20260102T000000Z", "20260103T000000Z"] {
            let m = seal_blob(&cold, stamp, None, Component::Db, &payload_of(300), 1000).await;
            write_manifest(&cold, stamp, None, 1000, &[&m])
                .await
                .unwrap();
        }

        let pruned = prune(&cold, 2).await.unwrap();
        assert_eq!(pruned, vec!["20260101T000000Z".to_owned()]);
        // Oldest gone, newer kept.
        assert_eq!(
            cold.chunk_count(&component_ref("20260101T000000Z", Component::Db))
                .await
                .unwrap(),
            0
        );
        assert!(cold
            .get_chunk(&manifest_ref("20260101T000000Z"), 0)
            .await
            .unwrap()
            .is_none());
        assert!(cold
            .get_chunk(&manifest_ref("20260103T000000Z"), 0)
            .await
            .unwrap()
            .is_some());
        // The real blob is untouched.
        assert_eq!(cold.chunk_count(blob).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn replace_over_live_db_needs_force() {
        let cold = MemoryColdTier::new();
        let db = seal_blob(&cold, STAMP, None, Component::Db, &payload_of(300), 1000).await;
        write_manifest(&cold, STAMP, None, 1000, &[&db])
            .await
            .unwrap();
        let staging = temp_dir("force");
        let base = |force| RestoreRequest {
            cold: &cold,
            passphrase: PW,
            from: STAMP,
            only: Only {
                db: true,
                state: false,
                code: false,
                blobs: false,
            },
            db_mode: DbMode::Replace,
            dry_run: true,
            force,
            live_db_present: true,
            staging: &staging,
        };
        assert!(matches!(
            plan(&base(false)).await.unwrap_err(),
            BackupError::ReplaceOverLiveDbNeedsForce
        ));
        let forced = plan(&base(true)).await.unwrap();
        assert!(matches!(
            forced.db,
            Some(DbPlan::Replace { over_live_db: true })
        ));
    }

    #[tokio::test]
    async fn merge_needs_a_live_db() {
        let cold = MemoryColdTier::new();
        let db = seal_blob(&cold, STAMP, None, Component::Db, &payload_of(300), 1000).await;
        write_manifest(&cold, STAMP, None, 1000, &[&db])
            .await
            .unwrap();
        let staging = temp_dir("merge");
        let req = RestoreRequest {
            cold: &cold,
            passphrase: PW,
            from: STAMP,
            only: Only {
                db: true,
                state: false,
                code: false,
                blobs: false,
            },
            db_mode: DbMode::Merge,
            dry_run: true,
            force: false,
            live_db_present: false,
            staging: &staging,
        };
        assert!(matches!(
            plan(&req).await.unwrap_err(),
            BackupError::LiveDbRequired
        ));
    }

    #[tokio::test]
    async fn state_round_trips_and_verifies_each_entry() {
        let cold = MemoryColdTier::new();
        let a = b"unit=maxsecu-server\n".to_vec();
        let b = b"refresh_token=SECRET\n".to_vec();
        let entries = vec![
            BackupEntry {
                path: Text::new("maxsecu-server.service").unwrap(),
                len: a.len() as u64,
                digest: Bytes32(sha256(&a)),
            },
            BackupEntry {
                path: Text::new("dropbox.env").unwrap(),
                len: b.len() as u64,
                digest: Bytes32(sha256(&b)),
            },
        ];
        let mut payload = a.clone();
        payload.extend_from_slice(&b);
        let state = seal_component(
            &cold,
            PW,
            STAMP,
            Some("beadfeed"),
            Component::State,
            entries,
            Cursor::new(payload),
            ARGON2_FLOOR,
            1000,
            1000,
        )
        .await
        .unwrap();
        write_manifest(&cold, STAMP, Some("beadfeed"), 1000, &[&state])
            .await
            .unwrap();

        let staging = temp_dir("state");
        let req = RestoreRequest {
            cold: &cold,
            passphrase: PW,
            from: "latest",
            only: Only {
                db: false,
                state: true,
                code: true,
                blobs: false,
            },
            db_mode: DbMode::Merge,
            dry_run: false,
            force: false,
            live_db_present: false,
            staging: &staging,
        };
        let the_plan = plan(&req).await.unwrap();
        assert_eq!(the_plan.git_sha.as_deref(), Some("beadfeed"));
        assert_eq!(
            the_plan.code.as_ref().unwrap().git_sha.as_deref(),
            Some("beadfeed")
        );
        let report = restore(&req, &the_plan).await.unwrap();
        assert_eq!(report.restored_state_files.len(), 2);
        assert_eq!(
            std::fs::read(staging.join("state").join("maxsecu-server.service")).unwrap(),
            a
        );
        assert_eq!(
            std::fs::read(staging.join("state").join("dropbox.env")).unwrap(),
            b
        );
        assert!(staging.join("plan.json").exists());
        let _ = std::fs::remove_dir_all(&staging);
    }

    #[tokio::test]
    async fn backup_end_to_end_over_files_lists_and_reopens() {
        let cold = MemoryColdTier::new();
        let dir = temp_dir("e2e");
        std::fs::create_dir_all(&dir).unwrap();
        let dump_path = dir.join("db.dump");
        let dump = payload_of(2600);
        std::fs::write(&dump_path, &dump).unwrap();
        let unit_path = dir.join("maxsecu-server.service");
        std::fs::write(&unit_path, b"unit body\n").unwrap();

        let state_files = [StateFile {
            path: "maxsecu-server.service".to_owned(),
            source: unit_path,
        }];
        let req = BackupRequest {
            cold: &cold,
            passphrase: PW,
            stamp: STAMP,
            git_sha: Some("abc123"),
            only: Only::components(),
            argon: ARGON2_FLOOR,
            part_size: 1000,
            created_at: 42,
            keep: 10,
            db_dump: Some(&dump_path),
            state_files: &state_files,
        };
        let report = backup(&req).await.unwrap();
        assert_eq!(report.components.len(), 2);
        assert!(commit_bundle(&req, &report).await.unwrap().is_empty());

        let summaries = list_backups(&cold).await.unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].stamp, STAMP);
        assert_eq!(summaries[0].git_sha.as_deref(), Some("abc123"));
        assert!(summaries[0].db_parts >= 3);

        assert_eq!(open_blob(&cold, STAMP, Component::Db).await, dump);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `list-backups` is the ONLY passphrase-free way an operator can check a bundle
    /// is complete, and on a real VPS they check it against `ls _backup/<stamp>/db/`.
    /// The manifest hints only at the PAYLOAD parts (part 0, the sealed index, cannot
    /// describe itself), so a summary built from `parts.len()` reported one FEWER than
    /// both the objects on the tier and the `db: N part(s)` line the SAME run had
    /// already printed from [`BundleMeta::part_count`]. An operator who reads
    /// "db: 2 part(s)" at seal time and `db=1` at list time sees a bundle that looks
    /// truncated but is whole — and may discard it, or (reading the gap the other way)
    /// trust a genuinely truncated one. Pins all three numbers to each other.
    #[tokio::test]
    async fn list_reports_the_same_part_count_as_the_seal_run_and_the_tier() {
        let cold = MemoryColdTier::new();
        let dir = temp_dir("partcount");
        std::fs::create_dir_all(&dir).unwrap();
        // Small enough that each component is ONE payload part + the index: the exact
        // `db/0 db/1 state/0 state/1` shape the off-by-one was observed on.
        let dump_path = dir.join("db.dump");
        std::fs::write(&dump_path, payload_of(64)).unwrap();
        let unit_path = dir.join("maxsecu-server.service");
        std::fs::write(&unit_path, b"unit body\n").unwrap();
        let state_files = [StateFile {
            path: "maxsecu-server.service".to_owned(),
            source: unit_path,
        }];
        let req = BackupRequest {
            cold: &cold,
            passphrase: PW,
            stamp: STAMP,
            git_sha: None,
            only: Only::components(),
            argon: ARGON2_FLOOR,
            part_size: 4096,
            created_at: 42,
            keep: 10,
            db_dump: Some(&dump_path),
            state_files: &state_files,
        };
        let report = backup(&req).await.unwrap();
        commit_bundle(&req, &report).await.unwrap();

        // 1. What the seal run printed, per component.
        let sealed = |c: Component| {
            report
                .components
                .iter()
                .find(|m| m.component == c)
                .unwrap_or_else(|| panic!("{} missing from the report", c.as_str()))
                .part_count()
        };
        assert_eq!(sealed(Component::Db), 2, "db: index part 0 + one payload");
        assert_eq!(sealed(Component::State), 2, "state: part 0 + one payload");

        // 2. What is actually on the tier (`ls _backup/<stamp>/<component>/`).
        assert_eq!(tier_part_count(&cold, STAMP, Component::Db).await, 2);
        assert_eq!(tier_part_count(&cold, STAMP, Component::State).await, 2);

        // 3. What `--list` tells the operator. This is the assertion that fails on
        //    the off-by-one (it reported 1 and 1).
        let summaries = list_backups(&cold).await.unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(
            summaries[0].db_parts,
            sealed(Component::Db),
            "--list disagrees with the seal run about db parts"
        );
        assert_eq!(
            summaries[0].state_parts,
            sealed(Component::State),
            "--list disagrees with the seal run about state parts"
        );
        assert_eq!(
            summaries[0].db_parts,
            tier_part_count(&cold, STAMP, Component::Db).await
        );
        assert_eq!(
            summaries[0].state_parts,
            tier_part_count(&cold, STAMP, Component::State).await
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The `+ 1` must not turn an ABSENT component into a phantom part: a bundle
    /// sealed `--only db` has NOTHING under `_backup/<stamp>/state/`, and `state=1`
    /// would tell an operator a state half exists to restore from when none does.
    #[tokio::test]
    async fn list_reports_zero_parts_for_a_component_the_bundle_does_not_have() {
        let cold = MemoryColdTier::new();
        let dir = temp_dir("onlydb");
        std::fs::create_dir_all(&dir).unwrap();
        let dump_path = dir.join("db.dump");
        std::fs::write(&dump_path, payload_of(64)).unwrap();
        let req = BackupRequest {
            cold: &cold,
            passphrase: PW,
            stamp: STAMP,
            git_sha: None,
            only: Only {
                db: true,
                state: false,
                code: false,
                blobs: false,
            },
            argon: ARGON2_FLOOR,
            part_size: 4096,
            created_at: 42,
            keep: 10,
            db_dump: Some(&dump_path),
            state_files: &[],
        };
        let report = backup(&req).await.unwrap();
        commit_bundle(&req, &report).await.unwrap();

        let summaries = list_backups(&cold).await.unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].db_parts, 2);
        assert_eq!(
            summaries[0].state_parts, 0,
            "a component absent from the bundle must list as 0, not as a phantom part 0"
        );
        assert_eq!(
            tier_part_count(&cold, STAMP, Component::State).await,
            0,
            "nothing should have been written under state/"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Blobs ride the cold tier and are copied AFTER the seal returns, so at the
    /// moment `backup` is done the bundle's own halves exist but the corpus behind
    /// them may not. Publishing there would make a run the operator was told FAILED
    /// resolve as `latest` — and it would already have evicted the last complete
    /// bundle to make room for it.
    #[tokio::test]
    async fn backup_publishes_nothing_until_commit_bundle() {
        let cold = MemoryColdTier::new();
        let old = seal_blob(
            &cold,
            "20260101T000000Z",
            None,
            Component::Db,
            &payload_of(64),
            1000,
        )
        .await;
        write_manifest(&cold, "20260101T000000Z", None, 1000, &[&old])
            .await
            .unwrap();

        let dir = temp_dir("commitpoint");
        std::fs::create_dir_all(&dir).unwrap();
        let dump_path = dir.join("db.dump");
        std::fs::write(&dump_path, payload_of(600)).unwrap();
        let req = BackupRequest {
            cold: &cold,
            passphrase: PW,
            stamp: "20260102T000000Z",
            git_sha: None,
            only: Only {
                db: true,
                state: false,
                code: false,
                blobs: false,
            },
            argon: ARGON2_FLOOR,
            part_size: 1000,
            created_at: 2000,
            keep: 1, // retention of one: committing evicts the old bundle
            db_dump: Some(&dump_path),
            state_files: &[],
        };
        let report = backup(&req).await.unwrap();

        assert_eq!(
            listed_stamps(&cold).await,
            vec!["20260101T000000Z".to_owned()],
            "the new bundle was published before its blobs were known to be copied"
        );

        let pruned = commit_bundle(&req, &report).await.unwrap();
        assert_eq!(pruned, vec!["20260101T000000Z".to_owned()]);
        assert_eq!(
            listed_stamps(&cold).await,
            vec!["20260102T000000Z".to_owned()]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A run that died between its first payload part and its manifest leaves a
    /// stamp dir behind, and it sorts NEWER than every good bundle — so counting it
    /// as a bundle silently costs the operator one real restore point per failed
    /// run.
    #[tokio::test]
    async fn retention_ignores_manifestless_orphan_stamps() {
        let cold = MemoryColdTier::new();
        for stamp in ["20260101T000000Z", "20260102T000000Z"] {
            let m = seal_blob(&cold, stamp, None, Component::Db, &payload_of(300), 1000).await;
            write_manifest(&cold, stamp, None, 1000, &[&m])
                .await
                .unwrap();
        }
        // The orphan: sealed, never committed.
        seal_blob(
            &cold,
            "20260103T000000Z",
            None,
            Component::Db,
            &payload_of(300),
            1000,
        )
        .await;

        assert!(
            prune(&cold, 2).await.unwrap().is_empty(),
            "an orphan stamp dir displaced a real bundle"
        );
        let listed = listed_stamps(&cold).await;
        assert_eq!(
            listed,
            vec!["20260101T000000Z".to_owned(), "20260102T000000Z".to_owned()]
        );
    }

    /// A tier whose component deletes always fault — the mid-prune cold-tier
    /// outage `prune` has to tolerate over Dropbox.
    struct FailComponentDelete {
        inner: MemoryColdTier,
    }
    #[async_trait]
    impl ColdTier for FailComponentDelete {
        async fn put_chunk(&self, r: &str, i: u64, b: Vec<u8>) -> Result<(), BlobError> {
            self.inner.put_chunk(r, i, b).await
        }
        async fn get_chunk(&self, r: &str, i: u64) -> Result<Option<Vec<u8>>, BlobError> {
            self.inner.get_chunk(r, i).await
        }
        async fn chunk_count(&self, r: &str) -> Result<u64, BlobError> {
            self.inner.chunk_count(r).await
        }
        async fn delete_stream(&self, r: &str) -> Result<(), BlobError> {
            if r.ends_with("/db") || r.ends_with("/state") {
                return Err(BlobError::new("delete_stream", "simulated tier outage"));
            }
            self.inner.delete_stream(r).await
        }
        async fn delete_chunk(&self, r: &str, i: u64) -> Result<(), BlobError> {
            self.inner.delete_chunk(r, i).await
        }
        async fn has_chunk(&self, r: &str, i: u64) -> Result<bool, BlobError> {
            self.inner.has_chunk(r, i).await
        }
        async fn list_prefix(&self, p: &str) -> Result<Option<Vec<String>>, BlobError> {
            self.inner.list_prefix(p).await
        }
    }

    /// An interrupted prune must leave an unlisted orphan, never a bundle still
    /// offered as restorable whose parts are already gone — the operator would only
    /// discover that by naming it during an incident.
    #[tokio::test]
    async fn prune_unlists_a_victim_before_deleting_its_parts() {
        let cold = FailComponentDelete {
            inner: MemoryColdTier::new(),
        };
        for stamp in ["20260101T000000Z", "20260102T000000Z"] {
            let m = seal_blob(&cold, stamp, None, Component::Db, &payload_of(300), 1000).await;
            write_manifest(&cold, stamp, None, 1000, &[&m])
                .await
                .unwrap();
        }
        assert!(prune(&cold, 1).await.is_err());
        let listed = listed_stamps(&cold).await;
        assert_eq!(
            listed,
            vec!["20260102T000000Z".to_owned()],
            "a half-pruned bundle is still advertised as restorable"
        );
    }

    /// One bad object under `_backup/<x>/manifest/0` must not take the whole
    /// enumeration down: the operator would then be unable to see — or even name —
    /// the healthy bundles beside it, mid-incident.
    #[tokio::test]
    async fn list_backups_skips_an_unreadable_manifest() {
        let cold = MemoryColdTier::new();
        let good = seal_blob(
            &cold,
            "20260102T000000Z",
            None,
            Component::Db,
            &payload_of(300),
            1000,
        )
        .await;
        write_manifest(&cold, "20260102T000000Z", None, 1000, &[&good])
            .await
            .unwrap();
        cold.put_chunk(&manifest_ref("20260101T000000Z"), 0, b"{ not json".to_vec())
            .await
            .unwrap();

        let listed = listed_stamps(&cold).await;
        assert_eq!(listed, vec!["20260102T000000Z".to_owned()]);
        assert_eq!(
            resolve_stamp(&cold, "latest").await.unwrap(),
            "20260102T000000Z"
        );
    }

    /// `list_backups` orders on the PLAINTEXT `created_at`, so a rewritten manifest
    /// is an attacker's only lever on which bundle `--from latest` picks. The
    /// authenticated copy is right there.
    #[tokio::test]
    async fn created_at_mismatch_aborts_in_plan() {
        let cold = MemoryColdTier::new();
        let db = seal_blob(&cold, STAMP, None, Component::Db, &payload_of(300), 1000).await;
        // `seal_blob` sealed created_at = 1000; the hint claims a much later time.
        write_manifest(&cold, STAMP, None, 9_999_999, &[&db])
            .await
            .unwrap();
        let staging = temp_dir("createdat");
        let req = RestoreRequest {
            cold: &cold,
            passphrase: PW,
            from: STAMP,
            only: Only {
                db: true,
                state: false,
                code: false,
                blobs: false,
            },
            db_mode: DbMode::Merge,
            dry_run: true,
            force: false,
            live_db_present: true,
            staging: &staging,
        };
        assert!(matches!(
            plan(&req).await.unwrap_err(),
            BackupError::CreatedAtDisagreement { .. }
        ));
    }

    /// The plan is what the operator reads and what `restore-server.sh` scrapes, so
    /// it may not assert a pre-pull that no code path performs.
    #[tokio::test]
    async fn only_blobs_plan_promises_no_prepull() {
        let cold = MemoryColdTier::new();
        let db = seal_blob(&cold, STAMP, None, Component::Db, &payload_of(64), 1000).await;
        write_manifest(&cold, STAMP, None, 1000, &[&db])
            .await
            .unwrap();
        let staging = temp_dir("blobsplan");
        let req = RestoreRequest {
            cold: &cold,
            passphrase: PW,
            from: STAMP,
            only: Only {
                db: false,
                state: false,
                code: false,
                blobs: true,
            },
            db_mode: DbMode::Merge,
            dry_run: true,
            force: false,
            live_db_present: true,
            staging: &staging,
        };
        let p = plan(&req).await.unwrap();
        assert!(!p.blobs.as_ref().unwrap().prepull);
        let printed = p.to_string();
        assert!(
            printed.contains("no pre-pull"),
            "the plan must say the pre-pull does not happen: {printed}"
        );
        assert!(!printed.contains("pre-pull true"), "{printed}");
    }

    /// The staging tree holds the plaintext `pg_dump` (every DEK wrap), the TLS
    /// private key, the operational signing seed and the unit file's DB password,
    /// and the driver leaves it in place for the whole restore. The seal side
    /// already hardens its transient dump dir; the unseal side must not be the hole
    /// that undoes it.
    #[tokio::test]
    async fn restore_staging_is_not_world_readable() {
        let cold = MemoryColdTier::new();
        let key = b"the TLS private key\n".to_vec();
        let state = seal_component(
            &cold,
            PW,
            STAMP,
            None,
            Component::State,
            vec![BackupEntry {
                path: Text::new("tls/key.der").unwrap(),
                len: key.len() as u64,
                digest: Bytes32(sha256(&key)),
            }],
            Cursor::new(key),
            ARGON2_FLOOR,
            1000,
            1000,
        )
        .await
        .unwrap();
        let db = seal_blob(&cold, STAMP, None, Component::Db, &payload_of(300), 1000).await;
        write_manifest(&cold, STAMP, None, 1000, &[&db, &state])
            .await
            .unwrap();

        let staging = temp_dir("modes");
        let req = RestoreRequest {
            cold: &cold,
            passphrase: PW,
            from: STAMP,
            only: Only::components(),
            db_mode: DbMode::Merge,
            dry_run: false,
            force: false,
            live_db_present: true,
            staging: &staging,
        };
        let the_plan = plan(&req).await.unwrap();
        let report = restore(&req, &the_plan).await.unwrap();
        assert_staging_modes(&staging, report.db_dump.as_ref().unwrap());
        let _ = std::fs::remove_dir_all(&staging);
    }

    #[cfg(unix)]
    fn assert_staging_modes(staging: &Path, dump: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(staging), 0o700, "staging root");
        assert_eq!(mode(&staging.join("state")), 0o700, "state dir");
        assert_eq!(
            mode(&staging.join("state").join("tls")),
            0o700,
            "nested state dir"
        );
        assert_eq!(
            mode(&staging.join("state").join("tls").join("key.der")),
            0o600,
            "restored TLS key"
        );
        assert_eq!(mode(dump), 0o600, "db dump");
    }

    /// Windows has no POSIX mode bits to assert, so only the assertions are gated —
    /// the restore itself still runs there, which is what keeps the `harden` calls
    /// from silently rotting off Unix.
    #[cfg(not(unix))]
    fn assert_staging_modes(_staging: &Path, _dump: &Path) {}
}
