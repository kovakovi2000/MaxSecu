//! Server backup & rollback subcommands
//! (`docs/superpowers/specs/2026-07-16-server-backup-rollback-design.md`).
//!
//! Three operator subcommands plus two driver-internal ones, all dispatched from
//! `main.rs` **before** the serve path's tokio runtime (each builds its own):
//!
//! ```text
//! maxsecu-portable-server backup       [--keep N]
//! maxsecu-portable-server restore      --from latest|<stamp>
//!                                      [--only db,state,code,blobs]
//!                                      [--db-mode merge|replace] [--dry-run] [--force]
//! maxsecu-portable-server list-backups
//! maxsecu-portable-server restore-db-merge [--apply]   (driver-internal; scratch URL on stdin)
//! maxsecu-portable-server verify-restored-blobs        (driver-internal; after pg_restore)
//! ```
//!
//! # The passphrase is on stdin, never argv
//!
//! argv is world-readable through `/proc`, so the bundle passphrase arrives as a
//! single trimmed line on **stdin** ([`read_stdin_line`]). Two consequences bind
//! the shell drivers (phase 3 stage 2): the drivers must not consume stdin
//! themselves, and every child *this binary* spawns — `pg_dump`, `git` — is
//! `Stdio::null`'d on stdin here so it cannot drink the passphrase line.
//! `list-backups` reads only the plaintext manifest and takes **no** passphrase;
//! `restore --only code|blobs` reads only the manifest too, so it skips the prompt.
//!
//! # The binary vs the shell driver — the split phase 3 stage 2 implements against
//!
//! `pg_dump -Fc` and `pg_restore` are the only tools that read that opaque archive
//! format, and only `pg_restore` can materialize its rows, so the DB work is split
//! by which side owns the Postgres CLI:
//!
//! * **`backup` is ONE binary invocation.** It holds `DATABASE_URL` through
//!   [`LauncherConfig`], so it runs `pg_dump -Fc` itself (into a `0700` work dir,
//!   sealed then unlinked — the plaintext dump never lingers), enumerates the
//!   FILTERED current-version `file_streams`, seals `db` + `state`, uploads the
//!   bundle, and `backup_copy_refs` every committed blob onto the cold tier. The
//!   driver (`backup-server.sh`) is therefore thin: export the unit's env, `sudo`
//!   so `/etc/...` state is readable, pipe the passphrase, done. Backup does **not**
//!   stop the server — it is a pure read.
//!
//! * **`restore` is a TWO-invocation flow** (the `db` merge cannot be one call —
//!   `INSERT … ON CONFLICT` needs real rows, and cross-database `INSERT..SELECT`
//!   is impossible without an extension this repo will not add to the dead-box
//!   path). The driver `systemctl stop`s first, then:
//!     1. `restore --from <stamp>` (this binary) — unseal `state` → `<staging>/state/`,
//!        unseal the `db` dump → `<staging>/db.dump`, write `<staging>/plan.json`
//!        (the driver contract), and print `staging=` / `db_dump=` / `state_dir=` /
//!        `plan_json=` on stdout. `<staging>` is `<data_dir>/_restore_work/<stamp>/`.
//!     2. driver — `createdb maxsecu_restore_<stamp>`; `pg_restore -d
//!        maxsecu_restore_<stamp> <staging>/db.dump`; copy `<staging>/state/*` into
//!        place; `daemon-reload`.
//!     3. `restore-db-merge [--apply]` (this binary), scratch URL piped on stdin —
//!        the one cross-database step. `restore_db_merge(live, staged, apply)`. The
//!        **live** pool is `max_connections(1)` on purpose: the stopped-server
//!        guard counts `pg_stat_activity` rows other than its own backend, so an
//!        idle sibling in our own pool would self-trip `ServerStillConnected`.
//!     4. driver — `dropdb maxsecu_restore_<stamp>`; `systemctl start`.
//!
//!   `--db-mode replace` skips step 3 entirely: it is a wholesale `pg_restore
//!   --clean` into live, done by the driver, gated behind `--force` because over a
//!   live DB it is the `2a626d6` shape by construction.
//!
//! * **`--dry-run`** here is plan-only: resolve, `plan()`, print, mutate nothing.
//!   The *row-level* merge preview (per-table counts) is produced by the driver's
//!   scratch-DB pass — it materializes into a throwaway DB and calls
//!   `restore-db-merge` **without** `--apply` (which runs the identical insert pass
//!   inside a `SERIALIZABLE` txn and rolls it back), then `dropdb`s and copies
//!   nothing into place.
//!
//! # No new env vars
//!
//! Every knob is a CLI flag or comes from [`LauncherConfig`]. Nothing here reads
//! `std::env` (the backup engine may not either — `env_surface.rs` walks
//! `crates/server/src`), so no `MAXSECU_*` variable is added and neither deployment
//! script's env surface changes. `--cold-tier-fs` / `--dropbox-env` live in the
//! shell drivers, not here: they only export the cold-tier location the binary then
//! reads through `LauncherConfig` (the sanctioned env reader).

use std::error::Error;
use std::path::{Path, PathBuf};
use std::time::Duration;

use maxsecu_crypto::ARGON2_DESKTOP_TARGET;
use maxsecu_server::backup::format::MIN_PASSPHRASE_CHARS;
use maxsecu_server::backup::{
    backup, commit_bundle, list_backups, plan, restore, restore_db_merge, verify_stream_blobs,
    BackupRequest, DbMode, Only, RestoreRequest, StateFile, MAX_PART_SIZE,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use zeroize::Zeroizing;

use maxsecu_portable_server::config::LauncherConfig;
use maxsecu_portable_server::layout::Layout;
use maxsecu_portable_server::run;

/// The systemd unit `install-server.sh` writes (its `UNIT_PATH`), plus the drop-in
/// dir and the Dropbox env file. Present only on the production Linux box; every
/// one absent here is skipped, so a Dev / Windows run seals only the data-dir
/// material (`tls/`, `config/`).
const UNIT_PATH: &str = "/etc/systemd/system/maxsecu-server.service";
const DROPIN_DIR: &str = "/etc/systemd/system/maxsecu-server.service.d";
const DROPBOX_ENV_PATH: &str = "/etc/maxsecu/dropbox.env";

/// Default retention: keep the newest N bundle stamps, prune older ones. Bundles
/// are small; blobs are never pruned (they are the live cold tier).
const DEFAULT_KEEP: usize = 10;

/// A parsed subcommand — the pure, unit-testable seam. [`parse`] turns argv into
/// one of these; the async handlers ([`dispatch`]) act on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Seal a new bundle (`db` + `state`) and copy every committed blob to cold.
    Backup { keep: usize },
    /// Unseal a bundle into staging + write the plan (invocation #1 of restore).
    Restore(RestoreArgs),
    /// List bundles from the plaintext manifests (no passphrase).
    ListBackups,
    /// The one cross-database merge step (driver-internal, invocation #3).
    RestoreDbMerge(MergeArgs),
    /// The dead-box `--replace` blob-resolution audit (driver-internal,
    /// invocation #4). Must run AFTER the driver's `pg_restore`: it walks the
    /// freshly restored `file_streams`, which do not exist while `restore` is
    /// still unsealing. Read-only — it reports, it never drops a row.
    VerifyRestoredBlobs,
}

/// `restore` flags. `only == None` means the default scope (`db,state,code`);
/// `db_mode == None` resolves to `merge` when a live DB is present, else `replace`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreArgs {
    pub from: String,
    pub only: Option<Only>,
    pub db_mode: Option<DbMode>,
    pub dry_run: bool,
    pub force: bool,
}

/// `restore-db-merge` flags. `apply` commits (default is the rolled-back preview).
/// The scratch-DB connection string is NOT a flag: it carries the DB password and
/// arrives on **stdin** (like the bundle passphrase), because argv is world-readable
/// via `/proc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeArgs {
    pub apply: bool,
}

const USAGE: &str = "\
maxsecu-portable-server <subcommand>

  backup       [--keep N]
  restore      --from latest|<stamp> [--only db,state,code,blobs]
               [--db-mode merge|replace] [--dry-run] [--force]
  list-backups
  restore-db-merge [--apply]   (driver-internal; scratch URL on stdin)
  verify-restored-blobs        (driver-internal; run after pg_restore)";

/// Parse the argv **after** the binary name (`args[0]` is the subcommand). Pure:
/// no environment, no I/O — the testable seam.
pub fn parse(args: &[String]) -> Result<Command, String> {
    let (sub, rest) = args
        .split_first()
        .ok_or_else(|| format!("missing subcommand\n{USAGE}"))?;
    match sub.as_str() {
        "backup" => parse_backup(rest),
        "restore" => parse_restore(rest),
        "list-backups" => {
            if rest.is_empty() {
                Ok(Command::ListBackups)
            } else {
                Err(format!("list-backups takes no arguments\n{USAGE}"))
            }
        }
        "restore-db-merge" => parse_merge(rest),
        "verify-restored-blobs" => {
            if rest.is_empty() {
                Ok(Command::VerifyRestoredBlobs)
            } else {
                Err(format!("verify-restored-blobs takes no arguments\n{USAGE}"))
            }
        }
        other => Err(format!("unknown subcommand {other:?}\n{USAGE}")),
    }
}

fn parse_backup(rest: &[String]) -> Result<Command, String> {
    let mut keep = DEFAULT_KEEP;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--keep" => {
                let v = rest.get(i + 1).ok_or("--keep needs a value")?;
                keep = v
                    .parse::<usize>()
                    .map_err(|_| format!("--keep wants a non-negative integer, got {v:?}"))?;
                // Retention keeps the newest N; N = 0 keeps none, and since the
                // prune runs after the bundle is committed it would delete the
                // bundle this very run just sealed — while the run still reports
                // "backup complete" and exits 0, leaving the operator with zero
                // restore points and the opposite belief. `0` also reads as
                // "unlimited" to anyone coming from a tool where it means that, so
                // the ambiguity resolves destructively. Refuse it here rather than
                // pick one meaning.
                if keep == 0 {
                    return Err(
                        "--keep must be at least 1 — a backup that keeps nothing would delete \
                         the bundle it just wrote"
                            .to_owned(),
                    );
                }
                i += 2;
            }
            other => return Err(format!("backup: unexpected argument {other:?}\n{USAGE}")),
        }
    }
    Ok(Command::Backup { keep })
}

fn parse_restore(rest: &[String]) -> Result<Command, String> {
    let mut from: Option<String> = None;
    let mut only: Option<Only> = None;
    let mut db_mode: Option<DbMode> = None;
    let mut dry_run = false;
    let mut force = false;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--from" => {
                from = Some(rest.get(i + 1).ok_or("--from needs a value")?.clone());
                i += 2;
            }
            "--only" => {
                let spec = rest.get(i + 1).ok_or("--only needs a value")?;
                only = Some(parse_only(spec)?);
                i += 2;
            }
            "--db-mode" => {
                let m = rest.get(i + 1).ok_or("--db-mode needs a value")?;
                db_mode = Some(match m.as_str() {
                    "merge" => DbMode::Merge,
                    "replace" => DbMode::Replace,
                    other => return Err(format!("--db-mode wants merge|replace, got {other:?}")),
                });
                i += 2;
            }
            "--dry-run" => {
                dry_run = true;
                i += 1;
            }
            "--force" => {
                force = true;
                i += 1;
            }
            other => return Err(format!("restore: unexpected argument {other:?}\n{USAGE}")),
        }
    }
    let from = from.ok_or_else(|| format!("restore: --from is required\n{USAGE}"))?;
    Ok(Command::Restore(RestoreArgs {
        from,
        only,
        db_mode,
        dry_run,
        force,
    }))
}

/// Parse a `--only` component list. An unknown token or an empty selection is an
/// error — a scope that touches nothing is never what the operator meant.
fn parse_only(spec: &str) -> Result<Only, String> {
    let mut o = Only {
        db: false,
        state: false,
        code: false,
        blobs: false,
    };
    for tok in spec.split(',') {
        match tok.trim() {
            "db" => o.db = true,
            "state" => o.state = true,
            "code" => o.code = true,
            "blobs" => o.blobs = true,
            "" => {}
            other => {
                return Err(format!(
                    "--only: unknown component {other:?} (want db,state,code,blobs)"
                ))
            }
        }
    }
    if !(o.db || o.state || o.code || o.blobs) {
        return Err("--only selected no components".to_owned());
    }
    Ok(o)
}

fn parse_merge(rest: &[String]) -> Result<Command, String> {
    let mut apply = false;
    for arg in rest {
        match arg.as_str() {
            "--apply" => apply = true,
            other => {
                return Err(format!(
                    "restore-db-merge: unexpected argument {other:?}\n{USAGE}"
                ))
            }
        }
    }
    Ok(Command::RestoreDbMerge(MergeArgs { apply }))
}

/// Entry point from `main.rs`. `argv` is the full process args (`argv[0]` is the
/// binary path); the subcommand and its flags are `argv[1..]`. Parse errors exit
/// with code 2 and print usage; a domain failure exits 1.
pub fn run(argv: &[String]) -> std::io::Result<()> {
    let cmd = match parse(&argv[1..]) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(2);
        }
    };
    let rt = tokio::runtime::Runtime::new()?;
    if let Err(e) = rt.block_on(dispatch(cmd)) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
    Ok(())
}

async fn dispatch(cmd: Command) -> Result<(), Box<dyn Error>> {
    match cmd {
        Command::Backup { keep } => do_backup(keep).await,
        Command::Restore(args) => do_restore(args).await,
        Command::ListBackups => do_list().await,
        Command::RestoreDbMerge(args) => do_merge(args).await,
        Command::VerifyRestoredBlobs => do_verify_restored_blobs().await,
    }
}

/// Read the bundle passphrase: a single trimmed line from stdin (never argv).
/// The one trimmed line the driver pipes in on stdin — the secret channel that
/// keeps a bundle passphrase or a password-bearing scratch-DB URL off argv (which
/// is world-readable via `/proc`). Each caller names what it expects.
/// Read one line of secret from stdin — the bundle passphrase, or the scratch
/// database's URL (which carries the DB password).
///
/// Both are secrets, which is the whole reason they arrive here instead of on
/// argv, so the returned `String` is wrapped in [`Zeroizing`]: dropping it wipes
/// the buffer rather than handing the bytes back to the allocator, where a core
/// dump or a swapped page could still surface them. The intermediate `line` is
/// wrapped too — `trim().to_owned()` copies, so the untrimmed original would
/// otherwise be freed intact.
fn read_stdin_line() -> std::io::Result<Zeroizing<String>> {
    use std::io::BufRead;
    let mut line = Zeroizing::new(String::new());
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(Zeroizing::new(line.trim().to_owned()))
}

// ---- backup ----

async fn do_backup(keep: usize) -> Result<(), Box<dyn Error>> {
    let cfg = LauncherConfig::from_env();
    let url = cfg.database_url.clone().ok_or(
        "backup requires the Postgres profile (DATABASE_URL); the DEV MemoryStore is \
         ephemeral and has nothing to back up",
    )?;
    let layout = Layout::ensure(&cfg.data_dir)?;
    // Fail closed with no cold tier: a backup you wrongly believe is complete is
    // worse than no backup, and there would be nowhere to seal the bundle.
    let tiers = run::build_backup_tiers(&cfg, &layout)?.ok_or(
        "no cold tier configured — refusing to write a backup you would wrongly believe is \
         complete. Set MAXSECU_COLD_TIER=fs (+ MAXSECU_COLD_FS_DIR) or configure Dropbox",
    )?;

    // Passphrase first, and validate the seal minimum up front so a short one fails
    // fast rather than after a full pg_dump.
    let passphrase = read_stdin_line()?;
    let chars = passphrase.chars().count();
    if chars < MIN_PASSPHRASE_CHARS {
        return Err(
            format!("passphrase too short: {chars} chars, minimum {MIN_PASSPHRASE_CHARS}").into(),
        );
    }

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&url)
        .await?;

    let now = now_unix();
    let stamp = utc_stamp(now);

    // pg_dump -Fc into a 0700 work dir; sealed, then unlinked.
    let work = cfg.data_dir.join("_backup_work");
    std::fs::create_dir_all(&work)?;
    harden_dir(&work);
    let dump = work.join(format!("db-{stamp}.dump"));
    // pg_dump creates its `--file` target before it can know it will fail, so an
    // aborted dump (a full disk being the usual cause) leaves a partial plaintext
    // archive behind. Nothing else ever sweeps `_backup_work`, so without this the
    // failures accumulate full-size DB archives on the very disk whose exhaustion
    // caused them — and the module's promise that the plaintext dump never lingers
    // would hold only on the happy path.
    let dumped = run_pg_dump(&url, &dump);
    if dumped.is_err() {
        let _ = std::fs::remove_file(&dump);
    }
    dumped?;
    // From here on the plaintext archive exists, and EVERY exit from this function
    // must unlink it — not just the happy path. The unlink used to sit at the bottom,
    // after `backup(&req).await?`, so any `?` in between (the stream enumeration, the
    // state-file checks below, the seal itself) returned with a full plaintext copy of
    // the metadata DB — every keyblob and every DEK wrap — left on disk. A Drop guard
    // makes that impossible to get wrong again as more early returns are added.
    struct DumpGuard(PathBuf);
    impl Drop for DumpGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _dump_guard = DumpGuard(dump.clone());

    // Enumerate the FILTERED, committed, current-version streams — the only
    // complete, restart-proof list (LocalIndex is empty after a restart, and an
    // unfiltered scan would sweep in a user's in-flight, not-yet-finalized upload).
    //
    // AFTER the dump, deliberately. The two reads cannot be atomic (pg_dump is a
    // separate process with its own snapshot), so one of them sees the other's
    // window — and the two orderings fail very differently. Enumerating FIRST means
    // a version finalized in the window is in the DUMP but not in the ref list: the
    // restored database would point at a blob_ref whose ciphertext was never copied
    // to cold, and on a dead-box rebuild that file is simply gone. Enumerating LAST
    // inverts it into copying a chunk the dump does not reference yet — a few
    // wasted bytes on the cold tier, which is the whole cost. Prefer the harmless
    // direction.
    let refs = enumerate_current_streams(&pool).await?;

    let state_files = collect_state_files(&layout);
    // FAIL CLOSED on a state set missing its load-bearing members.
    //
    // Every source in `collect_state_files` is silently skipped when absent
    // (`add_if_file` is a bare `is_file()`; `add_dir` swallows a `read_dir` error),
    // which is right for the Linux-only paths — a Dev/Windows run legitimately has no
    // systemd unit and no /etc/maxsecu. But it also means a WRONG `MAXSECU_DATA_DIR`,
    // or a data dir whose tls/ and config/ have not been created yet, produces an
    // EMPTY state component that seals, publishes, becomes `--from latest`, and prints
    // "backup complete" — and the operator's rollback point silently contains neither
    // the TLS key (lose it and every pinned client is locked out) nor the delegation
    // triple. A backup you wrongly believe is complete is worse than no backup, which
    // is the same rule that makes a missing cold tier fatal.
    //
    // Checked against the data-dir material only, never the Linux-only paths.
    for required in ["tls/cert.der", "tls/key.der"] {
        if !state_files.iter().any(|f| f.path == required) {
            return Err(format!(
                "refusing to seal a state bundle with no {required}: nothing was found under \
                 the data dir {}. A bundle without the TLS key cannot rebuild this box (every \
                 pinned client would be locked out by the new cert). Check MAXSECU_DATA_DIR.",
                cfg.data_dir.display()
            )
            .into());
        }
    }
    if !state_files.iter().any(|f| f.path.starts_with("config/")) {
        return Err(format!(
            "refusing to seal a state bundle with no config/ files: the delegation triple \
             (operational_secret.bin + d5_delegation.bin + directory_pub.der) is only coherent \
             as a set, and without it a restored box cannot serve enrollment. Data dir: {}.",
            cfg.data_dir.display()
        )
        .into());
    }
    let git_sha = git_sha_of_cwd();

    let req = BackupRequest {
        cold: tiers.cold.as_ref(),
        passphrase: &passphrase,
        stamp: &stamp,
        git_sha: git_sha.as_deref(),
        only: Only::components(),
        argon: ARGON2_DESKTOP_TARGET,
        part_size: MAX_PART_SIZE,
        // `Timestamp` (encoding/types.rs) is MILLISECONDS since the epoch, and it
        // is what the sealed `BackupIndex.created_at` is declared to be. The stamp
        // above needs seconds, so the two units part ways here. Surface #12 freezes
        // this field forever: seconds in a milliseconds slot would render as 1970
        // to any later reader, with no way to tell the two apart after the fact.
        created_at: now.saturating_mul(1_000),
        keep,
        db_dump: Some(&dump),
        state_files: &state_files,
    };
    // The plaintext dump is unlinked by `_dump_guard` on every path out of this
    // function, success or failure, so the `?` here is safe to take directly.
    let report = backup(&req).await?;

    // Blob backup: copy every current committed stream's chunks to cold, KEEP local.
    let copy = tiers.tier.backup_copy_refs(&refs).await?;
    if !copy.is_complete() {
        // Not every hole is a fault. The copy can run for a long time on a live
        // server, and an ordinary user action during it — deleting a file, or
        // rotating one to a new version — removes the old chunks from BOTH tiers
        // (`WriteBackTier::delete_stream`, and `finalize_version`'s purge of the
        // prior version). The copy loop then correctly finds nothing, and failing
        // on that would abort the operator's whole upgrade because someone deleted
        // a post. So re-read the committed set and forgive exactly the refs that
        // are no longer current; anything still current and still absent from both
        // tiers is a real fault and still fails closed.
        let still_current = enumerate_current_streams(&pool).await?;
        let (real, vanished): (Vec<_>, Vec<_>) = copy
            .missing
            .iter()
            .partition(|(r, _)| still_current.iter().any(|(cur, _)| cur == r));
        if !vanished.is_empty() {
            println!(
                "  note   : {} chunk(s) belonged to streams deleted or rotated during the \
                 backup — not a fault",
                vanished.len()
            );
        }
        if !real.is_empty() {
            // Fail closed: chunks missing from BOTH tiers mean the bundle is incomplete.
            eprintln!(
                "error: {} chunk(s) are missing from BOTH the local and cold tiers — the backup \
                 is INCOMPLETE:",
                real.len()
            );
            for (r, i) in &real {
                eprintln!("  {r} #{i}");
            }
            return Err("backup incomplete (committed streams missing from local and cold)".into());
        }
    }

    // Only now is the bundle published. `commit_bundle` writes the manifest — the
    // marker `--from latest` resolves through — and prunes to `keep`; doing that any
    // earlier would leave a run that failed above resolvable as `latest`, with a
    // good older bundle already evicted to make room for it.
    let pruned = commit_bundle(&req, &report).await?;

    println!("backup {stamp} complete");
    println!("  git sha : {}", git_sha.as_deref().unwrap_or("<none>"));
    for c in &report.components {
        println!("  {:<7}: {} part(s)", c.component.as_str(), c.part_count());
    }
    println!(
        "  blobs  : {} copied, {} already cold ({} stream(s))",
        copy.copied,
        copy.already_cold,
        refs.len()
    );
    if !pruned.is_empty() {
        println!("  pruned : {}", pruned.join(", "));
    }
    Ok(())
}

/// The FILTERED enumeration query (design "Blob enumeration"): only committed,
/// current-version streams — join to `files.current_version` so an in-flight,
/// not-yet-finalized upload is not walked as `missing_local`.
async fn enumerate_current_streams(
    pool: &sqlx::PgPool,
) -> Result<Vec<(String, u64)>, Box<dyn Error>> {
    let rows = sqlx::query(
        "SELECT s.blob_ref, s.chunk_count \
         FROM file_streams s \
         JOIN files f ON f.file_id = s.file_id AND f.current_version = s.version",
    )
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        let blob_ref: String = r.try_get("blob_ref")?;
        let chunk_count: i64 = r.try_get("chunk_count")?;
        out.push((blob_ref, chunk_count.max(0) as u64));
    }
    Ok(out)
}

/// `pg_dump -Fc` the live database to `out`. stdin is `null`'d so pg_dump can never
/// inherit — and drink — the passphrase line on our own stdin, and the DB password
/// travels in the environment rather than on the child's argv (see
/// [`split_pg_password`]).
fn run_pg_dump(url: &str, out: &Path) -> Result<(), Box<dyn Error>> {
    use std::process::{Command, Stdio};
    let (conninfo, password) = split_pg_password(url);
    let mut cmd = Command::new("pg_dump");
    if let Some(pw) = password {
        cmd.env("PGPASSWORD", pw);
    }
    let status = cmd
        .arg("--format=custom")
        .arg("--file")
        .arg(out)
        .arg(&conninfo)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| format!("could not run pg_dump (installed and on PATH?): {e}"))?;
    if !status.success() {
        return Err(format!("pg_dump exited with {status}").into());
    }
    Ok(())
}

/// Split the password out of a `postgres://user:password@host[:port]/db` conninfo,
/// returning the password-free URI plus the password (`None` when the URI carries
/// none, in which case the URI is returned untouched).
///
/// `pg_dump` does not scrub its argv, so a conninfo handed to it sits in
/// `/proc/<pid>/cmdline` — world-readable — for the whole dump, and on this box that
/// string carries the only copy of the app role's password outside the root-owned
/// `0600` unit file. This is the same rule the rest of the feature already keeps:
/// the bundle passphrase and the scratch-DB URL arrive on stdin, and
/// `backup-server.sh` moves `DATABASE_URL` through a `0600` env file precisely so
/// `/proc` cannot expose it. `PGPASSWORD` travels through the environment, and
/// `/proc/<pid>/environ` is readable only by the process owner.
fn split_pg_password(url: &str) -> (String, Option<String>) {
    let Some(scheme_end) = url.find("://") else {
        return (url.to_owned(), None);
    };
    let rest = &url[scheme_end + 3..];
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    // A host cannot contain `@` at all and a userinfo may only carry one
    // percent-encoded, so the LAST `@` is the userinfo boundary either way.
    let Some(at) = authority.rfind('@') else {
        return (url.to_owned(), None);
    };
    let userinfo = &authority[..at];
    let Some(colon) = userinfo.find(':') else {
        return (url.to_owned(), None);
    };
    // A malformed escape means we cannot reproduce the password libpq would have
    // parsed. Leaving the URI exactly as it was keeps the backup working (the whole
    // point of the feature) at the cost of this one hardening — a failed backup
    // would be the worse outcome.
    let Some(password) = percent_decode(&userinfo[colon + 1..]) else {
        return (url.to_owned(), None);
    };
    if password.is_empty() {
        return (url.to_owned(), None);
    }
    let stripped = format!(
        "{}{}{}",
        &url[..scheme_end + 3 + colon],
        &authority[at..],
        &rest[auth_end..]
    );
    (stripped, Some(password))
}

/// Decode `%XX` escapes in a URI userinfo field. `None` on a malformed escape or on
/// bytes that are not UTF-8 — the caller then leaves the URI alone rather than hand
/// `pg_dump` a password that would fail to authenticate.
fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hi = char::from(*b.get(i + 1)?).to_digit(16)?;
            let lo = char::from(*b.get(i + 2)?).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The state files to seal, in the design's "state bundle" table. System paths
/// (`unit`, drop-ins, `dropbox.env`) exist only on the Prod Linux box and are
/// skipped when absent; the data-dir material (`tls/`, `config/`) is always sealed
/// if present. The bundle-relative path is what `restore-server.sh` maps back to a
/// system location on the way in.
fn collect_state_files(layout: &Layout) -> Vec<StateFile> {
    let mut v = Vec::new();
    add_if_file(
        &mut v,
        "unit/maxsecu-server.service",
        PathBuf::from(UNIT_PATH),
    );
    add_dir(&mut v, "unit/drop-ins", &PathBuf::from(DROPIN_DIR));
    add_if_file(&mut v, "dropbox.env", PathBuf::from(DROPBOX_ENV_PATH));
    add_if_file(&mut v, "tls/cert.der", layout.cert_der_path());
    add_if_file(&mut v, "tls/key.der", layout.cert_key_path());
    add_dir(&mut v, "config", &layout.config_dir());
    v
}

fn add_if_file(v: &mut Vec<StateFile>, rel: &str, src: PathBuf) {
    if src.is_file() {
        v.push(StateFile {
            path: rel.to_owned(),
            source: src,
        });
    }
}

/// Seal every regular file directly under `dir` as `<rel>/<name>`.
fn add_dir(v: &mut Vec<StateFile>, rel: &str, dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_file() {
            if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                v.push(StateFile {
                    path: format!("{rel}/{name}"),
                    source: p,
                });
            }
        }
    }
}

/// The current git HEAD, or `None` when the CWD is not a git checkout / git is
/// absent (`.git` is excluded from the test source copy, so `null` is a legitimate
/// value restore treats as `null ≡ null` agreement). stdin is `null`'d so git
/// cannot inherit the passphrase.
fn git_sha_of_cwd() -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_owned())
    }
}

// ---- restore (invocation #1) ----

async fn do_restore(args: RestoreArgs) -> Result<(), Box<dyn Error>> {
    let cfg = LauncherConfig::from_env();
    let layout = Layout::ensure(&cfg.data_dir)?;
    // The cold tier holds the bundle. On a dead box the driver must export its
    // location (--cold-tier-fs / --dropbox-env) before exec'ing us.
    let tiers = run::build_backup_tiers(&cfg, &layout)?.ok_or(
        "no cold tier configured — cannot find the backup bundle. On a dead-box rebuild, \
         restore-server.sh must pass --cold-tier-fs <dir> or --dropbox-env <path>; on a \
         same-box rollback it scrapes the location from the live unit",
    )?;
    let cold = tiers.cold.as_ref();

    let only = args.only.unwrap_or_else(Only::default_restore);
    // "A live DB exists" ≈ "DATABASE_URL is configured" (a dead box has no unit and
    // so no DATABASE_URL). This drives the default mode and the replace-over-live
    // guard; --db-mode overrides it explicitly.
    let live_db_present = cfg.database_url.is_some();
    let db_mode = args.db_mode.unwrap_or(if live_db_present {
        DbMode::Merge
    } else {
        DbMode::Replace
    });

    // Passphrase only when a SEALED component is selected. --only code|blobs reads
    // only the plaintext manifest.
    let passphrase = if only.db || only.state {
        read_stdin_line()?
    } else {
        Zeroizing::new(String::new())
    };

    // plan() reads no staging; use a placeholder to resolve the stamp first.
    let placeholder = cfg.data_dir.join("_restore_work");
    let plan_req = RestoreRequest {
        cold,
        passphrase: &passphrase,
        from: &args.from,
        only,
        db_mode,
        dry_run: args.dry_run,
        force: args.force,
        live_db_present,
        staging: &placeholder,
    };
    let the_plan = plan(&plan_req).await?;
    print!("{the_plan}");

    if args.dry_run {
        // Plan-only: mutate nothing. The row-level merge preview is the driver's
        // scratch-DB pass (restore-db-merge without --apply) — see the module docs.
        return Ok(());
    }

    // Apply: materialize under <data_dir>/_restore_work/<stamp>/ for the driver.
    // The staging root is created and hardened HERE, before restore() can write a
    // byte into it: <data_dir> itself is a plain 0755 mkdir, restore-server.sh sets
    // no umask, and what lands under staging is the plaintext dump plus the TLS
    // key, the operational seed, the Dropbox token and the unit file's DB password
    // — left there for the whole restore. This is the mirror of the 0700 the backup
    // path already puts on its transient dump dir.
    let staging = cfg.data_dir.join("_restore_work").join(&the_plan.stamp);
    std::fs::create_dir_all(&staging)?;
    harden_dir(&staging);
    let apply_req = RestoreRequest {
        cold,
        passphrase: &passphrase,
        from: &args.from,
        only,
        db_mode,
        dry_run: false,
        force: args.force,
        live_db_present,
        staging: &staging,
    };
    let report = restore(&apply_req, &the_plan).await?;

    // The driver contract: everything the next steps need is under <staging>.
    println!("staging={}", staging.display());
    if let Some(p) = &report.db_dump {
        println!("db_dump={}", p.display());
    }
    if let Some(p) = &report.state_dir {
        println!("state_dir={}", p.display());
    }
    if let Some(p) = &report.plan_json {
        println!("plan_json={}", p.display());
    }
    Ok(())
}

// ---- list-backups ----

async fn do_list() -> Result<(), Box<dyn Error>> {
    let cfg = LauncherConfig::from_env();
    let layout = Layout::ensure(&cfg.data_dir)?;
    let tiers = run::build_backup_tiers(&cfg, &layout)?.ok_or(
        "no cold tier configured — nothing to list. Pass --cold-tier-fs/--dropbox-env via \
         restore-server.sh, or set MAXSECU_COLD_TIER",
    )?;
    // Fails closed on a tier that cannot enumerate (TierCannotList): an empty list
    // shown to an operator about to roll back would read as "nothing to roll back to".
    let summaries = list_backups(tiers.cold.as_ref()).await?;
    if summaries.is_empty() {
        println!("no backups");
    } else {
        for s in &summaries {
            println!(
                "{}  git={}  created_at={}  db={} state={}",
                s.stamp,
                s.git_sha.as_deref().unwrap_or("<none>"),
                s.created_at,
                s.db_parts,
                s.state_parts
            );
        }
    }
    Ok(())
}

// ---- restore-db-merge (invocation #3, driver-internal) ----

async fn do_merge(args: MergeArgs) -> Result<(), Box<dyn Error>> {
    let cfg = LauncherConfig::from_env();
    let live_url = cfg.database_url.clone().ok_or(
        "restore-db-merge needs a reachable live database (DATABASE_URL) — this is the \
         same-box merge path",
    )?;
    // The live pool MUST be max_connections(1): the merge's stopped-server guard
    // counts pg_stat_activity rows other than its own backend, so an idle sibling
    // in our own pool would self-trip ServerStillConnected.
    // The scratch-DB URL carries the DB password, so it arrives on stdin, never on
    // argv (which /proc exposes to every local user) — the same discipline the
    // bundle passphrase follows.
    let staged_url = read_stdin_line()?;
    if staged_url.is_empty() {
        return Err("restore-db-merge: expected the scratch-database URL on stdin".into());
    }
    let live = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&live_url)
        .await?;
    let staged = PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&staged_url)
        .await?;
    let preview = restore_db_merge(&live, &staged, args.apply).await?;
    println!(
        "db merge ({}):",
        if args.apply {
            "applied"
        } else {
            "dry-run preview"
        }
    );
    println!("{}", serde_json::to_string_pretty(&preview)?);
    Ok(())
}

/// `verify-restored-blobs` — the dead-box `--replace` blob-resolution audit
/// (design "Dead-box `--replace`").
///
/// With no live DB there are no tombstones, so a `replace` puts back every file
/// that existed at backup time — including ones deleted since, and ones whose
/// backed-up version was superseded by a post-backup **rotation** (that version's
/// chunks were purged at finalize). Either way the row returns as a feed entry
/// whose ciphertext is gone, and it 404s on download. This walks the restored
/// current-version streams and names the files whose bytes do not resolve.
///
/// Runs as its own subcommand, invoked by `restore-server.sh` AFTER `pg_restore`,
/// because at the moment `restore` finishes unsealing there is no restored
/// `file_streams` table to walk yet.
///
/// **Advisory by construction.** It exits 0 even when it finds missing ciphertext:
/// the restore already happened and is the right outcome, and a cold-tier fault is
/// indistinguishable from a real absence from here. It prints; the operator
/// decides. It never drops a row — conflating "the owner deleted this" with
/// "Dropbox hiccuped during the restore" would permanently destroy live files.
async fn do_verify_restored_blobs() -> Result<(), Box<dyn Error>> {
    let cfg = LauncherConfig::from_env();
    let url = cfg.database_url.clone().ok_or(
        "verify-restored-blobs needs the restored database (DATABASE_URL) — it runs after pg_restore",
    )?;
    let layout = Layout::ensure(&cfg.data_dir)?;
    // Fail closed on no cold tier: with `ColdTierCfg::Off` there is nothing to
    // probe, and silently printing "all resolved" would be the exact false
    // reassurance this audit exists to remove.
    let tiers = run::build_backup_tiers(&cfg, &layout)?.ok_or(
        "verify-restored-blobs needs a cold tier — without one there is nothing to probe, and a \
         clean report would be meaningless",
    )?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&url)
        .await?;

    let refs = enumerate_current_stream_owners(&pool).await?;
    let report = verify_stream_blobs(tiers.cold.as_ref(), &refs).await;

    println!(
        "blob resolution: {} of {} stream(s) resolved on the cold tier",
        report.present,
        refs.len()
    );

    let files = report.missing_file_ids();
    if !files.is_empty() {
        // The wording must name BOTH causes: attributing this only to deletions
        // would tell the operator to "let the owners re-delete them", which is
        // wrong advice for a rotation.
        println!(
            "warning: {} restored files have missing ciphertext:",
            files.len()
        );
        for chunk in files.chunks(6) {
            let line: Vec<String> = chunk.iter().map(hex16).collect();
            println!("  {}", line.join("  "));
        }
        println!(
            "these are post-backup deletions (their owners can re-delete them) or post-backup"
        );
        println!("rotations (the backed-up version's chunks were purged at finalize).");
        println!("no rows were dropped — a cold-tier fault looks identical from here.");
    }
    if !report.faults.is_empty() {
        println!(
            "warning: {} streams could not be verified (cold tier fault)",
            report.faults.len()
        );
        // Name a couple so the operator can tell a rate-limit from an auth failure.
        for (r, e) in report.faults.iter().take(3) {
            println!("  {r}: {e}");
        }
    }
    if report.is_clean() {
        println!("  every restored file's ciphertext resolves — nothing to audit");
    }
    Ok(())
}

/// Like [`enumerate_current_streams`], but carries the owning `file_id` so the
/// audit can report FILES rather than opaque blob refs. Same
/// `current_version` join, for the same reason: an in-flight, not-yet-finalized
/// upload must not be walked.
async fn enumerate_current_stream_owners(
    pool: &sqlx::PgPool,
) -> Result<Vec<([u8; 16], String)>, Box<dyn Error>> {
    let rows = sqlx::query(
        "SELECT s.file_id, s.blob_ref \
         FROM file_streams s \
         JOIN files f ON f.file_id = s.file_id AND f.current_version = s.version",
    )
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        let fid: Vec<u8> = r.try_get("file_id")?;
        let blob_ref: String = r.try_get("blob_ref")?;
        let fid: [u8; 16] = fid
            .as_slice()
            .try_into()
            .map_err(|_| "file_streams.file_id is not 16 bytes")?;
        out.push((fid, blob_ref));
    }
    Ok(out)
}

/// Lowercase hex of a 16-byte id, for operator-facing output.
fn hex16(b: &[u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---- time helpers (no date crate; Howard Hinnant's civil_from_days) ----

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A compact `YYYYMMDDTHHMMSSZ` UTC stamp. 16 chars, all `[0-9A-Za-z]`, so it
/// passes the engine's `[0-9A-Za-z-]{1,32}` stamp guard and sorts
/// lexicographically == chronologically (which is what `prune` relies on).
fn utc_stamp(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let sod = (unix_secs % 86_400) as i64;
    let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z")
}

/// Best-effort `0700` on a directory this binary is about to fill with plaintext
/// secrets (Unix only; a no-op elsewhere). Two call sites: the transient
/// pg_dump work dir on the backup path, and the restore staging root — the dump
/// carries every DEK wrap, and staging additionally materializes the TLS private
/// key and the delegation triple. Neither may be world-readable for the moment it
/// exists on disk.
#[cfg(unix)]
fn harden_dir(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn harden_dir(_dir: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn backup_defaults_keep_and_parses_keep() {
        assert_eq!(
            parse(&v(&["backup"])).unwrap(),
            Command::Backup { keep: DEFAULT_KEEP }
        );
        assert_eq!(
            parse(&v(&["backup", "--keep", "3"])).unwrap(),
            Command::Backup { keep: 3 }
        );
        assert!(parse(&v(&["backup", "--keep"])).is_err());
        assert!(parse(&v(&["backup", "--keep", "-1"])).is_err());
        assert!(parse(&v(&["backup", "--nope"])).is_err());
    }

    /// Retention prunes AFTER the bundle is committed, so `--keep 0` would delete
    /// the bundle this run just wrote and still print "backup complete".
    #[test]
    fn backup_refuses_keep_zero() {
        let err = parse(&v(&["backup", "--keep", "0"])).unwrap_err();
        assert!(err.contains("at least 1"), "{err}");
    }

    /// The DB password must never reach `pg_dump`'s argv, where `/proc` publishes it
    /// to every local account for the length of the dump.
    #[test]
    fn pg_password_is_split_out_of_the_conninfo() {
        assert_eq!(
            split_pg_password("postgres://maxsecu:hunter2@localhost/maxsecu"),
            (
                "postgres://maxsecu@localhost/maxsecu".to_owned(),
                Some("hunter2".to_owned())
            )
        );
        // Port, query string, and a percent-encoded password.
        assert_eq!(
            split_pg_password("postgres://u:p%40ss%3A1@127.0.0.1:5432/db?sslmode=require"),
            (
                "postgres://u@127.0.0.1:5432/db?sslmode=require".to_owned(),
                Some("p@ss:1".to_owned())
            )
        );
        // Nothing to split: no userinfo, no password, a malformed escape, or a
        // non-URI conninfo. Each must pass through byte-for-byte — a backup that
        // stops working is worse than one whose argv still carries the secret.
        for untouched in [
            "postgres://localhost/maxsecu",
            "postgres://maxsecu@localhost/maxsecu",
            "postgres://maxsecu:@localhost/maxsecu",
            "postgres://u:bad%zz@localhost/db",
            "host=localhost user=maxsecu dbname=maxsecu",
        ] {
            assert_eq!(
                split_pg_password(untouched),
                (untouched.to_owned(), None),
                "{untouched}"
            );
        }
    }

    #[test]
    fn restore_requires_from_and_defaults_the_rest() {
        assert!(parse(&v(&["restore"])).is_err());
        let cmd = parse(&v(&["restore", "--from", "latest"])).unwrap();
        assert_eq!(
            cmd,
            Command::Restore(RestoreArgs {
                from: "latest".to_owned(),
                only: None,
                db_mode: None,
                dry_run: false,
                force: false,
            })
        );
    }

    #[test]
    fn restore_parses_every_flag() {
        let cmd = parse(&v(&[
            "restore",
            "--from",
            "20260716T000000Z",
            "--only",
            "db,state",
            "--db-mode",
            "replace",
            "--force",
            "--dry-run",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Command::Restore(RestoreArgs {
                from: "20260716T000000Z".to_owned(),
                only: Some(Only {
                    db: true,
                    state: true,
                    code: false,
                    blobs: false,
                }),
                db_mode: Some(DbMode::Replace),
                dry_run: true,
                force: true,
            })
        );
    }

    #[test]
    fn only_component_list_is_validated() {
        assert_eq!(
            parse_only("code").unwrap(),
            Only {
                db: false,
                state: false,
                code: true,
                blobs: false,
            }
        );
        assert_eq!(
            parse_only("db,state,code,blobs").unwrap(),
            Only {
                db: true,
                state: true,
                code: true,
                blobs: true,
            }
        );
        assert!(parse_only("db,frobnicate").is_err());
        assert!(parse_only("").is_err());
    }

    #[test]
    fn db_mode_rejects_a_bad_value() {
        assert!(parse(&v(&["restore", "--from", "latest", "--db-mode", "wipe"])).is_err());
    }

    #[test]
    fn list_backups_takes_no_arguments() {
        assert_eq!(parse(&v(&["list-backups"])).unwrap(), Command::ListBackups);
        assert!(parse(&v(&["list-backups", "extra"])).is_err());
    }

    #[test]
    fn merge_parses_apply_and_takes_no_url_flag() {
        // The scratch URL is on stdin, never argv — so bare and `--apply` are the
        // only forms, and a `--staged-url` flag is rejected as unexpected.
        assert_eq!(
            parse(&v(&["restore-db-merge"])).unwrap(),
            Command::RestoreDbMerge(MergeArgs { apply: false })
        );
        assert_eq!(
            parse(&v(&["restore-db-merge", "--apply"])).unwrap(),
            Command::RestoreDbMerge(MergeArgs { apply: true })
        );
        assert!(parse(&v(&["restore-db-merge", "--staged-url", "postgres://x/s"])).is_err());
    }

    #[test]
    fn verify_restored_blobs_takes_no_arguments() {
        assert_eq!(
            parse(&v(&["verify-restored-blobs"])).unwrap(),
            Command::VerifyRestoredBlobs
        );
        // A typo'd flag must be a hard error, never silently ignored.
        assert!(parse(&v(&["verify-restored-blobs", "--apply"])).is_err());
    }

    #[test]
    fn unknown_subcommand_and_empty_are_errors() {
        assert!(parse(&v(&["frobnicate"])).is_err());
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn utc_stamp_is_a_valid_sortable_stamp() {
        // 2026-07-16T12:34:56Z.
        let s = utc_stamp(1_784_205_296);
        assert_eq!(s, "20260716T123456Z");
        assert_eq!(s.len(), 16);
        assert!(s.bytes().all(|b| b.is_ascii_alphanumeric()));
        // Lexicographic order tracks time.
        assert!(utc_stamp(1_000) < utc_stamp(1_000_000));
    }
}
