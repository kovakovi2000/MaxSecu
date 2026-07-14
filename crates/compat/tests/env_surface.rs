//! **The env surface — "a new setting must reach the servers that already exist."**
//!
//! The same hole as the schema one, in a different file.
//!
//! `scripts/install-server.sh` writes the systemd unit, **including its
//! `Environment=` lines**. `scripts/upgrade-server.sh` never rewrites that unit —
//! it only ever appended a `capacity.conf` drop-in. Therefore:
//!
//! > **A new `MAXSECU_*` environment variable added to the installer reaches
//! > FRESH INSTALLS ONLY. Every already-deployed server keeps the unit it was
//! > installed with, forever.**
//!
//! That was latent — every variable happens to have a safe default in
//! `LauncherConfig::from_parts`, so an upgraded server that never heard of one
//! still behaved identically. The day a variable lands *without* a safe default —
//! or the day a default's meaning changes — every upgraded server silently becomes
//! a different product from every fresh one, with real users on it and no admin
//! escape hatch.
//!
//! `upgrade-server.sh` now reconciles the unit's environment. This file makes that
//! reconcile **impossible to forget**, by locking together the three places the
//! surface is written down:
//!
//! ```text
//!   crates/portable-server/src/config.rs   MAXSECU_ENV_VARS  +  the env("…") reads
//!   scripts/install-server.sh              SERVER_ENV_SURFACE    (fresh installs)
//!   scripts/upgrade-server.sh              SERVER_ENV_RECONCILE  (existing servers)
//! ```
//!
//! Add a variable to the code without wiring both scripts and the gate fails,
//! naming the blast radius.
//!
//! **Why source text and not a `use`:** `crates/compat`'s library half must stay
//! dependency-light (it is dev-depended on from the *client* workspace, where
//! `sqlx` cannot be linked), so this crate cannot import `maxsecu-portable-server`.
//! Asserting against the source text is the same technique `value_locks.rs`
//! already uses for `HYBRID_WRAP_LABEL`, and it has a bonus: it compares what the
//! code *declares* against what the code *actually reads*, which a `use` could not
//! do at all.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use maxsecu_compat::CHECKLIST;

// =========================================================================== //
// The allow-list — the ONLY sanctioned way for a variable to skip the scripts
// =========================================================================== //

/// Variables the server reads that deliberately appear in **neither** script.
///
/// This is an opt-out that is **visible in review**, not an accident. A variable
/// belongs here only if it must not be named in a unit at all. If it merely needs
/// no *value* (its compiled-in default is correct), that is NOT this list — say so
/// in the scripts' own tables instead (`|default` in `SERVER_ENV_SURFACE`, `|-` in
/// `SERVER_ENV_RECONCILE`), where an operator reading the deployment scripts can
/// see the decision and its reason.
///
/// It is empty on purpose: today, every variable the server reads is accounted for
/// in both scripts, each with a written reason. Adding an entry here is a claim
/// that a deployed server never needs to know about a setting its own binary reads
/// — make that claim explicitly, with the reason, in the tuple's second field.
const NO_UNIT_ENTRY_ALLOWLIST: &[(&str, &str)] = &[
    // ("MAXSECU_EXAMPLE", "why a deployed unit must never name this"),
];

// =========================================================================== //
// Repo paths + source readers
// =========================================================================== //

fn repo_root() -> PathBuf {
    maxsecu_compat::fixtures_root()
        .parent()
        .and_then(Path::parent)
        .expect("compat/fixtures is two levels below the repo root")
        .to_path_buf()
}

fn read_repo_file(rel: &[&str]) -> String {
    let mut p = repo_root();
    for seg in rel {
        p.push(seg);
    }
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}. {CHECKLIST}", p.display()))
}

/// The part of a Rust source file that actually SHIPS: everything before the first
/// column-0 `#[cfg(test)]`.
///
/// Test code may read whatever it likes (`MAXSECU_TEST_PG`, the live-Dropbox
/// credentials, fake environments such as `env(&[("MAXSECU_PORT", "9000")])`) —
/// none of it is a read by the shipped server, and counting it would let a
/// variable that is only ever *tested* masquerade as part of the deployed surface.
///
/// Column-0 on purpose: `dropbox_tier.rs` mentions `#[cfg(test)]` inside a `//!`
/// doc comment, and cutting there would silently skip most of that file. This errs
/// toward scanning MORE prod code, never less.
fn ships(src: &str) -> &str {
    match src.find("\n#[cfg(test)]") {
        Some(i) => &src[..i],
        None => src,
    }
}

/// `crates/portable-server/src/config.rs`, test module cut off.
fn config_src_prod() -> String {
    let src = read_repo_file(&["crates", "portable-server", "src", "config.rs"]);
    ships(&src).to_string()
}

/// Every capture of `re`-ish pattern `prefix"NAME"suffix` in `hay`.
///
/// A hand-rolled scanner rather than a regex crate: `maxsecu-compat` deliberately
/// carries almost no dependencies, and the shapes we match are fixed.
fn scan_quoted_after(hay: &str, prefix: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = hay;
    while let Some(i) = rest.find(prefix) {
        rest = &rest[i + prefix.len()..];
        let Some(end) = rest.find('"') else { break };
        let name = &rest[..end];
        if !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            out.insert(name.to_string());
        }
        rest = &rest[end + 1..];
    }
    out
}

// --------------------------------------------------------------------------- //
// (1) What the CODE declares, and what the CODE actually reads
// --------------------------------------------------------------------------- //

/// The names inside `pub const MAXSECU_ENV_VARS: &[&str] = &[ … ];`.
fn declared_env_vars() -> BTreeSet<String> {
    let src = config_src_prod();
    let start = src.find("pub const MAXSECU_ENV_VARS").unwrap_or_else(|| {
        panic!(
            "crates/portable-server/src/config.rs no longer declares \
             `pub const MAXSECU_ENV_VARS`. It is the single source of truth for the server's \
             environment surface — the list that scripts/install-server.sh and \
             scripts/upgrade-server.sh are checked against. Without it, a new variable reaches \
             fresh installs only and every existing server silently runs without it. {CHECKLIST}"
        )
    });
    let end = src[start..]
        .find("];")
        .map(|i| start + i)
        .expect("MAXSECU_ENV_VARS must be terminated with `];`");

    let names = scan_quoted_after(&src[start..end], "\"");
    // `scan_quoted_after` with a bare `"` prefix walks the literals pairwise; the
    // slice holds nothing but the array literal, so every entry is a var name.
    assert!(!names.is_empty(), "MAXSECU_ENV_VARS is empty. {CHECKLIST}");
    names
}

/// Every variable `from_parts` actually reads: the literals in `env("NAME")`.
fn read_env_vars() -> BTreeSet<String> {
    scan_quoted_after(&config_src_prod(), "env(\"")
}

// --------------------------------------------------------------------------- //
// (2) What each deployment SCRIPT knows about
// --------------------------------------------------------------------------- //

/// One `NAME|VALUE` table embedded in a shell script:
///
/// ```sh
/// SERVER_ENV_SURFACE='
/// DATABASE_URL|unit
/// …
/// '
/// ```
fn shell_table(script: &str, var: &str) -> Vec<(String, String)> {
    let src = read_repo_file(&["scripts", script]);
    let open = format!("{var}='\n");
    let start = src.find(&open).unwrap_or_else(|| {
        panic!(
            "scripts/{script} no longer defines the `{var}` table. It is that script's half of \
             the server's environment surface, and the compat gate cannot verify a deployment \
             path that does not declare one. {CHECKLIST}"
        )
    }) + open.len();
    let end = src[start..]
        .find("\n'")
        .map(|i| start + i)
        .unwrap_or_else(|| panic!("scripts/{script}: `{var}` table is not closed with `'`"));

    let mut out = Vec::new();
    for line in src[start..end].lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line.split_once('|').unwrap_or_else(|| {
            panic!("scripts/{script}: malformed `{var}` row {line:?} (want `NAME|VALUE`)")
        });
        out.push((name.trim().to_string(), value.trim().to_string()));
    }
    assert!(
        !out.is_empty(),
        "scripts/{script}: the `{var}` table is empty. {CHECKLIST}"
    );
    out
}

fn install_surface() -> Vec<(String, String)> {
    shell_table("install-server.sh", "SERVER_ENV_SURFACE")
}

fn upgrade_reconcile() -> Vec<(String, String)> {
    shell_table("upgrade-server.sh", "SERVER_ENV_RECONCILE")
}

fn names_of(table: &[(String, String)]) -> BTreeSet<String> {
    table.iter().map(|(n, _)| n.clone()).collect()
}

fn allowlisted(name: &str) -> bool {
    NO_UNIT_ENTRY_ALLOWLIST.iter().any(|(n, _)| *n == name)
}

/// The set the scripts are required to cover: everything the code reads, minus the
/// explicit allow-list.
fn must_be_wired() -> BTreeSet<String> {
    declared_env_vars()
        .into_iter()
        .filter(|n| !allowlisted(n))
        .collect()
}

// =========================================================================== //
// The gate
// =========================================================================== //

/// The declared surface must be exactly what the code reads.
///
/// This is the join between "a human wrote a list" and "the binary reaches for a
/// variable". Without it, `MAXSECU_ENV_VARS` would be a comment: a new
/// `env("MAXSECU_NEW_THING")` could slip in with the list untouched, and the two
/// script checks below — which are driven off the list — would happily pass.
#[test]
fn compat_declared_env_surface_is_exactly_what_the_server_reads() {
    let declared = declared_env_vars();
    let read = read_env_vars();

    let undeclared: Vec<&String> = read.difference(&declared).collect();
    assert!(
        undeclared.is_empty(),
        "\n\nUNDECLARED ENVIRONMENT VARIABLE(S): {undeclared:?}\n\
         \n\
         crates/portable-server/src/config.rs READS these, but MAXSECU_ENV_VARS does not list\n\
         them — so neither deployment script can possibly know about them.\n\
         \n\
         BLAST RADIUS: this variable will reach FRESH INSTALLS ONLY. install-server.sh writes\n\
         the systemd unit; upgrade-server.sh never rewrites it. Every server that is already\n\
         deployed — real users, real data, no admin escape hatch — will silently run WITHOUT\n\
         this variable, forever, while every new install runs with it. The one binary you ship\n\
         then means two different things depending on when the box was installed.\n\
         \n\
         Fix: add each name to MAXSECU_ENV_VARS, then wire BOTH\n\
           scripts/install-server.sh    (SERVER_ENV_SURFACE  — fresh installs)\n\
           scripts/upgrade-server.sh    (SERVER_ENV_RECONCILE — servers that already exist)\n\
         {CHECKLIST}\n"
    );

    let stale: Vec<&String> = declared.difference(&read).collect();
    assert!(
        stale.is_empty(),
        "\n\nSTALE ENTRY IN MAXSECU_ENV_VARS: {stale:?} — declared, but nothing in \
         `from_parts` reads them. Either the read was dropped (then drop the entry, and \
         leave the scripts' tables alone until you are sure no deployed unit still sets it) \
         or the name was mistyped. {CHECKLIST}\n"
    );
}

/// Every variable must reach a FRESH install.
#[test]
fn compat_every_server_env_var_reaches_fresh_installs() {
    let want = must_be_wired();
    let have = names_of(&install_surface());

    let missing: Vec<&String> = want.difference(&have).collect();
    assert!(
        missing.is_empty(),
        "\n\nNOT WIRED INTO THE FRESH-INSTALL PATH: {missing:?}\n\
         \n\
         The server reads these, but scripts/install-server.sh's SERVER_ENV_SURFACE table does\n\
         not mention them — so a brand-new server would be configured without them.\n\
         \n\
         Add a row `NAME|unit` (an Environment= line in the unit), `NAME|unit-opt` (written\n\
         only on the deployment shape it applies to), `NAME|envfile` (a secret: it belongs in\n\
         the root-only 0600 EnvironmentFile, never in the unit), or `NAME|default` (the\n\
         compiled-in default is correct — say WHY on the line below the table).\n\
         {CHECKLIST}\n"
    );
}

/// Every variable must reach a server that **already exists**. This is the one the
/// whole file is for.
#[test]
fn compat_every_server_env_var_reaches_existing_installs() {
    let want = must_be_wired();
    let have = names_of(&upgrade_reconcile());

    let missing: Vec<&String> = want.difference(&have).collect();
    assert!(
        missing.is_empty(),
        "\n\nNOT WIRED INTO THE UPGRADE PATH: {missing:?}\n\
         \n\
         BLAST RADIUS: this variable will reach FRESH INSTALLS ONLY. Every server that is\n\
         ALREADY DEPLOYED will silently run without it.\n\
         \n\
         scripts/install-server.sh writes the systemd unit — including its Environment= lines —\n\
         and it runs exactly once, at install time. scripts/upgrade-server.sh never rewrites\n\
         that unit; it reconciles the unit's environment from its SERVER_ENV_RECONCILE table,\n\
         and a variable that is not in that table is a variable it cannot deliver. So the\n\
         operator who has been running MaxSecu for six months, with real users' data on it,\n\
         gets a new binary that reads a setting their unit has never heard of — and nobody\n\
         finds out until the default it silently fell back to turns out to be the wrong one.\n\
         \n\
         Add a row `NAME|<default>` to SERVER_ENV_RECONCILE in scripts/upgrade-server.sh. The\n\
         default must be EXACTLY the value the binary already uses when the variable is absent\n\
         — that is what makes writing it into a live server's unit provably behaviour-\n\
         preserving. If absence is meaningful or the value is unguessable (DATABASE_URL, a\n\
         data dir, a secret), use `-` (never synthesize) and write down why.\n\
         {CHECKLIST}\n"
    );
}

/// The two scripts must cover the SAME set. A variable known to one path only is
/// precisely the divergence this gate exists to prevent — and it is also how a
/// stale row (a variable the code stopped reading) is caught before it rots.
#[test]
fn compat_both_deployment_paths_declare_the_same_env_surface() {
    let install = names_of(&install_surface());
    let upgrade = names_of(&upgrade_reconcile());

    let fresh_only: Vec<&String> = install.difference(&upgrade).collect();
    let upgrade_only: Vec<&String> = upgrade.difference(&install).collect();
    assert!(
        fresh_only.is_empty() && upgrade_only.is_empty(),
        "\n\nTHE TWO DEPLOYMENT PATHS DISAGREE ABOUT THE SERVER'S ENVIRONMENT.\n\
         \n\
           only in scripts/install-server.sh  (fresh installs get it, existing servers never will): {fresh_only:?}\n\
           only in scripts/upgrade-server.sh  (upgrades try to deliver something no install writes): {upgrade_only:?}\n\
         \n\
         A fresh install and an upgraded install must be the same product. Both tables must\n\
         name every variable in MAXSECU_ENV_VARS — differing only in what each one DOES with\n\
         it. {CHECKLIST}\n"
    );

    // And neither table may carry a name the code does not read (a stale row would
    // quietly keep writing a setting the server has stopped honouring).
    let declared = declared_env_vars();
    let unknown: Vec<&String> = install.difference(&declared).collect();
    assert!(
        unknown.is_empty(),
        "\n\nthe deployment scripts declare {unknown:?}, which the server does not read \
         (not in MAXSECU_ENV_VARS). Either the code dropped the read — in which case leave \
         the row alone until every deployed unit has stopped setting it, and say so here — \
         or the name is a typo, which means the real variable is NOT being delivered. \
         {CHECKLIST}\n"
    );
}

/// `DATABASE_URL` is not a `MAXSECU_*` variable, and it is the most load-bearing
/// one there is: it carries a per-install random password that exists nowhere but
/// the unit. Synthesizing it would point the server at a database that does not
/// exist — every account, key and upload gone, from the users' point of view.
///
/// So it gets its own lock: present in both tables, **never** given a default, and
/// its absence on an existing server is a hard, pre-flight ERROR rather than
/// something the upgrade quietly papers over.
#[test]
fn compat_database_url_is_never_synthesized() {
    let install = install_surface();
    let upgrade = upgrade_reconcile();

    let install_row = install
        .iter()
        .find(|(n, _)| n == "DATABASE_URL")
        .unwrap_or_else(|| {
            panic!("scripts/install-server.sh's SERVER_ENV_SURFACE does not mention DATABASE_URL — a fresh install would have no database. {CHECKLIST}")
        });
    assert_eq!(
        install_row.1, "unit",
        "\n\nDATABASE_URL must be written into the unit by install-server.sh (`unit`): it is \
         generated there, with a fresh random password, and the unit (root:root 0600) is the \
         ONLY place it is ever recorded. {CHECKLIST}\n"
    );

    let upgrade_row = upgrade
        .iter()
        .find(|(n, _)| n == "DATABASE_URL")
        .unwrap_or_else(|| {
            panic!("scripts/upgrade-server.sh's SERVER_ENV_RECONCILE does not mention DATABASE_URL. {CHECKLIST}")
        });
    assert_eq!(
        upgrade_row.1, "-",
        "\n\nSERVER_ENV_RECONCILE gives DATABASE_URL a default of {:?}.\n\
         \n\
         There is no such thing as a default DATABASE_URL. It carries a per-install random\n\
         password that exists nowhere but that server's unit file. Writing a guess into a\n\
         drop-in would OVERRIDE the real one (drop-ins are applied after the base unit) and\n\
         point the server at a database that does not exist — from every user's point of view,\n\
         every account, every key and every upload would be gone. It must stay `-` (never\n\
         synthesize), and a missing DATABASE_URL must remain a hard pre-flight error.\n\
         {CHECKLIST}\n",
        upgrade_row.1
    );

    // The hard error must actually be there: upgrade-server.sh refuses to restart
    // into a server it cannot reach the database for, BEFORE it changes anything.
    let src = read_repo_file(&["scripts", "upgrade-server.sh"]);
    assert!(
        src.contains("error: no DATABASE_URL in"),
        "\n\nscripts/upgrade-server.sh no longer HARD-FAILS when the unit has no DATABASE_URL. \
         Because it can never be synthesized, its absence is unrecoverable and must abort the \
         upgrade before anything is touched — not fall through to a restart against a \
         database the server cannot find. {CHECKLIST}\n"
    );
}

/// The server must read its environment **only** through `LauncherConfig`.
///
/// A `std::env::var("MAXSECU_…")` anywhere else bypasses `MAXSECU_ENV_VARS`, and
/// with it every check in this file — the variable would be invisible to both
/// deployment scripts and would, once again, reach fresh installs only.
#[test]
fn compat_server_reads_env_only_through_launcher_config() {
    for krate in ["portable-server", "server"] {
        let dir = repo_root().join("crates").join(krate).join("src");

        for entry in walk_rs(&dir) {
            let src = std::fs::read_to_string(&entry).expect("read source");
            let found = scan_quoted_after(ships(&src), "env::var(\"");
            let leaked: Vec<&String> = found
                .iter()
                .filter(|n| n.starts_with("MAXSECU_") || *n == "DATABASE_URL")
                .collect();
            assert!(
                leaked.is_empty(),
                "\n\n{} reads {leaked:?} straight from the process environment.\n\
                 \n\
                 Every variable the server reads must go through LauncherConfig::from_parts, \
                 because MAXSECU_ENV_VARS — and therefore both deployment scripts, and \
                 therefore every already-deployed server — is derived from the reads there. A \
                 read hidden anywhere else is invisible to this gate: it would reach fresh \
                 installs only, and every existing server would silently run without it. \
                 Route it through crates/portable-server/src/config.rs. {CHECKLIST}\n",
                entry.display()
            );
        }
    }
}

/// Recurse a `src/` tree, yielding every `.rs` file.
fn walk_rs(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk_rs(&p));
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
    out
}

/// The generated drop-in is world-readable (0644). A secret must never be given a
/// default in the reconcile table, or the upgrade would copy it out of the
/// root-only 0600 creds file into a file anyone on the box can read.
#[test]
fn compat_reconcile_defaults_never_carry_a_secret() {
    for (name, default) in upgrade_reconcile() {
        let secretish = name.contains("SECRET")
            || name.contains("TOKEN")
            || name.contains("KEY")
            || name == "DATABASE_URL";
        if secretish {
            assert_eq!(
                default, "-",
                "\n\nSERVER_ENV_RECONCILE gives {name} a default value. That table's output is \
                 a 0644 systemd drop-in, and {name} looks like a credential. Secrets reach the \
                 server through the root-only 0600 EnvironmentFile (/etc/maxsecu/dropbox.env) \
                 and must be `-` (never synthesized) here. {CHECKLIST}\n"
            );
        }
    }
}
