//! The backward-compatibility gate.
//!
//! HARD RULE (docs/compat/CHECKLIST.md): *every upgrade must keep existing
//! users' access intact — account/login, keys, and already-uploaded data. No
//! change may force a re-enroll, re-key, re-upload, re-share, or reset.*
//!
//! This crate holds the two mechanisms that make that rule enforceable:
//!
//! 1. **The golden corpus** (`compat/fixtures/`) — artifacts produced ONCE and
//!    frozen, committed with the key material needed to open them. The tests
//!    *open* them (unlock / unwrap / verify / decode). This is deliberately NOT
//!    a round-trip: a round-trip seals and opens with the same code, so both
//!    sides drift together and the test stays green while real users' data
//!    rots.
//! 2. **Value locks** — direct assertions on the constants that *are* the
//!    format (type_ids, domain-separation labels, magic bytes, fixed lengths,
//!    path schemes), so a break fails at the line that causes it with a message
//!    naming the blast radius.
//!
//! Fixtures may be ADDED. Never edited. Never deleted. `corpus.lock` in each
//! area enforces that; `docs/compat/LEDGER.md` records every intentional
//! format change and how old data is still read.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Pointer printed by every failure so whoever hits the gate knows what to do.
pub const CHECKLIST: &str = "see docs/compat/CHECKLIST.md (backward-compatibility gate)";

/// Absolute path of the shared corpus root (`<repo>/compat/fixtures`).
///
/// Resolved from `CARGO_MANIFEST_DIR` so it works from BOTH cargo workspaces:
/// `crates/compat` (root workspace) and `crates/client-app` (client workspace)
/// are both two levels below the repo root.
pub fn fixtures_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo = manifest
        .parent()
        .and_then(Path::parent)
        .expect("crates/<crate> is two levels below the repo root");
    repo.join("compat").join("fixtures")
}

/// Absolute path of one corpus area (`encoding`, `crypto`, `keyblob`, …).
pub fn area(name: &str) -> PathBuf {
    fixtures_root().join(name)
}

/// Read a frozen fixture's raw bytes.
pub fn read(area_name: &str, file: &str) -> Vec<u8> {
    let path = area(area_name).join(file);
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "missing frozen fixture {}: {e}\n\
             Fixtures are ADD-ONLY: they may never be edited or deleted. If this file was \
             removed, restore it — an existing user's data depends on today's code still \
             being able to open it. {CHECKLIST}",
            path.display()
        )
    })
}

/// Read a frozen fixture as UTF-8 (trailing newline trimmed).
pub fn read_str(area_name: &str, file: &str) -> String {
    String::from_utf8(read(area_name, file))
        .expect("fixture is not UTF-8")
        .trim_end_matches(['\r', '\n'])
        .to_string()
}

/// Lowercase hex SHA-256 — the corpus-lock digest.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Enforce one area's `corpus.lock`: every listed fixture must exist and hash
/// exactly as recorded, and every file present must be listed.
///
/// This is the mechanism behind "fixtures may be added, never edited or
/// deleted". Editing a fixture changes its digest (fail). Deleting one drops a
/// lock entry (fail). Adding one without recording it (fail) — so a new fixture
/// is always a deliberate, reviewable act.
///
/// Lock format: `<filename>  <sha256-hex>`, one per line, sorted by filename.
/// `#` comments and blank lines are ignored. `corpus.lock` does not list itself.
pub fn verify_corpus_lock(area_name: &str) {
    let dir = area(area_name);
    let lock_path = dir.join("corpus.lock");
    let lock = std::fs::read_to_string(&lock_path).unwrap_or_else(|e| {
        panic!("missing corpus lock {}: {e}. {CHECKLIST}", lock_path.display())
    });

    let mut locked: Vec<(String, String)> = Vec::new();
    for line in lock.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let (name, digest) = (it.next(), it.next());
        match (name, digest) {
            (Some(n), Some(d)) => locked.push((n.to_string(), d.to_string())),
            _ => panic!(
                "malformed line in {}: {line:?} (want `<filename>  <sha256-hex>`)",
                lock_path.display()
            ),
        }
    }
    assert!(
        !locked.is_empty(),
        "{} is empty — the corpus for `{area_name}` would be unprotected. {CHECKLIST}",
        lock_path.display()
    );

    for (name, want) in &locked {
        let got = sha256_hex(&read(area_name, name));
        assert_eq!(
            &got, want,
            "\n\nFROZEN FIXTURE CHANGED: compat/fixtures/{area_name}/{name}\n\
             A fixture is a snapshot of data a REAL USER already has on disk. Editing it \
             does not fix a failing test — it hides the fact that today's code can no \
             longer open yesterday's data.\n\
             If you intended a format change: keep this fixture and the code path that \
             opens it, ADD a new fixture for the new format, and record it in \
             docs/compat/LEDGER.md.\n{CHECKLIST}\n"
        );
    }

    // Every file present must be locked (catches an un-recorded addition).
    let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .map(|e| e.expect("dir entry").file_name().to_string_lossy().into_owned())
        .filter(|n| n != "corpus.lock")
        .collect();
    on_disk.sort();

    for name in &on_disk {
        assert!(
            locked.iter().any(|(n, _)| n == name),
            "compat/fixtures/{area_name}/{name} is not recorded in corpus.lock. \
             Adding a fixture is fine — record its digest so the corpus stays add-only. {CHECKLIST}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures_root_resolves_to_the_shared_corpus() {
        let root = fixtures_root();
        assert!(
            root.ends_with("compat/fixtures") || root.ends_with("compat\\fixtures"),
            "unexpected corpus root: {}",
            root.display()
        );
    }

    #[test]
    fn sha256_hex_is_the_standard_digest() {
        // Known answer: SHA-256 of the empty string.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
