//! The CLIENT half of the backward-compatibility gate (surfaces 7 and 11 of
//! `docs/superpowers/specs/2026-07-14-backward-compat-gate-design.md`).
//!
//! HARD RULE: *every upgrade must keep existing users' access intact — account /
//! login, keys, and already-uploaded data. No change may force a re-enroll,
//! re-key, re-upload, re-share, or reset.*
//!
//! `crates/client-app` is its OWN cargo workspace and is EXCLUDED from CI, so the
//! user's most access-critical local state — keyblob, pinned server, TOFU pins,
//! contacts, settings, in-flight uploads — has had ZERO regression coverage. This
//! file is that coverage. It runs two mechanisms:
//!
//! 1. **Golden corpus** — artifacts produced ONCE (by `compat_emit_fixtures`,
//!    `#[ignore]`d, the `crates/encoding/tests/golden.rs` convention), committed
//!    under `compat/fixtures/`, and OPENED here. Deliberately NOT round-trips: a
//!    round-trip seals and opens with the same code, so both sides drift together,
//!    the suite stays green, and real users' data rots.
//! 2. **Value locks** — direct assertions on the constants that ARE the format, so
//!    a break fails at the line that causes it with a message naming the blast
//!    radius.
//!
//! Regenerating a fixture is a corpus-lock failure BY DESIGN. To land an
//! intentional format change: keep the old fixture + the code path that opens it,
//! ADD a new fixture, and record it in `docs/compat/LEDGER.md`.
//!
//! Run: `cargo test --manifest-path crates/client-app/Cargo.toml --test compat \
//!       --features unpinned-dev`
//! Emit (deliberate, once): `... --test compat -- --ignored compat_emit_fixtures`

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use maxsecu_client_app::commands::recovery_login::{
    build_recovery_challenge_body, build_recovery_verify_body,
};
use maxsecu_client_app::commands::register::build_register_body;
use maxsecu_client_app::commands::share::build_add_wrap_body;
use maxsecu_client_app::config::{FragmentCacheLocation, RouteMode, SettingsConfig};
use maxsecu_client_app::session::{build_session_challenge_body, build_session_prove_body};
use maxsecu_client_app::upload::{stage_body, StageFlags};
use maxsecu_client_app::upload_staging::StagingStore;
use maxsecu_client_app::{config, contacts, index, keystore, layout, ram, recovery_pin, tofu, transparency};

use maxsecu_client_core::transparency::{KtCheckpoint, KtCheckpointStore};
use maxsecu_client_core::{keyblob, Identity};

use maxsecu_compat::{self as compat, CHECKLIST};

use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Corpus areas
// ---------------------------------------------------------------------------

/// `compat/fixtures/pin/` — surface 7 (`canonical_pin` + the `pin_fp` connection
/// code). Flat.
const PIN: &str = "pin";
/// `compat/fixtures/client-state/` — surface 11 (settings / TOFU / contacts /
/// search index / KT checkpoint / staging record) plus `wire/` (the client-emitted
/// HTTP request bodies, §5).
const STATE: &str = "client-state";
/// `compat/fixtures/keyblob/` — OWNED BY TRACK 1 (`client-core` side). Read-only
/// here: we additionally assert the CLIENT-APP path (`keystore.rs`) opens the same
/// frozen blobs, i.e. a real user's existing keystore still logs in.
const KEYBLOB: &str = "keyblob";

/// The FIXED, non-secret seeds the frozen pin fixtures are derived from. Test-only
/// key material, and only ever the PUBLIC halves are written to the corpus.
const PIN_X25519_SEED: [u8; 32] = [0xA1; 32];
const PIN_MLKEM_SEED: [u8; 64] = [0xB2; 64];

/// The passphrase that opens the frozen client-state identity keyblob. Test-only.
const STATE_PASSPHRASE: &str = "compat gate frozen identity 2026!";

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn tmp_dir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "mxcompat-{tag}-{}-{}",
        std::process::id(),
        hex(&maxsecu_crypto::random_array::<8>())
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("temp dir");
    p
}

/// Read a frozen fixture that lives in a SUB-directory of an area (`wire/…`).
fn read_sub(area_name: &str, rel: &str) -> Vec<u8> {
    let path = compat::area(area_name).join(rel);
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "missing frozen fixture {}: {e}\nFixtures are ADD-ONLY. {CHECKLIST}",
            path.display()
        )
    })
}

fn read_json(area_name: &str, file: &str) -> Value {
    serde_json::from_slice(&compat::read(area_name, file)).expect("fixture is JSON")
}

/// Copy a frozen fixture into a throwaway app-dir at the path the SHIPPED code
/// reads it from — so the test exercises the real loader, not a bespoke one.
fn place(area_name: &str, fixture: &str, dir: &Path, rel: &str) {
    let dst = dir.join(rel);
    std::fs::create_dir_all(dst.parent().expect("has parent")).expect("mkdir");
    std::fs::write(&dst, compat::read(area_name, fixture)).expect("place fixture");
}

/// The unlocked identity every frozen client-state store was sealed to. Opening
/// them at all proves the keyblob + the four seal labels are unchanged.
fn frozen_identity() -> Identity {
    let blob = compat::read(STATE, "identity_v2.keyblob");
    keyblob::unlock(STATE_PASSPHRASE, &blob).unwrap_or_else(|_| {
        panic!(
            "\n\nThe frozen client-state identity keyblob no longer unlocks.\n\
             BLAST RADIUS: every existing user's `keystore/local_key_blob` is this \
             format — they can no longer log in, and their identity (hence every DEK \
             wrap and every uploaded file) is gone. There is no admin escape hatch.\n{CHECKLIST}\n"
        )
    })
}

/// Sorted top-level keys of a JSON object.
fn keys_of(v: &Value) -> BTreeSet<String> {
    v.as_object()
        .expect("body is a JSON object")
        .keys()
        .cloned()
        .collect()
}

fn frozen_keys(rel: &str) -> BTreeSet<String> {
    let v: Value = serde_json::from_slice(&read_sub(STATE, rel)).expect("frozen key set is JSON");
    v.as_array()
        .expect("frozen key set is a JSON array")
        .iter()
        .map(|k| k.as_str().expect("key is a string").to_owned())
        .collect()
}

/// The gate for one request body: today's builder must emit a SUPERSET of the
/// frozen key set. Adding keys is fine (additive discipline); DROPPING one is a
/// silent break — the server still reads it.
fn assert_superset(what: &str, blast: &str, frozen: &BTreeSet<String>, now: &BTreeSet<String>) {
    let missing: Vec<&String> = frozen.difference(now).collect();
    assert!(
        missing.is_empty(),
        "\n\n{what}: the client STOPPED SENDING {missing:?}\n\
         BLAST RADIUS: {blast}\n\
         The server still reads these keys. Dropping one is not a refactor — it is a \
         silent, unrecoverable break for every existing user. (Adding keys is fine.)\n{CHECKLIST}\n"
    );
}

// ---------------------------------------------------------------------------
// 0. corpus.lock — fixtures may be ADDED. Never edited. Never deleted.
// ---------------------------------------------------------------------------

/// Recursive corpus-lock check. `maxsecu_compat::verify_corpus_lock` reads only an
/// area's TOP-LEVEL dir; `client-state` has a `wire/` sub-dir, so that area is
/// verified here (same lock format, `/`-separated relative names) rather than by
/// editing the shared helper.
fn verify_corpus_lock_recursive(area_name: &str) {
    let dir = compat::area(area_name);
    let lock_path = dir.join("corpus.lock");
    let lock = std::fs::read_to_string(&lock_path)
        .unwrap_or_else(|e| panic!("missing corpus lock {}: {e}. {CHECKLIST}", lock_path.display()));

    let mut locked: Vec<(String, String)> = Vec::new();
    for line in lock.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        match (it.next(), it.next()) {
            (Some(n), Some(d)) => locked.push((n.to_owned(), d.to_owned())),
            _ => panic!("malformed line in {}: {line:?}", lock_path.display()),
        }
    }
    assert!(!locked.is_empty(), "{} is empty. {CHECKLIST}", lock_path.display());

    for (name, want) in &locked {
        let got = compat::sha256_hex(&read_sub(area_name, name));
        assert_eq!(
            &got, want,
            "\n\nFROZEN FIXTURE CHANGED: compat/fixtures/{area_name}/{name}\n\
             A fixture is a snapshot of data a REAL USER already has on disk. Editing it \
             does not fix a failing test — it hides the fact that today's code can no \
             longer open yesterday's data.\n\
             If you intended a format change: keep this fixture AND the code path that \
             opens it, ADD a new fixture, and record it in docs/compat/LEDGER.md.\n{CHECKLIST}\n"
        );
    }

    let mut on_disk = Vec::new();
    walk(&dir, &dir, &mut on_disk);
    for name in &on_disk {
        assert!(
            locked.iter().any(|(n, _)| n == name),
            "compat/fixtures/{area_name}/{name} is not recorded in corpus.lock. \
             Adding a fixture is fine — record its digest so the corpus stays add-only. {CHECKLIST}"
        );
    }
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
    for e in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let p = e.expect("dir entry").path();
        if p.is_dir() {
            walk(root, &p, out);
        } else {
            let rel = p
                .strip_prefix(root)
                .expect("under root")
                .to_string_lossy()
                .replace('\\', "/");
            if rel != "corpus.lock" {
                out.push(rel);
            }
        }
    }
}

#[test]
fn compat_corpus_is_locked() {
    compat::verify_corpus_lock(PIN); // flat area — the shared helper suffices
    verify_corpus_lock_recursive(STATE); // has `wire/`
}

// ---------------------------------------------------------------------------
// 1. Surface 7 — canonical_pin (33 B classical / 1217 B hybrid) + pin_fp
// ---------------------------------------------------------------------------

/// The frozen pins are what a SHIPPED, already-installed client has baked into its
/// binary. If today's `parse_pin` cannot read them, that client can no longer
/// verify the recovery pin it wraps every upload to.
#[test]
fn compat_canonical_pin_v1_classical_and_hybrid_still_parse() {
    for (fixture, expect) in [
        ("canonical_pin_v1_classical.bin", "canonical_pin_v1_classical.expect.json"),
        ("canonical_pin_v1_hybrid.bin", "canonical_pin_v1_hybrid.expect.json"),
    ] {
        let bytes = compat::read(PIN, fixture);
        let want = read_json(PIN, expect);

        assert_eq!(
            bytes.len() as u64,
            want["len"].as_u64().unwrap(),
            "\n\n{fixture}: the canonical pin LENGTH moved.\n\
             BLAST RADIUS: every shipped client embeds a pin of this exact shape and \
             compares the server-served recovery key against it byte-for-byte — a length \
             change makes every install trip the RecoveryPinMismatch trust alarm and \
             refuse to upload.\n{CHECKLIST}\n"
        );
        assert_eq!(
            bytes[32] as u64,
            want["tag"].as_u64().unwrap(),
            "\n\n{fixture}: the ML-KEM presence TAG byte moved (0x00 = classical, \
             0x01 = hybrid). Same blast radius as above. {CHECKLIST}\n"
        );

        let parsed = recovery_pin::parse_pin(&bytes).unwrap_or_else(|| {
            panic!(
                "\n\n{fixture}: today's `parse_pin` REJECTS a pin shape that shipped \
                 clients embed.\nBLAST RADIUS: those installs can no longer verify the \
                 recovery pin — uploads fail closed forever.\n{CHECKLIST}\n"
            )
        });
        assert_eq!(hex(&parsed.enc_pub), want["enc_pub_hex"].as_str().unwrap());
        match want["mlkem_pub_hex"].as_str() {
            None => assert!(parsed.mlkem_pub.is_none(), "{fixture}: unexpected ML-KEM half"),
            Some(h) => assert_eq!(
                hex(&parsed.mlkem_pub.expect("hybrid pin carries an ML-KEM key")),
                h,
                "\n\n{fixture}: the ML-KEM half of the pin decoded differently.\n\
                 BLAST RADIUS: a malicious server could swap ONLY the ML-KEM key and go \
                 undetected — the pin exists to make that impossible.\n{CHECKLIST}\n"
            ),
        }

        // `canonical_pin` must still RE-ENCODE the frozen bytes exactly (the ONE encoder
        // shared by maxsecu-setup, the server endpoint and this client).
        let re = recovery_pin::canonical_pin(&parsed.enc_pub, parsed.mlkem_pub.as_ref().map(|m| &m[..]));
        assert_eq!(re, bytes, "\n\n{fixture}: canonical_pin no longer re-encodes the frozen pin. {CHECKLIST}\n");

        // The install-client verify step hashes the embedded pin (`--print-recovery-pin-fp`).
        assert_eq!(
            hex(&maxsecu_crypto::sha256(&bytes)),
            want["sha256_hex"].as_str().unwrap(),
            "\n\n{fixture}: sha256(pin) changed — `install-client.ps1`'s fail-closed pin \
             verification compares exactly this digest against `recovery_pin.bin`. {CHECKLIST}\n"
        );
    }
}

/// The 32-char base32 **connection code** the user literally types/pastes at
/// install. It commits to `server_cert.der` ‖ `directory_pub.der`.
#[test]
fn compat_pin_bootstrap_connection_code_is_stable() {
    let cert = compat::read(PIN, "bootstrap_server_cert.der");
    let dir_pub = compat::read(PIN, "bootstrap_directory_pub.der");
    let want = read_json(PIN, "bootstrap_pins.expect.json");

    let code = maxsecu_crypto::pin_fingerprint(&cert, &dir_pub);
    assert_eq!(
        code,
        want["connection_code"].as_str().unwrap(),
        "\n\nThe pin-bootstrap CONNECTION CODE changed for the SAME pinned bytes.\n\
         BLAST RADIUS: the code an operator already handed to their users no longer \
         matches what their server prints — every new install fails its pin check, and \
         the in-band bootstrap (`maxsecu-setup fetch-pins`) is dead.\n{CHECKLIST}\n"
    );
    assert_eq!(code.len(), 32, "the connection code is exactly 32 base32 chars");
    assert!(
        code.chars().all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)),
        "RFC 4648 base32 alphabet, uppercase, no padding: {code}"
    );
}

// ---------------------------------------------------------------------------
// 2. Surface 11 — config/settings.json
// ---------------------------------------------------------------------------

/// Fixed RAM bounds so the migration assertions are machine-independent (the live
/// `normalized()` clamps against the box's actual RAM).
fn fixed_limits() -> ram::RamLimits {
    ram::RamLimits { default_mb: 1024, min_mb: 64, max_mb: 8192 }
}

#[test]
fn compat_settings_current_file_still_loads() {
    let dir = tmp_dir("settings-current");
    place(STATE, "settings_current.json", &dir, "config/settings.json");
    let s = SettingsConfig::load(&dir);
    let want = read_json(STATE, "settings_current.expect.json");

    assert_eq!(s.appearance.theme, want["theme"].as_str().unwrap());
    assert_eq!(s.appearance.frontend, want["frontend"].as_str().unwrap());
    assert_eq!(s.ui.bundle_view, want["bundle_view"].as_str().unwrap());
    assert_eq!(s.a11y.text_size, want["text_size"].as_str().unwrap());
    assert_eq!(s.connection.route_mode, RouteMode::PreferDropbox);
    assert_eq!(s.performance.cache_location, FragmentCacheLocation::Disk);
    // A settings.json that fails to parse silently reverts to defaults — the user's
    // route, theme and cache prefs vanish with no error. Assert we did NOT default.
    assert_ne!(
        s, SettingsConfig::default(),
        "\n\nThe frozen settings.json parsed as DEFAULTS.\n\
         BLAST RADIUS: `SettingsConfig::load` swallows a parse error and returns \
         `default()` — so a field rename silently RESETS every user's preferences \
         (including their Tor route) with no error at all.\n{CHECKLIST}\n"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn compat_settings_legacy_file_still_migrates() {
    // (a) The real loader accepts it at all.
    let dir = tmp_dir("settings-legacy");
    place(STATE, "settings_legacy.json", &dir, "config/settings.json");
    let live = SettingsConfig::load(&dir);
    assert_eq!(
        live.connection.route_mode,
        RouteMode::TorOnly,
        "\n\nA legacy `use_tor: true` no longer migrates to RouteMode::TorOnly.\n\
         BLAST RADIUS: a user who chose Tor is SILENTLY downgraded to clearnet on \
         upgrade — a privacy break they never consented to and cannot see.\n{CHECKLIST}\n"
    );
    let _ = std::fs::remove_dir_all(&dir);

    // (b) Exact migrated values, against FIXED RAM bounds (machine-independent).
    let raw = compat::read(STATE, "settings_legacy.json");
    let parsed: SettingsConfig = serde_json::from_slice(&raw).unwrap_or_else(|e| {
        panic!(
            "\n\nA LEGACY settings.json no longer deserializes: {e}\n\
             BLAST RADIUS: every user upgrading from that build silently loses their \
             saved preferences.\n{CHECKLIST}\n"
        )
    });
    let n = parsed.normalized_with_ram(&fixed_limits());
    let want = read_json(STATE, "settings_legacy.expect.json");
    assert_eq!(
        n.performance.media_cache_cap_mb as u64,
        want["media_cache_cap_mb"].as_u64().unwrap(),
        "\n\nThe dead `ram_cache_cap_mb` key no longer folds into `media_cache_cap_mb` \
         (`PerformanceSettingsWire`). BLAST RADIUS: every pre-rework user's cache budget \
         silently resets.\n{CHECKLIST}\n"
    );
    assert_eq!(n.performance.thumb_cache_cap_mb as u64, want["thumb_cache_cap_mb"].as_u64().unwrap());
    assert_eq!(n.connection.route_mode, RouteMode::TorOnly);
    assert!(n.connection.use_tor, "`use_tor` stays synced for older readers");
    // The dead key must never be written back out.
    let re = serde_json::to_string(&n).unwrap();
    assert!(!re.contains("ram_cache_cap_mb"), "the legacy key re-serialized: {re}");
}

/// Forward-compat: a file written by a NEWER client (unknown keys) must not brick
/// an older one. `SettingsConfig::load` swallows parse errors into `default()`, so
/// an unknown key that failed to parse would silently WIPE the user's settings.
#[test]
fn compat_settings_with_unknown_future_key_still_loads() {
    let dir = tmp_dir("settings-future");
    place(STATE, "settings_future_key.json", &dir, "config/settings.json");
    let s = SettingsConfig::load(&dir);
    assert_eq!(
        s.appearance.theme, "light",
        "\n\nA settings.json carrying an UNKNOWN (future) key no longer parses — it fell \
         back to defaults.\nBLAST RADIUS: a user who ran a newer build once (or synced their \
         folder) has every preference silently reset by the older build, with no error. \
         Never add `#[serde(deny_unknown_fields)]` to `SettingsConfig`.\n{CHECKLIST}\n"
    );
    assert_eq!(s.connection.route_mode, RouteMode::TorOnly);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 3. Surface 11 — the four IDENTITY-SEALED stores
// ---------------------------------------------------------------------------

/// TOFU pins (`tofu/pins.tofu`, label `MaxSecu-tofu-pins-v1`).
///
/// Losing this file is a SECURITY downgrade, not a UX bug: an empty pin store
/// re-trusts whatever key the server serves next, silently, with no alarm.
#[test]
fn compat_tofu_pins_still_unseal() {
    let dir = tmp_dir("tofu");
    place(STATE, "tofu_pins.tofu", &dir, "tofu/pins.tofu");
    let id = frozen_identity();

    let mut store = tofu::TofuStore::open(&dir, &id).unwrap_or_else(|_| {
        panic!(
            "\n\nThe frozen `tofu/pins.tofu` no longer UNSEALS.\n\
             BLAST RADIUS — THIS IS A SECURITY DOWNGRADE, NOT A UX BUG: the TOFU store is \
             the ONLY thing that detects a server swapping another user's key (trust-alarm \
             B). A store that cannot be opened is a store that gets rebuilt empty — and an \
             empty store re-pins whatever key the server serves next, SILENTLY, with no \
             alarm. Every prior pin's protection is gone.\n\
             Changing the seal label (`MaxSecu-tofu-pins-v1`), the nonce framing, or the \
             on-disk JSON shape does exactly this.\n{CHECKLIST}\n"
        )
    });

    let want = read_json(STATE, "tofu_pins.expect.json");
    for (username, fp_hex) in want.as_object().unwrap() {
        let pinned = store
            .pinned_fingerprint(username)
            .unwrap_or_else(|| panic!("pin for {username} was lost. {CHECKLIST}"));
        assert_eq!(&hex(&pinned), fp_hex.as_str().unwrap());
        // And the pinned key still MATCHES (not re-Pinned = it really was loaded).
        let enc: [u8; 32] = [0xE1; 32];
        let sig: [u8; 32] = [0x51; 32];
        if username == "alice" {
            assert_eq!(
                store.check_or_pin("alice", &enc, &sig).unwrap(),
                tofu::TofuOutcome::Match,
                "the frozen pin loaded but does not MATCH its key — TOFU is broken. {CHECKLIST}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Contacts (`contacts/contacts.bin`, label `MaxSecu-contacts-v1`).
#[test]
fn compat_contacts_still_unseal() {
    let dir = tmp_dir("contacts");
    place(STATE, "contacts.bin", &dir, "contacts/contacts.bin");
    let id = frozen_identity();

    let store = contacts::ContactStore::open(&dir, &id).unwrap_or_else(|_| {
        panic!(
            "\n\nThe frozen `contacts/contacts.bin` no longer UNSEALS.\n\
             BLAST RADIUS: the user's whole address book (the share picker's roster) is \
             gone — they must re-discover every person they have ever shared with. Seal \
             label `MaxSecu-contacts-v1`.\n{CHECKLIST}\n"
        )
    });
    let want = read_json(STATE, "contacts.expect.json");
    let list = store.list();
    assert_eq!(list.len(), want.as_array().unwrap().len(), "contacts were dropped. {CHECKLIST}");
    for (got, exp) in list.iter().zip(want.as_array().unwrap()) {
        assert_eq!(got.username, exp["username"].as_str().unwrap());
        assert_eq!(hex(&got.user_id), exp["user_id_hex"].as_str().unwrap());
        assert_eq!(hex(&got.fingerprint), exp["fingerprint_hex"].as_str().unwrap());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Search index (`index/search.idx`, label `MaxSecu-search-index-v1`).
#[test]
fn compat_search_index_still_unseals() {
    let dir = tmp_dir("index");
    place(STATE, "search_index.idx", &dir, "index/search.idx");
    let id = frozen_identity();

    let idx = index::load(&dir, &id).unwrap_or_else(|_| {
        panic!(
            "\n\nThe frozen `index/search.idx` no longer UNSEALS.\n\
             BLAST RADIUS: `index::load` FAILS CLOSED on a decrypt error, so search stops \
             working entirely (it does not silently rebuild) — the user's whole local \
             title/tag index is unreadable. Seal label `MaxSecu-search-index-v1`.\n{CHECKLIST}\n"
        )
    });
    let want = read_json(STATE, "search_index.expect.json");
    assert_eq!(idx.entries.len(), want.as_array().unwrap().len());
    for (got, exp) in idx.entries.iter().zip(want.as_array().unwrap()) {
        assert_eq!(got.file_id, exp["file_id"].as_str().unwrap());
        assert_eq!(got.file_type, exp["file_type"].as_str().unwrap());
        assert_eq!(got.title, exp["title"].as_str().unwrap());
    }
    // The index still SEARCHES (the consumer, not just the decoder).
    assert_eq!(idx.search("sunset").len(), 1, "the frozen index no longer searches. {CHECKLIST}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// KT gossip checkpoint (`kt/checkpoint.kt`, label `MaxSecu-kt-checkpoint-v1`).
#[test]
fn compat_kt_checkpoint_still_unseals() {
    let dir = tmp_dir("kt");
    place(STATE, "kt_checkpoint.kt", &dir, "kt/checkpoint.kt");
    let id = frozen_identity();

    let store = transparency::DiskKtCheckpointStore::open(&dir, &id).unwrap_or_else(|_| {
        panic!(
            "\n\nThe frozen `kt/checkpoint.kt` no longer UNSEALS.\n\
             BLAST RADIUS — SECURITY: the persisted gossip checkpoint is what makes a \
             cross-session key-transparency SPLIT-VIEW / ROLLBACK detectable. Losing it \
             resets the client to 'first use', so a server that already equivocated can \
             simply present a fresh consistent-looking log. Seal label \
             `MaxSecu-kt-checkpoint-v1`.\n{CHECKLIST}\n"
        )
    });
    let want = read_json(STATE, "kt_checkpoint.expect.json");
    let cp = store.latest().expect("the frozen checkpoint was lost");
    assert_eq!(cp.tree_size, want["tree_size"].as_u64().unwrap());
    assert_eq!(hex(&cp.root), want["root_hex"].as_str().unwrap());
    assert_eq!(hex(&cp.sig), want["sig_hex"].as_str().unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 4. Surface 11 — staging/<file_id>/record.json (in-flight resumable upload)
// ---------------------------------------------------------------------------

/// Plain, UNVERSIONED, unsealed JSON — a known weak spot, frozen AS-IS (see the
/// ledger). An in-flight resumable upload must survive an app upgrade.
#[test]
fn compat_staging_record_still_deserializes() {
    let dir = tmp_dir("staging");
    let want = read_json(STATE, "staging_record.expect.json");
    let file_id_hex = want["file_id_hex"].as_str().unwrap();
    place(STATE, "staging_record.json", &dir, &format!("staging/{file_id_hex}/record.json"));

    let store = StagingStore::new(dir.join("staging"));
    let mut file_id = [0u8; 16];
    for (i, b) in file_id.iter_mut().enumerate() {
        *b = u8::from_str_radix(&file_id_hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    let rec = store.load(&file_id).unwrap_or_else(|e| {
        panic!(
            "\n\nThe frozen `staging/<file_id>/record.json` no longer deserializes: {e}\n\
             BLAST RADIUS: every user with an in-flight resumable upload (a large video can \
             stage for hours) loses it on upgrade and must RE-UPLOAD from scratch. This \
             record is unversioned — adding/renaming a non-`Option` field breaks it. \
             Give it a version tag before you change it (docs/compat/LEDGER.md).\n{CHECKLIST}\n"
        )
    });
    assert_eq!(hex(&rec.file_id), file_id_hex);
    assert_eq!(rec.file_type, want["file_type"].as_str().unwrap());
    assert_eq!(rec.title, want["title"].as_str().unwrap());
    assert_eq!(rec.content_chunk_count, want["content_chunk_count"].as_u64().unwrap());
    assert_eq!(rec.progress, want["progress"].as_u64().unwrap());
    assert_eq!(rec.wraps.len(), want["wraps"].as_u64().unwrap() as usize);
    assert_eq!(rec.small_streams.len(), want["small_streams"].as_u64().unwrap() as usize);
    assert!(
        rec.small_streams.iter().all(|s| s.stream_type != 1),
        "the security invariant broke: a staged SMALL stream must never be `content` (1)"
    );
    // The RESUME wire body still builds from that record (the finalize path).
    let body = maxsecu_client_app::commands::upload::stage_body_from_record(&rec, StageFlags::default());
    let frozen = frozen_keys("wire/stage_files_body.keys.json");
    assert_superset(
        "POST /v1/files (resumed from staging record)",
        "an upload staged by yesterday's client can no longer be finalized — the user \
         re-uploads the whole file",
        &frozen,
        &keys_of(&body),
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 5. Surface 3 (client-app path) — the keystore opens Track 1's frozen keyblobs
// ---------------------------------------------------------------------------

/// A REAL user's existing `keystore/local_key_blob` must still log in. The blobs
/// are frozen by Track 1 in `compat/fixtures/keyblob/` (the `client-core` side);
/// this asserts the CLIENT-APP consumer (`keystore::unlock`) opens them too.
///
/// If that area is not present yet the test reports the dependency and passes —
/// it becomes a hard gate the moment Track 1's fixtures land.
#[test]
fn compat_client_app_keystore_opens_frozen_keyblobs() {
    let area = compat::area(KEYBLOB);
    if !area.is_dir() {
        eprintln!(
            "PENDING TRACK 1: {} does not exist yet — the client-app keystore gate is \
             INACTIVE. It activates automatically once the keyblob fixtures land.",
            area.display()
        );
        return;
    }

    let mut checked = 0usize;
    for entry in std::fs::read_dir(&area).expect("read keyblob area") {
        let path = entry.expect("dir entry").path();
        // Track 1 names them `keyblob_v*.bin`; accept `.blob` too so a rename there
        // cannot silently switch this gate off.
        if !matches!(path.extension().and_then(|e| e.to_str()), Some("bin" | "blob")) {
            continue;
        }
        let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
        let pw_path = area.join(format!("{stem}.passphrase.txt"));
        let Ok(pw) = std::fs::read_to_string(&pw_path) else {
            panic!(
                "{} has no sibling {stem}.passphrase.txt — the frozen keyblob cannot be \
                 opened, so this gate would silently pass. {CHECKLIST}",
                area.display()
            )
        };
        let pw = pw.trim_end_matches(['\r', '\n']);

        // Place it exactly where the shipped client reads it and drive the REAL loader.
        let dir = tmp_dir(&format!("keystore-{stem}"));
        std::fs::create_dir_all(dir.join("keystore")).unwrap();
        std::fs::copy(&path, keystore::keystore_path(&dir)).unwrap();
        assert!(keystore::exists(&dir));

        let id = keystore::unlock(&dir, pw).unwrap_or_else(|e| {
            panic!(
                "\n\nclient-app `keystore::unlock` REJECTS the frozen keyblob {stem} \
                 (code `{}`).\n\
                 BLAST RADIUS: this is a real user's `keystore/local_key_blob`. They cannot \
                 log in; their identity — and with it every DEK wrap and every file they \
                 have ever uploaded — is unrecoverable. There is no admin escape hatch.\n{CHECKLIST}\n",
                e.code
            )
        });

        // Cross-check against Track 1's expectation file (their key names; `_hex`
        // suffixes accepted too, in case they rename).
        let exp: Value = serde_json::from_slice(&std::fs::read(area.join(format!("{stem}.expect.json"))).unwrap_or_else(
            |_| panic!("{stem} has no sibling expect.json — nothing to compare. {CHECKLIST}"),
        ))
        .expect("expect.json");
        let want = |k: &str| -> Option<String> {
            exp.get(k)
                .or_else(|| exp.get(format!("{k}_hex").as_str()))
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        };
        if let Some(w) = want("enc_pub") {
            assert_eq!(hex(&id.enc_pub_bytes()), w, "{stem}: enc_pub changed on unlock. {CHECKLIST}");
        }
        if let Some(w) = want("sig_pub") {
            assert_eq!(hex(&id.sig_pub_bytes()), w, "{stem}: sig_pub changed on unlock. {CHECKLIST}");
        }
        if let Some(w) = want("fingerprint") {
            assert_eq!(hex(&id.fingerprint()), w, "{stem}: the identity FINGERPRINT changed. {CHECKLIST}");
        }
        // v1 = classical (no ML-KEM); v2 = PQ. BOTH must still log in: an existing v1
        // user must not be locked out by the PQ work, and a v2 user must keep their
        // ML-KEM half (without it every Suite::V2 reshare to them fails `pq_key_missing`).
        match exp.get("mlkem_pub_sha256").and_then(|v| v.as_str()) {
            None => assert!(
                id.mlkem_pub_bytes().is_none(),
                "{stem}: a v1 (classical) keyblob must unlock to a NON-PQ identity. {CHECKLIST}"
            ),
            Some(w) => {
                let mlkem = id.mlkem_pub_bytes().unwrap_or_else(|| {
                    panic!(
                        "\n\n{stem}: a v2 keyblob no longer yields its ML-KEM key.\n\
                         BLAST RADIUS: the PQ half is re-derived from the stored 64-byte seed on \
                         unlock — losing it means every `Suite::V2` reshare to this user fails \
                         `pq_key_missing`, and they cannot open PQ-hybrid wraps.\n{CHECKLIST}\n"
                    )
                });
                assert_eq!(hex(&maxsecu_crypto::sha256(&mlkem)), w, "{stem}: the ML-KEM key changed. {CHECKLIST}");
            }
        }
        checked += 1;
        let _ = std::fs::remove_dir_all(&dir);
    }

    assert!(
        checked > 0,
        "compat/fixtures/keyblob/ exists but holds no keyblob — the client-app keystore \
         gate would silently pass. {CHECKLIST}"
    );
}

// ---------------------------------------------------------------------------
// 6. Value locks — the constants that ARE the format
// ---------------------------------------------------------------------------

/// The four identity-derived seal labels. They are the HKDF `info` AND the AEAD
/// AAD of the four sealed stores, so changing one byte makes every existing store
/// of that kind permanently unopenable. The golden fixtures above prove this
/// behaviourally; this locks the literals so the break is reported at its cause.
#[test]
fn compat_value_lock_seal_labels() {
    for (module, src, label, blast) in [
        (
            "tofu.rs",
            include_str!("../src/tofu.rs"),
            "MaxSecu-tofu-pins-v1",
            "every TOFU pin is lost — and an empty pin store SILENTLY re-trusts whatever key \
             the server serves next (a security downgrade, not a UX bug)",
        ),
        (
            "contacts.rs",
            include_str!("../src/contacts.rs"),
            "MaxSecu-contacts-v1",
            "every user's address book is unreadable",
        ),
        (
            "index.rs",
            include_str!("../src/index.rs"),
            "MaxSecu-search-index-v1",
            "the local search index fails closed — search stops working entirely",
        ),
        (
            "transparency.rs",
            include_str!("../src/transparency.rs"),
            "MaxSecu-kt-checkpoint-v1",
            "the persisted KT gossip checkpoint is lost, so a cross-session split-view / \
             rollback by the server becomes undetectable",
        ),
    ] {
        assert!(
            src.contains(&format!("b\"{label}\"")),
            "\n\nSEAL LABEL CHANGED in src/{module}: `{label}` is gone.\n\
             BLAST RADIUS: {blast}.\n\
             The label is both the HKDF info and the AEAD AAD — one byte of drift and every \
             store already on a user's disk is permanently unopenable. If this is \
             intentional you MUST keep a read path for the old label.\n{CHECKLIST}\n"
        );
    }
}

/// `canonical_pin`'s wire shape: `enc_pub[32] ‖ tag u8 [‖ mlkem_pub[1184]]`.
#[test]
fn compat_value_lock_canonical_pin_shape() {
    let classical = recovery_pin::canonical_pin(&[0u8; 32], None);
    assert_eq!(classical.len(), 33, "a classical pin is 33 bytes. {CHECKLIST}");
    assert_eq!(classical[32], 0x00, "the ML-KEM absent tag is 0x00. {CHECKLIST}");

    let hybrid = recovery_pin::canonical_pin(&[0u8; 32], Some(&[0u8; 1184]));
    assert_eq!(hybrid.len(), 1217, "a hybrid pin is 32 + 1 + 1184 = 1217 bytes. {CHECKLIST}");
    assert_eq!(hybrid[32], 0x01, "the ML-KEM present tag is 0x01. {CHECKLIST}");

    // The decoder accepts ONLY those two shapes (fail-closed on anything else): a
    // widened parser would let a malformed/truncated pin through.
    assert!(recovery_pin::parse_pin(&[0u8; 34]).is_none());
    assert!(recovery_pin::parse_pin(&[0u8; 1216]).is_none());
}

/// The portable app-dir layout. These directory names are the paths a shipped,
/// already-installed client reads its state from.
#[test]
fn compat_value_lock_app_dir_layout() {
    let dir = tmp_dir("layout");
    layout::ensure_portable_layout(&dir).unwrap();
    for sub in ["config", "keystore", "index", "cache", "logs", "staging", "webview"] {
        assert!(
            dir.join(sub).is_dir(),
            "\n\nThe app-dir layout lost `{sub}/`.\n\
             BLAST RADIUS: an existing install's folder IS this layout. Renaming a directory \
             orphans whatever lives in it — `keystore/` is the user's identity, `staging/` is \
             their in-flight uploads, `config/` is their pinned server.\n{CHECKLIST}\n"
        );
    }
    // The keystore path is the one a real user's identity already sits at.
    assert!(keystore::keystore_path(&dir).ends_with("keystore/local_key_blob")
        || keystore::keystore_path(&dir).ends_with("keystore\\local_key_blob"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The pinned-trust files in `config/`: `directory_pub.der` (raw 32 bytes),
/// `sink_custodians.der` (a concat of 32-byte keys), `sink.json` (`addr` +
/// `server_name`). These are the client's offline trust roots.
#[test]
fn compat_value_lock_pinned_file_shapes() {
    let dir = tmp_dir("pins");
    let cfg = dir.join("config");
    std::fs::create_dir_all(&cfg).unwrap();

    // directory_pub.der = RAW 32 bytes. Not DER-wrapped, not base64, not 31, not 33.
    let d5 = [0x7Du8; 32];
    std::fs::write(cfg.join("directory_pub.der"), d5).unwrap();
    assert_eq!(
        config::load_directory_pub(&dir).unwrap(),
        d5,
        "\n\n`config/directory_pub.der` is RAW 32 bytes — the pinned D5 directory root.\n\
         BLAST RADIUS: change the encoding and every installed client rejects its own \
         pinned root and fails closed on browse/admin — a TOTAL LOCKOUT.\n{CHECKLIST}\n"
    );
    std::fs::write(cfg.join("directory_pub.der"), [0u8; 31]).unwrap();
    assert_eq!(
        config::load_directory_pub(&dir).unwrap_err().code,
        "untrusted",
        "a malformed pinned root must FAIL CLOSED. {CHECKLIST}"
    );
    std::fs::write(cfg.join("directory_pub.der"), d5).unwrap();

    // sink.json keys + sink_custodians.der = N × 32 raw bytes (len % 32 == 0).
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    std::fs::write(cfg.join("sink_root.der"), cert.cert.der()).unwrap();
    std::fs::write(cfg.join("sink.json"), br#"{"addr":"127.0.0.1:9443","server_name":"localhost"}"#).unwrap();
    std::fs::write(cfg.join("sink_custodians.der"), [0x11u8; 32]).unwrap();
    let pins = config::load_sink_pins(&dir).unwrap_or_else(|e| {
        panic!(
            "\n\nThe pinned sink files no longer load (code `{}`).\n\
             BLAST RADIUS: `sink.json` keys are `addr` + `server_name`; \
             `sink_custodians.der` is a raw concat of 32-byte keys. A shape change makes \
             every deployment that pinned a sink fail closed — reshare/revocation dies.\n{CHECKLIST}\n",
            e.code
        )
    });
    assert_eq!(pins.custodian_pubs, vec![[0x11u8; 32]]);
    assert_eq!(pins.server_name, "localhost");
    std::fs::write(cfg.join("sink_custodians.der"), [0u8; 31]).unwrap();
    assert_eq!(
        config::load_sink_pins(&dir).unwrap_err().code,
        "sink_unpinned",
        "a custodian allowlist that is not a multiple of 32 must FAIL CLOSED. {CHECKLIST}"
    );

    // A deployment with NO sink pinned is opt-in (unanchored reshare), not an error.
    let bare = tmp_dir("pins-bare");
    std::fs::create_dir_all(bare.join("config")).unwrap();
    assert!(
        config::load_sink_pins_opt(&bare).unwrap().is_none(),
        "\n\nAn absent `sink.json` must stay OPT-IN.\n\
         BLAST RADIUS: making the sink REQUIRED again is the exact bug that made sharing \
         DOA on every single-server deploy (`sink endpoint is not pinned`).\n{CHECKLIST}\n"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&bare);
}

// ---------------------------------------------------------------------------
// 7. §5 — the CLIENT half of the HTTP seam (pure body builders)
// ---------------------------------------------------------------------------

/// A deterministic-enough identity for the wire-shape tests (the KEY SET is what
/// is frozen, never the random key bytes).
fn wire_identity() -> Identity {
    Identity::generate()
}

/// THE test that would have caught the shipped `mlkem_pub_b64` break: enrollment
/// stopped publishing the ML-KEM key, so the server signed a CLASSICAL directory
/// binding, so EVERY V2 reshare to that user failed `pq_key_missing` — and the fix
/// was not retroactive, so every already-enrolled user had to RE-ENROLL.
#[test]
fn compat_wire_register_body_still_publishes_mlkem_pub() {
    let id = wire_identity();
    let body = build_register_body("alice", &id, "test-registration-key");

    assert!(
        body.get("mlkem_pub_b64").and_then(|v| v.as_str()).is_some(),
        "\n\n`POST /v1/users` no longer sends `mlkem_pub_b64`.\n\
         BLAST RADIUS: the server then signs a CLASSICAL directory binding for this user, so \
         every `Suite::V2` (PQ-hybrid) reshare or rotation TO them fails closed with \
         `pq_key_missing` — sharing to them is dead. The fix is NOT retroactive: the binding \
         is signed once at enrollment, so every already-enrolled user must RE-ENROLL. This is \
         the exact break `2a626d6` shipped.\n{CHECKLIST}\n"
    );

    assert_superset(
        "POST /v1/users (register)",
        "enrollment breaks: no account, or an account whose directory binding is missing the \
         key material every later share depends on",
        &frozen_keys("wire/register_body.keys.json"),
        &keys_of(&body),
    );
    // The values are the identity's PUBLIC halves — never a secret.
    let enc = body["enc_pub_b64"].as_str().unwrap();
    assert_eq!(
        base64_decode(enc),
        id.enc_pub_bytes().to_vec(),
        "`enc_pub_b64` must be the raw 32-byte X25519 public key, base64 (STANDARD, padded)"
    );
    assert_eq!(
        base64_decode(body["mlkem_pub_b64"].as_str().unwrap()).len(),
        1184,
        "`mlkem_pub_b64` must be the raw 1184-byte ML-KEM-768 encapsulation key"
    );
}

#[test]
fn compat_wire_session_bodies_still_carry_every_key() {
    assert_superset(
        "POST /v1/session/challenge",
        "no user can log in",
        &frozen_keys("wire/session_challenge_body.keys.json"),
        &keys_of(&build_session_challenge_body("alice")),
    );
    assert_superset(
        "POST /v1/session/proof",
        "the channel-bound login proof is unverifiable — no user can log in",
        &frozen_keys("wire/session_prove_body.keys.json"),
        &keys_of(&build_session_prove_body("alice", 1_719_500_000_000, "cHJvb2Y=")),
    );
}

#[test]
fn compat_wire_recovery_bodies_still_carry_every_key() {
    // The challenge body is deliberately EMPTY (the recovery account is a singleton).
    // A newly-REQUIRED field here would break every shipped client's recovery login.
    assert_eq!(
        build_recovery_challenge_body(),
        json!({}),
        "\n\n`POST /v1/recovery/challenge` grew a field.\n\
         BLAST RADIUS: if the server ever REQUIRES it, every shipped client's recovery login \
         breaks — and recovery is the ONLY way back in (there is no admin escape hatch).\n{CHECKLIST}\n"
    );
    assert_superset(
        "POST /v1/recovery/verify",
        "recovery login breaks — and recovery is the last resort when a user loses their \
         password; there is no admin escape hatch",
        &frozen_keys("wire/recovery_verify_body.keys.json"),
        &keys_of(&build_recovery_verify_body("0f1e2d3c4b5a69788796a5b4c3d2e1f0", "cHJvb2Y=", 1_719_500_000_000)),
    );
}

#[test]
fn compat_wire_upload_and_share_bodies_still_carry_every_key() {
    use maxsecu_client_core::{build_upload, UploadParams};
    use maxsecu_crypto::generate_enc_keypair;
    use maxsecu_encoding::types::{FileType, Id, Timestamp};

    let owner = wire_identity();
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
    let streams = maxsecu_client_app::upload::prepare_blog_streams(b"hello".to_vec(), "Hi", &["t".to_owned()]);
    let bundle = build_upload(&params, &streams).expect("build_upload");

    // POST /v1/files — the body that CREATES the file record.
    let body = stage_body(&bundle, StageFlags::default());
    assert_superset(
        "POST /v1/files (stage upload)",
        "uploading is dead: the file record, its manifest signature, its stream table or its \
         DEK wraps never reach the server, so the content can never be opened again",
        &frozen_keys("wire/stage_files_body.keys.json"),
        &keys_of(&body),
    );
    let stream0 = &body["streams"].as_array().unwrap()[0];
    assert_superset(
        "POST /v1/files → streams[]",
        "the server cannot size/verify a stream, so finalize fails and the upload is lost",
        &frozen_keys("wire/stage_files_stream.keys.json"),
        &keys_of(stream0),
    );
    let wrap0 = &body["wraps"].as_array().unwrap()[0];
    assert_superset(
        "POST /v1/files → wraps[]",
        "the DEK wrap or its signed grant never reaches the server — the file's key is \
         unrecoverable and the content is lost FOREVER",
        &frozen_keys("wire/stage_files_wrap.keys.json"),
        &keys_of(wrap0),
    );
    // The self-wrap and the recovery wrap must BOTH still be sent.
    let types: BTreeSet<&str> = body["wraps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["recipient_type"].as_str().unwrap())
        .collect();
    assert!(
        types.contains("user") && types.contains("recovery"),
        "\n\nAn upload no longer wraps to BOTH the author and the recovery account: {types:?}\n\
         BLAST RADIUS: dropping the recovery wrap means a user who loses their password can \
         NEVER recover that file. Dropping the self wrap means the AUTHOR cannot open it.\n{CHECKLIST}\n"
    );

    // POST /v1/files/{id}/wraps — the reshare body.
    let wrap_body = build_add_wrap_body(&bundle.wraps[0]);
    assert_superset(
        "POST /v1/files/{id}/wraps (reshare)",
        "sharing is dead: the recipient's wrapped DEK or its signed grant never reaches the \
         server, so they can never open the file",
        &frozen_keys("wire/add_wrap_body.keys.json"),
        &keys_of(&wrap_body),
    );
    assert_eq!(
        wrap_body["recipient_type"], "user",
        "a reshare always targets a USER (never the recovery sentinel)"
    );
    assert_eq!(wrap_body["wrap_alg"], 1, "`wrap_alg` is the frozen wrap-algorithm id");
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    B64.decode(s).expect("base64")
}

// ---------------------------------------------------------------------------
// 8. The fixture generator — run ONCE, deliberately. NOT part of the gate.
// ---------------------------------------------------------------------------

/// Emit the frozen corpus (repo convention: `crates/encoding/tests/golden.rs`).
///
/// ```text
/// cargo test --manifest-path crates/client-app/Cargo.toml --test compat \
///   --features unpinned-dev -- --ignored compat_emit_fixtures
/// ```
///
/// Regenerating an EXISTING fixture is a `corpus.lock` failure BY DESIGN — that is
/// the whole mechanism. Adding a new one is a deliberate, reviewable act: run this,
/// review the diff, append the new lines to `corpus.lock`, and record the change in
/// `docs/compat/LEDGER.md`.
#[test]
#[ignore = "fixture generator: run deliberately, then commit the corpus"]
fn compat_emit_fixtures() {
    let pin_dir = compat::area(PIN);
    let state_dir = compat::area(STATE);
    std::fs::create_dir_all(&pin_dir).unwrap();
    std::fs::create_dir_all(state_dir.join("wire")).unwrap();

    // --- surface 7: canonical pins -----------------------------------------
    let enc_pub = maxsecu_crypto::x25519_public_from_secret(&PIN_X25519_SEED);
    let mlkem_pub = maxsecu_crypto::mlkem_public_from_seed(&PIN_MLKEM_SEED).unwrap();

    let classical = recovery_pin::canonical_pin(&enc_pub, None);
    write(&pin_dir.join("canonical_pin_v1_classical.bin"), &classical);
    write_json(
        &pin_dir.join("canonical_pin_v1_classical.expect.json"),
        &json!({
            "len": classical.len(),
            "tag": 0,
            "enc_pub_hex": hex(&enc_pub),
            "mlkem_pub_hex": Value::Null,
            "sha256_hex": hex(&maxsecu_crypto::sha256(&classical)),
        }),
    );

    let hybrid = recovery_pin::canonical_pin(&enc_pub, Some(&mlkem_pub));
    write(&pin_dir.join("canonical_pin_v1_hybrid.bin"), &hybrid);
    write_json(
        &pin_dir.join("canonical_pin_v1_hybrid.expect.json"),
        &json!({
            "len": hybrid.len(),
            "tag": 1,
            "enc_pub_hex": hex(&enc_pub),
            "mlkem_pub_hex": hex(&mlkem_pub),
            "sha256_hex": hex(&maxsecu_crypto::sha256(&hybrid)),
        }),
    );

    // --- surface 7: the in-band pin-bootstrap connection code ---------------
    let cert = rcgen::generate_simple_self_signed(vec!["maxsecu.example".to_owned()]).unwrap();
    let cert_der = cert.cert.der().to_vec();
    let dir_pub = [0x5Du8; 32];
    write(&pin_dir.join("bootstrap_server_cert.der"), &cert_der);
    write(&pin_dir.join("bootstrap_directory_pub.der"), &dir_pub);
    write_json(
        &pin_dir.join("bootstrap_pins.expect.json"),
        &json!({ "connection_code": maxsecu_crypto::pin_fingerprint(&cert_der, &dir_pub) }),
    );

    // --- surface 11: the identity every sealed store is sealed to ------------
    let id = Identity::generate();
    // ARGON2_FLOOR (not the desktop target): the gate unlocks this on every run, and
    // the params travel WITH the blob, so a floor-cost blob is the fast, valid choice.
    let blob = keyblob::seal(STATE_PASSPHRASE, &id, maxsecu_client_core::ARGON2_FLOOR).unwrap();
    write(&state_dir.join("identity_v2.keyblob"), &blob);
    write(&state_dir.join("identity_v2.passphrase.txt"), STATE_PASSPHRASE.as_bytes());
    write_json(
        &state_dir.join("identity_v2.expect.json"),
        &json!({
            "enc_pub_hex": hex(&id.enc_pub_bytes()),
            "sig_pub_hex": hex(&id.sig_pub_bytes()),
            "has_mlkem": id.mlkem_pub_bytes().is_some(),
        }),
    );

    let work = tmp_dir("emit");

    // --- surface 11: settings.json (current / legacy / future-unknown-key) ---
    write(
        &state_dir.join("settings_current.json"),
        br#"{
  "a11y": { "reduced_motion": true, "high_contrast": false, "text_size": "large" },
  "behavior": { "confirm_destructive": true },
  "performance": {
    "media_cache_cap_mb": 2048,
    "thumb_cache_cap_mb": 512,
    "feed_concurrency": 6,
    "transcode_threads": 4,
    "decode_threads": 4,
    "cache_location": "Disk"
  },
  "connection": { "route_mode": "prefer-dropbox", "use_tor": false },
  "appearance": { "theme": "light", "frontend": "pizza" },
  "ui": { "bundle_view": "stacked" },
  "playback": { "volume": 0.5, "muted": true }
}
"#,
    );
    write_json(
        &state_dir.join("settings_current.expect.json"),
        &json!({
            "theme": "light", "frontend": "pizza", "bundle_view": "stacked",
            "text_size": "large", "route_mode": "prefer-dropbox", "cache_location": "Disk",
        }),
    );
    // A pre-rework file: the DEAD `ram_cache_cap_mb` key and the DEAD `use_tor` boolean,
    // with no `route_mode`, no `ui`, no `playback`, no `frontend`.
    write(
        &state_dir.join("settings_legacy.json"),
        br#"{
  "a11y": { "reduced_motion": false, "high_contrast": false, "text_size": "normal" },
  "behavior": { "confirm_destructive": false },
  "performance": { "ram_cache_cap_mb": 512 },
  "connection": { "use_tor": true },
  "appearance": { "theme": "dark" }
}
"#,
    );
    write_json(
        &state_dir.join("settings_legacy.expect.json"),
        &json!({ "media_cache_cap_mb": 512, "thumb_cache_cap_mb": 256, "route_mode": "tor-only" }),
    );
    // Written by a NEWER client: an unknown section AND an unknown key in a known one.
    write(
        &state_dir.join("settings_future_key.json"),
        br##"{
  "appearance": { "theme": "light", "frontend": "default", "accent_color": "#ff00aa" },
  "connection": { "route_mode": "tor-only", "use_tor": true },
  "quantum_teleport": { "enabled": true }
}
"##,
    );

    // --- surface 11: the four identity-sealed stores ------------------------
    {
        let mut store = tofu::TofuStore::open(&work, &id).unwrap();
        store.check_or_pin("alice", &[0xE1; 32], &[0x51; 32]).unwrap();
        store.check_or_pin("bob", &[0xE2; 32], &[0x52; 32]).unwrap();
        let mut expect = serde_json::Map::new();
        for (u, e, s) in [("alice", [0xE1u8; 32], [0x51u8; 32]), ("bob", [0xE2u8; 32], [0x52u8; 32])] {
            expect.insert(u.to_owned(), Value::String(hex(&tofu::key_fingerprint(&e, &s))));
        }
        copy(&work.join("tofu").join("pins.tofu"), &state_dir.join("tofu_pins.tofu"));
        write_json(&state_dir.join("tofu_pins.expect.json"), &Value::Object(expect));
    }
    {
        let mut store = contacts::ContactStore::open(&work, &id).unwrap();
        store.upsert("alice", [0x0A; 16], [0xF1; 32]).unwrap();
        store.upsert("bob", [0x0B; 16], [0xF2; 32]).unwrap();
        copy(&work.join("contacts").join("contacts.bin"), &state_dir.join("contacts.bin"));
        write_json(
            &state_dir.join("contacts.expect.json"),
            &json!([
                { "username": "alice", "user_id_hex": hex(&[0x0Au8; 16]), "fingerprint_hex": hex(&[0xF1u8; 32]) },
                { "username": "bob",   "user_id_hex": hex(&[0x0Bu8; 16]), "fingerprint_hex": hex(&[0xF2u8; 32]) },
            ]),
        );
    }
    {
        let mut idx = index::SearchIndex::default();
        idx.upsert(index::IndexEntry {
            file_id: "f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1".into(),
            file_type: "image".into(),
            title: "Sunset Beach".into(),
            tags: vec!["beach".into(), "2026".into()],
        });
        idx.upsert(index::IndexEntry {
            file_id: "f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2".into(),
            file_type: "blog".into(),
            title: "My Notes".into(),
            tags: vec!["draft".into()],
        });
        index::save(&work, &id, &idx).unwrap();
        copy(&work.join("index").join("search.idx"), &state_dir.join("search_index.idx"));
        write_json(
            &state_dir.join("search_index.expect.json"),
            &json!([
                { "file_id": "f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1", "file_type": "image", "title": "Sunset Beach" },
                { "file_id": "f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2", "file_type": "blog",  "title": "My Notes" },
            ]),
        );
    }
    {
        let mut store = transparency::DiskKtCheckpointStore::open(&work, &id).unwrap();
        let cp = KtCheckpoint { tree_size: 42, root: [0xC1; 32], sig: [0xC2; 64] };
        store.update(cp);
        store.persist().unwrap();
        copy(&work.join("kt").join("checkpoint.kt"), &state_dir.join("kt_checkpoint.kt"));
        write_json(
            &state_dir.join("kt_checkpoint.expect.json"),
            &json!({ "tree_size": 42, "root_hex": hex(&[0xC1u8; 32]), "sig_hex": hex(&[0xC2u8; 64]) }),
        );
    }

    // --- surface 11: staging/<file_id>/record.json (frozen AS-IS, unversioned) ---
    {
        use maxsecu_client_app::upload_staging::{StagedSmallStream, StagedWrap, StagingRecord};
        let rec = StagingRecord {
            file_id: [0xF1; 16],
            file_type: "video".into(),
            title: "Frozen upload".into(),
            manifest: vec![0x01, 0x02, 0x03],
            manifest_sig: vec![0x04; 64],
            genesis: vec![0x05, 0x06],
            genesis_sig: vec![0x07; 64],
            wraps: vec![StagedWrap {
                recipient_id: [0x11; 16],
                recipient_type: "user".into(),
                wrapped_dek: vec![0x08; 48],
                granted_by: [0x11; 16],
                grant: vec![0x09; 32],
                grant_sig: vec![0x0A; 64],
            }],
            out_mp4_path: PathBuf::from("staging/f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1/out.mp4"),
            chunk_size: 6 * 1024 * 1024,
            content_chunk_count: 3,
            content_total_bytes: 18_874_368,
            small_streams: vec![StagedSmallStream {
                stream_type: 2,
                chunk_size: 65536,
                chunk_count: 1,
                total_bytes: 96,
                digest: vec![0x0B; 32],
                chunks: vec![vec![0x0C; 96]],
            }],
            progress: 1,
            created_ms: 1_719_500_000_000,
            last_progress_ms: 1_719_500_060_000,
            finalized: false,
        };
        let staging = StagingStore::new(work.join("staging"));
        staging.persist(&rec).unwrap();
        copy(
            &work.join("staging").join(hex(&rec.file_id)).join("record.json"),
            &state_dir.join("staging_record.json"),
        );
        write_json(
            &state_dir.join("staging_record.expect.json"),
            &json!({
                "file_id_hex": hex(&rec.file_id),
                "file_type": "video",
                "title": "Frozen upload",
                "content_chunk_count": 3,
                "progress": 1,
                "wraps": 1,
                "small_streams": 1,
            }),
        );
    }

    // --- §5: the client-emitted request-body KEY SETS ------------------------
    {
        use maxsecu_client_core::{build_upload, UploadParams};
        use maxsecu_crypto::generate_enc_keypair;
        use maxsecu_encoding::types::{FileType, Id, Timestamp};

        let wire_id = Identity::generate();
        let (_rsk, rpk) = generate_enc_keypair();
        let params = UploadParams {
            owner: &wire_id,
            owner_id: Id([0x11; 16]),
            owner_key_version: 1,
            file_id: Id([0xF1; 16]),
            file_type: FileType::Blog,
            chunk_size: 4096,
            recovery_pub: rpk,
            recovery_mlkem_pub: None,
            created_at: Timestamp(1_719_500_000_000),
        };
        let streams =
            maxsecu_client_app::upload::prepare_blog_streams(b"hello".to_vec(), "Hi", &["t".to_owned()]);
        let bundle = build_upload(&params, &streams).unwrap();
        let files_body = stage_body(&bundle, StageFlags::default());

        let sets: [(&str, Value); 7] = [
            ("wire/register_body.keys.json", build_register_body("alice", &wire_id, "k")),
            ("wire/session_challenge_body.keys.json", build_session_challenge_body("alice")),
            ("wire/session_prove_body.keys.json", build_session_prove_body("alice", 1, "p")),
            ("wire/recovery_verify_body.keys.json", build_recovery_verify_body("cid", "p", 1)),
            ("wire/stage_files_body.keys.json", files_body.clone()),
            ("wire/stage_files_stream.keys.json", files_body["streams"][0].clone()),
            ("wire/stage_files_wrap.keys.json", files_body["wraps"][0].clone()),
        ];
        for (rel, body) in sets {
            let keys: Vec<String> = keys_of(&body).into_iter().collect();
            write_json(&state_dir.join(rel), &json!(keys));
        }
        let keys: Vec<String> = keys_of(&build_add_wrap_body(&bundle.wraps[0])).into_iter().collect();
        write_json(&state_dir.join("wire/add_wrap_body.keys.json"), &json!(keys));
    }

    // --- the per-area corpus.lock -------------------------------------------
    emit_lock(&pin_dir);
    emit_lock(&state_dir);
    let _ = std::fs::remove_dir_all(&work);

    eprintln!("emitted:\n  {}\n  {}", pin_dir.display(), state_dir.display());
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

/// Pretty JSON with a trailing LF (stable across platforms — `serde_json` never
/// emits CRLF).
fn write_json(path: &Path, v: &Value) {
    let mut s = serde_json::to_string_pretty(v).unwrap();
    s.push('\n');
    write(path, s.as_bytes());
}

fn copy(from: &Path, to: &Path) {
    std::fs::create_dir_all(to.parent().unwrap()).unwrap();
    std::fs::copy(from, to).unwrap_or_else(|e| panic!("copy {} → {}: {e}", from.display(), to.display()));
}

fn emit_lock(dir: &Path) {
    let mut names = Vec::new();
    walk(dir, dir, &mut names);
    names.sort();
    let mut out = String::from(
        "# corpus.lock — ADD-ONLY. Fixtures may be added; never edited, never deleted.\n\
         # Format: <filename>  <sha256-hex>, sorted by filename, LF endings.\n\
         # See docs/compat/CHECKLIST.md.\n",
    );
    for name in names {
        let bytes = std::fs::read(dir.join(&name)).unwrap();
        out.push_str(&format!("{name}  {}\n", compat::sha256_hex(&bytes)));
    }
    write(&dir.join("corpus.lock"), out.as_bytes());
}
