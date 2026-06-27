//! Committed golden fixtures (DESIGN §17 Phase 0 exit gate: "Commit the vectors
//! as fixtures (shared by client, server, and air-gapped tooling)").
//!
//! `tests/fixtures/canonical_vectors.tsv` holds `name<TAB>hex` for the canonical
//! encoding of one deterministic instance of every §4 structure. It is the
//! language-agnostic wire-format lock: any reimplementation (or a future Rust
//! change) that produces different bytes fails `golden_vectors_are_byte_exact`.
//!
//! To (re)generate after a *deliberate* format change:
//!   cargo test -p maxsecu-encoding --test golden emit_fixture_file -- --ignored
//! then review the diff and commit it.

use maxsecu_encoding::structs::*;
use maxsecu_encoding::types::*;
use maxsecu_encoding::{encode, RECOVERY_ID};
use std::collections::BTreeMap;
use std::path::PathBuf;

const FIXTURE_PATH: &str = "tests/fixtures/canonical_vectors.tsv";

fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}
fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn id(n: u8) -> Id {
    Id([n; 16])
}
fn b32(n: u8) -> Bytes32 {
    Bytes32([n; 32])
}
fn ts(n: u64) -> Timestamp {
    Timestamp(n)
}
fn text(s: &str) -> Text {
    Text::new(s).unwrap()
}
fn stream(t: StreamType, c: u64, d: u8) -> Stream {
    Stream {
        stream_type: t,
        compression: Compression::None,
        chunk_count: c,
        digest: b32(d),
    }
}

/// One deterministic, canonical instance of every §4 structure. Order-stable.
fn fixtures() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "dirbinding",
            encode(&DirBinding {
                username: text("alice"),
                user_id: id(0x33),
                enc_pub: b32(0xE1),
                sig_pub: b32(0x51),
                key_version: 1,
                roles: RoleSet::new([Role::User, Role::Admin]),
                not_before: ts(1_700_000_000_000),
                not_after: ts(1_731_536_000_000),
            }),
        ),
        (
            "manifest",
            encode(&Manifest {
                file_id: id(0x11),
                version: 1,
                file_type: FileType::Video,
                alg: Suite::V1,
                chunk_size: 1 << 20,
                dek_commit: b32(0xDE),
                streams: vec![
                    stream(StreamType::Content, 3, 0xC0),
                    stream(StreamType::Metadata, 1, 0x4D),
                    stream(StreamType::Thumbnail, 1, 0x70),
                    stream(StreamType::Preview, 1, 0x80),
                ],
                recovery_present: true,
                author_id: id(0x22),
                created_at: ts(1_700_000_000_000),
            }),
        ),
        ("stream", encode(&stream(StreamType::Content, 5, 0xC0))),
        (
            "grant_user",
            encode(&Grant {
                file_id: id(0x11),
                file_version: 1,
                recipient_id: id(0x55),
                recipient_type: RecipientType::User,
                dek_commit: b32(0xDE),
                granted_by: id(0x22),
                created_at: ts(1_700_000_000_000),
            }),
        ),
        (
            "grant_recovery",
            encode(&Grant {
                file_id: id(0x11),
                file_version: 1,
                recipient_id: RECOVERY_ID,
                recipient_type: RecipientType::Recovery,
                dek_commit: b32(0xDE),
                granted_by: id(0x22),
                created_at: ts(1_700_000_000_000),
            }),
        ),
        (
            "genesis",
            encode(&Genesis {
                file_id: id(0x11),
                owner_id: id(0x22),
                owner_key_version: 1,
                created_at: ts(1_700_000_000_000),
            }),
        ),
        (
            "revocation_accountwide",
            encode(&Revocation {
                scope: FileScope::AccountWide,
                revoked_user_id: id(0x44),
                revoked_capability: None,
                from_version: 2,
                revocation_epoch: 7,
                prev_head: b32(0xAB),
                issued_by: id(0x22),
                co_signed_by: Some(id(0x23)),
                created_at: ts(1_700_000_000_000),
            }),
        ),
        (
            "revocation_specific_rolenarrow",
            encode(&Revocation {
                scope: FileScope::Specific(id(0x11)),
                revoked_user_id: id(0x44),
                revoked_capability: Some(Role::Admin),
                from_version: 2,
                revocation_epoch: 7,
                prev_head: b32(0xAB),
                issued_by: id(0x22),
                co_signed_by: None,
                created_at: ts(1_700_000_000_000),
            }),
        ),
        (
            "reinstatement",
            encode(&Reinstatement {
                scope: FileScope::AccountWide,
                reinstated_user_id: id(0x44),
                supersedes_epoch: 7,
                reinstatement_epoch: 8,
                prev_head: b32(0xAB),
                issued_by: id(0x22),
                co_signed_by: id(0x23),
                created_at: ts(1_700_000_000_000),
            }),
        ),
        (
            "key_compromise",
            encode(&KeyCompromise {
                user_id: id(0x33),
                key_version: 2,
                effective_from: ts(1_700_000_000_000),
                prev_head: b32(0xAB),
                issued_by: id(0x22),
                co_signed_by: id(0x23),
                created_at: ts(1_700_000_000_001),
            }),
        ),
        (
            "auth_proof_context",
            encode(&AuthProofContext {
                server_id: text("maxsecu.example"),
                tls_exporter: b32(0xE7),
                nonce: b32(0x4E),
                timestamp: ts(1_700_000_000_000),
            }),
        ),
        (
            "wrap_context",
            encode(&WrapContext {
                file_id: id(0x11),
                version: 1,
                recipient_id: id(0x55),
            }),
        ),
        (
            "chunk_aad",
            encode(&ChunkAad {
                file_id: id(0x11),
                version: 1,
                stream_type: StreamType::Content,
                chunk_index: 0,
                is_last: false,
            }),
        ),
        (
            "fingerprint_input",
            encode(&FingerprintInput {
                enc_pub: b32(0xE1),
                sig_pub: b32(0x51),
            }),
        ),
    ]
}

fn fixture_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_PATH)
}

#[test]
fn golden_vectors_are_byte_exact() {
    let raw = std::fs::read_to_string(fixture_file()).unwrap_or_else(|e| {
        panic!(
            "missing golden fixtures at {} ({e}); regenerate with: \
             cargo test -p maxsecu-encoding --test golden emit_fixture_file -- --ignored",
            FIXTURE_PATH
        )
    });
    let mut committed: BTreeMap<&str, &str> = BTreeMap::new();
    for line in raw
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
    {
        let (name, hex) = line.split_once('\t').expect("name<TAB>hex");
        committed.insert(name, hex);
    }

    let current = fixtures();
    assert_eq!(
        current.len(),
        committed.len(),
        "fixture count drift: code has {}, file has {}",
        current.len(),
        committed.len()
    );
    for (name, bytes) in current {
        let want = committed
            .get(name)
            .unwrap_or_else(|| panic!("fixture '{name}' missing from {FIXTURE_PATH}"));
        assert_eq!(
            &to_hex(&bytes),
            want,
            "byte-exact mismatch for '{name}' (wire format changed?)"
        );
        // Sanity: the committed hex actually decodes back to these bytes.
        assert_eq!(from_hex(want), bytes, "hex decode mismatch for '{name}'");
    }
}

#[test]
#[ignore = "run with --ignored to (re)generate the committed fixtures after a deliberate format change"]
fn emit_fixture_file() {
    let path = fixture_file();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut out = String::new();
    out.push_str("# MaxSecu canonical encoding golden vectors (encoding-spec §4).\n");
    out.push_str(
        "# name<TAB>hex(canonical(struct)).  Regenerate via the emit_fixture_file test.\n",
    );
    for (name, bytes) in fixtures() {
        out.push_str(name);
        out.push('\t');
        out.push_str(&to_hex(&bytes));
        out.push('\n');
    }
    std::fs::write(&path, out).unwrap();
    eprintln!("wrote {}", path.display());
}
