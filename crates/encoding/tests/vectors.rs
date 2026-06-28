//! Phase-0 exit gate: the adversarial test vectors of encoding-spec §8.
//!
//! Every `V-N` below MUST be **rejected** with the documented reason; the
//! positive vectors must match **byte-for-byte**. A serializer that accepts any
//! rejecting case fails the phase (DESIGN §17 Phase 0, encoding-spec §9).
//!
//! These run against the public API only (`encode`/`decode`/`signing_input`),
//! exactly as the client, server early-reject, and air-gapped tooling will.

use maxsecu_encoding::structs::*;
use maxsecu_encoding::types::*;
use maxsecu_encoding::{
    decode, encode, labels, signing_input, DecodeError, RECOVERY_ID, SUITE_V1, SUITE_V2,
};

// ---------- builders for canonical, valid instances ----------

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
    Text::new(s).expect("valid text")
}

fn valid_genesis() -> Genesis {
    Genesis {
        file_id: id(0x11),
        owner_id: id(0x22),
        owner_key_version: 1,
        created_at: ts(1_700_000_000_000),
    }
}

fn stream(t: StreamType, chunks: u64, d: u8) -> Stream {
    Stream {
        stream_type: t,
        compression: Compression::None,
        chunk_count: chunks,
        digest: b32(d),
    }
}

fn valid_manifest(streams: Vec<Stream>) -> Manifest {
    Manifest {
        file_id: id(0x11),
        version: 1,
        file_type: FileType::Video,
        alg: Suite::V1,
        chunk_size: 1 << 20,
        dek_commit: b32(0xDE),
        streams,
        recovery_present: true,
        author_id: id(0x22),
        created_at: ts(1_700_000_000_000),
    }
}

fn valid_grant(rt: RecipientType, recipient: Id) -> Grant {
    Grant {
        file_id: id(0x11),
        file_version: 1,
        recipient_id: recipient,
        recipient_type: rt,
        dek_commit: b32(0xDE),
        granted_by: id(0x22),
        created_at: ts(1_700_000_000_000),
    }
}

fn valid_dirbinding() -> DirBinding {
    DirBinding {
        username: text("alice"),
        user_id: id(0x33),
        enc_pub: b32(0xE1),
        sig_pub: b32(0x51),
        key_version: 1,
        roles: RoleSet::new([Role::User, Role::Admin]),
        not_before: ts(1_700_000_000_000),
        not_after: ts(1_731_536_000_000),
        mlkem_pub: None,
    }
}

fn account_wide_revocation() -> Revocation {
    Revocation {
        scope: FileScope::AccountWide,
        revoked_user_id: id(0x44),
        revoked_capability: None,
        from_version: 2,
        revocation_epoch: 7,
        prev_head: b32(0xAB),
        issued_by: id(0x22),
        co_signed_by: Some(id(0x23)),
        created_at: ts(1_700_000_000_000),
    }
}

fn specific_revocation() -> Revocation {
    Revocation {
        scope: FileScope::Specific(id(0x11)),
        revoked_user_id: id(0x44),
        revoked_capability: Some(Role::Admin),
        from_version: 2,
        revocation_epoch: 7,
        prev_head: b32(0xAB),
        issued_by: id(0x22),
        co_signed_by: None,
        created_at: ts(1_700_000_000_000),
    }
}

fn valid_chunk_aad() -> ChunkAad {
    ChunkAad {
        file_id: id(0x11),
        version: 1,
        stream_type: StreamType::Content,
        chunk_index: 0,
        is_last: false,
    }
}

// ======================================================================
// Positive / canonical vectors
// ======================================================================

#[test]
fn v_pos_1_length_prefix_injectivity() {
    // The `text` length-prefix makes the ("ab") vs ("a","b…") split impossible.
    // Observe it through a struct whose first field is a `text` (auth_proof_context):
    // bytes are `type_id(2) ‖ u32 len ‖ utf8`.
    let mk = |s: &str| {
        encode(&AuthProofContext {
            server_id: text(s),
            tls_exporter: b32(1),
            nonce: b32(2),
            timestamp: ts(9),
        })
    };
    let ab = mk("ab");
    let a = mk("a");
    // type_id occupies [0,1]; the text length-prefix begins at [2].
    assert_eq!(&ab[2..8], &[0x00, 0x00, 0x00, 0x02, b'a', b'b']);
    assert_eq!(&a[2..7], &[0x00, 0x00, 0x00, 0x01, b'a']);
    // No field-tuple produces another's bytes: distinct lengths ⇒ distinct prefix.
    assert_ne!(ab, a);
}

#[test]
fn v_pos_2_round_trip_all_structures() {
    // decode(encode(v)) == v  AND  encode(decode(b)) == b  for each §4 struct.
    macro_rules! rt {
        ($v:expr, $T:ty) => {{
            let v = $v;
            let b = encode(&v);
            let back: $T = decode(&b).expect("decodes");
            assert_eq!(back, v, "value round-trip");
            assert_eq!(encode(&back), b, "byte round-trip (canonical guard)");
        }};
    }
    rt!(valid_dirbinding(), DirBinding);
    rt!(
        valid_manifest(vec![
            stream(StreamType::Content, 3, 0xC0),
            stream(StreamType::Metadata, 1, 0x4D),
            stream(StreamType::Thumbnail, 1, 0x70),
            stream(StreamType::Preview, 1, 0x80),
        ]),
        Manifest
    );
    rt!(stream(StreamType::Content, 5, 0xC0), Stream);
    rt!(valid_grant(RecipientType::User, id(0x55)), Grant);
    rt!(valid_grant(RecipientType::Recovery, RECOVERY_ID), Grant);
    rt!(valid_genesis(), Genesis);
    rt!(account_wide_revocation(), Revocation);
    rt!(specific_revocation(), Revocation);
    rt!(
        Reinstatement {
            scope: FileScope::AccountWide,
            reinstated_user_id: id(0x44),
            supersedes_epoch: 7,
            reinstatement_epoch: 8,
            prev_head: b32(0xAB),
            issued_by: id(0x22),
            co_signed_by: id(0x23),
            created_at: ts(1_700_000_000_000),
        },
        Reinstatement
    );
    rt!(
        KeyCompromise {
            user_id: id(0x33),
            key_version: 2,
            effective_from: ts(1_700_000_000_000),
            prev_head: b32(0xAB),
            issued_by: id(0x22),
            co_signed_by: id(0x23),
            created_at: ts(1_700_000_000_001),
        },
        KeyCompromise
    );
    rt!(
        AuthProofContext {
            server_id: text("maxsecu.example"),
            tls_exporter: b32(0xE7),
            nonce: b32(0x4E),
            timestamp: ts(1_700_000_000_000),
        },
        AuthProofContext
    );
    rt!(
        WrapContext {
            file_id: id(0x11),
            version: 1,
            recipient_id: id(0x55),
        },
        WrapContext
    );
    rt!(valid_chunk_aad(), ChunkAad);
    rt!(
        FingerprintInput {
            enc_pub: b32(0xE1),
            sig_pub: b32(0x51),
        },
        FingerprintInput
    );
}

// ======================================================================
// Must-reject vectors
// ======================================================================

#[test]
fn v1_trailing_data() {
    // Valid genesis ‖ one extra 0x00 → reject (§7 rule 2).
    let mut b = encode(&valid_genesis());
    b.push(0x00);
    assert_eq!(
        decode::<Genesis>(&b),
        Err(DecodeError::TrailingBytes { remaining: 1 })
    );
}

#[test]
fn v2_type_confusion() {
    // Bytes of a valid grant (type_id 0x0003) decoded as a different type → reject on id.
    let gb = encode(&valid_grant(RecipientType::User, id(0x55)));
    assert_eq!(
        decode::<Genesis>(&gb),
        Err(DecodeError::WrongTypeId {
            expected: 0x0005,
            got: 0x0003
        })
    );
    // The reserved 0x0004 (removed write_grant) is unknown to every reader.
    let mut reserved = gb.clone();
    reserved[0] = 0x00;
    reserved[1] = 0x04;
    assert_eq!(
        decode::<Grant>(&reserved),
        Err(DecodeError::UnknownTypeId(0x0004))
    );
}

#[test]
fn v3_non_canonical_bool() {
    // manifest.recovery_present = 0x02 → reject. It sits 25 bytes from the end
    // (author_id:16 + created_at:8 follow it).
    let mut b = encode(&valid_manifest(vec![stream(StreamType::Content, 3, 0xC0)]));
    let idx = b.len() - 25;
    b[idx] = 0x02;
    assert_eq!(decode::<Manifest>(&b), Err(DecodeError::InvalidBool(0x02)));
}

#[test]
fn v4_set_order_and_dup() {
    // roles canonical = [User(0x01), Admin(0x02)]. The 3-byte roles window in a
    // dirbinding with username "alice" begins at offset 99: count ‖ cp ‖ cp.
    let base = encode(&valid_dirbinding());
    assert_eq!(base[99], 0x02, "roles count");
    assert_eq!(&base[100..102], &[0x01, 0x02], "ascending codepoints");

    // descending [Admin, User] → reject
    let mut desc = base.clone();
    desc[100] = 0x02;
    desc[101] = 0x01;
    assert_eq!(
        decode::<DirBinding>(&desc),
        Err(DecodeError::SetNotAscending)
    );

    // duplicate [User, User] → reject
    let mut dup = base.clone();
    dup[100] = 0x01;
    dup[101] = 0x01;
    assert_eq!(
        decode::<DirBinding>(&dup),
        Err(DecodeError::SetNotAscending)
    );
}

#[test]
fn v5_option_presence() {
    // revocation.revoked_capability presence byte 0x02 → reject. With an
    // account-wide scope (1-byte tag), the presence byte is at offset 19:
    // type_id(2) ‖ scope(1) ‖ revoked_user_id(16) ‖ presence(1).
    let mut b = encode(&account_wide_revocation());
    assert_eq!(b[19], 0x00, "revoked_capability is absent in the fixture");
    b[19] = 0x02;
    assert_eq!(
        decode::<Revocation>(&b),
        Err(DecodeError::InvalidPresenceByte(0x02))
    );
}

#[test]
fn v6_integer_truncation_and_overrun() {
    // u32 with 3 bytes left → reject: truncate a genesis mid-`created_at`.
    let full = encode(&valid_genesis());
    let short = &full[..full.len() - 3];
    assert!(matches!(
        decode::<Genesis>(short),
        Err(DecodeError::ShortInput { .. })
    ));

    // bytes_var len 0xFFFFFFFF with little input → reject: an auth_proof_context
    // whose server_id length prefix is enormous.
    // type_id(2) ‖ u32 len ‖ ... — set the len to 0xFFFFFFFF with no payload.
    let bytes = [0x00, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0x61];
    assert!(matches!(
        decode::<AuthProofContext>(&bytes),
        Err(DecodeError::LengthOverrun {
            len: 0xFFFF_FFFF,
            ..
        })
    ));
}

#[test]
fn v7_unknown_enum() {
    // recipient_type = 0x03 → reject. In a grant it sits at offset 42:
    // type_id(2) ‖ file_id(16) ‖ file_version(8) ‖ recipient_id(16) ‖ type(1).
    let mut g = encode(&valid_grant(RecipientType::User, id(0x55)));
    g[42] = 0x03;
    assert_eq!(
        decode::<Grant>(&g),
        Err(DecodeError::UnknownEnum {
            kind: "RecipientType",
            value: 0x03
        })
    );

    // alg = 0xFFFF → reject. In a manifest the Suite u16 sits at offset 27:
    // type_id(2) ‖ file_id(16) ‖ version(8) ‖ file_type(1) ‖ alg(2).
    let mut m = encode(&valid_manifest(vec![stream(StreamType::Content, 1, 0xC0)]));
    m[27] = 0xFF;
    m[28] = 0xFF;
    assert_eq!(
        decode::<Manifest>(&m),
        Err(DecodeError::UnknownEnum {
            kind: "Suite",
            value: 0xFFFF
        })
    );

    // type_id = 0x00FF → reject.
    let unknown = [0x00u8, 0xFF, 0x00, 0x00];
    assert_eq!(
        decode::<Genesis>(&unknown),
        Err(DecodeError::UnknownTypeId(0x00FF))
    );
    // Sanity: the suite codepoint constant is the one we encode.
    assert_eq!(SUITE_V1, 0x0001);
}

#[test]
fn v8_text_hygiene() {
    // Non-UTF-8 username/server_id → reject. type_id(2) ‖ u32 len=1 ‖ 0xFF.
    let non_utf8 = [0x00u8, 0x09, 0x00, 0x00, 0x00, 0x01, 0xFF];
    assert_eq!(
        decode::<AuthProofContext>(&non_utf8),
        Err(DecodeError::InvalidUtf8)
    );

    // A decomposed (non-NFC) form that differs from its NFC bytes → reject.
    // "e" + U+0301 (combining acute) = 0x65 0xCC 0x81; NFC would be U+00E9.
    let non_nfc = [0x00u8, 0x09, 0x00, 0x00, 0x00, 0x03, 0x65, 0xCC, 0x81];
    assert_eq!(
        decode::<AuthProofContext>(&non_nfc),
        Err(DecodeError::NonNfcText)
    );
}

#[test]
fn v9_domain_separation() {
    // Identical canonical(grant) under "MaxSecu-grant-v1" vs the (reserved)
    // "MaxSecu-write-grant-v1" ⇒ different signing_input. The length-framed
    // label guarantees this regardless of any shared prefix.
    let gb = encode(&valid_grant(RecipientType::User, id(0x55)));
    let as_grant = signing_input(labels::GRANT, &gb);
    let as_write_grant = signing_input("MaxSecu-write-grant-v1", &gb);
    assert_ne!(as_grant, as_write_grant);
    // And a manifest label over the same bytes differs too.
    assert_ne!(as_grant, signing_input(labels::MANIFEST, &gb));
    // The framing itself: u32 len(label) ‖ label ‖ canonical.
    let label = labels::GRANT;
    assert_eq!(&as_grant[0..4], &(label.len() as u32).to_be_bytes());
    assert_eq!(&as_grant[4..4 + label.len()], label.as_bytes());
    assert_eq!(&as_grant[4 + label.len()..], &gb[..]);
}

#[test]
fn v10_filescope() {
    // 0x01 (specific) with no id → reject: strip the 16 id bytes after the tag.
    let specific = encode(&specific_revocation());
    assert_eq!(specific[2], 0x01, "specific scope tag");
    // Remove indices 3..19 (the FileScope id) → tag claims an id that is absent.
    let mut missing_id = Vec::new();
    missing_id.extend_from_slice(&specific[..3]);
    missing_id.extend_from_slice(&specific[19..]);
    assert!(
        decode::<Revocation>(&missing_id).is_err(),
        "0x01 with no id must reject"
    );

    // 0x02 (account-wide) followed by 16 id bytes → reject: inject 16 bytes
    // after the account-wide tag so the record is over-long / inconsistent.
    let aw = encode(&account_wide_revocation());
    assert_eq!(aw[2], 0x02, "account-wide scope tag");
    let mut id_after_wildcard = Vec::new();
    id_after_wildcard.extend_from_slice(&aw[..3]);
    id_after_wildcard.extend_from_slice(&[0x99; 16]);
    id_after_wildcard.extend_from_slice(&aw[3..]);
    assert!(
        decode::<Revocation>(&id_after_wildcard).is_err(),
        "0x02 followed by an id must reject"
    );
}

#[test]
fn v11_recovery_binding() {
    // recipient_type = recovery with recipient_id != RECOVERY_ID → reject.
    // Start from a user grant with a non-zero recipient_id, flip the type byte
    // (offset 42) to recovery (0x02).
    let mut g = encode(&valid_grant(RecipientType::User, id(0x55)));
    g[42] = 0x02;
    assert_eq!(decode::<Grant>(&g), Err(DecodeError::RecoveryIdMismatch));
    // Positive: recovery type WITH RECOVERY_ID decodes fine (covered in V-pos-2),
    // re-asserted here for clarity.
    let ok = encode(&valid_grant(RecipientType::Recovery, RECOVERY_ID));
    assert!(decode::<Grant>(&ok).is_ok());
}

#[test]
fn v12_reencode_guard_rejects_noncanonical() {
    // The master re-encode guard (§7 rule 5) is the backstop behind every field
    // rule. A non-canonical-but-parseable encoding must reject. Here: a manifest
    // whose `streams` are emitted in descending order (encode is order-faithful,
    // so we can synthesize the non-canonical bytes) is rejected on decode.
    let bad = encode(&valid_manifest(vec![
        stream(StreamType::Thumbnail, 1, 0x70),
        stream(StreamType::Content, 1, 0xC0),
    ]));
    // The descending order is caught (by the explicit streams rule and, were it
    // ever removed, by the canonical guard — both fail closed).
    assert_eq!(
        decode::<Manifest>(&bad),
        Err(DecodeError::StreamsNotAscending)
    );
    // And the guard itself never rejects a canonical value:
    let good = encode(&valid_manifest(vec![stream(StreamType::Content, 1, 0xC0)]));
    assert!(decode::<Manifest>(&good).is_ok());
}

#[test]
fn v13_stream_list_order_and_dup() {
    // thumbnail before content (descending stream_type) → reject.
    let desc = encode(&valid_manifest(vec![
        stream(StreamType::Thumbnail, 1, 0x70),
        stream(StreamType::Content, 1, 0xC0),
    ]));
    assert_eq!(
        decode::<Manifest>(&desc),
        Err(DecodeError::StreamsNotAscending)
    );

    // two content streams (duplicate stream_type) → reject.
    let dup = encode(&valid_manifest(vec![
        stream(StreamType::Content, 1, 0xC0),
        stream(StreamType::Content, 2, 0xC1),
    ]));
    assert_eq!(
        decode::<Manifest>(&dup),
        Err(DecodeError::StreamsNotAscending)
    );

    // reserved type_id 0x0004 in place of a Stream (0x000D) → reject.
    // In a single-stream manifest the embedded Stream type_id sits at offset 66:
    // type_id(2) ‖ file_id(16) ‖ version(8) ‖ file_type(1) ‖ alg(2) ‖
    // chunk_size(4) ‖ dek_commit(32) ‖ count(1) ‖ <Stream type_id>.
    let mut m = encode(&valid_manifest(vec![stream(StreamType::Content, 1, 0xC0)]));
    assert_eq!(&m[66..68], &[0x00, 0x0D], "embedded Stream type_id");
    m[66] = 0x00;
    m[67] = 0x04;
    assert_eq!(
        decode::<Manifest>(&m),
        Err(DecodeError::UnknownTypeId(0x0004))
    );
}

// ======================================================================
// Phase 7 (P7.3): Suite::V2 + optional ML-KEM pubkey on the binding
// ======================================================================

#[test]
fn suite_v2_roundtrips() {
    // Suite::V2 encodes to 0x0002 and decodes back. Observed through a manifest
    // whose `alg` field is the Suite u16 at offset 27 (see v7_unknown_enum).
    let mut m = valid_manifest(vec![stream(StreamType::Content, 1, 0xC0)]);
    m.alg = Suite::V2;
    let b = encode(&m);
    assert_eq!(&b[27..29], &[0x00, 0x02], "Suite::V2 codepoint");
    let back: Manifest = decode(&b).expect("V2 manifest decodes");
    assert_eq!(back.alg, Suite::V2);
    assert_eq!(SUITE_V2, 0x0002);
    assert_eq!(SUITE_V1, 0x0001);

    // An unknown suite (0x0003) is still rejected.
    let mut bad = b.clone();
    bad[27] = 0x00;
    bad[28] = 0x03;
    assert_eq!(
        decode::<Manifest>(&bad),
        Err(DecodeError::UnknownEnum {
            kind: "Suite",
            value: 0x0003
        })
    );
}

#[test]
fn binding_without_pq_roundtrips() {
    // A binding with mlkem_pub: None round-trips and ends in the 0x00 flag.
    let v = valid_dirbinding();
    assert_eq!(v.mlkem_pub, None);
    let b = encode(&v);
    assert_eq!(*b.last().unwrap(), 0x00, "absent PQ key ⇒ trailing 0x00 flag");
    let back: DirBinding = decode(&b).expect("non-PQ binding decodes");
    assert_eq!(back, v, "value round-trip");
    assert_eq!(back.mlkem_pub, None);
    assert_eq!(encode(&back), b, "canonical guard for the None shape");
}

#[test]
fn binding_with_pq_roundtrips() {
    // A binding with mlkem_pub: Some(MlKemPub([..1184..])) round-trips exactly.
    let mut v = valid_dirbinding();
    let key = [0xABu8; 1184];
    v.mlkem_pub = Some(MlKemPub(key));
    let b = encode(&v);
    // Tail layout: flag(1) ‖ key(1184).
    assert_eq!(b[b.len() - 1185], 0x01, "present flag");
    assert_eq!(&b[b.len() - 1184..], &key[..], "fixed 1184-byte key, no prefix");
    let back: DirBinding = decode(&b).expect("PQ binding decodes");
    assert_eq!(back, v, "value round-trip");
    assert_eq!(back.mlkem_pub, Some(MlKemPub(key)));
    assert_eq!(encode(&back), b, "canonical guard for the Some shape");
}

#[test]
fn binding_pq_flag_set_but_short_key_rejected() {
    // Flag 0x01 but fewer than 1184 trailing bytes → reject, no panic / no OOB.
    let mut v = valid_dirbinding();
    v.mlkem_pub = Some(MlKemPub([0xABu8; 1184]));
    let full = encode(&v);
    let short = &full[..full.len() - 1]; // 1183 key bytes left after the flag
    assert!(matches!(
        decode::<DirBinding>(short),
        Err(DecodeError::ShortInput { .. })
    ));
}

#[test]
fn binding_pq_bad_flag_rejected() {
    // A presence byte that is neither 0x00 nor 0x01 → reject, exactly like every
    // other `option` field (the generic Option<T> path returns InvalidPresenceByte).
    let mut b = encode(&valid_dirbinding());
    let last = b.len() - 1;
    assert_eq!(b[last], 0x00, "fixture is the None shape");
    b[last] = 0x02;
    assert_eq!(
        decode::<DirBinding>(&b),
        Err(DecodeError::InvalidPresenceByte(0x02))
    );
}
