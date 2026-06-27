# MaxSecu — Canonical Encoding Specification (Phase 0)

**Status:** Spec (implement in Phase 0, `DESIGN.md` §17).
**Resolves:** the `canonical(...)` / `‖` injectivity contract mandated by `DESIGN.md` §5.2 (review **R5 / D19**).
**Authority:** This document *defines* `canonical(struct)` for every signed and hashed record in `DESIGN.md`. Where the design writes `"label" ‖ canonical(x)`, this spec gives the exact bytes.

> **Why this is security-critical.** Every signature, digest, fingerprint, and AEAD-AAD in the system is computed over these bytes. If two distinct values can ever produce the same byte string, an attacker can transplant a signature from one structure onto another (the `("ab","c")` vs `("a","bc")` concatenation collision). The contract below is **injective** (one value → exactly one byte string) and **canonical** (one byte string → at most one accepted value), and §9 makes that a *runtime-enforced* property, not a hope.

Because the client is a single platform (Windows, `docs/stack.md`) and the server stores signed records as **opaque bytes**, there is exactly **one** encoder implementation (Rust, client core). The server never re-encodes; it may keep these vectors only for optional early rejection.

---

## 1. Invariants

An implementation MUST guarantee:

1. **Deterministic:** `encode(v)` yields the same bytes on every run, platform, and build.
2. **Injective:** `encode(a) == encode(b)` ⟹ `a == b`.
3. **Canonical:** for any byte string `b` the decoder accepts, `encode(decode(b)) == b`. There is **no** non-canonical-but-accepted encoding (enforced by §9).
4. **Self-delimiting & typed:** every structure carries its own type tag and is fully bounded; concatenations are unambiguous without external context.
5. **Fail-closed:** any deviation (unknown tag, bad length, non-minimal form, trailing bytes) is a hard reject, never a best-effort parse.

---

## 2. Primitive encodings

All integers are **fixed-width, big-endian, unsigned**, exactly the stated byte count.

| Type | Encoding | Reject if |
|---|---|---|
| `u8/u16/u32/u64` | 1/2/4/8 big-endian bytes | fewer bytes remain than the fixed width |
| `bool` | one byte: `0x00` (false) or `0x01` (true) | any other byte value |
| `bytes_fixed(N)` | exactly `N` raw bytes (N known from the field) | fewer than N bytes remain |
| `bytes_var` | `u32 len` ‖ `len` raw bytes | `len` > remaining input |
| `text` | a `bytes_var` whose content is **valid UTF-8** and **NFC-normalized** | invalid UTF-8, or bytes ≠ their NFC form, or `len` > `MAX_TEXT` (= 1024) |
| `enum8(R)` | `u8` codepoint from registry `R` | codepoint not in `R` |
| `enum16(R)` | `u16` codepoint from registry `R` | codepoint not in `R` |
| `set<enum8(R)>` | `u8 count` ‖ `count` codepoints in **strictly ascending** byte order | not strictly ascending (this rejects both unsorted *and* duplicates), or any codepoint ∉ `R`, or `count` > `|R|` |
| `option<T>` | presence byte `0x00` (absent — nothing follows) **or** `0x01` ‖ `encode(T)` | presence byte ∉ {`0x00`,`0x01`} |
| `struct` | `u16 type_id` (§5) ‖ fields in declared order | unknown `type_id`; see §9 for embedding |

> **Embedding a struct inside a struct:** wrap it as `bytes_var` containing its own `canonical(...)`. (No struct in this spec embeds another, but the rule is fixed for future use.)

---

## 3. Domain / identifier types

| Logical type | Encoding | Notes |
|---|---|---|
| `Id` | `bytes_fixed(16)` | 128-bit identifier — **server-assigned** (`user_id`/`recipient_id`/`granted_by`); **client-generated random** for `file_id`, which the owner signs into `genesis`/`manifest` before upload (`DESIGN.md` §12.2, server enforces uniqueness) |
| `FileScope` | `enum8`: `0x01` ‖ `Id` (specific file) **or** `0x02` (account-wide `*`, no id follows) | the `*` sentinel of §11.5; decoder rejects an id after `0x02` or a missing id after `0x01` |
| `X25519Pub` / `Ed25519Pub` | `bytes_fixed(32)` | raw public keys |
| `Hash` | `bytes_fixed(32)` | SHA-256 output (`content_digest`, `enc_metadata_digest`, `dek_commit`, `prev_head`) |
| `Timestamp` | `u64` | milliseconds since Unix epoch, UTC. **Informational** except `dirbinding.not_before/not_after` (coarse identity lifetime). Never the basis of a revocation-freshness decision (§7.5 is clock-independent). |
| `Suite` | `enum16`: `0x0001` = {AEAD AES-256-GCM, KDF HKDF-SHA256, KEM X25519, SIG Ed25519, PWKDF Argon2id} | the algorithm-agility identifier (§5.1). New suites get new codepoints; clients reject unknown/below-floor suites |
| `Role` | `enum8`: `user = 0x01`, `admin = 0x02` | |
| `RecipientType` | `enum8`: `user = 0x01`, `recovery = 0x02` | when `recovery`, the paired `recipient_id` MUST be `RECOVERY_ID` (16 zero bytes); decoder enforces |
| `StreamType` | `enum8`: `content = 0x01`, `metadata = 0x02`, `thumbnail = 0x03`, `preview = 0x04` | identifies a file's encrypted streams (§13 / D33) |
| `Compression` | `enum8`: `none = 0x00`, `zstd = 0x01` | per-stream, carried in the signed manifest (D32) |
| `FileType` | `enum8`: `video = 0x01`, `image = 0x02`, `blog = 0x03` | server-visible **and** authenticated listing key (§13 / D35) |

Constants: `RECOVERY_ID = 0x00…00` (16 bytes). `GENESIS_HEAD = 0x00…00` (32 bytes) — the `prev_head` of the first record in the anchored control-log (§7).

---

## 4. Signed & hashed structures

Each begins with its `u16 type_id`, then fields in this exact order. These field sets are the canonical source for the tables in `DESIGN.md` §11 (post-simplification: no `status_attestation`, no `dek_poss`, no `revcheckpoint`).

### `dirbinding` — `0x0001` (§7.1)
`username:text` · `user_id:Id` · `enc_pub:X25519Pub` · `sig_pub:Ed25519Pub` · `key_version:u64` · `roles:set<Role>` · `not_before:Timestamp` · `not_after:Timestamp`

### `manifest` — `0x0002` (§12.3, multi-stream per D33)
`file_id:Id` · `version:u64` · `file_type:FileType` · `alg:Suite` · `chunk_size:u32` · `dek_commit:Hash` · `streams:list<Stream>` · `recovery_present:bool` · `author_id:Id` · `created_at:Timestamp`
*(`file_type` is server-visible & authenticated — the listing key of D35. Decoder MAY require `recovery_present == true` and a `content` stream present. `streams` is ascending by `stream_type` with no duplicate type — §2 `set`-style ordering, count-prefixed; each element is a fixed-size `canonical(Stream)`.)*

### `Stream` (manifest sub-struct) — `0x000D` (§13 / D33)
`stream_type:StreamType` · `compression:Compression` · `chunk_count:u64` · `digest:Hash`
`digest` = SHA-256 over that stream's ordered per-chunk AEAD tags (the per-stream analogue of the old `content_digest`). The stream's bytes are encrypted under `ck_<type> = HKDF(DEK, "MaxSecu-<stream_type>-v1")` with the stream's id bound into every chunk's AAD (so the four streams never share a (key,nonce) space). Fixed size (44 bytes), so `list<Stream>` is `u8 count` ‖ `count` × `canonical(Stream)`.

### `grant` (read-grant) — `0x0003` (§12.3a)
`file_id:Id` · `file_version:u64` · `recipient_id:Id` · `recipient_type:RecipientType` · `dek_commit:Hash` · `granted_by:Id` · `created_at:Timestamp`

### `write_grant` — `0x0004` — REMOVED (owner-only write, D29)
Not used in v1: write is owner-only, so there are no write-grants. Type id `0x0004` is **reserved** and the decoder rejects it. Reintroduce only behind a new decision if multi-writer files are ever required.

### `genesis` — `0x0005` (§11.7)
`file_id:Id` · `owner_id:Id` · `owner_key_version:u64` · `created_at:Timestamp`

### `revocation` (tombstone) — `0x0006` (§11.5)
`scope:FileScope` · `revoked_user_id:Id` · `revoked_capability:option<Role>` · `from_version:u64` · `revocation_epoch:u64` · `prev_head:Hash` · `issued_by:Id` · `co_signed_by:option<Id>` · `created_at:Timestamp`
*(absent `revoked_capability` = full-access revoke; present = role-narrowing, §7.6. `co_signed_by` absent for single-file; present for mass/`*` dual control.)*

### `reinstatement` — `0x0007` (§11.5a)
`scope:FileScope` · `reinstated_user_id:Id` · `supersedes_epoch:u64` · `reinstatement_epoch:u64` · `prev_head:Hash` · `issued_by:Id` · `co_signed_by:Id` · `created_at:Timestamp`
*(`co_signed_by` is a required `Id` — reinstatement is always dual-controlled, §11.5a.)*

### `key_compromise` — `0x0008` (§11.7 / D28)
`user_id:Id` · `key_version:u64` · `effective_from:Timestamp` · `prev_head:Hash` · `issued_by:Id` · `co_signed_by:Id` · `created_at:Timestamp`
*(authoritative cutoff is this record's **position in the anchored log**, not `effective_from`, §11.7.)*

### `auth_proof_context` — `0x0009` (§9.2)
`server_id:text` · `tls_exporter:bytes_fixed(32)` · `nonce:bytes_fixed(32)` · `timestamp:Timestamp`

### `wrap_context` (HPKE `info`) — `0x000A` (§5)
`file_id:Id` · `version:u64` · `recipient_id:Id`

### `chunk_aad` — `0x000B` (§12.10, per-stream per D33)
`file_id:Id` · `version:u64` · `stream_type:StreamType` · `chunk_index:u64` · `is_last:bool`
*(the `stream_type` binds each chunk to its stream, so a chunk cannot be replayed across the `content`/`thumbnail`/`preview`/`metadata` streams of the same file-version.)*

### `fingerprint_input` — `0x000C` (§7.1)
`enc_pub:X25519Pub` · `sig_pub:Ed25519Pub`  → `fingerprint = SHA-256(canonical(fingerprint_input))`

> **Anchored control-log (§7.6).** `revocation`, `reinstatement`, and `key_compromise` form **one** append-only hash chain: each record's `prev_head = SHA-256(canonical(previous record))`, first record uses `GENESIS_HEAD`. The current head is what the external sink anchors and clients verify against (`docs/sink-interface.md`).

---

## 5. Type-id registry

| id | struct | id | struct |
|---|---|---|---|
| `0x0001` | dirbinding | `0x0008` | key_compromise |
| `0x0002` | manifest | `0x0009` | auth_proof_context |
| `0x0003` | grant | `0x000A` | wrap_context |
| `0x0004` | *reserved* (write_grant, removed D29) | `0x000B` | chunk_aad |
| `0x0005` | genesis | `0x000C` | fingerprint_input |
| `0x0006` | revocation | `0x000D` | Stream (manifest sub-struct) |
| `0x0007` | reinstatement | | |

Unknown id → reject. The id makes a value of one type structurally unusable as another (defeats cross-type signature transplant *before* the domain label is even considered).

---

## 6. Signing input & domain separation

For every Ed25519 signature, the signed message is:

```
signing_input = u32 len(label) ‖ label ‖ canonical(struct)
```

where `label` is the ASCII domain string for that record from `DESIGN.md` §5 (e.g. `"MaxSecu-dirbinding-v1"`, `"MaxSecu-manifest-v1"`, `"MaxSecu-grant-v1"`, `"MaxSecu-write-grant-v1"`, `"MaxSecu-genesis-v1"`, `"MaxSecu-revocation-v1"`, `"MaxSecu-reinstatement-v1"`, `"MaxSecu-key-compromise-v1"`, `"MaxSecu-auth-v1"`).

> **Strengthening over `DESIGN.md` notation:** the design writes `"label" ‖ canonical(x)` (raw concatenation, relying on labels being mutually non-prefix). This spec **length-prefixes the label** so the label/struct boundary is unambiguous regardless of label choice — strictly safer, and consistent with §5.2's "length-prefixed `‖`" rule. Verifiers MUST use this framed form.

Non-signature contexts reuse `canonical(struct)` directly: HPKE `info = canonical(wrap_context)`; AEAD `AAD = canonical(chunk_aad)`; `fingerprint = SHA-256(canonical(fingerprint_input))`. The KDF labels (`"MaxSecu-dek-commit-v1"`, and the per-stream subkey infos `"MaxSecu-content-v1"`, `"MaxSecu-metadata-v1"`, `"MaxSecu-thumbnail-v1"`, `"MaxSecu-preview-v1"`) are HKDF `info` constants, not struct encodings.

---

## 7. Decoder rules (strict)

A conforming decoder MUST:

1. Read fields in declared order, consuming exactly their bytes.
2. **Reject trailing bytes:** after the top-level struct, input must be fully consumed.
3. Reject on every primitive violation in §2 (bad bool, unknown enum, non-ascending set, invalid/non-NFC text, bad presence byte, length over-run, short fixed field).
4. Enforce structural constraints: `RecipientType::recovery` ⇒ `recipient_id == RECOVERY_ID`; `FileScope` tag/id consistency.
5. **Re-encode check (master canonical guard):** after producing value `v` from bytes `b`, compute `encode(v)` and require it equals `b`; otherwise reject. This makes invariant §1.3 mechanical and catches any non-canonical form a field rule missed.
6. Before trusting any signature: verify the Ed25519 signature over the framed `signing_input` (§6), **and** run step 5 on the covered struct — so a server cannot supply bytes that verify yet decode to a different value.

---

## 8. Adversarial test vectors (Phase-0 exit gate)

Every vector below MUST be **rejected** (or, for the positive cases, produce the **exact** expected bytes). Ship these as committed fixtures; a serializer that accepts any rejecting case **fails the phase** (`DESIGN.md` §17 Phase 0).

**Positive / canonical:**
- **V-pos-1 (length-prefix injectivity).** `text("ab")` = `00 00 00 02 61 62`; `text("a")` = `00 00 00 01 61`. Confirm no field-tuple produces another's bytes — the classic `("ab")` vs `("a","b…")` split is impossible because each `text` carries its own `u32` length.
- **V-pos-2 (round-trip).** For each struct in §4, `decode(encode(v)) == v` and `encode(decode(b)) == b`.

**Must reject:**
- **V-1 trailing data.** Valid `genesis` ‖ one extra `0x00` → reject (§7.2).
- **V-2 type confusion.** Bytes of a valid `grant` (`type_id 0x0003`) fed to the `write_grant` reader → reject on id; and a `grant_sig` checked under label `"MaxSecu-write-grant-v1"` → fails verification (§6).
- **V-3 non-canonical bool.** `manifest.recovery_present = 0x02` → reject.
- **V-4 set order/dup.** `roles = [0x02,0x01]` (descending) → reject; `roles = [0x01,0x01]` (dup) → reject; canonical is `[0x01,0x02]`.
- **V-5 option presence.** `revocation.revoked_capability` presence byte `0x02` → reject.
- **V-6 integer truncation / over-run.** A `bytes_var` `len` of `0xFFFFFFFF` with little input → reject; a `u32` with 3 bytes left → reject.
- **V-7 unknown enum.** `recipient_type = 0x03` → reject; `alg = 0xFFFF` → reject; `type_id = 0x00FF` → reject.
- **V-8 text hygiene.** Non-UTF-8 `username` → reject; a decomposed (non-NFC) form that differs from its NFC bytes → reject.
- **V-9 domain separation.** Identical `canonical(struct)` under `"MaxSecu-grant-v1"` vs `"MaxSecu-write-grant-v1"` ⇒ different `signing_input`; a signature valid under one MUST fail under the other.
- **V-10 FileScope.** `0x02` (account-wide) followed by 16 id bytes → reject; `0x01` with no id → reject.
- **V-11 recovery binding.** `recipient_type = recovery` with `recipient_id ≠ RECOVERY_ID` → reject.
- **V-12 re-encode mismatch.** Any crafted input that decodes but re-encodes to different bytes → reject via §7.5 (e.g. a malformed `set`/`option` form that slips a naive parser).
- **V-13 stream list order/dup.** `manifest.streams` with `thumbnail` before `content` (descending `stream_type`) → reject; two `content` streams → reject; the reserved `type_id 0x0004` (old write_grant) → reject. Canonical `streams` is ascending and unique by `stream_type`.

---

## 9. Phase-0 exit criteria (mirrors `DESIGN.md` §17)

- [ ] Encoder + strict decoder implemented in the Rust core for all twelve structures (§4).
- [ ] Property tests pass: `decode∘encode` identity; `encode∘decode` identity on all accepted inputs (the canonical guard, §7.5).
- [ ] **All V-1 … V-13 adversarial vectors reject; both positive vectors match byte-for-byte.**
- [ ] Domain-separated, length-framed `signing_input` (§6) wired into every Ed25519 sign/verify call; HPKE `info` and AEAD `AAD` wired to `canonical(wrap_context)` / `canonical(chunk_aad)`.
- [ ] Fixtures committed so the air-gapped ceremony tools (and any server-side sanity check) link the **same** encoder and the **same** vectors.

> Until this phase passes, **no other phase may sign or verify anything** — every later guarantee in `DESIGN.md` rests on these bytes being injective.
