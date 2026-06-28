# Phase 7 — Long-Term Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Subagents MUST run on the **same model (Opus 4.8) and effort** as the orchestrator — no quality loss.

**Goal:** Close the three committed `DESIGN.md` §17 Phase 7 exit gates: (1) recovery requires a **threshold of custodians** (no single cold copy is total); (2) **new uploads use the X25519+ML-KEM-768 hybrid wrap** (harvest-now-decrypt-later mitigated); (3) **clients detect directory split-views** against a key-transparency log.

**Architecture:** Hold the established MaxSecu pattern — a pure, transport-agnostic security core per side, with thin HTTP/TLS adapters layered on, proven e2e over real loopback TLS last. Build *real* in-TCB crypto/verification (hybrid KEM, GF(256) Shamir, Merkle consistency proofs, KT split-view detection) and *concrete in-repo adapters/services* (extend `sink-server` with the directory KT log; make `anchor_genesis` real) exercised e2e; leave the fleet-wide PQ re-enrollment ceremony, a real third-party witness/notary, and vendor WORM/SIEM as documented ops behind those adapters. (Forks: see "Decisions taken" below — surfaced for sign-off but **not** answered, so the recommended defaults are taken; redline any.)

**Tech Stack:** Rust 1.96 (MSVC on Windows dev, musl/gnu on WSL prod). Existing crates: `encoding`, `crypto`, `client-core`, `admin-core`, `server`, `media-worker`, `sink-server`. New external deps this phase: **`ml-kem`** (RustCrypto, FIPS 203, gated on the no-C/deny/audit check in P7.1) and possibly **`x25519-dalek`** as a direct dep (already transitive; needed for the raw-DH leg of the hybrid combiner). Crypto stays RustCrypto + dalek; TLS stays `rustls`/`tokio-rustls` (`aws-lc-rs`, the sole carve-out). No second TLS stack, no C/C++/asm.

---

## Decisions taken (forks surfaced 2026-06-28; user did not pick → recommended defaults taken — redline any)

1. **PQ-hybrid wrap — FULL real (binding + emit V2).** Adopt `ml-kem` (gated on the P7.1 no-C/deny/audit check), extend the directory binding with an ML-KEM-768 public key (admin-core ceremony signs it; identity keygen produces it; keyblob stores it), `upload`/`reshare`/`rotate` emit `Suite::V2` hybrid wraps **when the relevant bindings carry PQ keys**, `download` accepts both `V1` and `V2`, proven e2e with PQ-enrolled test identities. Only the fleet-wide re-enrollment **ceremony** is deferred (ops). This meets the exit gate literally ("new uploads use the hybrid wrap").
   - **Fallback (only if P7.1 fails the gate):** abstract the KEM behind a trait with a fake PQ KEM for tests; the concrete crate + the "emit V2" half defer; record the deviation in DESIGN §17 and stop to flag.
2. **Recovery Shamir split — REAL GF(256) Shamir of the recovery private scalar.** Pure-Rust `crypto::shamir`: split the 32-byte X25519 recovery secret into N shares, threshold K to reconstruct at the offline ceremony; the wrap/upload path is **unchanged** (custody-layer K-of-N, matching §16.3's framing). Residual (documented): the key is briefly reassembled in RAM at recovery time. (Rejected: threshold-recipient multi-wrap — wire change, no mature pure-Rust threshold KEM.)
3. **Directory KT log — REAL client verify + in-repo log producer.** Real client-side inclusion + consistency-proof verification over `crypto::merkle`, wired into directory verification (first-contact bindings require a KT inclusion proof; an inconsistent checkpoint = split-view → reject), **plus** an in-repo append-only KT log producer (extend `sink-server`, mirroring the Phase-6 control-log sink). External witness/notary **gossip** is the ops deferral. Meets the exit gate.
4. **Add-ons:** fold in the cheap **`anchor_genesis`-over-real-sink** cleanup (replace the no-op so the R27 cutoff is proven over the real HTTP sink). Keep the KT log as its **own** Merkle log but **served by the same `sink-server` process** (lightweight convergence per `sink-interface.md` §8; not one unified anchored structure).

### Smaller structural decisions taken (defaults; redline any)

- **D-A.** The hybrid KEM combiner lives in `crates/crypto/src/hybrid.rs`. Construction (a KEM-combiner binding **both** KEM ciphertexts into the KEK derivation, "X-Wing"-style, so neither leg can be re-bound):
  - `eph_x_pub, ss1 = X25519_ephemeral_static_DH(recipient_x_pub)` (raw DH via `x25519-dalek`)
  - `(ct_pq, ss2) = ML_KEM_768.encaps(recipient_mlkem_pub)`
  - `kek = HKDF-SHA256(ikm = ss1 ‖ ss2, salt = ∅, info = "MaxSecu-hybrid-wrap-v2" ‖ canonical(WrapContext) ‖ eph_x_pub ‖ ct_pq, len = 32)`
  - `aead_ct = AES-256-GCM(kek, nonce = 0¹², aad = ∅, dek)`
  - wire wrap = `eph_x_pub(32) ‖ ct_pq(1088) ‖ aead_ct(48)`
  All material is single-use (fresh ephemeral + fresh ML-KEM encaps per wrap), so the all-zero GCM nonce is safe (one message per KEK). `ss1`/`ss2`/`kek` are `Zeroizing`.
- **D-B.** `Suite::V2` (`0x0002`) = `{AEAD AES-256-GCM, KDF HKDF-SHA256, KEM **X25519+ML-KEM-768 hybrid**, SIG Ed25519, PWKDF Argon2id}`. The wrap **wire format** is selected by the manifest `alg` (`V1` → `enc(32)‖ct`; `V2` → the hybrid layout above), so no new per-wrap alg field is needed.
- **D-C.** The directory binding gains an **optional** `mlkem_pub` carried behind a 1-byte presence flag (`0x00` absent / `0x01` present, then 1184 bytes). This changes the canonical bytes of **every** binding (V1 bindings now serialize a trailing `0x00`); acceptable because `main` is unpushed/pre-deployment — all test bindings regenerate. `fingerprint` stays `SHA-256(canonical(enc_pub ‖ sig_pub))` (the human-checkable identity is the classical keypair; the PQ key is authenticated by the same D5 signature over the whole binding, not folded into the spoken fingerprint).
- **D-D.** GF(256) Shamir lives in `crates/crypto/src/shamir.rs` (a reusable primitive), exported to `admin-core::recovery`.
- **D-E.** Merkle **consistency** proofs extend the existing `crates/crypto/src/merkle.rs` (RFC 6962 §2.1.2). Inclusion proofs (P6.2) are reused as-is.
- **D-F.** The directory KT log is `crates/sink-server/src/dirlog.rs` + HTTP routes under `/v1/dir-log/*`, served by the same `sink-server` binary as the control-log (separate Merkle tree, separate log key). The client KT verifier is `crates/client-core/src/transparency.rs`.
- **D-G.** Identity keygen always produces an ML-KEM keypair from P7.4 on; the `local_key_blob` format bumps (magic stays `MXKB`, version `v1` → `v2`) to store the ML-KEM secret. A `v1` blob still loads (no PQ key → that identity simply can't be a V2 recipient until re-enrolled).

---

## Standard Verification Gate (run at the end of every increment, BOTH targets)

Every increment is "green" only when all of the following exit 0 on **both** targets. Reference this block from each task as **"the Standard Gate."**

**Windows (PowerShell tool — cargo must be on PATH):**
```
$env:PATH="$env:USERPROFILE\.cargo\bin;$env:PATH"
cargo test --workspace            # add $env:MAXSECU_PG_OPTIONAL=1 if WSL→localhost PG forwarding is down
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
cargo audit
```
Do **not** `2>&1` cargo in PowerShell (NativeCommandError wrapping); filter stdout.

**WSL prod (Bash tool):**
```
wsl -d Ubuntu-22.04 -- bash -lc 'rsync -a --delete --exclude target --exclude target-repro-a --exclude target-repro-b --exclude .git /mnt/d/scrs/programs/MaxSecu/ ~/maxsecu/ && cd ~/maxsecu && export PATH="$HOME/.cargo/bin:$PATH" && cargo test && cargo clippy --workspace --all-targets -- -D warnings && cargo deny check && cargo audit'
```

**Standing constraints (do not violate):**
- `main` is ahead of origin and UNPUSHED — **never push**.
- No new dep may pull C/C++/asm or a second TLS stack. After adding any dep, confirm `cargo tree -i openssl`, `-i native-tls`, `-i ring`, `-i cc` are empty (only `aws-lc-rs` is allowed) and that `cargo deny check` + `cargo audit` stay green. The RUSTSEC-2023-0071 (`rsa`, unreachable) ignore stays — re-confirm `cargo tree -i rsa -e normal,build` is empty.
- `cfg(windows)` `media-worker` stays cfg-excluded + green on WSL. Its AppContainer containment test can flake under parallel `--workspace` load on Windows — re-run in isolation; not a regression.
- Auto-commit per increment to local `main` once green on **both** targets (no per-commit confirmation). Keep `DESIGN.md` / docs / memory in sync **in the same commit**. Trailers on every commit:
  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01BJyhZPtdHPDcbDHVTJYRmw
  ```

---

## File structure (what this phase creates / modifies)

**New:**
- `crates/crypto/src/hybrid.rs` — X25519+ML-KEM-768 hybrid KEM wrap/unwrap. (P7.2)
- `crates/crypto/src/shamir.rs` — GF(256) Shamir split/combine. (P7.6)
- `crates/client-core/src/transparency.rs` — client-side KT inclusion+consistency verification + split-view detection. (P7.10)
- `crates/sink-server/src/dirlog.rs` — in-repo directory key-transparency Merkle log. (P7.11)
- `crates/server/tests/phase7_hardening_e2e.rs` — Phase-7 capstone e2e. (P7.14)
- `docs/security-review-phase7.md`, `docs/runbooks/pq-reenrollment.md`. (P7.13/P7.15)

**Modified:**
- `crates/crypto/src/merkle.rs` — add `verify_consistency` (+ prover `consistency_path`). (P7.9)
- `crates/crypto/src/lib.rs` — export `hybrid`, `shamir`, new `merkle` fns. (P7.2/P7.6/P7.9)
- `crates/crypto/Cargo.toml` — add `ml-kem`, `x25519-dalek`. (P7.1)
- `crates/encoding/src/types.rs` — `Suite::V2`; `crates/encoding/src/structs.rs` — binding `mlkem_pub`; `crates/encoding/src/lib.rs` — `SUITE_V2`, hybrid-wrap label. (P7.3)
- `crates/client-core/src/identity.rs`, `keyblob.rs` — ML-KEM keygen + keyblob v2. (P7.4)
- `crates/client-core/src/directory.rs` — carry `mlkem_pub`; KT gate hook. (P7.4/P7.10)
- `crates/client-core/src/{upload.rs,download.rs,reshare.rs,rotate.rs}` — V2 hybrid wrap emit/accept. (P7.5)
- `crates/admin-core/src/directory.rs` — sign PQ-enabled bindings; `recovery.rs` — Shamir split/reconstruct. (P7.4/P7.7)
- `crates/sink-server/src/{lib.rs,http.rs,serve.rs}` — wire the KT log. (P7.11)
- `crates/server/src/audit.rs` — real `HttpSinkPublisher::anchor_genesis`. (P7.12)
- `DESIGN.md` §5/§7.4/§16.3/§17/§19, `docs/stack.md` §1.3/§3, `docs/parameters.md`, `docs/sink-interface.md` §8, `docs/encoding-spec.md` §3/§4, `docs/api.md`, memory. (throughout + P7.15)

---

## Task P7.1 — Adopt & vet the `ml-kem` crate (no-C / deny / audit gate)

**Exit-gate target:** de-risk the central PQ dependency before any behavior depends on it. Standing constraint: "confirm `ml-kem` is pure-Rust and clears deny/audit before adopting."

**Files:**
- Modify: `crates/crypto/Cargo.toml`, `crates/crypto/src/lib.rs`
- Create (temporary smoke test): `crates/crypto/src/hybrid.rs` (just a keygen/encaps/decaps smoke test this task; the wrap lands in P7.2)

- [ ] **Step 1 — Add the deps.** In `crates/crypto/Cargo.toml` add `ml-kem = "<latest>"` (RustCrypto, FIPS 203 ML-KEM) and `x25519-dalek = { version = "2", default-features = false, features = ["static_secrets"] }` (raw DH leg; pin to match the dalek already in tree). `default-features = false` on both to avoid pulling extras.

- [ ] **Step 2 — Vet the supply chain (the gate).** Run:
  ```
  cargo tree -i cc -e normal,build       # expect empty (no C compiler dep)
  cargo tree -i openssl ; cargo tree -i ring ; cargo tree -i native-tls   # expect empty
  cargo tree -p ml-kem -e features        # eyeball: pure-Rust, no *-sys
  cargo deny check
  cargo audit
  ```
  Expected: all empty / exit 0. **If `ml-kem` pulls a `*-sys`/`cc`/C dep, or deny/audit flags it → STOP.** Switch to the Decision-2 fallback (trait-abstract KEM + fake), record the deviation in `DESIGN.md` §17 Phase 7 and in the commit, and flag the user before proceeding with the rest of Pillar A.

- [ ] **Step 3 — Smoke test (`hybrid.rs`):** `mlkem_keygen_encaps_decaps_roundtrip`.
  ```rust
  #[test]
  fn mlkem_keygen_encaps_decaps_roundtrip() {
      use ml_kem::{MlKem768, KemCore};
      use ml_kem::kem::{Encapsulate, Decapsulate};
      let (dk, ek) = MlKem768::generate(&mut rand_core::OsRng);
      let (ct, ss_sender) = ek.encapsulate(&mut rand_core::OsRng).unwrap();
      let ss_recv = dk.decapsulate(&ct).unwrap();
      assert_eq!(ss_sender.as_slice(), ss_recv.as_slice());
  }
  ```
  (Adjust the exact `ml-kem` API to the adopted version; the assertion — sender/receiver shared secrets match — is the contract.)

- [ ] **Step 4 — Run, watch it pass** (`cargo test -p maxsecu-crypto hybrid::tests::mlkem_keygen`). This confirms the crate works on the dev target.

- [ ] **Step 5 — Verify:** the Standard Gate, **both** targets. The ML-KEM keygen/encaps/decaps must run on WSL musl/gnu too (it is pure Rust, so it will).

- [ ] **Step 6 — Docs/commit:** note the `ml-kem` adoption + the cleared no-C gate in `docs/stack.md` §1.3 (the "Post-quantum (Phase 7)" row → "adopted, pure-Rust, no-C gate cleared") and the `aws-lc-rs`-only carve-out is unchanged. Commit.
  ```
  git commit -m "Phase 7 (P7.1): adopt ml-kem (FIPS 203) + x25519-dalek; no-C/deny/audit gate cleared"
  ```

---

## Task P7.2 — Hybrid KEM wrap/unwrap (X25519+ML-KEM-768) in `crypto`

**Exit-gate target:** the cryptographic core of "new uploads use the hybrid wrap" — a DEK wrap that survives a CRQC unless **both** X25519 and ML-KEM-768 break.

**Files:**
- Modify: `crates/crypto/src/hybrid.rs`, `crates/crypto/src/lib.rs`
- Reuse: `crates/crypto/src/{kdf.rs,aead.rs,dek.rs}` (HKDF, AES-256-GCM single-shot, `Dek`), `maxsecu_encoding::structs::WrapContext`

- [ ] **Step 1 — Failing tests (`hybrid.rs`):**
  - `hybrid_wrap_then_unwrap_recovers_the_dek` — round-trip through both legs.
  - `hybrid_unwrap_wrong_x25519_key_fails` and `hybrid_unwrap_wrong_mlkem_key_fails` — each leg's key is load-bearing.
  - `hybrid_unwrap_wrong_context_fails` — a different `WrapContext` changes the KDF `info` → open fails.
  - `hybrid_tampered_ct_fails` — flip a byte in `ct_pq`, in `eph_x_pub`, or in `aead_ct` → fail (each independently).
  - `hybrid_wrap_is_randomized` — two wraps of the same DEK differ (fresh ephemeral + fresh encaps).

  Signatures to introduce:
  ```rust
  pub struct HybridEncPublicKey { pub x25519: [u8; 32], pub mlkem: [u8; 1184] }
  pub struct HybridEncSecretKey { /* zeroizing x25519:[u8;32], mlkem decap key */ }
  pub struct HybridWrappedDek { pub eph_x_pub: [u8; 32], pub ct_pq: Vec<u8> /*1088*/, pub aead_ct: Vec<u8> /*48*/ }

  pub fn generate_hybrid_keypair() -> (HybridEncSecretKey, HybridEncPublicKey);
  pub fn wrap_dek_hybrid(recipient: &HybridEncPublicKey, dek: &Dek, ctx: &WrapContext)
      -> Result<HybridWrappedDek, CryptoError>;
  pub fn unwrap_dek_hybrid(recipient: &HybridEncSecretKey, wrapped: &HybridWrappedDek, ctx: &WrapContext)
      -> Result<Dek, CryptoError>;

  // Wire (de)serialization for the manifest/store path (D-B layout):
  pub fn serialize_hybrid_wrap(w: &HybridWrappedDek) -> Vec<u8>;            // eph_x_pub ‖ ct_pq ‖ aead_ct
  pub fn deserialize_hybrid_wrap(b: &[u8]) -> Result<HybridWrappedDek, CryptoError>; // strict lengths
  ```

- [ ] **Step 2 — Run, watch fail** (`wrap_dek_hybrid` undefined). `cargo test -p maxsecu-crypto hybrid`.

- [ ] **Step 3 — Implement the combiner (D-A).** `wrap_dek_hybrid`:
  1. fresh X25519 ephemeral; `ss1 = DH(eph_sk, recipient.x25519)` (`x25519-dalek`); `eph_x_pub = eph_pk.to_bytes()`.
  2. `(ct_pq, ss2) = MlKem768.encaps(recipient.mlkem)`.
  3. `kek = hkdf_sha256(ikm = ss1 ‖ ss2, salt = &[], info = HYBRID_WRAP_LABEL ‖ encode(ctx) ‖ eph_x_pub ‖ ct_pq, len = 32)` (wrap `ss1`,`ss2`,`kek` in `Zeroizing`).
  4. `aead_ct = aes256gcm_seal(kek, nonce = [0u8;12], aad = &[], pt = dek.expose())`.
  `unwrap_dek_hybrid` mirrors it: `ss1 = DH(recipient.x25519_sk, eph_x_pub)`, `ss2 = decaps(ct_pq)`, re-derive `kek`, open; map any failure → `CryptoError::WrapOpen`, length mismatch → `BadLength`; verify `pt.len()==32`. Add `HYBRID_WRAP_LABEL = b"MaxSecu-hybrid-wrap-v2"` (a `crypto`-local const; the per-record domain label is also registered in `encoding` in P7.3 for the signing-input table — keep them identical).

- [ ] **Step 4 — Run, watch pass.** `cargo test -p maxsecu-crypto hybrid`.

- [ ] **Step 5 — Verify:** Standard Gate, both targets.

- [ ] **Step 6 — Docs/commit:** `DESIGN.md` §5 PQ row → "implemented (Phase 7) via the hybrid combiner, `crypto::hybrid`"; cross-ref the combiner construction. Commit.
  ```
  git commit -m "Phase 7 (P7.2): X25519+ML-KEM-768 hybrid KEM wrap/unwrap (crypto::hybrid)"
  ```

---

## Task P7.3 — `Suite::V2` + ML-KEM key in the directory binding (encoding)

**Exit-gate target:** the wire-format substrate for V2 uploads and PQ-enrolled bindings.

**Files:**
- Modify: `crates/encoding/src/types.rs` (`Suite::V2`), `crates/encoding/src/structs.rs` (binding `mlkem_pub`), `crates/encoding/src/lib.rs` (`SUITE_V2`, `HYBRID_WRAP` label), `crates/encoding/tests/*` (golden/vectors)

- [ ] **Step 1 — Failing encoding tests:**
  - In `crates/encoding/src/types.rs` tests (or `tests/vectors.rs`): `suite_v2_roundtrips` — `Suite::V2` encodes to `0x0002` and decodes back; an unknown `0x0003` → `UnknownEnum`.
  - In `tests/vectors.rs`: `binding_without_pq_roundtrips` (presence flag `0x00`, no key) and `binding_with_pq_roundtrips` (flag `0x01` + 1184-byte `mlkem_pub`); `binding_pq_flag_set_but_short_key_rejected` (flag `0x01`, truncated key → `DecodeError`); the master re-encode guard still holds.
  - Update existing binding golden fixtures to the new canonical bytes (trailing `0x00` for non-PQ bindings).

- [ ] **Step 2 — Run, watch fail.** `cargo test -p maxsecu-encoding`.

- [ ] **Step 3 — Implement:**
  - `Suite::V2` in `types.rs` (`put` → `w.u16(0x0002)`, `get` → `0x0002 => Ok(Suite::V2)`). Add `pub const SUITE_V2: u16 = 0x0002;` in `lib.rs`.
  - In `structs.rs` `DirBinding`: add `pub mlkem_pub: Option<[u8; 1184]>`. Encode: after the existing fields, `w.u8(if some {1} else {0})` then the 1184 bytes if present. Decode: read the flag byte; `0x00` → `None`; `0x01` → read exactly 1184 bytes (short/missing → `DecodeError::Truncated`); any other flag byte → `DecodeError::UnknownEnum{kind:"PqPresence",..}`. Keep `fingerprint` derivation unchanged (over `enc_pub ‖ sig_pub` only, D-C).
  - Register the hybrid-wrap domain label in the `lib.rs`/`signing_input` label table (mirroring `SINK_HEAD`/`SINK_CHECKPOINT`): `MaxSecu-hybrid-wrap-v2` — value MUST equal `crypto::hybrid::HYBRID_WRAP_LABEL` (P7.2 step 3).

- [ ] **Step 4 — Run, watch pass.** `cargo test -p maxsecu-encoding`.

- [ ] **Step 5 — Verify:** Standard Gate, both targets.

- [ ] **Step 6 — Docs/commit:** `docs/encoding-spec.md` §3 (Suite `0x0002`) + §4 (binding `mlkem_pub` flag+field, hybrid-wrap wire layout) + the signing-input/label table. Commit.
  ```
  git commit -m "Phase 7 (P7.3): Suite::V2 + optional ML-KEM pubkey in directory binding (encoding)"
  ```

---

## Task P7.4 — ML-KEM identity keygen, keyblob v2, signed PQ bindings, directory carry

**Exit-gate target:** PQ-enrolled identities exist end-to-end — keygen → keyblob → D5-signed binding → client-resolved recipient PQ key.

**Files:**
- Modify: `crates/client-core/src/identity.rs` (ML-KEM keypair), `crates/client-core/src/keyblob.rs` (blob v2), `crates/admin-core/src/directory.rs` (`sign_binding` carries `mlkem_pub`), `crates/client-core/src/directory.rs` (`SignedBinding`/`authorize_recipient` expose `mlkem_pub`)

- [ ] **Step 1 — Failing identity test (`identity.rs`):** `identity_has_hybrid_enc_key` — a freshly generated `Identity` exposes an `enc_pub` (X25519, unchanged) **and** an `mlkem_pub` ([u8;1184]); the matching secrets unwrap a `wrap_dek_hybrid` to that identity (use `crypto::hybrid`).

- [ ] **Step 2 — Failing keyblob test (`keyblob.rs`):** `keyblob_v2_roundtrips_with_mlkem` — seal an identity carrying the ML-KEM secret into a `local_key_blob` (magic `MXKB`, version `2`) under Argon2id, re-open with the password, recover a working hybrid secret key. `keyblob_v1_still_loads` — an existing v1 blob (no ML-KEM) still opens; the identity has `mlkem_pub == None` and cannot be a V2 recipient.

- [ ] **Step 3 — Run, watch both fail.** `cargo test -p maxsecu-client-core identity keyblob`.

- [ ] **Step 4 — Implement:** `identity.rs` generates the ML-KEM keypair via `crypto::hybrid::generate_hybrid_keypair` (or a split keygen); store the ML-KEM secret in the `Identity`. `keyblob.rs`: bump the format to v2 — serialize the ML-KEM secret after the existing X25519/Ed25519 secrets; the version byte gates whether it is read (v1 → none). Zeroize on drop.

- [ ] **Step 5 — Failing admin/directory tests:**
  - `admin-core/src/directory.rs`: `sign_binding_includes_mlkem` — `DirectorySigner::sign_binding` accepts an optional `mlkem_pub` and the resulting `SignedBinding` verifies with the PQ key present (D5 signature covers the whole binding incl. the PQ field).
  - `client-core/src/directory.rs`: `verified_binding_exposes_mlkem` — after `verify_binding`, the resolved binding exposes `mlkem_pub`; `authorize_recipient` returns it so the wrapper can build a hybrid recipient.

- [ ] **Step 6 — Run, watch fail; implement** the `mlkem_pub` plumbing through `sign_binding` and the verifier (no new signature semantics — the existing D5 Ed25519 signature over `canonical(binding)` now covers the PQ field for free).

- [ ] **Step 7 — Verify:** Standard Gate, both targets.

- [ ] **Step 8 — Docs/commit:** `DESIGN.md` §7.1 (binding gains an optional ML-KEM key, fingerprint unchanged) + §6.1 (per-user keys now include an ML-KEM keypair, on-device only). Commit.
  ```
  git commit -m "Phase 7 (P7.4): ML-KEM identity keygen + keyblob v2 + PQ-signed bindings + directory carry"
  ```

---

## Task P7.5 — Upload emits `Suite::V2`; download/reshare/rotate accept both

**Exit-gate target:** **"new uploads use the hybrid wrap"** — the gate, literally. A PQ-enrolled upload produces V2; a mixed fleet still works.

**Files:**
- Modify: `crates/client-core/src/upload.rs`, `crates/client-core/src/download.rs`, `crates/client-core/src/reshare.rs`, `crates/client-core/src/rotate.rs`

- [ ] **Step 1 — Failing upload test (`upload.rs`):** `pq_upload_emits_v2_hybrid_wraps`.
  - Build `UploadParams` where both the self binding and the recovery binding carry `mlkem_pub`.
  - `build_upload(..)` → `manifest.alg == Suite::V2`; each wrap's stored bytes deserialize via `crypto::hybrid::deserialize_hybrid_wrap` and unwrap (self key + recovery key) to the committed DEK.
  - `non_pq_upload_stays_v1` — when a binding lacks `mlkem_pub`, the upload falls back to `Suite::V1` and the existing X25519 wrap (so a partially-enrolled fleet still uploads). *(Policy note: V2 requires BOTH self and recovery to have PQ keys, since recovery is a mandatory recipient.)*

- [ ] **Step 2 — Failing download test (`download.rs`):** `v2_hybrid_wrap_opens_on_download` — a V2 manifest + hybrid wrap is opened by `verify_and_open` (dispatch on `manifest.alg`); the V1 path is unchanged (`v1_wrap_still_opens`).

- [ ] **Step 3 — Run, watch fail.** `cargo test -p maxsecu-client-core upload download`.

- [ ] **Step 4 — Implement:**
  - `upload.rs`: a `wrap_and_grant` branch on suite — if all required recipients (self + recovery) carry `mlkem_pub`, set `alg = Suite::V2` and use `wrap_dek_hybrid` + `serialize_hybrid_wrap`; else `Suite::V1` as today. The grant/`dek_commit`/manifest-signing logic is unchanged (the grant binds `dek_commit`, not the wrap layout).
  - `download.rs`: in the unwrap step, dispatch on `manifest.alg` — `V1` → `unwrap_dek`; `V2` → `deserialize_hybrid_wrap` + `unwrap_dek_hybrid`. Everything downstream (the `dek_commit` self-validation, §12.5 ladder) is unchanged.

- [ ] **Step 5 — Reshare + rotate parity tests + impl:**
  - `reshare.rs`: `build_reshare` produces a wrap whose layout matches the file's `alg` (a V2 file re-shares with a hybrid wrap to the recipient's `mlkem_pub`); add `reshare_v2_roundtrips`. A recipient lacking a PQ key on a V2 file → `ResharePqKeyMissing` (fail closed, surfaced to the UI to prompt re-enrollment).
  - `rotate.rs`: `build_next_version` re-wraps carried-forward recipients under the file's suite (V2 → hybrid). Add `rotate_v2_carries_forward`. The DEK'/`PriorDekMismatch`/carry-forward-entailment logic is unchanged.

- [ ] **Step 6 — Verify:** Standard Gate, both targets.

- [ ] **Step 7 — Docs/commit:** `DESIGN.md` §5.1 (V2 is now the "current" suite when the fleet is PQ-enrolled; mixed-fleet fallback documented) + §12.2 (wrap layout selected by `alg`). Commit.
  ```
  git commit -m "Phase 7 (P7.5): upload emits Suite::V2 hybrid wrap; download/reshare/rotate accept V1+V2"
  ```

---

## Task P7.6 — GF(256) Shamir secret-sharing primitive (`crypto::shamir`)

**Exit-gate target:** the cryptographic core of "recovery requires a threshold of custodians."

**Files:**
- Create: `crates/crypto/src/shamir.rs`; Modify: `crates/crypto/src/lib.rs`

- [ ] **Step 1 — Failing tests (`shamir.rs`):**
  - `split_then_any_k_of_n_reconstructs` — `split(&secret, k=3, n=5)` → 5 shares; **every** 3-subset reconstructs `secret`; a 5-subset too.
  - `fewer_than_k_cannot_reconstruct` — combining any `k-1` shares yields a value `!= secret` (Shamir reveals nothing below threshold; assert the wrong result, and that `combine` of `<k` distinct shares is rejected or returns garbage per the chosen API — prefer an explicit `Err(ShamirError::InsufficientShares)` when the caller declares `k`).
  - `duplicate_or_tampered_share_rejected` — two shares with the same x-index → `Err(DuplicateIndex)`; a share whose bytes were flipped reconstructs a wrong secret (documented: bare Shamir is not authenticated — integrity comes from the downstream X25519-key check in P7.7).
  - `secret_is_32_bytes_byte_independent` — splitting is per-byte over GF(256); a 32-byte secret round-trips exactly.

  Signatures:
  ```rust
  pub struct Share { pub index: u8, pub body: Vec<u8> }   // index = GF(256) x ≠ 0
  pub enum ShamirError { InsufficientShares, DuplicateIndex, BadThreshold, LengthMismatch }
  pub fn split(secret: &[u8], k: u8, n: u8) -> Result<Vec<Share>, ShamirError>;   // 1 ≤ k ≤ n ≤ 255
  pub fn combine(k: u8, shares: &[Share]) -> Result<Zeroizing<Vec<u8>>, ShamirError>;
  ```

- [ ] **Step 2 — Run, watch fail.** `cargo test -p maxsecu-crypto shamir`.

- [ ] **Step 3 — Implement** GF(256) arithmetic (the AES field, reduction poly `0x11B`): `add = xor`, `mul` via log/exp tables or carry-less loop, `inv` via Fermat or table. `split`: per secret byte, a random degree-`k-1` polynomial with constant term = the byte, evaluated at `x = 1..=n`. `combine`: Lagrange interpolation at `x = 0` over the supplied shares (use exactly `k`). Random coefficients from `crypto::rng` (OS CSPRNG). Zeroize coefficients and the reconstructed secret buffer.

- [ ] **Step 4 — Run, watch pass.** `cargo test -p maxsecu-crypto shamir`.

- [ ] **Step 5 — Verify:** Standard Gate, both targets.

- [ ] **Step 6 — Docs/commit:** `DESIGN.md` §16.3 (the Shamir primitive now exists) + §19 (mark the split "implemented (Phase 7)"). Commit.
  ```
  git commit -m "Phase 7 (P7.6): GF(256) Shamir secret-sharing primitive (crypto::shamir)"
  ```

---

## Task P7.7 — Threshold recovery-key custody in `admin-core` (K-of-N)

**Exit-gate target:** **"recovery requires a threshold of custodians (no single cold copy is total)."**

**Files:**
- Modify: `crates/admin-core/src/recovery.rs`, `crates/admin-core/src/lib.rs`

- [ ] **Step 1 — Failing tests (`recovery.rs`):**
  - `recovery_key_split_reconstruct_unwraps` — split the 32-byte X25519 recovery secret with `(k=3,n=5)`; reconstruct from a 3-subset → the reconstructed secret unwraps a real recovery wrap built for that public key (chain to `crypto::wrap::unwrap_dek` / `validate_recovery_wrap`). This proves the reconstructed scalar **is** the recovery key.
  - `recovery_key_below_threshold_fails` — a 2-subset cannot reconstruct a working key (unwrap fails / `InsufficientShares`).
  - `reconstructed_then_zeroized` — the reconstructed key is held in `Zeroizing` (compile-level contract; assert the API returns a zeroizing wrapper).

  Signatures:
  ```rust
  pub fn split_recovery_key(recovery_secret: &EncSecretKey, k: u8, n: u8)
      -> Result<Vec<crypto::shamir::Share>, RecoveryError>;
  pub fn reconstruct_recovery_key(k: u8, shares: &[crypto::shamir::Share])
      -> Result<EncSecretKey, RecoveryError>;
  ```

- [ ] **Step 2 — Run, watch fail.** `cargo test -p maxsecu-admin-core recovery`.

- [ ] **Step 3 — Implement** as thin wrappers over `crypto::shamir` that expose/reconstruct the 32-byte X25519 secret and rebuild an `EncSecretKey` (zeroizing). `split_recovery_key` exposes the secret bytes once (already a privileged offline op), splits, and zeroizes the intermediate.

- [ ] **Step 4 — Verify:** Standard Gate, both targets.

- [ ] **Step 5 — Docs/commit:** update `docs/runbooks/recovery-session.md` and `docs/runbooks/recovery-key-rotation.md` to the **threshold ceremony** (K custodians each present a share; reconstruct in air-gapped RAM; zeroize after; the residual reassembly window documented). `DESIGN.md` §16.3 → "Shamir split shipped; recovery needs K-of-N custodians"; §3.1 "Stolen offline recovery device" row + §19 updated (single cold copy is no longer total). Commit.
  ```
  git commit -m "Phase 7 (P7.7): K-of-N threshold recovery-key custody (admin-core::recovery)"
  ```

---

## Task P7.8 — Make `anchor_genesis` real over the HTTP sink (R27 over real sink)

**Exit-gate target:** add-on — replace the no-op `HttpSinkPublisher::anchor_genesis` so the R27 genesis-after-compromise cutoff is proven over the **real** sink, not only `MemoryAuditSink`.

**Files:**
- Modify: `crates/server/src/audit.rs`; reuse the `sink-server` genesis-anchor surface (add a `/v1/control-log/genesis` append if not present, or reuse the records endpoint with a genesis-anchor record kind)

- [ ] **Step 1 — Failing server test (`crates/server/tests/`):** `genesis_anchored_to_real_sink` — bring up an in-proc `sink-server` (loopback TLS) + the app server with `audit: Arc::new(HttpSinkPublisher::new(pinned_sink_client))`; on v1 file create, the sink reflects the genesis anchor at a stable sink position; a download with a `CompromiseCheck` whose cutoff predates that position honors the genesis, and one after it → `GenesisAfterCompromise` (R27, now over the real sink).

- [ ] **Step 2 — Run, watch fail** (`anchor_genesis` is a no-op → sink has no genesis position).

- [ ] **Step 3 — Implement** `HttpSinkPublisher::anchor_genesis` to POST a genesis-anchor record to the sink (best-effort/infallible from the caller, same contract as `publish_control_record`); the sink assigns the monotonic position the R27 cutoff reads. Extend `sink-server` minimally if a genesis-anchor record kind/route is needed.

- [ ] **Step 4 — Verify:** Standard Gate, both targets.

- [ ] **Step 5 — Docs/commit:** `docs/sink-interface.md` + `DESIGN.md` §17 Phase 6 deferral list (strike "genesis anchoring over the real HTTP sink is a no-op" — now real). Commit.
  ```
  git commit -m "Phase 7 (P7.8): real genesis anchoring over the HTTP sink (R27 cutoff over real sink)"
  ```

---

## Task P7.9 — Merkle consistency proofs (`crypto::merkle`)

**Exit-gate target:** the split-view-detection primitive — a client that has gossiped/persisted one checkpoint can prove a later checkpoint is an append-only extension (or detect that it is **not** → equivocation).

**Files:**
- Modify: `crates/crypto/src/merkle.rs`, `crates/crypto/src/lib.rs`

- [ ] **Step 1 — Failing tests (`merkle.rs`):**
  - `consistency_verifies_for_append_only_extension` — build trees of size `m` then `n` (`m < n`) by appending; `verify_consistency(m, root_m, n, root_n, &proof)` → `true`.
  - `consistency_rejects_forked_history` — a tree of size `n` built on a **different** size-`m` prefix (a fork / split-view) → `false` for the honest `root_m`.
  - `consistency_rejects_tampered_proof` — flip any proof node → `false`; `m == 0` and `m == n` edge cases handled per RFC 6962.

  Signature:
  ```rust
  pub fn verify_consistency(m: u64, root_m: [u8;32], n: u64, root_n: [u8;32], proof: &[[u8;32]]) -> bool;
  // plus prover for the in-repo log + tests:
  pub fn consistency_path(leaves: &[Vec<u8>], m: u64, n: u64) -> Vec<[u8;32]>;
  ```

- [ ] **Step 2 — Run, watch fail.** `cargo test -p maxsecu-crypto merkle::tests::consistency`.

- [ ] **Step 3 — Implement** the RFC 6962 §2.1.2 consistency algorithm (reuse the existing `leaf_hash`/`node_hash` domain prefixes from P6.2). No `unsafe`; reject `m > n`.

- [ ] **Step 4 — Verify:** Standard Gate, both targets.

- [ ] **Step 5 — Docs/commit:** `docs/encoding-spec.md`/`sink-interface.md` cross-ref to the consistency form. Commit.
  ```
  git commit -m "Phase 7 (P7.9): RFC 6962 Merkle consistency proofs (crypto::merkle)"
  ```

---

## Task P7.10 — Client-side KT verification + split-view detection (`client-core::transparency`)

**Exit-gate target:** **"clients detect directory split-views against the log"** — the client half of the gate.

**Files:**
- Create: `crates/client-core/src/transparency.rs`; Modify: `crates/client-core/src/lib.rs`, `crates/client-core/src/directory.rs` (KT gate hook)

- [ ] **Step 1 — Failing tests (`transparency.rs`):**
  - `binding_with_valid_inclusion_and_consistency_accepts` — a signed checkpoint (pinned KT log key) + an inclusion proof of `canonical(binding)` as a leaf, consistent with the client's persisted checkpoint → `Ok(())`.
  - `split_view_inconsistent_checkpoint_detected` — a second checkpoint whose root is **not** a consistent extension of the persisted one → `Err(KtError::SplitView)` (the equivocation alarm).
  - `forged_checkpoint_sig_rejected` — checkpoint signed by a non-pinned key → `Err(KtError::BadCheckpoint)`.
  - `binding_not_in_log_rejected` — valid checkpoint but a bad/absent inclusion proof → `Err(KtError::NotIncluded)`.
  - `first_checkpoint_is_trusted_on_first_use` — with no persisted checkpoint, the first verified checkpoint is pinned (TOFU); subsequent ones must be consistent with it.

  Signatures:
  ```rust
  pub struct KtCheckpoint { pub tree_size: u64, pub root: [u8;32], pub sig: [u8;64] }
  pub enum KtError { BadCheckpoint, NotIncluded, SplitView, Regression }
  pub trait KtCheckpointStore {   // persisted gossip state (mirrors TrustStore)
      fn latest(&self) -> Option<KtCheckpoint>;
      fn update(&mut self, cp: KtCheckpoint);
  }
  pub fn verify_binding_in_log(
      binding_bytes: &[u8],
      inclusion: &InclusionProof,        // {index, tree_size, path} from crypto::merkle
      checkpoint: &KtCheckpoint,
      log_pubs: &[[u8;32]],              // pinned KT log keys (allowlist; empty ⇒ never validates)
      store: &mut dyn KtCheckpointStore,
  ) -> Result<(), KtError>;
  ```

- [ ] **Step 2 — Run, watch fail.** `cargo test -p maxsecu-client-core transparency`.

- [ ] **Step 3 — Implement:** verify `checkpoint.sig` over `canonical(checkpoint{tree_size,root})` under a pinned `log_pub` (reuse the P6.2 checkpoint label or a new `MaxSecu-kt-checkpoint-v1` label — register in `encoding`); if a prior checkpoint is persisted, require `crypto::merkle::verify_consistency(prev.tree_size, prev.root, cp.tree_size, cp.root, …)` — failure → `SplitView`, lower `tree_size` → `Regression`; then `crypto::merkle::verify_inclusion(binding_bytes, index, tree_size, path, cp.root)` — failure → `NotIncluded`. On success persist `cp` via the store.

- [ ] **Step 4 — Wire the gate into `directory.rs` (optional, fail-closed when enabled):** add an optional KT checker to `DirectoryVerifier` / `authorize_recipient` so that, **at first contact** (no TOLU record for the `user_id`), a binding must additionally pass `verify_binding_in_log`. Add `directory_first_contact_requires_kt_inclusion`. When the KT checker is absent (not configured), behavior is unchanged (backward-compatible) — but the Phase-7 client ships it configured.

- [ ] **Step 5 — Verify:** Standard Gate, both targets.

- [ ] **Step 6 — Docs/commit:** `DESIGN.md` §7.4 (the transparency log is now the live first-contact equivocation defense; describe inclusion+consistency+gossip) + §7.2 (KT as an added first-contact gate). Commit.
  ```
  git commit -m "Phase 7 (P7.10): client KT inclusion+consistency verification + split-view detection"
  ```

---

## Task P7.11 — In-repo directory KT log producer (`sink-server::dirlog`)

**Exit-gate target:** the server half of the KT gate — an append-only Merkle log of bindings serving checkpoints, inclusion, and consistency proofs over the same `sink-server` process.

**Files:**
- Create: `crates/sink-server/src/dirlog.rs`; Modify: `crates/sink-server/src/lib.rs`, `crates/sink-server/src/http.rs`, `crates/sink-server/src/serve.rs`

- [ ] **Step 1 — Failing core test (`dirlog.rs`):** `append_binding_emits_checkpoint_inclusion_consistency`.
  - `DirLog::new(log_key)`; `append(binding_bytes) -> u64 (leaf index)`; `checkpoint() -> KtCheckpoint` (signed `{tree_size, root}`); `inclusion(index) -> InclusionProof`; `consistency(m) -> Vec<[u8;32]>`.
  - Assert each output verifies under the client side: `client_core::transparency::verify_binding_in_log` accepts an appended binding under the pinned `log_key.public()`; `crypto::merkle::verify_consistency` holds between two successive checkpoints. (Cross-crate test: `sink-server` dev-deps `client-core` + `crypto`.)

- [ ] **Step 2 — Run, watch fail.** `cargo test -p maxsecu-sink-server dirlog`.

- [ ] **Step 3 — Implement `DirLog`** over `crypto::merkle` prover fns (`merkle_root`, `inclusion_path` from P6.2, `consistency_path` from P7.9); sign checkpoints with the log key; store the leaf bytes append-only (mirror `ControlLogStore`).

- [ ] **Step 4 — Failing HTTP test (`http.rs`, oneshot):** `dir_log_routes_roundtrip`.
  - `GET /v1/dir-log/checkpoint` → `{tree_size, root_b64, sig_b64}`.
  - `GET /v1/dir-log/inclusion?index=<i>` → `{index, tree_size, path_b64[]}`.
  - `GET /v1/dir-log/consistency?from=<m>` → `{path_b64[]}`.
  - `POST /v1/dir-log/bindings` (admin cred; append-only) → leaf index; appends are never reordered/rewritten.

- [ ] **Step 5 — Run, watch fail; implement** the axum routes over `DirLog` in shared state alongside the existing control-log routes (same `serve.rs` TLS listener).

- [ ] **Step 6 — Verify:** Standard Gate, both targets.

- [ ] **Step 7 — Docs/commit:** `docs/sink-interface.md` §8 (KT log served by the same sink process; routes; the witness/notary gossip is the ops swap-in). Commit.
  ```
  git commit -m "Phase 7 (P7.11): in-repo directory KT log producer (sink-server::dirlog)"
  ```

---

## Task P7.12 — KT integration: enrollment publishes bindings to the log

**Exit-gate target:** close the loop — bindings signed at the ceremony are published to the KT log so clients can require inclusion.

**Files:**
- Modify: `crates/admin-core/src/directory.rs` or the ceremony glue (the binding-publish path), `docs/runbooks/enrollment-signing.md`; possibly a small `server`/test harness helper that POSTs the signed binding to `/v1/dir-log/bindings`

- [ ] **Step 1 — Failing test:** `enrolled_binding_is_inclusion_provable` — sign a binding (admin-core), publish it to a live in-proc `sink-server` KT log over TLS, fetch the checkpoint + inclusion proof, and have `client_core::transparency::verify_binding_in_log` accept it. (This is the ceremony→log→client path, minus the air-gap transfer which is a runbook step.)

- [ ] **Step 2 — Run, watch fail; implement** the publish glue (the ceremony's binding-publish step writes to the KT log just as control records are published to the control-log; in-repo this is an HTTP POST, in ops it is the air-gapped publish documented in the runbook).

- [ ] **Step 3 — Verify:** Standard Gate, both targets.

- [ ] **Step 4 — Docs/commit:** `docs/runbooks/enrollment-signing.md` gains the "publish the signed binding to the KT log + confirm inclusion" step (mirroring the §6 control-log anchoring confirm). Commit.
  ```
  git commit -m "Phase 7 (P7.12): enrollment publishes bindings to the KT log (inclusion-provable)"
  ```

---

## Task P7.13 — PQ re-enrollment runbook

**Exit-gate target:** document the only PQ deferral (fleet-wide re-enrollment), so the "emit V2" gate is operationally completable.

**Files:**
- Create: `docs/runbooks/pq-reenrollment.md`

- [ ] **Step 1 — Write the runbook:** how the fleet migrates to PQ — generate ML-KEM keypairs on each device (keyblob v2), re-sign bindings with the PQ key at the next ceremony (incl. the recovery binding, which must be PQ before any file can be V2), the mixed-fleet window (V1 fallback while not all recipients are enrolled, per P7.5 policy), and the §5.1 fleet-currency reminder once V2 is "current". Cross-ref `DESIGN.md` §5.1, §16.1.

- [ ] **Step 2 — Verify:** Standard Gate (docs only — no code). Commit.
  ```
  git commit -m "Phase 7 (P7.13): PQ re-enrollment runbook"
  ```

---

## Task P7.14 — Phase-7 capstone e2e over real TLS

**Exit-gate target:** all three exit gates demonstrated end-to-end over the real stack, plus the add-on.

**Files:**
- Create: `crates/server/tests/phase7_hardening_e2e.rs` (reuses the TLS harness from `sharing_e2e.rs`/`phase6_integrity_ops_e2e.rs`)

- [ ] **Step 1 — Failing e2e:** `phase7_hardening_exit_gates_over_real_tls`.
  - **PQ gate:** register two **PQ-enrolled** identities (X25519+ML-KEM) + a PQ recovery binding; `build_upload` over real TLS → `manifest.alg == Suite::V2`; the recipient downloads and `verify_and_open` recovers the exact plaintext via the hybrid wrap; assert no V1 wrap is present.
  - **Recovery threshold gate:** split the recovery key `(k=3,n=5)`; reconstruct from 3 shares; the reconstructed key validates the file's recovery wrap (`admin-core::recovery` + `validate_recovery_wrap`); a 2-share attempt fails.
  - **KT gate:** stand up the `sink-server` KT log; enroll a binding → publish → client accepts via inclusion+consistency; then present a **split view** (a second checkpoint inconsistent with the gossiped one) → client returns `KtError::SplitView` (detected + rejected).
  - **Add-on:** genesis anchored to the real sink; R27 cutoff honored by sink position.

- [ ] **Step 2 — Run, watch fail; wire** the pieces to green (glue only — all behavior exists from P7.2–P7.12). Note expected `cfg(windows)` exclusions stay green on WSL.

- [ ] **Step 3 — Verify:** Standard Gate, both targets.

- [ ] **Step 4 — Commit.**
  ```
  git commit -m "Phase 7 (P7.14): PQ + threshold-recovery + KT split-view exit gates e2e over real TLS"
  ```

---

## Task P7.15 — Security-review sign-off + DESIGN/docs/memory sync (PHASE 7 COMPLETE)

**Exit-gate target:** leave the repo coherent + a recorded review; `DESIGN.md` §17 Phase 7 marked COMPLETE.

**Files:** `docs/security-review-phase7.md`; `DESIGN.md` §17 Phase 7 + §19; `docs/stack.md` §3; `docs/sink-interface.md`; `docs/audit-prompt.md`; memory `phase-0-status.md` + `MEMORY.md`.

- [ ] **Step 1 — Run the security-review skill** over the Phase-7 diff (current branch). Record findings + dispositions in `docs/security-review-phase7.md`; fix anything actionable as its own TDD commit before declaring complete. Pay special attention to: the hybrid combiner (KEM-binding completeness, nonce single-use), Shamir (no-leak below threshold, zeroization), and KT (split-view actually fails closed; empty allowlists never validate).

- [ ] **Step 2 — `DESIGN.md` §17 Phase 7:** add a *"Build status — COMPLETE (all exit gates met)"* block: hybrid wrap (`crypto::hybrid`, `Suite::V2`, binding ML-KEM key, V2 uploads + mixed-fleet fallback); K-of-N recovery (`crypto::shamir` + `admin-core::recovery`); directory KT log (`crypto::merkle` consistency + `client-core::transparency` + `sink-server::dirlog`, split-view detection); and the `anchor_genesis`-over-real-sink add-on. **Deferrals:** fleet-wide PQ re-enrollment ceremony (runbook ready); a real third-party witness/notary for KT gossip + vendor WORM/SIEM (in-repo producer is the swap-in); real CI runner + Authenticode cert; ffmpeg-video; real Dropbox; P3.10 zstd.

- [ ] **Step 3 — `DESIGN.md` §19 + §3.1:** mark all three §19 "Committed to Phase 7" items **shipped**; update the §3.1 "Stolen offline recovery device" row (single cold copy is no longer total — needs K custodians) and §15.2/§15.3 (PQ harvest-now-decrypt-later mitigated for V2 uploads).

- [ ] **Step 4 — Sync docs/memory:** `docs/stack.md` §3 (strike Phase-7 deferrals now shipped; keep re-enrollment + witness as ops); `docs/audit-prompt.md` phase list (per the `audit-prompt-upkeep` memory); `phase-0-status.md` (Phase 7 increments, "Phase 7 COMPLETE", what remains deferred) + `MEMORY.md` build-status line.

- [ ] **Step 5 — Final verify:** the Standard Gate on both targets. Commit.
  ```
  git commit -m "Phase 7 (P7.15): security-review sign-off; DESIGN/docs/memory sync — PHASE 7 COMPLETE"
  ```

---

## Self-review (spec coverage vs. §17 Phase 7 + §19)

| §17 Phase 7 / §19 requirement | Task(s) |
|---|---|
| Recovery-key Shamir/threshold split (§16.3/§19) | P7.6 (primitive) + P7.7 (K-of-N custody) |
| **Exit:** recovery requires a threshold (no single cold copy is total) | P7.7 + P7.14 |
| PQ-hybrid wrap X25519+ML-KEM-768 via algorithm agility (§5/D20/§19) | P7.1 (dep) + P7.2 (KEM) + P7.3 (Suite::V2/binding) + P7.4 (keys) + P7.5 (emit/accept) |
| **Exit:** new uploads use the hybrid wrap | P7.5 + P7.14 |
| Directory key-transparency log (§7.4/§19) | P7.9 (consistency) + P7.10 (client verify) + P7.11 (in-repo log) + P7.12 (publish) |
| **Exit:** clients detect directory split-views against the log | P7.10 + P7.14 |
| Algorithm agility threaded (no hard-coded suite; recovery as K-of-N abstraction) (stack §3) | P7.3 (Suite::V2) + P7.5 (alg dispatch) + P7.7 |
| Add-on: genesis anchoring over the real sink (R27, was a no-op) | P7.8 |
| PQ re-enrollment ops path | P7.13 |
| Security review sign-off + coherent repo | P7.15 |

**Deferrals intentionally left to ops (not built here):** fleet-wide PQ re-enrollment **ceremony** (P7.13 runbook is the path; the code emits V2 the moment bindings carry PQ keys); a genuinely **third-party** KT witness/notary for cross-org gossip + vendor WORM/SIEM (the in-repo `sink-server` KT producer + control-log sink are the swap-in points); a real CI runner + real Authenticode certificate; ffmpeg/dav1d video transcoder; real Dropbox `ColdTier`; P3.10 zstd encoder.

## Risks / watch-items

- **P7.1 is a hard gate.** If `ml-kem` is not pure-Rust / fails deny/audit, the FULL PQ path is blocked — fall back to the trait-abstract KEM (Decision 2 fallback) and flag before continuing Pillar A.
- **Binding format bump (D-C)** invalidates all previously-signed test bindings. Safe only because `main` is unpushed/pre-deployment. Regenerate every binding fixture in P7.3/P7.4.
- **Hybrid combiner correctness** is security-critical: both KEM ciphertexts MUST feed the KEK derivation (no re-binding), the GCM nonce is safe only because every KEK is single-use. The P7.15 review must confirm this.
- **Shamir reassembly residual:** the recovery key is briefly whole in air-gapped RAM at reconstruction. This is the documented §16.3 custody posture, not a true never-reassemble threshold scheme — call it out in the runbook + review.
