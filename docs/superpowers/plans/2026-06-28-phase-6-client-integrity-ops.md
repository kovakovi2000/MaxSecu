# Phase 6 — Client Integrity & Ops (C2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the C2 (client-integrity / ops) exit gates of `DESIGN.md` §17 Phase 6: turn the Phase-5 sink/audit seams into real, transport-exercised components; ship the offline recovery-wrap validation sweep (R26/D27); add the transparency-log `anchor_proof` form; add monitoring/alerting and a sanitized-error pass; and document reproducible builds, code-signing, signed/transparency-logged updates, and ceremony runbooks.

**Architecture:** Hold the established MaxSecu pattern — a pure, transport-agnostic security core per side, with thin HTTP/TLS adapters layered on, proven e2e over real loopback TLS last. Build *real* the in-TCB verification/crypto (recovery-wrap sweep, transparency-log proof, anomaly logic, update verification, sanitized errors) and *concrete in-repo adapters/services* (a real append-only sink service + a real HTTP `SinkClient`, server head-publication) exercised e2e; leave actual WORM/SIEM vendor, CI runner, and Authenticode cert as documented ops/runbooks behind those adapters. (Forks decided 2026-06-28 — see "Decisions taken" below.)

**Tech Stack:** Rust 1.96 (MSVC on Windows dev, musl/gnu on WSL prod). Existing crates: `encoding`, `crypto`, `client-core`, `admin-core`, `server`, `media-worker`. New crate this phase: `sink-server`. TLS via `rustls` + `tokio-rustls` (provider `aws-lc-rs`, the sole sanctioned carve-out); HTTP via `hyper`/`hyper-util`/`http-body-util` (already in tree — no `reqwest`, no second TLS stack). Crypto stays RustCrypto + dalek.

---

## Decisions taken (forks resolved 2026-06-28 — flag if you disagree)

These four were confirmed by you via the planning questions:

1. **Realness posture:** real in-TCB logic + concrete in-repo adapters/services exercised e2e; defer the actual WORM/SIEM vendor, CI runner, and code-signing cert to documented ops.
2. **External sink:** a new in-repo `crates/sink-server` (concrete append-only / WORM-semantics service over the `sink-interface.md` REST contract) + a real HTTP `SinkClient` adapter replacing `FakeSink`, server `publish_head`/`anchor_genesis` wired to publish over a real channel, proven e2e over TLS. Real vendor WORM/SIEM stays an ops swap behind the adapter.
3. **Transparency-log `anchor_proof` form:** build the **sink-head** transparency form now (signed checkpoint + Merkle inclusion of `{chain_seq, head}`). The Phase-7 *directory* key-transparency log stays separate.
4. **Reproducible builds / code-signing / updates:** code the client-side **verification** (signed update manifest + transparency inclusion proof) as a real TDD module; ship a double-build hash-diff repro script + an Authenticode signing script; document cert/CI as runbooks.

The fifth piece, **monitoring/alerting**, was not asked separately; per the realness posture it is built as a *pure anomaly-detection module with tests* emitting to a seam, with the dashboard/SIEM wiring documented (not coded). Flag if you want a different treatment.

### Smaller structural decisions taken (defaults; redline any)

- **D-A.** The independent sink is its own crate `crates/sink-server` (the workspace's 7th crate). A separate code unit mirrors the "separate failure domain / not on the app server" requirement (`sink-interface.md` §1, stack §2.3). It reuses `encoding` (canonical bytes, `GENESIS_HEAD`) and `crypto` (SHA-256, Ed25519).
- **D-B.** The real `HttpSinkClient` lives in `client-core` behind a **default-off `net` Cargo feature**, using `hyper` + `tokio-rustls` (the same TLS carve-out — no second stack). Default `client-core` builds stay pure, so `cargo deny`/`audit` on the default graph are unaffected; the adapter compiles only under the feature and in tests. *Alternative:* a tiny new `crates/client-net` crate — flag if you prefer crate-separation over a feature gate.
- **D-C.** The Merkle inclusion primitive (RFC 6962-style, domain-separated `0x00` leaf / `0x01` node) goes in `crates/crypto` (`merkle.rs`); it is shared by the sink transparency proof (P6.2) and the update transparency proof (P6.8).
- **D-D.** Monitoring is a pure `server::detect` module emitting to an `AlertSink` seam (`Null`/`Memory`), not a new crate.
- **D-E.** The **reproducible artifact of record** is the Linux `x86_64-unknown-linux-musl` server binary (deterministic target, stack §5.1). Windows MSVC PE determinism is documented with its known caveats (PE timestamp / `/Brepro`), not asserted bit-for-bit. Flag if you want Windows treated as a hard repro target.

---

## Standard Verification Gate (run at the end of every increment, BOTH targets)

Every increment is "green" only when all of the following exit 0 on **both** targets. Reference this block from each task as **"the Standard Gate."**

**Windows (PowerShell tool — cargo must be on PATH):**
```
$env:PATH="$env:USERPROFILE\.cargo\bin;$env:PATH"
cargo test --workspace            # add MAXSECU_PG_OPTIONAL=1 if WSL→localhost PG forwarding is down
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
cargo audit
```
Do **not** `2>&1` cargo in PowerShell (NativeCommandError wrapping); filter stdout.

**WSL prod (Bash tool):**
```
wsl -d Ubuntu-22.04 -- bash -lc 'rsync -a --delete --exclude target --exclude .git /mnt/d/scrs/programs/MaxSecu/ ~/maxsecu/ && cd ~/maxsecu && export PATH="$HOME/.cargo/bin:$PATH" && cargo test && cargo clippy --workspace --all-targets -- -D warnings && cargo deny check && cargo audit'
```

**Standing constraints (do not violate):**
- `main` is ahead of origin and UNPUSHED — **never push**.
- No new dep may pull C/C++/asm or a second TLS stack. After adding any dep, confirm `cargo tree -i openssl`, `-i native-tls`, `-i ring` are empty (only `aws-lc-rs` is allowed) and that `cargo deny check` + `cargo audit` stay green. RUSTSEC-2023-0071 (`rsa`, unreachable) ignore stays — re-confirm `cargo tree -i rsa -e normal,build` is empty.
- `cfg(windows)` `media-worker` stays cfg-excluded + green on WSL. Its AppContainer containment test can flake under parallel `--workspace` load on Windows — re-run in isolation; not a regression.
- Auto-commit per increment to local `main` once green on both targets (no per-commit confirmation). Keep `DESIGN.md` / docs / memory in sync **in the same commit**. Trailers on every commit:
  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  Claude-Session: <this session URL>
  ```

---

## File structure (what this phase creates / modifies)

**New:**
- `crates/sink-server/` — the independent append-only sink service (core + axum HTTP + TLS serve). 7th workspace crate. (P6.3, P6.4)
- `crates/crypto/src/merkle.rs` — RFC 6962-style Merkle inclusion verifier. (P6.2)
- `crates/admin-core/src/sweep.rs` — recovery-wrap validation sweep driver. (P6.1)
- `crates/client-core/src/update.rs` — signed + transparency-logged update verification. (P6.8)
- `crates/server/src/detect.rs` — anomaly-detection analyzer + `AlertSink` seam. (P6.6)
- `crates/server/tests/sanitized_errors.rs` — sanitized-error suite. (P6.7)
- `crates/server/tests/phase6_integrity_ops_e2e.rs` — Phase-6 capstone e2e. (P6.12)
- `scripts/reproducible-build.{ps1,sh}`, `scripts/sign-release.ps1` — ops tooling. (P6.9, P6.10)
- `docs/reproducible-builds.md`, `docs/runbooks/*.md`, `docs/security-review-phase6.md`. (P6.9–P6.13)

**Modified:**
- `crates/admin-core/src/recovery.rs` — add `validate_recovery_wrap`. (P6.1)
- `crates/client-core/src/sink.rs` — add `AnchorProof::TransparencyInclusion` + extend `verify_anchor_proof`; add `HttpSinkClient` under `net`. (P6.2, P6.4)
- `crates/client-core/Cargo.toml` — `net` feature (hyper/tokio-rustls). (P6.4)
- `crates/server/src/audit.rs` — `HttpSinkPublisher: AuditSink` (real `publish_head`/`anchor_genesis`). (P6.5)
- `crates/server/src/{serve.rs,http.rs,error.rs}` — wire the publisher; centralize the error sanitizer. (P6.5, P6.7)
- `Cargo.toml` (workspace), `deny.toml` (if a license needs allowing) — add `sink-server`. (P6.3)
- `docs/api.md`, `docs/sink-interface.md`, `docs/parameters.md`, `DESIGN.md` §16/§17, memory. (throughout + P6.13)

---

## Task P6.1 — Recovery-wrap validation sweep (R26/D27)

**Exit-gate target:** *"a recovery wrap that does not decrypt to the committed DEK behind a valid recovery grant is caught by the sweep (R26)"* (§17 Phase 6). This is the deferred Phase-5 item #2.

**Files:**
- Modify: `crates/admin-core/src/recovery.rs`
- Create: `crates/admin-core/src/sweep.rs`
- Modify: `crates/admin-core/src/lib.rs` (export `sweep`)

- [ ] **Step 1 — Write the failing unit test (`recovery.rs` tests):** `bad_recovery_wrap_is_caught` and `good_recovery_wrap_passes`.
  - Build a file-version's recovery artifacts the way `build_recovery_grant` / `upload::wrap_and_grant` do: a random `DEK`, `dek_commit = HKDF-SHA256(DEK, "MaxSecu-dek-commit-v1", 32)`, and an HPKE wrap of `DEK` to `recovery_pub` with `info = canonical(wrap_context{file_id, version, recipient_id = RECOVERY_ID})`.
  - Good case: `validate_recovery_wrap(&recovery_priv, &wrap, dek_commit, &ctx)` → `Ok(())`.
  - Bad case: replace the wrap with a wrap of a *different* `DEK2` (valid HPKE, wrong key) → `Err(SweepError::WrapMismatch)`. Also a corrupted-ciphertext wrap → `Err(SweepError::WrapUndecryptable)`.

  Signature to introduce:
  ```rust
  pub struct RecoveryWrapCtx { pub file_id: Id, pub version: u64 }
  pub enum SweepError { WrapUndecryptable, WrapMismatch }
  pub fn validate_recovery_wrap(
      recovery_priv: &X25519Secret,
      wrap: &[u8],            // enc(32) ‖ ct, the wire wrap format
      dek_commit: [u8; 32],
      ctx: &RecoveryWrapCtx,
  ) -> Result<(), SweepError>;
  ```

- [ ] **Step 2 — Run it, watch it fail** for the right reason (`validate_recovery_wrap` undefined).
  `cargo test -p maxsecu-admin-core recovery::tests::bad_recovery_wrap_is_caught -- --nocapture` → FAIL (unresolved).

- [ ] **Step 3 — Minimal implementation:** HPKE-open the wrap with `recovery_priv` under the same `info` binding → `DEK'` (map open failure → `WrapUndecryptable`); recompute `dek_commit' = HKDF(DEK', "MaxSecu-dek-commit-v1", 32)`; constant-time compare to `dek_commit` (mismatch → `WrapMismatch`). Reuse the existing `crypto` HPKE-open and `wrap_context` encoder used by `build_recovery_grant`.

- [ ] **Step 4 — Sweep driver test (`sweep.rs`):** `sweep_reports_only_bad_versions`.
  - Input: a `Vec<RecoverySample { file_id, version, wrap, dek_commit }>` mixing good and bad samples.
  - `run_sweep(&recovery_priv, &samples)` → `SweepReport { checked: usize, bad: Vec<RecoveryWrapCtx> }` listing only the bad file-versions.
  - Assert `report.checked == samples.len()` and `report.bad` is exactly the planted-bad set.

- [ ] **Step 5 — Implement `run_sweep`** as a thin loop over `validate_recovery_wrap`, collecting `Err` cases into `bad`. Pure; no I/O (sample acquisition is the caller's air-gapped ceremony, P6.11).

- [ ] **Step 6 — Verify:** the Standard Gate, both targets.

- [ ] **Step 7 — Docs/memory in-commit:** note R26 closed in `DESIGN.md` §16.1 (the sweep tooling now exists) and `parameters.md` §6 cross-ref. Commit.
  ```
  git commit -m "Phase 6 (P6.1): offline recovery-wrap validation sweep (R26/D27)"
  ```

---

## Task P6.2 — Merkle inclusion primitive + transparency-log `anchor_proof` form

**Exit-gate target:** supports *"tamper-evident external audit demonstrated"* — clients can accept a sink head anchored by a transparency-log inclusion proof, not only a custodian co-signature.

**Files:**
- Create: `crates/crypto/src/merkle.rs`; Modify: `crates/crypto/src/lib.rs`
- Modify: `crates/client-core/src/sink.rs`

- [ ] **Step 1 — Failing crypto test (`merkle.rs`):** `inclusion_verifies` and `tampered_leaf_or_path_rejected`.
  - RFC 6962 hashing: `leaf_hash(x) = SHA256(0x00 ‖ x)`, `node_hash(l,r) = SHA256(0x01 ‖ l ‖ r)`.
  - Build a tree of N leaves; for each leaf, `verify_inclusion(leaf_bytes, index, tree_size, &audit_path, root)` → `true`; flipping any audit-path byte, the index, or a leaf byte → `false`.

  Signature:
  ```rust
  pub fn verify_inclusion(leaf: &[u8], index: u64, tree_size: u64, path: &[[u8;32]], root: [u8;32]) -> bool;
  ```

- [ ] **Step 2 — Run, watch fail** (`verify_inclusion` undefined). `cargo test -p maxsecu-crypto merkle`.

- [ ] **Step 3 — Implement** the standard RFC 6962 inclusion-path recomputation (no `unsafe`; fixed domain prefixes; reject `index >= tree_size`).

- [ ] **Step 4 — Failing sink test (`sink.rs`):** `transparency_inclusion_anchor_proof_accepts`, `forged_checkpoint_rejected`, `transparency_proof_rejected_when_no_log_key_pinned`.
  - New variant on the `#[non_exhaustive]` enum:
    ```rust
    pub enum AnchorProof {
        CustodianCoSig { sig: [u8; 64] },
        TransparencyInclusion {
            checkpoint_sig: [u8; 64],   // log's Ed25519 sig over canonical(checkpoint{tree_size, root})
            tree_size: u64,
            root: [u8; 32],
            index: u64,
            path: Vec<[u8; 32]>,
        },
    }
    ```
  - The leaf is the **existing** `head_signing_bytes(head)` (so a head pins a specific transparency-log leaf).
  - Extend the verifier to take both trust anchors:
    ```rust
    pub fn verify_anchor_proof(
        head: &AnchoredHead, proof: &AnchorProof,
        custodian_pubs: &[[u8; 32]], transparency_log_pubs: &[[u8; 32]],
    ) -> Result<(), SinkError>;
    ```
    For `TransparencyInclusion`: a pinned log key must verify `checkpoint_sig` over `canonical(checkpoint)`, **and** `verify_inclusion(head_signing_bytes(head), index, tree_size, path, root)` must hold. Else `BadProof` (fail closed). Empty `transparency_log_pubs` ⇒ the form can never validate.
  - Update the 4 existing `verify_anchor_proof` call sites/tests to pass `&[]` for the new arg (custodian-only behavior preserved).

- [ ] **Step 5 — Implement** the new match arm + checkpoint encoding (a new `labels::SINK_CHECKPOINT` domain label in `encoding`, via `signing_input`, mirroring `SINK_HEAD`). No new `type_id` needed.

- [ ] **Step 6 — Verify:** Standard Gate. (Touches `crypto`, `client-core`, and `encoding` labels — full workspace.)

- [ ] **Step 7 — Docs in-commit:** mark the transparency-log form **shipped** in `docs/sink-interface.md` §4 (was "Phase-6 addition") and `client-core/src/sink.rs` module docs. Commit.
  ```
  git commit -m "Phase 6 (P6.2): Merkle inclusion + transparency-log sink anchor_proof form"
  ```

---

## Task P6.3 — Sink service core (append-only chain + digest anchoring)

**Exit-gate target:** *"external append-only audit sink with digest anchoring + tombstone-chain head publication (§16.5/§7.6)"* — the pure core. Deferred Phase-5 item #1 (the real sink).

**Files:**
- Create: `crates/sink-server/Cargo.toml`, `crates/sink-server/src/lib.rs`, `crates/sink-server/src/chain.rs`, `crates/sink-server/src/anchor.rs`
- Modify: workspace `Cargo.toml` (add member); `deny.toml` only if a transitive license needs allowing (it should not — deps are `encoding`/`crypto`/`tokio`/`hyper` already cleared).

- [ ] **Step 1 — Scaffold the crate** (`[lib]`, no `unsafe`, deps: `maxsecu-encoding`, `maxsecu-crypto`). Add to workspace members. Confirm `cargo build -p maxsecu-sink-server` + `cargo deny check` still green (no new external dep yet in this step).

- [ ] **Step 2 — Failing core test (`chain.rs`):** `append_extends_chain_and_head`, `rewrite_or_reorder_is_rejected`, `head_matches_recomputed_chain`.
  - `ControlLogStore::new()` starts at `chain_seq = 0`, `head = GENESIS_HEAD`.
  - `append(record_bytes)` requires the record's `prev_head` field == the store's current head; recomputes `head = SHA256(canonical(record))`; bumps `chain_seq`. Returns `AnchoredHead`.
  - A second `append` whose `prev_head` ≠ current head → `Err(AppendError::NotAppending)` (the §6.1 append-only / no-reorder / no-rewrite guarantee).
  - `records()` returns the appended bytes in order; `head()` equals the recomputed chain head.

  Signatures:
  ```rust
  pub enum AppendError { NotAppending, Malformed }
  pub struct ControlLogStore { /* records, head, chain_seq */ }
  impl ControlLogStore {
      pub fn new() -> Self;
      pub fn append(&mut self, record_bytes: Vec<u8>) -> Result<AnchoredHead, AppendError>;
      pub fn head(&self) -> AnchoredHead;            // {chain_seq, head}
      pub fn records(&self, since_seq: u64, limit: usize) -> Vec<(u64, Vec<u8>)>;
  }
  ```

- [ ] **Step 3 — Run, watch fail.** `cargo test -p maxsecu-sink-server chain`.

- [ ] **Step 4 — Implement `ControlLogStore`** reusing `maxsecu-encoding` to peek the record's `prev_head`/recompute the canonical head (the same chain math the client and `server::control` already use). Reject malformed bytes (`Malformed`).

- [ ] **Step 5 — Anchoring test (`anchor.rs`):** `anchor_emits_cosig_and_checkpoint`.
  - `Anchorer { custodian: SigningKey, log: SigningKey }`; `anchor(head) -> AnchorBundle { cosig_proof, transparency_proof }` where both verify under `client_core::sink::verify_anchor_proof` with the respective pinned keys. (Cross-crate test: `sink-server` dev-deps `client-core`.)
  - `anchor_log()` returns the history of `(AnchoredHead, AnchorBundle)` for the §3.3 reconciliation interface.

- [ ] **Step 6 — Implement `Anchorer`:** co-sign `head_signing_bytes` (custodian) and build a single-leaf-append transparency checkpoint + inclusion proof over the head leaf (log key). Keep the transparency tree minimal (append-only list of head leaves) — enough to emit a valid inclusion proof P6.2 accepts.

- [ ] **Step 7 — Verify:** Standard Gate (new crate compiles + tests on both targets; `cargo deny`/`audit` clean).

- [ ] **Step 8 — Commit** (with `DESIGN.md` §16.5 note that the sink core is now in-repo).
  ```
  git commit -m "Phase 6 (P6.3): in-repo append-only sink core + digest anchoring (co-sig + transparency)"
  ```

---

## Task P6.4 — Sink HTTP surface + real `HttpSinkClient`, e2e over TLS

**Exit-gate target:** *"tamper-evident external audit demonstrated"* — a client fetches and verifies a real anchored head over the sink's own pinned, independent channel; withholding is a Gap; a rewrite is rejected over the wire.

**Files:**
- Create: `crates/sink-server/src/http.rs` (axum), `crates/sink-server/src/serve.rs` (tokio-rustls accept loop, mirroring `crates/server/src/serve.rs`), `crates/sink-server/tests/sink_e2e.rs`
- Modify: `crates/sink-server/Cargo.toml` (axum, tokio, tokio-rustls, hyper-util — all already in the workspace tree)
- Modify: `crates/client-core/Cargo.toml` (`[features] net = ["dep:hyper", "dep:hyper-util", "dep:http-body-util", "dep:tokio", "dep:tokio-rustls"]`), `crates/client-core/src/sink.rs` (add `#[cfg(feature = "net")] pub struct HttpSinkClient`)

- [ ] **Step 1 — Dep vetting first.** Add the deps; run `cargo tree -i openssl`, `-i native-tls`, `-i ring` (expect empty), `cargo deny check`, `cargo audit`. If any fail, stop and reconsider the client (prefer the in-tree hyper+tokio-rustls path the app server already uses). Commit nothing yet.

- [ ] **Step 2 — Failing HTTP test (`http.rs` unit, oneshot):** `head_records_and_append_roundtrip`, `head_rewrite_returns_409`.
  - `GET /v1/control-log/head` → JSON `{chain_seq, head_b64, proof}` (proof carries both forms).
  - `GET /v1/control-log/records?since_seq=&limit=` → `[{chain_seq, record_b64}]`.
  - `POST /v1/control-log/records` (admin-cred header; §6.1 — append-only, **no** signature verification) appends; a body whose `prev_head` ≠ current head → `409`.
  - `GET /v1/control-log/anchor-log` → the §3.3 receipts.

- [ ] **Step 3 — Run, watch fail.** `cargo test -p maxsecu-sink-server http`.

- [ ] **Step 4 — Implement the axum router** over `ControlLogStore` + `Anchorer` in shared state; map `AppendError::NotAppending` → 409, `Malformed` → 400, missing admin cred → 403. Re-anchor (P6.3) on each successful append and serve the fresh proof from `/head`.

- [ ] **Step 5 — Implement `serve.rs`** (tokio-rustls accept → hyper-util `auto::Builder` + `TowerToHyperService`), copied from the app server's pattern.

- [ ] **Step 6 — Implement `HttpSinkClient`** (`client-core`, `cfg(feature="net")`): `fetch_head()` GETs `/head` over a pinned-TLS hyper client and returns `(AnchoredHead, AnchorProof)`; it does **not** trust the bytes until the caller runs `verify_anchor_proof`.

- [ ] **Step 7 — Failing e2e (`sink_e2e.rs`):** `client_fetches_verifies_and_detects_withholding_over_tls`.
  - Stand up `sink-server` on loopback TLS (rcgen self-signed, pinned by the client).
  - Append two real control records (built with `admin-core::ControlChain`); `HttpSinkClient::fetch_head()` → `AnchoredHead{chain_seq:2,..}`; `verify_anchor_proof` passes under both the pinned custodian key and the pinned transparency-log key.
  - Fetch records from `/records`, drop the tail, run `TombstoneSet::verify_authenticated(withheld, head.head, issuer)` → `Gap` (withholding caught against the sink's head).
  - `POST` a head-rewrite (a record with a stale `prev_head`) → `409`.

- [ ] **Step 8 — Implement** the glue to green the e2e.

- [ ] **Step 9 — Verify:** Standard Gate. Confirm `cargo build -p maxsecu-client-core` (default, **no** `net`) still pure and `cargo test --workspace` exercises the feature (enable `net` in dev-deps or via the e2e crate). Re-run dep vetting (Step 1 checks) once green.

- [ ] **Step 10 — Docs in-commit:** `docs/sink-interface.md` — mark §3/§4 client interface as implemented (real adapter + service in-repo; vendor WORM is the ops swap). Commit.
  ```
  git commit -m "Phase 6 (P6.4): sink HTTP surface + real HttpSinkClient, e2e over TLS"
  ```

---

## Task P6.5 — Wire server head/genesis publication to the real sink (issuer-side anchoring §6)

**Exit-gate target:** *"tombstone-chain head publication (§16.5/§7.6)"* — the app server publishes each control append to the sink, and the issuer confirms anchoring before treating a revocation as effective (closes write-time withholding, `sink-interface.md` §6).

**Files:**
- Modify: `crates/server/src/audit.rs` (add `HttpSinkPublisher`), `crates/server/src/serve.rs`/`http.rs` (inject it), `docs/api.md` §7.2 (already specifies publish-on-append — confirm wording).

- [ ] **Step 1 — Failing server test (`crates/server/tests/`):** `control_append_publishes_head_to_sink`.
  - Bring up an in-proc `sink-server` (loopback TLS) and the app server with `audit: Arc::new(HttpSinkPublisher::new(pinned_sink_client))`.
  - `POST /v1/revocations` with a real record → the sink's `/head` reflects the new `chain_seq`/`head`.

- [ ] **Step 2 — Run, watch fail** (`HttpSinkPublisher` undefined / head not published).

- [ ] **Step 3 — Implement `HttpSinkPublisher: AuditSink`:** `publish_head` POSTs the appended record to the sink's `/records` (best-effort, infallible from the caller — the local mirror must never block a sharing op, per the existing seam contract); `anchor_genesis` records the genesis position (POST a genesis-anchor event). Reuse the hyper+rustls client.

- [ ] **Step 4 — Failing test:** `issuer_confirms_anchoring_before_effective` — after `POST /v1/revocations`, the admin path verifies the sink head matches the just-appended head (the `sink-interface.md` §6 step-2 confirm); if the sink lags/refuses, the issuer flow surfaces a "not anchored" error (the revocation is not "done"). Implement the confirm helper (`client-core` or admin path) and green it.

- [ ] **Step 5 — Verify:** Standard Gate.

- [ ] **Step 6 — Commit** (api.md §7.2 confirmed in sync).
  ```
  git commit -m "Phase 6 (P6.5): server publishes control head/genesis to the real sink; issuer-side anchoring confirm"
  ```

---

## Task P6.6 — Monitoring / alerting anomaly-detection module

**Exit-gate target:** the §17 Phase-6 body item *"monitoring/alerting"* and the §16.5 anomaly list.

**Files:**
- Create: `crates/server/src/detect.rs`; Modify: `crates/server/src/lib.rs`
- Modify: `docs/parameters.md` (add §10 — alert thresholds)

- [ ] **Step 1 — Failing tests (`detect.rs`), one per anomaly class** from §16.5:
  - `auth_failure_spike_alerts` — a burst of auth-denial events over the window threshold → `Alert::AuthFailureSpike`.
  - `tombstone_gap_alerts` — a reported tombstone-set gap below the anchored head → `Alert::TombstoneGap`.
  - `reshare_fanout_alerts` — re-share fan-out above threshold → `Alert::HighReshareFanout`.
  - `grant_by_soon_revoked_alerts` — a grant by a user revoked shortly after → `Alert::GrantBySoonRevoked`.
  - `missing_recovery_grant_alerts` — a finalized version with no valid recovery grant → `Alert::MissingRecoveryGrant`.
  - `directory_change_outside_ceremony_alerts` — a binding change outside the published ceremony window → `Alert::DirectoryChangeOffCeremony`.
  - `quiet_stream_no_alerts` — a benign stream → `[]`.

  Signatures:
  ```rust
  pub enum Alert { AuthFailureSpike{..}, TombstoneGap{..}, HighReshareFanout{..},
                   GrantBySoonRevoked{..}, MissingRecoveryGrant{..}, DirectoryChangeOffCeremony{..} }
  pub struct Thresholds { /* from parameters.md §10, with documented defaults */ }
  pub fn analyze(events: &[AuditEvent], t: &Thresholds) -> Vec<Alert>;
  pub trait AlertSink { fn emit(&self, a: &Alert); }   // Null + Memory impls
  ```

- [ ] **Step 2 — Run, watch fail.** `cargo test -p maxsecu-server detect`.

- [ ] **Step 3 — Implement `analyze`** as pure window/threshold logic over a typed `AuditEvent` stream (reuse/extend the existing audit event shapes; `GrantEdge`/auth events). Add `AlertSink` (`Null`, `Memory`).

- [ ] **Step 4 — Verify:** Standard Gate.

- [ ] **Step 5 — Docs in-commit:** `parameters.md` §10 thresholds; note the dashboard/SIEM wiring is documented-not-coded in the runbook (P6.11). Commit.
  ```
  git commit -m "Phase 6 (P6.6): anomaly-detection analyzer + AlertSink seam (§16.5)"
  ```

---

## Task P6.7 — Sanitized-error pass

**Exit-gate target:** the §17 body item *"sanitized-error pass"* + §16.2 — never return DB errors, stack traces, paths, or username/file existence to clients.

**Files:**
- Modify: `crates/server/src/error.rs` / `http.rs` (centralize sanitization if not already single-path)
- Create: `crates/server/tests/sanitized_errors.rs`

- [ ] **Step 1 — Failing suite (`sanitized_errors.rs`):** `error_responses_never_leak_internals`.
  - Drive each error path over the HTTP stack: 500 (via `FaultyStore`), 400 (malformed body), 404 (absent file/user), 403 (non-admin/non-owner), 429 (rate-limited).
  - Assert each body is exactly the `api.md` §0 generic shape (`{ "error": "<code>" }`), and that the serialized response contains **none** of: a filesystem path, `sqlx`/SQL text, `StoreError`'s `detail`, `panic`/backtrace markers, or the literal username/file id probed.
  - `no_existence_oracle`: an unknown username and a known-but-unauthorized one yield indistinguishable shapes (already true for auth — assert it holds for the file/directory routes too).

- [ ] **Step 2 — Run, watch fail** wherever a path leaks (likely 1–3 spots).

- [ ] **Step 3 — Fix:** route every handler error through the single sanitizer; ensure `StoreError.detail` only ever reaches `log_internal`, never the body. Keep the 429+Retry-After shape (the one distinct signal).

- [ ] **Step 4 — Verify:** Standard Gate.

- [ ] **Step 5 — Commit** (`DESIGN.md` §16.2 cross-ref).
  ```
  git commit -m "Phase 6 (P6.7): sanitized-error pass — no internals/oracle in responses (§16.2)"
  ```

---

## Task P6.8 — Signed + transparency-logged update verification

**Exit-gate target:** the §17 body item *"signed + transparency-logged updates"* (client-side verification; the cert/CI/log infra is runbook, P6.10).

**Files:**
- Create: `crates/client-core/src/update.rs`; Modify: `crates/client-core/src/lib.rs`

- [ ] **Step 1 — Failing tests (`update.rs`):**
  - `valid_signed_logged_update_accepts` — an `UpdateManifest { version, artifact_sha256, min_version, sig }` signed by the **pinned release key** + a transparency inclusion proof of the manifest leaf → `Ok(Verified)`.
  - `downgrade_rejected` — `version <= current_version` → `Err(Downgrade)`.
  - `unsigned_or_forged_update_rejected` — bad/absent `sig` → `Err(BadSignature)`.
  - `update_without_transparency_inclusion_rejected` — valid sig but no/forged inclusion proof → `Err(NotLogged)`.
  - `artifact_hash_mismatch_rejected` — the downloaded artifact's SHA-256 ≠ `artifact_sha256` → `Err(ArtifactMismatch)`.

  Signature:
  ```rust
  pub enum UpdateError { Downgrade, BadSignature, NotLogged, ArtifactMismatch }
  pub fn verify_update(
      manifest: &UpdateManifest, manifest_sig: [u8;64],
      release_pubs: &[[u8;32]], log_pubs: &[[u8;32]],
      current_version: u64, artifact_sha256: [u8;32],
  ) -> Result<Verified, UpdateError>;
  ```

- [ ] **Step 2 — Run, watch fail.** `cargo test -p maxsecu-client-core update`.

- [ ] **Step 3 — Implement** `verify_update`: domain-separated Ed25519 verify of `canonical(manifest)` under a pinned release key; reuse `crypto::merkle::verify_inclusion` (P6.2) for the transparency leaf; downgrade + artifact-hash checks. Pure; download/apply + Authenticode is the OS/runbook layer.

- [ ] **Step 4 — Verify:** Standard Gate.

- [ ] **Step 5 — Commit** (`DESIGN.md` §8 / stack §1.5 cross-ref).
  ```
  git commit -m "Phase 6 (P6.8): client-side signed + transparency-logged update verification"
  ```

---

## Task P6.9 — Reproducible-build recipe + double-build hash-diff script

**Exit-gate target:** *"reproducible-build verification documented"* (§17 Phase 6 exit).

**Files:**
- Create: `scripts/reproducible-build.sh` (WSL/Linux, the deterministic target), `scripts/reproducible-build.ps1` (Windows, with caveats), `docs/reproducible-builds.md`
- Create/confirm: `rust-toolchain.toml` (pin `rustc`)

- [ ] **Step 1 — Write `reproducible-build.sh`:** build the server binary twice for `x86_64-unknown-linux-musl` with `--locked`, `SOURCE_DATE_EPOCH` fixed, `RUSTFLAGS` for path remapping (`--remap-path-prefix`), reproducible `CARGO_INCREMENTAL=0`; `sha256sum` both artifacts; exit non-zero on mismatch.

- [ ] **Step 2 — Run it on WSL:** `wsl -d Ubuntu-22.04 -- bash -lc 'cd ~/maxsecu && ./scripts/reproducible-build.sh'` → both hashes equal, exit 0. (If musl target is missing: `rustup target add x86_64-unknown-linux-musl` documented as a prereq.)

- [ ] **Step 3 — Write `docs/reproducible-builds.md`:** the exact recipe (toolchain pin, flags, target, env), how a third party reproduces the published hash, and the **honest scope** — the Linux musl server binary is the reproducible artifact of record (D-E); Windows MSVC PE determinism is best-effort with documented caveats (PE timestamp, `/Brepro`).

- [ ] **Step 4 — Write `reproducible-build.ps1`** (Windows double-build + hash diff, surfacing the caveats; not a hard gate).

- [ ] **Step 5 — Verify:** the Standard Gate still passes (no code changed); the repro script exits 0 on WSL. Commit.
  ```
  git commit -m "Phase 6 (P6.9): reproducible-build recipe + double-build hash-diff verification"
  ```

---

## Task P6.10 — Code-signing script + signed-update publication runbook

**Exit-gate target:** the §17 body items *"code signing"* and the publication half of *"signed + transparency-logged updates"* (ops side; verification was P6.8).

**Files:**
- Create: `scripts/sign-release.ps1` (Authenticode `signtool` wrapper — cert referenced by thumbprint/secret-manager, **never embedded**), `docs/runbooks/release-signing.md`

- [ ] **Step 1 — Write `sign-release.ps1`:** wrap `signtool sign` with timestamping; refuse to run if the cert is passed inline (enforce by-reference); verify the signature afterward (`signtool verify /pa`).

- [ ] **Step 2 — Write `docs/runbooks/release-signing.md`:** the full release flow — reproducible build (P6.9) → Authenticode sign (offline release key) → build the signed `UpdateManifest` → submit the manifest leaf to the transparency log → clients verify via P6.8. Explicit "no secrets/cert in repo or CI logs" (§16.6).

- [ ] **Step 3 — Verify:** Standard Gate (docs/scripts only — no code paths). Commit.
  ```
  git commit -m "Phase 6 (P6.10): Authenticode signing script + signed-update publication runbook"
  ```

---

## Task P6.11 — Ceremony runbooks

**Exit-gate target:** the §17 body item *"ceremony runbooks"* (§16.1 ceremonies + §16.4 rotation procedures).

**Files (all `docs/runbooks/`):** `enrollment-signing.md`, `tombstone-issuance.md`, `recovery-session.md`, `recovery-wrap-sweep.md`, `emergency-d5-rotation.md`, `recovery-key-rotation.md`.

- [ ] **Step 1 — Write each runbook** with: trigger/preconditions, air-gap handling, exact tooling (the `recovery-wrap-sweep.md` drives the P6.1 `run_sweep`; `tombstone-issuance.md` includes the P6.5 sink-anchoring **confirm** step), audit/anchor verification, and parameters cross-refs (`parameters.md` §6 sweep cadence, §7 ceremony cadence). `emergency-d5-rotation.md` mirrors `DESIGN.md` §16.4 step-by-step.

- [ ] **Step 2 — Verify:** Standard Gate (docs only). Commit.
  ```
  git commit -m "Phase 6 (P6.11): ceremony + rotation runbooks (§16.1/§16.4)"
  ```

---

## Task P6.12 — Phase-6 capstone e2e over real TLS

**Exit-gate target:** *"tamper-evident external audit demonstrated"* end-to-end, plus the R26 sweep proven against a planted bad wrap, over the real stack.

**Files:**
- Create: `crates/server/tests/phase6_integrity_ops_e2e.rs` (reuses the existing TLS harness from `sharing_e2e.rs`/`file_e2e.rs`)

- [ ] **Step 1 — Failing e2e:** `phase6_integrity_ops_exit_gates_over_real_tls`.
  - Stand up the **app server** and the **independent `sink-server`**, each on its own loopback TLS identity (two pinned channels).
  - Admin issues a revocation → app server publishes the head to the sink (P6.5) → a client fetches the head from the **sink's** channel + records from the **app server**, verifies contiguity → pass.
  - App server **withholds** the tail record → client detects `Gap` against the sink head (fail closed).
  - A head-**rewrite** attempt against the sink → `409` (append-only).
  - Plant a **bad recovery wrap** on a file-version; `run_sweep` (P6.1) flags exactly that version.
  - Hit an error path and assert the response is sanitized (P6.7) over the wire.

- [ ] **Step 2 — Run, watch fail; then wire** the pieces to green (glue only — all behavior exists from P6.1–P6.7).

- [ ] **Step 3 — Verify:** Standard Gate. Note any expected `cfg(windows)` exclusions stay green on WSL.

- [ ] **Step 4 — Commit.**
  ```
  git commit -m "Phase 6 (P6.12): tamper-evident external audit + R26 sweep e2e over real TLS"
  ```

---

## Task P6.13 — Security-review sign-off + DESIGN/docs/memory sync (PHASE 6 COMPLETE)

**Exit-gate target:** *"security review sign-off"* (§17 Phase 6 exit) + leave the repo coherent.

**Files:** `docs/security-review-phase6.md`; `DESIGN.md` §17 Phase 6; `docs/sink-interface.md`; `docs/audit-prompt.md`; memory `phase-0-status.md` + `MEMORY.md`.

- [ ] **Step 1 — Run the security-review skill** over the Phase-6 diff (current branch). Record findings + dispositions in `docs/security-review-phase6.md`; fix anything actionable as its own TDD commit (loop P6.x style) before declaring complete.

- [ ] **Step 2 — `DESIGN.md` §17 Phase 6:** add a *"Build status — COMPLETE (all exit gates met)"* block summarizing what shipped (real sink core+HTTP+adapter, transparency-log anchor_proof, recovery-wrap sweep, anomaly detection, sanitized errors, update verification, repro/signing/ceremony runbooks) and **deferrals**: real third-party WORM/SIEM vendor + live transparency-log/CI runner + real Authenticode cert (all behind the shipped adapters/scripts); Phase-7 directory key-transparency log; ffmpeg-video; real Dropbox; P3.10 zstd.

- [ ] **Step 3 — Sync docs:** `sink-interface.md` status → "real in-repo adapter + service shipped; vendor swap-in is ops"; `audit-prompt.md` phase list (per the `audit-prompt-upkeep` memory).

- [ ] **Step 4 — Sync memory:** update `phase-0-status.md` with the Phase-6 increments + the new `sink-server` crate (7 crates) and "Next is Phase 7"; update `MEMORY.md` build-status line.

- [ ] **Step 5 — Final verify:** the Standard Gate on both targets, plus the repro script on WSL. Commit.
  ```
  git commit -m "Phase 6 (P6.13): security-review sign-off; DESIGN/docs/memory sync — PHASE 6 COMPLETE"
  ```

---

## Self-review (spec coverage vs. §17 Phase 6)

| §17 Phase 6 requirement | Task |
|---|---|
| Reproducible builds | P6.9 |
| Code signing | P6.10 |
| Signed + transparency-logged updates | P6.8 (verify) + P6.10 (publish) |
| External append-only audit sink + digest anchoring + tombstone-chain head publication | P6.3 (core) + P6.4 (HTTP/adapter) + P6.5 (server publish) |
| Monitoring/alerting | P6.6 |
| Offline recovery-wrap validation sweep (R26/D27) | P6.1 |
| Sanitized-error pass | P6.7 |
| Ceremony runbooks | P6.11 |
| Transparency-log `anchor_proof` form (deferred from P5) | P6.2 |
| **Exit:** reproducible-build verification documented | P6.9 |
| **Exit:** tamper-evident external audit demonstrated | P6.4 + P6.12 |
| **Exit:** bad recovery wrap caught by the sweep (R26) | P6.1 + P6.12 |
| **Exit:** security review sign-off | P6.13 |

Both Phase-5-deferred items are covered: recovery-wrap sweep (P6.1) and the real external sink + transparency-log proof form (P6.2–P6.5).

## Open items intentionally left to ops / Phase 7 (not built here)

- A genuinely third-party WORM/SIEM and a live public transparency log / notary (the in-repo `sink-server` + scripts are the swap-in point).
- A real CI runner and a real Authenticode certificate (scripts + runbooks are ready).
- The Phase-7 **directory** key-transparency log (distinct from this phase's sink-head transparency form).
