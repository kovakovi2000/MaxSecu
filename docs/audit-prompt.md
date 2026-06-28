# MaxSecu — full audit of all phase-active code, then fix the gaps

> **Maintenance note:** This file is a paste-ready prompt for a fresh (post-`/clear`)
> session. It enumerates the per-phase exit gates that are claimed COMPLETE. **When a
> new phase or increment is committed, update the "What counts as phase-active code"
> section and the Phase-2 exit-gate checklist below** so the audit stays exhaustive.
> See memory `audit-prompt-upkeep`.

You are resuming MaxSecu (zero-knowledge file storage; Rust; Windows MSVC dev + WSL `Ubuntu-22.04` prod). Before doing anything, read `DESIGN.md` (esp. §17 roadmap + the exit gates per phase), `docs/api.md`, `docs/stack.md`, and the memory files under `C:\Users\gecim\.claude\projects\D--scrs-programs-MaxSecu\memory\` (start with `MEMORY.md` → `phase-0-status.md`). Do NOT trust my summary below over what the code/docs actually say — if they disagree, the code wins and you flag it.

## Standing constraints (do not violate)
- `main` is ahead of origin and UNPUSHED. Keep it that way — **NEVER push**.
- **No-C posture:** no new dependency may pull C/C++/asm or a second TLS stack. The deliberate carve-out is `aws-lc-rs` as the rustls provider (TLS = transport, not the ZK boundary); `ring`/`openssl` stay banned in `deny.toml`. `audit` ignores RUSTSEC-2023-0071 (`rsa`, unreachable in the build graph) — confirm it's still unreachable.
- Dropbox creds are test-only; never commit secrets.
- **Dual-target discipline.** Every claim of "works" must be backed by green on BOTH:
  - Windows: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo deny check`, `cargo audit`.
  - WSL prod (reaches live Postgres + exercises FS-blob/Linux paths): `rsync -a --delete --exclude target --exclude .git /mnt/d/scrs/programs/MaxSecu/ ~/maxsecu/ && cd ~/maxsecu && export PATH="$HOME/.cargo/bin:$PATH" && cargo test`.
  - PowerShell wraps native stderr as `NativeCommandError` — don't `2>&1` on cargo; filter stdout.
  - The `cfg(windows)` AppContainer/Job-Object module in `crates/media-worker` only exists on Windows — confirm its containment tests run on Windows and are correctly cfg-excluded (still green) on WSL.

## What counts as "phase-active code"
Phases **0, 1, 2, 3, 4, 4b, 5, 6, and 7 are claimed COMPLETE** on local `main` (latest on `main`). The workspace is **7 crates**: `encoding`, `crypto`, `client-core`, `admin-core`, `server`, `media-worker`, `sink-server`. Your job is to verify that claim end-to-end, not to take it on faith.

**Phase 7 — Long-term hardening (PQ-hybrid wrap, threshold recovery, directory key-transparency).** Exit gates to verify (sign-off `docs/security-review-phase7.md`): (a) the **PQ-hybrid DEK wrap** — `crypto::hybrid` X25519+ML-KEM-768 X-Wing-style combiner (both KEM ciphertexts bound into a single-use KEK; zero-nonce safe), `Suite::V2` + optional binding `mlkem_pub` (`encoding`), ML-KEM identity keygen + keyblob **v2** (v1 blobs still load), uploads emit V2 iff self+recovery are PQ-enrolled with mixed-fleet V1 fallback, and download/reshare/rotate accept both suites and **fail closed** (`PqKeyMissing`/`ResharePqKeyMissing`) on a missing PQ key — no silent downgrade; (b) **K-of-N threshold recovery** — `crypto::shamir` GF(256) primitive + `admin-core::recovery::{split_recovery_key, reconstruct_recovery_key}` (below-threshold fails closed, reconstructed key opens a real wrap); (c) the **directory key-transparency log** — RFC-6962 consistency proofs (`crypto::merkle`), client inclusion+consistency verification with **split-view detection** + a first-contact gate (`client-core::transparency`, `DirectoryVerifier::verify_binding_with_kt`), an in-repo producer (`sink-server::dirlog`, distinct `MaxSecu-kt-checkpoint-v1` label + separate log key), and enrollment publishing bindings to the log; plus (d) real `genesis` anchoring over the HTTP sink (`sink-server` `PositionLog` + admin-gated `POST/GET /v1/genesis-anchor`; `server::audit::HttpSinkPublisher::anchor_genesis`). Capstone e2e over real TLS: `server/tests/phase7_hardening_e2e.rs`. Confirm **no new C / second TLS stack** (`ml-kem`/`x25519-dalek` pure-Rust; only the sanctioned `aws-lc-rs`) and **no `unsafe`** added.

## Task

### Phase 1 — Mechanical green (both targets)
Run the full build/test/lint/supply-chain gate on both targets. Capture the actual test counts per crate. Record exit codes (must be 0). Any failure, warning, non-pristine output, skipped/ignored test, or flaky test → log it; don't paper over it.

### Phase 2 — Existence + behavior audit (the real work)
For EACH phase, walk DESIGN §17's exit gates and confirm there is (a) code that implements it and (b) a test that actually proves it. Build a coverage matrix with one row per exit gate / security property:

| Phase | Exit gate / property | Implementing code (`file:sym`) | Proving test (`file::test`) | Ran? | Status |

Cover at minimum these load-bearing properties (find the real test names; don't invent them):
- **P0:** canonical-encoding reject vectors (V-1..V-13) + re-encode guard; AEAD chunked/framed round-trip; Ed25519 `verify_strict`; HPKE wrap; Argon2id/HKDF/SHA-256.
- **P1:** login over real TLS+Postgres; replay/relay reject (channel binding via RFC-5705 exporter); no username/existence oracle; rate-limit → 429+Retry-After; store-fault → 500 (no new oracle); server holds no private material.
- **P2:** forged binding → BadSignature; unsigned account → absent/404; `*`-revoked user → Revoked; withheld tombstone (chain short of anchored head) → Gap/fail-closed. (The P2-deferred per-tombstone admin-sig/dual-control verification is now DONE in P5 — see P5 below.)
- **P3:** spliced/truncated chunk → digest/framing error; forged manifest → signature error; poisoned near-max version → first-contact ceiling; `../../etc/passwd` metadata filename refused; **no plaintext on disk** (FsBlobStore scan); owner-only write (D29); streaming path never materializes whole plaintext. (zstd encoder DEFERRED — confirm `compression='none'` is wired and zstd is rejected, not silently accepted.)
- **P4:** multi-hop grant-chain ancestor verification (directory-resolved granters, depth cap 32, cycle guard); carry-forward rotation under DEK'; soft-revoke (owner-or-granter) → 404; forged ancestor reject; audit-sink edges emitted (Author/Reshare/SoftRevoke).
- **P4b:** LRU cache eviction respects recency; cache-miss progress (§9.3); direct-link brokering never exposes master token (§9.4); real pure-Rust image transcode + decompression-bomb guard; sandbox output validation; **AppContainer/Job-Object worker differential containment** — confined worker DENIED network + key-blob read + child-spawn while unconfined is ALLOWED; media e2e over TLS (renders, no plaintext on either tier, tampered cold blob rejected).
- **P5:** authenticated control-log (`TombstoneSet::verify_authenticated`) — forged issuer sig → BadAuthority, non-admin → NotAdmin, `*`-revoke/reinstatement without distinct co-sign → DualControlMissing, **de-admin earlier in the chain strips a later record's authority** (prefix-state); external-sink seam — forged/wrong-key/tampered `anchor_proof` → BadProof, withholding vs the anchored head → Gap; download gates — **tombstoned author → AuthorRevoked**, revoked recipient → RecipientRevoked; **R27** genesis after a key-compromise (by sink position, not created_at) → GenesisAfterCompromise, pre-compromise genesis still opens; **recovery-operator grant** honored on download but dropped at carry-forward (R24); **R25** subtree walk from the sink edge-log still tombstones a server-withheld descendant; server `publish_head`/`anchor_genesis` wired; e2e `sharing_e2e.rs::phase5_revocation_exit_gates_over_real_tls`.

- **P6:** **offline recovery-wrap sweep** (`admin-core::sweep::run_sweep`/`recovery::validate_recovery_wrap`) — bad-DEK wrap → `WrapMismatch`, corrupt → `WrapUndecryptable` (R26/D27); **transparency-log `anchor_proof`** (`client-core::sink::AnchorProof::TransparencyInclusion` + RFC-6962 `crypto::merkle::verify_inclusion`) — forged checkpoint/path or empty `log_pubs` → `BadProof`; **real in-repo sink** (`sink-server`: `ControlLogStore` append-only → 409 on rewrite, `Anchorer` both proof forms) + **real `HttpSinkClient`** over TLS + server **`HttpSinkPublisher`** + **`confirm_anchored`** (issuer §6, `NotAnchored`/`BadProof` fail-closed); **`server::detect`** §16.5 anomalies; **sanitized errors** (`tests/sanitized_errors.rs` — empty bodies, no existence oracle); **`client-core::update::verify_update`** (downgrade/`BadSignature`/`NotLogged`/`ArtifactMismatch`, fail-closed); reproducible-build (`scripts/reproducible-build.sh` → byte-identical `media-worker`); e2e `server/tests/phase6_integrity_ops_e2e.rs` (publish→fetch+verify→withholding `Gap`→rewrite 409→R26 catch→sanitized error, two independent TLS endpoints).

For the **deferred** items (ffmpeg/dav1d video transcoder, real Dropbox `ColdTier`, zstd encoder; and the Phase-6 ops deferrals: a real third-party **WORM/SIEM + sink-head cross-publication**, a **live transparency log/notary** (proof shapes + client verify done; production keys pinned when stood up), **genesis anchoring over the real HTTP sink** (`HttpSinkPublisher::anchor_genesis` is a no-op; R27 cutoff proven with `MemoryAuditSink`), a real **CI runner + Authenticode cert**, the **Phase-7 directory key-transparency log**): confirm each is gated honestly (trait returns `CodecUnavailable`/`Unsupported`, seam + fake/no-op with the real adapter deferred, or documented as deferred) and is NOT a silent gap masquerading as done.

Also flag: any `todo!()`/`unimplemented!()`/`unreachable!()` on a reachable path, any test that passes without asserting the security property (false-passing — we hit two of these in P4b.6b: inverted pipe directions + missing pipe DACL made containment tests false-pass), any `#[ignore]`, and any exit gate with code but no test (or a test but no code).

### Phase 3 — Report
Produce two lists:
1. **CONFIRMED** — gate → test that proves it → observed PASS on both targets.
2. **MISSING / BROKEN / WEAK** — the gap, why it matters, and whether it's a real hole vs. an honestly-deferred item.

Show me both lists. **Stop here and wait for my go-ahead before fixing anything** unless a gap is a clear regression in already-committed work (a broken build, a failing test, a false-passing security test) — those you may fix immediately under TDD.

### Phase 4 — Fix (TDD)
For each real gap I approve: write the failing test FIRST, watch it fail for the right reason, implement minimally to green, re-verify BOTH targets + clippy -D / deny / audit (all exit 0), then commit to local `main` per-fix with the standard trailers (`Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` + `Claude-Session: …`). Keep DESIGN.md/docs/memory in sync. Never push.

Begin with Phase 1 (mechanical green on both targets) and report the raw numbers before moving on.
