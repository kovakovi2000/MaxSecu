# Phase 6 — Security Review & Sign-off (Client Integrity & Ops, C2)

**Scope:** the Phase-6 increments P6.1–P6.12 on local `main` (commits `011ff51`…`f6ec427`, base `585d63b`). 42 files, ~5.9k insertions. Reviewer: controller (plan author), reviewing each increment's diff at implementation time plus this cumulative pass.
**Verdict:** **PASS** — all `DESIGN.md` §17 Phase-6 exit gates met; no critical or high findings. Residuals are the intentional, documented ops deferrals (real vendor infra) listed in §4.

---

## 1. What was reviewed (by area)

| Area | Increment(s) | Security-relevant code |
|---|---|---|
| Offline recovery-wrap sweep (R26/D27) | P6.1 | `admin-core::recovery::validate_recovery_wrap`, `admin-core::sweep::run_sweep` |
| Merkle inclusion + transparency anchor-proof | P6.2 | `crypto::merkle::verify_inclusion`, `client-core::sink::AnchorProof::TransparencyInclusion`, `verify_anchor_proof` |
| In-repo append-only sink + anchoring | P6.3, P6.4 | `sink-server::chain::ControlLogStore`, `sink-server::anchor::Anchorer`, sink HTTP/serve, `client-core::sink::HttpSinkClient` |
| Server head publication + issuer confirm | P6.5 | `server::audit::{AuditSink, HttpSinkPublisher}`, `client-core::sink::confirm_anchored` |
| Monitoring/alerting | P6.6 | `server::detect::{analyze, AlertSink}` |
| Sanitized errors | P6.7 | `server::http` error mapping; `tests/sanitized_errors.rs` |
| Signed + transparency-logged updates | P6.8 | `client-core::update::verify_update` |
| Reproducible build / signing | P6.9, P6.10 | `scripts/reproducible-build.*`, `scripts/sign-release.ps1` |
| Capstone e2e | P6.12 | `server/tests/phase6_integrity_ops_e2e.rs` |

## 2. Findings

No critical/high/medium findings. Observations (all already handled, or intentional design):

1. **Anchor-proof verification is fail-closed (✓).** `verify_anchor_proof` accepts a head only if a **pinned** custodian key co-signs it *or* a **pinned** transparency-log key signs a checkpoint whose Merkle proof includes the head's signing bytes. An empty allowlist can never validate (asserted). Tampering the head, the checkpoint sig, an audit-path entry, or the index all reject. The RFC 6962 inclusion verifier matches the spec algorithm (index/`sn` folding, rejects `index ≥ tree_size` and over-long paths) and is tested against an independent from-scratch MTH+path.
2. **Withholding → Gap, clock-independent (✓).** Clients require the app-server-served control set to be contiguous up to the **sink-anchored** head and fail closed (`TombstoneError::Gap`) on any short/forked chain (proven over real TLS across two independent endpoints, P6.12). The sink head pins `(chain_seq, head)`; the bound is a monotonic counter, not a clock.
3. **Issuer-side anchoring is the authoritative write-time gate (✓, process dependency).** `HttpSinkPublisher` publication is best-effort/infallible (a publish failure must not deny the admin's append); the fail-closed control is `confirm_anchored`, which the issuing admin MUST run — it verifies the sink reflects the new head before the revocation is "effective" (returns `NotAnchored`/`BadProof` otherwise). This matches `sink-interface.md` §6. *Process dependency:* an admin who skips the confirm doesn't catch withholding at write time, but every downstream client still fails closed on the Gap within one sink-head refresh — documented in `docs/runbooks/tombstone-issuance.md` (step 3 mandatory).
4. **Append-only enforced server-side (✓).** The sink rejects a non-appending write (`prev_head ≠ head`) with 409. The deeper guarantee against a *compromised sink operator* is the two-leg integrity of `sink-interface.md` §1 (independent custody + cross-published head); the in-repo sink is the reference implementation and the real WORM/cross-publication vendor is the §4 deferral.
5. **Recovery-wrap sweep is sound (✓).** `validate_recovery_wrap` HPKE-opens under the exact `RECOVERY_ID`-bound wrap context the upload path used and compares the re-derived `dek_commit`; a wrong-DEK wrap → `WrapMismatch`, a corrupt/foreign wrap → `WrapUndecryptable`. The non-constant-time compare is on the **public** commitment (in the signed manifest), so no secret-dependent side channel. Offline/air-gapped only.
6. **Update verification is fail-closed at each step (✓).** Downgrade (and `min_version` exclusion) → `Downgrade`; artifact-hash mismatch → `ArtifactMismatch`; release-key sig under a distinct domain label `MaxSecu-update-v1` → `BadSignature`; transparency inclusion (pinned log key checkpoint + Merkle proof of the manifest leaf) → `NotLogged`. Empty allowlists never validate.
7. **Domain separation across two transparency logs (✓, note).** The sink-head log and the update log reuse the same checkpoint byte construction (`sink_checkpoint_signing_input`, a `{tree_size, root}` structure) but are distinguished by **independently pinned** log keys (`log_pubs` are separate sets). This is sound because the keys are the trust boundary; recorded here so the two logs are never given a shared key.
8. **Sanitized errors, no oracle (✓).** Audit found all error paths already route internal `detail`/`context` only to `log_internal`; bodies are empty (strictly more sanitized than a JSON envelope) except the sanctioned 429+`Retry-After` and the constant `direct_disabled`. Unknown vs. known-unauthorized resources are byte-identical (no existence oracle). The proof suite has verified teeth. `docs/api.md` §3 updated to match the empty-body contract.
9. **No-C posture / supply chain held (✓).** New deps (`axum`/`tokio-rustls`/`hyper`/`hyper-util` for `sink-server`; the `client-core` `net` feature) pull **no** second TLS stack — `cargo tree -i {openssl,ring,native-tls}` empty; only the sanctioned `aws-lc-rs`. `client-core`'s default build stays pure (the HTTP adapter is behind `net`). `cargo deny`/`audit` green on both targets; RUSTSEC-2023-0071 (`rsa`) remains unreachable.
10. **Reproducible build verified (✓).** The Linux artifact-of-record (`media-worker`) reproduces byte-identical across two isolated builds (`9ff38fe6…`). Windows PE is best-effort (`/Brepro`), documented.

## 3. Threat-model coverage (Phase-6-relevant rows)

- **Malicious software update (D1 residual):** addressed by reproducible builds (P6.9) + Authenticode signing (P6.10) + client-side signed/transparency-logged update verification (P6.8). Real cert/CI/log are §4 deferrals; the verification logic is complete and fail-closed.
- **Active malicious server — tombstone withholding (R16/D22):** prevented within one sink-head refresh by the real independent sink + anchored-head Gap check (P6.2–P6.5, P6.12), now exercised over a real wire across two endpoints.
- **Audit integrity (R2/D18):** the external append-only sink is now a real in-repo component with digest anchoring (P6.3) and head publication (P6.5); the real WORM/SIEM vendor swap-in sits behind the adapter.
- **Bad recovery wrap (R26/D27):** caught by the offline sweep (P6.1, P6.12).

## 4. Residuals / deferrals (intentional)

- A genuinely third-party **WORM/SIEM** and **cross-publication** of the sink head (the in-repo `sink-server` + scripts are the swap-in point; two-leg integrity per `sink-interface.md` §1 completes when the vendor leg is real).
- A live **public transparency log / notary** for both the sink head and the update manifest (proof shapes implemented + client verification complete; production `log_pub`s pinned when the log is stood up).
- **Genesis anchoring over the real HTTP sink** (R27 cutoff by sink position) — `HttpSinkPublisher::anchor_genesis` is a documented no-op; the R27 cutoff remains proven with `MemoryAuditSink` (Phase 5) and is not re-exercised over the HTTP sink this phase. Closing write-time withholding of **control records** did not require it.
- A real **CI runner** and a real **Authenticode certificate** (scripts + runbooks ready).
- The **Phase-7 directory key-transparency log** (distinct from this phase's sink-head/update transparency forms) — closes first-contact directory equivocation (§7.4).

## 5. Sign-off

Phase 6 meets its `DESIGN.md` §17 exit gates: reproducible-build verification is documented **and** demonstrated (byte-identical); tamper-evident external audit is demonstrated end-to-end over real TLS (publish → fetch → verify → Gap on withholding → 409 on rewrite); a recovery wrap that does not decrypt to the committed DEK is caught by the sweep; and this security review records no open critical/high/medium issues. **Approved to mark Phase 6 COMPLETE.**
