# Phase 5 — Recovery, Grant-Old-File, Revocation — Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Every increment ends green on **both** targets (Windows MSVC + WSL `Ubuntu-22.04`) with `clippy -D` / `deny` / `audit` clean, then **auto-commits to local `main`** (never push).

**Goal:** Make strong-revoke, reinstatement, recovery, and the key-compromise cutoff cryptographically authoritative against a malicious server — authenticating *who* issued every control-log record and *what the sink says is current*, so a revoked user cannot be re-admitted at rotation, a tombstoned author cannot mint a version, a withheld tombstone/grant-edge fails closed, and a backdated genesis under a compromised key is rejected.

**Architecture:** Continue the established pattern — pure, transport-agnostic security cores (`client-core`, `admin-core`) with thin server adapters, e2e over real TLS last. The external append-only **sink** and its **grant-edge log** are modeled as **abstract seams + real verification logic + in-memory/fake transports** (decided: same posture as the Dropbox `ColdTier` / `AuditSink` / anchored-head seams; real WORM/transparency deployment is a Phase-6 ops item). The two carried-over audit action items are done first.

**Tech stack:** Rust 1.96 MSVC (Windows) + WSL Ubuntu-22.04 (PG14). No new external deps anticipated (all logic is over existing `encoding`/`crypto` primitives). No-C posture and `aws-lc-rs`-only TLS carve-out unchanged.

**Decided design forks (this run):**
- **Sink posture:** abstract `SinkClient` trait + real `AnchoredHead`/`anchor_proof` verification (Ed25519 separate-custodian co-signature form) + fake transport; the R25 subtree walk sources from an abstract **grant-edge log** with a fake. Real external deployment deferred to Phase 6.
- **R27 cutoff:** **sink-anchored genesis position** — a genesis under a compromised `(owner_id, key_version)` is honored only if its sink-anchoring position predates the `key_compromise` (ignores the attacker-chosen `created_at`, per D28).
- **pg_store tests:** **fail-hard** when Postgres is unreachable, unless `MAXSECU_PG_OPTIONAL=1` is set.

**Key design refinement introduced here (flag at review):** control-log records are authenticated **sequentially against the chain-prefix state**. Each record at chain position `i` is authorized by the issuer's effective admin role computed from records `[0, i)` only (binding ceiling minus role-narrowing tombstones that precede `i`, honoring `key_compromise` cutoffs by sink position). This breaks the apparent circularity (a tombstone that de-admins an admin who later issues another tombstone) deterministically and matches `sink-interface.md` §5 step 4 ("honor a `key_compromise` cutoff by the record's **sink position**, not its `effective_from`").

---

## File map

**Modify**
- `crates/server/tests/pg_store.rs` — fail-hard PG guard (P5.0b).
- `crates/client-core/src/revocation.rs` — authenticated tombstone set (P5.1), sequential prefix-state authority (P5.1), key_compromise lookup helper (P5.4).
- `crates/client-core/src/download.rs` — tombstone-completeness + author-revocation gate (P5.3), recovery-clause grant edge (P5.5), genesis cutoff wiring (P5.4).
- `crates/client-core/src/error.rs` — new `DownloadError` / `TombstoneError` / `SinkError` variants.
- `crates/client-core/src/lib.rs` — re-exports for the new `sink` module + new public types.
- `crates/client-core/src/rotate.rs` — confirm carry-forward rejects recovery-clause edges (P5.5).
- `crates/admin-core/src/lib.rs` — re-exports for `recovery` + `subtree` modules.
- `crates/server/src/audit.rs` / `crates/server/src/lib.rs` — `SinkPublisher` seam (head + genesis-anchor + grant-edge emission) (P5.8).
- `DESIGN.md` §17 (Phase 5 build-status block), `docs/api.md` (§7 notes if any), memory (`phase-0-status.md`, `audit-prompt-upkeep.md`) — per increment.

**Create**
- `crates/client-core/src/sink.rs` — `AnchoredHead`, `AnchorProof`, `verify_anchor_proof`, `SinkClient` trait + `FakeSink` (P5.2).
- `crates/admin-core/src/recovery.rs` — `build_recovery_grant` (§12.7) (P5.5).
- `crates/admin-core/src/subtree.rs` — sink-sourced subtree-revocation walk (§14.5/§12.9b, R25) (P5.6).
- `crates/server/tests/revocation_e2e.rs` — full Phase-5 lifecycle over real TLS (P5.9).

---

## P5.0 — Carried-over audit action items (do first)

### Task 0a: Install supply-chain tooling in WSL and run the gate there

**Files:** none (environment + memory).

- [ ] **Step 1:** In `wsl -d Ubuntu-22.04`, with `PATH="$HOME/.cargo/bin:$PATH"`, run `cargo install --locked cargo-deny cargo-audit` (or confirm present).
- [ ] **Step 2:** From `~/maxsecu` (after the rsync), run `cargo deny check` and `cargo audit`. Expected: both exit 0, the `rsa` RUSTSEC-2023-0071 ignore honored (same as Windows).
- [ ] **Step 3:** Update memory `dev-environment.md` — note cargo-deny/cargo-audit now installed in the WSL `Ubuntu-22.04` distro; the supply-chain gate is literally green on both targets.
- [ ] **Step 4:** No commit needed unless `deny.toml`/`audit.toml` changed; if they did, commit with the standard trailers.

### Task 0b: Harden pg_store tests to fail-hard (unless opted out)

**Files:** Modify `crates/server/tests/pg_store.rs`.

- [ ] **Step 1: Write the failing test guard.** Replace the silent skip-on-unreachable with: attempt the PG connection; on failure, if `std::env::var("MAXSECU_PG_OPTIONAL").as_deref() != Ok("1")`, `panic!` with a clear message (so the suite **fails**, not passes vacuously); only skip (return) when the opt-out is set. Add one test `pg_reachable_or_opt_out` asserting the connection succeeds under the default env.
- [ ] **Step 2: Verify it fails for the right reason.** Temporarily point the DSN at a dead port and run `cargo test -p maxsecu-server --test pg_store` — expect a panic/FAIL, not a pass. Restore the DSN.
- [ ] **Step 3: Verify green.** With WSL PG reachable (localhost forwarding from Windows; native on WSL), run the suite on both targets → PASS. With `MAXSECU_PG_OPTIONAL=1` and PG down → tests skip cleanly.
- [ ] **Step 4: Dual-target verify** (`cargo test --workspace` + clippy -D + deny + audit on Windows; rsync + `cargo test` on WSL).
- [ ] **Step 5: Commit** `Phase 5 (P5.0b): pg_store tests fail-hard unless MAXSECU_PG_OPTIONAL=1`.

---

## P5.1 — Authenticated control-log records (client) — the deferred §11.5/§12.9b gate

**Exit-gate target:** "a tombstoned author cannot mint an accepted version", "reinstatement … only under dual control", "de-admin takes effect once its tombstone is anchored" — all rest on the client actually **verifying each record's issuer signature, issuer admin role, and dual-control co-signature** (today `TombstoneSet::verify` checks only chain contiguity). This is the explicit P2.2/P2.3 deferral.

**Files:** Modify `crates/client-core/src/revocation.rs`, `crates/client-core/src/error.rs`.

**New surface:**
```rust
/// What the caller resolves out of band for a control-log record's issuer: the
/// admin's directory-verified Ed25519 sig_pub for the key_version that signed it
/// (historical binding, §11.7), and the binding's role ceiling.
pub struct IssuerInfo { pub sig_pub: [u8; 32], pub roles: Vec<Role>, pub key_version: u64 }

/// One served control-log record: its canonical bytes, issuer signature, and the
/// optional second-admin co-signature (api.md §7.1 record/sig/co_sig).
pub struct ControlRecordIn { pub bytes: Vec<u8>, pub sig: [u8; 64], pub co_sig: Option<[u8; 64]> }

impl TombstoneSet {
    /// Verify contiguity to `anchored_head` AND authenticate every record against
    /// its issuer's directory binding (resolved by `issuer` from (issued_by,
    /// key_version)): issuer sig valid, issuer holds the `admin` effective role
    /// **as of the chain prefix before this record**, dual control present where
    /// required (`*`/mass revoke, every reinstatement, every key_compromise),
    /// co-signer ≠ issuer and itself a prefix-admin. Fail closed on any failure.
    pub fn verify_authenticated(
        records: &[ControlRecordIn],
        anchored_head: [u8; 32],
        issuer: &dyn Fn(Id /*issued_by*/, u64 /*key_version… see note*/) -> Option<IssuerInfo>,
    ) -> Result<TombstoneSet, TombstoneError>;
}
```
> **Note on issuer key_version:** the record structs (`Revocation`/`Reinstatement`/`KeyCompromise`) carry `issued_by` but **not** the issuer's `key_version`. Resolve the issuer binding by `issued_by` at its **current** key_version for admin authority (role is a present-state property, not a durable-record property) — the resolver takes `issued_by` only; the `key_version` parameter above is dropped in the final signature. (Confirm against `sink-interface.md` §5 step 4 during implementation; durable-record historical-binding selection applies to genesis/grants in P5.4, not to control records, which are evaluated at issuance time.)

- [ ] **Step 1: Write the failing test** `forged_issuer_signature_is_rejected` in `revocation.rs` tests: build a contiguous chain with `ControlChain`, but corrupt `r1.sig[0] ^= 1`; resolve the issuer to its real admin binding; assert `verify_authenticated(...).unwrap_err() == TombstoneError::BadAuthority` (new variant).
- [ ] **Step 2: Run, watch RED** for the right reason (`BadAuthority` variant or method does not exist yet) — `cargo test -p maxsecu-client-core revocation::tests::forged_issuer_signature_is_rejected`.
- [ ] **Step 3: Implement.** Add `TombstoneError::BadAuthority`, `TombstoneError::DualControlMissing`, `TombstoneError::NotAdmin`, `TombstoneError::UnknownIssuer`. Implement `verify_authenticated`: fold over records in chain order, maintaining `(running_head, prefix_state)`; for each record decode (reuse `Decoded::from_bytes`), check `prev_head == running_head`, resolve `IssuerInfo` (else `UnknownIssuer`), verify the issuer sig under the record's domain label (reuse `SignedControlRecord`-style verify; or verify directly via `VerifyingKey::verify_canonical` on the decoded struct), compute the issuer's **effective admin role from `prefix_state`** (ceiling minus prefix role-narrowing tombstones for the issuer) → else `NotAdmin`, enforce dual control (where required: `co_signed_by.is_some()` AND `co_sig` present AND co-signer is a distinct prefix-admin) → else `DualControlMissing`, then fold this record into `prefix_state`. End: require `running_head == anchored_head` (`Gap`).
- [ ] **Step 4: Run, watch GREEN.**
- [ ] **Step 5: Add the authority red-team tests** (each RED→GREEN, separate or batched per the executing-plans cadence):
  - `account_wide_revoke_without_cosig_is_rejected` → `DualControlMissing`.
  - `cosigner_equals_issuer_is_rejected` (dual control must be *distinct* admins).
  - `non_admin_issuer_is_rejected` → `NotAdmin` (issuer binding lacks `admin` ceiling).
  - `de_admin_tombstone_then_issuer_loses_authority`: admin A de-admins admin B (role-narrowing `*` tombstone), then a later record *issued by B* is rejected `NotAdmin` (prefix-state authority — the headline "de-admin takes effect once anchored" gate).
  - `reinstatement_requires_dual_control` (already structurally enforced by `ControlChain::reinstate`, but the *verifier* must independently reject a hand-forged single-signed reinstatement).
  - Keep the existing contiguity tests passing (the old `verify` stays for callers that only need chain shape; `verify_authenticated` is the authoritative path).
- [ ] **Step 6: Dual-target verify + commit** `Phase 5 (P5.1): authenticated control-log verification — issuer sig + prefix-state admin role + dual control`.

---

## P5.2 — External-sink seam: AnchoredHead + anchor_proof (client)

**Exit-gate target:** "nor withhold a fresh tombstone beyond one sink-head refresh" — clients must obtain a **trusted** head from a channel independent of the app server and validate its `anchor_proof` (`sink-interface.md` §3–§5). Today the anchored head is a bare injected value.

**Files:** Create `crates/client-core/src/sink.rs`; modify `crates/client-core/src/lib.rs`, `crates/client-core/src/error.rs`.

**New surface:**
```rust
pub struct AnchoredHead { pub chain_seq: u64, pub head: [u8; 32] }  // anchored_at is advisory; omitted (never a freshness basis)

/// The accepted anchor-proof forms (client allowlist, sink-interface §4). v1
/// ships the separate-custodian Ed25519 co-signature form; other forms are
/// `#[non_exhaustive]`-style future additions.
pub enum AnchorProof { CustodianCoSig { sig: [u8; 64] } }

/// Verify a head's anchor proof against the **pinned custodian key allowlist**
/// (a separate trust domain from D5/D6 and the app server). Fail closed if no
/// allowlisted proof validates.
pub fn verify_anchor_proof(
    head: &AnchoredHead, proof: &AnchorProof, custodian_pubs: &[[u8; 32]],
) -> Result<(), SinkError>;

/// The client's pinned-channel read interface to the sink (sink-interface §3).
pub trait SinkClient {
    fn fetch_head(&self) -> Result<(AnchoredHead, AnchorProof), SinkError>;
    // fetch_records optional/recommended; v1 verifies app-server records up to the head.
}
pub struct FakeSink { /* holds a custodian SigningKey + current (chain_seq, head) */ }
```
The custodian co-signature is over `canonical(chain_seq ‖ head)` (define a tiny domain label e.g. `"MaxSecu-sink-head-v1"`; add to the domain-separation set in DESIGN §5 / encoding labels). `chain_seq` binds the chain length so a short (withheld) chain is a `Gap` at the `TombstoneSet` layer; `head` binds content.

- [ ] **Step 1: Write the failing test** `forged_anchor_proof_is_rejected`: a `FakeSink` mints a head co-signed by custodian K; corrupt the sig; assert `verify_anchor_proof` → `Err(SinkError::BadProof)`. Add `valid_anchor_proof_accepts` and `wrong_custodian_key_rejected`.
- [ ] **Step 2: RED** (`sink` module / `SinkError` absent).
- [ ] **Step 3: Implement** the module + `SinkError { BadProof, Unreachable, ... }`, the domain label, and `FakeSink`. The custodian key is a pinned `[u8;32]` allowlist (mirrors the D5 pin).
- [ ] **Step 4: GREEN.**
- [ ] **Step 5:** Add `head_and_records_compose`: `FakeSink::fetch_head()` → feed `head.head` into `TombstoneSet::verify_authenticated` over the server-served records → Ok; drop the last record from the served set → `TombstoneError::Gap` (the withholding gate, end-to-end across the two seams).
- [ ] **Step 6: Dual-target verify + commit** `Phase 5 (P5.2): external-sink seam — AnchoredHead + custodian anchor_proof + FakeSink`.

---

## P5.3 — Download: tombstone-completeness + author-revocation gate (client)

**Exit-gate target:** "a tombstoned author cannot mint an accepted version; revoked users lose future versions" — the download ladder must consult an authenticated tombstone set proven contiguous to the sink head and **reject a version whose author is account-revoked**.

**Files:** Modify `crates/client-core/src/download.rs`, `crates/client-core/src/error.rs`.

**Surface change:** add to `VerifyContext` an optional borrowed `tombstones: Option<&'a TombstoneSet>` (None only at first contact where no completeness is required for *reads* of already-verified content; for any served version the caller passes the verified set). `verify_header` after step (3) author-entitlement adds:
```rust
// (3b) Author must not be account-revoked (a tombstoned author cannot mint, §12.9/§12.5).
if let Some(ts) = ctx.tombstones {
    if ts.is_account_revoked(&manifest.author_id.0) { return Err(AuthorRevoked); }
    // (4b) The downloader itself must not be revoked from this file at this version.
    if ts.is_revoked(&ctx.recipient_id.0, &ctx.file_id.0, manifest.version) { return Err(RecipientRevoked); }
}
```

- [ ] **Step 1: Write the failing test** `tombstoned_author_version_is_rejected`: build a normal upload (author = owner O); build an authenticated `TombstoneSet` containing a `*` revocation of O; pass it in `VerifyContext.tombstones`; assert `verify_and_open` → `Err(DownloadError::AuthorRevoked)`.
- [ ] **Step 2: RED** (`AuthorRevoked` / `tombstones` field absent).
- [ ] **Step 3: Implement** the field, the two new `DownloadError` variants (`AuthorRevoked`, `RecipientRevoked`), and the gate. Thread the field through `verify_and_open` and `verify_and_stream_content`; update every existing `VerifyContext { … }` literal in tests to add `tombstones: None` (no behavior change where None).
- [ ] **Step 4: GREEN.**
- [ ] **Step 5:** Add `revoked_recipient_is_rejected` (per-file revocation of the downloader at `from_version ≤ version`) and `unrevoked_author_with_clean_set_opens` (a set with unrelated tombstones still opens).
- [ ] **Step 6: Dual-target verify + commit** `Phase 5 (P5.3): download gates on authenticated tombstone set — author-revocation + recipient-revocation`.

---

## P5.4 — R27 key-compromise cutoff on genesis, by sink position (client + sink)

**Exit-gate target:** "a backdated durable record (genesis) forged under a compromised, rotated-away key is rejected by the sink-anchored cutoff (R27)."

**Approach (decided fork = sink-anchored position):** the sink records a **genesis-anchoring position** per `file_id` (a monotonically increasing `genesis_seq` / sink position, modeled in the `SinkClient`/`FakeSink` seam). A `KeyCompromise` record sits at a chain position too. The client, when verifying `genesis_sig` under `(owner_id, owner_key_version)`, looks up any `KeyCompromise` for that pair in the tombstone set; if present, it honors the genesis **only if the genesis's sink position precedes the compromise's sink position** — independent of the attacker-chosen `genesis.created_at`.

**Files:** Modify `crates/client-core/src/download.rs`, `crates/client-core/src/revocation.rs` (a `key_compromise_for(user_id, key_version)` lookup on `TombstoneSet`), `crates/client-core/src/sink.rs` (carry a genesis-position lookup), `crates/client-core/src/error.rs`.

**Surface:**
```rust
impl TombstoneSet {
    /// The active key_compromise cutoff for (user_id, key_version), if any.
    pub fn key_compromise_for(&self, user_id: &[u8;16], key_version: u64) -> Option<&KeyCompromise>;
}
// VerifyContext gains:
//   genesis_sink_pos: Option<u64>,                    // the genesis's anchored position
//   compromise_sink_pos: &dyn Fn(&KeyCompromise) -> u64, // the compromise record's chain position
```
> The compromise's sink position = its index in the (already verified-contiguous) tombstone set, which the client knows during `verify_authenticated`; expose it as part of the decoded record metadata so the resolver is trivial. The genesis position comes from the sink seam (P5.2 extended). Where the client cannot obtain the genesis position (legacy/first-contact), fail **closed** for a compromised key_version (reject), open otherwise.

- [ ] **Step 1: Write the failing test** `backdated_genesis_under_compromised_key_is_rejected`: owner O signs genesis under key_version 1, `created_at` backdated to before the compromise; a `KeyCompromise{owner=O, key_version=1}` is anchored at sink position P; the genesis's sink position is `> P` (it was actually anchored after the compromise); assert `verify_and_open` → `Err(DownloadError::GenesisAfterCompromise)`.
- [ ] **Step 2: RED.**
- [ ] **Step 3: Implement** `key_compromise_for`, expose compromise positions, add `GenesisAfterCompromise` variant + the gate in `verify_header` step (2). A genesis whose sink position **precedes** the compromise (a legitimately old file) still opens — add that as the paired GREEN assertion in the same test or a sibling `pre_compromise_genesis_still_opens`.
- [ ] **Step 4: GREEN.**
- [ ] **Step 5: Dual-target verify + commit** `Phase 5 (P5.4): R27 — genesis key-compromise cutoff by sink position`.

---

## P5.5 — Recovery-operator grant (admin-core) + download honoring + carry-forward exclusion

**Exit-gate target:** §12.7 offline recovery-key grant works; "a recovery-clause (admin-signed) grant is honored only for its own version and is *not* carried forward (R24)."

**Files:** Create `crates/admin-core/src/recovery.rs`; modify `crates/admin-core/src/lib.rs`, `crates/client-core/src/download.rs` (grant-chain recovery-clause edge), `crates/client-core/src/rotate.rs` (confirm exclusion).

**admin-core surface:**
```rust
/// Build a recovery-operator read grant + wrap (§12.7 steps 4–5): the admin has
/// unwrapped the DEK on the air-gapped device (checked vs dek_commit) and
/// re-wraps it to the new recipient's directory-verified enc_pub, signing the
/// grant with the admin's own sig key. granted_by = the admin's user_id.
pub fn build_recovery_grant(
    admin_sig: &SigningKey, admin_id: Id,
    file_id: Id, version: u64, dek: &Dek, dek_commit: Hash,
    recipient_id: Id, recipient_enc_pub: &EncPublicKey, created_at: Timestamp,
) -> Result<RecoveryGrantOut, RecoveryError>; // { wrapped_dek, grant, grant_sig }
```

**client download:** `verify_grant_chain` gains a mode flag (`accept_recovery_clause: bool`, true for download, false for carry-forward). When the leaf granter is **not** the author and **not** resolvable as a re-sharer-with-a-wrap, but **is** a directory-verified admin (resolved via a new `admin_sig_pub: &dyn Fn(Id) -> Option<[u8;32]>` resolver on `VerifyContext`), accept it as a **recovery-clause terminal** (honored for this version only). The recovery-clause leaf still binds file/version/dek_commit/recipient.

- [ ] **Step 1 (admin-core): Write the failing test** `recovery_grant_round_trips`: admin unwraps a DEK, `build_recovery_grant` to a new recipient; the produced wrap re-opens to the committed DEK and the grant verifies under the admin's sig key. RED → implement → GREEN.
- [ ] **Step 2 (client download): Write the failing test** `recovery_clause_grant_opens_for_its_version`: a leaf grant with `granted_by = ADMIN_ID`, recipient holds the admin-made wrap; resolver maps `ADMIN_ID` to the admin's directory-verified admin key; assert `verify_and_open` succeeds. RED (`admin_sig_pub` / recovery-clause path absent) → implement → GREEN.
- [ ] **Step 3 (carry-forward exclusion): Write the failing test** in `rotate.rs`: a prior-version recipient holds **only** a recovery-clause grant (granted_by = admin); after `build_next_version`, that recipient is **dropped** from the carry-forward set (recovery-clause is not possession-entailing, R24). RED if `verify_grant_chain` in carry-forward mode currently accepts admin edges → set `accept_recovery_clause=false` for carry-forward → GREEN. (If already excluded by construction, assert it explicitly so a regression is caught.)
- [ ] **Step 4:** Add `recovery_clause_rejected_when_granter_not_admin` (a non-admin `granted_by` with no wrap → `GrantChainBroken`).
- [ ] **Step 5: Dual-target verify + commit** `Phase 5 (P5.5): recovery-operator grant (§12.7) + download honoring + carry-forward exclusion (R24)`.

---

## P5.6 — Subtree-revocation tooling from the sink grant-edge log (admin-core, R25)

**Exit-gate target:** "a colluding server cannot shield a delegated subtree by withholding grant edges — the subtree walk sources from the external sink (R25)."

**Files:** Create `crates/admin-core/src/subtree.rs`; modify `crates/admin-core/src/lib.rs`.

**Surface:**
```rust
/// A grant edge as recorded in the external audit sink (§16.5): who granted read
/// to whom, for which file. The sink is append-only and independent of the app
/// server, so a server cannot hide an edge from this source (R25/D26).
pub struct GrantEdge { pub file_id: Id, pub granted_by: Id, pub recipient: Id }

/// Compute the revocation subtree for target `r` on `file_id`: every recipient
/// reachable from `r` via `granted_by` edges that has **no independent grant
/// from a still-authorized path** (i.e. not re-rooted by someone outside the
/// subtree). Pure graph walk over the sink's edge log; cycle- and depth-guarded.
pub fn revocation_subtree(edges: &[GrantEdge], file_id: Id, r: Id, owner: Id) -> Vec<Id>;
```
The ceremony then feeds the returned ids (plus `r`) to `ControlChain::revoke` as one dual-controlled batch (§12.9b step 4). The **R25 proof**: the walk runs over the *sink* edge set; a server that withholds a descendant edge from its *served* rows still cannot remove it from the sink set, so the descendant is still tombstoned.

- [ ] **Step 1: Write the failing test** `withheld_server_edge_still_tombstoned_via_sink`: edges A→V, V→W in the **sink** set; build a "server-served" set that omits V→W (the withholding); assert `revocation_subtree(sink_edges, file, A, owner)` contains both V and W, while a walk over the server-served set would miss W (assert the difference to make the R25 point non-vacuous).
- [ ] **Step 2: RED** (module absent).
- [ ] **Step 3: Implement** the BFS/DFS with `visited` cycle-guard and a depth cap (reuse `MAX_GRANT_CHAIN_DEPTH` semantics or a local cap), excluding any node with an independent in-edge from outside the subtree.
- [ ] **Step 4: GREEN.**
- [ ] **Step 5:** Add `independent_path_survivor_not_revoked` (W also granted by an outside still-authorized U → W excluded from the subtree) and `cycle_in_edges_terminates`.
- [ ] **Step 6: Dual-target verify + commit** `Phase 5 (P5.6): sink-sourced subtree-revocation walk (§14.5/R25)`.

---

## P5.7 — Device-loss re-enrollment vs. reinstatement (client invariant)

**Exit-gate target:** "reinstatement restores access only under dual control and clears only the specific revocation it names (R28)"; "Re-enrollment after device loss does not by itself clear a tombstone."

**Files:** Modify `crates/client-core/src/revocation.rs` tests (logic largely lands in P5.1's authenticated set + the existing supersession code).

- [ ] **Step 1: Write the failing/explicit test** `reenrolled_revoked_user_stays_revoked_until_reinstatement`: a `*` revocation of user U at key_version 1; U "re-enrolls" (a new directory binding at key_version 2 — modeled by resolving U's issuer/recipient under the new key); assert `is_account_revoked(U)` is still true over the authenticated set (the tombstone keys on stable `user_id`, not key_version); then add a dual-controlled `reinstatement` superseding that epoch → `is_account_revoked(U)` false. Confirm a *later* re-revoke (new epoch) is not cleared (already covered by `reinstatement_clears_only_the_revocation_it_names`, assert again over the authenticated path).
- [ ] **Step 2: RED/observe** — if the existing supersession logic already satisfies this over `verify_authenticated`, the test passes immediately; in that case the increment is a **proof** (non-vacuous regression guard) rather than new code. Note it explicitly per verification-before-completion.
- [ ] **Step 3:** If a gap surfaces (e.g. reinstatement authority not enforced), implement the minimal fix.
- [ ] **Step 4: Dual-target verify + commit** `Phase 5 (P5.7): re-enrollment does not clear a tombstone; reinstatement under dual control (R28)`.

---

## P5.8 — Server seams: sink publish (head + genesis-anchor) + grant-edge emission

**Exit-gate target:** "audit complete in the external sink"; the server "publishes the new head to the external sink" (api §7.2) and records genesis anchoring + grant edges so the sink is the authoritative source for P5.2/P5.4/P5.6 (modeled as a seam; real sink = Phase 6).

**Files:** Modify `crates/server/src/audit.rs` (or a new `crates/server/src/sink.rs`), `crates/server/src/lib.rs`, the control/file/wrap handlers.

**Surface:**
```rust
/// The server's publish-side view of the external sink (§6 of sink-interface):
/// append-only, the server is *expected* to publish but cannot forge/reorder.
pub trait SinkPublisher: Send + Sync {
    fn publish_head(&self, chain_seq: u64, head: [u8; 32]);     // after append_control
    fn anchor_genesis(&self, file_id: [u8; 16]);                // at file create (genesis position)
    fn record_grant_edge(&self, edge: GrantEdge);               // at stage/add_wrap (mirrors AuditSink)
}
pub struct MemorySink { /* shared with FakeSink shape for the e2e */ }
pub struct NullSink;
```
Wire `AppState` to hold `Arc<dyn SinkPublisher>` (default `NullSink`); call `publish_head` from the `post_control` handler, `anchor_genesis` from file create finalize, `record_grant_edge` alongside the existing `AuditSink` emissions (P4.5). Coarse/forgeable by design — the **authority** is client-side verification of the anchored head + custodian proof.

- [ ] **Step 1: Write the failing test** (server lib unit) `control_append_publishes_head`: a `MemorySink` records the head/seq after `append_control`; assert it matches `control_head`. Add `file_create_anchors_genesis` and `reshare_records_grant_edge`.
- [ ] **Step 2: RED** (`SinkPublisher` absent).
- [ ] **Step 3: Implement** the trait + impls + AppState field + handler calls (additive; existing handlers unchanged otherwise).
- [ ] **Step 4: GREEN.**
- [ ] **Step 5: Dual-target verify + commit** `Phase 5 (P5.8): server SinkPublisher seam — head publish + genesis anchor + grant-edge log`.

---

## P5.9 — End-to-end Phase-5 lifecycle over real TLS

**Exit-gate target:** the full §17 Phase-5 gate set, proven against the real stack (loopback TLS, real `PgStore`/`MemoryStore`, `FakeSink` as the sink, `MemorySink` server-side), with red-team assertions.

**Files:** Create `crates/server/tests/revocation_e2e.rs` (add `admin-core`/`client-core` server dev-deps already present).

The test drives the real flow with channel-bound parties O (owner/admin A1), A2 (second admin), V (recipient), W (V's re-share):
- [ ] **Step 1:** Upload v1 by O; V granted; V re-shares to W (server records edges to `MemorySink`).
- [ ] **Step 2 (strong-revoke + rotation):** admins A1+A2 issue a `*` revocation of V (dual control); the new head is published to the sink; the `FakeSink` co-signs it. O fetches the head, builds an **authenticated** `TombstoneSet` contiguous to it, and rotates (`build_next_version`) — V is **dropped** from carry-forward, the recovery recipient re-added. Assert V cannot open v2 (no wrap / `RecipientRevoked`).
- [ ] **Step 3 (withholding red-team):** the server serves a tombstone set **missing** the V revocation while the sink head is post-revocation → `TombstoneSet::verify_authenticated` → `TombstoneError::Gap` (fail closed; O refuses to rotate on the incomplete set).
- [ ] **Step 4 (rollback red-team):** server replays a lower-epoch / shorter chain → `Gap`/`BrokenChain`.
- [ ] **Step 5 (tombstoned author):** account-revoke O, then have the server serve a version authored by O → every downloader → `DownloadError::AuthorRevoked`.
- [ ] **Step 6 (reinstatement):** A1+A2 reinstate V (dual control, superseding the exact epoch) → V opens the next version again; assert a single-signed forged reinstatement is rejected (`DualControlMissing`).
- [ ] **Step 7 (R25 subtree):** with edges A→V→W in the sink, server withholds V→W from its served rows; `revocation_subtree` over the **sink** edges still includes W → both tombstoned; W loses v_next.
- [ ] **Step 8 (R27 genesis):** a genesis forged under O's compromised+rotated key_version, anchored after the `key_compromise` → `GenesisAfterCompromise`.
- [ ] **Step 9: Dual-target verify** (full workspace, both targets, clippy -D / deny / audit exit 0) **+ commit** `Phase 5 (P5.9): revocation/recovery e2e over real TLS — PHASE 5 COMPLETE`.
- [ ] **Step 10: Docs/memory sync (in the same commit):** update `DESIGN.md` §17 Phase 5 with a build-status block (what's real vs. seam-deferred: real sink deployment + transparency-log anchor_proof form → Phase 6; recovery-wrap validation sweep → Phase 6 per §16.1); refresh `phase-0-status.md` and `audit-prompt-upkeep.md`.

---

## Deferrals carried into Phase 6 (record honestly in DESIGN §17)

- Real external **sink deployment** (WORM/independent SIEM) + the **transparency-log `anchor_proof`** form (only the Ed25519 custodian-co-signature form ships in v1; the allowlist is built to admit the stronger form later).
- **Recovery-wrap validation sweep** (§16.1/D27, R26) — the offline session that unwraps each `recovery` wrap and checks it against `dek_commit`. Phase-6 ops tooling.
- Real Dropbox `ColdTier`, ffmpeg video transcoder, zstd encoder — unchanged prior deferrals.

---

## Self-review notes

- **Spec coverage:** every §17 Phase-5 exit-gate clause maps to an increment — re-admit/inject at rotation → P5.1+P5.3+P5.9 step 2; withholding/rollback → P5.2+P5.9 steps 3–4; tombstoned author → P5.3+P5.9 step 5; revoked-future-versions → P5.3/P5.5; reinstatement dual-control + R28 → P5.1/P5.7/P5.9 step 6; R25 subtree → P5.6+P5.9 step 7; R27 cutoff → P5.4+P5.9 step 8; de-admin → P5.1; audit-in-sink → P5.8. Action items → P5.0.
- **Type consistency:** `TombstoneSet::verify_authenticated`, `ControlRecordIn`, `IssuerInfo`, `AnchoredHead`, `AnchorProof`, `SinkClient`/`FakeSink`/`SinkPublisher`/`MemorySink`, `GrantEdge`, `revocation_subtree`, `build_recovery_grant` are referenced consistently across tasks.
- **Open implementation question to resolve at P5.1 (flagged):** the exact issuer key_version selection for control-record authority (current-state vs. historical binding). Resolution leans current-state (admin role is present-state); confirm against `sink-interface.md` §5 step 4 when writing the resolver.
