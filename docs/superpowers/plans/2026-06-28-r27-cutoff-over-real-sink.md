# R27 Cutoff Over the Real Sink — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the one half-done Phase-7 add-on — make the client-side R27/D28 key-compromise cutoff comparison source BOTH positions (the durable genesis's anchor position AND the `key_compromise` control record's position) from the **real external sink over TLS**, not from `MemoryAuditSink`.

**Architecture:** The sink already records control-append positions and genesis-anchor positions in one global counter (`sink-server::position::PositionLog`) and already serves genesis positions over HTTP. It does **not** yet serve a control record's unified global position. This plan (1) adds that read route to `sink-server`, (2) adds the matching reads to the production `client-core::HttpSinkClient`, and (3) proves the full R27 cutoff end-to-end over real TLS sourcing both positions from the real sink.

**Tech Stack:** Rust, axum + tokio-rustls (sink-server HTTP), hyper/hyper-util (HttpSinkClient, `net` feature), `client-core::download::CompromiseCheck`.

**Increment labels:** P7.16 (sink route), P7.17 (client reads), P7.18 (e2e + docs/memory sync). Continues the existing P7.x numbering — this closes the residual recorded at P7.8/P7.15.

**Dual-target verification each increment (both must be exit 0):**
- Windows: `$env:PATH="$env:USERPROFILE\.cargo\bin;$env:PATH"; $env:MAXSECU_PG_OPTIONAL=1; cargo test --workspace; cargo clippy --workspace --all-targets -- -D warnings; cargo deny check; cargo audit`
- WSL: `wsl -d Ubuntu-22.04 -- bash -lc 'rsync -a --delete --exclude target --exclude target-repro-a --exclude target-repro-b --exclude .git /mnt/d/scrs/programs/MaxSecu/ ~/maxsecu/ && cd ~/maxsecu && export PATH="$HOME/.cargo/bin:$PATH" && cargo test && cargo clippy --workspace --all-targets -- -D warnings && cargo deny check && cargo audit'`

No new dependencies. No-C posture unaffected.

---

## File Structure

- `crates/sink-server/src/http.rs` — add `GET /v1/control-log/position?chain_seq=<n>` route + handler (reuses `PositionLog::control_pos`, `GenesisPositionJson`).
- `crates/sink-server/src/position.rs` — doc-comment update only (the "not yet routed over HTTP" note is now stale).
- `crates/client-core/src/sink.rs` — add `HttpSinkClient::fetch_control_pos` + `fetch_genesis_pos` (net feature); refactor the internal GET to expose the status code so genesis 404 is `Ok(None)`.
- `crates/sink-server/tests/sink_e2e.rs` — integration test for the two new `HttpSinkClient` reads over TLS.
- `crates/server/tests/phase7_hardening_e2e.rs` — new `r27_cutoff_over_real_sink` test driving `verify_and_open` with both positions sourced from the real sink.
- `docs/sink-interface.md`, `DESIGN.md` (§15.2/§17 residual), `memory/phase-0-status.md`, `memory/MEMORY.md` — mark the residual closed.

---

### Task P7.16: Sink control-record position read route

**Files:**
- Modify: `crates/sink-server/src/http.rs` (router + new handler + test)
- Modify: `crates/sink-server/src/position.rs` (doc comment)

- [ ] **Step 1: Write the failing test** — add to the `tests` mod in `crates/sink-server/src/http.rs`:

```rust
#[tokio::test]
async fn control_position_route_serves_global_order() {
    let app = app();
    let (r1, r2) = two_records();

    // No control appends yet, and chain_seq is 1-based → 404 for 0 and 1.
    let (st, _) = send(&app, get("/v1/control-log/position?chain_seq=0")).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = send(&app, get("/v1/control-log/position?chain_seq=1")).await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    // Anchor a genesis (global position g), then append r1 (next position).
    let f = [0xF1u8; 16];
    let (st, gbody) = send(&app, post_genesis_req(Some(TOKEN), &B64.encode(f))).await;
    assert_eq!(st, StatusCode::OK);
    let g = gbody["position"].as_u64().unwrap();
    let (st, _) = send(&app, post_record_req(Some(TOKEN), &B64.encode(&r1.bytes))).await;
    assert_eq!(st, StatusCode::OK);

    // chain_seq 1's global position is one past the genesis anchor — the two event
    // kinds share one ordered space (the R27 cutoff basis).
    let (st, body) = send(&app, get("/v1/control-log/position?chain_seq=1")).await;
    assert_eq!(st, StatusCode::OK);
    let c1 = body["position"].as_u64().unwrap();
    assert_eq!(c1, g + 1);

    // Append r2 → chain_seq 2 at the next position.
    let (st, _) = send(&app, post_record_req(Some(TOKEN), &B64.encode(&r2.bytes))).await;
    assert_eq!(st, StatusCode::OK);
    let (st, body) = send(&app, get("/v1/control-log/position?chain_seq=2")).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["position"].as_u64().unwrap(), c1 + 1);

    // Past the end → 404.
    let (st, _) = send(&app, get("/v1/control-log/position?chain_seq=3")).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}
```

- [ ] **Step 2: Run test to verify it fails** — `cargo test -p maxsecu-sink-server control_position_route_serves_global_order`. Expected: FAIL (route 404s on the success cases / handler missing). Confirm the failure is the missing route, not a harness error.

- [ ] **Step 3: Add the route + handler** in `crates/sink-server/src/http.rs`. Add to `router()`, after the `anchor-log` route:

```rust
        .route("/v1/control-log/position", get(get_control_position))
```

Add the handler near `get_genesis_anchor` (reuse `GenesisPositionJson` — it is just `{position}`):

```rust
// ---- GET /v1/control-log/position?chain_seq= (R27/D28 cutoff basis, §3) ----

#[derive(Deserialize)]
struct ControlPositionQuery {
    chain_seq: u64,
}

/// Serve the global sink position of the `chain_seq`-th control append (1-based),
/// or `404` if no such control record has been appended. This is the cutoff side
/// of the R27/D28 comparison: a client maps a `key_compromise` record's chain
/// position to its global sink position here, then compares it against a genesis's
/// anchored position (`get_genesis_anchor`). Public read — the position is no
/// secret.
async fn get_control_position(
    State(st): State<SinkState>,
    Query(q): Query<ControlPositionQuery>,
) -> Response {
    let inner = st.inner.lock().await;
    match inner.positions.control_pos(q.chain_seq) {
        Some(position) => Json(GenesisPositionJson { position }).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
```

- [ ] **Step 4: Run test to verify it passes** — `cargo test -p maxsecu-sink-server control_position_route_serves_global_order`. Expected: PASS.

- [ ] **Step 5: Refresh the stale doc comment** in `crates/sink-server/src/position.rs` on `control_pos` — replace the "Recorded now but not yet routed over HTTP …" sentence with one noting it is served at `GET /v1/control-log/position` for the client-side R27 cutoff.

- [ ] **Step 6: Document the route** in `docs/sink-interface.md` §3 — add a `### 3.5` subsection mirroring §3.4 describing `GET {sink}/v1/control-log/position?chain_seq=<n>` → `{ position }` (404 if no such control append), feeding `download::CompromiseCheck.cutoff`.

- [ ] **Step 7: Dual-target verify** (full workspace test + clippy -D + deny + audit on BOTH targets, see header). All exit 0.

- [ ] **Step 8: Commit**

```bash
git add crates/sink-server docs/sink-interface.md
git commit  # message: "Phase 7 add-on (P7.16): sink control-record unified-position read route"
```

---

### Task P7.17: Production client reads for both positions

**Files:**
- Modify: `crates/client-core/src/sink.rs` (`HttpSinkClient`, net feature)
- Test: `crates/sink-server/tests/sink_e2e.rs`

- [ ] **Step 1: Write the failing test** — add to `crates/sink-server/tests/sink_e2e.rs`. It stands up the real sink over TLS (reuse the file's existing harness — `serve` + `test_pki()`/`pki` + admin `TOKEN`; mirror the existing `sink_head_*` test's setup), appends a record + anchors a genesis via admin POSTs, then asserts the production `HttpSinkClient` reads:

```rust
#[tokio::test]
async fn http_client_reads_control_and_genesis_positions() {
    // --- stand up the sink over TLS exactly as the existing sink_e2e tests do ---
    // (reuse this file's harness: bind a TLS listener on an ephemeral port over a
    // fresh SinkState with admin TOKEN, spawn `serve`, build the pinned client
    // config `pki.client_config`. See `sink_head_verifies_over_tls` above.)
    let (addr, pki, _admin) = spawn_sink().await; // existing helper in this file

    // Anchor a genesis and append one real control record via admin POSTs over TLS
    // (reuse the file's `post_json`/admin helpers; mirror dir_log_enrollment_e2e).
    let g = admin_post_genesis(addr, pki.client_config.clone(), &[0xF1; 16]).await;
    admin_append_record(addr, pki.client_config.clone(), &real_record_bytes()).await;

    let sink = HttpSinkClient::new(addr, "localhost", pki.client_config.clone());

    // The production client reads the genesis position …
    let gp = tokio::task::spawn_blocking({
        let sink = sink_clone(&sink); // HttpSinkClient is cheap to rebuild; or move
        move || sink.fetch_genesis_pos(&[0xF1; 16])
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(gp, Some(g));

    // … an un-anchored file is a clean `Ok(None)` (not an error) …
    let none = tokio::task::spawn_blocking({
        let sink = HttpSinkClient::new(addr, "localhost", pki.client_config.clone());
        move || sink.fetch_genesis_pos(&[0xAB; 16])
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(none, None);

    // … the 1st control append's global position (one past the genesis) …
    let cp = tokio::task::spawn_blocking({
        let sink = HttpSinkClient::new(addr, "localhost", pki.client_config.clone());
        move || sink.fetch_control_pos(1)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(cp, g + 1);

    // … and a chain_seq with no record fails closed (Err, not a silent 0).
    let missing = tokio::task::spawn_blocking({
        let sink = HttpSinkClient::new(addr, "localhost", pki.client_config.clone());
        move || sink.fetch_control_pos(99)
    })
    .await
    .unwrap();
    assert!(missing.is_err());
}
```

> Adapt the harness/helpers to whatever `sink_e2e.rs` already defines (it already builds a TLS sink, an admin POST path for `dir-log/bindings`, and an `HttpSinkClient`). Reuse them rather than re-implementing. The four asserts (genesis position, un-anchored→`Ok(None)`, control position = g+1, missing chain_seq→`Err`) are the contract.

- [ ] **Step 2: Run test to verify it fails** — `cargo test -p maxsecu-sink-server http_client_reads_control_and_genesis_positions`. Expected: FAIL with "no method named `fetch_control_pos`/`fetch_genesis_pos`".

- [ ] **Step 3: Implement the reads** in `crates/client-core/src/sink.rs`. First refactor the internal GET so a 404 is distinguishable from a transport failure. Replace the body of `get_async` with a call to a status-returning core, and add the two public reads:

```rust
    /// Run a blocking GET and return `(status, body)`. Any transport/TLS/parse
    /// failure collapses to [`SinkError::Unreachable`] (fail closed).
    fn get_with_status(&self, path: &str) -> Result<(u16, Vec<u8>), SinkError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| SinkError::Unreachable)?;
        rt.block_on(self.get_with_status_async(path))
    }
```

Rename the existing `get_async` to `get_with_status_async`, dropping its `is_success` gate and returning `Ok((resp.status().as_u16(), body))` instead of erroring on non-2xx. Then make the old success-only `get` delegate:

```rust
    fn get(&self, path: &str) -> Result<Vec<u8>, SinkError> {
        let (status, body) = self.get_with_status(path)?;
        if (200..300).contains(&status) {
            Ok(body)
        } else {
            Err(SinkError::Unreachable)
        }
    }
```

Add the two public reads (after `fetch_head_all_proofs`):

```rust
    /// `GET /v1/genesis-anchor/{file_id}` — the global sink position at which the
    /// file's `genesis` was anchored, or `Ok(None)` if it was never anchored (a
    /// legitimate state — the R27 cutoff treats an unknown position under an active
    /// compromise as fail-closed at the comparison site, not here). Feeds
    /// `download::CompromiseCheck.genesis_sink_pos`.
    pub fn fetch_genesis_pos(&self, file_id: &[u8; 16]) -> Result<Option<u64>, SinkError> {
        let hex: String = file_id.iter().map(|b| format!("{b:02x}")).collect();
        let (status, body) = self.get_with_status(&format!("/v1/genesis-anchor/{hex}"))?;
        if status == 404 {
            return Ok(None);
        }
        if !(200..300).contains(&status) {
            return Err(SinkError::Unreachable);
        }
        let v: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| SinkError::Unreachable)?;
        v.get("position")
            .and_then(|p| p.as_u64())
            .map(Some)
            .ok_or(SinkError::Unreachable)
    }

    /// `GET /v1/control-log/position?chain_seq=<n>` — the global sink position of
    /// the `chain_seq`-th control append (1-based). A `404` (no such record at the
    /// sink) is **fail-closed** [`SinkError::Unreachable`], never a silent zero:
    /// the caller maps a verified `key_compromise` record's chain position here to
    /// obtain `download::CompromiseCheck.cutoff`, and must refuse to proceed if it
    /// cannot be established.
    pub fn fetch_control_pos(&self, chain_seq: u64) -> Result<u64, SinkError> {
        let body = self.get(&format!("/v1/control-log/position?chain_seq={chain_seq}"))?;
        let v: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| SinkError::Unreachable)?;
        v.get("position")
            .and_then(|p| p.as_u64())
            .ok_or(SinkError::Unreachable)
    }
```

- [ ] **Step 4: Run test to verify it passes** — `cargo test -p maxsecu-sink-server http_client_reads_control_and_genesis_positions`. Expected: PASS. Also re-run the existing sink e2e tests to confirm the `get_async`→`get_with_status_async` refactor didn't regress `fetch_head`: `cargo test -p maxsecu-sink-server`.

- [ ] **Step 5: Dual-target verify** (full workspace, both targets; the new reads are `net`-feature, exercised via the sink-server dev-dep which already enables it). All exit 0.

- [ ] **Step 6: Commit**

```bash
git add crates/client-core crates/sink-server/tests/sink_e2e.rs
git commit  # message: "Phase 7 add-on (P7.17): HttpSinkClient reads control + genesis sink positions"
```

---

### Task P7.18: R27 cutoff e2e over the real sink + docs/memory sync

**Files:**
- Modify: `crates/server/tests/phase7_hardening_e2e.rs` (new test)
- Modify: `DESIGN.md`, `docs/sink-interface.md`, `memory/phase-0-status.md`, `memory/MEMORY.md`

- [ ] **Step 1: Write the failing test** — add `r27_cutoff_over_real_sink` to `crates/server/tests/phase7_hardening_e2e.rs`. Model the bundle/cutoff construction on the existing phase-5 R27 assertion in `sharing_e2e.rs` (~lines 981–1010), but source `kc_pos` and `g_pos` from the **real sink over TLS** via `HttpSinkClient`, not from `MemoryAuditSink`. Shape:

```rust
#[tokio::test]
async fn r27_cutoff_over_real_sink() {
    // Stand up the honest sink over TLS (reuse this file's `test_pki()` + `serve`).
    // Build a real upload bundle for a file (reuse this file's upload helpers) so
    // we hold a genuine genesis + DownloadBundle that verify_and_open accepts when
    // no compromise applies.
    //
    // Timeline drawn from the sink's single global counter:
    //   1. anchor `file_before`'s genesis            -> pos a
    //   2. append a key_compromise(owner, kv=1)      -> pos b  (b > a)
    //   3. anchor `file_after`'s genesis             -> pos c  (c > b)
    //
    // Source EVERY position from the real sink via the production client:
    let sink = HttpSinkClient::new(sink_addr, "localhost", sink_pki.client_config.clone());
    let a = run_blocking(|| sink_a.fetch_genesis_pos(&file_before.0)).unwrap().unwrap();
    let kc_chain_seq = /* the key_compromise record's 1-based position in the chain */;
    let b = run_blocking(|| sink_b.fetch_control_pos(kc_chain_seq)).unwrap();
    let c = run_blocking(|| sink_c.fetch_genesis_pos(&file_after.0)).unwrap().unwrap();
    assert!(a < b && b < c);

    // The cutoff closure is assembled AFTER the fetch (fail-closed: if the fetch had
    // errored we would refuse to build it). It encodes the resolved sink position.
    let owner_id = owner.user_id().0;
    let cutoff = move |id: Id, kv: u64| (id.0 == owner_id && kv == 1).then_some(b);

    // A genesis anchored BEFORE the compromise (pos a) is honored.
    let mut ok_ctx = download_ctx_for(&bundle_before);
    ok_ctx.compromise = Some(CompromiseCheck { genesis_sink_pos: Some(a), cutoff: &cutoff });
    assert!(verify_and_open(&ok_ctx, &db_before).is_ok());

    // A genesis anchored AFTER the compromise (pos c) is rejected as a forgery.
    let mut bad_ctx = download_ctx_for(&bundle_after);
    bad_ctx.compromise = Some(CompromiseCheck { genesis_sink_pos: Some(c), cutoff: &cutoff });
    assert_eq!(verify_and_open(&bad_ctx, &db_after), Err(DownloadError::GenesisAfterCompromise));
}
```

> Reuse this file's existing upload/download helpers and TLS-sink harness; do not hand-roll a new bundle if a helper exists. The non-negotiable assertions: positions `a`/`b`/`c` are read through `HttpSinkClient` from the real sink, `a < b < c`, the before-genesis verifies, the after-genesis → `GenesisAfterCompromise`. Run the `HttpSinkClient` calls under `spawn_blocking` (its per-call runtime panics if nested in an async task) — mirror `sink_publish_e2e.rs`'s `spawn_blocking` usage.

- [ ] **Step 2: Run test to verify it fails** — `cargo test -p maxsecu-server --test phase7_hardening_e2e r27_cutoff_over_real_sink`. Expected: FAIL initially (compile error on the helper names / wiring) until the harness is assembled; once it compiles, it must fail for the RIGHT reason if any wiring is wrong, then pass.

- [ ] **Step 3: Make it pass** — fill in the real harness (sink spawn, upload helpers, `kc_chain_seq`, `run_blocking`/`spawn_blocking` wrappers) using the patterns already in `phase7_hardening_e2e.rs` and `sink_publish_e2e.rs`. No new production code should be needed — P7.16/P7.17 provide the route + client reads; this task is glue + proof.

- [ ] **Step 4: Run test to verify it passes** — `cargo test -p maxsecu-server --test phase7_hardening_e2e r27_cutoff_over_real_sink`. Expected: PASS.

- [ ] **Step 5: Sync docs + memory (mark the residual closed):**
  - `DESIGN.md` — in the §15.2/§17 Phase-7 residual list, change "client-side R27-comparison over the real sink" from deferred to DONE (note the route + `HttpSinkClient` reads + e2e).
  - `docs/sink-interface.md` — update the §3/§3.4 status note: the control-record position route (§3.5) now exists, so the R27 cutoff sources BOTH positions from the real sink (no longer "proven via MemoryAuditSink").
  - `memory/phase-0-status.md` — move "client-side R27-comparison over the real sink" out of the Phase-7 DEFERRED line into a short DONE note (P7.16–P7.18, the route + client reads + `r27_cutoff_over_real_sink` e2e).
  - `memory/MEMORY.md` — update the build-status one-liner's deferral list to drop the R27-over-real-sink item.

- [ ] **Step 6: Dual-target verify** (full workspace, both targets). All exit 0.

- [ ] **Step 7: Commit**

```bash
git add crates/server/tests/phase7_hardening_e2e.rs DESIGN.md docs/sink-interface.md
git commit  # message: "Phase 7 add-on (P7.18): R27 key-compromise cutoff e2e over the real sink; residual closed"
```

(Memory files live outside the repo tree and are written directly, not committed.)

---

## Self-Review

**Spec coverage:** The deferral is "Add a sink control-record position read route (P7.16) + wire client `CompromiseCheck` (genesis_sink_pos + cutoff) to source from the real sink (P7.17), proven e2e (P7.18)." All three are tasks. ✓

**Placeholder scan:** The e2e (P7.18) intentionally references this-file helpers by intent rather than reproducing the full ~200-line upload harness; the contract (read both positions via `HttpSinkClient`, assert `a<b<c`, before→Ok, after→`GenesisAfterCompromise`) is concrete. Acceptable because the helpers already exist in the target file and must be reused, not rewritten.

**Type consistency:** `fetch_genesis_pos(&[u8;16]) -> Result<Option<u64>, SinkError>` and `fetch_control_pos(u64) -> Result<u64, SinkError>` are used consistently across P7.17/P7.18. `GenesisPositionJson{position}` is reused for the new sink route (P7.16). `CompromiseCheck{genesis_sink_pos: Option<u64>, cutoff: &dyn Fn(Id,u64)->Option<u64>}` matches `download.rs`. ✓
