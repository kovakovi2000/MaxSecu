# Security Review — Part C: Real Tor Transport (arti-client) + Client-Workspace Split

**Scope:** the change that makes the client's `TorOnly` download route actually route through Tor (in-process, `arti-client` 0.44), plus the workspace split + server `postgres` feature-gate that make arti and `sqlx` coexist.
**Commits:** `50543ae` (server feature-gate) · `8c53623` (workspace split + e2e relocation) · `cb0fbc9` (arti dep + `tls_over`) · `89c469d` (`TorState`) · `21a032f` (route wiring) · `520c811` (client deny) · `2050db7` (demo-seed move) · `118be9b` (packaging).
**Verdict: PASS** — no Critical/High. Two accepted deviations (bundled-C SQLite; `rsa` in-graph via arti) with rationale below; one ops follow-up (live Tor verification).

---

## Method

Two-stage self-review (spec conformance, then adversarial security), against the plan's invariants (a)–(e), reading the actual code paths rather than the plan text. Full test matrix green: root workspace build+test (pg tests skip cleanly without a live PG), client workspace build+test (149 lib + 7 e2e over real TLS), both `cargo deny` clean, UI 60/60.

## Invariant checks

### (a) `TorOnly` NEVER falls back to clearnet (no client-IP leak) — PASS
`open_conn` (commands/connection.rs) selects transport by the **persisted** `route_mode`. The `TorOnly` arm dials the Tor circuit and, on ANY failure (`tor::global()` missing, unparseable port, `dial` error), returns `Err` via `?` — it is the `if` arm of a mutually-exclusive `if/else`, so control can never reach the direct `Transport::connect()` arm. `connect` additionally pre-bootstraps under `TorOnly` and returns `Err` (emitting `Disconnected`) on bootstrap failure — again no direct dial. Because `connect` persists the effective mode *before* opening, every downstream path (`reauth` for feed/viewer/video/upload/admin, and the unauthenticated `bootstrap` commands) reads `TorOnly` from the same settings and routes identically. **All server egress under `TorOnly` traverses Tor.**

### (a′) No DNS leak — PASS
`TorState::dial` calls `client.connect((host, port))` with a **string** host. Arti's `IntoTorAddr for (&str, u16)` performs **remote** name resolution over the circuit (arti deliberately reserves `DangerouslyIntoTorAddr` for pre-resolved `IpAddr`s). The client never resolves the server hostname locally on the `TorOnly` path.

### (b) Channel binding preserved over the Tor tunnel — PASS
The Tor arm layers the SAME pinned TLS 1.3 via `transport::tls_over`, which runs the aws-lc-rs handshake over the boxed Tor stream and exports the RFC 5705 keying material with the unchanged `EXPORTER_LABEL`/`EXPORTER_LEN` (context `None`). The login proof is therefore bound to the TLS-over-Tor channel exactly as on the direct path; the server contract (`serve.rs` `CHANNEL_BINDING_*`) is untouched. TLS is pinned to the private server cert (not public roots), so the Tor **exit** node sees only opaque TLS to the pinned server — no MITM surface at the exit.

### (c) Direct-link (cloud) download stays disabled under Tor — PASS
`direct_link::direct_allowed(route_mode)` returns `true` only for `PreferDropbox`; `TorOnly` never brokers or fetches a public cloud URL. Covered by existing tests `direct_allowed_only_under_prefer_dropbox` and the "TorOnly must never even broker a link" assertion (direct_link.rs). So under Tor there is no bare-GET egress to a public host outside the circuit.

### (d) Bundled-C SQLite is transport-only, outside the crypto/key TCB — PASS (with deviation, below)
Arti's `tor-dirmgr → rusqlite` (bundled `libsqlite3-sys`, `static-sqlite` feature) is the Tor **directory cache** (consensus/descriptors/guard state). It never touches the app-layer crypto TCB (`maxsecu-crypto`, `client-core`): no user identity, DEK, keyblob, or AEAD path uses SQLite. `cargo tree` confirms `rusqlite` reaches only the arti subtree.

### (e) Arti state confined; no MaxSecu secret written there — PASS
`TorState::new(config_dir)` confines all arti state to `config_dir/tor` (i.e. `<app-dir>/config/tor`). Arti's own keystore there holds **Tor** keys (guard/circuit/client-onion), not the user's identity keystore, which remains at the separate `<app-dir>/keystore`. Failed bootstrap is not cached (tokio `OnceCell::get_or_try_init`), so a transient network failure is retryable and cannot wedge the client into a broken Tor state.

## Supply-chain posture (cargo-deny, client workspace)

- **`ring` ban upheld.** arti's `rustls-webpki` lists `ring` as an *optional* feature; our transport forces the aws-lc-rs provider, so the real build never enables/links `ring` (`cargo tree -i ring` → nothing). deny is evaluated at the binary's real feature set (`all-features = false`) so the ban stays meaningful without a false positive on the never-compiled edge. `openssl`/`native-tls` absent (arti on `rustls`, not `native-tls`).
- **New license:** `Unlicense` (public-domain-equivalent, OSI/FSF) for `async_executors` via `tor-rtcompat` — justified in deny.toml.
- **`sqlx` fully absent** from the client lock (the whole point of the split); server + `portable-server` build byte-identically with `postgres` on.

## Accepted deviations (call-outs)

1. **Bundled-C SQLite enters the client.** A deliberate departure from the client's pure-Rust/zero-C ethos. Contained: transport-only, outside the crypto TCB, compiled from source (`static-sqlite`) so no system `sqlite3.lib` is trusted. Accepted because arti is the documented preferred Tor design and the C is not on the confidentiality boundary. Re-evaluate if arti offers a pure-Rust dir-store.
2. **`rsa` (RUSTSEC-2023-0071 "Marvin" PKCS#1v1.5 timing sidechannel) is now in the client build graph** via `ssh-key-fork-arti → tor-key-forge → tor-keymgr → arti-client` (was previously a never-compiled sqlx lock entry on the server). **Assessment:** the Marvin attack needs an attacker-observable timing oracle over RSA *decryption* of chosen ciphertexts. Arti's usage here is Tor relay/onion **key parsing/verification/storage**, not a network-exposed RSA-decrypt oracle, and the MaxSecu client presents no such oracle to a peer. No upstream fix exists; ignored with this justification in deny.toml, to be revisited if arti drops `rsa`.
3. **"Zero server change" became one additive feature gate.** `sqlx`/`PgStore` behind a default-on `postgres` feature. The shipped server is unchanged; only the client-side e2e crate links the server without it. Behavior-preserving; not a semver-major bump.

## Pre-existing findings surfaced (not introduced here)

- `quick-xml` 0.39.4 DoS advisories RUSTSEC-2026-0194/0195 (via `plist → tauri`). Not reachable: the client parses no attacker-controlled XML at runtime (its wire is JSON + AEAD ciphertext). Ignored with justification; remove when Tauri's plist pulls quick-xml ≥ 0.41.

## Ops follow-up (not a blocker)

- **Live Tor verification.** `crates/client-e2e/tests/tor_route_e2e.rs` is `#[ignore]` + gated on `MAXSECU_TOR_LIVE=1` (real network, never in CI). Run it once in an environment with outbound Tor reachability to confirm end-to-end bootstrap+circuit; the automated suite proves everything except the live network hop.

## Conclusion

The Tor transport preserves every existing security property of the direct path — pinned TLS, RFC 5705 channel binding, zero-knowledge server, fail-closed with no clearnet/DNS leak — and adds Tor circuit routing beneath them. The supply-chain deltas are bounded and justified. **PASS.**
