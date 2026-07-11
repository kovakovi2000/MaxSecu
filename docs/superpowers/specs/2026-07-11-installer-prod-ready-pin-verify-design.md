# Installer prod-ready feedback + test-pin guard — design

**Date:** 2026-07-11
**Branch:** `fix/installer-prod-ready-pin-verify`

## Problem

A clean prod deploy (`install-server.sh --public` → `install-client.ps1`) succeeds and
produces a **correct, prod-ready** client: the final `cargo build` embeds the real
`recovery_pin.bin` (file-present branch of `build.rs`), with the `unpinned-dev` feature
OFF and fail-closed active. But the operator cannot tell:

1. **Scary intermediate warning.** `install-client.ps1` builds `maxsecu-setup` twice
   (fetch-pins step 3, ceremony step 4). `tools/maxsecu-setup/Cargo.toml` depends on
   `maxsecu-client-app` with `features = ["unpinned-dev"]`, so those *tool* builds compile
   a throwaway client-app with the NON-SECURE test pin and emit
   `cargo:warning=recovery_pin: NON-SECURE test pin embedded (unpinned-dev) — do not ship`.
   The operator reads this as "my client shipped a test pin."
2. **No proof of the final binary.** After the real build the installer never confirms the
   shipped `.exe` actually embedded the real pin — "prod ready" is true but unproven.
3. **No structural guard.** Nothing physically prevents a test-pin binary from shipping if
   the flow is mis-run (e.g. the test pin copied in as `recovery_pin.bin`).
4. **Server side gives no explicit prod-ready feedback** either; `AWAITING DELEGATION`
   reads like a warning rather than the expected prod state.

## Non-goals

- No change to the trust model, wire formats, or the recovery-pin byte layout.
- No change to how the real pin is produced (`maxsecu-setup` still writes `recovery_pin.bin`).
- The intermediate `unpinned-dev` warning on the *tool* build is not suppressed (it is
  correct for that binary); we explain it inline instead.

## Design

### 1. Client verify subcommand — `--print-recovery-pin-fp`

Add an early argv check at the very top of `main()` (`crates/client-app/src/main.rs`),
BEFORE any app-dir / Tauri / temp-dir setup, so it runs headlessly and exits without a
window. When `std::env::args()` contains `--print-recovery-pin-fp`, print exactly:

```
recovery-pin-sha256: <64 lowercase hex chars of sha256(embedded_pin())>
recovery-pin-is-test: <true|false>
```

then `std::process::exit(0)`. Because `EMBEDDED_PIN` is an `include_bytes!` of
`recovery_pin.bin`, `sha256(embedded_pin())` equals the SHA-256 of that file byte-for-byte,
so the installer verifies with a plain `Get-FileHash -Algorithm SHA256`. Reuse
`maxsecu_crypto::sha256` (already a client-app dependency); render hex inline.

### 2. Hard test-pin guard (build + runtime)

`build.rs` already derives the test pin from fixed seeds in the `unpinned-dev` branch.
Restructure so the test-pin bytes are computed on EVERY build (both branches) via
`maxsecu-crypto` (already a build-dependency), then:

- Emit into `OUT_DIR/recovery_pin_gen.rs`, alongside `EMBEDDED_PIN`:
  ```rust
  pub(crate) const EMBEDDED_PIN_IS_TEST_PIN: bool = <embedded == test_pin>;
  ```
- **Build-time primary guard:** in the file-present branch, if the embedded bytes equal the
  test pin AND `unpinned-dev` is OFF → `panic!` with a clear message. A release build then
  physically cannot embed the test pin.
- Keep the existing `cargo:warning` only in the `unpinned-dev` + file-absent branch
  (unchanged behavior for the tool build).

`recovery_pin.rs`:
- Expose `EMBEDDED_PIN_IS_TEST_PIN` (via the generated include) and add:
  ```rust
  /// Fail closed if a release binary somehow embedded the NON-SECURE test pin.
  /// No-op under `unpinned-dev` (tests legitimately use the test pin).
  pub fn assert_shippable() { ... }
  ```
  Under `not(feature = "unpinned-dev")`, if `EMBEDDED_PIN_IS_TEST_PIN` → `panic!`
  (fail closed, loud). Under `unpinned-dev` → no-op.
- Call `recovery_pin::assert_shippable()` at the top of `main()` (right after the argv
  check, before app setup).

### 3. `install-client.ps1`

- **Sections 3 & 4** (fetch-pins + ceremony): print an inline note BEFORE each build that a
  `recovery_pin: NON-SECURE test pin (unpinned-dev)` cargo warning will scroll past, that it
  belongs to the setup TOOL's throwaway build (not the shipped client), and that the shipped
  client is cryptographically verified at the end.
- **New verification section after step 7 (final client build):** run
  `maxsecu-client-app.exe --print-recovery-pin-fp`, parse the two lines, compute
  `(Get-FileHash $RecoveryPin -Algorithm SHA256).Hash`, and assert:
  `recovery-pin-sha256` == file hash (case-insensitive) AND `recovery-pin-is-test` == `false`.
  On success: green `✓ VERIFIED — real recovery pin embedded (sha256 <short>…), no test pin.`
  On any mismatch/test-pin/nonzero-exit: `Fail` with guidance.
- **Final summary:** add a `PROD-READY ✓` line (real pin verified · delegation installed ·
  pins committed to the connection code).

### 4. `install-server.sh`

Add a concise prod-readiness checklist to BOTH final banners (the `ALREADY DELEGATED` and
`AWAITING DELEGATION` cases): `✓ release build · ✓ TLS cert for <addr> · ✓ firewall <port> ·
✓ systemd enabled · Dropbox <ENABLED|off>`. For the awaiting case, state explicitly that
`AWAITING DELEGATION` / enrollment CLOSED is the EXPECTED prod state after a fresh install,
not an error — enrollment opens once the admin PC uploads the delegation.

## Testing

- `recovery_pin.rs` unit tests (run under `unpinned-dev`):
  - `EMBEDDED_PIN_IS_TEST_PIN == true`;
  - `assert_shippable()` does not panic under `unpinned-dev`;
  - `sha256(embedded_pin())` hex matches an independently computed digest (ties the
    subcommand's contract to the embedded bytes).
- Whole existing suite stays green: crypto/encoding, server lib, client-core, client-app,
  portable-server, maxsecu-setup ceremony/fetch/renew/setup-e2e, client-e2e, UI.
- Manual self-verify: release-build client-app with the real pin, run
  `--print-recovery-pin-fp`, confirm `is-test: false` and the sha256 matches the file.

## Execution

Three parallel workstreams (same model/effort), then an integration + full-suite verify
pass run by the orchestrator:

- **A — Rust client:** `build.rs`, `src/recovery_pin.rs`, `src/main.rs`, unit tests. Owns
  the `--print-recovery-pin-fp` output contract (§1) and the guard (§2).
- **B — `scripts/install-server.sh`:** §4 (independent).
- **C — `scripts/install-client.ps1`:** §3, coding against the fixed §1 contract.

Workstreams touch disjoint files, so they run concurrently in one worktree.
