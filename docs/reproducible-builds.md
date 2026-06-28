# MaxSecu — Reproducible Builds

**Status:** Phase 6 (client integrity & ops, C2). Companion to `DESIGN.md` §8 (control 2, D1) and `docs/stack.md` §1.5.
**Scope:** how anyone can rebuild a published MaxSecu binary from source and confirm, byte-for-byte, that it matches the signed artifact — so a malicious build/CI pipeline cannot ship code that differs from the public source. This closes the residual code-integrity vector left after native + code-signed clients (D1): *a malicious software update* (`DESIGN.md` §3.1, threat row "Malicious software update").

> **Why this matters.** The whole zero-knowledge guarantee rests on the client running the code that the source says it runs (§8). Code signing proves *who* built it; reproducible builds prove *what* they built. Together with the transparency-logged update verification (`crates/client-core/src/update.rs`, P6.8) and the signing runbook (`docs/runbooks/release-signing.md`), a verifier can independently confirm a release is exactly the audited source.

---

## 1. Determinism levers (what must match to reproduce a hash)

Two builds reproduce the same artifact hash only if **all** of these are identical:

| Lever | Pinned by |
|---|---|
| Toolchain (rustc/cargo version, channel) | `rust-toolchain.toml` → `channel = "1.96.0"` (never floats) |
| Dependency graph (exact versions) | `Cargo.lock`, built with `--locked` |
| Build epoch | `SOURCE_DATE_EPOCH=1700000000` (the value is arbitrary but must be shared) |
| Source / dependency / target paths | `--remap-path-prefix` mapping `$repo`→`/src`, `~/.cargo`→`/cargo`, the target dir→`/target` |
| Incremental compilation | `CARGO_INCREMENTAL=0` (incremental output is non-deterministic) |
| Build profile | `--release` |

The two helper scripts set every lever for you:

- **`scripts/reproducible-build.sh`** (Linux/WSL) — the **artifact-of-record** path. Builds the chosen binary twice in two isolated target dirs, each remapped to the same logical `/target`, and **exits non-zero unless the two SHA-256 hashes are identical**.
- **`scripts/reproducible-build.ps1`** (Windows) — **best-effort only** (see §3); never fails CI on a PE difference.

```
# Linux / WSL — the gate:
./scripts/reproducible-build.sh                       # default: maxsecu-media-worker :: media-worker
./scripts/reproducible-build.sh maxsecu-media-worker media-worker
# → "REPRODUCIBLE: identical SHA-256 (<hash>)"  (exit 0)  or  exit 1 on a mismatch
```

---

## 2. The reproducible artifact of record — Linux musl static binary

Per `docs/stack.md` §5.1 the production **server** ships as a single static
`x86_64-unknown-linux-musl` binary, and that musl build is the **reproducible
artifact of record** (fully static ⇒ no host-libc variance in the output):

```bash
rustup target add x86_64-unknown-linux-musl          # one-time prerequisite
SOURCE_DATE_EPOCH=1700000000 CARGO_INCREMENTAL=0 \
RUSTFLAGS="--remap-path-prefix=$PWD=/src --remap-path-prefix=$HOME/.cargo=/cargo" \
  cargo build --release --locked --target x86_64-unknown-linux-musl -p <crate> --bin <bin>
sha256sum target/x86_64-unknown-linux-musl/release/<bin>
```

> **Prerequisite note.** The musl target requires `rustup target add x86_64-unknown-linux-musl` and a musl-capable linker. Crates that build C (the sanctioned `aws-lc-rs` TLS provider, `DESIGN.md` §5/stack §1.3) may require a musl C toolchain for a fully-static link; the **default host-target determinism check (`scripts/reproducible-build.sh`) needs none** and is what the Phase-6 gate runs. The musl recipe above is the documented release path; run it on the release host once the musl toolchain is provisioned (`stack.md` §4 item 8).

The currently shipped standalone binary is the sandboxed decode worker
(`crates/media-worker` → `media-worker`), so it is the script's default subject.
The server and sink-server are libraries today; when they are packaged as
binaries the same recipe applies (`scripts/reproducible-build.sh <crate> <bin>`).

---

## 3. Honest determinism scope (Windows caveat)

The Windows MSVC client (`stack.md` §1.5, §5.2) is **best-effort** reproducible, not a hard gate:

- The PE format carries a **`TimeDateStamp`** and the MSVC linker can embed a **build GUID / debug signature**, so two otherwise-identical builds can differ in those fields. `scripts/reproducible-build.ps1` passes the linker flag **`/Brepro`** (`-C link-arg=/Brepro`) to replace the timestamp with a content hash, which removes the dominant source of variance, but full MSVC PE determinism is not guaranteed across machines/SDK versions.
- Therefore the **Linux musl build is the reproducible artifact of record**; the Windows PE script reports differences informationally and **exits 0** (a PE difference is not a CI failure). Windows code-integrity is anchored by **Authenticode** (`docs/runbooks/release-signing.md`) + the transparency-logged update manifest (P6.8), with reproducibility as a corroborating, best-effort check.

---

## 4. How a third party verifies a published release

1. Clone the exact source tag and confirm `rust-toolchain.toml` + `Cargo.lock` match the release.
2. Run `scripts/reproducible-build.sh <crate> <bin>` (or the musl recipe in §2 for the server artifact).
3. Compare the printed SHA-256 against the **published** hash (release notes) and against the **transparency-log** entry the client's `verify_update` checks (P6.8). All three must agree.
4. A divergence is a supply-chain alarm — do not run the binary; escalate (`DESIGN.md` §16.4 emergency posture).

---

## Cross-references
`DESIGN.md` §8 (client integrity, D1) / §3.1 (malicious-update threat row) / §16.4 (emergency runbook); `docs/stack.md` §1.5 (reproducible builds + signing) / §5 (packaging); `docs/runbooks/release-signing.md` (Authenticode + signed/transparency-logged update publication); `crates/client-core/src/update.rs` (client-side signed + transparency-logged update verification, P6.8).
