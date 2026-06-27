# MaxSecu — implementation workspace

Zero-knowledge file storage. Design is authoritative in [`DESIGN.md`](DESIGN.md)
and [`docs/`](docs/); this README covers the **code**.

## Layout

```
crates/
  encoding/   maxsecu-encoding — the single canonical injective binary encoder
              (docs/encoding-spec.md). Shared verbatim by client, server, and
              air-gapped ceremony tools.
  crypto/     maxsecu-crypto  — primitive wrappers (DESIGN §5): AES-256-GCM
              chunked/framed, HPKE base-mode wrap, Ed25519 (strict), Argon2id,
              HKDF-SHA256, SHA-256, OS CSPRNG.
```

Toolchain is pinned in [`rust-toolchain.toml`](rust-toolchain.toml) (Rust 1.96.0,
`x86_64-pc-windows-msvc` — the production client target, stack.md §1.5).

## Build & test

```sh
cargo test --workspace            # all unit, vector, golden, and property tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo deny check                  # supply-chain (advisories, licenses, sources)
cargo audit                       # RUSTSEC advisories
```

The server (Phase 1+) builds and runs in a dedicated **WSL2 Ubuntu 22.04** distro
(`Ubuntu-22.04`) matching prod; Phase 0 is pure library work and needs only the
Windows toolchain.

## Phase 0 — status: exit gate met

Phase 0 (DESIGN §17) builds and **test-first** verifies the canonical encoder +
strict decoder and the crypto primitive wrappers. Exit-gate coverage:

| Exit-gate requirement (DESIGN §17 / encoding-spec §9) | Where |
|---|---|
| Encoder + strict decoder for all 12 §4 structures | `crates/encoding/src/{structs,types,primitives}.rs` |
| §7 decoder rules + master re-encode canonical guard | `crates/encoding/src/lib.rs` (`decode`) |
| Adversarial vectors **V-1…V-13 all reject** | `crates/encoding/tests/vectors.rs` |
| Positive vectors **byte-exact** | `tests/vectors.rs` + committed `tests/fixtures/canonical_vectors.tsv` |
| `decode∘encode` / `encode∘decode` identity (property) | `crates/encoding/tests/properties.rs` |
| Domain-separated, length-framed `signing_input` | `lib.rs` (`signing_input`) + `crypto` `sign` |
| encrypt→decrypt, wrap→unwrap, sign→verify, framing tamper-reject | `crates/crypto/tests/properties.rs` + per-module tests |
| Committed fixtures shared by client/server/tooling | `crates/encoding/tests/fixtures/` |

The re-encode guard is proven to be a real backstop (not dead code) by a mutation
test: with the explicit set/stream ordering checks disabled, non-canonical inputs
are still rejected as `NonCanonical`.

> Until Phase 0 passes, no later phase may sign or verify anything — every later
> guarantee rests on these bytes being injective (encoding-spec §9).
