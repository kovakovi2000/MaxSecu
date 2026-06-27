# MaxSecu — Technology Stack & Build Decisions

**Status:** Decided (pre-implementation). Companion to `DESIGN.md`; this file records the *how-we-build* decisions that `DESIGN.md` deliberately left open.
**Scope:** v1 — **Windows desktop client, Linux server.** No mobile, no browser client (a deliberate security decision, `DESIGN.md` §1.3 / D1).

This document is authoritative for language/runtime/library choices. Where a choice is forced by a security requirement in `DESIGN.md`, that requirement is cited — these are not stylistic preferences.

---

## 0. Summary

| Component | Choice | Forced by |
|---|---|---|
| Client core (all crypto, key custody, plaintext handling) | **Rust** | §8.1 (in-memory-only plaintext, zeroize, locked pages) cannot be honored on a managed runtime |
| Client UI shell | **Tauri** (Rust backend + WebView2 UI) | Keeps security-critical code in Rust; UI is outside the TCB |
| Server / API | **Rust or Go** on Linux (team's call) | Server holds no secrets (§4.3) — language is not a security decision |
| Database | **PostgreSQL** | Relational schema (§11); strong constraints/transactions |
| Blob store | **S3-compatible object store** | Chunked ciphertext (§12.10) |
| Canonical encoder | **One Rust implementation** (`docs/encoding-spec.md`) | Single client platform ⇒ one encoder; server stores opaque bytes |
| Air-gapped tooling | **Rust CLI binaries** sharing the client core crates | Ceremony tools are security-critical software (§12.1, §12.7) |
| TLS | **rustls** | TLS 1.3 + keying-material exporter for channel binding (§9.2) |

---

## 1. Client: Rust core + Tauri shell (Windows)

### 1.1 Why Rust is *required*, not preferred

`DESIGN.md` §8.1 imposes hard rules on decrypted data and keys:

- plaintext and DEKs live **only in RAM**, never on disk/swap/temp/caches;
- secrets are **zeroized** the instant they are no longer needed;
- secret pages are **locked against swap** and the process **disables crash dumps**.

A garbage-collected or managed runtime (**C#/.NET, Electron/JavaScript, JVM**) **cannot guarantee any of these**: the runtime freely copies, relocates, and retains buffers, and you cannot force-wipe or pin a specific allocation. Choosing such a runtime would make the §8.1 guarantee *aspirational* — i.e. it would quietly break the product's core promise. Rust gives deterministic memory control, no GC, and a mature audited crypto ecosystem. This is the single most important stack decision.

> **C++ would also satisfy §8.1** but is rejected for the *crypto/TCB* code: memory-safety bugs in the one component that touches plaintext and private keys are exactly the class of defect we cannot afford. Rust removes that class.

### 1.2 Architecture: thin TCB, fat UI

```
┌─────────────────────────── Windows client process ───────────────────────────┐
│                                                                               │
│   WebView2 UI (HTML/CSS/JS)        ──IPC──►   Rust core  (the TCB)            │
│   - screens, navigation                       - Argon2id, keygen, AEAD        │
│   - NEVER sees private keys                    - HPKE wrap/unwrap             │
│   - NEVER sees plaintext bytes                 - manifest/grant signing+verify│
│     (only render-on-demand via core)           - directory verification (§7) │
│                                                - tombstone/sink verification │
│                                                - canonical encoder (one impl) │
│                                                - zeroize + VirtualLock + no-dump│
└───────────────────────────────────────────────────────────────────────────────┘
```

- **Tauri** is the shell: a small native Windows app (WebView2) with a Rust backend. The UI is HTML/JS for productivity but is treated as **non-TCB** — it receives only what the core decides to show, and never holds key material or whole-plaintext buffers. Plaintext is streamed to the renderer on demand and never materialized to disk (see §1.4).
- The **Rust core** is the trusted computing base. Everything in `DESIGN.md` §4.1 ("native client … the only component that ever holds plaintext or private keys") lives here.

### 1.3 Crypto library selection (RustCrypto-centric)

Maps every primitive in `DESIGN.md` §5 to a concrete, audited crate. One ecosystem (RustCrypto + dalek) for consistency and pure-Rust reproducibility.

| Purpose (§5) | Crate | Notes |
|---|---|---|
| HPKE wrap (base mode, X25519+HKDF-SHA256+AES-256-GCM) | `hpke` | RFC 9180; base mode only (Auth mode removed, §5/R29) |
| X25519 (unwrap) | `x25519-dalek` | |
| Ed25519 (auth, manifest, grants, tombstones…) | `ed25519-dalek` | Use the strict-verification / `verify_strict` API to avoid malleability |
| AES-256-GCM (chunked content + metadata) | `aes-gcm` | Framing (§12.10) hand-rolled over the AEAD |
| Argon2id | `argon2` | Desktop profile `m=256 MiB, t=3, p=1` (§5); calibrate at install |
| SHA-256 | `sha2` | Digests, fingerprints, tombstone hash chain |
| HKDF-SHA256 | `hkdf` | `ck`, `dek_commit`, `mk` derivations |
| Secret hygiene | `zeroize` | `Zeroizing<…>` wrappers on all key/plaintext buffers |
| Page locking | `region` **or** `windows` (`VirtualLock`) | §8.1 lock secret pages |
| CSPRNG | `getrandom` / `rand` | OS RNG (`BCryptGenRandom` on Windows) — never `rand`'s userspace PRNG for keys |
| TLS 1.3 + channel binding | `rustls` | `export_keying_material` (RFC 5705) feeds the §9.2 auth challenge |
| Post-quantum (Phase 7) | `ml-kem` (RustCrypto) | Behind the `alg` registry; not in v1 (§5/D20) |

> **Pin and audit (D1/§8 supply chain).** Lockfile with hashes, `cargo audit`/`cargo deny` in CI, pinned toolchain. No `build.rs` network access. Vendoring dependencies is acceptable for the air-gapped tooling.

### 1.4 Windows-specific §8.1 mechanics (easy to miss)

These are concrete Windows behaviours that will leak plaintext unless explicitly handled:

- **Lock secret pages:** `VirtualLock` on buffers holding DEKs/private keys/plaintext; `VirtualUnlock` + zeroize on release.
- **Disable crash dumps for the process:** opt out of **Windows Error Reporting** (`WerAddExcludedApplication` / set process dump policy) so a crash never writes a memory image containing plaintext.
- **Transiently-staged ciphertext only:** any chunk staged to disk during transfer (allowed by §8.1) must be **ciphertext**, deleted on completion, and written to a path excluded from **Windows Search indexing** and **thumbnail/`Thumbs.db` caching** (set `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED`; avoid shell-known folders).
- **No plaintext temp path to other apps:** viewers render from the in-RAM buffer (§8.1). The "Save to disk" export is the *only* path that writes plaintext, and it carries the §8.1 warning + audit event.
- **Large files:** decrypt-and-render must **stream** (chunk-at-a-time) so a multi-GB file is never wholly in RAM and never on disk — see the open item in `DESIGN.md` review (large-file vs. in-memory-only). The viewer consumes a bounded sliding window from the core; nothing whole is materialized. *This pipeline shape must be settled before building file I/O.*

### 1.5 Reproducible builds + signing (D1, §8)

- **Reproducible build** of the Rust core/shell: pinned `rustc` + locked deps + deterministic build flags; document the recipe so a third party can reproduce the published binary (§8 control 2). One target (Windows x64) ⇒ one pipeline.
- **Authenticode** code-signing of the released binary; signed, transparency-logged updates (§8 control 4); update-signing key held offline.
- In-person delivery of the first install (§8 "Install bootstrap") removes the MITM'd-download vector.

### 1.6 Air-gapped ceremony tooling

The directory-signing (D5) and recovery (D6) ceremonies (§12.1, §12.7) run on an **offline Windows (or Linux) machine** via **separate small Rust CLI binaries** that reuse the client core crates (same canonical encoder, same Ed25519/HPKE code). They never link networking. Built and signed under the same reproducible pipeline.

---

## 2. Server: Linux, secret-free

### 2.1 Language is a free choice

Per §4.3 the server stores **inert records** and enforces only **coarse** authorization, rate-limiting, and serving — it holds **no** file-decryption secrets and performs **no** security-critical cryptography (clients do all verification). Therefore the server language is driven by team familiarity, not security.

- **Recommended: Rust** (shares record types + the canonical-encoder crate with the client; one codebase for the wire format) — *or* **Go** (fast to build services, fine here). Either is acceptable.
- The server **may** sanity-check signatures for early rejection, but must never be *relied upon* to — every guarantee is re-checked client-side (§10).

### 2.2 Data + blobs

- **PostgreSQL** for the relational tables in §11 (`users`, `files`, `file_key_wraps`, `auth_events` mirror, `revocations`, `reinstatements`, `write_grants`, `file_genesis`). Use DB constraints to enforce the append-only/monotonic invariants where possible (e.g. no-delete triggers on tombstones).
- **S3-compatible object store** (MinIO on-prem, or cloud) for chunked ciphertext blobs (§12.10), referenced by `files.blob_ref`.
- **TLS 1.3** terminated by the app (rustls) with the client pinning the server identity (§9.2); the keying-material exporter binds the auth challenge and session token to the channel.

### 2.3 The external append-only sink is a *separate, real* dependency

`DESIGN.md` §16.5 + the simplification pass make the **external, append-only audit sink** load-bearing for **revocation completeness** (§7.6), not just audit. This is **not** the Postgres `auth_events` table (which is the untrusted server's own, forgeable mirror).

- Provision a genuinely independent **WORM store or SIEM** outside the app server's control, with **digest anchoring** (hash-chain the event/tombstone stream and publish/cross-store the head).
- The **anchored tombstone-chain head** that clients fetch to verify revocation completeness lives here. Its concrete client-facing interface is the subject of a separate spec (`docs/sink-interface.md`, to be written) and **must exist before coding revocation (Phase 5).**

---

## 3. What v1 does *not* build (deferred)

- **Mobile client** — out of scope; the §5 "mobile Argon2id floor" (R10) is dormant until a mobile client exists. Don't let the Argon2id wiring hard-code the desktop profile in a way that blocks a future mobile profile.
- **Recovery-key Shamir/threshold split, PQ-hybrid wrap, key-transparency log** — Phase 7 (§17/§19). **Code now so these aren't wire-format changes later:** keep the `alg` identifier threaded through every record (no hard-coded suite), and model the **recovery recipient as an abstraction that can become K-of-N** rather than a single fixed key.

---

## 4. Pre-coding checklist (derived from the above)

1. ✅ Canonical encoding chosen — explicit length-prefixed binary; spec in `docs/encoding-spec.md`.
2. ☐ Stand up the **external sink** + define `docs/sink-interface.md` (anchored-head fetch/verify) — blocks Phase 5.
3. ☐ Settle the **large-file streaming-decrypt** pipeline shape (§1.4) — blocks Phase 3 file I/O.
4. ☐ Confirm operational prerequisites exist: air-gapped machine, reproducible-build + Authenticode pipeline, WORM/SIEM sink.
5. ☐ Lock remaining product scope that changes the schema: write delegation (DESIGN review item #6); single-device confirmed (D4).
6. ☐ External cryptographer review of the protocol before/while building the core.
