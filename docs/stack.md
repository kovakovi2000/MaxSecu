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
| Blob storage | **Dropbox (2 TB) backing + local LRU/LFU cache** | Bounds server disk; both tiers ciphertext-only (D31) |
| Media pipeline | **client-side ffmpeg + image libs in an OS sandbox** | Transcode/thumbnail/preview before encryption; decode shared media safely (D30) |
| Compression | **client-side, per-file, selective (zstd)** | Text yes, already-compressed media no; size side-channel accepted (D32) |
| Listing | **server-visible `file_type` + stream structure; values encrypted** | Browse by decrypted title/thumbnail without the full file (D35) |
| Tor (optional) | **`arti-client`; fail-closed; onion service** | Hide client IP from server/Dropbox; forces server-proxy (D34) |
| Canonical encoder | **One Rust implementation** (`docs/encoding-spec.md`) | Single client platform ⇒ one encoder; server stores opaque bytes |
| Air-gapped tooling | **Rust CLI binaries** sharing the client core crates | Ceremony tools are security-critical software (§12.1, §12.7) |
| TLS | **rustls** | TLS 1.3 + keying-material exporter for channel binding (§9.2) |
| Server packaging | **single signed static binary** or one `docker-compose.yml`; one-line bootstrap | Secret-free server (`DESIGN.md` §4.3) ⇒ low installer bar; secrets injected at runtime (§5.1) |
| Client packaging | **portable, no-install** (pendrive-friendly); password-derived at-rest state | No machine-bound keystore; plaintext never on disk except explicit export (§5.2 / `DESIGN.md` §8.1) |

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
| TLS 1.3 + channel binding | `rustls` + `tokio-rustls` (provider: **`aws-lc-rs`**) | `export_keying_material` (RFC 5705) feeds the §9.2 auth challenge; TLS 1.3 only (no `tls12` feature). Provider note below |
| Post-quantum (Phase 7) | `ml-kem` (RustCrypto) | Behind the `alg` registry; not in v1 (§5/D20) |

> **Pin and audit (D1/§8 supply chain).** Lockfile with hashes, `cargo audit`/`cargo deny` in CI, pinned toolchain. No `build.rs` network access. Vendoring dependencies is acceptable for the air-gapped tooling.

> **TLS crypto provider — the one sanctioned exception to "pure-Rust, single ecosystem."** rustls requires a `CryptoProvider`; the only pure-Rust one (`rustls-rustcrypto`) is pre-1.0 alpha, so the v1 server uses **`aws-lc-rs`** (chosen on **runtime speed** — the fastest rustls backend on the bulk-AEAD path that the §2.4/D31 blob proxy exercises). This is a **deliberate, narrow carve-out**, not a loosening of the app-layer TCB: (1) the application's confidentiality/integrity TCB — every key, wrap, signature, manifest and AEAD over *file data* — stays 100% RustCrypto + dalek (table above); TLS is the **transport**, not the zero-knowledge boundary (the server holds no decryption key regardless, §4.3). (2) The security-relevant output of the provider here is the **RFC 5705 exporter** (channel binding, §9.2) plus server-identity pinning — not data confidentiality. (3) `deny.toml` still **bans `ring`/`openssl`** (the accidental-second-stack guard); `aws-lc-rs` is the *only* non-RustCrypto crypto crate, admitted on purpose for TLS alone, and its license clears the allow-list. (4) It builds with **no extra toolchain** (no cmake/NASM on PATH) on both Linux (prod) and Windows MSVC, so the loopback channel-binding test runs on both. Revisit if `rustls-rustcrypto` reaches a stable release (would restore a fully pure-Rust graph) or if a FIPS posture is ever required (aws-lc-rs already supports it).

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

### 1.7 Media pipeline & decode sandbox (D30 — the biggest new attack surface)

All content understanding is **client-side** (the server has no key). Two activities, both touching plaintext:

- **At upload (author's own content):** transcode video to the canonical format, render the `thumbnail`, cut the `preview`, and compress text — then encrypt each as a stream (§13/D33). Tools: **ffmpeg/libav** (via `ffmpeg-sidecar` or a vendored libav binding) for video; an image library (`image` crate, or libvips for speed) for thumbnails; **`zstd`** for selective compression.
  - **Build status (Phase 4b, P4b.5):** the pipeline is a `Transcoder` seam (`client-core::media`). The **image path is built and real, in pure Rust** — the `image` crate (png/jpeg only, `default-features = false`, **no C**), canonical image format **PNG** (lossless; already-PNG sources are stream-copied), with aspect-preserving thumbnail/preview and a pre-decode dimension/pixel **bomb guard** (`MediaBounds`). The **video path (`FfmpegVideo`) is deferred behind the trait** — it returns `CodecUnavailable` until a sandboxed ffmpeg/dav1d transcoder is ratified as a C carve-out (the only sanctioned C so far is `aws-lc-rs`). So the no-C posture holds and a transcoded **image** upload already round-trips and renders (the §17 gate, via the image path).
- **At view (someone *else's* shared media):** decode `content`/`thumbnail`/`preview` to render. **This decodes attacker-authored bytes in complex C codecs — the system's top RCE risk.**

> **Mandatory sandbox.** Media decode/transcode runs in a **separate worker process** with **no network, no access to keys/the directory, a restricted token + Job Object, and ideally a Windows AppContainer**. The worker is handed only the decrypted media bytes and returns only decoded frames/clips over IPC; a decoder 0-day is then contained to a process that holds no secrets and cannot exfiltrate. Enforce **dimension/duration/size caps before allocation**, keep ffmpeg patched, and prefer memory-safe decoders where they exist. The main (key-holding) process never links ffmpeg directly. Treat this worker as **untrusted output** — validate decoded dimensions/format before use. This is `DESIGN.md` §8.1 / threat-model row "Malicious author's media → viewer's decoder".

> **"Quality-preserving" transcode** is usually impossible on re-encode. Prefer **remux / stream-copy** (container normalize, no re-encode, no loss) when the source codec is already acceptable; otherwise a visually-lossless high-bitrate encode. Less processing = smaller plaintext-handling window and less decoder surface.

> **Single-format playback shrinks the surface.** Because the uploader converts to **one canonical format**, a *viewer* decodes only that format — so the playback path can ship a **single hardened/minimal decoder** instead of ffmpeg's whole demuxer set. The full transcoder is needed only at upload (author's own input). Both still run in the sandbox. The author also **previews the converted result in the same in-app player and confirms** before upload (D30).

### 1.8 Optional Tor transport (D34)

A client setting routes **all** connections over **Tor** for users who need network-location privacy.

- **Implementation: `arti-client`** (pure-Rust Tor, embeddable — no external `tor` daemon). All client HTTP goes through Arti; pinned-TLS (rustls) runs *inside* the tunnel, so server-identity verification (§9.2) is unchanged.
- **Strongest form: a server onion service (v3).** No exit node, the server's location is also hidden, and the client talks to the `.onion` directly (Arti onion-service support, or a C-tor hidden service fronting the app).
- **Fail closed.** With Tor enabled the client makes **no clearnet connection, ever** — if Tor is unavailable it **blocks** rather than falling back (a silent fallback would leak the IP).
- **Forces server-proxy (§2.4).** In Tor mode the client does **not** use direct Dropbox links (Dropbox blocks Tor exits, and it would expose access to a third party); all blobs come via the server/onion.
- **Honest scope:** Tor hides the client's **IP / network location and coarse timing** from the server and Dropbox. It does **not** hide the **application-level sharing graph** or the server-visible `file_type`/sizes — you still authenticate as your account, so the server knows *who does what*, just not *from where* (`DESIGN.md` §13/§15.3). Large media over Tor is slow — pairs with the whole-file-download decode path (§8.1).

---

## 2. Server: Linux, secret-free

### 2.1 Language is a free choice

Per §4.3 the server stores **inert records** and enforces only **coarse** authorization, rate-limiting, and serving — it holds **no** file-decryption secrets and performs **no** security-critical cryptography (clients do all verification). Therefore the server language is driven by team familiarity, not security.

- **Recommended: Rust** (shares record types + the canonical-encoder crate with the client; one codebase for the wire format) — *or* **Go** (fast to build services, fine here). Either is acceptable.
- The server **may** sanity-check signatures for early rejection, but must never be *relied upon* to — every guarantee is re-checked client-side (§10).

### 2.2 Data + blobs

- **PostgreSQL** for the small relational records of §11 — `users` (+ retained `directory_bindings`), `files`/`file_versions`/`file_streams`, `file_key_wraps`, `file_genesis`, the unified append-only **`control_log`** (revocation + reinstatement + key-compromise as **one** hash chain), the `auth_events` mirror, and the Phase-1 ephemeral `auth_nonces`/`sessions`/`enrollment_vouchers`. **Authoritative DDL: `docs/schema.sql`.** *No `write_grants`* — write is owner-only (D29). DB constraints/triggers enforce the append-only/monotonic invariants (no-update/delete on `control_log`/`file_genesis`, hash-chain `prev_head` linkage, one-genesis-per-file, unique `(file_id,version,recipient)`).
- **Chunked ciphertext blobs** go to the **Dropbox backing tier + local cache** (§2.4), not a general object store, referenced by `files.blob_ref` (a logical id resolved to cache path or Dropbox path).
- **TLS 1.3** terminated by the app (rustls) with the client pinning the server identity (§9.2); the keying-material exporter binds the auth challenge and session token to the channel.

### 2.3 The external append-only sink is a *separate, real* dependency

`DESIGN.md` §16.5 + the simplification pass make the **external, append-only audit sink** load-bearing for **revocation completeness** (§7.6), not just audit. This is **not** the Postgres `auth_events` table (which is the untrusted server's own, forgeable mirror).

- Provision a genuinely independent **WORM store or SIEM** outside the app server's control, with **digest anchoring** (hash-chain the event/tombstone stream and publish/cross-store the head).
- The **anchored tombstone-chain head** that clients fetch to verify revocation completeness lives here. Its concrete client-facing interface is specified in `docs/sink-interface.md` (**must exist before coding revocation, Phase 5** — spec done; standing up the sink infra remains).

### 2.4 Blob storage tiering — Dropbox backing + local cache (D31)

Large ciphertext blobs (the chunked `content`/`thumbnail`/`preview` streams) are **not** kept on the server long-term:

- **Backing tier: Dropbox (2 TB).** Durable store of inert ciphertext. The server holds the Dropbox API token (a high-value **availability** secret — see risks); use a **scoped/app-folder token**, store it in a secret manager, never in code/env-in-image (§16.6).
- **Cache tier: server local disk (50–100 GB), LRU/LFU.** On a cache miss the server pulls from Dropbox, **reports progress to the client**, and relays. Evict oldest-accessed / least-requested.
- **Server-proxy is the default; direct client↔Dropbox is *optional* (D31).** By default the client only ever talks to the server, which relays blob bytes — so the client never contacts a third party. As a bandwidth optimization the server *may* broker a **short-lived, scoped, read-only link** (Dropbox temporary link) for a large blob so the client downloads it directly; the client can **disable** this, and **Tor mode forces proxy** (§1.8). Either way the client **verifies every byte** against the signed manifest + per-chunk AEAD tags (§12.3/§12.10); the master token is never given to the client.
- **Listing index (D35).** The server indexes each file's authenticated **`file_type`** (from the manifest) + small-stream **structure**/sizes to serve a browsable listing; **values stay encrypted** (the client decrypts the small `title`/`thumbnail` streams to render). The server can sort/filter only on `file_type`/size/time, never on content.
- **No dedup.** Per-file random DEKs ⇒ identical plaintext yields different ciphertext, so cross-user dedup is impossible (good for privacy, costs storage — size the Dropbox tier accordingly).
- **Small records stay in Postgres** (manifests, wraps, grants, tombstones, directory) — never in Dropbox.

> **Security note carried into `DESIGN.md`:** Dropbox is in the **untrusted** zone (D31). It cannot read files (ciphertext only) and cannot feed bad bytes undetected (AEAD + manifest). Residuals: a **second metadata observer** (sizes/timing/access) and a **second, independent availability dependency** (the Dropbox account). **Mass-delete is *not* a new risk** — a compromised operator could always destroy stored data, server or Dropbox alike; durability rests on the storage tier either way, so plan an independent ciphertext backup regardless. Secure the token (scoped/app-folder, secret manager, never in image env, §16.6). Crates: `dropbox-sdk` (or raw HTTP v2) on the server; client uses `reqwest` + `rustls` (over Tor when enabled) for any direct fetch.

### 2.5 Compression (D32)

Client-side, **before** encryption, **per file, no shared dictionary**: `zstd` for text/blog bodies; **skip** already-compressed media (transcoded video, JPEG). The chosen algorithm id rides **inside the signed manifest** (per stream) so it is authenticated. Accept the static size side-channel (folded into the disclosed size residual, `DESIGN.md` §13/§15.2); optional padding/bucketing is the future mitigation.

> **Codec status (Phase 3): DEFERRED — manifest wired to `none`.** The per-stream `compression` id is plumbed through the signed manifest end-to-end, but the only value emitted today is `none` (the downloader rejects a `zstd` stream as `CompressionUnsupported`). Reason: there is **no mature pure-Rust zstd *encoder*** — `ruzstd` (0.8.x) is **decode-only**, and the pure-Rust encoders (`rust-zstd` 0.1.0, `zstd-pure-rs` 0.1.2, `structured-zstd` 0.0.x) are brand-new and unvetted. The mainstream `zstd` crate is a **C** (`libzstd`/`zstd-sys`+`cc`) binding, which would breach the no-C posture that keeps the client TCB pure-Rust beside the single deliberate `aws-lc-rs` carve-out (§1.3 / `deny.toml` bans `ring`/`openssl`). Because compression is **security-irrelevant** here (only the authenticated algorithm id matters; decompression is deterministic regardless of compressor effort, `parameters.md` §1.4), deferring costs only space, not confidentiality/integrity. **Revisit** when a vetted pure-Rust zstd encoder is available, or on an explicit decision to accept a documented C-`libzstd` carve-out.

---

## 3. What v1 does *not* build (deferred)

- **Mobile client** — out of scope; the §5 "mobile Argon2id floor" (R10) is dormant until a mobile client exists. Don't let the Argon2id wiring hard-code the desktop profile in a way that blocks a future mobile profile.
- **Recovery-key Shamir/threshold split, PQ-hybrid wrap, key-transparency log** — Phase 7 (§17/§19). **Code now so these aren't wire-format changes later:** keep the `alg` identifier threaded through every record (no hard-coded suite), and model the **recovery recipient as an abstraction that can become K-of-N** rather than a single fixed key.

---

## 4. Pre-coding checklist (derived from the above)

1. ✅ Canonical encoding chosen — explicit length-prefixed binary; spec in `docs/encoding-spec.md`.
2. ✅ Write model — **owner-only write** (D29); `write_grants` not built.
3. ✅ Large-file handling — **user RAM budget; warned disk-unlock past it** (D12/§8.1); no server-side size limit.
4. **Spec ✅ / infra ☐** — `docs/sink-interface.md` defines the anchored-head fetch/verify; **standing up the external sink** (independent WORM/SIEM) remains. Blocks Phase 5.
5. ✅ **Defined** — `docs/api.md` (RPC contract, chunk up/download, session tokens) + `docs/schema.sql` + `docs/parameters.md` (sink-head refresh cadence pinned = revocation bound). **Phase 1 unblocked.**
6. **Spec ✅ / build ☐** — `docs/media-sandbox.md` fixes the isolation model, pre-decode bounds, and canonical format; **building + fuzzing the AppContainer worker** (top RCE risk) remains. Blocks Phase 4b.
7. ☐ Stand up the **Dropbox tier + cache + scoped-link brokering** (§2.4); secure the Dropbox token; plan independent ciphertext backup (availability/DR).
8. ☐ Confirm operational prerequisites: air-gapped machine, reproducible-build + Authenticode pipeline, WORM/SIEM sink, Dropbox app account.
9. ☐ Confirm single-device (D4).
10. ☐ External cryptographer review of the protocol before/while building the core.

---

## 5. Deployment & packaging

### 5.1 Server — one-file / one-line install (secret-free ⇒ low bar)

Because the server holds no file-confidentiality secret (`DESIGN.md` §4.3), the installer bar is operational, not cryptographic. v1 ships **one** of:

- a **single static Rust binary** (`x86_64-unknown-linux-musl`) that embeds the SQL migrations (`docs/schema.sql`) and self-applies them on first run, behind a one-line pinned bootstrap; **or**
- a single **`docker-compose.yml`** bundling the server + PostgreSQL → `docker compose up -d`.

Constraints either way:

- **Secrets are injected at runtime, never baked in.** The Dropbox scoped token and the sink-write credentials are availability/integrity secrets (§2.4, `DESIGN.md` §16.6) — pass them by env / secret-manager reference, never in the binary, image, or compose file.
- **Pin + verify the installer artifact** (publish a checksum/signature) — a `curl | sh`-style one-liner is itself MITM-able.
- The one-liner still expects to reach: **PostgreSQL** (bundled in the compose form), the **external sink** (`docs/sink-interface.md`), and a **TLS certificate** for the pinned server identity (`DESIGN.md` §9.2).

### 5.2 Client — portable, no-install (runs from a pendrive)

The Windows client (§1) is a **portable, single Authenticode-signed `.exe`** — no installer, no registry writes; its state lives **beside the executable** (e.g. on the pendrive) and, per `DESIGN.md` §8.1, is **ciphertext-only** (`local_key_blob`, the trust-on-last-use store). Portability forces two refinements:

- **At-rest state is password-derived, not machine-bound.** `DESIGN.md` §8.1 permits tying the local state key to the OS secure keystore (DPAPI/TPM), but those are machine-bound and don't travel. In **portable mode the at-rest key derives from the password (Argon2id)** so the encrypted state moves with the stick. Session tokens are ephemeral + channel-bound (`DESIGN.md` §9.2), so a new host simply re-authenticates — nothing token-shaped persists portably.
- **The pendrive is "disk."** The §8.1 rule applies to it unchanged: only **ciphertext** is ever staged there; **plaintext never lands on it** except the explicit, warned **"Save unlocked"** export the user browses to. Large media is viewed via **decrypt-while-play** (`DESIGN.md` §8.1/§12.10) — a bounded RAM window — so even multi-GB files leave no plaintext on the drive.

Two things portability does **not** change:

- **Code-signing still applies** (§1.5): the `.exe` is Authenticode-signed and the OS verifies it on launch (D1); updates replace the signed exe (fits in-person delivery).
- **Endpoint trust is still assumed (honest caveat).** Running portably on an **untrusted/borrowed host** widens exposure — that machine's keylogger / RAM scraper / pagefile is outside the client's control. `VirtualLock` + crash-dump-off protect the secret pages, but a compromised *running* host is the assumed-trusted endpoint limit (`DESIGN.md` §15.3). A pendrive client is **not** a safe-on-a-public-terminal guarantee.
