# MaxSecu — Zero-Knowledge File Storage

## System Design & Build Plan

**Status:** Design (pre-implementation)
**Supersedes:** an earlier design narrative (removed; this document is self-contained)
**Design name:** Per-file envelope encryption with per-recipient key wrapping, an authenticated (signed) key directory, an offline recovery key, and native end-to-end-encrypting clients.

This document is the authoritative, self-contained design and build plan. It folds in the first-pass security review of the original design narrative and records the decisions taken to close every open concern.

---

## 0. How to read this document

- **§1–§4** establish goals, the decision log, the threat model, and the high-level architecture.
- **§5–§9** specify the security-critical machinery: cryptographic primitives, the key hierarchy and custody, the **signed key directory** (the heart of the confidentiality guarantee), the client-integrity model, and identity/authentication.
- **§10–§14** specify the data model and every protocol flow, including large-file handling, metadata protection, and revocation.
- **§15–§17** cover security properties (including honest residual limitations), operations, and the phased build plan.
- **§18 (traceability matrix)** maps every review finding to the section that resolves it. If you only read one table, read that one.

Defined terms: **DEK** = per-file Data Encryption Key (symmetric). **Wrap** = a DEK encrypted to one recipient's public key. **Directory** = the authenticated mapping of username → public keys. **Recovery key** = the offline asymmetric key that can re-derive any file's DEK. **Signing key** = the offline key that signs directory entries.

---

## 1. Goals and non-goals

### 1.1 Hard requirements

1. The server stores file data **only as ciphertext**.
2. The server stores **no key that, by itself, decrypts a file**.
3. Decryption happens **only on the client**.
4. Access to a file can be granted to additional users **after** upload.
5. Access can be revoked.
6. **No standing re-grant capability lives on the server.** Re-granting a file that *no current user can already read* requires the **offline** recovery key (removable device / "pendrive", §12.7). Current recipients may re-share files they already hold — online and audited (§12.4b, D11) — since that grants nothing they couldn't pass on out of band.
7. Users log in with **username + password only** — no carried hardware token or key file.

### 1.2 Non-goals

- It does **not** claw back data a user already downloaded and decrypted (impossible; see §14.1).
- It does **not** use a single global key that decrypts every file (rejected; see §6.2).
- It does **not** require trusting the server with file confidentiality — **provided** the client-integrity (§8) and key-authenticity (§7) controls are in place. These two controls are what make the "honest server is not required for confidentiality" claim *true* rather than aspirational.
- It does **not** (in v1) hide metadata that is structurally visible to the server: ciphertext **sizes**, **timing**, and the **sharing graph** (who can access what). Filenames and file attributes *are* hidden (§13). See §15.2 for the honest boundary of the "zero-knowledge" label.

### 1.3 Product constraints driving the design

- **Native desktop + mobile clients only** (no browser client in v1). This is a deliberate security decision (§8): it keeps the server out of the client's trusted computing base.
- **Single-device identity:** a user's private key is generated on, and never leaves, their device. Moving devices is a re-enrollment + recovery operation (§12.6), not a sync.
- **Plaintext stays in memory:** decrypted files and keys live only in RAM; nothing decrypted is written to disk, swap, or temp storage except by an explicit, warned user export (§8.1).
- **In-person operations:** clients are delivered in person, and enrollment is approved in person by confirming a key fingerprint (§12.1). This is a small, closed deployment, not an app-store-scale product.

---

## 2. Decision log

Every entry below was an open question in the review; the chosen option and its rationale are recorded so future readers know *why*, not just *what*.

| # | Decision point | Choice | Rationale | Residual risk (see §15.3) |
|---|---|---|---|---|
| D1 | Client platform / code integrity | **Native desktop + mobile**, code-signed, reproducible builds | Keeps the server out of the client TCB; makes "confidential even under server compromise" actually hold | Malicious **software update** is the remaining code-integrity vector → mitigated by signed + reproducible + transparency-logged builds (§8) |
| D2 | Authentication & private-key protection | **Approach A:** random keypair encrypted under `Argon2id(password)` | Simpler than OPAQUE, mature libraries; combined with D4 it removes the server-side blob entirely | Local encrypted key is an offline target **only if the device is stolen** |
| D3 | Public-key authenticity (review **C1**) | **Recovery/admin-signed key directory** | Reuses the offline trust root the system already has; server cannot forge bindings | Directory equivocation is prevented by signature, not (yet) by transparency — see §18/future |
| D4 | Multi-device / key custody | **Single-device; private key never leaves the device** | Strongest secrecy; with D2 the server stores only public material | Device loss ⇒ user-key loss ⇒ requires re-grant to a new key (§12.6) — online if another recipient remains, else the offline recovery key |
| D5 | Directory-signing key custody | **Dedicated offline signing key**, batched enrollment ceremonies | Maximum protection of the binding root; the server can never sign | Enrollment is **not instant**; new users wait for the next signing ceremony (§12.1) |
| D6 | Recovery key custody | **Single offline device** | Operationally simplest | **Single point of theft *and* loss** — strongly mitigated by a sealed encrypted backup (§16.3); Shamir split is the recommended future upgrade |
| D7 | Metadata exposure | **Encrypt filenames + attributes** client-side | Reasonable privacy/complexity balance | Sizes, timing, sharing graph still visible (§13, §15.2) |
| D8 | Strong-revoke rotation timing | **Lazy** (rotate DEK on next write) | Cheap; the revoked user only retains the version they already had | A strong-revoked user can read the *current* version until it next changes (§14.4) |
| D9 | In-person identity proofing | Approve the **public-key fingerprint** in person — *not* the `user_id` | The `user_id`→key mapping is asserted by the untrusted server; only a fingerprint shown from the user's own device binds the human to the actual key (§7.1, §12.1) | A careless admin who signs without truly matching the fingerprint reintroduces the MITM |
| D10 | Rollback / freshness | Client **trust-on-last-use memory for both file `version` and binding `key_version`** + **short-epoch (12 h) re-attested status bindings** | Detects stale-but-signed file versions and stale revocation/key bindings without bringing the signing key online on demand (§7.5) | A never-before-seen file can't be range-checked by memory alone; bounded by the binding epoch |
| D11 | Re-sharing / delegation | **Any current recipient can grant any directory-verified user — no recovery key** | A recipient already holds the DEK; in-system sharing is strictly better than out-of-band because it is **tracked** (§12.4) | Cannot stop a determined recipient from leaking content out of band (inherent endpoint trust) |
| D12 | Client plaintext handling | **In-memory only**; plaintext never persisted; explicit "Save to disk" carries an exposure warning | Minimizes the footprint/lifetime of decrypted data; keeps export a conscious, audited user choice (§8.1) | Once the user exports a file, it leaves the system's protection (by design, with warning) |
| D13 | Directory freshness vs offline-key exposure | **Split identity (offline-signed) from status (separate short-lived signer)** — OCSP-stapling | A 12 h freshness/revocation epoch (§7.5) without operating the air-gapped directory key twice a day | A compromised status signer can keep a revoked user `active` for ≤ one epoch (bounded, detectable); it cannot forge bindings (§7.6, §3.1) |
| D14 | D5-forgery mitigation (stolen signing key) | **Peer key pinning + warn-on-key-change**, plus an **emergency D5 rotation runbook** | Leverages the in-person deployment to make D5 advisory for verified pairs — a forged binding becomes a visible re-verify prompt, not a silent MITM — at near-zero infra cost | First-contact (never-met) pairs still rely on D5+D13 until the transparency log (§7.4); legit rotations cost a re-verification (§7.7, §16.4) |

**Applied without asking (clear best practice):** uploader-signed manifests (H1, §12.3), chunked/framed AEAD (M1, §12.3/§12.10), domain-separated channel-bound challenge + short-lived session token (H2, §9), single-use expiring nonces (L4, §9), per-record algorithm identifiers with a future X25519+ML-KEM hybrid wrap path (§5), schema fixes (L1/L3, §11).

---

## 3. Threat model

### 3.1 Adversaries and guarantees

| Adversary | Capability | Guarantee under this design |
|---|---|---|
| **Passive server compromise** (read DB + disk) | Read all ciphertext, all wraps, all public keys, all directory signatures, encrypted metadata | Cannot decrypt any file; cannot recover any private key or any plaintext DEK. Stolen data is inert. |
| **Active malicious server** (serves chosen bytes/records) | Substitute records, withhold records, attempt key substitution, replay old signed records | **Key substitution is blocked** by the signed directory (§7); **stale/rolled-back records are detected** (§7.5). The server can deny service, but cannot read files, impersonate a recipient, or pass off an old file version or directory binding as current. It **cannot** ship malicious client code (native clients, §8). |
| **Network attacker, passive** | Observe traffic | TLS protects transport; the auth proof is a fresh, channel-bound signature → not replayable. |
| **Network attacker, active / MITM** | Tamper, relay | TLS with client-verified server identity; per-chunk AEAD detects tampering; channel-bound challenge (§9) prevents relay. |
| **Stolen user device** | Holds the local encrypted private key + previously downloaded plaintext | Attacker must still defeat `Argon2id(password)` offline to use the key; already-downloaded plaintext is, by definition, already exposed. Remote wipe / re-enrollment is an operational response, not a cryptographic one. |
| **Stolen offline recovery device / cold copy (D6)** | Holds the recovery private key | Can decrypt **every** file uploaded so far (past + present) — the highest-value secret in the system. It is breakglass (used only when no current recipient remains, §12.7), so its risk is **physical custody of the cold copy**, not device/online security: sealed, dual-custody backup (§16.3), Shamir split planned (§19). Does **not** by itself grant identity forgery (that needs D5 **and** D13). |
| **Stolen offline signing device (D5)** | Holds the directory-signing key | **Alone cannot forge a usable binding** — a forged binding also needs a matching D13 status attestation (§7.6). Even **D5+D13** cannot *silently* MITM a pair that has verified in person (peer-pinning, §7.7); for never-verified pairs it can MITM **future** uploads until detected. Cannot decrypt already-uploaded files. Mitigated by air-gap, the D13 gate, peer-pinning (D14), and emergency rotation (§16.4). |
| **Compromised status signer (D13)** | Holds the lower-privilege status-signing key | **Cannot** forge username→key bindings, substitute keys, or read files. At worst keeps a revoked user `active` for ≤ one freshness epoch (bounded, detectable) or denies service by withholding attestations. Mitigated by routine rotation, anomaly alerts, and the monotonic `key_version` guard (§7.5/§7.6). |
| **Revoked user** | Keeps their private key + anything downloaded | Gets no new wraps (soft revoke); loses access to **future versions** (strong revoke, §14). Retains what they already downloaded. |
| **Malicious authorized client** | Is legitimately entitled to a file | Can always exfiltrate plaintext it is entitled to read. Out of scope for cryptography; endpoint trust is assumed (§15.3). |

> **Combined / co-located custody (M-5).** D5 and D6 may be kept on the same cold device or on two separate ones (§4.1, §6.1). Even if **co-located**, a single cold-vault theft yields only *decrypt-everything* (via D6) — **not** identity forgery, which additionally requires **D13** on the separately-housed status signer (§7.6). The catastrophic *decrypt-all **and** forge-future* union therefore needs the cold vault **plus** the D13 signer, not a single theft. D6's standalone power (decrypt all past/present files) is unavoidable and is bounded only by physical custody (§16.3) and the planned Shamir split (§19).

### 3.2 The offline-guessing reality

Because authentication ultimately rests on a password, an attacker who steals offline-guessable material can mount a dictionary attack. This design **minimizes** that material:

- The keypair is **random**, not password-derived, so a stolen **public key is not a password oracle**.
- Because of D4 (key stays local), the encrypted private key and its `Argon2id` salt/params are **not stored on the server at all** — so a server-only compromise yields **no** per-user offline-guessing target. The encrypted key becomes a target only if the **device** is stolen.

This is the single most important consequence of combining D2 + D4 and is why Approach A is acceptable here without OPAQUE.

---

## 4. Architecture overview

### 4.1 Components

- **Native client** (desktop + mobile): performs all cryptography — Argon2id, key generation, AEAD encrypt/decrypt, wrap/unwrap, manifest signing, directory verification. The only component that ever holds plaintext or private keys.
- **Application server / API:** stores and serves inert records (ciphertext, wraps, public keys, directory entries + signatures, encrypted metadata); enforces *coarse* authorization (who may request what) and serves the authenticated directory. It is **not** trusted for confidentiality.
- **Blob store:** holds large ciphertext objects (chunked); referenced by the `files` records.
- **Offline trust root (cold / air-gapped):** holds the **directory-signing key** (D5) and the **recovery key** (D6) — both **breakglass**, kept cold (sealed, dual-custody, §16.3) and brought out only for controlled ceremonies (§12.1) or last-resort recovery (§12.7). One device or two; even co-located, the *forge-future* power is **not** unlocked without the separately-housed D13 (§7.6, §3.1).
- **Status signer (hardened, not air-gapped):** holds the **status-signing key** (D13); runs a scheduled job re-issuing short-lived directory **status attestations** (§7.6). Lower privilege than the offline root — it cannot mint identity bindings.

### 4.2 Trust boundaries

```
 UNTRUSTED              SEMI-TRUSTED                     TRUSTED (offline)
 ┌──────────────┐  TLS  ┌─────────────────────────┐     ┌────────────────────────────┐
 │ Network /    │◀─────▶│ App server + blob store  │     │ Air-gapped trust root      │
 │ active MITM  │       │  - serves ciphertext     │     │  - directory-signing key   │
 └──────────────┘       │  - serves wraps          │     │      (Ed25519, D5)         │
                        │  - serves SIGNED dir     │     │  - recovery key            │
 ┌──────────────┐       │  - coarse authz          │     │      (X25519, D6)          │
 │ Native client│◀─────▶│  - CANNOT read files     │     └────────────────────────────┘
 │ (TRUSTED for │  TLS  └─────────────────────────┘            ▲  manual ceremony
 │  its user)   │                  ▲  manual ceremony          │  (§12.1 sign,
 │ - all crypto │                  └───────────────────────────┘   §12.7 recover)
 │ - holds keys │
 └──────────────┘   Confidentiality depends on: (a) client integrity (§8),
                                                 (b) directory authenticity (§7).
                    It does NOT depend on the server behaving honestly.
```

The ceremony arrows are **manual, air-gapped transfers**, not live network links.

### 4.3 The core invariant

> Every record the server stores is one of: ciphertext, a public key, a directory signature, a wrapped DEK, or encrypted metadata. **No combination of stored records lets the server decrypt a file.** Decryption requires a user's password-unlocked private key (never on the server) **or** the recovery key (offline).

---

## 5. Cryptographic primitives

Standards-aligned choices. Every stored cryptographic record carries an **algorithm identifier** so primitives can be migrated (algorithm agility).

| Purpose | Primitive | Notes |
|---|---|---|
| File content encryption (AEAD) | **AES-256-GCM**, chunked/framed (§12.10) | 96-bit deterministic counter nonce *per file-version DEK*; 128-bit tag; per-chunk AAD binds index + last-chunk flag. Never reuse a (key, nonce). |
| Key wrapping (DEK → recipient) | **HPKE (RFC 9180)**, X25519 + HKDF-SHA256 + AES-256-GCM, **Auth mode** where uploader provenance is wanted | Wraps the DEK to a recipient public key. Auth mode additionally authenticates the sender (complements §12.3 manifest signing). |
| User encryption keypair | **X25519** | Used only to unwrap DEKs. |
| User signing keypair | **Ed25519** | Used for challenge-response (§9) and manifest signing (§12.3). Distinct from the X25519 key. |
| Directory-signing key (D5) | **Ed25519** (offline) | Signs long-lived identity bindings (§7.1). |
| Status-signing key (D13) | **Ed25519** (HSM / hardened, not air-gapped) | Signs short-lived directory status attestations (§7.6); cannot mint identity bindings. |
| Recovery key (D6) | **X25519** (offline) | A standing recipient on every file (§6.3). |
| Password KDF | **Argon2id (RFC 9106)**, unique per-user salt | Floor: `m ≥ 19 MiB, t ≥ 2, p = 1` (OWASP). Target on desktop: `m = 256 MiB, t = 3, p = 1`, calibrated to ≈0.5–1 s; reduced profile on mobile. Full params stored **with the local key** (§11.1). |
| Hashing | **SHA-256** | Content/manifest digests, Merkle binding of chunks. |
| Transport | **TLS 1.3**, client verifies server identity; **channel binding** (exporter) fed into the auth challenge (§9) | |
| Post-quantum (future) | Hybrid **X25519 + ML-KEM-768** wrap via HPKE / CMS (RFC 9936, KEMRecipientInfo per RFC 9629) | Not in v1; enabled by algorithm agility. |

Citations verified: RFC 9180 (HPKE), RFC 9106 (Argon2), RFC 9629 (CMS KEMRecipientInfo), RFC 9936 (ML-KEM in CMS, 2026), NIST SP 800-38D (GCM), FIPS 203 (ML-KEM).

**Signature domain separation.** Every Ed25519 signature carries a unique, versioned context prefix — `"MaxSecu-auth-v1"` for the auth challenge (§9.2), `"MaxSecu-manifest-v1"` for the upload manifest (§12.3), and `"MaxSecu-dirbinding-v1"` for directory bindings (§7.1), plus `"MaxSecu-status-v1"` for status attestations (§7.6). The prefixes are distinct and none is a prefix of another, so a signature produced in one context cannot be reinterpreted as valid in another — even where the same `sig` key signs in more than one role (auth + manifest).

### 5.1 Algorithm migration & downgrade protection

Algorithm agility is only safe if the *client*, not the server, decides what is acceptable.

- **Allowlist + floor (mandatory).** Each client ships a hardcoded allowlist of accepted algorithms and a minimum-strength floor per purpose (content AEAD, wrap, signature, KDF), and **rejects any record whose `alg` is unknown or below the floor** — fail closed. The server-supplied `alg` only ever selects *among approved options*; it can never force a weak or unknown primitive. This is what prevents a downgrade attack. For files the `alg` sits inside the signed manifest (§12.3), so it cannot even be forged — only chosen from the approved set.
- **One "current" algorithm per purpose.** Exactly one algorithm per purpose is designated current; new uploads always use the current set.
- **Fleet currency while a migration is in progress.** Whenever records under more than one algorithm coexist, clients not on the build that produces the *current* algorithm show a **daily update reminder** to pull the fleet forward; after a published grace period, out-of-date clients may be blocked from *writing* (reading still works).
- **Lazy auto-migration on access.** A file still on a superseded algorithm is transparently re-encrypted to the current one the next time it is accessed by a capable client — reusing the lazy key-rotation machinery of §12.9 (fresh DEK, `version++`, re-wrap to the current recipients + recovery). The corpus migrates passively as files are touched, with no mass re-encryption project. A read-only recipient defers the migration to the next access by a recipient permitted to write.

---

## 6. Key hierarchy and the role of the recovery key

### 6.1 Hierarchy

```
Offline trust root
 ├── Directory-signing key (Ed25519)      → signs username→pubkey bindings (§7)
 └── Recovery key (X25519)                → standing recipient on every file (§6.3)
                                              │
 Per-file DEK (random, AES-256-GCM) ────────┤ encrypts file content (chunked)
                                              │ wrapped once per authorized user + once to recovery
                                              ▼
 Per-user keys (generated on device, never exported)
  ├── X25519 (unwrap DEKs)        ── stored on server: PUBLIC half only, directory-signed
  └── Ed25519 (auth + sign)       ── stored on server: PUBLIC half only, directory-signed
        encrypted private halves  ── stored ONLY on the user's device, under Argon2id(password)
```

> **Custody (M-5).** D5 and D6 are **breakglass** keys kept **cold** — their risk is physical custody of the cold copy, not online/device security (D6 is touched only for last-resort recovery, §12.7; D5 only at ceremonies). They may share one cold device or live on two; either way a single cold-vault theft does not unlock both *decrypt-everything* (D6) **and** *forge-future*, because forgery also needs **D13**, housed separately (§7.6). Sealed, dual-custody storage and the planned Shamir split protect the cold copy (§16.3, §19).

### 6.2 Why there is no global master *decrypt* key

Encrypting every file under one key and distributing that key to users is rejected: the first unwrap permanently hands a user the decryptor for everything. Per-file random DEKs bound the blast radius of any single key compromise to **one file**.

### 6.3 What the recovery key *is*

The recovery key is an asymmetric keypair whose **public** half is a standing recipient: at every upload, the client wraps the DEK to the recovery public key in addition to the human recipients. Its **private** half lives offline (D6) and is used only to re-derive a DEK during a grant-to-old-file (§12.7) or account recovery (§12.6). The server never holds it, and it is never the live decryptor for served files. Operationally it is a **breakglass admin identity**: its private half is handled exactly like any admin's local key — it stays on its offline device and never touches a networked machine — and every use is authenticated and audited like any privileged action. The *only* thing distinguishing it from a normal user is that it is a standing recipient on every file; that same exception is why its theft — which requires physical access to the offline device — recovers everything (§3.1, §15.3).

---

## 7. Public-key authenticity — the signed key directory (resolves C1)

This is the control that makes the confidentiality claim real. Without it, a malicious server could hand a uploading client an attacker's public key and silently receive a wrap it can decrypt.

### 7.1 The directory entry

For authenticity **and** freshness the directory uses **two signatures by two different keys**, so the high-value offline key is not exposed on a 12 h cadence (decision **D13**; mechanism in §7.6).

**Identity binding — long-lived, offline-signed (D5).** Produced only at the in-person ceremony (§12.1); changes only on enrollment or key rotation:

```
binding = {
  username,
  user_id,
  enc_pub      : X25519 public key,
  sig_pub      : Ed25519 public key,
  key_version  : integer,          // increments on rotation / re-enrollment
  roles        : set,              // {user} or {user, admin} — offline-signed capability (§10.1)
  not_before   : timestamp,
  not_after    : timestamp         // long validity (e.g. 1 year) — identity, not freshness
}
fingerprint = SHA-256( canonical(enc_pub ‖ sig_pub) )   // the human-checkable identity (§12.1)
directory_signature = Ed25519_sign( directory_signing_key, "MaxSecu-dirbinding-v1" ‖ canonical(binding) )
```

**Status attestation — short-lived, status-signer-signed (D13).** Re-issued frequently for every currently-valid user; a revoked or rotated-out user simply stops receiving one (§7.6):

```
status_attestation = {
  user_id,
  key_version,                                                            // must equal the binding's
  binding_digest : SHA-256("MaxSecu-dirbinding-v1" ‖ canonical(binding)), // pins this exact binding
  status         : active | suspended | revoked,
  not_after      : timestamp                                              // 12 h freshness epoch (§7.5)
}
status_signature = Ed25519_sign( status_signing_key, "MaxSecu-status-v1" ‖ canonical(status_attestation) )
```

The `directory_signature` is produced **only** by the offline directory-signing key (D5); the `status_signature` only by the separate, lower-privilege **status-signing key** (D13, §7.6). The server stores and serves `binding + directory_signature` plus the latest `status_attestation + status_signature`, but can forge neither.

The **`fingerprint`** is the value a human confirms in person at enrollment (§12.1). Because it is a hash of the *actual public keys*, confirming it binds the real person to the real key — unlike the `user_id`, which is just a handle the (untrusted) server assigned. Clients render the **full 256-bit** fingerprint as **base64** (≈43 characters) and/or a QR code; the entire value is compared, never a truncated prefix. Because base64 is case-sensitive, visual side-by-side or QR comparison is preferred over reading it aloud (D9).

### 7.2 Client verification rule (mandatory before any wrap)

Before a client wraps a DEK to any recipient (human or recovery), and before it trusts a manifest signature, it **must**:

1. Fetch the recipient's `binding + directory_signature`.
2. Also fetch the latest `status_attestation + status_signature` for this `user_id` (§7.6).
3. Verify `directory_signature` against the **pinned** directory-signing public key (§8), and `status_signature` against the **pinned** status-signing public key (§7.3).
4. Check the attestation refers to *this* binding: `status_attestation.key_version == binding.key_version` and `status_attestation.binding_digest == SHA-256("MaxSecu-dirbinding-v1" ‖ canonical(binding))`.
5. **Peer-pin check.** If this `user_id` has a locally **pinned** key from a prior in-person verification (§7.7), the binding's `enc_pub` / `sig_pub` **must equal the pin** — a mismatch is rejected and alerted (a verified peer's key cannot change without re-verification).
6. **Rollback + key-change check** against the client's trust-on-last-use record for this `user_id` (§7.5/§7.7): a **lower** `key_version` is **rejected** (rollback); the **same** `key_version` with the same keys proceeds; a **higher** `key_version` or changed keys is **not silently accepted** — the client warns *"this user's key changed — re-verify out of band"* and **blocks new wraps until the new fingerprint is confirmed**, then updates the pin/record.
7. Check `binding.not_before <= now <= binding.not_after` (identity validity), `status == active`, and `now <= status_attestation.not_after` — **reject if expired or not active** (§7.5/§7.6). Only then use `enc_pub` / `sig_pub`.

A binding that fails verification is treated as **absent** (fail closed). The recovery public key is itself a directory entry and is verified the same way — the server cannot substitute the recovery recipient either.

### 7.3 Trust root pinning

The directory-signing **public** key is compiled into the signed client binary (§8) and may be cross-published (e.g., on the vendor site, in release notes) so users and auditors can confirm it out of band. The **status-signing public key** (D13, §7.6) is pinned the same way. Rotating either key (§16.4) ships in a new signed client release that pins both old and new keys during an overlap window.

### 7.4 Residual: equivocation

A signed directory stops *forgery* but not *equivocation* (showing different valid bindings to different users) if the **signing key itself** is compromised. The defenses are: air-gapped signing (D5/§12.1), signing-key rotation, **peer key pinning** (§7.7) — which removes D5 from the trust path entirely for any pair that has verified in person, so a compromised D5 cannot touch an already-verified channel — and, for pairs that have *never* met, a future **key-transparency log** (append-only, auditable) so clients can detect split views (§18, future).

### 7.5 Freshness and rollback resistance (resolves the rollback gap, D10)

A signature proves a record is *authentic*, not that it is *current*. A malicious server can therefore replay an old but still-validly-signed record — a **rollback attack** — on two surfaces. Both are addressed without putting the offline signing key online on demand:

**Directory bindings (revocation / key-rotation freshness).** Two independent guards apply:

- **Monotonic `key_version` (clock-independent).** Each binding carries a monotonic `key_version` (§7.1). Each client keeps a local **trust-on-last-use** record of the highest `key_version` it has accepted per `user_id` and **rejects any binding with a lower `key_version`** — regardless of the local clock. A server that replays a superseded key binding is therefore detected even if the client's clock is wrong (§7.2 step 5).
- **Freshness epoch (clock-based).** Each binding also carries a `not_after` epoch. Current users are re-signed with a fresh epoch (default validity **12 hours**); a revoked or rotated-out user is simply **not** re-signed, so their old binding expires within one epoch. Clients reject expired bindings (§7.2 step 6, fail closed). This is the guard for the case the monotonic check cannot cover — revoking a user whose `key_version` has *not* changed — and it bounds revocation staleness to at most one epoch.

> **Operational consequence of a 12 h epoch.** A 12 h freshness window means current bindings must be re-attested at least every 12 h, or every user expires as a recipient. Re-attesting with the *offline directory-signing key* (D5) that often would expose the system's highest-value key far more than the batched enrollment ceremony intends. This is why freshness is **split from identity** (§7.6, **D13**): the offline key signs the long-lived **identity binding**, while a separate, lower-privilege **status-signing key** issues the 12 h status attestation on a frequent automated schedule. A compromised status signer can at worst keep a revoked user alive within one epoch — bounded, detectable, and still blocked by the monotonic `key_version` guard from pairing a stale status with a superseded key; it **cannot** forge a username→key binding.

**File versions.** The signed `manifest` (§12.3) carries a monotonic `version`. Each client keeps a small local **trust-on-last-use** record of the highest `version` (and its `content_digest`) it has seen per `file_id`, and **rejects any served version lower than the highest it has seen**. A server that rolls a file back to an earlier signed version is therefore detected on any client that saw the newer one.

**Residual.** Memory can't range-check a file the client has *never* seen (first contact); that case is still covered by manifest authenticity (uploader-signed) and by the recipient binding's epoch. Detecting a server that equivocates *consistently* to a client from day one remains the job of the future transparency log (§7.4). For this deployment's scale, last-use memory + epoch expiry is the proportionate answer.

### 7.6 Status-signing key and the identity/status split (resolves M-3)

A 12 h freshness epoch (§7.5) must not require operating the **offline** directory-signing key (D5) twice a day — that would expose the system's highest-value key far more than the in-person enrollment ceremony intends. Freshness is therefore delegated to a **separate, lower-privilege status-signing key** (D13), following the short-lived-certificate / OCSP-stapling pattern:

- **The offline directory key signs identity** — `username → (enc_pub, sig_pub, key_version, roles)` — rarely (enrollment / rotation only), at the air-gapped ceremony (§12.1), with long validity.
- **The status-signing key signs only freshness/status** of an *already* offline-signed binding (pinned by `binding_digest`): it can attest that an existing binding is current and `active` with a 12 h `not_after`, but **cannot mint or alter** a `username → key` binding.
- **Cadence:** a scheduled job re-issues a fresh `status_attestation` for every currently-valid user well inside the 12 h window (e.g., every 1–3 h). Revoking a user = stop issuing their attestation (or issue one with `status = revoked`); within one epoch every client rejects them (§7.5).
- **Custody:** because its compromise cannot forge identities, the status key may live in an HSM or a hardened, more-available signer rather than fully air-gapped — a deliberate privilege/availability trade-off. It is **never** on the application server.

**Compromised status signer — bounded.** It cannot forge a `username → key` binding, substitute a recipient key, or read any file (it never touches DEKs or private keys). At worst it keeps a revoked user `active` until its current epoch lapses (≤ one epoch, detectable in the audit log) or denies service by withholding attestations. The monotonic `key_version` guard (§7.5) still blocks pairing a stale status with a superseded key. Mitigations: routine status-key rotation (§16.4) and alerting on issuance outside the scheduled job (§16.5). The threat-model row is in §3.1.

### 7.7 Peer key pinning and key-change warnings (resolves the D5-forgery gap, D14)

The signed directory roots recipient trust in D5 (+ D13). A stolen **D5 + D13** could therefore sign a forged binding for a victim and MITM their *future* uploads. Because this deployment is small and **in-person**, that gap is closed by making D5 *advisory* rather than *final* for anyone two users have actually verified:

- **Pin on verification.** When a user confirms a peer's fingerprint in person (§7.1 / §12.1), the client **pins** that peer's `enc_pub` / `sig_pub` locally (stored as authenticated ciphertext, §8.1). For a pinned peer the pin is authoritative: any directory binding that disagrees is rejected and alerted (§7.2 step 5). **D5 is no longer in the trust path for that pair** — a forged binding cannot touch an already-verified channel.
- **Warn on key change.** For peers seen-but-not-pinned, the client remembers the last-accepted `key_version` / keys. A **lower** version is rejected as rollback (§7.5); an **unchanged** key proceeds; a **higher** version or changed key is treated as suspicious — the client shows *"this user's key changed — re-verify out of band"* and will **not** wrap new data to the new key until the fingerprint is re-confirmed (then it re-pins). Legitimate key rotations (§12.6, §16.4) are rare and are simply re-verified; a D5 forgery surfaces as exactly this prompt instead of a silent MITM.
- **First contact.** With no prior pin or record, the client trusts the directory binding (D5 + D13) for the first wrap and prompts for in-person verification when the pair can meet, pinning the key once confirmed. First contact is the only window a forged binding could slip through unseen — exactly what the future key-transparency log (§7.4) is meant to cover for pairs that never meet.

This converts D5 compromise from a *silent* MITM into a *visible, re-verifiable* event for every relationship that matters, at near-zero infrastructure cost. Emergency D5 rotation on detection is in §16.4.

---

## 8. Client integrity & data handling (resolves C2)

A zero-knowledge guarantee is only as strong as the code performing the crypto. Because clients are **native and code-signed** (D1), the server is **not** in a position to ship malicious crypto code — unlike a browser app, where the server/CDN serves the code on every load.

Controls:

1. **Native, code-signed apps.** Desktop and mobile builds are signed with the vendor's platform signing identity; the OS rejects tampered binaries.
2. **Reproducible builds.** Builds are deterministic from pinned sources + locked dependencies, so a third party can rebuild and confirm the published binary matches the published source.
3. **Pinned trust root.** The directory-signing public key (§7.3) and the server's expected TLS identity are pinned in the build.
4. **Signed, transparency-logged updates.** The remaining code-integrity vector is a **malicious update** (Decision D1 residual). Updates are signed; build provenance is published to an append-only transparency log so a targeted malicious update is detectable. Update signing keys are held offline.
5. **Dependency supply chain.** Lockfiles with hashes; pinned, audited dependencies; CI builds with least privilege.

> **Honest statement of the guarantee:** with native signed clients, confidentiality holds against a fully compromised *server*. It does **not** hold against a compromised *client build/update pipeline*; that pipeline is part of the TCB and is defended by signing + reproducibility + transparency, not by the server being honest.

> **Install bootstrap (resolves #5 for this deployment):** clients are delivered **in person**, which removes the "trust the first download" / MITM'd-installer vector without app-store machinery. Updates are likewise hand-delivered or signed (§8 control 4).

### 8.1 Plaintext handling — in-memory only (D12)

A hard client rule, independent of the code-integrity controls above. Decrypted data is the most valuable thing the client ever holds; its on-disk footprint must be **zero**.

- **Decrypted file content and DEKs live only in RAM.** They are never written to disk, swap, temp files, application caches, logs, crash/core dumps, or OS conveniences (thumbnail caches, "recent files", quarantine copies) in plaintext.
- **Transferred file ciphertext may be staged, and only transiently** — e.g., chunked ciphertext staged during an in-progress upload or download — and it is deleted as soon as the transfer completes.
- **Display and read happen from the in-memory buffer.** Viewers/players/previews render from RAM; the client does not hand a plaintext temp path to an external application.
- **Explicit export is a conscious, warned action.** "Save decrypted to disk" is *allowed* but must show a clear warning that the exported copy **leaves MaxSecu's protection** and becomes the user's responsibility; every export is recorded in the audit log (§16.5).
- **Persistent local state is ciphertext-only, mirroring the server invariant.** The few items the client must keep across restarts — the `local_key_blob` (§9.1) and the **trust-on-last-use store** (highest file `version`, per-user `key_version`, and in-person-pinned peer keys, §7.5/§7.7) — are stored as **authenticated ciphertext** (AES-256-GCM) under a key tied to the user's unlock or the OS secure keystore, never in cleartext; any other client state that must persist follows the same rule by default. *User data at rest is only ever encrypted — on the client as well as on the server.* For the rollback store the GCM tag doubles as its integrity guarantee: a local attacker cannot silently lower a remembered version without the unlock key (tampering fails closed). Wholesale *deletion* of the store reverts the affected files to first-contact handling, bounded by the binding epoch and manifest authenticity (§7.5) — the residual a purely local attacker leaves.
- **Zeroize on release.** DEKs, private keys, and plaintext buffers are wiped from memory the moment they are no longer needed, and on lock/logout. Where the platform allows, mark secret pages non-swappable (`mlock` / `VirtualLock`) and disable core dumps for the process.

This rule **shrinks the footprint and lifetime** of plaintext; it does not change the endpoint-trust limitation (§15.3): a compromised, *running* client with a file open can still read what is in memory. It is not a substitute for the user locking their device.

---

## 9. Identity and authentication

### 9.1 Registration (Approach A, local key)

On the user's device:

1. Generate a **random** X25519 keypair (`enc`) and a **random** Ed25519 keypair (`sig`). High entropy; not derived from the password.
2. Generate a per-user `salt`; choose Argon2id params (§5).
3. `pw_key = Argon2id(password, salt, params)`.
4. Encrypt the two **private** keys under `pw_key` with AES-256-GCM → `local_key_blob` (stored on **device only**).
5. Submit to the server for enrollment: `username, enc_pub, sig_pub` (public halves only); receive a `user_id` handle.
6. Compute and display the **key fingerprint** `SHA-256(enc_pub ‖ sig_pub)` as the full 256-bit value in base64 (and QR) (§7.1). The user presents this fingerprint at in-person approval (§12.1).
7. The binding is signed into the directory at the next offline ceremony **only after the admin confirms that fingerprint in person**. Until signed, the account exists and can authenticate to manage its own files, but is **not yet a valid recipient** for others.

The password and the private keys **never leave the device**. The server stores no salt, no params, no encrypted private key (a direct consequence of D4, and the reason H3's pre-auth-leakage concern does not apply here).

### 9.2 Login (challenge-response, channel-bound)

1. Client unlocks `local_key_blob` locally: re-derive `pw_key` from the entered password, AES-GCM-decrypt the private keys. (All offline, on device.)
2. Client opens TLS to the server (verifying the pinned server identity) and requests a challenge for `username`.
3. Server returns a **fresh, single-use, short-TTL nonce** (tracked server-side, default 60 s expiry).
4. Client signs a **domain-separated, channel-bound** message:
   `proof = Ed25519_sign( sig_priv, "MaxSecu-auth-v1" ‖ server_id ‖ tls_exporter ‖ nonce ‖ timestamp )`.
5. Server verifies `proof` against the `sig_pub` it holds on record for that `username`, checks nonce freshness/single-use and channel binding, then issues a **short-lived session token** bound to the TLS channel.
6. Subsequent requests present the session token; tokens are stored in the OS secure keystore, never persisted in plaintext, and expire / are revocable server-side.

Domain separation + channel binding prevent cross-protocol reuse and relay of the signature; single-use nonces prevent replay (resolves L4 and the channel-binding part of H2).

> **Self-login does not require directory verification.** The server verifies the *user against the key it stored*; if a malicious server swapped that `sig_pub`, the user's own genuine signature would fail to verify and login would break (a detectable denial, not a silent compromise). Directory verification (§7.2) is for the *opposite* direction — trusting **other** users as recipients/senders — so an account whose binding is not yet signed (§12.1) can still log in and manage its own files, but cannot yet be selected as a recipient by others.

### 9.3 Anti-automation (resolves H3 operationally)

- **Rate-limit and lock out** challenge issuance and proof attempts per account and per source.
- **No user-existence oracle:** issue a well-formed challenge for unknown usernames too (the proof simply never verifies), so timing/shape does not reveal account existence.
- **Audit-log** every auth attempt, success, denial, and lockout (§16.5).

### 9.4 Password policy (current guidance)

- **Minimum length 15**; allow long passphrases; allow all printable characters + spaces; support paste; generous maximum (≥ 64).
- **No forced composition rules.**
- **Block known-breached / common passwords** via a local blocklist check at set-time.
- Unique random salt per account (stored with the local key).

### 9.5 Password change

Changing the password re-derives `pw_key` and re-encrypts `local_key_blob` locally; the keypair itself is unchanged. Two rules apply:

- **Re-issue any exported backup.** An exported sealed backup of `local_key_blob` (§12.6) — and any OS- or file-level backup of it — was encrypted under the *old* password and stays openable with it. A password change does not reach those copies, so any such backup must be re-exported under the new password and the old copy destroyed; otherwise the old password still unlocks the old blob.
- **Make the re-encryption atomic, with fresh parameters.** `local_key_blob` is the only copy of the private key (D4); re-encrypting it in place can brick the account if interrupted (→ forces device-loss recovery, §12.6). Write the new blob and swap atomically, and generate a **fresh per-user salt** and re-tuned Argon2id params (§5) as part of the change.

---

## 10. Authorization model

- **Authentication** (§9): who is this, proven server-side by a channel-bound signature.
- **Authorization is per-file and lives in the wrap table** (§11.3): a user may access a file **iff** a wrap row exists for `(file_id, current file_version, that user_id)` **and** the user's `status == active`. There is no global "authorized users" set; the recipient set is chosen **explicitly per upload** by the uploader from directory-verified bindings (resolves L3).
- The server enforces *coarse* authorization (don't serve a wrap to someone with no row). This is a **defense-in-depth / availability** control, not the confidentiality boundary — even if the server mis-serves, a user without the matching private key cannot unwrap.
- **Re-sharing is delegated (D11):** any active user who already holds a wrap for a file may add a wrap for any other **directory-verified** active user (the online re-share path, §12.4b). The server accepts the new wrap row and records `granted_by` for the sharing-graph audit (§11.4). The server itself still **cannot** mint a usable wrap — that needs the plaintext DEK, which only a current recipient or the offline recovery key holds. (Restricting re-sharing further would be theater: a recipient can always pass the content out of band; doing it in-system at least makes it *tracked*.)
- **Every state-changing request** (upload, grant, revoke, rotate) re-checks the session and the caller's entitlement before any side effect; failures **fail closed** (deny) and are audit-logged.

### 10.1 Privileged (admin) operations (resolves M-4)

State-changing operations beyond a user's own files — soft/strong revoke of another user, triggering rotation, changing a user's server-side `status`, scheduling enrollment/recovery ceremonies, and publishing directory updates — require an **operator (admin) capability**, not mere authentication.

- **Rooted in the offline trust, not the server.** Admin capability is a `roles` entry in the user's **offline-signed identity binding** (§7.1). The server therefore **cannot promote anyone** (it can't forge the binding), so a compromised server cannot grant itself admin.
- **Authenticated like any user.** Admins prove identity with the same channel-bound challenge-response (§9.2); there is no separate password path.
- **Authorized per operation, server-side, fail closed.** Every privileged endpoint checks the caller's directory-verified `roles` (§7.2) before any side effect; absence or any verification failure ⇒ deny and audit.
- **Dual control for destructive / breakglass ops.** Mass revoke, key rotation, and any **recovery-key** use (the breakglass admin, §6.3 / §12.7) require **two distinct admins** to authorize, limiting a single rogue or compromised admin.
- **Accountable.** The audit log (§11.4, §16.5) binds `actor` to the authenticated admin identity for every privileged action — including ceremony fingerprint match/mismatch and recovery use.
- **Confidentiality is unaffected either way.** No admin action yields plaintext: decryption still needs a user's private key or the offline recovery key. The admin role governs **integrity, availability, and accountability**, not file confidentiality — a rogue admin can deny or disrupt, but cannot read files.

---

## 11. Server data model

All fields below are inert (ciphertext, public key, signature, wrapped key, or encrypted metadata).

### 11.1 `users`

| Field | Description |
|---|---|
| `user_id` | Stable identifier |
| `username` | Login name |
| `enc_pub` | X25519 public key (unwrap target) |
| `sig_pub` | Ed25519 public key (auth + manifest verify) |
| `key_version` | Increments on rotation / re-enrollment |
| `roles` | Offline-signed capability set, e.g. `{user}` or `{user, admin}` (§7.1, §10.1) |
| `directory_signature` | Ed25519 signature over the identity binding by the offline signing key (§7.1) |
| `status_attestation`, `status_signature` | Latest short-lived status attestation + its signature by the status signer (§7.6) — the **authoritative** status |
| `status` | Server-side coarse copy for serving decisions; the signed `status_attestation` is authoritative (§7.6) |
| `enrolled_at`, `signed_at` | Timestamps (`signed_at` null until the ceremony signs the binding) |

> Note (D4): there is **no** `salt`, `kdf_params`, or `encrypted_private_key` column. Those live only on the user's device (§9.1), which is what removes the server-side offline-guessing target (resolves L1 by eliminating the overloaded `verifier` column entirely).

### 11.2 `files`

| Field | Description |
|---|---|
| `file_id` | Stable identifier |
| `owner_id` | Uploader (for accountability; not a decryption capability) |
| `blob_ref` | Pointer to chunked ciphertext in the blob store |
| `chunk_size`, `chunk_count` | Framing parameters (§12.10) |
| `enc_metadata` | Client-encrypted filename + attributes (§13) |
| `manifest` | Signed manifest (§12.3): sizes, content digest, key commitment |
| `manifest_sig` | Uploader's Ed25519 signature over `manifest` |
| `alg` | Algorithm identifiers (content + framing) for agility |
| `version` | Increments on re-encryption / rotation |
| `created_at`, `updated_at` | Timestamps |

### 11.3 `file_key_wraps` — where access control lives

One row per `(file, version, recipient)`.

| Field | Description |
|---|---|
| `file_id` | The file |
| `file_version` | Which version this wrap unlocks |
| `recipient_id` | A `user_id`, or the special recovery recipient |
| `recipient_type` | `user` / `recovery` |
| `wrapped_dek` | DEK encrypted to the recipient's directory-verified `enc_pub` (HPKE) |
| `wrap_alg` | Wrapping algorithm identifier |
| `granted_by` | `user_id` (or `recovery`) that created this wrap — sharing-graph audit (§12.4b) |
| `created_at` | When the wrap was added |

> **Invariant restated:** the server can *delete* wraps (deny access / revoke) but cannot *create* a usable wrap for a new recipient — that needs the plaintext DEK, which requires either an authorized user's private key or the offline recovery key. So the server cannot grant itself or anyone else read access.

### 11.4 `auth_events` (audit)

Append-only: auth attempts, grants, revokes, rotations, ceremony actions — with actor, target, result, timestamp. No secrets or plaintext.

---

## 12. Protocol flows

### 12.1 Enrollment + offline signing ceremony (consequence of D5)

1. User registers (§9.1); server stores an **unsigned** `users` row (`status=active`, `signed_at=null`). The account can authenticate but is **not yet a valid recipient** (its binding is unsigned, so other clients reject it per §7.2).
2. The user presents their **key fingerprint** to the admin **in person** (D9) — compared visually on-screen or scanned by QR. The full base64 value is matched; because it is case-sensitive, visual/QR comparison is preferred over reading it aloud.
3. The admin runs a **signing ceremony** on the air-gapped device. For each pending binding, the admin's signing tool displays the fingerprint computed from the binding's `enc_pub`/`sig_pub`; the admin **signs only if it matches the fingerprint the person presented**. A mismatch means the server tampered with (or confused) the key — refuse and investigate. Short-lived 12 h **status attestations** are issued separately by the status signer on a frequent automated schedule, **not** at this air-gapped ceremony (§7.6); this ceremony only creates or rotates identity bindings.
4. Server publishes the now-signed bindings. Verified users become valid recipients.

> **Why the fingerprint, not the `user_id`:** the binding's public keys come from the (untrusted) server, so confirming only the `user_id` would let a malicious server slip in its own key under that id. Confirming the *fingerprint* — a hash of the actual keys, shown by the user's own client — is what binds the real human to the real key and makes C1 genuinely closed (D9).

> **Operational note:** enrollment is **not instant** (the accepted cost of D5). Communicate the signing cadence (e.g., daily) to users. Steps 2–3 are the human checkpoint against a server that tries to enroll or substitute bogus bindings.

### 12.2 File upload

1. Client generates a random per-file **DEK**.
2. Client encrypts content with **chunked AEAD** (§12.10) → chunked ciphertext + per-chunk tags.
3. Client encrypts filename/attributes → `enc_metadata` (§13).
4. Client selects the recipient set explicitly and **verifies every recipient's binding** against the directory (§7.2); always includes the **recovery** recipient.
5. For each recipient `R`: `wrapped_dek_R = HPKE-Wrap(R.enc_pub, DEK)`.
6. Client builds and **signs the manifest** (§12.3).
7. Client uploads: `files` row (+ `enc_metadata`, `manifest`, `manifest_sig`), the chunked ciphertext, and one `file_key_wraps` row per recipient (including recovery).
8. Client zeroizes the plaintext DEK.

### 12.3 Signed manifest (resolves H1 — uploader authenticity)

```
manifest = {
  file_id, version, alg, chunk_size, chunk_count,
  content_digest        : SHA-256 over the ordered per-chunk GCM tags,  // binds the whole ciphertext
  enc_metadata_digest   : SHA-256(enc_metadata),
  dek_commit            : SHA-256("MaxSecu-dek-commit-v1" ‖ DEK),       // binds the content key
  uploader_id, created_at
}
manifest_sig = Ed25519_sign(uploader.sig_priv, "MaxSecu-manifest-v1" ‖ canonical(manifest))
```

On download, the recipient verifies `manifest_sig` against the uploader's **directory-verified** `sig_pub`, then checks the actual chunk tags hash to `content_digest`. This authenticates **who** produced the file and detects server-side splicing of chunks across versions/files. (HPKE **Auth mode** in §5 provides a second, wrap-level provenance signal.)

`dek_commit` binds the content key itself. Any party that unwraps the DEK — a recipient on download (§12.5), a granter on re-share (§12.4b), or the admin on recovery (§12.7) — recomputes `SHA-256("MaxSecu-dek-commit-v1" ‖ DEK)` and **rejects the key unless it matches**, before relying on or re-wrapping it. Publishing the commitment leaks nothing: the DEK is a 256-bit random key, so its hash is neither invertible nor guessable (unlike a low-entropy password). This lets the uploader's own client self-check every wrap before upload, and lets a recovery or re-share party confirm it holds the *intended* key and cheaply detect a wrong wrap (a 32-byte hash check) without decrypting the whole file — distinguishing a bad wrap from corrupted ciphertext.

### 12.4 Grant access — the common cases (no recovery key needed)

**(a) At upload.** Include the new user in the recipient set (§12.2 step 4).

**(b) Re-share an already-uploaded file (online).** Any user who currently has access already holds the DEK (they can unwrap it), so they can extend access without any offline ceremony. To grant user `V`:

1. The granter's client fetches and **verifies `V`'s binding** against the directory (§7.2) — including the fingerprint-rooted signature and the freshness epoch.
2. The granter unwraps the current DEK with their own `enc_priv`.
3. The granter computes `wrapped_dek_V = HPKE-Wrap(V.enc_pub, DEK)`.
4. The granter uploads the new `file_key_wraps` row with `granted_by = granter_id`.

No recovery key, no admin. The server records who granted access to whom (§11.4). This is the everyday sharing path and is strictly better than out-of-band sharing because it is **tracked** (D11).

### 12.5 Download / decrypt

1. Authenticated client requests `file_id`.
2. Server checks authorization (§10) and returns the chunked ciphertext, `enc_metadata`, `manifest + manifest_sig`, and **only that user's** `wrapped_dek` (never another user's, never the recovery wrap).
3. Client **verifies the manifest** (§12.3) and the uploader binding (§7.2), and checks the manifest `version` against its **trust-on-last-use** record for this `file_id` — rejecting any version older than the highest already seen (§7.5).
4. Client unwraps the DEK with `enc_priv`, **checks `SHA-256("MaxSecu-dek-commit-v1" ‖ DEK)` equals the manifest `dek_commit`** (rejecting on mismatch), then decrypts chunks (verifying each tag and the framing, §12.10) and decrypts `enc_metadata`. Plaintext and the DEK stay **in memory only** (§8.1).
5. Any verification failure ⇒ reject and surface a sanitized error (§15).

### 12.6 Account recovery after device loss (consequence of D4)

Because the private key never leaves the device, losing the device loses the key. Recovery:

1. User re-enrolls on a new device → **new** random keypair → new binding signed in the next ceremony (§12.1), `key_version` incremented.
2. Re-grant each file the user was previously entitled to, against their **new** `enc_pub`:
   - For files that **still have another current recipient**, that recipient can re-wrap online (§12.4b) — no recovery key needed.
   - Only for files where **no current recipient remains** does an admin use the offline recovery key (§12.7).
3. User regains access.

> Optional self-recovery (does not violate D4): the client may let the user **explicitly export** a sealed backup of `local_key_blob` (still password-encrypted) to user-controlled storage. This is a deliberate, user-initiated action, not server storage. Without it, recovery depends on the admin + recovery key (and therefore on the recovery device not being lost — see §15.3 / §16.3).

### 12.7 Grant access via the offline recovery key (fallback only)

Needed **only** when no current recipient is available to perform the online re-share (§12.4b) — e.g., the last authorized user is gone, or for device-loss account recovery (§12.6). For everyday sharing, use §12.4b; this keeps the recovery device in the safe almost all the time.

1. Admin operates the **air-gapped** recovery device, exactly as any user unlocks their own key locally (§9.2): `recovery_priv` never touches a networked machine. The recovery wraps to process are hand-carried in (e.g., removable media), and the resulting new wraps are hand-carried out — only ciphertext crosses the air gap.
2. For each target `file_id`, the server provides the **recovery** wrap of the current version.
3. Admin unwraps the DEK locally with `recovery_priv`.
4. Admin **verifies the new recipient's binding** (§7.2), then computes `wrapped_dek_new = HPKE-Wrap(new_user.enc_pub, DEK)`.
5. Admin uploads the new `file_key_wraps` row.
6. The plaintext DEK is zeroized; the recovery device returns offline.

The server never sees the plaintext DEK.

> **Unavoidable tradeoff (scoped to the no-current-holder case):** when *no current recipient still holds a file's DEK*, you cannot simultaneously have (a) no online secret able to recover that DEK, (b) instant online granting, and (c) purely local client decryption. Keeping the recovery capability offline makes *this* case a deliberate offline action — a choice, not a defect. When a current recipient *does* hold the DEK, online re-share (§12.4b) covers it and the recovery key stays in the safe.

### 12.8 Soft revoke

Delete the user's `file_key_wraps` rows and/or set `status=revoked`. The server stops serving them ciphertext/wraps. Does not affect anything already downloaded (§14).

### 12.9 Strong revoke + key rotation (lazy, per D8)

Strong revoke marks the file for rotation; the rotation happens **on the next write**:

1. On the next update to the file, the writing client (or an admin) recovers the current DEK, generates `DEK'`, re-encrypts → new chunks + `version+1`.
2. New wraps of `DEK'` are created **only** for the still-authorized users + recovery; the revoked user gets none.
3. Old-version chunks and wraps are deleted after the new version is committed.

Until that next write, the strong-revoked user can still read the **current** version (which they already had). Eager rotation is available as an explicit admin action for high-sensitivity files (§14.4).

### 12.10 Large-file handling — chunked/framed AEAD (resolves M1)

- Content is split into fixed-size chunks (default **1 MiB**).
- Each chunk: `AES-256-GCM(DEK, nonce_i, chunk_i, AAD_i)` where
  `nonce_i = 96-bit big-endian counter i` (unique because the DEK is unique per file-version), and
  `AAD_i = canonical(file_id ‖ version ‖ chunk_index=i ‖ is_last)`.
- The framing **prevents truncation, reordering, and cross-file/version splicing**: a missing final chunk (no `is_last`) or an out-of-range index is rejected.
- Enables **streaming** encrypt/decrypt and partial integrity, and avoids AES-GCM's single-message size limits. The per-chunk tags are what `manifest.content_digest` (§12.3) commits to.

---

## 13. Metadata protection (resolves M2, per D7)

- **Encrypted client-side:** filename, MIME type, user-visible attributes (tags, notes), and any client-side folder structure → stored as `enc_metadata`, encrypted with **AES-256-GCM under a separate metadata key `mk = HKDF(DEK, "MaxSecu-metadata-v1")`**. Deriving a distinct key (rather than reusing the DEK directly) keeps metadata out of the content chunks' counter-nonce space (§12.10), so there is no (key, nonce) reuse. `enc_metadata` is therefore unlocked by the same per-recipient wrap as the content.
- **Visible to the server (residual):** ciphertext **size** (bucketed by chunking but not padded in v1), **timing** of operations, and the **sharing graph** (which `user_id`s have wraps for which files). These are structural to a server that stores and routes the data.
- **Implication for search/listing:** server-side search over filenames is **not** possible; listing/search is a client-side capability over decrypted metadata (or a future client-built encrypted index). This is a deliberate product consequence of D7.
- **Future option:** size padding / fixed-size buckets to blunt size inference (deferred; see §18).

---

## 14. Revocation semantics

### 14.1 The hard limit

Cryptography stops the *server* from reading data; it **cannot** un-give what an authorized user already received. A user who downloaded a file (or its wrap) and keeps their private key can decrypt that copy **offline, forever**. No server action changes that.

### 14.2 Soft revoke

Delete wraps / mark `revoked` → blocks **future server delivery**. Does not touch already-downloaded data.

### 14.3 Strong revoke

Rotate the DEK and re-encrypt (lazily, §12.9) → the revoked user has no wrap for the **new version** and cannot derive it. Protects **future versions**, not the old version they already held.

### 14.4 Summary

| Operation | Action | Protects against | Does **not** protect against |
|---|---|---|---|
| Grant (old file) | Online re-share by a current recipient (§12.4b); offline recovery only if none remain (§12.7) | — | — |
| Soft revoke | Delete user's wraps / mark revoked | Future server delivery to that user | Data already downloaded |
| Strong revoke (lazy) | Mark for rotation; rotate on next write | Future *versions* of the file | The current version until next write; the old version they held |
| Strong revoke (eager, opt-in) | Immediately re-encrypt + re-wrap | Future versions immediately | The old version they already held |

---

## 15. Security properties and residual limitations

### 15.1 Provided

- Server stores no plaintext and no standalone decryption key; confidentiality at rest holds under **passive** server compromise.
- **Active** server compromise cannot read files or substitute recipient keys, because of the signed directory (§7) and native client integrity (§8).
- Per-file DEKs bound blast radius to one file.
- Authentication is replay-resistant, channel-bound, and non-enumerable (§9).
- Uploader provenance is authenticated (§12.3); chunk framing prevents splicing/truncation (§12.10).
- Memory-hard password hashing with per-user salt; **no server-side per-user offline-guessing target** (D2 + D4).
- Filenames/attributes are hidden from the server (§13).
- Recipient keys are bound to real people by an **in-person fingerprint check** (§12.1), so a malicious server cannot substitute its own key (C1 genuinely closed).
- **Rollback is detected:** stale file versions and superseded directory bindings cannot be passed off as current — the binding-`key_version` guard is clock-independent, and an unchanged-key revocation is bounded by the 12 h freshness epoch (§7.5).
- Decrypted data and keys are held **in memory only** and zeroized after use (§8.1), minimizing on-device plaintext exposure.

### 15.2 Honest scope of "zero-knowledge"

This system is zero-knowledge of **file content and filenames/attributes**. It is **not** zero-knowledge of **sizes, timing, or the sharing graph**, and the server learns *coarse* access patterns. The label should be read accordingly in product copy (§13, §18).

### 15.3 Inherent / residual limitations

- **Offline guessing** of a stolen *device's* local key is always possible; Argon2id only makes it expensive (not impossible).
- **Revocation cannot retroactively** remove already-downloaded data (§14.1).
- **User private-key compromise is retroactive:** whoever obtains a user's `enc_priv` can unwrap **every DEK ever wrapped to that user** — i.e., every file that user could access (resolves L2 by documenting it).
- **Recovery device (D6) is a single point of theft and of loss.** Theft ⇒ all uploaded files recoverable by the attacker. Loss ⇒ no future old-file grants and broken device-loss recovery (§12.6) unless a sealed backup exists (§16.3). **Shamir split is the recommended future upgrade** (§19).
- **Signing device (D5) compromise** enables MITM of *future* uploads via forged bindings (not past files); mitigated by air-gap, ceremony review, rotation, and (future) transparency (§7.4).
- **Client build/update pipeline is in the TCB** (§8); defended by signing + reproducibility + transparency, not by server honesty.
- **Malicious authorized client** can exfiltrate plaintext it is entitled to read; endpoint trust is assumed. In-memory-only handling (§8.1) shrinks but does not remove this; a running client with a file open still exposes that file. User-level discipline (lock your device) is the mitigation (§1.3).
- **Directory equivocation** by a *compromised signing key* is bounded by air-gapped custody, the freshness epoch (§7.5), rotation, and **peer key pinning** (§7.7) — which fully closes it for any pair that has verified in person. It stays open only for pairs that have *never* met, pending the transparency log (§19).

---

## 16. Operations

### 16.1 Ceremonies

- **Enrollment signing** (§12.1): scheduled, air-gapped, with **in-person fingerprint verification** of each new identity binding (§7.1). Cadence published to users.
- **Status attestation** (§7.6): automated, frequent re-issuance (well within the 12 h epoch) of directory status by the status signer; revoking a user = stop attesting them. Not air-gapped.
- **Old-file grant / account recovery** (§12.7, §12.6): air-gapped recovery-key sessions, audited.

### 16.2 Error handling

- **Sanitized errors only:** never return DB errors, stack traces, paths, or whether a username exists. Verification failures return a generic rejection; details go to server logs, not clients.
- **Fail closed:** any exception on an auth/authorization path yields deny (401/403), never proceed-as-anonymous.

### 16.3 Backups of the trust root

- **Recovery key (D6):** breakglass, kept **cold** (offline; a written-down/sealed copy is acceptable) with a **sealed, encrypted backup in separate physical custody** (e.g., a second safe). Anyone who physically obtains the cold copy can decrypt **everything**, so custody is the whole control: **tamper-evident sealing, dual-custody, access logged**, and ideally a **Shamir / threshold split** (§19) so no single safe or person holds the whole key — a lone written copy is itself a single point of total compromise. Plan rotation as a deliberate (expensive) re-wrap project, not an emergency.
- **Signing key (D5):** backed up under equivalent controls; rotation in §16.4 (incl. the emergency runbook). May share D6's cold custody — co-location does not unlock identity forgery, which also requires the separately-housed D13 (§7.6).

### 16.4 Key rotation procedures

- **User keys:** new keypair + new signed binding (`key_version++`); existing files re-wrapped on next access/write or via recovery re-grant.
- **Directory-signing key (planned):** new client release pinning old+new keys for an overlap window; re-sign active bindings under the new key during the window; retire the old key after.
- **Emergency D5 rotation (suspected compromise / theft) — runbook:**
   1. **Trigger:** a key-change alarm (§7.7), a directory-history/transparency-log alert, or known device theft.
   2. **Cut over fast:** ship a new signed client release that pins the **new** D5 public key and **drops the old one immediately** (no long overlap — accept that bindings must be re-signed).
   3. **Re-sign legitimately:** at an air-gapped ceremony, re-sign every current identity binding under the new D5, **re-confirming fingerprints in person** for anything suspect (§12.1).
   4. **Hunt forgeries:** review the directory history for bindings issued under the old key; notify affected users to re-verify (they will already be seeing key-change prompts, §7.7).
   5. **Bounded exposure:** D5 forgery only affects *future* uploads, never past files — the damage window is detection-to-cutover, so keep it short.
- **Status-signing key (D13):** rotated routinely (low ceremony — it cannot forge identities); a new client release pins old+new status keys for an overlap window (§7.3).
- **Recovery key:** generate new offline keypair; re-wrap the recovery recipient across files as a background project; retire the old key once complete.

### 16.5 Logging & detection

- Audit-log (append-only, §11.4) every security-relevant event: auth attempts/denials/lockouts, grants (with `granted_by`), revokes, rotations, ceremony actions (incl. fingerprint match/mismatch), explicit plaintext exports (§8.1), admin operations.
- Redact sensitive data; never log secrets, tokens, or plaintext.
- Alert on anomalies: spikes in auth failures, unusual grant/revoke volume, directory-binding changes outside a ceremony window.

### 16.6 Secrets handling

- No secrets in source, client bundles, container `ENV`, CI logs, or error responses.
- Server holds **no** file-decryption secrets by design; the only high-value secrets (D5/D6 keys) live offline.

---

## 17. Build plan (phased)

Each phase is independently testable and leaves the system in a coherent state.

**Phase 0 — Foundations**
Crypto library selection + wrappers (AES-256-GCM chunked, HPKE/X25519, Ed25519, Argon2id); algorithm-identifier scheme; canonical-serialization spec; test vectors. *Exit:* property tests for encrypt→decrypt, wrap→unwrap, sign→verify, and framing tamper-rejection pass.

**Phase 1 — Identity & auth**
Native client registration (local key generation + Argon2id blob), server `users` storage (public material only), challenge-response with channel binding, session tokens, rate limiting, password policy + breach blocklist. *Exit:* login works; replay/relay/enumeration tests pass; no private material on server.

**Phase 2 — Signed key directory + freshness (C1)**
Offline signing-key tooling + **fingerprint-confirmed** ceremony workflow (§12.1); binding epochs with ceremony re-signing (§7.5); directory storage/serving; client-side mandatory binding verification with pinned root + expiry check; client trust-on-last-use version memory. *Exit:* a server returning a forged binding is rejected; a binding whose fingerprint doesn't match is never signed; expired bindings and rolled-back file versions are rejected; unsigned bindings are not usable as recipients.

**Phase 3 — File upload/download (single-recipient)**
Chunked AEAD blob storage; per-file DEK; wrap to self + recovery; signed manifest; download with full verification + decrypt; **in-memory-only plaintext handling + zeroization + warned export** (§8.1). *Exit:* large-file streaming round-trips; spliced/truncated/forged-manifest payloads are rejected; no plaintext written to disk (verified by filesystem/swap inspection); export shows the warning and is audited.

**Phase 4 — Sharing & authorization**
Multi-recipient wraps; per-file ACL via wrap table; **online re-share by a current recipient** with `granted_by` audit (§12.4b); coarse server authz; encrypted metadata (§13). *Exit:* grant-at-upload and online re-share work; server cannot mint wraps; cross-user wrap leakage tests pass; sharing-graph audit is complete.

**Phase 5 — Recovery, grant-old-file, revocation**
Offline recovery-key tooling (fallback grant, §12.7); device-loss recovery preferring online re-share (§12.6); soft revoke; strong revoke with lazy rotation + versioning; epoch-expiry revocation (§7.5). *Exit:* end-to-end grant/revoke/rotate flows verified; revoked users lose future versions and their binding expires within one epoch; audit log complete.

**Phase 6 — Client integrity & ops (C2)**
Reproducible builds; code signing; signed + transparency-logged updates; monitoring/alerting; sanitized-error pass; ceremony runbooks. *Exit:* reproducible-build verification documented; security review sign-off.

**Cross-cutting throughout:** threat-model tests per phase, audit logging, sanitized errors, dependency pinning + audit.

---

## 18. Concern → resolution traceability

Maps every finding from the first-pass security review to where this design resolves it.

| Finding | Severity | Resolved in |
|---|---|---|
| **C1** Unauthenticated public-key distribution (key MITM) | Critical | §7 Signed key directory; §12.2/§12.5/§12.7 mandatory verification; Phase 2 |
| **C2** Web-delivered client = server in TCB | Critical | §8 Native signed clients + reproducible/transparency-logged builds (D1); Phase 6 |
| **H1** No uploader authentication | High | §12.3 Signed manifest; §5 HPKE Auth mode |
| **H2** Session mgmt + channel binding undefined | High | §9.2 Channel-bound challenge + short-lived session token |
| **H3** Pre-auth salt/blob leakage + no anti-automation | High | §9.1 (no server-side key material, per D4) + §9.3 anti-automation |
| **M1** Large-file / GCM limits | Medium | §12.10 Chunked/framed AEAD |
| **M2** Metadata leakage / ZK overclaim | Medium | §13 Encrypted metadata; §15.2 honest scope |
| **M3** Argon2id params not stored | Medium | §5 + §11.1 (params stored with the local key) |
| **M4** OPAQUE doesn't custody the unwrap key | Medium | N/A — Approach A chosen (D2); custody is the local Argon2id blob (§9.1) |
| **L1** `verifier` column overloads two objects | Low | §11.1 — column eliminated (no server-side key blob) |
| **L2** User-key compromise is retroactive | Low | §15.3 documented |
| **L3** Per-file vs global ACL ambiguity | Low | §10 per-file ACL; explicit per-upload recipient set |
| **L4** Nonce lifecycle unspecified | Low | §9.2 single-use, expiring, server-tracked |

### 18.1 Design-phase open questions (raised after the review, resolved here)

| Question | Resolution |
|---|---|
| #1 Initial identity proofing (the truth under C1) | **In-person fingerprint confirmation** at the signing ceremony (D9, §7.1 / §12.1) |
| #2 Rollback / freshness | Client **version memory** + **epoch-expiring re-signed bindings** (D10, §7.5) |
| #3 Delegation / re-sharing | **Allowed + audited** online re-share by any current recipient (D11, §12.4b) |
| #4 Client install bootstrap | Accepted: **in-person delivery** removes the MITM'd-download vector (§8) |
| Plaintext on disk | **In-memory only**; explicit, warned, audited export (D12, §8.1) |
| #5 Directory equivocation (split view) | **Mostly closed** by peer key pinning for verified pairs (§7.7, D14); the transparency log (§7.4, §19) remains for never-met pairs |

---

## 19. Open items / future work

- **Key transparency log** for the directory (defends against signing-key equivocation, §7.4).
- **Shamir / threshold split** of the recovery key (removes the D6 single-point-of-theft/loss, §15.3).
- **Post-quantum hybrid wrap** (X25519 + ML-KEM-768), enabled by algorithm agility (§5).
- **Size padding / bucketing** for metadata (§13).
- **Multi-device** support (would revisit D4 — e.g., device-to-device key transfer).
- **Encrypted client-built search index** to restore search lost to §13.
