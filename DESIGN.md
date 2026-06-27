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
- **§18 (traceability matrix)** maps every review finding to the section that resolves it — §18.1 the first review pass, **§18.2 the second**, **§18.3 the third**, **§18.4 the fourth**. If you only read one table, read those four.

Defined terms: **DEK** = per-file Data Encryption Key (symmetric). **Wrap** = a DEK encrypted to one recipient's public key. **Grant** (a.k.a. *wrap-grant*) = a granter-signed, per-version record authenticating that a wrap is legitimate and chaining to the file-version's author (§12.3a) — it authorizes **holding a version's key (read)**. **Write-grant** = a durable, owner-rooted record authorizing a user to **author new versions (write)** of a file (§11.6/§12.3b). **Genesis** = the immutable, owner-signed record that authenticates a file's `owner_id` as the root of write authority (§11.7). **Tombstone** = an admin-signed, monotonic strong-revoke record consulted by rotators/re-sharers (§11.5/§12.9b). **Directory** = the authenticated mapping of username → public keys. **Recovery key** = the offline asymmetric key (a standing recipient on every file — an escrow, §1.2) that can re-derive any file's DEK. **Signing key** = the offline key that signs directory entries.

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
- It does **not** use a single global key that decrypts every file *as a live, online, or user-distributed decryptor* (rejected; see §6.2).
- **It is not "no-one can ever decrypt your files."** A standing **recovery recipient** is wrapped into *every* file (§6.3), so whoever physically holds the **offline recovery key (D6) can decrypt 100% of all files, past and present** — a deliberate, disclosed **escrow / breakglass** capability, not an accident. "Zero-knowledge" here means *the server* learns nothing (§15.2), **not** that the operator is cryptographically incapable of recovery. This must be stated plainly in any product copy; users who need operator-incapable secrecy are outside this design's model. The escrow's power is bounded only by physical custody of the cold key (§16.3) and, when shipped, the Shamir/threshold split (§19).
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
| D15 | Recipient-set authenticity (review **R1**) | **Per-wrap `grant` signatures chaining to the version author** + manifest `recovery_present` assertion | Moves "who may hold the key" off the untrusted server: a malicious server can no longer inject or re-admit a recipient at rotation, and recovery-wrap omission is detectable (§12.3a) | A *malicious current recipient* can still grant a colluder (inherent delegation/endpoint trust, D11) — now authenticated and tombstone-revocable (§14.5) |
| D16 | Strong-revoke integrity (review **R1a**) | **Admin-signed, monotonic revocation tombstones** consulted by rotators/re-sharers; **grant-graph revocation** | Strong revoke now holds against a malicious server (it cannot hide a known revocation past the rollback-guarded epoch) and a re-shared subtree is walkable | Tombstone *withholding* and first-contact are closed by epoch anchoring (D22, §7.6); the residual is status-signer availability, plus the inherent "already-downloaded" limit (§14.1) |
| D17 | Role-revocation latency (review **R4**) | **Effective roles = binding.roles ∩ status `eff_roles`** (status may narrow, never widen) | De-admining takes effect within one freshness epoch without an air-gapped re-sign; status signer still cannot escalate | Removing the binding's role *ceiling* still waits for expiry / emergency re-sign (§16.4) |
| D18 | Audit integrity (review **R2**) | **External, append-only audit sink with digest anchoring**; server `auth_events` is a mirror | Detection survives a malicious server that would otherwise suppress/forge its own logs — on which many "detectable" bounds depend | Requires operating out-of-band WORM/SIEM infrastructure; anchoring cadence bounds tamper-detection latency |
| D19 | Serialization safety (review **R5**) | **Mandated injective canonical encoding**; `‖` is length-prefixed (§5.2) | Removes the concatenation-collision class that would otherwise forge any signature/digest | Correctness now rests on the canonical spec + its adversarial test vectors (Phase 0) |
| D20 | Long-term & catastrophic-key risk (review **R6**) | **Elevate PQ-hybrid wrap and recovery-key Shamir split to a committed phase (Phase 7)** | Harvest-now-decrypt-later against X25519 + a single all-files escrow key is the dominant long-horizon risk for a long-lived store; it should not sit in open-ended "future work" | Not in v1; v1 confidentiality is non-PQ and the escrow is a single cold key until Phase 7 ships (§15.2/§15.3) |
| D21 | Write authorization (review **R15**) | **Separate the durable ACL from per-version key custody: an immutable owner-signed `genesis` (§11.7) roots write authority; durable owner-rooted `write-grants` (§11.6) authorize authoring; a version's `author_id` must prove a write-grant chain to genesis and not be tombstoned, checked by downloaders (§12.5)** | Authorship was authenticated (manifest_sig) but never *authorized* — any read recipient could overwrite content, exclude other readers, or drop recovery. This closes the gap by making "who may write" an owner-rooted, server-unforgeable fact | A holder of write *can* still overwrite/lock-out within their grant (inherent endpoint trust, now attributable + tombstone-revocable); excluding a still-entitled reader is *detectable*, not prevented (§12.9) |
| D22 | Strong-revoke completeness (review **R16**) | **Anchor the monotonic `max_revocation_epoch` in the online status attestation (§7.6); clients require a contiguous tombstone set up to the anchored head and fail closed on a gap** | The prior design detected — but did not prevent — a malicious server *withholding* a fresh tombstone (a completeness gap, not a rollback). Anchoring converts suppression into prevented-within-one-epoch, matching the design's other bounds | Bound is one freshness epoch; relies on the status infrastructure learning epochs authoritatively at issuance, not from the untrusted server (§7.6/§12.9b) |
| D23 | Version monotonicity (review **R17**) | **`version` increments by exactly 1; a client rejects any served version exceeding the highest it has seen by more than a small bound, and applies an absolute sanity ceiling at first contact** | The anti-rollback "highest version seen" memory (§7.5) was itself weaponizable: an author could publish a near-max `version` and poison peers into rejecting all future legitimate updates (a DoS). Strict +1 progression removes the poisoning surface | Concurrent writers must rebase onto the winner (§12.9); first contact relies on the absolute ceiling |
| D24 | Untrusted decrypted metadata (review **R18**) | **Treat cross-user filenames/attributes as adversarial input: sanitize before any filesystem path, external-process, or UI/webview sink (§8.1, §13)** | Metadata is authenticated, but the author may be malicious (D11) — *authenticated ≠ benign*. A crafted filename is untrusted input reaching the **downloader's** filesystem on export (path traversal) or a renderer (injection) | Standard client-side input-sanitization burden; covered by Phase 3/4 exit tests |
| D25 | Grant honored-ness must prove DEK possession (review **R24**) | **Every `grant` carries a `dek_poss = HKDF(DEK, "MaxSecu-grant-poss-v1" ‖ …)` tag; a grant is honored and carried-forward only if a DEK-holder (the rotator at carry-forward, the recipient on download) re-derives and matches it (§12.3a)** | The prior "admin clause" let an *online* admin sign a carry-forward grant **without holding the DEK**; the honest rotator would then re-wrap the next version's fresh DEK to the admin's chosen recipient — handing an online admin the read access §10.1/§3.1 forbid. Binding honored-ness to DEK *possession* makes the recovery clause add no power and closes the escalation cryptographically | A *malicious current recipient* who genuinely holds the DEK can still grant a colluder (inherent D11) — now also DEK-bound and attributable (§14.5) |
| D26 | Delegation-graph revocation source (review **R25**) | **Compute the read/write `granted_by` subtree from the digest-anchored external audit sink (§16.5), not from server-served grant rows (§12.9b/§14.5)** | A malicious server could *withhold* a descendant's grant edge from the revoking admin (so it is never tombstoned) while still honoring it for rotation/download — a grant-graph analogue of tombstone-withholding (R16/D22). The append-only sink is the authoritative edge set | Completeness now depends on the external sink being intact and current — the same dependency every other "detectable" claim already has (§11.4/§16.5) |
| D27 | Recovery-wrap validity is offline-only (review **R26**) | **Periodic air-gapped recovery-wrap validation sweep (§16.1): the recovery operator unwraps sampled `recovery` wraps with `recovery_priv` and confirms each decrypts to the committed DEK** | The downloader-side `recovery_present` check proves the author *intended* recovery (a signed grant over the right `dek_commit`), **not** that the recovery *wrap ciphertext* decrypts to that DEK — only `recovery_priv` can confirm that. A malicious writer could sign a good grant but upload a bad wrap, silently breaking recoverability | Detection is at sweep time, not upload time; risk-based cadence/coverage bounds cold-key exposure vs. detection latency (§15.3) |
| D28 | Durable records under a rotated-away key (review **R27**) | **On compromise-driven rotation, publish a signed, sink-anchored `key_compromise` cutoff for the old `(user_id, key_version)`; durable records (write-grants/genesis) under that key_version are honored only if their external-sink anchoring predates the cutoff (§11.7)** | Historical bindings are retained forever to verify durable records (§11.7); without a cutoff a compromised-then-rotated `sig` key could forge **backdated** write-grants that verify indefinitely. Tying acceptance to append-only sink ordering defeats an attacker-chosen `created_at` | A forgery the attacker manages to anchor *before* the cutoff is indistinguishable from a legitimate pre-compromise grant; the cutoff bounds exposure to the detection-to-cutoff window, like the D5 emergency runbook (§16.4) |

**Applied without asking (clear best practice):** uploader/rotator-signed manifests (H1, §12.3), chunked/framed AEAD (M1, §12.3/§12.10), domain-separated channel-bound challenge + short-lived session token (H2, §9), single-use expiring nonces (L4, §9), per-record algorithm identifiers with a prioritized X25519+ML-KEM hybrid wrap path (§5/D20), schema fixes (L1/L3, §11), **KDF-derived DEK commitment (§12.3), explicit metadata nonce + rotation re-encryption (§13), client bound-checking of server-supplied framing (§12.10), mobile Argon2id security floor (§5), nonce-challenged status-freshness option (§7.5).**

---

## 3. Threat model

### 3.1 Adversaries and guarantees

| Adversary | Capability | Guarantee under this design |
|---|---|---|
| **Passive server compromise** (read DB + disk) | Read all ciphertext, all wraps, all public keys, all directory signatures, encrypted metadata | Cannot decrypt any file; cannot recover any private key or any plaintext DEK. Stolen data is inert. |
| **Active malicious server** (serves chosen bytes/records) | Substitute records, withhold records, attempt key substitution, replay old signed records, **misreport the recipient set**, **withhold a fresh tombstone** | **Key substitution is blocked** by the signed directory (§7); **stale/rolled-back records are detected** (§7.5); **recipient *injection* and *unauthorized authorship* are blocked** by per-wrap grants, durable write-grants, and the author-entitlement check (§12.3a/§12.3b/§12.5) — the server cannot make an honest rotator wrap the next version to a non-authorized recipient, nor pass off a version authored by a non-writer/tombstoned user. **Strong-revoke re-admission is blocked against rollback** (monotonic tombstones, §12.9b) and, against a server *withholding* a not-yet-seen tombstone, **prevented within one freshness epoch** by the anchored `max_revocation_epoch` + contiguity check (§7.6, D22). The server can deny service, but cannot read files, impersonate a recipient, grant access, author a version, or pass off an old version/binding as current. It **cannot** ship malicious client code (native clients, §8), and its self-kept audit log is not trusted — detection roots in the external sink (§16.5). |
| **Network attacker, passive** | Observe traffic | TLS protects transport; the auth proof is a fresh, channel-bound signature → not replayable. |
| **Network attacker, active / MITM** | Tamper, relay | TLS with client-verified server identity; per-chunk AEAD detects tampering; channel-bound challenge (§9) prevents relay. |
| **Stolen user device** | Holds the local encrypted private key + previously downloaded plaintext | Attacker must still defeat `Argon2id(password)` offline to use the key; already-downloaded plaintext is, by definition, already exposed. Remote wipe / re-enrollment is an operational response, not a cryptographic one. |
| **Stolen offline recovery device / cold copy (D6)** | Holds the recovery private key | Can decrypt **every** file uploaded so far (past + present) — the highest-value secret in the system. It is breakglass (used only when no current recipient remains, §12.7), so its risk is **physical custody of the cold copy**, not device/online security: sealed, dual-custody backup (§16.3), Shamir split planned (§19). Does **not** by itself grant identity forgery (that needs D5 **and** D13). |
| **Stolen offline signing device (D5)** | Holds the directory-signing key | **Alone cannot forge a usable binding** — a forged binding also needs a matching D13 status attestation (§7.6). Even **D5+D13** cannot *silently* MITM a pair that has verified in person (peer-pinning, §7.7); for never-verified pairs it can MITM **future** uploads until detected. Cannot decrypt already-uploaded files. Mitigated by air-gap, the D13 gate, peer-pinning (D14), and emergency rotation (§16.4). |
| **Compromised status signer (D13)** | Holds the lower-privilege status-signing key | **Cannot** forge username→key bindings, substitute keys, read files, or **escalate roles** (its `eff_roles` can only narrow the offline binding, §7.2/§7.6). At worst keeps a revoked user `active`, keeps a de-admined user's `admin` alive, or denies service by withholding attestations — each ≤ one freshness epoch (bounded, detectable in the external sink). Mitigated by routine rotation, anomaly alerts, HA issuance, and the monotonic `key_version` guard (§7.5/§7.6). |
| **Revoked user** (incl. one colluding with a malicious server) | Keeps their private key + anything downloaded | Gets no new wraps (soft revoke); loses access to **future versions** (strong revoke, §14). Against a colluding server the guarantee holds **by rollback-resistance always** (monotonic tombstone, §12.9b) and **within one freshness epoch against tombstone *withholding*** (anchored `max_revocation_epoch` + contiguity, §7.6/D22): an honest rotator excludes them, grants stop the server re-adding them, and a server cannot indefinitely hide the revocation from a rotator. A still-DEK-holding revoked user also cannot mint an accepted version, because the author-entitlement check rejects a tombstoned author (§12.5). Retains only what they already downloaded (§14.1). |
| **Malicious authorized client** | Is legitimately entitled to a file (read, and/or write) | Can always exfiltrate plaintext it is entitled to **read**. A **read-only** recipient additionally **cannot author/overwrite a version** — write is separately authorized (§11.6/§12.5). A recipient holding **write** can overwrite content and lock out other readers, but every such act is attributable to a signed write-grant and tombstone-revocable (§14.5); unauthorized lock-out of a still-entitled reader is detectable (§12.9). Out of scope for cryptography otherwise; endpoint trust is assumed (§15.3). |

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
| File content encryption (AEAD) | **AES-256-GCM**, chunked/framed (§12.10) | Keyed by a derived per-version **content subkey** `ck = HKDF(DEK, "MaxSecu-content-v1")` — so the raw DEK is only ever a KDF root (for `ck`, `dek_commit`, `dek_poss`, `mk`), never directly an AEAD key (L-5). 96-bit deterministic counter nonce *per `ck`*; 128-bit tag; per-chunk AAD binds index + last-chunk flag. Never reuse a (`ck`, nonce). |
| Key wrapping (DEK → recipient) | **HPKE (RFC 9180)**, X25519 + HKDF-SHA256 + AES-256-GCM, **Auth mode** where uploader provenance is wanted | Wraps the DEK to a recipient public key. The HPKE `info` is bound to the context — `info = "MaxSecu-wrap-v1" ‖ canonical(file_id ‖ version ‖ recipient_id)` — so a wrap cannot be reinterpreted for another file/version/recipient even before the grant check. **Auth mode** additionally authenticates the sender; the recipient verifies the HPKE sender key equals the **wrap's `granted_by`** directory-verified `enc_pub` — the version `author_id` for an upload/rotation wrap, the **re-sharer** for a re-share wrap (§12.4b), or the **recovery operator** for a recovery re-grant (§12.7), *not* always `author_id` (L-1) — complementing §12.3 manifest signing and the per-wrap grant (§12.3a). |
| User encryption keypair | **X25519** | Used only to unwrap DEKs. |
| User signing keypair | **Ed25519** | Used for challenge-response (§9) and manifest signing (§12.3). Distinct from the X25519 key. |
| Directory-signing key (D5) | **Ed25519** (offline) | Signs long-lived identity bindings (§7.1). |
| Status-signing key (D13) | **Ed25519** (HSM / hardened, not air-gapped) | Signs short-lived directory status attestations (§7.6); cannot mint identity bindings. |
| Recovery key (D6) | **X25519** (offline) | A standing recipient on every file (§6.3). |
| Password KDF | **Argon2id (RFC 9106)**, unique per-user salt | Floor: `m ≥ 19 MiB, t ≥ 2, p = 1` (OWASP). Target on desktop: `m = 256 MiB, t = 3, p = 1`, calibrated to ≈0.5–1 s. **Mobile floor: `m ≥ 64 MiB, t ≥ 3, p = 1`** (calibrated to the device, never below this) — a stolen mobile `local_key_blob` is an offline-guessing target just like a desktop one (§3.2, §15.3), so the mobile profile is *reduced from the desktop target, not from the security floor*. Full params stored **with the local key** (§11.1). |
| Hashing | **SHA-256** | Content/manifest digests, Merkle binding of chunks. |
| Transport | **TLS 1.3**, client verifies server identity; **channel binding** (exporter) fed into the auth challenge (§9) | |
| Post-quantum (future) | Hybrid **X25519 + ML-KEM-768** wrap via HPKE / CMS (RFC 9936, KEMRecipientInfo per RFC 9629) | Not in v1; enabled by algorithm agility. |

Citations verified: RFC 9180 (HPKE), RFC 9106 (Argon2), RFC 9629 (CMS KEMRecipientInfo), RFC 9936 (ML-KEM in CMS, 2026), NIST SP 800-38D (GCM), FIPS 203 (ML-KEM).

**Signature domain separation.** Every Ed25519 signature carries a unique, versioned context prefix — `"MaxSecu-auth-v1"` for the auth challenge (§9.2), `"MaxSecu-manifest-v1"` for the upload manifest (§12.3), `"MaxSecu-grant-v1"` for per-wrap (read) grant records (§12.4), `"MaxSecu-write-grant-v1"` for durable write-grants (§11.6/§12.3b), `"MaxSecu-genesis-v1"` for the file ownership genesis (§11.7), `"MaxSecu-revocation-v1"` for revocation tombstones (§11.5/§12.9b), `"MaxSecu-reinstatement-v1"` for reinstatements (§11.5a), `"MaxSecu-key-compromise-v1"` for signing-compromise cutoffs (§11.7/D28), `"MaxSecu-dirbinding-v1"` for directory bindings (§7.1), `"MaxSecu-status-v1"` for status attestations (§7.6), and `"MaxSecu-revcheckpoint-v1"` for revocation checkpoints (§7.6/L-3). The non-signature (KDF / AEAD-context) domain tags are `"MaxSecu-dek-commit-v1"` (DEK commitment, §12.3), `"MaxSecu-grant-poss-v1"` (per-grant DEK-possession tag, §12.3a), `"MaxSecu-content-v1"` (content subkey, §12.10), `"MaxSecu-metadata-v1"` (metadata key, §13), and `"MaxSecu-wrap-v1"` (HPKE wrap context, §5 table) — all derived from the per-version DEK under distinct `info` strings, so each is an independent PRF output that reveals nothing about the DEK or the others. The prefixes are distinct and none is a prefix of another, so a signature produced in one context cannot be reinterpreted as valid in another — even where the same `sig` key signs in more than one role (auth + manifest + grant + write-grant + genesis + revocation).

> **Key separation note.** A user's single Ed25519 `sig` key signs in several roles (auth, manifest, revocation). This is safe **only** because of the domain separation above; it is a deliberate simplicity/availability trade (one key to custody on-device) rather than a recommendation against role-separated signing keys. The X25519 `enc` key is never used for signing, and the offline D5 / status D13 keys are wholly separate (§6.1).

### 5.1 Algorithm migration & downgrade protection

Algorithm agility is only safe if the *client*, not the server, decides what is acceptable.

- **Allowlist + floor (mandatory).** Each client ships a hardcoded allowlist of accepted algorithms and a minimum-strength floor per purpose (content AEAD, wrap, signature, KDF), and **rejects any record whose `alg` is unknown or below the floor** — fail closed. The server-supplied `alg` only ever selects *among approved options*; it can never force a weak or unknown primitive. This is what prevents a downgrade attack. For files the `alg` sits inside the signed manifest (§12.3), so it cannot even be forged — only chosen from the approved set.
- **One "current" algorithm per purpose.** Exactly one algorithm per purpose is designated current; new uploads always use the current set.
- **Fleet currency while a migration is in progress.** Whenever records under more than one algorithm coexist, clients not on the build that produces the *current* algorithm show a **daily update reminder** to pull the fleet forward; after a published grace period, out-of-date clients may be blocked from *writing* (reading still works).
- **Lazy auto-migration on access (deprecated primitives).** A file still on a *superseded-but-unbroken* algorithm is transparently re-encrypted to the current one the next time it is accessed by a capable client **holding write authority** (§11.6) — reusing the lazy key-rotation machinery of §12.9 (fresh DEK, `version++`, re-wrap to the current recipients + recovery). The corpus migrates passively as files are touched, with no mass re-encryption project. A **read-only** recipient cannot migrate (it cannot author a version, §12.5); migration defers to the next access by a **writer**, or to the eager sweep below.
- **Eager sweep (broken primitives).** Lazy migration is acceptable only while the superseded primitive is merely *deprecated*: a file left untouched stays *readable* under the old `alg` indefinitely, which is unacceptable if that primitive becomes **broken** (not just dated). On a break, the operator triggers an **eager admin sweep** — a background re-encryption project over every file still on the broken `alg` (writers, or the recovery key where no writer remains, §12.7) — rather than waiting for organic access. Until a file is swept, clients **block reads** of content under a below-floor/broken `alg` (fail closed, §5.1 allowlist), not merely writes.

### 5.2 Canonical encoding — injective serialization (security-critical)

Every signature, digest, fingerprint, and AAD in this design is computed over `canonical(...)` and uses the `‖` operator. The security of *all* of them collapses if that encoding is not **injective** — if two distinct field-tuples can produce the same byte string, an attacker can forge a signature for one structure by presenting another (the classic `("ab","c")` vs `("a","bc")` concatenation collision). This is a mandatory implementation contract, not an aesthetic preference:

- **`‖` is length-prefixed concatenation, never raw byte concatenation.** Each variable-length field is emitted as `len(field) ‖ field` with a fixed-width big-endian length, or the whole structure is encoded in a self-delimiting, deterministic format. Fixed-width fields (e.g., 32-byte keys) may be emitted directly.
- **`canonical(...)` is a single, deterministic, typed encoding** — strict DER, deterministic/canonical CBOR (RFC 8949 §4.2), or an explicitly specified TLS-style length-prefixed wire format. Map keys sorted; no optional whitespace; no ambiguous integer widths; one and only one valid byte string per value.
- **Type/context tags are inside the encoding**, so a value of one type can never be reinterpreted as another even before the domain-separation prefix is applied.
- **The canonical-serialization spec ships in Phase 0 with adversarial test vectors** (§17) that specifically attempt field-splitting and trailing-data collisions; an implementation that accepts any such collision fails the phase exit.

This single contract underwrites C1 (directory bindings), H1 (manifests), the status/revocation attestations, and the per-chunk AAD (§12.10).

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
  eff_roles      : subset of binding.roles,                              // current roles — may NARROW the binding, never widen (§7.6, §10.1)
  global_revocation_epoch : integer,                                      // anchored head of the account-wide (`*`) tombstone counter (§7.6, §11.5) — clients require a contiguous `*` tombstone set up to this value (D22)
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
8. **Effective roles** for any capability decision (§10.1) are `binding.roles ∩ status_attestation.eff_roles` — the offline binding sets the *ceiling*, the short-lived status attestation may *narrow* it. A privileged operation is permitted only if the required role is in that intersection. This is what lets admin capability be dropped within one freshness epoch (§7.6) without an air-gapped re-sign, while keeping the status signer unable to *grant* a role the offline binding never conferred.

A binding that fails verification is treated as **absent** (fail closed). The recovery public key is itself a directory entry and is verified the same way — the server cannot substitute the recovery recipient either.

### 7.3 Trust root pinning

The directory-signing **public** key is compiled into the signed client binary (§8) and may be cross-published (e.g., on the vendor site, in release notes) so users and auditors can confirm it out of band. The **status-signing public key** (D13, §7.6) is pinned the same way. Rotating either key (§16.4) ships in a new signed client release that pins both old and new keys during an overlap window.

### 7.4 Residual: equivocation

A signed directory stops *forgery* but not *equivocation* (showing different valid bindings to different users) if the **signing key itself** is compromised. The defenses are: air-gapped signing (D5/§12.1), signing-key rotation, **peer key pinning** (§7.7) — which removes D5 from the trust path entirely for any pair that has verified in person, so a compromised D5 cannot touch an already-verified channel — and, for pairs that have *never* met, a future **key-transparency log** (append-only, auditable) so clients can detect split views (§18, future).

### 7.5 Freshness and rollback resistance (resolves the rollback gap, D10)

A signature proves a record is *authentic*, not that it is *current*. A malicious server can therefore replay an old but still-validly-signed record — a **rollback attack** — on two surfaces. Both are addressed without putting the offline signing key online on demand:

**Directory bindings (revocation / key-rotation freshness).** Two independent guards apply:

- **Monotonic `key_version` (clock-independent).** Each binding carries a monotonic `key_version` (§7.1). Each client keeps a local **trust-on-last-use** record of the highest `key_version` it has accepted per `user_id` and **rejects any binding with a lower `key_version`** — regardless of the local clock. A server that replays a superseded key binding is therefore detected even if the client's clock is wrong (§7.2 step 6).
- **Freshness epoch (clock-based).** Each binding also carries a `not_after` epoch. Current users are re-signed with a fresh epoch (default validity **12 hours**); a revoked or rotated-out user is simply **not** re-signed, so their old binding expires within one epoch. Clients reject expired bindings (§7.2 step 7, fail closed). This is the guard for the case the monotonic check cannot cover — revoking a user whose `key_version` has *not* changed — and it bounds revocation staleness to at most one epoch.

> **Clock-integrity caveat (and the nonce upgrade).** Because expiry is *clock-based*, the ≤ one-epoch revocation bound holds only as far as the verifying client's clock is honest: a client with a **backdated** clock (local tampering, or an NTP/time-source attack) would accept a long-expired `active` attestation, extending a revoked user's window past the epoch. Two defenses, in order of strength: (1) the client treats large backward clock jumps as suspicious and refuses to *widen* validity from cached state; (2) **preferred — a nonce-challenged status fetch:** the verifying client may send a fresh random nonce when it pulls a recipient's status, and the status signer returns a freshly-signed attestation echoing that nonce (the OCSP-nonce pattern), proving currency relative to the client's own nonce rather than the client's clock. The stapled `not_after` model is the low-latency default; the nonced fetch is the fallback when a client cannot trust its clock or wants a hard freshness proof before a high-value wrap. Note the monotonic `key_version` guard above is **clock-independent** and always applies, so this caveat is confined to the revoke-without-key-change case only.

> **Operational consequence of a 12 h epoch.** A 12 h freshness window means current bindings must be re-attested at least every 12 h, or every user expires as a recipient. Re-attesting with the *offline directory-signing key* (D5) that often would expose the system's highest-value key far more than the batched enrollment ceremony intends. This is why freshness is **split from identity** (§7.6, **D13**): the offline key signs the long-lived **identity binding**, while a separate, lower-privilege **status-signing key** issues the 12 h status attestation on a frequent automated schedule. A compromised status signer can at worst keep a revoked user alive within one epoch — bounded, detectable, and still blocked by the monotonic `key_version` guard from pairing a stale status with a superseded key; it **cannot** forge a username→key binding.

**File versions.** The signed `manifest` (§12.3) carries a `version` that **increments by exactly 1** per write (§12.3/§12.9). Each client keeps a small local **trust-on-last-use** record of the highest `version` (and its `content_digest`) it has seen per `file_id`, and **rejects any served version lower than the highest it has seen**. A server that rolls a file back to an earlier signed version is therefore detected on any client that saw the newer one.

> **Upper-bound guard (resolves the rollback-memory poisoning DoS, D23).** Because any holder of write authority chooses the `version` it signs, a malicious *writer* could otherwise publish a near-maximal `version` once, poisoning every peer's trust-on-last-use memory so that **all future legitimately-numbered updates are rejected as rollbacks** — a permanent denial of service for that file. The monotonic-by-exactly-1 rule makes this checkable: a client that has seen version `v` accepts only `v+1` as the next version, and **rejects any served `version` exceeding the highest it has seen by more than a small configured bound** (default 1, with slack only for the concurrent-rotation rebase of §12.9). At **first contact** (no prior record) the client additionally applies an absolute sanity ceiling on `version`. Writers are restricted by the author-entitlement check (§12.5), so this surface is confined to authorized writers and is fully attributable.

**Residual.** Memory can't range-check a file the client has *never* seen (first contact); that case is still covered by manifest authenticity (uploader-signed) and by the recipient binding's epoch. Detecting a server that equivocates *consistently* to a client from day one remains the job of the future transparency log (§7.4). For this deployment's scale, last-use memory + epoch expiry is the proportionate answer.

### 7.6 Status-signing key and the identity/status split (resolves M-3)

A 12 h freshness epoch (§7.5) must not require operating the **offline** directory-signing key (D5) twice a day — that would expose the system's highest-value key far more than the in-person enrollment ceremony intends. Freshness is therefore delegated to a **separate, lower-privilege status-signing key** (D13), following the short-lived-certificate / OCSP-stapling pattern:

- **The offline directory key signs identity** — `username → (enc_pub, sig_pub, key_version, roles)` — rarely (enrollment / rotation only), at the air-gapped ceremony (§12.1), with long validity.
- **The status-signing key signs only freshness/status/roles** of an *already* offline-signed binding (pinned by `binding_digest`): it can attest that an existing binding is current, `active`, and carries some `eff_roles` ⊆ the binding's roles, with a 12 h `not_after` — but it **cannot mint or alter** a `username → key` binding, and its `eff_roles` can only *narrow* the binding's roles, never widen them (§7.2 step 8). This is what gives **fast role revocation**: dropping a user's `admin` capability is a status-attestation change that takes effect within one epoch, with no air-gapped ceremony (§10.1).
- **Cadence:** a scheduled job re-issues a fresh `status_attestation` for every currently-valid user well inside the 12 h window (e.g., every 1–3 h). Revoking a user = stop issuing their attestation (or issue one with `status = revoked`); de-admining a user = re-issue with reduced `eff_roles`; within one epoch every client rejects/narrows them (§7.5).
- **Revocation-completeness anchoring (resolves the tombstone-withholding gap, D22).** A signed tombstone defeats *rollback* (serving a lower epoch, §7.5) but not *withholding* — without a completeness anchor, a malicious server could simply not show a rotator a fresh, not-yet-seen tombstone, and the rotator would carry the revoked user forward. Two anchors close this, both reusing the status signer (which is online and lower-privilege but **cannot** read files or forge bindings):
  - **Global (`*`) head, stapled.** Each `status_attestation` carries `global_revocation_epoch` (§7.1), the current head of the account-wide tombstone counter (§11.5). A client **requires a contiguous `*` tombstone set up to that value** and **fails closed on any gap** — so an account-wide strong-revoke cannot be hidden longer than one freshness epoch.
  - **Checkpointing the `*` set (bounds unbounded replay, L-3).** The contiguous-`*`-tombstone requirement makes the set a client must hold and replay grow without bound, and turns a single missing/corrupt historical tombstone into a fail-closed brick on *all* decryption. The status signer therefore periodically issues a signed **revocation checkpoint** `{up_to_epoch, active_revoked_digest, not_after}` (domain `"MaxSecu-revcheckpoint-v1"`) — `active_revoked_digest` committing to the set of still-active account-wide revocations as of `up_to_epoch`. A client may trust a checkpoint (pinned status key, anchored), verify the served active-set against `active_revoked_digest`, and replay only tombstones *after* `up_to_epoch` rather than from epoch 0. A missing checkpoint degrades to full replay (fail-safe); a missing *post-checkpoint* tombstone still fails closed, but the "one corrupt historical tombstone bricks the fleet" footgun is bounded to the post-checkpoint window. Add `"MaxSecu-revcheckpoint-v1"` to the domain-separation set (§5).
  - **Per-file head, on demand.** Pre-attesting every file's head is infeasible, so before a **rotation (§12.9) or re-share (§12.4b)** the writer fetches a **nonce-challenged** signed statement of *that* `file_id`'s current `max_revocation_epoch` from the status signer (the OCSP-nonce pattern of §7.5) and requires the served per-file tombstone set to be **contiguous up to that head**. The stapled global head is the low-latency default; the nonced per-file head is the hard completeness proof taken before a high-value write.
  - **Authoritative epochs.** For these heads to mean anything, the status infrastructure must learn epochs from the **admins issuing tombstones (§12.9b)**, not from the untrusted application server: tombstone issuance registers the new epoch with the status signer (or the signer co-publishes it), so the anchored head cannot be under-reported by the server.
- **Custody:** because its compromise cannot forge identities, the status key may live in an HSM or a hardened, more-available signer rather than fully air-gapped — a deliberate privilege/availability trade-off. It is **never** on the application server. A compromised status signer can *withhold* or *stall* these heads (a bounded DoS, like any status outage, §7.6 availability) but **cannot** forge a *lower* head to hide a revocation, because the per-file/global counters are monotonic and the issuing admins' registrations are the source of truth.
- **Availability (the 12 h global fuse).** Because *every* user's binding expires within one epoch, a status signer that stops issuing — outage, or a malicious server withholding staples — makes **every** recipient look expired fleet-wide within 12 h, halting all new wraps/sharing (a system-wide DoS, not a confidentiality break). The status signer is therefore run **redundantly / highly-available** (active-passive signers sharing the D13 key in HSM, monitored issuance heartbeat, §16.5), and clients surface "directory status stale — sharing temporarily unavailable" rather than failing opaquely. A longer epoch trades revocation latency for fuse length; 12 h is the chosen balance.

**Compromised status signer — bounded.** It cannot forge a `username → key` binding, substitute a recipient key, or read any file (it never touches DEKs or private keys). At worst it (a) keeps a revoked user `active`, (b) keeps a de-admined user's `admin` role alive, or (c) denies service by withholding attestations — each bounded to ≤ one epoch, since it cannot *widen* roles beyond the offline binding and the monotonic `key_version` guard (§7.5) still blocks pairing a stale status with a superseded key. These are *detectable* — but only against a trustworthy audit trail: the relevant signal (status issuance outside the scheduled job) must be recorded to the **external, append-only audit sink** (§16.5), because a compromise that also reaches the application server could otherwise suppress a server-local log. Mitigations: routine status-key rotation (§16.4), HA issuance heartbeat, and external-sink alerting on off-schedule issuance (§16.5). The threat-model row is in §3.1.

### 7.7 Peer key pinning and key-change warnings (resolves the D5-forgery gap, D14)

The signed directory roots recipient trust in D5 (+ D13). A stolen **D5 + D13** could therefore sign a forged binding for a victim and MITM their *future* uploads. Because this deployment is small and **in-person**, that gap is closed by making D5 *advisory* rather than *final* for anyone two users have actually verified:

- **Pin on verification.** When a user confirms a peer's fingerprint in person, the client **pins** that peer's `enc_pub` / `sig_pub` locally (stored as authenticated ciphertext, §8.1). For a pinned peer the pin is authoritative: any directory binding that disagrees is rejected and alerted (§7.2 step 5). **D5 is no longer in the trust path for that pair** — a forged binding cannot touch an already-verified channel.

  > **Peer-verification protocol (distinct from admin enrollment).** Enrollment (§12.1) is an *admin ↔ user* fingerprint check that gets a binding signed; it does **not** by itself pin peers to each other. Peer pinning is a separate *user ↔ user* step:
  > 1. Out of the directory, each client displays **its own** fingerprint (the local `SHA-256(enc_pub ‖ sig_pub)`, §7.1) as full base64 + QR.
  > 2. The two users meet (or use a trusted side channel) and each **scans/compares the other's** fingerprint against the binding their own client fetched for that `user_id`. Both directions must match.
  > 3. On a match, each client pins the peer. The pin records `(user_id, enc_pub, sig_pub, key_version, pinned_at)` and the event is written to the external audit sink (§16.5).
  >
  > Clients should make this a one-tap "Verify <user>" / scan-QR action and visibly mark contacts as *verified* vs *directory-trusted (unverified)* so users can see which relationships still rest on D5+D13.
- **Warn on key change.** For peers seen-but-not-pinned, the client remembers the last-accepted `key_version` / keys. A **lower** version is rejected as rollback (§7.5); an **unchanged** key proceeds; a **higher** version or changed key is treated as suspicious — the client shows *"this user's key changed — re-verify out of band"* and will **not** wrap new data to the new key until the fingerprint is re-confirmed (then it re-pins). Legitimate key rotations (§12.6, §16.4) are rare and are simply re-verified; a D5 forgery surfaces as exactly this prompt instead of a silent MITM.
- **First contact.** With no prior pin or record, the client trusts the directory binding (D5 + D13) for the first wrap and prompts for in-person verification when the pair can meet, pinning the key once confirmed. First contact is the only window a forged binding could slip through unseen — exactly what the future key-transparency log (§7.4) is meant to cover for pairs that never meet.

This converts D5 compromise from a *silent* MITM into a *visible, re-verifiable* event **for every pair that has actually completed the peer-verification step above** — and only for those pairs. It is **not** a blanket mitigation: any relationship still in first-contact / directory-trusted state (likely the majority, since most sharing happens before two users bother to verify) continues to rest on D5+D13 until either the pair verifies or the key-transparency log lands (§7.4, §19). The honest framing is therefore *"silent MITM becomes visible for verified pairs; unverified pairs remain exposed at first contact"* — which is why the client surfaces the verified/unverified distinction (above) and why the transparency log stays on the roadmap rather than being considered redundant. Emergency D5 rotation on detection is in §16.4.

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
- **Decrypted metadata from other users is untrusted input (resolves D24).** Filenames, MIME types, tags, notes, and folder paths in `enc_metadata` (§13) are authenticated to their author — but the author may be a *malicious sharer* (D11): **authenticated ≠ benign**. The client therefore treats decrypted metadata as adversarial before it reaches any dangerous sink:
  - **Filesystem (export, §13 listing).** A chosen filename is untrusted input reaching the **downloader's** filesystem on export — a path-traversal / overwrite vector (CWE-22). The client uses the basename only, strips path separators and control characters, rejects absolute paths, `..` segments, and platform-reserved names (Windows `CON`, `NUL`, trailing dot/space, NTFS alternate-data-stream `name:stream` syntax), and never passes a plaintext path to an external application.
  - **UI / rendering.** Metadata rendered in any embedded webview or markup context is escaped for that context (no `innerHTML`-style sinks) to prevent injection (CWE-79).
  - **No metadata value is interpreted as a path, command, or markup** without the sanitization above, regardless of its signature.
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

> **What "bound to the TLS channel" means (token-binding spec).** The session token is **not** a bare bearer credential. The server records, alongside the issued token, the **TLS exporter value** of the channel it was minted on, and every subsequent request is accepted **only** when presented over a channel whose exporter matches (RFC 8471-style token binding, or the connection's exporter re-derived per request). A token lifted from the keystore and replayed over a *different* TLS channel therefore fails the binding check (fail closed). This makes a stolen token unusable off the originating device's live channel, complementing keystore storage and short TTL.

Domain separation + channel binding prevent cross-protocol reuse and relay of the signature; single-use nonces prevent replay; token-channel binding prevents lifted-token replay (resolves L4 and the channel-binding part of H2).

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
- **Two distinct, separately-authorized capabilities per file (resolves R15 / D21).** The model separates the **durable ACL** (who may read / who may write) from **per-version key custody** (who holds a given version's DEK):
  - **Read** = the ability to decrypt a version. A user may read a version **iff** a wrap row exists for `(file_id, that version, that user_id)` with a valid wrap-grant (§12.3a) **and** the user's `status == active`. There is no global "authorized users" set; the per-version recipient set is chosen **explicitly** by the version author from directory-verified bindings (resolves L3).
  - **Write** = the ability to author a new version (re-encrypt content, rotate the DEK, choose the next recipient set). Write is **not** implied by read. A user may write a file **iff** they are the file **owner** (authenticated by the immutable `genesis`, §11.7) **or** they hold a valid **write-grant** chaining to that owner (§11.6), **and** they are **not** under an active tombstone for the file. Authorship is verified by **every downloader** via the author-entitlement check (§12.5) — so the server cannot pass off a version authored by a non-writer.
- **The owner is the root of write authority.** The uploader of version 1 is the file `owner_id`, fixed by the owner-signed `genesis` (§11.7). The owner implicitly holds read+write and is the root to which all write-grants chain.
- The server enforces *coarse* authorization (don't serve a wrap to someone with no row; don't accept a write from someone with no apparent grant). This is a **defense-in-depth / availability** control, not the confidentiality/integrity boundary — even if the server mis-serves, a user without the matching private key cannot unwrap, and a version authored without a valid write-grant chain is rejected by clients regardless of what the server accepted.
- **Re-sharing *read* is delegated (D11):** any active user who already holds a wrap for a file may add a **read** wrap for any other **directory-verified** active user who is **not under an active tombstone** for that file (the online re-share path, §12.4b). The new wrap carries a **granter signature** (`grant_sig`, §12.3a) and records `granted_by` for the sharing-graph audit (§11.4).
- **Delegating *write* is a stronger, owner-rooted act:** only a current write-holder (or the owner) may issue a **write-grant** (§12.3b) to another user; it is durable, append-only, and likewise chains to the owner. Granting read does **not** confer write.
- The server still **cannot** mint a usable wrap (needs the plaintext DEK), **inject a recipient into a future version** (every honored wrap must carry a valid grant chaining to the version author), **or forge write authority** (write-grants/genesis carry signatures it cannot produce). Restricting *read* re-sharing further would be theater for the *current* version — a recipient can pass content out of band — but the grant + write-grant + tombstone machinery makes the in-system paths *authenticated, attributable, and revocable*. Cutting off a re-shared subtree means walking `granted_by` (§14.5).
- **Every state-changing request** (upload, read-grant, write-grant, revoke, rotate) re-checks the session and the caller's entitlement before any side effect; failures **fail closed** (deny) and are audit-logged.

### 10.1 Privileged (admin) operations (resolves M-4)

State-changing operations beyond a user's own files — soft/strong revoke of another user, triggering rotation, changing a user's server-side `status`, scheduling enrollment/recovery ceremonies, and publishing directory updates — require an **operator (admin) capability**, not mere authentication.

- **Rooted in the offline trust, not the server.** Admin capability is a `roles` entry in the user's **offline-signed identity binding** (§7.1), which sets the *ceiling*. The server therefore **cannot promote anyone** (it can't forge the binding), so a compromised server cannot grant itself admin.
- **Effective role = ceiling ∩ status (fast revocation).** The capability actually honored is `binding.roles ∩ status_attestation.eff_roles` (§7.2 step 8). This closes the role-revocation-latency gap: dropping someone's `admin` capability is a **status-attestation change that takes effect within one freshness epoch** (≤ 12 h, §7.6) — no air-gapped re-sign and no need to suspend the whole account. The status signer can only *narrow* roles, so it can de-admin but never escalate. Full removal of the *ceiling* (the binding's `roles`) still waits for binding expiry or an emergency re-sign (§16.4), but the user is already non-privileged within an epoch.
- **Authenticated like any user.** Admins prove identity with the same channel-bound challenge-response (§9.2); there is no separate password path.
- **Authorized per operation, server-side, fail closed.** Every privileged endpoint checks the caller's directory-verified **effective** roles (§7.2 step 8) before any side effect; absence or any verification failure ⇒ deny and audit.
- **Dual control for destructive / breakglass ops.** Mass revoke, key rotation, and any **recovery-key** use (the breakglass admin, §6.3 / §12.7) require **two distinct admins** to authorize. For the **recovery-key** ceremony this is a *physical/procedural* control (two people at the air-gapped device) and is robust; for purely **server-side** destructive ops (e.g., mass soft-revoke) it is enforced by the untrusted server and is therefore *advisory* against a fully-compromised server — those ops affect availability/integrity, not confidentiality, and the cryptographic backstops (tombstones §11.5, grants §12.3a) are what actually bind.
- **Accountable.** The **external** audit sink (§11.4, §16.5) binds `actor` to the authenticated admin identity for every privileged action — including ceremony fingerprint match/mismatch and recovery use — so accountability survives even if the server-local mirror is tampered.
- **Confidentiality is unaffected either way.** No admin action yields plaintext: decryption still needs a user's private key or the offline recovery key. The admin role governs **integrity, availability, and accountability**, not file confidentiality — a rogue admin can deny or disrupt, but cannot read files (unless they hold the offline recovery key, which is the breakglass power, dual-controlled above). This holds **even through a rotation**: an online admin cannot escalate to read by signing a carry-forward grant, because an honored grant requires the DEK-possession tag `dek_poss` (§12.3a, D25) that only a party actually holding the plaintext DEK — i.e. the offline recovery operator — can produce (closes R24).

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
| `roles` | Offline-signed capability **ceiling**, e.g. `{user}` or `{user, admin}` (§7.1, §10.1). The capability actually honored is this ∩ the status attestation's `eff_roles` |
| `directory_signature` | Ed25519 signature over the identity binding by the offline signing key (§7.1) |
| `status_attestation`, `status_signature` | Latest short-lived status attestation (carries `status` + `eff_roles`) + its signature by the status signer (§7.6) — the **authoritative** status and effective roles |
| `status` | Server-side coarse copy for serving decisions; the signed `status_attestation` is authoritative (§7.6) |
| `enrolled_at`, `signed_at` | Timestamps (`signed_at` null until the ceremony signs the binding) |

> Note (D4): there is **no** `salt`, `kdf_params`, or `encrypted_private_key` column. Those live only on the user's device (§9.1), which is what removes the server-side offline-guessing target (resolves L1 by eliminating the overloaded `verifier` column entirely).

### 11.2 `files`

| Field | Description |
|---|---|
| `file_id` | Stable identifier |
| `owner_id` | Uploader; the **root of write authority** for the file (§10/§11.6). Authenticated by the immutable `genesis` record (§11.7), **not** by this server-held column — a server-altered `owner_id` is detected because it won't match the owner-signed genesis. Still not a decryption capability |
| `blob_ref` | Pointer to chunked ciphertext in the blob store |
| `chunk_size`, `chunk_count` | Framing parameters (§12.10) |
| `enc_metadata` | Client-encrypted filename + attributes (§13) |
| `manifest` | Signed manifest (§12.3): sizes, content digest, key commitment (`dek_commit`), and the mandatory-recovery assertion (`recovery_present`). It does **not** commit to the full recipient set — recipients are authenticated **per-wrap** by grants (§12.3a), which is precisely what lets re-share (§12.4b) add a wrap to an already-signed version without re-signing the manifest (L-2) |
| `manifest_sig` | Uploader's (or rotator's) Ed25519 signature over `manifest` |
| `alg` | Algorithm identifiers (content + framing) for agility |
| `version` | Increments on re-encryption / rotation |
| `created_at`, `updated_at` | Timestamps |

### 11.3 `file_key_wraps` — where **read** access lives (per-version key custody)

One row per `(file, version, recipient)`. This table governs **read** (who holds a given version's DEK); **write** authority is durable and lives separately in `write_grants` (§11.6), rooted at the file `genesis` (§11.7).

| Field | Description |
|---|---|
| `file_id` | The file |
| `file_version` | Which version this wrap unlocks |
| `recipient_id` | A `user_id`, or the special recovery recipient |
| `recipient_type` | `user` / `recovery` |
| `wrapped_dek` | DEK encrypted to the recipient's directory-verified `enc_pub` (HPKE) |
| `wrap_alg` | Wrapping algorithm identifier |
| `granted_by` | `user_id` (or `recovery`) that created this wrap — sharing-graph audit (§12.4b) |
| `dek_poss` | DEK-possession tag `HKDF(DEK, "MaxSecu-grant-poss-v1" ‖ canonical(file_id ‖ file_version ‖ recipient_id ‖ recipient_type ‖ granted_by))` — only a party that **held the version DEK** can compute it. Re-derived and matched by any DEK-holder (the rotator at carry-forward, the recipient on download), so a grant signed by a non-DEK-holder is **not honored** even with a valid signature (§12.3a, D25) |
| `grant_sig` | The granter's Ed25519 grant signature over `(file_id, file_version, recipient_id, recipient_type, dek_commit, dek_poss, granted_by, created_at)` (§12.3a). A wrap whose `grant_sig` does not verify — or whose `dek_poss` does not match — is treated as **absent** |
| `created_at` | When the wrap was added |

> **Invariant restated:** the server can *delete* wraps (deny access / revoke) but cannot *create* a usable wrap for a new recipient — that needs the plaintext DEK, which requires either an authorized user's private key or the offline recovery key. **Nor can it inject a recipient to be carried into the next version**, because every wrap honored by clients must carry a valid `grant_sig` chaining to the version author (§12.3a), which the server cannot forge. **Nor can it confer write authority** — authorship is gated by owner-rooted `write_grants` + `genesis` (§11.6/§11.7) and re-checked by every downloader (§12.5). So the server cannot grant itself or anyone else read **or** write access — now or at the next rotation.

### 11.4 `auth_events` (audit)

Append-only: auth attempts, grants, revokes, rotations, ceremony actions — with actor, target, result, timestamp. No secrets or plaintext.

> **This table is convenience, not evidence (resolves the audit-integrity gap).** `auth_events` lives on the **untrusted** application server, yet the design repeatedly cites the audit log as the *detection* backstop for exactly the attacks a malicious server or compromised signer would mount (§3.1, §7.6). A server that is itself the adversary can drop, reorder, or forge these rows. Therefore the **authoritative** audit trail is an **external, append-only sink outside the server's control** (§16.5) — write-once storage / an independent SIEM, with periodic digest anchoring — and `auth_events` is treated as a fast local mirror only. Every "bounded, detectable" claim in this document means *detectable in the external sink*, not in this table.

### 11.5 `revocations` (authenticated tombstones)

Signed records that drive **strong revoke** and gate re-sharing (§12.9b). One row per revocation action; never deleted (append-only, monotonic).

| Field | Description |
|---|---|
| `file_id` | The file, or the sentinel `*` for an account-wide strong revoke across every file |
| `revoked_user_id` | The recipient being removed from future versions |
| `from_version` | Revocation applies to this file `version` and all later ones |
| `revocation_epoch` | **Monotonic** counter per `file_id` (and a separate global counter for `*`); rollback-guarded by client trust-on-last-use memory exactly like file `version`/`key_version` (§7.5) |
| `issued_by` | Admin `user_id`; the action requires the `admin` effective role (§10.1) |
| `co_signed_by` | Second distinct admin for mass/destructive revoke (dual control, §10.1); null for single-file |
| `revocation_sig` | `Ed25519_sign(admin.sig_priv, "MaxSecu-revocation-v1" ‖ canonical(revocation))` over the fields above, verified against the issuer's directory-verified admin binding |
| `created_at` | Timestamp (also written to the external audit sink, §16.5) |

> **Why this exists:** without it, the set of "still-authorized users" consulted during lazy rotation (§12.9) would be whatever the **untrusted server** says it is — letting a malicious server silently re-admit a strong-revoked user to the next version (a revocation bypass). A signed, monotonic tombstone moves that decision onto authenticated ground (§12.9b).

> **Completeness anchoring (D22).** At issuance, a tombstone's new `revocation_epoch` is **registered with the status-signing infrastructure** (§7.6), not derived from the application server: the status signer staples the **global (`*`) head** into every `status_attestation` (§7.1) and answers **nonce-challenged per-file head** queries (§7.6). Clients require the served tombstone set to be **contiguous up to the anchored head** and fail closed on a gap — so a malicious server can no longer *withhold* a fresh tombstone beyond one freshness epoch, only deny service.

### 11.5a `reinstatements` (authenticated un-revoke)

Because tombstones are append-only and keyed by the stable `user_id`, an account-wide (`*`) strong-revoke would otherwise permanently bar a `user_id` that is later legitimately re-admitted (e.g., a user revoked in error, or a returning member). A **reinstatement** is the only way to supersede a tombstone; it never deletes one.

| Field | Description |
|---|---|
| `file_id` | The file, or `*` for an account-wide reinstatement |
| `reinstated_user_id` | The user being re-admitted to future grants/versions |
| `supersedes_epoch` | The `revocation_epoch` this reinstatement clears; must reference an existing tombstone |
| `reinstatement_epoch` | **Monotonic** counter (per `file_id`, and global for `*`), anchored exactly like `revocation_epoch` (§7.6) so it cannot be hidden or rolled back |
| `issued_by`, `co_signed_by` | Admin (`admin` effective role, §10.1); **dual control mandatory** — reinstatement is a privilege-restoring act |
| `reinstatement_sig` | `Ed25519_sign(admin.sig_priv, "MaxSecu-reinstatement-v1" ‖ canonical(reinstatement))`, verified against the issuer's directory-verified admin binding |
| `created_at` | Timestamp (also to the external audit sink, §16.5) |

A user is "under an active tombstone" for a file (as of a given version) **iff** there exists a `revocation` naming them with `from_version ≤` that version for which **no** `reinstatement` carries `supersedes_epoch ==` that revocation's `revocation_epoch`. The match is by the explicit `supersedes_epoch` **reference**, per `(file_id, revoked_user_id)` — **never** by numerically comparing the `revocation_epoch` and `reinstatement_epoch` counters, which are **independent** monotonic sequences whose direct comparison is ill-typed: counter drift could otherwise let an unrelated reinstatement appear to clear a never-superseded revocation, a revocation bypass (M-4). Consequently a `reinstatement` clears **only** the specific revocation it names; a *later* re-revocation (a new, higher `revocation_epoch`) is unaffected, and a stale reinstatement cannot clear it. A `reinstatement.supersedes_epoch` must reference the **highest outstanding** (not-yet-superseded) revocation for that `(file_id, revoked_user_id)`. Re-enrollment after device loss (§12.6) does **not** by itself clear a tombstone — a previously strong-revoked `user_id` needs an explicit reinstatement; a never-revoked user needs none.

> Add `"MaxSecu-reinstatement-v1"` to the domain-separation set (§5).

### 11.6 `write_grants` — where **write** authority lives (durable, owner-rooted)

Authorizes a user to **author new versions** of a file (§10/§12.5). Durable and **append-only** — *not* pruned on rotation (unlike per-version wrap-grants), because a downloader of a future version must be able to verify the author's authority without access to pruned prior versions. One row per `(file_id, grantee_id)` write delegation.

```
write_grant = {
  file_id,
  grantee_id,                  // the user granted write authority
  granted_by,                  // the owner (rooted by genesis, §11.7) or a current write-holder (delegation)
  granted_by_key_version,      // pins which directory binding verifies granted_by's signature (§11.1 historical bindings)
  created_at
}
write_grant_sig = Ed25519_sign(granted_by.sig_priv, "MaxSecu-write-grant-v1" ‖ canonical(write_grant))
```

| Field | Description |
|---|---|
| `file_id` | The file |
| `grantee_id` | User receiving write authority |
| `granted_by` | Owner or an existing write-holder (delegation edge, like `file_key_wraps.granted_by`) |
| `granted_by_key_version` | The granter's `key_version` at signing time — selects the (possibly historical) binding that verifies `write_grant_sig` |
| `write_grant_sig` | Granter's Ed25519 signature, domain `"MaxSecu-write-grant-v1"` |
| `created_at` | When write authority was conferred (also to the external audit sink, §16.5) |

**Validity (client-enforced, fail-closed).** A `write_grant` is valid iff `write_grant_sig` verifies against `granted_by`'s directory binding for `granted_by_key_version`, **and** that `(granted_by, granted_by_key_version)` is **not** under a `key_compromise` cutoff whose effective time predates this record's external-sink anchoring (§11.7 addendum, D28), **and** `granted_by` is the file **owner** (matches `genesis.owner_id`, §11.7) **or** `granted_by` itself holds a valid `write_grant` for the file (the chain to the owner). A write-holder under an active tombstone (§11.5) confers nothing, and revoking a write-delegator means walking the `granted_by` subtree (§14.5) exactly as for read re-shares.

> **Why durable, not per-version.** Read custody is intrinsically per-version (a wrap unlocks one version's DEK), so wrap-grants are pruned with their version. Write authority is a property of the *file*, and the proof must survive content rotation/pruning — so write-grants persist. The version author embeds the genesis + its write-grant chain (small signed records) so any downloader can verify authorship offline of the pruned history (§12.5).

### 11.7 `file_genesis` — the immutable ownership root

Created once at upload (§12.2); **never modified or deleted**. It is the authenticated root of write authority, replacing trust in the server-held `files.owner_id` column.

```
genesis = {
  file_id,
  owner_id,
  owner_key_version,           // pins the owner binding that verifies this signature
  created_at
}
genesis_sig = Ed25519_sign(owner.sig_priv, "MaxSecu-genesis-v1" ‖ canonical(genesis))
```

| Field | Description |
|---|---|
| `file_id` | The file |
| `owner_id` | The root write-authority holder (the version-1 uploader) |
| `owner_key_version` | Owner's `key_version` at creation — selects the binding that verifies `genesis_sig` |
| `genesis_sig` | Owner's Ed25519 signature, domain `"MaxSecu-genesis-v1"` |
| `created_at` | Creation timestamp |

> **Verifying durable records across owner key rotation (§11.1 addendum).** Because `genesis` and `write_grants` are durable, their signers may later rotate keys (`key_version++`, §12.6). The directory therefore **retains superseded bindings indexed by `(user_id, key_version)` solely for verifying signatures over durable records** — a signature is checked against the binding valid *at signing time* (its `not_before`/`not_after` window), which is a *historical-validity* check, **not** a *freshness* check. Freshness/revocation of the underlying authority is handled separately by tombstones (§11.5) and status (§7.6); ownership itself does not expire. Re-enrollment does not break ownership: `owner_id` is stable and the historical binding still verifies the original `genesis_sig`.

> **Compromised old keys cannot forge new durable records (resolves R27/D28).** Indefinite retention of a historical binding is exactly what an attacker who steals a user's *old* `sig` key would exploit: because durable records are append-only and carry a client-chosen `created_at`, a stolen `key_version` could otherwise mint **backdated** `write_grant`s that verify forever against the retained binding — even after the user rotated *because* of that compromise. The historical-validity check is therefore gated by a **signing-compromise cutoff**: on a compromise-driven rotation an `admin` publishes a signed `key_compromise = {user_id, key_version, effective_from}` (domain `"MaxSecu-key-compromise-v1"`, dual-controlled, §10.1) and **registers it with the external audit sink (§16.5)**. A durable record signed under `(user_id, key_version)` is honored **only if its append-only sink anchoring predates `effective_from`** — so a forgery inserted after the compromise is rejected regardless of a backdated `created_at`, because it cannot retroactively acquire an earlier sink position. Add `"MaxSecu-key-compromise-v1"` to the domain-separation set (§5). Genesis is immutable and created once (§12.2), so this primarily guards `write_grant`s; a never-compromised key needs no cutoff and verifies as before.

---

## 12. Protocol flows

### 12.1 Enrollment + offline signing ceremony (consequence of D5)

1. User registers (§9.1); server stores an **unsigned** `users` row (`status=active`, `signed_at=null`). The account can authenticate but is **not yet a valid recipient** (its binding is unsigned, so other clients reject it per §7.2).
2. The user presents their **key fingerprint** to the admin **in person** (D9) — compared visually on-screen or scanned by QR. The full base64 value is matched; because it is case-sensitive, visual/QR comparison is preferred over reading it aloud.
3. The admin runs a **signing ceremony** on the air-gapped device. For each pending binding, the admin's signing tool displays the fingerprint computed from the binding's `enc_pub`/`sig_pub` **and the `username` the server attached to it**; the admin **signs only if (a) the fingerprint matches the one the person presented *and* (b) the `username` in the binding is the correct name for the person physically present** (L-4). The fingerprint binds the *key* to the human (D9); confirming the `username` too binds the *name* to the human — which matters because the common first-contact sharing path addresses recipients by `username`, and the in-person setting makes this check natural (the admin already knows who is enrolling). A fingerprint **or** username mismatch means the server tampered with (or confused) the binding — refuse and investigate. Short-lived 12 h **status attestations** are issued separately by the status signer on a frequent automated schedule, **not** at this air-gapped ceremony (§7.6); this ceremony only creates or rotates identity bindings.
4. Server publishes the now-signed bindings. Verified users become valid recipients.

> **Why the fingerprint, not the `user_id`:** the binding's public keys come from the (untrusted) server, so confirming only the `user_id` would let a malicious server slip in its own key under that id. Confirming the *fingerprint* — a hash of the actual keys, shown by the user's own client — is what binds the real human to the real key and makes C1 genuinely closed (D9).

> **Operational note:** enrollment is **not instant** (the accepted cost of D5). Communicate the signing cadence (e.g., daily) to users. Steps 2–3 are the human checkpoint against a server that tries to enroll or substitute bogus bindings.

### 12.2 File upload

1. Client generates a random per-file **DEK** and a fresh `file_id`; **`version = 1`** (§7.5 monotonic-by-1).
2. Client signs the immutable **`genesis`** (§11.7) binding `file_id → owner_id = self`, establishing itself as the root of write authority.
3. Client encrypts content with **chunked AEAD** (§12.10) → chunked ciphertext + per-chunk tags.
4. Client encrypts filename/attributes → `enc_metadata` (§13).
5. Client selects the **read** recipient set explicitly and **verifies every recipient's binding** against the directory (§7.2); always includes the **recovery** recipient. (The owner is implicitly a writer; to let any of these recipients *also* write, the owner additionally issues a **`write_grant`** per §12.3b.)
6. For each recipient `R`: `wrapped_dek_R = HPKE-Wrap(R.enc_pub, DEK)` with the context-bound `info` (§5).
7. Client builds and **signs the manifest** (§12.3) — setting `author_id` to itself, `version = 1`, and `recovery_present: true` (the one `recovery` recipient **must** be among the wraps) — and **signs a `grant` for every wrap** it just created (§12.3a).
8. Client uploads: `files` row, the **`genesis` + `genesis_sig`**, `enc_metadata`, `manifest` + `manifest_sig`, the chunked ciphertext, one `file_key_wraps` row per recipient (including recovery) **each with its `grant_sig`**, and any `write_grants`. A wrap whose grant does not verify is ignored by honest recipients (§12.3a); for v1 the author is the owner, so the author-entitlement check (§12.5) is satisfied by the genesis directly.
9. Client zeroizes the plaintext DEK.

### 12.3 Signed manifest (resolves H1 — uploader authenticity)

```
manifest = {
  file_id, version, alg, chunk_size, chunk_count,                            // version increments by exactly 1 from the prior version (§7.5, D23)
  content_digest        : SHA-256 over the ordered per-chunk GCM tags,        // binds the whole ciphertext
  enc_metadata_digest   : SHA-256(enc_metadata),
  dek_commit            : HKDF-SHA256(ikm=DEK, info="MaxSecu-dek-commit-v1", L=32),  // binds the content key (derived, not a hash of the raw key)
  recovery_present      : true,                                               // MUST be true — a recovery wrap+grant is mandatory for this version (§6.3, §12.3a)
  author_id, created_at                                                       // author_id = who produced THIS version: the owner (v1) or a write-authorized rotator (§12.9). Authorization checked at §12.5
}
manifest_sig = Ed25519_sign(author.sig_priv, "MaxSecu-manifest-v1" ‖ canonical(manifest))
```

On download, the recipient verifies `manifest_sig` against the **author's directory-verified** `sig_pub` (§7.2), then checks the actual chunk tags hash to `content_digest`. This authenticates **who** produced the version and detects server-side splicing of chunks across versions/files. (HPKE **Auth mode** in §5 provides a second, wrap-level provenance signal.) **Authenticating the author is necessary but not sufficient: the downloader also verifies the author was *authorized to write* — `author_id` equals the genesis owner or holds a valid write-grant chain, and is not tombstoned — via the author-entitlement check (§12.5).** Without that second check, any read recipient who holds the DEK could sign an accepted "next version."

`dek_commit` binds the content key itself. Any party that unwraps the DEK — a recipient on download (§12.5), a granter on re-share (§12.4b), or the admin on recovery (§12.7) — recomputes `HKDF-SHA256(ikm=DEK, info="MaxSecu-dek-commit-v1", L=32)` and **rejects the key unless it matches**, before relying on or re-wrapping it. Committing to a *derived* value (rather than a hash of the raw key) means no direct function of the live DEK is published; and since the DEK is a 256-bit random key the commitment is neither invertible nor guessable regardless. This lets the author's own client self-check every wrap before upload, and lets a recovery or re-share party confirm it holds the *intended* key and cheaply detect a wrong wrap (a 32-byte check) without decrypting the whole file — distinguishing a bad wrap from corrupted ciphertext.

#### 12.3a Grants — authenticating every wrap (resolves the recipient-set-authenticity gap)

The manifest authenticates *content*; a separate, per-wrap **grant** authenticates *who is allowed to hold the key* — i.e. **read** access. (Write authority is the separate, durable owner-rooted grant of §12.3b; holding a read wrap-grant does **not** confer write.) Without the wrap-grant, the set of recipients a rotating client carries into the next version (§12.9) would be whatever the **untrusted server** presents — letting a malicious server inject a colluding (or strong-revoked) user into the next re-wrap and read the file. Every `file_key_wraps` row therefore carries a granter signature:

```
grant = {
  file_id, file_version,
  recipient_id, recipient_type,        // user | recovery
  dek_commit,                          // MUST equal the manifest's — ties this grant to this exact DEK/version
  dek_poss,                            // DEK-possession tag (D25): HKDF(DEK, "MaxSecu-grant-poss-v1" ‖ canonical(file_id ‖ file_version ‖ recipient_id ‖ recipient_type ‖ granted_by)). Only a party that actually held the version DEK can produce it
  granted_by,                          // the author (upload/rotation), a then-current recipient (re-share), or the recovery operator (§12.7)
  created_at
}
grant_sig = Ed25519_sign(granted_by.sig_priv, "MaxSecu-grant-v1" ‖ canonical(grant))
```

Rules, all fail-closed and client-enforced (the server can store grants but cannot forge one — it never holds a `sig_priv`):

- **A wrap is only honored if its grant verifies *and* is DEK-bound.** A downloader fetches its wrap *and* the accompanying grant, verifies `grant_sig` against the granter's **directory-verified** `sig_pub` (§7.2), checks `grant.dek_commit == manifest.dek_commit` and the file/version match, and — once it has unwrapped the DEK — **recomputes `dek_poss` and rejects the grant unless it matches** (D25). A wrap with no valid grant, or whose `dek_poss` does not match, is treated as absent.
- **Grants chain to the version author — and every grant is DEK-bound (D25).** A grant is valid only if `grant_sig` verifies **and** `dek_poss` matches the version DEK, **and** `granted_by` is the version `author_id` (rooted by `manifest_sig`), **or** `granted_by` itself holds a valid grant for the same version (a re-share, §12.4b), **or** `granted_by` is the **recovery operator** performing the offline recovery re-grant (§12.7). The recovery clause adds no extra power, and this is now *cryptographic*, not procedural: a valid grant requires `dek_poss`, which **only a party that actually held the plaintext DEK can produce** — for the recovery operator that is the offline recovery key (§6.3, §12.7), already an all-files capability. **A merely-`admin` identity that does not hold the DEK cannot produce `dek_poss`, so it cannot mint an honored grant.** (This closes R24: previously an admin-signed grant would have been *carried forward and re-wrapped to the next version's fresh DEK by the honest rotator*, handing an **online** admin read access the threat model forbids, §3.1/§10.1. Possession-binding removes that path without dropping legitimate offline recovery re-grants.) Each rotation re-roots all carried-forward recipients under the new author (§12.9), so chains stay short (only re-shares since the last rotation).
- **The carry-forward set is authenticated and DEK-bound, not server-asserted.** When a rotator builds the next version's recipients (§12.9) it holds the current DEK, so it **recomputes `dek_poss` for every candidate grant** and includes a prior recipient **only** if that recipient had a grant whose `grant_sig` verifies *and* whose `dek_poss` matches — so a server-fabricated recipient row (no valid grant), **and any grant whose issuer never held the DEK (e.g. a bare-`admin`-signed one, R24),** is never carried forward, and **strong-revoked recipients are excluded by tombstone** (§11.5).
- **Recovery is mandatory; its *intent* is publicly checkable, its *wrap* only offline (resolves R26).** `recovery_present: true` in the signed manifest asserts the author created a recovery wrap+grant; a recipient verifies a valid **author** grant for the `recovery` recipient exists for the current version and **flags/anomaly-reports** its absence. **This proves the author *intended* recovery (a signed grant over the right `dek_commit`/`dek_poss`); it does *not* prove the recovery `wrapped_dek` ciphertext actually decrypts to that DEK** — only a holder of `recovery_priv` can confirm that. A malicious write-holder (D11) could therefore sign a valid recovery grant while uploading a *garbage* recovery wrap, leaving the file silently unrecoverable. That gap is closed operationally by the **periodic offline recovery-wrap validation sweep (§16.1, D27)**; a current holder can re-wrap recovery via §12.4b if a wrap is found bad. The residual (a deliberately bad recovery wrap is caught at sweep time, not upload time) is documented in §15.3.

> **Residual (honestly).** Grants stop a malicious server from *injecting* or *re-admitting* recipients during rotation/re-share, and make every wrap attributable to a signed granter. They do **not** stop a *malicious current recipient* from grant-signing access to a colluder — that is the inherent endpoint-trust / delegation limit (D11, §15.3), now at least authenticated, attributed, and tombstone-revocable (§12.9b, §14).

#### 12.3b Write-grants — authorizing *authorship* (resolves R15 / D21)

A wrap-grant says "may hold this version's key." A **write-grant** says "may author **new** versions" — re-encrypt content, rotate the DEK, and choose the next recipient set. The two are deliberately separate: sharing a file for reading must not silently hand the reader the power to overwrite it, exclude other readers, or drop the recovery recipient. Write-grants are the durable `write_grants` records (§11.6).

```
write_grant = { file_id, grantee_id, granted_by, granted_by_key_version, created_at }
write_grant_sig = Ed25519_sign(granted_by.sig_priv, "MaxSecu-write-grant-v1" ‖ canonical(write_grant))
```

Rules, fail-closed and client-enforced (the server holds no `sig_priv`, so it can neither forge a write-grant nor a genesis):

- **Issuance.** Only the file **owner** (per `genesis`, §11.7) or a user who **already holds a valid write-grant** may issue a write-grant to another directory-verified user. Issuing write is therefore an owner-rooted, delegable, attributable act — strictly stronger than read re-share (§12.4b).
- **Chain to the owner.** A write-grant is valid iff its signature verifies (against the granter's binding for `granted_by_key_version`, §11.7) **and** `granted_by` is the genesis owner, **or** `granted_by` holds a valid write-grant for the file. Chains root at the owner; there is no re-rooting under a version author (unlike read grants), so write authority cannot be manufactured by becoming an author.
- **Durability.** Write-grants are **not** pruned on rotation; they persist so future-version downloaders can verify authorship (§12.5). The author of a version carries (server-served) the genesis + the write-grant chain proving its own authority.
- **Revocation.** Write authority is revoked by tombstoning the grantee (§11.5/§12.9b); cutting a delegated write subtree walks `granted_by` exactly like read re-shares (§14.5). A tombstoned grantee both loses authorship and confers nothing onward.

> **Residual (honestly).** Write-grants stop a *read-only* recipient and a *malicious server* from authoring or conferring authorship. They do **not** stop a *legitimate write-holder* from overwriting content or excluding other readers — that is the inherent power of write, now owner-rooted, attributable to a signed grant, and tombstone-revocable, with unauthorized reader-exclusion detectable (§12.9). Grant write only to those trusted to modify the file.

### 12.4 Grant access — the common cases (no recovery key needed)

**(a) At upload.** Include the new user in the recipient set (§12.2 step 4).

**(b) Re-share *read* of an already-uploaded file (online).** Any user who currently has access already holds the DEK (they can unwrap it), so they can extend **read** access without any offline ceremony. (Extending **write** is the separate, owner-rooted act of §12.3b — re-sharing read never confers write.) To grant read to user `V`:

1. The granter's client fetches and **verifies `V`'s binding** against the directory (§7.2) — including the fingerprint-rooted signature and the freshness epoch.
2. **Tombstone check (rollback- and withholding-resistant).** The granter fetches the file's revocation tombstones (§11.5), verifies their admin signatures, and **refuses the re-share if `V` is under an active tombstone** for this file (you cannot re-admit a strong-revoked user). It rejects any tombstone set whose `revocation_epoch` is below the highest the client has seen (rollback guard, §7.5), **and** — to defeat a server that *withholds* a fresh tombstone — fetches the **nonce-challenged per-file `max_revocation_epoch` head** from the status signer (§7.6) and **requires the served tombstone set to be contiguous up to that head**, failing closed on any gap (D22).
3. The granter unwraps the current DEK with their own `enc_priv` and checks it against the manifest `dek_commit` (§12.3).
4. The granter computes `wrapped_dek_V = HPKE-Wrap(V.enc_pub, DEK)` with the context-bound `info` (§5).
5. The granter uploads the new `file_key_wraps` row with `granted_by = granter_id`, **the `dek_poss` tag** (which it can compute because it just unwrapped the DEK in step 3, §12.3a/D25), **and a `grant_sig` over the grant** — so `V`'s read access is authenticated to the granter, DEK-bound, and will be honored on download and carried into future rotations.

No recovery key, no admin. The grant is written to the external audit sink with `granted_by` (§11.4/§16.5). This is the everyday sharing path and is strictly better than out-of-band sharing because it is **tracked and authenticated** (D11).

> **Delegation grows the access graph (see §14.5).** A re-shared recipient persists across rotations (the rotator carries forward all validly-granted, non-tombstoned recipients), and **revoking the granter does not automatically revoke whom they granted**. Cutting off a re-shared subtree requires walking `granted_by` and tombstoning the descendants (§14.5) — soft-deleting only the granter's own wrap leaves the colluder in place.

### 12.5 Download / decrypt

1. Authenticated client requests `file_id`.
2. Server checks authorization (§10) and returns the chunked ciphertext, `enc_metadata`, `manifest + manifest_sig`, the immutable **`genesis + genesis_sig`** (§11.7), the **author's write-grant chain** (the `write_grants` + sigs linking `author_id` to the genesis owner, unless `author_id == owner`), **only that user's** `wrapped_dek` **plus its read-grant chain** (the leaf `grant + grant_sig`, and any ancestor re-share grants needed to chain to the version author — never another user's wrap, never the recovery wrap), and the `recovery` recipient's `grant + grant_sig` (the grant only, for the presence check below — not the recovery wrap itself).
3. Client **verifies the manifest** (§12.3) and the author binding (§7.2), then performs the **author-entitlement check (new, D21)**: it verifies the `genesis_sig` (so `owner_id` is authentic), and confirms `author_id == genesis.owner_id` **or** a valid **write-grant chain** (§11.6/§12.3b) links `author_id` to that owner — **and** that `author_id` is **not** excluded from this version by a tombstone (no tombstone for `author_id` with `from_version ≤ manifest.version`, using the contiguity/head checks below). A version whose author lacks write authority, or who was already tombstoned *as of that version*, is **rejected** regardless of a valid `manifest_sig`. (A writer legitimately authored versions *before* their revocation `from_version` remain valid — revocation bars *future* authorship, §11.5, not past history.)
4. **Freshness / rollback.** Client checks the manifest `version` against its **trust-on-last-use** record for this `file_id` — rejecting any version *older* than the highest already seen, and any version exceeding it by more than the small bound / first-contact ceiling (§7.5, D23). It enforces tombstone completeness: a contiguous account-wide (`*`) tombstone set up to the stapled `global_revocation_epoch` in the recipient/author status attestation (§7.1), failing closed on a gap (D22).
5. Client **verifies its own wrap's read-`grant` chains to the author** (§12.3a), and checks `recovery_present` is asserted and a valid author recovery grant exists, flagging anomaly if not (§12.3a). A recipient that **previously read this file** (its trust-on-last-use record shows a prior version) but now finds **no wrap for itself and no tombstone naming it** treats this as an **unauthorized exclusion** and reports it to the audit sink (§12.9 lock-out detection).
6. Client unwraps the DEK with `enc_priv` (verifying the wrap's HPKE Auth-mode sender equals the wrap's `granted_by` `enc_pub`, §5/L-1), **checks `HKDF-SHA256(ikm=DEK, info="MaxSecu-dek-commit-v1", L=32)` equals the manifest `dek_commit`** (rejecting on mismatch), and **confirms every grant in its read-grant chain carries a `dek_poss` matching the now-known DEK** (D25, rejecting any grant whose issuer did not hold the DEK). It then decrypts chunks under the content subkey `ck = HKDF(DEK, "MaxSecu-content-v1")` (verifying each tag and the framing, §12.10) and decrypts `enc_metadata` with `mk = HKDF(DEK, "MaxSecu-metadata-v1")` (§13). Decrypted metadata is **sanitized as untrusted input before any filesystem/UI sink** (§8.1/§13, D24). Plaintext and the DEK stay **in memory only** (§8.1).
7. Any verification failure ⇒ reject and surface a sanitized error (§15).

### 12.6 Account recovery after device loss (consequence of D4)

Because the private key never leaves the device, losing the device loses the key. Recovery:

1. User re-enrolls on a new device → **new** random keypair → new binding signed in the next ceremony (§12.1), `key_version` incremented.
2. Re-grant each file the user was previously entitled to, against their **new** `enc_pub`:
   - For files that **still have another current recipient**, that recipient can re-wrap online (§12.4b) — no recovery key needed.
   - Only for files where **no current recipient remains** does an admin use the offline recovery key (§12.7).
3. User regains access.

> **Re-enrollment and the durable authority records.** **Read** custody is per-`enc_pub`, so each file's wrap must be re-issued to the new key (step 2). **Write** authority is keyed by the *stable* `user_id` (write-grants and genesis name `user_id`, not a key), so a re-enrolled owner/writer **retains write authority automatically** — no re-grant needed; their old `genesis_sig`/`write_grant_sig` still verify against the retained historical binding (§11.7). A re-enrolled user who was previously **strong-revoked** is **not** silently re-admitted: their `user_id` stays under the tombstone until an explicit `reinstatement` (§11.5a).

> Optional self-recovery (does not violate D4): the client may let the user **explicitly export** a sealed backup of `local_key_blob` (still password-encrypted) to user-controlled storage. This is a deliberate, user-initiated action, not server storage. Without it, recovery depends on the admin + recovery key (and therefore on the recovery device not being lost — see §15.3 / §16.3).

### 12.7 Grant access via the offline recovery key (fallback only)

Needed **only** when no current recipient is available to perform the online re-share (§12.4b) — e.g., the last authorized user is gone, or for device-loss account recovery (§12.6). For everyday sharing, use §12.4b; this keeps the recovery device in the safe almost all the time.

1. Admin operates the **air-gapped** recovery device, exactly as any user unlocks their own key locally (§9.2): `recovery_priv` never touches a networked machine. The recovery wraps to process are hand-carried in (e.g., removable media), and the resulting new wraps are hand-carried out — only ciphertext crosses the air gap.
2. For each target `file_id`, the server provides the **recovery** wrap of the current version.
3. Admin unwraps the DEK locally with `recovery_priv` and **checks it against the manifest `dek_commit`** (§12.3) before relying on it.
4. Admin **verifies the new recipient's binding** (§7.2) and that the recipient is not under an active tombstone for this file (§11.5), then computes `wrapped_dek_new = HPKE-Wrap(new_user.enc_pub, DEK)`.
5. Admin uploads the new `file_key_wraps` row **with a recovery-operator `grant_sig` and the `dek_poss` tag** (§12.3a) — signed on the air-gapped device by the admin's own `sig` key, with `dek_poss` computed from the DEK they just unwrapped with `recovery_priv` (D25). Only the resulting ciphertext + grant cross the air gap. Because honored-ness now rests on `dek_poss` (proof of DEK possession), **not** on the bare `admin` role, an online admin who has *not* performed this offline unwrap cannot forge an equivalent honored grant (R24). The action is dual-controlled and written to the external audit sink (§10.1, §16.5).
6. The plaintext DEK is zeroized; the recovery device returns offline.

The server never sees the plaintext DEK. This path restores **read** (it re-wraps the DEK); **write** authority is not granted here and does not need to be — it is keyed by the stable `user_id` and survives re-enrollment (§11.6/§12.6). The admin clause in the read-grant chain (§12.3a) is what makes the admin-rooted re-wrap honored, and it adds no decrypt power the recovery key did not already have (§6.3).

> **Unavoidable tradeoff (scoped to the no-current-holder case):** when *no current recipient still holds a file's DEK*, you cannot simultaneously have (a) no online secret able to recover that DEK, (b) instant online granting, and (c) purely local client decryption. Keeping the recovery capability offline makes *this* case a deliberate offline action — a choice, not a defect. When a current recipient *does* hold the DEK, online re-share (§12.4b) covers it and the recovery key stays in the safe.

### 12.8 Soft revoke

Delete the user's `file_key_wraps` rows and/or set `status=revoked`. The server stops serving them ciphertext/wraps. Does not affect anything already downloaded (§14).

> Soft revoke is a server-side denial and is *not* a cryptographic boundary (a malicious server can simply not honor it — §10). For a guarantee that survives a malicious server, use **strong revoke** (tombstone + rotation, §12.9/§12.9b). And recall that soft-revoking a user who **re-shared** a file does **not** revoke whom they granted — cut the subtree (§14.5).

### 12.9 Strong revoke + key rotation (lazy, per D8)

Strong revoke is recorded as an authenticated **tombstone** (§12.9b); the DEK rotation happens **on the next write**:

0. **Write-authority gate (new, D21).** Only a client holding **write** authority for the file — the genesis owner or a valid write-grant holder (§11.6), and not tombstoned as of the version it is about to author (`from_version >` the new version) — may author the next version. A read-only recipient holds the DEK but **cannot** produce an accepted version, because every downloader runs the author-entitlement check (§12.5).
1. On the next update, the writing client (or an admin) recovers the current DEK (checking `dek_commit`, §12.3), generates `DEK'`, re-encrypts → new chunks + **`version` incremented by exactly 1** (§7.5/D23), and becomes the new version's `author_id`.
2. **Authenticated, DEK-bound recipient carry-forward (not server-asserted).** The writer holds the current DEK, so for each candidate it **recomputes `dek_poss`** (D25). It forms the new **read** recipient set from the prior version's recipients, keeping a recipient **only if** (a) its prior-version wrap carried a **valid grant** chaining to the prior author whose `grant_sig` verifies **and whose `dek_poss` matches** (§12.3a) — dropping any server-injected row *and any grant whose issuer never held the DEK, including a bare-`admin`-signed one (R24)* — **and** (b) it is **not** under an active tombstone (§11.5/§12.9b) — dropping strong-revoked users — then **always re-adds the recovery recipient**. Tombstone exclusion uses the **rollback- and withholding-resistant** check: contiguous tombstones up to the **nonce-challenged per-file head** and stapled global head (§7.6/D22), failing closed on a gap. It wraps `DEK'` to each survivor (context-bound `info`, §5) and issues a fresh **read-grant** per recipient, re-rooting the read-grant chain under itself. **Write-grants are durable and are *not* re-issued or pruned** (§11.6) — write authority is unaffected by rotation.
3. **Metadata re-encryption.** Because `mk = HKDF(DEK, "MaxSecu-metadata-v1")` is bound to the DEK (§13), the writer re-encrypts `enc_metadata` under `mk' = HKDF(DEK', …)`; otherwise new-version recipients could not read filenames/attributes.
4. The new signed manifest sets `recovery_present: true`; old-version **chunks, wraps, and read-grants** are deleted after the new version is committed. The immutable **`genesis`** and the durable **`write_grants`** are **retained** (they authenticate authorship of the new and all future versions, §12.5).

> **Concurrent rotation (resolves R22).** Two writers can race to produce `version v+1`. The server serializes commits on `(file_id, version)` so only the first `v+1` is accepted; a writer whose commit loses (or any writer that sees a newer committed version mid-flight) **rebases** — re-fetches the now-current version, re-derives from its DEK, and authors `v+2`. This keeps `version` a strict +1 chain (compatible with the §7.5 rollback memory and the D23 upper-bound guard) instead of forking. Clients seeing a transient gap wait for the contiguous chain rather than accepting a fork.

> **Lock-out detection (D21 residual).** A write-holder *can* exclude a still-entitled reader by omitting them from the carry-forward set (the inherent power of write). This is **detectable, not prevented**: the excluded reader, on its next download, sees it previously held the file yet now has no wrap and no tombstone naming it, and reports the unauthorized exclusion to the external audit sink (§12.5 step 5 / §16.5). Dropping the recovery recipient is likewise flagged (§12.3a).

Until that next write, the strong-revoked user can still read the **current** version (which they already had). Eager rotation is available as an explicit admin action for high-sensitivity files (§14.4).

> **Why the tombstone is load-bearing.** Step 2's exclusion must not rest on the untrusted server: a strong-revoked user is still an `active` directory identity whose binding verifies fine (§7.2), so binding verification alone would *not* drop them. The **admin-signed, monotonic tombstone** is what an honest writer consults to exclude them, and the monotonic `revocation_epoch` (rollback-guarded by trust-on-last-use memory, §7.5) stops the server from hiding a *known* revocation. **First-contact is now covered too (D22):** before rotating, the writer fetches the **nonce-challenged per-file `max_revocation_epoch` head** from the status signer (§7.6) and requires a contiguous tombstone set up to it — so a writer touching the file for the first time still cannot be fed an incomplete tombstone set. The remaining residual is no longer first-contact but **status-signer availability**: if the head cannot be fetched, the writer fails closed (no rotation) rather than rotating on an unverified set — a bounded DoS, not a revocation bypass (§7.6).

### 12.9b Issuing a strong-revoke tombstone

To strong-revoke user `R` from file `F` (or, with `file_id = *`, from every file):

1. An **admin** (directory-verified `admin` effective role, §10.1) creates a `revocation` record (§11.5) with the next monotonic `revocation_epoch` for `F`, `from_version` = the next version, and `revoked_user_id = R`, signed `"MaxSecu-revocation-v1"`.
2. For mass / `*` revokes, a **second admin co-signs** (dual control, §10.1).
3. The tombstone is published, **registered with the status-signing infrastructure** (so the new epoch is reflected in the stapled global head and the nonce-challenged per-file head, §7.6/D22), and written to the external audit sink (§16.5). From then on every honest rotator excludes `R` (§12.9 step 2) and every honest re-sharer refuses to re-add `R` (§12.4b step 2) — defended against both **rollback** (lower epoch) and **withholding** (gap below the anchored head), bounded to ≤ one freshness epoch (§7.5/§7.6).
4. **Grant-graph completeness — walked from the external sink, not the server (§14.5, D26).** If `R` had re-shared read or **delegated write** for `F` onward, the admin also tombstones the affected descendants (walk both the read `granted_by` graph **and** the write-grant `granted_by` graph, §11.6); revoking only `R` leaves any colluder `R` planted — as a reader or, worse, as a writer — in place. **The subtree is computed from the digest-anchored external audit sink (§16.5), which records every grant edge — *not* from the server-served grant rows.** Otherwise a malicious server colluding with a descendant could *withhold that descendant's edge* from the revoking admin (so it is never tombstoned) while still serving the edge to rotators/downloaders (so the descendant's access persists and is carried forward) — a strong-revoke bypass directly parallel to tombstone-withholding (R16/D22) but on the grant graph. Sourcing the walk from the append-only sink closes it (R25).

> **Reinstating a revoked user.** A tombstone is never deleted; a `user_id` barred by an account-wide (`*`) revoke is re-admitted only by a **dual-controlled, anchored `reinstatement`** (§11.5a), not by re-enrollment. This keeps revoke/reinstate auditable and monotonic.

### 12.10 Large-file handling — chunked/framed AEAD (resolves M1)

- Content is split into fixed-size chunks (default **1 MiB**).
- Each chunk: `AES-256-GCM(ck, nonce_i, chunk_i, AAD_i)` where `ck = HKDF(DEK, "MaxSecu-content-v1")` is the per-version **content subkey** (so the raw DEK is only ever a KDF root — for `ck`, `dek_commit`, `dek_poss`, and `mk` — never directly an AEAD key, L-5), and
  `nonce_i = 96-bit big-endian counter i` (unique because `ck` is unique per file-version), and
  `AAD_i = canonical(file_id ‖ version ‖ chunk_index=i ‖ is_last)`.
- The framing **prevents truncation, reordering, and cross-file/version splicing**: a missing final chunk (no `is_last`) or an out-of-range index is rejected.
- Enables **streaming** encrypt/decrypt and partial integrity, and avoids AES-GCM's single-message size limits. The per-chunk tags are what `manifest.content_digest` (§12.3) commits to.
- **Bound-check framing before allocating.** `chunk_size` and `chunk_count` arrive from the (untrusted) server in the `files` row / manifest; the client validates them against hard limits (e.g., `chunk_size ∈ [4 KiB, 8 MiB]`, `chunk_count · chunk_size ≤ a configured max file size`) and streams rather than buffering the whole object, so a manifest claiming an absurd `chunk_count` cannot drive the client into unbounded allocation (a client-side DoS). Since these fields are inside the signed manifest they cannot be forged — only chosen within the validated range.

---

## 13. Metadata protection (resolves M2, per D7)

- **Encrypted client-side:** filename, MIME type, user-visible attributes (tags, notes), and any client-side folder structure → stored as `enc_metadata`, encrypted with **AES-256-GCM under a separate metadata key `mk = HKDF(DEK, "MaxSecu-metadata-v1")`**. Deriving a distinct key (separate from the content subkey `ck`, §12.10) keeps metadata out of the content chunks' counter-nonce space, so there is no (key, nonce) reuse. `enc_metadata` is therefore unlocked by the same per-recipient wrap as the content. **Nonce:** because `mk` is unique per file-version (it is derived from the per-version DEK) and encrypts exactly one blob, a fixed all-zero 96-bit nonce is used — uniqueness of (`mk`, nonce) is guaranteed by the uniqueness of `mk`, not the nonce. **On rotation** (§12.9) the DEK changes, so `mk` changes and `enc_metadata` is re-encrypted under `mk'`; the manifest's `enc_metadata_digest` binds the per-version ciphertext.
- **Treated as untrusted on decrypt (D24).** Metadata is authenticated to its author, but a *malicious sharer* (D11) controls its contents — **authenticated ≠ benign**. Before a decrypted filename/attribute reaches any filesystem path, external process, or UI/webview sink, the client sanitizes it per §8.1 (basename-only, strip separators/control chars, reject `..`/absolute/reserved-name forms, escape for rendering). A signature on the metadata does **not** exempt it from input validation.
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
| Soft revoke | Delete user's wraps / mark revoked | Future server delivery to that user (server-side only; not vs a malicious server) | Data already downloaded; a malicious server restoring the row |
| Strong revoke (lazy) | **Admin-signed tombstone** (§12.9b) + rotate on next write | Future *versions* — holds even vs a malicious server (tombstone + grants, §12.9) | The current version until next write; the old version they held |
| Strong revoke (eager, opt-in) | Tombstone + immediately re-encrypt + re-wrap | Future versions immediately | The old version they already held |
| Revoke a re-sharer | Tombstone the user **and walk `granted_by`** to tombstone the subtree (§14.5) | The granter *and* whom they granted | Anything any of them already downloaded |

### 14.5 Delegation and grant-graph revocation

Delegated re-sharing (§12.4b, D11) means access forms a **graph**, not a flat list: if A grants V, and V grants W, then revoking A does **not** by itself remove V or W. Because the rotator carries forward *every* validly-granted, non-tombstoned recipient (§12.9), a recipient an insider planted **persists across rotations and survives the insider's own revocation** until that recipient is individually tombstoned. This is the in-system analogue of the inherent "a recipient can leak out of band" limit (D11) — but it is now authenticated and, crucially, **walkable**:

- **`granted_by` forms the edges — for both read and write.** Each read wrap-grant (§11.3/§12.3a) **and** each durable write-grant (§11.6) records who granted it, so **two** authenticated delegation graphs are reconstructable for a file: the read graph and the write graph. Neither rests on server say-so for *authenticity* — and, because *completeness* of the walk would otherwise rest on the server (see below), the graphs are reconstructed from the **external audit sink** (§16.5, D26), not from server-served rows.
- **Write delegation is the higher-impact graph.** A planted *reader* can exfiltrate; a planted *writer* can also overwrite content and exclude others (§12.9). Revoking an insider therefore walks **both** graphs — see §12.9b step 4.
- **Revoking a re-sharer means revoking the subtree.** To truly cut off user `R`, an admin tombstones `R` **and** every recipient reachable from `R` via `granted_by` that has no *independent* grant from a still-authorized path. Tooling computes this subtree **from the digest-anchored external sink (§16.5), not from server-served edges (D26)** — a malicious server could otherwise hide a descendant's edge from the revoker while still honoring it for rotation/download (R25), a grant-graph analogue of tombstone-withholding — and emits the tombstones in one dual-controlled action (§12.9b).
- **Detection.** The external audit sink (§16.5) carries every grant; anomaly rules flag unusually fan-out re-sharing and grants by soon-to-be-revoked users, so an insider planting persistent recipients is visible.
- **Residual.** As with all revocation, this protects *future* versions only; anything already downloaded is gone (§14.1). And a sufficiently determined insider can still leak content out of band — cryptography cannot prevent that (§15.3).

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
- **Rollback is detected:** stale file versions and superseded directory bindings cannot be passed off as current — the binding-`key_version` guard is clock-independent, and an unchanged-key revocation is bounded by the 12 h freshness epoch (§7.5). File `version` advances by exactly 1 and is bounded above, so the rollback memory cannot be poisoned into a permanent-update-denial DoS (§7.5/D23).
- **Authorship is authorized, not just authenticated:** content is **write-protected** — only the owner or an owner-rooted write-grant holder can author an accepted version; a read-only recipient holding the DEK cannot overwrite, exclude readers, or drop recovery silently (§10/§11.6/§12.5, D21). Ownership is rooted in an immutable owner-signed genesis the server cannot forge or reassign (§11.7).
- **Read grants are DEK-bound:** every honored grant carries a `dek_poss` tag only a DEK-holder can produce (§12.3a, D25), so neither a malicious server nor an *online* admin can inject or carry-forward a recipient without having held the plaintext DEK — an online admin cannot escalate to read via a forged grant (closes R24).
- **Strong revoke resists withholding, not just rollback:** a malicious server can no longer indefinitely hide a fresh tombstone — the anchored `max_revocation_epoch` + contiguity check bounds suppression to ≤ one freshness epoch (§7.6, D22).
- Decrypted metadata from other users is **validated as untrusted input** before reaching any filesystem/UI sink (§8.1/§13, D24).
- Decrypted data and keys are held **in memory only** and zeroized after use (§8.1), minimizing on-device plaintext exposure.

### 15.2 Honest scope of "zero-knowledge"

This system is zero-knowledge **of the server**: the server learns nothing of file content or filenames/attributes. Three honest qualifications belong next to the label in any product copy (§13, §18):

- **Not metadata-private.** It is **not** zero-knowledge of **sizes, timing, or the sharing graph**; the server learns *coarse* access patterns.
- **Not operator-incapable (escrow).** "Zero-knowledge of the server" is **not** "no-one can decrypt." The offline recovery key (D6) is a standing recipient on every file and can decrypt everything (§1.2, §6.3, §3.1). The guarantee is about the *server's* knowledge, not the *operator's* capability.
- **Not post-quantum (v1).** Confidentiality rests on X25519 wraps; a future cryptographically-relevant quantum computer plus *harvested* ciphertext breaks v1 confidentiality retroactively, and the standing recovery wrap concentrates that into one key. The PQ-hybrid wrap (§5/§19) is the mitigation and is **prioritized** accordingly (§17 Phase 7).

### 15.3 Inherent / residual limitations

- **Offline guessing** of a stolen *device's* local key is always possible; Argon2id only makes it expensive (not impossible).
- **Revocation cannot retroactively** remove already-downloaded data (§14.1).
- **User private-key compromise is retroactive:** whoever obtains a user's `enc_priv` can unwrap **every DEK ever wrapped to that user** — i.e., every file that user could access (resolves L2 by documenting it).
- **Recovery device (D6) is a single point of theft and of loss.** Theft ⇒ all uploaded files recoverable by the attacker. Loss ⇒ no future old-file grants and broken device-loss recovery (§12.6) unless a sealed backup exists (§16.3). **Shamir split is the recommended future upgrade** (§19).
- **Signing device (D5) compromise** enables MITM of *future* uploads via forged bindings (not past files); mitigated by air-gap, ceremony review, rotation, and (future) transparency (§7.4).
- **Client build/update pipeline is in the TCB** (§8); defended by signing + reproducibility + transparency, not by server honesty.
- **Malicious authorized client** can exfiltrate plaintext it is entitled to read; endpoint trust is assumed. In-memory-only handling (§8.1) shrinks but does not remove this; a running client with a file open still exposes that file. User-level discipline (lock your device) is the mitigation (§1.3).
- **A legitimate *write*-holder can overwrite or lock out — detectable, not prevented.** Write authorization (D21) stops *read-only* recipients and the *server* from authoring versions, but anyone genuinely granted write can replace content, exclude other readers, or drop the recovery recipient. These acts are owner-rooted, attributable to a signed write-grant, tombstone-revocable (§14.5), and an unauthorized reader-exclusion is detected by the excluded reader (§12.5/§12.9) — but they are not cryptographically *prevented*. Grant write only to those trusted to modify the file.
- **Tombstone completeness is bounded by one freshness epoch and by the status infrastructure.** The withholding defense (D22) depends on the status signer learning revocation epochs authoritatively at issuance (§7.6) and on clients reaching it; a status outage degrades to the §7.6 availability fuse, and first-contact on a brand-new file still relies on the served set until the head is fetched.
- **Account-wide revoke is sticky by design.** A `*`-tombstoned `user_id` is barred until an explicit dual-controlled `reinstatement` (§11.5a); re-enrollment alone does not clear it. An operator error here is recoverable only by reinstatement, not silently.
- **Directory equivocation** by a *compromised signing key* is bounded by air-gapped custody, the freshness epoch (§7.5), rotation, and **peer key pinning** (§7.7) — which fully closes it for any pair that has verified in person. It stays open for pairs that have *never* met (likely the majority of sharing, which happens at first contact, §7.7), pending the transparency log (§19).
- **No post-quantum confidentiality (v1).** X25519 wraps are vulnerable to *harvest-now-decrypt-later*: an attacker who copies the blob store + wraps today decrypts them once a CRQC exists, and the standing recovery wrap means one key breaks everything. Mitigated only by the future PQ-hybrid wrap (§5), now prioritized as Phase 7 (§17/§19).
- **Audit/detection integrity depends on the external sink.** Many "bounded, detectable" claims (revocation latency, off-schedule status issuance, over-sharing) are only real if the **external, append-only audit sink** (§16.5) is intact; the server-local `auth_events` mirror is forgeable by a malicious server (§11.4).
- **Recovery-wrap validity is verified offline, after the fact (R26/D27).** A downloader can confirm the recovery *grant* (intent), but only `recovery_priv` can confirm the recovery *wrap* actually decrypts to the DEK. A malicious write-holder can thus upload a bad recovery wrap that passes every online check; it is caught by the **periodic offline validation sweep (§16.1)**, not at upload — so an undetected window exists between a bad write and the next covering sweep. Sampled sweeps trade coverage latency against cold-key exposure.
- **Grant-graph subtree revocation depends on the external sink (R25/D26).** Cutting a re-shared/delegated-write subtree (§14.5) is only complete if the `granted_by` graph is walked from the **anchored external sink**; if tooling instead trusts the server's served edges, a malicious server can hide a descendant to shield a colluder. This is the same trust dependency as every other "detectable" property, now made explicit for the grant graph.
- **Durable-record forgery is bounded by the compromise cutoff, not eliminated (R27/D28).** A stolen pre-rotation `sig` key can still mint durable write-grants that the attacker manages to anchor in the sink *before* the `key_compromise` cutoff (§11.7) — indistinguishable from legitimate pre-compromise grants. The cutoff bounds exposure to the detection-to-cutoff window (like emergency D5 rotation, §16.4); it does not retroactively invalidate authority the old key could legitimately have conferred.
- **Revocation freshness depends on the client clock** for the revoke-without-key-change case (§7.5); a backdated client extends a revoked user's window past the epoch unless the nonce-challenged status fetch is used. The clock-independent `key_version` guard is unaffected.
- **Admin-role *ceiling* removal is not instant.** Effective admin is dropped within one epoch via the status attestation (§7.6/§10.1), but removing the binding's `roles` ceiling waits for binding expiry or an emergency re-sign (§16.4). A user is non-privileged within an epoch, but the long-lived binding still *names* the role until then.
- **Status signer is a fleet-wide availability fuse.** Loss of status issuance (outage or a malicious server withholding staples) halts all new sharing within one epoch (§7.6); mitigated by HA issuance, not eliminated.
- **First-contact rotation no longer relies on the served tombstone set (D22).** A writer that has never seen a file fetches the nonce-challenged per-file `max_revocation_epoch` head (§7.6) and requires a contiguous tombstone set up to it before rotating, so an incomplete set is rejected. The residual shifts from *first-contact suppression* to *status-signer availability*: if the head is unreachable the writer fails closed (no rotation), a bounded DoS rather than a revocation bypass. Grants still independently prevent injecting a never-authorized recipient.

---

## 16. Operations

### 16.1 Ceremonies

- **Enrollment signing** (§12.1): scheduled, air-gapped, with **in-person fingerprint verification** of each new identity binding (§7.1). Cadence published to users.
- **Status attestation** (§7.6): automated, frequent re-issuance (well within the 12 h epoch) of directory status by the status signer; revoking a user = stop attesting them. Not air-gapped.
- **Old-file grant / account recovery** (§12.7, §12.6): air-gapped recovery-key sessions, audited.
- **Recovery-wrap validation sweep** (§12.3a, D27): a periodic air-gapped session in which the recovery operator **samples file-versions, unwraps each `recovery` wrap with `recovery_priv`, and confirms it decrypts to the committed DEK (`dek_commit`)** — catching a malicious write-holder who signed a valid recovery *grant* but uploaded a bad recovery *wrap* (R26), which the downloader-side presence check cannot detect. Any bad wrap is re-wrapped by a current holder (§12.4b) or flagged for eager recovery. Coverage/cadence are risk-based (e.g., all high-sensitivity files; a rolling sample of the rest) to bound cold-key exposure against detection latency.

### 16.2 Error handling

- **Sanitized errors only:** never return DB errors, stack traces, paths, or whether a username exists. Verification failures return a generic rejection; details go to server logs, not clients.
- **Fail closed:** any exception on an auth/authorization path yields deny (401/403), never proceed-as-anonymous.

### 16.3 Backups of the trust root

- **Recovery key (D6):** breakglass, kept **cold** (offline; a written-down/sealed copy is acceptable) with a **sealed, encrypted backup in separate physical custody** (e.g., a second safe). Anyone who physically obtains the cold copy can decrypt **everything** (the escrow, §1.2/§6.3), so custody is the whole control: **tamper-evident sealing, dual-custody, access logged**, and a **Shamir / threshold split** (§19) so no single safe or person holds the whole key. Because a lone written copy is itself a single point of total compromise, the threshold split is treated as a **prioritized hardening item (Phase 7, §17), not open-ended "future work."** Plan rotation as a deliberate (expensive) re-wrap project, not an emergency.
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

- **Authoritative sink is external and append-only.** Because the application server is untrusted and the audit log is the detection backstop for malicious-server / compromised-signer behavior, security events are shipped to an **append-only sink outside the server's control** — write-once (WORM) storage or an independent SIEM — with periodic **digest anchoring** (hash-chain the event stream and publish/cross-store the head, so deletion or reordering is detectable). The server-local `auth_events` table (§11.4) is a fast mirror only; "detectable in the audit log" means *detectable in the external sink*.
- Log (to that sink) every security-relevant event: auth attempts/denials/lockouts, **read grants (with `granted_by` and `grant_sig`)**, **write-grants and genesis creation (§11.6/§11.7)**, **revocation tombstones and reinstatements (§12.9b/§11.5a)**, rotations, **status issuance** (to detect off-schedule issuance, §7.6), ceremony actions (incl. fingerprint match/mismatch), explicit plaintext exports (§8.1), admin operations.
- Redact sensitive data; never log secrets, tokens, or plaintext.
- Alert on anomalies: spikes in auth failures, unusual grant/revoke volume, **high re-share fan-out, write-grant fan-out, or grants by soon-to-be-revoked users (§14.5)**, **client-reported author-entitlement rejections or unauthorized reader-exclusions (§12.5/§12.9, D21)**, **tombstone-set gaps below an anchored head (§7.6, D22)**, **status issuance outside the scheduled job or a stalled issuance heartbeat (§7.6)**, directory-binding changes outside a ceremony window, and files missing a valid recovery grant (§12.3a).

### 16.6 Secrets handling

- No secrets in source, client bundles, container `ENV`, CI logs, or error responses.
- Server holds **no** file-decryption secrets by design; the only high-value secrets (D5/D6 keys) live offline.

---

## 17. Build plan (phased)

Each phase is independently testable and leaves the system in a coherent state.

**Phase 0 — Foundations**
Crypto library selection + wrappers (AES-256-GCM chunked, HPKE/X25519 **with context-bound `info` (§5)**, Ed25519, Argon2id); algorithm-identifier scheme; **injective canonical-serialization spec (§5.2)** covering every signed record (manifest, read-grant, **write-grant, genesis, revocation, reinstatement**, dirbinding, status); test vectors. *Exit:* property tests for encrypt→decrypt, wrap→unwrap, sign→verify, and framing tamper-rejection pass; **adversarial canonical-encoding vectors (field-splitting / trailing-data collision attempts) are all rejected** — a serializer that admits any `‖` ambiguity fails the phase.

**Phase 1 — Identity & auth**
Native client registration (local key generation + Argon2id blob), server `users` storage (public material only), challenge-response with channel binding, session tokens, rate limiting, password policy + breach blocklist. *Exit:* login works; replay/relay/enumeration tests pass; no private material on server.

**Phase 2 — Signed key directory + freshness (C1)**
Offline signing-key tooling + **fingerprint-confirmed** ceremony workflow (§12.1); binding epochs with ceremony re-signing (§7.5); directory storage/serving; client-side mandatory binding verification with pinned root + expiry check; client trust-on-last-use version memory. *Exit:* a server returning a forged binding is rejected; a binding whose fingerprint doesn't match is never signed; expired bindings and rolled-back file versions are rejected; unsigned bindings are not usable as recipients.

**Phase 3 — File upload/download (single-recipient)**
Chunked AEAD blob storage; per-file DEK; **owner-signed genesis (§11.7)**; wrap to self + recovery; signed manifest with **`version`-by-1 (§7.5/D23)**; download with full verification + decrypt; **in-memory-only plaintext handling + zeroization + warned export** (§8.1); **decrypted-metadata sanitization (§8.1/§13/D24)**. *Exit:* large-file streaming round-trips; spliced/truncated/forged-manifest payloads are rejected; no plaintext written to disk (verified by filesystem/swap inspection); **a manifest with a poisoned (near-max) `version` is rejected by the upper-bound guard; a malicious filename cannot traverse outside the chosen export directory** (path-traversal test); export shows the warning and is audited.

**Phase 4 — Sharing & authorization (read *and* write)**
Multi-recipient wraps; per-file read ACL via wrap table; **per-wrap read-`grant` signatures + manifest `recovery_present` (§12.3a)**; **durable owner-rooted write-grants + author-entitlement check (§11.6/§12.3b/§12.5, D21)**; **online re-share of read** with `granted_by` + `grant_sig` audit (§12.4b); **per-grant `dek_poss` DEK-possession tags (§12.3a/D25)**; coarse server authz; encrypted metadata (§13). *Exit:* grant-at-upload, online read re-share, and owner-rooted write delegation work; server cannot mint **or inject** wraps; **an admin-signed (or otherwise non-DEK-holder) grant is neither honored on download nor carried forward at rotation (R24 red-team test)**; **a version authored by a read-only (non-write-granted) recipient is rejected by every downloader (red-team test); a forged/absent genesis or write-grant chain is rejected**; a wrap with an invalid/absent grant is treated as absent; recovery-grant omission is flagged; cross-user wrap leakage tests pass; **unauthorized reader-exclusion is detected**; read- and write-sharing-graph audit is complete.

**Phase 5 — Recovery, grant-old-file, revocation**
Offline recovery-key tooling (admin-grant fallback, §12.7); device-loss recovery preferring online re-share (§12.6); soft revoke; **admin-signed tombstones + status-anchored completeness (§12.9b/§7.6/D22)**; **dual-controlled reinstatement (§11.5a)**; strong revoke with lazy rotation + **authenticated recipient carry-forward** + metadata re-encryption + versioning + **concurrent-rotation rebase (§12.9/R22)**; **read- and write-grant subtree revocation computed from the external sink (§14.5/D26)**; **signing-compromise cutoffs for durable records (§11.7/D28)**; epoch-expiry revocation (§7.5); **fast role revocation via status `eff_roles` (§7.6/§10.1)**. *Exit:* end-to-end grant/revoke/rotate flows verified; **a malicious server cannot re-admit a strong-revoked or inject a never-authorized recipient at rotation, *nor withhold a fresh tombstone beyond one epoch*** (red-team tests against both rollback and withholding); a tombstoned author cannot mint an accepted version; revoked users lose future versions and their binding expires within one epoch; reinstatement restores access only under dual control **and clears only the specific revocation it names (R28)**; **a colluding server cannot shield a delegated subtree by withholding grant edges — the subtree walk sources from the external sink (R25)**; **a backdated write-grant forged under a compromised, rotated-away key is rejected by the sink-anchored cutoff (R27)**; de-admin takes effect within one epoch; audit complete in the external sink.

**Phase 6 — Client integrity & ops (C2)**
Reproducible builds; code signing; signed + transparency-logged updates; **external append-only audit sink with digest anchoring (§16.5)**; status-signer HA + issuance heartbeat (§7.6); monitoring/alerting; **offline recovery-wrap validation sweep (§16.1/D27)**; **revocation checkpoints (§7.6/L-3)**; sanitized-error pass; ceremony runbooks. *Exit:* reproducible-build verification documented; tamper-evident external audit demonstrated; **a recovery wrap that does not decrypt to the committed DEK behind a valid recovery grant is caught by the sweep (R26)**; security review sign-off.

**Phase 7 — Long-term hardening (committed, not "someday")**
**Recovery-key Shamir/threshold split (§16.3)**; **PQ-hybrid wrap X25519+ML-KEM-768 via the algorithm-agility path (§5)**; key-transparency log for the directory (§7.4) closing first-contact equivocation. *Exit:* recovery requires a threshold of custodians (no single cold copy is total); new uploads use the hybrid wrap; clients detect directory split-views against the log.

**Cross-cutting throughout:** threat-model tests per phase, **security events to the external append-only sink (not just the server-local mirror)**, sanitized errors, dependency pinning + audit.

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

### 18.2 Second review round (this revision)

Maps the second-pass findings to where this revision resolves them.

| Finding | Severity | Resolved in |
|---|---|---|
| **R1** Recipient/wrap set never authenticated (strong-revoke bypass at rotation; silent recovery-wrap omission; server recipient injection) | High | §12.3a per-wrap grants; §11.5 tombstones; §12.9 authenticated carry-forward; manifest `recovery_present` (D15/D16); Phase 4/5 |
| **R2** Audit log / detection live on the untrusted server | Med→High | §11.4 + §16.5 external append-only sink + digest anchoring (D18); Phase 6 |
| **R3** Delegated re-share survives the granter's revocation | Medium | §14.5 grant-graph revocation; §12.4b / §12.8 notes (D16); Phase 5 |
| **R4** Admin-role revocation latency (≤ 1 yr) | Medium | §7.1 `eff_roles`; §7.2 step 8; §7.6; §10.1 effective-role intersection (D17); Phase 5 |
| **R5** Canonical serialization / `‖` injectivity | Medium | §5.2 injective-encoding mandate + Phase 0 adversarial vectors (D19) |
| **R6** Mandatory escrow + no post-quantum confidentiality | Medium | §1.2 / §15.2 / §15.3 honest statements; §17 Phase 7 + §19 (D20) |
| **R7** Peer-to-peer verification underspecified & overclaimed | Medium | §7.7 explicit peer-verification protocol + calibrated claim |
| **R8** Revocation freshness depends on client clock | Low→Med | §7.5 clock caveat + nonce-challenged status fetch |
| **R9** Status signer = 12 h fleet-wide availability fuse | Low→Med | §7.6 HA/redundancy + §16.5 issuance heartbeat |
| **R10** Mobile Argon2id reduced profile weakens stolen-device boundary | Low | §5 explicit mobile security floor |
| **R11** Server-supplied framing params not bound-checked | Low | §12.10 client bounds-check before allocation |
| **R12** `dek_commit` published a hash of the raw key | Low | §12.3 KDF-derived commitment (HKDF) |
| **R13** Metadata nonce + rotation re-encryption unspecified | Low | §13 fixed-nonce justification; §12.9 metadata re-encryption |
| **R14** Single `sig` key for auth + manifest (+ grant/revocation) | Info | §5 key-separation note (safe via domain separation) |

### 18.3 Third review round (this revision)

Maps the third-pass findings to where this revision resolves them.

| Finding | Severity | Resolved in |
|---|---|---|
| **R15** Write authorization undefined — authorship authenticated but never *authorized*; any read recipient could overwrite content, exclude readers, or drop recovery; downloaders never checked author entitlement | High | §10 read/write split; §11.6 durable owner-rooted write-grants; §11.7 immutable genesis; §12.3b write-grant issuance; §12.5 author-entitlement check; §12.9 write gate (D21); Phase 4 |
| **R16** "Strong revoke holds vs a malicious server" overstated — a withheld (not-yet-seen) tombstone is detected, not prevented | Medium | §7.1 `global_revocation_epoch`; §7.6 stapled global + nonce-challenged per-file head + issuance registration; §12.4b/§12.9 contiguity checks (D22); Phase 5 |
| **R17** Anti-rollback version memory weaponizable into a permanent-update-denial DoS | Medium | §7.5 monotonic-by-1 + upper-bound/first-contact ceiling (D23); Phase 3 |
| **R18** Decrypted cross-user metadata reaches FS/UI sinks unsanitized (path traversal / injection on the downloader) | Medium | §8.1 + §13 untrusted-input sanitization; §12.5 step 6 (D24); Phase 3 |
| **R19** HPKE wrap not context-bound; Auth-mode sender not verified | Low | §5 `info = "MaxSecu-wrap-v1" ‖ …` + sender == author `enc_pub` |
| **R20** Lazy migration leaves *broken* (not just deprecated) primitives readable indefinitely | Low | §5.1 eager-sweep trigger + read-block below floor |
| **R21** No reinstatement after an append-only account-wide tombstone | Low | §11.5a dual-controlled `reinstatement`; §12.9b note |
| **R22** Concurrent rotation / version fork undefined | Low | §12.9 serialize-on-`(file_id, version)` + rebase |
| **R23** Session-token "channel binding" underspecified (bearer risk) | Low | §9.2 TLS-exporter token binding |

### 18.4 Fourth review round (this revision)

Maps the fourth-pass findings to where this revision resolves them.

| Finding | Severity | Resolved in |
|---|---|---|
| **R24** Admin clause in grant validity + authenticated carry-forward = *online*-admin read escalation — an admin-signed grant needs no DEK, yet the honest rotator re-wraps the next version's DEK to it, contradicting §10.1/§3.1 ("an online admin cannot read files") | High | §12.3a per-grant **`dek_poss`** DEK-possession tag; §12.9 step 2 DEK-bound carry-forward; §12.5 step 6 chain check; §12.7 step 5 recovery-operator grant; §11.3 schema; §10.1/§15.1 (D25); Phase 4 |
| **R25** Grant-graph subtree revocation trusts server-served edges — a malicious server can withhold a descendant's edge from the revoker while honoring it for rotation/download (grant-graph analogue of R16) | Medium | §12.9b step 4 + §14.5 walk computed from the **digest-anchored external sink** (§16.5), not the server (D26); Phase 5 |
| **R26** "Recovery is checkable" only checks the grant, not the wrap — a malicious writer can sign a valid recovery grant but upload a bad recovery wrap, silently breaking recoverability | Medium | §12.3a (intent-vs-wrap distinction); §16.1 **offline recovery-wrap validation sweep** (D27); §15.3 residual; Phase 6 |
| **R27** Compromised-then-rotated `sig` key can forge backdated durable write-grants verifying forever against the retained historical binding | Medium | §11.7 **`key_compromise` cutoff** gated by external-sink anchoring; §11.6 validity; §16.4 (D28); Phase 5 |
| **R28** Reinstatement-vs-revocation predicate compares two independent monotonic counters (ill-typed → possible revocation bypass) | Medium | §11.5a predicate rewritten to per-`(file_id, user_id)` `supersedes_epoch` matching, never raw counter comparison |
| **R29** HPKE Auth-mode sender check specified as `== author_id`, breaking for re-shared/recovery wraps whose sender is the granter | Low | §5 wrap row + §12.5 step 6: sender verified against the wrap's `granted_by` `enc_pub` |
| **R30** Manifest claimed a "recipient-set commitment" it does not (and cannot, given post-hoc re-share) carry | Low | §11.2 corrected — recipients authenticated per-wrap by grants; `recovery_present` is the only manifest recipient assertion |
| **R31** Contiguous `*`-tombstone replay is unbounded; one corrupt historical tombstone fails-closed fleet-wide | Low | §7.6 signed **revocation checkpoints** bound the replay window (L-3) |
| **R32** Enrollment binds key↔human (fingerprint) but not name↔human (`username`), while first-contact sharing addresses by `username` | Low | §12.1 step 3: admin confirms `username` as well as fingerprint |
| **R33** DEK used directly as an AEAD key while also being HKDF-committed/stretched | Info | §5 + §12.10 derive a content subkey `ck = HKDF(DEK, "MaxSecu-content-v1")`; DEK is now only ever a KDF root |

---

## 19. Open items / future work

**Committed to Phase 7 (§17) — promoted out of open-ended "future work" by the second review round (D20):**
- **Post-quantum hybrid wrap** (X25519 + ML-KEM-768), enabled by algorithm agility (§5) — closes the harvest-now-decrypt-later exposure of v1 (§15.2/§15.3).
- **Shamir / threshold split** of the recovery key (removes the D6 single-point-of-theft/loss and the lone-cold-copy total-compromise risk, §15.3/§16.3).
- **Key transparency log** for the directory (defends against signing-key equivocation for never-met pairs, §7.4/§7.7).

**Still genuinely future / optional:**
- **Size padding / bucketing** for metadata (§13).
- **Multi-device** support (would revisit D4 — e.g., device-to-device key transfer).
- **Encrypted client-built search index** to restore search lost to §13.
