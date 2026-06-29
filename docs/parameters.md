# MaxSecu — Security Parameters

**Status:** Decided (pre-implementation); the low-stakes operational rows in §9 ride documented defaults.
**Scope:** v1 — the concrete numeric/policy values `DESIGN.md` and `docs/stack.md` reference by name but leave unpinned. Companion to both; cite-back, not a re-derivation.
**Authority:** This file is the single source for *values*. Where `DESIGN.md` says "short-lived", "small bound", "risk-based cadence", or "e.g. 1 year", the number lives here. Cryptographic-primitive choices are settled in `DESIGN.md` §5 and `docs/encoding-spec.md`; this file pins their *parameters* and the operational knobs.

> **Two kinds of parameter.** **Settled** rows are cryptographic/encoding calls (delegated to the reviewer per the working agreement) or values already fixed in `DESIGN.md`; they need no further decision. **⚙ confirm** rows are *operational risk-tolerance* calls whose "right" value depends on your deployment (sink availability, enrollment latency you'll accept, cold-key handling budget, griefing exposure). Each carries a recommended default so the system is fully specified today; §9 collects them for sign-off.

> **Algorithm agility.** Every cryptographic value here is the v1 instantiation of `Suite 0x0001` (`encoding-spec.md` §3). New suites get new codepoints and may carry different parameters; clients reject unknown/below-floor suites (`DESIGN.md` §5.1). No value here is hard-coded past the `alg` registry.

---

## 1. Cryptographic parameters (settled)

### 1.1 Password KDF — Argon2id (`DESIGN.md` §5, M3/R10)

| Parameter | Value | Notes |
|---|---|---|
| Algorithm | Argon2id (RFC 9106) | `argon2` crate (stack §1.3) |
| **Floor (all platforms)** | `m ≥ 19 MiB, t ≥ 2, p = 1` | OWASP / RFC 9106 minimum; a client **rejects** any blob whose stored params fall below this |
| **Desktop v1 target** | `m = 256 MiB, t = 3, p = 1` | Calibrated at install to **0.5–1.0 s** on the actual machine; never tuned below the floor |
| **Mobile floor (dormant)** | `m ≥ 64 MiB, t ≥ 3, p = 1` | No mobile client in v1 (stack §3); value reserved so the wiring is not hard-coded to desktop (R10). Not active code in v1 |
| Salt | **16 bytes**, OS-CSPRNG, unique per account | Stored *with the local blob only* (D4) — never on the server |
| Output | 32 bytes → AES-256-GCM key for `local_key_blob` | |
| Stored params | Full `(m, t, p, salt, version)` stored beside the blob | So a re-tuned/older blob still opens (M3); re-tuned on password change (§9.5) |

> Calibration is **per device**: store the *measured* params, not a constant. The floor is a hard reject; the target is an aspiration the device may exceed but must meet ≥ floor.

### 1.2 Content & stream AEAD — AES-256-GCM (`DESIGN.md` §5, §12.10, §13/D33)

| Parameter | Value | Notes |
|---|---|---|
| DEK | **256-bit**, OS-CSPRNG, per file, random | Only ever a KDF root (L-5/R33); never a direct AEAD key |
| Stream subkey | `ck_<type> = HKDF-SHA256(ikm=DEK, info="MaxSecu-<type>-v1", L=32)` | One per stream: `content`/`metadata`/`thumbnail`/`preview` — disjoint nonce spaces |
| Cipher | AES-256-GCM | `aes-gcm` crate; framing hand-rolled (stack §1.3) |
| Nonce | **96-bit big-endian chunk counter**, starts 0, +1 per chunk, **per `ck`** | Unique because each `ck` is unique per file-version; deterministic counter, **not** random — so uniqueness is *guaranteed*, not probabilistic |
| Tag | **128-bit** | |
| AAD | `canonical(chunk_aad)` = `{file_id, version, stream_type, chunk_index, is_last}` | Binds index, stream, last-chunk flag (`encoding-spec.md` §4) |
| Chunk size | **default 1 MiB**; client-accepted range **[4 KiB, 8 MiB]** | `chunk_size` outside range → reject (R11). Bound-checked **before** allocation (§12.10) |
| Max addressable file (anti-DoS guard) | reject if `chunk_count · chunk_size > 256 GiB` (configurable) | Sanity cap on the *framing fields* only — **not** a product size limit (server imposes none, D31). Separate from the user's RAM/disk budget (§1.6 below) |

> **GCM safety.** Per-chunk plaintext ≤ 8 MiB ≪ GCM's ~64 GiB single-message limit; chunk count ≤ `2^96` (counter space) ≫ any real file, and uniqueness is structural (counter, fresh `ck` per version), so the random-nonce `2^32`-message bound does **not** apply. No (`ck`, nonce) is ever reused.

### 1.3 Key wrapping, signatures, hashing (`DESIGN.md` §5)

| Purpose | Value | Notes |
|---|---|---|
| Wrap | HPKE **base mode**, X25519 + HKDF-SHA256 + AES-256-GCM (RFC 9180) | `info = canonical(wrap_context)` (`encoding-spec.md` §4); Auth mode not used |
| User `enc` key | X25519 (32-byte keys) | unwrap only |
| User `sig` key | Ed25519 | **strict verification** (`verify_strict`) to reject malleable encodings (stack §1.3) |
| Directory-signing (D5) | Ed25519, offline | pinned in client build (§7.3) |
| Recovery (D6) | X25519, offline | standing recipient on every file (§6.3) |
| Hash | SHA-256 (32-byte output) | digests, fingerprints, tombstone-chain `prev_head` |
| Fingerprint | `SHA-256(canonical(fingerprint_input))`, rendered full **256-bit** as base64 (≈43 chars) + QR | compared whole, never truncated (§7.1/D9) |
| KDF | HKDF-SHA256, `L = 32` for all derivations | `ck`/`mk`/per-stream subkeys + `dek_commit` |
| `dek_commit` | `HKDF-SHA256(ikm=DEK, info="MaxSecu-dek-commit-v1", L=32)` | derived commitment, not a raw-key hash (R12) |

### 1.4 Compression (`DESIGN.md` §13/D32, stack §2.5)

| Parameter | Value | Notes |
|---|---|---|
| Algorithm | zstd (id `0x01`) for `text`/`blog`; `none` (`0x00`) for already-compressed media | per-stream id rides **inside the signed manifest** (authenticated) |
| Level | **default 19** (range 1–22), client-configurable | **Security-irrelevant:** only the *algorithm id* is signed, and decompression is deterministic regardless of compressor effort — level is a pure local space/time tradeoff |
| Dictionary | **none** — no shared/cross-file dictionary, ever | one file's content can never leak into another's size (D32) |

### 1.5 Encoding limits & sentinels (`docs/encoding-spec.md`)

| Parameter | Value |
|---|---|
| `MAX_TEXT` (per `text` field, NFC bytes) | **1024** |
| `RECOVERY_ID` | 16 zero bytes |
| `GENESIS_HEAD` (control-log `prev_head` seed) | 32 zero bytes |
| Current suite codepoint | `0x0001` |
| Integer widths | fixed, big-endian, unsigned, as declared (no varints) |
| `MAX_GRANT_CHAIN_DEPTH` (re-share ancestor chain, `DESIGN.md` §12.3a/§12.5) | **32** — a client-enforced, fail-closed cap on a server-supplied re-share grant chain. Each rotation re-roots every carried recipient under the new author, so a real chain is only the re-shares since the last rotation (typically 1–3); the cap is an anti-DoS bound, with a cycle guard rejecting repeated granters independently |

### 1.6 RNG & memory budget (stack §1.3/§1.4, `DESIGN.md` §8.1/D12)

| Parameter | Value | Notes |
|---|---|---|
| CSPRNG | OS (`BCryptGenRandom` on Windows) for **all** keys, salts, DEKs | never a userspace PRNG for key material |
| Client RAM budget | **user-configurable**; default sized to the device (e.g. 2 GiB) | governs streaming-vs-whole-decode; exceeding it **warns + requires confirmation**, then unlocks to a user-chosen disk path (the one sanctioned plaintext-on-disk path, audited) |

---

## 2. Authentication & session

| Parameter | Value | Status | Notes |
|---|---|---|---|
| Auth nonce TTL | **60 s**, single-use, server-tracked | settled | `DESIGN.md` §9.2; expired/reused → reject |
| Channel binding | TLS exporter (RFC 5705) fed into the proof + token | settled | rustls `export_keying_material` |
| **Session token TTL** | **60 min absolute**, channel-bound, revocable, re-challenge on expiry/new channel | **⚙ confirm** | Token is usable *only* on its origin TLS channel (§9.2), so TTL mainly bounds a single long-lived connection; 60 min is a low-stakes default |
| Password min length | **15** | settled | §9.4 |
| Password max length | **128** | settled | generous; allow all printable + space + paste |
| Password composition | none forced; breach/common blocklist at set-time | settled | §9.4 |

---

## 3. Anti-automation / rate limiting (`DESIGN.md` §9.3 — **posture decided**, Tor-aware)

Tor (D34) collapses source-IP signal (shared exits), so **per-account limits are primary**; per-IP is a secondary, best-effort global cap that is **not relied upon** under Tor.

| Parameter | Recommended default | Tradeoff direction |
|---|---|---|
| Failed-proof backoff | exponential per account: 1s, 2s, 4s … capped at 60 s | tighter = slower brute force, worse UX on fat-finger |
| Lockout posture | **rate-limit, not hard account-lock** (see note) | hard-lock on a *public username* is a griefing/account-DoS vector |
| Challenge-issuance cap | 30 / account / minute; 10 / source / minute (advisory) | lower = less automation, more false positives behind shared exits |
| Registration anti-automation | manual (in-person enrollment, §12.1) gates account creation; **no public signup** in v1 | in-person delivery already throttles new accounts — no CAPTCHA/PoW needed in v1 |
| User-existence oracle | none — well-formed challenge for unknown usernames too | settled (§9.3) |

> **Lockout posture is the real decision.** Because usernames are addressable by other users (first-contact sharing is by `username`, §12.1/R32), a *hard* lockout-after-N lets anyone freeze a known account by spamming bad proofs. Throttle the **attempt rate** (backoff + per-account challenge cap) so a legitimate user with the correct password is never locked out by a third party's failures, and alert on sustained failure spikes (§16.5) rather than auto-locking. **Decided: rate-limit only — no hard lockout, including admin accounts** (alert on spikes instead).

---

## 4. Identity, versioning & monotonic counters

| Parameter | Value | Status | Notes |
|---|---|---|---|
| Binding `not_after` | **365 days** (identity lifetime, **not** a freshness/revocation timer) | settled-ish | §7.1/§7.5; rotation re-signs. Revocation is sink-anchored, clock-independent (§7.6) |
| File `version` step | **exactly +1** per write | settled | §7.5/D23 |
| Upper-bound guard | accept served `version ≤ seen_max + 1`; reject above | settled | **No concurrent-rotation slack needed** — owner-only write (D29) ⇒ one writer per file ⇒ no fork/rebase (R22 cannot arise) |
| First-contact ceiling | reject `version > 1,000,000` when no prior record | settled | absolute sanity cap against rollback-memory poisoning (D23); far above any real write count |
| `key_version`, `revocation_epoch`, `reinstatement_epoch` | monotonic u64 counters; rollback-guarded by trust-on-last-use memory | settled | §7.5/§11.5/§11.5a |

---

## 5. Revocation freshness — the sink-head refresh cadence (**decided — the headline security parameter**)

Per the simplification pass, **this cadence *is* the revocation-staleness bound** (`DESIGN.md` §7.6, D13/D22). It replaced the removed status signer's fixed 12 h epoch. There are **two** sub-cadences; the staleness bound is their sum.

```
admin anchors *-tombstone ──▶ sink re-publishes head ──▶ client refreshes its head ──▶ client enforces on next op
                            └── (a) sink anchor interval ──┘└──── (b) client refresh ─────┘
       revocation-staleness bound (for fail-closed ops) ≈ (a) + (b)
```

| Parameter | Value | Notes |
|---|---|---|
| **(a) Sink anchor/publish interval** | **≤ 60 s** (anchor-on-append preferred; 60 s ceiling) | shorter = fresher revocation, more anchor writes |
| **(b) Client head-refresh model** | **relaxed periodic cache: 30 min** (configurable 30–60 min). A completeness-requiring op (new-recipient wrap, rotation, read re-share, download completeness check) checks the cached head; the head is refreshed when older than the cache window | larger cache = less sink load, staler enforcement |
| **(b′) High-sensitivity bypass** | files flagged high-sensitivity (the §6 flag) **bypass the cache and fetch the head fresh** per op | near-real-time revocation where it matters, without loading the sink for routine files |
| **Resulting staleness bound** | **≈ 30 min** for routine files; **near-real-time** (sink propagation only) for high-sensitivity files | replaces the old "12 h"; **chosen posture: relaxed** to spare the sink |
| Fail-closed behavior | if the head is unfetchable: **block** wrap/rotate/re-share (no operation on an unverifiable set); **reads of already-verified content continue** | settled (§7.6) — a sink outage is a bounded *sharing* DoS, never a read lock-out |

> **Decided: relaxed (30 min cache).** The sink-load saving is taken in exchange for a ~30 min window in which an honest-but-stale rotator/re-sharer could still re-admit a just-revoked user **to a newly-written version** (existing versions are unaffected; the revoked user still cannot decrypt anything they lack a wrap for). This window is **bounded and detectable** — the re-admitting wrap carries an auditable grant (§16.5), and the periodic refresh/sweep catches it — and two escape hatches blunt it: (i) **high-sensitivity files bypass the cache** (near-real-time, b′ above), and (ii) an admin needing *immediate* enforcement on a specific file uses **eager rotation** (`DESIGN.md` §14.4), performed on a freshly-fetched head regardless of other clients' cache. Tighten the global cache toward 30→5 min later if routine-file staleness proves too loose; `docs/sink-interface.md` must keep the head fetch cheap enough that this stays a free knob.

---

## 6. Recovery-wrap validation sweep (`DESIGN.md` §16.1/D27 — **⚙ confirm**)

The offline sweep that catches a valid recovery *grant* over a *bad* recovery *wrap* (R26). Cadence/coverage trade **detection latency** against **cold-key (`recovery_priv`) handling exposure**.

| Parameter | Recommended default | Tradeoff direction |
|---|---|---|
| High-sensitivity files | **100% every 30 days** | more frequent = shorter bad-wrap window, more cold-key sessions |
| General corpus | **rolling 10% per monthly cycle** ⇒ full coverage ≈ 10 months | higher sample = shorter worst-case window, more cold-key exposure |
| Cold-key exposure | **one air-gapped session / month** | each session is a custody event (§16.3) |
| New-upload spot-check | sweep the **most-recent N uploads** opportunistically each session | shortens the window for actively-shared new files |

> Mark a file "high-sensitivity" at upload (client flag) so the 30-day tier is meaningful. This is the only routine reason to bring out the recovery key short of an actual recovery — keep it batched.

---

## 7. Ceremony cadence (`DESIGN.md` §12.1 — **⚙ confirm**)

| Parameter | Recommended default | Tradeoff direction |
|---|---|---|
| Enrollment signing | **daily** | faster = shorter "account exists but not yet a valid recipient" wait; more air-gapped sessions |
| Emergency D5 re-sign | on-demand (runbook §16.4) | — |

> Enrollment latency is a published, user-visible promise (§12.1). Daily is a reasonable closed-deployment default; tighten if onboarding volume warrants.

---

## 8. Storage & cache (`docs/stack.md` §2.4/D31 — settled)

| Parameter | Value | Notes |
|---|---|---|
| Dropbox backing tier | **2 TB** | size to corpus; **no dedup** (per-file DEKs) so plan headroom |
| Server cache | **50–100 GB**, LRU/LFU eviction | cache-miss → Dropbox fetch + client progress |
| Default blob path | **server-proxy** (client never contacts Dropbox) | direct mode is opt-in; **Tor forces proxy** (D34) |
| Direct-link TTL (opt-in) | **15 min**, scoped, read-only, single-blob | client still verifies every byte (manifest + AEAD); token never shared |
| Independent ciphertext backup | **required** (availability/DR) | mass-delete risk is not new but durability rests on the tier (§15.3) |

---

## 9. Operational parameters to confirm (decision surface)

Everything else in this file is settled. These are the **⚙ confirm** rows — each already has a working default, so nothing is blocked; confirm or redline:

| # | Parameter | Value / default | Status | §ref |
|---|---|---|---|---|
| 1 | **Sink-head refresh model + cache** (= revocation-staleness bound) | **relaxed 30 min cache** (≈ 30 min bound); high-sensitivity files bypass to near-real-time | ✓ decided | §5 |
| 2 | Sink anchor/publish interval | ≤ 60 s (anchor-on-append) | default | §5 |
| 3 | Anti-automation **lockout posture** | **rate-limit** (backoff + cap), **no** hard account-lock (incl. admins) | ✓ decided | §3 |
| 4 | Session token TTL | 60 min, channel-bound, revocable | default | §2 |
| 5 | Recovery-wrap sweep cadence/coverage | hi-sens 100%/30d; corpus 10%/cycle | default | §6 |
| 6 | Enrollment signing cadence | daily | default | §7 |

> #1 and #3 (the consequential ones — a security bound and a griefing-exposure posture) are **decided**. #2, #4–#6 ride the documented defaults unless you have a specific constraint.

---

## 10. Monitoring / alert thresholds (`DESIGN.md` §16.5 — anomaly detection)

The pure anomaly analyzer (`server::detect`) consumes the external audit-event
stream and raises typed alerts for the §16.5 anomalies. These are the
`Thresholds::default()` values; SIEM/dashboard forwarding is a runbook (P6.11),
not a coded threshold. All are **⚙ confirm** — operational risk-tolerance knobs
with conservative closed-deployment defaults.

| Parameter | Default | Tradeoff direction |
|---|---|---|
| Auth-failure spike | **> 20** `AuthDenied` within any **60 s** sliding window | lower = catches slower brute-force, more noise from fat-fingering |
| Re-share fan-out | **> 10** `Reshare` grants by one granter within any **1 h** sliding window | lower = flags over-sharing sooner, more false positives for power users (§14.5) |
| Grant-by-soon-revoked | grant by `G` then `UserRevoked{G}` within **24 h** after | longer = catches slower insider clean-up, more incidental matches (§14.5) |
| Tombstone-set gap | **always alert** (no threshold) | security-critical: a withheld tombstone below the anchored head (D22/§7.6) |
| Missing recovery grant | **always alert** on any `VersionFinalized{recovery_present:false}` | a finalized version with no recovery clause (§12.3a) |
| Off-ceremony directory change | a `DirectoryBindingChanged` outside **every** configured ceremony window | windows are deployment-specific; **empty by default** ⇒ every change flagged until windows are set (§12.1) |

> The sliding-window rules emit **once** with the peak window count, so a sustained
> spike is one alert, not one per event. Ceremony windows are inclusive `[start, end]`
> epoch-ms intervals supplied per deployment (the daily enrollment ceremony, §7);
> until populated the analyzer treats every binding change as off-ceremony, which is
> the safe default (alert, don't silently allow).

---

## 11. Media decode bounds — canonical video caps (`docs/media-sandbox.md` §3/§4, Phase 7 Gate 1 — settled)

Pre-decode ceilings for the **canonical video format** (AV1 / AAC-LC / CMAF closed-GOP, ratified in `media-sandbox.md` §4 and `docs/security-review-phase7-codec-ratification.md`). Checked in the main process (cheap, no decoder) **and** re-checked in each worker **before any decoder allocates** a frame/audio buffer (the decompression-bomb guard, §3). Anything over a ceiling is **rejected pre-allocation**; the Job Object memory + wall-clock caps kill a pathological input rather than hang. These values are the canonical source for Gate 2's `VideoBounds::default()` — encode them verbatim.

| Parameter | Value | Notes |
|---|---|---|
| `MAX_DURATION_MS` | **1_800_000** (30 min) | hard duration ceiling; longer clips rejected before decode |
| `MAX_FRAMERATE` | **120** | fps ceiling; bounds frame-count × per-frame allocation |
| `MAX_FRAGMENT_BYTES` | **16_777_216** (16 MiB) | per-CMAF-fragment byte ceiling; a single fragment over this is rejected before demux |
| `MAX_TOTAL_BYTES` | **4_294_967_296** (4 GiB) | whole-stream byte ceiling (cross-checked against the signed manifest's `total_bytes`, §3) |
| `MAX_FRAGMENTS` | **4096** | fragment-count ceiling; bounds the `pts→fragment→chunk` index and per-session state |
| `MAX_AUDIO_CHANNELS` | **2** | stereo ceiling for the AAC-LC track |
| `MAX_SAMPLE_RATE` | **48_000** | audio sample-rate ceiling (Hz) |

**Existing pixel caps reused (the `Media/VideoBounds` geometry, recorded here so Gate 2 stays consistent):**

| Parameter | Value | Notes |
|---|---|---|
| `max_width` | **7680** | 8K-class width ceiling |
| `max_height` | **4320** | 8K-class height ceiling |
| `max_pixels` | **33_177_600** (= 7680 × 4320, 8K) | per-frame pixel-area ceiling; the decompression-bomb guard, checked before allocating a frame buffer |

> These are hard ceilings on the **canonical** format only — a viewer decodes nothing but the canonical set (§4), so no codec auto-probing of the demuxer zoo. They are independent of the framing-field anti-DoS cap (§1.2's 256 GiB addressable-file guard) and the user's RAM/disk budget (§1.6); a real input must clear **all** of them. Worker output is **also** validated against these caps post-decode (plane lengths vs `width·height`, dims-within-caps, monotonic `pts`, PCM length/format/channel/rate) before the renderer touches it (`media-sandbox.md` §6, spec §7).

> **These caps bound per-allocation size, NOT aggregate decode compute (Gate-2 load-bearing).** Each value is a **per-frame / per-fragment** ceiling, not a bound on total decode work. An input *at* the ceilings — `max_pixels` 8K (33.18 Mpx) × `MAX_FRAMERATE` 120 fps × `MAX_DURATION_MS` 30 min ≈ **216k frames** — decoded on **asm-OFF pure-Rust `rav1d`** (slower than C dav1d) is a real CPU/wall-clock exhaustion vector that **no numeric cap here bounds**. That vector rests **entirely on the worker's Job Object wall-clock + committed-memory cap** (`media-sandbox.md` §2/§3), which is therefore **load-bearing and MANDATORY** for the Gate-2 decode worker — not optional. The numeric caps bound a single allocation; the Job Object bounds the aggregate run.

> **`MAX_FRAGMENTS` vs `MAX_TOTAL_BYTES` (read them right):** `MAX_FRAGMENTS` (4096) × `MAX_FRAGMENT_BYTES` (16 MiB) = **64 GiB**, 16× the `MAX_TOTAL_BYTES` (4 GiB) ceiling — **not a hole**: the caps are independent ceilings and an input must clear **all** of them, so the binding constraint on byte **volume** is `MAX_TOTAL_BYTES`. `MAX_FRAGMENTS` bounds per-session **index/state** (the `pts→fragment→chunk` table + resume bookkeeping), **not** byte volume — don't treat the fragment count as a volume control.

---

## Cross-references

- Primitive choices & rationale: `DESIGN.md` §5; per-record bytes: `docs/encoding-spec.md`.
- Where the sink head comes from and how clients verify it: **`docs/sink-interface.md`** — §5's cadence is the client side of that contract.
- Build-phase mapping: Phase 1 (auth/session §2–§3), Phase 3 (AEAD/versioning §1.2/§4), Phase 5 (revocation §5, sweep §6), Phase 4b (storage §8), Phase 7 media-app (canonical video decode bounds §11).
- Canonical video format + decode-sandbox model: **`docs/media-sandbox.md`** §3/§4; codec ratification: **`docs/security-review-phase7-codec-ratification.md`**.
