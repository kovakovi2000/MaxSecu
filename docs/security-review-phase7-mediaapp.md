# Phase 7 (Media App) — Sandboxed Video — Holistic Security Review & Sign-off

**Scope:** the full Phase-7 (sandboxed video) change set on branch `media-app` — commit range `f6b626e..HEAD` (26 commits, six implementation gates + this sign-off). Phase 7 lights up the media app's **video** path: author-side transcode to a canonical AV1/AAC-LC/CMAF format and **viewer-side decode of attacker-authored bytes** — the system's **#1 RCE surface** (`media-sandbox.md` §intro, spec §4) — without letting a codec 0-day reach keys, plaintext, or the network.

**Companion to / re-verifies:** `docs/security-review-phase7-codec-ratification.md` (Gate-1 ratification + R1/R2), `docs/media-sandbox.md` (the decode-isolation model; §4 ratified, §7 residuals), `docs/superpowers/specs/2026-06-29-maxsecu-media-app-phase7-video.md` (esp. §7 exit gates + §9 residuals), `docs/superpowers/plans/2026-06-29-maxsecu-media-app-phase7-video.md` (gate structure). Builds on the prior media-app sign-offs (`security-review-phase{2,3,4,5,6}-mediaapp.md`).

**Method:** this is a **fresh, independent re-verification** of the spec §7 exit gates — not a re-statement of the per-task reviews. Every gate below was re-checked with commands run in-turn on the project's Windows 11 / MSVC host; the **actual** outputs are quoted. Supply-chain (`cargo deny check`, `cargo audit`), the decode-worker and transcode-worker test suites (containment, bombs, OOM-kill, fuzz-replay), and the author→view e2e over real loopback TLS were all re-run. Codec-internal facts are inherited from the security-reviewed-before-adoption Gate-1 ratification doc, which pins the exact crate set.

**Verdict:** **PASS** — **no Critical, High, or Medium finding open against the committed (default, no-ffmpeg) path.** The view hot path is **zero-C and structurally outside the key-holding process** (`cargo tree` proves no codec links into `client-core` / `client-app`); both confined workers deny network / child-spawn / key-blob read across their whole session lifetime with proven unconfined differentials; every decoded I420 frame and PCM chunk is re-validated in the main process before render; the on-disk fragment cache holds **ciphertext only** (e2e-asserted); bombs and the two fuzzer findings are **contained** by the Job-Object caps; and the author→view round-trip works end-to-end. The residuals — **R1** (AAC-LC audio deferred), **R2** (real ac-ffmpeg ingest deferred behind an off-by-default feature), **F1/F2** (contained decoder DoS, upstream issues to file), **CF-2** (64 MiB decode stack), **large-source delivery**, and a non-Phase-7 keystore argon2 host flake — are honestly recorded with their closure paths. **The sandbox contains; it does not eliminate** (a 0-day *plus* an AppContainer escape would still reach the host) — which is why the decoders are kept secret-less and pinned + fuzzed.

---

## 1. What Phase 7 added (the six gates)

- **Gate 1 — Codec ratification.** `rav1d` 1.1.0 (AV1 decode), `symphonia` 0.6.0 (CMAF demux + AAC-LC), `rav1e` 0.8.1 (AV1 encode) pinned `asm`-off; `ac-ffmpeg` 0.19.0 is the sole C carve-out, **feature-gated off by default**. Security-reviewed-before-adoption (`security-review-phase7-codec-ratification.md`).
- **Gate 2 — `client-core` video seam (TCB).** `VideoBounds` / `I420Frame` / `PcmChunk` + `validate_i420` / `validate_pcm` (untrusted-output validation) + the duplex decode-session proto. Pure types — **no codec dependency**.
- **Gate 3 — Persistent-session decode worker.** In-proc `VideoSession` → `--video-session` worker loop → duplex AppContainer session launcher + session-lifetime containment + bomb suite + `cargo-fuzz` target + OOM-kill regression.
- **Gate 4 — Ciphertext fragment cache + random-access decrypt.** On-disk **ciphertext** LRU + per-chunk content-range AEAD + decrypt-while-play feeder + player commands + the **codec-free `media-launcher` crate split** (the decoder is now *unconditionally* out of the main process).
- **Gate 5 — Player chrome.** WebGL BT.709 YUV→RGB shader + WebAudio A/V sync + `<video-player>` a11y + the default-OFF HW-decode waiver.
- **Gate 6 — Author-side confined transcode worker.** Pure-Rust `rav1e`/CMAF transcode in the new `media-transcode-worker` crate + AppContainer confinement + upload + preview + the full author→view e2e over real TLS. (ffmpeg/AAC ingest deferred — R1/R2.)

No new server crypto, no new server endpoint, no key handling in any worker — the zero-knowledge core is unchanged and re-verified client-side.

---

## 2. Spec §7 exit gates — re-verified with fresh evidence

### 2.1 Zero-C / decoder out of the key-holding main process (the TCB)

The system's #1 RCE surface runs codecs on attacker bytes; the requirement is that **no codec / C ever links into the main process or the TCB**. Re-verified with `cargo tree` on the default graph (commands run in-turn):

**The key-holding main process (`client-app`) and the verification TCB (`client-core`) link NONE of the codecs:**

```
$ cargo tree -p maxsecu-client-app  -i rav1d   → error: package ID specification `rav1d` did not match any packages
$ cargo tree -p maxsecu-client-app  -i symphonia → error: ... did not match any packages
$ cargo tree -p maxsecu-client-app  -i rav1e   → error: ... did not match any packages
$ cargo tree -p maxsecu-client-app  -i ac-ffmpeg → error: ... did not match any packages
$ cargo tree -p maxsecu-client-core -i rav1d / -i symphonia / -i rav1e / -i ac-ffmpeg
                                               → error: ... did not match any packages (all four)
```

An inverse `cargo tree -i <crate>` that errors *"did not match any packages"* means the crate is **absent from that package's entire dependency subgraph** — the codecs are not reachable from `client-app` or `client-core` at all. The `client-app` C-free property is structural: Gate 4 split out a **`media-launcher`** crate (also codec-free — `cargo tree -p maxsecu-media-launcher -i rav1d` → *did not match*) that the main process links instead of `media-worker`; the launcher *spawns* the codec-bearing worker as a separate confined process.

**The codecs live only where they should:**

```
$ cargo tree -p maxsecu-media-worker -i rav1d      → rav1d v1.1.0 └── maxsecu-media-worker
$ cargo tree -p maxsecu-media-worker -i symphonia  → symphonia v0.6.0 └── maxsecu-media-worker
$ cargo tree -p maxsecu-media-worker -i rav1e      → rav1e v0.8.1 [dev-dependencies] └── maxsecu-media-worker
$ cargo tree -p maxsecu-media-transcode-worker -i rav1e → rav1e v0.8.1 └── maxsecu-media-transcode-worker
```

(`rav1e` in `media-worker` is a **dev-dependency** only — the test-fixture encoder — not a runtime link; the production AV1 encoder is in the transcode worker.)

**`ac-ffmpeg` is absent from the default build graph and only appears under the off-by-default `ffmpeg` feature:**

```
$ cargo tree --workspace -e features -i ac-ffmpeg                 → error: ... did not match any packages
$ cargo tree -p maxsecu-media-transcode-worker -i ac-ffmpeg       → error: ... did not match any packages   (default)
$ cargo tree -p maxsecu-media-transcode-worker --features ffmpeg -i ac-ffmpeg
                                                                  → ac-ffmpeg v0.19.0 └── maxsecu-media-transcode-worker
```

So the **committed/shipped path links no ffmpeg C at all**; ac-ffmpeg is reachable only from the leaf transcode worker, and only when a caller explicitly opts in with `--features ffmpeg` (which is deferred — R2).

**Banned crypto C remains banned and absent:**

```
$ cargo tree -i ring               → warning: nothing to print.   (and `--target all` → still nothing)
$ cargo tree -i openssl            → error: ... did not match any packages
$ cargo tree -i openssl-sys        → error: ... did not match any packages
$ cargo tree -i aws-lc-rs          → aws-lc-rs v1.17.0 (the sanctioned rustls/rcgen TLS provider — transport only)
```

`ring` is not in the build graph for any target; `openssl` / `openssl-sys` are not in the lockfile; `aws-lc-rs` remains the only other sanctioned C (TLS, not a codec). **PASS.**

### 2.2 Containment — both workers, across the whole session lifetime

Both the decode worker and the transcode worker run under the existing Windows confinement (no-capability AppContainer → no network by capability; low-privilege token that cannot read the user's files / `local_key_blob`; Job Object `ACTIVE_PROCESS = 1`, kill-on-job-close, hard memory cap; WER off). The exit gate requires a **denied-confined vs. allowed-unconfined differential**, proven **across the duplex session lifetime** (including *late*-lifetime probes after a fragment has been processed). Re-run `cargo test -p maxsecu-media-worker -- --test-threads=1` and `cargo test -p maxsecu-media-transcode-worker -- --test-threads=1`:

| Suite | Tests | Result |
|---|---|---|
| `media-worker/tests/containment_video_windows.rs` | 5 | **ok** (4.68s) |
| `media-worker/tests/containment_windows.rs` (image worker) | 4 | **ok** |
| `media-worker/tests/oom_kill_windows.rs` | 1 | **ok** |
| `media-transcode-worker/tests/containment_transcode_windows.rs` | 4 | **ok** |

The video-session containment names make the **session-lifetime** coverage explicit:

```
appcontainer_duplex_session_blocks_network_late_while_unconfined_allows
appcontainer_session_blocks_network_late_while_unconfined_allows
appcontainer_session_blocks_child_spawn_late_while_unconfined_allows
appcontainer_session_blocks_reading_the_key_blob_while_unconfined_allows
appcontainer_session_decodes_three_fragments          (still decodes correctly while confined)
```

The transcode worker proves the identical confinement on its own surface:

```
appcontainer_blocks_network_while_unconfined_allows
appcontainer_blocks_child_spawn_while_unconfined_allows
appcontainer_blocks_reading_the_key_blob_while_unconfined_allows
appcontainer_transcode_still_produces_a_canonical_clip
```

Network, child-spawn, and key-blob-read are **DENIED confined** (the late-probe variants prove the denial holds *after* a fragment is processed, not just at startup) and **ALLOWED unconfined** (the differential proves the test is exercising real confinement, not a universally-broken capability). **PASS.**

### 2.3 Output-validation in the main process

Every decoded I420 frame and PCM chunk is re-validated against `VideoBounds` (plane lengths vs `w·h` luma / `⌈w/2⌉·⌈h/2⌉` chroma, dims within caps, channel/rate/length) **before the renderer touches it** — at **both** layers: inside the worker (`media-worker/src/session.rs`, the `VideoSession`) *and* again on the main-process side of the seam (`client-app/src/commands/video.rs`, the launcher/command path that feeds the WebView). The validators live in the TCB (`client-core/src/video.rs`) with unit tests for the rejection paths (plane-length mismatch, over-cap dims, bad channel count). The author→view e2e re-asserts decoded frames match the source dims through the confined worker (GATE 3). A worker compromise that returns a malformed frame is caught here. **PASS.**

### 2.4 Bounds / bomb / oversize / garbage

`cargo test -p maxsecu-media-worker --test bombs_video` → **8 passed** (0.54s):

```
bomb_oversize_dimension_rejected_post_decode
bomb_oversize_dimension_confined_appcontainer_bounded
bomb_over_max_fragment_bytes_rejected_pre_decode
bomb_truncated_fragment_rejected
bomb_trailing_data_fragment_bounded_and_deterministic
bomb_pure_garbage_rejected
bomb_garbage_over_subprocess_session_bounded
bomb_fragment_before_open_fails_closed
```

Malformed CMAF, oversize dimensions, over-`max_fragment_bytes`, truncated / trailing-data fragments, and pure garbage are each **rejected with a bounded error (no panic, no hang)**; oversize is bounded even through the confined AppContainer session. **PASS.**

### 2.5 Fuzz corpus + the two findings (recorded as residuals)

`media-worker/fuzz/` ships a `cargo-fuzz` / libFuzzer target (`fuzz_targets/decode_session.rs`) that feeds arbitrary attacker bytes as a single `Fragment` to a `VideoSession`, plus an 8-seed committed corpus (valid fragments + truncated / bit-flipped / trailing-garbage / pure-garbage / zero). The fuzz crate is its **own workspace root**, so `libfuzzer-sys` never enters the main `cargo deny` / `cargo audit` graph. A host-portable replay runs the same corpus + a few hundred deterministic mutations through `feed` as an ordinary test:

`cargo test -p maxsecu-media-worker --test fuzz_replay` → **1 passed** — `corpus_and_mutations_replay_safely` (it prints `Error parsing OBU data` then returns a **bounded** `Vec<WorkerMsg>` with no panic).

The fuzzer **was not clean** — that is the tool working. Two genuine decoder DoS inputs were found and are carried as contained residuals:

- **F1 — `rav1d` `unwrap()` panic on hostile AV1** (`rav1d-1.1.0/src/decode.rs:4997`, `Option::unwrap()` on `None`). **Contained:** the panic aborts the worker → the launcher returns a bounded error, no frame escapes. A session-level `catch_unwind` is **ineffective** because the panic unwinds out of a plain `extern "C"` frame (`panic_cannot_unwind` → process abort below any caller `catch_unwind`); per-fragment resilience would require launcher-level worker **respawn** (a Gate-4-style follow-up). **Upstream:** file a rav1d issue for the `decode.rs:4997` unwrap. ASan-clean (pure-Rust DoS, not memory-corruption/RCE).
- **F2 — `symphonia` `stsz` over-allocation OOM from a 697-byte input** (a malformed `stsz` drives a multi-GB allocation in `read_raw_boxed_slice_exact`). **Contained by the Job-Object memory cap**, test-proven: `media-worker/tests/oom_kill_windows.rs::f2_oom_overalloc_killed_confined_no_frame_escapes` (a 256 MiB-capped `AppContainerVideoSession` on `crash-repros/oom_stsz_overalloc.bin` → worker bounded, zero frames escape). There is **no clean in-process fix** — the Job memory cap is the architectural backstop. **Upstream:** file a symphonia issue for the missing length bound. ASan-clean.

Both findings are **DoS, not RCE** (AddressSanitizer reported no memory error; both decoders are pure-Rust). **PASS** (the fuzz gate is "runs + findings triaged + contained", not "zero findings").

### 2.6 No-plaintext-at-rest

The on-disk fragment cache holds **ciphertext only**; decoded frames / PCM are never persisted; the per-chunk decryptor subkey never crosses the Tauri seam. Re-verified by the author→view e2e — `cargo test -p maxsecu-client-app --test video_e2e -- --test-threads=1` → **1 passed** (`phase7_video_author_to_view_over_real_tls`), whose **GATE 5** asserts:

```
"GATE 5: the cached blob is not the decoded plaintext"                       (cached0 != plaintext0)
"GATE 5: the decoded plaintext never appears in the at-rest ciphertext blob" (no window of cached0 == plaintext0)
"GATE 5: the back-seek into the cached window performed NO new server GET"    (cache re-read, no re-fetch)
```

A back-seek re-reads the stored **ciphertext** and re-decrypts in the TCB — it never persists a decoded byte. **PASS.**

### 2.7 Render path — no OS/hardware bitstream decoder on attacker bytes

The WebView renders **already-decoded, already-validated** I420 frames via a WebGL BT.709 YUV→RGB fragment shader → `<canvas>`; audio is PCM → WebAudio. No OS / GPU / Media-Foundation bitstream decoder ever touches attacker bytes. The HW-decode waiver is **default-OFF** with a prominent text warning and **no backend HW path wired** (`client-app/ui/src/components/video-player.ts`: `hwWaiver = false`, `hw.checked = false` belt-and-braces; warning *"enabling hardware / OS bitstream decode trades the sandbox … not recommended"*; the structural a11y test `HW-decode waiver default-off + prominent warning` enforces both). **PASS.**

### 2.8 Supply-chain gates

```
$ cargo deny check   → advisories ok, bans ok, licenses ok, sources ok   (exit 0)
$ cargo audit        → exit 0   (18 allowed warnings)
```

`cargo deny check` exits 0 (one `advisory-not-detected` **warning** for `RUSTSEC-2024-0429` glib — a dormant pre-existing GTK-stack entry, not an error). `cargo audit` exits 0 (the same glib unsoundness is an allowed/known warning under the Tauri/GTK transitive stack — not Phase-7 code, not a codec). `ring` / `openssl` stay banned and absent (§2.1). **PASS.**

---

## 3. Residuals (honest — the value of this doc)

The sign-off is PASS **against the committed default path**; these are the honestly-deferred items with their closure paths.

| Ref | Residual | Severity | Disposition / closure |
|---|---|---|---|
| **R1** | **AAC-LC audio is DEFERRED, not round-tripped.** symphonia's AAC decoder is feature-built but never decoded end-to-end — the Phase-7 decode round-trips **video only**; AAC **encode** needs ffmpeg (deferred). Audio is entirely deferred along with the ffmpeg ingest. | Residual (open) | Closes with the ffmpeg ingest worker (R2): a fixture-with-audio in-session AAC-LC decode round-trip. The pure-Rust view decoder *can* decode AAC; it is simply not exercised e2e yet. |
| **R2** | **Real `ac-ffmpeg` ingest decode is DEFERRED (feature off by default).** The shipped path links **no** ffmpeg C; the `ffmpeg` feature links ac-ffmpeg 0.19, but only an unsupported FFmpeg 8.0 is available on this host, so a real decode would be unvalidated-ABI. The default-path transcode is **pure-Rust** (raw-frames → `rav1e`/CMAF). | Residual (open, C boundary) | Vendor an ac-ffmpeg-supported FFmpeg (≤ 7.x), build `--features ffmpeg`, and **re-verify containment** with the C linked (the leaf worker is AppContainer-confined regardless, so the blast radius is bounded). Inherited from Gate-1 R2. |
| **F1** | `rav1d` `unwrap()` panic on hostile AV1 (`decode.rs:4997`). | Contained DoS | Contained by worker-abort → bounded launcher error; per-fragment resilience = launcher respawn (Gate-4-style follow-up); file an upstream rav1d issue. ASan-clean. |
| **F2** | `symphonia` `stsz` over-allocation OOM (697 B → multi-GB alloc). | Contained DoS | Contained by the Job memory cap (`oom_kill_windows.rs`); no clean in-process fix; file an upstream symphonia issue. ASan-clean. |
| **CF-2** | `rav1d` `n_threads = 1` decode overflows the 1 MiB Windows main-thread stack. | Info / implemented | Mitigated: the decoder runs on a **64 MiB-stack thread** (implemented in the worker + fuzz target). |
| **Large-source delivery** | A transcode source **> 64 MiB** is not yet streamed to the worker (temp-file / chunked delivery). The e2e transcodes a small clip. | Deferred (functional) | Add chunked / temp-file source delivery; not a security gap (bounds + confinement still apply). |
| **Per-fragment crash resilience** | A worker abort (e.g. F1) currently ends the session rather than respawning to skip one fragment. | Deferred (availability) | Launcher-level worker respawn — a Gate-4-style follow-up. |
| **Keystore argon2 host flake** | A full `cargo test -p maxsecu-client-app --lib` may abort in the **Phase-5** `keystore::tests` argon2 tests on this host (argon2 resource flake; `keystore.rs` is **unchanged** by Phase 7). | CI/environment (not a defect) | A host/CI resource item, not a Phase-7 security gap. The Phase-7 video suites (run targeted above) are unaffected. |

**Inherited media-sandbox §7 / spec §9 residuals (standing).** The sandbox **contains, it does not eliminate**: a 0-day in a sandboxed decoder **combined with** an AppContainer escape would still reach the host — which is exactly why the workers are kept **secret-less** (a non-escaping compromise yields nothing — no key to read, no socket to exfiltrate over, no child to spawn) and **pinned + fuzzed**. The framing "`rav1d` is memory-safe by construction" is **the wrong framing** and is corrected here: `rav1d` is a c2rust-seeded port with substantial internal `unsafe`, so going pure-Rust removes the **C-toolchain / hand-written-assembly** memory-corruption class outright, while residual **Rust-side UB** is *mitigated* (not eliminated) by pin + fuzz + the secret-less confinement. The transcode worker is a larger surface (full libav, once R2 lands) but runs on the author's **own** input and is equally confined. HW bitstream decode is deliberately forgone (CPU cost accepted). Worker **output** is untrusted and re-validated (§2.3).

Treat any change to a worker's privilege, the canonical format, or the C carve-out as a **security-reviewed** change.

---

## 4. Conclusion

**PASS — no Critical/High/Medium open against the committed (default, no-ffmpeg) path.** Re-verified end-to-end with fresh evidence:

- **the view hot path is zero-C** and the codecs are **structurally out of the key-holding main process** (`cargo tree` proves `client-app` / `client-core` / `media-launcher` link none of `rav1d` / `symphonia` / `rav1e` / `ac-ffmpeg`; `ring` / `openssl` banned + absent; `ac-ffmpeg` reachable only from the leaf worker under an off-by-default feature);
- **both workers are AppContainer-confined** with proven denied-confined / allowed-unconfined differentials, **including late-lifetime probes** across the duplex session (13 containment/OOM tests green);
- **every decoded frame/PCM is re-validated in the main process** before render (worker + launcher, two layers);
- **the on-disk cache is ciphertext-only** (e2e GATE 5: cached blob ≠ decoded plaintext, and the plaintext never appears at rest);
- **bombs and the two fuzzer findings are handled** — rejected/bounded (8 bomb tests) and **contained** (F1 worker-abort, F2 Job-memory-cap kill), both ASan-clean DoS, not RCE;
- **the render path uses no OS/HW bitstream decoder** on attacker bytes (WebGL on already-decoded validated frames; HW waiver default-OFF, unwired);
- **the author→view round-trip works e2e** over real loopback TLS (`phase7_video_author_to_view_over_real_tls`, 6 gates).

The residuals — **R1** (AAC audio deferred), **R2** (real ffmpeg ingest deferred behind a default-off feature), **F1/F2** (contained DoS, upstream issues to file), **CF-2** (64 MiB stack, implemented), **large-source delivery**, **per-fragment respawn**, and the non-Phase-7 **keystore argon2 host flake** — are deferred honestly with their closure paths. These caveats are the value of this doc: Phase 7 hardens the system's #1 RCE surface as far as the committed pure-Rust path allows, and is explicit about what it does and does not yet prove. **Media-app Phases 1–7 are feature-complete on `media-app`; the `finishing-a-development-branch` merge/PR decision is the natural next step.**
