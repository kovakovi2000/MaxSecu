# MaxSecu Media App — Phase 7: Sandboxed Video

**Status:** Design (approved in brainstorming 2026-06-29). Next step: implementation plan (writing-plans).
**Scope:** Light up the **video** path of the media app (D-B) — author-side transcode to a canonical format and **viewer-side decode of attacker-authored bytes** — without letting a codec 0-day reach keys, plaintext, or the network. This is the system's **#1 RCE surface** and the last media-app roadmap phase (spec §10.7).
**Companion to / amends:** `docs/media-sandbox.md` (the decode-isolation model; this spec **ratifies §4** and extends §2/§3), `docs/superpowers/specs/2026-06-28-maxsecu-media-app-design.md` (D-B, §5 player, §6 feedback, §10.7), `DESIGN.md` §8.1/§13/§15.3, `docs/stack.md` §1.7.

> Every confidentiality/integrity guarantee continues to rest on the existing core and is re-verified client-side. The UI and the codec workers are **outside the TCB**. The decode worker holds **no keys and opens no sockets**; the launcher hands it only already-decrypted canonical bytes for one file and kills it per session. **No C ever enters `client-core`, `client-app`, or the main process** — the one sanctioned C carve-out (ffmpeg/libav) lives only in a spawned, AppContainer-confined leaf worker.

---

## 1. Decisions taken in this brainstorm (2026-06-29)

| # | Decision | Choice |
|---|---|---|
| P7-1 | Codec / C carve-out scope | **Pure-Rust view path; C confined to author-side ingest.** View = `rav1d` (AV1) + `symphonia` (CMAF demux + AAC-LC) — **zero C** on the maximally-adversarial hot path. Author ingest of arbitrary source = `ffmpeg`/libav (the sole C carve-out), itself AppContainer-confined. |
| P7-2 | Render path to screen | **Worker emits native I420/YUV; a WebGL shader does YUV→RGB on the GPU → `<canvas>`; audio PCM → WebAudio.** No OS/hardware bitstream decoder ever touches attacker bytes (media-sandbox §4). ~2× less seam bandwidth than RGBA. |
| P7-3 | Worker model | **Persistent per-clip session worker** fed CMAF fragments over a **duplex streaming proto**, emitting a continuous `I420 frame` + `PCM` stream until close/seek/error. Hard-killed (Job Object kill-on-close) on session end / seek-reset / error / cap breach. |
| P7-4 | Canonical audio codec | **AAC-LC**, pure-Rust decode via `symphonia` (Opus has no mature pure-Rust decoder). Author-side ingest encodes the AAC track. Re-ratifies media-sandbox §4 (which named Opus) — an `alg`-registry addition, **not** a wire-format break. |
| P7-5 | Sub-gate sequencing | **Pure-Rust spine first, the C ingest worker last** — the dangerous C lands atop a proven, fuzzed pure-Rust spine. |

These build on the locked media-app decisions (design §2, esp. D-B) and do **not** alter the zero-knowledge core: no new server crypto/endpoints, no key handling in any worker.

---

## 2. Canonical video format (ratifies media-sandbox §4)

The uploader transcodes **every** source to ONE canonical format so the viewer ships a single hardened decoder set and decodes only that format (no demuxer-zoo auto-probing).

| Class | Canonical | Encode (author side) | Decode (view side) |
|---|---|---|---|
| **Container** | fragmented MP4 / **CMAF**, faststart, **key-frame-aligned closed-GOP fragments** (each independently decodable) | mux in the ingest worker | `symphonia` (pure Rust) |
| **Video** | **AV1** | `rav1e` (pure Rust) | **`rav1d`** (pure Rust) |
| **Audio** | **AAC-LC** | ffmpeg AAC encoder (in the confined ingest worker) | `symphonia` (pure Rust) |

- **Closed-GOP independently-decodable fragments are mandatory.** They are what enable (a) the persistent-session decode worker to resume from any fragment, (b) **arbitrary seek** (§5), and (c) **bounded decrypt-while-play** (§6).
- **Fragment ↔ chunk alignment:** fragment boundaries are aligned to upload-chunk boundaries at encode time, so a seek to time *T* maps to a contiguous encrypted-chunk range.
- **Fragment index:** a small `pts → fragment → chunk-range` table is produced at transcode time and carried in the file metadata; the main process uses it to map seek-time → chunks to fetch/decrypt.
- The `alg`/format identifier is threaded through the manifest, so this format set is a **registry addition**, not a wire-format break.

### 2.1 Pre-decode bounds (reject before you allocate — media-sandbox §3)

Checked in the main process (cheap, no decoder) **and** re-checked in each worker before any decoder touches the bytes:

`max_width`, `max_height`, `max_pixels` (existing `MediaBounds`) **plus new** `max_duration_ms`, `max_framerate`, `max_fragment_bytes`, `max_total_bytes`, `max_fragments`, `max_audio_channels`, `max_sample_rate`. All are hard ceilings; anything over is rejected before frame/audio buffers are allocated. The Job Object memory + wall-clock caps kill a pathological input rather than hang.

---

## 3. Codec dependencies (charter item 1 — the ratification)

**View path = zero C** (the maximally-adversarial hot path is memory-safe by construction):
- `rav1d` — AV1 decoder (memory-safe Rust port of dav1d).
- `symphonia` — ISO-BMFF/CMAF demux + AAC-LC decode.

**Author ingest = the sole C carve-out** (the author's own bytes — untrusted but less adversarial, §5):
- `ffmpeg`/libav (via an `-sys` binding) — **decode arbitrary source** video/audio → raw frames / PCM, and (where no pure-Rust path exists) AAC encode + CMAF mux.
- `rav1e` — AV1 encode (pure Rust).
- A pure-Rust MP4/CMAF muxer where viable; otherwise muxing rides ffmpeg inside the confined worker. The exact internal split (pure-Rust muxer vs. ffmpeg) is pinned at sub-gate 1.

**Containment of the C itself (mirrors `media-worker::win32`):**
- ffmpeg lives **only** in a NEW leaf crate `media-transcode-worker` (lib+bin), spawned + AppContainer-confined. The `-sys` C dependency is isolated to that crate.
- `client-core::media::FfmpegVideo` is reshaped into a **thin launcher** that spawns the confined transcode worker and exchanges bytes — exactly as the decode seam spawns `media-worker`. `client-core` and `client-app` stay **C-free**; the TCB never links a codec.

**Supply-chain / deny.toml:**
- The ffmpeg `-sys` crate is the **one** new C dependency. `ring`/`openssl` stay hard-banned; `aws-lc-rs` remains the only other sanctioned C.
- Pin the `-sys` crate; `cargo audit` it; document its advisory posture in `deny.toml` with a written justification (as with the existing Tauri/GTK entries).
- A reproducible build of the bundled C library is a documented **deferred-op** (like Authenticode signing and PG bundling), not a security gap.

> **Verify-points (settled at sub-gate 1, before adoption):** `rav1d` production-readiness + crate name/version; `symphonia` AAC-LC completeness; availability of a pure-Rust CMAF/fMP4 muxer; the chosen ffmpeg binding crate and how its C library is sourced/pinned. These are confirmed and the codec decision is **security-reviewed before any adoption**.

---

## 4. The two confined workers

Both run under the existing Windows confinement (media-sandbox §2): a **no-capability AppContainer** (no `internetClient` — no network by capability), a low-privilege token that cannot read the user's files / `local_key_blob`, and a **Job Object** with `ACTIVE_PROCESS = 1` (no child processes), `KILL_ON_JOB_CLOSE`, and a hard memory cap. WER/crash dumps disabled (a crash writes no memory image). Worker **output is untrusted too** and validated before render.

### 4.1 Decode / view worker (extend `media-worker`, pure Rust — the hot path)
- **Persistent per-clip session.** New **duplex streaming proto** (many messages): the launcher feeds CMAF fragments + control messages in; the worker streams `I420Frame { y, u, v planes, width, height, pts }` and `Pcm { samples, channels, sample_rate, pts }` out.
- The audited `unsafe` AppContainer launcher (`win32.rs`) grows **duplex streaming pipe I/O** (concurrent write-requests / read-responses across the session) — the largest single review surface in the phase.
- **Seek/flush control message:** flush decoder state and resume from fragment *K* (clean because each fragment is self-contained).
- Per-fragment bounds + session caps (§2.1). Hard-killed on session end / seek-reset / error / cap breach.

### 4.2 Transcode / ingest worker (NEW crate `media-transcode-worker`, the C — one-shot per upload)
- Input: the author's arbitrary source file bytes (one file). Output: canonical **CMAF + thumbnail + preview** (`CanonicalStreams`) + the fragment index + optional loudness-normalization metadata.
- ffmpeg decodes source → raw; `rav1e` encodes AV1; AAC encode + CMAF mux. One worker per upload, killed per job.
- AppContainer-confined identically to the decode worker; the author's bytes are untrusted (media-sandbox §5/§7).

---

## 5. Seek, caching & bounded decrypt-while-play

- **Decrypt-while-streaming (explicit for video):** fetch encrypted chunk → decrypt in the **main process (TCB)** → feed the canonical fragment to the worker → decode → render → **discard**. No whole-file download; no plaintext at rest; bounded-RAM window.
- **Arbitrary seek:** fragment index maps seek-time → fragment *K* → contiguous chunk range; the player issues a seek/flush; the worker resumes at *K*.
- **On-disk ciphertext fragment cache (NEW):** a bounded LRU keyed by `(file_id, fragment)`, extending the `cache/` model (§8.1). Jumping **back** to an already-watched part **re-fetches nothing** — it re-reads the cached **ciphertext**, then re-decrypts (fast) + re-decodes (cheap). **Decoded/plaintext frames are NEVER persisted**; only ciphertext on disk. The cache is `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED`, LRU-bounded by a configurable cap.
- **In-RAM decoded-frame ring (NEW):** a small ring of recently-decoded frames for instant scrubbing within a few seconds, bounded by the Phase-5 RAM-cache cap.

---

## 6. Player / render (UI, outside the TCB)

`<video-player>` Web Component:
- Receives **paced** `I420Frame` + `Pcm` over the Tauri event stream → uploads Y/U/V as GPU textures → a **WebGL BT.709 YUV→RGB fragment shader** → `<canvas>`. Audio via **WebAudio**; A/V sync off `pts` against the audio clock.
- **GPU is used for render only** (on already-decoded, validated frames). **HW bitstream decode is OFF by design** (media-sandbox §4); an **optional, default-OFF, security-reviewed waiver toggle** is documented for users who knowingly trade containment for battery/perf — documented, not shipped enabled.
- **Volume/mute** via a WebAudio `GainNode` (keyboard-accessible, persisted preference). **Optional loudness normalization:** EBU R128 (`ffmpeg loudnorm`) measured at transcode, stored as a metadata gain, applied as a playback gain offset (off if absent).
- **Scrubber:** played-vs-loaded-segment indication driven by the fragment cache / fetch state.
- **States (design §146):** buffering · playing · stalled · error · codec-unavailable, plus a "decode worker pending" badge. Reduced-motion = **no autoplay**.
- **Optional playback-rate** 0.5×–2× (audio resampled / dropped per rate) in this phase if cheap; **captions/CC** track wiring is a documented later follow-up (the chrome exists from §146; canonical CMAF can carry a timed-text track).
- Only decoded frames/PCM + typed state cross the seam — **never** keys, signed-record interiors, or whole-plaintext.

---

## 7. Bounds, output-validation, containment & fuzzing (the exit gates)

- **Output untrusted too:** every `I420Frame` validated (plane lengths vs `width·height` luma / `⌈w/2⌉·⌈h/2⌉` chroma, dims within caps, sane/monotonic `pts`); every `Pcm` length/format/channel/rate-checked — **before** the renderer touches it. A worker compromise that returns a malformed frame is caught here.
- **Containment tests** (mirror `media-worker/tests/containment_windows.rs`) for **both** workers, and for the decode worker across its **whole session lifetime**: denied network / child-spawn / key-blob read while the unconfined differential is allowed; still decodes/transcodes correctly; crash writes **no** memory image.
- **Bomb / oversize / garbage suite:** malformed CMAF, oversize dimensions/duration/framerate, AV1 decompression bombs, truncated / trailing-data fragments → rejected **pre-allocation**; the worker is killed, not hung.
- **Committed fuzz corpus** + a `cargo-fuzz` target over the decode proto + AV1/CMAF inputs (media-sandbox §6).
- **No-plaintext:** the server, cache, and any cold tier never hold a decoded byte/thumbnail/preview — all artifacts are client-made and encrypted.

---

## 8. Sub-gate roadmap (P7-5: pure-Rust spine first, C ingest last)

Each sub-gate = one **fresh `opus` subagent** (never downgraded), two-stage review between tasks (spec-compliance vs. this spec, then code-quality; a **dedicated security review** on every TCB/codec/sandbox/launcher task, combined review only for pure-UI tasks), all findings fixed via SendMessage to the same implementer, then **exactly one auto-commit** on green (conventional commit; the mandated `Co-Authored-By` + `Claude-Session` trailers). **No push, no merge to main.**

1. **Codec ratification + adoption** — verify/pin `rav1d`, `rav1e`, `symphonia`, the muxer, and the ffmpeg `-sys` choice; `deny.toml` + `cargo audit` justification; **security-reviewed before adoption**.
2. **`client-core` video seam contracts** — duplex decode proto types, `VideoBounds` (§2.1), `I420Frame` / `Pcm` types + output-validation; reshape `FfmpegVideo` into a launcher contract. (TCB — dedicated security review.)
3. **Persistent session decode worker** — duplex proto + AppContainer launcher **duplex streaming** extension + **seek/flush** + containment/bomb tests; pure Rust, driven by **pre-canonicalized AV1/AAC/CMAF fixtures**. (TCB/launcher — dedicated security review.)
4. **Ciphertext fragment cache + fragment index** — bounded on-disk LRU `(file_id, fragment)` ciphertext cache + in-RAM decoded-frame ring + the `pts→fragment→chunk` mapping; decoded frames never persisted.
5. **Player chrome light-up** — YUV/WebGL canvas + WebAudio + volume/mute + scrubber (played-vs-loaded) + state machine + (optional) playback-rate + the default-off HW-decode waiver toggle; e2e vs fixtures.
6. **Author-side ffmpeg ingest worker** — the C carve-out crate `media-transcode-worker` + AppContainer confinement + `loudnorm` measurement + preview-before-upload + **full author→view e2e** over real TLS.
7. **Holistic security review** → `docs/security-review-phase7-mediaapp.md` (PASS/residuals) → update `MEMORY.md` + `media-app-plan.md`.

**Gates per task (all green before commit):** `cargo clippy --workspace -D warnings`; `cargo deny check`; `cargo audit`; `MAXSECU_PG_OPTIONAL=1 cargo test --workspace` (run `maxsecu-media-worker` **isolated single-threaded** — known parallel-only flake); UI: `npm run typecheck && npm test && npm run test:a11y && npm run build`. cargo is not on the tool PATH (prefix with the `.cargo/bin` PATH export). Tauri CLI/GUI absent — verify via build/clippy/test + tsc/npm only; never launch the window. fmt: new crates + `client-app` + `ui` kept fmt-clean; `client-core`/`server` carry pre-existing drift — never `cargo fmt --all`.

---

## 9. Residuals (honest)

The sandbox **contains**, it does not eliminate (media-sandbox §7):
- A 0-day in a sandboxed decoder **combined with** an AppContainer escape would still reach the host — the workers are kept secret-less so a *non-escaping* compromise yields nothing; keep decoders pinned + fuzzed.
- `rav1d` is memory-safe **by construction** but younger in fuzz-deployment than C dav1d — pin + fuzz; the memory-safety class is removed regardless.
- The ffmpeg ingest worker is a larger surface (full libav) but runs on the author's **own** input, is equally confined, and never touches the view hot path; its C is isolated to a leaf crate.
- Worker **output** validation is its own small typed surface — kept minimal.
- HW bitstream decode deliberately forgone (CPU cost accepted). Reproducible C-lib build, captions/CC track wiring, and advanced player features are documented follow-ups.

Treat any change to a worker's privilege, the canonical format, or the C carve-out as a **security-reviewed** change.
