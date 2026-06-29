# Phase 7 (Media App) — Codec Ratification & Security Review (Gate 1)

**Scope:** the sandboxed-video codec set for the media app's view and author-ingest paths — branch `media-app`, Phase-7 Gate 1 (codec ratification). This is the **security-reviewed-before-adoption** artifact: it pins the exact crate set + versions, records the APIs that a running round-trip actually exercised (a throwaway spike crate, since deleted), states the attack-surface justification for the pure-Rust view path + the C ingest carve-out, and records the deny/audit posture and the honest residuals. Later Gates **adopt these exact pins** into real crates — so this doc is authoritative.

**Companion to / ratifies:** `docs/media-sandbox.md` (the decode-isolation model; §4 canonical-format choice is ratified here and in that file), `docs/superpowers/specs/2026-06-29-maxsecu-media-app-phase7-video.md` §2/§2.1/§3 (canonical-format + caps + codec-dependency spec), `docs/parameters.md` (the numeric caps), `DESIGN.md` §8.1/§13/§15.3, `docs/stack.md` §1.7.

**Method:** a throwaway spike crate (`crates/_spike-codecs`, now deleted) compiled the candidate crates and ran a **real round-trip** — `rav1e` AV1 encode → hand-built non-fragmented MP4 → `symphonia` ISO-BMFF demux → `rav1d` AV1 decode — plus an optional `--features ingest` probe that ran a **real C ffmpeg H.264 decode** of a generated clip. The crate sources were read under `~/.cargo/registry/src/...`; every API below was proven by a running program (`ROUND-TRIP OK: 64x64`, exit 0; `INGEST DECODE OK: 48x32`), not assumed from memory. The spike's findings were two-stage reviewed (spec + quality) across Tasks 1.1–1.3 and are folded here verbatim, then the spike was deleted.

**Verdict:** **PASS — adopt the pinned set below**, subject to the recorded carry-forward directives for Gates 3 and 6. No Critical/High/Medium finding. The view path (the system's #1 RCE surface) is **zero-C (verified — built nasm-free, `asm` off); memory-safety is greatly improved over C but not *guaranteed*** (`rav1d` is a c2rust-seeded port with substantial internal `unsafe`), so **pin + fuzz is retained** as the standing mitigation. The one C carve-out (`ac-ffmpeg`) is author-side only, feature-gated, and slated for AppContainer confinement in a secret-less leaf worker. Two real residuals are carried forward and must be closed where they land: **(R1)** a genuine AAC-LC decode round-trip is verified only in Gate 3 (the spike round-tripped **video only**); **(R2)** the `ac-ffmpeg` 0.19.0 ↔ FFmpeg 8.0 pairing is **undocumented/unsupported** and a single happy-path decode is **weak ABI evidence** — Gate 6 must pin a vendored, ac-ffmpeg-supported FFmpeg (≤ 7.x) inside the confined worker and re-verify.

---

## 1. The pinned crate set (adopt these exact versions)

All view-path crates are built `default-features = false` with the **`asm` features OFF** — pure-Rust fallback paths, **no nasm / external assembler required**. The author-ingest C crate is optional and feature-gated.

| Crate | Version | Role | Path | Features (production) |
|---|---|---|---|---|
| **`rav1d`** | **1.1.0** | AV1 **decode** — the view-path TCB | view (hot path) | `default-features = false`, `bitdepth_8`, `bitdepth_16`; **`asm` OFF** |
| **`symphonia`** | **0.6.0** | CMAF/ISO-BMFF **demux** + **AAC-LC decode** | view (hot path) | `default-features = false`, `isomp4`, `aac` |
| **`rav1e`** | **0.8.1** | AV1 **encode** (author-side, pure Rust) | author ingest | `default-features = false`; **`asm` OFF** |
| **`ac-ffmpeg`** | **0.19.0** | libav **decode of arbitrary source** + AAC encode + CMAF mux (the C carve-out) | author ingest, **feature-gated** | `default-features = false`, `optional = true` (no avfilter) |

Notes that drive adoption:
- **`rav1d` requires** at least one of `bitdepth_8` / `bitdepth_16` (a `compile_error!` enforces it); `asm` is **not** in that required set, so it can — and must — stay off.
- **`rav1d`'s `cc` / `nasm-rs` build-deps are present-but-unused** with `asm` off: they appear in `cargo tree` as declared build-deps, but the spike built and ran with **no nasm installed**, confirming `build.rs` gates every C/asm invocation behind the `asm` feature. **Production keeps `asm` OFF for the view path and re-confirms** (a clean build with no nasm present is the check). See §6 carry-forward (CF-1).
- `ac-ffmpeg`'s `default-features = false` keeps `filters`/avfilter off → fewer linked libs, aligning with the minimize-the-C posture.

---

## 2. Verified APIs (proven by the spike round-trip; the adoption surface)

The Gate-3/Gate-6 implementers adopt against these exact APIs (read from the crate sources, exercised by a running program). This section is the durable record after the spike's deletion.

### 2.1 `rav1d` 1.1.0 — AV1 decode (THE view-path TCB)

`rav1d` is an rlib exposing the **dav1d C ABI** as `pub unsafe extern "C"` Rust functions, callable directly (a memory-safe Rust port of dav1d — see §5 justification).

- Types: `rav1d::include::dav1d::dav1d::{Dav1dContext, Dav1dSettings}` (`Dav1dContext = RawArc<Rav1dContext>`, `Copy`; API takes `Option<Dav1dContext>`); `Dav1dSettings` has public `n_threads: c_int`, `max_frame_delay: c_int`; `rav1d::include::dav1d::data::Dav1dData`; `rav1d::include::dav1d::picture::Dav1dPicture` (`pic.p: Dav1dPictureParameters { w, h, layout, bpc }` is the geometry; `pic.data: [Option<NonNull<c_void>>;3]`, `pic.stride: [ptrdiff_t;2]` for plane access).
- Functions (`rav1d::src::lib::…`): `dav1d_default_settings`, `dav1d_open`, `dav1d_data_create`, `dav1d_send_data`, `dav1d_get_picture`, `dav1d_picture_unref`, `dav1d_close`.
- Result: `Dav1dResult(pub c_int)` — **`0` == success**; negative == `-errno` (e.g. `-EAGAIN`).
- Send/drain pattern that worked (single still, single-threaded): set `n_threads = 1`, `max_frame_delay = 1`; bounded loop — if `data.sz > 0` send (ignore EAGAIN), then `get_picture`; on `res.0 == 0` read `pic.p.w/h`, `unref`, break.

> **Carry-forward (CF-2 — Gate 3):** rav1d's single-threaded (`n_threads = 1`) decode uses large/deep stack frames that **overflow the default 1 MiB main-thread stack on Windows (`STATUS_STACK_OVERFLOW`)**. The spike ran the decoder on a `std::thread::Builder::stack_size(64 MiB)` worker. **Production must run the rav1d decoder on an enlarged-stack thread (or rely on `n_threads > 1`).** This is a directive for the Gate-3 session worker.

### 2.2 `symphonia` 0.6.0 — CMAF demux (`isomp4`) + AAC-LC decode (`aac`)

- Imports: `symphonia::core::io::{MediaSourceStream, MediaSourceStreamOptions}`; `symphonia::core::formats::{FormatOptions, FormatReader, TrackType}`; `symphonia::core::codecs::CodecParameters`; `symphonia::default::formats::IsoMp4Reader` (under `isomp4`); `symphonia::default::codecs::AacDecoder` (under `aac`).
- Open/read: `MediaSourceStream::new(Box<dyn MediaSource>, opts)` (a `std::io::Cursor<Vec<u8>>` is a seekable `MediaSource`); `IsoMp4Reader::try_new(mss, FormatOptions::default())` — requires `ftyp` + `moov` + `mdat`; **supports both fragmented (`moof/traf/trun`) and non-fragmented (`stbl`)**. `first_track(TrackType::Video)` → `Track { id, codec_params, .. }`; `next_packet()` → `Packet { track_id, data: Box<[u8]>, pts, dts, dur, .. }` — `pkt.data` is the raw AV1 sample, fed straight to `dav1d_send_data`; `Ok(None)` == end of stream.
- For an `av01` sample entry symphonia 0.6.0 reads `width`/`height` from the visual sample entry but does **not** set a concrete `codec` id (stays the NULL video id) and does not parse `av1C` — it still yields the raw sample bytes, which is all the view path needs.

> **Carry-forward (R1 / CF-3 — Gate 3): AAC-LC is "feature builds," NOT round-trip-verified.** The spike's round-trip exercised **VIDEO ONLY** (rav1e → CMAF → symphonia-demux → rav1d-decode). symphonia's AAC decoder (`AacDecoder`, `aac` feature) was **compiled and registered but no audio sample was actually decoded end-to-end**. A genuine AAC-LC decode round-trip (fixture-with-audio → in-process session decode of PCM) **is verified in Gate 3**, not assumed here. This is the single most important honesty caveat in this doc.

### 2.3 `rav1e` 0.8.1 — AV1 encode (author-ingest, not TCB)

- Import: `rav1e::prelude::{ChromaSampling, Config, Context, EncoderConfig, EncoderStatus}`.
- `EncoderConfig::with_speed_preset(u8)`; public fields `width/height/bit_depth/chroma_sampling (Cs420)/still_picture`. `Config::new().with_encoder_config(cfg).new_context::<u8>()`.
- Frame fill: `Context::new_frame()` → `frame.planes: [Plane<T>;3]`; `Plane::copy_from_raw_u8(src, stride, bytewidth)` (8-bit → bytewidth 1; chroma `W/2×H/2` for 4:2:0).
- Encode loop: `send_frame` → `flush` → `receive_packet` → `Ok(Packet{data: Vec<u8>,..})`; `Err(Encoded)` keep polling; `Err(LimitReached|NeedMoreData)` done. For a single `still_picture`, packet 0's `data` is self-contained (carries the sequence-header OBU; decodes with no separate `av1C`). `container_sequence_header()` is available for building an `av1C` if a later task wants one.

### 2.4 `ac-ffmpeg` 0.19.0 — author-side ingest decode (the C carve-out)

- `format::io::IO::from_seekable_read_stream(File)`; `format::demuxer::Demuxer::builder().build(io)?.find_stream_info(None)` (error variant `(Demuxer, Error)` → `.map_err(|(_, e)| e)`); first stream where `stream.codec_parameters().is_video_codec()` (scope the immutable borrow so the packet pump can borrow `demuxer` mut); `codec::video::VideoDecoder::from_stream(&stream)?.build()?`; pump `demuxer.take()? -> Option<Packet>`, skip mismatched `stream_index()`, `decoder.push(packet)?`, drain `decoder.take()? -> Option<VideoFrame>`, then `decoder.flush()?` + final drain; `frame.width()/height() -> usize`.
- Link mode is `dylib` by default (`FFMPEG_STATIC` unset) → links import libs; matching DLLs must be on `PATH` at runtime.

> **Do NOT copy the spike's first-frame decode loop verbatim into production** — it is a minimal happy-path probe and **lacks proper decoder drain / frame-reorder handling**. Gate 6 writes the real ingest loop.

---

## 3. Attack-surface justification (the heart of the ratification)

**The view path is the system's #1 RCE surface.** Viewing shared media runs codecs on **attacker-authored bytes**; in the key-holding main process a memory-corruption RCE would expose that user's private key and plaintext (`media-sandbox.md` §intro, threat-model "Malicious author's media → viewer's decoder"). Authenticated authorship does not make the bytes safe (authenticated ≠ benign, D24).

**Why this set contains a codec 0-day:**

1. **The view hot path is zero-C (verified); memory-safety greatly improved, not guaranteed.** AV1 decode is `rav1d` — a **Rust port of dav1d** (the security-purpose-built, continuously-fuzzed AV1 decoder), seeded by c2rust and still carrying **substantial internal `unsafe`** (raw `NonNull<c_void>` plane pointers, manual `unref`, pointer/stride arithmetic — see §2.1). Demux + AAC-LC are `symphonia` (pure Rust). With `asm` off and the build proven nasm-free, **no C and no hand-written assembly is compiled into the view path** — what the spike actually **verified is zero-C**. This *eliminates the C-toolchain / hand-written-assembly memory-corruption class* and greatly improves memory-safety over a C decoder, but it is **not** "memory-safe by construction": Rust-side UB inside the port's `unsafe` remains possible, which is exactly why pin + fuzz is retained (point 4).
2. **The remaining C runs author-side only, on the author's OWN input.** `ac-ffmpeg` (libav) decodes only the *author's own* arbitrary source media — untrusted, but **less adversarial** than arbitrary shared bytes (`media-sandbox.md` §5). It never touches the view hot path.
3. **Containment, not elimination, of the C.** The ingest C is slated to live ONLY inside a future **AppContainer-confined leaf worker** (`media-transcode-worker`) that **holds no keys and opens no sockets** (no `internetClient` capability; restricted/lowbox token; Job Object `ACTIVE_PROCESS = 1`, kill-on-job-close, hard memory cap; WER/crash-dumps off). A **non-escaping** compromise therefore yields **nothing** — no secret to read, no socket to exfiltrate over, no child to spawn. The view decode worker mirrors the existing `media-worker::win32` confinement.
4. **Pin + fuzz.** The decoders are pinned (this doc) and slated for a committed fuzz corpus + `cargo-fuzz` target over the decode proto + AV1/CMAF inputs (`media-sandbox.md` §6, spec §7). `rav1d` carries internal `unsafe` and is younger in fuzz-deployment than C dav1d — pinned + fuzzed regardless: the **C-toolchain / asm corruption class is removed** by going zero-C, while **residual Rust-side UB is mitigated by pin + fuzz + the secret-less confinement** (a non-escaping compromise yields nothing), not assumed away.

**Deny / audit outcome (this is what the gate decided):** **adopt.** The view path links no C; the sole new C link is `ac-ffmpeg*` (author-side, feature-gated). `ring` / `openssl` stay **banned and absent**; `aws-lc-rs` remains the only other sanctioned C (the rustls TLS provider, transport-only). Supply-chain gates (`cargo deny check`, `cargo audit`) exit 0 — see §4.

Reference `media-sandbox.md` §7 for the residual model this inherits.

---

## 4. Supply-chain posture (`deny.toml` + `cargo audit`)

From Task 1.3 (codec deps present) and re-confirmed after spike deletion (codec deps pruned from the graph):

- **`cargo deny check` → exit 0; `cargo audit` → exit 0.** `ring` / `openssl` / `openssl-sys` remain on the `deny` ban list and are **absent** from the lockfile (`cargo tree -i ring` / `-i openssl` print nothing). `aws-lc-rs` stays the only other sanctioned C; `ac-ffmpeg*` is the sole new C **link** (not a crypto stack — not listed in `[bans]`, and need not be).
- **Two justified `deny.toml` entries support the codecs** (added in Task 1.3 to keep `cargo deny check` green while the codec crates were in-graph):
  - `ignore = ["RUSTSEC-2024-0436"]` — **`paste`** (unmaintained, repo archived): a compile-time token-concatenation **proc-macro** reached only via `rav1d` / `rav1e`. **Not a vulnerability** (build-time macro, no I/O, no unsafe FFI), and no safe upgrade exists. Remove if the codecs move to the `pastey` fork.
  - `allow = ["NCSA"]` (license) — **`libfuzzer-sys`** (`(MIT OR Apache-2.0) AND NCSA`): a transitive dep of `rav1e` gated behind `cfg(fuzzing)`, so **never compiled into a real build** (appears only under `--target all`, which is how `cargo deny` surfaces it). Admitted solely to satisfy the license gate for a never-linked fuzz harness.
- **Spike-deletion handling (important):** when the spike is deleted and `Cargo.lock` is refreshed, the codec deps (`rav1d` / `symphonia` / `rav1e` / `ac-ffmpeg` / `paste` / `libfuzzer-sys`) leave the dependency graph **entirely** — they are re-adopted only in Gate 3 (`rav1d`/`symphonia`/`rav1e`) and Gate 6 (`ac-ffmpeg`). The two entries above then become temporarily **unused**, which `cargo deny` reports as **warnings** (`advisory-not-detected` / unused-license), **not errors** — so `cargo deny check` still exits 0. **Both entries are KEPT** (annotated *dormant until Gate 3/6 re-adopt the codec crates*) to preserve the audited decision and avoid churn.

---

## 5. The canonical-format ratification (media-sandbox §4)

Gate 1 **ratifies** the canonical format that `media-sandbox.md` §4 had flagged for sign-off (and that the Phase-7 spec §2/§2.1 fixes):

| Class | Canonical (ratified) | Author encode | View decode |
|---|---|---|---|
| **Container** | fragmented MP4 / **CMAF**, faststart, **key-frame-aligned closed-GOP fragments** (each independently decodable) | mux in the ingest worker | `symphonia` (pure Rust) |
| **Video** | **AV1** | `rav1e` (pure Rust) | **`rav1d`** (pure Rust) |
| **Audio** | **AAC-LC** | ffmpeg AAC encoder (confined ingest worker) | `symphonia` (pure Rust) |

- **Audio is AAC-LC, not Opus.** §4 originally named Opus; AAC-LC is chosen because it has a **mature pure-Rust decoder** (`symphonia`) while Opus does not, keeping the view path zero-C. This is an `alg`-registry addition, **not** a wire-format break (P7-4).
- **Closed-GOP independently-decodable fragments are mandatory** — they enable the persistent-session worker to resume from any fragment, arbitrary seek, and bounded decrypt-while-play. Fragment boundaries align to upload-chunk boundaries; a `pts → fragment → chunk-range` index rides in the file metadata.
- The numeric caps that bound a pathological input pre-allocation are pinned in `docs/parameters.md` §11 (`MAX_DURATION_MS` … `MAX_SAMPLE_RATE` + the existing pixel caps) — see §6 below; Gate 2 encodes them as `VideoBounds::default()`.

> **Gate-2 guidance — the numeric caps bound per-allocation size, NOT aggregate compute.** Each cap is a **per-allocation / per-fragment** ceiling (per-frame pixels, per-fragment bytes, sample rate, …), not a bound on **total decode work**. They do **not** close a CPU/wall-clock exhaustion vector: an input at the ceilings — 8K (33.18 Mpx) × 120 fps × 30 min ≈ **216k frames** — decoded on **asm-OFF pure-Rust `rav1d`** (slower than C dav1d) is a real compute-exhaustion attack that **no numeric cap bounds**. That vector rests **entirely on the Job Object wall-clock + committed-memory cap**, which is therefore **load-bearing and MANDATORY** for the Gate-2 worker (the decode session), **not optional**. The numeric caps and the Job Object cap are complementary: the former bound a single allocation, the latter bounds the aggregate run.
>
> **Cap-interaction note (so Gate 2 reads them right):** `MAX_FRAGMENTS` (4096) × `MAX_FRAGMENT_BYTES` (16 MiB) = **64 GiB**, which is **16×** the `MAX_TOTAL_BYTES` (4 GiB) ceiling. This is **NOT a hole** — the caps are **independent ceilings and an input must clear ALL of them simultaneously**, so the binding constraint on byte **volume** is `MAX_TOTAL_BYTES`. `MAX_FRAGMENTS` bounds per-session **index/state** (the `pts→fragment→chunk` table and resume bookkeeping), **not** byte volume — Gate 2 must not treat the fragment count as a volume control.

---

## 6. Carry-forward directives & residuals (honest — these drive later gates)

| Ref | Finding | Severity | Disposition / where it closes |
|---|---|---|---|
| **CF-1** | `rav1d`/`rav1e` `cc`/`nasm-rs` build-deps are **present-but-unused** with `asm` off; the build is gated nasm-free. | Info | **Keep `asm` OFF in production** and re-confirm a clean build with no nasm present (the zero-C check). Gate 3. |
| **CF-2** | `rav1d` `n_threads = 1` decode **overflows the 1 MiB Windows main-thread stack** (`STATUS_STACK_OVERFLOW`). | Info / operational (a crash/availability directive, **not** a security finding against the adoption) | **Run the decoder on an enlarged-stack thread or `n_threads > 1`.** The spike's 64 MiB was validated only against a **benign** clip — **Gate 3 must confirm the stack headroom holds against adversarial inputs** (deeply-nested OBU/tile structures); do **not** hardcode 64 MiB as proven-sufficient. Gate 3 (session worker). |
| **R1 / CF-3** | **AAC-LC was feature-built, not round-tripped.** The spike decoded **video only**; the AAC decoder compiled + registered but no audio sample was decoded e2e. | Residual (open) | **Gate 3 verifies a genuine AAC-LC decode round-trip** (fixture-with-audio + in-process session decode). Do not assume AAC works until then. |
| **R2 / CF-4** | **`ac-ffmpeg` 0.19.0 ↔ FFmpeg 8.0 is undocumented/unsupported.** ac-ffmpeg's README lists only FFmpeg **4.x–7.x**; the spike decoded against system **FFmpeg 8.0 / libavcodec 62**. Because ac-ffmpeg uses **hand-written FFI struct/function layouts**, a single happy-path decode is **WEAK evidence** — a struct-layout/ABI drift could **silently corrupt memory** while the probe still prints OK. | Residual (open, C boundary) | **Gate 6 must pin a vendored, ac-ffmpeg-supported FFmpeg (≤ 7.x) inside the confined `media-transcode-worker` and re-verify.** Confinement bounds the blast radius regardless. |
| **CF-5** | `ac-ffmpeg` chosen over `ffmpeg-next`/`ffmpeg-sys-next` because it is **bindgen-free** (hand-written FFI + a `cc`-compiled shim) → no libclang. `ffmpeg-sys-next` 8.1.0's build ran `bindgen` unconditionally and **blocked headlessly on missing libclang** (discovery + the `cl`-probe both succeeded; only FFI generation failed). | Info | `ac-ffmpeg` is the adoption choice (narrower surface, builds + decodes headlessly). To use `ffmpeg-next` instead, Gate 6 must provision `libclang` or vendor prebuilt bindings. |
| **CF-6** | The spike's minimal first-frame decode loop **lacks proper drain/reorder handling**. | Info | Do not copy verbatim; Gate 6 writes the real loop. |

**Standing residuals (inherited from `media-sandbox.md` §7 / spec §9):** the sandbox **contains**, it does not eliminate — a 0-day **plus** an AppContainer escape would still reach the host (keep decoders secret-less so a non-escaping compromise yields nothing; pin + fuzz). The ingest worker is a larger surface (full libav) but runs on the author's own input and is equally confined. Worker **output** is untrusted and validated (plane lengths, dims-within-caps, monotonic `pts`, PCM length/format/channel/rate) before the renderer touches it. HW bitstream decode is deliberately forgone (CPU cost accepted). A reproducible build of the bundled C lib is a documented **deferred-op**, not a security gap.

Treat any change to a worker's privilege, the canonical format, or the C carve-out as a **security-reviewed** change.

---

## 7. Conclusion

**PASS — adopt the pinned set in §1.** The view path is **zero-C (verified)** (`rav1d` + `symphonia`, `asm` off, proven nasm-free), removing the **C-toolchain / asm** memory-corruption class on the system's #1 RCE surface and greatly improving memory-safety over a C decoder — though **not guaranteeing it** (`rav1d` is a c2rust port with internal `unsafe`), so **pin + fuzz is retained**; the one C carve-out (`ac-ffmpeg`, author-side, feature-gated) is slated for a secret-less AppContainer leaf worker where a non-escaping compromise yields nothing. Supply-chain gates exit 0 with `ring`/`openssl` banned + absent, and the two codec-supporting `deny.toml` entries are kept and annotated dormant. The canonical format (AV1 / AAC-LC / CMAF closed-GOP) is ratified and its caps pinned. **Two real residuals are carried forward and MUST be closed where they land: R1 (AAC-LC round-trip — Gate 3) and R2 (the ac-ffmpeg ↔ FFmpeg-8.0 ABI risk — Gate 6 vendored ≤ 7.x re-verify).** These caveats are the value of this doc: the adoption is honest about what was and was not proven.
