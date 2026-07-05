# Remux-first / GPU-ladder Video Ingest — Security Review & Sign-off

**Date:** 2026-07-05
**Branch:** `feat/fast-ingest-gpu`
**Scope:** the fast-ingest rewrite of the author-side video pipeline — **probe → plan (copy-vs-reencode) → stream-copy OR H.264 re-encode ladder (NVENC → AMF → x264)** — plus the optional **in-RAM (`Memory`) fragment-cache backend**. Client-side only.

**Companion to / builds on:** `docs/security-review-universal-video-ingest.md` (the embedded-ffmpeg confinement model this extends), `docs/security-review-phase7-mediaapp.md` (the AppContainer + Job Object decode-isolation model), and `docs/media-sandbox.md`.

**Verdict:** **PASS** — no Critical/High/Medium open against the committed path. Confinement is **UNCHANGED**; no GPU-device grant or capability relaxation was added; the server sees exactly today's ciphertext (no new plaintext/metadata). The former GPU residual is now **resolved**: with an adequate driver, NVENC **and** AMF were confirmed to initialize **inside the full confinement** (spike, 2026-07-05) — full GPU speed at zero security cost; on a host with too-old a driver the ladder degrades to confined x264.

---

## 1. Scope

The ingest path was rewritten from an unconditional re-encode to a **remux-first** design:

1. **Probe.** `maxsecu_media_launcher::probe_source` spawns the embedded `ffmpeg -i` on the source and classifies it (`ProbeResult { video, audio, video_8bit_420 }`).
2. **Plan.** `plan_ingest(&probe, &opts) -> IngestPlan { reencode_video, reencode_audio }` decides per-stream copy-vs-reencode: a video stream is copyable only if already **H.264 or AV1**, **already plain 8-bit 4:2:0**, and no rescale/re-rate is requested (Original resolution + Original bitrate); audio is copyable iff already AAC (or absent). Everything else — 10/12-bit, HDR, 4:2:2/4:4:4, non-AAC audio — is re-encoded.
3. **Ingest.** `prepare_video_streams` either **stream-copies** (`-c copy`, `VideoArg::Copy`) an already-player-compatible source or **re-encodes** to H.264 via a **NVENC → AMF → x264** encoder ladder that degrades to the always-present pure-CPU x264 floor.

Separately, a `FragmentCacheLocation::Memory` fragment-cache backend was added alongside the existing on-disk backend (ciphertext-only, selectable from settings).

**No server, wire, or `client-core` change.** No new endpoint, no new server-visible field, no duration/plaintext metadata. The server stores exactly the same opaque ciphertext streams as before this change.

---

## 2. Confinement — UNCHANGED

Every ffmpeg spawn on the ingest path runs under the **identical** Phase-7 confinement used by the universal-video-ingest and decode workers, via `FfmpegLauncher::new` → the shared `media-launcher` win32 launcher:

- capability-free **AppContainer SID** ⇒ no network *by capability*;
- **low-IL** token ⇒ cannot read the user's key blob;
- **Job Object** with `ActiveProcessLimit=1` (no children), `JOB_OBJECT_LIMIT_PROCESS_MEMORY` (a decompression bomb is Job-killed, not hung), `KILL_ON_JOB_CLOSE`, and a finite bounded-wait-then-force-kill;
- filesystem reach scoped to one per-job dir via a merged, RAII-revoked DACL ACE;
- `stdin`/`stdout` = `NUL`, stderr a bounded 64 KiB diagnostic capture, and an explicit handle-inheritance allow-list.

This holds for **all three** spawn kinds — the **probe** (`ffmpeg -i`), the **copy** (`-c copy`), and **every re-encode rung** (NVENC/AMF/x264). **No relaxation, no GPU-device grant, and no new capability was added.**

**The "relax for GPU" option was NOT taken — and the spike proved it is unnecessary.** The design contemplated granting the confined process access to a GPU device to let NVENC/AMF initialize. The GPU-encode spike (`crates/media-launcher/tests/gpu_confined_spike.rs`, run 2026-07-05 on an RTX 5090 + AMD iGPU) established two things:

1. **Initial driver gap (since resolved by the operator).** On the first run NVENC/AMF failed to load *even unconfined*, for a driver/runtime **version** reason independent of confinement (NVENC: *"Required nvenc API 13.1, Found 13.0, min driver 610.00"* — the vendored ffmpeg was newer than the installed NVIDIA driver; AMF: `AMFQueryVersion failed`). After the operator updated the NVIDIA driver (to `32.0.16.1062`), both encoders load unconfined.
2. **GPU initializes INSIDE the full confinement.** With a working driver, `h264_nvenc` **and** `h264_amf` both run to a valid non-empty output through the *unchanged* `FfmpegLauncher` — the same capability-free AppContainer + low-IL + no-network + Job-Object confinement listed above (`nvenc_initializes_inside_appcontainer` / `amf_initializes_inside_appcontainer`, both exit 0). **The sandbox does not block GPU device / driver-DLL access.**

Therefore the app uses hardware H.264 encoding with **zero confinement relaxation, no GPU-device grant, and no new capability** — keys and network stay blocked to the process decoding attacker media. The only host dependency is a GPU driver new enough for the vendored ffmpeg's NVENC/AMF API; on a host without one, the ladder transparently falls through to confined x264.

---

## 3. Attack surface

The process that parses/transcodes attacker-authored media keeps **no network, no key access, and a hard memory cap** — the decode of untrusted bytes stays structurally outside the key-holding `client-app`.

- **Probe** (`ffmpeg -i`) parses untrusted input under full confinement. It produces **no output file** (ffmpeg exits non-zero by design); only the bounded stderr tail is parsed by pure-Rust code (`parse_probe`, anchored on `Stream #` lines so a hostile filename/metadata containing `Video: h264` cannot spoof the classification, and cover-art `attached pic` still-image "video" tracks are ignored).
- **Copy** (`-c copy`) still **demuxes** untrusted input to re-container it — the *same* pre-existing demux surface that the previous always-re-encode path already exercised (it, too, demuxed the source before re-encoding). Copy performs **no decode**, so relative to the prior behavior it is **strictly less** codec surface on the source, not more.
- **Re-encode** rungs are unchanged from the universal-video-ingest model.

No new external crate is added; the classification/planning (`parse_probe`, `plan_ingest`) is pure-Rust with no `unsafe`.

---

## 4. Codec / format

Output is **H.264 / AAC / fMP4 only**. `plan_ingest` copies through only sources that are **already** H.264/AV1 8-bit-4:2:0 video **and** AAC (or no) audio; everything else — 10-bit/HDR, 4:2:2/4:4:4 high-subsampling, non-AAC audio — is re-encoded down to guaranteed-playable 8-bit-4:2:0 H.264 (a deliberate conservative tradeoff: guaranteed WebView2 `<video>` playability over a lossless copy). There is therefore no path for active-content or exotic-container smuggling into the canonical stream: the viewer only ever receives H.264/AAC/fMP4, whether the bytes arrived by copy or by re-encode.

The copy path is gated by the e2e test in §7: an H.264/AAC 8-bit source is asserted to be classified copyable (`!reencode_video && !reencode_audio`) and to yield a valid, parseable-fragment-index fMP4 — with the encoder cache confirming **no H.264 encoder rung ran at all**.

---

## 5. RAM fragment cache

The new `FragmentCacheLocation::Memory` backend preserves the **ciphertext-only** invariant: it stores exactly the opaque bytes handed to the cache (the same per-chunk-AEAD ciphertext the disk backend stores), never plaintext, never keys. It is **strictly less** at-rest exposure than the disk backend — nothing touches the filesystem, so there is no on-disk ciphertext residue to recover. The selection is a plain settings enum (`Disk` default | `Memory`); it changes only *where* the opaque bytes live, not *what* they are.

---

## 6. Cross-cutting invariants

- **Codec-free key holder.** The key-holding `client-app` still links none of the decoders; ffmpeg remains a confined external `.exe`, not a Rust dependency. The remux-first change adds only `media-launcher` classification/argv logic (`probe.rs`, `ffmpeg_args.rs`) — pure-Rust, no `unsafe`, no codec.
- **No new server-visible data.** No wire/`client-core`/endpoint change; the fragment index and canonical streams are byte-for-byte the same shape as before, and round-trip through the unchanged `verify_and_open` ladder (proven by the copy-path e2e's fragment-index parse + the re-encode gate's byte-exact content round-trip).
- **Fail-closed.** Every ingest failure — unsupported/corrupt input, probe failure, copy/demux failure, every encoder rung failing, over-cap geometry — collapses to a sanitized `video_failed`/`video_unavailable`; no path/IO detail or ffmpeg stderr crosses the Tauri seam, and there is no decode oracle. A source whose GPU rungs fail lands on x264 with no user-visible difference.

---

## 7. Test evidence

`crates/client-e2e/tests/video_upload_e2e.rs` (run isolated, `--test-threads=1`):

| Test | Path exercised | Result |
|---|---|---|
| `phase7_video_upload_over_real_tls` | **Re-encode** — raw `.y4m` → `plan_ingest` requires re-encode → NVENC/AMF fail → x264 floor → canonical H.264 fMP4, byte-exact content + fragment-index round-trip over real TLS, all confined, no network | **PASS** |
| `copy_path_taken_for_h264_aac_source` | **Copy** — H.264/AAC 8-bit fixture → `probe_source` classifies `H264`/`Aac`/8-bit-4:2:0 → `plan_ingest` returns `!reencode_video && !reencode_audio` → `prepare_video_streams` stream-copies (encoder cache stays `None` — **no encoder rung ran**) → valid non-empty fMP4 with a parseable fragment index covering the content's chunk count | **PASS** |

Both pass on this GPU-less host (NVENC/AMF unavailable per §2; the re-encode ladder falls to x264, the copy path uses no encoder). The two tests together cover both legs of the `plan_ingest` decision.

---

## 8. Residuals

| Residual | Severity | Disposition |
|---|---|---|
| **Real GPU (NVENC/AMF) encode** | Resolved | Initially blocked by a host driver **version** gap; after a driver update, NVENC **and** AMF were confirmed (spike, 2026-07-05) to initialize and produce valid output **inside the unchanged full confinement** — no device grant, no relaxation. Only host dependency: a GPU driver new enough for the vendored ffmpeg's NVENC/AMF API. Too-old a driver → transparent fall-through to confined x264. |
| **Copy path inherits source GOP** | Low (QoE, not security) | Unlike the re-encode path (`-g 48` ≈ 1 s fragments), a stream-copied source keeps its own keyframe interval, so `VideoBounds::max_fragment_bytes` (16 MiB) is **not** enforced on copy output. This is **not** a correctness/security break: the fragment seek index is **byte-based and GOP-agnostic** (`chunk_grouped_index` maps 1 MiB byte bands, `pts_ms=0`), range serving is byte-ranged under the 2 MiB cap, and `+global_sidx` supplies the time→byte seek index for copy and encode alike. A pathological long-GOP / sparse-keyframe source only yields larger moof fragments → **coarser seek granularity + higher time-to-first-frame** (the least-tested new behavior). `max_fragment_bytes` was never hard-asserted against actual output even pre-change; the copy path merely widens that pre-existing gap. |

**Standing.** The Phase-7 / universal-video-ingest view-side and confinement residuals stand unchanged; the sandbox **contains, it does not eliminate**. Treat any change to a confined process's privilege, the canonical format, the ffmpeg pin/argv, or the copy-eligibility gate as a security-reviewed change.

---

## 9. Conclusion

**PASS.** The remux-first ingest adds a fast **stream-copy** path and a **GPU→CPU H.264 ladder** while keeping the #1 RCE surface (ffmpeg on attacker bytes) inside the **unchanged** capability-free AppContainer + Job Object — probe, copy, and every encode rung alike. No relaxation, no GPU grant, no new capability, no new crate, and no new server-visible data were introduced; the copy path emits only guaranteed-playable H.264/AAC/fMP4; the RAM fragment cache preserves the ciphertext-only invariant with strictly less at-rest exposure; and both the copy and re-encode legs are e2e-gated. The single residual (real GPU encode) is deferred to a driver update plus an in-container spike and carries no code residual. Signed off **PASS**.
