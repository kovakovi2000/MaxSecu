# Fast remux-first ingest (GPU re-encode) + in-RAM fragment cache — design

**Date:** 2026-07-05
**Status:** design, pending user spec review → implementation plan
**Scope:** client-side only. **No server changes, no wire/metadata schema changes,
no `client-core` changes.** The server continues to see exactly what it sees today
(opaque ciphertext).

## Problem

Uploading video is unbearably slow: every upload unconditionally **re-encodes to
AV1** with `libsvtav1` — a pure-CPU software encoder — at `-preset 6 -crf 18`
(near-max quality, slowest end of the slowest mainstream codec). Three sub-1GB
files take ~an hour while a high-end GPU sits idle. A commercial tool (UniConverter)
does 1 GB in ~10 s because it (a) stream-copies when the source codec is already
fine and (b) uses the GPU when it must re-encode. We do neither.

The **only** real requirement for the transcode is: *produce something the player
can decode and that streams in chunks.* Playback is the native `<video>` element
(WebView2/Chromium), which decodes H.264, AV1, VP9, HEVC natively — so **AV1 is no
longer required** (it was mandated only by the retired pure-Rust `rav1d` decode
sandbox). We are paying the most expensive possible encoder for a job that usually
needs no encoding at all.

Separately: the on-disk ciphertext fragment cache (`<dir>/cache/frag/`) accumulates
files during playback. Users on fast machines / privacy-conscious users want the
option to keep those fragments in RAM only, never touching disk.

## Non-goals

- No AV1 anywhere (H.264 is the canonical re-encode target).
- No duration/`total_len` persistence, no server-visible metadata of any kind. The
  time-to-first-frame problem was already fixed by the `+global_sidx` muxer flag
  (confirmed by the user via re-upload); this design does not touch it.
- No change to the range server, fragment index, stream protocol, or player.
- No new confined *decode* worker (that path stays retired).

---

## Part A — Remux-first ingest with GPU-accelerated re-encode

### A.1 Decision flow (per upload)

```
probe(input) -> ProbeResult { video_codec, audio_codec }

copy_eligible =
      video_codec ∈ {h264, av1}
   && audio_codec ∈ {aac}
   && options.resolution == Original       # copy cannot rescale
   && options.bitrate    == Original       # copy cannot re-rate

if copy_eligible:
    # container rewrite only — no decode, no encode, no quality loss, CONFINED
    ffmpeg -i in  -c copy \
        -movflags +frag_keyframe+empty_moov+default_base_moof+global_sidx \
        out.mp4   [+ thumbnail second output]
else:
    # per-stream: copy the streams that are already fine; re-encode only what isn't
    -c:v { copy | <h264 encoder> }     # copy iff video_codec ∈ {h264, av1}* and no rescale/re-rate
    -c:a { copy | aac -b:a 128k -ac 2 } # copy iff audio_codec == aac
    -movflags +frag_keyframe+empty_moov+default_base_moof+global_sidx
    out.mp4   [+ thumbnail second output]
```

Notes:
- **Per-stream copy** — an HEVC-video/AAC-audio file re-encodes only the video; an
  H.264/Opus file re-encodes only the (cheap) audio. `*` a video-stream copy is used
  only when the *video* is already H.264/AV1 **and** no rescale/re-rate is requested;
  otherwise the video is re-encoded to H.264.
- **Re-encode target is always H.264** (`yuv420p`, 8-bit) — the universally
  WebView2-decodable, GPU-encodable codec. HEVC is excluded (unreliable WebView2
  playback); AV1 is excluded (slow even on GPU, unnecessary).
- **Thumbnail unchanged** — the existing second output (`-map 0:v:0 -frames:v 1 -vf
  scale…`, PNG) decodes exactly one frame regardless of the main output's codec, so
  one confined/relaxed spawn still produces both `out.mp4` and `thumb.png`.
- **Fragment layout / seek granularity** — copied streams inherit the source
  keyframe interval (seek granularity follows source GOP); re-encoded streams use the
  existing `-g 48` closed GOP. Either way the chunk-grouped range index
  (`chunk_grouped_index`, byte-size based) and the 2 MiB range cap are unaffected.

### A.2 Probe

New module `crates/media-launcher/src/probe.rs`. No new binary: the vendored ffmpeg
has all decoders, and BtbN's `win64-gpl` build ships `h264_nvenc`, `hevc_nvenc`,
`h264_amf`, and `libx264`. There is no `ffprobe.exe`, so we probe by spawning the
**confined** `ffmpeg -hide_banner -i <input>` (no output file → ffmpeg prints stream
info to stderr and exits non-zero), and parse the bounded stderr for the first
`Stream #… Video: <codec>` and `… Audio: <codec>` tokens.

- Runs under the **full Phase-7 confinement** (no output, no GPU need; it parses
  untrusted input, so confinement is most valuable here).
- Parser is a pure function `parse_probe(stderr: &[u8]) -> ProbeResult` with table
  tests over captured real ffmpeg stderr samples. Unknown/absent codec → treated as
  "not copy-eligible" (fail toward re-encode, never toward an unplayable copy).
- `ProbeResult` normalizes codec names to a small known set (`h264`, `hevc`, `av1`,
  `vp9`, `vp8`, `aac`, `opus`, `mp3`, `other`).

### A.3 GPU encoder ladder (both vendors, no detection code)

Re-encode selects the H.264 encoder by **try-and-fallback**, cached for the session:

```
h264_nvenc  (NVIDIA)  --init fails-->  h264_amf  (AMD)  --init fails-->  libx264 (CPU)
```

- No WMI/NVML/dxdiag probing. We attempt the encoder; a spawn whose ffmpeg exits with
  an encoder-init failure triggers the next rung. The winning rung is stored in app
  state (`OnceCell`/`Mutex<Option<H264Encoder>>`) so later uploads skip dead rungs.
- Quality knobs tuned near-transparent, honoring `Bitrate::Kbps` when the user set an
  explicit target:
  - `h264_nvenc`: `-preset p5 -tune hq -rc vbr -cq 19` (or `-b:v Nk` when explicit).
  - `h264_amf`: `-quality quality -rc cqp -qp_i 20 -qp_p 20` (or `-rc vbr -b:v Nk`).
  - `libx264`: `-preset veryfast -crf 18` (or `-b:v Nk`).
- `-threads <transcode_threads>` continues to flow into `libx264` (GPU encoders
  ignore it, harmless).

### A.4 Confinement level

`FfmpegLauncher` gains an explicit confinement level; `win32::spawn_confined_exe`
gains the corresponding relaxed spawn path.

| Spawn | Confinement |
|---|---|
| Probe (`ffmpeg -i`) | **Full** (unchanged Phase-7 hardening) |
| Copy path | **Full** |
| `libx264` re-encode | **Full** (CPU only — no reason to relax) |
| `h264_nvenc` / `h264_amf` re-encode | **RelaxedGpu** |

**RelaxedGpu** (user-chosen "relax fully for re-encode", with one retained
protection): drops the low-integrity token, the `ActiveProcessLimit = 1` child-proc
ban, and the AppContainer restriction that blocks the GPU device + driver DLLs
(`nvEncodeAPI64.dll`, `nvcuda.dll`, `amfrt64.dll`). **Retained even when relaxed:**
**no network** (a video encoder never needs it — highest-value protection against an
RCE calling home) and a generous **memory cap** (GPU encode is light on system RAM, so
the cap costs nothing and preserves the DoS ceiling). The exact relaxation is
documented and re-reviewed in the security sign-off (§C).

Rationale for keeping `libx264` confined: it needs no GPU, so relaxing it would spend
security for nothing. Only the spawns that actually touch the GPU relax.

### A.5 Orchestration

`crates/client-app/src/upload.rs` `prepare_video_streams` changes from "one fixed
argv, one confined spawn" to:

1. Copy source into the per-job dir (unchanged).
2. **Probe** (confined spawn) → `ProbeResult`.
3. Build a **plan** (`IngestPlan::{Copy, Reencode{video, audio, encoder}}`) from the
   probe + normalized `TranscodeOptions`.
4. Execute:
   - `Copy` → one confined spawn.
   - `Reencode` with `libx264` → one confined spawn.
   - `Reencode` with GPU → one **RelaxedGpu** spawn; on encoder-init failure, fall to
     the next ladder rung (re-planning the encoder), ultimately `libx264` (confined).
5. Everything after (thumbnail derive, chunk-grouped index, metadata) is unchanged.

The `JobDirGuard` cleanup obligation and the existing progress/cancel/stall-watchdog
plumbing carry over to every spawn variant.

---

## Part B — In-RAM fragment cache option

### B.1 Setting

`PerformanceSettings` (config.rs) gains:

```rust
#[serde(default)]                       // older settings.json loads with the default
pub fragment_cache_location: FragmentCacheLocation,   // Disk (default) | Memory
```

An older `settings.json` without the key loads as `Disk` (today's behavior). Exposed
in the Phase-5 `<settings-screen>` performance section; no clamp needed (enum).

### B.2 Backend

`FragmentCache` is generalized so the byte-budgeted LRU logic (cap, tick, eviction,
validated hex key, ciphertext-only invariant) is shared, with two backends:

- **Disk** — today's `<dir>/cache/frag/*.frag` files (unchanged, still marked
  `NOT_CONTENT_INDEXED`, still wiped on `open`).
- **Memory** — the same LRU holding ciphertext blobs in an in-process
  `BTreeMap<(String,u32), Vec<u8>>`; nothing is written to disk. Same `cap_bytes`
  (`ram_cache_cap_mb`), same eviction, same **ciphertext-only** invariant (it still
  only ever stores the opaque bytes it is handed — the RAM variant is *strictly less*
  at-rest exposure than disk).

The public API (`open`/`put`/`get`/`contains`/`evict`/`total_bytes`) is identical, so
the fragment feeder (`commands/video.rs`) is unchanged apart from choosing the backend
from the setting at cache construction.

### B.3 Zeroization

Ciphertext (not plaintext) so the security bar is low, but the Memory backend drops
blobs on eviction/close like the disk one deletes files; no plaintext ever enters
either backend (unchanged invariant, re-pinned by the existing round-trip tests
extended to the Memory backend).

---

## Part C — Security review

A sign-off addendum (`docs/security-review-2026-07-05-remux-gpu-ingest.md`) covers:

1. **Confinement relaxation** — exactly which protections drop for GPU spawns, which
   are retained (no-network, memory cap), and the argument that the residual RCE
   surface (ffmpeg decoding untrusted input) is bounded by no-network + no-key-access
   + memory cap even when low-IL/child-ban are dropped. Note the copy path, probe, and
   x264 path keep full confinement.
2. **No new egress** — confirm no server-visible data added (no duration, no
   plaintext metadata); the server sees exactly today's ciphertext.
3. **Codec target** — H.264/AAC/fMP4 only; no format that could smuggle active content.
4. **RAM cache** — ciphertext-only invariant preserved in the Memory backend.

---

## Components & isolation

| Unit | File | Purpose | Depends on |
|---|---|---|---|
| argv builders | `media-launcher/src/ffmpeg_args.rs` | pure `probe_args`, `copy_args`, `reencode_args(encoder, opts)` | — |
| probe | `media-launcher/src/probe.rs` (new) | spawn `ffmpeg -i` confined, parse codecs | argv, launcher |
| confinement level | `media-launcher/src/lib.rs`, `win32.rs` | `Confinement::{Full, RelaxedGpu}` spawn | — |
| RAM cache backend | `client-app/src/fragment_cache.rs` | Disk/Memory LRU behind one API | — |
| setting | `client-app/src/config.rs` + UI `<settings-screen>` | `fragment_cache_location` | — |
| orchestration | `client-app/src/upload.rs` | probe → plan → spawn ladder + session cache | all above |
| sign-off | `docs/security-review-2026-07-05-remux-gpu-ingest.md` | confinement delta review | orchestration |

## Testing

- **argv builders** — unit/pinning tests (mirror existing `ffmpeg_args` tests):
  copy args carry `-c copy` + `global_sidx`; reencode args carry the right H.264
  encoder + quality knobs; per-stream copy/re-encode combinations.
- **probe parser** — table tests over captured real ffmpeg stderr for h264/hevc/av1/
  vp9 + aac/opus/mp3; malformed/empty → not copy-eligible.
- **RAM cache** — the disk round-trip/LRU/eviction/traversal/ciphertext-only test
  suite re-run against the Memory backend; plus a test that Memory writes nothing to
  `cache/frag/`.
- **e2e** (`client-e2e/tests/video_e2e.rs`) — (a) an H.264/AAC source → assert the
  **copy path** is taken (fast, no re-encode marker) and the result opens + streams;
  (b) a non-H.264 source → assert re-encode to H.264 + streams. GPU rungs are verified
  manually on a GPU machine (CI has none); automation asserts the **x264 confined
  fallback** is reached and produces a playable file.

## Implementation waves (multi-subagent, Opus 4.8)

- **Wave 1 (parallel):** argv builders; probe module; confinement level; RAM cache
  backend + setting. Independent units, each TDD.
- **Wave 2:** orchestration in `upload.rs` (probe → plan → GPU ladder + session
  cache); wire the cache-location setting at cache construction.
- **Wave 3:** security sign-off; holistic verification (build + tests + a real upload
  on the dev machine to confirm copy-fast + GPU engages).
