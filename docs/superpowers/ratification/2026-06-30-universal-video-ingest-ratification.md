# Universal Video Ingest — Phase-0 Ratification (HARD GATE)

**Date:** 2026-06-30
**Task:** 0.2 (spike + ratification) of the Universal Video Ingest feature
**Branch:** `feat/universal-video-ingest`
**Status:** **PASS** — end-to-end confined-capable round trip proven on real video; **Fork X ratified.**

This document is the **source of truth** for Phases 1–7. Later phases copy the
ffmpeg pin, argv, fragment layout, and caps from here verbatim. Every claim below
is backed by the evidence appendix (real runs of the throwaway
`crates/media-worker/examples/spike_ingest.rs`, now deleted).

---

## 1. FFmpeg pin

| Field | Value |
|-------|-------|
| Binary | `vendor/ffmpeg/ffmpeg.exe` (gitignored; embedded at package time) |
| Version string | `N-125365-g9a01c1cb6a-20260630` |
| Git hash | `9a01c1cb6a` |
| SHA-256 | `6ed7e5c931d3cbc72931ee7e97efc4b7d8a1287f03c60585fab81a6a293b2e0e` |
| Size | 143,314,944 bytes |
| Build | BtbN static GPL build, gcc 15.2.0 / mingw32, self-contained (no DLLs) |
| Relevant encoders | `libsvtav1` (AV1), native `aac` (AAC-LC) |
| Relevant decoders | `h264`, `hevc`, `libdav1d` (AV1), `vp9`, `libvpx`, MPEG-4 family, plus Opus/Vorbis audio |

The pinned binary decodes arbitrary input (H.264, VP9, … verified) and re-encodes
to AV1 + AAC-LC. **Use this exact binary** — the argv below is validated against it.

---

## 2. Exact ffmpeg argv (PINNED)

The ingest worker (Phase 2+ confined) drives ffmpeg as **one subprocess per
source**. The decode side is input-agnostic (ffmpeg auto-detects the demuxer +
decoder); the encode side is fixed to AV1/AAC. Pinned argv, in order:

```
-y
-i <SOURCE>
-vf scale=trunc(iw/2)*2:trunc(ih/2)*2
-pix_fmt yuv420p
-c:v libsvtav1
-preset <P>
-g <GOP>
-svtav1-params keyint=<GOP>:pred-struct=1
-c:a aac
-b:a 128k
-ac 2
<OUTPUT.mp4>
```

| Flag | Meaning / why |
|------|---------------|
| `-y` | overwrite the output path without prompting (non-interactive worker). |
| `-i <SOURCE>` | the author's arbitrary source; ffmpeg auto-selects demuxer+decoder. The only input-dependent argument. |
| `-vf scale=trunc(iw/2)*2:trunc(ih/2)*2` | **even-dimension guard**: AV1 4:2:0 requires even width AND height. No-op on already-even inputs (all 5 test files); forces a 1-px crop on odd dims so the encoder never rejects them. |
| `-pix_fmt yuv420p` | force 8-bit I420. The viewer decoder (`extract_i420`) accepts **only** 8-bit `DAV1D_PIXEL_LAYOUT_I420`; this guarantees the encode matches. (10-bit/4:2:2 sources are down-converted here.) |
| `-c:v libsvtav1` | AV1 video encoder (SVT-AV1). |
| `-preset <P>` | SVT-AV1 speed/quality. Spike used `10` for speed; production picks a slower preset (e.g. 6–8) for quality. Does **not** affect the layout. |
| `-g <GOP>` | keyframe interval = the **fragment granularity**: one closed GOP per fragment. Pick `GOP ≈ fps` (≈1 s/fragment), e.g. `48`. |
| `-svtav1-params keyint=<GOP>:pred-struct=1` | `keyint` re-asserts the GOP to SVT-AV1's own parser; **`pred-struct=1` = low-delay (no B-frame reordering)** so samples are in presentation = decode order — **no `ctts` needed** and the per-fragment sample table is trivially monotonic. |
| `-c:a aac` | native AAC-LC encoder (the viewer's symphonia `aac` decoder reads LC). |
| `-b:a 128k` | audio bitrate (tunable; not layout-affecting). |
| `-ac 2` | down/up-mix to **stereo** — matches `VideoBounds.max_audio_channels = 2`. |
| `<OUTPUT.mp4>` | a **temp file** (see §2.1). |

### 2.1 Output container: temp file (PINNED), not stdout pipe

ffmpeg's standard MP4 muxer writes `moov` **last** and must seek back to patch it,
so it cannot stream to `pipe:1`. Two options were considered:

* **Temp file (CHOSEN).** ffmpeg writes a normal seekable MP4 to a temp path; the
  worker reads it back, re-muxes (Fork X, §4), and discards it.
  **Confinement implication (Phase 2):** the confined ingest worker needs an
  **ACL granting write+read to exactly one temp file** (e.g. a per-job path under
  the worker's private temp dir). This is a narrow, well-understood grant —
  preferable to the alternative's complexity.
* **Fragmented MP4 to `pipe:1`** (`-movflags frag_keyframe+empty_moov`) would avoid
  the temp file but produces `moof`/`mdat` streaming output — that is **Fork Y's**
  on-wire shape, and adopting it would change the view-side seek/cache path (§4).
  Rejected for the same reason Fork X is chosen.

The temp file is an **ffmpeg-internal artifact only**; the bytes shipped to viewers
are the re-muxed canonical fragments, never ffmpeg's MP4.

---

## 3. Fork decision: **FORK X** (extend the hand-rolled muxer)

**Decision: Fork X.** The author-side worker decodes ffmpeg's standard MP4 with
symphonia, then **re-muxes the AV1 samples (and the AAC track) into the existing
canonical, chunk-aligned, self-contained-MP4-per-fragment layout** by extending the
hand-rolled muxer already in `media-transcode-worker`/`media-worker/tests/support`.

### Rationale (grounded in what actually decoded)

The spike proved every load-bearing assumption of Fork X on **real** ffmpeg output:

1. **ffmpeg's libsvtav1 AV1 samples carry the sequence-header OBU in-band.** Each
   sample, extracted via symphonia and re-muxed into the existing `av01`
   VisualSampleEntry **with NO `av1C` box**, decoded cleanly through the **existing,
   unmodified `VideoSession`** (symphonia demux → rav1d). 24/24 (720×1280) and
   60/60 (480×272) single-sample fragments decoded at exactly the source geometry.
   → The whole view/seek/cache path stays **byte-compatible** with what is already
   tested; no `av1C` authoring is required.
2. **Multi-sample (whole-GOP) fragments work.** A single fragment carrying a
   24-sample / 60-sample low-delay GOP (1 keyframe + N inter), tabled with
   multi-entry `stsz` + N-per-chunk `stsc` + uniform `stts` + single-entry `stss`,
   decoded **all** frames through the existing `VideoSession` (which feeds the GOP's
   samples to one persistent rav1d context in decode order). → The multi-sample
   `stbl` tabling is mechanical and demonstrably symphonia-demuxable + rav1d-decodable.
3. **The hand-muxed AUDIO track is symphonia-readable and AAC-decodes to PCM.** A
   two-track fragment (av01 + `mp4a`) built by **reusing ffmpeg's `mp4a`/`esds`
   SampleEntry verbatim** (copied out of ffmpeg's `stsd`) was demuxed by symphonia,
   and symphonia's `aac` decoder produced PCM (stereo, 44.1/48 kHz). → Fork X audio
   is viable **without hand-authoring `esds`** (the riskiest part) — we lift
   ffmpeg's exact descriptor bytes.
4. **Chunk alignment holds.** Every fragment, after a trailing `free`-box pad,
   landed on a whole 4096-byte multiple, contiguous from offset 0 — exactly what
   `client-app::parse_fragment_index` / `chunks_for_fragment` already enforce.

Fork Y (adopt ffmpeg's native fragmented MP4 + adapt the view-side index/seek/cache)
would force changes to the **tested** view path (init-segment + `moof` offset
indexing, symphonia fragmented-mp4 read, cache keyed on `moof` rather than whole
chunks) for **zero** benefit here, because Fork X re-mux proved tractable on the
first attempt. **Fork X is chosen; Fork Y is not required.**

---

## 4. The EXACT canonical fragment layout (validated)

One **self-contained, non-fragmented MP4 per fragment** = one closed GOP. Box order
(unchanged from the existing muxer for video; audio track is the Fork X addition):

```
[ftyp 'av01' … 'isommp41']
[moov]
  [mvhd]                       (timescale 1000; next_track_id = 2 video-only, 3 with audio)
  [trak]  (VIDEO, track_id 1)
    [tkhd flags=0x7]           width/height = source W×H in 16.16
    [mdia]
      [mdhd] [hdlr 'vide']
      [minf]
        [vmhd] [dinf>dref>'url ' self-contained]
        [stbl]
          [stsd] -> [av01 VisualSampleEntry]   W×H; **NO av1C** (seq hdr is in-band)
          [stts]  1 entry: sample_count=N, delta=1            (uniform; low-delay)
          [stsc]  1 entry: first_chunk=1, samples_per_chunk=N, desc=1
          [stsz]  sample_size=0, sample_count=N, then N per-sample sizes
          [stco]  1 entry: offset of the VIDEO chunk in mdat payload
          [stss]  1 entry: sample_number=1   (the keyframe = closed GOP)
          [ctts]  OMITTED — pred-struct=1 (low-delay) ⇒ decode order = presentation order
  [trak]  (AUDIO, track_id 2)  — Fork X addition, present only when the source has audio
    [tkhd flags=0x7]           width=height=0, volume=1.0
    [mdia]
      [mdhd]                   timescale = audio sample_rate
      [hdlr 'soun']
      [minf]
        [smhd] [dinf>dref>'url ' self-contained]
        [stbl]
          [stsd] -> [mp4a AudioSampleEntry + esds]   **REUSED VERBATIM from ffmpeg's stsd**
          [stts]  1 entry: sample_count=M, delta=1024   (AAC frame = 1024 samples)
          [stsc]  1 entry: first_chunk=1, samples_per_chunk=M, desc=1
          [stsz]  sample_size=0, sample_count=M, then M per-sample sizes
          [stco]  1 entry: offset of the AUDIO chunk in mdat payload
          (no stss — every AAC frame is independently decodable)
[mdat]  = <all video samples concatenated> ++ <all audio samples concatenated>
[free]  = trailing pad to the next 4096-byte multiple
```

* **Multi-sample GOP tabling.** Samples are stored in **decode order** (= symphonia's
  packet order = file order from ffmpeg). With `pred-struct=1` decode order equals
  presentation order, so `stts` is uniform and **`ctts` is omitted**. (If a future
  phase enables B-frame pyramids for compression, it MUST add a `ctts` table and
  keep samples in decode order — flagged as the single layout-affecting knob.)
* **Audio interleave.** Per-fragment self-contained MP4s are short (≈1 GOP ≈ 1 s),
  so track-level chunking (one video chunk + one audio chunk in `mdat`) is
  sufficient — no sub-fragment interleaving needed. Two `stco` entries (one per
  track) point at the two chunks.
* **`mp4a`/`esds` provenance.** The audio SampleEntry is **copied byte-for-byte**
  from ffmpeg's output `moov>trak(soun)>…>stsd>mp4a` (110 bytes observed). This
  avoids hand-authoring the AudioSpecificConfig and was proven symphonia-readable.
* **Chunk alignment + `FragmentEntry`.** After building a fragment, pad with one
  ISO-BMFF `free` box up to a whole **4096-byte** (`TRANSCODE_CHUNK_SIZE`) multiple
  (the existing `pad_to_chunk`). The fragment then occupies a contiguous whole-chunk
  range; `FragmentEntry { seq, pts_ms, chunk_start, chunk_len }` records it exactly
  as today: `chunk_start = running_offset/4096`, `chunk_len = fragment_len/4096`.
* **pts/duration.** `FragmentEntry.pts_ms` = GOP-start time = `(first_frame_index *
  1000)/fps`, monotonic non-decreasing across fragments (the player's index
  validator's requirement). Per-sample timing inside a fragment comes from `stts`.

**View-side impact: NONE for the video path.** The fragments are the same shape the
existing `VideoSession` + `client-app` fragment index already consume; the spike fed
them to the **unmodified** `VideoSession` and they decoded.

---

## 5. Audio proof (HARD requirement) — PASS

symphonia's `isomp4` demuxer + `aac` decoder were exercised two ways:

1. **From ffmpeg's output MP4 directly** (the Task-5.1 decode path): symphonia
   demuxed the AAC track and its `aac` decoder produced interleaved i16 PCM —
   `ch=2, rate=44100, frames=46080` from 45 packets (720×1280 source);
   `ch=2, rate=48000, frames=49152` from 48 packets (480×272 source).
2. **From a HAND-MUXED Fork-X fragment** (audio `trak` built by this spike, reusing
   ffmpeg's `mp4a`/`esds`): symphonia demuxed the hand-built audio track AND
   AAC-decoded it to PCM — `ch=2, rate=44100, frames=8192` (8 packets) and
   `ch=2, rate=48000, frames=8192` — proving the Fork X audio layout is readable by
   the viewer's exact codec stack.

**Conclusion:** AAC-LC → PCM via symphonia works for both ffmpeg's container and the
hand-muxed Fork X fragment. Task 5.1 (emit `WorkerMsg::Audio(PcmChunk)`) is feasible
against this layout. (`VideoSession.demux_video_samples` today reads only the video
track and harmlessly ignores the audio `trak`; the spike confirmed video still
decodes from a two-track fragment.)

---

## 6. VideoBounds caps (PINNED) + measured files

The defaults already in `client-core::video::VideoBounds` are **generous-but-finite
(8K-class)** and are **ratified unchanged**:

| Field | Value | Rationale |
|-------|-------|-----------|
| `max_width` | 7680 | 8K width. |
| `max_height` | 4320 | 8K height. |
| `max_pixels` | 33,177,600 | 7680×4320; the real per-frame allocation guard. |
| `max_duration_ms` | 1,800,000 (30 min) | generous social-clip ceiling. |
| `max_framerate` | 120 | covers 60/90/120 fps high-rate sources. |
| `max_fragment_bytes` | 16,777,216 (16 MiB) | one closed GOP ≪ this even at 4K (largest observed multi-sample fragment: 270,336 B). |
| `max_total_bytes` | 4,294,967,296 (4 GiB) | whole-stream ceiling. |
| `max_fragments` | 4096 | at ≈1 GOP/s ⇒ ≈68 min of fragments; pairs with the 30-min duration cap. |
| `max_audio_channels` | 2 | stereo (`-ac 2` enforces it on encode). |
| `max_sample_rate` | 48,000 | 48 kHz; covers 44.1/48 kHz sources. |

### Measured real files (vendored `ffmpeg -i`)

| # | File | W×H (aspect) | Duration | Bitrate | Video / Audio codec | Role |
|---|------|--------------|----------|---------|---------------------|------|
| 1 | `ttget-7604733407821771146-video-hd-ttget.com.mp4` | 720×1280 (9:16 portrait) | 10.05 s | 1141 kb/s | H.264 / AAC-LC 44.1 kHz stereo | canonical |
| 2 | `Half Life 2022.10.02 - 15.30.02.01.mp4` | **2560×1600 (8:5)** | 31.02 s | **37676 kb/s** | H.264 60 fps / AAC 48 kHz stereo | **high-res / high-bitrate** |
| 3 | `2024-06-26_12-06-30.mp4` | 1920×1080 (16:9) | 4 m 58 s | 8584 kb/s | H.264 / AAC-LC 48 kHz stereo | **large (305 MB)** |
| 4 | `2365.webm` | **480×272 (30:17)** | ~2 m 59 s | n/a | **VP9 60 fps / Opus** 48 kHz | **odd-aspect + non-H.264/non-AAC input** |
| 5 | `knee.mp4` | 1080×1920 (9:16) | 57.9 s | 5876 kb/s | H.264 60 fps / AAC-LC 44.1 kHz | portrait high-rate |

Every file is within caps (max observed: 2560×1600 = 4.10 MP ≪ 33.2 MP; 60 fps ≪
120; 37.7 Mb/s, 305 MB ≪ 4 GiB). The 8:5 and 30:17 entries exercise odd aspect
ratios; the VP9/Opus entry proves the **input-agnostic** decode side (non-H.264
video AND non-AAC audio both transcode to the canonical AV1/AAC).

---

## 7. View-side changes required

* **Fork X (chosen): NONE for the video path.** Fragments match the existing
  `VideoSession` + `client-app` fragment-index/seek/cache contract exactly (proven
  by feeding spike fragments to the unmodified `VideoSession`). The **only**
  view-side addition is the already-planned **Task 5.1** (have the worker emit
  `WorkerMsg::Audio(PcmChunk)` by also demuxing+AAC-decoding the audio `trak` —
  `VideoSession.demux_video_samples` currently reads video only). The audio layout
  this requires is proven readable in §5.
* **Fork Y (not chosen) would have forced:** symphonia fragmented-MP4 reads
  (init-segment `moov` + per-`moof` samples); a new seek index mapping fragment→
  `moof`/`mdat` byte offsets instead of whole-4096-chunk ranges; cache keyed on
  init-segment+`moof` rather than contiguous chunk spans; and re-validation of the
  whole tested view/seek/cache path. Avoided.

---

## 8. Evidence appendix

### Commands

```
# pin verification
sha256sum vendor/ffmpeg/ffmpeg.exe
#  6ed7e5c931d3cbc72931ee7e97efc4b7d8a1287f03c60585fab81a6a293b2e0e
vendor/ffmpeg/ffmpeg.exe -version
#  ffmpeg version N-125365-g9a01c1cb6a-20260630 …

# the spike (throwaway, since deleted)
cargo run -p maxsecu-media-worker --example spike_ingest -- <ffmpeg> <input>
```

### Encode argv actually run (canonical file, all-intra path)

```
-y -i <SOURCE> -t 1 -vf scale=trunc(iw/2)*2:trunc(ih/2)*2 -pix_fmt yuv420p
-c:v libsvtav1 -preset 10 -g 1 -svtav1-params keyint=1:pred-struct=1
-c:a aac -b:a 128k -ac 2 <OUT.mp4>
```
(`-t 1` was a spike-only clip-length cap for speed; the multi-sample path used
`-g 48 -svtav1-params keyint=48:pred-struct=1`.)

### Observed output

**File 1 — `ttget…` 720×1280, H.264+AAC:**
```
PATH A all-intra mp4: 282884 bytes
  symphonia video: 720x1280, 24 samples
  symphonia AAC->PCM: ch=2 rate=44100 frames=46080 (from 45 packets) => 92160 i16 samples
  PATH A fragments: 24 frags, total 344064 bytes, all chunk-aligned=true,
                    sizes(first6)=[32768,28672,20480,20480,20480,12288]
  VideoSession decoded 24/24 fragments to I420 @ 720x1280
PATH B GOP mp4: symphonia video 720x1280, 24 samples (one fragment)
  PATH B multi-sample fragment: 1 frag, 270336 bytes, chunk-aligned=true
  VideoSession decoded 24 frames from the single multi-sample GOP fragment
PATH C Fork-X audio: reusing ffmpeg's mp4a sample entry (110 bytes) verbatim
  PATH C AV fragment: 1 frag, 139264 bytes, chunk-aligned=true
  VideoSession (video track of AV fragment) decoded 8 frame(s)
  symphonia read HAND-MUXED audio track + AAC->PCM: ch=2 rate=44100 frames=8192 (8 pkts) -> OK
```

**File 4 — `2365.webm` 480×272, VP9+Opus (input-agnostic decode):**
```
PATH A all-intra mp4: 156994 bytes
  symphonia video: 480x272, 60 samples
  symphonia AAC->PCM: ch=2 rate=48000 frames=49152 (from 48 packets) => 98304 i16 samples
  PATH A fragments: 60 frags, total 245760 bytes, all chunk-aligned=true,
                    sizes(first6)=[4096,4096,4096,4096,4096,4096]
  VideoSession decoded 60/60 fragments to I420 @ 480x272
PATH B multi-sample fragment: 1 frag, 20480 bytes, chunk-aligned=true
  VideoSession decoded 60 frames from the single multi-sample GOP fragment
PATH C AV fragment: 1 frag, 24576 bytes, chunk-aligned=true
  VideoSession (video track) decoded 8 frame(s)
  symphonia read HAND-MUXED audio track + AAC->PCM: ch=2 rate=48000 frames=8192 (8 pkts) -> OK
```

**File 2 — `Half Life…` 2560×1600, high-res / high-bitrate (37.7 Mb/s source):**
```
PATH A all-intra mp4: 8711047 bytes
  symphonia video: 2560x1600, 60 samples
  symphonia AAC->PCM: ch=2 rate=48000 frames=48128 (from 47 packets) => 96256 i16 samples
  PATH A fragments: 60 frags, total 8851456 bytes, all chunk-aligned=true,
                    sizes(first6)=[135168,131072,131072,131072,131072,131072]
  VideoSession decoded 60/60 fragments to I420 @ 2560x1600   <-- HIGH-RES ROUND TRIP
PATH B GOP mp4: symphonia video 2560x1600, 60 samples (one fragment)
  PATH B multi-sample fragment: 1 frag, 6434816 bytes, chunk-aligned=true
                    (6.43 MB << max_fragment_bytes 16 MiB)
```
The 60 single-sample 2560×1600 fragments each decoded through the **unmodified**
`VideoSession` to validated I420 at exactly 2560×1600, and the largest fragment
produced anywhere in the spike — the 60-sample GOP fragment at **6,434,816 bytes** —
is comfortably under the 16 MiB `max_fragment_bytes` cap and whole-4096-chunk
aligned. (`-preset 10` keeps the encode fast; this resolution's main cost is
single-threaded rav1d decode of 60 × 4.1 MP frames, a test-only artifact — the
production view path decodes on demand, one fragment at a time.)

### Key conclusions from the evidence
* ffmpeg libsvtav1 AV1 samples decode through the **existing** `VideoSession` with
  the **no-`av1C`** `av01` entry → Fork X video needs no `av1C` authoring.
* Multi-sample GOP fragments decode every frame → multi-sample `stbl` tabling works.
* Hand-muxed `mp4a` (ffmpeg's `esds` verbatim) is symphonia-demuxable + AAC-decodable
  → Fork X audio is viable.
* All fragments are whole-4096-chunk aligned and contiguous → existing fragment
  index/seek/cache is reusable unchanged.
