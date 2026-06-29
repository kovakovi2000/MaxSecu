# Codec spike notes — Phase 7 Gate 1, Task 1.1

TEMPORARY. Records the REAL crate versions + APIs the round-trip in `src/main.rs`
actually exercised. Folds into the Task 1.4 ratification doc, then this crate is
deleted. Everything below was read from the crate sources under
`~/.cargo/registry/src/...` and proven by a running round-trip (not from memory).

Host: Rust/Cargo 1.96.0 MSVC, Windows 11, **no nasm installed**.

## Confirmed crate versions (latest-compatible, via `cargo add --dry-run`)

| crate                         | version | features used                                  |
| ----------------------------- | ------- | ---------------------------------------------- |
| `rav1d` (AV1 decoder)         | 1.1.0   | `default-features = false`, `bitdepth_8`, `bitdepth_16` |
| `symphonia` (demux + AAC)     | 0.6.0   | `default-features = false`, `isomp4`, `aac`    |
| `rav1e` (AV1 encoder)         | 0.8.1   | `default-features = false`                     |

### Zero-C / no-nasm posture (IMPORTANT for the view path)

- `rav1d`'s and `rav1e`'s `asm` features (which require **nasm** and compile
  x86/arm assembly via `nasm-rs`/`cc`) are **disabled**. With them off, both
  crates build and run on this host with **no external assembler** — pure-Rust
  fallback paths. `rav1d` REQUIRES at least one of `bitdepth_8` / `bitdepth_16`
  (its `lib.rs` has a `compile_error!` otherwise); `asm` is NOT in that set.
- `cargo tree -i ring|openssl|openssl-sys` over `spike-codecs` → **all empty**.
- CONCERN (note for Task 1.2/1.4, not a blocker): `cc` and `nasm-rs` still appear
  as **declared build-deps of `rav1d`** in `cargo tree` even with `asm` off. The
  build succeeded with no nasm present, which confirms `rav1d`'s `build.rs` gates
  every C/asm invocation behind the `asm` feature — they are present-but-unused.
  Production should keep `asm` off for the view path and re-confirm no C/asm is
  compiled (clean build with no nasm is the check).
- CONCERN (Windows): rav1d's single-threaded decode uses large/deep stack frames
  that overflow the default 1 MiB main-thread stack (`STATUS_STACK_OVERFLOW`).
  The spike runs the decode on a `std::thread::Builder::stack_size(64 MiB)`
  worker. **Production must run the rav1d decoder on a thread with an enlarged
  stack** (or rely on its worker threads with `n_threads > 1`).

## Real APIs used

### rav1e 0.8.1 — encode (synthesizes the AV1 to decode; ingest-side, not TCB)

Import: `use rav1e::prelude::{ChromaSampling, Config, Context, EncoderConfig, EncoderStatus};`

Config / encoder config:
- `EncoderConfig::with_speed_preset(speed: u8) -> EncoderConfig` (10 = fastest).
- `EncoderConfig` is a struct with public fields; set directly:
  `width: usize`, `height: usize`, `bit_depth: usize`, `chroma_sampling: ChromaSampling`
  (`ChromaSampling::Cs420`), `still_picture: bool`.
- `Config::new() -> Config`
- `Config::with_encoder_config(self, EncoderConfig) -> Config`
- `Config::new_context::<T: Pixel>(&self) -> Result<Context<T>, InvalidConfig>`
  (use `Context<u8>` for 8-bit).

Frame fill (planes are `v_frame`):
- `Context::new_frame(&self) -> Frame<T>`
- `frame.planes: [Plane<T>; 3]` (Y, U, V).
- `Plane::copy_from_raw_u8(&mut self, source: &[u8], source_stride: usize, source_bytewidth: usize)`
  (8-bit → `source_bytewidth = 1`; chroma planes are `W/2 × H/2` for 4:2:0).

Encode loop:
- `Context::send_frame<F: IntoFrame<T>>(&mut self, frame: F) -> Result<(), EncoderStatus>`
  (a `Frame<T>` is accepted directly).
- `Context::flush(&mut self)`
- `Context::receive_packet(&mut self) -> Result<Packet<T>, EncoderStatus>`
  - `Ok(Packet { data: Vec<u8>, .. })` — `packet.data` is a temporal unit of OBUs.
  - `Err(EncoderStatus::Encoded)` → frame consumed, keep polling.
  - `Err(EncoderStatus::LimitReached | NeedMoreData)` → done.
- For a single `still_picture`, packet 0's `data` is **self-contained** (includes
  the sequence header OBU) — dav1d/rav1d decodes it with no separate `av1C`.
- (Available but unused: `Context::container_sequence_header(&self) -> Vec<u8>`
  for building an `av1C` config record if a later task wants one.)

### rav1d 1.1.0 — decode (THE view-path TCB; dav1d C-ABI exposed as Rust fns)

`rav1d` is an rlib exposing the dav1d C API as `pub unsafe extern "C"` Rust
functions, callable directly. Paths:

Types:
- `rav1d::include::dav1d::dav1d::{Dav1dContext, Dav1dSettings}`
  - `Dav1dContext = RawArc<Rav1dContext>` (`Copy`). API takes `Option<Dav1dContext>`.
  - `Dav1dSettings` public fields incl. `n_threads: c_int`, `max_frame_delay: c_int`.
- `rav1d::include::dav1d::data::Dav1dData` — `{ data: Option<NonNull<u8>>, sz: usize, m: .. }`.
- `rav1d::include::dav1d::picture::Dav1dPicture`
  - `pic.p: Dav1dPictureParameters { w: c_int, h: c_int, layout, bpc: c_int }` (geometry = `p.w`/`p.h`).
  - `pic.data: [Option<NonNull<c_void>>; 3]`, `pic.stride: [ptrdiff_t; 2]` (plane access for later tasks).

Functions: `use rav1d::src::lib::{ dav1d_default_settings, dav1d_open, dav1d_data_create, dav1d_send_data, dav1d_get_picture, dav1d_picture_unref, dav1d_close };`

- `unsafe dav1d_default_settings(s: NonNull<Dav1dSettings>)` — writes defaults; then
  set `n_threads = 1`, `max_frame_delay = 1` for a single still.
- `unsafe dav1d_open(c_out: Option<NonNull<Option<Dav1dContext>>>, s: Option<NonNull<Dav1dSettings>>) -> Dav1dResult`
  — pass `&mut Option<Dav1dContext>`; on success the `Option` is `Some(handle)`.
- `unsafe dav1d_data_create(buf: Option<NonNull<Dav1dData>>, sz: usize) -> *mut u8`
  — fully initializes `*buf` and returns a dav1d-owned buffer ptr; `copy_nonoverlapping`
  the AV1 bytes into it.
- `unsafe dav1d_send_data(c: Option<Dav1dContext>, in: Option<NonNull<Dav1dData>>) -> Dav1dResult`
  — consumes from `in` (decrements `in.sz`); may return EAGAIN until pictures are drained.
- `unsafe dav1d_get_picture(c: Option<Dav1dContext>, out: Option<NonNull<Dav1dPicture>>) -> Dav1dResult`
  — only *writes* `out` (pass `MaybeUninit`); returns `Dav1dResult(0)` on a picture.
- `unsafe dav1d_picture_unref(p: Option<NonNull<Dav1dPicture>>)` — release planes after reading.
- `unsafe dav1d_close(c_out: Option<NonNull<Option<Dav1dContext>>>)` — closes and nulls the handle.

Result type:
- `rav1d::src::lib::Dav1dResult` re-exported as `rav1d::Dav1dResult`; `struct Dav1dResult(pub c_int)`.
  **`0` == success**; negative == `-errno` (e.g. `-EAGAIN`). Spike checks `res.0 == 0`
  for open/picture and bounded-polls send+get for a single frame.

Send/drain pattern that worked (single still picture, single-threaded):
```
loop (bounded):
    if data.sz > 0 { dav1d_send_data(handle, &mut data); }   // ignore EAGAIN
    if dav1d_get_picture(handle, &mut pic) == 0 { read pic.p.w/p.h; unref; break }
```

### symphonia 0.6.0 — demux (`isomp4`) + AAC decoder (`aac`) registration

Imports:
- `use symphonia::core::io::{MediaSourceStream, MediaSourceStreamOptions};`
- `use symphonia::core::formats::{FormatOptions, FormatReader, TrackType};`
- `use symphonia::core::codecs::CodecParameters;`
- `use symphonia::default::formats::IsoMp4Reader;`  (gated by `isomp4` feature)
- (AAC: `symphonia::default::codecs::AacDecoder` is exposed under the `aac`
  feature; the isomp4 reader registers/decodes `av01` video tracks regardless.)

Open + read:
- `MediaSourceStream::new(source: Box<dyn MediaSource + 's>, MediaSourceStreamOptions) -> MediaSourceStream`
  — `std::io::Cursor<Vec<u8>>` implements `MediaSource` (seekable); `Options::default()` ok.
- `IsoMp4Reader::try_new(mss, FormatOptions::default()) -> Result<IsoMp4Reader>`
  — requires `ftyp` + `moov` + `mdat`; supports both fragmented (`moof/traf/trun`)
    and non-fragmented (`stbl` sample tables). Spike muxes a **non-fragmented** MP4.
- `FormatReader::first_track(&self, TrackType::Video) -> Option<&Track>`
  - `Track { id: u32, codec_params: Option<CodecParameters>, .. }`.
  - For an `av01` sample entry → `Some(CodecParameters::Video(VideoCodecParameters { width: Option<u16>, height: Option<u16>, codec, extra_data, .. }))`.
    NOTE: symphonia 0.6.0's `av01` reader does **not** set a concrete `codec` id
    (stays the NULL video id) and does not parse `av1C` — but it DOES read
    `width`/`height` from the visual sample entry and yields the raw sample bytes.
- `FormatReader::next_packet(&mut self) -> Result<Option<Packet>>`
  - `Packet { track_id: u32, data: Box<[u8]>, pts, dts, dur, .. }` — `pkt.data` is the
    raw AV1 sample (fed straight to `dav1d_send_data`). `Ok(None)` == end of stream.

## Round-trip result (proof)

`cargo run -p spike-codecs` prints and exits 0:
```
rav1e: encoded 64x64 still picture -> 73 bytes of AV1
rav1d (Stage A, direct): decoded 64x64
muxed minimal MP4 (av01 track): 700 bytes
symphonia (isomp4): video track 64x64, demuxed sample 73 bytes
rav1d (Stage B, via symphonia): decoded 64x64
ROUND-TRIP OK: 64x64
```

## Minimal MP4/CMAF muxer (spike-only, in `main.rs`)

To exercise symphonia's demux without an external file, the spike hand-builds a
non-fragmented ISO-BMFF: `ftyp` + `moov(mvhd, trak(tkhd, mdia(mdhd, hdlr,
minf(vmhd, dinf/dref/url, stbl(stsd→av01, stts, stsc, stsz, stco, stss))))) +
mdat`. `stco` chunk offset = byte offset of the `mdat` payload (moov built once
with a placeholder offset to learn its fixed length, then rebuilt with the real
offset). No `av1C` box is emitted (symphonia tolerates its absence; geometry comes
from the `av01` visual sample entry's width/height fields). This is throwaway:
production ingest will mux real CMAF on the C-confined side, not in the view path.

## Gate results

- `cargo build -p spike-codecs` — OK
- `cargo run -p spike-codecs` — `ROUND-TRIP OK: 64x64`, exit 0
- `cargo clippy -p spike-codecs --all-targets -- -D warnings` — clean
- `cargo tree -p spike-codecs -i {ring,openssl,openssl-sys}` — all empty
- `cargo metadata` — workspace resolves with `crates/_spike-codecs` added to `members`
