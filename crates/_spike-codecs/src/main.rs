//! TEMPORARY codec spike (MaxSecu Media App Phase 7, Gate 1, Task 1.1).
//!
//! Proves the pure-Rust *view-path* decode crates exist and can decode our
//! canonical format (AV1 video in a CMAF/ISO-BMFF container).
//!
//! - `rav1e`: pure-Rust AV1 *encoder*. Used here only to synthesize a real AV1
//!   bitstream to decode; NOT in the production view path (it lives on the
//!   ingest/transcode side).
//! - `rav1d`: memory-safe Rust port of dav1d, the AV1 *decoder*. THE #1 RCE
//!   surface; this is the crate the production view path runs.
//! - `symphonia`: pure-Rust demuxer (`isomp4`) + AAC decoder (`aac`). Here it
//!   demuxes the AV1 sample back out of an MP4 we mux by hand.
//!
//! The whole graph is zero-C: the `asm` features of `rav1d`/`rav1e` (which need
//! nasm) are disabled in Cargo.toml, so this builds and runs with no external
//! assembler. This crate is DELETED at the end of Gate 1 (Task 1.4); its only
//! deliverables are (a) confirmed crate versions, (b) confirmed real APIs
//! (recorded in SPIKE_NOTES.md), and (c) this asserting round-trip.
//!
//! Round-trip:
//!   raw 64x64 YUV420 frame
//!     -> rav1e encode   -> AV1 bitstream
//!     -> rav1d decode   (Stage A, in-process)              -> assert 64x64
//!     -> hand-muxed MP4 -> symphonia demux -> rav1d decode (Stage B) -> assert 64x64

use std::io::Cursor;
use std::mem::MaybeUninit;
use std::ptr::NonNull;

use rav1e::prelude::{ChromaSampling, Config, Context, EncoderConfig, EncoderStatus};

// rav1d exposes the dav1d C-ABI surface as `pub unsafe extern "C"` Rust fns
// (callable directly from Rust because the crate is an rlib). Types live under
// `rav1d::include::dav1d::*`; the entry points under `rav1d::src::lib::*`.
use rav1d::include::dav1d::data::Dav1dData;
use rav1d::include::dav1d::dav1d::{Dav1dContext, Dav1dSettings};
use rav1d::include::dav1d::picture::Dav1dPicture;
use rav1d::src::lib::{
    dav1d_close, dav1d_data_create, dav1d_default_settings, dav1d_get_picture, dav1d_open,
    dav1d_picture_unref, dav1d_send_data,
};

use symphonia::core::codecs::CodecParameters;
use symphonia::core::formats::{FormatOptions, FormatReader, TrackType};
use symphonia::core::io::{MediaSourceStream, MediaSourceStreamOptions};
use symphonia::default::formats::IsoMp4Reader;

const W: usize = 64;
const H: usize = 64;

fn main() {
    // rav1d's single-threaded decode path uses large/deep stack frames that
    // overflow Windows' default 1 MiB main-thread stack. Run the whole spike on
    // a worker thread with a generous stack. (Production will run the decoder in
    // its own sized worker thread; noted for Task 1.4.)
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(run)
        .expect("spawn worker thread")
        .join()
        .expect("worker thread panicked");
}

fn run() {
    // ---- 1. Synthesize a tiny raw YUV420 frame ---------------------------
    // Y is a diagonal gradient; chroma is neutral (128). Content is irrelevant;
    // only the decoded geometry is asserted.
    let mut y = vec![0u8; W * H];
    for (i, px) in y.iter_mut().enumerate() {
        let (x, row) = (i % W, i / W);
        *px = ((x + row) & 0xff) as u8;
    }
    let chroma = vec![128u8; (W / 2) * (H / 2)];

    // ---- 2. rav1e: encode the frame to an AV1 bitstream ------------------
    let bitstream = encode_av1(&y, &chroma);
    println!(
        "rav1e: encoded {}x{} still picture -> {} bytes of AV1",
        W,
        H,
        bitstream.len()
    );

    // ---- 3. Stage A: rav1d decodes the raw bitstream in-process ----------
    let (aw, ah) = decode_av1_dims(&bitstream).expect("rav1d failed to decode the rav1e bitstream");
    println!("rav1d (Stage A, direct): decoded {aw}x{ah}");
    assert_eq!(
        (aw as usize, ah as usize),
        (W, H),
        "Stage A decoded dimensions must match source"
    );

    // ---- 4. Wrap the AV1 sample in a minimal CMAF/ISO-BMFF MP4 -----------
    let mp4 = mux_minimal_mp4(&bitstream);
    println!("muxed minimal MP4 (av01 track): {} bytes", mp4.len());

    // ---- 5. Stage B: symphonia demuxes the MP4; rav1d decodes the sample -
    let (demuxed, tw, th) = demux_av1(mp4);
    println!(
        "symphonia (isomp4): video track {}x{}, demuxed sample {} bytes",
        tw,
        th,
        demuxed.len()
    );
    assert_eq!(
        (tw, th),
        (W, H),
        "symphonia track geometry must match source"
    );

    let (bw, bh) = decode_av1_dims(&demuxed).expect("rav1d failed to decode the demuxed sample");
    println!("rav1d (Stage B, via symphonia): decoded {bw}x{bh}");
    assert_eq!(
        (bw as usize, bh as usize),
        (W, H),
        "Stage B decoded dimensions must match source"
    );

    // ---- Final round-trip result -----------------------------------------
    println!("ROUND-TRIP OK: {}x{}", bw, bh);
}

/// Encode one still YUV420 frame to a raw low-overhead AV1 bitstream via rav1e.
fn encode_av1(y: &[u8], chroma: &[u8]) -> Vec<u8> {
    let mut enc = EncoderConfig::with_speed_preset(10);
    enc.width = W;
    enc.height = H;
    enc.bit_depth = 8;
    enc.chroma_sampling = ChromaSampling::Cs420;
    enc.still_picture = true;

    let cfg = Config::new().with_encoder_config(enc);
    let mut ctx: Context<u8> = cfg.new_context().expect("rav1e: invalid encoder config");

    let mut frame = ctx.new_frame();
    frame.planes[0].copy_from_raw_u8(y, W, 1);
    frame.planes[1].copy_from_raw_u8(chroma, W / 2, 1);
    frame.planes[2].copy_from_raw_u8(chroma, W / 2, 1);

    ctx.send_frame(frame).expect("rav1e: send_frame");
    ctx.flush();

    let mut out = Vec::new();
    loop {
        match ctx.receive_packet() {
            Ok(pkt) => out.extend_from_slice(&pkt.data),
            Err(EncoderStatus::Encoded) => continue,
            Err(EncoderStatus::LimitReached) | Err(EncoderStatus::NeedMoreData) => break,
            Err(e) => panic!("rav1e: receive_packet: {e:?}"),
        }
    }
    assert!(!out.is_empty(), "rav1e produced no AV1 bytes");
    out
}

/// Open a fresh dav1d/rav1d context, decode a single AV1 sample, and return the
/// decoded picture geometry. Returns `None` if no picture was produced.
fn decode_av1_dims(bitstream: &[u8]) -> Option<(i32, i32)> {
    unsafe {
        // Default settings, then force single-threaded, minimal delay so a lone
        // still picture comes back immediately.
        let mut settings = MaybeUninit::<Dav1dSettings>::uninit();
        dav1d_default_settings(NonNull::new(settings.as_mut_ptr()).unwrap());
        let mut settings = settings.assume_init();
        settings.n_threads = 1;
        settings.max_frame_delay = 1;

        let mut ctx: Option<Dav1dContext> = None;
        let res = dav1d_open(
            Some(NonNull::from(&mut ctx)),
            Some(NonNull::from(&mut settings)),
        );
        assert_eq!(res.0, 0, "dav1d_open failed: {}", res.0);
        let handle = ctx.expect("dav1d_open returned a null context");

        // Allocate a dav1d-owned buffer and copy the bitstream into it.
        let mut data = MaybeUninit::<Dav1dData>::uninit();
        let buf = dav1d_data_create(
            Some(NonNull::new(data.as_mut_ptr()).unwrap()),
            bitstream.len(),
        );
        assert!(!buf.is_null(), "dav1d_data_create returned null");
        std::ptr::copy_nonoverlapping(bitstream.as_ptr(), buf, bitstream.len());
        let mut data = data.assume_init();

        // Send then drain. dav1d may answer EAGAIN (a non-zero result) while it
        // still wants data fed or pictures drained; keep feeding any remaining
        // bytes and polling get_picture until a picture pops out. Bounded so a
        // genuinely undecodable stream terminates instead of spinning forever.
        let mut result = None;
        for _ in 0..64 {
            if data.sz > 0 {
                let _ = dav1d_send_data(Some(handle), Some(NonNull::from(&mut data)));
            }
            let mut pic = MaybeUninit::<Dav1dPicture>::uninit();
            let r = dav1d_get_picture(Some(handle), Some(NonNull::new(pic.as_mut_ptr()).unwrap()));
            if r.0 == 0 {
                let mut pic = pic.assume_init();
                let dims = (pic.p.w, pic.p.h);
                dav1d_picture_unref(Some(NonNull::from(&mut pic)));
                result = Some(dims);
                break;
            }
        }

        dav1d_close(Some(NonNull::from(&mut ctx)));
        result
    }
}

/// Demux the single AV1 sample (and its geometry) back out of the MP4 with
/// symphonia's isomp4 reader.
fn demux_av1(mp4: Vec<u8>) -> (Vec<u8>, usize, usize) {
    let mss = MediaSourceStream::new(
        Box::new(Cursor::new(mp4)),
        MediaSourceStreamOptions::default(),
    );
    let mut reader = IsoMp4Reader::try_new(mss, FormatOptions::default())
        .expect("symphonia: failed to open the muxed MP4");

    let track = reader
        .first_track(TrackType::Video)
        .expect("symphonia: no video track found");
    let track_id = track.id;

    let (w, h) = match track.codec_params.as_ref() {
        Some(CodecParameters::Video(v)) => (
            v.width.expect("symphonia: video track has no width") as usize,
            v.height.expect("symphonia: video track has no height") as usize,
        ),
        other => panic!("symphonia: expected video codec params, got {other:?}"),
    };

    // Pull the first packet belonging to the video track.
    loop {
        match reader.next_packet().expect("symphonia: next_packet") {
            Some(pkt) if pkt.track_id == track_id => {
                return (pkt.data.into_vec(), w, h);
            }
            Some(_) => continue,
            None => panic!("symphonia: no packets for the video track"),
        }
    }
}

// ---------------------------------------------------------------------------
// Minimal ISO-BMFF / CMAF muxer (spike-only; just enough for symphonia's
// isomp4 reader to expose one av01 video track carrying one sample).
// ---------------------------------------------------------------------------

/// `[u32 size][u8;4 type][payload]`.
fn b(typ: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + payload.len());
    v.extend_from_slice(&((payload.len() as u32) + 8).to_be_bytes());
    v.extend_from_slice(typ);
    v.extend_from_slice(payload);
    v
}

/// Full box: `[size][type][version+flags][payload]`.
fn fb(typ: &[u8; 4], version: u8, flags: u32, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(4 + payload.len());
    p.push(version);
    p.extend_from_slice(&flags.to_be_bytes()[1..]); // 3-byte flags
    p.extend_from_slice(payload);
    b(typ, &p)
}

const UNITY_MATRIX: [u8; 36] = [
    0x00, 0x01, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, // a, b, u
    0, 0, 0, 0, 0x00, 0x01, 0x00, 0x00, 0, 0, 0, 0, // c, d, v
    0, 0, 0, 0, 0, 0, 0, 0, 0x40, 0x00, 0x00, 0x00, // x, y, w
];

fn mux_minimal_mp4(sample: &[u8]) -> Vec<u8> {
    let ftyp = b(b"ftyp", b"av01\0\0\0\0av01isommp41");

    // Build moov twice: first with a placeholder chunk offset to learn its
    // length, then with the real offset (the value's width is fixed, so the
    // length is identical between the two builds).
    let moov_probe = build_moov(sample, 0);
    let mdat_payload_offset = (ftyp.len() + moov_probe.len() + 8) as u32;
    let moov = build_moov(sample, mdat_payload_offset);
    let mdat = b(b"mdat", sample);

    concat(&[&ftyp, &moov, &mdat])
}

fn build_moov(sample: &[u8], chunk_offset: u32) -> Vec<u8> {
    // mvhd
    let mut mvhd = Vec::new();
    mvhd.extend_from_slice(&0u32.to_be_bytes()); // creation
    mvhd.extend_from_slice(&0u32.to_be_bytes()); // modification
    mvhd.extend_from_slice(&1000u32.to_be_bytes()); // timescale
    mvhd.extend_from_slice(&1u32.to_be_bytes()); // duration
    mvhd.extend_from_slice(&0x0001_0000u32.to_be_bytes()); // rate 1.0
    mvhd.extend_from_slice(&0x0100u16.to_be_bytes()); // volume 1.0
    mvhd.extend_from_slice(&0u16.to_be_bytes()); // reserved
    mvhd.extend_from_slice(&[0u8; 8]); // reserved
    mvhd.extend_from_slice(&UNITY_MATRIX);
    mvhd.extend_from_slice(&[0u8; 24]); // predefined
    mvhd.extend_from_slice(&2u32.to_be_bytes()); // next_track_id
    let mvhd = fb(b"mvhd", 0, 0, &mvhd);

    // tkhd
    let mut tkhd = Vec::new();
    tkhd.extend_from_slice(&0u32.to_be_bytes()); // creation
    tkhd.extend_from_slice(&0u32.to_be_bytes()); // modification
    tkhd.extend_from_slice(&1u32.to_be_bytes()); // track_id
    tkhd.extend_from_slice(&0u32.to_be_bytes()); // reserved
    tkhd.extend_from_slice(&1u32.to_be_bytes()); // duration
    tkhd.extend_from_slice(&[0u8; 8]); // reserved
    tkhd.extend_from_slice(&0u16.to_be_bytes()); // layer
    tkhd.extend_from_slice(&0u16.to_be_bytes()); // alternate_group
    tkhd.extend_from_slice(&0u16.to_be_bytes()); // volume (0 for video)
    tkhd.extend_from_slice(&0u16.to_be_bytes()); // reserved
    tkhd.extend_from_slice(&UNITY_MATRIX);
    tkhd.extend_from_slice(&((W as u32) << 16).to_be_bytes()); // width 16.16
    tkhd.extend_from_slice(&((H as u32) << 16).to_be_bytes()); // height 16.16
    let tkhd = fb(b"tkhd", 0, 0x000007, &tkhd); // enabled|in-movie|in-preview

    // mdhd
    let mut mdhd = Vec::new();
    mdhd.extend_from_slice(&0u32.to_be_bytes()); // creation
    mdhd.extend_from_slice(&0u32.to_be_bytes()); // modification
    mdhd.extend_from_slice(&1000u32.to_be_bytes()); // timescale
    mdhd.extend_from_slice(&1u32.to_be_bytes()); // duration
    mdhd.extend_from_slice(&0x55c4u16.to_be_bytes()); // language 'und'
    mdhd.extend_from_slice(&0u16.to_be_bytes()); // predefined
    let mdhd = fb(b"mdhd", 0, 0, &mdhd);

    // hdlr
    let mut hdlr = Vec::new();
    hdlr.extend_from_slice(&0u32.to_be_bytes()); // predefined
    hdlr.extend_from_slice(b"vide"); // handler_type
    hdlr.extend_from_slice(&[0u8; 12]); // reserved
    hdlr.extend_from_slice(b"VideoHandler\0"); // name
    let hdlr = fb(b"hdlr", 0, 0, &hdlr);

    // vmhd
    let mut vmhd = Vec::new();
    vmhd.extend_from_slice(&0u16.to_be_bytes()); // graphicsmode
    vmhd.extend_from_slice(&[0u8; 6]); // opcolor
    let vmhd = fb(b"vmhd", 0, 1, &vmhd);

    // dinf > dref > url
    let url = fb(b"url ", 0, 1, &[]); // self-contained
    let mut dref = Vec::new();
    dref.extend_from_slice(&1u32.to_be_bytes()); // entry_count
    dref.extend_from_slice(&url);
    let dref = fb(b"dref", 0, 0, &dref);
    let dinf = b(b"dinf", &dref);

    // stsd > av01 (VisualSampleEntry, no av1C — symphonia tolerates its absence)
    let mut av01 = Vec::new();
    av01.extend_from_slice(&[0u8; 6]); // SampleEntry reserved
    av01.extend_from_slice(&1u16.to_be_bytes()); // data_reference_index
    av01.extend_from_slice(&0u16.to_be_bytes()); // predefined
    av01.extend_from_slice(&0u16.to_be_bytes()); // reserved
    av01.extend_from_slice(&[0u8; 12]); // predefined
    av01.extend_from_slice(&(W as u16).to_be_bytes()); // width
    av01.extend_from_slice(&(H as u16).to_be_bytes()); // height
    av01.extend_from_slice(&0x0048_0000u32.to_be_bytes()); // horiz_res 72dpi
    av01.extend_from_slice(&0x0048_0000u32.to_be_bytes()); // vert_res 72dpi
    av01.extend_from_slice(&0u32.to_be_bytes()); // reserved
    av01.extend_from_slice(&1u16.to_be_bytes()); // frame_count
    av01.extend_from_slice(&[0u8; 32]); // compressorname
    av01.extend_from_slice(&0x0018u16.to_be_bytes()); // depth
    av01.extend_from_slice(&0xffffu16.to_be_bytes()); // predefined
    let av01 = b(b"av01", &av01);

    let mut stsd = Vec::new();
    stsd.extend_from_slice(&1u32.to_be_bytes()); // entry_count
    stsd.extend_from_slice(&av01);
    let stsd = fb(b"stsd", 0, 0, &stsd);

    // stts (1 sample, delta 1)
    let mut stts = Vec::new();
    stts.extend_from_slice(&1u32.to_be_bytes()); // entry_count
    stts.extend_from_slice(&1u32.to_be_bytes()); // sample_count
    stts.extend_from_slice(&1u32.to_be_bytes()); // sample_delta
    let stts = fb(b"stts", 0, 0, &stts);

    // stsc (1 chunk, 1 sample/chunk, desc 1)
    let mut stsc = Vec::new();
    stsc.extend_from_slice(&1u32.to_be_bytes()); // entry_count
    stsc.extend_from_slice(&1u32.to_be_bytes()); // first_chunk
    stsc.extend_from_slice(&1u32.to_be_bytes()); // samples_per_chunk
    stsc.extend_from_slice(&1u32.to_be_bytes()); // sample_description_index
    let stsc = fb(b"stsc", 0, 0, &stsc);

    // stsz (per-sample sizes)
    let mut stsz = Vec::new();
    stsz.extend_from_slice(&0u32.to_be_bytes()); // sample_size 0 => table follows
    stsz.extend_from_slice(&1u32.to_be_bytes()); // sample_count
    stsz.extend_from_slice(&(sample.len() as u32).to_be_bytes()); // entry size
    let stsz = fb(b"stsz", 0, 0, &stsz);

    // stco (chunk offset into mdat payload)
    let mut stco = Vec::new();
    stco.extend_from_slice(&1u32.to_be_bytes()); // entry_count
    stco.extend_from_slice(&chunk_offset.to_be_bytes()); // chunk_offset
    let stco = fb(b"stco", 0, 0, &stco);

    // stss (sample 1 is a sync sample)
    let mut stss = Vec::new();
    stss.extend_from_slice(&1u32.to_be_bytes()); // entry_count
    stss.extend_from_slice(&1u32.to_be_bytes()); // sample_number
    let stss = fb(b"stss", 0, 0, &stss);

    let stbl = b(
        b"stbl",
        &concat(&[&stsd, &stts, &stsc, &stsz, &stco, &stss]),
    );
    let minf = b(b"minf", &concat(&[&vmhd, &dinf, &stbl]));
    let mdia = b(b"mdia", &concat(&[&mdhd, &hdlr, &minf]));
    let trak = b(b"trak", &concat(&[&tkhd, &mdia]));
    b(b"moov", &concat(&[&mvhd, &trak]))
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    for p in parts {
        v.extend_from_slice(p);
    }
    v
}
