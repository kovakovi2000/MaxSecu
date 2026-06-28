//! Windows AppContainer + Job Object **containment** tests (DESIGN §8.1/D30,
//! media-sandbox §6 exit gate). Each asserts the confined worker is DENIED an
//! action that the same worker, run unconfined, is allowed — so the test proves
//! the confinement bites, not merely that the action happened to fail.
#![cfg(windows)]

use image::{DynamicImage, ImageFormat, RgbImage};
use maxsecu_client_core::media::MediaBounds;
use maxsecu_client_core::sandbox::SandboxedDecoder;
use maxsecu_media_worker::{AppContainerDecoder, SubprocessDecoder};
use std::io::Cursor;
use std::net::TcpListener;
use std::thread;

const WORKER: &str = env!("CARGO_BIN_EXE_media-worker");

fn make_png(w: u32, h: u32) -> Vec<u8> {
    let mut img = RgbImage::new(w, h);
    for (x, y, px) in img.enumerate_pixels_mut() {
        *px = image::Rgb([(x % 256) as u8, (y % 256) as u8, 13]);
    }
    let mut buf = Vec::new();
    DynamicImage::ImageRgb8(img)
        .write_to(&mut Cursor::new(&mut buf), ImageFormat::Png)
        .unwrap();
    buf
}

#[test]
fn appcontainer_worker_still_decodes_correctly() {
    let png = make_png(40, 30);
    let bounds = MediaBounds::default();
    let got = AppContainerDecoder::new(WORKER).decode_image(&png, &bounds);
    let img = got.expect("confined worker should still decode (AppContainer functional)");
    assert_eq!((img.width, img.height), (40, 30));
    assert_eq!(img.channels, 4);
    assert_eq!(img.pixels.len(), 40 * 30 * 4);
}

#[test]
fn appcontainer_blocks_network_while_unconfined_allows() {
    // A loopback listener the worker will try to reach (offline, deterministic).
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || loop {
        if listener.accept().is_err() {
            break;
        }
    });
    let ports = port.to_string();
    let args = ["--selftest-net", ports.as_str()];

    // Sanity: the same worker unconfined DOES reach loopback.
    let unconfined = SubprocessDecoder::new(WORKER).selftest(&args).unwrap();
    assert!(unconfined, "unconfined worker should reach loopback (test sanity)");

    // The containment gate: the AppContainer worker cannot reach the network.
    let confined = AppContainerDecoder::new(WORKER)
        .selftest(&args)
        .expect("spawn confined worker");
    assert!(
        !confined,
        "AppContainer worker reached the network — confinement FAILED"
    );
}

#[test]
fn appcontainer_blocks_reading_the_key_blob_while_unconfined_allows() {
    // A stand-in for the user's `local_key_blob`: a file in the user profile that
    // does not grant access to app packages.
    let mut path = std::env::temp_dir();
    path.push(format!("maxsecu_secret_{}.bin", std::process::id()));
    std::fs::write(&path, b"PRETEND-KEY-MATERIAL").unwrap();
    let p = path.to_string_lossy().to_string();
    let args = ["--selftest-read", p.as_str()];

    let unconfined = SubprocessDecoder::new(WORKER).selftest(&args).unwrap();
    let confined = AppContainerDecoder::new(WORKER)
        .selftest(&args)
        .expect("spawn confined worker");
    let _ = std::fs::remove_file(&path);

    assert!(unconfined, "unconfined worker can read the user file (test sanity)");
    assert!(
        !confined,
        "AppContainer worker read the user's key blob — confinement FAILED"
    );
}

#[test]
fn appcontainer_blocks_child_spawn_while_unconfined_allows() {
    let args = ["--selftest-spawn"];

    let unconfined = SubprocessDecoder::new(WORKER).selftest(&args).unwrap();
    assert!(unconfined, "unconfined worker can spawn a child (test sanity)");

    let confined = AppContainerDecoder::new(WORKER)
        .selftest(&args)
        .expect("spawn confined worker");
    assert!(
        !confined,
        "Job Object (active-process=1) must block child spawn"
    );
}
