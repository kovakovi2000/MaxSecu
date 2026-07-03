//! Embed an `asInvoker` application manifest into every binary this crate builds
//! (the `maxsecu-setup` bin AND its integration-test executables). Without it,
//! Windows UAC "installer detection" auto-elevates any executable whose file name
//! contains "setup"/"install"/"update" — which would both make the operator tool
//! demand elevation and make `cargo test` fail with `os error 740` (elevation
//! required). An explicit `requestedExecutionLevel` disables that heuristic.
//!
//! MSVC-only (`/MANIFEST:EMBED` is a link.exe feature); a no-op elsewhere.

fn main() {
    let is_windows = std::env::var("CARGO_CFG_WINDOWS").is_ok();
    let is_msvc = std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    if is_windows && is_msvc {
        let dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
        let manifest = std::path::Path::new(&dir).join("setup.manifest");
        let manifest = manifest.display();
        // Apply to both the crate's bins and its test executables.
        for kind in ["bins", "tests"] {
            println!("cargo::rustc-link-arg-{kind}=/MANIFEST:EMBED");
            println!("cargo::rustc-link-arg-{kind}=/MANIFESTINPUT:{manifest}");
        }
        println!("cargo::rerun-if-changed=setup.manifest");
    }
    println!("cargo::rerun-if-changed=build.rs");
}
