//! Library surface for the MaxSecu portable server launcher. The launcher binary
//! (`main.rs`) is a thin shell over these modules; exposing them as a lib also lets
//! the Phase-6 integration smoke test drive the reusable [`run::prepare`] seam.
//!
//! See `main.rs` for the runtime entry point. All DEV artifacts produced here
//! (self-signed cert, bootstrap secret, D5 key) are SECURITY-DEGRADED — never a
//! production ceremony key.
#![forbid(unsafe_code)]

pub mod bootstrap;
pub mod bootstrap_pins;
pub mod config;
pub mod delegation_setup;
pub mod layout;
pub mod pki;
pub mod run;
