//! DIAGNOSTIC (not a real test): surface arti's bootstrap tracing so we can see
//! WHY Tor bootstrap stalls on this machine — blocked (network/ISP filtering the
//! directory) vs. merely slow. Reuses the production `TorState` (60s bootstrap
//! bound) and dials a known-good `check.torproject.org:443`.
//!
//! Run:
//! ```text
//! MAXSECU_TOR_DIAG=1 RUST_LOG=info,tor_dirmgr=debug,tor_guardmgr=debug \
//! cargo test --manifest-path crates/client-app/Cargo.toml -p maxsecu-client-e2e \
//!   --test tor_diag -- --ignored --nocapture
//! ```

use maxsecu_client_app::tor::TorState;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "diagnostic; run with MAXSECU_TOR_DIAG=1 and RUST_LOG set"]
async fn observe_tor_bootstrap_and_dial() {
    if std::env::var("MAXSECU_TOR_DIAG").as_deref() != Ok("1") {
        eprintln!("skipping: set MAXSECU_TOR_DIAG=1 to run the Tor bootstrap diagnostic");
        return;
    }
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(true)
        .try_init();

    let tmp = std::env::temp_dir().join(format!("mxtor-diag-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let tor = TorState::new(tmp.clone());
    eprintln!("=== dialing check.torproject.org:443 over Tor (bootstrap bound = 60s) ===");
    let started = std::time::Instant::now();
    let r = tor
        .dial("check.torproject.org", 443, || {
            eprintln!("=== bootstrap starting… ===");
        })
        .await;
    eprintln!(
        "=== result after {:?}: {:?} ===",
        started.elapsed(),
        r.as_ref().map(|_| "OK").map_err(|e| e.code.clone())
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
