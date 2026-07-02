//! Part C — LIVE Tor transport smoke test (opt-in, real network).
//!
//! `#[ignore]` by default and additionally gated on `MAXSECU_TOR_LIVE=1`, exactly
//! like the Dropbox live round-trip: it talks to the REAL Tor network, so it must
//! never run in CI or a normal `cargo test`. Run it deliberately with:
//!
//! ```text
//! MAXSECU_TOR_LIVE=1 cargo test -p maxsecu-client-e2e --test tor_route_e2e -- --ignored --nocapture
//! ```
//!
//! It bootstraps the real `TorState` (arti), dials a well-known host:443 over a Tor
//! circuit, and asserts a stream opened — proving the in-process Tor transport
//! genuinely reaches the network end to end. It does NOT stand up a MaxSecu server
//! (the direct-vs-Tor server flow is covered by connect_login_e2e over TCP; this
//! isolates the one thing unit/integration tests cannot fake: a real Tor circuit).

use maxsecu_client_app::tor::TorState;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live Tor network; run explicitly with MAXSECU_TOR_LIVE=1 -- --ignored"]
async fn tor_bootstraps_and_dials_a_real_host() {
    if std::env::var("MAXSECU_TOR_LIVE").as_deref() != Ok("1") {
        eprintln!("skipping: set MAXSECU_TOR_LIVE=1 to run the live Tor test");
        return;
    }

    // Arti state under a throwaway dir so the test leaves nothing behind.
    let tmp = std::env::temp_dir().join(format!("mxtor-live-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let tor = TorState::new(tmp.clone());
    // Dials over a freshly-bootstrapped circuit. `check.torproject.org:443` is a
    // stable, Tor-friendly endpoint; any reachable HTTPS host proves the circuit.
    let mut bootstrapped = false;
    let stream = tor
        .dial("check.torproject.org", 443, || {
            bootstrapped = true;
            eprintln!("bootstrapping Tor (first connect)…");
        })
        .await;

    assert!(
        stream.is_ok(),
        "expected a Tor circuit stream to open, got {:?}",
        stream.err().map(|e| e.code)
    );
    assert!(bootstrapped, "the bootstrap callback should have fired once");

    drop(stream);
    let _ = std::fs::remove_dir_all(&tmp);
}
