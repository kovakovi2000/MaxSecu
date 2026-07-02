//! Test-only crate: the client↔server end-to-end suites live in `tests/`. This
//! crate exists so those tests can link `maxsecu-server` WITHOUT its `postgres`
//! feature (no `sqlx`), which is what lets the real server coexist with
//! `arti-client` in the client workspace's single lockfile. No library code.
