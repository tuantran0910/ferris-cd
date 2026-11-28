//! Compiles the workspace-level live `T19.4` notifications acceptance suite
//! (`tests/integration/v0_5_notifications.rs`) as a test target of this package.
//!
//! The workspace root is a virtual manifest (no root package), so its `tests/` directory is not a
//! Cargo test target of its own. Including the file here — inside the `ferriscd-cli` package —
//! gives the live test `CARGO_BIN_EXE_ferriscd`, which is the point: the suite starts the **real
//! controller binary** with `--enable-notifications`, `--notifications-ca-file` and
//! `--notifications-allow-private-cidrs`, so the flags are exercised end to end and not simulated.
//!
//! The test is `#[ignore]`d and asserts a `kind-*` context before touching anything, so `make gate`
//! never needs a cluster:
//!
//! ```text
//! make kind-up
//! cargo test -p ferriscd-cli --test v0_5_notifications -- --ignored --nocapture
//! ```

#[path = "../../../tests/integration/v0_5_notifications.rs"]
mod v0_5_notifications;
