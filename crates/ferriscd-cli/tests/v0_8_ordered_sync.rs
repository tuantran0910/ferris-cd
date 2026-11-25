//! Compiles the workspace-level live `v0.8` ordered-sync integration test
//! (`tests/integration/v0_8_ordered_sync.rs`).
//!
//! The workspace root is a virtual manifest (no root package), so its `tests/` directory is not a
//! Cargo test target of its own. Including the file here — inside the `ferriscd-cli` package,
//! which owns the `ferriscd` binary — gives the live test a real test target and makes
//! `CARGO_BIN_EXE_ferriscd` available.

#[path = "../../../tests/integration/v0_8_ordered_sync.rs"]
mod v0_8_ordered_sync;
