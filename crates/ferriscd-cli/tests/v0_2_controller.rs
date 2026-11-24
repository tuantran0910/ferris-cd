//! Compiles the workspace-level live `v0.2` integration test (`tests/integration/`).
//!
//! The workspace root is a virtual manifest (no root package), so its `tests/` directory is
//! not a Cargo test target of its own. Including the file here — inside the `ferriscd-cli`
//! package, which owns the `ferriscd` binary — gives the live test a real test target and
//! makes `CARGO_BIN_EXE_ferriscd` available.

#[path = "../../../tests/integration/v0_2_controller.rs"]
mod v0_2_controller;
