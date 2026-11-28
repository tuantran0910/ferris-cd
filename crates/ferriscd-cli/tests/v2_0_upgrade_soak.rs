//! Compiles the workspace-level live `v2.0` upgrade/DR acceptance suite
//! (`tests/integration/v2_0_upgrade_soak.rs`, `T20.4`) as a test target of this package.
//!
//! The workspace root is a virtual manifest (no root package), so its `tests/` directory is not a
//! Cargo test target of its own. Including the file here — inside the `ferriscd-cli` package, which
//! owns the `ferriscd` binary the suite starts (`CARGO_BIN_EXE_ferriscd`) — gives the live test a
//! real target. Both tests are `#[ignore]`d, so `make gate` never needs a cluster.

#[path = "../../../tests/integration/v2_0_upgrade_soak.rs"]
mod v2_0_upgrade_soak;
