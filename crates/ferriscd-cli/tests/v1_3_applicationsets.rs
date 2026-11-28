//! Compiles the workspace-level live `v1.3` `ApplicationSet` acceptance suite
//! (`tests/integration/v1_3_applicationsets.rs`, `T19.3`) as a test target of this package.
//!
//! The workspace root is a virtual manifest (no root package), so its `tests/` directory is not a
//! Cargo test target of its own. Including the file here — inside the `ferriscd-cli` package, which
//! owns the `ferriscd` binary the suite starts (`CARGO_BIN_EXE_ferriscd`) — gives the live test a
//! real target. It is `#[ignore]`d, so `make gate` never needs a cluster.

#[path = "../../../tests/integration/v1_3_applicationsets.rs"]
mod v1_3_applicationsets;
