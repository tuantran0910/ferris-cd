//! Compiles the workspace-level live `v1.1` readiness & live RBAC hot-reload test
//! (`tests/integration/v1_1_readiness_rbac.rs`) as a test target of this package.
//!
//! The workspace root is a virtual manifest (no root package), so its `tests/` directory is not a
//! Cargo test target of its own. Including the file here — inside `ferriscd-cli`, which owns the
//! binary the test spawns (`CARGO_BIN_EXE_ferriscd`) — gives the live test a real test target. It
//! is `#[ignore]`d, so `make gate` never needs a cluster.

#[path = "../../../tests/integration/v1_1_readiness_rbac.rs"]
mod v1_1_readiness_rbac;
