//! Compiles the workspace-level live `v0.5` enterprise acceptance suite
//! (`tests/integration/v0_5_enterprise.rs`, `T13.4`) as a test target of this package.
//!
//! The workspace root is a virtual manifest (no root package), so its `tests/` directory is not a
//! Cargo test target of its own. Including the file here — inside the `ferriscd-controller` package,
//! which owns the project policy, the impersonation pool, the cluster registry, the leader elector
//! and the sync pipeline the suite drives — gives the live tests a real test target. All four are
//! `#[ignore]`d, so `make gate` never needs a cluster.

#[path = "../../../tests/integration/v0_5_enterprise.rs"]
mod v0_5_enterprise;
