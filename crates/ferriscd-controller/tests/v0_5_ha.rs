//! Compiles the workspace-level live `v0.5` HA integration tests
//! (`tests/integration/v0_5_ha.rs`) as a test target of this package.
//!
//! The workspace root is a virtual manifest (no root package), so its `tests/` directory is not a
//! Cargo test target of its own. Including the file here — inside the `ferriscd-controller`
//! package, which owns the cluster registry, the leader elector and the sync pipeline the tests
//! drive — gives the live tests a real test target. Both are `#[ignore]`d, so `make gate` never
//! needs a cluster.

#[path = "../../../tests/integration/v0_5_ha.rs"]
mod v0_5_ha;
