//! Compiles the workspace-level live `v0.5` multi-tenancy integration test
//! (`tests/integration/v0_5_multi_tenancy.rs`).
//!
//! The workspace root is a virtual manifest (no root package), so its `tests/` directory is not a
//! Cargo test target of its own. Including the file here — inside the `ferriscd-controller`
//! package, which owns the impersonation pool and the sync pipeline the test drives — gives the
//! live test a real test target. The test is `#[ignore]`d, so `make gate` never needs a cluster.

#[path = "../../../tests/integration/v0_5_multi_tenancy.rs"]
mod v0_5_multi_tenancy;
