//! Compiles the workspace-level live `v0.4` renderer integration test
//! (`tests/integration/v0_4_renderers.rs`).
//!
//! The workspace root is a virtual manifest (no root package), so its `tests/` directory is not a
//! Cargo test target of its own. Including the file here — inside the `ferriscd-engine` package,
//! which owns the renderer pipeline — gives the live test a real test target. Both tests are
//! `#[ignore]`d, so `make gate` never needs `kustomize`, `helm`, or a cluster.

#[path = "../../../tests/integration/v0_4_renderers.rs"]
mod v0_4_renderers;
