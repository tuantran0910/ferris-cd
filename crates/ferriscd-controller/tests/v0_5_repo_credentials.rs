//! Compiles the workspace-level live `v0.5` repository-credentials integration test
//! (`tests/integration/v0_5_repo_credentials.rs`) as a test target of this package.
//!
//! The workspace root is a virtual manifest (no root package), so its `tests/` directory is not a
//! Cargo test target of its own. Including the file here — inside the `ferriscd-controller`
//! package, which owns `SecretCredentialStore` and the sync pipeline the test drives — gives the
//! live test a real test target. Both tests are `#[ignore]`d, so `make gate` never needs a
//! cluster, a `git` binary, or a loopback socket.

#[path = "../../../tests/integration/v0_5_repo_credentials.rs"]
mod v0_5_repo_credentials;
