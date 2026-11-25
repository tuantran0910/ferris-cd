//! Compiles the workspace-level live `v0.9` control-plane API/webhook test
//! (`tests/integration/v0_9_api_webhooks.rs`) as a test target of this package.
//!
//! The workspace root is a virtual manifest (no root package), so its `tests/` directory is not a
//! Cargo test target of its own. Including the file here — inside the `ferriscd-server` package,
//! which owns the router, the webhook verification and the OpenAPI document the test drives — gives
//! the live test a real test target. It is `#[ignore]`d, so `make gate` never needs a cluster.

#[path = "../../../tests/integration/v0_9_api_webhooks.rs"]
mod v0_9_api_webhooks;
