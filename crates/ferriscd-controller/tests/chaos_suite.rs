//! Compiles the workspace-level Phase 15 chaos test suite
//! (`tests/integration/chaos_suite.rs`, `T15.4`) as a test target of `ferriscd-controller`.
//!
//! The workspace root is a virtual manifest (no root package), so its `tests/` directory is not a
//! Cargo test target of its own. Including the suite here gives both:
//!
//! * **Hermetic deterministic chaos tests** — run automatically under `cargo test --workspace`
//!   (and `cargo test -p ferriscd-controller --test chaos_suite`) with zero cluster dependency and
//!   zero timing sleeps.
//! * **Live `kind` chaos tests** — `#[ignore]`d and guarded by `assert_kind_context()`, invoked
//!   explicitly against a local `kind-*` cluster.

#[path = "../../../tests/integration/chaos_suite.rs"]
mod chaos_suite;
