//! Sync planning: turning a diff pass and the `Application` policy into an explicit, auditable
//! action list **before** anything is written to the cluster.
//!
//! ```text
//! DiffSummary + SyncDecision + SyncOptions + orphan ownership
//!        │
//!        ▼   (pure: no client, no clock, no I/O)
//!   SyncPlan { pre_create_namespace, steps: Vec<SyncAction> }
//!        │
//!        ▼   (controller/src/sync_executor.rs)
//!   SSA apply / replace / ownership-verified prune
//! ```
//!
//! Phase 08 populates this module; Phase 10 adds the wave/hook state machine on top of the same
//! [`SyncPlan`] shape (group by `ferriscd.io/sync-wave`, partition `ferriscd.io/hook`), so the
//! plan stays the single place where "what will this sync do" is decided.

pub mod plan;

pub use plan::{
    OrphanCandidate, OrphanOwnership, PlanConflict, PlanRequest, PlanSkipReason, PlanSummary,
    ResourceSyncOptions, SyncAction, SyncPlan, resource_sync_options, statuses_by_key,
};
