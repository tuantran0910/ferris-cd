//! Sync planning and orchestration: the explicit plan for one pass, plus the re-entrant
//! wave/hook state machine and bounded revision history.
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
//! Phase 08 populates the planner. Phase 10 adds the wave/hook state machine on top of the same
//! [`SyncPlan`] shape (group by `ferriscd.io/sync-wave`, partition `ferriscd.io/hook`), so the
//! plan stays the single place where "what will this sync do" is decided.
//!
//! The Phase 10 half is deliberately **pure**: no client, no clock, no disk, no sleeps. The
//! controller owns the impure half (rendering a commit, creating hooks with `generateName`,
//! patching `/status`) and asks the engine what the next step is:
//!
//! ```text
//! controller                                   engine
//! ----------                                   ------
//! read Application.status.operationState  -->  state_machine::SyncMachine::step
//! resolve spec.source to a commit SHA     -->  (restarts at PreSync when it moved)
//! read live health (Phase 09)             -->  (determines Execute/Wait/Finished)
//! write SyncPlan actions / hook Jobs      <--  StepOutcome { state, action }
//! patch /status (operationState, history) <--  history::record_operation_success / plan_rollback
//! ```
//!
//! | Concern | Module |
//! |---|---|
//! | `PreSync` -> `Sync(wave)` -> `PostSync` -> `Succeeded` \| `SyncFail` -> `Failed`, crash-safe resume, wave/timeout failures, requeue hints as data | [`state_machine`] |
//! | bounded `status.history`, rollback target lookup, `AutomatedSyncDisabledByRollback` warning | [`history`] |
//! | `ferriscd.io/sync-wave` partitioning | [`crate::graph::waves`] |
//! | `ferriscd.io/hook` / `ferriscd.io/hook-delete-policy` parsing + hook partition | [`crate::graph::hooks`] |
//!
//! The wire types are owned by `ferriscd-crd` (`SyncPhase`, `OperationState`,
//! `RevisionHistoryEntry`, `Condition`) and re-exported here, so the CRD schema and the engine
//! cannot drift apart.

pub mod history;
pub mod plan;
pub mod state_machine;

pub use history::{
    CONDITION_WARNING, MAX_HISTORY, REASON_AUTOMATED_SYNC_DISABLED_BY_ROLLBACK, RollbackDecision,
    RollbackError, RollbackRequest, RollbackTarget, SyncRecording, clear_rollback_warning,
    clear_rollback_warning_if_automation_reenabled, disable_automated_sync,
    effective_history_limit, parse_rollback_request, plan_rollback, record_operation_success,
    record_sync_success, rollback_target,
};
pub use plan::{
    OrphanCandidate, OrphanOwnership, PlanConflict, PlanRequest, PlanSkipReason, PlanSummary,
    ResourceSyncOptions, SyncAction, SyncPlan, resource_sync_options, statuses_by_key,
};
pub use state_machine::{
    DEFAULT_OPERATION_TIMEOUT, DEFAULT_REQUEUE_AFTER, DEFAULT_WAVE_TIMEOUT, StepAction, StepHealth,
    StepOutcome, SyncFailureReason, SyncMachine, SyncPhase, SyncSchedule, SyncStep, SyncTimeouts,
    WaveGate, is_terminal, phase_rank,
};
