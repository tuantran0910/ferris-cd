//! Finalizer gate, always-update-status wrapper, and the (Phase 07–08) sync-pipeline seam.
//!
//! Two safety properties live here:
//!
//! * **Never wedge in `Terminating`** (finding C5). The finalizer is only kept when cleanup
//!   failed *and* can plausibly succeed later. A `404`/`410`/`NoMatchesForKind` response
//!   means the target is already gone, a missing destination-cluster secret means there is
//!   nothing we could possibly delete, and `ferriscd.io/force-delete: "true"` is the
//!   documented escape hatch — all of them release the finalizer (with a warning) instead
//!   of blocking deletion forever.
//! * **Never fail silently** (trap T3). Every reconcile patches `/status` on both `Ok` and
//!   `Err`, updating `observedGeneration` and a `Ready` condition
//!   (`Ready=False, reason=...` on failure), so `kubectl describe app` always explains the
//!   current state.
//!
//! The diff/sync pipeline itself arrives in Phases 07–08. It is modelled here as two
//! traits — [`SyncPipeline`] (apply/cleanup) and [`StatusWriter`] (`/status` patching) — so
//! the finalizer, condition and status logic is fully unit-testable without a cluster.

use std::sync::Arc;
use std::time::Duration;

use ferriscd_crd::status::{
    ApplicationStatus, Condition, ConditionStatus, HealthState, MAX_STATUS_MESSAGE_CHARS,
    OperationState, REASON_SYNC_ERROR, REASON_SYNC_SUCCEEDED, ResourceStatus, RevisionHistoryEntry,
    SyncState, SyncStatus,
};
use ferriscd_crd::{Application, annotations};
use ferriscd_engine::diff::{DiffSummary, ResourceDiff};
use ferriscd_engine::inventory::Inventory;
use ferriscd_engine::manifest::{ManifestError, ResourceKey};
use ferriscd_engine::repo::RepoError;
use futures::FutureExt;
use futures::future::BoxFuture;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use kube::Client;
use kube::ResourceExt;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{self, Event};
use tracing::Instrument;

use crate::controller::{BackoffTracker, FailureClass, object_key};
use crate::discovery::DiscoveryError;
use crate::events::EventRecorder;
use crate::live_state::LiveStateError;
use crate::scope::ScopeError;

/// Finalizer owned by FerrisCD; deleting an `Application` runs the cleanup branch.
pub const FINALIZER: &str = "ferriscd.io/finalizer";

/// Requeue interval used when a successful apply requests no specific one.
pub const DEFAULT_REQUEUE: Duration = Duration::from_secs(180);

/// Condition reason recorded when the API server reports the target as already deleted.
pub const REASON_NOT_FOUND: &str = "NotFound";

/// Condition reason recorded when the API server does not serve the resource kind.
pub const REASON_NO_MATCHES_FOR_KIND: &str = "NoMatchesForKind";

/// Condition reason recorded for validation/configuration failures.
pub const REASON_INVALID_SPEC: &str = "InvalidSpec";

/// Condition reason recorded when the finalizer is released without a full cleanup.
pub const REASON_CLEANUP_SKIPPED: &str = "CleanupSkipped";

/// Condition reason recorded when a sync is waiting on a CRD or namespace creation.
///
/// This is a `Ready=True` reason, not a failure: the resources that *can* be applied were
/// applied, and the deferred ones are retried on a short requeue
/// ([`crate::sync::PENDING_REQUEUE`]) instead of failing the reconcile.
pub const REASON_PENDING: &str = "PendingDependencies";

/// Condition reason recorded when the sync-decision gate deliberately applied nothing.
///
/// A skip is a *successful* reconcile (`Ready=True`): the pass read Git, diffed the cluster and
/// concluded that nothing should be applied (`automated: None`, `selfHeal: false` with an
/// unchanged source, or "already up to date"). `status.sync.status` carries the drift verdict,
/// so a skipped-but-drifting `Application` is visible as `OutOfSync` without being an error.
pub const REASON_SYNC_SKIPPED: &str = "SyncSkipped";

/// Condition reason recorded when a deployed sync window blocks automation (`T17.4`).
///
/// Deliberately `Ready=True`: a governance window is not a failure. A blocked pass still reads Git,
/// diffs the cluster, reports `OutOfSync`, and requeues for the window boundary — so it must never
/// flip `Ready=False`, which would also fire a `Warning SyncFailed`-style notification (`T19.4`)
/// for a change freeze an operator asked for. The `message` carries the blocking window and the
/// next transition instant.
///
/// **A manual `POST .../sync` refused by a window is deferred, not dropped** (finding N-c). The
/// request is recorded as a running operation, [`crate::sync`]'s pass pauses it at the existing
/// phase/step (moving `startedAt`/`phaseStartedAt` to `now`, so a freeze never counts against the
/// wave/operation timeouts) and requeues for the window boundary; when the window lifts, the
/// operation resumes and executes **without a second confirmation**. That is what an operator asking
/// for a manual sync has already given: the window decides *when*, not *whether*. A window with
/// `manualSync: true` still executes immediately instead.
pub const REASON_SYNC_WINDOW_ACTIVE: &str = "SyncWindowActive";

/// Condition reason recorded when a managed object belongs to another `Application`.
///
/// Terminal (trap T10): no apply FerrisCD could issue would resolve the conflict, so the
/// reconcile fails once and is retried on the terminal backoff instead of self-healing forever.
pub const REASON_OWNERSHIP_CONFLICT: &str = "OwnershipConflict";

/// Condition reason recorded when the referenced `AppProject` denies the `Application`.
///
/// Terminal (`T12.1`): the project — or the `Application`'s namespace, repository, destination,
/// ServiceAccount, or a rendered resource — must change. `kubectl describe app` shows which one,
/// because the condition message names the offending field and key.
pub const REASON_POLICY_VIOLATION: &str = "PolicyViolation";

/// Condition reason recorded when a pre-sync **policy rule** refuses the bundle (`T20.2`).
///
/// Distinct from [`REASON_POLICY_VIOLATION`], which is the `AppProject` allow-list verdict: this one
/// means every rendered resource was authorized but at least one broke a manifest invariant (a
/// `privileged` container, an unapproved registry, a missing label). Terminal — the manifests or the
/// rule must change — and raised before a single apply, prune, or `dryRun=All` call.
pub const REASON_POLICY_GATE_VIOLATION: &str = "PolicyGateViolation";

/// Whether a deletion cascades through `status.inventory`.
///
/// Defaulting to [`CleanupMode::Orphan`] means deleting an `Application` never silently
/// deletes the workloads it manages: cascading is opt-in via
/// `ferriscd.io/cascade-delete: "true"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupMode {
    /// Release the finalizer without deleting managed resources (default).
    Orphan,
    /// Delete every resource tracked in `status.inventory`.
    Cascade,
}

/// Outcome of a successful apply (diff + sync) pass.
///
/// Beyond the condition text it carries everything the pipeline learned that must be persisted
/// on `/status`: the crash-safe inventory, the sync state, and the health assessment. All of them
/// stay `None` for a pipeline that has nothing to report (e.g. [`UnwiredSyncPipeline`]), in which
/// case `apply_once` leaves the corresponding status fields untouched instead of clearing them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOutcome {
    /// `Ready=True` reason (e.g. `SyncSucceeded`).
    pub reason: String,
    /// Human-readable message for the `Ready` condition.
    pub message: String,
    /// Optional requeue override (persisted operation state may need a follow-up pass).
    pub requeue: Option<Duration>,
    /// Crash-safe inventory to persist in `status.inventory` (`None` = leave untouched).
    pub inventory: Option<Inventory>,
    /// Sync observability to persist in `status.sync` (`None` = leave untouched).
    pub sync: Option<SyncState>,
    /// Aggregated health to persist in `status.health` (`None` = leave untouched).
    pub health: Option<HealthState>,
    /// Per-resource health summaries for `status.resources` (`None` = leave untouched).
    ///
    /// When present the list is authoritative: `status.resources` is replaced, so a resource that
    /// no longer exists cannot linger in the status forever.
    pub resources: Option<Vec<ResourceStatus>>,
    /// Wave/hook operation state to persist in `status.operationState` (`None` = leave untouched).
    pub operation_state: Option<OperationState>,
    /// The authoritative `status.history` list (`None` = leave untouched).
    pub history: Option<Vec<RevisionHistoryEntry>>,
    /// Conditions to add or refresh (the `T10.5` rollback warning).
    pub warnings: Vec<Condition>,
    /// The `T20.2` `PolicyAdvisory` condition for this pass (`None` = leave untouched).
    ///
    /// Kept out of [`Self::warnings`] deliberately: policy advisories are refreshed on **every**
    /// pass (including the `False`/`PolicyCompliant` form that clears a stale advisory), and the
    /// rollback-warning lifecycle keys off `warnings.is_empty()`.
    pub policy_advisories: Option<Condition>,
    /// Canonical GKNN keys confirmed pruned during this pass (`T15.2` `ResourcePruned` event).
    pub pruned: Vec<ResourceKey>,
}

impl ApplyOutcome {
    /// Builds a successful outcome without status fields.
    #[must_use]
    pub fn ready(reason: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            message: message.into(),
            requeue: None,
            inventory: None,
            sync: None,
            health: None,
            resources: None,
            operation_state: None,
            history: None,
            warnings: Vec::new(),
            policy_advisories: None,
            pruned: Vec::new(),
        }
    }

    /// Requests a follow-up reconcile after `delay`.
    #[must_use]
    pub fn with_requeue(mut self, delay: Duration) -> Self {
        self.requeue = Some(delay);
        self
    }

    /// Attaches the crash-safe inventory to persist.
    #[must_use]
    pub fn with_inventory(mut self, inventory: Inventory) -> Self {
        self.inventory = Some(inventory);
        self
    }

    /// Attaches the sync state to persist.
    #[must_use]
    pub fn with_sync(mut self, sync: SyncState) -> Self {
        self.sync = Some(sync);
        self
    }

    /// Attaches the aggregated health and the per-resource summaries to persist.
    #[must_use]
    pub fn with_health(mut self, health: HealthState, resources: Vec<ResourceStatus>) -> Self {
        self.health = Some(health);
        self.resources = Some(resources);
        self
    }

    /// Attaches the wave/hook operation state to persist (`T10.1`).
    #[must_use]
    pub fn with_operation_state(mut self, operation: Option<OperationState>) -> Self {
        self.operation_state = operation;
        self
    }

    /// Attaches the authoritative `status.history` list to persist (`T10.5`).
    #[must_use]
    pub fn with_history(mut self, history: Option<Vec<RevisionHistoryEntry>>) -> Self {
        self.history = history;
        self
    }

    /// Attaches the `T20.2` `PolicyAdvisory` condition for this pass.
    #[must_use]
    pub fn with_policy_advisories(mut self, condition: Option<Condition>) -> Self {
        self.policy_advisories = condition;
        self
    }

    /// Adds a condition to the status this pass writes (the rollback warning).
    #[must_use]
    pub fn with_warning(mut self, condition: Condition) -> Self {
        self.warnings.push(condition);
        self
    }

    /// Attaches the confirmed pruned GKNN keys for `Normal ResourcePruned` event emission (`T15.2`).
    #[must_use]
    pub fn with_pruned(mut self, pruned: Vec<ResourceKey>) -> Self {
        self.pruned = pruned;
        self
    }
}

/// Outcome of a cleanup (prune) pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupOutcome {
    /// Every inventoried resource was deleted (or was already gone).
    Completed,
    /// The destination cluster cannot be reached (e.g. its `Secret` is missing), so nothing
    /// could be pruned. The finalizer is released with a warning instead of wedging the
    /// object in `Terminating`.
    TargetUnavailable {
        /// Why the destination is unusable.
        message: String,
    },
}

/// What to do with the finalizer after the cleanup branch ran.
#[derive(Debug)]
pub enum CleanupDisposition {
    /// Remove the finalizer; `warning` is logged and recorded on the status condition.
    Release {
        /// Non-fatal reason for releasing without a full cleanup.
        warning: Option<String>,
    },
    /// Keep the finalizer; the reconcile fails and is retried with backoff.
    Retain {
        /// The cleanup error that keeps the finalizer in place.
        error: ReconcileError,
    },
}

/// Errors produced by a single reconcile pass.
#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    /// A Kubernetes API call failed.
    #[error("kubernetes API error: {0}")]
    Api(#[from] kube::Error),

    /// API discovery failed or the kind is unknown.
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),

    /// Scope normalization rejected the bundle.
    #[error(transparent)]
    Scope(#[from] ScopeError),

    /// Reading live state failed.
    #[error(transparent)]
    Live(#[from] LiveStateError),

    /// Git resolution, caching or worktree sanitization failed.
    #[error(transparent)]
    Repo(#[from] RepoError),

    /// Manifest loading, parsing or normalization failed.
    #[error(transparent)]
    Manifest(#[from] ManifestError),

    /// The Server-Side Apply `dryRun=All` diff pass failed (T07.1–T07.3).
    ///
    /// A diff that cannot read the API server must retry instead of guessing: a guessed
    /// "synced" would silently skip an apply that is actually needed.
    #[error(transparent)]
    Diff(#[from] crate::dry_run::DryRunError),

    /// A desired object is managed by a different `Application` (trap T10).
    ///
    /// Terminal: the apply this pass would issue cannot succeed, so retrying is pointless and
    /// must not become a self-heal loop. The pass still reports `status.sync.status = OutOfSync`
    /// with the unchanged inventory, so the conflict stays visible in `kubectl describe`.
    #[error("{message}")]
    OwnershipConflict {
        /// Actionable, secret-free description naming every conflicting key and its owner.
        message: String,
        /// The inventory as it was before the pass: nothing was applied, so nothing changed.
        inventory: Inventory,
        /// The revision that could not be synced.
        revision: Option<String>,
    },

    /// The referenced `AppProject` does not permit this `Application` (`T12.1`, `T12.2`).
    ///
    /// Terminal and raised **before any mutation** — before the repository is cloned, before the
    /// `dryRun=All` diff, before an apply or a prune — so a denial costs the cluster nothing. Every
    /// variant names the offending field, key, or resource.
    #[error(transparent)]
    Policy(#[from] ferriscd_engine::policy::PolicyError),

    /// The `Application`'s `ServiceAccount` cannot be impersonated (`T12.3`).
    ///
    /// Terminal: an invalid ServiceAccount or namespace name, a forbidden group, or no
    /// impersonation pool wired into the pipeline can never be fixed by retrying — and refusing
    /// is the only safe answer, because the alternative is deploying a tenant `Application` with
    /// the controller's own privileged identity (trap T12).
    #[error(transparent)]
    Impersonation(#[from] crate::impersonation::ImpersonationError),

    /// A `ferriscd.io/secret-type=repository` `Secret` cannot be used (`T12.4`).
    ///
    /// Terminal: the credential lives in a `Secret` the controller does not write, and the
    /// alternative to refusing — picking a different `Secret`, or cloning anonymously when a
    /// credential was configured — would hide a misconfiguration and could leak a repository to
    /// the wrong identity. Every variant names the `Secret`, its namespace, and the offending
    /// keys; none carries a secret value.
    #[error(transparent)]
    Credentials(#[from] crate::credentials::CredentialError),

    /// The destination cluster is not registered, or its `Secret` cannot be used (`T13.1`).
    ///
    /// Terminal: the `Secret` registry is the only way a remote cluster becomes addressable, and
    /// applying a remote `Application` to the control plane instead would deploy the manifests
    /// into the wrong cluster. Every variant names the `Secret` or the cluster name; none carries
    /// a credential value.
    #[error(transparent)]
    Cluster(#[from] crate::cluster_manager::ClusterError),

    /// A Server-Side Apply call failed for a specific resource.
    #[error("server-side apply failed for {resource}: {source}")]
    Apply {
        /// Canonical GKNN key of the offending resource.
        resource: String,
        /// Underlying API error.
        #[source]
        source: kube::Error,
    },

    /// A delete call failed for a specific resource.
    #[error("delete failed for {resource}: {source}")]
    Delete {
        /// Canonical GKNN key of the offending resource.
        resource: String,
        /// Underlying API error.
        #[source]
        source: kube::Error,
    },

    /// The sync ran but stopped after at least one resource failed.
    ///
    /// Carries the inventory that is already true (every confirmed apply/prune so far) so
    /// `apply_once` can still persist it: a create that succeeded must never become an
    /// untracked orphan just because a later resource failed (finding C1).
    #[error("{message}")]
    PartialSync {
        /// Actionable, secret-free description of the failure.
        message: String,
        /// Crash-safe inventory confirming everything that succeeded before the failure.
        inventory: Inventory,
        /// The revision that was being synced.
        revision: Option<String>,
        /// The wave/hook operation state the failed pass produced (`T10.3`, finding M4).
        ///
        /// A pass that failed *after* creating hooks must still persist their tracking records:
        /// `status.operationState.activeHooks` is the only thing that keeps a `generateName` `Job`
        /// from being created a second time by the next pass (a second migration).
        ///
        /// Boxed so carrying it does not grow every `ReconcileError` in the pass (the enum is
        /// returned by value from every pipeline call).
        operation: Option<Box<OperationState>>,
    },

    /// A planned action could not be executed and retrying cannot help (terminal).
    ///
    /// Raised by the sync executor for the cases that are *policy* failures, not API failures: an
    /// immutable field without `ferriscd.io/sync-options: Replace=true`, or a `409 Conflict` whose
    /// conflicting field manager is not listed in `syncOptions.takeoverFieldManagers` (T08.4).
    /// Carries the confirmed inventory so `/status` still records what did apply (finding C1).
    #[error("{message}")]
    SyncConflict {
        /// Actionable, secret-free description naming the resource and the opt-in.
        message: String,
        /// Crash-safe inventory confirming everything the pass confirmed before the failure.
        inventory: Inventory,
        /// The revision that could not be fully synced.
        revision: Option<String>,
        /// The wave/hook operation state the failed pass produced (finding H-A).
        ///
        /// A **terminal** failure inside an operation (a rejected hook create, an immutable field)
        /// drops nothing: the state — including `status.operationState.activeHooks` and its
        /// `Failed` phase — must still reach `/status`, or the next terminal-backoff pass restarts
        /// the operation with an empty hook set and creates a second `generateName` `Job` (a second
        /// database migration).
        ///
        /// Boxed for the same reason as [`Self::PartialSync::operation`].
        operation: Option<Box<OperationState>>,
    },

    /// A recovery step could not confirm completion inside its bounded window (retryable).
    ///
    /// The delete of a `Replace` succeeded but the object was still present when the wait
    /// expired (a finalizer, most likely). Re-applying now would answer `409 AlreadyExists`, so
    /// the pass stops and the next reconcile re-reads live state and continues (finding M3).
    #[error("{message}")]
    SyncRetry {
        /// Actionable, secret-free description.
        message: String,
    },

    /// The pre-sync policy gate refused the bundle (`T20.2`).
    ///
    /// Terminal and raised **before any mutation**: after tenancy policy and Stage-2 scope
    /// normalization, before the live read, the `dryRun=All` diff, every apply and every prune. The
    /// inventory is the one that was already true — nothing was applied or pruned — so `/status`
    /// reports `OutOfSync` and **keeps** `lastSyncedRevision`: a refused pass must never look like a
    /// pass that lost its history, and `selfHeal` must still be able to converge once the manifests
    /// change.
    ///
    /// Boxed for the same reason [`Self::PartialSync`]'s operation state is: `ReconcileError` is
    /// returned **by value** from every pipeline call, so a refusal carrying two violation lists,
    /// the unchanged inventory and the revision must not grow the enum that every other, far more
    /// common error pays for (`clippy::result_large_err`).
    #[error("{0}")]
    PolicyGate(Box<PolicyGateRefusal>),

    /// The desired state is invalid and retrying cannot help (terminal).
    #[error("{message}")]
    Invalid {
        /// Actionable, secret-free description.
        message: String,
    },
}

/// The detail of a [`ReconcileError::PolicyGate`] refusal (`T20.2`).
///
/// A refusal carries more than a sentence: the blocking violations are what the operator has to fix
/// and the advisories are what the refusal path must write (or clear) on `/status`, and the
/// inventory is what has to survive a pass that applied nothing. It lives in its own struct only so
/// the error variant can box it.
#[derive(Debug)]
pub struct PolicyGateRefusal {
    /// Actionable, `Secret`-free summary naming every blocking violation.
    pub message: String,
    /// The blocking violations, in rule-then-resource order.
    pub violations: Vec<ferriscd_engine::policy::PolicyViolation>,
    /// The advisory (`Warn`) violations of the same pass.
    ///
    /// Carried so the refusal path can write — or **clear** — the `PolicyAdvisory` condition
    /// (finding M7): a refused pass never reaches the success path that refreshes it, so without
    /// them a stale advisory would outlive the violation that produced it.
    pub advisories: Vec<ferriscd_engine::policy::PolicyViolation>,
    /// How many rules were in force, for the advisory condition's message.
    pub rules: usize,
    /// How many advisories the gate found but could not list (its violation budget).
    ///
    /// Carried for the same reason as [`Self::advisories`], and it is what makes the condition's
    /// count **accurate** (`T20.2`, finding M10): a refused pass whose advisory list overflowed
    /// must not report the retained entries as the whole story, and it must not claim there were no
    /// advisories at all when every one of them was dropped.
    pub advisories_omitted: usize,
    /// The inventory as it was before the pass: nothing was applied, so nothing changed.
    pub inventory: Inventory,
    /// The revision that could not be synced.
    pub revision: Option<String>,
}

impl std::fmt::Display for PolicyGateRefusal {
    /// The one-line refusal; the `ReconcileError` carries it verbatim into `Ready=False`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl ReconcileError {
    /// Returns `true` when the error means "the target is already gone".
    ///
    /// `404`/`410` API responses and `NoMatchesForKind` discovery failures all mean there is
    /// nothing left to delete, so cleanup must release the finalizer instead of retrying.
    #[must_use]
    pub fn is_already_deleted(&self) -> bool {
        match self {
            Self::Api(err) | Self::Apply { source: err, .. } | Self::Delete { source: err, .. } => {
                is_absent(err)
            }
            Self::Discovery(err) => err.is_no_matches_for_kind(),
            Self::Scope(_)
            | Self::Invalid { .. }
            | Self::PartialSync { .. }
            | Self::SyncConflict { .. }
            | Self::SyncRetry { .. }
            | Self::OwnershipConflict { .. }
            | Self::PolicyGate(_)
            | Self::Policy(_)
            | Self::Impersonation(_)
            | Self::Credentials(_)
            | Self::Cluster(_) => false,
            // A kind nobody serves means nothing is left to clean up.
            Self::Live(err) => matches!(err, LiveStateError::UnknownKind { .. }),
            Self::Repo(_) | Self::Manifest(_) | Self::Diff(_) => false,
        }
    }

    /// Classifies the error for the controller's backoff policy.
    #[must_use]
    pub fn failure_class(&self) -> FailureClass {
        match self {
            // `code == 0` is an unpopulated status: assume transient and retry.
            // 408/409/425/429 are transient API conditions (SSA field-ownership and
            // resourceVersion conflicts in particular must back off, not wait 10 minutes).
            Self::Api(err) | Self::Apply { source: err, .. } | Self::Delete { source: err, .. } => {
                classify_api_error(err)
            }
            Self::Discovery(DiscoveryError::NoMatchesForKind { .. }) => FailureClass::Terminal,
            Self::Discovery(DiscoveryError::Refresh { .. }) => FailureClass::Retryable,
            // An ownership conflict cannot be fixed by retrying: another `Application` owns the
            // object, so the terminal backoff is what stops a self-heal loop (trap T10).
            // A policy violation is deterministic too (`T12.1`): the `AppProject` or the
            // `Application` must change, and retrying only churns the work queue.
            Self::Scope(_)
            | Self::Invalid { .. }
            | Self::SyncConflict { .. }
            | Self::OwnershipConflict { .. }
            | Self::PolicyGate(_)
            | Self::Policy(_)
            // An unusable ServiceAccount identity is deterministic too: the spec (or the
            // controller's wiring) must change.
            | Self::Impersonation(_)
            // A malformed or ambiguous repository credential `Secret` is a configuration error
            // only the operator can fix (`T12.4`); retrying would churn the queue while every
            // clone failed the same way.
            | Self::Credentials(_)
            // A cluster that is not registered (or whose Secret cannot be used) is a
            // configuration state only an operator can change (`T13.1`): never retried.
            | Self::Cluster(_) => FailureClass::Terminal,
            // The next pass picks the replacement up where this one stopped.
            Self::SyncRetry { .. } => FailureClass::Retryable,
            Self::Diff(err) => classify_engine_error(err.is_retryable()),
            Self::Live(err) => {
                if err.is_retryable() {
                    FailureClass::Retryable
                } else {
                    FailureClass::Terminal
                }
            }
            Self::Repo(err) => classify_engine_error(err.is_retryable()),
            Self::Manifest(err) => classify_engine_error(err.is_retryable()),
            // A partially applied sync is retried: the next pass converges from live state.
            Self::PartialSync { .. } => FailureClass::Retryable,
        }
    }

    /// The inventory and revision a failure already determines.
    ///
    /// `apply_once` persists these on the failure path so the crash-safe inventory property
    /// holds even when the reconcile fails half-way, and so an unfixable state (an ownership
    /// conflict) is reported as `OutOfSync` instead of only living in the error message.
    #[must_use]
    pub fn partial_status(&self) -> Option<(&Inventory, Option<&String>)> {
        match self {
            Self::PartialSync {
                inventory,
                revision,
                ..
            } => Some((inventory, revision.as_ref())),
            // Nothing was applied, so the inventory is the one that was already true; the
            // conflict still has to surface as `OutOfSync` (T07.4 semantics).
            Self::OwnershipConflict {
                inventory,
                revision,
                ..
            }
            | Self::SyncConflict {
                inventory,
                revision,
                ..
            } => Some((inventory, revision.as_ref())),
            // `T20.2`: nothing was applied, so the inventory is unchanged; reporting it still
            // surfaces `sync.status = OutOfSync` while `merge_sync_state` preserves the
            // `lastSynced*` markers (they are `None` here on purpose).
            Self::PolicyGate(refusal) => Some((&refusal.inventory, refusal.revision.as_ref())),
            _ => None,
        }
    }

    /// The wave/hook operation state a failure already determines (finding M4, finding H-A).
    ///
    /// `apply_once` persists it on the failure path so a retry resumes with the hook records the
    /// failed pass created instead of creating a second `generateName` hook object. Both failure
    /// shapes carry it: a terminal (`SyncConflict`) failure must survive exactly like a retryable
    /// (`PartialSync`) one, otherwise the state is dropped and the retry re-runs the migration.
    #[must_use]
    pub fn partial_operation(&self) -> Option<&OperationState> {
        match self {
            Self::PartialSync { operation, .. } | Self::SyncConflict { operation, .. } => {
                operation.as_deref()
            }
            _ => None,
        }
    }
}

/// Maps an engine error's `is_retryable` verdict onto the controller's backoff classification.
fn classify_engine_error(retryable: bool) -> FailureClass {
    if retryable {
        FailureClass::Retryable
    } else {
        FailureClass::Terminal
    }
}

/// Classifies a `kube` error for the backoff policy.
fn classify_api_error(err: &kube::Error) -> FailureClass {
    match err {
        kube::Error::Api(status) => {
            if matches!(status.code, 0 | 408 | 409 | 425 | 429) || status.code >= 500 {
                FailureClass::Retryable
            } else {
                FailureClass::Terminal
            }
        }
        // Transport/timeout/decode failures: retry.
        _ => FailureClass::Retryable,
    }
}

/// Returns whether a `kube` error reports an absent object (`404`/`410`).
fn is_absent(err: &kube::Error) -> bool {
    matches!(err, kube::Error::Api(status) if status.code == 404 || status.code == 410)
}

/// A read-only diff preview for the control-plane API (`T14.1`).
///
/// Produced from the **same** in-process engine a reconcile uses — the shared `RepoCache`,
/// renderer, `ClusterManager` and SSA `dryRun=All` diff — so `GET .../diff` can never disagree
/// with what the next reconcile would do (finding C9). Nothing here is persisted: a preview is
/// computed on demand from `desired ∪ status.inventory`, exactly like drift detection.
///
/// Every [`ResourceDiff`] is built by the engine's only redacting constructor, so no `Secret`
/// value can reach the API payload, a log line, or an error.
#[derive(Debug, Clone)]
pub struct DiffPreview {
    /// The commit the desired state was rendered from (a rollback pin is honoured).
    pub revision: String,
    /// One entry per resource in `desired ∪ status.inventory`, with field-level changes.
    pub diffs: Vec<ResourceDiff>,
    /// Counts derived from [`Self::diffs`] (the same summary a reconcile reports to `/status`).
    pub summary: DiffSummary,
    /// How many resources the rendered bundle contains (drift-independent).
    pub desired: usize,
    /// Whether the sync decision gate would apply this set right now.
    ///
    /// A blocking `T20.2` policy violation makes this `false`: the preview reports the verdict the
    /// next reconcile would reach instead of pretending the bundle is applicable.
    pub would_sync: bool,
    /// The pre-sync policy gate's violations (`T20.2`), blockings and advisories alike.
    ///
    /// Carried as data rather than as an error so `GET .../diff` (and therefore
    /// `ferriscd app diff`, exit code `3`) can *show* a refused bundle. Nothing is applied either
    /// way: the gate runs before the first mutating call.
    pub policy_violations: Vec<ferriscd_engine::policy::PolicyViolation>,
}

/// The diff/sync pipeline seam implemented in Phases 07–08.
///
/// Both methods are idempotent and must tolerate being cancelled: they are wrapped in the
/// finalizer helper, which may re-run them after a restart.
pub trait SyncPipeline: Send + Sync + 'static {
    /// Applies the desired state and reports the resulting condition.
    fn apply<'a>(
        &'a self,
        app: &'a Application,
    ) -> BoxFuture<'a, Result<ApplyOutcome, ReconcileError>>;

    /// Cleans up managed resources when the `Application` is being deleted.
    fn cleanup<'a>(
        &'a self,
        app: &'a Application,
        mode: CleanupMode,
    ) -> BoxFuture<'a, Result<CleanupOutcome, ReconcileError>>;

    /// Computes a **read-only** diff preview (`T14.1`).
    ///
    /// The contract is "no writes at all": no apply, no prune, no `/status` patch, no
    /// `Application` patch. It is the read-only prefix of a reconcile, so the same policy checks,
    /// the same render and the same `dryRun=All` diff run — a preview can therefore be refused
    /// (`PolicyViolation`, an unreachable cluster, a bad revision) exactly like a sync would be.
    ///
    /// The default **refuses**: a pipeline that cannot preview must not fabricate a diff, because
    /// an invented "everything is synced" is indistinguishable from the real thing.
    fn diff<'a>(
        &'a self,
        app: &'a Application,
    ) -> BoxFuture<'a, Result<DiffPreview, ReconcileError>> {
        let _ = app;
        Box::pin(async {
            Err(ReconcileError::Invalid {
                message: "this sync pipeline cannot compute a live diff preview".to_owned(),
            })
        })
    }
}

/// `/status` patching seam so the always-update-status contract is testable.
pub trait StatusWriter: Send + Sync + 'static {
    /// Patches the `status` subresource of `app`.
    fn patch<'a>(
        &'a self,
        app: &'a Application,
        status: ApplicationStatus,
    ) -> BoxFuture<'a, Result<(), ReconcileError>>;

    /// Called once the object is going away (the finalizer was released).
    ///
    /// A no-op by default: a writer that holds no state keyed by the object has nothing to forget.
    /// [`MetricsStatusWriter`](crate::metrics::MetricsStatusWriter) overrides it to drop the
    /// `Application`'s status gauges, which would otherwise outlive the object forever (`T15.1`).
    fn forget_app(&self, app: &Application) {
        let _ = app;
    }
}

/// [`StatusWriter`] backed by `Api::patch_status`.
pub struct ApiStatusWriter {
    api: Api<Application>,
    /// Client used to patch an `Application` in its **own** namespace (`T12.2`); `None` keeps the
    /// fixed `api` (hermetic tests and the single-namespace default are unaffected).
    client: Option<Client>,
    params: PatchParams,
}

impl ApiStatusWriter {
    /// Builds a writer over the `Application` API.
    #[must_use]
    pub fn new(api: Api<Application>) -> Self {
        Self {
            api,
            client: None,
            params: PatchParams::default(),
        }
    }

    /// Patches `/status` in each `Application`'s own namespace (`T12.2`).
    #[must_use]
    pub fn with_client(mut self, client: Client) -> Self {
        self.client = Some(client);
        self
    }

    /// The `Application` API for `app`'s own namespace.
    fn api_for(&self, app: &Application) -> Api<Application> {
        match (self.client.as_ref(), app.namespace()) {
            (Some(client), Some(namespace)) => Api::namespaced(client.clone(), &namespace),
            _ => self.api.clone(),
        }
    }
}

impl std::fmt::Debug for ApiStatusWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiStatusWriter")
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

impl StatusWriter for ApiStatusWriter {
    fn patch<'a>(
        &'a self,
        app: &'a Application,
        status: ApplicationStatus,
    ) -> BoxFuture<'a, Result<(), ReconcileError>> {
        Box::pin(async move {
            let name = app
                .metadata
                .name
                .clone()
                .ok_or_else(|| ReconcileError::Invalid {
                    message: "application has no metadata.name".to_owned(),
                })?;
            let body = status_patch_body(&status)?;
            // Merge patch on the `/status` subresource: only the fields we send are
            // updated, so Phase 06+ fields written by another pass are preserved.
            self.api_for(app)
                .patch_status(&name, &self.params, &Patch::Merge(&body))
                .await?;
            Ok(())
        })
    }
}

/// Builds the JSON merge-patch body of one `/status` write.
///
/// A merge patch treats an **absent** field as "unchanged", and [`ApplicationStatus`] skips empty
/// and zero fields on serialization. That is right for everything Phase 06–08 writes (`inventory`,
/// `sync`, `health`, `operationState`, `history` are only omitted when the pass had nothing to say),
/// but it would make the two Phase 09 fields go stale, because the per-resource list is
/// *replaced* on every pass rather than merged:
///
/// * `resources` — a pass that assesses zero resources must clear the previous summaries, so the
///   array is always sent (even when empty);
/// * `resourcesOmitted` — the overflow counter is reset together with the list, so a `0` has to
///   reach the API server instead of being omitted and leaving the previous count behind.
///
/// # Errors
///
/// Returns [`ReconcileError::Invalid`] when the status cannot be serialized (it is a plain data
/// structure, so this is unreachable in practice — but `patch` must not guess).
fn status_patch_body(status: &ApplicationStatus) -> Result<serde_json::Value, ReconcileError> {
    let serialization_error = |err: serde_json::Error| ReconcileError::Invalid {
        message: format!("cannot serialize the application status: {err}"),
    };

    let serde_json::Value::Object(mut fields) =
        serde_json::to_value(status).map_err(serialization_error)?
    else {
        return Err(ReconcileError::Invalid {
            message: "the application status did not serialize to a JSON object".to_owned(),
        });
    };
    fields.insert(
        "resources".to_owned(),
        serde_json::to_value(&status.resources).map_err(serialization_error)?,
    );
    fields.insert(
        "resourcesOmitted".to_owned(),
        serde_json::Value::from(status.resources_omitted),
    );

    let mut body = serde_json::Map::new();
    body.insert("status".to_owned(), serde_json::Value::Object(fields));
    Ok(serde_json::Value::Object(body))
}

/// Shared controller state handed to every reconcile.
pub struct ReconcileContext {
    apps_api: Api<Application>,
    /// Client used to target an `Application`'s **own** namespace (`T12.2`).
    ///
    /// With `--application-namespaces` the controller may reconcile `Application` objects outside
    /// the control-plane namespace, and the finalizer helper has to patch the object it was called
    /// with — in that object's namespace. `None` (the hermetic tests) keeps the single fixed
    /// `apps_api`.
    client: Option<Client>,
    pipeline: Arc<dyn SyncPipeline>,
    status: Arc<dyn StatusWriter>,
    backoff: BackoffTracker,
    /// `T15.1`: the Prometheus recorder, or `None` when metrics are disabled.
    metrics: Option<crate::metrics::Metrics>,
    /// `T15.2`: rate-limited Kubernetes Event recorder (defaults to a no-op publisher in tests).
    events: EventRecorder,
}

impl ReconcileContext {
    /// Builds a reconcile context.
    #[must_use]
    pub fn new(
        apps_api: Api<Application>,
        pipeline: Arc<dyn SyncPipeline>,
        status: Arc<dyn StatusWriter>,
    ) -> Self {
        Self {
            apps_api,
            client: None,
            pipeline,
            status,
            backoff: BackoffTracker::new(),
            metrics: None,
            events: EventRecorder::noop(),
        }
    }

    /// Wires the Prometheus recorder (`T15.1`).
    ///
    /// Two things happen at once, on purpose: the reconcile start/end instrumentation is enabled,
    /// and the `/status` writer is wrapped in [`MetricsStatusWriter`](crate::metrics::MetricsStatusWriter)
    /// so the per-`Application` sync/health gauges always describe the status a pass **persisted**.
    /// Wiring one without the other would leave the gauges describing a state nobody applied.
    #[must_use]
    pub fn with_metrics(mut self, metrics: crate::metrics::Metrics) -> Self {
        self.status = Arc::new(crate::metrics::MetricsStatusWriter::new(
            self.status.clone(),
            metrics.clone(),
        ));
        self.metrics = Some(metrics);
        self
    }

    /// The Prometheus recorder, or `None` when metrics are disabled.
    #[must_use]
    pub fn metrics(&self) -> Option<&crate::metrics::Metrics> {
        self.metrics.as_ref()
    }

    /// Wires the rate-limited Kubernetes Event recorder (`T15.2`).
    #[must_use]
    pub fn with_events(mut self, events: EventRecorder) -> Self {
        self.events = events;
        self
    }

    /// The rate-limited Kubernetes Event recorder (`T15.2`).
    #[must_use]
    pub fn events(&self) -> &EventRecorder {
        &self.events
    }

    /// Resolves the `Application` API per object namespace instead of a fixed one (`T12.2`).
    #[must_use]
    pub fn with_client(mut self, client: Client) -> Self {
        self.client = Some(client);
        self
    }

    /// The `Application` API for `app`'s own namespace.
    ///
    /// This is the **only** way to reach the object: the finalizer helper and the `/status` writer
    /// patch the object they were handed, so with `--application-namespaces` (`T12.2`) that object
    /// may live outside the control-plane namespace. It falls back to the configured
    /// `apps_api` only when no client is wired (hermetic tests) or when the object carries no
    /// namespace (which the API server never returns for a namespaced kind).
    #[must_use]
    pub fn apps_api_for(&self, app: &Application) -> Api<Application> {
        match (self.client.as_ref(), app.namespace()) {
            (Some(client), Some(namespace)) => Api::namespaced(client.clone(), &namespace),
            _ => self.apps_api.clone(),
        }
    }

    /// The diff/sync pipeline.
    #[must_use]
    pub fn pipeline(&self) -> &dyn SyncPipeline {
        self.pipeline.as_ref()
    }

    /// The `/status` writer.
    #[must_use]
    pub fn status(&self) -> &dyn StatusWriter {
        self.status.as_ref()
    }

    /// Per-object retry backoff.
    #[must_use]
    pub fn backoff(&self) -> &BackoffTracker {
        &self.backoff
    }
}

impl std::fmt::Debug for ReconcileContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReconcileContext")
            .field("apps_api", &self.apps_api)
            .finish_non_exhaustive()
    }
}

/// Phase 05 placeholder pipeline.
///
/// The controller runtime is complete, but no diff/sync engine is wired yet: applying
/// reports a terminal `Ready=False` (never a false `Ready=True`) and cleanup is a no-op so
/// deletions can never wedge. Replaced in Phase 07–08.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnwiredSyncPipeline;

impl SyncPipeline for UnwiredSyncPipeline {
    fn apply<'a>(
        &'a self,
        _app: &'a Application,
    ) -> BoxFuture<'a, Result<ApplyOutcome, ReconcileError>> {
        Box::pin(async {
            Err(ReconcileError::Invalid {
                message: "the diff/sync pipeline is not wired yet (Phases 07-08)".to_owned(),
            })
        })
    }

    fn cleanup<'a>(
        &'a self,
        _app: &'a Application,
        _mode: CleanupMode,
    ) -> BoxFuture<'a, Result<CleanupOutcome, ReconcileError>> {
        Box::pin(async { Ok(CleanupOutcome::Completed) })
    }
}

/// The cleanup mode selected by the `Application`'s control annotations.
#[must_use]
pub fn cleanup_mode(app: &Application) -> CleanupMode {
    if annotation_enabled(app, annotations::CASCADE_DELETE) {
        CleanupMode::Cascade
    } else {
        CleanupMode::Orphan
    }
}

/// Returns whether the `ferriscd.io/force-delete` escape hatch is enabled.
#[must_use]
pub fn force_delete(app: &Application) -> bool {
    annotation_enabled(app, annotations::FORCE_DELETE)
}

fn annotation_enabled(app: &Application, key: &str) -> bool {
    annotations::is_enabled(app.annotations().get(key).map(String::as_str))
}

/// Decides whether the finalizer may be released after a cleanup attempt.
///
/// Ordered so the *safest* explanation wins: a completed cleanup releases silently, an
/// unreachable destination or an already-deleted target releases with a warning, and only
/// a genuine failure keeps the finalizer (unless force-delete is set).
#[must_use]
pub fn cleanup_disposition(
    app: &Application,
    result: Result<CleanupOutcome, ReconcileError>,
) -> CleanupDisposition {
    match result {
        Ok(CleanupOutcome::Completed) => CleanupDisposition::Release { warning: None },
        Ok(CleanupOutcome::TargetUnavailable { message }) => CleanupDisposition::Release {
            warning: Some(format!(
                "destination cluster is unavailable; releasing the finalizer without pruning: {message}"
            )),
        },
        Err(error) if error.is_already_deleted() => CleanupDisposition::Release { warning: None },
        Err(error) if force_delete(app) => CleanupDisposition::Release {
            warning: Some(format!(
                "{} released the finalizer after a cleanup failure: {error}",
                annotations::FORCE_DELETE
            )),
        },
        Err(error) => CleanupDisposition::Retain { error },
    }
}

/// Condition reason for a reconcile error.
#[must_use]
pub fn failure_reason(err: &ReconcileError) -> &'static str {
    if err.is_already_deleted() {
        return match err {
            ReconcileError::Discovery(DiscoveryError::NoMatchesForKind { .. }) => {
                REASON_NO_MATCHES_FOR_KIND
            }
            _ => REASON_NOT_FOUND,
        };
    }
    match err {
        // Deterministic input problems: retrying cannot help, the spec must change.
        ReconcileError::Scope(_)
        | ReconcileError::Invalid { .. }
        | ReconcileError::Live(LiveStateError::UnknownKind { .. })
        | ReconcileError::Live(LiveStateError::ScopeMismatch { .. }) => REASON_INVALID_SPEC,
        // A foreign owner is not a spec bug: `kubectl describe` must name the conflict.
        ReconcileError::OwnershipConflict { .. } => REASON_OWNERSHIP_CONFLICT,
        // Nor is a project denial: it is a tenancy decision, and the message names the field.
        ReconcileError::Policy(_) => REASON_POLICY_VIOLATION,
        // A manifest-invariant denial is its own reason: `kubectl describe app` must let an
        // operator tell "the project does not allow this" from "the manifest breaks a policy".
        ReconcileError::PolicyGate(_) => REASON_POLICY_GATE_VIOLATION,
        // An unusable ServiceAccount identity is a spec problem (`T12.3`): the operator has to fix
        // `spec.serviceAccountName`, `spec.destination.namespace`, or the controller's RBAC.
        ReconcileError::Impersonation(_) => REASON_INVALID_SPEC,
        // An unusable repository credential `Secret` is a spec/configuration problem too (`T12.4`):
        // the operator has to fix the `Secret` named in the message, and no retry can do that.
        ReconcileError::Credentials(_) => REASON_INVALID_SPEC,
        // An unregistered cluster (or an unusable cluster `Secret`) is the same kind of problem
        // (`T13.1`): the `Application`'s `spec.destination.cluster` or the `Secret` must change.
        ReconcileError::Cluster(_) => REASON_INVALID_SPEC,
        _ => REASON_SYNC_ERROR,
    }
}

/// Current wall clock as a Kubernetes timestamp.
#[must_use]
pub fn now() -> Time {
    Time(k8s_openapi::jiff::Timestamp::now())
}

/// Shortest opaque run that is treated as possible secret material in a status message.
///
/// A base64 payload quoted back by a `422` is a long, unbroken run of `[A-Za-z0-9+/=]`; ordinary
/// prose and resource names are not. The alphabet deliberately excludes `-`/`_`/`.` so that
/// hyphenated advice (`kubectl-client-side-apply`, `ferriscd.io/sync-options`) and qualified
/// names survive intact.
///
/// The trade-off is **best effort, not a guarantee**, in two directions:
///
/// * **Missed payloads.** A run shorter than [`MIN_OPAQUE_RUN`] is left alone (a short base64
///   value, e.g. a 20-character secret, is not redacted), and the alphabet stops at `-`/`_`, so a
///   `base64url` value only redacts the pieces that happen to be long enough on their own — a
///   43-character base64url string split by a `-` in the middle stays visible.
/// * **Over-redaction.** The check is structural, not semantic: a long, equally opaque *non*
///   secret run (a long resource name, a bare hex digest) is redacted too. That is the deliberate
///   direction to err in — a redacted directive is noise, a leaked `Secret` value is a breach.
const MIN_OPAQUE_RUN: usize = 40;

/// Replaces base64-looking runs with a length marker.
///
/// This is the last line of defense for trap T4: the API server can quote the value it rejected,
/// so an `Apply`/`Live` error message may contain a `Secret` `.data` value, and `/status` is
/// readable by anyone allowed to `get` the `Application`. Only runs of payload characters are
/// touched, so actionable prose (which names managers, annotations, and reasons) survives intact.
pub(crate) fn redact_payloads(message: &str) -> String {
    fn is_payload_char(c: char) -> bool {
        c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=')
    }

    fn flush(run: &mut String, out: &mut String) {
        if run.chars().count() >= MIN_OPAQUE_RUN {
            out.push_str(&format!("<redacted {} char(s)>", run.chars().count()));
        } else {
            out.push_str(run);
        }
        run.clear();
    }

    let mut redacted = String::with_capacity(message.len());
    let mut run = String::new();
    for c in message.chars() {
        if is_payload_char(c) {
            run.push(c);
        } else {
            flush(&mut run, &mut redacted);
            redacted.push(c);
        }
    }
    flush(&mut run, &mut redacted);
    redacted
}

/// Truncates `message` to [`MAX_STATUS_MESSAGE_CHARS`] on a UTF-8 boundary.
///
/// `/status` is capped by `etcd`'s 1.5 MiB object limit, so an unbounded error message
/// (a stack-trace-shaped string) can never be allowed to grow the status. Payload-looking runs
/// are redacted first ([`redact_payloads`]), so a `Secret` value quoted by the API server never
/// reaches `/status`.
pub(crate) fn bounded(message: &str) -> String {
    let redacted = redact_payloads(message);
    if redacted.chars().count() <= MAX_STATUS_MESSAGE_CHARS {
        return redacted;
    }
    let mut truncated: String = redacted.chars().take(MAX_STATUS_MESSAGE_CHARS).collect();
    truncated.push('…');
    truncated
}

/// Builds the `Ready=True` condition for a successful apply.
#[must_use]
pub fn ready_condition(
    generation: Option<i64>,
    outcome: &ApplyOutcome,
    timestamp: Time,
) -> Condition {
    Condition::ready(
        ConditionStatus::True,
        outcome.reason.clone(),
        bounded(&outcome.message),
        timestamp,
    )
    .with_observed_generation(generation)
}

/// Builds the `Ready=False` condition for a failed reconcile.
#[must_use]
pub fn failure_condition(
    generation: Option<i64>,
    err: &ReconcileError,
    timestamp: Time,
) -> Condition {
    Condition::ready(
        ConditionStatus::False,
        failure_reason(err),
        bounded(&err.to_string()),
        timestamp,
    )
    .with_observed_generation(generation)
}

/// Records a successful apply on `status` (always-update-status contract).
pub fn record_success(
    status: &mut ApplicationStatus,
    generation: Option<i64>,
    outcome: &ApplyOutcome,
    timestamp: Time,
) {
    status.observed_generation = generation;
    status.set_condition(ready_condition(generation, outcome, timestamp));
}

/// Records a failed reconcile on `status` (always-update-status contract).
pub fn record_failure(
    status: &mut ApplicationStatus,
    generation: Option<i64>,
    err: &ReconcileError,
    timestamp: Time,
) {
    status.observed_generation = generation;
    status.set_condition(failure_condition(generation, err, timestamp.clone()));
    // `T20.2` (finding M7): a policy gate refusal is a *failed* pass, so it never reaches
    // `apply_outcome_status`, which is where a completed pass refreshes the advisory condition.
    // Without this, a stale `PolicyAdvisory=True` from an earlier pass would outlive the violation
    // that produced it — and the advisories of the refused bundle itself would never be shown.
    if let Some(condition) = policy_advisory_for_failure(status, generation, err, timestamp) {
        status.set_condition(condition);
    }
}

/// The `PolicyAdvisory` condition to write on a **refused** pass (`T20.2`, finding M7).
///
/// Returns `None` for every error that is not a policy refusal, and for a refusal with no rule in
/// force that also has no advisory on `/status` — an `Application` that never had a policy must not
/// gain a condition it did not have before `T20.2`. A stale advisory *is* cleared, exactly like the
/// success path does.
fn policy_advisory_for_failure(
    status: &ApplicationStatus,
    generation: Option<i64>,
    err: &ReconcileError,
    timestamp: Time,
) -> Option<Condition> {
    let ReconcileError::PolicyGate(refusal) = err else {
        return None;
    };
    if refusal.rules == 0
        && status
            .condition(ferriscd_engine::policy::CONDITION_POLICY_ADVISORY)
            .is_none()
    {
        return None;
    }
    Some(ferriscd_engine::policy::policy_advisory_condition(
        &refusal.advisories,
        refusal.rules,
        refusal.advisories_omitted,
        generation,
        timestamp,
    ))
}

/// Runs the apply pipeline under the always-update-status wrapper.
///
/// This is the unit-testable core of the finalizer's `Event::Apply` branch: it performs no
/// API calls of its own beyond the injected [`StatusWriter`].
///
/// The failure path still persists everything the pipeline already confirmed
/// ([`ReconcileError::partial_status`]), so a create that succeeded before a later resource
/// failed stays in `status.inventory` instead of leaking as an untracked orphan (finding C1).
///
/// # Errors
///
/// Returns the pipeline error after the status patch was attempted, or the status-patch
/// error when the apply itself succeeded (a lost status update must be retried — otherwise
/// `observedGeneration` would silently stop advancing).
pub async fn apply_once(
    app: &Application,
    pipeline: &dyn SyncPipeline,
    status_writer: &dyn StatusWriter,
) -> Result<Action, ReconcileError> {
    apply_once_with_events(app, pipeline, status_writer, &EventRecorder::noop()).await
}

/// Runs the apply pipeline under the always-update-status wrapper and emits rate-limited
/// Kubernetes Events (`T15.2`: `Normal SyncSucceeded`, `Normal ResourcePruned`, and
/// `Warning SyncFailed`).
///
/// Event emission is strictly best-effort: a publisher error is logged at `warn!` and never fails
/// reconciliation.
///
/// # Errors
///
/// Returns the pipeline error after the status patch was attempted, or the status-patch error when
/// the apply itself succeeded.
pub async fn apply_once_with_events(
    app: &Application,
    pipeline: &dyn SyncPipeline,
    status_writer: &dyn StatusWriter,
    events: &EventRecorder,
) -> Result<Action, ReconcileError> {
    let generation = app.metadata.generation;
    let mut status = app.status.clone().unwrap_or_default();
    match pipeline.apply(app).await {
        Ok(outcome) => {
            record_success(&mut status, generation, &outcome, now());
            apply_outcome_status(&mut status, &outcome);
            // Re-enabling `spec.syncPolicy.automated` is exactly what the rollback warning asks the
            // operator to do, so the warning is cleared on the first pass that sees automation back
            // on (finding M-4: a stale warning trains operators to ignore warnings).
            //
            // A pass that *emitted* the warning must never clear it (finding C1): the rollback path
            // patches a **clone** of the spec, so `app.spec` still reports `automated` inside that
            // very pass. Clearing unconditionally would delete the warning — and with it the pin
            // (`pinned_rollback_revision` reads the warning) — on the pass that created it, which is
            // exactly the rollback-vs-`selfHeal` fight the warning exists to break.
            if outcome.warnings.is_empty()
                && ferriscd_engine::sync::clear_rollback_warning_if_automation_reenabled(
                    &app.spec,
                    &mut status,
                )
            {
                tracing::info!(
                    app.namespace = %app.namespace().unwrap_or_default(),
                    app.name = %app.name_any(),
                    "cleared the rollback warning: spec.syncPolicy.automated is enabled again"
                );
            }
            if let Err(patch_err) = status_writer.patch(app, status).await {
                events
                    .emit_sync_failed(app, failure_reason(&patch_err), &patch_err.to_string())
                    .await;
                return Err(patch_err);
            }
            if !outcome.pruned.is_empty() {
                events.emit_resource_pruned(app, &outcome.pruned).await;
            }
            // Emit `Normal SyncSucceeded` only when a sync execution actually settled — never on
            // no-op `SyncSkipped` periodic passes or mid-wave `SyncInProgress` passes.
            if outcome.reason == REASON_SYNC_SUCCEEDED {
                events.emit_sync_succeeded(app, &outcome.message).await;
            }
            Ok(Action::requeue(outcome.requeue.unwrap_or(DEFAULT_REQUEUE)))
        }
        Err(err) => {
            record_failure(&mut status, generation, &err, now());
            // Crash safety: a sync that half applied still persists the inventory it confirms,
            // so a create that succeeded can never become an untracked orphan (finding C1). An
            // ownership conflict carries the *unchanged* inventory and lands here too, which is
            // what surfaces it as `status.sync.status = OutOfSync` (T07.4 semantics).
            if let Some((inventory, revision)) = err.partial_status() {
                status.set_inventory(ferriscd_engine::inventory::to_status_entries(inventory));
                merge_sync_state(
                    &mut status,
                    SyncState {
                        status: SyncStatus::OutOfSync,
                        revision: revision.cloned(),
                        last_synced_revision: None,
                        last_synced_spec_hash: None,
                        last_synced_at: None,
                    },
                );
            }
            // Finding M4: a wave pass that failed after creating hooks still hands its
            // `activeHooks` records over, so the retry observes the object that already exists
            // instead of creating a second `generateName` hook (a second migration).
            if let Some(operation) = err.partial_operation() {
                status.operation_state = Some(operation.clone());
            }
            // Best effort: the reconcile error is the one the caller must see.
            if let Err(patch_err) = status_writer.patch(app, status).await {
                tracing::warn!(
                    app.namespace = %app.namespace().unwrap_or_default(),
                    app.name = %app.name_any(),
                    error = %patch_err,
                    "failed to patch status after a reconcile error"
                );
            }
            events
                .emit_sync_failed(app, failure_reason(&err), &err.to_string())
                .await;
            Err(err)
        }
    }
}

/// Persists the pipeline-reported inventory, sync state and health on `status`.
///
/// Only fields the pipeline actually reported are written: an outcome without them (for
/// example [`UnwiredSyncPipeline`]) must never clear state owned by another pass, and
/// `lastSynced*` markers are preserved by [`merge_sync_state`].
///
/// The per-resource list is **replaced**, not merged: it is this pass's assessment of exactly the
/// desired set, so a resource that was removed from Git (or from the cluster) must not keep a stale
/// summary in `status.resources` forever. The list is bounded by
/// [`ApplicationStatus::record_resource_status`], which also counts the overflow.
pub fn apply_outcome_status(status: &mut ApplicationStatus, outcome: &ApplyOutcome) {
    if let Some(inventory) = &outcome.inventory {
        status.set_inventory(ferriscd_engine::inventory::to_status_entries(inventory));
    }
    if let Some(sync) = &outcome.sync {
        merge_sync_state(status, sync.clone());
    }
    if let Some(health) = &outcome.health {
        status.health = Some(health.clone());
    }
    if let Some(resources) = &outcome.resources {
        status.resources.clear();
        status.resources_omitted = 0;
        for resource in resources {
            status.record_resource_status(resource.clone());
        }
    }
    // `operationState` is the crash-safe progress record of a multi-wave/hook sync (`T10.1`), so it
    // is written on **every** pass of one — including a pass that only observed a `Progressing` wave
    // and applied nothing. That is what makes a controller restart resume at `(phase, wave)`.
    if let Some(operation) = &outcome.operation_state {
        status.operation_state = Some(operation.clone());
    }
    // `history` is authoritative when present: the engine bounds it to
    // `min(revisionHistoryLimit, MAX_HISTORY_ENTRIES)`, so replacing the array can never grow
    // `/status` past its budget.
    if let Some(history) = &outcome.history {
        status.history = history.clone();
    }
    for warning in &outcome.warnings {
        status.set_condition(warning.clone());
    }
    // `T20.2`: the policy advisory is refreshed on every pass, so a stale `PolicyAdvisory=True`
    // cannot outlive the violation that produced it.
    if let Some(advisories) = &outcome.policy_advisories {
        status.set_condition(advisories.clone());
    }
}

/// Merges `next` into `status.sync`, preserving `lastSynced*` markers it did not set.
///
/// A reconcile that reports "still out of sync" reports only the revision it just read; the
/// last successful sync markers belong to an earlier (successful) pass and must survive, or
/// `selfHeal: false` drift detection would forget what it already deployed (finding H7).
pub fn merge_sync_state(status: &mut ApplicationStatus, next: SyncState) {
    let previous = status.sync.take();
    let mut merged = next;
    if merged.last_synced_revision.is_none() {
        merged.last_synced_revision = previous
            .as_ref()
            .and_then(|previous| previous.last_synced_revision.clone());
    }
    if merged.last_synced_spec_hash.is_none() {
        merged.last_synced_spec_hash = previous
            .as_ref()
            .and_then(|previous| previous.last_synced_spec_hash.clone());
    }
    if merged.last_synced_at.is_none() {
        merged.last_synced_at = previous
            .as_ref()
            .and_then(|previous| previous.last_synced_at.clone());
    }
    status.sync = Some(merged);
}

/// Runs the cleanup pipeline through the finalizer gate.
///
/// # Errors
///
/// Returns the cleanup error while the finalizer must be retained; a released finalizer
/// always returns `Ok`.
pub async fn cleanup_once(
    app: &Application,
    pipeline: &dyn SyncPipeline,
    status_writer: &dyn StatusWriter,
) -> Result<Action, ReconcileError> {
    cleanup_once_with_events(app, pipeline, status_writer, &EventRecorder::noop()).await
}

/// Runs the cleanup pipeline through the finalizer gate and clears per-`Application` event
/// deduplication state when the finalizer is released (`T15.2`).
///
/// # Errors
///
/// Returns the cleanup error while the finalizer must be retained; a released finalizer always
/// returns `Ok`.
pub async fn cleanup_once_with_events(
    app: &Application,
    pipeline: &dyn SyncPipeline,
    status_writer: &dyn StatusWriter,
    events: &EventRecorder,
) -> Result<Action, ReconcileError> {
    let generation = app.metadata.generation;
    let mode = cleanup_mode(app);
    let result = pipeline.cleanup(app, mode).await;

    match cleanup_disposition(app, result) {
        CleanupDisposition::Release { warning } => {
            if let Some(warning) = &warning {
                tracing::warn!(
                    app.namespace = %app.namespace().unwrap_or_default(),
                    app.name = %app.name_any(),
                    cleanup_mode = ?mode,
                    reason = %warning,
                    "releasing the finalizer with a warning"
                );
            }
            let mut status = app.status.clone().unwrap_or_default();
            status.observed_generation = generation;
            if let Some(warning) = warning {
                status.set_condition(
                    Condition::ready(
                        ConditionStatus::False,
                        REASON_CLEANUP_SKIPPED,
                        bounded(&warning),
                        now(),
                    )
                    .with_observed_generation(generation),
                );
            }
            if let Err(patch_err) = status_writer.patch(app, status).await {
                tracing::warn!(
                    app.namespace = %app.namespace().unwrap_or_default(),
                    app.name = %app.name_any(),
                    error = %patch_err,
                    "failed to patch status while releasing the finalizer"
                );
            }
            // The object is going away, so whatever this writer and the event deduplicator
            // remember about it must go too (`T15.1` gauges, `T15.2` warning dedup state).
            status_writer.forget_app(app);
            events.forget_app(app);
            Ok(Action::await_change())
        }
        CleanupDisposition::Retain { error } => {
            let mut status = app.status.clone().unwrap_or_default();
            record_failure(&mut status, generation, &error, now());
            if let Err(patch_err) = status_writer.patch(app, status).await {
                tracing::warn!(
                    app.namespace = %app.namespace().unwrap_or_default(),
                    app.name = %app.name_any(),
                    error = %patch_err,
                    "failed to patch status while retaining the finalizer"
                );
            }
            Err(error)
        }
    }
}

/// Controller reconciler: finalizer gate around [`apply_once`]/[`cleanup_once`].
///
/// # Errors
///
/// Returns [`ControllerError`] carrying the retry classification consumed by the
/// controller's `error_policy`.
pub async fn reconcile_instance(
    app: Arc<Application>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, ControllerError> {
    let span = crate::reconcile_span(&app);
    reconcile_inner(app, ctx).instrument(span).await
}

async fn reconcile_inner(
    app: Arc<Application>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, ControllerError> {
    // `T15.1`: the reconcile histogram/counter and the in-flight gauge. Without a wired recorder
    // (hermetic tests, `RunOptions::metrics_addr = None`) the pass runs exactly as before.
    let Some(metrics) = ctx.metrics().cloned() else {
        return reconcile_gate(&app, &ctx).await;
    };
    let guard = metrics.start_reconcile();
    let result = reconcile_gate(&app, &ctx).await;
    // The result label comes only from the retry classification (`success|retryable|terminal`),
    // never from the error message.
    guard.finish(crate::metrics::ReconcileResult::of(&result));
    result
}

/// The finalizer gate itself: [`apply_once`]/[`cleanup_once`] wrapped in the object's own API.
async fn reconcile_gate(
    app: &Arc<Application>,
    ctx: &Arc<ReconcileContext>,
) -> Result<Action, ControllerError> {
    let key = object_key(app);
    // The finalizer helper patches the object it was handed, so it must use that object's own
    // namespace: a tenant `Application` (`T12.2`) does not live in the control-plane namespace.
    let api = ctx.apps_api_for(app);
    let inner_ctx = ctx.clone();

    let result = finalizer::finalizer(&api, FINALIZER, app.clone(), move |event| {
        let ctx = inner_ctx.clone();
        async move {
            match event {
                Event::Apply(object) => {
                    apply_once_with_events(&object, ctx.pipeline(), ctx.status(), ctx.events())
                        .await
                }
                Event::Cleanup(object) => {
                    cleanup_once_with_events(&object, ctx.pipeline(), ctx.status(), ctx.events())
                        .await
                }
            }
        }
        .boxed()
    })
    .await;

    match result {
        Ok(action) => {
            ctx.backoff().reset(&key);
            Ok(action)
        }
        Err(err) => Err(ControllerError::from(err)),
    }
}

/// Error returned by [`reconcile_instance`].
///
/// Flattens `kube_runtime::finalizer::Error<_>` (which cannot be nested inside the
/// reconciler's own error enum) into a message plus a retry classification, while keeping
/// the original error as the `source`.
#[derive(Debug)]
pub struct ControllerError {
    failure: FailureClass,
    message: String,
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl ControllerError {
    /// Retry classification used by the controller's backoff policy.
    #[must_use]
    pub fn failure(&self) -> FailureClass {
        self.failure
    }

    /// Wraps a bare reconcile error.
    #[must_use]
    pub fn from_reconcile(err: ReconcileError) -> Self {
        Self {
            failure: err.failure_class(),
            message: err.to_string(),
            source: Box::new(err),
        }
    }
}

impl std::fmt::Display for ControllerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ControllerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl From<finalizer::Error<ReconcileError>> for ControllerError {
    fn from(err: finalizer::Error<ReconcileError>) -> Self {
        let failure = match &err {
            finalizer::Error::ApplyFailed(inner) | finalizer::Error::CleanupFailed(inner) => {
                inner.failure_class()
            }
            // Patching `metadata.finalizers` failed: always worth retrying.
            finalizer::Error::AddFinalizer(_) | finalizer::Error::RemoveFinalizer(_) => {
                FailureClass::Retryable
            }
            // Malformed objects cannot be fixed by retrying.
            finalizer::Error::UnnamedObject | finalizer::Error::InvalidFinalizer => {
                FailureClass::Terminal
            }
        };
        Self {
            failure,
            message: err.to_string(),
            source: Box::new(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use ferriscd_crd::application::{
        DEFAULT_REQUEUE_AFTER_SECONDS, DEFAULT_REVISION_HISTORY_LIMIT,
    };
    use ferriscd_crd::status::{
        ActiveHook, CONDITION_READY, HealthState, HealthStatus, OperationPhase, ResourceStatus,
        RevisionHistoryEntry, SyncPhase, SyncState, SyncStatus,
    };
    use ferriscd_crd::{
        ApplicationSpec, AutomatedSyncPolicy, DEFAULT_PROJECT_NAME, DestinationSpec, GitSourceSpec,
        RendererSpec, SourceSpec, SyncPolicy,
    };
    use ferriscd_engine::inventory::{Inventory, InventoryEntry};
    use ferriscd_engine::manifest::ResourceKey;
    use kube::core::Status;

    use super::*;
    use crate::lock_recover;

    fn api_error(code: u16) -> kube::Error {
        kube::Error::Api(Status::failure("boom", "NotFound").with_code(code).boxed())
    }

    fn transport_error() -> kube::Error {
        kube::Error::Service("connection reset".into())
    }

    fn application(annotations: &[(&str, &str)]) -> Application {
        let spec = ApplicationSpec {
            project: DEFAULT_PROJECT_NAME.to_owned(),
            service_account_name: None,
            source: SourceSpec {
                git: Some(GitSourceSpec {
                    repo_url: "https://example.com/repo.git".to_owned(),
                    target_revision: "HEAD".to_owned(),
                    path: String::new(),
                }),
                oci: None,
                renderer: RendererSpec::default(),
            },
            destination: DestinationSpec {
                cluster: "in-cluster".to_owned(),
                namespace: "payments".to_owned(),
            },
            sync_policy: None,
            ignore_differences: Vec::new(),
            requeue_after_seconds: DEFAULT_REQUEUE_AFTER_SECONDS,
            revision_history_limit: DEFAULT_REVISION_HISTORY_LIMIT,
        };
        let mut app = Application::new("demo-app", spec);
        app.metadata.namespace = Some("ferriscd-system".to_owned());
        app.metadata.generation = Some(7);
        if !annotations.is_empty() {
            let mut map = std::collections::BTreeMap::new();
            for (key, value) in annotations {
                map.insert((*key).to_owned(), (*value).to_owned());
            }
            app.metadata.annotations = Some(map);
        }
        app
    }

    /// Pipeline whose apply/cleanup results are scripted by the test.
    ///
    /// `kube::Error` is not `Clone`, so scripted results are produced by factories instead of
    /// being stored.
    struct FakePipeline {
        apply: Box<dyn Fn() -> Result<ApplyOutcome, ReconcileError> + Send + Sync>,
        cleanup: Box<dyn Fn() -> Result<CleanupOutcome, ReconcileError> + Send + Sync>,
        cleanup_modes: StdMutex<Vec<CleanupMode>>,
    }

    impl FakePipeline {
        fn ready() -> Self {
            Self {
                apply: Box::new(|| Ok(ApplyOutcome::ready("SyncSucceeded", "applied 3 resources"))),
                cleanup: Box::new(|| Ok(CleanupOutcome::Completed)),
                cleanup_modes: StdMutex::new(Vec::new()),
            }
        }

        fn failing(make: impl Fn() -> ReconcileError + Send + Sync + 'static) -> Self {
            Self {
                apply: Box::new(move || Err(make())),
                ..Self::ready()
            }
        }

        fn with_cleanup(
            self,
            make: impl Fn() -> Result<CleanupOutcome, ReconcileError> + Send + Sync + 'static,
        ) -> Self {
            Self {
                cleanup: Box::new(make),
                ..self
            }
        }

        fn modes(&self) -> Vec<CleanupMode> {
            lock_recover(&self.cleanup_modes).clone()
        }
    }

    impl SyncPipeline for FakePipeline {
        fn apply<'a>(
            &'a self,
            _app: &'a Application,
        ) -> BoxFuture<'a, Result<ApplyOutcome, ReconcileError>> {
            let result = (self.apply)();
            Box::pin(async move { result })
        }

        fn cleanup<'a>(
            &'a self,
            _app: &'a Application,
            mode: CleanupMode,
        ) -> BoxFuture<'a, Result<CleanupOutcome, ReconcileError>> {
            lock_recover(&self.cleanup_modes).push(mode);
            let result = (self.cleanup)();
            Box::pin(async move { result })
        }
    }

    /// Status writer that records every patch instead of calling the API server.
    #[derive(Debug, Default)]
    struct RecordingStatusWriter {
        patches: StdMutex<Vec<ApplicationStatus>>,
        fail: bool,
    }

    impl RecordingStatusWriter {
        fn patches(&self) -> Vec<ApplicationStatus> {
            lock_recover(&self.patches).clone()
        }

        fn failing() -> Self {
            Self {
                fail: true,
                ..Self::default()
            }
        }
    }

    impl StatusWriter for RecordingStatusWriter {
        fn patch<'a>(
            &'a self,
            _app: &'a Application,
            status: ApplicationStatus,
        ) -> BoxFuture<'a, Result<(), ReconcileError>> {
            Box::pin(async move {
                if self.fail {
                    return Err(ReconcileError::Api(api_error(500)));
                }
                lock_recover(&self.patches).push(status);
                Ok(())
            })
        }
    }

    /// **Secret safety (trap T4):** a value the API server quoted back is never written to
    /// `/status` verbatim, and actionable prose survives the redaction.
    #[test]
    fn status_messages_redact_payload_looking_runs_and_stay_bounded() {
        let quoted = "Secret \"db\" is invalid: data[password]: Invalid value: \
                      \"c3VwZXItc2VjcmV0LXZhbHVlLXdpdGgtbG90cy1vZi1ieXRlcw==\": field is immutable";
        let rendered = bounded(quoted);
        assert!(
            !rendered.contains("c3VwZXItc2VjcmV0LXZhbHVlLXdpdGgtbG90cy1vZi1ieXRlcw=="),
            "the payload leaked: {rendered}"
        );
        assert!(rendered.contains("redacted"), "{rendered}");
        assert!(
            rendered.contains("field is immutable"),
            "prose must survive: {rendered}"
        );
        assert!(
            rendered.contains("ferriscd") || rendered.contains("Secret"),
            "{rendered}"
        );

        // A hyphenated annotation name and a manager name are not payloads.
        let prose = "add ferriscd.io/sync-options: Replace=true, or list \
                     kubectl-client-side-apply in syncOptions.takeoverFieldManagers";
        assert_eq!(bounded(prose), prose);

        // The bound still applies (prose, so nothing is redacted first).
        let long = "apply failed ".repeat(MAX_STATUS_MESSAGE_CHARS);
        assert_eq!(bounded(&long).chars().count(), MAX_STATUS_MESSAGE_CHARS + 1);
        assert!(bounded(&long).ends_with('…'));

        // An unbroken opaque run is redacted *and* the result stays small.
        let opaque = "A".repeat(400);
        assert_eq!(bounded(&opaque), "<redacted 400 char(s)>");
    }

    #[test]
    fn cleanup_defaults_to_non_cascading_orphan() {
        assert_eq!(cleanup_mode(&application(&[])), CleanupMode::Orphan);
        assert_eq!(
            cleanup_mode(&application(&[(annotations::CASCADE_DELETE, "false")])),
            CleanupMode::Orphan
        );
        assert_eq!(
            cleanup_mode(&application(&[(annotations::CASCADE_DELETE, "true")])),
            CleanupMode::Cascade
        );
        assert!(!force_delete(&application(&[])));
        assert!(force_delete(&application(&[(
            annotations::FORCE_DELETE,
            "true"
        )])));
    }

    #[test]
    fn already_deleted_targets_release_the_finalizer() {
        for err in [
            ReconcileError::Api(api_error(404)),
            ReconcileError::Api(api_error(410)),
            ReconcileError::Discovery(DiscoveryError::NoMatchesForKind {
                group: "apps".to_owned(),
                version: "v1".to_owned(),
                kind: "Deployment".to_owned(),
            }),
        ] {
            assert!(err.is_already_deleted(), "{err} must count as deleted");
            match cleanup_disposition(&application(&[]), Err(err)) {
                CleanupDisposition::Release { warning } => assert!(warning.is_none()),
                other => panic!("expected release, got {other:?}"),
            }
        }
    }

    #[test]
    fn missing_destination_secret_releases_with_a_warning() {
        let disposition = cleanup_disposition(
            &application(&[]),
            Ok(CleanupOutcome::TargetUnavailable {
                message: "secret ferriscd/prod-cluster not found".to_owned(),
            }),
        );
        match disposition {
            CleanupDisposition::Release {
                warning: Some(warning),
            } => {
                assert!(warning.contains("prod-cluster"), "{warning}");
            }
            other => panic!("expected a warned release, got {other:?}"),
        }
    }

    #[test]
    fn force_delete_releases_even_after_a_cleanup_failure() {
        let failure = ReconcileError::Invalid {
            message: "prune hook exploded".to_owned(),
        };

        // Without the escape hatch the finalizer is retained.
        match cleanup_disposition(
            &application(&[]),
            Err(ReconcileError::Invalid {
                message: "prune hook exploded".to_owned(),
            }),
        ) {
            CleanupDisposition::Retain { error } => assert!(error.to_string().contains("exploded")),
            other => panic!("expected retention, got {other:?}"),
        }

        let forced = application(&[(annotations::FORCE_DELETE, "true")]);
        match cleanup_disposition(&forced, Err(failure)) {
            CleanupDisposition::Release {
                warning: Some(warning),
            } => {
                assert!(warning.contains(annotations::FORCE_DELETE), "{warning}");
                assert!(warning.contains("exploded"), "{warning}");
            }
            other => panic!("expected a forced release, got {other:?}"),
        }
    }

    #[test]
    fn successful_cleanup_releases_silently() {
        match cleanup_disposition(&application(&[]), Ok(CleanupOutcome::Completed)) {
            CleanupDisposition::Release { warning } => assert!(warning.is_none()),
            other => panic!("expected release, got {other:?}"),
        }
    }

    #[test]
    fn retryable_and_terminal_errors_are_classified() {
        let cases: Vec<(ReconcileError, FailureClass)> = vec![
            (ReconcileError::Api(api_error(500)), FailureClass::Retryable),
            (ReconcileError::Api(api_error(503)), FailureClass::Retryable),
            (ReconcileError::Api(api_error(429)), FailureClass::Retryable),
            (ReconcileError::Api(api_error(408)), FailureClass::Retryable),
            (ReconcileError::Api(api_error(409)), FailureClass::Retryable),
            (ReconcileError::Api(api_error(425)), FailureClass::Retryable),
            (
                ReconcileError::Api(transport_error()),
                FailureClass::Retryable,
            ),
            (ReconcileError::Api(api_error(404)), FailureClass::Terminal),
            (ReconcileError::Api(api_error(422)), FailureClass::Terminal),
            (
                ReconcileError::Discovery(DiscoveryError::Refresh {
                    message: "timeout".to_owned(),
                }),
                FailureClass::Retryable,
            ),
            (
                ReconcileError::Discovery(DiscoveryError::NoMatchesForKind {
                    group: "apps".to_owned(),
                    version: "v1".to_owned(),
                    kind: "Deployment".to_owned(),
                }),
                FailureClass::Terminal,
            ),
            (
                ReconcileError::Scope(ScopeError::UnknownScope {
                    gvk: "example.com/v1/Widget".to_owned(),
                }),
                FailureClass::Terminal,
            ),
            (
                ReconcileError::Invalid {
                    message: "bad repo URL".to_owned(),
                },
                FailureClass::Terminal,
            ),
            // `T20.2`: a policy gate refusal is deterministic — the manifests or the rule must
            // change — so it is terminal, exactly like a project denial.
            (
                ReconcileError::PolicyGate(Box::new(PolicyGateRefusal {
                    message: "policy gate: privileged containers are forbidden".to_owned(),
                    violations: Vec::new(),
                    advisories: Vec::new(),
                    rules: 1,
                    advisories_omitted: 0,
                    inventory: Inventory::new(),
                    revision: Some("deadbeef".to_owned()),
                })),
                FailureClass::Terminal,
            ),
            // Trap T10: another `Application` owns the object, so no amount of retrying helps.
            (
                ReconcileError::OwnershipConflict {
                    message: "owned by ferriscd-system/other".to_owned(),
                    inventory: Inventory::new(),
                    revision: Some("deadbeef".to_owned()),
                },
                FailureClass::Terminal,
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(err.failure_class(), expected, "unexpected class for {err}");
        }

        // A failed `dryRun=All` classification is classified exactly like the apply path's API
        // errors (finding M2): transient conditions back off, the rest is terminal.
        let diff_error = |code: u16| {
            ReconcileError::Diff(crate::dry_run::DryRunError::Api {
                resource: "apps/Deployment/payments/api".to_owned(),
                code,
                message: "boom".to_owned(),
            })
        };
        for code in [0u16, 408, 409, 425, 429, 500, 503] {
            assert_eq!(
                diff_error(code).failure_class(),
                FailureClass::Retryable,
                "a {code} dry-run must back off and retry"
            );
        }
        for code in [403u16, 404, 422] {
            assert_eq!(
                diff_error(code).failure_class(),
                FailureClass::Terminal,
                "a {code} dry-run cannot succeed by retrying"
            );
        }
        // An unserved kind and an unserializable document are terminal too: neither converges.
        for err in [
            crate::dry_run::DryRunError::Discovery(DiscoveryError::NoMatchesForKind {
                group: "example.com".to_owned(),
                version: "v1".to_owned(),
                kind: "Widget".to_owned(),
            }),
            crate::dry_run::DryRunError::Serialization {
                resource: "apps/Deployment/payments/api".to_owned(),
                message: "nope".to_owned(),
            },
        ] {
            assert_eq!(
                ReconcileError::Diff(err).failure_class(),
                FailureClass::Terminal
            );
        }
    }

    #[test]
    fn failure_reasons_are_specific_and_actionable() {
        assert_eq!(
            failure_reason(&ReconcileError::Api(api_error(404))),
            REASON_NOT_FOUND
        );
        assert_eq!(
            failure_reason(&ReconcileError::Api(api_error(500))),
            REASON_SYNC_ERROR
        );
        assert_eq!(
            failure_reason(&ReconcileError::Discovery(
                DiscoveryError::NoMatchesForKind {
                    group: "apps".to_owned(),
                    version: "v1".to_owned(),
                    kind: "Deployment".to_owned(),
                }
            )),
            REASON_NO_MATCHES_FOR_KIND
        );
        assert_eq!(
            failure_reason(&ReconcileError::Scope(ScopeError::UnknownScope {
                gvk: "example.com/v1/Widget".to_owned(),
            })),
            REASON_INVALID_SPEC
        );
        // A project denial is its own condition reason: it is a tenancy decision, not a spec typo.
        let policy =
            ReconcileError::Policy(ferriscd_engine::policy::PolicyError::ProjectNotFound {
                project: "payments".to_owned(),
                namespace: "ferriscd-system".to_owned(),
                application: "ferriscd-system/demo".to_owned(),
            });
        assert_eq!(failure_reason(&policy), REASON_POLICY_VIOLATION);
        assert_eq!(policy.failure_class(), FailureClass::Terminal);
        assert!(!policy.is_already_deleted());
        assert!(
            policy.partial_status().is_none(),
            "a policy denial happens before any mutation, so there is no inventory to persist"
        );

        // `T20.2`: a pre-sync policy refusal has its own reason, and it carries the unchanged
        // inventory + revision so `/status` still reports `OutOfSync` without clearing
        // `lastSyncedRevision`.
        let gate = ReconcileError::PolicyGate(Box::new(PolicyGateRefusal {
            message: "policy gate: 1 blocking violation(s)".to_owned(),
            violations: vec![ferriscd_engine::policy::PolicyViolation {
                rule: "no-privileged".to_owned(),
                enforcement: ferriscd_engine::policy::PolicyEnforcement::Enforce,
                resource_key: "apps/Deployment/payments/api".to_owned(),
                message: "privileged containers are forbidden".to_owned(),
            }],
            advisories: Vec::new(),
            rules: 1,
            advisories_omitted: 0,
            inventory: Inventory::new(),
            revision: Some("deadbeef".to_owned()),
        }));
        assert_eq!(failure_reason(&gate), REASON_POLICY_GATE_VIOLATION);
        assert_ne!(
            failure_reason(&gate),
            REASON_POLICY_VIOLATION,
            "a manifest-invariant denial must be distinguishable from a project denial"
        );
        assert_eq!(gate.failure_class(), FailureClass::Terminal);
        assert!(!gate.is_already_deleted());
        assert!(
            gate.partial_status().is_some(),
            "the unchanged inventory must still reach `/status` as `OutOfSync`"
        );
        assert!(
            gate.to_string().contains("priv") || gate.to_string().contains("policy gate"),
            "{gate}"
        );

        // `T12.3`: an unusable ServiceAccount identity is a spec problem, and it is just as
        // terminal — the alternative (deploying as the controller) is a privilege escalation.
        let impersonation = ReconcileError::Impersonation(
            crate::impersonation::ImpersonationError::InvalidServiceAccountName {
                service_account: "Deployer".to_owned(),
            },
        );
        assert_eq!(failure_reason(&impersonation), REASON_INVALID_SPEC);
        assert_eq!(impersonation.failure_class(), FailureClass::Terminal);
        assert!(!impersonation.is_already_deleted());
        assert!(
            impersonation.partial_status().is_none(),
            "an impersonation refusal happens before any mutation"
        );
        assert!(
            impersonation.to_string().contains("Deployer"),
            "the message must name the rejected name: {impersonation}"
        );

        // `T12.4`: an unusable repository credential `Secret` is the operator's configuration to
        // fix, so it gets the spec reason instead of the generic `SyncError` (finding M-5).
        let credentials =
            ReconcileError::Credentials(crate::credentials::CredentialError::Malformed {
                secret: "repo-creds".to_owned(),
                namespace: "ferriscd-system".to_owned(),
                reason: "both password and token are set".to_owned(),
            });
        assert_eq!(failure_reason(&credentials), REASON_INVALID_SPEC);
        assert_eq!(credentials.failure_class(), FailureClass::Terminal);
        assert!(!credentials.is_already_deleted());
        assert!(
            credentials.partial_status().is_none(),
            "a credential error happens before the clone, so there is no inventory to persist"
        );
        // The offending `Secret` is named; no credential value is (there is none in the error).
        assert!(
            credentials.to_string().contains("repo-creds"),
            "{credentials}"
        );
    }

    /// **`T12.3` trap guard:** refusing an `Application` because its `ServiceAccount` cannot be
    /// impersonated must behave exactly like a policy denial: `Ready=False` with an actionable
    /// reason, and the previous good inventory untouched.
    #[tokio::test]
    async fn an_impersonation_refusal_fails_the_reconcile_without_touching_the_inventory() {
        let mut app = application(&[]);
        let mut status = ApplicationStatus {
            inventory: vec![ferriscd_crd::InventoryEntry::new(
                "/ConfigMap/payments/kept",
                "v1",
            )],
            ..ApplicationStatus::default()
        };
        status.observed_generation = Some(1);
        app.status = Some(status);
        app.metadata.generation = Some(2);
        let pipeline = FakePipeline::failing(|| {
            ReconcileError::Impersonation(crate::impersonation::ImpersonationError::NotWired {
                service_account: "system:serviceaccount:payments:deployer".to_owned(),
            })
        });
        let writer = RecordingStatusWriter::default();

        let err = apply_once(&app, &pipeline, &writer)
            .await
            .expect_err("a refusal must fail the reconcile");
        assert!(matches!(err, ReconcileError::Impersonation(_)), "{err:?}");

        let patched = writer.patches();
        assert_eq!(
            patched.len(),
            1,
            "the always-update-status contract holds for this failure class too"
        );
        let status = &patched[0];
        assert_eq!(status.observed_generation, Some(2));
        let ready = status
            .condition(CONDITION_READY)
            .expect("a Ready condition must be written");
        assert_eq!(ready.status, ConditionStatus::False);
        assert_eq!(ready.reason, REASON_INVALID_SPEC);
        assert!(
            ready
                .message
                .contains("system:serviceaccount:payments:deployer"),
            "the operator must see which identity was refused: {}",
            ready.message
        );
        assert_eq!(
            status.inventory,
            vec![ferriscd_crd::InventoryEntry::new(
                "/ConfigMap/payments/kept",
                "v1"
            )],
            "a refusal must never corrupt the inventory of the last good pass"
        );
        assert!(
            status.sync.is_none(),
            "a refusal must not claim a sync state it never reached"
        );
    }

    #[tokio::test]
    async fn a_policy_denial_fails_the_reconcile_without_touching_the_inventory() {
        // `T12.1`: a denial must never look like a successful sync, and it must not corrupt the
        // crash-safe inventory of a previous good pass.
        let mut app = application(&[]);
        let mut status = ApplicationStatus {
            inventory: vec![ferriscd_crd::InventoryEntry::new(
                "/ConfigMap/payments/kept",
                "v1",
            )],
            ..ApplicationStatus::default()
        };
        status.observed_generation = Some(1);
        app.status = Some(status);
        app.metadata.generation = Some(2);
        let pipeline = FakePipeline::failing(|| {
            ReconcileError::Policy(ferriscd_engine::policy::PolicyError::SourceRepoNotAllowed {
                application: "ferriscd-system/demo".to_owned(),
                project: "payments".to_owned(),
                repo_url: "https://github.com/evil/demo.git".to_owned(),
            })
        });
        let writer = RecordingStatusWriter::default();

        let err = apply_once(&app, &pipeline, &writer)
            .await
            .expect_err("a policy denial must fail the reconcile");
        assert!(matches!(err, ReconcileError::Policy(_)), "{err:?}");

        let patched = writer.patches();
        assert_eq!(patched.len(), 1, "the always-update-status contract holds");
        let status = &patched[0];
        assert_eq!(status.observed_generation, Some(2));
        let ready = status
            .conditions
            .iter()
            .find(|condition| condition.type_ == "Ready")
            .expect("a Ready condition must be written");
        assert_eq!(ready.reason, REASON_POLICY_VIOLATION);
        assert_eq!(
            status.inventory,
            vec![ferriscd_crd::InventoryEntry::new(
                "/ConfigMap/payments/kept",
                "v1"
            )],
            "the inventory of the last good pass must survive a denial"
        );
        assert!(
            status.sync.is_none(),
            "a denial must not claim a sync state it never reached"
        );
    }

    /// **`T20.2` trap guard:** a policy gate refusal must be terminal, must leave the inventory of
    /// the last good pass untouched, must report `OutOfSync` — and must **keep
    /// `lastSyncedRevision`**. A refused pass that cleared that marker would look like an
    /// `Application` that never deployed anything, and a subsequent `selfHeal` pass could no longer
    /// tell what it had already shipped.
    #[tokio::test]
    async fn a_policy_gate_refusal_keeps_the_last_synced_revision_and_the_inventory() {
        let mut app = application(&[]);
        app.status = Some(inventory_status());
        app.metadata.generation = Some(9);
        // The pipeline reports the inventory it started from: nothing was applied, so nothing
        // changed (this is `prepare_pass`'s `prev_inventory`).
        let mut kept = Inventory::new();
        kept.insert(
            ResourceKey::new("apps", "Deployment", Some("payments".to_owned()), "old"),
            InventoryEntry::new("v1"),
        );
        let reported = kept.clone();
        let pipeline = FakePipeline::failing(move || {
            ReconcileError::PolicyGate(Box::new(PolicyGateRefusal {
                message: "policy gate: 1 blocking, 0 advisory violation(s): no-privileged on \
                          apps/Deployment/payments/api: privileged containers are forbidden"
                    .to_owned(),
                violations: vec![ferriscd_engine::policy::PolicyViolation {
                    rule: "no-privileged".to_owned(),
                    enforcement: ferriscd_engine::policy::PolicyEnforcement::Enforce,
                    resource_key: "apps/Deployment/payments/api".to_owned(),
                    message: "privileged containers are forbidden".to_owned(),
                }],
                advisories: Vec::new(),
                rules: 1,
                advisories_omitted: 0,
                inventory: reported.clone(),
                revision: Some("newsha".to_owned()),
            }))
        });
        let writer = RecordingStatusWriter::default();

        let err = apply_once(&app, &pipeline, &writer)
            .await
            .expect_err("a policy gate refusal must fail the reconcile");
        assert!(matches!(err, ReconcileError::PolicyGate(_)), "{err:?}");

        let patched = writer.patches();
        assert_eq!(patched.len(), 1, "the always-update-status contract holds");
        let status = &patched[0];
        assert_eq!(status.observed_generation, Some(9));

        let ready = status
            .conditions
            .iter()
            .find(|condition| condition.type_ == ferriscd_crd::status::CONDITION_READY)
            .expect("a Ready condition must be written");
        assert_eq!(ready.status, ferriscd_crd::status::ConditionStatus::False);
        assert_eq!(
            ready.reason, REASON_POLICY_GATE_VIOLATION,
            "an operator must be able to tell a policy refusal from a project denial"
        );
        assert!(
            ready.message.contains("no-privileged"),
            "the condition must name the rule: {}",
            ready.message
        );

        let sync = status
            .sync
            .as_ref()
            .expect("a refused pass reports OutOfSync, never nothing");
        assert_eq!(sync.status, SyncStatus::OutOfSync);
        assert_eq!(
            sync.last_synced_revision.as_deref(),
            Some("oldsha"),
            "a policy refusal must never clear the last successful revision"
        );
        assert_eq!(sync.last_synced_spec_hash.as_deref(), Some("spec-hash"));
        assert_eq!(
            status
                .inventory
                .iter()
                .map(|entry| entry.key.as_str())
                .collect::<Vec<_>>(),
            vec!["apps/Deployment/payments/old"],
            "the inventory a refused pass reports is the unchanged one"
        );
        assert_eq!(
            status.history.len(),
            1,
            "a refused pass appends no history entry"
        );
    }

    /// **`T20.2` finding M10:** a *refused* pass writes the advisory condition too — and its count
    /// includes the advisories the gate's violation budget dropped.
    ///
    /// The refusal path never reaches `apply_outcome_status`, so it is the only place these
    /// advisories can surface. Before the fix the condition received the retained advisories only,
    /// so a refused pass whose list overflowed reported a truncated set as the whole story (or,
    /// when every advisory was evicted by blocking findings, claimed there were none).
    #[tokio::test]
    async fn a_refused_pass_reports_advisories_it_could_not_list() {
        let mut app = application(&[]);
        app.metadata.generation = Some(11);
        let pipeline = FakePipeline::failing(|| {
            ReconcileError::PolicyGate(Box::new(PolicyGateRefusal {
                message: "policy gate: 1 blocking, 5 advisory violation(s)".to_owned(),
                violations: vec![ferriscd_engine::policy::PolicyViolation {
                    rule: "no-privileged".to_owned(),
                    enforcement: ferriscd_engine::policy::PolicyEnforcement::Enforce,
                    resource_key: "apps/Deployment/payments/api".to_owned(),
                    message: "privileged containers are forbidden".to_owned(),
                }],
                // Every advisory was evicted by the blocking findings, so the retained advice list
                // is empty — and the count must still be five.
                advisories: Vec::new(),
                advisories_omitted: 5,
                rules: 2,
                inventory: Inventory::new(),
                revision: Some("newsha".to_owned()),
            }))
        });
        let writer = RecordingStatusWriter::default();
        apply_once(&app, &pipeline, &writer)
            .await
            .expect_err("a policy gate refusal must fail the reconcile");

        let status = &writer.patches()[0];
        let condition = status
            .condition(ferriscd_engine::policy::CONDITION_POLICY_ADVISORY)
            .expect("the refusal must write the advisory condition");
        assert_eq!(
            condition.status,
            ferriscd_crd::status::ConditionStatus::True,
            "five advisories were found, so the condition is `True`"
        );
        assert!(
            condition.message.contains('5'),
            "the message must report all five, not zero: {condition:?}"
        );
        assert_eq!(condition.observed_generation, Some(11));
    }

    /// The `T20.2` advisory condition is refreshed on **every** pass: `True` with the advisories and
    /// `False`/`PolicyCompliant` without, which is what clears a stale advisory.
    #[tokio::test]
    async fn the_policy_advisory_condition_is_refreshed_and_cleared() {
        let app = application(&[]);
        let timestamp = now();
        let advisory = |status, reason: &'static str, message: &'static str| {
            ApplyOutcome::ready("SyncSucceeded", "applied").with_policy_advisories(Some(
                Condition::new(
                    ferriscd_engine::policy::CONDITION_POLICY_ADVISORY,
                    status,
                    reason,
                    message,
                    timestamp.clone(),
                ),
            ))
        };

        // A pass with advisories writes `PolicyAdvisory=True`.
        let pipeline = FakePipeline {
            apply: Box::new(|| {
                Ok(
                    ApplyOutcome::ready("SyncSucceeded", "applied").with_policy_advisories(Some(
                        Condition::new(
                            ferriscd_engine::policy::CONDITION_POLICY_ADVISORY,
                            ferriscd_crd::status::ConditionStatus::True,
                            ferriscd_engine::policy::REASON_POLICY_ADVISORY,
                            "no-privileged: privileged containers are forbidden",
                            now(),
                        ),
                    )),
                )
            }),
            ..FakePipeline::ready()
        };
        let writer = RecordingStatusWriter::default();
        apply_once(&app, &pipeline, &writer)
            .await
            .expect("apply must succeed");
        let status = writer.patches()[0].clone();
        let condition = status
            .condition(ferriscd_engine::policy::CONDITION_POLICY_ADVISORY)
            .expect("the advisory must be persisted");
        assert_eq!(
            condition.status,
            ferriscd_crd::status::ConditionStatus::True
        );
        assert!(condition.message.contains("privileged"), "{condition:?}");

        // The next compliant pass overwrites it with `False`/`PolicyCompliant`.
        let mut app = app;
        app.status = Some(status);
        let cleared = advisory(
            ferriscd_crd::status::ConditionStatus::False,
            ferriscd_engine::policy::REASON_POLICY_COMPLIANT,
            "no policy advisories",
        );
        let pipeline = FakePipeline {
            apply: Box::new(move || Ok(cleared.clone())),
            ..FakePipeline::ready()
        };
        let writer = RecordingStatusWriter::default();
        apply_once(&app, &pipeline, &writer)
            .await
            .expect("apply must succeed");
        let condition = writer.patches()[0]
            .condition(ferriscd_engine::policy::CONDITION_POLICY_ADVISORY)
            .cloned()
            .expect("the advisory condition must still be present");
        assert_eq!(
            condition.status,
            ferriscd_crd::status::ConditionStatus::False
        );
        assert_eq!(
            condition.reason,
            ferriscd_engine::policy::REASON_POLICY_COMPLIANT
        );
    }

    /// **`T15.1` wiring:** the sync/health gauges describe the `/status` a pass **persisted** (via
    /// [`crate::metrics::MetricsStatusWriter`]), for a successful and a failed pass alike — those
    /// are the two paths the always-update-status contract patches.
    #[tokio::test]
    async fn the_metrics_status_writer_records_the_persisted_sync_and_health_status() {
        use crate::metrics::{Metrics, MetricsStatusWriter};

        let app = application(&[]);
        let metrics = Metrics::with_fixed_series();
        let writer =
            MetricsStatusWriter::new(Arc::new(RecordingStatusWriter::default()), metrics.clone());
        let pipeline = FakePipeline {
            apply: Box::new(|| {
                Ok(ApplyOutcome::ready("SyncSucceeded", "applied")
                    .with_sync(SyncState::new(
                        SyncStatus::OutOfSync,
                        Some("deadbeef".to_owned()),
                    ))
                    .with_health(HealthState::new(HealthStatus::Degraded), Vec::new()))
            }),
            ..FakePipeline::ready()
        };

        apply_once(&app, &pipeline, &writer)
            .await
            .expect("apply must succeed");

        let body = metrics.encode().expect("the registry encodes");
        let samples = crate::metrics::exposition::parse(&body);
        for (family, status) in [
            (crate::metrics::APP_SYNC_STATUS, "OutOfSync"),
            (crate::metrics::APP_HEALTH_STATUS, "Degraded"),
        ] {
            assert_eq!(
                crate::metrics::exposition::value_of(
                    &samples,
                    family,
                    &[
                        ("app_namespace", "ferriscd-system"),
                        ("app_name", "demo-app"),
                        ("status", status),
                    ],
                    &body
                ),
                "1",
                "{family} must report the status the pass persisted:\n{body}"
            );
        }

        // A failed pass still patches `/status` (trap T3), and its message routinely names a commit
        // or a URL. None of that may become a label, and a pass that reports no sync/health state
        // must not invent one: the gauges stay empty rather than claiming a status nobody observed.
        let failed_metrics = Metrics::with_fixed_series();
        let failed_writer = MetricsStatusWriter::new(
            Arc::new(RecordingStatusWriter::default()),
            failed_metrics.clone(),
        );
        let failing = FakePipeline::failing(|| ReconcileError::Invalid {
            message: "commit_sha=deadbeef is not reachable".to_owned(),
        });
        assert!(
            apply_once(&app, &failing, &failed_writer).await.is_err(),
            "the failure must surface"
        );
        let body = failed_metrics.encode().expect("the registry encodes");
        assert!(
            !body.contains("commit_sha"),
            "the error message must never reach a label:\n{body}"
        );
        assert!(
            crate::metrics::exposition::samples_of(
                &crate::metrics::exposition::parse(&body),
                crate::metrics::APP_SYNC_STATUS
            )
            .is_empty(),
            "a pass that reported no sync state must not create a status series:\n{body}"
        );
    }

    /// A `kube::Client` over a service that never dials out.
    ///
    /// The finalizer helper's `PATCH` is issued and its empty response body fails to decode, so a
    /// `reconcile_instance` over it runs every wiring step (including the metrics guard) and ends
    /// in an error instead of needing a cluster.
    fn offline_client() -> Client {
        Client::new(
            tower::service_fn(|_request| async {
                Ok::<_, std::convert::Infallible>(http::Response::new(kube::client::Body::empty()))
            }),
            "ferriscd-system",
        )
    }

    /// **Verification bullet (`T15.1`, reconcile path):** a whole pass through
    /// [`reconcile_instance`] is recorded by the recorder wired into the context — one `result`
    /// observation, one histogram count, and an `active_reconciles` gauge that returned to zero.
    ///
    /// Removing the guard from `reconcile_inner` (or the `.with_metrics`) leaves every series at
    /// zero, and the removed guard is the only thing that would ever produce `active_reconciles 1`.
    #[tokio::test]
    async fn a_reconcile_is_counted_through_the_wired_recorder() {
        use std::collections::BTreeSet;

        use crate::metrics::exposition::Sample;
        use crate::metrics::{
            ACTIVE_RECONCILES, APP_HEALTH_STATUS, APP_SYNC_STATUS, GIT_FETCH_DURATION_SECONDS,
            Metrics, RECONCILE_DURATION_SECONDS, RECONCILE_TOTAL, RENDER_CACHE_TOTAL, exposition,
        };

        let metrics = Metrics::with_fixed_series();
        let ctx = Arc::new(
            ReconcileContext::new(
                Api::namespaced(offline_client(), "ferriscd-system"),
                Arc::new(UnwiredSyncPipeline),
                Arc::new(RecordingStatusWriter::default()),
            )
            .with_metrics(metrics.clone()),
        );

        // An `Err` is the expected outcome: adding the finalizer is the first write of the pass, and
        // the offline client answers it with a body that does not decode.
        let result = reconcile_instance(Arc::new(application(&[])), ctx).await;
        assert!(
            result.is_err(),
            "the offline API cannot patch the finalizer: {result:?}"
        );

        let body = metrics.encode().expect("the registry encodes");
        let samples = exposition::parse(&body);

        // Exactly one `result` series carries the pass (the others stay at the zero
        // `with_fixed_series` prepared), and the value is exactly one observation.
        let counted: Vec<(&str, &str)> = samples
            .iter()
            .filter(|sample| sample.name == RECONCILE_TOTAL)
            .filter_map(|sample| {
                sample
                    .label("result")
                    .map(|result| (result, sample.value.as_str()))
            })
            .filter(|(_, value)| *value != "0")
            .collect();
        assert_eq!(
            counted.len(),
            1,
            "one pass must be counted exactly once:\n{body}"
        );
        assert_eq!(
            counted[0].1, "1",
            "the counter is incremented once:\n{body}"
        );
        assert_eq!(
            exposition::value_of(
                &samples,
                &format!("{RECONCILE_DURATION_SECONDS}_count"),
                &[("result", counted[0].0)],
                &body
            ),
            "1",
            "the histogram observed the same single pass:\n{body}"
        );
        assert_eq!(
            exposition::value_of(&samples, ACTIVE_RECONCILES, &[], &body),
            "0",
            "the guard must release the in-flight gauge:\n{body}"
        );

        // Every pre-instantiated family is exposed, and the per-`Application` ones are not: this
        // pass persisted no sync/health state, so no status series may be invented.
        let families: BTreeSet<&str> = samples.iter().map(Sample::family).collect();
        let expected: BTreeSet<&str> = [
            RECONCILE_DURATION_SECONDS,
            RECONCILE_TOTAL,
            GIT_FETCH_DURATION_SECONDS,
            RENDER_CACHE_TOTAL,
            ACTIVE_RECONCILES,
            crate::metrics::RBAC_RELOAD_TOTAL,
            crate::metrics::RBAC_WATCH_ERRORS_TOTAL,
            crate::metrics::AUDIT_EVENTS_TOTAL,
            crate::metrics::AUDIT_DROPPED_TOTAL,
            // `T18.2`: the drift watcher's families are registered (and zero-instantiated) on every
            // replica, whether or not the opt-in watch is running.
            crate::metrics::DRIFT_FALLBACK_TOTAL,
            crate::metrics::DRIFT_EVENTS_TOTAL,
            crate::metrics::DRIFT_TRIGGERS_TOTAL,
            crate::metrics::DRIFT_ACTIVE_WATCHES,
            // `T19.4`: the notification families are pre-created too (a replica that has delivered
            // nothing still exposes them, as zeros).
            crate::metrics::NOTIFICATIONS_TOTAL,
            // `T18.4`: the source-fetch histogram is pre-created with a zero series per source kind,
            // so a replica that has fetched nothing still states which kinds it can fetch.
            crate::metrics::SOURCE_FETCH_DURATION_SECONDS,
        ]
        .into_iter()
        .collect();
        assert_eq!(families, expected, "{body}");
        assert!(
            !body.contains(APP_SYNC_STATUS) && !body.contains(APP_HEALTH_STATUS),
            "no status was persisted, so no status gauge may exist:\n{body}"
        );
    }

    /// **`T15.1` (deletion):** releasing the finalizer drops the object's status gauges, so a
    /// deleted `Application` cannot leave a series in the exposition forever.
    #[tokio::test]
    async fn a_released_cleanup_forgets_the_application_gauges() {
        use crate::metrics::{APP_HEALTH_STATUS, APP_SYNC_STATUS, Metrics, MetricsStatusWriter};

        let metrics = Metrics::with_fixed_series();
        let app = application(&[]);
        metrics.record_app_status(
            "ferriscd-system",
            "demo-app",
            &ApplicationStatus {
                sync: Some(SyncState::new(
                    SyncStatus::Synced,
                    Some("deadbeef".to_owned()),
                )),
                health: Some(HealthState::new(HealthStatus::Healthy)),
                ..ApplicationStatus::default()
            },
        );
        let body = metrics.encode().expect("encodes");
        assert_eq!(
            crate::metrics::exposition::samples_of(
                &crate::metrics::exposition::parse(&body),
                APP_SYNC_STATUS
            )
            .len(),
            3,
            "the gauges exist while the object does:\n{body}"
        );

        let writer =
            MetricsStatusWriter::new(Arc::new(RecordingStatusWriter::default()), metrics.clone());
        cleanup_once(&app, &FakePipeline::ready(), &writer)
            .await
            .expect("a completed cleanup releases the finalizer");

        let body = metrics.encode().expect("encodes");
        let samples = crate::metrics::exposition::parse(&body);
        for family in [APP_SYNC_STATUS, APP_HEALTH_STATUS] {
            assert!(
                crate::metrics::exposition::samples_of(&samples, family).is_empty(),
                "a deleted Application must not keep a {family} series:\n{body}"
            );
        }
    }

    #[tokio::test]
    async fn successful_apply_patches_status_with_a_ready_condition() {
        let app = application(&[]);
        let writer = RecordingStatusWriter::default();

        let action = apply_once(&app, &FakePipeline::ready(), &writer)
            .await
            .expect("apply must succeed");

        let patches = writer.patches();
        assert_eq!(patches.len(), 1, "exactly one status patch");
        let status = &patches[0];
        assert_eq!(status.observed_generation, Some(7));
        assert!(status.is_ready());
        let condition = status
            .condition(CONDITION_READY)
            .expect("Ready condition must be present");
        assert_eq!(condition.status, ConditionStatus::True);
        assert_eq!(condition.reason, "SyncSucceeded");
        assert_eq!(condition.observed_generation, Some(7));
        assert_eq!(action, Action::requeue(DEFAULT_REQUEUE));
    }

    #[tokio::test]
    async fn failed_apply_still_patches_status_with_ready_false() {
        let app = application(&[]);
        let writer = RecordingStatusWriter::default();
        let pipeline = FakePipeline::failing(|| ReconcileError::Invalid {
            message: "repository https://example.com/repo.git is unreachable".to_owned(),
        });

        let err = apply_once(&app, &pipeline, &writer)
            .await
            .expect_err("apply must surface the failure");

        let patches = writer.patches();
        assert_eq!(
            patches.len(),
            1,
            "the failure path must still patch /status"
        );
        let status = &patches[0];
        assert_eq!(status.observed_generation, Some(7));
        assert!(!status.is_ready());
        let condition = status
            .condition(CONDITION_READY)
            .expect("Ready condition must be present");
        assert_eq!(condition.status, ConditionStatus::False);
        assert_eq!(condition.reason, REASON_INVALID_SPEC);
        assert_eq!(condition.observed_generation, Some(7));
        assert!(
            condition.message.contains("unreachable"),
            "the message must be actionable: {}",
            condition.message
        );
        assert!(err.to_string().contains("unreachable"));
    }

    #[tokio::test]
    async fn status_patch_failure_after_a_successful_apply_is_retried() {
        let app = application(&[]);
        let writer = RecordingStatusWriter::failing();

        let err = apply_once(&app, &FakePipeline::ready(), &writer)
            .await
            .expect_err("a lost status update must be retried");
        assert_eq!(err.failure_class(), FailureClass::Retryable);
    }

    #[tokio::test]
    async fn status_is_preserved_across_reconciles() {
        let mut app = application(&[]);
        app.status = Some(ApplicationStatus {
            inventory: vec![ferriscd_crd::InventoryEntry::new(
                "apps/Deployment/payments/api",
                "apps/v1",
            )],
            ..ApplicationStatus::default()
        });
        let writer = RecordingStatusWriter::default();
        apply_once(&app, &FakePipeline::ready(), &writer)
            .await
            .expect("apply");

        let patches = writer.patches();
        assert_eq!(
            patches[0].inventory.len(),
            1,
            "fields owned by other phases must survive the status patch"
        );
    }

    #[test]
    fn long_condition_messages_are_bounded_and_utf8_safe() {
        let message = "é".repeat(MAX_STATUS_MESSAGE_CHARS * 3);
        let condition = failure_condition(Some(1), &ReconcileError::Invalid { message }, now());
        assert_eq!(
            condition.message.chars().count(),
            MAX_STATUS_MESSAGE_CHARS + 1,
            "the message is truncated plus an ellipsis"
        );
        assert!(condition.message.ends_with('…'));
    }

    #[tokio::test]
    async fn cleanup_passes_the_annotation_selected_mode_to_the_pipeline() {
        let writer = RecordingStatusWriter::default();

        let orphan = FakePipeline::ready();
        cleanup_once(&application(&[]), &orphan, &writer)
            .await
            .expect("orphan cleanup");
        assert_eq!(orphan.modes(), vec![CleanupMode::Orphan]);

        let cascade = FakePipeline::ready();
        cleanup_once(
            &application(&[(annotations::CASCADE_DELETE, "true")]),
            &cascade,
            &writer,
        )
        .await
        .expect("cascade cleanup");
        assert_eq!(cascade.modes(), vec![CleanupMode::Cascade]);
    }

    #[tokio::test]
    async fn cleanup_releases_the_finalizer_when_the_target_is_gone() {
        let writer = RecordingStatusWriter::default();
        let pipeline =
            FakePipeline::ready().with_cleanup(|| Err(ReconcileError::Api(api_error(404))));

        let action = cleanup_once(&application(&[]), &pipeline, &writer)
            .await
            .expect("a deleted target must release the finalizer");
        assert_eq!(action, Action::await_change());
        let patches = writer.patches();
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].observed_generation, Some(7));
        assert!(
            patches[0].condition(CONDITION_READY).is_none(),
            "a clean release must not invent a failure condition"
        );
    }

    #[tokio::test]
    async fn cleanup_retains_the_finalizer_after_a_real_failure() {
        let writer = RecordingStatusWriter::default();
        let pipeline = FakePipeline::ready().with_cleanup(|| {
            Err(ReconcileError::Invalid {
                message: "cleanup hook failed".to_owned(),
            })
        });

        let err = cleanup_once(&application(&[]), &pipeline, &writer)
            .await
            .expect_err("a genuine failure must retain the finalizer");
        assert!(err.to_string().contains("cleanup hook failed"));

        let patches = writer.patches();
        assert_eq!(patches.len(), 1);
        assert!(!patches[0].is_ready());
    }

    #[tokio::test]
    async fn cleanup_release_with_a_warning_records_the_reason() {
        let writer = RecordingStatusWriter::default();
        let pipeline = FakePipeline::ready().with_cleanup(|| {
            Ok(CleanupOutcome::TargetUnavailable {
                message: "secret ferriscd/prod-cluster not found".to_owned(),
            })
        });

        cleanup_once(&application(&[]), &pipeline, &writer)
            .await
            .expect("a missing destination secret must release the finalizer");

        let patches = writer.patches();
        let condition = patches[0]
            .condition(CONDITION_READY)
            .expect("the warning must be recorded");
        assert_eq!(condition.reason, REASON_CLEANUP_SKIPPED);
        assert!(
            condition.message.contains("prod-cluster"),
            "{}",
            condition.message
        );
    }

    /// Builds an inventory with one Deployment entry.
    fn sample_inventory() -> Inventory {
        let mut inventory = Inventory::new();
        inventory.insert(
            ResourceKey::new("apps", "Deployment", Some("payments".to_owned()), "api"),
            InventoryEntry::new("v1"),
        );
        inventory
    }

    fn inventory_status() -> ApplicationStatus {
        ApplicationStatus {
            inventory: vec![ferriscd_crd::InventoryEntry::new(
                "apps/Deployment/payments/old",
                "v1",
            )],
            sync: Some(SyncState {
                status: SyncStatus::Synced,
                revision: Some("oldsha".to_owned()),
                last_synced_revision: Some("oldsha".to_owned()),
                last_synced_spec_hash: Some("spec-hash".to_owned()),
                last_synced_at: Some(now()),
            }),
            health: Some(HealthState::new(HealthStatus::Healthy)),
            history: vec![RevisionHistoryEntry::new(
                1,
                Some("oldsha".to_owned()),
                now(),
            )],
            ..ApplicationStatus::default()
        }
    }

    #[tokio::test]
    async fn a_successful_outcome_persists_inventory_and_sync_and_keeps_other_fields() {
        let mut app = application(&[]);
        app.status = Some(inventory_status());

        let outcome = ApplyOutcome::ready("SyncSucceeded", "applied 1 resource")
            .with_inventory(sample_inventory())
            .with_sync(SyncState {
                status: SyncStatus::OutOfSync,
                revision: Some("newsha".to_owned()),
                // The pipeline did not set the markers; the previous pass owns them.
                last_synced_revision: None,
                last_synced_spec_hash: None,
                last_synced_at: None,
            });
        let pipeline = FakePipeline {
            apply: Box::new(move || Ok(outcome.clone())),
            ..FakePipeline::ready()
        };
        let writer = RecordingStatusWriter::default();

        apply_once(&app, &pipeline, &writer)
            .await
            .expect("apply must succeed");

        let status = &writer.patches()[0];
        assert_eq!(
            status
                .inventory
                .iter()
                .map(|entry| entry.key.as_str())
                .collect::<Vec<_>>(),
            vec!["apps/Deployment/payments/api"]
        );
        let sync = status.sync.as_ref().expect("sync must be persisted");
        assert_eq!(sync.revision.as_deref(), Some("newsha"));
        assert_eq!(
            sync.last_synced_revision.as_deref(),
            Some("oldsha"),
            "lastSynced markers must survive a pass that did not refresh them"
        );
        assert_eq!(sync.last_synced_spec_hash.as_deref(), Some("spec-hash"));
        assert!(sync.last_synced_at.is_some());
        assert_eq!(
            status.health.as_ref().map(|health| health.status),
            Some(HealthStatus::Healthy),
            "fields owned by other phases must survive"
        );
        assert_eq!(status.history.len(), 1);
        assert!(status.is_ready());
    }

    /// `T09.5`: health reaches `status.health` and the per-resource list is replaced, not merged.
    /// A merge patch must be able to *clear* the per-resource list and reset its counter.
    #[test]
    fn the_status_patch_body_always_sends_the_per_resource_fields() {
        // An empty list: both fields would otherwise be skipped by `skip_serializing_if`, and the
        // API server would keep the previous summaries forever.
        let empty = ApplicationStatus::default();
        let body = status_patch_body(&empty).expect("status must serialize");
        assert_eq!(
            body,
            serde_json::json!({ "status": { "resources": [], "resourcesOmitted": 0 } }),
            "an empty assessment must clear the previous per-resource statuses"
        );

        let mut filled = ApplicationStatus {
            resources_omitted: 0,
            ..ApplicationStatus::default()
        };
        filled.record_resource_status(ResourceStatus::new(
            "apps/Deployment/payments/api",
            "v1",
            HealthStatus::Progressing,
            "Waiting for controller to observe generation",
        ));
        let body = status_patch_body(&filled).expect("status must serialize");
        assert_eq!(
            body["status"]["resources"][0]["key"],
            serde_json::json!("apps/Deployment/payments/api")
        );
        assert_eq!(
            body["status"]["resources"][0]["health"],
            serde_json::json!("Progressing")
        );
        assert_eq!(body["status"]["resourcesOmitted"], serde_json::json!(0));
        // Fields the pass did not report stay absent, so a merge patch leaves them untouched.
        assert!(body["status"].get("inventory").is_none());
        assert!(body["status"].get("health").is_none());
    }

    #[tokio::test]
    async fn a_successful_outcome_persists_health_and_replaces_the_resource_summaries() {
        let mut app = application(&[]);
        let mut seeded = inventory_status();
        seeded.resources = vec![ResourceStatus::new(
            "apps/Deployment/payments/gone",
            "v1",
            HealthStatus::Healthy,
            "a resource that no longer exists",
        )];
        seeded.resources_omitted = 4;
        app.status = Some(seeded);

        let outcome = ApplyOutcome::ready("SyncSucceeded", "applied 1 resource").with_health(
            HealthState {
                status: HealthStatus::Progressing,
                message: Some("1 of 1 resource(s) are not Healthy".to_owned()),
            },
            vec![
                ResourceStatus::new(
                    "apps/Deployment/payments/api",
                    "v1",
                    HealthStatus::Progressing,
                    "Waiting for controller to observe generation",
                ),
                ResourceStatus::new(
                    "/ConfigMap/payments/settings",
                    "v1",
                    HealthStatus::Healthy,
                    "ConfigMap exists",
                ),
            ],
        );
        let pipeline = FakePipeline {
            apply: Box::new(move || Ok(outcome.clone())),
            ..FakePipeline::ready()
        };
        let writer = RecordingStatusWriter::default();

        apply_once(&app, &pipeline, &writer)
            .await
            .expect("apply must succeed");

        let status = &writer.patches()[0];
        assert_eq!(
            status.health.as_ref().map(|health| health.status),
            Some(HealthStatus::Progressing),
            "health must be persisted independently of the sync status"
        );
        assert_eq!(
            status
                .resources
                .iter()
                .map(|resource| resource.key.as_str())
                .collect::<Vec<_>>(),
            vec![
                "apps/Deployment/payments/api",
                "/ConfigMap/payments/settings"
            ],
            "the per-resource list is this pass's assessment, so stale entries must be dropped"
        );
        assert_eq!(
            status.resources_omitted, 0,
            "the overflow counter belongs to the list that was just replaced"
        );
        assert!(
            status.is_ready(),
            "the Ready condition is untouched by health"
        );
    }

    #[tokio::test]
    async fn a_partial_sync_persists_the_inventory_it_already_confirms() {
        let mut app = application(&[]);
        app.status = Some(inventory_status());

        let pipeline = FakePipeline::failing(|| ReconcileError::PartialSync {
            message: "applying apps/Deployment/payments/api failed".to_owned(),
            inventory: sample_inventory(),
            revision: Some("newsha".to_owned()),
            operation: Some(Box::new(running_operation("newsha"))),
        });
        let writer = RecordingStatusWriter::default();

        let err = apply_once(&app, &pipeline, &writer)
            .await
            .expect_err("a partial sync is still a failure");
        assert_eq!(err.failure_class(), FailureClass::Retryable);
        assert!(err.partial_status().is_some());

        let patches = writer.patches();
        assert_eq!(
            patches.len(),
            1,
            "the failure path must still patch /status"
        );
        let status = &patches[0];
        assert!(
            !status.is_ready(),
            "a partial sync must report Ready=False even though it persisted state"
        );
        assert_eq!(
            status
                .inventory
                .iter()
                .map(|entry| entry.key.as_str())
                .collect::<Vec<_>>(),
            vec!["apps/Deployment/payments/api"],
            "the confirmed inventory must survive the failure (finding C1)"
        );
        let sync = status.sync.as_ref().expect("sync must be persisted");
        assert_eq!(sync.status, SyncStatus::OutOfSync);
        assert_eq!(sync.revision.as_deref(), Some("newsha"));
        assert_eq!(
            sync.last_synced_revision.as_deref(),
            Some("oldsha"),
            "a failure must never move the last successful sync markers"
        );
        assert_eq!(status.history.len(), 1);
        assert!(
            status
                .condition(CONDITION_READY)
                .is_some_and(|condition| condition.message.contains("failed")),
            "the failure reason must be actionable"
        );
        // Finding M4: the hook records the failed pass produced survive the failure, so the retry
        // observes the object that was already created instead of creating a second one.
        let operation = status
            .operation_state
            .as_ref()
            .expect("a failed wave pass must still persist its operation state");
        assert_eq!(operation.phase, OperationPhase::Running);
        assert_eq!(operation.active_hooks.len(), 1);
        assert_eq!(operation.active_hooks[0].generated_name, "migrate-abcde");
    }

    /// The `Running` operation state a failed wave pass persists: one tracked `generateName` hook.
    fn running_operation(revision: &str) -> OperationState {
        OperationState {
            phase: OperationPhase::Running,
            sync_phase: Some(SyncPhase::PreSync),
            current_wave: 0,
            phase_started_at: Some(now()),
            revision: Some(revision.to_owned()),
            active_hooks: vec![ActiveHook::new(
                SyncPhase::PreSync,
                0,
                "Job-.yaml#0",
                "migrate-abcde",
                HealthStatus::Progressing,
            )],
            message: Some("running PreSync hooks".to_owned()),
            started_at: now(),
            finished_at: None,
        }
    }

    /// The automation the fixtures start from (`automated: { prune: false, selfHeal: true }`).
    fn automated_policy() -> SyncPolicy {
        SyncPolicy {
            automated: Some(AutomatedSyncPolicy {
                prune: false,
                self_heal: true,
            }),
            sync_options: None,
            retry: None,
        }
    }

    /// The commit a rollback is pinned to (the revision `status.history` id 1 recorded).
    const PINNED: &str = "1111111111111111111111111111111111111111";
    /// `ferriscd.io/operation: {"rollback":{"id":1}}`, the request that started the rollback.
    const ROLLBACK_REQUEST: &str = r#"{"rollback":{"id":1}}"#;

    /// The outcome of a pass that reports `revision` as the commit it is following.
    fn following(revision: &str) -> ApplyOutcome {
        let mut operation = running_operation(revision);
        operation.phase = OperationPhase::Succeeded;
        operation.sync_phase = Some(SyncPhase::Succeeded);
        operation.active_hooks.clear();
        operation.finished_at = operation.phase_started_at.clone();
        ApplyOutcome::ready(
            "SyncSucceeded",
            format!("applied the pinned commit {revision}"),
        )
        .with_sync(SyncState {
            status: SyncStatus::Synced,
            revision: Some(revision.to_owned()),
            last_synced_revision: Some(revision.to_owned()),
            last_synced_spec_hash: Some("spec-hash".to_owned()),
            last_synced_at: Some(now()),
        })
        .with_operation_state(Some(operation))
    }

    /// **Finding C1:** the rollback warning is *not* cleared on the pass that emits it.
    ///
    /// The rollback path patches a **clone** of the spec, so the `Application` this pass reconciles
    /// still reports `automated: Some(...)`. Clearing the warning unconditionally therefore deleted
    /// it — and with it the pin `pinned_rollback_revision` derives from it — on the very pass that
    /// created it, which is the rollback-vs-`selfHeal` fight `T10.5` exists to break.
    #[tokio::test]
    async fn the_rollback_warning_survives_the_pass_that_emits_it_and_pins_the_revision() {
        // The rollback this pass honours: history id 1 recorded the pinned commit.
        let decision = ferriscd_engine::sync::plan_rollback(
            &ApplicationStatus {
                history: vec![RevisionHistoryEntry::new(1, Some(PINNED.to_owned()), now())],
                ..ApplicationStatus::default()
            },
            ferriscd_engine::sync::RollbackRequest { id: 1 },
            &now(),
        )
        .expect("a valid rollback request");
        assert_eq!(decision.pinned_revision(), PINNED);

        // This pass's copy of the Application: the annotation asked for the rollback and the spec
        // still carries the automation the rollback is about to remove (it patches a clone).
        let mut app = application(&[(annotations::OPERATION, ROLLBACK_REQUEST)]);
        app.spec.sync_policy = Some(automated_policy());

        let warning = decision.condition;
        let pipeline = FakePipeline {
            apply: Box::new(move || Ok(following(PINNED).with_warning(warning.clone()))),
            ..FakePipeline::ready()
        };
        let writer = RecordingStatusWriter::default();

        apply_once(&app, &pipeline, &writer)
            .await
            .expect("the rollback pass must succeed");

        let first = writer.patches().remove(0);
        let condition = first
            .condition(ferriscd_engine::sync::CONDITION_WARNING)
            .expect("the pass that emitted the warning must persist it");
        assert_eq!(
            condition.reason,
            ferriscd_engine::sync::REASON_AUTOMATED_SYNC_DISABLED_BY_ROLLBACK
        );
        // The pin the next pass resolves is derived from `/status`, so it must still be there.
        assert_eq!(
            crate::sync::pinned_rollback_revision(&first).as_deref(),
            Some(PINNED),
            "the warning is what pins the revision: {}",
            condition.message
        );
        assert_eq!(
            first
                .sync
                .as_ref()
                .and_then(|sync| sync.revision.as_deref()),
            Some(PINNED)
        );

        // Pass 2: the spec patch has landed, so this pass reads a manual-only spec and follows the
        // commit the persisted warning pins (exactly what `pinned_rollback_revision` returns).
        let pinned = crate::sync::pinned_rollback_revision(&first).expect("the pin survives");
        let mut second_app = app.clone();
        second_app.spec.sync_policy = None;
        second_app.metadata.annotations = None;
        second_app.status = Some(first.clone());
        let second_pipeline = FakePipeline {
            apply: Box::new({
                let pinned = pinned.clone();
                move || Ok(following(&pinned))
            }),
            ..FakePipeline::ready()
        };
        let second_writer = RecordingStatusWriter::default();

        apply_once(&second_app, &second_pipeline, &second_writer)
            .await
            .expect("a manual-only pass must succeed");

        let second = second_writer.patches().remove(0);
        assert_eq!(
            second
                .sync
                .as_ref()
                .and_then(|sync| sync.revision.as_deref()),
            Some(PINNED),
            "the following pass must still report the pinned revision, not HEAD"
        );
        assert!(
            second
                .condition(ferriscd_engine::sync::CONDITION_WARNING)
                .is_some(),
            "a manual-only application keeps the warning: it is what holds HEAD back"
        );
        assert_eq!(
            crate::sync::pinned_rollback_revision(&second).as_deref(),
            Some(PINNED),
            "the pin must survive every pass until automation is re-enabled"
        );

        // Pass 3: the operator reverted Git and re-enabled automation, so the warning (and the pin)
        // are cleared — the C1 guard must not break the finding M-4 cleanup.
        let mut third_app = second_app.clone();
        third_app.spec.sync_policy = Some(automated_policy());
        third_app.status = Some(second);
        let third_writer = RecordingStatusWriter::default();
        apply_once(
            &third_app,
            &FakePipeline {
                apply: Box::new(|| Ok(following("2222222222222222222222222222222222222222"))),
                ..FakePipeline::ready()
            },
            &third_writer,
        )
        .await
        .expect("a re-enabled pass must succeed");

        let third = third_writer.patches().remove(0);
        assert!(
            third
                .condition(ferriscd_engine::sync::CONDITION_WARNING)
                .is_none(),
            "re-enabling spec.syncPolicy.automated must clear the stale rollback warning"
        );
        assert_eq!(crate::sync::pinned_rollback_revision(&third), None);
    }

    #[tokio::test]
    async fn the_unwired_pipeline_still_reports_not_ready_and_writes_no_state() {
        let mut app = application(&[]);
        app.status = Some(inventory_status());
        let writer = RecordingStatusWriter::default();

        let err = apply_once(&app, &UnwiredSyncPipeline, &writer)
            .await
            .expect_err("the unwired pipeline must never report success");
        assert!(err.to_string().contains("not wired"), "{err}");

        let status = &writer.patches()[0];
        assert!(!status.is_ready());
        assert_eq!(
            status.inventory.len(),
            1,
            "a pipeline that reports no inventory must not clear the existing one"
        );
        assert_eq!(
            status
                .sync
                .as_ref()
                .and_then(|sync| sync.revision.as_deref()),
            Some("oldsha"),
            "a pipeline that reports no sync state must not clear it"
        );
    }

    #[test]
    fn sync_state_merge_only_fills_the_missing_last_synced_markers() {
        let mut status = inventory_status();
        merge_sync_state(
            &mut status,
            SyncState {
                status: SyncStatus::Synced,
                revision: Some("newsha".to_owned()),
                last_synced_revision: Some("newsha".to_owned()),
                last_synced_spec_hash: None,
                last_synced_at: None,
            },
        );
        let sync = status.sync.expect("merged");
        assert_eq!(sync.last_synced_revision.as_deref(), Some("newsha"));
        assert_eq!(
            sync.last_synced_spec_hash.as_deref(),
            Some("spec-hash"),
            "an unset marker keeps the previous value"
        );

        // No previous sync at all: nothing to preserve, no panic.
        let mut empty = ApplicationStatus::default();
        merge_sync_state(&mut empty, SyncState::new(SyncStatus::Synced, None));
        assert!(empty.sync.expect("merged").last_synced_revision.is_none());
    }

    #[test]
    fn partial_sync_errors_expose_their_inventory_only() {
        let partial = ReconcileError::PartialSync {
            message: "boom".to_owned(),
            inventory: sample_inventory(),
            revision: Some("sha".to_owned()),
            operation: None,
        };
        let (inventory, revision) = partial.partial_status().expect("partial status");
        assert_eq!(inventory.len(), 1);
        assert_eq!(revision.map(String::as_str), Some("sha"));
        assert!(!partial.is_already_deleted());
        assert_eq!(failure_reason(&partial), REASON_SYNC_ERROR);

        for err in [
            ReconcileError::Invalid {
                message: "bad".to_owned(),
            },
            ReconcileError::Api(api_error(500)),
        ] {
            assert!(err.partial_status().is_none());
        }
    }

    #[test]
    fn reconcile_errors_keep_their_source_and_classification() {
        let err = ControllerError::from_reconcile(ReconcileError::Invalid {
            message: "bad spec".to_owned(),
        });
        assert_eq!(err.failure(), FailureClass::Terminal);
        assert_eq!(err.to_string(), "bad spec");
        assert!(std::error::Error::source(&err).is_some());

        let wrapped = ControllerError::from_reconcile(ReconcileError::Api(api_error(500)));
        assert_eq!(wrapped.failure(), FailureClass::Retryable);
    }

    /// **`T15.2`:** `apply_once_with_events` emits `Normal SyncSucceeded` and `Normal ResourcePruned`
    /// on settled syncs, suppresses `Normal SyncSucceeded` on no-op `SyncSkipped` passes, and
    /// ignores publisher failures so observability never breaks reconciliation.
    #[tokio::test]
    async fn apply_once_with_events_emits_normal_events_and_tolerates_publish_errors() {
        use crate::events::{
            AppEventType, EVENT_REASON_RESOURCE_PRUNED, EVENT_REASON_SYNC_SUCCEEDED,
            RecordingEventPublisher,
        };

        let app = application(&[]);
        let writer = RecordingStatusWriter::default();
        let publisher = Arc::new(RecordingEventPublisher::new());
        let events = EventRecorder::new(publisher.clone());

        // Settled sync with a pruned key -> emits both ResourcePruned and SyncSucceeded.
        let pruned_key = ResourceKey::new("", "ConfigMap", Some("payments".to_owned()), "stale-cm");
        let pruned_key_clone = pruned_key.clone();
        let pipeline = FakePipeline {
            apply: Box::new(move || {
                Ok(ApplyOutcome::ready(
                    REASON_SYNC_SUCCEEDED,
                    "applied 1 of 1 resource(s), pruned 1",
                )
                .with_pruned(vec![pruned_key_clone.clone()]))
            }),
            ..FakePipeline::ready()
        };
        apply_once_with_events(&app, &pipeline, &writer, &events)
            .await
            .expect("settled sync must succeed");

        let recorded = publisher.events();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0].type_, AppEventType::Normal);
        assert_eq!(recorded[0].reason, EVENT_REASON_RESOURCE_PRUNED);
        assert!(recorded[0].note.contains(&pruned_key.canonical()));
        assert_eq!(recorded[1].type_, AppEventType::Normal);
        assert_eq!(recorded[1].reason, EVENT_REASON_SYNC_SUCCEEDED);

        // No-op `SyncSkipped` pass -> emits zero events (no spam on periodic requeues).
        publisher.clear();
        let skipped = FakePipeline {
            apply: Box::new(|| {
                Ok(ApplyOutcome::ready(
                    REASON_SYNC_SKIPPED,
                    "no sync performed",
                ))
            }),
            ..FakePipeline::ready()
        };
        apply_once_with_events(&app, &skipped, &writer, &events)
            .await
            .expect("skipped pass must succeed");
        assert!(
            publisher.events().is_empty(),
            "no-op SyncSkipped passes must not spam Normal SyncSucceeded"
        );

        // Failing event publisher must NEVER fail reconciliation.
        let failing_events =
            EventRecorder::new(Arc::new(RecordingEventPublisher::failing("403 Forbidden")));
        apply_once_with_events(&app, &FakePipeline::ready(), &writer, &failing_events)
            .await
            .expect("event publish failure must not abort reconciliation");
    }

    /// **`T15.2`:** `apply_once_with_events` rate-limits repeated `Warning SyncFailed` events and
    /// `cleanup_once_with_events` clears the app's dedup state when the finalizer is released.
    #[tokio::test]
    async fn apply_once_with_events_rate_limits_warnings_and_clears_on_cleanup() {
        use crate::events::test_support::ManualClock;
        use crate::events::{AppEventType, EVENT_REASON_SYNC_FAILED, RecordingEventPublisher};

        let app = application(&[]);
        let writer = RecordingStatusWriter::default();
        let clock = Arc::new(ManualClock::new());
        let publisher = Arc::new(RecordingEventPublisher::new());
        let events = EventRecorder::new(publisher.clone()).with_clock(clock.clone());
        let failing = FakePipeline::failing(|| ReconcileError::Invalid {
            message: "bad manifest https://bot:secret@git.example.com/repo.git".to_owned(),
        });

        // Two failures within 5 minutes -> only 1 Warning SyncFailed emitted, with URL redacted.
        assert!(
            apply_once_with_events(&app, &failing, &writer, &events)
                .await
                .is_err()
        );
        clock.advance(Duration::from_secs(60));
        assert!(
            apply_once_with_events(&app, &failing, &writer, &events)
                .await
                .is_err()
        );
        let recorded = publisher.events();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].type_, AppEventType::Warning);
        assert_eq!(recorded[0].reason, EVENT_REASON_SYNC_FAILED);
        assert!(!recorded[0].note.contains("secret"), "{}", recorded[0].note);
        assert_eq!(events.tracked_apps(), 1);

        // Releasing the finalizer clears the dedup table entry for the deleted app.
        cleanup_once_with_events(&app, &FakePipeline::ready(), &writer, &events)
            .await
            .expect("cleanup releases finalizer");
        assert_eq!(
            events.tracked_apps(),
            0,
            "deleting an Application must drop its warning dedup entry"
        );
    }
}
