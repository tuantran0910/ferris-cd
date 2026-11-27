//! The Server-Side Apply sync executor: runs a [`SyncPlan`] in order, waits for
//! `CustomResourceDefinition` establishment, refreshes discovery between a CRD and its custom
//! resources, and reports exactly what was confirmed (T08.3).
//!
//! ```text
//! SyncPlan { pre_create_namespace, steps }
//!    │
//!    ├─ pre_create_namespace ──► SSA apply a bare Namespace (NO tracking-id: never prunable)
//!    │
//!    └─ for each step, in order
//!          Apply   ──► SSA apply (force=false; a 409 may escalate to one forced retry, T08.4)
//!          Replace ──► delete → wait 404 → SSA apply (T08.4)
//!          Prune   ──► ownership-verified delete (T08.5)
//!          Skip    ──► nothing (already synced / deferred / gated / retained)
//!          FailConflict ──► terminal, actionable failure (never adopts a foreign object)
//!
//!          after applying a CustomResourceDefinition:
//!             poll status.conditions[type=Established, status=True]  (bounded, ~15s)
//!             ├─ established ──► DiscoveryCache::invalidate_and_refresh()
//!             └─ not yet     ──► stop, report the rest as *pending*, requeue (never an error)
//! ```
//!
//! # Deferral always costs exactly one extra pass
//!
//! A `Skip(Deferred)` step is **never** resolved inside the pass that reports it, whatever the
//! executor did before it (even a discovery refresh): it is marked pending and left for the next
//! reconcile, unconditionally. The plan is handed exactly the `DeferredPendingNamespace` keys, so
//! the only deferral in the wired pipeline is "this resource targets a `Namespace` this bundle
//! declares" — and that namespace can only exist after this pass commits it. One extra pass, every
//! time, is therefore the whole contract.
//!
//! A custom resource whose kind a CRD in the same bundle defines is *not* deferred here: the
//! planner emits an `Apply` for it (tier 11), and the CRD step above establishes the definition and
//! refreshes discovery before it runs, so a CRD + CR pair in one commit lands on the **first** sync.
//!
//! # Why the CRD wait is a requeue and not an error
//!
//! A freshly applied `CustomResourceDefinition` is not served immediately: the API server has to
//! establish it (and the aggregated discovery document has to be republished). A CR applied
//! against a not-yet-served kind answers `404 NoMatchesForKind`. Waiting inside the reconcile is
//! bounded ([`DEFAULT_CRD_ESTABLISH_TIMEOUT`]); when the window closes the pass reports
//! [`ExecutionReport::pending`] and the controller requeues on the short pending interval, so a
//! slow `kind` cluster converges instead of failing (finding C3, trap T6).
//!
//! # Cancel safety and idempotency
//!
//! Every action is individually idempotent and re-verifying:
//!
//! * `Apply` is Server-Side Apply — replaying it is a no-op,
//! * `Replace` re-reads live state and only applies once the name is free,
//! * `Prune` re-reads and re-verifies `ferriscd.io/tracking-id` immediately before the delete.
//!
//! A controller killed mid-pass therefore leaves a cluster the next pass can converge from, and
//! [`ExecutionReport`] is the crash-safe input to `status.inventory`:
//! `next_inventory = (prev \ pruned_ok) ∪ applied_ok` (finding C1).
//!
//! # Async hygiene
//!
//! Every Kubernetes call is a plain `async` `kube` request; the only waits are `tokio::time`
//! timers between polls (never `std::thread::sleep`, never a blocking syscall on a worker).
//! Nothing in this module touches Git or the filesystem.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use ferriscd_engine::graph::order::is_crd_key;
use ferriscd_engine::inventory::{Inventory, InventoryEntry};
use ferriscd_engine::manifest::{DesiredResource, GroupVersionKind, ResourceKey};
use ferriscd_engine::sync::{PlanSkipReason, SyncAction, SyncPlan};
use futures::future::BoxFuture;
use kube::api::{ApiResource, DynamicObject};
use kube::discovery::Scope;
use tracing::{info, warn};

use crate::discovery::DiscoveryCache;
use crate::live_state::{ClusterStateReader, TrackingOwner};
use crate::prune::{PruneResult, ResourcePruner};
use crate::reconcile::ReconcileError;
use crate::sync::{Applier, ApplyRequest};
use crate::sync_recovery::{
    Recovery, ReplacePolicy, ReplaceRecovery, classify_apply_failure, log_takeover,
};

/// How long one CRD is given to report `Established=True` before the pass requeues.
pub const DEFAULT_CRD_ESTABLISH_TIMEOUT: Duration = Duration::from_secs(15);

/// Delay between two `Established` reads.
pub const DEFAULT_CRD_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// The CRD condition type that means "the custom kind is being served".
pub const ESTABLISHED_CONDITION: &str = "Established";

/// The CRD condition type that means "the API server accepted the names and versions".
///
/// `NamesAccepted=False` is the one CRD condition that is terminal: the definition is invalid, so
/// waiting longer cannot help (finding H5).
pub const NAMES_ACCEPTED_CONDITION: &str = "NamesAccepted";

/// A resolved Kubernetes target: the discovered resource plus its scope.
#[derive(Clone, Debug)]
pub struct Target {
    /// Discovered resource (real plural name and served version).
    pub api_resource: ApiResource,
    /// Whether the kind is namespaced or cluster-scoped.
    pub scope: Scope,
}

/// Resolves the exact GVK a desired manifest asks for.
///
/// No version fallback: a manifest that pins an unserved `apiVersion` is a spec bug and must fail
/// terminally instead of being silently applied through another version.
///
/// # Errors
///
/// [`ReconcileError::Discovery`] when the kind is unknown or discovery cannot be refreshed.
pub async fn resolve_desired_target(
    discovery: &DiscoveryCache,
    resource: &DesiredResource,
) -> Result<Target, ReconcileError> {
    let gvk = kube::api::GroupVersionKind::gvk(
        &resource.gvk.group,
        &resource.gvk.version,
        &resource.gvk.kind,
    );
    let (api_resource, capabilities) = discovery.resolve(&gvk).await?;
    Ok(Target {
        api_resource,
        scope: capabilities.scope,
    })
}

/// Resolves a version-agnostic key, preferring the recorded version hint.
///
/// Used for deletes and replacements, where only `status.inventory`/the manifest hint is
/// available and identity must survive an API upgrade (finding C2). `Ok(None)` means the cluster
/// serves no resource for that group + kind — the object went with its CRD.
///
/// # Errors
///
/// Propagates discovery refresh failures.
pub async fn resolve_key_target(
    discovery: &DiscoveryCache,
    key: &ResourceKey,
    version_hint: Option<&str>,
) -> Result<Option<Target>, ReconcileError> {
    if let Some(version) = version_hint.map(str::trim).filter(|hint| !hint.is_empty()) {
        let gvk = kube::api::GroupVersionKind::gvk(&key.group, version, &key.kind);
        match discovery.resolve(&gvk).await {
            Ok((api_resource, capabilities)) => {
                return Ok(Some(Target {
                    api_resource,
                    scope: capabilities.scope,
                }));
            }
            Err(err) if err.is_no_matches_for_kind() => {}
            Err(err) => return Err(err.into()),
        }
    }
    Ok(discovery
        .resolve_kind(&key.group, &key.kind)
        .await?
        .map(|(api_resource, capabilities)| Target {
            api_resource,
            scope: capabilities.scope,
        }))
}

/// Returns the namespace a namespaced target must be applied in.
///
/// # Errors
///
/// [`ReconcileError::Invalid`] when a namespaced kind has no `metadata.namespace` after scope
/// normalization (scope normalization guarantees one, so this is a defensive check).
pub fn desired_namespace(
    resource: &DesiredResource,
    target_scope: Scope,
) -> Result<Option<String>, ReconcileError> {
    match target_scope {
        Scope::Cluster => Ok(None),
        Scope::Namespaced => resource
            .object
            .metadata
            .namespace
            .clone()
            .filter(|namespace| !namespace.trim().is_empty())
            .map(Some)
            .ok_or_else(|| ReconcileError::Invalid {
                message: format!(
                    "{}: namespaced kind {} has no metadata.namespace after scope normalization",
                    resource.key.canonical(),
                    resource.gvk.kind
                ),
            }),
    }
}

/// The `Established` verdict of one `CustomResourceDefinition` read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrdReadiness {
    /// The custom kind is served: the CRs can be resolved and applied.
    Established,
    /// Not established (yet): requeue, never fail.
    Pending,
    /// The API server rejected the definition (`NamesAccepted=False`): it will never establish,
    /// so the pass fails with an actionable message instead of requeueing until the heat death of
    /// the cluster.
    Rejected {
        /// `reason` + `message` of the terminal condition (bounded, payload-free).
        message: String,
    },
}

/// Reads the `Established`/`NamesAccepted` conditions of a `CustomResourceDefinition`.
pub trait CrdStatusReader: Send + Sync + 'static {
    /// Reads the readiness of the CRD called `name`.
    ///
    /// A missing CRD (`404`/`410`) is [`CrdReadiness::Pending`]: it has not been established
    /// (yet), which is a requeue, never a failure.
    fn readiness<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<CrdReadiness, ReconcileError>>;
}

/// [`CrdStatusReader`] backed by the same live-object source as every other read.
///
/// The CRD is read as a [`DynamicObject`] instead of the typed
/// `k8s_openapi::apiextensions_apiserver::…::CustomResourceDefinition`, so this module never
/// depends on a `k8s-openapi` version feature (and the hermetic tests can script it).
#[derive(Clone, Debug)]
pub struct LiveCrdStatusReader {
    reader: ClusterStateReader,
}

impl LiveCrdStatusReader {
    /// Builds a reader that reads CRDs through `reader`.
    #[must_use]
    pub fn new(reader: ClusterStateReader) -> Self {
        Self { reader }
    }
}

impl CrdStatusReader for LiveCrdStatusReader {
    fn readiness<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<CrdReadiness, ReconcileError>> {
        Box::pin(async move {
            let api_resource = crd_api_resource();
            let object = self
                .reader
                .get_object(&api_resource, None, name)
                .await
                .map_err(ReconcileError::Live)?;
            Ok(match object {
                Some(object) => crd_readiness(&object),
                None => CrdReadiness::Pending,
            })
        })
    }
}

/// The discovered shape of `apiextensions.k8s.io/v1 CustomResourceDefinition`.
fn crd_api_resource() -> ApiResource {
    let gvk = kube::api::GroupVersionKind::gvk(
        ferriscd_engine::graph::order::APIEXTENSIONS_GROUP,
        "v1",
        ferriscd_engine::graph::order::CRD_KIND,
    );
    let mut api_resource = ApiResource::from_gvk(&gvk);
    api_resource.plural = "customresourcedefinitions".to_owned();
    api_resource
}

/// Returns whether a `CustomResourceDefinition` object reports `Established=True`.
#[must_use]
pub fn is_established(object: &DynamicObject) -> bool {
    conditions(object).is_some_and(|conditions| {
        conditions.iter().any(|condition| {
            type_of(condition) == Some(ESTABLISHED_CONDITION)
                && condition.get("status").and_then(serde_json::Value::as_str) == Some("True")
        })
    })
}

/// Classifies a `CustomResourceDefinition` object (finding H5).
///
/// `NamesAccepted=False` is **terminal**: the API server rejected the names/versions, so polling
/// cannot help. Everything else (no `status` yet, `Established=False`, `NamesAccepted=Unknown`) is
/// a genuine "not yet".
#[must_use]
pub fn crd_readiness(object: &DynamicObject) -> CrdReadiness {
    if is_established(object) {
        return CrdReadiness::Established;
    }
    if let Some(conditions) = conditions(object) {
        for condition in conditions {
            if type_of(condition) == Some(NAMES_ACCEPTED_CONDITION)
                && condition.get("status").and_then(serde_json::Value::as_str) == Some("False")
            {
                let reason = condition
                    .get("reason")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("NamesAccepted=False");
                let message = condition
                    .get("message")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                return CrdReadiness::Rejected {
                    message: crate::reconcile::bounded(&format!(
                        "{}: {}",
                        reason.trim(),
                        message.trim()
                    )),
                };
            }
        }
    }
    CrdReadiness::Pending
}

/// The `status.conditions` array of `object`, if any.
fn conditions(object: &DynamicObject) -> Option<&Vec<serde_json::Value>> {
    object
        .data
        .get("status")
        .and_then(|status| status.get("conditions"))
        .and_then(serde_json::Value::as_array)
}

/// The `type` of one condition entry.
fn type_of(condition: &serde_json::Value) -> Option<&str> {
    condition.get("type").and_then(serde_json::Value::as_str)
}

/// How the executor paces its waits and which managers it may take over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionPolicy {
    /// Bounded wait for a CRD to become `Established`.
    pub crd_timeout: Duration,
    /// Delay between two `Established` reads (`Duration::ZERO` = poll without sleeping).
    pub crd_interval: Duration,
    /// `syncOptions.takeoverFieldManagers`.
    pub takeover_field_managers: Vec<String>,
    /// Delete → wait `404` → re-apply pacing.
    pub replace: ReplacePolicy,
}

impl Default for ExecutionPolicy {
    fn default() -> Self {
        Self {
            crd_timeout: DEFAULT_CRD_ESTABLISH_TIMEOUT,
            crd_interval: DEFAULT_CRD_POLL_INTERVAL,
            takeover_field_managers: Vec::new(),
            replace: ReplacePolicy::default(),
        }
    }
}

impl ExecutionPolicy {
    /// A policy that never waits: used by hermetic tests and by callers that want the pure
    /// requeue behaviour.
    #[must_use]
    pub fn without_waits() -> Self {
        Self {
            crd_timeout: Duration::ZERO,
            crd_interval: Duration::ZERO,
            takeover_field_managers: Vec::new(),
            replace: ReplacePolicy {
                timeout: Duration::ZERO,
                interval: Duration::ZERO,
            },
        }
    }
}

/// One action that failed.
#[derive(Debug)]
pub struct ActionFailure {
    /// The resource the action targeted.
    pub key: ResourceKey,
    /// Which kind of action failed (`apply`, `replace`, `prune`, `createNamespace`, …).
    pub action: &'static str,
    /// The underlying error (classified by the caller for backoff).
    pub error: ReconcileError,
}

/// What one plan execution confirmed.
#[derive(Debug, Default)]
pub struct ExecutionReport {
    /// Applies/creates this pass confirmed — the `applied_ok` half of the inventory formula.
    pub applied_ok: Inventory,
    /// Keys the diff verified are already in place **and** owned by this `Application`.
    ///
    /// Recorded from the plan without a mutating call, so a wiped `status.inventory` is repaired
    /// from live state instead of by re-applying everything (finding C1). [`Self::synced_keys`] is
    /// the accessor: the caller must not have to rebuild this from the plan itself.
    pub synced_ok: Inventory,
    /// Deletes this pass confirmed (`404`/`410` counts) — the `pruned_ok` half.
    pub pruned_ok: Vec<ResourceKey>,
    /// Orphans deliberately kept, with the reason (already logged).
    pub retained: usize,
    /// Actions still to do: a deferred resource, or everything after a CRD that is not
    /// established yet. A pending report requeues on the short interval, it is *not* an error.
    pub pending: BTreeSet<ResourceKey>,
    /// The first failure, in execution order. Execution stops there (crash-safe: the caller
    /// persists [`Self::applied_ok`]/[`Self::pruned_ok`] as they are).
    pub failed: Vec<ActionFailure>,
    /// How many discovery refreshes were triggered by an applied CRD.
    pub discovery_refreshes: usize,
    /// How many SSA applies were issued (including the namespace pre-create). A metric seam:
    /// an already-synced `Application` must leave this at zero.
    pub apply_calls: usize,
}

impl ExecutionReport {
    /// Returns whether nothing failed.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.failed.is_empty()
    }

    /// The first failure, if any.
    #[must_use]
    pub fn first_failure(&self) -> Option<&ActionFailure> {
        self.failed.first()
    }

    /// Returns whether the pass must requeue on the short pending interval.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// The desired keys the diff verified are already in place and owned by this `Application`.
    ///
    /// Part of `next_inventory = (prev \ pruned_ok) ∪ (applied_ok ∪ synced_keys)`: a plan that
    /// only re-confirms live state still has to keep those entries tracked (finding C1).
    #[must_use]
    pub fn synced_keys(&self) -> &Inventory {
        &self.synced_ok
    }

    /// Everything this pass confirmed, without touching `prev_inventory`.
    ///
    /// The caller folds this into the crash-safe formula; every confirmed prune is in
    /// [`Self::pruned_ok`].
    #[must_use]
    pub fn confirmed(&self) -> Inventory {
        let mut confirmed = self.applied_ok.clone();
        for (key, entry) in &self.synced_ok {
            confirmed
                .entry(key.clone())
                .or_insert_with(|| entry.clone());
        }
        confirmed
    }
}

/// Which mutation a step asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ApplyMode {
    /// Server-Side Apply.
    Apply,
    /// Delete → wait `404` → Server-Side Apply.
    Replace,
}

/// What one step achieved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StepOutcome {
    /// Applied, nothing else to do.
    Applied,
    /// Applied a CRD and refreshed discovery.
    AppliedWithRefresh,
    /// Applied a CRD that is not established yet: requeue instead of applying its dependents.
    RequeuePending,
}

/// Executes one [`SyncPlan`].
pub struct SyncExecutor<'a> {
    applier: &'a dyn Applier,
    pruner: &'a dyn ResourcePruner,
    reader: &'a ClusterStateReader,
    discovery: &'a DiscoveryCache,
    crd_status: &'a dyn CrdStatusReader,
    owner: &'a TrackingOwner,
    policy: &'a ExecutionPolicy,
}

impl std::fmt::Debug for SyncExecutor<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncExecutor")
            .field("policy", self.policy)
            .field("owner", self.owner)
            .finish_non_exhaustive()
    }
}

impl<'a> SyncExecutor<'a> {
    /// Builds an executor for one reconcile pass.
    #[must_use]
    pub fn new(
        applier: &'a dyn Applier,
        pruner: &'a dyn ResourcePruner,
        reader: &'a ClusterStateReader,
        discovery: &'a DiscoveryCache,
        crd_status: &'a dyn CrdStatusReader,
        owner: &'a TrackingOwner,
        policy: &'a ExecutionPolicy,
    ) -> Self {
        Self {
            applier,
            pruner,
            reader,
            discovery,
            crd_status,
            owner,
            policy,
        }
    }

    /// Executes `plan` against the cluster and reports what was confirmed.
    ///
    /// Never returns `Err`: a failure is reported in [`ExecutionReport::failed`] so the caller can
    /// persist the confirmed inventory **and** the error (finding C1). Only the first failure is
    /// recorded — execution stops there, exactly like a half-applied sync must.
    pub async fn execute(
        &self,
        plan: &SyncPlan,
        desired: &[DesiredResource],
        version_hints: &Inventory,
    ) -> ExecutionReport {
        let mut report = ExecutionReport::default();
        let by_key: BTreeMap<&ResourceKey, &DesiredResource> = desired
            .iter()
            .map(|resource| (&resource.key, resource))
            .collect();

        // A `Synced` key is already live and ours: track it without an apply (finding C1).
        for key in plan.synced_keys() {
            let version = by_key
                .get(&key)
                .map(|resource| resource.gvk.version.clone())
                .unwrap_or_default();
            report.synced_ok.insert(key, InventoryEntry::new(version));
        }

        // --- T08.3: the destination namespace, before anything else ---------------------
        if let Some(namespace) = plan.pre_create_namespace() {
            let key = ResourceKey::new("", "Namespace", None, namespace);
            if let Err(error) = self.ensure_namespace(namespace, &mut report).await {
                report.failed.push(ActionFailure {
                    key,
                    action: "createNamespace",
                    error,
                });
                return report;
            }
        }

        // --- the plan, in order --------------------------------------------------------
        for (index, step) in plan.steps.iter().enumerate() {
            match step {
                SyncAction::Skip { key, reason } => {
                    if matches!(reason, PlanSkipReason::Deferred) {
                        // A deferred step is never resolved in this pass, unconditionally — even
                        // when this pass just applied a CRD and refreshed discovery. Only a
                        // **`Namespace`** this bundle declares defers a key (the plan is handed
                        // exactly the `DeferredPendingNamespace` keys, `sync.rs`), and that
                        // namespace exists only after this pass commits it, so the resource waits
                        // for exactly one more reconcile: the documented `PendingDependencies`
                        // requeue, not an error.
                        //
                        // A custom resource whose kind a CRD in this bundle defines is *not* here:
                        // it is planned `Apply` at tier 11 and the CRD step above establishes the
                        // definition and refreshes discovery before it (T08.3, trap T6).
                        report.pending.insert(key.clone());
                        continue;
                    }
                }
                SyncAction::FailConflict { key, conflict } => {
                    report.failed.push(ActionFailure {
                        key: key.clone(),
                        action: "failConflict",
                        error: ReconcileError::Invalid {
                            message: format!("{}: {conflict}", key.canonical()),
                        },
                    });
                    return report;
                }
                SyncAction::Prune { key } => {
                    let hint = version_hints
                        .get(key)
                        .map(|entry| entry.version.as_str())
                        .or_else(|| {
                            by_key
                                .get(key)
                                .map(|resource| resource.gvk.version.as_str())
                        });
                    match self.pruner.prune(key, hint).await {
                        Ok(PruneResult::Pruned) => report.pruned_ok.push(key.clone()),
                        Ok(PruneResult::Retained(reason)) => {
                            report.retained += 1;
                            info!(
                                resource = %key.canonical(),
                                reason = reason.as_str(),
                                "retaining an orphan"
                            );
                        }
                        Err(error) => {
                            report.failed.push(ActionFailure {
                                key: key.clone(),
                                action: "prune",
                                error,
                            });
                            return report;
                        }
                    }
                }
                SyncAction::Apply { key } => {
                    if self
                        .run_step(key, ApplyMode::Apply, &by_key, plan, index, &mut report)
                        .await
                    {
                        return report;
                    }
                }
                SyncAction::Replace { key } => {
                    if self
                        .run_step(key, ApplyMode::Replace, &by_key, plan, index, &mut report)
                        .await
                    {
                        return report;
                    }
                }
            }
        }
        report
    }

    /// Applies one step and records its outcome; returns whether the pass must stop.
    async fn run_step(
        &self,
        key: &ResourceKey,
        mode: ApplyMode,
        desired: &BTreeMap<&ResourceKey, &DesiredResource>,
        plan: &SyncPlan,
        index: usize,
        report: &mut ExecutionReport,
    ) -> bool {
        match self.apply_step(key, mode, desired, report).await {
            Ok(outcome) => {
                record_applied(report, desired, key);
                match outcome {
                    StepOutcome::Applied => false,
                    StepOutcome::AppliedWithRefresh => {
                        report.discovery_refreshes += 1;
                        false
                    }
                    StepOutcome::RequeuePending => {
                        mark_pending(report, plan, index);
                        true
                    }
                }
            }
            Err(error) => {
                report.failed.push(ActionFailure {
                    key: key.clone(),
                    action: match mode {
                        ApplyMode::Apply => "apply",
                        ApplyMode::Replace => "replace",
                    },
                    error,
                });
                true
            }
        }
    }

    /// Creates the destination namespace unless it already exists.
    ///
    /// The namespace is applied **without** `ferriscd.io/tracking-id`: it is not a resource the
    /// Git source declares, so FerrisCD must never prune it. A namespace that *is* in Git is
    /// planned as a normal tier-0 apply instead (and stays prunable when it leaves Git).
    ///
    /// Whether the namespace existed is deliberately not reported: a `Skip(Deferred)` step is never
    /// resolved in-pass (see the module docs), so no caller can legitimately branch on it.
    async fn ensure_namespace(
        &self,
        namespace: &str,
        report: &mut ExecutionReport,
    ) -> Result<(), ReconcileError> {
        if ensure_namespace_exists(self.applier, self.reader, self.discovery, namespace).await? {
            report.apply_calls += 1;
        }
        Ok(())
    }

    /// Applies (or replaces) one desired resource.
    async fn apply_step(
        &self,
        key: &ResourceKey,
        mode: ApplyMode,
        desired: &BTreeMap<&ResourceKey, &DesiredResource>,
        report: &mut ExecutionReport,
    ) -> Result<StepOutcome, ReconcileError> {
        let Some(resource) = desired.get(key) else {
            return Err(ReconcileError::Invalid {
                message: format!(
                    "internal error: the plan asks to {} {} which is not in the desired set",
                    match mode {
                        ApplyMode::Apply => "apply",
                        ApplyMode::Replace => "replace",
                    },
                    key.canonical()
                ),
            });
        };
        let target = resolve_desired_target(self.discovery, resource).await?;
        let namespace = desired_namespace(resource, target.scope)?;

        match mode {
            ApplyMode::Replace => {
                report.apply_calls += 1;
                ReplaceRecovery::new(
                    self.applier,
                    self.reader,
                    self.discovery,
                    self.owner,
                    self.policy.replace,
                )
                .replace(key, resource, &target.api_resource, namespace.as_deref())
                .await?;
            }
            ApplyMode::Apply => {
                report.apply_calls += 1;
                match self
                    .applier
                    .apply(ApplyRequest {
                        resource,
                        api_resource: &target.api_resource,
                        namespace: namespace.as_deref(),
                        force: false,
                    })
                    .await
                {
                    Ok(_) => {}
                    Err(ReconcileError::Apply {
                        resource: offending,
                        source,
                    }) => {
                        match classify_apply_failure(&source, &self.policy.takeover_field_managers)
                        {
                            Recovery::Propagate => {
                                return Err(ReconcileError::Apply {
                                    resource: offending,
                                    source,
                                });
                            }
                            Recovery::Fail { message } => {
                                return Err(ReconcileError::Invalid {
                                    message: format!("{}: {message}", key.canonical()),
                                });
                            }
                            Recovery::Takeover { managers } => {
                                log_takeover(key, &managers);
                                report.apply_calls += 1;
                                self.applier
                                    .apply(ApplyRequest {
                                        resource,
                                        api_resource: &target.api_resource,
                                        namespace: namespace.as_deref(),
                                        force: true,
                                    })
                                    .await?;
                            }
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
        }

        self.after_apply(key).await
    }

    /// Post-apply hook: a `CustomResourceDefinition` must be established (and discovery
    /// refreshed) before its custom resources can be applied.
    async fn after_apply(&self, key: &ResourceKey) -> Result<StepOutcome, ReconcileError> {
        if !is_crd_key(key) {
            return Ok(StepOutcome::Applied);
        }
        match self.await_established(&key.name).await? {
            CrdReadiness::Established => {
                // Trap T6: the CRD is served now, but the cached discovery document is not:
                // without this refresh the custom resource would be resolved against a snapshot
                // that predates the CRD.
                self.discovery.invalidate_and_refresh().await?;
                Ok(StepOutcome::AppliedWithRefresh)
            }
            CrdReadiness::Pending => {
                warn!(
                    crd = %key.name,
                    timeout = ?self.policy.crd_timeout,
                    "the CustomResourceDefinition did not report Established=True in time; the \
                     remaining resources are requeued instead of failing"
                );
                Ok(StepOutcome::RequeuePending)
            }
            // Finding H5: an invalid definition never establishes, so a requeue loop would hide a
            // permanent error behind a `PendingDependencies` condition forever.
            CrdReadiness::Rejected { message } => Err(ReconcileError::Invalid {
                message: format!(
                    "{} was rejected by the API server and will never become established ({message}); \
                     fix the CustomResourceDefinition in Git — the custom resources that depend on \
                     it cannot be applied until it is accepted",
                    key.canonical()
                ),
            }),
        }
    }

    /// Polls the CRD for at most [`ExecutionPolicy::crd_timeout`].
    ///
    /// Stops early on a terminal `NamesAccepted=False` (finding H5): only a genuinely pending
    /// definition is worth waiting for.
    async fn await_established(&self, name: &str) -> Result<CrdReadiness, ReconcileError> {
        let deadline = std::time::Instant::now() + self.policy.crd_timeout;
        loop {
            let readiness = self.crd_status.readiness(name).await?;
            if readiness != CrdReadiness::Pending {
                return Ok(readiness);
            }
            if std::time::Instant::now() >= deadline {
                return Ok(CrdReadiness::Pending);
            }
            if !self.policy.crd_interval.is_zero() {
                tokio::time::sleep(self.policy.crd_interval).await;
            }
        }
    }
}

/// Records a confirmed apply, refreshing the version hint (never the key: ADR-003).
fn record_applied(
    report: &mut ExecutionReport,
    desired: &BTreeMap<&ResourceKey, &DesiredResource>,
    key: &ResourceKey,
) {
    let version = desired
        .get(key)
        .map(|resource| resource.gvk.version.clone())
        .unwrap_or_default();
    report
        .applied_ok
        .insert(key.clone(), InventoryEntry::new(version));
}

/// Marks everything after `index` as still to do (deferred, or waiting on a CRD).
fn mark_pending(report: &mut ExecutionReport, plan: &SyncPlan, index: usize) {
    for remaining in plan.steps.iter().skip(index + 1) {
        let waits_for_dependency = matches!(
            remaining,
            SyncAction::Skip {
                reason: PlanSkipReason::Deferred,
                ..
            }
        );
        if remaining.mutates() || waits_for_dependency {
            report.pending.insert(remaining.key().clone());
        }
    }
}

/// Creates `namespace` via Server-Side Apply (unstamped, so never prunable) when it does not yet
/// exist. Returns `Ok(true)` if the namespace was created, or `Ok(false)` if it already existed.
///
/// Shared between [`SyncExecutor::ensure_namespace`] (for `Sync` steps) and orchestrated `PreSync`
/// hooks so a `PreSync` `Job` in a brand-new destination namespace with `createNamespace: true`
/// never fails with `404 namespaces "<ns>" not found`.
pub(crate) async fn ensure_namespace_exists(
    applier: &dyn Applier,
    reader: &ClusterStateReader,
    discovery: &DiscoveryCache,
    namespace: &str,
) -> Result<bool, ReconcileError> {
    if reader.namespace_exists(namespace).await? {
        return Ok(false);
    }
    let resource = namespace_resource(namespace);
    let target = resolve_desired_target(discovery, &resource).await?;
    applier
        .apply(ApplyRequest {
            resource: &resource,
            api_resource: &target.api_resource,
            namespace: None,
            force: false,
        })
        .await?;
    info!(
        namespace = %namespace,
        "created the destination namespace (syncOptions.createNamespace)"
    );
    Ok(true)
}

/// Builds the bare `Namespace` object created by `syncOptions.createNamespace`.
///
/// Deliberately annotation-free: no `ferriscd.io/tracking-id` means the object classifies as
/// [`ferriscd_engine::inventory::Ownership::Unmanaged`] and can never be pruned by FerrisCD.
#[must_use]
pub fn namespace_resource(namespace: &str) -> DesiredResource {
    let gvk = kube::api::GroupVersionKind::gvk("", "v1", "Namespace");
    let object = DynamicObject::new(namespace, &ApiResource::from_gvk(&gvk));
    DesiredResource {
        key: ResourceKey::new("", "Namespace", None, namespace),
        gvk: GroupVersionKind {
            group: String::new(),
            version: "v1".to_owned(),
            kind: "Namespace".to_owned(),
        },
        object,
        source_file: "<syncOptions.createNamespace>".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};

    use ferriscd_crd::SyncOptions;
    use ferriscd_engine::diff::types::DiffStatus;
    use ferriscd_engine::diff::{SyncDecision, SyncTrigger};
    use ferriscd_engine::inventory::Inventory;
    use ferriscd_engine::sync::{OrphanCandidate, PlanConflict, PlanRequest};
    use kube::core::GroupVersionKind as KubeGvk;
    use kube::discovery::ApiCapabilities;
    use serde_json::{Value, json};

    use super::*;
    use crate::discovery::{DiscoveryFuture, DiscoverySnapshot, DiscoverySource};
    use crate::live_state::{FetchTarget, LiveFuture, LiveObjectSource, LiveStateError};
    use crate::sync::{DeleteOutcome, DeleteRequest};

    const NAMESPACE: &str = "payments";

    fn status(value: Value) -> kube::core::Status {
        serde_json::from_value(value).expect("valid kube Status")
    }

    // ------------------------------------------------------------------
    // Fakes
    // ------------------------------------------------------------------

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Call {
        Apply {
            key: String,
            force: bool,
            tracking_id: Option<String>,
        },
        Delete {
            key: String,
        },
    }

    #[derive(Default)]
    struct FakeCluster {
        calls: StdMutex<Vec<Call>>,
        /// Live objects served by `GET`, keyed by canonical GKNN.
        objects: StdMutex<BTreeMap<String, DynamicObject>>,
        /// Applies that always fail with the scripted error.
        failures: StdMutex<BTreeMap<String, kube::Error>>,
        /// Applies that fail **only when `force` is false** (models a `409` a forced retry can
        /// take over).
        fail_unforced: StdMutex<BTreeMap<String, kube::Error>>,
        /// Namespaces that exist.
        namespaces: StdMutex<Vec<String>>,
    }

    impl FakeCluster {
        fn with_object(self, object: DynamicObject) -> Self {
            self.objects
                .lock()
                .unwrap()
                .insert(gknn_of(&object), object);
            self
        }

        fn failing(self, key: &str, error: kube::Error) -> Self {
            self.failures.lock().unwrap().insert(key.to_owned(), error);
            self
        }

        fn failing_unless_forced(self, key: &str, error: kube::Error) -> Self {
            self.fail_unforced
                .lock()
                .unwrap()
                .insert(key.to_owned(), error);
            self
        }

        fn with_namespace(self, namespace: &str) -> Self {
            self.namespaces.lock().unwrap().push(namespace.to_owned());
            self
        }

        fn calls(&self) -> Vec<Call> {
            self.calls.lock().unwrap().clone()
        }

        fn applied(&self) -> Vec<String> {
            self.calls()
                .into_iter()
                .filter_map(|call| match call {
                    Call::Apply { key, .. } => Some(key),
                    Call::Delete { .. } => None,
                })
                .collect()
        }
    }

    fn as_apply_error(key: &str, error: &kube::Error) -> ReconcileError {
        match error {
            kube::Error::Api(status) => ReconcileError::Apply {
                resource: key.to_owned(),
                // `kube::Error` is not `Clone`, so the status is rebuilt from its cloned body.
                source: kube::Error::Api(status.clone()),
            },
            other => ReconcileError::Api(kube::Error::Service(other.to_string().into())),
        }
    }

    impl Applier for FakeCluster {
        fn apply<'a>(
            &'a self,
            request: ApplyRequest<'a>,
        ) -> BoxFuture<'a, Result<DynamicObject, ReconcileError>> {
            let key = request.resource.key.canonical();
            let force = request.force;
            let tracking_id = request
                .resource
                .object
                .metadata
                .annotations
                .as_ref()
                .and_then(|map| map.get("ferriscd.io/tracking-id"))
                .cloned();
            let body = request.resource.object.clone();
            Box::pin(async move {
                if let Some(error) = self.failures.lock().unwrap().get(&key) {
                    return Err(as_apply_error(&key, error));
                }
                if !force && let Some(error) = self.fail_unforced.lock().unwrap().get(&key) {
                    return Err(as_apply_error(&key, error));
                }
                self.calls.lock().unwrap().push(Call::Apply {
                    key,
                    force,
                    tracking_id,
                });
                Ok(body)
            })
        }

        fn delete<'a>(
            &'a self,
            request: DeleteRequest<'a>,
        ) -> BoxFuture<'a, Result<DeleteOutcome, ReconcileError>> {
            let key = request.key.canonical();
            Box::pin(async move {
                self.calls
                    .lock()
                    .unwrap()
                    .push(Call::Delete { key: key.clone() });
                self.objects.lock().unwrap().remove(&key);
                Ok(DeleteOutcome::Deleted)
            })
        }
    }

    /// Canonical GKNN string of a live object.
    fn gknn_of(object: &DynamicObject) -> String {
        let api_version = object
            .types
            .as_ref()
            .map(|types| types.api_version.clone())
            .unwrap_or_default();
        let kind = object
            .types
            .as_ref()
            .map(|types| types.kind.clone())
            .unwrap_or_default();
        let group = api_version
            .split_once('/')
            .map(|(group, _)| group)
            .unwrap_or("");
        ResourceKey::new(
            group,
            &kind,
            object.metadata.namespace.clone(),
            object.metadata.name.as_deref().unwrap_or_default(),
        )
        .canonical()
    }

    /// A live `ConfigMap` owned by this `Application` (the `Replace` precondition).
    fn owned_config_map(name: &str) -> DynamicObject {
        serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": name,
                "namespace": NAMESPACE,
                "annotations": {
                    "ferriscd.io/tracking-id":
                        format!("ferriscd-system/payments:/ConfigMap:{NAMESPACE}/{name}"),
                },
            },
            "data": { "key": "value" },
        }))
        .expect("object")
    }

    impl LiveObjectSource for FakeCluster {
        fn get<'a>(&'a self, target: FetchTarget<'a>) -> LiveFuture<'a, Option<DynamicObject>> {
            let wanted = ResourceKey::new(
                &target.api_resource.group,
                &target.api_resource.kind,
                target.namespace.map(str::to_owned),
                target.name,
            )
            .canonical();
            let object = self.objects.lock().unwrap().get(&wanted).cloned();
            Box::pin(async move { Ok(object) })
        }

        fn namespace_exists<'a>(&'a self, namespace: &'a str) -> LiveFuture<'a, bool> {
            let exists = self
                .namespaces
                .lock()
                .unwrap()
                .iter()
                .any(|existing| existing == namespace);
            Box::pin(async move { Ok(exists) })
        }
    }

    #[derive(Default)]
    struct FakePruner {
        pruned: StdMutex<Vec<String>>,
    }

    impl ResourcePruner for FakePruner {
        fn prune<'a>(
            &'a self,
            key: &'a ResourceKey,
            _version_hint: Option<&'a str>,
        ) -> BoxFuture<'a, Result<PruneResult, ReconcileError>> {
            Box::pin(async move {
                self.pruned.lock().unwrap().push(key.canonical());
                Ok(PruneResult::Pruned)
            })
        }
    }

    /// Pruner that retains everything, for the retained-count assertion.
    struct RetainingPruner;

    impl ResourcePruner for RetainingPruner {
        fn prune<'a>(
            &'a self,
            _key: &'a ResourceKey,
            _version_hint: Option<&'a str>,
        ) -> BoxFuture<'a, Result<PruneResult, ReconcileError>> {
            Box::pin(async {
                Ok(PruneResult::Retained(
                    crate::prune::RetainReason::PruneOptedOut,
                ))
            })
        }
    }

    /// Scripted `CrdStatusReader`: a queue of answers, the last one repeating.
    #[derive(Default)]
    struct FakeCrdStatus {
        answers: StdMutex<Vec<CrdReadiness>>,
        reads: AtomicUsize,
    }

    impl FakeCrdStatus {
        fn always(established: bool) -> Self {
            Self {
                answers: StdMutex::new(vec![if established {
                    CrdReadiness::Established
                } else {
                    CrdReadiness::Pending
                }]),
                reads: AtomicUsize::new(0),
            }
        }

        fn scripted(answers: Vec<CrdReadiness>) -> Self {
            Self {
                answers: StdMutex::new(answers),
                reads: AtomicUsize::new(0),
            }
        }

        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl CrdStatusReader for FakeCrdStatus {
        fn readiness<'a>(
            &'a self,
            _name: &'a str,
        ) -> BoxFuture<'a, Result<CrdReadiness, ReconcileError>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let mut answers = self.answers.lock().unwrap();
            let answer = if answers.len() > 1 {
                answers.remove(0)
            } else {
                answers.first().cloned().unwrap_or(CrdReadiness::Pending)
            };
            Box::pin(async move { Ok(answer) })
        }
    }

    #[derive(Default)]
    struct FakeDiscovery {
        snapshot: StdMutex<DiscoverySnapshot>,
        fetches: AtomicUsize,
    }

    impl FakeDiscovery {
        fn with_kinds() -> Self {
            let mut snapshot = DiscoverySnapshot::new("v1.35.0");
            for (group, kind, scope) in [
                ("", "ConfigMap", Scope::Namespaced),
                ("", "Namespace", Scope::Cluster),
                ("", "Service", Scope::Namespaced),
                ("apps", "Deployment", Scope::Namespaced),
                (
                    "apiextensions.k8s.io",
                    "CustomResourceDefinition",
                    Scope::Cluster,
                ),
                ("example.com", "Widget", Scope::Namespaced),
            ] {
                snapshot = register(snapshot, group, kind, scope);
            }
            Self {
                snapshot: StdMutex::new(snapshot),
                fetches: AtomicUsize::new(0),
            }
        }
    }

    fn register(
        snapshot: DiscoverySnapshot,
        group: &str,
        kind: &str,
        scope: Scope,
    ) -> DiscoverySnapshot {
        let mut resource = ApiResource::from_gvk(&KubeGvk::gvk(group, "v1", kind));
        resource.plural = format!("{}s", kind.to_ascii_lowercase());
        snapshot.with_resource(
            resource,
            ApiCapabilities {
                scope,
                subresources: Vec::new(),
                operations: vec!["get".to_owned(), "patch".to_owned(), "delete".to_owned()],
            },
        )
    }

    impl DiscoverySource for FakeDiscovery {
        fn fetch(&self) -> DiscoveryFuture<'_> {
            Box::pin(async move {
                self.fetches.fetch_add(1, Ordering::SeqCst);
                Ok(self.snapshot.lock().unwrap().clone())
            })
        }
    }

    struct Fixture {
        cluster: Arc<FakeCluster>,
        cache: DiscoveryCache,
        reader: ClusterStateReader,
        owner: TrackingOwner,
        pruner: FakePruner,
        crd_status: FakeCrdStatus,
    }

    fn fixture(cluster: FakeCluster, crd_status: FakeCrdStatus) -> Fixture {
        let cluster = Arc::new(cluster);
        let discovery = Arc::new(FakeDiscovery::with_kinds());
        let cache = DiscoveryCache::with_source(discovery, Duration::from_secs(3600));
        Fixture {
            cluster: cluster.clone(),
            cache,
            reader: ClusterStateReader::new(cluster),
            owner: TrackingOwner::new("ferriscd-system", "payments"),
            pruner: FakePruner::default(),
            crd_status,
        }
    }

    impl Fixture {
        async fn execute(
            &self,
            plan: &SyncPlan,
            desired: &[DesiredResource],
            policy: &ExecutionPolicy,
            pruner: &dyn ResourcePruner,
            hints: &Inventory,
        ) -> ExecutionReport {
            let applier: &dyn Applier = &*self.cluster;
            SyncExecutor::new(
                applier,
                pruner,
                &self.reader,
                &self.cache,
                &self.crd_status,
                &self.owner,
                policy,
            )
            .execute(plan, desired, hints)
            .await
        }
    }

    // ------------------------------------------------------------------
    // Fixtures
    // ------------------------------------------------------------------

    fn resource(group: &str, kind: &str, name: &str) -> DesiredResource {
        let api_version = if group.is_empty() {
            "v1".to_owned()
        } else {
            format!("{group}/v1")
        };
        let namespace = if kind == "Namespace" || kind == "CustomResourceDefinition" {
            None
        } else {
            Some(NAMESPACE)
        };
        let mut metadata = json!({ "name": name });
        if let Some(namespace) = namespace {
            metadata["namespace"] = json!(namespace);
        }
        metadata["annotations"] = json!({
            "ferriscd.io/tracking-id": format!(
                "ferriscd-system/payments:{group}/{kind}:{}/{name}",
                namespace.unwrap_or_default()
            )
        });
        DesiredResource {
            key: ResourceKey::new(group, kind, namespace.map(str::to_owned), name),
            gvk: GroupVersionKind::parse(&api_version, kind).expect("gvk"),
            object: serde_json::from_value(json!({
                "apiVersion": api_version,
                "kind": kind,
                "metadata": metadata,
            }))
            .expect("object"),
            source_file: "fixture.yaml".to_owned(),
        }
    }

    fn statuses(desired: &[DesiredResource]) -> BTreeMap<ResourceKey, DiffStatus> {
        desired
            .iter()
            .map(|resource| (resource.key.clone(), DiffStatus::Missing))
            .collect()
    }

    fn plan_for(desired: &[DesiredResource], options: &SyncOptions) -> SyncPlan {
        let statuses = statuses(desired);
        SyncPlan::build(
            &PlanRequest::new(
                SyncDecision::Execute(SyncTrigger::SourceChanged),
                desired,
                &statuses,
                options,
                NAMESPACE,
            )
            .with_prune(true),
        )
    }

    fn plan_with_orphan(
        desired: &[DesiredResource],
        options: &SyncOptions,
        orphan: &OrphanCandidate,
    ) -> SyncPlan {
        let statuses = statuses(desired);
        SyncPlan::build(
            &PlanRequest::new(
                SyncDecision::Execute(SyncTrigger::SourceChanged),
                desired,
                &statuses,
                options,
                NAMESPACE,
            )
            .with_orphans(std::slice::from_ref(orphan))
            .with_prune(true),
        )
    }

    fn key(group: &str, kind: &str, namespace: Option<&str>, name: &str) -> String {
        ResourceKey::new(group, kind, namespace.map(str::to_owned), name).canonical()
    }

    fn reason(report: &ExecutionReport) -> String {
        report
            .first_failure()
            .map(|failure| failure.error.to_string())
            .unwrap_or_default()
    }

    // ------------------------------------------------------------------
    // Ordering
    // ------------------------------------------------------------------

    /// **Verification:** the executor mutates exactly what the plan says, in plan order.
    #[tokio::test]
    async fn executes_the_plan_in_order_and_applies_only_planned_actions() {
        let fixture = fixture(FakeCluster::default(), FakeCrdStatus::always(true));
        let desired = vec![
            resource("", "ConfigMap", "settings"),
            resource("apps", "Deployment", "api"),
        ];
        let options = SyncOptions::default();
        let plan = plan_for(&desired, &options);
        let policy = ExecutionPolicy::without_waits();

        let report = fixture
            .execute(&plan, &desired, &policy, &fixture.pruner, &Inventory::new())
            .await;

        assert!(report.is_ok(), "{}", reason(&report));
        assert_eq!(
            fixture.cluster.applied(),
            vec![
                key("", "ConfigMap", Some(NAMESPACE), "settings"),
                key("apps", "Deployment", Some(NAMESPACE), "api"),
            ],
            "ConfigMap (tier 6) before Deployment (tier 9)"
        );
        assert_eq!(report.apply_calls, 2);
        assert_eq!(report.applied_ok.len(), 2);
        assert!(!report.is_pending());
        assert!(fixture.pruner.pruned.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_skipped_plan_performs_no_call() {
        let fixture = fixture(FakeCluster::default(), FakeCrdStatus::always(true));
        let desired = vec![resource("", "ConfigMap", "settings")];
        let options = SyncOptions::default();
        let synced = desired
            .iter()
            .map(|resource| (resource.key.clone(), DiffStatus::Synced))
            .collect::<BTreeMap<_, _>>();
        let plan = SyncPlan::build(&PlanRequest::new(
            SyncDecision::Skip(ferriscd_engine::diff::SkipReason::AlreadySynced),
            &desired,
            &synced,
            &options,
            NAMESPACE,
        ));
        let policy = ExecutionPolicy::without_waits();

        let report = fixture
            .execute(&plan, &desired, &policy, &fixture.pruner, &Inventory::new())
            .await;
        assert!(report.is_ok());
        assert_eq!(report.apply_calls, 0, "a skip plans no SSA apply");
        assert!(fixture.cluster.calls().is_empty());
    }

    // ------------------------------------------------------------------
    // CRD establishment + discovery refresh (trap T6 / finding C3)
    // ------------------------------------------------------------------

    /// **Verification (trap T6):** after a CRD applies, it is polled for `Established` and
    /// discovery is refreshed *before* the custom resource is resolved and applied.
    #[tokio::test]
    async fn a_crd_triggers_an_established_wait_and_a_discovery_refresh_before_its_cr() {
        let fixture = fixture(FakeCluster::default(), FakeCrdStatus::always(true));
        let desired = vec![
            resource(
                "apiextensions.k8s.io",
                "CustomResourceDefinition",
                "widgets.example.com",
            ),
            resource("example.com", "Widget", "one"),
        ];
        let options = SyncOptions::default();
        let plan = plan_for(&desired, &options);
        let policy = ExecutionPolicy::without_waits();
        let fetches_before = fixture.cache.generation();

        let report = fixture
            .execute(&plan, &desired, &policy, &fixture.pruner, &Inventory::new())
            .await;

        assert!(report.is_ok(), "{}", reason(&report));
        assert_eq!(
            fixture.cluster.applied(),
            vec![
                key(
                    "apiextensions.k8s.io",
                    "CustomResourceDefinition",
                    None,
                    "widgets.example.com"
                ),
                key("example.com", "Widget", Some(NAMESPACE), "one"),
            ],
            "the CRD must be applied first, its custom resource second"
        );
        assert!(
            fixture.cache.generation() > fetches_before,
            "an applied CRD must force a discovery refresh (trap T6)"
        );
        assert_eq!(report.discovery_refreshes, 1);
        assert!(
            fixture.crd_status.reads() >= 1,
            "Established must be polled"
        );
        assert!(report.applied_ok.contains_key(&ResourceKey::new(
            "example.com",
            "Widget",
            Some(NAMESPACE.to_owned()),
            "one"
        )));
    }

    /// **Trap guard (finding C3):** an unestablished CRD requeues; the dependent custom resource
    /// is never applied against a kind the API server does not serve.
    #[tokio::test]
    async fn an_unestablished_crd_requeues_instead_of_failing() {
        let fixture = fixture(FakeCluster::default(), FakeCrdStatus::always(false));
        let desired = vec![
            resource(
                "apiextensions.k8s.io",
                "CustomResourceDefinition",
                "widgets.example.com",
            ),
            resource("example.com", "Widget", "one"),
        ];
        let options = SyncOptions::default();
        let plan = plan_for(&desired, &options);
        let policy = ExecutionPolicy::without_waits();
        // Warm the discovery snapshot first: resolving the CRD itself fetches it once, and that
        // first fetch is not a *refresh*.
        fixture.cache.ensure_fresh().await.expect("warm discovery");
        let generation_before = fixture.cache.generation();

        let report = fixture
            .execute(&plan, &desired, &policy, &fixture.pruner, &Inventory::new())
            .await;

        assert!(report.is_ok(), "a pending CRD is not an error");
        assert!(report.is_pending());
        assert_eq!(
            report.pending,
            BTreeSet::from([ResourceKey::new(
                "example.com",
                "Widget",
                Some(NAMESPACE.to_owned()),
                "one"
            )]),
            "the custom resource is pending, never applied"
        );
        assert_eq!(
            fixture.cluster.applied(),
            vec![key(
                "apiextensions.k8s.io",
                "CustomResourceDefinition",
                None,
                "widgets.example.com"
            )]
        );
        assert_eq!(
            fixture.cache.generation(),
            generation_before,
            "no refresh is needed while the CRD is not established"
        );
        assert_eq!(
            report.discovery_refreshes, 0,
            "an unestablished CRD must not trigger a discovery refresh"
        );
        assert!(
            report.applied_ok.contains_key(&ResourceKey::new(
                "apiextensions.k8s.io",
                "CustomResourceDefinition",
                None,
                "widgets.example.com"
            )),
            "the CRD itself applied and must be tracked"
        );
    }

    /// **Trap guard (finding H5):** a CRD the API server rejects is terminal and actionable.
    #[test]
    fn crd_readiness_classifies_rejection_terminal_and_pending() {
        let rejected: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": { "name": "widgets.example.com" },
            "status": { "conditions": [
                { "type": "NamesAccepted", "status": "False", "reason": "InvalidDefinition",
                  "message": "spec.names.plural must not be empty" },
                { "type": "Established", "status": "False" },
            ] },
        }))
        .expect("object");
        let CrdReadiness::Rejected { message } = crd_readiness(&rejected) else {
            panic!(
                "NamesAccepted=False must be terminal: {:?}",
                crd_readiness(&rejected)
            );
        };
        assert!(message.contains("InvalidDefinition"), "{message}");
        assert!(message.contains("must not be empty"), "{message}");

        // `NamesAccepted=Unknown` (or absent) is a genuine "not yet", never a rejection.
        let pending: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": { "name": "widgets.example.com" },
            "status": { "conditions": [ { "type": "Established", "status": "False" } ] },
        }))
        .expect("object");
        assert_eq!(crd_readiness(&pending), CrdReadiness::Pending);

        let established: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": { "name": "widgets.example.com" },
            "status": { "conditions": [ { "type": "Established", "status": "True" } ] },
        }))
        .expect("object");
        assert_eq!(crd_readiness(&established), CrdReadiness::Established);
    }

    /// **Trap guard (finding H5):** waiting on a rejected definition fails the pass instead of
    /// requeueing forever, and the custom resource behind it is never applied.
    #[tokio::test]
    async fn a_rejected_crd_fails_the_pass_actionably() {
        let fixture = fixture(
            FakeCluster::default(),
            FakeCrdStatus::scripted(vec![CrdReadiness::Rejected {
                message: "InvalidDefinition: spec.names.plural must not be empty".to_owned(),
            }]),
        );
        let desired = vec![
            resource(
                "apiextensions.k8s.io",
                "CustomResourceDefinition",
                "widgets.example.com",
            ),
            resource("example.com", "Widget", "one"),
        ];
        let options = SyncOptions::default();
        let plan = plan_for(&desired, &options);
        let policy = ExecutionPolicy::without_waits();

        let report = fixture
            .execute(&plan, &desired, &policy, &fixture.pruner, &Inventory::new())
            .await;

        let failure = report.first_failure().expect("a rejected CRD must fail");
        assert_eq!(failure.action, "apply");
        assert_eq!(
            failure.error.failure_class(),
            crate::FailureClass::Terminal,
            "retrying a rejected definition cannot help: {}",
            failure.error
        );
        assert!(
            failure.error.to_string().contains("NamesAccepted")
                || failure.error.to_string().contains("InvalidDefinition"),
            "the failure must explain the rejection: {}",
            failure.error
        );
        assert!(
            !report.is_pending(),
            "a rejection is a failure, not a pending dependency"
        );
        assert_eq!(
            fixture.cluster.applied(),
            vec![key(
                "apiextensions.k8s.io",
                "CustomResourceDefinition",
                None,
                "widgets.example.com"
            )],
            "the custom resource behind a rejected CRD must never be applied"
        );
    }

    #[test]
    fn established_detection_reads_the_condition_list() {
        let object: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": { "name": "widgets.example.com" },
            "status": { "conditions": [
                { "type": "NamesAccepted", "status": "True" },
                { "type": "Established", "status": "False" },
            ] },
        }))
        .expect("object");
        assert!(!is_established(&object));

        let established: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": { "name": "widgets.example.com" },
            "status": { "conditions": [ { "type": "Established", "status": "True" } ] },
        }))
        .expect("object");
        assert!(is_established(&established));

        let bare: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": { "name": "widgets.example.com" },
        }))
        .expect("object");
        assert!(!is_established(&bare), "no status means not established");
    }

    #[tokio::test]
    async fn established_polling_stops_at_the_first_true() {
        let fixture = fixture(
            FakeCluster::default(),
            FakeCrdStatus::scripted(vec![CrdReadiness::Pending, CrdReadiness::Established]),
        );
        let policy = ExecutionPolicy {
            crd_timeout: Duration::from_secs(5),
            crd_interval: Duration::ZERO,
            ..ExecutionPolicy::without_waits()
        };
        let applier: &dyn Applier = &*fixture.cluster;
        let executor = SyncExecutor::new(
            applier,
            &fixture.pruner,
            &fixture.reader,
            &fixture.cache,
            &fixture.crd_status,
            &fixture.owner,
            &policy,
        );
        assert_eq!(
            executor
                .await_established("widgets.example.com")
                .await
                .expect("poll"),
            CrdReadiness::Established,
            "the second read answers Established"
        );
        assert_eq!(fixture.crd_status.reads(), 2);
    }

    // ------------------------------------------------------------------
    // Deferred plan steps (always one extra pass)
    // ------------------------------------------------------------------

    /// **Verification (T08.3):** a `Skip(Deferred)` step is never resolved in-pass — not even when
    /// the pass itself applied a CRD and refreshed discovery right before it. It is always reported
    /// pending, so the documented cost of a deferral is exactly one extra pass, unconditionally.
    #[tokio::test]
    async fn a_deferred_step_always_reports_pending_even_after_a_discovery_refresh() {
        let fixture = fixture(FakeCluster::default(), FakeCrdStatus::always(true));
        let desired = vec![
            resource(
                "apiextensions.k8s.io",
                "CustomResourceDefinition",
                "widgets.example.com",
            ),
            resource("example.com", "Widget", "one"),
        ];
        let options = SyncOptions::default();
        let crd_key = desired[0].key.clone();
        let widget_key = desired[1].key.clone();
        let statuses = BTreeMap::from([(crd_key.clone(), DiffStatus::Missing)]);
        let deferred = BTreeSet::from([widget_key.clone()]);
        let plan = SyncPlan::build(
            &PlanRequest::new(
                SyncDecision::Execute(SyncTrigger::SourceChanged),
                &desired,
                &statuses,
                &options,
                NAMESPACE,
            )
            .with_deferred(&deferred),
        );
        let policy = ExecutionPolicy::without_waits();

        let report = fixture
            .execute(&plan, &desired, &policy, &fixture.pruner, &Inventory::new())
            .await;

        assert!(report.is_ok(), "{}", reason(&report));
        assert_eq!(
            fixture.cluster.applied(),
            vec![crd_key.canonical()],
            "the deferral is never resolved in-pass, whatever ran before it"
        );
        assert_eq!(report.pending, BTreeSet::from([widget_key.clone()]));
        assert!(
            !report.applied_ok.contains_key(&widget_key),
            "a pending resource must never be tracked as applied"
        );
        assert_eq!(
            report.discovery_refreshes, 1,
            "the CRD did refresh discovery in this very pass — and that must not promote the step"
        );
    }

    /// A `Skip(Deferred)` step is applied on the **next** pass, once the live read no longer defers
    /// it. (The wired namespace deferral flow is covered end-to-end in `sync.rs`.)
    #[tokio::test]
    async fn a_deferred_step_is_applied_on_the_next_pass() {
        let fixture = fixture(FakeCluster::default(), FakeCrdStatus::always(true));
        let desired = vec![
            resource(
                "apiextensions.k8s.io",
                "CustomResourceDefinition",
                "widgets.example.com",
            ),
            resource("example.com", "Widget", "one"),
        ];
        let options = SyncOptions::default();
        let crd_key = desired[0].key.clone();
        let widget_key = desired[1].key.clone();
        let statuses = BTreeMap::from([(crd_key.clone(), DiffStatus::Missing)]);
        let deferred = BTreeSet::from([widget_key.clone()]);
        let first = SyncPlan::build(
            &PlanRequest::new(
                SyncDecision::Execute(SyncTrigger::SourceChanged),
                &desired,
                &statuses,
                &options,
                NAMESPACE,
            )
            .with_deferred(&deferred),
        );
        let policy = ExecutionPolicy::without_waits();

        let report = fixture
            .execute(
                &first,
                &desired,
                &policy,
                &fixture.pruner,
                &Inventory::new(),
            )
            .await;
        assert!(report.is_ok(), "{}", reason(&report));
        assert_eq!(report.pending, BTreeSet::from([widget_key.clone()]));

        // The requeued pass: the live read no longer defers the resource, so the plan carries a
        // plain `Apply` for it.
        let second = plan_for(&desired, &options);
        let report = fixture
            .execute(
                &second,
                &desired,
                &policy,
                &fixture.pruner,
                &Inventory::new(),
            )
            .await;

        assert!(report.is_ok(), "{}", reason(&report));
        assert!(
            report.applied_ok.contains_key(&widget_key),
            "the deferred resource applies on the extra pass"
        );
        assert!(!report.is_pending(), "nothing is left pending");
        assert_eq!(
            fixture.cluster.applied().last(),
            Some(&widget_key.canonical()),
            "the extra pass applies the deferred resource"
        );
    }

    // ------------------------------------------------------------------
    // The inventory halves
    // ------------------------------------------------------------------

    /// **Finding C1:** the keys the plan reports as `AlreadySynced` are exposed by the report, so
    /// the caller records them without a second pass over the plan.
    #[tokio::test]
    async fn synced_keys_are_reported_without_an_apply() {
        let fixture = fixture(FakeCluster::default(), FakeCrdStatus::always(true));
        let desired = vec![
            resource("", "ConfigMap", "settings"),
            resource("apps", "Deployment", "api"),
        ];
        let options = SyncOptions::default();
        let statuses = BTreeMap::from([
            (desired[0].key.clone(), DiffStatus::Synced),
            (desired[1].key.clone(), DiffStatus::OutOfSync),
        ]);
        let plan = SyncPlan::build(&PlanRequest::new(
            SyncDecision::Execute(SyncTrigger::DriftDetected),
            &desired,
            &statuses,
            &options,
            NAMESPACE,
        ));
        let policy = ExecutionPolicy::without_waits();

        let report = fixture
            .execute(&plan, &desired, &policy, &fixture.pruner, &Inventory::new())
            .await;

        assert!(report.is_ok(), "{}", reason(&report));
        assert_eq!(
            fixture.cluster.applied(),
            vec![key("apps", "Deployment", Some(NAMESPACE), "api")],
            "the synced ConfigMap is never re-applied"
        );
        assert!(report.synced_keys().contains_key(&desired[0].key));
        assert!(!report.synced_keys().contains_key(&desired[1].key));
        assert_eq!(
            report
                .synced_keys()
                .get(&desired[0].key)
                .map(|entry| entry.version.as_str()),
            Some("v1"),
            "the version hint comes from the desired resource, never from the key"
        );
        assert!(
            report.confirmed().contains_key(&desired[0].key)
                && report.confirmed().contains_key(&desired[1].key),
            "`confirmed()` is the union the inventory formula needs"
        );
    }

    // ------------------------------------------------------------------
    // createNamespace
    // ------------------------------------------------------------------

    /// **Verification:** `createNamespace: true` applies the destination namespace first, without
    /// a `tracking-id`, so FerrisCD can never prune it.
    #[tokio::test]
    async fn pre_creates_an_unstamped_namespace_before_the_first_apply() {
        let fixture = fixture(FakeCluster::default(), FakeCrdStatus::always(true));
        let desired = vec![resource("", "ConfigMap", "settings")];
        let options = SyncOptions {
            create_namespace: true,
            ..SyncOptions::default()
        };
        let plan = plan_for(&desired, &options);
        assert_eq!(plan.pre_create_namespace(), Some(NAMESPACE));
        let policy = ExecutionPolicy::without_waits();

        let report = fixture
            .execute(&plan, &desired, &policy, &fixture.pruner, &Inventory::new())
            .await;

        assert!(report.is_ok(), "{}", reason(&report));
        assert_eq!(report.apply_calls, 2, "namespace + ConfigMap");
        let calls = fixture.cluster.calls();
        assert_eq!(
            calls[0],
            Call::Apply {
                key: key("", "Namespace", None, NAMESPACE),
                force: false,
                tracking_id: None,
            },
            "the namespace is applied first and carries no ownership marker"
        );
        assert_eq!(
            calls[1],
            Call::Apply {
                key: key("", "ConfigMap", Some(NAMESPACE), "settings"),
                force: false,
                tracking_id: Some(format!(
                    "ferriscd-system/payments:/ConfigMap:{NAMESPACE}/settings"
                )),
            }
        );
        assert!(
            !report
                .applied_ok
                .contains_key(&ResourceKey::new("", "Namespace", None, NAMESPACE)),
            "a pre-created namespace is never tracked, so it is never prunable"
        );
    }

    #[tokio::test]
    async fn an_existing_namespace_is_not_re_applied() {
        let fixture = fixture(
            FakeCluster::default().with_namespace(NAMESPACE),
            FakeCrdStatus::always(true),
        );
        let desired = vec![resource("", "ConfigMap", "settings")];
        let options = SyncOptions {
            create_namespace: true,
            ..SyncOptions::default()
        };
        let plan = plan_for(&desired, &options);
        let policy = ExecutionPolicy::without_waits();

        let report = fixture
            .execute(&plan, &desired, &policy, &fixture.pruner, &Inventory::new())
            .await;
        assert_eq!(
            fixture.cluster.applied(),
            vec![key("", "ConfigMap", Some(NAMESPACE), "settings")],
            "an existing namespace must not be re-applied on every pass"
        );
        assert_eq!(report.apply_calls, 1);
    }

    // ------------------------------------------------------------------
    // Recovery (T08.4 hooks)
    // ------------------------------------------------------------------

    /// A `409` whose managers are all opted in is retried once with `force: true`.
    #[tokio::test]
    async fn a_listed_field_manager_conflict_is_taken_over_with_a_forced_retry() {
        let target = key("", "ConfigMap", Some(NAMESPACE), "settings");
        let conflict = kube::Error::Api(
            status(json!({
                "status": "Failure",
                "message": "Apply failed with 1 conflict: conflict with \"kubectl-client-side-apply\"",
                "reason": "Conflict",
                "details": { "causes": [ {
                    "reason": "FieldManagerConflict",
                    "message": "conflict with \"kubectl-client-side-apply\"",
                    "field": "data",
                } ] },
                "code": 409,
            }))
            .boxed(),
        );
        let fixture = fixture(
            FakeCluster::default().failing_unless_forced(&target, conflict),
            FakeCrdStatus::always(true),
        );
        let desired = vec![resource("", "ConfigMap", "settings")];
        let options = SyncOptions::default();
        let plan = plan_for(&desired, &options);
        let policy = ExecutionPolicy {
            takeover_field_managers: vec!["kubectl-client-side-apply".to_owned()],
            ..ExecutionPolicy::without_waits()
        };

        let report = fixture
            .execute(&plan, &desired, &policy, &fixture.pruner, &Inventory::new())
            .await;

        assert!(report.is_ok(), "{}", reason(&report));
        assert_eq!(
            fixture.cluster.calls(),
            vec![Call::Apply {
                key: target,
                force: true,
                tracking_id: Some(format!(
                    "ferriscd-system/payments:/ConfigMap:{NAMESPACE}/settings"
                )),
            }],
            "exactly one forced retry after the 409, and nothing else"
        );
        assert_eq!(
            report.apply_calls, 2,
            "one rejected attempt + one forced retry"
        );
        assert!(report.applied_ok.contains_key(&desired[0].key));
    }

    /// **Trap guard (T5):** an unlisted manager is never forced, and the failure names it.
    #[tokio::test]
    async fn an_unlisted_manager_fails_without_forcing() {
        let target = key("apps", "Deployment", Some(NAMESPACE), "api");
        let conflict = kube::Error::Api(
            status(json!({
                "status": "Failure",
                "message": "conflict",
                "reason": "Conflict",
                "details": { "causes": [ {
                    "reason": "FieldManagerConflict",
                    "message": "conflict with \"horizontal-pod-autoscaler\"",
                    "field": "spec.replicas",
                } ] },
                "code": 409,
            }))
            .boxed(),
        );
        let fixture = fixture(
            FakeCluster::default().failing(&target, conflict),
            FakeCrdStatus::always(true),
        );
        let desired = vec![resource("apps", "Deployment", "api")];
        let options = SyncOptions::default();
        let plan = plan_for(&desired, &options);
        let policy = ExecutionPolicy {
            takeover_field_managers: vec!["kubectl-client-side-apply".to_owned()],
            ..ExecutionPolicy::without_waits()
        };

        let report = fixture
            .execute(&plan, &desired, &policy, &fixture.pruner, &Inventory::new())
            .await;

        let failure = report.first_failure().expect("the apply must fail");
        assert_eq!(
            failure.error.failure_class(),
            crate::FailureClass::Terminal,
            "an HPA conflict is not retryable: {}",
            failure.error
        );
        assert!(
            failure
                .error
                .to_string()
                .contains("horizontal-pod-autoscaler"),
            "{}",
            failure.error
        );
        assert!(
            fixture.cluster.calls().is_empty(),
            "an unlisted manager must never be forced"
        );
        assert_eq!(
            report.apply_calls, 1,
            "exactly one attempt, no forced retry"
        );
    }

    /// An immutable-field `422` fails cleanly and suggests `Replace=true`.
    #[tokio::test]
    async fn an_immutable_field_failure_is_actionable() {
        let target = key("", "ConfigMap", Some(NAMESPACE), "settings");
        let immutable = kube::Error::Api(
            status(json!({
                "status": "Failure",
                "message": "ConfigMap \"settings\" is invalid: data: Invalid value: ...: field is immutable when `immutable` is set",
                "reason": "Invalid",
                "code": 422,
            }))
            .boxed(),
        );
        let fixture = fixture(
            FakeCluster::default().failing(&target, immutable),
            FakeCrdStatus::always(true),
        );
        let desired = vec![resource("", "ConfigMap", "settings")];
        let options = SyncOptions::default();
        let plan = plan_for(&desired, &options);
        let policy = ExecutionPolicy::without_waits();

        let report = fixture
            .execute(&plan, &desired, &policy, &fixture.pruner, &Inventory::new())
            .await;

        let failure = report.first_failure().expect("the apply must fail");
        assert_eq!(failure.error.failure_class(), crate::FailureClass::Terminal);
        assert!(
            failure.error.to_string().contains("Replace=true"),
            "the failure must name the opt-in: {}",
            failure.error
        );
        assert!(
            report.applied_ok.is_empty(),
            "a failed apply must never be tracked as applied (finding C1)"
        );
    }

    /// A `Replace` step re-verifies ownership, deletes, waits for the `404`, then applies.
    #[tokio::test]
    async fn a_replace_step_deletes_before_it_applies() {
        let fixture = fixture(
            FakeCluster::default().with_object(owned_config_map("settings")),
            FakeCrdStatus::always(true),
        );
        let desired = vec![resource("", "ConfigMap", "settings")];
        let plan = SyncPlan {
            pre_create_namespace: None,
            steps: vec![SyncAction::Replace {
                key: desired[0].key.clone(),
            }],
        };
        let policy = ExecutionPolicy::without_waits();

        let report = fixture
            .execute(&plan, &desired, &policy, &fixture.pruner, &Inventory::new())
            .await;

        let target = key("", "ConfigMap", Some(NAMESPACE), "settings");
        assert!(report.is_ok(), "{}", reason(&report));
        assert_eq!(
            fixture.cluster.calls(),
            vec![
                Call::Delete {
                    key: target.clone()
                },
                Call::Apply {
                    key: target,
                    force: false,
                    tracking_id: Some(format!(
                        "ferriscd-system/payments:/ConfigMap:{NAMESPACE}/settings"
                    )),
                },
            ],
            "delete, wait for 404, then a non-forced apply"
        );
        assert!(report.applied_ok.contains_key(&desired[0].key));
    }

    // ------------------------------------------------------------------
    // Prune and failure semantics
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn prunes_are_delegated_to_the_ownership_verified_pruner() {
        let fixture = fixture(FakeCluster::default(), FakeCrdStatus::always(true));
        let desired = vec![resource("", "ConfigMap", "settings")];
        let options = SyncOptions::default();
        let orphan = OrphanCandidate::owned(ResourceKey::new(
            "",
            "Service",
            Some(NAMESPACE.to_owned()),
            "removed",
        ));
        let plan = plan_with_orphan(&desired, &options, &orphan);
        let policy = ExecutionPolicy::without_waits();

        let report = fixture
            .execute(&plan, &desired, &policy, &fixture.pruner, &Inventory::new())
            .await;

        assert!(report.is_ok(), "{}", reason(&report));
        assert_eq!(
            *fixture.pruner.pruned.lock().unwrap(),
            vec![key("", "Service", Some(NAMESPACE), "removed")],
            "prunes go through the pruner, never through the applier"
        );
        assert_eq!(
            report.pruned_ok,
            vec![ResourceKey::new(
                "",
                "Service",
                Some(NAMESPACE.to_owned()),
                "removed"
            )]
        );
    }

    #[tokio::test]
    async fn a_retained_orphan_is_counted_but_not_pruned_ok() {
        let fixture = fixture(FakeCluster::default(), FakeCrdStatus::always(true));
        let desired = vec![resource("", "ConfigMap", "settings")];
        let options = SyncOptions::default();
        let orphan = OrphanCandidate::owned(ResourceKey::new(
            "",
            "Service",
            Some(NAMESPACE.to_owned()),
            "removed",
        ));
        let plan = plan_with_orphan(&desired, &options, &orphan);
        let policy = ExecutionPolicy::without_waits();

        let report = fixture
            .execute(
                &plan,
                &desired,
                &policy,
                &RetainingPruner,
                &Inventory::new(),
            )
            .await;
        assert!(report.is_ok());
        assert_eq!(report.retained, 1);
        assert!(report.pruned_ok.is_empty());
    }

    /// **Finding C1:** a failure stops execution but keeps everything already confirmed.
    #[tokio::test]
    async fn a_failure_stops_execution_and_keeps_the_confirmed_applies() {
        // Plan order is tier order: ConfigMap (6) -> Service (8) -> Deployment (9). Failing the
        // Service proves both halves: the ConfigMap before it stays confirmed, the Deployment
        // after it is never attempted.
        let fixture = fixture(
            FakeCluster::default().failing(
                &key("", "Service", Some(NAMESPACE), "api"),
                kube::Error::Api(
                    kube::core::Status::failure("nope", "InternalError")
                        .with_code(500)
                        .boxed(),
                ),
            ),
            FakeCrdStatus::always(true),
        );
        let desired = vec![
            resource("", "ConfigMap", "settings"),
            resource("apps", "Deployment", "api"),
            resource("", "Service", "api"),
        ];
        let options = SyncOptions::default();
        let plan = plan_for(&desired, &options);
        let policy = ExecutionPolicy::without_waits();

        let report = fixture
            .execute(&plan, &desired, &policy, &fixture.pruner, &Inventory::new())
            .await;

        assert!(!report.is_ok());
        assert_eq!(
            report
                .first_failure()
                .map(|failure| failure.key.canonical())
                .as_deref(),
            Some("/Service/payments/api")
        );
        assert!(
            report.applied_ok.contains_key(&desired[0].key),
            "the ConfigMap applied before the failure must stay confirmed (finding C1)"
        );
        assert!(
            !report.applied_ok.contains_key(&desired[1].key),
            "the Deployment is planned after the failing Service and must not be applied"
        );
        assert_eq!(
            fixture.cluster.applied(),
            vec![key("", "ConfigMap", Some(NAMESPACE), "settings")],
            "execution stops at the failure"
        );
    }

    #[tokio::test]
    async fn a_foreign_object_blocks_the_pass_without_any_mutation() {
        let fixture = fixture(FakeCluster::default(), FakeCrdStatus::always(true));
        let desired = vec![resource("", "ConfigMap", "settings")];
        let plan = SyncPlan {
            pre_create_namespace: None,
            steps: vec![SyncAction::FailConflict {
                key: desired[0].key.clone(),
                conflict: PlanConflict::ForeignOwner {
                    owner: "ferriscd-system/other:/ConfigMap:payments/settings".to_owned(),
                },
            }],
        };
        let policy = ExecutionPolicy::without_waits();

        let report = fixture
            .execute(&plan, &desired, &policy, &fixture.pruner, &Inventory::new())
            .await;

        let failure = report.first_failure().expect("the pass must fail");
        assert_eq!(failure.action, "failConflict");
        assert_eq!(failure.error.failure_class(), crate::FailureClass::Terminal);
        assert!(failure.error.to_string().contains("another Application"));
        assert!(fixture.cluster.calls().is_empty(), "nothing may be mutated");
    }

    #[test]
    fn the_namespace_object_is_never_stamped_and_parses() {
        let resource = namespace_resource("team-a");
        assert_eq!(resource.key.canonical(), "/Namespace//team-a");
        assert!(
            resource
                .object
                .metadata
                .annotations
                .as_ref()
                .is_none_or(|annotations| annotations.is_empty()),
            "a pre-created namespace must not look owned"
        );
        assert_eq!(resource.gvk.kind, "Namespace");
        assert!(resource.object.metadata.name.is_some());
    }

    #[test]
    fn live_state_errors_are_classified_through_the_executor_error_type() {
        let err: ReconcileError = LiveStateError::Api {
            resource: "/ConfigMap/payments/settings".to_owned(),
            code: 500,
            message: "boom".to_owned(),
        }
        .into();
        assert_eq!(err.failure_class(), crate::FailureClass::Retryable);
    }
}
