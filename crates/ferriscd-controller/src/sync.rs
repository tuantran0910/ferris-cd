//! The wired sync pipeline: `Application` -> Git -> manifests -> scope -> live state ->
//! SSA `dryRun=All` diff -> sync decision -> [`SyncPlan`] -> [`SyncExecutor`] -> crash-safe
//! inventory -> `/status`.
//!
//! Phase 07 replaced the `v0.2` "apply everything on every pass" loop with a diff-gated one: the
//! pipeline classifies the whole bundle with a Server-Side Apply dry-run (T07.1–T07.3) and asks
//! [`ferriscd_engine::diff::should_sync`] whether this reconcile may apply anything (T07.4).
//! Phase 08 turns that verdict into an explicit [`SyncPlan`] (T08.2) and executes it with
//! [`SyncExecutor`] (T08.3–T08.5) instead of looping over the desired set here.
//!
//! | Concern | Here |
//! |---|---|
//! | Drift detection | `crate::dry_run` (SSA `dryRun=All`, `ignoreDifferences` honoured) |
//! | Sync decision gate | `ferriscd_engine::diff::should_sync` (`automated`, `selfHeal`, source change, manual operation) |
//! | What may be mutated | `ferriscd_engine::sync::SyncPlan` (pure: order, rails, skip reasons) |
//! | How it is mutated | [`SyncExecutor`]: SSA apply, `Replace` (delete → `404` → apply), ownership-verified prune, CRD `Established` wait + discovery refresh |
//! | Force / takeover | `force: false` on every first attempt (trap T5); one forced retry only for managers listed in `syncOptions.takeoverFieldManagers` (T08.4) |
//! | Prune | `automated.prune` + the gate; `OwnedBySelf` only, re-verified immediately before `Delete`; `CRD`/`Namespace` need `pruneCRDs`/`pruneNamespaces`; exact reverse apply order (T08.5) |
//! | CRD `Established` wait | bounded poll + `DiscoveryCache::invalidate_and_refresh()` before the CRs, so a CRD + CR pair lands on the **first** sync (T08.3) |
//! | `createNamespace: true` | `SyncPlan::pre_create_namespace`: the namespace is SSA-applied (unstamped, so never prunable) before the first step |
//! | Rendering | `spec.source.renderer` via the Phase 11 `RenderPipeline` (auto-detected plain/YAML, Kustomize, or Helm; one parse+normalize funnel; tier-sorted; cached per render tuple) |
//! | Waves | `ferriscd_engine::graph::waves`: the permanent set grouped by `ferriscd.io/sync-wave`, applied one wave per pass, gated on the wave being `Healthy` (`T10.2`) |
//! | Hooks | `crate::hooks`: created with `Api::create` (so `generateName` works), tracked in `status.operationState.activeHooks`, reaped by their delete policy, never in `status.inventory` (`T10.3`/`T10.4`) |
//! | Operation state | `ferriscd_engine::sync::SyncMachine`: `PreSync` -> `Sync(wave)` -> `PostSync` -> `Succeeded`, persisted before the requeue, 5 s while waiting, 10 min timeouts (`T10.1`) |
//! | History & rollback | `ferriscd_engine::sync::history`: bounded `status.history`, and `{"rollback":{"id":N}}` pinned before the diff gate with automation disabled (`T10.5`) |
//! | Tenancy policy | `ferriscd_engine::policy::AppProjectPolicy`: the referenced `AppProject` is read from the control-plane namespace and enforced **before** the repository is resolved, then re-checked on **every** rendered resource after scope normalization (`T12.1`) |
//! | Application namespaces | `--application-namespaces` widens the watch (`T12.2`), and a tenant `Application` is refused unless its project lists its namespace and it names its own authorized `serviceAccountName` |
//! | Impersonation | `crate::impersonation` (`T12.3`): an `Application` with `spec.serviceAccountName` deploys as that ServiceAccount in `spec.destination.namespace` — live reads, `dryRun=All` diffs, applies, deletes/hooks and the cascade cleanup all run as it — while the `Application`'s own `/status` and finalizer stay with the controller |
//! | Destination clusters | `crate::cluster_manager` (`T13.1`): `in-cluster` uses the controller's own seams, any other name resolves through the `ClusterManager` registry, and **every** workload call of the pass (live reads, `dryRun=All` diffs, applies, deletes, hooks, prune, cascade) runs over that cluster's client and discovery — while the `Application`'s `/status` and finalizer stay on the control plane |
//! | Git credentials | `ferriscd.io/secret-type=repository` Secrets in the control-plane namespace (`T12.4`): exact URL or longest-prefix match, one scoped label-filtered list per resolve, no match is anonymous |
//! | Health | evaluated from the pass-level live read on **every** pass (including a `Skip`), into `status.health` + `status.resources`, and it is what the wave gate waits on (`T09.5`, `T10.2`) |
//!
//! Blocking work never runs on a Tokio worker: manifest file I/O and YAML parsing run in
//! `tokio::task::spawn_blocking` here, and the repo/git layer does the same internally. Every
//! Kubernetes call — the live GETs, the `dryRun=All` PATCHes and the real applies — is a plain
//! async `kube` request. The diff *comparison* itself is CPU-only engine code over the payloads
//! the API server returned, so it never blocks a worker on a syscall either.
//!
//! A resource whose namespace is created *by this bundle's* `Namespace` manifest is deferred to
//! the next pass (`DeferredPendingNamespace`): the namespace has to exist before anything can be
//! applied into it, and the requeue is the documented "not an error" path
//! ([`PENDING_REQUEUE`]). `syncOptions.createNamespace` removes that wait by creating the
//! namespace up front.
//!
//! Three safety properties are non-negotiable and implemented here:
//!
//! * **Ownership is verified before any mutation** (the `T06.4` trap guard, trap T10). Every
//!   desired key whose live object carries a *foreign* `ferriscd.io/tracking-id` fails the
//!   reconcile **before** a single `Patch` is issued — before the dry-run pass too — so two
//!   `Application`s pointing at the same manifest can never fight over (or prune) each other's
//!   workloads. The failure is terminal (retrying cannot help) and still reports
//!   `status.sync.status = OutOfSync`. Prunes and `Replace`s re-verify the same marker
//!   immediately before their `Delete`.
//! * **Nothing is applied without proof it is needed.** The dry-run diff decides; a `Skip` from
//!   [`should_sync`] issues **zero** mutating `Patch` calls, and a second reconcile of an
//!   already-synced `Application` converges to exactly that (the assertion the T07.5 live test
//!   makes against a real API server).
//! * **The inventory is crash-safe.** It is only ever `next_inventory(prev, confirmed,
//!   pruned_ok)`, and a mid-sync failure still persists the partial inventory
//!   ([`ReconcileError::PartialSync`] / [`ReconcileError::SyncConflict`]), so a create that
//!   already succeeded can never become an untracked orphan (finding C1).
//! * **A wave is only done when it is `Healthy`** (`T10.2`). A pass applies **one** wave per
//!   requeue and never sleeps waiting for it: the phase (`Sync(wave -1)`, …) lives in
//!   `status.operationState`, which is patched *before* the requeue, so a controller restart resumes
//!   where it stopped. A wave that carries a `CustomResourceDefinition` refreshes discovery before
//!   the next wave (`WavePlan::contains_crd`), which is the `T08.3` rule lifted to the wave boundary.
//! * **A hook is never desired state** (`T10.3`). Hooks are partitioned out before anything is
//!   stamped, planned, diffed or inventoried; they are created with `Api::create` and tracked in
//!   `status.operationState.activeHooks` by their rendered id, so a requeue observes the `Job` the
//!   previous pass created instead of running the migration again (finding H2).
//! * **A rollback is pinned, not compared** (`T10.5`). `{"rollback":{"id":N}}` is parsed before the
//!   diff gate: the pass renders the *historical* commit, removes `spec.syncPolicy.automated` and
//!   records a `Warning` condition, because a rollback `selfHeal` immediately reverts is not a
//!   rollback.
//! * **`Synced` is never reported as `Healthy`** (`T09.5` trap guard). `status.sync.status` comes
//!   from the diff, `status.health.status` from the live objects' `status` blocks; a pass that
//!   applies nothing still assesses health, and a pass that applied everything still reports
//!   `Progressing` for the objects it just created (the live read predates the write).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ferriscd_crd::status::{
    ApplicationStatus, HealthState, OperationPhase, OperationState, REASON_SYNC_SUCCEEDED,
    ResourceStatus, RevisionHistoryEntry, SyncPhase, SyncState, SyncStatus,
};
use ferriscd_crd::{Application, SyncOptions, annotations};
use ferriscd_engine::diff::{
    DiffStatus, DiffSummary, IgnoreRuleSet, ResourceDiff, SyncDecision, SyncTrigger, should_sync,
    source_spec_hash,
};
use ferriscd_engine::graph::sort_keys_prune_order;
use ferriscd_engine::health::{
    self, HealthConfig, HealthInput, HealthRegistry, HealthStatus, HealthSummary,
};
use ferriscd_engine::inventory::{self, Inventory, Ownership};
use ferriscd_engine::manifest::{
    self, DesiredResource, ManifestLoaderConfig, RenderContext, RenderPipeline, RendererBinaries,
    ResourceKey,
};
use ferriscd_engine::policy::{AppProjectPolicy, ApplicationScope, PolicyError};
use ferriscd_engine::repo::{GitSource, RepoCache, RepoCredentials, RepoUrlPolicy};
use ferriscd_engine::sync::{
    DEFAULT_REQUEUE_AFTER, OrphanCandidate, OrphanOwnership, PlanRequest, RollbackDecision,
    RollbackError, StepAction, SyncMachine, SyncPlan, SyncStep, parse_rollback_request,
    plan_rollback, record_operation_success,
};
use futures::future::BoxFuture;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use kube::ResourceExt;
use kube::api::{Api, ApiResource, DeleteParams, DynamicObject, Patch, PatchParams, PostParams};
use tracing::{Instrument as _, warn};

use crate::cluster_manager::{ClusterError, ClusterSource, ClusterTarget};
use crate::controller::FailureClass;
use crate::credentials::CredentialSource;
use crate::discovery::DiscoveryCache;
use crate::dry_run::{DryRunApi, DryRunEvaluator};
use crate::hooks::{self, HookCluster, HookRun};
use crate::impersonation::{
    ClusterAccess, ClusterIdentity, Impersonation, ImpersonationError, ImpersonationSource,
};
use crate::live_state::{
    ClusterStateReader, LiveObjectSource, LiveState, LiveStateMap, TrackingOwner, plan_fetch,
};
use crate::project::ProjectSource;
use crate::prune::{OwnershipVerifiedPruner, PruneResult};
use crate::reconcile::{
    ApplyOutcome, CleanupMode, CleanupOutcome, DiffPreview, REASON_PENDING, REASON_SYNC_SKIPPED,
    ReconcileError, SyncPipeline, now,
};
use crate::scope::{self, InBundleCrd};
use crate::sync_executor::{
    ActionFailure, ExecutionPolicy, ExecutionReport, LiveCrdStatusReader, SyncExecutor,
};
use crate::waves::{self, BundleWaves};

/// Requeue delay while any resource is pending on a `CustomResourceDefinition` or namespace.
///
/// A pending resource is not an error (it is the documented `DeferredPending*` behaviour), so
/// the controller retries quickly instead of waiting for the full `spec.requeueAfterSeconds`.
pub const PENDING_REQUEUE: Duration = Duration::from_secs(10);

/// Upper bound on the requeue delay while an `Application` is `Progressing` (`T09.5`).
///
/// A rollout is expected to converge in seconds, so a settled interval of three minutes means the
/// operator (and the sync wave that waits for it, in Phase 10) waits three minutes for a `Healthy`
/// verdict that was available after ten seconds. While anything is still converging the controller
/// polls at least this often; the interval is never *longer* than the configured
/// `spec.requeueAfterSeconds` (so an operator who asked for a 3 s interval keeps it).
pub const PROGRESSING_REQUEUE: Duration = Duration::from_secs(10);

/// `Ready` reason while a multi-wave/hook operation is between requeues (`T10.2`).
///
/// A pass that dispatched one wave is neither `Synced` (later waves have not been applied yet) nor
/// idle: the operator has to be able to tell "FerrisCD is working through the waves" from "nothing
/// happened".
pub const REASON_SYNC_IN_PROGRESS: &str = "SyncInProgress";

/// The destination cluster name that means "the cluster the controller runs in".
///
/// Every other name is resolved through the [`ClusterSource`] registry (`T13.1`); this one is
/// always available and never goes through a `Secret`.
pub const IN_CLUSTER: &str = crate::cluster_manager::IN_CLUSTER;

/// Opt-in switch for syncing an **empty** desired set over a non-empty inventory.
///
/// An empty desired set (a wrong `spec.source.git.path`, an empty repository, a botched
/// template render) is indistinguishable from "the operator removed everything". Refusing it by
/// default is the only way to keep prune from deleting an entire `Application` by accident;
/// setting `FERRISCD_ALLOW_EMPTY_DESIRED=1` (or `true`) restores the literal GitOps behaviour.
pub const ALLOW_EMPTY_DESIRED_ENV: &str = "FERRISCD_ALLOW_EMPTY_DESIRED";

/// How many invalid `ignoreDifferences` pointers are logged individually per reconcile.
///
/// The rule set is compiled on every pass, so an `Application` with thousands of typos must not
/// turn each reconcile into thousands of log lines. The full count still reaches
/// `Application.status` through the `Ready` message.
pub const MAX_LOGGED_INVALID_POINTERS: usize = 8;

/// What the `Ready` condition message reports.
#[derive(Clone, Debug, Default)]
struct SyncCounts {
    /// Resources in the desired set.
    desired: usize,
    /// Resources whose SSA apply was confirmed.
    applied: usize,
    /// Orphans whose delete (or absence) was confirmed.
    pruned: usize,
    /// Orphans left in place: not verifiably ours, still deferred, or protected by a rail.
    retained_orphans: usize,
    /// Resources deferred on a `CustomResourceDefinition` or a `Namespace`.
    pending: usize,
    /// `ignoreDifferences` pointers that are not valid RFC 6901 and were therefore ignored
    /// (finding H1).
    invalid_ignore_pointers: usize,
    /// Whether `spec.syncPolicy.automated.prune` is enabled.
    ///
    /// It decides how a retained orphan is reported: with pruning enabled an orphan still means
    /// "a prune is due" (`OutOfSync`), with pruning disabled it can never be deleted, so it must
    /// not pin the status (finding H2).
    prune_enabled: bool,
    /// The aggregated health verdict of this pass (`T09.5`).
    ///
    /// It only selects the requeue interval ([`plan_requeue`]): a `Progressing` `Application` is
    /// polled every [`PROGRESSING_REQUEUE`] instead of every `spec.requeueAfterSeconds`. It never
    /// touches `status.sync.status` — synced and healthy are different questions.
    health: HealthStatus,
    /// Whether this pass completed the sync and may therefore claim `Synced`.
    ///
    /// A pass that dispatched one wave of a multi-wave rollout applied everything it was asked to,
    /// but it is **not** a finished sync: the remaining waves have not been applied yet.
    settled: bool,
    /// The step an in-flight operation is waiting on (`Sync(wave 0)`, `PreSync`, …).
    phase: Option<String>,
    /// The state machine's requeue hint, which wins over the adaptive interval.
    requeue: Option<Duration>,
}

/// One Server-Side Apply call.
#[derive(Debug)]
pub struct ApplyRequest<'a> {
    /// The desired resource (already normalized, scoped and tracking-id stamped).
    pub resource: &'a DesiredResource,
    /// Discovered resource (carries the real plural name and served version).
    pub api_resource: &'a ApiResource,
    /// Namespace for a namespaced resource; `None` for a cluster-scoped one.
    pub namespace: Option<&'a str>,
    /// `force` for the apply patch. `v0.2` always passes `false`.
    pub force: bool,
}

/// One delete call.
#[derive(Debug)]
pub struct DeleteRequest<'a> {
    /// Version-agnostic identity of the object to delete.
    pub key: &'a ResourceKey,
    /// Discovered resource of the object's kind.
    pub api_resource: &'a ApiResource,
    /// Namespace for a namespaced resource; `None` for a cluster-scoped one.
    pub namespace: Option<&'a str>,
}

/// Whether a delete confirmed that the object is gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeleteOutcome {
    /// The API server accepted the delete.
    Deleted,
    /// The object was already absent (`404`/`410`), which counts as a confirmed prune.
    AlreadyGone,
}

/// One imperative create of a lifecycle hook (`T10.3`).
#[derive(Debug)]
pub struct CreateRequest<'a> {
    /// The hook's rendered object (it is never part of the desired state).
    pub resource: &'a DesiredResource,
    /// Discovered resource of the hook's kind.
    pub api_resource: &'a ApiResource,
    /// Namespace for a namespaced hook; `None` for a cluster-scoped one.
    pub namespace: Option<&'a str>,
}

/// One JSON merge patch on the `Application`'s **own** object (`T10.5`).
///
/// A rollback mutates `spec.syncPolicy.automated` and consumes the `ferriscd.io/operation`
/// annotation, neither of which is part of the `/status` subresource. Both go through this narrow,
/// typed seam so a test can assert exactly which patch a pass issued without an API server.
#[derive(Debug)]
pub struct ApplicationPatch<'a> {
    /// Namespace of the `Application`.
    pub namespace: &'a str,
    /// Name of the `Application`.
    pub name: &'a str,
    /// Merge-patch body (never contains a manifest, never a secret).
    pub patch: serde_json::Value,
}

/// Cluster mutation seam, so the pipeline is testable without an API server.
pub trait Applier: Send + Sync + 'static {
    /// Server-Side Applies one desired resource.
    fn apply<'a>(
        &'a self,
        request: ApplyRequest<'a>,
    ) -> BoxFuture<'a, Result<DynamicObject, ReconcileError>>;

    /// Deletes one previously managed resource.
    fn delete<'a>(
        &'a self,
        request: DeleteRequest<'a>,
    ) -> BoxFuture<'a, Result<DeleteOutcome, ReconcileError>>;

    /// Creates one lifecycle hook (`Api::create`, so `metadata.generateName` is honoured).
    ///
    /// Default: a terminal error. A hook is never applied as desired state, so a cluster seam that
    /// only knows how to patch cannot run one, and silently doing nothing would report a
    /// `PreSync` migration as done.
    fn create<'a>(
        &'a self,
        _request: CreateRequest<'a>,
    ) -> BoxFuture<'a, Result<DynamicObject, ReconcileError>> {
        Box::pin(async {
            Err(ReconcileError::Invalid {
                message: "this cluster seam cannot create lifecycle hooks (Api::create is \
                          required for generateName hooks)"
                    .to_owned(),
            })
        })
    }

    /// Patches the `Application`'s own object (`spec`/`metadata`, never `/status`).
    ///
    /// Deliberately **not** impersonated (`T12.3`): the object is the tenant's `Application` CR,
    /// which the tenant's ServiceAccount typically cannot write, and the controller must always be
    /// able to record a rollback (`T10.5`) even when the destination is unavailable.
    fn patch_application<'a>(
        &'a self,
        _request: ApplicationPatch<'a>,
    ) -> BoxFuture<'a, Result<(), ReconcileError>> {
        Box::pin(async {
            Err(ReconcileError::Invalid {
                message: "this cluster seam cannot patch the Application spec/metadata".to_owned(),
            })
        })
    }
}

/// [`Applier`] backed by dynamic `Api` clients.
#[derive(Clone)]
pub struct DynamicApiApplier {
    client: kube::Client,
    field_manager: String,
}

impl std::fmt::Debug for DynamicApiApplier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicApiApplier")
            .field("field_manager", &self.field_manager)
            .finish_non_exhaustive()
    }
}

impl DynamicApiApplier {
    /// Builds an applier that always applies with the FerrisCD field manager.
    #[must_use]
    pub fn new(client: kube::Client) -> Self {
        Self {
            client,
            field_manager: Self::field_manager(),
        }
    }

    /// The field manager every apply uses (trap T5: one stable manager, never `client-side`).
    ///
    /// Split out of [`Self::new`] so tests can prove the construction path without a cluster:
    /// it must be [`ferriscd_engine::default_field_manager`], never a literal.
    #[must_use]
    fn field_manager() -> String {
        ferriscd_engine::default_field_manager().to_owned()
    }
}

/// Builds the `PatchParams` of one Server-Side Apply patch.
///
/// `force` is the trap T5 lever: `true` silently steals fields an HPA or another controller
/// owns. `v0.2` pins it to `false`, so a `409` stays visible instead of being resolved by
/// clobbering.
fn apply_patch_params(field_manager: &str, force: bool) -> PatchParams {
    let mut params = PatchParams::apply(field_manager);
    params.force = force;
    params
}

impl Applier for DynamicApiApplier {
    fn apply<'a>(
        &'a self,
        request: ApplyRequest<'a>,
    ) -> BoxFuture<'a, Result<DynamicObject, ReconcileError>> {
        let client = self.client.clone();
        let field_manager = self.field_manager.clone();
        Box::pin(async move {
            let name = request.resource.key.name.clone();
            let resource = request.resource.key.canonical();
            let api: Api<DynamicObject> =
                dynamic_api(&client, request.api_resource, request.namespace);
            // Strip `.status` (and be idempotent if the caller already did).
            let body = apply_body(&request.resource.object);

            let params = apply_patch_params(&field_manager, request.force);

            api.patch(&name, &params, &Patch::Apply(&body))
                .await
                .map_err(|source| ReconcileError::Apply { resource, source })
        })
    }

    fn delete<'a>(
        &'a self,
        request: DeleteRequest<'a>,
    ) -> BoxFuture<'a, Result<DeleteOutcome, ReconcileError>> {
        let client = self.client.clone();
        Box::pin(async move {
            let resource = request.key.canonical();
            let api: Api<DynamicObject> =
                dynamic_api(&client, request.api_resource, request.namespace);
            // `background()` (finding H1): the API server owns garbage collection, so a
            // finalizer can never block this worker while the object drains.
            match api
                .delete(&request.key.name, &DeleteParams::background())
                .await
            {
                Ok(_) => Ok(DeleteOutcome::Deleted),
                Err(err) if is_absent(&err) => Ok(DeleteOutcome::AlreadyGone),
                Err(source) => Err(ReconcileError::Delete { resource, source }),
            }
        })
    }

    /// Creates a hook with `Api::create`, which is the *only* way `metadata.generateName` works.
    ///
    /// A `PreSync` migration must not be Server-Side Applied: SSA needs a name, so a
    /// `generateName: migrate-` Job would either be rejected or (worse) overwrite the previous
    /// run of a hook that has the same explicit name (finding H2).
    fn create<'a>(
        &'a self,
        request: CreateRequest<'a>,
    ) -> BoxFuture<'a, Result<DynamicObject, ReconcileError>> {
        let client = self.client.clone();
        Box::pin(async move {
            let resource = request.resource.key.canonical();
            let api: Api<DynamicObject> =
                dynamic_api(&client, request.api_resource, request.namespace);
            let body = apply_body(&request.resource.object);
            api.create(&PostParams::default(), &body)
                .await
                .map_err(|source| ReconcileError::Apply { resource, source })
        })
    }

    fn patch_application<'a>(
        &'a self,
        request: ApplicationPatch<'a>,
    ) -> BoxFuture<'a, Result<(), ReconcileError>> {
        let client = self.client.clone();
        Box::pin(async move {
            let api: Api<Application> = Api::namespaced(client, request.namespace);
            api.patch(
                request.name,
                &PatchParams::default(),
                &Patch::Merge(&request.patch),
            )
            .await?;
            Ok(())
        })
    }
}

/// Builds the dynamic `Api` for `api_resource`, namespaced when `namespace` is set.
fn dynamic_api(
    client: &kube::Client,
    api_resource: &ApiResource,
    namespace: Option<&str>,
) -> Api<DynamicObject> {
    match namespace {
        Some(namespace) => Api::namespaced_with(client.clone(), namespace, api_resource),
        None => Api::all_with(client.clone(), api_resource),
    }
}

/// Returns whether `err` means "the object is not there" (`404`/`410`).
fn is_absent(err: &kube::Error) -> bool {
    matches!(err, kube::Error::Api(status) if status.code == 404 || status.code == 410)
}

/// Returns a copy of `object` with the top-level `status` field removed.
///
/// `manifest::normalize` strips it too; doing it again immediately before the apply keeps the
/// SSA safety default intact even if a caller hands the applier an unnormalized object.
#[must_use]
pub fn apply_body(object: &DynamicObject) -> DynamicObject {
    let mut body = object.clone();
    if let Some(map) = body.data.as_object_mut() {
        map.remove("status");
    }
    body
}

/// Everything one pass needs once the diff gate has decided (`T08.2`, `T10.2`).
struct PassRequest<'a> {
    app: &'a Application,
    /// The cluster access this pass acts through (`T12.3`): the pipeline's own seams for a
    /// controller-identity `Application`, the pooled impersonated client for a tenant one.
    access: ClusterAccess,
    /// The destination cluster's discovery cache (`T13.1`): a remote cluster's API surface is not
    /// the control plane's, so nothing in the pass may fall back to it.
    discovery: &'a DiscoveryCache,
    owner: &'a TrackingOwner,
    revision: &'a str,
    bundle: &'a BundleWaves,
    live: &'a LiveStateMap,
    statuses: &'a BTreeMap<ResourceKey, DiffStatus>,
    deferred: &'a BTreeSet<ResourceKey>,
    orphans: &'a [OrphanCandidate],
    options: &'a SyncOptions,
    decision: SyncDecision,
    prune_enabled: bool,
    prev_inventory: &'a Inventory,
    now: &'a Time,
}

/// What one pass executed, aggregated over the plans it ran (one per wave, plus the prune step).
#[derive(Debug, Default)]
struct PassExecution {
    /// One report per executed plan, in execution order.
    reports: Vec<ExecutionReport>,
    /// Mutating applies issued outside a `SyncPlan` report (e.g. `createNamespace` before `PreSync`).
    extra_apply_calls: usize,
    /// Orphans deliberately kept (planner `Skip`s and deletes the pruner declined).
    retained: usize,
    /// The `status.operationState` to persist (`None` = leave it untouched).
    operation: Option<OperationState>,
    /// Whether this pass completed the sync, i.e. may claim `Synced` and advance `lastSynced*`.
    settled: bool,
    /// The state machine's requeue hint while an operation is in flight.
    requeue: Option<Duration>,
}

impl PassExecution {
    /// Everything the pass confirmed (applies plus diff-verified live state).
    fn confirmed(&self) -> Inventory {
        let mut confirmed = Inventory::new();
        for report in &self.reports {
            for (key, entry) in report.confirmed() {
                confirmed.entry(key).or_insert(entry);
            }
        }
        confirmed
    }

    /// How many resources this pass actually wrote.
    fn applied(&self) -> usize {
        self.reports
            .iter()
            .map(|report| report.applied_ok.len())
            .sum()
    }

    /// Every confirmed prune.
    fn pruned_ok(&self) -> Vec<ResourceKey> {
        self.reports
            .iter()
            .flat_map(|report| report.pruned_ok.iter().cloned())
            .collect()
    }

    /// Everything still to do (deferred on a CRD/namespace).
    fn pending(&self) -> BTreeSet<ResourceKey> {
        let mut pending = BTreeSet::new();
        for report in &self.reports {
            pending.extend(report.pending.iter().cloned());
        }
        pending
    }

    /// How many mutating Server-Side Apply calls the pass issued.
    fn apply_calls(&self) -> usize {
        self.extra_apply_calls
            + self
                .reports
                .iter()
                .map(|report| report.apply_calls)
                .sum::<usize>()
    }

    /// The first failure, in execution order.
    fn first_failure(&self) -> Option<&ActionFailure> {
        self.reports.iter().find_map(ExecutionReport::first_failure)
    }
}

/// A rollback this pass must honour (`T10.5`).
struct RollbackRequested {
    decision: RollbackDecision,
}

/// Whether a prepared pass may write to the cluster (`T14.1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PassMode {
    /// A full reconcile: applies, prunes, `/status` patches, and the documented rollback spec edit.
    Apply,
    /// A read-only preview (`SyncPipeline::diff`): **nothing** may be written, so a rollback keeps
    /// its revision pin but does not clear `spec.syncPolicy.automated` here — that write belongs to
    /// the reconcile that actually redeploys the pin.
    Preview,
}

/// Everything one pass learns before it writes anything (`T14.1`).
///
/// Shared by [`InventorySyncPipeline::sync_apply`] and [`InventorySyncPipeline::diff_preview`], so
/// the API's diff and the controller's reconcile cannot diverge: both resolve policy, cluster,
/// identity, render, live state and the SSA dry-run through this one path.
struct PreparedPass {
    owner: TrackingOwner,
    access: ClusterAccess,
    /// The destination cluster (`T13.1`): its discovery cache answers every kind lookup.
    target: ClusterTarget,
    options: SyncOptions,
    prev_inventory: Inventory,
    previous_status: ApplicationStatus,
    pass_started: Time,
    rollback: Option<RollbackRequested>,
    revision: String,
    bundle: BundleWaves,
    live: LiveStateMap,
    diffs: Vec<ResourceDiff>,
    summary: DiffSummary,
    spec_hash: String,
    decision: SyncDecision,
    statuses: BTreeMap<ResourceKey, DiffStatus>,
    orphans: Vec<OrphanCandidate>,
    deferred: BTreeSet<ResourceKey>,
    prune_enabled: bool,
    desired_inventory: Inventory,
    invalid_ignore_pointers: usize,
}

/// The wired [`SyncPipeline`].
pub struct InventorySyncPipeline {
    repos: Arc<RepoCache>,
    discovery: DiscoveryCache,
    reader: ClusterStateReader,
    applier: Arc<dyn Applier>,
    dry_run: Arc<dyn DryRunApi>,
    /// Phase 11 render pipeline: `spec.source.renderer` (auto-detected by default) → raw manifests
    /// → Phase 03/04 parse + normalize → tier-sorted `DesiredResource`s, with a collision-free
    /// render cache in front of the subprocess.
    render: RenderPipeline,
    /// `kustomize`/`helm` binary overrides handed to every render context.
    renderer_binaries: RendererBinaries,
    loader: ManifestLoaderConfig,
    url_policy: RepoUrlPolicy,
    /// Phase 09 health registry: `(group, kind)` -> evaluator, unknown kinds falling back to the
    /// generic `status.conditions` heuristic.
    health: HealthRegistry,
    /// Phase 09 health tunables (`LoadBalancer` on a local cluster, spec-only CRs).
    health_config: HealthConfig,
    /// Phase 08 executor pacing (CRD `Established` wait, `Replace` delete wait).
    execution_policy: ExecutionPolicy,
    /// Phase 10 wave/hook state machine (timeouts, wave gate, requeue hint).
    machine: SyncMachine,
    /// `T12.1`: reads the `AppProject` an `Application` references. `None` is a wiring bug and
    /// refuses every sync (fail closed) — policy is never silently skipped.
    project_source: Option<Arc<dyn ProjectSource>>,
    /// `T12.2`: which namespaces may host `Application` objects; the safe default is the
    /// control-plane namespace only.
    application_scope: ApplicationScope,
    /// `T12.3`: how an `Application`'s `serviceAccountName` is turned into cluster access. `None`
    /// means impersonation is not wired, and an `Application` that asks for it is refused rather
    /// than silently deployed with the controller's own identity.
    impersonation: Option<Arc<dyn ImpersonationSource>>,
    /// `T12.4`: how a repository URL is turned into `RepoCredentials`. `None` — the default —
    /// clones every repository anonymously, exactly as before `T12.4`; that stays correct for
    /// public repositories, which is why a missing source is not an error (unlike a missing
    /// [`ProjectSource`], which would disable multi-tenancy).
    credentials: Option<Arc<dyn CredentialSource>>,
    /// `T13.1`: how `spec.destination.cluster` is resolved to a client and a discovery cache.
    /// `None` means only `in-cluster` is addressable, and any other name is a terminal error —
    /// never a silent fallback to the control plane, which would deploy into the wrong cluster.
    clusters: Option<Arc<dyn ClusterSource>>,
    /// `T15.1`: the Prometheus recorder, or `None` (metrics disabled). It observes the Git fetch
    /// duration and bridges the render cache's own counters — nothing else in the pipeline is
    /// instrumented, so the metric surface stays small and matching the roadmap's families.
    metrics: Option<crate::metrics::Metrics>,
    mutating_applies: Arc<AtomicUsize>,
}

impl std::fmt::Debug for InventorySyncPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InventorySyncPipeline")
            .field("discovery", &self.discovery)
            .field("render", &self.render)
            .field("renderer_binaries", &self.renderer_binaries)
            .field("loader", &self.loader)
            .field("url_policy", &self.url_policy)
            .field("health", &self.health)
            .field("health_config", &self.health_config)
            .field("application_scope", &self.application_scope)
            .field("impersonation", &self.impersonation.is_some())
            .field("credentials", &self.credentials.is_some())
            .field("clusters", &self.clusters.is_some())
            .field("metrics", &self.metrics.is_some())
            .finish_non_exhaustive()
    }
}

impl InventorySyncPipeline {
    /// Builds the pipeline from its collaborators.
    ///
    /// `dry_run` is required, not optional: without it the pipeline cannot tell "already synced"
    /// from "drifted", and guessing would either apply everything on every pass (the `v0.2`
    /// behaviour) or apply nothing at all.
    #[must_use]
    pub fn new(
        repos: Arc<RepoCache>,
        discovery: DiscoveryCache,
        live: Arc<dyn LiveObjectSource>,
        applier: Arc<dyn Applier>,
        dry_run: Arc<dyn DryRunApi>,
    ) -> Self {
        Self {
            repos,
            discovery,
            reader: ClusterStateReader::new(live),
            applier,
            dry_run,
            render: RenderPipeline::default(),
            renderer_binaries: RendererBinaries::default(),
            loader: ManifestLoaderConfig::default(),
            url_policy: RepoUrlPolicy::Production,
            health: HealthRegistry::builtin(),
            health_config: HealthConfig::default(),
            execution_policy: ExecutionPolicy::default(),
            machine: SyncMachine::default(),
            project_source: None,
            application_scope: ApplicationScope::default(),
            impersonation: None,
            credentials: None,
            clusters: None,
            metrics: None,
            mutating_applies: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Wires the Prometheus recorder (`T15.1`).
    ///
    /// Without one the pipeline behaves exactly as before: no allocation, no lock, no metric. The
    /// recorder observes the Git fetch duration ([`Self::fetch_desired`]) and bridges the render
    /// cache's existing counters — the pipeline does not keep its own copy of any of them.
    #[must_use]
    pub fn with_metrics(mut self, metrics: crate::metrics::Metrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Number of mutating Server-Side Apply calls this pipeline has issued so far.
    ///
    /// A metric/test seam, not part of the stable API. Every in-place mutation goes through
    /// [`Applier`]; every *prediction* goes through [`DryRunApi`] (`dryRun=All`) and is
    /// deliberately **not** counted here. The delta across two reconciles is therefore exactly
    /// "how many mutating `Patch` calls did that pass issue", which is the seam the T07.5
    /// invariant is asserted on: an already-synced `Application` performs zero of them (its
    /// dry-run PATCHes still happen, and must).
    #[doc(hidden)]
    #[must_use]
    pub fn mutating_applies(&self) -> usize {
        self.mutating_applies.load(Ordering::SeqCst)
    }

    /// Accepts `file://` and local repository paths (tests/dev only; never a production
    /// default).
    #[must_use]
    pub fn with_url_policy(mut self, policy: RepoUrlPolicy) -> Self {
        self.url_policy = policy;
        self
    }

    /// Wires the `AppProject` reader the policy enforcer uses (`T12.1`).
    ///
    /// Without one the pipeline refuses every sync (`Ready=False`): a missing project source is a
    /// wiring bug, and treating it as "permissive" would silently disable multi-tenancy.
    #[must_use]
    pub fn with_project_source(mut self, source: Arc<dyn ProjectSource>) -> Self {
        self.project_source = Some(source);
        self
    }

    /// Sets the namespaces that may host `Application` objects (`T12.2`).
    ///
    /// The safe default is [`ApplicationScope::default`] (`ferriscd-system` only); the controller
    /// passes the same scope it watches, so the guard and the watch never disagree.
    #[must_use]
    pub fn with_application_scope(mut self, scope: ApplicationScope) -> Self {
        self.application_scope = scope;
        self
    }

    /// The namespace scope this pipeline enforces.
    #[must_use]
    pub fn application_scope(&self) -> &ApplicationScope {
        &self.application_scope
    }

    /// Wires the pooled `ServiceAccount` impersonation seam (`T12.3`).
    ///
    /// Without it an `Application` that sets `spec.serviceAccountName` is **refused**
    /// ([`ReconcileError::Impersonation`] via [`ImpersonationError::NotWired`]): deploying it with
    /// the controller's own identity instead would hand a tenant the controller's privileges
    /// (trap T12). `Application`s that name no `serviceAccountName` are unaffected.
    #[must_use]
    pub fn with_impersonation_source(mut self, source: Arc<dyn ImpersonationSource>) -> Self {
        self.impersonation = Some(source);
        self
    }

    /// Wires the Secret-backed repository credential store (`T12.4`).
    ///
    /// Without one every clone is anonymous — the pre-`T12.4` behaviour, which is still the right
    /// answer for public repositories and therefore not an error. With one, an `Application`'s
    /// `spec.source.git.repoUrl` is matched against the labeled
    /// [`SecretCredentialStore`](crate::credentials::SecretCredentialStore) templates and the
    /// result is handed to the Git client; a URL that matches nothing is `Anonymous`, and a
    /// `Secret` that cannot be used is a **terminal** [`ReconcileError::Credentials`] (never a
    /// silent fallback to anonymity).
    #[must_use]
    pub fn with_credential_source(mut self, source: Arc<dyn CredentialSource>) -> Self {
        self.credentials = Some(source);
        self
    }

    /// Wires the remote-cluster registry (`T13.1`).
    ///
    /// Without one, only `spec.destination.cluster: in-cluster` is addressable and any other name
    /// is a **terminal** [`ReconcileError::Cluster`]: silently deploying a remote `Application`
    /// into the control plane would apply manifests to the wrong cluster. The production
    /// controller always wires a [`ClusterManager`](crate::cluster_manager::ClusterManager), which
    /// answers every registered name from the matching `ferriscd.io/secret-type=cluster` `Secret`;
    /// `in-cluster` is answered here, from the pipeline's own seams, and never goes through the
    /// registry.
    #[must_use]
    pub fn with_cluster_source(mut self, source: Arc<dyn ClusterSource>) -> Self {
        self.clusters = Some(source);
        self
    }

    /// Resolves the credentials one repository is cloned with (`T12.4`).
    ///
    /// The lookup happens **after** the `AppProject` policy has authorized the repository URL
    /// (`T12.1`), so a credential is never resolved for an `Application` the project does not
    /// permit, and **before** the URL is fetched, so the clone never starts anonymously.
    ///
    /// # Errors
    ///
    /// [`ReconcileError::Credentials`] for an unusable `Secret` (terminal), and any API failure of
    /// the namespaced read itself.
    async fn credentials_for(&self, repo_url: &str) -> Result<RepoCredentials, ReconcileError> {
        let Some(source) = self.credentials.as_deref() else {
            return Ok(RepoCredentials::Anonymous);
        };
        let credentials = source.credentials_for(repo_url).await?;
        tracing::debug!(
            // Finding M4: this line and the `/status` message that may quote it go through the
            // shared redaction helper — a Git remote routinely embeds a personal access token.
            repo = %manifest::redact_repo_url(repo_url),
            credentials = %credentials,
            "resolved repository credentials"
        );
        Ok(credentials)
    }

    /// Resolves the destination cluster of `app` to the seams this pass uses (`T13.1`).
    ///
    /// Called **after** [`AppProjectPolicy::check_application`] authorized
    /// `(spec.destination.cluster, spec.destination.namespace)`, so a tenant can only ever probe
    /// cluster names its own project lists. `in-cluster` never consults the registry: it is the
    /// controller's own applier, live source, dry-run source and discovery cache, i.e. exactly the
    /// wiring Phases 05–12 had. Any other name resolves through the [`ClusterSource`]; a name
    /// nothing registers is a **terminal** [`ReconcileError::Cluster`] — never a silent fallback to
    /// the control plane, which would apply the manifests into the wrong cluster.
    ///
    /// # Errors
    ///
    /// [`ReconcileError::Cluster`] (`NotFound`) when the cluster is not registered, and any
    /// registry error (an unusable `Secret` is reported too).
    fn target_for(&self, app: &Application) -> Result<ClusterTarget, ReconcileError> {
        // The name is compared **trimmed**, consistently with `AppProjectPolicy` (which trims both
        // the `Application`'s destination and the project's entries). A blank name is a typo, never
        // an implicit `in-cluster`: `serde(default)` already covers the omitted field (finding M11).
        let cluster = app.spec.destination.cluster.trim();
        if cluster.is_empty() {
            return Err(ReconcileError::Cluster(ClusterError::InvalidName {
                name: app.spec.destination.cluster.clone(),
                reason: format!(
                    "a destination cluster must not be blank: omit the field to mean \
                     {IN_CLUSTER:?}, or name a registered cluster"
                ),
            }));
        }
        if cluster == IN_CLUSTER {
            return Ok(ClusterTarget::new(
                IN_CLUSTER,
                self.discovery.clone(),
                ClusterAccess::new(
                    ClusterIdentity::Controller,
                    self.applier.clone(),
                    self.reader.source().clone(),
                    self.dry_run.clone(),
                ),
                self.impersonation.clone(),
            ));
        }
        let Some(clusters) = self.clusters.as_deref() else {
            return Err(ReconcileError::Cluster(ClusterError::NotFound {
                cluster: cluster.to_owned(),
                namespace: self.application_scope.control_plane().to_owned(),
            }));
        };
        clusters.target(cluster)
    }

    /// Resolves the cluster access one `Application` deploys through (`T12.3`).
    ///
    /// The `ServiceAccount` is resolved in `spec.destination.namespace` — never in the
    /// `Application`'s own namespace (ADR-007) — and only after the caller has run
    /// [`AppProjectPolicy::check_application`], i.e. after the project has authorized the
    /// destination *and* the `ServiceAccount` name. The identity is resolved **on the target
    /// cluster**: a remote `Application` is impersonated with the remote cluster's own pool
    /// (`T13.1`), so a tenant never inherits the control plane's connector.
    ///
    /// # Errors
    ///
    /// [`ReconcileError::Impersonation`] for an invalid name, a forbidden group, or an
    /// `Application` that asks for impersonation when none is wired. Every variant is terminal:
    /// the alternative (falling back to the controller's identity) is a privilege escalation.
    fn access_for(
        &self,
        app: &Application,
        target: &ClusterTarget,
    ) -> Result<ClusterAccess, ReconcileError> {
        let Some(impersonation) = Impersonation::for_application(app)? else {
            // No `serviceAccountName`: the target cluster's credential (the controller's own
            // identity in-cluster). Cloning a `ClusterAccess` is four `Arc` clones, so the
            // non-impersonated path costs what it did before `T12.3`.
            return Ok(target.access().clone());
        };
        let Some(source) = target.impersonation() else {
            return Err(ReconcileError::Impersonation(
                ImpersonationError::NotWired {
                    service_account: impersonation.user().to_owned(),
                },
            ));
        };
        let access = source.access_for(&impersonation)?;
        tracing::debug!(
            app.namespace = %app.namespace().unwrap_or_default(),
            app.name = %app.name_any(),
            identity = %access.identity(),
            "reconciling as an impersonated ServiceAccount"
        );
        Ok(access)
    }

    /// Overrides the manifest loader budgets.
    #[must_use]
    pub fn with_loader_config(mut self, loader: ManifestLoaderConfig) -> Self {
        self.loader = loader;
        self
    }

    /// Overrides the `kustomize`/`helm` binaries used to render `Application`s.
    ///
    /// Operators normally pin the renderers by container image, so this exists for non-standard
    /// images and for hermetic tests (a fake renderer script instead of the real tool). Each entry
    /// must be an absolute path or a bare `PATH` name; the sandbox rejects relative paths.
    #[must_use]
    pub fn with_renderer_binaries(mut self, binaries: RendererBinaries) -> Self {
        self.renderer_binaries = binaries;
        self
    }

    /// Render-cache counters (`hits`/`misses`/`entries`), for Phase 15 metrics and tests.
    #[must_use]
    pub fn render_cache_stats(&self) -> ferriscd_engine::manifest::RenderCacheStats {
        self.render.cache().stats()
    }

    /// Overrides the health tunables (`T09.5`).
    ///
    /// A local cluster needs `health_config.load_balancer = LoadBalancerPolicy::Ignore`, otherwise
    /// every `Service: LoadBalancer` stays `Progressing` forever (there is no cloud provider to
    /// publish an address). The per-object annotation
    /// [`ferriscd_engine::health::LOAD_BALANCER_HEALTH_ANNOTATION`] remains the narrower lever.
    #[must_use]
    pub fn with_health_config(mut self, config: HealthConfig) -> Self {
        self.health_config = config;
        self
    }

    /// Replaces the health registry (a test/metric seam; production uses
    /// [`HealthRegistry::builtin`]).
    #[must_use]
    pub fn with_health_registry(mut self, registry: HealthRegistry) -> Self {
        self.health = registry;
        self
    }

    /// The health tunables this pipeline evaluates with.
    #[must_use]
    pub fn health_config(&self) -> &HealthConfig {
        &self.health_config
    }

    /// Overrides the executor's pacing (CRD `Established` wait, `Replace` delete wait).
    ///
    /// Production uses [`ExecutionPolicy::default`]; hermetic tests use
    /// [`ExecutionPolicy::without_waits`] so a scripted cluster never sleeps.
    #[must_use]
    pub fn with_execution_policy(mut self, policy: ExecutionPolicy) -> Self {
        self.execution_policy = policy;
        self
    }

    /// The configured repository URL policy (production rejects local paths).
    #[must_use]
    pub fn url_policy(&self) -> RepoUrlPolicy {
        self.url_policy
    }

    /// Overrides the wave/hook state machine (`T10.1` tunables).
    ///
    /// Production uses [`SyncMachine::default`] (5 s requeue, 10 min wave and operation timeouts);
    /// hermetic tests shorten the timeouts so a stuck wave is provable without sleeping.
    #[must_use]
    pub fn with_sync_machine(mut self, machine: SyncMachine) -> Self {
        self.machine = machine;
        self
    }

    /// The wave/hook state machine this pipeline drives.
    #[must_use]
    pub fn machine(&self) -> &SyncMachine {
        &self.machine
    }

    /// Runs one apply pass.
    ///
    /// The pass is one of two shapes, and which one is a property of the **commit**, not of a
    /// configuration flag (see [`BundleWaves::needs_operation`]):
    ///
    /// * a single hook-less wave is applied in one pass exactly like Phase 08
    ///   ([`Self::run_single_pass`]);
    /// * anything with several waves, a lifecycle hook, or an operation that is already running is
    ///   driven by [`SyncMachine`] across requeues ([`Self::run_operation`]).
    async fn sync_apply(&self, app: &Application) -> Result<ApplyOutcome, ReconcileError> {
        let prepared = self.prepare_pass(app, PassMode::Apply).await?;

        // --- Phase 08/10: execute -------------------------------------------------------
        let request = PassRequest {
            app,
            access: prepared.access.clone(),
            discovery: prepared.target.discovery(),
            owner: &prepared.owner,
            revision: &prepared.revision,
            bundle: &prepared.bundle,
            live: &prepared.live,
            statuses: &prepared.statuses,
            deferred: &prepared.deferred,
            orphans: &prepared.orphans,
            options: &prepared.options,
            decision: prepared.decision,
            prune_enabled: prepared.prune_enabled,
            prev_inventory: &prepared.prev_inventory,
            now: &prepared.pass_started,
        };
        let sync_span = tracing::info_span!(
            "sync_execute",
            decision = %prepared.decision,
            waves = prepared.bundle.plan.wave_count(),
            prune_enabled = prepared.prune_enabled,
        );
        let pass = async {
            if prepared
                .bundle
                .needs_operation(BundleWaves::operation_running(app.status.as_ref()))
            {
                self.run_operation(&request).await
            } else {
                Ok(self.run_single_pass(&request).await)
            }
        }
        .instrument(sync_span)
        .await?;
        // The zero-mutation seam (T07.5): only the SSA applies are counted, never a
        // `dryRun=All` prediction.
        self.mutating_applies
            .fetch_add(pass.apply_calls(), Ordering::SeqCst);

        // Crash-safe inventory: `next_inventory = (prev \ pruned_ok) ∪ (applied_ok ∪ synced)`.
        let pruned_ok = pass.pruned_ok();
        let next_inventory =
            inventory::next_inventory(&prepared.prev_inventory, &pass.confirmed(), &pruned_ok);

        if let Some(failure) = pass.first_failure() {
            // A policy failure (immutable field without `Replace`, an unlisted field manager, a
            // foreign owner) can never be fixed by retrying; everything else is a partial sync the
            // next pass converges from. Both carry the inventory that is already true, so a create
            // that succeeded never becomes an untracked orphan (finding C1). The retryable case also
            // carries the `operationState` this pass reached (finding M4): its `activeHooks` records
            // are the only thing that keeps the next pass from creating a second `generateName` hook
            // (a second database migration) instead of observing the one that already exists.
            let message = failure.error.to_string();
            let operation = pass.operation.clone().map(Box::new);
            return Err(match failure.error.failure_class() {
                FailureClass::Terminal => ReconcileError::SyncConflict {
                    message,
                    inventory: next_inventory,
                    revision: Some(prepared.revision.clone()),
                    // Finding H-A: a terminal failure drops nothing either. The state (and with it
                    // `activeHooks`) has to reach `/status` for both failure classes, or the next
                    // pass sees a hook that already exists as untracked.
                    operation,
                },
                FailureClass::Retryable => ReconcileError::PartialSync {
                    message,
                    inventory: next_inventory,
                    revision: Some(prepared.revision.clone()),
                    operation,
                },
            });
        }

        // --- Phase 10: history, and consuming a completed rollback request ---------------
        let deployment_is_new = prepared
            .previous_status
            .sync
            .as_ref()
            .and_then(|sync| sync.last_synced_revision.as_deref())
            != Some(prepared.revision.as_str());
        let operation = pass.operation.clone().or_else(|| {
            // A single-pass sync is an operation too (`T10.5`): recording it is what makes a later
            // `{"rollback":{"id":N}}` possible for an application that has no waves.
            pass.settled.then(|| {
                succeeded_operation(
                    &prepared.revision,
                    &prepared.pass_started,
                    prepared.bundle.plan.last_wave(),
                )
            })
        });
        let history = match (&operation, pass.settled && deployment_is_new) {
            (Some(operation), true) => record_history(&prepared.previous_status, app, operation),
            _ => None,
        };
        if pass.settled
            && let Some(value) = honoured_operation(app)
        {
            // The request has been honoured: consuming it keeps it from re-triggering forever. A
            // rollback's pin now lives in `/status`, next to its warning condition; a manual sync has
            // no trace at all, and `manual_operation()` reads this annotation, so leaving it behind
            // would keep bypassing `automated: None` on every requeue (finding `P14-C1`).
            self.consume_operation(app, value, prepared.rollback.as_ref())
                .await?;
        }

        // --- Phase 09: health --------------------------------------------------------------
        // Assessed from the pass-level live read on **every** pass, including a `Skip` one: health
        // and sync are orthogonal (T09.5 trap guard). A `Deployment` can be `Synced` and
        // `ImagePullBackOff` at the same time, and it can be `OutOfSync` (an HPA owns
        // `spec.replicas`) while every pod is serving.
        let assessment = self.assess_health(
            prepared.bundle.hooks.permanent(),
            &prepared.live,
            &pass.confirmed(),
            &waves::scheduled_keys(&prepared.bundle.plan, pass.operation.as_ref()),
        );
        let counts = SyncCounts {
            desired: prepared.desired_inventory.len(),
            applied: pass.applied(),
            pruned: pruned_ok.len(),
            // A retained orphan is either a `Skip` the plan refused (foreign, unmanaged,
            // rail-protected, pruning disabled) or a prune the pruner declined at delete time.
            retained_orphans: pass.retained,
            pending: pass.pending().len(),
            invalid_ignore_pointers: prepared.invalid_ignore_pointers,
            prune_enabled: prepared.prune_enabled,
            health: assessment.status,
            settled: pass.settled,
            phase: pass.operation.as_ref().map(|state| {
                waves::step_label(
                    state.sync_phase.unwrap_or(SyncPhase::Sync),
                    state.current_wave,
                )
            }),
            requeue: pass.requeue,
        };
        tracing::debug!(
            app.namespace = %prepared.owner.namespace,
            app.name = %prepared.owner.name,
            decision = %prepared.decision,
            waves = prepared.bundle.plan.wave_count(),
            hooks = prepared.bundle.hooks.hooks().len(),
            out_of_sync = prepared.summary.out_of_sync,
            missing = prepared.summary.missing,
            synced = prepared.summary.synced,
            health = %health::status_label(assessment.status),
            "completed a reconcile pass"
        );
        let outcome = build_outcome(
            app,
            prepared.decision,
            &prepared.summary,
            &prepared.spec_hash,
            counts,
            prepared.revision.clone(),
            next_inventory,
        )
        .with_health(
            HealthState {
                status: assessment.status,
                message: Some(assessment.message.clone()),
            },
            resource_statuses(&assessment, &prepared.desired_inventory),
        )
        .with_operation_state(operation)
        .with_history(history)
        .with_pruned(pruned_ok);
        Ok(match &prepared.rollback {
            Some(rollback) => outcome.with_warning(rollback.decision.condition.clone()),
            None => outcome,
        })
    }

    /// Collects everything a pass learns **before** it writes anything (`T14.1`).
    ///
    /// This is the whole read-only half of a reconcile: tenancy policy, the destination cluster and
    /// identity, the desired bundle (resolved commit → render → normalize → scope), the live read of
    /// `desired ∪ status.inventory`, the ownership gate, and the SSA `dryRun=All` diff. Nothing here
    /// applies, prunes, or patches anything (except the documented rollback spec edit, which
    /// [`PassMode::Preview`] suppresses), so the control-plane API's `GET .../diff` can run the very
    /// same code in-process instead of duplicating the engine (finding C9) — a preview can therefore
    /// never disagree with the reconcile that follows it.
    ///
    /// # Errors
    ///
    /// Every refusal a sync would report before touching the cluster: invalid `spec`, a denied
    /// `AppProject` (a missing project is terminal), an unreachable/unknown destination cluster, an
    /// unusable repository or revision, a render/parse failure, a foreign owner, an unusable
    /// credential, a diff that the API server could not answer, or the empty-desired safety rail.
    async fn prepare_pass(
        &self,
        app: &Application,
        mode: PassMode,
    ) -> Result<PreparedPass, ReconcileError> {
        app.spec.validate().map_err(|err| ReconcileError::Invalid {
            message: err.to_string(),
        })?;
        let options = app.spec.sync_options();
        let owner = TrackingOwner::for_application(app).ok_or_else(|| ReconcileError::Invalid {
            message: "the Application has no metadata.namespace, so no ferriscd.io/tracking-id \
                      can be verified"
                .to_owned(),
        })?;

        // --- Phase 12 (`T12.1`/`T12.2`): tenancy policy, *before* anything is cloned ------
        // The project is read from the control-plane namespace and enforced here, before the
        // repository is resolved: an `Application` the project does not permit must never cause a
        // fetch, a render, a `dryRun=All` PATCH, an apply, or a prune. A missing project is a
        // terminal denial, never an implicit "allow".
        let policy = self.load_project_policy(app).await?;
        policy.check_application(app, &self.application_scope)?;
        // `T13.1`: the project has authorized `(destination.cluster, destination.namespace)`, so
        // this is the first point at which the cluster registry may be consulted — a tenant can
        // therefore only probe cluster names its project lists.
        let target = self.target_for(app)?;
        // `T12.3`: the project has also authorized the `serviceAccountName`, so this is the first
        // point at which the identity may be resolved — in the destination namespace, never in the
        // `Application`'s own namespace, and on the destination **cluster**.
        let access = self.access_for(app, &target)?;

        let prev_inventory = status_inventory(app)?;
        let previous_status = app.status.clone().unwrap_or_default();
        let pass_started = now();

        // --- Phase 10: the rollback request decides *which commit* this pass sees ---------
        // Parsed before the diff gate and before `spec.source` is resolved: a rollback that first
        // applied `HEAD` and then "rolled back" would have mutated the cluster towards the wrong
        // commit (and, with `selfHeal`, fought itself on every requeue).
        let rollback = self
            .plan_rollback(app, &previous_status, &pass_started, mode)
            .await?;
        let pinned_revision = rollback
            .as_ref()
            .map(|rollback| rollback.decision.pinned_revision().to_owned())
            .or_else(|| pinned_rollback_revision(&previous_status));

        if options.server_side_force {
            warn!(
                app.namespace = %owner.namespace,
                app.name = %owner.name,
                "spec.syncPolicy.syncOptions.serverSideForce is ignored in v0.2: every apply uses \
                 force=false so field conflicts stay visible (trap T5)"
            );
        }

        let (revision, mut resources) = self
            .fetch_desired(app, pinned_revision.as_deref(), target.discovery())
            .await?;
        let (in_bundle_crds, in_bundle_namespaces) = self
            .prepare(
                &mut resources,
                &app.spec.destination.namespace,
                target.discovery(),
            )
            .await?;

        // `T12.1`: re-check **every** rendered resource on its *actual* scope. Scope normalization
        // is what makes "namespaced vs cluster-scoped" and the effective namespace facts, so a
        // manifest that hardcodes `metadata.namespace: kube-system` (preserved by Stage 2) or ships
        // a `ClusterRoleBinding` is caught here — before the partition, the ownership stamp, the
        // dry-run diff, the apply, and the prune. Hooks are covered too: they are created
        // imperatively but they are still rendered resources.
        policy.check_resources(&app.spec.destination.cluster, &resources)?;

        // --- Phase 10: hooks out of the desired state, permanent set into waves ------------
        // The partition is what keeps a hook out of `status.inventory`, the pruner's universe and
        // the drift diff (finding H2), so it happens before anything is stamped, planned or read.
        let mut bundle = BundleWaves::partition(resources).map_err(ReconcileError::Manifest)?;
        // Stamp ownership *after* scope normalization, because the marker is rendered from the
        // final GKNN key (Phase 05 mirrors the effective namespace onto the key) — and only onto
        // the permanent half: a hook is never prunable inventory.
        stamp_ownership(bundle.hooks.permanent_mut(), &owner)?;
        // The wave plan owns clones of the permanent resources, so it has to be re-derived from the
        // stamped half — a plan built before the stamp would apply every wave member without its
        // `ferriscd.io/tracking-id` and report that annotation as permanent drift.
        bundle.replan().map_err(ReconcileError::Manifest)?;

        let desired_inventory = bundle.hooks.permanent_inventory();
        // Safety rail: an empty desired set over a non-empty inventory is far more likely to be
        // a wrong `spec.source.git.path` than an intentional "delete everything". Require an
        // explicit opt-in before a pass that would prune the whole inventory.
        if desired_inventory.is_empty() && !prev_inventory.is_empty() && !empty_desired_allowed() {
            return Err(ReconcileError::Invalid {
                message: format!(
                    "the desired set from {} at path '{}' is empty but {} resource(s) are still \
                     tracked in status.inventory; refusing to sync (check spec.source.git.path \
                     and the repository contents). Set {ALLOW_EMPTY_DESIRED_ENV}=1 to allow \
                     pruning the entire inventory",
                    // Finding M4: this message reaches `Application.status`, so the repository URL
                    // is quoted through the shared redaction helper — a Git remote routinely
                    // carries a personal access token.
                    manifest::redact_repo_url(&app.spec.source.git.repo_url),
                    app.spec.source.git.path,
                    prev_inventory.len()
                ),
            });
        }

        let requests = plan_fetch(&desired_inventory, &prev_inventory);
        let live_span = tracing::info_span!(
            "live_state_fetch",
            resources = requests.len(),
            cluster = %target.name(),
        );
        let live = access
            .reader()
            .fetch_live(
                &requests,
                // The destination cluster's snapshot: a remote cluster resolves the same GKNN to a
                // different plural/scope (or not at all), so the control plane's cache must never
                // answer for it (`T13.1`).
                target.discovery(),
                &in_bundle_crds,
                &in_bundle_namespaces,
                &owner,
            )
            .instrument(live_span)
            .await?;

        // Trap guard: ownership is verified for the whole bundle *before* any mutation — and
        // before the dry-run pass, so an object another `Application` owns never even receives a
        // `dryRun=All` PATCH. The failure is terminal and still reports `OutOfSync`.
        if let Err(err) = reject_foreign_ownership(bundle.hooks.permanent(), &live) {
            return Err(ReconcileError::OwnershipConflict {
                message: err.to_string(),
                inventory: prev_inventory,
                revision: Some(revision),
            });
        }

        // --- Phase 07: diff gate -------------------------------------------------------
        // The dry-run diff runs over the *permanent* stamped slice the applier receives (see
        // `DryRunEvaluator::evaluate`'s desired-body contract): diffing a pre-stamp body would look
        // like a request to remove `ferriscd.io/tracking-id`, leaving every resource `OutOfSync`
        // forever. A hook is never diffed: it is created imperatively and its lifetime belongs to
        // its delete policy, not to the cluster-vs-Git comparison.
        let orphan_keys = inventory::orphans(&desired_inventory, &prev_inventory);
        let rules = IgnoreRuleSet::from_ignore_differences(&app.spec.ignore_differences);
        let invalid_ignore_pointers = report_invalid_pointers(&rules, &owner);
        let diff_span = tracing::info_span!(
            "diff_evaluate",
            desired = bundle.hooks.permanent().len(),
            orphans = orphan_keys.len(),
        );
        let diffs = self
            .evaluate_diff(
                &access,
                target.discovery(),
                bundle.hooks.permanent(),
                &orphan_keys,
                &live,
                &rules,
            )
            .instrument(diff_span)
            .await?;
        let summary = DiffSummary::from_diffs(&diffs);
        let spec_hash = source_spec_hash(&app.spec).map_err(|err| ReconcileError::Invalid {
            message: err.to_string(),
        })?;
        let decision = should_sync(app, &revision, &spec_hash, &summary, manual_operation(app));
        let statuses = status_by_key(&diffs);

        let orphans: Vec<OrphanCandidate> = orphan_keys
            .iter()
            .map(|key| orphan_candidate(key, &live))
            .collect();
        // A resource the pass-level live read deferred on a *Namespace* cannot be applied yet;
        // one deferred on a *CRD* is planned as an apply, because the executor establishes the
        // CRD and refreshes discovery inside this very pass (T08.3, trap T6).
        let deferred: BTreeSet<ResourceKey> = bundle
            .hooks
            .permanent()
            .iter()
            .filter(|resource| {
                matches!(
                    live.get(&resource.key),
                    Some(LiveState::DeferredPendingNamespace)
                )
            })
            .map(|resource| resource.key.clone())
            .collect();
        let prune_enabled = prune_enabled(app);

        Ok(PreparedPass {
            owner,
            access,
            target,
            options,
            prev_inventory,
            previous_status,
            pass_started,
            rollback,
            revision,
            bundle,
            live,
            diffs,
            summary,
            spec_hash,
            decision,
            statuses,
            orphans,
            deferred,
            prune_enabled,
            desired_inventory,
            invalid_ignore_pointers,
        })
    }

    /// Computes the read-only diff preview the control-plane API serves (`T14.1`).
    ///
    /// It is [`Self::prepare_pass`] in [`PassMode::Preview`] and nothing else: no apply, no prune,
    /// no `/status` patch, no annotation patch, no counter for mutating applies. The returned
    /// [`DiffPreview`] carries the engine's own [`ResourceDiff`]s — the only type that can be built
    /// from live/predicted payloads, which is what keeps `Secret` values out of the API response.
    ///
    /// # Errors
    ///
    /// See [`Self::prepare_pass`]: a preview refuses exactly what a sync would refuse.
    async fn diff_preview(&self, app: &Application) -> Result<DiffPreview, ReconcileError> {
        let prepared = self.prepare_pass(app, PassMode::Preview).await?;
        tracing::debug!(
            app.namespace = %prepared.owner.namespace,
            app.name = %prepared.owner.name,
            revision = %prepared.revision,
            desired = prepared.desired_inventory.len(),
            out_of_sync = prepared.summary.out_of_sync,
            missing = prepared.summary.missing,
            synced = prepared.summary.synced,
            decision = %prepared.decision,
            "computed a read-only diff preview"
        );
        Ok(DiffPreview {
            revision: prepared.revision,
            diffs: prepared.diffs,
            summary: prepared.summary,
            desired: prepared.desired_inventory.len(),
            would_sync: prepared.decision.is_execute(),
        })
    }

    /// Applies the whole permanent set in one pass (Phase 08 behaviour).
    ///
    /// Used for a bundle with exactly one wave and no lifecycle hooks: there is nothing to order
    /// and nothing to wait for, so the operation state machine would only add a requeue.
    async fn run_single_pass(&self, request: &PassRequest<'_>) -> PassExecution {
        let (plan, execution) = self
            .execute_plan(
                &request.access,
                request.discovery,
                request.bundle.hooks.permanent(),
                request.decision,
                request.statuses,
                request.deferred,
                request.orphans,
                request.options,
                request.prune_enabled,
                request.owner,
                &request.app.spec.destination.namespace,
                request.prev_inventory,
            )
            .await;
        if request.decision.is_execute() {
            log_plan(request, &plan);
        } else {
            tracing::debug!(
                app.namespace = %request.owner.namespace,
                app.name = %request.owner.name,
                decision = %request.decision,
                "diff gate skipped this reconcile"
            );
        }
        // Only "executed *and* nothing left pending" is a full sync.
        let settled = request.decision.is_execute() && execution.pending.is_empty();
        PassExecution {
            retained: execution.retained + plan.retained_orphans().len(),
            reports: vec![execution],
            extra_apply_calls: 0,
            operation: None,
            settled,
            requeue: None,
        }
    }

    /// Drives one step of a multi-wave / hook operation (`T10.1`, `T10.2`, `T10.3`).
    ///
    /// One pass does exactly one of the following, and every branch persists the state it reached
    /// **before** the caller requeues (crash safety):
    ///
    /// 1. run the hooks of the persisted step (create what is missing, observe what is tracked);
    /// 2. step the pure machine with the health that step is judged on;
    /// 3. execute what the machine asked for — a wave's Server-Side Applies, or nothing at all when
    ///    it asked to wait — and, once every `Sync` wave has converged, the prunes.
    async fn run_operation(
        &self,
        request: &PassRequest<'_>,
    ) -> Result<PassExecution, ReconcileError> {
        let mut pass = PassExecution::default();
        let schedule = request.bundle.schedule();
        let persisted = request
            .app
            .status
            .as_ref()
            .and_then(|status| status.operation_state.clone());

        // 1. Start a new operation, or resume the persisted one.
        let mut state = match persisted.as_ref() {
            Some(state) if state.phase == OperationPhase::Running => state.clone(),
            Some(state) if failed_operation_is_not_retried(request, state) => {
                // Finding M5: a `Failed` operation is only restarted for a **new revision** or an
                // explicit manual operation. Restarting it on every requeue would re-run `PreSync`
                // (and `SyncFail`) hooks against an unchanged commit — for a `generateName` hook a
                // brand-new `Job`, i.e. a migration that already failed re-run forever.
                tracing::debug!(
                    app.namespace = %request.owner.namespace,
                    app.name = %request.owner.name,
                    revision = %request.revision,
                    operation_message = state.message.as_deref().unwrap_or_default(),
                    "the persisted operation failed; waiting for a new revision or a manual operation"
                );
                // Reported as-is: the failure reason lives in `operationState.message`.
                pass.operation = Some(state.clone());
                return Ok(pass);
            }
            _ if request.decision.is_execute() => {
                self.machine
                    .start(Some(request.revision.to_owned()), request.now)
                    .state
            }
            // Nothing to do: no operation is running and the gate said `Skip`.
            _ => return Ok(pass),
        };

        // 2. The hooks of the persisted step. Idempotent by construction: a hook that is already
        //    tracked is observed, never created again (finding H2).
        let step = self.machine.current_step(&state);
        // When `syncOptions.createNamespace: true` is set and `PreSync` actually has hooks to run,
        // ensure the destination namespace exists *before* creating `PreSync` hooks: otherwise a
        // `PreSync` migration `Job` into a brand-new namespace fails with `404 Namespace not found`
        // before wave 0's `createNamespace` ever runs. Hook-less multi-wave operations skip this so
        // `SyncPlan::pre_create_namespace` preserves its `declared_in_git` rule in wave 0.
        let destination_ns = request.app.spec.destination.namespace.trim();
        if step.phase == SyncPhase::PreSync
            && request.options.create_namespace
            && !destination_ns.is_empty()
            && !hooks::hooks_for_step(&request.bundle.hooks, step).is_empty()
        {
            match crate::sync_executor::ensure_namespace_exists(
                request.access.applier(),
                request.access.reader(),
                request.discovery,
                destination_ns,
            )
            .await
            {
                Ok(true) => pass.extra_apply_calls += 1,
                Ok(false) => {}
                Err(error) => {
                    return Err(mid_operation_error(
                        request,
                        &error,
                        request.prev_inventory,
                        Some(state),
                    ));
                }
            }
        }
        // Hooks are created and observed as the pass's identity, like every other workload call.
        let hook_cluster = PassHooks {
            pipeline: self,
            access: &request.access,
            discovery: request.discovery,
        };
        let hook_step = hooks::run_step(
            &hook_cluster,
            step,
            &request.bundle.hooks,
            &state.active_hooks,
        )
        .await;
        // The records are merged **before** the error is inspected (finding H-NEW): a hook created
        // before the failure is only protected by its `activeHooks` record, and `apply_once` can
        // only persist the state the error carries. Merging afterwards would let the retry create a
        // second `migrate-*` `Job` for a hook that already exists.
        waves::merge_hook_records(&mut state.active_hooks, &hook_step.run.records);
        log_hooks(request, step, &hook_step.run);
        if let Some(error) = hook_step.error {
            // No wave was applied yet (hooks run before the step executes), so the inventory that
            // is already true is the one the pass read.
            return Err(mid_operation_error(
                request,
                &error,
                request.prev_inventory,
                Some(state),
            ));
        }
        let hook_run = hook_step.run;
        if let Some(name) = &hook_run.pending_delete {
            // `BeforeHookCreation` deleted a previous run of a named hook and Kubernetes has not
            // finished reaping it: re-creating now would answer `409 AlreadyExists` (finding M3), so
            // this pass only requeues.
            tracing::debug!(
                app.namespace = %request.owner.namespace,
                app.name = %request.owner.name,
                hook = %name,
                step = %step,
                "waiting for a previous hook run to be deleted"
            );
            pass.operation = Some(state);
            pass.requeue = Some(DEFAULT_REQUEUE_AFTER);
            return Ok(pass);
        }

        // 3. One pure step: the machine owns the phase graph, the timeouts and the failure path.
        let health = waves::step_health(
            step,
            &request.bundle.plan,
            request.live,
            &hook_run.observed,
            &self.health,
            &self.health_config,
        );
        let outcome = self.machine.step(
            &state,
            &schedule,
            &health,
            Some(request.revision),
            request.now,
        );
        pass.operation = Some(outcome.state.clone());
        pass.requeue = outcome.action.requeue_after();

        // 4. Execute what the machine asked for.
        let mut targets = Vec::new();
        if let StepAction::Execute { step: target, .. } = outcome.action {
            targets.push(target);
        }
        for target in targets {
            if target.phase != SyncPhase::Sync {
                // A hook phase was already handled in step 2; its verdict is what moved the machine.
                // (A `Sync` hook of a wave the machine *dispatches* in this pass is created on the
                // next one: the hooks of the persisted step are the ones this pass may act on, and
                // the wave's own `Execute` is idempotent, so nothing is skipped — only ordered.)
                continue;
            }
            let Some(wave) = request.bundle.plan.wave(target.wave) else {
                continue;
            };
            let mut wave_options = request.options.clone();
            // The destination namespace is created once, by the first wave: re-applying it on every
            // wave would bump its `resourceVersion` (and churn `managedFields`) for nothing.
            wave_options.create_namespace = request
                .bundle
                .plan
                .wave_numbers()
                .first()
                .is_some_and(|first| *first == target.wave)
                && request.options.create_namespace;
            let (plan, execution) = self
                .execute_plan(
                    &request.access,
                    request.discovery,
                    &wave.resources,
                    forced_execute(request.decision),
                    request.statuses,
                    request.deferred,
                    // Pruning never happens between waves: an orphan is reaped once the whole
                    // rollout has converged (see below).
                    &[],
                    &wave_options,
                    false,
                    request.owner,
                    &request.app.spec.destination.namespace,
                    request.prev_inventory,
                )
                .await;
            log_plan(request, &plan);
            pass.retained += execution.retained + plan.retained_orphans().len();
            pass.reports.push(execution);
            // `T10.2` trap guard: a wave that carries a `CustomResourceDefinition` registers new
            // kinds only once the API server establishes it, so the next wave must resolve against a
            // refreshed discovery snapshot (this is `T08.3`'s rule, lifted to the wave boundary).
            if request.bundle.plan.contains_crd(target.wave) {
                // A refresh failure stops the pass, but not the state: the wave that was just
                // applied (and any hook record) must survive the requeue (finding H-NEW).
                if let Err(error) = request.discovery.invalidate_and_refresh().await {
                    let inventory =
                        inventory::next_inventory(request.prev_inventory, &pass.confirmed(), &[]);
                    return Err(mid_operation_error(
                        request,
                        &ReconcileError::from(error),
                        &inventory,
                        pass.operation.take(),
                    ));
                }
            }
        }

        // Pruning runs once every `Sync` wave has converged: on the `PostSync` step, which is always
        // part of the schedule. A prune in the middle of a rollout could delete a resource that a
        // later wave depends on, and a hook-only commit (no permanent resources at all) still has to
        // be able to prune what a previous commit left behind.
        let prune_due = step.phase == SyncPhase::PostSync
            || outcome
                .action
                .step()
                .is_some_and(|target| target.phase == SyncPhase::PostSync);
        if prune_due {
            let mut prune_options = request.options.clone();
            prune_options.create_namespace = false;
            let (plan, execution) = self
                .execute_plan(
                    &request.access,
                    request.discovery,
                    &[],
                    SyncDecision::Execute(SyncTrigger::PruneRequired),
                    request.statuses,
                    request.deferred,
                    request.orphans,
                    &prune_options,
                    request.prune_enabled,
                    request.owner,
                    &request.app.spec.destination.namespace,
                    request.prev_inventory,
                )
                .await;
            pass.retained += execution.retained + plan.retained_orphans().len();
            pass.reports.push(execution);
        }

        pass.settled = outcome.state.phase == OperationPhase::Succeeded;
        Ok(pass)
    }

    /// Builds and executes the plan for one slice of desired resources.
    ///
    /// The single place that turns "these resources, this decision" into cluster calls, so the
    /// Phase 08 executor (its rails, its `Replace` recovery, its ownership-verified prune, its CRD
    /// `Established` wait) is shared bit-for-bit by a single pass, each wave, and the prune step.
    #[allow(clippy::too_many_arguments)]
    async fn execute_plan(
        &self,
        access: &ClusterAccess,
        discovery: &DiscoveryCache,
        desired: &[DesiredResource],
        decision: SyncDecision,
        statuses: &BTreeMap<ResourceKey, DiffStatus>,
        deferred: &BTreeSet<ResourceKey>,
        orphans: &[OrphanCandidate],
        options: &SyncOptions,
        prune_enabled: bool,
        owner: &TrackingOwner,
        destination_namespace: &str,
        prev_inventory: &Inventory,
    ) -> (SyncPlan, ExecutionReport) {
        let request = PlanRequest::new(decision, desired, statuses, options, destination_namespace)
            .with_deferred(deferred)
            .with_orphans(orphans)
            .with_prune(prune_enabled);
        let plan = SyncPlan::build(&request);
        let policy = ExecutionPolicy {
            takeover_field_managers: options.takeover_field_managers.clone(),
            ..self.execution_policy.clone()
        };
        let crd_status = LiveCrdStatusReader::new(access.reader().clone());
        let pruner = OwnershipVerifiedPruner::new(
            access.applier(),
            access.reader(),
            discovery,
            owner,
            options,
        );
        let execution = SyncExecutor::new(
            access.applier(),
            &pruner,
            access.reader(),
            discovery,
            &crd_status,
            owner,
            &policy,
        )
        .execute(&plan, desired, prev_inventory)
        .await;
        (plan, execution)
    }

    /// Resolves and applies a `{"rollback":{"id":N}}` request (`T10.5`).
    ///
    /// Returns the decision when the annotation really is a rollback request. Pins
    /// `spec.syncPolicy.automated` to disabled **before** the diff gate runs: with automation left
    /// on, the very next reconcile compares live state against `HEAD` and self-heals the rollback
    /// away — the classic GitOps rollback-vs-`selfHeal` fight loop.
    async fn plan_rollback(
        &self,
        app: &Application,
        status: &ApplicationStatus,
        now: &Time,
        mode: PassMode,
    ) -> Result<Option<RollbackRequested>, ReconcileError> {
        let Some(raw) = app.annotations().get(annotations::OPERATION).cloned() else {
            return Ok(None);
        };
        let request = match parse_rollback_request(&raw) {
            Ok(request) => request,
            // `{"sync":{...}}` (or any other operation) is a manual sync request, not a rollback.
            Err(RollbackError::NotARollback) => return Ok(None),
            Err(err) => {
                return Err(ReconcileError::Invalid {
                    message: err.to_string(),
                });
            }
        };
        let decision =
            plan_rollback(status, request, now).map_err(|err| ReconcileError::Invalid {
                message: err.to_string(),
            })?;

        // Idempotent: a spec that is already manual-only is not patched again.
        let mut spec = app.spec.clone();
        if decision.apply_to_spec(&mut spec) {
            if mode == PassMode::Preview {
                // A preview must not write: `GET .../diff` reports the pin and the warning the
                // reconcile will produce, and the reconcile that redeploys it is what actually
                // disables automation (`T14.1`).
                tracing::debug!(
                    app.namespace = %app.namespace().unwrap_or_default(),
                    app.name = %app.name_any(),
                    history_id = decision.target.history_id,
                    revision = %decision.pinned_revision(),
                    "diff preview: the reconcile this previews would disable \
                     spec.syncPolicy.automated so self-heal cannot overwrite the pinned revision"
                );
                return Ok(Some(RollbackRequested { decision }));
            }
            let owner =
                TrackingOwner::for_application(app).ok_or_else(|| ReconcileError::Invalid {
                    message: "the Application has no metadata.namespace, so its spec cannot be \
                          patched"
                        .to_owned(),
                })?;
            self.applier
                .patch_application(ApplicationPatch {
                    namespace: &owner.namespace,
                    name: &owner.name,
                    patch: serde_json::json!({
                        "spec": { "syncPolicy": { "automated": serde_json::Value::Null } }
                    }),
                })
                .await?;
            warn!(
                app.namespace = %owner.namespace,
                app.name = %owner.name,
                history_id = decision.target.history_id,
                revision = %decision.pinned_revision(),
                "rollback: spec.syncPolicy.automated was removed so self-heal cannot overwrite the \
                 pinned revision; revert the commit in Git and re-enable automation"
            );
        }
        Ok(Some(RollbackRequested { decision }))
    }

    /// Consumes the `ferriscd.io/operation` annotation a settled pass has honoured.
    ///
    /// One path for both operations, because both are the same annotation slot and both are
    /// one-shot requests:
    ///
    /// * a rollback's pin and its `Warning` condition now live in `/status`, so leaving the request
    ///   behind would keep asking for the same rollback on every requeue (`T10.5`);
    /// * a manual sync leaves no trace at all, and [`manual_operation`] reads this annotation — so
    ///   leaving it behind would keep bypassing `automated: None` (and `selfHeal: false`) on every
    ///   requeue forever, and an API `POST .../sync` would block every later sync/rollback (finding
    ///   `P14-C1`).
    ///
    /// `value` is the exact annotation value that was read, which is what the log line reports; it is
    /// never interpreted here.
    async fn consume_operation(
        &self,
        app: &Application,
        value: &str,
        rollback: Option<&RollbackRequested>,
    ) -> Result<(), ReconcileError> {
        let owner = TrackingOwner::for_application(app).ok_or_else(|| ReconcileError::Invalid {
            message: "the Application has no metadata.namespace, so its annotations cannot be \
                      patched"
                .to_owned(),
        })?;
        self.applier
            .patch_application(ApplicationPatch {
                namespace: &owner.namespace,
                name: &owner.name,
                patch: serde_json::json!({
                    "metadata": { "annotations": { annotations::OPERATION: serde_json::Value::Null } }
                }),
            })
            .await?;
        match rollback {
            Some(rollback) => tracing::info!(
                app.namespace = %owner.namespace,
                app.name = %owner.name,
                operation = %value,
                history_id = rollback.decision.target.history_id,
                revision = %rollback.decision.pinned_revision(),
                "rollback applied: consumed the ferriscd.io/operation annotation"
            ),
            None => tracing::info!(
                app.namespace = %owner.namespace,
                app.name = %owner.name,
                operation = %value,
                "manual sync settled: consumed the ferriscd.io/operation annotation"
            ),
        }
        Ok(())
    }

    /// Assesses the health of the desired set from this pass's live read (`T09.5`).
    ///
    /// `scheduled` is the part of `resources` a *later* wave of the running operation owns
    /// (finding M3): those resources have deliberately not been created yet, so they are
    /// `Progressing` (scheduled) instead of `Missing`.
    fn assess_health(
        &self,
        resources: &[DesiredResource],
        live: &LiveStateMap,
        applied: &Inventory,
        scheduled: &BTreeSet<ResourceKey>,
    ) -> HealthSummary {
        let inputs = health_inputs(resources, live, applied, scheduled);
        health::assess(&inputs, &self.health, &self.health_config)
    }

    /// Classifies the stamped desired set with the SSA `dryRun=All` evaluator (T07.1–T07.3).
    ///
    /// `resources` **must** be the stamped slice the applier receives (the desired-body contract
    /// documented on [`DryRunEvaluator::evaluate`]). Handing the evaluator a pre-stamp body would
    /// make it predict the removal of the `ferriscd.io/tracking-id` annotation the apply actually
    /// keeps, so every resource would be `OutOfSync` forever. A diff that cannot read the API
    /// server is an error, never a guessed "synced": guessing would silently skip a needed apply.
    async fn evaluate_diff(
        &self,
        access: &ClusterAccess,
        discovery: &DiscoveryCache,
        resources: &[DesiredResource],
        orphans: &[ResourceKey],
        live: &LiveStateMap,
        rules: &IgnoreRuleSet,
    ) -> Result<Vec<ResourceDiff>, ReconcileError> {
        // The `dryRun=All` predictions run as the pass's identity (`T12.3`): a tenant's diff must
        // be rejected by the API server exactly like its applies would be, or the controller would
        // report `Synced` for a resource it cannot actually write.
        DryRunEvaluator::with_api(access.dry_run_arc(), discovery.clone())
            .evaluate(resources, orphans, live, rules)
            .await
            .map_err(ReconcileError::Diff)
    }

    /// Resolves the `AppProject` an `Application` references and builds its policy (`T12.1`).
    ///
    /// The project is fetched once per reconcile from the control-plane namespace (a scoped read,
    /// never a cluster-wide informer) and reduced to a pure [`AppProjectPolicy`] the engine can
    /// enforce offline.
    ///
    /// # Errors
    ///
    /// * [`PolicyError::ProjectNotFound`] when the referenced project does not exist — terminal, so
    ///   an operator sees "create the AppProject" instead of an unexplained refusal.
    /// * [`ReconcileError::Invalid`] when no project source is wired at all: a pipeline that cannot
    ///   enforce policy must not sync, and must not pretend the project is permissive.
    /// * Any API failure of the fetch itself (retryable by classification).
    async fn load_project_policy(
        &self,
        app: &Application,
    ) -> Result<AppProjectPolicy, ReconcileError> {
        let Some(source) = self.project_source.as_deref() else {
            return Err(ReconcileError::Invalid {
                message: "no AppProject source is wired into the sync pipeline, so AppProject \
                          policy cannot be enforced; refusing to sync (wire `ApiProjectSource` \
                          when building the pipeline)"
                    .to_owned(),
            });
        };
        let project = source.get(&app.spec.project).await?;
        let Some(project) = project else {
            return Err(ReconcileError::Policy(PolicyError::ProjectNotFound {
                project: app.spec.project.clone(),
                namespace: self.application_scope.control_plane().to_owned(),
                application: format!("{}/{}", app.namespace().unwrap_or_default(), app.name_any()),
            }));
        };
        Ok(AppProjectPolicy::from_project(&project))
    }

    /// Resolves the revision and renders the desired manifest set.
    ///
    /// Rendering goes through the Phase 11 pipeline (`T11.1`): the renderer is selected by
    /// `spec.source.renderer` (`Auto` → `Chart.yaml`/`kustomization.yaml` detection, else plain
    /// YAML) and every byte it produces flows through the same Phase 03 parse and Phase 04
    /// normalize steps a plain-YAML bundle does. The pipeline returns the bundle already tier
    /// sorted, and its result cache is keyed on the full render tuple, so a periodic requeue at an
    /// unchanged commit costs one hash lookup instead of a `kustomize`/`helm` subprocess.
    ///
    /// `pinned` overrides `spec.source.git.targetRevision` (`T10.5`): a rollback — or an application
    /// still holding a rollback warning — must render the commit it was pinned to, never `HEAD`.
    async fn fetch_desired(
        &self,
        app: &Application,
        pinned: Option<&str>,
        discovery: &DiscoveryCache,
    ) -> Result<(String, Vec<DesiredResource>), ReconcileError> {
        let source = GitSource::new(
            app.spec.source.git.repo_url.clone(),
            pinned
                .map(str::to_owned)
                .unwrap_or_else(|| app.spec.source.git.target_revision.clone()),
            app.spec.source.git.path.clone(),
        );
        // Explicit, configurable local-repository policy: `Production` rejects `file://` and
        // bare local paths, so a misconfigured `Application` cannot read the pod's filesystem.
        source.validate(self.url_policy)?;

        // `T12.4`: the credentials come from a `ferriscd.io/secret-type=repository` Secret in the
        // control-plane namespace. No match is `Anonymous` (public repositories keep working);
        // an unusable Secret is a terminal error instead of a silent anonymous clone.
        let credentials = self.credentials_for(&source.repo_url).await?;
        // `T15.1`: resolve + checkout is the Git work of one pass (both go through the `RepoCache`,
        // which carries the mirror/worktree state), so they are timed together. The observation is
        // recorded for a failed fetch too — the latency of a timeout is exactly what an operator
        // needs — and the histogram has no label, so neither the URL nor the error can widen it.
        let fetch_started = std::time::Instant::now();
        let git_span = tracing::info_span!(
            "git_fetch",
            repo = %manifest::redact_repo_url(&source.repo_url),
            target_revision = %source.target_revision,
        );
        let fetched: Result<_, ReconcileError> = async {
            let resolved = self.repos.resolve_revision(&source, &credentials).await?;
            let checkout = self
                .repos
                .checkout(&source, &resolved.commit_sha, &credentials)
                .await?;
            Ok((resolved, checkout))
        }
        .instrument(git_span)
        .await;
        if let Some(metrics) = &self.metrics {
            metrics.record_git_fetch(fetch_started.elapsed());
        }
        let (resolved, checkout) = fetched?;

        // Helm's `.Capabilities.KubeVersion` must match the destination cluster, so the discovery
        // snapshot has to be populated *before* the render. This is TTL-gated: an already-fresh
        // snapshot costs no API call. For a remote cluster this is that cluster's snapshot, so a
        // chart templated with `.Capabilities.KubeVersion` renders the version it will meet.
        discovery.ensure_fresh().await?;

        let context = RenderContext::for_application(
            checkout.root_dir().to_path_buf(),
            app,
            &discovery.kube_version(),
        )
        .with_commit_sha(resolved.commit_sha.clone())
        .with_loader_config(self.loader.clone())
        .with_binaries(self.renderer_binaries.clone());

        // File I/O, YAML parsing, and the renderer subprocess all run off the Tokio worker pool
        // inside the pipeline.
        let render_span = tracing::info_span!(
            "manifest_render",
            commit_sha = %resolved.commit_sha,
            path = %app.spec.source.git.path,
        );
        let rendered = self.render.render(&context).instrument(render_span).await;
        // `T15.1`: the render cache owns the `hits`/`misses` counters; the recorder turns the
        // increase into `ferriscd_render_cache_total{outcome="hit|miss"}`. Sampled on a failed
        // render too, because a miss is counted before the renderer runs.
        if let Some(metrics) = &self.metrics {
            metrics.record_render_cache(self.render.cache().stats());
        }
        let rendered = rendered?;
        // The pipeline hands back a shared, already-normalized bundle; stamping ownership below
        // mutates the resources, so this pass needs its own copy.
        Ok((resolved.commit_sha, rendered.as_ref().clone()))
    }

    /// Rejects unsupported manifests, collects in-bundle CRDs/namespaces, refreshes discovery
    /// and normalizes the cluster-aware scope of every resource.
    async fn prepare(
        &self,
        resources: &mut [DesiredResource],
        destination_namespace: &str,
        discovery: &DiscoveryCache,
    ) -> Result<(Vec<InBundleCrd>, Vec<String>), ReconcileError> {
        for resource in resources.iter() {
            reject_unsupported(resource)?;
        }

        let in_bundle_crds = scope::collect_in_bundle_crds(resources)?;
        let in_bundle_namespaces: Vec<String> = resources
            .iter()
            .filter(|resource| resource.gvk.group.is_empty() && resource.gvk.kind == "Namespace")
            .map(|resource| resource.key.name.clone())
            .collect();

        // Refresh before scope normalization: a CRD installed by a previous sync must be
        // visible now (trap T6). A bundle that (re)defines CRDs forces the refresh instead of
        // waiting for the 5-minute TTL, otherwise a `DeferredPendingCrd` resource would spin on
        // a stale snapshot for minutes before its kind resolves.
        if in_bundle_crds.is_empty() {
            discovery.ensure_fresh().await?;
        } else {
            discovery.invalidate_and_refresh().await?;
        }
        scope::normalize_scopes(resources, destination_namespace, discovery, &in_bundle_crds)?;
        // Namespace injection can create GKNN collisions that were absent in the raw set. Hooks are
        // excluded: a `generateName` hook has no name at all, so two of them legitimately share a
        // GKNN — they are distinguishable only by their rendered id (`T10.3`, finding H2).
        manifest::check_duplicate_keys(resources.iter().filter(|resource| !is_hook(resource)))?;
        Ok((in_bundle_crds, in_bundle_namespaces))
    }

    /// Cleans up managed resources when the `Application` is being deleted.
    ///
    /// The cascade uses exactly the same [`OwnershipVerifiedPruner`] as a normal prune (T08.5),
    /// in **reverse apply order** (`sort_keys_prune_order`): a `Namespace` is deleted after the
    /// workloads inside it, and a `CustomResourceDefinition` after its custom resources. Deleting
    /// an `Application` can therefore never delete more than a prune would — every delete is
    /// re-verified against `ferriscd.io/tracking-id` on a freshly read object, and the
    /// `pruneCRDs`/`pruneNamespaces`/`ferriscd.io/prune=false` rails apply unchanged.
    ///
    /// # Intentional policy bypass (finding N2)
    ///
    /// Unlike [`Self::sync_apply`], this path does **not** evaluate the whole
    /// [`AppProjectPolicy`](ferriscd_engine::policy::AppProjectPolicy): it runs while the
    /// `Application` is being deleted, and refusing here would wedge the object in
    /// `Terminating` (finding C5) for a project that — say — dropped the `sourceNamespaces` entry
    /// the `Application` still lives in. The bypass is safe because cleanup is strictly narrower
    /// than a sync in every other respect:
    ///
    /// * it only ever deletes keys that are in **this** `Application`'s `status.inventory`, i.e.
    ///   objects FerrisCD itself applied and stamped;
    /// * every delete re-reads the live object and re-verifies `ferriscd.io/tracking-id` before
    ///   issuing it (`OwnershipVerifiedPruner`), so a foreign object is retained, never deleted;
    /// * the `pruneCRDs`/`pruneNamespaces`/`ferriscd.io/prune=false` rails still apply;
    /// * it runs with the `Application`'s own identity (`T12.3`), so the API server's RBAC still
    ///   bounds what a tenant can cascade.
    ///
    /// A denied project therefore cannot be used to delete anything a permitted one could not.
    ///
    /// **One exception: the ServiceAccount allow-list (finding H1).** `spec.allowedServiceAccounts`
    /// is not a "may this `Application` deploy?" question — it decides *as whom* the deletes are
    /// issued. A tenant could otherwise leave an unauthorized `spec.serviceAccountName` on the
    /// object, delete the `Application`, and cascade with an identity no project ever authorized
    /// (or with an identity it retargeted a moment earlier). The check therefore runs here too,
    /// **before** the identity is resolved: a denial retains the finalizer and fails the cleanup,
    /// so nothing is ever deleted by an unauthorized identity. `ferriscd.io/force-delete: "true"`
    /// stays the documented escape hatch for an operator who needs the object gone anyway.
    async fn cleanup_inner(
        &self,
        app: &Application,
        mode: CleanupMode,
    ) -> Result<CleanupOutcome, ReconcileError> {
        if mode == CleanupMode::Orphan {
            // Non-cascading is the default: deleting an Application never deletes workloads.
            return Ok(CleanupOutcome::Completed);
        }

        let owner = TrackingOwner::for_application(app).ok_or_else(|| ReconcileError::Invalid {
            message: "the Application has no metadata.namespace".to_owned(),
        })?;
        let inventory = status_inventory(app)?;
        if inventory.is_empty() {
            return Ok(CleanupOutcome::Completed);
        }

        let options = app.spec.sync_options();
        // Finding H1: authorize the identity *before* resolving it. With no `serviceAccountName`
        // this is a no-op (the controller identity the cascade has always used).
        self.check_cascade_service_account(app).await?;
        // `T13.1` finding C5 + finding M-new-1: a destination cluster that cannot be resolved — its
        // `Secret` was deleted (or it was never registered), or `spec.destination.cluster` is blank
        // (a spec typo: `serde(default)` covers only the omitted field) — is reported as
        // `TargetUnavailable`, which releases the finalizer with a warning instead of wedging the
        // `Application` in `Terminating` forever: there is nothing left to delete with, and the
        // objects died with the cluster or its credentials.
        let target = match self.target_for(app) {
            Ok(target) => target,
            Err(ReconcileError::Cluster(err)) if err.blocks_cleanup() => {
                return Ok(CleanupOutcome::TargetUnavailable {
                    message: err.to_string(),
                });
            }
            Err(err) => return Err(err),
        };
        // `T12.3`: the cascade runs as the *Application's* identity, like the sync that created
        // the objects — a tenant `Application` must not be able to use the controller's privileges
        // to delete (or to fail to delete) its own namespace's resources. `access_for` is the same
        // resolution the sync path uses, so an unusable ServiceAccount fails here too (retaining
        // the finalizer, with `ferriscd.io/force-delete` as the documented escape hatch).
        let access = self.access_for(app, &target)?;
        let pruner = OwnershipVerifiedPruner::new(
            access.applier(),
            access.reader(),
            target.discovery(),
            &owner,
            &options,
        );
        let keys = sort_keys_prune_order(inventory.keys().cloned().collect());
        for key in keys {
            let hint = inventory.get(&key).map(|entry| entry.version.as_str());
            match pruner.prune(&key, hint).await? {
                PruneResult::Pruned => {}
                PruneResult::Retained(reason) => {
                    warn!(
                        resource = %key.canonical(),
                        reason = reason.as_str(),
                        "cascade cleanup kept a resource it may not delete"
                    );
                }
            }
        }
        Ok(CleanupOutcome::Completed)
    }

    /// Enforces `AppProject.spec.allowedServiceAccounts` before the cascade resolves an identity
    /// (finding H1).
    ///
    /// The project is read from the control-plane namespace, exactly like the sync path, and the
    /// ServiceAccount is compared in `spec.destination.namespace` (ADR-007). An `Application` that
    /// names no `serviceAccountName` is unaffected: it cascades with the controller identity, as it
    /// always has, and there is no tenant identity to authorize.
    ///
    /// A denial is **terminal** ([`ReconcileError::Policy`]) so the reconcile stops, the finalizer
    /// is retained, and the operator sees `Ready=False, reason=PolicyViolation` naming the
    /// ServiceAccount. `ferriscd.io/force-delete: "true"` releases the finalizer without pruning
    /// (`cleanup_disposition`), which is the documented way out of a project that no longer
    /// authorizes the identity an `Application` is stuck with.
    ///
    /// # Errors
    ///
    /// [`ReconcileError::Policy`] when the project does not list the ServiceAccount,
    /// [`ReconcileError::Policy`] (`ProjectNotFound`) when the project itself is gone, and any API
    /// failure of the project read (retryable).
    async fn check_cascade_service_account(&self, app: &Application) -> Result<(), ReconcileError> {
        let service_account = app
            .spec
            .service_account_name
            .as_deref()
            .map(str::trim)
            .unwrap_or_default();
        if service_account.is_empty() {
            return Ok(());
        }
        let policy = self.load_project_policy(app).await?;
        if policy.allows_service_account(&app.spec.destination.namespace, service_account) {
            return Ok(());
        }
        Err(ReconcileError::Policy(
            PolicyError::ServiceAccountNotAllowed {
                application: format!("{}/{}", app.namespace().unwrap_or_default(), app.name_any()),
                project: app.spec.project.clone(),
                namespace: app.spec.destination.namespace.trim().to_owned(),
                service_account: service_account.to_owned(),
            },
        ))
    }
}

impl SyncPipeline for InventorySyncPipeline {
    fn apply<'a>(
        &'a self,
        app: &'a Application,
    ) -> BoxFuture<'a, Result<ApplyOutcome, ReconcileError>> {
        Box::pin(self.sync_apply(app))
    }

    fn cleanup<'a>(
        &'a self,
        app: &'a Application,
        mode: CleanupMode,
    ) -> BoxFuture<'a, Result<CleanupOutcome, ReconcileError>> {
        Box::pin(self.cleanup_inner(app, mode))
    }

    fn diff<'a>(
        &'a self,
        app: &'a Application,
    ) -> BoxFuture<'a, Result<DiffPreview, ReconcileError>> {
        Box::pin(self.diff_preview(app))
    }
}

/// Implements the [`HookCluster`] seam for **one pass**, over that pass's cluster access.
///
/// Hooks are created with `Api::create` (see [`Applier::create`]) and are **not** stamped with a
/// `ferriscd.io/tracking-id`: their lifetime belongs to their delete policy, not to the pruner. The
/// health read deliberately goes through [`ClusterStateReader::get_object`] (no ownership
/// classification), because a hook object is neither `OwnedBySelf` nor foreign — it is simply not
/// part of Git.
///
/// It is a wrapper rather than an implementation on the pipeline because a hook must be created and
/// observed as the pass's identity (`T12.3`): a `PreSync` migration Job of a tenant `Application`
/// runs as that tenant's ServiceAccount, not as the controller.
struct PassHooks<'a> {
    pipeline: &'a InventorySyncPipeline,
    access: &'a ClusterAccess,
    /// The destination cluster's discovery cache (`T13.1`): a hook kind is resolved on the cluster
    /// the hook is created on.
    discovery: &'a DiscoveryCache,
}

impl HookCluster for PassHooks<'_> {
    fn create_hook<'a>(
        &'a self,
        resource: &'a DesiredResource,
    ) -> BoxFuture<'a, Result<DynamicObject, ReconcileError>> {
        Box::pin(async move {
            let gvk = kube::core::GroupVersionKind::gvk(
                &resource.gvk.group,
                &resource.gvk.version,
                &resource.gvk.kind,
            );
            let (api_resource, _) = self.discovery.resolve(&gvk).await?;
            self.access
                .applier()
                .create(CreateRequest {
                    resource,
                    api_resource: &api_resource,
                    namespace: resource.key.namespace.as_deref(),
                })
                .await
        })
    }

    fn delete_hook<'a>(
        &'a self,
        key: &'a ResourceKey,
        version_hint: &'a str,
    ) -> BoxFuture<'a, Result<DeleteOutcome, ReconcileError>> {
        Box::pin(async move {
            let api_resource = self
                .pipeline
                .resolve_hook_resource(self.discovery, key, version_hint)
                .await?;
            self.access
                .applier()
                .delete(DeleteRequest {
                    key,
                    api_resource: &api_resource,
                    namespace: key.namespace.as_deref(),
                })
                .await
        })
    }

    fn hook_health<'a>(
        &'a self,
        key: &'a ResourceKey,
        version_hint: &'a str,
    ) -> BoxFuture<'a, Result<Option<HealthStatus>, ReconcileError>> {
        Box::pin(async move {
            let api_resource = self
                .pipeline
                .resolve_hook_resource(self.discovery, key, version_hint)
                .await?;
            let object = self
                .access
                .reader()
                .get_object(&api_resource, key.namespace.as_deref(), &key.name)
                .await?;
            let Some(object) = object else {
                return Ok(None);
            };
            let inputs = [HealthInput::live(key, &object)];
            let summary =
                health::assess(&inputs, &self.pipeline.health, &self.pipeline.health_config);
            Ok(summary.resources.first().map(|entry| entry.health.status))
        })
    }
}

impl InventorySyncPipeline {
    /// Resolves the served [`ApiResource`] of a hook object.
    ///
    /// Resolved by `(group, kind)` — the same version-agnostic identity a [`ResourceKey`] carries
    /// (ADR-003), so a hook keeps working across an API version bump and the *served* version always
    /// comes from discovery rather than from the rendered manifest.
    async fn resolve_hook_resource(
        &self,
        discovery: &DiscoveryCache,
        key: &ResourceKey,
        version_hint: &str,
    ) -> Result<ApiResource, ReconcileError> {
        discovery
            .resolve_kind(&key.group, &key.kind)
            .await?
            .map(|(api_resource, _)| api_resource)
            .ok_or_else(|| {
                ReconcileError::Discovery(crate::discovery::DiscoveryError::NoMatchesForKind {
                    group: key.group.clone(),
                    version: version_hint.to_owned(),
                    kind: key.kind.clone(),
                })
            })
    }
}

/// The decision a resumed operation plans its waves with.
///
/// A running operation keeps applying its waves even when the diff gate would now `Skip` (say
/// `automated` was disabled mid-rollout, or the resource happens to be `Synced` already). This only
/// grants *permission*: the plan still refuses to touch a resource the dry-run classified as
/// `Synced` (`applyOutOfSyncOnly`), so the pass issues no mutating call it does not need.
fn forced_execute(decision: SyncDecision) -> SyncDecision {
    if decision.is_execute() {
        decision
    } else {
        SyncDecision::Execute(SyncTrigger::Manual)
    }
}

/// Whether this pass must **not** restart a terminally failed operation (finding M5).
///
/// `false` means "restart it": that is the case for every phase that is not a terminal failure, and
/// for a failed operation whose commit changed (a new revision is a new sync) or that the operator
/// explicitly asked for (`ferriscd.io/operation`). Anything else stays failed until one of those
/// happens, so a requeue can never re-run the hooks of a commit that already failed.
fn failed_operation_is_not_retried(request: &PassRequest<'_>, persisted: &OperationState) -> bool {
    if !matches!(
        persisted.phase,
        OperationPhase::Failed | OperationPhase::Error
    ) {
        return false;
    }
    let new_revision = persisted.revision.as_deref() != Some(request.revision);
    !(new_revision || manual_operation(request.app))
}

/// Turns a failure that happened *inside* a running operation into the error that still carries the
/// state the pass reached (finding H-NEW).
///
/// A hook created before the failure is tracked nowhere but in
/// `status.operationState.activeHooks`, and `apply_once` can only persist the state the error
/// carries. Returning the bare API error would therefore make the next pass see the created hook as
/// untracked and create a second `generateName` `Job` — a second database migration.
///
/// A terminal failure is not retried, so it is reported as the [`ReconcileError::SyncConflict`] the
/// rest of the pipeline uses for policy failures (it still carries the inventory that is true). It
/// carries the operation state too, **marked `Failed`** (finding H-A): dropping it made the next
/// requeue restart the operation with an empty `activeHooks` list and create a second
/// `generateName` `Job` — a second migration. Persisting the terminal phase is what makes
/// `failed_operation_is_not_retried` hold an unchanged commit on the terminal backoff instead; a new
/// revision or an explicit `ferriscd.io/operation` still restarts it.
fn mid_operation_error(
    request: &PassRequest<'_>,
    error: &ReconcileError,
    inventory: &Inventory,
    operation: Option<OperationState>,
) -> ReconcileError {
    let message = error.to_string();
    let revision = Some(request.revision.to_owned());
    match error.failure_class() {
        FailureClass::Retryable => ReconcileError::PartialSync {
            message,
            inventory: inventory.clone(),
            revision,
            operation: operation.map(Box::new),
        },
        FailureClass::Terminal => ReconcileError::SyncConflict {
            message: message.clone(),
            inventory: inventory.clone(),
            revision,
            operation: operation.map(|mut state| {
                state.phase = OperationPhase::Failed;
                state.finished_at = Some(request.now.clone());
                state.message = Some(message);
                Box::new(state)
            }),
        },
    }
}

/// The `Succeeded` operation state a **single-pass** sync records (`T10.5`).
///
/// A hook-less single-wave commit is applied in one pass and never enters the state machine, but its
/// deployment still has to be auditable and rollback-able: this synthesizes the terminal state the
/// machine would have produced, so `status.operationState.revision` is the commit that is live and
/// `record_operation_success` can append it to `status.history`.
fn succeeded_operation(revision: &str, now: &Time, last_wave: Option<i32>) -> OperationState {
    OperationState {
        phase: OperationPhase::Succeeded,
        sync_phase: Some(SyncPhase::Succeeded),
        current_wave: last_wave.unwrap_or(0),
        phase_started_at: Some(now.clone()),
        revision: Some(revision.to_owned()),
        active_hooks: Vec::new(),
        message: Some("sync completed: every resource is applied".to_owned()),
        started_at: now.clone(),
        finished_at: Some(now.clone()),
    }
}

/// Appends `operation` to `status.history` (idempotent), returning the new list when it changed.
///
/// `record_operation_success` refuses a non-`Succeeded` operation and is idempotent per
/// `(revision, finishedAt)`, so the caller gates the call on "this is a **new** deployment"
/// (`lastSyncedRevision != revision`): otherwise every drift-healing pass of the same commit would
/// append another identical entry and `history` would fill with duplicates of one deployment.
fn record_history(
    previous: &ApplicationStatus,
    app: &Application,
    operation: &OperationState,
) -> Option<Vec<RevisionHistoryEntry>> {
    let mut scratch = previous.clone();
    record_operation_success(
        &mut scratch,
        operation,
        Some(&app.spec.source),
        app.spec.revision_history_limit,
    )
    .is_first()
    .then_some(scratch.history)
}

/// The commit a still-standing rollback is pinned to (`T10.5`).
///
/// While the `AutomatedSyncDisabledByRollback` warning is on the application, the revision recorded
/// by the operation that performed it — not `HEAD` — is what the controller must keep resolving:
/// that is what makes a rollback **stable** across requeues. Re-enabling
/// `spec.syncPolicy.automated` clears the warning
/// ([`ferriscd_engine::sync::clear_rollback_warning_if_automation_reenabled`]), and from then on
/// `HEAD` wins again.
pub(crate) fn pinned_rollback_revision(status: &ApplicationStatus) -> Option<String> {
    let warned = status.conditions.iter().any(|condition| {
        condition.type_ == ferriscd_engine::sync::CONDITION_WARNING
            && condition.reason == ferriscd_engine::sync::REASON_AUTOMATED_SYNC_DISABLED_BY_ROLLBACK
    });
    if !warned {
        return None;
    }
    status
        .operation_state
        .as_ref()
        .and_then(|state| state.revision.clone())
}

/// Logs the plan one executed step produced.
fn log_plan(request: &PassRequest<'_>, plan: &SyncPlan) {
    let summary = plan.summary();
    tracing::debug!(
        app.namespace = %request.owner.namespace,
        app.name = %request.owner.name,
        decision = %request.decision,
        applies = summary.apply,
        replaces = summary.replace,
        prunes = summary.prune,
        skips = summary.skip,
        "executing a sync plan"
    );
}

/// Logs the hook lifecycle of one step.
fn log_hooks(request: &PassRequest<'_>, step: SyncStep, run: &HookRun) {
    if run.is_noop() {
        return;
    }
    tracing::debug!(
        app.namespace = %request.owner.namespace,
        app.name = %request.owner.name,
        step = %step,
        created = run.created,
        deleted = run.deleted.len(),
        pending_delete = run.pending_delete.as_deref().unwrap_or_default(),
        "ran lifecycle hooks"
    );
}

/// Stamps `ferriscd.io/tracking-id` onto every **permanent** desired resource.
///
/// Called with `HookPartition::permanent_mut()`, so a lifecycle hook is never stamped and nothing
/// that is created imperatively ends up looking prunable (`T10.3`).
fn stamp_ownership(
    resources: &mut [DesiredResource],
    owner: &TrackingOwner,
) -> Result<(), ReconcileError> {
    for resource in resources.iter_mut() {
        let key = resource.key.canonical();
        inventory::stamp_tracking_id(resource, &owner.namespace, &owner.name).map_err(|err| {
            ReconcileError::Invalid {
                message: format!("{key}: {err}"),
            }
        })?;
    }
    Ok(())
}

/// Reads `prev_inventory` from `status.inventory`.
///
/// A malformed key is terminal: silently skipping it would drop a live resource out of the
/// inventory and leak it forever (finding C1).
fn status_inventory(app: &Application) -> Result<Inventory, ReconcileError> {
    match app.status.as_ref() {
        Some(status) => inventory::from_status_entries(status.inventory.iter()).map_err(|err| {
            ReconcileError::Invalid {
                message: err.to_string(),
            }
        }),
        None => Ok(Inventory::new()),
    }
}

/// Returns whether `app` carries a **manual sync request** (T07.4 `SyncTrigger::Manual`).
///
/// `ferriscd.io/operation` is the annotation the CLI/API writes to ask for a sync
/// (`{"sync":{"revision":"..."}}`). Any non-blank value counts as a manual operation, which
/// bypasses `automated` and `selfHeal` entirely — that is the documented escape hatch for
/// `automated: None`, and the reason a blank value is *not* an operation (an empty annotation
/// is what a `kubectl annotate --overwrite` with an empty string leaves behind).
///
/// `ferriscd.io/refresh` is deliberately **not** a manual operation: it only asks for an
/// immediate reconcile (the composite watch predicate), and the diff gate must still decide
/// whether anything is applied.
///
/// A present operation used to mean "manual, forever": nothing consumed it, so one request kept
/// every later reconcile executing (and, through the API, made every later sync/rollback a
/// conflict). [`Pipeline::consume_operation`] now clears the annotation once a pass has settled, so
/// "present" really means "pending": the request is honoured **once**, by the pass
/// [`honoured_operation`] identifies.
#[must_use]
pub fn manual_operation(app: &Application) -> bool {
    honoured_operation(app).is_some()
}

/// The `ferriscd.io/operation` request a settled pass has honoured, if any.
///
/// This is the complement of [`manual_operation`]: the same non-blank annotation, so what one
/// function treats as a request the other consumes. It covers a manual sync (`{"sync":{...}}`) and,
/// conservatively, any other non-rollback value — a rollback request is consumed by the same code
/// path (`prepared.rollback` says which), so the caller only needs the raw value.
fn honoured_operation(app: &Application) -> Option<&str> {
    app.annotations()
        .get(annotations::OPERATION)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
}

/// Indexes a diff pass by resource key.
fn status_by_key(diffs: &[ResourceDiff]) -> BTreeMap<ResourceKey, DiffStatus> {
    diffs
        .iter()
        .map(|diff| (diff.key().clone(), diff.status().clone()))
        .collect()
}

/// Returns whether `spec.syncPolicy.automated.prune` is enabled.
///
/// One helper, so the prune pass and the status mapping can never disagree about whether an
/// orphan may be deleted in this milestone.
#[must_use]
fn prune_enabled(app: &Application) -> bool {
    app.spec
        .sync_policy
        .as_ref()
        .is_some_and(|policy| policy.prune_enabled())
}

/// Warns about every `ignoreDifferences` pointer that is not valid RFC 6901 and returns the total
/// (finding H1).
///
/// [`IgnoreRule::with_json_pointer`](ferriscd_engine::diff::ignore::IgnoreRule) records such a
/// pointer instead of applying it, so a typo never fails a reconcile — but an ignored rule that
/// silently does nothing is worse than an error: the operator believes a field is ignored while
/// it keeps reporting drift. The warnings are bounded by
/// [`MAX_LOGGED_INVALID_POINTERS`]; the count that reaches `Application.status` is not.
fn report_invalid_pointers(rules: &IgnoreRuleSet, owner: &TrackingOwner) -> usize {
    let mut total = 0;
    for pointer in rules.invalid_pointers() {
        total += 1;
        if total <= MAX_LOGGED_INVALID_POINTERS {
            warn!(
                app.namespace = %owner.namespace,
                app.name = %owner.name,
                pointer = %pointer,
                "spec.ignoreDifferences contains a JSON pointer that is not valid RFC 6901: it is \
                 not applied, so the field it names is still compared"
            );
        }
    }
    if total > MAX_LOGGED_INVALID_POINTERS {
        warn!(
            app.namespace = %owner.namespace,
            app.name = %owner.name,
            omitted = total - MAX_LOGGED_INVALID_POINTERS,
            "further invalid spec.ignoreDifferences pointers are not logged individually"
        );
    }
    total
}

/// Maps a diff summary onto `status.sync.status` **without** counting orphans (finding H2).
///
/// [`DiffSummary::sync_status`] deliberately reports `OutOfSync` for an orphan — the operator
/// removed a resource from Git and must be told — and that engine semantic is unchanged. The
/// controller needs a narrower reading when pruning is **disabled**: FerrisCD will never delete
/// that object, so counting it makes the `Skip` pass that follows an executing one flip the
/// status to `OutOfSync` forever, for a resource the operator explicitly asked to keep (the T06
/// contract). Retained orphans are still reported, in the `Ready` message.
#[must_use]
fn sync_status_without_orphans(summary: &DiffSummary) -> SyncStatus {
    DiffSummary {
        orphaned: 0,
        ..*summary
    }
    .sync_status()
}

/// Classifies one orphan for the planner from the pass-level live read.
///
/// The planner is pure, so the ownership *verdict* is what it gets — never a live object (no
/// `Secret` document can reach it). A key the pass never classified, or one still deferred on a
/// CRD/namespace, is [`OrphanOwnership::NotFetched`]: FerrisCD never deletes what it did not look
/// at.
fn orphan_candidate(key: &ResourceKey, live: &BTreeMap<ResourceKey, LiveState>) -> OrphanCandidate {
    // The per-resource opt-out is the one rail the *planner* cannot infer from the key alone, so
    // it travels with the candidate; the CRD/namespace rails are key-derived and checked there.
    let opted_out = match live.get(key) {
        Some(LiveState::Present(object, _)) => crate::prune::prune_opted_out(object),
        _ => false,
    };
    OrphanCandidate::new(key.clone(), orphan_ownership(live, key), opted_out)
}

/// Maps a live-state verdict onto the planner's ownership enum.
fn orphan_ownership(live: &BTreeMap<ResourceKey, LiveState>, key: &ResourceKey) -> OrphanOwnership {
    match live.get(key) {
        Some(LiveState::Present(_, Ownership::OwnedBySelf)) => OrphanOwnership::SelfOwned,
        Some(LiveState::Present(_, Ownership::OwnedByForeign(owner))) => {
            OrphanOwnership::Foreign(owner.clone())
        }
        Some(LiveState::Present(_, Ownership::Unmanaged)) => OrphanOwnership::Unmanaged,
        // A confirmed absence is a confirmed prune (MASTER_PLAN §4.3).
        Some(LiveState::Missing | LiveState::OrphanGvkGone) => OrphanOwnership::Gone,
        // Deferred on a CRD/namespace this bundle creates, or never fetched at all: wait.
        Some(LiveState::DeferredPendingCrd | LiveState::DeferredPendingNamespace) | None => {
            OrphanOwnership::NotFetched
        }
    }
}

/// Builds the successful [`ApplyOutcome`], including the crash-safe inventory and sync state.
///
/// `status.sync.status` is derived from the diff summary, **not** from "did an apply succeed":
/// a pass that deliberately skipped over a drifting cluster must still report `OutOfSync` (the
/// operator has to see it), and only a pass that executed and finished every resource may claim
/// `Synced` and advance the `lastSynced*` markers.
///
/// Counts (retained orphans, ignored `ignoreDifferences` pointers) and the `prune` policy all
/// reach the `Ready` message: `Application.status` is the only place an operator looks, so a
/// warning that only exists in a log line is invisible (findings H1/H2).
fn build_outcome(
    app: &Application,
    decision: SyncDecision,
    summary: &DiffSummary,
    spec_hash: &str,
    counts: SyncCounts,
    revision: String,
    inventory: Inventory,
) -> ApplyOutcome {
    let SyncCounts {
        desired,
        applied,
        pruned,
        retained_orphans,
        pending,
        invalid_ignore_pointers,
        prune_enabled,
        health,
        settled,
        phase,
        requeue: requeue_hint,
    } = counts;
    // Only a pass that finished the whole operation may claim a full sync.
    //
    // `settled` is path-specific and already accounts for the gate: a single-pass sync is only
    // settled when it executed and nothing is pending, while an operation is settled when the state
    // machine reached `Succeeded`. The second case must **not** be re-gated on
    // `decision.is_execute()`: the pass that finishes a rollout routinely has nothing left to apply,
    // so the gate says `Skip` — and re-gating would leave `lastSynced*` unset (making `selfHeal:
    // false` re-execute forever) and report `SyncSkipped` for a sync that in fact completed.
    let synced = settled;
    let trigger = decision
        .trigger()
        .map_or("operation", ferriscd_engine::diff::SyncTrigger::as_str);
    let sync = SyncState {
        status: if synced {
            SyncStatus::Synced
        } else if prune_enabled {
            summary.sync_status()
        } else {
            // Finding H2: an orphan FerrisCD will never delete must not pin `OutOfSync` forever.
            sync_status_without_orphans(summary)
        },
        revision: Some(revision.clone()),
        // Finding H7: the (revision, spec hash) pair is what `selfHeal: false` compares, so both
        // markers are written together by the same successful pass. `merge_sync_state` keeps the
        // previous values when a pass reports `None` here.
        last_synced_revision: synced.then(|| revision.clone()),
        last_synced_spec_hash: synced.then(|| spec_hash.to_owned()),
        last_synced_at: synced.then(now),
    };

    // A stuck orphan is otherwise invisible: `prune: true` that deletes nothing looks exactly
    // like "there was nothing to prune", and `prune: false` would report nothing at all.
    let retained = if retained_orphans == 0 {
        String::new()
    } else {
        format!(
            "; {retained_orphans} orphan(s) retained (not owned, not prunable, or still pending)"
        )
    };
    // Finding H1: a pointer that is not valid RFC 6901 is never applied, so the operator must see
    // that the rule did nothing (the count is a number, so the message stays bounded).
    let invalid = match invalid_ignore_pointers {
        0 => String::new(),
        1 => "; 1 invalid ignoreDifferences pointer ignored".to_owned(),
        count => format!("; {count} invalid ignoreDifferences pointers ignored"),
    };
    let short = short_sha(&revision);

    let (reason, message) = if synced {
        (
            REASON_SYNC_SUCCEEDED,
            format!(
                "applied {applied} of {desired} resource(s) at revision {short}, \
                 pruned {pruned}{retained}{invalid} ({trigger})"
            ),
        )
    } else {
        match decision {
            SyncDecision::Skip(skip) => (
                REASON_SYNC_SKIPPED,
                format!(
                    "no sync performed: {skip}; {desired} resource(s) at revision {short}, \
                     {} out of sync, {} missing, {} orphan(s){retained}{invalid}",
                    summary.out_of_sync, summary.missing, summary.orphaned
                ),
            ),
            SyncDecision::Execute(_) if pending > 0 => (
                REASON_PENDING,
                format!(
                    "applied {applied} of {desired} resource(s) at revision {short}; {pending} \
                     resource(s) pending on a CustomResourceDefinition or namespace{retained}\
                     {invalid}"
                ),
            ),
            SyncDecision::Execute(_) => (
                REASON_SYNC_IN_PROGRESS,
                format!(
                    "sync in progress ({}): applied {applied} of {desired} resource(s) at \
                     revision {short}, waiting for it to become Healthy{retained}{invalid}",
                    phase.as_deref().unwrap_or("running")
                ),
            ),
        }
    };

    let requeue = plan_requeue(decision.is_execute(), pending, health, app, requeue_hint);

    ApplyOutcome::ready(reason, message)
        .with_inventory(inventory)
        .with_sync(sync)
        .with_requeue(requeue)
}

/// Returns whether an empty desired set may prune the inventory.
///
/// Reads [`ALLOW_EMPTY_DESIRED_ENV`]; any value other than empty, `0` or `false` counts as
/// consent.
fn empty_desired_allowed() -> bool {
    std::env::var(ALLOW_EMPTY_DESIRED_ENV).is_ok_and(|value| {
        let value = value.trim();
        !value.is_empty()
            && !value.eq_ignore_ascii_case("0")
            && !value.eq_ignore_ascii_case("false")
    })
}

/// Builds the [`HealthInput`] list for a pass (`T09.5`).
///
/// Health is assessed **per desired resource**, fed by the live state the pass already fetched
/// (one scoped read, model 1 drift detection — no extra API calls, no cluster-wide informers):
///
/// | `LiveState` | Observation | Verdict source |
/// |---|---|---|
/// | `Present` | [`HealthInput::live`] | the object's `status` (the real evaluator) |
/// | `Missing`, applied this pass | [`HealthInput::applied`] | `Progressing`: the live read predates the write |
/// | `Missing`, scheduled for a later wave | [`HealthInput::pending`] | `Progressing`: the rollout has not reached it |
/// | `Missing`, not applied | [`HealthInput::missing`] | `Missing` |
/// | `DeferredPendingCrd` / `DeferredPendingNamespace` | [`HealthInput::pending`] | `Progressing` |
/// | `OrphanGvkGone` | skipped | a desired key can never be an orphan |
///
/// A `Present` object is used even when this pass re-applied it: its `status` is at worst one
/// reconcile stale, and the next pass corrects it, whereas reporting `Missing` for an object that
/// demonstrably exists would be a lie.
///
/// **Orphans are not assessed.** A resource that is tracked in `status.inventory` but no longer in
/// Git is on its way out (`prune`) or deliberately retained (`prune: false`); letting it pin
/// `status.health` could keep the `Application` `Degraded`/`Missing` forever for an object nobody
/// declares any more. Health describes what Git asks for — which is also exactly what Phase 10's
/// waves wait on.
///
/// **A scheduled wave is not `Missing` (finding M3).** Mid-rollout, the resources of a wave the
/// operation has not dispatched yet do not exist *by design*. Reporting them `Missing` makes
/// `status.health` (and the per-resource list) claim the Application is broken in the middle of a
/// perfectly healthy rollout; they are `Progressing` until their wave is dispatched.
fn health_inputs<'a>(
    resources: &'a [DesiredResource],
    live: &'a LiveStateMap,
    applied: &Inventory,
    scheduled: &BTreeSet<ResourceKey>,
) -> Vec<HealthInput<'a>> {
    resources
        .iter()
        .filter_map(|resource| {
            let key = &resource.key;
            let observation = match live.get(key)? {
                LiveState::Present(object, _) => HealthInput::live(key, object.as_ref()),
                LiveState::Missing if applied.contains_key(key) => HealthInput::applied(key),
                LiveState::Missing if scheduled.contains(key) => HealthInput::pending(
                    key,
                    "scheduled: waiting for a later sync wave of the running operation",
                ),
                LiveState::Missing => HealthInput::missing(key),
                LiveState::DeferredPendingCrd => HealthInput::pending(
                    key,
                    "waiting for the CustomResourceDefinition to be served",
                ),
                LiveState::DeferredPendingNamespace => {
                    HealthInput::pending(key, "waiting for the Namespace to exist")
                }
                // A desired key is never fetched as an orphan; if one shows up, its health is not
                // this pass's business (the prune path owns it).
                LiveState::OrphanGvkGone => return None,
            };
            Some(observation)
        })
        .collect()
}

/// Renders the per-resource `status.resources` summaries.
///
/// The version hint comes from `status.inventory`'s desired half (never from the key), so the
/// operator sees the same GKNN identity in `status.resources[].key` and `status.inventory[].key`
/// (ADR-003: identity is version-agnostic).
fn resource_statuses(health: &HealthSummary, desired: &Inventory) -> Vec<ResourceStatus> {
    health
        .resources
        .iter()
        .map(|assessment| {
            ResourceStatus::new(
                assessment.key.canonical(),
                desired
                    .get(&assessment.key)
                    .map(|entry| entry.version.clone())
                    .unwrap_or_default(),
                assessment.health.status,
                assessment.health.message.clone(),
            )
        })
        .collect()
}

/// Decides how long to wait before the next reconcile (`T09.5` adaptive requeue).
///
/// * a resource pending on a CRD/namespace → [`PENDING_REQUEUE`] (it is not an error, and the
///   deployment that follows it is blocked on it);
/// * `Progressing` → [`PROGRESSING_REQUEUE`], capped by `spec.requeueAfterSeconds` so an operator
///   who asked for a *faster* interval still gets it;
/// * settled (`Healthy`/`Degraded`/`Suspended`/`Missing`/`Unknown`) → the configured interval.
///
/// Only `Progressing` shortens the interval on purpose: `Degraded` and `Missing` are terminal-ish
/// observations that a faster poll cannot change, and hammering the API server while a workload is
/// broken helps nobody.
#[must_use]
fn plan_requeue(
    execute: bool,
    pending: usize,
    health: HealthStatus,
    app: &Application,
    hint: Option<Duration>,
) -> Duration {
    // An in-flight wave/hook operation owns its own pacing (`T10.1`: `Action::requeue(5s)`): it is
    // waiting for a rollout, not for a timer, and `spec.requeueAfterSeconds` (default 180 s) would
    // make a three-wave sync take nine minutes for no reason.
    if let Some(hint) = hint {
        return hint;
    }
    let configured = Duration::from_secs(u64::from(app.spec.requeue_after_seconds));
    if execute && pending > 0 {
        return PENDING_REQUEUE;
    }
    if health == HealthStatus::Progressing {
        return PROGRESSING_REQUEUE.min(configured);
    }
    configured
}

/// First 7 characters of a commit SHA (the full SHA lives in `status.sync.revision`).
fn short_sha(sha: &str) -> String {
    sha.chars().take(7).collect()
}

/// Rejects every desired resource whose live object is owned by a different `Application`.
///
/// Runs before any mutation, so a foreign object is never adopted, patched or pruned (trap
/// T10: two `Application`s pointing at the same manifest must not fight).
fn reject_foreign_ownership(
    resources: &[DesiredResource],
    live: &BTreeMap<ResourceKey, LiveState>,
) -> Result<(), ReconcileError> {
    let mut foreign: Vec<String> = Vec::new();
    for resource in resources {
        // Every desired key is fetched by `plan_fetch`, so a missing entry means the caller
        // skipped the live read. Refuse rather than apply without an ownership check.
        let Some(state) = live.get(&resource.key) else {
            return Err(ReconcileError::Invalid {
                message: format!(
                    "internal error: no live state was read for {}; refusing to apply without an                      ownership check",
                    resource.key.canonical()
                ),
            });
        };
        if let LiveState::Present(_, Ownership::OwnedByForeign(owner)) = state {
            foreign.push(format!("{} (owned by {owner})", resource.key.canonical()));
        }
    }
    if foreign.is_empty() {
        return Ok(());
    }

    let shown = foreign.len().min(5);
    let mut listing = foreign[..shown].join(", ");
    if foreign.len() > shown {
        listing.push_str(&format!(", and {} more", foreign.len() - shown));
    }
    Err(ReconcileError::Invalid {
        message: format!(
            "refusing to sync {} resource(s) whose ferriscd.io/tracking-id belongs to another \
             Application: {listing}",
            foreign.len()
        ),
    })
}

/// Returns whether `resource` is a lifecycle hook (`ferriscd.io/hook` is present and non-blank).
///
/// A blank value is *not* a hook here: `graph::hooks::partition` rejects it as a malformed control
/// annotation (a typo must never silently mean "no hook"), which is a terminal manifest error.
fn is_hook(resource: &DesiredResource) -> bool {
    resource
        .object
        .metadata
        .annotations
        .as_ref()
        .and_then(|map| map.get(annotations::HOOK))
        .is_some_and(|phase| !phase.trim().is_empty())
}

/// Rejects manifests the controller cannot order or track correctly.
///
/// `metadata.generateName` stays unsupported for **permanent** resources: a planned resource is
/// identified by its GKNN, and a name the API server picks cannot be tracked, diffed or pruned. A
/// lifecycle hook is the one legitimate user of `generateName` (`T10.3`): it is created with
/// `Api::create` and tracked in `status.operationState.activeHooks` by its rendered id instead.
fn reject_unsupported(resource: &DesiredResource) -> Result<(), ReconcileError> {
    if resource.object.metadata.generate_name.is_some() && !is_hook(resource) {
        return Err(ReconcileError::Invalid {
            message: format!(
                "{}: metadata.generateName is only supported on lifecycle hooks \
                 ({}); a permanent resource must be named so it can be tracked and pruned",
                resource.key.canonical(),
                annotations::HOOK
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ferriscd_crd::application::{
        DEFAULT_REQUEUE_AFTER_SECONDS, DEFAULT_REVISION_HISTORY_LIMIT,
    };
    use ferriscd_crd::status::{
        ApplicationStatus, CONDITION_READY, Condition, ConditionStatus, HealthState, HealthStatus,
    };
    use ferriscd_crd::{
        AppProject, ApplicationSpec, AutomatedSyncPolicy, DestinationSpec, GitSourceSpec,
        RendererSpec, SourceSpec, SyncOptions, SyncPolicy,
    };
    use ferriscd_engine::health::Observation;
    use ferriscd_engine::manifest::GroupVersionKind;
    use ferriscd_engine::policy::ApplicationNamespaces;
    use ferriscd_engine::repo::{FakeGitClient, FakeGitClientConfig, RepoCacheConfig};
    use kube::api::GroupVersionKind as KubeGvk;
    use kube::discovery::{ApiCapabilities, Scope};
    use serde_json::json;

    use super::*;
    use crate::cluster_manager::ClusterError;
    use crate::credentials::CredentialError;
    use crate::discovery::{DiscoveryError, DiscoveryFuture, DiscoverySnapshot, DiscoverySource};
    use crate::dry_run::{DryRunFuture, DryRunOutcome, DryRunTarget};
    use crate::live_state::{FetchTarget, LiveFuture};
    use crate::reconcile::{
        CleanupDisposition, REASON_OWNERSHIP_CONFLICT, StatusWriter, apply_once,
    };

    // ---------------------------------------------------------------------
    // Fixtures
    // ---------------------------------------------------------------------

    /// Scripted API server: live objects keyed by canonical GKNN.
    #[derive(Default)]
    struct FakeCluster {
        objects: StdMutex<BTreeMap<String, DynamicObject>>,
        namespaces: StdMutex<Vec<String>>,
        /// Hook object names `Api::create` produced (a `generateName` hook gets a suffix appended).
        creates: StdMutex<Vec<String>>,
        /// Merge patches issued against the `Application` object itself (`T10.5`).
        app_patches: StdMutex<Vec<serde_json::Value>>,
        applies: StdMutex<Vec<String>>,
        applied_objects: StdMutex<Vec<DynamicObject>>,
        applied_tracking_ids: StdMutex<Vec<String>>,
        deletes: StdMutex<Vec<String>>,
        fail_apply: StdMutex<Vec<String>>,
        /// GKNNs the API server rejects with a retryable `500` (a `PartialSync`).
        retryable_apply: StdMutex<Vec<String>>,
        /// `generateName` prefixes whose *next* create the API server rejects with a retryable `500`
        /// (each entry is consumed by the failing call, so the retry succeeds).
        retryable_create: StdMutex<Vec<String>>,
        /// `generateName` prefixes whose *next* create the API server rejects with a terminal `422`
        /// (`field is immutable`), so the hook step ends in a `SyncConflict`.
        terminal_create: StdMutex<Vec<String>>,
        /// GKNNs the API server rejects with `422`/`field is immutable` (a terminal failure).
        immutable_apply: StdMutex<Vec<String>>,
        /// GKNNs whose `tracking-id` is replaced with a foreign one after their first `GET`
        /// (simulates a takeover between the pass-level fetch and the prune re-check).
        ownership_flip_after_get: StdMutex<Vec<String>>,
        deletes_confirmed: AtomicUsize,
        /// How the fake API server treats a `CustomResourceDefinition` it is handed.
        crd_mode: CrdMode,
    }

    /// What the fake API server does with an applied `CustomResourceDefinition`.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    enum CrdMode {
        /// Accepted, established, and its kind immediately served (a real cluster).
        #[default]
        Establish,
        /// Accepted but not established (yet): `Established=False`.
        Pending,
        /// Accepted, then rejected: `NamesAccepted=False` (never establishes, finding H5).
        Rejected,
    }

    impl FakeCluster {
        fn with_object(self, object: DynamicObject) -> Self {
            self.objects
                .lock()
                .unwrap()
                .insert(gknn_of_object(&object), object);
            self
        }

        fn with_namespace(self, namespace: &str) -> Self {
            self.namespaces.lock().unwrap().push(namespace.to_owned());
            self
        }

        /// Names of the hook objects this fake API server created.
        fn creates(&self) -> Vec<String> {
            self.creates.lock().unwrap().clone()
        }

        /// The merge patches this test issued against the `Application`'s own object.
        fn app_patches(&self) -> Vec<serde_json::Value> {
            self.app_patches.lock().unwrap().clone()
        }

        /// One field of a live object (`/data/version` -> `v1`), for asserting what really landed.
        fn live_pointer(&self, gknn: &str, pointer: &str) -> Option<String> {
            self.objects
                .lock()
                .unwrap()
                .get(gknn)
                .and_then(|object| object.data.pointer(pointer))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        }

        /// Models a `Deployment` whose rollout converged (`T09.2`'s health contract).
        fn make_deployment_ready(&self, name: &str, replicas: i32) {
            self.drift(&format!("apps/Deployment/payments/{name}"), |object| {
                object.data["status"] = json!({
                    "observedGeneration": object.metadata.generation,
                    "replicas": replicas,
                    "updatedReplicas": replicas,
                    "availableReplicas": replicas,
                    "readyReplicas": replicas,
                    "conditions": [],
                });
            });
        }

        /// Models the API server finishing a hook `Job`: it reports `Complete`.
        fn complete_job(&self, name: &str) {
            self.drift(&format!("batch/Job/payments/{name}"), |object| {
                object.data["status"] = json!({
                    "conditions": [{ "type": "Complete", "status": "True" }],
                    "succeeded": 1,
                });
            });
        }

        /// Models a hook `Job` that gave up: the API server reports `Failed=True` (a `Degraded`
        /// hook, which is what makes the wave machine enter `SyncFail`).
        fn fail_job(&self, name: &str) {
            self.drift(&format!("batch/Job/payments/{name}"), |object| {
                object.data["status"] = json!({
                    "conditions": [{
                        "type": "Failed",
                        "status": "True",
                        "reason": "BackoffLimitExceeded",
                    }],
                    "failed": 1,
                });
            });
        }

        fn fail_apply_for(self, key: &str) -> Self {
            self.fail_apply.lock().unwrap().push(key.to_owned());
            self
        }

        /// The next apply of `key` is rejected with a *retryable* API error (`500`), so the pass
        /// ends in [`ReconcileError::PartialSync`] and the next reconcile converges from live state.
        fn fail_apply_retryably(self, key: &str) -> Self {
            self.retryable_apply.lock().unwrap().push(key.to_owned());
            self
        }

        /// The next `Api::create` of a hook whose `generateName` is `prefix` is rejected with a
        /// *retryable* API error (`500`), so a hook step fails *after* creating its first hook.
        fn fail_create_retryably(self, prefix: &str) -> Self {
            self.retryable_create
                .lock()
                .unwrap()
                .push(prefix.to_owned());
            self
        }

        /// The next `Api::create` of a hook whose `generateName` is `prefix` is rejected with the
        /// API server's terminal `422`, so the hook step fails *after* creating its first hook and
        /// the reconcile is classified terminal (finding H-A).
        fn fail_create_terminally(self, prefix: &str) -> Self {
            self.terminal_create.lock().unwrap().push(prefix.to_owned());
            self
        }

        /// The next apply of `key` is rejected with the API server's immutable-field `422`.
        fn fail_apply_as_immutable(self, key: &str) -> Self {
            self.immutable_apply.lock().unwrap().push(key.to_owned());
            self
        }

        /// The next applied CRD stays `Established=False` (and its kind is never served).
        fn with_unestablished_crds(mut self) -> Self {
            self.crd_mode = CrdMode::Pending;
            self
        }

        /// The next applied CRD is rejected by the API server (`NamesAccepted=False`).
        fn with_rejected_crds(mut self) -> Self {
            self.crd_mode = CrdMode::Rejected;
            self
        }

        fn with_ownership_flip_after_get(self, gknn: &str) -> Self {
            self.ownership_flip_after_get
                .lock()
                .unwrap()
                .push(gknn.to_owned());
            self
        }

        fn applies(&self) -> Vec<String> {
            self.applies.lock().unwrap().clone()
        }

        /// Models a `Namespace` the API server has accepted: the *next* pass sees it as existing.
        ///
        /// [`Self::seed_applied`] records the applied object itself; this records the namespace
        /// *existence* verdict the live read probes for, which is what ends a
        /// `DeferredPendingNamespace` wait.
        fn seed_namespace(&self, namespace: &str) {
            self.namespaces.lock().unwrap().push(namespace.to_owned());
        }

        /// Makes every object the applier has written live, modelling the API server write.
        ///
        /// Re-seeding the same key overwrites it with the newest body, exactly like a real apply.
        fn seed_applied(&self) {
            let applied = self.applied_objects.lock().unwrap().clone();
            let mut objects = self.objects.lock().unwrap();
            for object in applied {
                objects.insert(gknn_of_object(&object), object);
            }
        }

        /// Applies `mutate` to the live object at `gknn` (drift injection).
        fn drift(&self, gknn: &str, mutate: impl FnOnce(&mut DynamicObject)) {
            let mut objects = self.objects.lock().unwrap();
            let object = objects
                .get_mut(gknn)
                .unwrap_or_else(|| panic!("no live object at {gknn}"));
            mutate(object);
        }

        fn applied_tracking_ids(&self) -> Vec<String> {
            self.applied_tracking_ids.lock().unwrap().clone()
        }

        fn deletes(&self) -> Vec<String> {
            self.deletes.lock().unwrap().clone()
        }

        fn deletes_confirmed(&self) -> usize {
            self.deletes_confirmed.load(Ordering::SeqCst)
        }
    }

    /// Canonical GKNN string of a live object.
    fn gknn_of_object(object: &DynamicObject) -> String {
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
        gknn_of(
            group,
            &kind,
            object.metadata.namespace.as_deref(),
            object.metadata.name.as_deref().unwrap_or_default(),
        )
    }

    fn gknn_of(group: &str, kind: &str, namespace: Option<&str>, name: &str) -> String {
        format!("{group}/{kind}/{}/{}", namespace.unwrap_or_default(), name)
    }

    /// The API server's `422 Invalid` rejection of an in-place update of an immutable field.
    ///
    /// The message mirrors what Kubernetes actually returns for an `immutable: true`
    /// `ConfigMap`, which is what the executor's recovery layer classifies as terminal.
    fn immutable_field_error() -> kube::Error {
        kube::Error::Api(
            serde_json::from_value::<kube::core::Status>(json!({
                "status": "Failure",
                "message": "ConfigMap \"api\" is invalid: data: Invalid value: field is immutable \
                            when `immutable` is set",
                "reason": "Invalid",
                "code": 422,
            }))
            .expect("a valid kube Status")
            .boxed(),
        )
    }

    /// The API server's `500` (a transient failure the next reconcile retries).
    fn backend_error() -> kube::Error {
        kube::Error::Api(
            serde_json::from_value::<kube::core::Status>(json!({
                "status": "Failure",
                "message": "the server is currently unable to handle the request",
                "reason": "InternalError",
                "code": 500,
            }))
            .expect("a valid kube Status")
            .boxed(),
        )
    }

    impl LiveObjectSource for FakeCluster {
        fn get<'a>(&'a self, target: FetchTarget<'a>) -> LiveFuture<'a, Option<DynamicObject>> {
            let wanted = gknn_of(
                &target.api_resource.group,
                &target.api_resource.kind,
                target.namespace,
                target.name,
            );
            let flip = self
                .ownership_flip_after_get
                .lock()
                .unwrap()
                .contains(&wanted);
            Box::pin(async move {
                let mut objects = self.objects.lock().unwrap();
                let object = objects.get(&wanted).cloned();
                if flip && let Some(mut taken) = object.clone() {
                    // Another Application takes the object over between the pass-level GET
                    // and the delete's re-check.
                    taken
                        .metadata
                        .annotations
                        .get_or_insert_with(BTreeMap::new)
                        .insert(
                            annotations::TRACKING_ID.to_owned(),
                            "ferriscd-system/hijacker:/ConfigMap:payments/removed".to_owned(),
                        );
                    objects.insert(wanted, taken);
                }
                Ok(object)
            })
        }

        fn namespace_exists<'a>(&'a self, namespace: &'a str) -> LiveFuture<'a, bool> {
            Box::pin(async move {
                Ok(self
                    .namespaces
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|existing| existing == namespace))
            })
        }
    }

    /// Applier that records the calls and never touches a cluster.
    struct FakeApplier {
        cluster: Arc<FakeCluster>,
        /// Snapshot the fake API server publishes a newly applied CRD's kind into.
        discovery: Arc<FakeDiscovery>,
        /// How the fake API server treats an applied CRD (see [`CrdMode`]).
        crd_mode: CrdMode,
    }

    impl Applier for FakeApplier {
        fn apply<'a>(
            &'a self,
            request: ApplyRequest<'a>,
        ) -> BoxFuture<'a, Result<DynamicObject, ReconcileError>> {
            let key = request.resource.key.canonical();
            let body = apply_body(&request.resource.object);
            let tracking_id = body
                .metadata
                .annotations
                .as_ref()
                .and_then(|map| map.get(annotations::TRACKING_ID))
                .cloned()
                .unwrap_or_default();
            Box::pin(async move {
                if self.cluster.fail_apply.lock().unwrap().contains(&key) {
                    return Err(ReconcileError::Invalid {
                        message: format!("applying {key} failed"),
                    });
                }
                if self.cluster.retryable_apply.lock().unwrap().contains(&key) {
                    // A transient API failure (the API server answered `500`): the pass must end in
                    // `PartialSync` so the next reconcile converges from live state.
                    return Err(ReconcileError::Apply {
                        resource: key,
                        source: backend_error(),
                    });
                }
                if self.cluster.immutable_apply.lock().unwrap().contains(&key) {
                    // The real API server rejects the SSA patch with `422 Invalid`; the executor's
                    // recovery layer (not this fake) turns it into the terminal, actionable
                    // message, which is exactly the path a terminal failure has to survive.
                    return Err(ReconcileError::Apply {
                        resource: key,
                        source: immutable_field_error(),
                    });
                }
                self.cluster.applies.lock().unwrap().push(key.clone());
                // A `CustomResourceDefinition` is established by the API server as soon as it is
                // accepted, and the aggregated discovery document then serves its kind. Modelling
                // both here is what lets the CRD+CR tests converge like a real cluster (T08.3).
                let is_crd = body.types.as_ref().is_some_and(|types| {
                    types.kind == scope::CRD_KIND
                        && types.api_version.starts_with(scope::APIEXTENSIONS_GROUP)
                });
                if is_crd {
                    let mut served = body.clone();
                    served.data["status"] = match self.crd_mode {
                        CrdMode::Establish => json!({
                            "conditions": [{ "type": "Established", "status": "True" }],
                        }),
                        CrdMode::Pending => json!({
                            "conditions": [
                                { "type": "NamesAccepted", "status": "True" },
                                { "type": "Established", "status": "False" },
                            ],
                        }),
                        CrdMode::Rejected => json!({
                            "conditions": [
                                { "type": "NamesAccepted", "status": "False" },
                                { "type": "Established", "status": "False" },
                            ],
                        }),
                    };
                    self.cluster
                        .objects
                        .lock()
                        .unwrap()
                        .insert(gknn_of_object(&served), served);
                    if self.crd_mode == CrdMode::Establish {
                        install_crd_kind(&self.discovery, &body);
                    }
                }
                self.cluster
                    .applied_objects
                    .lock()
                    .unwrap()
                    .push(body.clone());
                self.cluster
                    .applied_tracking_ids
                    .lock()
                    .unwrap()
                    .push(tracking_id);
                Ok(body)
            })
        }

        fn delete<'a>(
            &'a self,
            request: DeleteRequest<'a>,
        ) -> BoxFuture<'a, Result<DeleteOutcome, ReconcileError>> {
            let key = request.key.canonical();
            Box::pin(async move {
                self.cluster.deletes.lock().unwrap().push(key);
                self.cluster
                    .deletes_confirmed
                    .fetch_add(1, Ordering::SeqCst);
                Ok(DeleteOutcome::Deleted)
            })
        }

        /// `Api::create` semantics: a `generateName` hook gets a generated name, a named hook keeps
        /// the one it rendered, and the created object is then live (a real API server persists it).
        fn create<'a>(
            &'a self,
            request: CreateRequest<'a>,
        ) -> BoxFuture<'a, Result<DynamicObject, ReconcileError>> {
            Box::pin(async move {
                let mut body = apply_body(&request.resource.object);
                if let Some(prefix) = body.metadata.generate_name.as_deref() {
                    let mut failing = self.cluster.retryable_create.lock().unwrap();
                    if let Some(index) = failing.iter().position(|failed| failed == prefix) {
                        failing.remove(index);
                        // A transient API failure on the create: the hook step stops here, and the
                        // hooks it already created must survive the requeue (finding H-NEW).
                        return Err(ReconcileError::Api(backend_error()));
                    }
                    drop(failing);
                    let mut terminal = self.cluster.terminal_create.lock().unwrap();
                    if let Some(index) = terminal.iter().position(|failed| failed == prefix) {
                        terminal.remove(index);
                        // The API server rejects the create outright (`422`), so retrying the same
                        // commit cannot help: the pass ends in a terminal `SyncConflict` (H-A).
                        return Err(ReconcileError::Apply {
                            resource: request.resource.key.canonical(),
                            source: immutable_field_error(),
                        });
                    }
                }
                let name = match body.metadata.generate_name.as_deref() {
                    Some(prefix) => format!("{prefix}abcde"),
                    None => body.metadata.name.clone().unwrap_or_default(),
                };
                if name.is_empty() {
                    return Err(ReconcileError::Invalid {
                        message: "the fake API server rejects an unnamed object".to_owned(),
                    });
                }
                body.metadata.name = Some(name.clone());
                self.cluster.creates.lock().unwrap().push(name);
                self.cluster
                    .objects
                    .lock()
                    .unwrap()
                    .insert(gknn_of_object(&body), body.clone());
                Ok(body)
            })
        }

        fn patch_application<'a>(
            &'a self,
            request: ApplicationPatch<'a>,
        ) -> BoxFuture<'a, Result<(), ReconcileError>> {
            Box::pin(async move {
                assert_eq!(
                    request.namespace, "ferriscd-system",
                    "an Application patch must target the Application's own namespace"
                );
                self.cluster.app_patches.lock().unwrap().push(request.patch);
                Ok(())
            })
        }
    }

    /// Scripted discovery source whose snapshot the test can mutate between reconciles.
    #[derive(Default)]
    struct FakeDiscovery {
        snapshot: StdMutex<DiscoverySnapshot>,
        fetches: AtomicUsize,
        /// Discovery-outage seam (finding H-A): how many further round trips are still served
        /// before every refresh fails (`Some(0)` = failing now, `None` = never fails).
        ///
        /// A single pass polls discovery several times (render, `prepare`, the executor's post-CRD
        /// refresh, the wave-boundary refresh of `T10.2`), so "the API server goes down at *this*
        /// point of the pass" cannot be scripted as a blanket failure — that would land on the
        /// render refresh and prove nothing about the boundary.
        fail_refresh_after: StdMutex<Option<usize>>,
    }

    impl FakeDiscovery {
        fn with_cluster_kinds() -> Self {
            let mut snapshot = DiscoverySnapshot::new("v1.35.0");
            for (group, kind, scope) in [
                ("", "ConfigMap", Scope::Namespaced),
                ("", "Namespace", Scope::Cluster),
                ("", "Service", Scope::Namespaced),
                ("apps", "Deployment", Scope::Namespaced),
                // Lifecycle hooks (T10.3) are `Job`s: scope normalization has to resolve them.
                ("batch", "Job", Scope::Namespaced),
                // `T12.1` trap guard: an unauthorized cluster-scoped kind must be resolvable (so the
                // policy, not a scope lookup, is what rejects it).
                ("rbac.authorization.k8s.io", "ClusterRole", Scope::Cluster),
                (scope::APIEXTENSIONS_GROUP, scope::CRD_KIND, Scope::Cluster),
            ] {
                snapshot = with_resource(snapshot, group, kind, scope);
            }
            Self {
                snapshot: StdMutex::new(snapshot),
                fetches: AtomicUsize::new(0),
                fail_refresh_after: StdMutex::new(None),
            }
        }

        /// Simulates a `CustomResourceDefinition` becoming established.
        fn install(&self, group: &str, kind: &str, scope: Scope) {
            let mut snapshot = self.snapshot.lock().unwrap();
            *snapshot = with_resource(snapshot.clone(), group, kind, scope);
        }

        /// Arms the discovery outage: the next `successes` round trips are served as before, and
        /// every refresh after them fails (`DiscoveryError::Refresh`).
        fn fail_refresh_after(&self, successes: usize) {
            *self.fail_refresh_after.lock().unwrap() = Some(successes);
        }

        fn fetches(&self) -> usize {
            self.fetches.load(Ordering::SeqCst)
        }
    }

    /// Publishes the kind a just-applied `CustomResourceDefinition` defines.
    ///
    /// Reads the same fields the API server does (`spec.group`, `spec.names.kind`,
    /// `spec.scope`), so the fixture cannot drift from the manifest under test.
    fn install_crd_kind(discovery: &FakeDiscovery, crd: &DynamicObject) {
        let group = crd
            .data
            .pointer("/spec/group")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let kind = crd
            .data
            .pointer("/spec/names/kind")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let scope = match crd
            .data
            .pointer("/spec/scope")
            .and_then(serde_json::Value::as_str)
        {
            Some("Cluster") => Scope::Cluster,
            _ => Scope::Namespaced,
        };
        if !group.is_empty() && !kind.is_empty() {
            discovery.install(group, kind, scope);
        }
    }

    fn with_resource(
        snapshot: DiscoverySnapshot,
        group: &str,
        kind: &str,
        scope: Scope,
    ) -> DiscoverySnapshot {
        let mut resource = ApiResource::from_gvk(&KubeGvk::gvk(group, "v1", kind));
        resource.plural = format!("{}s", kind.to_ascii_lowercase());
        snapshot.with_resource(resource, capabilities(scope))
    }

    impl DiscoverySource for FakeDiscovery {
        fn fetch(&self) -> DiscoveryFuture<'_> {
            Box::pin(async move {
                self.fetches.fetch_add(1, Ordering::SeqCst);
                // Discovery outage (finding H-A): serve the scripted number of round trips, then
                // fail every refresh the way an unavailable API server does.
                let served = {
                    let mut remaining = self.fail_refresh_after.lock().unwrap();
                    match *remaining {
                        Some(0) => false,
                        Some(left) => {
                            *remaining = Some(left - 1);
                            true
                        }
                        None => true,
                    }
                };
                if !served {
                    return Err(DiscoveryError::Refresh {
                        message: "apiserver unavailable".to_owned(),
                    });
                }
                Ok(self.snapshot.lock().unwrap().clone())
            })
        }
    }

    fn capabilities(scope: Scope) -> ApiCapabilities {
        ApiCapabilities {
            scope,
            subresources: Vec::new(),
            operations: vec!["get".to_owned(), "patch".to_owned(), "delete".to_owned()],
        }
    }

    /// A discovery cache with a one-hour TTL over a scripted snapshot.
    fn cache(discovery: Arc<FakeDiscovery>) -> DiscoveryCache {
        DiscoveryCache::with_source(discovery, std::time::Duration::from_secs(3600))
    }

    fn discovery() -> DiscoveryCache {
        cache(Arc::new(FakeDiscovery::with_cluster_kinds()))
    }

    fn application(repo_url: &str, path: &str, destination_namespace: &str) -> Application {
        let spec = ApplicationSpec {
            project: ferriscd_crd::DEFAULT_PROJECT_NAME.to_owned(),
            service_account_name: None,
            source: SourceSpec {
                git: GitSourceSpec {
                    repo_url: repo_url.to_owned(),
                    target_revision: "main".to_owned(),
                    path: path.to_owned(),
                },
                renderer: RendererSpec::default(),
            },
            destination: DestinationSpec {
                cluster: IN_CLUSTER.to_owned(),
                namespace: destination_namespace.to_owned(),
            },
            // Automated self-healing is the fixture default: a first pass has no
            // `lastSyncedRevision`, so it always executes (`SourceChanged`) and applies the
            // whole desired set. Tests that care about the gate override this.
            sync_policy: Some(self_heal_policy()),
            ignore_differences: Vec::new(),
            requeue_after_seconds: DEFAULT_REQUEUE_AFTER_SECONDS,
            revision_history_limit: DEFAULT_REVISION_HISTORY_LIMIT,
        };
        let mut app = Application::new("payments", spec);
        app.metadata.namespace = Some("ferriscd-system".to_owned());
        app.metadata.generation = Some(4);
        app
    }

    /// `automated: { prune: false, selfHeal: true }`: the "drift is corrected, nothing is
    /// deleted automatically" default of the fixtures.
    fn self_heal_policy() -> SyncPolicy {
        SyncPolicy {
            automated: Some(AutomatedSyncPolicy {
                prune: false,
                self_heal: true,
            }),
            sync_options: None,
            retry: None,
        }
    }

    /// The same policy with `selfHeal: false` (source-change-only sync).
    fn source_only_policy() -> SyncPolicy {
        SyncPolicy {
            automated: Some(AutomatedSyncPolicy {
                prune: false,
                self_heal: false,
            }),
            sync_options: None,
            retry: None,
        }
    }

    fn auto_prune(app: &mut Application) {
        app.spec.sync_policy = Some(SyncPolicy {
            automated: Some(AutomatedSyncPolicy {
                prune: true,
                self_heal: true,
            }),
            sync_options: None,
            retry: None,
        });
    }

    fn config_map(name: &str, tracking_id: Option<&str>) -> DynamicObject {
        let mut annotation_map = serde_json::Map::new();
        if let Some(tracking_id) = tracking_id {
            annotation_map.insert(annotations::TRACKING_ID.to_owned(), json!(tracking_id));
        }
        serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": name,
                "namespace": "payments",
                "annotations": annotation_map,
            },
            "data": { "key": "value" },
        }))
        .unwrap()
    }

    fn status_with_inventory(keys: &[&str]) -> ApplicationStatus {
        ApplicationStatus {
            inventory: keys
                .iter()
                .map(|key| ferriscd_crd::InventoryEntry::new(*key, "v1"))
                .collect(),
            ..ApplicationStatus::default()
        }
    }

    /// Scripted `dryRun=All` source.
    ///
    /// An unscripted dry-run echoes the apply body it was handed, which is exactly "the API
    /// server accepted the body and defaulted nothing" — the case an in-sync object diffs
    /// `Synced` against. Tests script a different prediction to model API-defaulted or
    /// webhook-mutated fields.
    #[derive(Default)]
    struct FakeDryRun {
        calls: StdMutex<Vec<String>>,
        predictions: StdMutex<BTreeMap<String, DynamicObject>>,
    }

    impl FakeDryRun {
        /// Canonical keys of every dry-run this pipeline issued (prediction PATCHes are *not*
        /// mutations, so they must keep happening even when zero applies are allowed).
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl DryRunApi for FakeDryRun {
        fn dry_run<'a>(&'a self, target: DryRunTarget<'a>) -> DryRunFuture<'a> {
            let key = target.key.canonical();
            self.calls.lock().unwrap().push(key.clone());
            let echoed = apply_body(target.object);
            let predicted = self
                .predictions
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .unwrap_or(echoed);
            Box::pin(async move { Ok(DryRunOutcome::Predicted(Box::new(predicted))) })
        }
    }

    /// A hermetic pipeline: fake Git, fake discovery, fake live cluster, fake applier.
    struct Fixture {
        git: Arc<FakeGitClient>,
        cluster: Arc<FakeCluster>,
        discovery: Arc<FakeDiscovery>,
        dry_run: Arc<FakeDryRun>,
        /// Scripted `AppProject` store wired into the pipeline (`T12.1`).
        projects: Arc<FakeProjectSource>,
        /// Scripted `T12.3` identity seam (the pipeline may be wired without one).
        impersonation: Option<Arc<FakeImpersonationSource>>,
        pipeline: InventorySyncPipeline,
        repo_url: String,
        _temp: tempfile::TempDir,
    }

    /// The shipped `default` `AppProject` (`deploy/manifests/default-project.yaml`).
    ///
    /// Using the real manifest keeps the fixtures honest: every pre-existing sync test now runs
    /// through the *actual* single-tenant default project, so the manifest cannot drift away from
    /// what the policy enforcer accepts.
    const DEFAULT_PROJECT_MANIFEST: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/manifests/default-project.yaml"
    ));

    /// A project that permits any repository and only the `payments` destination, with a narrow
    /// cluster-scoped allow-list (no `ClusterRole`, no `ClusterRoleBinding`).
    fn payments_only_project(name: &str) -> AppProject {
        serde_saphyr::from_str(&format!(
            r#"
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: {name}
  namespace: ferriscd-system
spec:
  sourceRepos:
    - "*"
  sourceNamespaces:
    - ferriscd-system
    - team-a
  destinations:
    - cluster: in-cluster
      namespace: payments
  clusterResourceWhitelist:
    - group: apiextensions.k8s.io
      kind: CustomResourceDefinition
    - group: ""
      kind: Namespace
  namespaceResourceWhitelist:
    - group: "*"
      kind: "*"
"#
        ))
        .expect("test project must parse")
    }

    /// Scripted `AppProject` store: the `T12.1` fetch seam, without an API server.
    #[derive(Default)]
    struct FakeProjectSource {
        projects: StdMutex<BTreeMap<String, AppProject>>,
        /// Project names the pipeline looked up, in order.
        reads: StdMutex<Vec<String>>,
    }

    impl FakeProjectSource {
        fn with_project(self, project: AppProject) -> Self {
            let name = project.name_any();
            self.projects.lock().unwrap().insert(name, project);
            self
        }

        fn reads(&self) -> Vec<String> {
            self.reads.lock().unwrap().clone()
        }
    }

    impl ProjectSource for FakeProjectSource {
        fn get<'a>(
            &'a self,
            name: &'a str,
        ) -> BoxFuture<'a, Result<Option<AppProject>, ReconcileError>> {
            self.reads.lock().unwrap().push(name.to_owned());
            let project = self.projects.lock().unwrap().get(name).cloned();
            Box::pin(async move { Ok(project) })
        }
    }

    /// Scripted `T12.3` seam: resolves an impersonated identity onto the **same** fake cluster.
    ///
    /// The pass therefore behaves exactly as it would with the real pool — same live objects, same
    /// applies, same dry-runs — while the identity it resolved is observable, which is what the
    /// tests assert (and what proves the resolution order: policy first, identity second).
    struct FakeImpersonationSource {
        applier: Arc<dyn Applier>,
        live: Arc<dyn LiveObjectSource>,
        /// The impersonated identity's own dry-run recorder (see `build_fixture`).
        dry_run: Arc<FakeDryRun>,
        /// Impersonated users the pipeline resolved, in order.
        identities: StdMutex<Vec<String>>,
    }

    impl FakeImpersonationSource {
        fn identities(&self) -> Vec<String> {
            self.identities.lock().unwrap().clone()
        }

        fn dry_runs(&self) -> usize {
            self.dry_run.calls().len()
        }
    }

    impl ImpersonationSource for FakeImpersonationSource {
        fn access_for(
            &self,
            impersonation: &Impersonation,
        ) -> Result<ClusterAccess, ReconcileError> {
            self.identities
                .lock()
                .unwrap()
                .push(impersonation.user().to_owned());
            Ok(ClusterAccess::new(
                ClusterIdentity::ServiceAccount(impersonation.clone()),
                self.applier.clone(),
                self.live.clone(),
                self.dry_run.clone() as Arc<dyn DryRunApi>,
            ))
        }
    }

    /// Scripted [`CredentialSource`] (`T12.4`): answers per repository URL, records every lookup.
    ///
    /// The real store reads Kubernetes `Secret`s, which a hermetic test cannot do; this double
    /// proves the *seam* — that `fetch_desired` asks it for the `Application`'s URL, hands the
    /// answer to the Git client, and turns an unusable `Secret` into a terminal error instead of a
    /// silent anonymous clone.
    struct FakeCredentialSource {
        /// Credentials returned for a matching URL key.
        entries: BTreeMap<String, RepoCredentials>,
        /// Credentials returned when no key matches (default: anonymous).
        fallback: RepoCredentials,
        /// When set, every lookup fails with this malformed-`Secret` reason.
        malformed: Option<&'static str>,
        /// Repository URLs looked up, in call order.
        lookups: StdMutex<Vec<String>>,
    }

    impl Default for FakeCredentialSource {
        fn default() -> Self {
            Self {
                entries: BTreeMap::new(),
                fallback: RepoCredentials::Anonymous,
                malformed: None,
                lookups: StdMutex::new(Vec::new()),
            }
        }
    }

    impl FakeCredentialSource {
        /// A source answering `credentials` for every URL.
        fn returning(credentials: RepoCredentials) -> Self {
            Self {
                fallback: credentials,
                ..Self::default()
            }
        }

        /// A source whose every lookup fails like an unusable `Secret` does.
        fn malformed(reason: &'static str) -> Self {
            Self {
                malformed: Some(reason),
                ..Self::default()
            }
        }

        /// Repository URLs this source was asked about, in call order.
        fn lookups(&self) -> Vec<String> {
            self.lookups.lock().unwrap().clone()
        }
    }

    impl CredentialSource for FakeCredentialSource {
        fn credentials_for<'a>(
            &'a self,
            repo_url: &'a str,
        ) -> BoxFuture<'a, Result<RepoCredentials, ReconcileError>> {
            Box::pin(async move {
                self.lookups.lock().unwrap().push(repo_url.to_owned());
                if let Some(reason) = self.malformed {
                    return Err(ReconcileError::Credentials(CredentialError::Malformed {
                        secret: "repo-creds".to_owned(),
                        namespace: "ferriscd-system".to_owned(),
                        reason: reason.to_owned(),
                    }));
                }
                Ok(self
                    .entries
                    .get(repo_url)
                    .cloned()
                    .unwrap_or_else(|| self.fallback.clone()))
            })
        }
    }

    /// Scripted `T13.1` registry: answers registered targets and records every lookup.
    ///
    /// The lookup recorder is what proves the **order** of the pass: the `AppProject` policy is
    /// enforced before the registry is consulted, so a tenant can never probe cluster names its
    /// project does not list.
    #[derive(Default)]
    struct FakeClusterSource {
        targets: StdMutex<BTreeMap<String, ClusterTarget>>,
        lookups: StdMutex<Vec<String>>,
    }

    impl FakeClusterSource {
        fn with_target(self, name: &str, target: ClusterTarget) -> Self {
            self.targets.lock().unwrap().insert(name.to_owned(), target);
            self
        }

        fn lookups(&self) -> Vec<String> {
            self.lookups.lock().unwrap().clone()
        }
    }

    impl ClusterSource for FakeClusterSource {
        fn target(&self, name: &str) -> Result<ClusterTarget, ReconcileError> {
            self.lookups.lock().unwrap().push(name.to_owned());
            self.targets
                .lock()
                .unwrap()
                .get(name)
                .cloned()
                .ok_or_else(|| {
                    ReconcileError::Cluster(ClusterError::NotFound {
                        cluster: name.to_owned(),
                        namespace: "ferriscd-system".to_owned(),
                    })
                })
        }
    }

    /// The seams a registered remote cluster contributes, over a scripted cluster.
    ///
    /// Deliberately a **different** [`FakeCluster`] (and a different [`FakeDiscovery`]) from the
    /// control plane's, so "the pass really used the remote client" is observable instead of being
    /// indistinguishable from `in-cluster`.
    fn remote_target(
        name: &str,
        cluster: Arc<FakeCluster>,
        discovery: Arc<FakeDiscovery>,
    ) -> ClusterTarget {
        remote_target_with_impersonation(name, cluster, discovery, None)
    }

    /// The same seams, with the remote cluster's own impersonation pool (`T13.1` + `T12.3`).
    fn remote_target_with_impersonation(
        name: &str,
        cluster: Arc<FakeCluster>,
        discovery: Arc<FakeDiscovery>,
        impersonation: Option<Arc<dyn ImpersonationSource>>,
    ) -> ClusterTarget {
        let applier: Arc<dyn Applier> = Arc::new(FakeApplier {
            cluster: cluster.clone(),
            discovery: discovery.clone(),
            crd_mode: CrdMode::Establish,
        });
        let live: Arc<dyn LiveObjectSource> = cluster;
        ClusterTarget::new(
            name,
            cache(discovery),
            ClusterAccess::new(
                ClusterIdentity::Controller,
                applier,
                live,
                Arc::new(FakeDryRun::default()),
            ),
            impersonation,
        )
    }

    /// A project that authorizes the remote `prod` cluster and nothing else.
    fn remote_project() -> AppProject {
        serde_saphyr::from_str(
            r#"
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: default
  namespace: ferriscd-system
spec:
  sourceRepos:
    - "*"
  sourceNamespaces:
    - ferriscd-system
  destinations:
    - cluster: prod
      namespace: payments
  clusterResourceWhitelist:
    - group: ""
      kind: Namespace
  namespaceResourceWhitelist:
    - group: "*"
      kind: "*"
"#,
        )
        .expect("the remote project must parse")
    }

    /// [`remote_project`] plus the ServiceAccount a remote tenant `Application` impersonates.
    fn remote_project_with_service_account() -> AppProject {
        serde_saphyr::from_str(
            r#"
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: default
  namespace: ferriscd-system
spec:
  sourceRepos:
    - "*"
  sourceNamespaces:
    - ferriscd-system
  destinations:
    - cluster: prod
      namespace: payments
  clusterResourceWhitelist:
    - group: ""
      kind: Namespace
  namespaceResourceWhitelist:
    - group: "*"
      kind: "*"
  allowedServiceAccounts:
    - payments/deployer
"#,
        )
        .expect("the remote project with a ServiceAccount must parse")
    }

    /// Whether a fixture wires the `T12.3` impersonation seam.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ImpersonationWiring {
        /// Production wiring: an `Application` that names a ServiceAccount is impersonated.
        Wired,
        /// A pipeline with no pool: an `Application` that asks for impersonation must be refused.
        NotWired,
    }

    fn default_project_source() -> FakeProjectSource {
        let project: AppProject =
            serde_saphyr::from_str(DEFAULT_PROJECT_MANIFEST).expect("default project must parse");
        FakeProjectSource::default().with_project(project)
    }

    /// A parseable `metav1.Time` fixture.
    fn at(rfc3339: &str) -> k8s_openapi::apimachinery::pkg::apis::meta::v1::Time {
        k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
            rfc3339.parse().expect("valid RFC 3339 timestamp"),
        )
    }

    fn fixture(cluster: FakeCluster) -> Fixture {
        fixture_with(cluster, FakeDryRun::default())
    }

    fn fixture_with(cluster: FakeCluster, dry_run: FakeDryRun) -> Fixture {
        build_fixture(
            cluster,
            dry_run,
            RendererBinaries::default(),
            default_project_source(),
            None,
            ImpersonationWiring::Wired,
            None,
            None,
        )
    }

    /// A fixture whose render pipeline executes `binaries` instead of the real tools.
    fn fixture_with_renderers(cluster: FakeCluster, binaries: RendererBinaries) -> Fixture {
        build_fixture(
            cluster,
            FakeDryRun::default(),
            binaries,
            default_project_source(),
            None,
            ImpersonationWiring::Wired,
            None,
            None,
        )
    }

    /// A fixture whose pipeline enforces `projects` and `scope` (`T12.1`/`T12.2`) and wires the
    /// impersonation seam (`T12.3`), like the production controller does.
    fn fixture_with_policy(
        cluster: FakeCluster,
        projects: FakeProjectSource,
        scope: ApplicationScope,
    ) -> Fixture {
        fixture_with_policy_and_impersonation(cluster, projects, scope, ImpersonationWiring::Wired)
    }

    /// The same fixture with an explicit impersonation wiring.
    fn fixture_with_policy_and_impersonation(
        cluster: FakeCluster,
        projects: FakeProjectSource,
        scope: ApplicationScope,
        wiring: ImpersonationWiring,
    ) -> Fixture {
        build_fixture(
            cluster,
            FakeDryRun::default(),
            RendererBinaries::default(),
            projects,
            Some(scope),
            wiring,
            None,
            None,
        )
    }

    /// A fixture whose pipeline resolves Git credentials through `source` (`T12.4`).
    fn fixture_with_credentials(
        cluster: FakeCluster,
        source: Arc<FakeCredentialSource>,
    ) -> Fixture {
        build_fixture(
            cluster,
            FakeDryRun::default(),
            RendererBinaries::default(),
            default_project_source(),
            None,
            ImpersonationWiring::Wired,
            Some(source as Arc<dyn CredentialSource>),
            None,
        )
    }

    /// A fixture whose pipeline resolves remote clusters through `source` (`T13.1`).
    fn fixture_with_clusters(
        cluster: FakeCluster,
        projects: FakeProjectSource,
        source: Arc<FakeClusterSource>,
    ) -> Fixture {
        build_fixture(
            cluster,
            FakeDryRun::default(),
            RendererBinaries::default(),
            projects,
            None,
            ImpersonationWiring::Wired,
            None,
            Some(source as Arc<dyn ClusterSource>),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_fixture(
        cluster: FakeCluster,
        dry_run: FakeDryRun,
        binaries: RendererBinaries,
        projects: FakeProjectSource,
        scope: Option<ApplicationScope>,
        wiring: ImpersonationWiring,
        credentials: Option<Arc<dyn CredentialSource>>,
        clusters: Option<Arc<dyn ClusterSource>>,
    ) -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let git = Arc::new(FakeGitClient::with_config(FakeGitClientConfig {
            url_policy: RepoUrlPolicy::AllowLocal,
            work_root: Some(temp.path().join("work")),
        }));
        let cluster = Arc::new(cluster);
        let discovery = Arc::new(FakeDiscovery::with_cluster_kinds());
        let dry_run = Arc::new(dry_run);
        let projects = Arc::new(projects);
        let repos = Arc::new(RepoCache::new(
            git.clone(),
            RepoCacheConfig::new(temp.path().join("cache")),
        ));
        let applier: Arc<dyn Applier> = Arc::new(FakeApplier {
            cluster: cluster.clone(),
            discovery: discovery.clone(),
            crd_mode: cluster.crd_mode,
        });
        let live: Arc<dyn LiveObjectSource> = cluster.clone();
        let impersonation = (wiring == ImpersonationWiring::Wired).then(|| {
            Arc::new(FakeImpersonationSource {
                applier: applier.clone(),
                live: live.clone(),
                // A *separate* recorder, so "the `dryRun=All` diff ran as the impersonated
                // identity" is observable instead of indistinguishable from the controller's.
                dry_run: Arc::new(FakeDryRun::default()),
                identities: StdMutex::new(Vec::new()),
            })
        });
        let pipeline = InventorySyncPipeline::new(
            repos,
            cache(discovery.clone()),
            live,
            applier,
            dry_run.clone(),
        )
        .with_url_policy(RepoUrlPolicy::AllowLocal)
        .with_renderer_binaries(binaries)
        // `T12.1`: policy is enforced on every pass, so the fixture wires the real `default`
        // project. Tests that need a narrower or missing project replace the store.
        .with_project_source(projects.clone())
        // Hermetic: a scripted cluster never needs a bounded wait, and `without_waits` keeps the
        // suite free of timing sleeps.
        .with_execution_policy(ExecutionPolicy::without_waits());
        let pipeline = match scope {
            Some(scope) => pipeline.with_application_scope(scope),
            None => pipeline,
        };
        // `T12.3`: the production controller always wires a pool, so the fixtures do too unless a
        // test is specifically about a pipeline that cannot impersonate.
        let pipeline = match &impersonation {
            Some(source) => pipeline.with_impersonation_source(source.clone()),
            None => pipeline,
        };
        // `T12.4`: the production controller always wires a credential store, so a fixture that
        // cares about credentials does too; the rest keep the anonymous default on purpose.
        let pipeline = match &credentials {
            Some(source) => pipeline.with_credential_source(source.clone()),
            None => pipeline,
        };
        // `T13.1`: the production controller always wires the registry, so a fixture that cares
        // about remote clusters does too; the rest keep `in-cluster` only.
        let pipeline = match &clusters {
            Some(source) => pipeline.with_cluster_source(source.clone()),
            None => pipeline,
        };
        let repo_url = temp.path().join("repo.git").display().to_string();
        Fixture {
            git,
            cluster,
            discovery,
            dry_run,
            projects,
            impersonation,
            pipeline,
            repo_url,
            _temp: temp,
        }
    }

    /// Returns `fixture` with the `T15.1` recorder wired into its pipeline.
    ///
    /// `InventorySyncPipeline::with_metrics` consumes the pipeline (it owns the render cache and the
    /// applier, so it is deliberately not `Clone`), so the fixture is taken apart and put back
    /// together instead of being mutated in place.
    fn with_metrics(fixture: Fixture, metrics: &crate::metrics::Metrics) -> Fixture {
        Fixture {
            pipeline: fixture.pipeline.with_metrics(metrics.clone()),
            git: fixture.git,
            cluster: fixture.cluster,
            discovery: fixture.discovery,
            dry_run: fixture.dry_run,
            projects: fixture.projects,
            impersonation: fixture.impersonation,
            repo_url: fixture.repo_url,
            _temp: fixture._temp,
        }
    }

    impl Fixture {
        /// Impersonated users the pipeline resolved, in order (`T12.3`).
        fn identities(&self) -> Vec<String> {
            self.impersonation
                .as_ref()
                .map(|source| source.identities())
                .unwrap_or_default()
        }

        /// `dryRun=All` predictions the impersonated identity issued.
        fn impersonated_dry_runs(&self) -> usize {
            self.impersonation
                .as_ref()
                .map(|source| source.dry_runs())
                .unwrap_or_default()
        }

        fn commit(&self, files: &[(&str, &str)]) -> String {
            self.git.add_commit("main", files.iter().copied())
        }

        fn app(&self, path: &str) -> Application {
            application(&self.repo_url, path, "payments")
        }
    }

    /// A fake `kustomize`/`helm` binary: a POSIX shell script that records its invocations and
    /// prints `stdout`.
    ///
    /// `make gate` must stay hermetic (no `kustomize`/`helm` on `PATH` required), so the controller
    /// tests that render through the CR point the pipeline at one of these.
    #[cfg(unix)]
    struct FakeRenderer {
        dir: tempfile::TempDir,
        path: std::path::PathBuf,
    }

    impl FakeRenderer {
        fn new(name: &str, stdout: &str) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(name);
            let script = format!(
                "#!/bin/sh\n\
                 printf 'x\\n' >> \"$(dirname \"$0\")/invocations\"\n\
                 {{ printf '%s\\n' \"$@\"; printf -- '---\\n'; }} >> \"$(dirname \"$0\")/args\"\n\
                 cat <<'FERRISCD_FAKE_STDOUT'\n{stdout}\nFERRISCD_FAKE_STDOUT\n"
            );
            std::fs::write(&path, script).unwrap();
            make_executable(&path);
            Self { dir, path }
        }

        fn path(&self) -> &std::path::Path {
            &self.path
        }

        fn invocations(&self) -> usize {
            match std::fs::read_to_string(self.dir.path().join("invocations")) {
                Ok(contents) => contents.lines().filter(|line| !line.is_empty()).count(),
                Err(_) => 0,
            }
        }

        fn recorded_args(&self) -> Vec<String> {
            match std::fs::read_to_string(self.dir.path().join("args")) {
                Ok(contents) => contents
                    .lines()
                    .filter(|line| !line.is_empty() && *line != "---")
                    .map(str::to_owned)
                    .collect(),
                Err(_) => Vec::new(),
            }
        }
    }

    #[cfg(unix)]
    fn make_executable(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    const CONFIGMAP: &str = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\n";
    /// A `generateName` `PreSync` hook — the one legitimate `generateName` user (`T10.3`).
    const PRE_SYNC_HOOK: &str = "apiVersion: batch/v1\nkind: Job\nmetadata:\n  generateName: migrate-\n  annotations:\n    ferriscd.io/hook: PreSync\n";
    /// A second `generateName` `PreSync` hook that runs *before* [`PRE_SYNC_HOOK`] (wave `-1`), so a
    /// failure on the second create still has a hook object that already exists.
    const SEED_PRE_SYNC_HOOK: &str = "apiVersion: batch/v1\nkind: Job\nmetadata:\n  generateName: seed-\n  annotations:\n    ferriscd.io/hook: PreSync\n    ferriscd.io/sync-wave: \"-1\"\n";
    /// The same ConfigMap with a `data` field, for the `ignoreDifferences` tests.
    const CONFIGMAP_WITH_DATA: &str =
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\ndata:\n  key: value\n";
    const DEPLOYMENT: &str =
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\nspec:\n  replicas: 1\n";

    /// Stand-in for `status.sync.lastSyncedSpecHash` in outcomes built by hand: only its
    /// presence and round-trip matter, never the digest itself (the real value comes from
    /// `source_spec_hash`, which is pinned by its own engine tests).
    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// Canonical GKNN keys of the two fixture resources.
    const CONFIGMAP_KEY: &str = "/ConfigMap/payments/settings";
    const DEPLOYMENT_KEY: &str = "apps/Deployment/payments/api";

    // ---------------------------------------------------------------------
    // Happy path
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn applies_the_desired_set_and_records_the_inventory_and_revision() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        let sha = fixture.commit(&[
            ("configmap.yaml", CONFIGMAP),
            ("deployment.yaml", DEPLOYMENT),
        ]);
        let app = fixture.app(".");

        let outcome = fixture
            .pipeline
            .apply(&app)
            .await
            .expect("apply must succeed");

        assert_eq!(
            fixture.cluster.applies(),
            vec![
                "/ConfigMap/payments/settings".to_owned(),
                "apps/Deployment/payments/api".to_owned(),
            ],
            "resources must be applied in tier order, deterministically"
        );
        let inventory = outcome
            .inventory
            .as_ref()
            .expect("inventory must be reported");
        assert_eq!(inventory.len(), 2);
        assert_eq!(
            inventory
                .get(&ResourceKey::new(
                    "",
                    "ConfigMap",
                    Some("payments".to_owned()),
                    "settings"
                ))
                .map(|entry| entry.version.as_str()),
            Some("v1"),
            "the version hint is stored but never part of the key"
        );

        let sync = outcome.sync.as_ref().expect("sync state must be reported");
        assert_eq!(sync.status, SyncStatus::Synced);
        assert_eq!(sync.revision.as_deref(), Some(sha.as_str()));
        assert_eq!(sync.last_synced_revision.as_deref(), Some(sha.as_str()));
        assert!(sync.last_synced_at.is_some());
        assert_eq!(
            sync.last_synced_spec_hash.as_deref(),
            Some(source_spec_hash(&app.spec).expect("spec hash").as_str()),
            "finding H7: a successful sync persists the spec hash alongside the revision"
        );
        assert_eq!(outcome.reason, REASON_SYNC_SUCCEEDED);
        // T09.5: the pass applied both resources, so the live read that predates the write saw
        // nothing: the `Application` is `Synced` (Git matches) but not yet `Healthy` (the API
        // server has not reported the new objects), and the controller polls fast until it is.
        assert_eq!(
            outcome.health.as_ref().map(|health| health.status),
            Some(HealthStatus::Progressing),
            "a just-applied resource has not been observed yet"
        );
        assert_eq!(outcome.requeue, Some(PROGRESSING_REQUEUE));
    }

    #[tokio::test]
    async fn every_applied_object_is_stamped_with_the_tracking_id() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);
        let app = fixture.app(".");

        fixture
            .pipeline
            .apply(&app)
            .await
            .expect("apply must succeed");

        assert_eq!(
            fixture.cluster.applied_tracking_ids(),
            vec!["ferriscd-system/payments:/ConfigMap:payments/settings".to_owned()],
            "the applied body must carry the ownership marker"
        );
    }

    #[tokio::test]
    async fn a_new_commit_triggers_a_new_revision_and_a_wider_inventory() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        let first = fixture.commit(&[("configmap.yaml", CONFIGMAP)]);
        let app = fixture.app(".");
        let outcome = fixture.pipeline.apply(&app).await.expect("first apply");
        assert_eq!(
            outcome.sync.as_ref().unwrap().revision.as_deref(),
            Some(first.as_str())
        );

        let second = fixture.commit(&[
            ("configmap.yaml", CONFIGMAP),
            (
                "extra.yaml",
                "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: extra\n",
            ),
        ]);
        assert_ne!(first, second, "the fixture commits must differ");

        let outcome = fixture.pipeline.apply(&app).await.expect("second apply");
        assert_eq!(
            outcome.sync.as_ref().unwrap().revision.as_deref(),
            Some(second.as_str())
        );
        assert_eq!(outcome.inventory.unwrap().len(), 2);
    }

    // ---------------------------------------------------------------------
    // Trap guards
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn a_foreign_tracking_id_is_rejected_before_any_mutation() {
        let foreign = config_map(
            "settings",
            Some("ferriscd-system/other:/ConfigMap:payments/settings"),
        );
        let fixture = fixture(
            FakeCluster::default()
                .with_namespace("payments")
                .with_object(foreign),
        );
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);
        let app = fixture.app(".");

        let err = fixture
            .pipeline
            .apply(&app)
            .await
            .expect_err("a foreign resource must be rejected");

        assert!(
            fixture.cluster.applies().is_empty(),
            "nothing may be applied once a foreign owner is detected"
        );
        assert!(fixture.cluster.deletes().is_empty());
        let message = err.to_string();
        assert!(
            message.contains("/ConfigMap/payments/settings"),
            "{message}"
        );
        assert!(message.contains("ferriscd-system/other"), "{message}");
        assert!(message.contains("another Application"), "{message}");
    }

    #[tokio::test]
    async fn an_unmanaged_resource_is_applied_and_keeps_ssa_conflict_semantics() {
        let fixture = fixture(
            FakeCluster::default()
                .with_namespace("payments")
                .with_object(config_map("settings", None)),
        );
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);
        let app = fixture.app(".");

        let outcome = fixture
            .pipeline
            .apply(&app)
            .await
            .expect("an unmanaged object is applied; SSA reports real field conflicts");
        assert_eq!(
            fixture.cluster.applies(),
            vec!["/ConfigMap/payments/settings".to_owned()]
        );
        assert_eq!(outcome.inventory.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_failed_apply_persists_the_partial_inventory() {
        let fixture = fixture(
            FakeCluster::default()
                .with_namespace("payments")
                .fail_apply_for("apps/Deployment/payments/api"),
        );
        fixture.commit(&[
            ("configmap.yaml", CONFIGMAP),
            ("deployment.yaml", DEPLOYMENT),
        ]);
        let app = fixture.app(".");

        let err = fixture.pipeline.apply(&app).await.expect_err("apply fails");
        let (inventory, revision) = err
            .partial_status()
            .expect("a partial sync must report the inventory it already owns");
        assert_eq!(
            inventory.len(),
            1,
            "the ConfigMap applied before the failure must stay tracked (C1)"
        );
        assert_eq!(inventory.keys().next().unwrap().kind, "ConfigMap");
        assert!(
            revision.is_some(),
            "the attempted revision must be recorded"
        );
    }

    /// **Finding M2:** a *terminal* apply failure — the API server's `422` for an immutable field
    /// without `ferriscd.io/sync-options: Replace=true` — must surface as
    /// [`ReconcileError::SyncConflict`], never [`ReconcileError::PartialSync`]. The two carry a
    /// different [`crate::FailureClass`] downstream (terminal backoff vs retry), so a silent
    /// downgrade would turn a permanent policy failure into a livelock, and the inventory that is
    /// already true must still travel with it (finding C1).
    #[tokio::test]
    async fn an_immutable_field_failure_is_a_sync_conflict_not_a_partial_sync() {
        let fixture = fixture(
            FakeCluster::default()
                .with_namespace("payments")
                .fail_apply_as_immutable("apps/Deployment/payments/api"),
        );
        fixture.commit(&[
            ("configmap.yaml", CONFIGMAP),
            ("deployment.yaml", DEPLOYMENT),
        ]);
        let app = fixture.app(".");

        let err = fixture.pipeline.apply(&app).await.expect_err("apply fails");

        assert!(
            matches!(err, ReconcileError::SyncConflict { .. }),
            "an immutable field without Replace=true is terminal, so it must be a \
             SyncConflict and not a PartialSync: {err:?}"
        );
        assert_eq!(err.failure_class(), crate::FailureClass::Terminal);
        let message = err.to_string();
        assert!(message.contains("immutable"), "{message}");
        assert!(
            message.contains("Replace=true"),
            "the failure must name the opt-in: {message}"
        );
        let (inventory, revision) = err
            .partial_status()
            .expect("a SyncConflict still reports the inventory it already owns");
        assert_eq!(
            inventory.len(),
            1,
            "the ConfigMap applied before the failure must stay tracked (C1)"
        );
        assert_eq!(inventory.keys().next().unwrap().kind, "ConfigMap");
        assert!(revision.is_some());
    }

    // ---------------------------------------------------------------------
    // Deferred states
    // ---------------------------------------------------------------------

    const CRD_MANIFEST: &str = "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: widgets.example.com\nspec:\n  group: example.com\n  names:\n    kind: Widget\n    plural: widgets\n  scope: Namespaced\n  versions:\n    - name: v1\n      served: true\n      storage: true\n      schema:\n        openAPIV3Schema:\n          type: object\n";
    const WIDGET_MANIFEST: &str =
        "apiVersion: example.com/v1\nkind: Widget\nmetadata:\n  name: one\n";

    /// **Verification (T08.3, trap T6):** a brand-new CRD and its CR in one commit land on the
    /// **first** sync: the CRD is applied, polled for `Established`, discovery is refreshed, and
    /// only then is the custom resource resolved and applied.
    #[tokio::test]
    async fn a_crd_and_its_custom_resource_are_applied_in_one_pass() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[("crd.yaml", CRD_MANIFEST), ("widget.yaml", WIDGET_MANIFEST)]);
        let app = fixture.app(".");
        let fetches_before = fixture.discovery.fetches();

        let outcome = fixture
            .pipeline
            .apply(&app)
            .await
            .expect("a brand-new CRD plus its CR must sync on the first pass");

        assert_eq!(
            fixture.cluster.applies(),
            vec![
                "apiextensions.k8s.io/CustomResourceDefinition//widgets.example.com".to_owned(),
                "example.com/Widget/payments/one".to_owned(),
            ],
            "the CRD must be applied before its custom resource (trap T6)"
        );
        assert!(
            fixture.discovery.fetches() > fetches_before,
            "the executor must refresh discovery after the CRD is established"
        );
        assert_eq!(outcome.reason, REASON_SYNC_SUCCEEDED, "{}", outcome.message);
        let inventory = outcome.inventory.expect("inventory is always reported");
        assert!(
            inventory.keys().any(|key| key.kind == "Widget"),
            "the custom resource that applied must be tracked"
        );
    }

    /// **Trap guard (T08.3):** when the CRD never establishes, the pass requeues and the custom
    /// resource is never applied against a kind the API server does not serve.
    #[tokio::test]
    async fn an_unestablished_crd_defers_the_custom_resource_and_requeues() {
        let fixture = fixture(
            FakeCluster::default()
                .with_namespace("payments")
                .with_unestablished_crds(),
        );
        fixture.commit(&[("crd.yaml", CRD_MANIFEST), ("widget.yaml", WIDGET_MANIFEST)]);
        let app = fixture.app(".");

        let outcome = fixture
            .pipeline
            .apply(&app)
            .await
            .expect("a pending CRD is not an error");
        assert_eq!(outcome.reason, REASON_PENDING);
        assert_eq!(outcome.requeue, Some(PENDING_REQUEUE));
        let sync = outcome.sync.unwrap();
        assert_eq!(sync.status, SyncStatus::OutOfSync);
        assert!(
            sync.last_synced_revision.is_none(),
            "a deferred resource means the revision is not fully synced"
        );
        assert_eq!(
            fixture.cluster.applies(),
            vec!["apiextensions.k8s.io/CustomResourceDefinition//widgets.example.com".to_owned()],
            "the CRD applies now; the CR waits for the follow-up reconcile"
        );
        let inventory = outcome.inventory.expect("inventory is always reported");
        assert!(
            !inventory.keys().any(|key| key.kind == "Widget"),
            "the deferred CR must not be recorded as applied"
        );
    }

    /// **Trap guard (H5):** a CRD the API server rejects (`NamesAccepted=False`) fails with an
    /// actionable message instead of requeueing forever.
    #[tokio::test]
    async fn a_rejected_crd_fails_instead_of_requeueing() {
        let fixture = fixture(
            FakeCluster::default()
                .with_namespace("payments")
                .with_rejected_crds(),
        );
        fixture.commit(&[("crd.yaml", CRD_MANIFEST), ("widget.yaml", WIDGET_MANIFEST)]);
        let app = fixture.app(".");

        let err = fixture
            .pipeline
            .apply(&app)
            .await
            .expect_err("a rejected CRD must not be reported as pending");
        assert_eq!(
            err.failure_class(),
            crate::FailureClass::Terminal,
            "a rejected definition can never be fixed by retrying: {err}"
        );
        let message = err.to_string();
        assert!(message.contains("NamesAccepted"), "{message}");
        assert!(
            message.contains("widgets.example.com"),
            "the message must name the CRD: {message}"
        );
        assert!(
            !fixture
                .cluster
                .applies()
                .iter()
                .any(|applied| applied.contains("Widget")),
            "the custom resource must never be applied"
        );
    }

    /// A bundle that defines CRDs forces a discovery refresh instead of trusting the TTL, and the
    /// second pass is a no-op (nothing is re-applied).
    #[tokio::test]
    async fn a_crd_bundle_forces_a_discovery_refresh_and_settles() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[("crd.yaml", CRD_MANIFEST), ("widget.yaml", WIDGET_MANIFEST)]);
        let app = fixture.app(".");
        let fetches_before = fixture.discovery.fetches();
        fixture.pipeline.apply(&app).await.expect("first pass");
        assert!(
            fixture.discovery.fetches() > fetches_before,
            "a bundle that defines CRDs must force a discovery refresh"
        );

        // The second pass sees both objects live and synced: zero mutating applies.
        fixture.cluster.seed_applied();
        let applies_before = fixture.cluster.applies().len();
        let second = fixture.pipeline.apply(&app).await.expect("second pass");
        assert_eq!(
            fixture.cluster.applies().len(),
            applies_before,
            "an already-synced CRD + CR must not be re-applied: {:?}",
            fixture.cluster.applies()
        );
        assert_eq!(second.reason, REASON_SYNC_SUCCEEDED, "{}", second.message);
        assert!(
            second.message.contains("applied 0 of 2"),
            "both the CRD and its CR are already synced: {}",
            second.message
        );
    }

    #[tokio::test]
    async fn a_pending_namespace_defers_the_namespaced_resource() {
        // The bundle declares the `Namespace` but it is not live yet: nothing may be applied
        // into a namespace that does not exist, and `DeferredPendingNamespace` is the only
        // state that expresses "wait for the next pass".
        let fixture = fixture(FakeCluster::default());
        fixture.commit(&[
            (
                "namespace.yaml",
                "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: payments\n",
            ),
            ("configmap.yaml", CONFIGMAP),
        ]);
        let app = fixture.app(".");

        let outcome = fixture
            .pipeline
            .apply(&app)
            .await
            .expect("apply must not fail");
        assert_eq!(outcome.reason, REASON_PENDING);
        assert_eq!(outcome.requeue, Some(PENDING_REQUEUE));
        assert_eq!(
            fixture.cluster.applies(),
            vec!["/Namespace//payments".to_owned()],
            "the Namespace applies now; the ConfigMap waits for the follow-up reconcile"
        );
    }

    /// The `DeferredPendingNamespace` wait costs exactly **one** extra pass, unconditionally.
    ///
    /// The executor never resolves a `Skip(Deferred)` step in-pass, whatever else the pass did: a
    /// deferred key is always reported pending and left for the next reconcile. Only a
    /// `Namespace` this bundle declares can defer a key (the plan is handed exactly the
    /// `DeferredPendingNamespace` keys), and that namespace exists only after the pass that
    /// applies it, so pass 1 applies the `Namespace`, the requeue brings the `ConfigMap`, and
    /// nothing is ever applied into a namespace that does not exist yet.
    #[tokio::test]
    async fn a_namespace_deferral_costs_exactly_one_extra_pass() {
        let fixture = fixture(FakeCluster::default());
        fixture.commit(&[
            (
                "namespace.yaml",
                "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: payments\n",
            ),
            ("configmap.yaml", CONFIGMAP),
        ]);
        let mut app = fixture.app(".");

        let (err, status) = reconcile_pass(&fixture, &mut app).await;
        assert!(
            err.is_none(),
            "a pending namespace is not an error: {err:?}"
        );
        assert_eq!(ready(&status).reason, REASON_PENDING);
        assert_eq!(
            fixture.cluster.applies(),
            vec!["/Namespace//payments".to_owned()],
            "nothing may be applied into a namespace that does not exist yet"
        );

        // The namespace the first pass applied exists now: the requeued pass completes the sync.
        fixture.cluster.seed_namespace("payments");
        let (err, status) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_none(), "{err:?}");
        assert_eq!(
            fixture.cluster.applies(),
            vec!["/Namespace//payments".to_owned(), CONFIGMAP_KEY.to_owned()],
            "the extra pass applies the deferred ConfigMap and nothing else"
        );
        assert_eq!(ready(&status).reason, REASON_SYNC_SUCCEEDED);
    }

    /// **Verification (T08.3):** `createNamespace: true` creates the destination namespace in the
    /// same pass and then applies into it — no livelock, and the namespace is never stamped with a
    /// `tracking-id` (so it is never prunable).
    #[tokio::test]
    async fn create_namespace_creates_the_namespace_then_syncs_into_it() {
        let fixture = fixture(FakeCluster::default());
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);
        let mut app = fixture.app(".");
        app.spec.sync_policy = Some(SyncPolicy {
            automated: Some(AutomatedSyncPolicy {
                prune: true,
                self_heal: true,
            }),
            sync_options: Some(SyncOptions {
                create_namespace: true,
                ..SyncOptions::default()
            }),
            retry: None,
        });

        let outcome = fixture
            .pipeline
            .apply(&app)
            .await
            .expect("createNamespace must be honoured, not rejected");

        assert_eq!(
            fixture.cluster.applies(),
            vec!["/Namespace//payments".to_owned(), CONFIGMAP_KEY.to_owned()],
            "the Namespace is applied first, then the ConfigMap in the same pass"
        );
        assert_eq!(
            fixture.cluster.applied_tracking_ids(),
            vec![
                String::new(),
                "ferriscd-system/payments:/ConfigMap:payments/settings".to_owned()
            ],
            "a namespace FerrisCD only created must never look owned (and so is never prunable)"
        );
        assert_eq!(outcome.reason, REASON_SYNC_SUCCEEDED);
        let inventory = outcome.inventory.expect("inventory is always reported");
        assert!(
            !inventory
                .keys()
                .any(|key| key.kind == "Namespace" && key.name == "payments"),
            "the pre-created namespace must never be tracked in status.inventory"
        );
        assert!(inventory.contains_key(&ResourceKey::new(
            "",
            "ConfigMap",
            Some("payments".to_owned()),
            "settings"
        )));
    }

    #[tokio::test]
    async fn an_empty_desired_set_over_a_non_empty_inventory_is_refused() {
        // A wrong `spec.source.git.path` renders nothing; that must never silently prune the
        // whole inventory.
        let owned = config_map(
            "settings",
            Some("ferriscd-system/payments:/ConfigMap:payments/settings"),
        );
        let fixture = fixture(
            FakeCluster::default()
                .with_namespace("payments")
                .with_object(owned),
        );
        fixture.commit(&[]);
        let mut app = fixture.app(".");
        app.status = Some(status_with_inventory(&["/ConfigMap/payments/settings"]));

        let err = fixture
            .pipeline
            .apply(&app)
            .await
            .expect_err("an empty desired set must be refused");

        assert!(
            matches!(err, ReconcileError::Invalid { .. }),
            "the refusal must be terminal: {err}"
        );
        assert_eq!(err.failure_class(), crate::FailureClass::Terminal);
        let message = err.to_string();
        assert!(message.contains("status.inventory"), "{message}");
        assert!(
            message.contains(ALLOW_EMPTY_DESIRED_ENV),
            "the message must name the opt-in: {message}"
        );
        assert!(fixture.cluster.applies().is_empty());
        assert!(
            fixture.cluster.deletes().is_empty(),
            "no delete may be issued by a refused pass"
        );

        // A first pass (empty inventory) with an empty desired set is not an error: there is
        // nothing to lose.
        let mut fresh = fixture.app(".");
        fresh.status = None;
        let outcome = fixture
            .pipeline
            .apply(&fresh)
            .await
            .expect("an empty application is not a failure");
        assert_eq!(outcome.reason, REASON_SYNC_SUCCEEDED);
    }

    #[tokio::test]
    async fn prune_skips_an_orphan_whose_ownership_flipped_between_fetch_and_delete() {
        // TOCTOU: the pass-level fetch sees our tracking-id, another Application takes the
        // object over before the delete. The re-check must refuse (and count) it.
        let orphan = config_map(
            "removed",
            Some("ferriscd-system/payments:/ConfigMap:payments/removed"),
        );
        let fixture = fixture(
            FakeCluster::default()
                .with_namespace("payments")
                .with_object(orphan)
                .with_ownership_flip_after_get("/ConfigMap/payments/removed"),
        );
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);
        let mut app = fixture.app(".");
        app.status = Some(status_with_inventory(&["/ConfigMap/payments/removed"]));
        auto_prune(&mut app);

        let outcome = fixture
            .pipeline
            .apply(&app)
            .await
            .expect("apply must succeed");

        assert!(
            fixture.cluster.deletes().is_empty(),
            "a takeover between the live read and the delete must abort the delete"
        );
        assert!(
            outcome.inventory.unwrap().contains_key(&ResourceKey::new(
                "",
                "ConfigMap",
                Some("payments".to_owned()),
                "removed"
            )),
            "the retained orphan must stay tracked so the conflict stays visible"
        );
        assert!(
            outcome.message.contains("1 orphan(s) retained"),
            "the retained orphan must be visible in the outcome: {}",
            outcome.message
        );
    }

    // ---------------------------------------------------------------------
    // Prune
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn prune_deletes_an_owned_orphan_only_when_enabled() {
        let orphan = config_map(
            "removed",
            Some("ferriscd-system/payments:/ConfigMap:payments/removed"),
        );
        let fixture = fixture(
            FakeCluster::default()
                .with_namespace("payments")
                .with_object(orphan),
        );
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);
        let mut app = fixture.app(".");
        app.status = Some(status_with_inventory(&["/ConfigMap/payments/removed"]));

        // Prune disabled (the default): the orphan is fetched but never deleted.
        let outcome = fixture
            .pipeline
            .apply(&app)
            .await
            .expect("apply must succeed");
        assert!(fixture.cluster.deletes().is_empty());
        assert_eq!(
            outcome.inventory.unwrap().len(),
            2,
            "a non-pruned orphan stays in the inventory"
        );

        // Prune enabled: the orphan is deleted and leaves the inventory atomically.
        auto_prune(&mut app);
        let outcome = fixture
            .pipeline
            .apply(&app)
            .await
            .expect("apply must succeed");
        assert_eq!(
            fixture.cluster.deletes(),
            vec!["/ConfigMap/payments/removed".to_owned()]
        );
        assert_eq!(fixture.cluster.deletes_confirmed(), 1);
        assert!(
            !outcome.inventory.unwrap().contains_key(&ResourceKey::new(
                "",
                "ConfigMap",
                Some("payments".to_owned()),
                "removed"
            )),
            "a confirmed prune must leave the inventory"
        );
    }

    #[tokio::test]
    async fn prune_never_deletes_a_foreign_orphan() {
        let foreign = config_map(
            "removed",
            Some("ferriscd-system/other:/ConfigMap:payments/removed"),
        );
        let fixture = fixture(
            FakeCluster::default()
                .with_namespace("payments")
                .with_object(foreign),
        );
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);
        let mut app = fixture.app(".");
        app.status = Some(status_with_inventory(&["/ConfigMap/payments/removed"]));
        auto_prune(&mut app);

        let outcome = fixture
            .pipeline
            .apply(&app)
            .await
            .expect("apply must succeed");
        assert!(
            fixture.cluster.deletes().is_empty(),
            "a resource owned by another Application must never be pruned"
        );
        assert_eq!(
            outcome.inventory.unwrap().len(),
            2,
            "the untouchable orphan stays tracked so the conflict stays visible"
        );
        assert!(
            outcome.message.contains("1 orphan(s) retained"),
            "a stuck orphan must be visible in /status: {}",
            outcome.message
        );
    }

    #[tokio::test]
    async fn prune_skips_a_resource_that_opted_out() {
        let mut orphan = config_map(
            "removed",
            Some("ferriscd-system/payments:/ConfigMap:payments/removed"),
        );
        orphan
            .metadata
            .annotations
            .get_or_insert_with(BTreeMap::new)
            .insert(annotations::PRUNE.to_owned(), "false".to_owned());
        let fixture = fixture(
            FakeCluster::default()
                .with_namespace("payments")
                .with_object(orphan),
        );
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);
        let mut app = fixture.app(".");
        app.status = Some(status_with_inventory(&["/ConfigMap/payments/removed"]));
        auto_prune(&mut app);

        fixture
            .pipeline
            .apply(&app)
            .await
            .expect("apply must succeed");
        assert!(fixture.cluster.deletes().is_empty());
    }

    // ---------------------------------------------------------------------
    // Repository credentials (`T12.4`)
    // ---------------------------------------------------------------------

    /// **`T12.4`:** the credentials the pipeline resolved actually reach the Git client.
    ///
    /// Before this task `fetch_desired` hardcoded `RepoCredentials::Anonymous`, so a private
    /// repository could never be cloned no matter what the operator put in a `Secret`. The fake
    /// records the credential *kind* (never a value) of every resolve/checkout call, so this
    /// asserts the seam rather than a log line.
    #[tokio::test]
    async fn resolved_repository_credentials_reach_the_git_client() {
        let source = Arc::new(FakeCredentialSource::returning(
            RepoCredentials::HttpToken {
                token: "ghp_super_secret_token_987654".to_owned(),
            },
        ));
        let fixture = fixture_with_credentials(
            FakeCluster::default().with_namespace("payments"),
            source.clone(),
        );
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);

        fixture
            .pipeline
            .apply(&fixture.app("."))
            .await
            .expect("the fixture apply must succeed");

        assert_eq!(
            source.lookups(),
            vec![fixture.repo_url.clone()],
            "the lookup must ask for the Application's own spec.source.git.repoUrl"
        );
        assert_eq!(
            fixture.git.credential_log(),
            vec!["http-token".to_owned(), "http-token".to_owned()],
            "both the revision resolve and the checkout must authenticate"
        );
        assert!(
            !fixture
                .git
                .credential_log()
                .iter()
                .any(|kind| kind == "anonymous"),
            "a configured credential must never be dropped for an anonymous clone"
        );
    }

    /// A repository no `Secret` matches keeps working: `T12.4` must not break public repositories.
    #[tokio::test]
    async fn a_repository_no_secret_matches_is_cloned_anonymously() {
        let source = Arc::new(FakeCredentialSource::default());
        let fixture = fixture_with_credentials(
            FakeCluster::default().with_namespace("payments"),
            source.clone(),
        );
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);

        fixture
            .pipeline
            .apply(&fixture.app("."))
            .await
            .expect("an unmatched repository must sync");

        assert_eq!(source.lookups().len(), 1);
        assert_eq!(
            fixture.git.credential_log(),
            vec!["anonymous".to_owned(), "anonymous".to_owned()],
            "no match is anonymous, exactly as before T12.4"
        );
    }

    /// The default pipeline (no store wired) still clones anonymously.
    #[tokio::test]
    async fn a_pipeline_without_a_credential_store_still_clones_anonymously() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);

        fixture
            .pipeline
            .apply(&fixture.app("."))
            .await
            .expect("the fixture apply must succeed");

        assert_eq!(
            fixture.git.credential_log(),
            vec!["anonymous".to_owned(), "anonymous".to_owned()]
        );
    }

    /// **Trap guard:** an unusable credential `Secret` is a *terminal* error raised **before** the
    /// clone starts. Falling back to an anonymous clone would turn "the operator's credential is
    /// broken" into an unexplained `RepositoryNotFound`, and retrying it would churn the queue.
    #[tokio::test]
    async fn an_unusable_credential_secret_is_terminal_and_clones_nothing() {
        let source = Arc::new(FakeCredentialSource::malformed(
            "the \"url\" key is missing or empty",
        ));
        let fixture = fixture_with_credentials(
            FakeCluster::default().with_namespace("payments"),
            source.clone(),
        );
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);

        let err = fixture
            .pipeline
            .apply(&fixture.app("."))
            .await
            .expect_err("an unusable credential Secret must stop the pass");

        assert!(
            matches!(&err, ReconcileError::Credentials(_)),
            "expected a Credentials error, got {err:?}"
        );
        assert_eq!(err.failure_class(), FailureClass::Terminal);
        let message = err.to_string();
        assert!(message.contains("repo-creds"), "{message}");
        assert!(message.contains("ferriscd-system"), "{message}");
        assert_eq!(source.lookups().len(), 1);
        assert_eq!(
            fixture.git.resolve_calls(),
            0,
            "nothing may be cloned with a credential the operator did not finish configuring"
        );
        assert!(fixture.cluster.applies().is_empty());
    }

    /// The pipeline's `Debug` says whether a credential store is wired — and nothing else about
    /// it, since everything it holds is secret material.
    #[test]
    fn the_pipeline_debug_only_reports_whether_a_credential_store_is_wired() {
        let plain = fixture(FakeCluster::default().with_namespace("payments"));
        assert!(
            format!("{:?}", plain.pipeline).contains("credentials: false"),
            "the anonymous default must be visible in Debug"
        );

        let wired = fixture_with_credentials(
            FakeCluster::default().with_namespace("payments"),
            Arc::new(FakeCredentialSource::returning(
                RepoCredentials::HttpBasic {
                    username: "ci-user-secret".to_owned(),
                    password: "ci-pass-secret".to_owned(),
                },
            )),
        );
        let debug = format!("{:?}", wired.pipeline);
        assert!(debug.contains("credentials: true"), "{debug}");
        for secret in ["ci-user-secret", "ci-pass-secret"] {
            assert!(!debug.contains(secret), "{secret} leaked into {debug}");
        }
    }

    // ---------------------------------------------------------------------
    // Rejections
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn a_local_repository_is_rejected_by_the_production_url_policy() {
        let temp = tempfile::tempdir().unwrap();
        let cluster = Arc::new(FakeCluster::default().with_namespace("payments"));
        let pipeline = InventorySyncPipeline::new(
            Arc::new(RepoCache::new(
                Arc::new(FakeGitClient::default()),
                RepoCacheConfig::new(temp.path().join("cache")),
            )),
            discovery(),
            cluster.clone(),
            Arc::new(FakeApplier {
                cluster: cluster.clone(),
                discovery: Arc::new(FakeDiscovery::with_cluster_kinds()),
                crd_mode: CrdMode::Establish,
            }),
            Arc::new(FakeDryRun::default()),
        )
        // Policy is enforced before the repository is resolved (`T12.1`), so the wiring has to be
        // complete for this test to reach the URL classification at all.
        .with_project_source(Arc::new(default_project_source()));
        assert_eq!(pipeline.url_policy(), RepoUrlPolicy::Production);

        let app = application(
            &temp.path().join("repo").display().to_string(),
            ".",
            "payments",
        );
        let err = pipeline
            .apply(&app)
            .await
            .expect_err("a local path must be rejected in production");
        assert!(
            matches!(err, ReconcileError::Repo(_)),
            "the repo classification must be preserved: {err}"
        );
        assert_eq!(err.failure_class(), crate::FailureClass::Terminal);
        assert!(cluster.applies().is_empty());
    }

    /// A remote destination that nothing registers is a **terminal** error naming the cluster: it
    /// must never fall back to the control plane, which would apply the manifests into the wrong
    /// cluster (`T13.1`).
    ///
    /// The fixture wires an **empty** registry rather than none — the same answer both paths give,
    /// and the shape a control plane whose cluster `Secret`s are all absent has.
    #[tokio::test]
    async fn an_unregistered_remote_destination_cluster_is_terminal() {
        // The project authorizes `prod`, so the refusal can only come from the registry.
        let projects = FakeProjectSource::default().with_project(remote_project());
        let fixture = fixture_with_clusters(
            FakeCluster::default().with_namespace("payments"),
            projects,
            Arc::default(),
        );
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);
        let mut app = fixture.app(".");
        app.spec.destination.cluster = "prod".to_owned();

        let err = fixture.pipeline.apply(&app).await.expect_err("rejected");
        assert!(matches!(err, ReconcileError::Cluster(_)), "{err:?}");
        assert_eq!(err.failure_class(), crate::FailureClass::Terminal);
        assert!(err.to_string().contains("\"prod\""), "{err}");
        assert!(
            err.to_string().contains("not registered"),
            "the operator must be told what to create: {err}"
        );
        assert!(
            fixture.cluster.applies().is_empty(),
            "nothing may be applied to the control plane for a remote destination"
        );
        assert!(
            fixture.cluster.app_patches().is_empty(),
            "nothing may be written to the control plane's objects either"
        );
    }

    /// **Finding M11:** `destination.cluster` is normalized one way everywhere — trimmed for the
    /// comparison, and a **blank** value is a terminal refusal rather than a silent `in-cluster`.
    #[tokio::test]
    async fn the_destination_cluster_is_normalized_consistently() {
        // A blank name is a typo. `serde(default)` only covers the omitted field, so accepting
        // `"  "` would make the meaning depend on which call path read it first.
        let strict = fixture(FakeCluster::default().with_namespace("payments"));
        strict.commit(&[("configmap.yaml", CONFIGMAP)]);
        let mut blank = strict.app(".");
        blank.spec.destination.cluster = "   ".to_owned();
        let err = strict
            .pipeline
            .apply(&blank)
            .await
            .expect_err("a blank destination cluster must be refused");
        assert_eq!(err.failure_class(), crate::FailureClass::Terminal);
        assert!(
            err.to_string().contains("destination.cluster"),
            "the operator must be told which field: {err}"
        );
        assert!(strict.cluster.applies().is_empty());
        assert_eq!(
            strict.git.resolve_calls(),
            0,
            "nothing may be read from Git"
        );

        // A *padded* name is the same cluster: the policy trims it and so does the registry
        // lookup, so `"  in-cluster  "` syncs exactly like `in-cluster`.
        let padded_fixture = fixture(FakeCluster::default().with_namespace("payments"));
        padded_fixture.commit(&[("configmap.yaml", CONFIGMAP)]);
        let mut padded = padded_fixture.app(".");
        padded.spec.destination.cluster = "  in-cluster  ".to_owned();
        padded_fixture
            .pipeline
            .apply(&padded)
            .await
            .expect("a padded in-cluster name must still resolve");
        assert_eq!(
            padded_fixture.cluster.applies(),
            vec![CONFIGMAP_KEY.to_owned()],
            "the trimmed name addresses the control plane"
        );
    }

    /// **Finding M10:** a remote `Application` that names a `serviceAccountName` is impersonated
    /// with the **remote cluster's** pool, never with the control plane's connector.
    ///
    /// The remote cluster's credential may not even be allowed to impersonate: silently using the
    /// control-plane pool would deploy as an identity the remote API server never authorized, or —
    /// worse — inherit a connector with the control plane's trust.
    #[tokio::test]
    async fn a_remote_application_is_impersonated_through_the_remote_cluster() {
        let local = FakeCluster::default().with_namespace("payments");
        let remote = Arc::new(FakeCluster::default().with_namespace("payments"));
        let remote_discovery = Arc::new(FakeDiscovery::with_cluster_kinds());
        // The remote cluster's own pool: a separate recorder, so "which connector resolved the
        // identity" is observable instead of implied.
        let remote_pool = Arc::new(FakeImpersonationSource {
            applier: Arc::new(FakeApplier {
                cluster: remote.clone(),
                discovery: remote_discovery.clone(),
                crd_mode: CrdMode::Establish,
            }),
            live: remote.clone(),
            dry_run: Arc::new(FakeDryRun::default()),
            identities: StdMutex::new(Vec::new()),
        });
        let source = Arc::new(FakeClusterSource::default().with_target(
            "prod",
            remote_target_with_impersonation(
                "prod",
                remote.clone(),
                remote_discovery,
                Some(remote_pool.clone()),
            ),
        ));
        let projects =
            FakeProjectSource::default().with_project(remote_project_with_service_account());
        let fixture = fixture_with_clusters(local, projects, source);
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);

        let mut app = fixture.app(".");
        app.spec.destination.cluster = "prod".to_owned();
        app.spec.service_account_name = Some("deployer".to_owned());

        fixture
            .pipeline
            .apply(&app)
            .await
            .expect("a remote Application with a ServiceAccount must sync");
        assert_eq!(
            remote_pool.identities(),
            vec!["system:serviceaccount:payments:deployer".to_owned(),],
            "the identity must be resolved on the remote cluster"
        );
        assert!(
            fixture.identities().is_empty(),
            "the control plane's pool must never resolve a remote identity: {:?}",
            fixture.identities()
        );
        assert_eq!(
            remote.applies(),
            vec![CONFIGMAP_KEY.to_owned()],
            "the workload must land on the remote cluster, as the impersonated identity"
        );
        assert!(fixture.cluster.applies().is_empty());
    }

    /// **The remote apply path:** live reads, the `dryRun=All` diff, the applies and the discovery
    /// snapshot all come from the registered cluster, and the control plane's own seams stay
    /// untouched.
    #[tokio::test]
    async fn a_remote_application_applies_through_the_remote_cluster() {
        let local = FakeCluster::default().with_namespace("payments");
        let remote = Arc::new(FakeCluster::default().with_namespace("payments"));
        let remote_discovery = Arc::new(FakeDiscovery::with_cluster_kinds());
        let source = Arc::new(FakeClusterSource::default().with_target(
            "prod",
            remote_target("prod", remote.clone(), remote_discovery.clone()),
        ));
        let projects = FakeProjectSource::default().with_project(remote_project());
        let fixture = fixture_with_clusters(local, projects, source.clone());
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);

        let mut app = fixture.app(".");
        app.spec.destination.cluster = "prod".to_owned();

        let outcome = fixture
            .pipeline
            .apply(&app)
            .await
            .expect("a registered remote cluster must sync");
        assert_eq!(
            remote.applies(),
            vec![CONFIGMAP_KEY.to_owned()],
            "the apply must go to the remote cluster"
        );
        assert!(
            fixture.cluster.applies().is_empty(),
            "the control plane must never receive the workload: {:?}",
            fixture.cluster.applies()
        );
        assert!(
            remote_discovery.fetches() > 0,
            "the pass must have discovered the *remote* API surface"
        );
        assert_eq!(
            fixture.discovery.fetches(),
            0,
            "not one discovery round trip may hit the control plane for a remote pass: live reads, \
             the diff and the applies all resolve against the remote cluster's snapshot"
        );
        assert_eq!(source.lookups(), vec!["prod".to_owned()]);
        assert_eq!(
            outcome
                .sync
                .as_ref()
                .map(|sync| sync.status)
                .expect("sync state"),
            SyncStatus::Synced
        );
        let inventory = outcome.inventory.expect("inventory");
        assert!(inventory.keys().any(|key| key.canonical() == CONFIGMAP_KEY));
    }

    /// **The `AppProject` stays the boundary:** a project that does not list the remote cluster
    /// refuses the `Application` *before* the registry is consulted, so a tenant cannot use a
    /// denied `Application` to probe which clusters exist (`T13.1` + `T12.1`).
    #[tokio::test]
    async fn the_project_must_list_the_remote_cluster_before_the_registry_is_consulted() {
        let local = FakeCluster::default().with_namespace("payments");
        let remote = Arc::new(FakeCluster::default().with_namespace("payments"));
        let source = Arc::new(FakeClusterSource::default().with_target(
            "prod",
            remote_target(
                "prod",
                remote.clone(),
                Arc::new(FakeDiscovery::with_cluster_kinds()),
            ),
        ));
        // The shipped `default` project authorizes `in-cluster` only.
        let fixture = fixture_with_clusters(local, default_project_source(), source.clone());
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);

        let mut app = fixture.app(".");
        app.spec.destination.cluster = "prod".to_owned();

        let err = fixture
            .pipeline
            .apply(&app)
            .await
            .expect_err("the project does not authorize the prod destination");
        assert!(matches!(err, ReconcileError::Policy(_)), "{err:?}");
        assert_eq!(err.failure_class(), crate::FailureClass::Terminal);
        assert!(
            source.lookups().is_empty(),
            "the cluster registry must not be probed for a destination the project denies: {:?}",
            source.lookups()
        );
        assert!(remote.applies().is_empty());
    }

    /// The `/status` subresource (and every spec patch) stays on the **control plane**, even when
    /// the pass deployed into a remote cluster (`T13.1`): the remote credential may not even serve
    /// the FerrisCD CRs.
    #[tokio::test]
    async fn a_remote_sync_keeps_status_and_spec_patches_on_the_control_plane() {
        #[derive(Default)]
        struct RecordingStatusWriter {
            statuses: StdMutex<Vec<ApplicationStatus>>,
        }

        impl StatusWriter for RecordingStatusWriter {
            fn patch<'a>(
                &'a self,
                _app: &'a Application,
                status: ApplicationStatus,
            ) -> futures::future::BoxFuture<'a, Result<(), ReconcileError>> {
                self.statuses.lock().unwrap().push(status);
                Box::pin(async { Ok(()) })
            }
        }

        let local = FakeCluster::default().with_namespace("payments");
        let remote = Arc::new(FakeCluster::default().with_namespace("payments"));
        let source = Arc::new(FakeClusterSource::default().with_target(
            "prod",
            remote_target(
                "prod",
                remote.clone(),
                Arc::new(FakeDiscovery::with_cluster_kinds()),
            ),
        ));
        let projects = FakeProjectSource::default().with_project(remote_project());
        let fixture = fixture_with_clusters(local, projects, source);
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);

        let mut app = fixture.app(".");
        app.spec.destination.cluster = "prod".to_owned();
        let writer = RecordingStatusWriter::default();

        apply_once(&app, &fixture.pipeline, &writer)
            .await
            .expect("the remote reconcile must succeed");

        let statuses = writer.statuses.lock().unwrap().clone();
        assert_eq!(statuses.len(), 1, "exactly one /status patch");
        assert_eq!(
            statuses[0].sync.as_ref().map(|sync| sync.status),
            Some(SyncStatus::Synced),
            "the status records the remote sync"
        );
        assert_eq!(
            remote.applies(),
            vec![CONFIGMAP_KEY.to_owned()],
            "the workload landed remotely"
        );
        assert!(
            remote.app_patches().is_empty(),
            "the remote cluster must never receive an Application patch: {:?}",
            remote.app_patches()
        );
    }

    /// **Finding C5:** deleting an `Application` whose destination cluster `Secret` is gone releases
    /// the finalizer with a warning instead of wedging the object in `Terminating` forever.
    #[tokio::test]
    async fn deleting_an_application_whose_cluster_disappeared_releases_the_finalizer() {
        let local = FakeCluster::default().with_namespace("payments");
        // The registry knows no `prod` (its Secret was deleted).
        let fixture = fixture_with_clusters(local, default_project_source(), Arc::default());
        let mut app = fixture.app(".");
        app.spec.destination.cluster = "prod".to_owned();
        auto_prune(&mut app);
        app.status = Some(status_with_inventory(&[CONFIGMAP_KEY]));

        let outcome = fixture
            .pipeline
            .cleanup(&app, CleanupMode::Cascade)
            .await
            .expect("a vanished destination is not a cleanup failure");
        match &outcome {
            CleanupOutcome::TargetUnavailable { message } => {
                assert!(message.contains("prod"), "{message}");
                assert!(
                    message.contains("not registered"),
                    "the operator must be told the cluster is not registered: {message}"
                );
            }
            other => panic!("expected TargetUnavailable, got {other:?}"),
        }

        let disposition = crate::reconcile::cleanup_disposition(&app, Ok(outcome));
        match disposition {
            CleanupDisposition::Release { warning } => {
                let warning = warning.expect("releasing without pruning must warn");
                assert!(warning.contains("unavailable"), "{warning}");
                assert!(warning.contains("prod"), "{warning}");
            }
            CleanupDisposition::Retain { error } => {
                panic!("the finalizer must be released, not retained: {error}");
            }
        }
        assert!(
            fixture.cluster.deletes().is_empty(),
            "nothing may be deleted from the control plane for a remote destination"
        );
    }

    /// **Finding M-new-1:** a blank `spec.destination.cluster` is a spec typo, not a registration.
    /// Cleanup must treat it like a missing cluster — finalizer released with a warning — instead of
    /// wedging the deleted `Application` in `Terminating` on an `InvalidName` (which is not
    /// `is_not_found`).
    #[tokio::test]
    async fn deleting_an_application_with_a_blank_destination_cluster_releases_the_finalizer() {
        let fixture = fixture_with_clusters(
            FakeCluster::default().with_namespace("payments"),
            default_project_source(),
            // A registry that registers nothing: a blank name is never registered anywhere.
            Arc::default(),
        );
        let mut app = fixture.app(".");
        app.spec.destination.cluster = "   ".to_owned();
        auto_prune(&mut app);
        app.status = Some(status_with_inventory(&[CONFIGMAP_KEY]));

        let outcome = fixture
            .pipeline
            .cleanup(&app, CleanupMode::Cascade)
            .await
            .expect("a blank destination is a spec typo, not a cleanup failure");
        match &outcome {
            CleanupOutcome::TargetUnavailable { message } => {
                assert!(message.contains("destination cluster"), "{message}");
                assert!(message.contains("must not be blank"), "{message}");
            }
            other => panic!("expected TargetUnavailable, got {other:?}"),
        }

        match crate::reconcile::cleanup_disposition(&app, Ok(outcome)) {
            CleanupDisposition::Release { warning } => {
                let warning = warning.expect("releasing without pruning must warn");
                assert!(warning.contains("unavailable"), "{warning}");
            }
            CleanupDisposition::Retain { error } => {
                panic!("the finalizer must be released, not retained: {error}");
            }
        }
        assert!(
            fixture.cluster.deletes().is_empty(),
            "a blank destination names no cluster, so nothing may be deleted"
        );
    }

    /// `T10.3`: a lifecycle hook is created **once** with `Api::create`, tracked in
    /// `status.operationState.activeHooks` by its generated name, and never becomes prunable
    /// inventory (finding H2).
    #[tokio::test]
    async fn a_generate_name_hook_is_created_once_and_never_becomes_inventory() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[
            (
                "hook.yaml",
                "apiVersion: batch/v1\nkind: Job\nmetadata:\n  generateName: migrate-\n  annotations:\n    ferriscd.io/hook: PreSync\n",
            ),
            ("configmap.yaml", CONFIGMAP),
        ]);
        let app = fixture.app(".");

        // Pass 1: the PreSync hook is created, the wave is not touched yet.
        let first = fixture
            .pipeline
            .apply(&app)
            .await
            .expect("hooks are supported");
        assert_eq!(
            fixture.cluster.creates(),
            vec!["migrate-abcde".to_owned()],
            "exactly one hook object, named by the API server"
        );
        assert!(
            fixture.cluster.applies().is_empty(),
            "wave 0 must wait for PreSync (only the hook is created): {:?}",
            fixture.cluster.applies()
        );
        let operation = first
            .operation_state
            .clone()
            .expect("a hook operation persists its state");
        assert_eq!(operation.sync_phase, Some(SyncPhase::PreSync));
        assert_eq!(operation.active_hooks.len(), 1);
        assert_eq!(operation.active_hooks[0].generated_name, "migrate-abcde");
        assert_eq!(operation.active_hooks[0].phase, SyncPhase::PreSync);
        assert_eq!(first.reason, REASON_SYNC_IN_PROGRESS);
        assert_eq!(first.requeue, Some(DEFAULT_REQUEUE_AFTER));
        let inventory = first.inventory.clone().expect("inventory");
        assert!(
            inventory.keys().all(|key| key.kind != "Job"),
            "a hook must never enter status.inventory: {inventory:?}"
        );

        // Pass 2: the hook is still running -> observed, never created again.
        let mut second_app = app.clone();
        second_app.status = Some(ApplicationStatus {
            operation_state: Some(operation),
            ..app.status.clone().unwrap_or_default()
        });
        let second = fixture
            .pipeline
            .apply(&second_app)
            .await
            .expect("the hook is observed, not recreated");
        assert_eq!(
            fixture.cluster.creates(),
            vec!["migrate-abcde".to_owned()],
            "a requeue must never run the migration twice"
        );
        assert_eq!(second.reason, REASON_SYNC_IN_PROGRESS);

        // Pass 3: the Job completed -> PreSync advances to wave 0 and the ConfigMap is applied.
        fixture.cluster.complete_job("migrate-abcde");
        let mut third_app = second_app.clone();
        third_app.status = Some(ApplicationStatus {
            operation_state: second.operation_state.clone(),
            ..second_app.status.clone().unwrap_or_default()
        });
        let third = fixture.pipeline.apply(&third_app).await.expect("wave 0");
        assert_eq!(
            fixture.cluster.applies(),
            vec![CONFIGMAP_KEY.to_owned()],
            "the wave applies only its own resources"
        );
        let operation = third.operation_state.clone().expect("state");
        assert_eq!(operation.sync_phase, Some(SyncPhase::Sync));
        assert_eq!(operation.current_wave, 0);
    }

    /// `metadata.generateName` stays unsupported for a **permanent** resource: its name is its
    /// identity, and a name the API server picks cannot be tracked, diffed or pruned.
    #[tokio::test]
    async fn a_permanent_generate_name_resource_is_still_rejected() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[(
            "job.yaml",
            "apiVersion: batch/v1\nkind: Job\nmetadata:\n  generateName: migrate-\n",
        )]);
        let app = fixture.app(".");

        let err = fixture
            .pipeline
            .apply(&app)
            .await
            .expect_err("generateName is unsupported for a permanent resource");
        assert!(err.to_string().contains("generateName"), "{err}");
        assert!(
            err.to_string().contains("ferriscd.io/hook"),
            "the error must name the one legitimate use: {err}"
        );
        assert_eq!(err.failure_class(), crate::FailureClass::Terminal);
        assert!(fixture.cluster.creates().is_empty());
        assert!(fixture.cluster.applies().is_empty());
    }

    /// `T10.2`: a two-wave bundle is applied one wave at a time, gated on health, and the whole
    /// rollout is recorded as an operation.
    #[tokio::test]
    async fn a_two_wave_bundle_is_applied_wave_by_wave() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        let sha = fixture.commit(&[
            (
                "migration.yaml",
                "apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: smoke\n  annotations:\n    ferriscd.io/sync-wave: \"-1\"\n",
            ),
            ("configmap.yaml", CONFIGMAP),
            ("deployment.yaml", DEPLOYMENT),
        ]);
        let app = fixture.app(".");

        // Pass 1: wave -1 only.
        let first = fixture.pipeline.apply(&app).await.expect("wave -1");
        assert_eq!(
            fixture.cluster.applies(),
            vec!["batch/Job/payments/smoke".to_owned()],
            "wave 0 must not be applied before wave -1 is Healthy"
        );
        let state = first.operation_state.clone().expect("operation state");
        assert_eq!(state.sync_phase, Some(SyncPhase::Sync));
        assert_eq!(state.current_wave, -1);
        assert_eq!(state.revision.as_deref(), Some(sha.as_str()));

        // Pass 2: wave -1 converged -> wave 0. The fake API server persists the writes, and the
        // migration Job reports `Complete` (a `Progressing` Job keeps its wave open on purpose).
        fixture.cluster.seed_applied();
        fixture.cluster.complete_job("smoke");
        let mut second_app = app.clone();
        second_app.status = Some(ApplicationStatus {
            operation_state: Some(state),
            ..app.status.clone().unwrap_or_default()
        });
        let second = fixture.pipeline.apply(&second_app).await.expect("wave 0");
        let mut applies = fixture.cluster.applies();
        applies.drain(0..1);
        assert_eq!(
            applies,
            vec![CONFIGMAP_KEY.to_owned(), DEPLOYMENT_KEY.to_owned()],
            "wave 0 applies its own resources in tier order"
        );
        let state = second.operation_state.clone().expect("state");
        assert_eq!(state.current_wave, 0);
        assert!(second.reason == REASON_SYNC_IN_PROGRESS);

        // Pass 3: the rollout converged -> PostSync (one step per pass; the machine never skips a
        // phase, so `Succeeded` is reached on the following pass).
        fixture.cluster.seed_applied();
        fixture.cluster.complete_job("smoke");
        fixture.cluster.make_deployment_ready("api", 1);
        let mut third_app = app.clone();
        third_app.status = Some(ApplicationStatus {
            operation_state: Some(state),
            ..app.status.clone().unwrap_or_default()
        });
        let third = fixture.pipeline.apply(&third_app).await.expect("post sync");
        assert_eq!(
            third.operation_state.as_ref().map(|state| state.sync_phase),
            Some(Some(SyncPhase::PostSync)),
            "every wave is Healthy, so the operation moved to its cleanup phase"
        );
        assert_eq!(third.reason, REASON_SYNC_IN_PROGRESS);
        let state = third.operation_state.clone().expect("state");

        // Pass 4: PostSync has nothing to run -> Succeeded, and the deployment is recorded.
        let mut fourth_app = app.clone();
        fourth_app.status = Some(ApplicationStatus {
            operation_state: Some(state),
            ..app.status.clone().unwrap_or_default()
        });
        let fourth = fixture
            .pipeline
            .apply(&fourth_app)
            .await
            .expect("succeeded");
        let state = fourth.operation_state.clone().expect("state");
        assert_eq!(state.phase, OperationPhase::Succeeded);
        assert_eq!(state.sync_phase, Some(SyncPhase::Succeeded));
        assert_eq!(
            fourth.requeue,
            Some(Duration::from_secs(u64::from(
                DEFAULT_REQUEUE_AFTER_SECONDS
            ))),
            "a finished operation falls back to the drift-detection interval, not the 5 s wave one"
        );
        assert_eq!(
            fourth.reason, REASON_SYNC_SUCCEEDED,
            "the last wave completes the sync: {}",
            fourth.message
        );
        let history = fourth.history.clone().expect("history");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].id, 1);
        assert_eq!(history[0].revision, state.revision);

        // Pass 5: the operation is terminal and the cluster converged -> zero mutation.
        let mut fifth_app = app.clone();
        fifth_app.status = Some(ApplicationStatus {
            operation_state: Some(state),
            history,
            // The `lastSynced*` markers the succeeded pass wrote: without them the gate would see a
            // commit it has "never synced" and start a new operation on every pass.
            sync: fourth.sync.clone(),
            ..app.status.clone().unwrap_or_default()
        });
        let before = fixture.cluster.applies().len();
        let fifth = fixture.pipeline.apply(&fifth_app).await.expect("settled");

        assert_eq!(
            fixture.cluster.applies().len(),
            before,
            "a settled application issues no mutating apply"
        );
        assert!(
            fifth.history.is_none(),
            "re-running does not duplicate history"
        );
    }

    /// **Finding M3:** mid-rollout, the resources of a wave the operation has not dispatched yet do
    /// not exist *by design*, so they are reported `Progressing` (scheduled) — never `Missing`,
    /// which would describe a perfectly healthy rollout as broken between every pair of waves.
    #[tokio::test]
    async fn resources_of_a_wave_the_operation_has_not_reached_are_progressing_not_missing() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[
            (
                "migration.yaml",
                "apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: smoke\n  annotations:\n    ferriscd.io/sync-wave: \"-1\"\n",
            ),
            ("configmap.yaml", CONFIGMAP),
            ("deployment.yaml", DEPLOYMENT),
        ]);
        let app = fixture.app(".");

        // Pass 1 dispatches wave -1 only, so wave 0 has deliberately not been created.
        let outcome = fixture.pipeline.apply(&app).await.expect("wave -1");
        assert_eq!(
            fixture.cluster.applies(),
            vec!["batch/Job/payments/smoke".to_owned()],
            "wave 0 must not be applied before wave -1 is Healthy"
        );
        assert_eq!(
            outcome.health.as_ref().map(|health| health.status),
            Some(HealthStatus::Progressing),
            "a rollout in flight is Progressing, never Missing: {:?}",
            outcome
                .health
                .as_ref()
                .and_then(|health| health.message.clone())
        );
        let resources = outcome.resources.expect("per-resource health");
        assert_eq!(resources.len(), 3);
        for resource in &resources {
            assert_eq!(
                resource.health,
                HealthStatus::Progressing,
                "{} must be scheduled, not Missing: {}",
                resource.key,
                resource.message
            );
        }
        let wave_zero = resources
            .iter()
            .find(|resource| resource.key == CONFIGMAP_KEY)
            .expect("the wave 0 ConfigMap is part of this pass's assessment");
        assert!(
            wave_zero.message.contains("scheduled"),
            "a scheduled resource must say why it is not here yet: {}",
            wave_zero.message
        );

        // Once wave 0 has been dispatched, nothing is scheduled any more: a resource that is still
        // absent then is genuinely `Missing`.
        fixture.cluster.seed_applied();
        fixture.cluster.complete_job("smoke");
        let mut second_app = app.clone();
        second_app.status = Some(ApplicationStatus {
            operation_state: outcome.operation_state,
            ..ApplicationStatus::default()
        });
        let second = fixture.pipeline.apply(&second_app).await.expect("wave 0");
        let second_resources = second.resources.expect("per-resource health");
        assert!(
            second_resources
                .iter()
                .all(|resource| !resource.message.contains("scheduled")),
            "no resource of the last dispatched wave is scheduled: {second_resources:?}"
        );
    }

    /// **Finding H1:** the persisted operation is on a wave the new commit no longer has. The pass
    /// must not trip `StepHealth::wave`'s debug assertion; it restarts the operation at `PreSync`
    /// for the new revision.
    #[tokio::test]
    async fn a_commit_that_removes_the_current_wave_restarts_at_pre_sync() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[
            (
                "migration.yaml",
                "apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: smoke\n  annotations:\n    ferriscd.io/sync-wave: \"-1\"\n",
            ),
            ("configmap.yaml", CONFIGMAP),
        ]);
        let app = fixture.app(".");
        let first = fixture.pipeline.apply(&app).await.expect("wave -1");
        let state = first.operation_state.clone().expect("operation state");
        assert_eq!(state.current_wave, -1);
        assert_eq!(state.sync_phase, Some(SyncPhase::Sync));

        // The next commit deletes wave -1 entirely: `FakeGitClient` commits replace the tree.
        let new_sha = fixture.commit(&[("configmap.yaml", CONFIGMAP_WITH_DATA)]);
        let mut second_app = app.clone();
        second_app.status = Some(ApplicationStatus {
            operation_state: Some(state),
            ..ApplicationStatus::default()
        });

        let second = fixture
            .pipeline
            .apply(&second_app)
            .await
            .expect("a vanished wave is not an error");
        let state = second.operation_state.expect("state");
        assert_eq!(
            state.sync_phase,
            Some(SyncPhase::PreSync),
            "the operation restarts for the new revision instead of judging a wave that is gone"
        );
        assert_eq!(state.current_wave, 0);
        assert_eq!(state.revision.as_deref(), Some(new_sha.as_str()));
        assert!(
            state
                .message
                .as_deref()
                .is_some_and(|message| message.contains("revision changed")),
            "{:?}",
            state.message
        );
        assert!(
            fixture.cluster.applies().len() == 1,
            "the restart pass applies nothing new: {:?}",
            fixture.cluster.applies()
        );
    }

    /// **Finding M4:** a wave pass that fails with a *retryable* API error must persist the hook
    /// records it created, or the retry creates a second `generateName` `Job` — a second migration.
    #[tokio::test]
    async fn a_retryable_wave_failure_persists_the_hook_records_it_created() {
        let fixture = fixture(
            FakeCluster::default()
                .with_namespace("payments")
                .fail_apply_retryably(DEPLOYMENT_KEY),
        );
        fixture.commit(&[
            ("hook.yaml", PRE_SYNC_HOOK),
            ("configmap.yaml", CONFIGMAP),
            ("deployment.yaml", DEPLOYMENT),
        ]);
        let app = fixture.app(".");

        // Pass 1: the PreSync hook is created and tracked.
        let first = fixture.pipeline.apply(&app).await.expect("the hook pass");
        assert_eq!(fixture.cluster.creates(), vec!["migrate-abcde".to_owned()]);
        let state = first.operation_state.clone().expect("operation state");
        assert_eq!(state.active_hooks.len(), 1);

        // Pass 2: the hook completed, wave 0 is dispatched, the Deployment fails with a `500`.
        fixture.cluster.complete_job("migrate-abcde");
        let mut second_app = app.clone();
        second_app.status = Some(ApplicationStatus {
            operation_state: Some(state),
            ..ApplicationStatus::default()
        });
        let err = fixture
            .pipeline
            .apply(&second_app)
            .await
            .expect_err("the wave apply fails");
        assert_eq!(
            err.failure_class(),
            crate::FailureClass::Retryable,
            "a 500 is retryable, so the failure must be a PartialSync: {err:?}"
        );
        assert!(matches!(err, ReconcileError::PartialSync { .. }), "{err:?}");

        // The failure carries the operation state, hook record included.
        let operation = err
            .partial_operation()
            .expect("a retryable wave failure must carry its operation state")
            .clone();
        assert_eq!(operation.sync_phase, Some(SyncPhase::Sync));
        assert_eq!(operation.current_wave, 0);
        assert_eq!(operation.active_hooks.len(), 1);
        assert_eq!(operation.active_hooks[0].generated_name, "migrate-abcde");
        assert_eq!(
            operation.active_hooks[0].health,
            HealthStatus::Healthy,
            "the record is refreshed to what the pass observed"
        );

        // Pass 3: the retry resumes from that persisted state and never re-runs the migration.
        let mut third_app = app.clone();
        third_app.status = Some(ApplicationStatus {
            operation_state: Some(operation),
            ..ApplicationStatus::default()
        });
        let _ = fixture.pipeline.apply(&third_app).await;
        assert_eq!(
            fixture.cluster.creates(),
            vec!["migrate-abcde".to_owned()],
            "a retry must observe the created hook, never create a second Job"
        );
    }

    /// **Finding H-NEW:** a hook step that fails on the *second* hook must still hand the hooks it
    /// already created to `apply_once` (`PartialSync.operation`), or the retry sees them untracked
    /// and creates a second `generateName` `Job` — a second database migration.
    #[tokio::test]
    async fn a_failing_hook_create_persists_the_hooks_created_before_it() {
        let fixture = fixture(
            FakeCluster::default()
                .with_namespace("payments")
                .fail_create_retryably("migrate-"),
        );
        fixture.commit(&[
            ("seed-hook.yaml", SEED_PRE_SYNC_HOOK),
            ("hook.yaml", PRE_SYNC_HOOK),
            ("configmap.yaml", CONFIGMAP),
        ]);
        let app = fixture.app(".");

        // Pass 1: `seed-` (wave -1) is created, the create of `migrate-` (wave 0) answers `500`.
        let err = fixture
            .pipeline
            .apply(&app)
            .await
            .expect_err("the second hook create fails");
        assert_eq!(
            err.failure_class(),
            crate::FailureClass::Retryable,
            "a 500 is retryable, so the failure must be a PartialSync: {err:?}"
        );
        assert!(matches!(err, ReconcileError::PartialSync { .. }), "{err:?}");
        assert_eq!(
            fixture.cluster.creates(),
            vec!["seed-abcde".to_owned()],
            "the first hook really was created before the failure"
        );

        // The failure carries the record of the hook that already exists.
        let operation = err
            .partial_operation()
            .expect("a failing hook step must carry the state it reached")
            .clone();
        assert_eq!(operation.sync_phase, Some(SyncPhase::PreSync));
        assert_eq!(operation.active_hooks.len(), 1);
        assert_eq!(operation.active_hooks[0].generated_name, "seed-abcde");
        assert_eq!(
            operation.active_hooks[0].phase,
            SyncPhase::PreSync,
            "the record is what keeps the retry from creating a duplicate"
        );

        // Pass 2: the retry resumes from that state, observes `seed-abcde` and creates only
        // `migrate-abcde`, so the operation performs exactly one create per hook.
        fixture.cluster.complete_job("seed-abcde");
        let mut retry = app.clone();
        retry.status = Some(ApplicationStatus {
            operation_state: Some(operation),
            ..ApplicationStatus::default()
        });
        fixture
            .pipeline
            .apply(&retry)
            .await
            .expect("the retry resumes the operation and succeeds");
        assert_eq!(
            fixture.cluster.creates(),
            vec!["seed-abcde".to_owned(), "migrate-abcde".to_owned()],
            "the retry creates the missing hook once, never a second copy of a tracked one"
        );
    }

    /// **Finding H-A:** a *terminal* hook-create failure (`422`) is a `SyncConflict`, and it must
    /// carry the operation state it reached — marked `Failed`. Dropping it made the next requeue
    /// restart the operation with an empty `activeHooks` list and create a second `seed-*` `Job`
    /// (a second migration). Persisting the `Failed` phase makes
    /// `failed_operation_is_not_retried` hold an unchanged revision instead.
    #[tokio::test]
    async fn a_terminal_hook_create_failure_persists_a_failed_operation_and_is_not_retried() {
        let fixture = fixture(
            FakeCluster::default()
                .with_namespace("payments")
                .fail_create_terminally("migrate-"),
        );
        fixture.commit(&[
            ("seed-hook.yaml", SEED_PRE_SYNC_HOOK),
            ("hook.yaml", PRE_SYNC_HOOK),
            ("configmap.yaml", CONFIGMAP),
        ]);
        let mut app = fixture.app(".");

        // Pass 1 (through the real `apply_once`): `seed-` is created, the create of `migrate-`
        // answers `422`, which is terminal.
        let (err, status) = reconcile_pass(&fixture, &mut app).await;
        let err = err.expect("the second hook create fails");
        assert_eq!(
            err.failure_class(),
            crate::FailureClass::Terminal,
            "a 422 cannot be fixed by retrying: {err:?}"
        );
        assert!(
            matches!(err, ReconcileError::SyncConflict { .. }),
            "{err:?}"
        );
        assert_eq!(
            fixture.cluster.creates(),
            vec!["seed-abcde".to_owned()],
            "the first hook really was created before the failure"
        );

        // The failure carries the state, `Failed`, with the record of the hook that exists.
        let operation = err
            .partial_operation()
            .expect("a terminal hook failure must carry the state it reached")
            .clone();
        assert_eq!(operation.phase, OperationPhase::Failed);
        assert_eq!(operation.sync_phase, Some(SyncPhase::PreSync));
        assert_eq!(operation.active_hooks.len(), 1);
        assert_eq!(operation.active_hooks[0].generated_name, "seed-abcde");
        assert!(
            operation.finished_at.is_some(),
            "a terminal failure stamps the end of the operation"
        );
        assert!(
            operation
                .message
                .as_deref()
                .is_some_and(|message| message.contains("immutable")),
            "the failure reason reaches status.operationState.message: {:?}",
            operation.message
        );

        // `apply_once` persisted it, so the next pass sees the terminal operation.
        let status = status.expect("the failure path must still patch /status");
        assert!(!status.is_ready());
        let persisted = status
            .operation_state
            .clone()
            .expect("a terminal wave failure must persist its operation state");
        assert_eq!(persisted.phase, OperationPhase::Failed);
        assert_eq!(persisted.active_hooks.len(), 1);

        // Pass 2: the same revision does not restart the failed operation, so nothing is created
        // again — in particular no second `seed-*` migration `Job`.
        let outcome = fixture
            .pipeline
            .apply(&app)
            .await
            .expect("a terminally failed operation is reported, not retried as an error");
        assert_eq!(
            fixture.cluster.creates(),
            vec!["seed-abcde".to_owned()],
            "a failed operation must never re-run a generateName hook: {:?}",
            fixture.cluster.creates()
        );
        assert_eq!(
            outcome.operation_state.as_ref().map(|state| state.phase),
            Some(OperationPhase::Failed),
            "the operation stays terminally failed"
        );
    }

    /// **Finding H-A:** a discovery-refresh failure *after* a CRD wave (`T10.2`'s boundary guard)
    /// must not drop what the pass reached: the wave that was just applied stays in the carried
    /// inventory and the hook records stay in the carried operation state.
    #[tokio::test]
    async fn a_wave_boundary_discovery_failure_keeps_the_inventory_and_the_hook_records() {
        // A CRD plus a `PreSync` hook in one commit: the hook has to be created and tracked before
        // the CRD wave is dispatched.
        let crd_wave = "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: widgets.example.com\n  annotations:\n    ferriscd.io/sync-wave: \"-1\"\nspec:\n  group: example.com\n  scope: Namespaced\n  names:\n    kind: Widget\n    plural: widgets\n  versions:\n    - name: v1\n      served: true\n      storage: true\n";
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[
            ("hook.yaml", PRE_SYNC_HOOK),
            ("crd.yaml", crd_wave),
            ("configmap.yaml", CONFIGMAP),
        ]);
        let app = fixture.app(".");

        // Pass 1: the PreSync hook is created and tracked; no wave is dispatched yet.
        let first = fixture.pipeline.apply(&app).await.expect("the hook pass");
        let state = first.operation_state.clone().expect("operation state");
        assert_eq!(state.active_hooks.len(), 1);
        assert!(
            fixture.cluster.applies().is_empty(),
            "a `Progressing` PreSync hook keeps the waves closed: {:?}",
            fixture.cluster.applies()
        );

        // Pass 2 dispatches the CRD wave. Discovery is served for the two refreshes of the pass
        // itself (`prepare`'s and the executor's post-CRD one) and fails at the wave boundary.
        fixture.discovery.fail_refresh_after(2);
        fixture.cluster.complete_job("migrate-abcde");
        let mut second_app = app.clone();
        second_app.status = Some(ApplicationStatus {
            operation_state: Some(state),
            ..ApplicationStatus::default()
        });

        let err = fixture
            .pipeline
            .apply(&second_app)
            .await
            .expect_err("the wave-boundary refresh fails");
        assert_eq!(
            err.failure_class(),
            crate::FailureClass::Retryable,
            "an unavailable API server is retryable, so the pass must be a PartialSync: {err:?}"
        );
        assert!(matches!(err, ReconcileError::PartialSync { .. }), "{err:?}");

        // The wave that was applied stays confirmed: a create that succeeded must never become an
        // untracked orphan (finding C1) just because the refresh after it failed.
        let (inventory, revision) = err
            .partial_status()
            .expect("a partial sync must report the inventory it already owns");
        assert!(
            inventory
                .keys()
                .any(|key| key.kind == scope::CRD_KIND && key.name == "widgets.example.com"),
            "the CRD of the wave that was just applied must stay tracked: {:?}",
            inventory.keys().collect::<Vec<_>>()
        );
        assert!(revision.is_some());

        // ...and so does the operation state, hook record included.
        let operation = err
            .partial_operation()
            .expect("a wave-boundary failure must carry the state it reached");
        assert_eq!(operation.sync_phase, Some(SyncPhase::Sync));
        assert_eq!(operation.current_wave, -1);
        assert_eq!(operation.active_hooks.len(), 1);
        assert_eq!(operation.active_hooks[0].generated_name, "migrate-abcde");
        assert_eq!(
            operation.active_hooks[0].health,
            HealthStatus::Healthy,
            "the record is refreshed to what the pass observed"
        );
    }

    /// **Finding M5:** a `Failed` operation is not restarted by a plain requeue — that would
    /// re-run `PreSync`/`SyncFail` hooks (and, for a `generateName` hook, start a second migration).
    /// Only a new revision or an explicit manual operation starts a new operation.
    #[tokio::test]
    async fn a_failed_operation_is_not_restarted_without_a_new_revision_or_a_manual_operation() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[("hook.yaml", PRE_SYNC_HOOK), ("configmap.yaml", CONFIGMAP)]);
        let app = fixture.app(".");

        // Pass 1: the PreSync hook is created.
        let first = fixture.pipeline.apply(&app).await.expect("the hook pass");
        assert_eq!(fixture.cluster.creates().len(), 1);
        let mut state = first.operation_state.clone().expect("state");

        // Pass 2: the migration failed -> `SyncFail`.
        fixture.cluster.fail_job("migrate-abcde");
        let mut second_app = app.clone();
        second_app.status = Some(ApplicationStatus {
            operation_state: Some(state),
            ..ApplicationStatus::default()
        });
        let second = fixture
            .pipeline
            .apply(&second_app)
            .await
            .expect("sync fail");
        assert_eq!(
            second
                .operation_state
                .as_ref()
                .map(|state| state.sync_phase),
            Some(Some(SyncPhase::SyncFail))
        );
        state = second.operation_state.clone().expect("state");

        // Pass 3: a `SyncFail` phase without hooks is over -> terminal `Failed`.
        let mut third_app = app.clone();
        third_app.status = Some(ApplicationStatus {
            operation_state: Some(state),
            ..ApplicationStatus::default()
        });
        let third = fixture.pipeline.apply(&third_app).await.expect("failed");
        let failed = third.operation_state.clone().expect("state");
        assert_eq!(failed.phase, OperationPhase::Failed);
        assert_eq!(
            fixture.cluster.creates().len(),
            1,
            "the failed PreSync hook is never created again by the failure path itself"
        );

        // Passes 4 and 5: repeated requeues of the same, unchanged commit change nothing.
        for pass in 0..2 {
            let mut requeue = app.clone();
            requeue.status = Some(ApplicationStatus {
                operation_state: Some(failed.clone()),
                ..ApplicationStatus::default()
            });
            let outcome = fixture
                .pipeline
                .apply(&requeue)
                .await
                .unwrap_or_else(|err| panic!("pass {pass} must not fail: {err}"));
            assert_eq!(
                outcome.operation_state.as_ref().map(|state| state.phase),
                Some(OperationPhase::Failed),
                "pass {pass}: the operation stays terminally failed"
            );
            assert_eq!(
                fixture.cluster.creates().len(),
                1,
                "pass {pass}: a requeue must not re-run PreSync/SyncFail hooks"
            );
        }

        // A new revision is a new sync: it starts a fresh operation at PreSync.
        fixture.commit(&[
            ("hook.yaml", PRE_SYNC_HOOK),
            ("configmap.yaml", CONFIGMAP_WITH_DATA),
        ]);
        let mut new_revision = app.clone();
        new_revision.status = Some(ApplicationStatus {
            operation_state: Some(failed.clone()),
            ..ApplicationStatus::default()
        });
        let restarted = fixture
            .pipeline
            .apply(&new_revision)
            .await
            .expect("a new revision restarts the operation");
        assert_eq!(
            restarted
                .operation_state
                .as_ref()
                .map(|state| state.sync_phase),
            Some(Some(SyncPhase::PreSync))
        );
        assert_eq!(
            fixture.cluster.creates().len(),
            2,
            "the new commit runs its own PreSync hook"
        );

        // ...and so is an explicit manual operation on the same commit.
        let mut manual = app.clone();
        manual.metadata.annotations = Some(BTreeMap::from([(
            annotations::OPERATION.to_owned(),
            r#"{"sync":{}}"#.to_owned(),
        )]));
        manual.status = Some(ApplicationStatus {
            operation_state: Some(failed),
            ..ApplicationStatus::default()
        });
        let manual_outcome = fixture
            .pipeline
            .apply(&manual)
            .await
            .expect("a manual operation restarts the operation");
        assert_eq!(
            manual_outcome
                .operation_state
                .as_ref()
                .map(|state| state.sync_phase),
            Some(Some(SyncPhase::PreSync)),
            "an explicit ferriscd.io/operation is the escape hatch from a failed operation"
        );
        assert_eq!(fixture.cluster.creates().len(), 3);
    }

    /// A pass that *finishes* an operation must claim `Synced` even when the diff gate would now
    /// skip: the rollout has nothing left to apply, so the gate says `Skip`, but the sync is over.
    /// Re-gating on `decision.is_execute()` would leave `lastSynced*` unset (making `selfHeal:
    /// false` re-execute forever) and report `SyncSkipped` for a completed sync.
    #[tokio::test]
    async fn a_finished_operation_claims_synced_even_when_the_gate_would_skip() {
        use ferriscd_crd::status::OperationState;

        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        let sha = fixture.commit(&[
            (
                "migration.yaml",
                "apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: smoke\n  annotations:\n    ferriscd.io/sync-wave: \"-1\"\n",
            ),
            ("configmap.yaml", CONFIGMAP),
        ]);
        let mut app = fixture.app(".");
        // Manual-only: `should_sync` returns `Skip(AutomatedDisabled)` no matter what drifts, which
        // is exactly the "the gate would skip" case.
        app.spec.sync_policy = None;
        // ... and an operation that is one step away from finishing.
        app.status = Some(ApplicationStatus {
            operation_state: Some(OperationState {
                phase: OperationPhase::Running,
                sync_phase: Some(SyncPhase::PostSync),
                current_wave: 0,
                // `now`, not a fixture timestamp: the operation timeout is measured from
                // `startedAt`, so a hard-coded date would put this operation a day past its
                // deadline.
                phase_started_at: Some(now()),
                revision: Some(sha.clone()),
                active_hooks: Vec::new(),
                message: None,
                started_at: now(),
                finished_at: None,
            }),
            ..ApplicationStatus::default()
        });

        let outcome = fixture.pipeline.apply(&app).await.expect("the last step");
        assert_eq!(
            outcome.operation_state.as_ref().map(|state| state.phase),
            Some(OperationPhase::Succeeded)
        );
        assert_eq!(
            outcome.reason, REASON_SYNC_SUCCEEDED,
            "a completed operation is a sync, even on a pass the gate would skip: {}",
            outcome.message
        );
        let sync = outcome.sync.clone().expect("sync state");
        assert_eq!(sync.status, SyncStatus::Synced);
        assert_eq!(
            sync.last_synced_revision.as_deref(),
            Some(sha.as_str()),
            "the sync markers prove the commit was deployed"
        );
        assert!(sync.last_synced_spec_hash.is_some());
        assert_eq!(outcome.history.map(|history| history.len()), Some(1));
        assert!(
            fixture.cluster.applies().is_empty(),
            "nothing was left to apply"
        );
    }

    /// `T10.2` trap guard: a wave that carries a `CustomResourceDefinition` refreshes discovery
    /// before the next wave, so the custom resource of wave 0 resolves in the same operation.
    #[tokio::test]
    async fn a_crd_in_a_wave_refreshes_discovery_before_the_next_wave() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        let crd = "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: widgets.example.com\n  annotations:\n    ferriscd.io/sync-wave: \"-1\"\nspec:\n  group: example.com\n  scope: Namespaced\n  names:\n    kind: Widget\n    plural: widgets\n  versions:\n    - name: v1\n      served: true\n      storage: true\n";
        let widget = "apiVersion: example.com/v1\nkind: Widget\nmetadata:\n  name: one\n";
        fixture.commit(&[("crd.yaml", crd), ("widget.yaml", widget)]);
        let app = fixture.app(".");

        let fetches_before = fixture.discovery.fetches();
        let first = fixture.pipeline.apply(&app).await.expect("the CRD wave");
        assert_eq!(
            fixture.cluster.applies(),
            vec!["apiextensions.k8s.io/CustomResourceDefinition//widgets.example.com".to_owned()]
        );
        let fetches_after_first = fixture.discovery.fetches();
        let state = first.operation_state.clone().expect("state");
        assert_eq!(state.current_wave, -1);
        // Four refreshes in the pass that applies the CRD wave, each with a different job:
        //   1. rendering      — the Phase 11 pipeline needs a fresh `kube_version` before it
        //                       renders (T11.1/T11.4);
        //   2. `prepare`      — the bundle declares a CRD, so the snapshot is refreshed up front;
        //   3. the executor   — a CRD applied *inside* a wave must serve its kind immediately
        //                       (`T08.3`, trap T6), so the CR of the same wave can be resolved;
        //   4. the wave runner — the boundary guard (`T10.2`), which is what makes the *next* wave
        //                       resolvable and is the one this test names.
        // Removing (4) makes this number 3.
        assert_eq!(
            fetches_after_first - fetches_before,
            4,
            "the CRD wave must refresh discovery on top of the render, per-pass and executor refreshes"
        );

        // The fake API server persists an applied CRD *with* its `Established` status, so the wave is
        // healthy on the next pass without `seed_applied` (which would re-insert the status-less
        // desired body).
        let mut second_app = app.clone();
        second_app.status = Some(ApplicationStatus {
            operation_state: Some(state),
            ..app.status.clone().unwrap_or_default()
        });
        let _ = fixture
            .pipeline
            .apply(&second_app)
            .await
            .expect("the CR wave");
        assert!(
            fixture
                .cluster
                .applies()
                .contains(&"example.com/Widget/payments/one".to_owned()),
            "the CR of wave 0 must be applied, got {:?}",
            fixture.cluster.applies()
        );
        assert_eq!(
            fixture.discovery.fetches() - fetches_after_first,
            1,
            "a wave without a CRD needs only the per-pass refresh"
        );
    }

    // ---------------------------------------------------------------------
    // T10.5 — bounded history and GitOps-safe rollback
    // ---------------------------------------------------------------------

    /// Runs `count` successful single-pass syncs, each on a fresh commit, and returns
    /// `(application, sha)` pairs so a test can thread `/status` forward by hand.
    async fn synced_commits(fixture: &Fixture, contents: &[&str]) -> (Application, Vec<String>) {
        let mut app = fixture.app(".");
        let mut shas = Vec::new();
        for (index, content) in contents.iter().enumerate() {
            let sha = fixture.commit(&[(format!("configmap-{index}.yaml").as_str(), content)]);
            let outcome = fixture.pipeline.apply(&app).await.expect("a clean sync");
            let mut status = app.status.clone().unwrap_or_default();
            status.operation_state = outcome.operation_state.clone();
            status.history = outcome.history.clone().unwrap_or(status.history);
            if let Some(sync) = outcome.sync.clone() {
                status.sync = Some(sync);
            }
            status.inventory = outcome
                .inventory
                .clone()
                .map(|inventory| ferriscd_engine::inventory::to_status_entries(&inventory))
                .unwrap_or(status.inventory);
            app.status = Some(status);
            shas.push(sha);
        }
        (app, shas)
    }

    /// `T10.5`: a rollback re-deploys the historical commit, disables automation, warns the
    /// operator, consumes the request, and then **stays** on the pinned commit across requeues.
    #[tokio::test]
    async fn a_rollback_pins_the_historical_commit_and_disables_automation() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        let (mut app, shas) = synced_commits(
            &fixture,
            &[
                "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\ndata:\n  version: v1\n",
                "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\ndata:\n  version: v2\n",
            ],
        )
        .await;
        assert_eq!(shas.len(), 2);
        let history = app.status.as_ref().expect("status").history.clone();
        assert_eq!(history.len(), 2, "each commit is recorded once");
        assert_eq!(history[0].revision.as_deref(), Some(shas[1].as_str()));
        assert_eq!(history[1].id, 1);
        assert_eq!(history[1].revision.as_deref(), Some(shas[0].as_str()));

        // The operator asks for history id 1 (commit v1).
        app.annotations_mut().insert(
            annotations::OPERATION.to_owned(),
            "{\"rollback\":{\"id\":1}}".to_owned(),
        );
        let before = fixture.cluster.applies().len();
        let outcome = fixture
            .pipeline
            .apply(&app)
            .await
            .expect("the rollback pass");

        // 1. The pass rendered the *pinned* commit, not HEAD.
        let sync = outcome.sync.clone().expect("sync state");
        assert_eq!(
            sync.revision.as_deref(),
            Some(shas[0].as_str()),
            "a rollback applies history entry 1, never HEAD"
        );
        fixture.cluster.seed_applied();
        assert_eq!(
            fixture
                .cluster
                .live_pointer(CONFIGMAP_KEY, "/data/version")
                .as_deref(),
            Some("v1"),
            "the historical manifest is what reached the cluster: {:?}",
            fixture.cluster.applies()
        );
        assert!(fixture.cluster.applies().len() > before);

        // 2. Automation was disabled through a narrow spec patch, and the request consumed.
        let patches = fixture.cluster.app_patches();
        assert_eq!(
            patches.len(),
            2,
            "one spec patch, one consume patch: {patches:?}"
        );
        assert_eq!(
            patches[0],
            serde_json::json!({"spec": {"syncPolicy": {"automated": null}}}),
            "only spec.syncPolicy.automated is removed (prune/syncOptions survive)"
        );
        assert_eq!(
            patches[1],
            serde_json::json!({"metadata": {"annotations": {annotations::OPERATION: null}}}),
            "the honoured request is consumed so it cannot re-trigger forever"
        );

        // 3. The operator is told why the app is no longer following Git.
        assert_eq!(outcome.warnings.len(), 1);
        let warning = &outcome.warnings[0];
        assert_eq!(warning.type_, ferriscd_engine::sync::CONDITION_WARNING);
        assert_eq!(
            warning.reason,
            ferriscd_engine::sync::REASON_AUTOMATED_SYNC_DISABLED_BY_ROLLBACK
        );
        assert!(warning.message.contains("re-enable"), "{}", warning.message);
        assert_eq!(warning.status, ferriscd_crd::status::ConditionStatus::True);

        // 4. History records the rollback as a new deployment, idempotently.
        let history = outcome.history.clone().expect("history");
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].id, 3);
        assert_eq!(history[0].revision.as_deref(), Some(shas[0].as_str()));

        // 5. Stability across requeues: the next passes keep resolving the pinned commit even though
        //    the annotation is gone and `HEAD` moved on.
        let mut parked = app.clone();
        parked.annotations_mut().remove(annotations::OPERATION);
        // Exactly what the rollback patched: automation is gone, nothing else changed.
        parked.spec.sync_policy = None;
        let mut status = parked.status.clone().unwrap_or_default();
        status.operation_state = outcome.operation_state.clone();
        status.history = history;
        status.conditions = outcome.warnings.clone();
        parked.status = Some(status);

        let applies_before = fixture.cluster.applies().len();
        for pass in 0..3 {
            let outcome = fixture
                .pipeline
                .apply(&parked)
                .await
                .expect("a parked rollback is not an error");
            assert_eq!(
                outcome.sync.as_ref().and_then(|sync| sync.revision.clone()),
                Some(shas[0].to_owned()),
                "pass {pass}: the pinned revision must not flip back to HEAD"
            );
            assert_eq!(
                outcome.reason, REASON_SYNC_SKIPPED,
                "pass {pass}: automation is off, so nothing is applied"
            );
            assert!(outcome.history.is_none(), "no new deployment to record");
            // Mirror `apply_outcome_status`: a field the pass did not report is left untouched, so
            // the terminal operation (and therefore the pinned revision) survives a skipped pass.
            let previous = parked.status.clone().unwrap_or_default();
            parked.status = Some(ApplicationStatus {
                operation_state: outcome
                    .operation_state
                    .clone()
                    .or(previous.operation_state.clone()),
                sync: outcome.sync.clone().or(previous.sync.clone()),
                ..previous
            });
        }
        assert_eq!(
            fixture.cluster.applies().len(),
            applies_before,
            "a parked rollback issues no mutating apply"
        );
        assert!(
            fixture.cluster.app_patches().len() == 2,
            "the spec is not patched again once it is manual-only"
        );
    }

    /// Re-enabling automation clears the warning and lets `HEAD` win again (finding M-4).
    #[tokio::test]
    async fn re_enabling_automation_clears_the_rollback_warning() {
        let mut status = ApplicationStatus::default();
        status.set_condition(ferriscd_crd::status::Condition::new(
            ferriscd_engine::sync::CONDITION_WARNING,
            ferriscd_crd::status::ConditionStatus::True,
            ferriscd_engine::sync::REASON_AUTOMATED_SYNC_DISABLED_BY_ROLLBACK,
            "rollback disabled automation",
            at("2026-11-24T12:00:00Z"),
        ));
        status.set_condition(ferriscd_crd::status::Condition::ready(
            ferriscd_crd::status::ConditionStatus::True,
            ferriscd_crd::status::CONDITION_READY,
            "ready",
            at("2026-11-24T12:00:00Z"),
        ));
        assert_eq!(status.conditions.len(), 2);

        let mut app = application("https://example.com/repo.git", ".", "payments");
        // Manual-only, exactly as a rollback leaves it: the warning stands, because the rollback is
        // still what pins the revision to the historical commit.
        app.spec.sync_policy = None;
        assert!(
            !ferriscd_engine::sync::clear_rollback_warning_if_automation_reenabled(
                &app.spec,
                &mut status
            )
        );
        assert_eq!(status.conditions.len(), 2);

        app.spec.sync_policy = Some(self_heal_policy());
        assert!(
            ferriscd_engine::sync::clear_rollback_warning_if_automation_reenabled(
                &app.spec,
                &mut status
            )
        );
        assert_eq!(status.conditions.len(), 1);
        assert!(
            status
                .condition(ferriscd_engine::sync::CONDITION_WARNING)
                .is_none(),
            "the stale warning is gone"
        );
        assert!(
            status
                .condition(ferriscd_crd::status::CONDITION_READY)
                .is_some(),
            "the Ready condition is untouched"
        );

        // The same clearing happens on a real pass (`apply_once` drives it), so an operator who
        // re-enables automation never has to delete the warning by hand.
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);
        let app_with_warning = {
            let mut app = fixture.app(".");
            app.status = Some(status);
            app
        };
        let writer = RecordingStatus::default();
        let _ = apply_once(&app_with_warning, &fixture.pipeline, &writer).await;
        let written = writer.last().expect("the pass writes the status");
        assert!(
            written.conditions.iter().all(|condition| condition.reason
                != ferriscd_engine::sync::REASON_AUTOMATED_SYNC_DISABLED_BY_ROLLBACK),
            "automation is on, so the rollback warning must not survive the pass: {:?}",
            written.conditions
        );
    }

    /// A rollback to a history id that does not exist is terminal: guessing would redeploy the
    /// wrong commit, and retrying can never succeed.
    #[tokio::test]
    async fn an_unknown_rollback_id_is_terminal_and_mutates_nothing() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);
        let mut app = fixture.app(".");
        app.annotations_mut().insert(
            annotations::OPERATION.to_owned(),
            "{\"rollback\":{\"id\":7}}".to_owned(),
        );

        let err = fixture
            .pipeline
            .apply(&app)
            .await
            .expect_err("an unknown history id cannot be rolled back to");
        assert_eq!(err.failure_class(), crate::FailureClass::Terminal);
        assert!(
            err.to_string()
                .contains("no status.history entry with id 7"),
            "{err}"
        );
        assert!(fixture.cluster.applies().is_empty());
        assert!(fixture.cluster.app_patches().is_empty());
    }

    /// `{"sync":{...}}` (and any other non-rollback operation) stays a manual sync request — and a
    /// settled one consumes its own annotation, never touching `spec` (finding `P14-C1`).
    #[tokio::test]
    async fn a_non_rollback_operation_annotation_is_a_manual_sync() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);
        let mut app = fixture.app(".");
        // A manual-only application: without the annotation the gate would skip.
        app.spec.sync_policy = None;
        app.annotations_mut().insert(
            annotations::OPERATION.to_owned(),
            "{\"sync\":{}}".to_owned(),
        );

        let outcome = fixture.pipeline.apply(&app).await.expect("a manual sync");
        assert_eq!(
            fixture.cluster.applies(),
            vec![CONFIGMAP_KEY.to_owned()],
            "a manual operation applies the desired set"
        );
        assert!(outcome.warnings.is_empty());
        assert_eq!(
            fixture.cluster.app_patches(),
            vec![serde_json::json!({"metadata": {"annotations": {annotations::OPERATION: null}}})],
            "a manual sync consumes its annotation and never patches the spec"
        );
    }

    /// **Finding `P14-C1`:** a settled manual sync clears its own `ferriscd.io/operation`, so the
    /// manual escape hatch cannot stay switched on. The next pass therefore obeys `automated: None`
    /// again — `Skip(AutomatedDisabled)` — and a later sync/rollback request is not a conflict.
    ///
    /// Non-vacuous: the same application *with* the annotation is asserted to apply (the pass
    /// above), and the second pass is asserted to write no annotation patch of its own.
    #[tokio::test]
    async fn a_settled_manual_sync_consumes_its_annotation_and_the_next_pass_skips() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);
        let mut app = fixture.app(".");
        app.spec.sync_policy = None;
        app.metadata.annotations = Some(operation_annotation());
        assert!(
            manual_operation(&app),
            "the fixture must really carry a pending request"
        );

        let (err, status) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_none(), "{err:?}");
        assert_eq!(
            fixture.cluster.applies(),
            vec![CONFIGMAP_KEY.to_owned()],
            "the pending request is honoured once"
        );
        assert_eq!(
            fixture.cluster.app_patches(),
            vec![serde_json::json!({"metadata": {"annotations": {annotations::OPERATION: null}}})],
            "a settled manual sync consumes the annotation: {:#?}",
            fixture.cluster.app_patches()
        );
        assert_eq!(ready(&status).reason, REASON_SYNC_SUCCEEDED);

        // Exactly what the consume patch left behind: no annotation, automation still off.
        app.metadata.annotations = None;
        assert!(!manual_operation(&app));
        let applies_before = fixture.cluster.applies().len();
        let patches_before = fixture.cluster.app_patches().len();
        let (err, status) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_none(), "{err:?}");
        let condition = ready(&status);
        assert_eq!(
            condition.reason, REASON_SYNC_SKIPPED,
            "with the request consumed, automated: None decides again: {condition:?}"
        );
        assert!(
            condition.message.contains("automated sync is disabled"),
            "the skip reason must be `AutomatedDisabled`, not a drift-free pass: {}",
            condition.message
        );
        assert_eq!(
            fixture.cluster.applies().len(),
            applies_before,
            "a skipped pass applies nothing"
        );
        assert_eq!(
            fixture.cluster.app_patches().len(),
            patches_before,
            "and it has no annotation left to consume"
        );
    }

    /// The consume is a **settled**-pass event: a pass that fails (here: the destination cluster
    /// refuses the apply) must leave the request in place, or the retried reconcile would silently
    /// turn into a skipped one.
    #[tokio::test]
    async fn an_unsettled_manual_sync_keeps_its_annotation() {
        let fixture = fixture(
            FakeCluster::default()
                .with_namespace("payments")
                .fail_apply_retryably(CONFIGMAP_KEY),
        );
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);
        let mut app = fixture.app(".");
        app.spec.sync_policy = None;
        app.metadata.annotations = Some(operation_annotation());

        let (err, _) = reconcile_pass(&fixture, &mut app).await;
        assert!(
            matches!(err, Some(ReconcileError::PartialSync { .. })),
            "the retryable failure must surface: {err:?}"
        );
        assert!(
            fixture.cluster.app_patches().is_empty(),
            "a failed pass must not consume the request: {:?}",
            fixture.cluster.app_patches()
        );
        assert!(
            manual_operation(&app),
            "the request is still pending after the failure"
        );
    }

    #[tokio::test]
    async fn a_kind_the_cluster_does_not_serve_fails_terminally() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[(
            "ingress.yaml",
            "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: web\n",
        )]);
        let app = fixture.app(".");

        let err = fixture
            .pipeline
            .apply(&app)
            .await
            .expect_err("unserved kind");
        assert!(
            matches!(err, ReconcileError::Scope(_)),
            "an unknown scope must fail before any apply: {err}"
        );
        assert!(fixture.cluster.applies().is_empty());
    }

    // ---------------------------------------------------------------------
    // Cleanup
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn orphan_cleanup_deletes_nothing() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        let mut app = fixture.app(".");
        app.status = Some(status_with_inventory(&["/ConfigMap/payments/settings"]));

        let outcome = fixture
            .pipeline
            .cleanup(&app, CleanupMode::Orphan)
            .await
            .expect("orphan cleanup");
        assert_eq!(outcome, CleanupOutcome::Completed);
        assert!(fixture.cluster.deletes().is_empty());
    }

    #[tokio::test]
    async fn cascade_cleanup_deletes_only_owned_inventory_entries() {
        let owned = config_map(
            "settings",
            Some("ferriscd-system/payments:/ConfigMap:payments/settings"),
        );
        let foreign = config_map(
            "other",
            Some("ferriscd-system/other:/ConfigMap:payments/other"),
        );
        let fixture = fixture(
            FakeCluster::default()
                .with_namespace("payments")
                .with_object(owned)
                .with_object(foreign),
        );
        let mut app = fixture.app(".");
        app.status = Some(status_with_inventory(&[
            "/ConfigMap/payments/settings",
            "/ConfigMap/payments/other",
        ]));

        let outcome = fixture
            .pipeline
            .cleanup(&app, CleanupMode::Cascade)
            .await
            .expect("cascade cleanup");
        assert_eq!(outcome, CleanupOutcome::Completed);
        assert_eq!(
            fixture.cluster.deletes(),
            vec!["/ConfigMap/payments/settings".to_owned()],
            "only OwnedBySelf entries may be deleted"
        );
    }

    /// **Finding H2(a):** the cascade deletes as the `Application`'s own ServiceAccount, not as
    /// the controller. Reverting the cleanup path to the controller identity empties
    /// [`Fixture::identities`] and fails the last assertion.
    #[tokio::test]
    async fn a_cascade_deletes_as_the_impersonated_service_account() {
        let owned = config_map(
            "settings",
            Some("team-a/payments:/ConfigMap:payments/settings"),
        );
        let fixture = fixture_with_policy(
            FakeCluster::default()
                .with_namespace("payments")
                .with_object(owned),
            FakeProjectSource::default().with_project(tenant_project()),
            tenant_scope(&["team-a"]),
        );
        let mut app = tenant_application(&fixture, "team-a", Some("deployer"));
        app.status = Some(status_with_inventory(&["/ConfigMap/payments/settings"]));

        let outcome = fixture
            .pipeline
            .cleanup(&app, CleanupMode::Cascade)
            .await
            .expect("an authorized tenant cascade");
        assert_eq!(outcome, CleanupOutcome::Completed);
        assert_eq!(
            fixture.cluster.deletes(),
            vec!["/ConfigMap/payments/settings".to_owned()],
            "the tracked object must be pruned through the pass's own applier"
        );
        assert_eq!(
            fixture.identities(),
            vec!["system:serviceaccount:payments:deployer".to_owned()],
            "the cascade must resolve the tenant's ServiceAccount: deleting with the controller's \
             identity is exactly the privilege escalation finding H1/H2(a) is about"
        );
    }

    /// **Finding H1 + H2(b):** a tenant can retarget `spec.serviceAccountName` and then delete the
    /// `Application`. The cascade must refuse an identity the project does not allow — *before*
    /// resolving (and therefore before building) that impersonated client — and retain the
    /// finalizer, with `ferriscd.io/force-delete` as the documented escape hatch.
    #[tokio::test]
    async fn a_cascade_with_an_unauthorized_service_account_retains_the_finalizer() {
        let owned = config_map(
            "settings",
            Some("team-a/payments:/ConfigMap:payments/settings"),
        );
        let fixture = fixture_with_policy(
            FakeCluster::default()
                .with_namespace("payments")
                .with_object(owned),
            FakeProjectSource::default().with_project(tenant_project()),
            tenant_scope(&["team-a"]),
        );
        // The project lists `payments/deployer` only; this is the retargeted identity.
        let mut app = tenant_application(&fixture, "team-a", Some("root-sa"));
        app.status = Some(status_with_inventory(&["/ConfigMap/payments/settings"]));

        let err = fixture
            .pipeline
            .cleanup(&app, CleanupMode::Cascade)
            .await
            .expect_err("an unauthorized ServiceAccount must never be used for a cascade");
        assert!(
            err.to_string().contains("root-sa"),
            "the denial must name the refused ServiceAccount: {err}"
        );
        assert!(
            err.to_string().contains("allowedServiceAccounts"),
            "the denial must name the field to fix: {err}"
        );
        assert_eq!(
            err.failure_class(),
            crate::FailureClass::Terminal,
            "no retry can authorize the identity"
        );
        assert_eq!(
            crate::reconcile::failure_reason(&err),
            crate::reconcile::REASON_POLICY_VIOLATION
        );
        // Ordering is policy → identity (finding H2b): no access bundle, no client, no delete.
        assert!(
            fixture.identities().is_empty(),
            "an unauthorized ServiceAccount must be rejected before any impersonated access is \
             resolved: {:?}",
            fixture.identities()
        );
        assert!(
            fixture.cluster.deletes().is_empty(),
            "nothing may be deleted by an unauthorized identity: {:?}",
            fixture.cluster.deletes()
        );
        assert!(matches!(
            err,
            ReconcileError::Policy(PolicyError::ServiceAccountNotAllowed { .. })
        ));

        // The finalizer is retained unless the operator forces the deletion.
        let denied = || {
            ReconcileError::Policy(PolicyError::ServiceAccountNotAllowed {
                application: "team-a/payments".to_owned(),
                project: "payments".to_owned(),
                namespace: "payments".to_owned(),
                service_account: "root-sa".to_owned(),
            })
        };
        match crate::reconcile::cleanup_disposition(&app, Err(denied())) {
            crate::CleanupDisposition::Retain { error } => assert!(matches!(
                error,
                ReconcileError::Policy(PolicyError::ServiceAccountNotAllowed { .. })
            )),
            other => panic!("a denied identity must retain the finalizer, got {other:?}"),
        }
        let mut forced = app.clone();
        forced
            .annotations_mut()
            .insert(annotations::FORCE_DELETE.to_owned(), "true".to_owned());
        match crate::reconcile::cleanup_disposition(&forced, Err(denied())) {
            crate::CleanupDisposition::Release { warning } => {
                let warning = warning.expect("a forced release must be warned about");
                assert!(warning.contains(annotations::FORCE_DELETE), "{warning}");
                assert!(warning.contains("root-sa"), "{warning}");
            }
            other => panic!("force-delete must release the finalizer, got {other:?}"),
        }
    }

    // ---------------------------------------------------------------------
    // Phase 07 diff gate (T07.5)
    // ---------------------------------------------------------------------

    /// `/status` writer that records patches instead of calling the API server.
    #[derive(Default)]
    struct RecordingStatus {
        patches: StdMutex<Vec<ApplicationStatus>>,
    }

    impl RecordingStatus {
        fn last(&self) -> Option<ApplicationStatus> {
            self.patches.lock().unwrap().last().cloned()
        }
    }

    impl StatusWriter for RecordingStatus {
        fn patch<'a>(
            &'a self,
            _app: &'a Application,
            status: ApplicationStatus,
        ) -> BoxFuture<'a, Result<(), ReconcileError>> {
            Box::pin(async move {
                self.patches.lock().unwrap().push(status);
                Ok(())
            })
        }
    }

    /// Runs one full reconcile the way the controller does.
    ///
    /// The real [`apply_once`] wrapper is used (so the always-update-status contract, the
    /// `lastSynced*` merge and the failure-path inventory persistence are all exercised), the
    /// just-applied objects become live (modelling the API server write), and the persisted
    /// `/status` becomes `app.status` for the next pass.
    async fn reconcile_pass(
        fixture: &Fixture,
        app: &mut Application,
    ) -> (Option<ReconcileError>, Option<ApplicationStatus>) {
        let writer = RecordingStatus::default();
        let result = apply_once(app, &fixture.pipeline, &writer).await;
        fixture.cluster.seed_applied();
        let status = writer.last();
        app.status = status.clone();
        (result.err(), status)
    }

    /// The `Ready` condition of a persisted status.
    fn ready(status: &Option<ApplicationStatus>) -> Condition {
        status
            .as_ref()
            .expect("the pass must persist /status")
            .condition(CONDITION_READY)
            .expect("every reconcile sets Ready")
            .clone()
    }

    /// The `sync` block of a persisted status.
    fn sync_state(status: &Option<ApplicationStatus>) -> SyncState {
        status
            .as_ref()
            .expect("the pass must persist /status")
            .sync
            .clone()
            .expect("the pass must persist status.sync")
    }

    fn operation_annotation() -> BTreeMap<String, String> {
        BTreeMap::from([(
            annotations::OPERATION.to_owned(),
            r#"{"sync":{"revision":"main"}}"#.to_owned(),
        )])
    }

    /// Manual-operation detection is one pure helper (T07.4's `manual_op` input).
    #[test]
    fn manual_operations_are_detected_from_the_operation_annotation() {
        let mut app = application("https://example.com/repo.git", ".", "payments");
        assert!(
            !manual_operation(&app),
            "no annotation, no manual operation"
        );

        app.metadata.annotations = Some(BTreeMap::from([(
            annotations::REFRESH.to_owned(),
            "1712345678".to_owned(),
        )]));
        assert!(
            !manual_operation(&app),
            "a refresh only asks for a reconcile; the diff gate still decides"
        );

        app.metadata
            .annotations
            .as_mut()
            .unwrap()
            .insert(annotations::OPERATION.to_owned(), "   ".to_owned());
        assert!(
            !manual_operation(&app),
            "a blank operation is not a request"
        );

        app.metadata.annotations.as_mut().unwrap().insert(
            annotations::OPERATION.to_owned(),
            r#"{"sync":{}}"#.to_owned(),
        );
        assert!(manual_operation(&app));
    }

    /// The headline T07.5 invariant: an already-synced `Application` performs **zero** mutating
    /// `Patch` calls, while the diff still dry-runs every present resource.
    #[tokio::test]
    async fn a_second_reconcile_of_a_synced_application_performs_zero_applies() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        let sha = fixture.commit(&[
            ("configmap.yaml", CONFIGMAP),
            ("deployment.yaml", DEPLOYMENT),
        ]);
        let mut app = fixture.app(".");

        let (err, status) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_none(), "first pass must sync: {err:?}");
        assert_eq!(
            fixture.cluster.applies(),
            vec![CONFIGMAP_KEY.to_owned(), DEPLOYMENT_KEY.to_owned()],
            "a first pass creates the whole desired set in tier order"
        );
        let sync = sync_state(&status);
        assert_eq!(sync.status, SyncStatus::Synced);
        assert_eq!(sync.last_synced_revision.as_deref(), Some(sha.as_str()));
        let spec_hash = source_spec_hash(&app.spec).expect("spec hash");
        assert_eq!(
            sync.last_synced_spec_hash.as_deref(),
            Some(spec_hash.as_str())
        );
        assert!(sync.last_synced_at.is_some());
        assert_eq!(ready(&status).reason, REASON_SYNC_SUCCEEDED);

        // Second reconcile: the cluster already matches Git, so nothing may be patched.
        let applies_before = fixture.cluster.applies().len();
        let mutating_before = fixture.pipeline.mutating_applies();
        let dry_runs_before = fixture.dry_run.calls().len();

        let (err, status) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_none(), "the second pass must succeed: {err:?}");

        assert_eq!(
            fixture.cluster.applies().len(),
            applies_before,
            "an already-synced Application must issue zero mutating Patch calls"
        );
        assert_eq!(
            fixture.pipeline.mutating_applies(),
            mutating_before,
            "the pipeline must not count (or issue) a mutating apply"
        );
        assert!(
            fixture.dry_run.calls().len() > dry_runs_before,
            "the diff still dry-runs every present resource (dryRun PATCHes are expected)"
        );
        assert!(
            fixture
                .dry_run
                .calls()
                .iter()
                .any(|key| key == CONFIGMAP_KEY),
            "the ConfigMap must have been classified: {:?}",
            fixture.dry_run.calls()
        );

        let condition = ready(&status);
        assert_eq!(condition.reason, REASON_SYNC_SKIPPED);
        assert!(
            condition.message.contains("already matches Git"),
            "{}",
            condition.message
        );
        let sync = sync_state(&status);
        assert_eq!(sync.status, SyncStatus::Synced);
        assert_eq!(
            sync.last_synced_revision.as_deref(),
            Some(sha.as_str()),
            "a skipped pass must not move the last successful sync markers"
        );
        assert_eq!(
            sync.last_synced_spec_hash.as_deref(),
            Some(spec_hash.as_str())
        );
    }

    /// Drift is healed, and only the drifted resource is re-applied (`applyOutOfSyncOnly`).
    #[tokio::test]
    async fn drift_heals_only_the_drifted_resource() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[
            ("configmap.yaml", CONFIGMAP),
            ("deployment.yaml", DEPLOYMENT),
        ]);
        let mut app = fixture.app(".");
        let (err, _) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_none(), "{err:?}");

        // Somebody edits the live ConfigMap: live state no longer matches Git.
        fixture.cluster.drift(CONFIGMAP_KEY, |object| {
            object.data["data"]["key"] = json!("tampered");
        });
        let applies_before = fixture.cluster.applies().len();

        let (err, status) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_none(), "{err:?}");
        assert_eq!(
            fixture.cluster.applies()[applies_before..],
            [CONFIGMAP_KEY.to_owned()],
            "only the drifted ConfigMap may be re-applied, never the synced Deployment"
        );
        let condition = ready(&status);
        assert_eq!(condition.reason, REASON_SYNC_SUCCEEDED);
        assert!(
            condition.message.contains("driftDetected"),
            "the trigger must be reported: {}",
            condition.message
        );
        assert!(
            condition.message.contains("applied 1 of 2"),
            "{}",
            condition.message
        );
        assert_eq!(sync_state(&status).status, SyncStatus::Synced);
    }

    /// `selfHeal: false` + unchanged `(revision, spec hash)` ⇒ `Skip(SelfHealDisabled)`, zero
    /// applies, and the drift is still reported as `OutOfSync`.
    #[tokio::test]
    async fn self_heal_disabled_skips_drift_without_applying() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        let sha = fixture.commit(&[
            ("configmap.yaml", CONFIGMAP),
            ("deployment.yaml", DEPLOYMENT),
        ]);
        let mut app = fixture.app(".");
        app.spec.sync_policy = Some(source_only_policy());

        // The first pass has no `lastSyncedRevision`, so it syncs (source "changed").
        let (err, status) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_none(), "{err:?}");
        assert_eq!(
            sync_state(&status).last_synced_revision.as_deref(),
            Some(sha.as_str())
        );

        fixture.cluster.drift(CONFIGMAP_KEY, |object| {
            object.data["data"]["key"] = json!("tampered");
        });
        let applies_before = fixture.cluster.applies().len();

        let (err, status) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_none(), "{err:?}");
        assert_eq!(
            fixture.cluster.applies().len(),
            applies_before,
            "selfHeal: false must never apply drift"
        );
        let condition = ready(&status);
        assert_eq!(condition.reason, REASON_SYNC_SKIPPED);
        assert!(
            condition.message.contains("self-heal is disabled"),
            "{}",
            condition.message
        );
        let sync = sync_state(&status);
        assert_eq!(
            sync.status,
            SyncStatus::OutOfSync,
            "a skipped-but-drifting application must be reported OutOfSync"
        );
        assert_eq!(
            sync.revision.as_deref(),
            Some(sha.as_str()),
            "the observed revision is still recorded"
        );
        assert_eq!(
            sync.last_synced_revision.as_deref(),
            Some(sha.as_str()),
            "a skip must not move the last successful sync"
        );
    }

    // ---------------------------------------------------------------------
    // Findings H1/H2: what `/status` says about ignored pointers and orphans
    // ---------------------------------------------------------------------

    /// Finding H1: an `ignoreDifferences` pointer that is not valid RFC 6901 is never applied
    /// (a typo must not fail a reconcile), so it must be *visible* in `Application.status` —
    /// otherwise the operator believes a field is ignored while it keeps reporting drift.
    #[tokio::test]
    async fn an_invalid_ignore_pointer_is_reported_in_the_ready_message() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[("configmap.yaml", CONFIGMAP_WITH_DATA)]);
        let mut app = fixture.app(".");
        let (err, _) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_none(), "{err:?}");

        // `spec/replicaz` has no leading `/`, so it is not an RFC 6901 pointer at all. The second
        // entry *is* valid and simply names a field this object does not have: that is the
        // documented no-op, so it must not be counted as invalid.
        app.spec.ignore_differences = vec![ferriscd_crd::IgnoreDifference {
            kind: "ConfigMap".to_owned(),
            json_pointers: vec!["spec/replicaz".to_owned(), "/spec/replicaz".to_owned()],
            ..ferriscd_crd::IgnoreDifference::default()
        }];
        fixture.cluster.drift(CONFIGMAP_KEY, |object| {
            object.data["data"]["key"] = json!("tampered");
        });
        let applies_before = fixture.cluster.applies().len();

        let (err, status) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_none(), "{err:?}");

        let condition = ready(&status);
        assert!(
            condition
                .message
                .contains("1 invalid ignoreDifferences pointer ignored"),
            "the ignored typo must be visible on the CR: {}",
            condition.message
        );
        assert_eq!(
            fixture.cluster.applies()[applies_before..],
            [CONFIGMAP_KEY.to_owned()],
            "the typo must not suppress the drift it names (it is not applied)"
        );

        // A valid pointer really is honoured, so the count is about validity, not about the
        // pointer happening not to resolve.
        app.spec.ignore_differences = vec![ferriscd_crd::IgnoreDifference {
            kind: "ConfigMap".to_owned(),
            json_pointers: vec!["/data/key".to_owned()],
            ..ferriscd_crd::IgnoreDifference::default()
        }];
        fixture.cluster.drift(CONFIGMAP_KEY, |object| {
            object.data["data"]["key"] = json!("tampered-again");
        });
        let applies_before = fixture.cluster.applies().len();
        let (err, status) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_none(), "{err:?}");
        assert_eq!(
            fixture.cluster.applies().len(),
            applies_before,
            "the ignored field must not be re-applied"
        );
        assert!(
            !ready(&status).message.contains("invalid ignoreDifferences"),
            "a valid pointer must not be reported as invalid: {}",
            ready(&status).message
        );
    }

    /// Finding H2 (a): a `Skip` pass with `prune: false` must reach the same verdict as the
    /// executing pass before it — `Synced` — while still naming the retained orphan. Otherwise
    /// removing a resource from Git with pruning disabled pins `OutOfSync` forever (T06 contract).
    #[tokio::test]
    async fn a_skip_pass_with_prune_disabled_reports_retained_orphans_as_synced() {
        let orphan = config_map(
            "removed",
            Some("ferriscd-system/payments:/ConfigMap:payments/removed"),
        );
        let fixture = fixture(
            FakeCluster::default()
                .with_namespace("payments")
                .with_object(orphan),
        );
        let sha = fixture.commit(&[("configmap.yaml", CONFIGMAP)]);
        let mut app = fixture.app(".");
        app.spec.sync_policy = Some(source_only_policy());

        let (err, status) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_none(), "{err:?}");
        assert_eq!(sync_state(&status).status, SyncStatus::Synced);

        // Git no longer declares a tracked resource; `prune: false` means it stays.
        app.status
            .as_mut()
            .expect("the first pass persists /status")
            .inventory
            .push(ferriscd_crd::InventoryEntry::new(
                "/ConfigMap/payments/removed",
                "v1",
            ));

        let (err, status) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_none(), "{err:?}");

        let sync = sync_state(&status);
        assert_eq!(
            sync.status,
            SyncStatus::Synced,
            "a retained orphan must never pin OutOfSync when pruning is disabled"
        );
        assert_eq!(
            sync.last_synced_revision.as_deref(),
            Some(sha.as_str()),
            "a skipped pass must not move the markers"
        );
        let condition = ready(&status);
        assert_eq!(condition.reason, REASON_SYNC_SKIPPED);
        assert!(
            condition.message.contains("1 orphan(s) retained"),
            "the retained orphan must be visible: {}",
            condition.message
        );
        assert!(
            fixture.cluster.deletes().is_empty(),
            "a skipped pass issues no deletes"
        );
    }

    /// Finding H2 (b): with pruning **enabled** the engine reading stands — the orphan is a prune
    /// that is still due, so the skip pass reports `OutOfSync`. It still deletes nothing: only an
    /// executing pass prunes (M1).
    #[tokio::test]
    async fn a_skip_pass_with_prune_enabled_reports_an_orphan_out_of_sync_without_deleting() {
        let orphan = config_map(
            "removed",
            Some("ferriscd-system/payments:/ConfigMap:payments/removed"),
        );
        let fixture = fixture(
            FakeCluster::default()
                .with_namespace("payments")
                .with_object(orphan),
        );
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);
        let mut app = fixture.app(".");
        app.spec.sync_policy = Some(SyncPolicy {
            automated: Some(AutomatedSyncPolicy {
                prune: true,
                self_heal: false,
            }),
            sync_options: None,
            retry: None,
        });

        let (err, status) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_none(), "{err:?}");
        assert_eq!(sync_state(&status).status, SyncStatus::Synced);

        app.status
            .as_mut()
            .expect("the first pass persists /status")
            .inventory
            .push(ferriscd_crd::InventoryEntry::new(
                "/ConfigMap/payments/removed",
                "v1",
            ));

        let (err, status) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_none(), "{err:?}");

        assert_eq!(
            sync_state(&status).status,
            SyncStatus::OutOfSync,
            "with pruning enabled an orphan is a prune that is still due"
        );
        assert_eq!(ready(&status).reason, REASON_SYNC_SKIPPED);
        assert!(
            fixture.cluster.deletes().is_empty(),
            "a skip decision must never issue a delete, even with prune enabled"
        );
    }

    /// Finding H2 (c): the existing T06 contract on an executing pass — `prune: false` plus a
    /// live orphan reports `Synced` *and* names the retained orphan.
    #[tokio::test]
    async fn an_executing_pass_with_prune_disabled_reports_retained_orphans_as_synced() {
        let orphan = config_map(
            "removed",
            Some("ferriscd-system/payments:/ConfigMap:payments/removed"),
        );
        let fixture = fixture(
            FakeCluster::default()
                .with_namespace("payments")
                .with_object(orphan),
        );
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);
        let mut app = fixture.app(".");
        assert!(app.spec.sync_policy.as_ref().is_some_and(|policy| {
            policy
                .automated
                .as_ref()
                .is_some_and(|automated| !automated.prune)
        }));

        let (err, _) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_none(), "{err:?}");

        app.status
            .as_mut()
            .expect("the first pass persists /status")
            .inventory
            .push(ferriscd_crd::InventoryEntry::new(
                "/ConfigMap/payments/removed",
                "v1",
            ));
        // Something must still need applying, otherwise the gate would skip (H2 a).
        fixture.cluster.drift(CONFIGMAP_KEY, |object| {
            object.data["data"]["key"] = json!("tampered");
        });

        let (err, status) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_none(), "{err:?}");
        assert_eq!(
            sync_state(&status).status,
            SyncStatus::Synced,
            "an executing pass that finished every resource reports Synced"
        );
        assert!(
            ready(&status).message.contains("1 orphan(s) retained"),
            "the retained orphan must be reported: {}",
            ready(&status).message
        );
        assert!(fixture.cluster.deletes().is_empty());
    }

    /// A pass the gate **skipped** still reports the orphans it may never delete: a foreign or
    /// unmanaged orphan used to count as zero on a skipped pass, which made a permanent conflict
    /// look like "nothing to retain".
    #[tokio::test]
    async fn a_skipped_pass_still_reports_foreign_and_unmanaged_orphans() {
        let foreign = config_map(
            "foreign",
            Some("ferriscd-system/other:/ConfigMap:payments/foreign"),
        );
        let unmanaged = config_map("unmanaged", None);
        let fixture = fixture(
            FakeCluster::default()
                .with_namespace("payments")
                .with_object(foreign)
                .with_object(unmanaged),
        );
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);
        let mut app = fixture.app(".");
        // `automated: None`: the gate never executes, so nothing is applied and nothing is pruned.
        // The two orphans are still *retained*, and that must be visible in `/status`.
        app.spec.sync_policy = None;
        app.status = Some(ApplicationStatus {
            inventory: vec![
                ferriscd_crd::InventoryEntry::new("/ConfigMap/payments/foreign", "v1"),
                ferriscd_crd::InventoryEntry::new("/ConfigMap/payments/unmanaged", "v1"),
            ],
            ..ApplicationStatus::default()
        });

        let outcome = fixture
            .pipeline
            .apply(&app)
            .await
            .expect("a skipped pass is not an error");

        assert_eq!(outcome.reason, REASON_SYNC_SKIPPED, "{}", outcome.message);
        assert!(
            outcome.message.contains("2 orphan(s) retained"),
            "both orphans must be reported on a skipped pass: {}",
            outcome.message
        );
        assert!(
            fixture.cluster.deletes().is_empty(),
            "a skipped pass deletes nothing"
        );
        assert!(
            outcome
                .inventory
                .expect("inventory is always reported")
                .len()
                == 2,
            "the retained orphans stay tracked"
        );
    }

    /// Finding H7: a `spec.source.git.path` edit produces no new commit, so `selfHeal: false`
    /// must key off `lastSyncedSpecHash` and sync anyway.
    #[tokio::test]
    async fn a_spec_path_edit_with_an_unchanged_revision_executes_a_sync() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        let sha = fixture.commit(&[
            ("deploy/deployment.yaml", DEPLOYMENT),
            ("config/configmap.yaml", CONFIGMAP),
        ]);
        let mut app = fixture.app("deploy");
        app.spec.sync_policy = Some(source_only_policy());

        let (err, status) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_none(), "{err:?}");
        assert_eq!(
            fixture.cluster.applies(),
            vec![DEPLOYMENT_KEY.to_owned()],
            "only the deploy/ directory is desired by the first pass"
        );
        let old_hash = sync_state(&status)
            .last_synced_spec_hash
            .expect("the first pass persists the spec hash");

        // The operator points the Application at a different directory in the *same* commit.
        app.spec.source.git.path = "config".to_owned();
        let new_hash = source_spec_hash(&app.spec).expect("spec hash");
        assert_ne!(old_hash, new_hash, "a path edit must change the hash");

        let applies_before = fixture.cluster.applies().len();
        let (err, status) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_none(), "{err:?}");
        assert_eq!(
            fixture.cluster.applies()[applies_before..],
            [CONFIGMAP_KEY.to_owned()],
            "the newly desired ConfigMap must be applied"
        );
        let condition = ready(&status);
        assert_eq!(condition.reason, REASON_SYNC_SUCCEEDED);
        assert!(
            condition.message.contains("sourceChanged"),
            "the spec hash change is the trigger: {}",
            condition.message
        );
        let sync = sync_state(&status);
        assert_eq!(
            sync.revision.as_deref(),
            Some(sha.as_str()),
            "the commit SHA did not change; only the spec did"
        );
        assert_eq!(
            sync.last_synced_spec_hash.as_deref(),
            Some(new_hash.as_str())
        );
        assert_eq!(sync.status, SyncStatus::Synced);
    }

    /// `automated: None` reports drift but never applies it; a manual operation overrides it.
    #[tokio::test]
    async fn a_manual_operation_annotation_executes_a_manual_sync() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);
        let mut app = fixture.app(".");
        app.spec.sync_policy = None;

        let (err, status) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_none(), "{err:?}");
        assert!(
            fixture.cluster.applies().is_empty(),
            "automated: None must never apply automatically"
        );
        let condition = ready(&status);
        assert_eq!(condition.reason, REASON_SYNC_SKIPPED);
        assert!(
            condition.message.contains("automated sync is disabled"),
            "{}",
            condition.message
        );
        let sync = sync_state(&status);
        assert_eq!(sync.status, SyncStatus::OutOfSync);
        assert!(
            sync.last_synced_revision.is_none(),
            "nothing was deployed, so no sync marker may be written"
        );

        // The CLI/API requests a sync through the operation annotation.
        app.metadata.annotations = Some(operation_annotation());
        let (err, status) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_none(), "{err:?}");
        assert_eq!(
            fixture.cluster.applies(),
            vec![CONFIGMAP_KEY.to_owned()],
            "a manual operation bypasses `automated: None`"
        );
        let condition = ready(&status);
        assert_eq!(condition.reason, REASON_SYNC_SUCCEEDED);
        assert!(
            condition.message.contains("manual"),
            "the trigger must be reported: {}",
            condition.message
        );
        let sync = sync_state(&status);
        assert_eq!(sync.status, SyncStatus::Synced);
        assert!(sync.last_synced_revision.is_some());
        assert!(sync.last_synced_spec_hash.is_some());
    }

    /// `applyOutOfSyncOnly: false` re-applies resources the diff already considers synced.
    #[tokio::test]
    async fn apply_out_of_sync_only_false_applies_synced_resources_too() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[
            ("configmap.yaml", CONFIGMAP),
            ("deployment.yaml", DEPLOYMENT),
        ]);
        let mut app = fixture.app(".");
        let (err, _) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_none(), "{err:?}");

        // Default (`applyOutOfSyncOnly: true`) + a manual operation: nothing needs an apply.
        app.metadata.annotations = Some(operation_annotation());
        let applies_before = fixture.cluster.applies().len();
        let (err, _) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_none(), "{err:?}");
        assert_eq!(
            fixture.cluster.applies().len(),
            applies_before,
            "an executed pass still skips synced resources by default"
        );

        // Opting out re-applies the whole desired set, in tier order.
        app.spec.sync_policy = Some(SyncPolicy {
            automated: Some(AutomatedSyncPolicy {
                prune: false,
                self_heal: true,
            }),
            sync_options: Some(SyncOptions {
                apply_out_of_sync_only: false,
                ..SyncOptions::default()
            }),
            retry: None,
        });
        let applies_before = fixture.cluster.applies().len();
        let (err, status) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_none(), "{err:?}");
        assert_eq!(
            fixture.cluster.applies()[applies_before..],
            [CONFIGMAP_KEY.to_owned(), DEPLOYMENT_KEY.to_owned()],
            "applyOutOfSyncOnly: false must patch every desired resource"
        );
        assert_eq!(sync_state(&status).status, SyncStatus::Synced);
    }

    /// Trap T10 / finding M4: an ownership conflict applies nothing, reports `OutOfSync`, and is
    /// terminal so it can never become a self-heal loop.
    #[tokio::test]
    async fn an_ownership_conflict_applies_nothing_and_reports_out_of_sync() {
        let foreign = config_map(
            "settings",
            Some("ferriscd-system/other:/ConfigMap:payments/settings"),
        );
        let fixture = fixture(
            FakeCluster::default()
                .with_namespace("payments")
                .with_object(foreign),
        );
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);
        let mut app = fixture.app(".");

        let (err, status) = reconcile_pass(&fixture, &mut app).await;
        let err = err.expect("a foreign owner must fail the reconcile");
        assert!(
            matches!(err, ReconcileError::OwnershipConflict { .. }),
            "the conflict must be classified: {err}"
        );
        assert_eq!(
            err.failure_class(),
            crate::FailureClass::Terminal,
            "no apply can fix a foreign owner, so retrying must not loop"
        );
        assert!(
            fixture.cluster.applies().is_empty(),
            "nothing may be applied when a foreign owner is detected"
        );
        assert!(
            fixture.dry_run.calls().is_empty(),
            "a doomed pass must not even dry-run the bundle"
        );
        assert_eq!(fixture.pipeline.mutating_applies(), 0);

        let persisted = status
            .as_ref()
            .expect("the failure path must patch /status");
        assert_eq!(
            persisted.sync.as_ref().map(|sync| sync.status),
            Some(SyncStatus::OutOfSync),
            "an ownership conflict must surface as OutOfSync"
        );
        let condition = ready(&status);
        assert_eq!(condition.status, ConditionStatus::False);
        assert_eq!(condition.reason, REASON_OWNERSHIP_CONFLICT);
        assert!(
            condition.message.contains("another Application"),
            "{}",
            condition.message
        );

        // A second pass is not a loop: still terminal, still zero applies.
        app.status = status;
        let (err, _) = reconcile_pass(&fixture, &mut app).await;
        assert!(err.is_some_and(|err| err.failure_class() == crate::FailureClass::Terminal));
        assert!(fixture.cluster.applies().is_empty());
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    #[test]
    fn the_sent_body_never_contains_a_status_field() {
        let mut object = config_map("settings", None);
        object
            .data
            .as_object_mut()
            .unwrap()
            .insert("status".to_owned(), json!({ "phase": "Injected" }));

        let body = apply_body(&object);
        assert!(body.data.get("status").is_none());
        assert_eq!(body.data.get("data"), Some(&json!({ "key": "value" })));
        assert!(
            object.data.get("status").is_some(),
            "the caller's object must not be mutated"
        );
    }

    #[test]
    fn a_pending_outcome_is_not_synced_and_requeues_fast() {
        let mut app = application("https://example.com/repo.git", ".", "payments");
        app.spec.requeue_after_seconds = 600;
        let execute = SyncDecision::Execute(ferriscd_engine::diff::SyncTrigger::SourceChanged);
        // A first pass: nothing exists yet, so everything is `Missing`.
        let summary = DiffSummary {
            total: 3,
            missing: 3,
            ..DiffSummary::default()
        };

        let pending = build_outcome(
            &app,
            execute,
            &summary,
            HASH,
            SyncCounts {
                health: HealthStatus::Healthy,
                desired: 3,
                applied: 1,
                pruned: 0,
                retained_orphans: 0,
                pending: 2,
                invalid_ignore_pointers: 0,
                prune_enabled: false,
                settled: false,
                ..SyncCounts::default()
            },
            "0123456789abcdef0123456789abcdef01234567".to_owned(),
            Inventory::new(),
        );
        assert_eq!(pending.reason, REASON_PENDING);
        assert_eq!(pending.requeue, Some(PENDING_REQUEUE));
        let sync = pending.sync.unwrap();
        assert_eq!(sync.status, SyncStatus::OutOfSync);
        assert!(sync.last_synced_revision.is_none());
        assert!(
            sync.last_synced_spec_hash.is_none(),
            "a pending resource means the spec hash is not yet synced"
        );
        assert!(sync.last_synced_at.is_none());

        let complete = build_outcome(
            &app,
            execute,
            &summary,
            HASH,
            SyncCounts {
                health: HealthStatus::Healthy,
                desired: 3,
                applied: 3,
                pruned: 1,
                retained_orphans: 0,
                pending: 0,
                invalid_ignore_pointers: 0,
                prune_enabled: false,
                settled: true,
                ..SyncCounts::default()
            },
            "0123456789abcdef0123456789abcdef01234567".to_owned(),
            Inventory::new(),
        );
        assert_eq!(complete.reason, REASON_SYNC_SUCCEEDED);
        assert_eq!(
            complete.requeue,
            Some(Duration::from_secs(600)),
            "a settled sync honors spec.requeueAfterSeconds"
        );
        let sync = complete.sync.as_ref().unwrap();
        assert_eq!(sync.status, SyncStatus::Synced);
        assert_eq!(
            sync.last_synced_revision.as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
        assert_eq!(
            sync.last_synced_spec_hash.as_deref(),
            Some(HASH),
            "finding H7: a successful sync persists the spec hash with the revision"
        );
        assert!(sync.last_synced_at.is_some());
        assert!(complete.message.contains("0123456"), "{}", complete.message);
        assert!(
            complete.message.contains("pruned 1"),
            "{}",
            complete.message
        );
        assert!(
            complete.message.contains("sourceChanged"),
            "the trigger must be visible: {}",
            complete.message
        );
        assert!(
            !complete.message.contains("retained"),
            "no orphan was retained: {}",
            complete.message
        );

        // A stuck orphan must be visible in `/status`, not only in a log line.
        let retained = build_outcome(
            &app,
            execute,
            &summary,
            HASH,
            SyncCounts {
                health: HealthStatus::Healthy,
                desired: 1,
                applied: 1,
                pruned: 0,
                retained_orphans: 1,
                pending: 0,
                invalid_ignore_pointers: 0,
                prune_enabled: false,
                settled: true,
                ..SyncCounts::default()
            },
            "0123456789abcdef0123456789abcdef01234567".to_owned(),
            Inventory::new(),
        );
        assert!(
            retained.message.contains("1 orphan(s) retained"),
            "{}",
            retained.message
        );
        assert_eq!(retained.reason, REASON_SYNC_SUCCEEDED);
    }

    /// A skipped pass never claims `Synced` for a drifting cluster and never advances the
    /// `lastSynced*` markers (that is what `selfHeal: false` relies on).
    #[test]
    fn a_skipped_outcome_reports_the_diff_status_and_keeps_the_markers_unset() {
        let app = application("https://example.com/repo.git", ".", "payments");
        let drifting = DiffSummary {
            total: 2,
            synced: 1,
            out_of_sync: 1,
            ..DiffSummary::default()
        };
        let outcome = build_outcome(
            &app,
            SyncDecision::Skip(ferriscd_engine::diff::SkipReason::SelfHealDisabled),
            &drifting,
            HASH,
            SyncCounts {
                health: HealthStatus::Healthy,
                desired: 2,
                applied: 0,
                pruned: 0,
                retained_orphans: 0,
                pending: 0,
                invalid_ignore_pointers: 0,
                prune_enabled: false,
                settled: false,
                ..SyncCounts::default()
            },
            "0123456789abcdef0123456789abcdef01234567".to_owned(),
            Inventory::new(),
        );

        assert_eq!(outcome.reason, REASON_SYNC_SKIPPED);
        assert!(
            outcome.message.contains("self-heal is disabled"),
            "the skip reason must be explained: {}",
            outcome.message
        );
        assert_eq!(
            outcome.requeue,
            Some(Duration::from_secs(u64::from(
                DEFAULT_REQUEUE_AFTER_SECONDS
            ))),
            "a skipped pass requeues on the spec interval, not the pending one"
        );
        let sync = outcome.sync.expect("sync state");
        assert_eq!(
            sync.status,
            SyncStatus::OutOfSync,
            "a skipped-but-drifting application is still out of sync"
        );
        assert!(sync.last_synced_revision.is_none());
        assert!(sync.last_synced_spec_hash.is_none());
        assert!(sync.last_synced_at.is_none());

        // An already-synced cluster that the gate skipped reports `Synced` without pretending a
        // sync happened (`lastSynced*` stays `None`, so `merge_sync_state` keeps the previous
        // values instead of moving them).
        let settled = build_outcome(
            &app,
            SyncDecision::Skip(ferriscd_engine::diff::SkipReason::AlreadySynced),
            &DiffSummary {
                total: 2,
                synced: 2,
                ..DiffSummary::default()
            },
            HASH,
            SyncCounts {
                health: HealthStatus::Healthy,
                desired: 2,
                applied: 0,
                pruned: 0,
                retained_orphans: 0,
                pending: 0,
                invalid_ignore_pointers: 0,
                prune_enabled: false,
                settled: false,
                ..SyncCounts::default()
            },
            "0123456789abcdef0123456789abcdef01234567".to_owned(),
            Inventory::new(),
        );
        let sync = settled.sync.expect("sync state");
        assert_eq!(sync.status, SyncStatus::Synced);
        assert!(sync.last_synced_revision.is_none());
    }

    /// Finding H2: the controller's orphan-free status mapping, with the engine semantic intact.
    #[test]
    fn the_orphan_free_status_mapping_only_drops_orphans() {
        let orphan_only = DiffSummary {
            total: 1,
            orphaned: 1,
            ..DiffSummary::default()
        };
        // The engine keeps reporting an orphan as `OutOfSync` (pinned in `types.rs`, unchanged:
        // with pruning enabled that verdict is exactly right).
        assert_eq!(orphan_only.sync_status(), SyncStatus::OutOfSync);
        assert_eq!(
            sync_status_without_orphans(&orphan_only),
            SyncStatus::Synced
        );
        assert_eq!(
            sync_status_without_orphans(&DiffSummary::default()),
            SyncStatus::Synced,
            "an empty pass is trivially in sync"
        );

        // Drift and ownership conflicts still count: only orphans are filtered.
        for summary in [
            DiffSummary {
                total: 2,
                orphaned: 1,
                out_of_sync: 1,
                ..DiffSummary::default()
            },
            DiffSummary {
                total: 2,
                orphaned: 1,
                missing: 1,
                ..DiffSummary::default()
            },
            DiffSummary {
                total: 2,
                orphaned: 1,
                ownership_conflicts: 1,
                ..DiffSummary::default()
            },
        ] {
            assert_eq!(
                sync_status_without_orphans(&summary),
                SyncStatus::OutOfSync,
                "{summary:?}"
            );
        }
    }

    /// Findings H1/H2: the `Ready` message carries the counts a log line cannot.
    #[test]
    fn retained_orphans_and_invalid_pointers_reach_the_ready_message() {
        let mut app = application("https://example.com/repo.git", ".", "payments");
        app.spec.sync_policy = Some(source_only_policy());
        let revision = "0123456789abcdef0123456789abcdef01234567".to_owned();
        let orphan_summary = DiffSummary {
            total: 1,
            orphaned: 1,
            ..DiffSummary::default()
        };
        let counts = SyncCounts {
            health: HealthStatus::Healthy,
            desired: 0,
            applied: 0,
            pruned: 0,
            retained_orphans: 1,
            pending: 0,
            invalid_ignore_pointers: 1,
            prune_enabled: false,
            ..SyncCounts::default()
        };

        let skipped = build_outcome(
            &app,
            SyncDecision::Skip(ferriscd_engine::diff::SkipReason::SelfHealDisabled),
            &orphan_summary,
            HASH,
            counts.clone(),
            revision.clone(),
            Inventory::new(),
        );
        assert_eq!(skipped.reason, REASON_SYNC_SKIPPED);
        assert_eq!(
            skipped.sync.as_ref().map(|sync| sync.status),
            Some(SyncStatus::Synced),
            "prune: false means the retained orphan cannot pin OutOfSync"
        );
        assert!(
            skipped.message.contains("1 orphan(s) retained"),
            "{}",
            skipped.message
        );
        assert!(
            skipped
                .message
                .contains("1 invalid ignoreDifferences pointer ignored"),
            "{}",
            skipped.message
        );

        // The same message renders a plural count, and stays empty when there is nothing to say.
        let plural = build_outcome(
            &app,
            SyncDecision::Skip(ferriscd_engine::diff::SkipReason::SelfHealDisabled),
            &orphan_summary,
            HASH,
            SyncCounts {
                invalid_ignore_pointers: 3,
                ..counts
            },
            revision.clone(),
            Inventory::new(),
        );
        assert!(
            plural
                .message
                .contains("3 invalid ignoreDifferences pointers ignored"),
            "{}",
            plural.message
        );

        let clean = build_outcome(
            &app,
            SyncDecision::Skip(ferriscd_engine::diff::SkipReason::AlreadySynced),
            &DiffSummary::default(),
            HASH,
            SyncCounts::default(),
            revision,
            Inventory::new(),
        );
        assert!(
            !clean.message.contains("retained") && !clean.message.contains("ignoreDifferences"),
            "{}",
            clean.message
        );
    }

    #[test]
    fn ssa_patch_params_are_force_false_with_the_ferriscd_field_manager() {
        // Trap T5: `force: true` silently steals fields another manager owns (HPA,
        // kube-controller-manager). v0.2 must never do that, and the field manager must be the
        // engine's documented default rather than a literal that can drift.
        let field_manager = DynamicApiApplier::field_manager();
        assert_eq!(field_manager, ferriscd_engine::default_field_manager());

        let params = apply_patch_params(&field_manager, false);
        assert!(!params.force, "a v0.2 apply must never force");
        assert!(!params.dry_run);
        assert_eq!(
            params.field_manager.as_deref(),
            Some(ferriscd_engine::default_field_manager())
        );
    }

    #[test]
    fn foreign_ownership_reports_every_offending_key() {
        let resources: Vec<DesiredResource> = ["one", "two"]
            .iter()
            .map(|name| DesiredResource {
                key: ResourceKey::new("", "ConfigMap", Some("payments".to_owned()), *name),
                gvk: GroupVersionKind::parse("v1", "ConfigMap").unwrap(),
                object: config_map(name, None),
                source_file: "configmap.yaml".to_owned(),
            })
            .collect();

        let mut live: BTreeMap<ResourceKey, LiveState> = BTreeMap::new();
        for resource in &resources {
            live.insert(
                resource.key.clone(),
                LiveState::Present(
                    Box::new(resource.object.clone()),
                    Ownership::OwnedByForeign("ferriscd-system/other".to_owned()),
                ),
            );
        }
        let err = reject_foreign_ownership(&resources, &live).expect_err("foreign owners");
        let message = err.to_string();
        assert!(message.contains("2 resource(s)"), "{message}");
        assert!(message.contains("/ConfigMap/payments/one"), "{message}");
        assert!(message.contains("/ConfigMap/payments/two"), "{message}");
        assert_eq!(err.failure_class(), crate::FailureClass::Terminal);

        // No live state at all would bypass the ownership check, so it is refused instead.
        let err = reject_foreign_ownership(&resources, &BTreeMap::new())
            .expect_err("applying without a live read must be refused");
        assert!(err.to_string().contains("ownership check"), "{err}");
    }

    // ---------------------------------------------------------------------
    // Phase 09: health assessment (T09.5)
    // ---------------------------------------------------------------------

    /// A live `Deployment` that diffs `Synced` against `DEPLOYMENT` and carries a chosen status.
    fn deployment_live(generation: i64, status: serde_json::Value) -> DynamicObject {
        let mut annotation_map = serde_json::Map::new();
        annotation_map.insert(
            annotations::TRACKING_ID.to_owned(),
            json!("ferriscd-system/payments:apps/Deployment:payments/api"),
        );
        serde_json::from_value(json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "api",
                "namespace": "payments",
                "generation": generation,
                "annotations": annotation_map,
            },
            "spec": { "replicas": 1 },
            "status": status,
        }))
        .unwrap()
    }

    /// A `status.sync` that claims the revision in `sha` is already deployed.
    fn synced_status(sha: &str, spec_hash: &str) -> ApplicationStatus {
        ApplicationStatus {
            inventory: vec![ferriscd_crd::InventoryEntry::new(DEPLOYMENT_KEY, "v1")],
            sync: Some(SyncState {
                status: SyncStatus::Synced,
                revision: Some(sha.to_owned()),
                last_synced_revision: Some(sha.to_owned()),
                last_synced_spec_hash: Some(spec_hash.to_owned()),
                last_synced_at: Some(now()),
            }),
            ..ApplicationStatus::default()
        }
    }

    /// `T09.5` trap guard: `Synced` and `Healthy` are different questions.
    ///
    /// The Deployment's `spec` is exactly what Git says (`Synced`, the gate skips, zero applies)
    /// while the rollout it describes is still in flight (`Progressing`).
    #[tokio::test]
    async fn a_skipped_pass_still_reports_health_and_never_claims_healthy() {
        let fixture = fixture(
            FakeCluster::default()
                .with_namespace("payments")
                // The previous rollout's counters: `observedGeneration` 1 vs `generation` 2.
                .with_object(deployment_live(
                    2,
                    json!({
                        "observedGeneration": 1,
                        "replicas": 1,
                        "updatedReplicas": 1,
                        "availableReplicas": 1,
                        "readyReplicas": 1,
                    }),
                )),
        );
        let sha = fixture.commit(&[("deployment.yaml", DEPLOYMENT)]);
        let mut app = fixture.app(".");
        let spec_hash = source_spec_hash(&app.spec).expect("spec hash");
        app.status = Some(synced_status(&sha, &spec_hash));

        let outcome = fixture
            .pipeline
            .apply(&app)
            .await
            .expect("apply must succeed");

        assert!(
            fixture.cluster.applies().is_empty(),
            "nothing drifted, so the gate must issue zero applies: {:?}",
            fixture.cluster.applies()
        );
        assert_eq!(
            outcome.sync.as_ref().map(|sync| sync.status),
            Some(SyncStatus::Synced),
            "the spec matches Git, so the sync status is Synced"
        );
        assert_eq!(outcome.reason, REASON_SYNC_SKIPPED);

        let health = outcome.health.as_ref().expect("health must be reported");
        assert_eq!(
            health.status,
            HealthStatus::Progressing,
            "a stale observedGeneration is not healthy: {:?}",
            health.message
        );
        assert!(
            health
                .message
                .as_deref()
                .is_some_and(|message| message.contains("Deployment")),
            "the message must name the resource: {:?}",
            health.message
        );

        let resources = outcome.resources.as_ref().expect("per-resource health");
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].key, DEPLOYMENT_KEY);
        assert_eq!(
            resources[0].version, "v1",
            "the version hint comes from the inventory"
        );
        assert_eq!(resources[0].health, HealthStatus::Progressing);
        assert!(
            resources[0].message.contains("observe generation"),
            "{}",
            resources[0].message
        );

        // A converging Application is polled fast so the next verdict is seconds old, not minutes.
        assert_eq!(outcome.requeue, Some(PROGRESSING_REQUEUE));
    }

    /// The bad-image case, hermetically: `Synced`, `Degraded`, and a *settled* requeue interval.
    #[tokio::test]
    async fn a_synced_but_degraded_workload_is_degraded_and_requeues_at_the_configured_interval() {
        let fixture = fixture(
            FakeCluster::default()
                .with_namespace("payments")
                .with_object(deployment_live(
                    2,
                    json!({
                        "observedGeneration": 2,
                        "replicas": 1,
                        "updatedReplicas": 1,
                        "availableReplicas": 0,
                        "readyReplicas": 0,
                        "conditions": [{
                            "type": "Progressing",
                            "status": "False",
                            "reason": "ProgressDeadlineExceeded",
                            "message": "ReplicaSet \"api-6f9\" has timed out progressing.",
                        }],
                    }),
                )),
        );
        fixture.commit(&[("deployment.yaml", DEPLOYMENT)]);
        let app = fixture.app(".");

        let outcome = fixture
            .pipeline
            .apply(&app)
            .await
            .expect("apply must succeed");

        assert_eq!(
            outcome.sync.as_ref().map(|sync| sync.status),
            Some(SyncStatus::Synced)
        );
        let health = outcome.health.as_ref().expect("health must be reported");
        assert_eq!(health.status, HealthStatus::Degraded);
        assert!(
            health
                .message
                .as_deref()
                .is_some_and(|message| message.contains("progress deadline")),
            "{:?}",
            health.message
        );
        // Degraded is settled: a faster poll cannot change it, so the full interval is used.
        assert_eq!(
            outcome.requeue,
            Some(Duration::from_secs(u64::from(
                DEFAULT_REQUEUE_AFTER_SECONDS
            )))
        );
    }

    #[tokio::test]
    async fn a_healthy_application_reports_healthy_and_requeues_slowly() {
        let fixture = fixture(
            FakeCluster::default()
                .with_namespace("payments")
                .with_object(deployment_live(
                    2,
                    json!({
                        "observedGeneration": 2,
                        "replicas": 1,
                        "updatedReplicas": 1,
                        "availableReplicas": 1,
                        "readyReplicas": 1,
                    }),
                )),
        );
        fixture.commit(&[("deployment.yaml", DEPLOYMENT)]);
        let mut app = fixture.app(".");
        app.spec.requeue_after_seconds = 300;

        let outcome = fixture
            .pipeline
            .apply(&app)
            .await
            .expect("apply must succeed");

        assert_eq!(
            outcome.health.as_ref().map(|health| health.status),
            Some(HealthStatus::Healthy)
        );
        assert_eq!(
            outcome
                .health
                .as_ref()
                .and_then(|health| health.message.clone()),
            Some("all 1 resource(s) are healthy".to_owned())
        );
        assert_eq!(
            outcome.requeue,
            Some(Duration::from_secs(300)),
            "a settled Application uses spec.requeueAfterSeconds"
        );
    }

    /// The adaptive requeue table (`T09.5`).
    #[test]
    fn plan_requeue_polls_fast_only_while_converging() {
        let mut app = application("https://example.com/repo.git", ".", "payments");
        app.spec.requeue_after_seconds = 180;
        assert_eq!(
            plan_requeue(true, 2, HealthStatus::Healthy, &app, None),
            PENDING_REQUEUE,
            "a deferred CRD/namespace is retried quickly regardless of health"
        );
        assert_eq!(
            plan_requeue(true, 0, HealthStatus::Progressing, &app, None),
            PROGRESSING_REQUEUE
        );
        assert_eq!(
            plan_requeue(false, 0, HealthStatus::Progressing, &app, None),
            PROGRESSING_REQUEUE,
            "a skipped pass still polls fast while a rollout converges"
        );
        for settled in [
            HealthStatus::Healthy,
            HealthStatus::Degraded,
            HealthStatus::Suspended,
            HealthStatus::Missing,
            HealthStatus::Unknown,
        ] {
            assert_eq!(
                plan_requeue(true, 0, settled, &app, None),
                Duration::from_secs(180),
                "{settled:?} is settled"
            );
        }

        // The progressing interval never *lengthens* an operator's explicit faster interval.
        app.spec.requeue_after_seconds = 3;
        assert_eq!(
            plan_requeue(true, 0, HealthStatus::Progressing, &app, None),
            Duration::from_secs(3)
        );
        assert_eq!(
            plan_requeue(true, 1, HealthStatus::Progressing, &app, None),
            PENDING_REQUEUE,
            "a pending dependency outranks the health interval"
        );
    }

    #[test]
    fn health_inputs_cover_every_live_state() {
        let missing = ResourceKey::new(
            "".to_owned(),
            "ConfigMap".to_owned(),
            Some("payments".to_owned()),
            "settings".to_owned(),
        );
        let deferred = ResourceKey::new(
            "example.com".to_owned(),
            "Widget".to_owned(),
            Some("payments".to_owned()),
            "one".to_owned(),
        );
        let desired: Vec<DesiredResource> = [&missing, &deferred]
            .iter()
            .map(|key| DesiredResource {
                key: (*key).clone(),
                gvk: ferriscd_engine::manifest::GroupVersionKind::parse("v1", &key.kind)
                    .expect("gvk"),
                object: config_map(&key.name, None),
                source_file: "fixture.yaml".to_owned(),
            })
            .collect();

        let mut live: LiveStateMap = BTreeMap::new();
        live.insert(missing.clone(), LiveState::Missing);
        live.insert(deferred.clone(), LiveState::DeferredPendingCrd);

        let planned: BTreeSet<ResourceKey> = BTreeSet::new();
        let inputs = health_inputs(&desired, &live, &Inventory::new(), &planned);
        assert_eq!(inputs.len(), 2);
        assert!(matches!(inputs[0].observation, Observation::Missing));
        assert!(matches!(inputs[1].observation, Observation::Pending(_)));

        // A resource this pass applied is not `Missing`: the live read simply predates the write.
        let applied = inventory::inventory_from_desired(&desired);
        let inputs = health_inputs(&desired, &live, &applied, &planned);
        assert!(
            matches!(
                inputs[0].observation,
                Observation::AppliedAwaitingObservation
            ),
            "an applied resource must not be reported Missing"
        );

        // Finding M3: a resource a *later* wave of the running operation owns has deliberately not
        // been created yet, so it is scheduled (`Progressing`), never `Missing` — and the explicit
        // "applied this pass" observation still wins over it.
        let scheduled: BTreeSet<ResourceKey> = BTreeSet::from([missing.clone()]);
        let inputs = health_inputs(&desired, &live, &Inventory::new(), &scheduled);
        assert!(
            matches!(inputs[0].observation, Observation::Pending(_)),
            "a scheduled wave must be Progressing, not Missing: {:?}",
            inputs[0].observation
        );
        assert!(matches!(inputs[1].observation, Observation::Pending(_)));
        let inputs = health_inputs(&desired, &live, &applied, &scheduled);
        assert!(matches!(
            inputs[0].observation,
            Observation::AppliedAwaitingObservation
        ));

        // A kind whose CRD disappeared is not this pass's health business.
        let mut gone: LiveStateMap = BTreeMap::new();
        gone.insert(missing.clone(), LiveState::OrphanGvkGone);
        assert!(health_inputs(&desired, &gone, &Inventory::new(), &scheduled).is_empty());
    }

    #[test]
    fn empty_outcome_fields_leave_other_status_fields_untouched() {
        // `apply_once` only writes what the pipeline reports; unrelated status fields owned
        // by other phases must survive (health, history, operationState, conditions).
        let mut status = ApplicationStatus {
            health: Some(HealthState::new(HealthStatus::Healthy)),
            ..ApplicationStatus::default()
        };
        let before = status.clone();
        let outcome = ApplyOutcome::ready(REASON_SYNC_SUCCEEDED, "done");
        crate::reconcile::apply_outcome_status(&mut status, &outcome);
        assert_eq!(status.health, before.health);
        assert!(status.inventory.is_empty());
        assert!(status.sync.is_none());
        assert!(status.conditions.is_empty());
    }

    // ---------------------------------------------------------------------
    // Phase 11: rendering through the Application CR (`T11.1`)
    // ---------------------------------------------------------------------

    /// A committed kustomization is *not* a raw manifest: the pre-Phase-11 controller tried to
    /// parse `kustomization.yaml` as a Kubernetes object and failed with a missing-`kind`
    /// validation error. Rendering through the CR must instead run the renderer, parse its output,
    /// and apply the rendered resource.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_kustomize_application_renders_through_the_cr() {
        let fake = FakeRenderer::new(
            "kustomize",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\ndata:\n  key: rendered\n",
        );
        let fixture = fixture_with_renderers(
            FakeCluster::default().with_namespace("payments"),
            RendererBinaries {
                kustomize: Some(fake.path().to_path_buf()),
                ..RendererBinaries::default()
            },
        );
        fixture.commit(&[
            (
                "kustomization.yaml",
                "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - configmap.yaml\n",
            ),
            ("configmap.yaml", CONFIGMAP),
        ]);

        let mut app = fixture.app(".");
        app.spec.source.renderer = RendererSpec::Kustomize(ferriscd_crd::KustomizeRenderer {
            kustomization_path: None,
            images: Vec::new(),
        });

        let outcome = fixture
            .pipeline
            .apply(&app)
            .await
            .expect("a kustomize Application must render through the CR");

        assert_eq!(
            fixture.cluster.applies(),
            vec![CONFIGMAP_KEY.to_owned()],
            "the rendered resource must be applied"
        );
        assert_eq!(
            outcome.inventory.as_ref().expect("inventory").len(),
            1,
            "the rendered resource — not `kustomization.yaml` — is what enters the inventory"
        );
        assert_eq!(fake.invocations(), 1, "the renderer must have been invoked");

        // The render cache is wired into the controller: an unchanged commit renders once.
        fixture.pipeline.apply(&app).await.expect("second pass");
        assert_eq!(
            fake.invocations(),
            1,
            "a repeated pass at the same commit must hit the render cache"
        );
        let stats = fixture.pipeline.render_cache_stats();
        assert_eq!(stats.misses, 1, "{stats:?}");
        assert!(stats.hits >= 1, "{stats:?}");
    }

    /// **`T15.1` verification:** a real pass records the Git fetch duration and bridges the render
    /// cache's own `hits`/`misses` into `ferriscd_render_cache_total{outcome=...}` — the metric is
    /// the engine's counter, not a second bookkeeping copy.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_pass_records_git_fetch_and_render_cache_metrics() {
        let fake = FakeRenderer::new(
            "kustomize",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\ndata:\n  key: rendered\n",
        );
        let metrics = crate::metrics::Metrics::with_fixed_series();
        // The fixture owns the pipeline, and `with_metrics` consumes it: rebuild the fixture with
        // the recorder attached rather than mutating a shared pipeline.
        let fixture = with_metrics(
            fixture_with_renderers(
                FakeCluster::default().with_namespace("payments"),
                RendererBinaries {
                    kustomize: Some(fake.path().to_path_buf()),
                    ..RendererBinaries::default()
                },
            ),
            &metrics,
        );
        fixture.commit(&[
            (
                "kustomization.yaml",
                "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - configmap.yaml\n",
            ),
            ("configmap.yaml", CONFIGMAP),
        ]);
        let mut app = fixture.app(".");
        app.spec.source.renderer = RendererSpec::Kustomize(ferriscd_crd::KustomizeRenderer {
            kustomization_path: None,
            images: Vec::new(),
        });

        // Two passes at the same commit: one render (a miss) and one cache hit.
        fixture.pipeline.apply(&app).await.expect("first pass");
        fixture.pipeline.apply(&app).await.expect("second pass");
        assert_eq!(
            fake.invocations(),
            1,
            "the second pass must be served from the render cache"
        );

        let body = metrics.encode().expect("the registry encodes");
        let samples = crate::metrics::exposition::parse(&body);
        for (outcome, expected) in [("miss", "1"), ("hit", "1")] {
            assert_eq!(
                crate::metrics::exposition::value_of(
                    &samples,
                    crate::metrics::RENDER_CACHE_TOTAL,
                    &[("outcome", outcome)],
                    &body
                ),
                expected,
                "the bridge must report the engine's own cache counters:\n{body}"
            );
        }
        assert_eq!(
            crate::metrics::exposition::value_of(
                &samples,
                &format!("{}_count", crate::metrics::GIT_FETCH_DURATION_SECONDS),
                &[],
                &body
            ),
            "2",
            "one Git resolve/checkout per pass:\n{body}"
        );
        // The histogram carries no label at all, so neither the repository URL nor an error can
        // widen it.
        for sample in crate::metrics::exposition::samples_of(
            &samples,
            crate::metrics::GIT_FETCH_DURATION_SECONDS,
        ) {
            let labels: Vec<&str> = sample.labels.keys().map(String::as_str).collect();
            assert!(
                labels.is_empty() || labels == vec!["le"],
                "the Git fetch histogram must stay label-free: {labels:?}\n{body}"
            );
        }
    }

    /// The Helm path renders offline with the **discovered** cluster version, so
    /// `.Capabilities.KubeVersion` matches the destination instead of helm's built-in default.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_helm_application_renders_with_the_discovered_kube_version() {
        let fake = FakeRenderer::new(
            "helm",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: render-settings\n  namespace: payments\n",
        );
        let fixture = fixture_with_renderers(
            FakeCluster::default().with_namespace("payments"),
            RendererBinaries {
                helm: Some(fake.path().to_path_buf()),
                ..RendererBinaries::default()
            },
        );
        fixture.commit(&[
            ("Chart.yaml", "apiVersion: v2\nname: demo\nversion: 0.1.0\n"),
            ("values.yaml", "replicaCount: 1\n"),
        ]);

        let mut app = fixture.app(".");
        app.spec.source.renderer = RendererSpec::Helm(ferriscd_crd::HelmRenderer {
            release_name: None,
            value_files: Vec::new(),
            include_crds: false,
        });

        fixture
            .pipeline
            .apply(&app)
            .await
            .expect("a helm Application must render through the CR");

        assert_eq!(
            fixture.cluster.applies(),
            vec!["/ConfigMap/payments/render-settings".to_owned()],
            "the rendered object must reach the applier"
        );

        // Finding H2/M3: the render argv carries the *discovered* cluster version, so
        // `.Capabilities.KubeVersion` reflects the destination cluster instead of helm's default.
        let args = fake.recorded_args();
        assert!(
            args.windows(2)
                .any(|window| window[0] == "--kube-version" && window[1] == "v1.35.0"),
            "the discovered kube version must reach helm template: {args:?}"
        );
        assert!(
            args.windows(2)
                .any(|window| window[0] == "--namespace" && window[1] == "payments"),
            "the destination namespace must reach helm template: {args:?}"
        );
    }

    // ---------------------------------------------------------------------
    // Phase 12: `AppProject` policy (`T12.1`) and the namespace scope (`T12.2`)
    // ---------------------------------------------------------------------

    /// A manifest set that the permissive `default` project accepts.
    const POLICY_CONFIGMAP: &str = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: settings
data:
  key: value
"#;

    /// The same manifest, but hardcoding a namespace the project does not own: the classic
    /// `AppProject` bypass (`spec.destination.namespace` is `payments`, the manifest says
    /// `kube-system`).
    const CONFIGMAP_IN_KUBE_SYSTEM: &str = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: settings
  namespace: kube-system
data:
  key: value
"#;

    /// A cluster-scoped resource no project whitelists by default.
    const CLUSTER_ROLE: &str = r#"
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: escalation
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
"#;

    /// An `Application` in a tenant namespace, with an optional ServiceAccount (`T12.2`).
    fn tenant_application(
        fixture: &Fixture,
        namespace: &str,
        service_account: Option<&str>,
    ) -> Application {
        let mut app = fixture.app(".");
        app.metadata.namespace = Some(namespace.to_owned());
        app.spec.project = "payments".to_owned();
        app.spec.service_account_name = service_account.map(str::to_owned);
        app
    }

    fn tenant_scope(namespaces: &[&str]) -> ApplicationScope {
        ApplicationScope::new(
            "ferriscd-system",
            ApplicationNamespaces::Listed(namespaces.iter().map(|ns| (*ns).to_owned()).collect()),
        )
    }

    /// A `payments` project that additionally authorizes `team-a` and one ServiceAccount.
    fn tenant_project() -> AppProject {
        serde_saphyr::from_str(
            r#"
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: payments
  namespace: ferriscd-system
spec:
  sourceRepos:
    - "*"
  sourceNamespaces:
    - ferriscd-system
    - team-a
  destinations:
    - cluster: in-cluster
      namespace: payments
  clusterResourceWhitelist:
    - group: ""
      kind: Namespace
  namespaceResourceWhitelist:
    - group: "*"
      kind: "*"
  allowedServiceAccounts:
    # A ServiceAccount always resolves in the *destination* namespace, never in the tenant's own
    # namespace (ADR-007 / MASTER_PLAN §5).
    - payments/deployer
"#,
        )
        .expect("tenant project must parse")
    }

    #[tokio::test]
    async fn a_missing_project_is_a_terminal_denial_before_any_work() {
        let fixture = fixture_with_policy(
            FakeCluster::default().with_namespace("payments"),
            FakeProjectSource::default(),
            ApplicationScope::default(),
        );
        fixture.commit(&[("configmap.yaml", POLICY_CONFIGMAP)]);
        let app = fixture.app(".");

        let err = fixture
            .pipeline
            .apply(&app)
            .await
            .expect_err("a missing AppProject must never be treated as permissive");
        assert!(
            matches!(
                err,
                ReconcileError::Policy(PolicyError::ProjectNotFound { .. })
            ),
            "expected ProjectNotFound, got {err:?}"
        );
        assert_eq!(
            err.failure_class(),
            crate::FailureClass::Terminal,
            "a policy violation is deterministic"
        );
        assert!(err.to_string().contains("default"), "{err}");
        assert_eq!(fixture.projects.reads(), vec!["default".to_owned()]);
        // Nothing was read from Git, diffed, or applied.
        assert_eq!(fixture.git.resolve_calls(), 0);
        assert!(fixture.dry_run.calls().is_empty());
        assert!(fixture.cluster.applies().is_empty());
    }

    #[tokio::test]
    async fn a_pipeline_without_a_project_source_refuses_to_sync() {
        let temp = tempfile::tempdir().unwrap();
        let cluster = Arc::new(FakeCluster::default().with_namespace("payments"));
        let pipeline = InventorySyncPipeline::new(
            Arc::new(RepoCache::new(
                Arc::new(FakeGitClient::default()),
                RepoCacheConfig::new(temp.path().join("cache")),
            )),
            discovery(),
            cluster.clone(),
            Arc::new(FakeApplier {
                cluster: cluster.clone(),
                discovery: Arc::new(FakeDiscovery::with_cluster_kinds()),
                crd_mode: CrdMode::Establish,
            }),
            Arc::new(FakeDryRun::default()),
        )
        .with_url_policy(RepoUrlPolicy::AllowLocal);

        let app = application(
            &temp.path().join("repo").display().to_string(),
            ".",
            "payments",
        );
        let err = pipeline
            .apply(&app)
            .await
            .expect_err("a pipeline that cannot enforce policy must not sync");
        assert!(matches!(err, ReconcileError::Invalid { .. }), "{err:?}");
        assert!(err.to_string().contains("AppProject"), "{err}");
        assert_eq!(err.failure_class(), crate::FailureClass::Terminal);
        assert!(cluster.applies().is_empty());
    }

    #[tokio::test]
    async fn a_repository_outside_source_repos_never_reaches_git() {
        let project: AppProject = serde_saphyr::from_str(
            r#"
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: default
  namespace: ferriscd-system
spec:
  sourceRepos:
    - https://github.com/example/payments.git
  destinations:
    - cluster: in-cluster
      namespace: payments
  clusterResourceWhitelist:
    - group: "*"
      kind: "*"
"#,
        )
        .expect("project must parse");
        let fixture = fixture_with_policy(
            FakeCluster::default().with_namespace("payments"),
            FakeProjectSource::default().with_project(project),
            ApplicationScope::default(),
        );
        fixture.commit(&[("configmap.yaml", POLICY_CONFIGMAP)]);
        let app = fixture.app(".");

        let err = fixture
            .pipeline
            .apply(&app)
            .await
            .expect_err("an unlisted repository must be rejected");
        assert!(
            matches!(
                err,
                ReconcileError::Policy(PolicyError::SourceRepoNotAllowed { .. })
            ),
            "expected SourceRepoNotAllowed, got {err:?}"
        );
        assert!(
            err.to_string().contains("spec.source.git.repoURL"),
            "the message must name the field: {err}"
        );
        assert_eq!(
            fixture.git.resolve_calls(),
            0,
            "an unauthorized repository must never be cloned"
        );
        assert!(fixture.dry_run.calls().is_empty());
        assert!(fixture.cluster.applies().is_empty());
    }

    #[tokio::test]
    async fn a_manifest_hardcoding_an_unlisted_namespace_is_rejected_before_the_dry_run() {
        let fixture = fixture_with_policy(
            FakeCluster::default().with_namespace("payments"),
            FakeProjectSource::default().with_project(payments_only_project("default")),
            ApplicationScope::default(),
        );
        fixture.commit(&[("configmap.yaml", CONFIGMAP_IN_KUBE_SYSTEM)]);
        let app = fixture.app(".");

        let err = fixture
            .pipeline
            .apply(&app)
            .await
            .expect_err("`metadata.namespace: kube-system` must be rejected");
        assert!(
            matches!(
                err,
                ReconcileError::Policy(PolicyError::ResourceNamespaceNotAllowed { .. })
            ),
            "expected ResourceNamespaceNotAllowed, got {err:?}"
        );
        let message = err.to_string();
        assert!(message.contains("kube-system"), "{message}");
        assert!(message.contains("spec.destinations"), "{message}");
        assert_eq!(err.failure_class(), crate::FailureClass::Terminal);
        assert!(
            fixture.dry_run.calls().is_empty(),
            "the denied resource must never receive a dryRun=All PATCH"
        );
        assert!(fixture.cluster.applies().is_empty());
    }

    #[tokio::test]
    async fn an_unauthorized_cluster_scoped_kind_is_rejected_before_any_mutation() {
        let fixture = fixture_with_policy(
            FakeCluster::default().with_namespace("payments"),
            FakeProjectSource::default().with_project(payments_only_project("default")),
            ApplicationScope::default(),
        );
        fixture.commit(&[("clusterrole.yaml", CLUSTER_ROLE)]);
        let app = fixture.app(".");

        let err = fixture
            .pipeline
            .apply(&app)
            .await
            .expect_err("an unlisted ClusterRole must be rejected");
        assert!(
            matches!(
                err,
                ReconcileError::Policy(PolicyError::ClusterResourceNotAllowed { .. })
            ),
            "expected ClusterResourceNotAllowed, got {err:?}"
        );
        assert!(err.to_string().contains("ClusterRole"), "{err}");
        assert!(fixture.cluster.applies().is_empty());
        assert!(fixture.cluster.deletes().is_empty());
        assert_eq!(fixture.pipeline.mutating_applies(), 0);
    }

    #[tokio::test]
    async fn a_service_account_outside_allowed_service_accounts_is_rejected() {
        let fixture = fixture_with_policy(
            FakeCluster::default().with_namespace("payments"),
            FakeProjectSource::default().with_project(tenant_project()),
            ApplicationScope::default(),
        );
        fixture.commit(&[("configmap.yaml", POLICY_CONFIGMAP)]);
        let mut app = tenant_application(&fixture, "ferriscd-system", Some("cluster-admin"));
        app.spec.service_account_name = Some("root-sa".to_owned());

        let err = fixture
            .pipeline
            .apply(&app)
            .await
            .expect_err("an unlisted ServiceAccount must be rejected");
        assert!(
            matches!(
                err,
                ReconcileError::Policy(PolicyError::ServiceAccountNotAllowed { .. })
            ),
            "expected ServiceAccountNotAllowed, got {err:?}"
        );
        assert!(fixture.cluster.applies().is_empty());
        // Finding H2(b): the ordering is policy → identity. An unauthorized ServiceAccount is
        // rejected before any impersonated client is built.
        assert!(
            fixture.identities().is_empty(),
            "an unauthorized ServiceAccount must be refused before an impersonated client is \
             built: {:?}",
            fixture.identities()
        );
    }

    #[tokio::test]
    async fn a_tenant_application_without_a_service_account_is_rejected() {
        let fixture = fixture_with_policy(
            FakeCluster::default().with_namespace("payments"),
            FakeProjectSource::default().with_project(tenant_project()),
            tenant_scope(&["team-a"]),
        );
        fixture.commit(&[("configmap.yaml", POLICY_CONFIGMAP)]);
        let app = tenant_application(&fixture, "team-a", None);

        let err = fixture
            .pipeline
            .apply(&app)
            .await
            .expect_err("a tenant Application must name its own ServiceAccount");
        assert!(
            matches!(
                err,
                ReconcileError::Policy(PolicyError::TenantServiceAccountRequired { .. })
            ),
            "expected TenantServiceAccountRequired, got {err:?}"
        );
        assert!(err.to_string().contains("serviceAccountName"), "{err}");
        assert_eq!(err.failure_class(), crate::FailureClass::Terminal);
        assert_eq!(fixture.git.resolve_calls(), 0);
        assert!(fixture.cluster.applies().is_empty());
    }

    #[tokio::test]
    async fn an_authorized_tenant_application_reconciles() {
        let fixture = fixture_with_policy(
            FakeCluster::default().with_namespace("payments"),
            FakeProjectSource::default().with_project(tenant_project()),
            tenant_scope(&["team-a"]),
        );
        fixture.commit(&[("configmap.yaml", POLICY_CONFIGMAP)]);
        let app = tenant_application(&fixture, "team-a", Some("deployer"));

        fixture
            .pipeline
            .apply(&app)
            .await
            .expect("an authorized tenant Application must reconcile");
        assert_eq!(
            fixture.cluster.applies(),
            vec!["/ConfigMap/payments/settings".to_owned()],
            "the rendered resource must reach the destination namespace"
        );
        assert_eq!(
            fixture.identities(),
            vec!["system:serviceaccount:payments:deployer".to_owned()],
            "the pass must be resolved as the ServiceAccount, in the *destination* namespace"
        );
    }

    // ---------------------------------------------------------------------
    // Phase 12: `T12.3` pooled ServiceAccount impersonation
    // ---------------------------------------------------------------------

    /// No `serviceAccountName` ⇒ the controller's own identity, and the impersonation seam is
    /// never consulted (the pre-`T12.3` behaviour, bit for bit).
    #[tokio::test]
    async fn an_application_without_a_service_account_keeps_the_controller_identity() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[("configmap.yaml", POLICY_CONFIGMAP)]);
        let app = fixture.app(".");

        fixture
            .pipeline
            .apply(&app)
            .await
            .expect("controller identity");
        assert_eq!(
            fixture.identities(),
            Vec::<String>::new(),
            "a non-impersonated Application must not touch the impersonation pool at all"
        );
        assert_eq!(
            fixture.cluster.applies(),
            vec!["/ConfigMap/payments/settings".to_owned()]
        );
        // Its dry-runs went through the pipeline's own seam.
        assert_eq!(
            fixture.impersonated_dry_runs(),
            0,
            "no diff may run as a ServiceAccount for a non-impersonated Application"
        );
    }

    /// The whole pass — live read, `dryRun=All` diff, apply, prune — runs as the identity the
    /// policy authorized, never as the controller.
    #[tokio::test]
    async fn a_tenant_pass_diffs_and_applies_as_its_service_account() {
        let fixture = fixture_with_policy(
            FakeCluster::default().with_namespace("payments"),
            FakeProjectSource::default().with_project(tenant_project()),
            tenant_scope(&["team-a"]),
        );
        fixture.commit(&[("configmap.yaml", POLICY_CONFIGMAP)]);
        let app = tenant_application(&fixture, "team-a", Some("deployer"));

        // Pass 1 creates the ConfigMap; nothing exists yet, so nothing is dry-run.
        let first = fixture.pipeline.apply(&app).await.expect("first pass");
        assert_eq!(fixture.impersonated_dry_runs(), 0);
        assert_eq!(first.reason, REASON_SYNC_SUCCEEDED, "{}", first.message);
        fixture.cluster.seed_applied();

        // Pass 2 sees the live object, so the diff runs — as the impersonated identity.
        let mut second_app = app.clone();
        second_app.status = Some(ApplicationStatus {
            sync: first.sync.clone(),
            ..ApplicationStatus::default()
        });
        fixture
            .pipeline
            .apply(&second_app)
            .await
            .expect("second pass");
        assert_eq!(
            fixture.impersonated_dry_runs(),
            1,
            "the `dryRun=All` prediction must run as the ServiceAccount"
        );
        assert!(
            fixture.dry_run.calls().is_empty(),
            "no workload diff may be issued with the controller's identity: {:?}",
            fixture.dry_run.calls()
        );
        assert_eq!(
            fixture.identities(),
            vec![
                "system:serviceaccount:payments:deployer".to_owned(),
                "system:serviceaccount:payments:deployer".to_owned(),
            ],
            "one resolution per pass, always in the destination namespace"
        );
    }

    /// **Trap T12:** an `Application` that asks for a `ServiceAccount` when the pipeline has no pool
    /// is refused. Falling back to the controller's identity would hand the tenant the
    /// controller's privileges.
    #[tokio::test]
    async fn an_impersonating_application_is_refused_when_no_pool_is_wired() {
        let fixture = fixture_with_policy_and_impersonation(
            FakeCluster::default().with_namespace("payments"),
            FakeProjectSource::default().with_project(tenant_project()),
            tenant_scope(&["team-a"]),
            ImpersonationWiring::NotWired,
        );
        fixture.commit(&[("configmap.yaml", POLICY_CONFIGMAP)]);
        let app = tenant_application(&fixture, "team-a", Some("deployer"));

        let err = fixture
            .pipeline
            .apply(&app)
            .await
            .expect_err("a ServiceAccount identity must never silently degrade");
        assert!(
            matches!(err, ReconcileError::Impersonation(_)),
            "expected an Impersonation error, got {err:?}"
        );
        assert!(
            err.to_string()
                .contains("system:serviceaccount:payments:deployer"),
            "the message must name the identity that was requested: {err}"
        );
        assert_eq!(
            err.failure_class(),
            crate::FailureClass::Terminal,
            "a missing pool is a wiring bug, not a transient failure"
        );
        // Nothing was cloned, rendered, diffed or applied.
        assert_eq!(fixture.git.resolve_calls(), 0);
        assert!(fixture.dry_run.calls().is_empty());
        assert!(fixture.cluster.applies().is_empty());

        // The very same pipeline still reconciles a controller-identity Application: the refusal
        // is about the ServiceAccount, not about the controller.
        let mut control_plane = fixture.app(".");
        control_plane.spec.project = "payments".to_owned();
        fixture
            .pipeline
            .apply(&control_plane)
            .await
            .expect("a control-plane Application needs no impersonation");
        assert_eq!(
            fixture.cluster.applies(),
            vec!["/ConfigMap/payments/settings".to_owned()]
        );
    }

    #[tokio::test]
    async fn create_namespace_runs_before_a_presync_hook() {
        // Destination namespace does NOT exist yet; `createNamespace: true` must create it before
        // the `PreSync` hook Job is submitted so live clusters do not reject the Job with 404.
        let fixture = fixture(FakeCluster::default());
        fixture.commit(&[
            (
                "hook.yaml",
                "apiVersion: batch/v1\nkind: Job\nmetadata:\n  generateName: migrate-\n  annotations:\n    ferriscd.io/hook: PreSync\n",
            ),
            ("configmap.yaml", CONFIGMAP),
        ]);
        let mut app = fixture.app(".");
        app.spec.sync_policy = Some(SyncPolicy {
            automated: Some(AutomatedSyncPolicy {
                prune: false,
                self_heal: true,
            }),
            sync_options: Some(SyncOptions {
                create_namespace: true,
                ..SyncOptions::default()
            }),
            ..SyncPolicy::default()
        });

        let first = fixture
            .pipeline
            .apply(&app)
            .await
            .expect("createNamespace must pre-create the namespace before PreSync");
        assert_eq!(
            fixture.cluster.applies(),
            vec!["/Namespace//payments".to_owned()],
            "destination Namespace must be pre-created before wave 0 runs"
        );
        assert_eq!(
            fixture.cluster.creates(),
            vec!["migrate-abcde".to_owned()],
            "PreSync hook must be created in the same pass after ensuring the Namespace"
        );
        assert_eq!(
            first.operation_state.as_ref().and_then(|s| s.sync_phase),
            Some(SyncPhase::PreSync)
        );
        assert_eq!(
            fixture.pipeline.mutating_applies(),
            1,
            "the PreSync createNamespace apply must be counted in mutating_applies"
        );
    }

    #[tokio::test]
    async fn hookless_multi_wave_with_git_namespace_does_not_pre_create_bare_namespace() {
        // Multi-wave bundle with NO PreSync hooks and a Git-declared Namespace in wave -1:
        // `createNamespace: true` must not pre-create a bare unstamped Namespace during PreSync,
        // letting wave -1 apply the Git-declared Namespace directly (preserving labels & tracking-id).
        let fixture = fixture(FakeCluster::default());
        fixture.commit(&[
            (
                "namespace.yaml",
                "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: payments\n  labels:\n    pod-security.kubernetes.io/enforce: restricted\n  annotations:\n    ferriscd.io/sync-wave: \"-1\"\n",
            ),
            (
                "configmap.yaml",
                "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\n  annotations:\n    ferriscd.io/sync-wave: \"0\"\ndata:\n  key: val\n",
            ),
        ]);
        let mut app = fixture.app(".");
        app.spec.sync_policy = Some(SyncPolicy {
            automated: Some(AutomatedSyncPolicy {
                prune: false,
                self_heal: true,
            }),
            sync_options: Some(SyncOptions {
                create_namespace: true,
                ..SyncOptions::default()
            }),
            ..SyncPolicy::default()
        });

        let first = fixture
            .pipeline
            .apply(&app)
            .await
            .expect("hookless multi-wave must dispatch wave -1 directly");
        assert_eq!(
            fixture.cluster.applies(),
            vec!["/Namespace//payments".to_owned()],
            "only the Git-declared Namespace in wave -1 must be applied (no bare pre-create)"
        );
        assert_eq!(
            fixture.pipeline.mutating_applies(),
            1,
            "exactly one apply for the Git-declared Namespace"
        );
        let ns_applied = fixture
            .cluster
            .applied_objects
            .lock()
            .unwrap()
            .first()
            .cloned()
            .expect("Namespace was applied");
        assert_eq!(
            ns_applied
                .metadata
                .labels
                .as_ref()
                .and_then(|labels| labels.get("pod-security.kubernetes.io/enforce"))
                .map(String::as_str),
            Some("restricted"),
            "Git-declared Namespace labels must be applied directly, never bypassed by a bare pre-create"
        );
        assert!(
            ns_applied
                .metadata
                .annotations
                .as_ref()
                .is_some_and(|anns| anns.contains_key(annotations::TRACKING_ID)),
            "Git-declared Namespace must carry ferriscd.io/tracking-id"
        );
        assert_eq!(
            first.operation_state.as_ref().and_then(|s| s.sync_phase),
            Some(SyncPhase::Sync)
        );
    }

    /// A `ServiceAccount` name that Kubernetes could never have accepted is refused **before** any
    /// cluster access — even when the project's allow-list (deliberately) uses a wildcard.
    #[tokio::test]
    async fn an_invalid_service_account_name_is_refused_before_any_work() {
        let wildcard_service_accounts: AppProject = serde_saphyr::from_str(
            r#"
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: payments
  namespace: ferriscd-system
spec:
  sourceRepos:
    - "*"
  sourceNamespaces:
    - ferriscd-system
    - team-a
  destinations:
    - cluster: in-cluster
      namespace: payments
  namespaceResourceWhitelist:
    - group: "*"
      kind: "*"
  allowedServiceAccounts:
    - payments/*
"#,
        )
        .expect("project must parse");
        let fixture = fixture_with_policy(
            FakeCluster::default().with_namespace("payments"),
            FakeProjectSource::default().with_project(wildcard_service_accounts),
            tenant_scope(&["team-a"]),
        );
        fixture.commit(&[("configmap.yaml", POLICY_CONFIGMAP)]);
        // The project's `payments/*` entry matches, so only the name validation can reject this.
        let app = tenant_application(&fixture, "team-a", Some("Deployer"));

        let err = fixture
            .pipeline
            .apply(&app)
            .await
            .expect_err("an invalid ServiceAccount name must be refused");
        assert!(
            matches!(
                err,
                ReconcileError::Impersonation(ImpersonationError::InvalidServiceAccountName { .. })
            ),
            "expected InvalidServiceAccountName, got {err:?}"
        );
        assert_eq!(err.failure_class(), crate::FailureClass::Terminal);
        assert_eq!(fixture.git.resolve_calls(), 0);
        assert!(fixture.cluster.applies().is_empty());
        assert_eq!(
            fixture.identities(),
            Vec::<String>::new(),
            "an unusable name never reaches the pool"
        );
    }

    /// **Phase preservation:** impersonation is a transport identity, not a different sync. A
    /// tenant `Application` still walks the wave/hook state machine — and its `PreSync` hook is
    /// created as the tenant's ServiceAccount.
    #[tokio::test]
    async fn impersonation_preserves_the_wave_and_hook_phases() {
        let fixture = fixture_with_policy(
            FakeCluster::default().with_namespace("payments"),
            FakeProjectSource::default().with_project(tenant_project()),
            tenant_scope(&["team-a"]),
        );
        fixture.commit(&[
            ("hook.yaml", PRE_SYNC_HOOK),
            ("configmap.yaml", POLICY_CONFIGMAP),
        ]);
        let app = tenant_application(&fixture, "team-a", Some("deployer"));

        // Pass 1: the `PreSync` hook is created (as the tenant) and the wave stays closed.
        let first = fixture.pipeline.apply(&app).await.expect("the hook pass");
        assert_eq!(fixture.cluster.creates(), vec!["migrate-abcde".to_owned()]);
        assert!(
            fixture.cluster.applies().is_empty(),
            "wave 0 must wait for PreSync: {:?}",
            fixture.cluster.applies()
        );
        let state = first.operation_state.clone().expect("operation state");
        assert_eq!(state.sync_phase, Some(SyncPhase::PreSync));
        assert_eq!(first.reason, REASON_SYNC_IN_PROGRESS);
        assert_eq!(
            fixture.identities(),
            vec!["system:serviceaccount:payments:deployer".to_owned()]
        );

        // Pass 2: the hook completed, so the wave applies — still as the tenant.
        fixture.cluster.complete_job("migrate-abcde");
        let mut second_app = app.clone();
        second_app.status = Some(ApplicationStatus {
            operation_state: Some(state),
            ..ApplicationStatus::default()
        });
        let second = fixture.pipeline.apply(&second_app).await.expect("wave 0");
        assert_eq!(
            fixture.cluster.applies(),
            vec!["/ConfigMap/payments/settings".to_owned()],
            "the wave applies its own resources"
        );
        assert_eq!(
            second
                .operation_state
                .as_ref()
                .map(|state| state.sync_phase),
            Some(Some(SyncPhase::Sync))
        );
        assert_eq!(
            fixture.identities().len(),
            2,
            "each pass resolves its own identity"
        );
        assert!(
            fixture
                .identities()
                .iter()
                .all(|identity| identity == "system:serviceaccount:payments:deployer"),
            "{:?}",
            fixture.identities()
        );
    }

    #[tokio::test]
    async fn the_default_scope_refuses_an_application_outside_the_control_plane_namespace() {
        let fixture = fixture_with_policy(
            FakeCluster::default().with_namespace("payments"),
            FakeProjectSource::default().with_project(tenant_project()),
            ApplicationScope::default(),
        );
        fixture.commit(&[("configmap.yaml", POLICY_CONFIGMAP)]);
        // The project *does* authorize `team-a`; only the watch scope does not, which proves the
        // two layers are independent (finding C8).
        let app = tenant_application(&fixture, "team-a", Some("deployer"));

        let err = fixture
            .pipeline
            .apply(&app)
            .await
            .expect_err("the default scope watches only the control-plane namespace");
        assert!(
            matches!(
                err,
                ReconcileError::Policy(PolicyError::ApplicationNamespaceNotAllowed { .. })
            ),
            "expected ApplicationNamespaceNotAllowed, got {err:?}"
        );
        assert!(err.to_string().contains("ferriscd-system"), "{err}");
        assert_eq!(fixture.git.resolve_calls(), 0);
    }

    #[tokio::test]
    async fn wildcard_scope_still_requires_a_tenant_service_account() {
        let wildcard = ApplicationScope::new("ferriscd-system", ApplicationNamespaces::All);
        let fixture = fixture_with_policy(
            FakeCluster::default().with_namespace("payments"),
            FakeProjectSource::default().with_project(tenant_project()),
            wildcard.clone(),
        );
        fixture.commit(&[("configmap.yaml", POLICY_CONFIGMAP)]);

        // `*` widens the *watch*, never the tenancy guard.
        let err = fixture
            .pipeline
            .apply(&tenant_application(&fixture, "team-a", None))
            .await
            .expect_err("`*` must not authorize an Application without a ServiceAccount");
        assert!(
            matches!(
                err,
                ReconcileError::Policy(PolicyError::TenantServiceAccountRequired { .. })
            ),
            "expected TenantServiceAccountRequired, got {err:?}"
        );

        // With its own (authorized) ServiceAccount the same Application reconciles.
        fixture
            .pipeline
            .apply(&tenant_application(&fixture, "team-a", Some("deployer")))
            .await
            .expect("an authorized tenant Application must reconcile under `*`");
        assert_eq!(
            fixture.cluster.applies(),
            vec!["/ConfigMap/payments/settings".to_owned()]
        );

        // A namespace the project does not list in `spec.sourceNamespaces` is refused even under
        // `*`: the scope is not the authorization.
        let err = fixture
            .pipeline
            .apply(&tenant_application(&fixture, "team-b", Some("deployer")))
            .await
            .expect_err("`team-b` is not a project source namespace");
        assert!(
            matches!(
                err,
                ReconcileError::Policy(PolicyError::SourceNamespaceNotAllowed { .. })
            ),
            "expected SourceNamespaceNotAllowed, got {err:?}"
        );
    }

    // -----------------------------------------------------------------
    // `T14.1`: the read-only diff preview the control-plane API serves
    // -----------------------------------------------------------------

    /// **`T14.1` trap guard:** a preview renders, reads live state and classifies the diff — and
    /// writes **nothing**. No apply, no prune, no `Application` patch, and the zero-mutation counter
    /// (T07.5) stays at zero, so `GET .../diff` can never change the cluster it reports on.
    #[tokio::test]
    async fn a_diff_preview_is_read_only_and_reports_what_a_pass_would_see() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        let sha = fixture.commit(&[
            ("configmap.yaml", CONFIGMAP),
            ("deployment.yaml", DEPLOYMENT),
        ]);
        let app = fixture.app(".");

        let preview = fixture
            .pipeline
            .diff(&app)
            .await
            .expect("the preview must succeed");
        assert_eq!(
            preview.revision, sha,
            "the preview renders the resolved commit"
        );
        assert_eq!(preview.desired, 2);
        assert_eq!(preview.diffs.len(), 2);
        assert_eq!(
            preview
                .diffs
                .iter()
                .map(|diff| diff.key().canonical())
                .collect::<Vec<_>>(),
            vec![
                "/ConfigMap/payments/settings".to_owned(),
                "apps/Deployment/payments/api".to_owned(),
            ],
            "the same GKNN set a pass would apply, in tier order"
        );
        assert!(
            preview.diffs.iter().all(|diff| diff.status().is_missing()),
            "nothing exists yet, so everything is Missing: {:?}",
            preview.diffs
        );
        assert_eq!(preview.summary.missing, 2);
        assert!(
            preview.would_sync,
            "spec.syncPolicy.automated.selfHeal executes a first pass, and the preview must say so"
        );

        // Read-only: nothing was written, in any form.
        assert!(
            fixture.cluster.applies().is_empty(),
            "a preview must never apply: {:?}",
            fixture.cluster.applies()
        );
        assert!(
            fixture.cluster.deletes().is_empty(),
            "a preview must never prune"
        );
        assert!(
            fixture.cluster.app_patches().is_empty(),
            "a preview must never patch the Application: {:?}",
            fixture.cluster.app_patches()
        );
        assert!(
            fixture.cluster.creates().is_empty(),
            "a preview creates no hook"
        );
        assert_eq!(fixture.pipeline.mutating_applies(), 0);
    }

    /// A preview of an **existing** object runs the real `dryRun=All` classification against live
    /// state: it is a prediction, never a guess, and it still writes nothing.
    #[tokio::test]
    async fn a_preview_of_a_live_application_uses_the_dry_run() {
        // The live object is exactly what Git renders (plus the tracking id an apply would add), so
        // the prediction echoes it and the ConfigMap is `Synced`.
        let fixture = fixture(
            FakeCluster::default()
                .with_namespace("payments")
                .with_object(config_map(
                    "settings",
                    Some("ferriscd-system/payments:/ConfigMap:payments/settings"),
                )),
        );
        fixture.commit(&[("configmap.yaml", CONFIGMAP_WITH_DATA)]);
        let mut app = fixture.app(".");
        app.status = Some(status_with_inventory(&[CONFIGMAP_KEY]));

        let preview = fixture
            .pipeline
            .diff(&app)
            .await
            .expect("the preview succeeds");
        assert_eq!(preview.diffs.len(), 1);
        assert_eq!(preview.diffs[0].key().canonical(), CONFIGMAP_KEY);
        assert!(
            preview.diffs[0].status().is_synced(),
            "a live object that matches the rendered body previews as Synced: {:?}",
            preview.diffs[0]
        );
        assert_eq!(preview.summary.synced, 1);
        assert!(
            !fixture.dry_run.calls().is_empty(),
            "a preview of an existing object must issue the `dryRun=All` prediction"
        );
        assert!(
            fixture.cluster.applies().is_empty(),
            "the preview applied nothing"
        );
        assert_eq!(fixture.pipeline.mutating_applies(), 0);
    }

    /// A preview refuses exactly what a sync refuses, so the API cannot report a diff for an
    /// application the controller would reject (finding C9's other half).
    #[tokio::test]
    async fn a_preview_refuses_the_same_applications_a_sync_refuses() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);
        let mut app = fixture.app(".");
        app.spec.project = "nope".to_owned();

        let preview_error = fixture
            .pipeline
            .diff(&app)
            .await
            .expect_err("an unknown AppProject is a terminal denial");
        let sync_error = fixture
            .pipeline
            .apply(&app)
            .await
            .expect_err("the same application must be refused by a sync");
        assert!(
            matches!(
                preview_error,
                ReconcileError::Policy(PolicyError::ProjectNotFound { .. })
            ),
            "expected ProjectNotFound, got {preview_error:?}"
        );
        assert_eq!(
            preview_error.to_string(),
            sync_error.to_string(),
            "the API must report the same refusal a reconcile would"
        );
        assert!(fixture.cluster.applies().is_empty());
    }

    /// **`T15.2` end-to-end:** wired `InventorySyncPipeline` + `apply_once_with_events` emits
    /// `Normal SyncSucceeded`, `Normal ResourcePruned`, and rate-limited `Warning SyncFailed`
    /// without spamming on no-op `SyncSkipped` passes or failing when event publishing fails.
    #[tokio::test]
    async fn wired_pipeline_emits_sync_succeeded_resource_pruned_and_rate_limited_sync_failed() {
        use crate::events::test_support::ManualClock;
        use crate::events::{
            AppEventType, EVENT_REASON_RESOURCE_PRUNED, EVENT_REASON_SYNC_FAILED,
            EVENT_REASON_SYNC_SUCCEEDED, EventRecorder, RecordingEventPublisher,
        };
        use crate::reconcile::apply_once_with_events;

        const SECOND_CONFIGMAP: &str = "\
apiVersion: v1
kind: ConfigMap
metadata:
  name: extra
data:
  key: value
";

        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[
            ("configmap.yaml", CONFIGMAP_WITH_DATA),
            ("extra.yaml", SECOND_CONFIGMAP),
        ]);

        let clock = Arc::new(ManualClock::new());
        let publisher = Arc::new(RecordingEventPublisher::new());
        let events = EventRecorder::new(publisher.clone()).with_clock(clock.clone());
        let writer = RecordingStatus::default();

        // Pass 1: initial sync of 2 ConfigMaps -> emits 1 Normal SyncSucceeded.
        let mut app = fixture.app(".");
        app.spec.sync_policy = Some(ferriscd_crd::SyncPolicy {
            automated: Some(ferriscd_crd::AutomatedSyncPolicy {
                prune: true,
                self_heal: true,
            }),
            ..Default::default()
        });
        apply_once_with_events(&app, &fixture.pipeline, &writer, &events)
            .await
            .expect("initial sync succeeds");

        let pass1_events = publisher.events();
        assert_eq!(pass1_events.len(), 1, "{pass1_events:?}");
        assert_eq!(pass1_events[0].type_, AppEventType::Normal);
        assert_eq!(pass1_events[0].reason, EVENT_REASON_SYNC_SUCCEEDED);

        // Pass 2: already synced (`Skip`) -> emits zero new events (no spam).
        fixture.cluster.seed_applied();
        publisher.clear();
        app.status = writer.last();
        apply_once_with_events(&app, &fixture.pipeline, &writer, &events)
            .await
            .expect("already-synced pass succeeds");
        assert!(
            publisher.events().is_empty(),
            "already-synced Skip pass must not spam Normal SyncSucceeded: {:?}",
            publisher.events()
        );

        // Pass 3: remove `extra.yaml` so prune deletes `/ConfigMap/payments/extra` -> emits
        // `Normal ResourcePruned` (naming the GKNN key) AND `Normal SyncSucceeded`.
        publisher.clear();
        fixture.commit(&[("configmap.yaml", CONFIGMAP_WITH_DATA)]);
        app.status = writer.last();
        apply_once_with_events(&app, &fixture.pipeline, &writer, &events)
            .await
            .expect("prune pass succeeds");

        let pass3_events = publisher.events();
        assert_eq!(pass3_events.len(), 2, "{pass3_events:?}");
        assert_eq!(pass3_events[0].type_, AppEventType::Normal);
        assert_eq!(pass3_events[0].reason, EVENT_REASON_RESOURCE_PRUNED);
        assert!(
            pass3_events[0].note.contains("/ConfigMap/payments/extra"),
            "ResourcePruned note must list the pruned GKNN key: {}",
            pass3_events[0].note
        );
        assert_eq!(pass3_events[1].type_, AppEventType::Normal);
        assert_eq!(pass3_events[1].reason, EVENT_REASON_SYNC_SUCCEEDED);

        // Pass 4 & 5: repeated failure within 5 minutes -> only 1 Warning SyncFailed; after 5 min
        // emits again.
        publisher.clear();
        let mut broken = app.clone();
        broken.spec.project = "does-not-exist".to_owned();
        assert!(
            apply_once_with_events(&broken, &fixture.pipeline, &writer, &events)
                .await
                .is_err()
        );
        clock.advance(Duration::from_secs(120));
        assert!(
            apply_once_with_events(&broken, &fixture.pipeline, &writer, &events)
                .await
                .is_err()
        );
        assert_eq!(
            publisher.events().len(),
            1,
            "second failure inside 5-minute window must be deduplicated"
        );
        assert_eq!(publisher.events()[0].type_, AppEventType::Warning);
        assert_eq!(publisher.events()[0].reason, EVENT_REASON_SYNC_FAILED);

        clock.advance(Duration::from_secs(180));
        assert!(
            apply_once_with_events(&broken, &fixture.pipeline, &writer, &events)
                .await
                .is_err()
        );
        assert_eq!(
            publisher.events().len(),
            2,
            "failure after 5-minute window must emit again"
        );

        // Pass 6: publisher failure must never fail a real sync pass.
        let failing_events = EventRecorder::new(Arc::new(RecordingEventPublisher::failing(
            "events API unavailable",
        )));
        fixture.commit(&[
            ("configmap.yaml", CONFIGMAP_WITH_DATA),
            ("extra.yaml", SECOND_CONFIGMAP),
        ]);
        app.status = writer.last();
        apply_once_with_events(&app, &fixture.pipeline, &writer, &failing_events)
            .await
            .expect("sync must succeed even when event publishing fails");
    }
}
