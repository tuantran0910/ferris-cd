//! The wired sync pipeline: `Application` -> Git -> manifests -> scope -> live state ->
//! SSA `dryRun=All` diff -> sync decision -> ordered SSA apply -> crash-safe inventory ->
//! `/status`.
//!
//! This is the first *real* [`SyncPipeline`]. Phase 07 replaced the `v0.2` "apply everything on
//! every pass" loop with a diff-gated one: the pipeline classifies the whole bundle with a
//! Server-Side Apply dry-run (T07.1–T07.3), asks
//! [`ferriscd_engine::diff::should_sync`] whether this reconcile may apply anything (T07.4), and
//! then applies **only** what the diff says needs it (`applyOutOfSyncOnly`).
//!
//! | Concern | Here | Later phase |
//! |---|---|---|
//! | Drift detection | SSA `dryRun=All` diff of the stamped desired set, `ignoreDifferences` honoured | — |
//! | Sync decision gate | `automated: None` / `selfHeal` / source change (`revision` + `lastSyncedSpecHash`) / manual operation | `T10.x` consumes `ferriscd.io/operation` |
//! | Force | `false` for both the dry-run and the apply (trap T5); `serverSideForce` is logged and ignored | `T08.4` (`takeoverFieldManagers`) |
//! | Prune | minimal: only with `automated.prune` and only when the gate executes; only `OwnedBySelf`, never `CRD`/`Namespace` unless opted in, reverse key order (not reverse wave order) | `T08.1` reverse prune order, `T08.2` `SyncPlan`, `T08.5` ownership-verified pruner |
//! | CRD `Established` wait | a CRD + CR bundle simply requeues (`DeferredPendingCrd`) until discovery serves the kind | `T08.3` |
//! | `createNamespace: true` | **rejected** with an actionable message; namespace creation is not wired | `T08.2`/`T08.3` (`pre_create_namespace`) |
//! | Waves/hooks | rejected with an actionable message instead of being mis-ordered | `T10.x` |
//! | Destination clusters | `in-cluster` only; anything else is rejected | `T12.x` credentials |
//! | Git credentials | anonymous only | `T12.x` |
//!
//! Blocking work never runs on a Tokio worker: manifest file I/O and YAML parsing run in
//! `tokio::task::spawn_blocking` here, and the repo/git layer does the same internally. Every
//! Kubernetes call — the live GETs, the `dryRun=All` PATCHes and the real applies — is a plain
//! async `kube` request. The diff *comparison* itself is CPU-only engine code over the payloads
//! the API server returned, so it never blocks a worker on a syscall either.
//!
//! `syncOptions.createNamespace` is rejected instead of silently livelocking: there is no
//! namespace creator, so a `404` in a namespace nobody declares would classify as
//! `DeferredPendingNamespace` and requeue forever. Declaring the `Namespace` in Git (or
//! creating it by hand) is the supported path until `T08.3` adds on-demand creation.
//!
//! Three safety properties are non-negotiable and implemented here:
//!
//! * **Ownership is verified before any mutation** (the `T06.4` trap guard, trap T10). Every
//!   desired key whose live object carries a *foreign* `ferriscd.io/tracking-id` fails the
//!   reconcile **before** a single `Patch` is issued — before the dry-run pass too — so two
//!   `Application`s pointing at the same manifest can never fight over (or prune) each other's
//!   workloads. The failure is terminal (retrying cannot help) and still reports
//!   `status.sync.status = OutOfSync`.
//! * **Nothing is applied without proof it is needed.** The dry-run diff decides; a `Skip` from
//!   [`should_sync`] issues **zero** mutating `Patch` calls, and a second reconcile of an
//!   already-synced `Application` converges to exactly that (the assertion the T07.5 live test
//!   makes against a real API server).
//! * **The inventory is crash-safe.** It is only ever `next_inventory(prev, confirmed,
//!   pruned_ok)`, and a mid-sync failure still persists the partial inventory
//!   ([`ReconcileError::PartialSync`]), so a create that already succeeded can never become an
//!   untracked orphan (finding C1).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ferriscd_crd::application::DEFAULT_DESTINATION_CLUSTER;
use ferriscd_crd::status::{REASON_SYNC_SUCCEEDED, SyncState, SyncStatus};
use ferriscd_crd::{Application, SyncOptions, annotations};
use ferriscd_engine::diff::{
    DiffStatus, DiffSummary, IgnoreRuleSet, ResourceDiff, SyncDecision, should_sync,
    source_spec_hash,
};
use ferriscd_engine::graph::sort_by_tier;
use ferriscd_engine::inventory::{self, Inventory, InventoryEntry, Ownership};
use ferriscd_engine::manifest::{self, DesiredResource, ManifestLoaderConfig, ResourceKey};
use ferriscd_engine::repo::{GitSource, RepoCache, RepoCheckout, RepoCredentials, RepoUrlPolicy};
use futures::future::BoxFuture;
use kube::ResourceExt;
use kube::api::{self, Api, ApiResource, DeleteParams, DynamicObject, Patch, PatchParams};
use kube::discovery::Scope;
use tracing::warn;

use crate::discovery::DiscoveryCache;
use crate::dry_run::{DryRunApi, DryRunEvaluator};
use crate::live_state::{
    ClusterStateReader, FetchRequest, LiveObjectSource, LiveState, LiveStateMap, TrackingOwner,
    plan_fetch,
};
use crate::reconcile::{
    ApplyOutcome, CleanupMode, CleanupOutcome, REASON_PENDING, REASON_SYNC_SKIPPED, ReconcileError,
    SyncPipeline, now,
};
use crate::scope::{self, InBundleCrd};

/// Requeue delay while any resource is pending on a `CustomResourceDefinition` or namespace.
///
/// A pending resource is not an error (it is the documented `DeferredPending*` behaviour), so
/// the controller retries quickly instead of waiting for the full `spec.requeueAfterSeconds`.
pub const PENDING_REQUEUE: Duration = Duration::from_secs(10);

/// The only destination cluster this milestone can talk to.
pub const IN_CLUSTER: &str = DEFAULT_DESTINATION_CLUSTER;

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
#[derive(Clone, Copy, Debug, Default)]
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
}

/// What one prune pass did.
#[derive(Debug, Default)]
struct PruneReport {
    /// Keys that were confirmed gone (`Delete` accepted, `404`, `410`).
    pruned: Vec<ResourceKey>,
    /// Orphans deliberately left alone, so a stuck orphan is visible in `/status`.
    retained: usize,
}

/// A resolved apply/delete target.
#[derive(Clone, Debug)]
struct Target {
    api_resource: ApiResource,
    scope: Scope,
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
            match api
                .delete(&request.key.name, &DeleteParams::default())
                .await
            {
                Ok(_) => Ok(DeleteOutcome::Deleted),
                Err(err) if is_absent(&err) => Ok(DeleteOutcome::AlreadyGone),
                Err(source) => Err(ReconcileError::Delete { resource, source }),
            }
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

/// The wired [`SyncPipeline`].
pub struct InventorySyncPipeline {
    repos: Arc<RepoCache>,
    discovery: DiscoveryCache,
    reader: ClusterStateReader,
    applier: Arc<dyn Applier>,
    dry_run: Arc<dyn DryRunApi>,
    loader: ManifestLoaderConfig,
    url_policy: RepoUrlPolicy,
    mutating_applies: Arc<AtomicUsize>,
}

impl std::fmt::Debug for InventorySyncPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InventorySyncPipeline")
            .field("discovery", &self.discovery)
            .field("loader", &self.loader)
            .field("url_policy", &self.url_policy)
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
            loader: ManifestLoaderConfig::default(),
            url_policy: RepoUrlPolicy::Production,
            mutating_applies: Arc::new(AtomicUsize::new(0)),
        }
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

    /// Overrides the manifest loader budgets.
    #[must_use]
    pub fn with_loader_config(mut self, loader: ManifestLoaderConfig) -> Self {
        self.loader = loader;
        self
    }

    /// The configured repository URL policy (production rejects local paths).
    #[must_use]
    pub fn url_policy(&self) -> RepoUrlPolicy {
        self.url_policy
    }

    /// Runs one apply pass.
    async fn sync_apply(&self, app: &Application) -> Result<ApplyOutcome, ReconcileError> {
        app.spec.validate().map_err(|err| ReconcileError::Invalid {
            message: err.to_string(),
        })?;
        if app.spec.destination.cluster != IN_CLUSTER {
            return Err(ReconcileError::Invalid {
                message: format!(
                    "spec.destination.cluster '{}' is not supported yet: only '{IN_CLUSTER}' can \
                     be synced (remote destination clusters arrive with cluster credentials, \
                     Phase 12)",
                    app.spec.destination.cluster
                ),
            });
        }
        let options = app.spec.sync_options();
        // Rejected before *anything* else happens: `v0.2` never creates a namespace, so honoring
        // the flag would classify every key in the missing namespace as
        // `DeferredPendingNamespace` and requeue forever without ever making progress.
        if options.create_namespace {
            return Err(ReconcileError::Invalid {
                message: "syncOptions.createNamespace is not supported in v0.2; declare the \
                          Namespace in Git or create it manually"
                    .to_owned(),
            });
        }
        let owner = TrackingOwner::for_application(app).ok_or_else(|| ReconcileError::Invalid {
            message: "the Application has no metadata.namespace, so no ferriscd.io/tracking-id \
                      can be verified"
                .to_owned(),
        })?;
        let prev_inventory = status_inventory(app)?;

        if options.server_side_force {
            warn!(
                app.namespace = %owner.namespace,
                app.name = %owner.name,
                "spec.syncPolicy.syncOptions.serverSideForce is ignored in v0.2: every apply uses \
                 force=false so field conflicts stay visible (trap T5)"
            );
        }

        let (revision, mut resources) = self.fetch_desired(app).await?;
        let (in_bundle_crds, in_bundle_namespaces) = self
            .prepare(&mut resources, &app.spec.destination.namespace)
            .await?;
        // Stamp ownership *after* scope normalization, because the marker is rendered from the
        // final GKNN key (Phase 05 mirrors the effective namespace onto the key).
        stamp_ownership(&mut resources, &owner)?;

        let desired_inventory = inventory::inventory_from_desired(&resources);
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
                    app.spec.source.git.repo_url,
                    app.spec.source.git.path,
                    prev_inventory.len()
                ),
            });
        }

        let requests = plan_fetch(&desired_inventory, &prev_inventory);
        let live = self
            .reader
            .fetch_live(
                &requests,
                &self.discovery,
                &in_bundle_crds,
                &in_bundle_namespaces,
                &owner,
            )
            .await?;

        // Trap guard: ownership is verified for the whole bundle *before* any mutation — and
        // before the dry-run pass, so an object another `Application` owns never even receives a
        // `dryRun=All` PATCH. The failure is terminal and still reports `OutOfSync`.
        if let Err(err) = reject_foreign_ownership(&resources, &live) {
            return Err(ReconcileError::OwnershipConflict {
                message: err.to_string(),
                inventory: prev_inventory,
                revision: Some(revision),
            });
        }

        // --- Phase 07: diff gate -------------------------------------------------------
        // The dry-run diff runs over `resources`, which is the *stamped* slice the applier
        // receives below (see `DryRunEvaluator::evaluate`'s desired-body contract: diffing a
        // pre-stamp body would look like a request to remove `ferriscd.io/tracking-id`, leaving
        // every resource `OutOfSync` forever).
        let orphans = inventory::orphans(&desired_inventory, &prev_inventory);
        let rules = IgnoreRuleSet::from_ignore_differences(&app.spec.ignore_differences);
        // Finding H1: a pointer that is not valid RFC 6901 is never applied (a typo must not
        // fail the reconcile), so it must be *visible* instead of silently dropped: one warning
        // per pointer here, plus a count in the `Ready` message below (a log line is not
        // observable on the CR).
        let invalid_ignore_pointers = report_invalid_pointers(&rules, &owner);
        let diffs = self
            .evaluate_diff(&resources, &orphans, &live, &rules)
            .await?;
        let summary = DiffSummary::from_diffs(&diffs);
        let spec_hash = source_spec_hash(&app.spec).map_err(|err| ReconcileError::Invalid {
            message: err.to_string(),
        })?;
        let decision = should_sync(app, &revision, &spec_hash, &summary, manual_operation(app));
        let statuses = status_by_key(&diffs);
        let apply_keys = apply_selection(
            decision,
            &statuses,
            &resources,
            options.apply_out_of_sync_only,
        );
        let execute = decision.is_execute();
        if execute {
            tracing::debug!(
                app.namespace = %owner.namespace,
                app.name = %owner.name,
                decision = %decision,
                to_apply = apply_keys.len(),
                out_of_sync = summary.out_of_sync,
                missing = summary.missing,
                synced = summary.synced,
                "diff gate decided to sync"
            );
        } else {
            tracing::debug!(
                app.namespace = %owner.namespace,
                app.name = %owner.name,
                decision = %decision,
                out_of_sync = summary.out_of_sync,
                missing = summary.missing,
                "diff gate skipped this reconcile"
            );
        }

        // --- apply -------------------------------------------------------------------------
        // `applied_ok`: applies this pass confirmed (the crash-safe inventory input).
        // `synced_ok`: resources the diff verified are already in place *and* carry our
        // `tracking-id`, so they are recorded without a mutating call.
        let mut applied_ok = Inventory::new();
        let mut synced_ok = Inventory::new();
        let mut pending: Vec<ResourceKey> = Vec::new();

        for resource in &resources {
            if live.get(&resource.key).is_some_and(LiveState::is_deferred) {
                // `DeferredPendingCrd` / `DeferredPendingNamespace`: requeue, never fail — but
                // only a pass that actually tried to apply has something to wait for.
                if execute {
                    pending.push(resource.key.clone());
                }
                continue;
            }

            // Finding C1: a `Synced` resource exists and is ours, so it belongs in the
            // inventory even on a skipped pass — otherwise a wiped `status.inventory` would leak
            // it as an untracked orphan (the `v0.2` loop re-applied everything and self-healed).
            if statuses
                .get(&resource.key)
                .is_some_and(DiffStatus::is_synced)
            {
                synced_ok.insert(
                    resource.key.clone(),
                    InventoryEntry::new(resource.gvk.version.clone()),
                );
            }

            if !apply_keys.contains(&resource.key) {
                // `applyOutOfSyncOnly` (the default): the diff says this one already matches,
                // so it must not be patched again.
                continue;
            }

            let target = self.resolve_desired_target(resource).await?;
            let namespace = desired_namespace(resource, target.scope)?;
            let request = ApplyRequest {
                resource,
                api_resource: &target.api_resource,
                namespace: namespace.as_deref(),
                // `serverSideForce` stays ignored: the dry-run and the apply must agree, and a
                // forced apply silently steals fields another manager owns (trap T5).
                force: false,
            };

            self.mutating_applies.fetch_add(1, Ordering::SeqCst);
            match self.applier.apply(request).await {
                Ok(_) => {
                    applied_ok.insert(
                        resource.key.clone(),
                        InventoryEntry::new(resource.gvk.version.clone()),
                    );
                }
                Err(err) => {
                    // Crash-safe: persist what already applied instead of losing it (C1).
                    return Err(ReconcileError::PartialSync {
                        message: err.to_string(),
                        inventory: inventory::next_inventory(&prev_inventory, &applied_ok, &[]),
                        revision: Some(revision),
                    });
                }
            }
        }

        // Prune is part of "execute": a gate that decided to skip issues no deletes either.
        let prune_enabled = prune_enabled(app);
        let prune = if execute {
            self.prune(
                app,
                &options,
                &desired_inventory,
                &prev_inventory,
                &live,
                &applied_ok,
                &revision,
                &owner,
            )
            .await?
        } else {
            PruneReport::default()
        };

        // Finding H2: with pruning disabled `prune()` is a pure no-op and reports zero, while the
        // diff still classified the tracked-but-undesired keys as orphans. They *are* retained
        // (FerrisCD will never delete them), so the count comes from the summary there.
        let retained_orphans = if prune_enabled {
            prune.retained
        } else {
            summary.orphaned
        };

        let confirmed = inventory::next_inventory(&applied_ok, &synced_ok, &[]);
        let next_inventory = inventory::next_inventory(&prev_inventory, &confirmed, &prune.pruned);
        Ok(build_outcome(
            app,
            decision,
            &summary,
            &spec_hash,
            SyncCounts {
                desired: resources.len(),
                applied: applied_ok.len(),
                pruned: prune.pruned.len(),
                retained_orphans,
                pending: pending.len(),
                invalid_ignore_pointers,
                prune_enabled,
            },
            revision,
            next_inventory,
        ))
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
        resources: &[DesiredResource],
        orphans: &[ResourceKey],
        live: &LiveStateMap,
        rules: &IgnoreRuleSet,
    ) -> Result<Vec<ResourceDiff>, ReconcileError> {
        DryRunEvaluator::with_api(self.dry_run.clone(), self.discovery.clone())
            .evaluate(resources, orphans, live, rules)
            .await
            .map_err(ReconcileError::Diff)
    }

    /// Resolves the revision and loads the desired manifest set off the worker pool.
    async fn fetch_desired(
        &self,
        app: &Application,
    ) -> Result<(String, Vec<DesiredResource>), ReconcileError> {
        let source = GitSource::new(
            app.spec.source.git.repo_url.clone(),
            app.spec.source.git.target_revision.clone(),
            app.spec.source.git.path.clone(),
        );
        // Explicit, configurable local-repository policy: `Production` rejects `file://` and
        // bare local paths, so a misconfigured `Application` cannot read the pod's filesystem.
        source.validate(self.url_policy)?;

        // Phase 12 reads credentials from a `RepoCredentials` Secret; v0.2 is anonymous only.
        let credentials = RepoCredentials::Anonymous;
        let resolved = self.repos.resolve_revision(&source, &credentials).await?;
        let checkout = self
            .repos
            .checkout(&source, &resolved.commit_sha, &credentials)
            .await?;

        let source_path = app.spec.source.git.path.clone();
        let loader = self.loader.clone();
        // All manifest file I/O and YAML parsing runs off the Tokio worker pool.
        let resources = tokio::task::spawn_blocking(move || {
            load_desired_resources(&checkout, &source_path, &loader)
        })
        .await
        .map_err(|err| ReconcileError::Invalid {
            message: format!("manifest loading task failed: {err}"),
        })??;

        Ok((resolved.commit_sha, resources))
    }

    /// Rejects unsupported manifests, collects in-bundle CRDs/namespaces, refreshes discovery
    /// and normalizes the cluster-aware scope of every resource.
    async fn prepare(
        &self,
        resources: &mut [DesiredResource],
        destination_namespace: &str,
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
            self.discovery.ensure_fresh().await?;
        } else {
            self.discovery.invalidate_and_refresh().await?;
        }
        scope::normalize_scopes(
            resources,
            destination_namespace,
            &self.discovery,
            &in_bundle_crds,
        )?;
        // Namespace injection can create GKNN collisions that were absent in the raw set.
        manifest::check_duplicate_keys(resources.iter())?;
        Ok((in_bundle_crds, in_bundle_namespaces))
    }

    /// Resolves the exact GVK the manifest asks for.
    ///
    /// No version fallback here: a manifest that pins an unserved `apiVersion` is a spec bug
    /// and must fail terminally instead of being silently applied through another version.
    async fn resolve_desired_target(
        &self,
        resource: &DesiredResource,
    ) -> Result<Target, ReconcileError> {
        let gvk = api::GroupVersionKind::gvk(
            &resource.gvk.group,
            &resource.gvk.version,
            &resource.gvk.kind,
        );
        let (api_resource, capabilities) = self.discovery.resolve(&gvk).await?;
        Ok(Target {
            api_resource,
            scope: capabilities.scope,
        })
    }

    /// Resolves a version-agnostic key: version hint first, then any served version.
    ///
    /// Used for deletes, where only the `status.inventory` hint is available and identity must
    /// survive an API upgrade (finding C2).
    async fn resolve_key(
        &self,
        key: &ResourceKey,
        version_hint: Option<&str>,
    ) -> Result<Option<Target>, ReconcileError> {
        if let Some(version) = version_hint.map(str::trim).filter(|hint| !hint.is_empty()) {
            let gvk = api::GroupVersionKind::gvk(&key.group, version, &key.kind);
            match self.discovery.resolve(&gvk).await {
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
        Ok(self
            .discovery
            .resolve_kind(&key.group, &key.kind)
            .await?
            .map(|(api_resource, capabilities)| Target {
                api_resource,
                scope: capabilities.scope,
            }))
    }

    /// Minimal `v0.2` prune.
    ///
    /// Only runs with `spec.syncPolicy.automated.prune`, only deletes objects that are
    /// verifiably `OwnedBySelf` — **twice**: once from the pass-level live read and once more
    /// immediately before `Delete`, because a live object can be taken over or deleted between
    /// the two (TOCTOU) — and never deletes `CRD`/`Namespace` unless explicitly opted in.
    /// Deliberately *not* the full planner: deletion order is reverse key order rather than
    /// reverse sync-wave order (`T08.1`/`T08.2`), and `ferriscd.io/prune: "false"` is the only
    /// per-resource opt-out. The dedicated ownership-verified pruner is `T08.5`.
    #[allow(clippy::too_many_arguments)]
    async fn prune(
        &self,
        app: &Application,
        options: &SyncOptions,
        desired: &Inventory,
        prev_inventory: &Inventory,
        live: &BTreeMap<ResourceKey, LiveState>,
        applied_ok: &Inventory,
        revision: &str,
        owner: &TrackingOwner,
    ) -> Result<PruneReport, ReconcileError> {
        let mut report = PruneReport::default();
        if !prune_enabled(app) {
            return Ok(report);
        }

        let mut orphans = inventory::orphans(desired, prev_inventory);
        if desired.is_empty() && !orphans.is_empty() {
            // Reachable only with `FERRISCD_ALLOW_EMPTY_DESIRED` set: a repository (or
            // `spec.source.git.path`) that renders nothing prunes the whole inventory. That is
            // literal GitOps behaviour, but it must never happen silently.
            warn!(
                destination.namespace = %app.spec.destination.namespace,
                orphans = orphans.len(),
                "the desired set is empty and pruning is enabled: every tracked resource will be \
                 pruned"
            );
        }
        // Reverse key order: reverse-wave ordering arrives with the sync planner (`T08.1`).
        orphans.reverse();

        for key in orphans {
            let Some(state) = live.get(&key) else {
                // Not fetched at all: never delete something this pass did not classify.
                report.retained += 1;
                continue;
            };
            match state {
                // A confirmed absence counts as a confirmed prune (MASTER_PLAN §4.3).
                LiveState::Missing | LiveState::OrphanGvkGone => report.pruned.push(key),
                LiveState::Present(object, Ownership::OwnedBySelf) => {
                    if !prune_allowed(&key, options, object) {
                        report.retained += 1;
                        continue;
                    }
                    let hint = prev_inventory.get(&key).map(|entry| entry.version.as_str());
                    let Some(target) = self.resolve_key(&key, hint).await? else {
                        // The kind disappeared between the fetch and the delete: it is gone.
                        report.pruned.push(key);
                        continue;
                    };
                    let namespace = match target.scope {
                        Scope::Namespaced => key.namespace.clone(),
                        Scope::Cluster => None,
                    };
                    // TOCTOU: re-read and re-classify right before the delete. Pruning is the
                    // highest-blast-radius operation, so a stale verdict from the pass-level
                    // fetch is not good enough.
                    let rechecked = self
                        .reader
                        .recheck(
                            &key,
                            Some(target.api_resource.version.as_str()),
                            &self.discovery,
                            &[],
                            &[],
                            owner,
                        )
                        .await?;
                    match &rechecked {
                        LiveState::Present(fresh, Ownership::OwnedBySelf) => {
                            // The opt-out annotation may have changed in the same window.
                            if !prune_allowed(&key, options, fresh) {
                                report.retained += 1;
                                continue;
                            }
                        }
                        // Gone in the meantime: a confirmed absence is a confirmed prune.
                        LiveState::Missing | LiveState::OrphanGvkGone => {
                            report.pruned.push(key);
                            continue;
                        }
                        other => {
                            warn!(
                                resource = %key.canonical(),
                                state = %describe_state(other),
                                "refusing to prune: the object changed between the live read and \
                                 the delete"
                            );
                            report.retained += 1;
                            continue;
                        }
                    }
                    let request = DeleteRequest {
                        key: &key,
                        api_resource: &target.api_resource,
                        namespace: namespace.as_deref(),
                    };
                    match self.applier.delete(request).await {
                        Ok(DeleteOutcome::Deleted | DeleteOutcome::AlreadyGone) => {
                            report.pruned.push(key);
                        }
                        Err(err) => {
                            return Err(ReconcileError::PartialSync {
                                message: err.to_string(),
                                inventory: inventory::next_inventory(
                                    prev_inventory,
                                    applied_ok,
                                    &report.pruned,
                                ),
                                revision: Some(revision.to_owned()),
                            });
                        }
                    }
                }
                // Never delete something we cannot prove we own, or something still pending.
                LiveState::Present(_, ownership) => {
                    warn!(
                        resource = %key.canonical(),
                        ownership = %describe_ownership(ownership),
                        "refusing to prune a resource this Application does not own"
                    );
                    report.retained += 1;
                }
                LiveState::DeferredPendingCrd | LiveState::DeferredPendingNamespace => {
                    report.retained += 1;
                }
            }
        }
        Ok(report)
    }

    /// Cleans up managed resources when the `Application` is being deleted.
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

        let requests: Vec<FetchRequest> = inventory
            .iter()
            .map(|(key, entry)| {
                FetchRequest::new(key.clone(), vec![entry.version.clone()]).as_orphan()
            })
            .collect();
        let live = self
            .reader
            .fetch_live(&requests, &self.discovery, &[], &[], &owner)
            .await?;

        let options = app.spec.sync_options();
        let mut keys: Vec<&ResourceKey> = live.keys().collect();
        keys.reverse();

        for key in keys {
            let Some(LiveState::Present(object, Ownership::OwnedBySelf)) = live.get(key) else {
                // Gone, foreign or unmanaged: never delete on cascade either.
                continue;
            };
            if !prune_allowed(key, &options, object) {
                continue;
            }
            let hint = inventory.get(key).map(|entry| entry.version.as_str());
            let Some(target) = self.resolve_key(key, hint).await? else {
                continue;
            };
            let namespace = match target.scope {
                Scope::Namespaced => key.namespace.clone(),
                Scope::Cluster => None,
            };
            self.applier
                .delete(DeleteRequest {
                    key,
                    api_resource: &target.api_resource,
                    namespace: namespace.as_deref(),
                })
                .await?;
        }
        Ok(CleanupOutcome::Completed)
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
}

/// Stamps `ferriscd.io/tracking-id` onto every desired resource.
///
/// Hooks are never stamped (and are rejected earlier), so nothing that could be created
/// imperatively ends up looking prunable.
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
/// whether anything is applied. Whether an operation annotation came from this reconcile or a
/// previous one is not trackable until `T10.x` persists and clears `status.operationState`; until
/// then "present operation ⇒ manual" is the conservative reading (it can only cause an extra
/// idempotent apply, never a missed sync).
#[must_use]
pub fn manual_operation(app: &Application) -> bool {
    app.annotations()
        .get(annotations::OPERATION)
        .is_some_and(|value| !value.trim().is_empty())
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

/// Selects the desired keys this pass must apply.
///
/// The trap guard for `syncOptions.applyOutOfSyncOnly` (default `true`) lives here, as one pure
/// function, so the "synced resources are skipped cleanly" property is provable without a
/// cluster: a `Skip` decision (or a resource the diff classified `Synced`) can never end up in
/// the returned set. A resource with no diff entry at all is *not* applied — every desired key is
/// classified by [`DryRunEvaluator::evaluate`], so a missing entry means the pass never looked at
/// it, and patching something that was never compared would defeat the gate.
#[must_use]
fn apply_selection(
    decision: SyncDecision,
    statuses: &BTreeMap<ResourceKey, DiffStatus>,
    resources: &[DesiredResource],
    apply_out_of_sync_only: bool,
) -> BTreeSet<ResourceKey> {
    if decision.is_skip() {
        return BTreeSet::new();
    }
    resources
        .iter()
        .filter(|resource| {
            !apply_out_of_sync_only
                || statuses
                    .get(&resource.key)
                    .is_some_and(DiffStatus::needs_apply)
        })
        .map(|resource| resource.key.clone())
        .collect()
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
    } = counts;
    let complete = pending == 0;
    // Only "executed *and* nothing left pending" may claim a full sync.
    let synced = decision.is_execute() && complete;
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

    let (reason, message) = match decision {
        SyncDecision::Skip(skip) => (
            REASON_SYNC_SKIPPED,
            format!(
                "no sync performed: {skip}; {desired} resource(s) at revision {short}, \
                 {} out of sync, {} missing, {} orphan(s){retained}{invalid}",
                summary.out_of_sync, summary.missing, summary.orphaned
            ),
        ),
        SyncDecision::Execute(trigger) if complete => (
            REASON_SYNC_SUCCEEDED,
            format!(
                "applied {applied} of {desired} resource(s) at revision {short}, \
                 pruned {pruned}{retained}{invalid} ({trigger})"
            ),
        ),
        SyncDecision::Execute(_) => (
            REASON_PENDING,
            format!(
                "applied {applied} of {desired} resource(s) at revision {short}; {pending} \
                 resource(s) pending on a CustomResourceDefinition or namespace{retained}{invalid}"
            ),
        ),
    };

    let requeue = if decision.is_execute() && !complete {
        // A deferred resource is retried quickly; the full interval is for settled passes.
        PENDING_REQUEUE
    } else {
        Duration::from_secs(u64::from(app.spec.requeue_after_seconds))
    };

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

/// Returns whether a live object may be deleted.
///
/// Safety rails: `CustomResourceDefinition` and `Namespace` need an explicit opt-in, and
/// `ferriscd.io/prune: "false"` opts out a single resource.
fn prune_allowed(key: &ResourceKey, options: &SyncOptions, object: &DynamicObject) -> bool {
    let opted_out = object
        .metadata
        .annotations
        .as_ref()
        .and_then(|map| map.get(annotations::PRUNE))
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("false"));
    if opted_out {
        return false;
    }

    if key.group == scope::APIEXTENSIONS_GROUP && key.kind == scope::CRD_KIND {
        if !options.prune_crds {
            warn!(
                resource = %key.canonical(),
                "not pruning a CustomResourceDefinition: set syncOptions.pruneCRDs to opt in"
            );
            return false;
        }
        return true;
    }
    if key.group.is_empty() && key.kind == "Namespace" && !options.prune_namespaces {
        warn!(
            resource = %key.canonical(),
            "not pruning a Namespace: set syncOptions.pruneNamespaces to opt in"
        );
        return false;
    }
    true
}

/// Human-readable ownership, used only in warnings.
fn describe_ownership(ownership: &Ownership) -> &'static str {
    match ownership {
        Ownership::OwnedBySelf => "OwnedBySelf",
        Ownership::Unmanaged => "Unmanaged",
        Ownership::OwnedByForeign(_) => "OwnedByForeign",
    }
}

/// Human-readable live state, used only in warnings.
fn describe_state(state: &LiveState) -> &'static str {
    match state {
        LiveState::Present(_, ownership) => describe_ownership(ownership),
        LiveState::Missing => "Missing",
        LiveState::DeferredPendingCrd => "DeferredPendingCrd",
        LiveState::DeferredPendingNamespace => "DeferredPendingNamespace",
        LiveState::OrphanGvkGone => "OrphanGvkGone",
    }
}

/// Rejects manifests `v0.2` cannot order or track correctly.
fn reject_unsupported(resource: &DesiredResource) -> Result<(), ReconcileError> {
    let name = resource.key.canonical();
    if resource.object.metadata.generate_name.is_some() {
        return Err(ReconcileError::Invalid {
            message: format!(
                "{name}: metadata.generateName is not supported by the v0.2 controller \
                 (lifecycle hooks arrive in Phase 10)"
            ),
        });
    }
    let hook = resource
        .object
        .metadata
        .annotations
        .as_ref()
        .and_then(|map| map.get(annotations::HOOK))
        .map(|phase| phase.trim().to_owned())
        .filter(|phase| !phase.is_empty());
    if let Some(phase) = hook {
        return Err(ReconcileError::Invalid {
            message: format!(
                "{name}: lifecycle hooks are not supported by the v0.2 controller \
                 (found {} = {phase}; Phase 10)",
                annotations::HOOK
            ),
        });
    }
    Ok(())
}

/// Returns the namespace a namespaced target must be applied in.
fn desired_namespace(
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

/// Loads, parses, normalizes and tier-sorts the desired manifest set (blocking).
///
/// A free function so it can run inside `tokio::task::spawn_blocking` holding no `&self`.
fn load_desired_resources(
    checkout: &RepoCheckout,
    source_path: &str,
    loader: &ManifestLoaderConfig,
) -> Result<Vec<DesiredResource>, ReconcileError> {
    let files = manifest::load(checkout.root_dir(), source_path, loader)?;

    let mut resources = Vec::new();
    for file in files {
        resources.extend(manifest::parse_file(&file.source_file, &file.contents)?);
    }

    let resources = manifest::normalize(resources)?;
    manifest::check_duplicate_keys(resources.iter())?;
    Ok(sort_by_tier(resources))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ferriscd_crd::application::{
        DEFAULT_REQUEUE_AFTER_SECONDS, DEFAULT_REVISION_HISTORY_LIMIT,
    };
    use ferriscd_crd::status::{
        ApplicationStatus, CONDITION_READY, Condition, ConditionStatus, HealthState, HealthStatus,
    };
    use ferriscd_crd::{
        ApplicationSpec, AutomatedSyncPolicy, DestinationSpec, GitSourceSpec, RendererSpec,
        SourceSpec, SyncPolicy,
    };
    use ferriscd_engine::diff::{SkipReason, SyncTrigger};
    use ferriscd_engine::manifest::GroupVersionKind;
    use ferriscd_engine::repo::{FakeGitClient, FakeGitClientConfig, RepoCacheConfig};
    use kube::discovery::ApiCapabilities;
    use serde_json::json;

    use super::*;
    use crate::discovery::{DiscoveryFuture, DiscoverySnapshot, DiscoverySource};
    use crate::dry_run::{DryRunFuture, DryRunOutcome, DryRunTarget};
    use crate::live_state::{FetchTarget, LiveFuture};
    use crate::reconcile::{REASON_OWNERSHIP_CONFLICT, StatusWriter, apply_once};

    // ---------------------------------------------------------------------
    // Fixtures
    // ---------------------------------------------------------------------

    /// Scripted API server: live objects keyed by canonical GKNN.
    #[derive(Default)]
    struct FakeCluster {
        objects: StdMutex<BTreeMap<String, DynamicObject>>,
        namespaces: StdMutex<Vec<String>>,
        applies: StdMutex<Vec<String>>,
        applied_objects: StdMutex<Vec<DynamicObject>>,
        applied_tracking_ids: StdMutex<Vec<String>>,
        deletes: StdMutex<Vec<String>>,
        fail_apply: StdMutex<Vec<String>>,
        /// GKNNs whose `tracking-id` is replaced with a foreign one after their first `GET`
        /// (simulates a takeover between the pass-level fetch and the prune re-check).
        ownership_flip_after_get: StdMutex<Vec<String>>,
        deletes_confirmed: AtomicUsize,
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

        fn fail_apply_for(self, key: &str) -> Self {
            self.fail_apply.lock().unwrap().push(key.to_owned());
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
                self.cluster.applies.lock().unwrap().push(key);
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
    }

    /// Scripted discovery source whose snapshot the test can mutate between reconciles.
    #[derive(Default)]
    struct FakeDiscovery {
        snapshot: StdMutex<DiscoverySnapshot>,
        fetches: AtomicUsize,
    }

    impl FakeDiscovery {
        fn with_cluster_kinds() -> Self {
            let mut snapshot = DiscoverySnapshot::new("v1.35.0");
            for (group, kind, scope) in [
                ("", "ConfigMap", Scope::Namespaced),
                ("", "Namespace", Scope::Cluster),
                ("", "Service", Scope::Namespaced),
                ("apps", "Deployment", Scope::Namespaced),
                (scope::APIEXTENSIONS_GROUP, scope::CRD_KIND, Scope::Cluster),
            ] {
                snapshot = with_resource(snapshot, group, kind, scope);
            }
            Self {
                snapshot: StdMutex::new(snapshot),
                fetches: AtomicUsize::new(0),
            }
        }

        /// Simulates a `CustomResourceDefinition` becoming established.
        fn install(&self, group: &str, kind: &str, scope: Scope) {
            let mut snapshot = self.snapshot.lock().unwrap();
            *snapshot = with_resource(snapshot.clone(), group, kind, scope);
        }

        fn fetches(&self) -> usize {
            self.fetches.load(Ordering::SeqCst)
        }
    }

    fn with_resource(
        snapshot: DiscoverySnapshot,
        group: &str,
        kind: &str,
        scope: Scope,
    ) -> DiscoverySnapshot {
        let mut resource = ApiResource::from_gvk(&api::GroupVersionKind::gvk(group, "v1", kind));
        resource.plural = format!("{}s", kind.to_ascii_lowercase());
        snapshot.with_resource(resource, capabilities(scope))
    }

    impl DiscoverySource for FakeDiscovery {
        fn fetch(&self) -> DiscoveryFuture<'_> {
            Box::pin(async move {
                self.fetches.fetch_add(1, Ordering::SeqCst);
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
        pipeline: InventorySyncPipeline,
        repo_url: String,
        _temp: tempfile::TempDir,
    }

    fn fixture(cluster: FakeCluster) -> Fixture {
        fixture_with(cluster, FakeDryRun::default())
    }

    fn fixture_with(cluster: FakeCluster, dry_run: FakeDryRun) -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let git = Arc::new(FakeGitClient::with_config(FakeGitClientConfig {
            url_policy: RepoUrlPolicy::AllowLocal,
            work_root: Some(temp.path().join("work")),
        }));
        let cluster = Arc::new(cluster);
        let discovery = Arc::new(FakeDiscovery::with_cluster_kinds());
        let dry_run = Arc::new(dry_run);
        let repos = Arc::new(RepoCache::new(
            git.clone(),
            RepoCacheConfig::new(temp.path().join("cache")),
        ));
        let pipeline = InventorySyncPipeline::new(
            repos,
            cache(discovery.clone()),
            cluster.clone(),
            Arc::new(FakeApplier {
                cluster: cluster.clone(),
            }),
            dry_run.clone(),
        )
        .with_url_policy(RepoUrlPolicy::AllowLocal);
        let repo_url = temp.path().join("repo.git").display().to_string();
        Fixture {
            git,
            cluster,
            discovery,
            dry_run,
            pipeline,
            repo_url,
            _temp: temp,
        }
    }

    impl Fixture {
        fn commit(&self, files: &[(&str, &str)]) -> String {
            self.git.add_commit("main", files.iter().copied())
        }

        fn app(&self, path: &str) -> Application {
            application(&self.repo_url, path, "payments")
        }
    }

    const CONFIGMAP: &str = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\n";
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
        assert_eq!(
            outcome.requeue,
            Some(Duration::from_secs(u64::from(
                DEFAULT_REQUEUE_AFTER_SECONDS
            )))
        );
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

    // ---------------------------------------------------------------------
    // Deferred states
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn a_pending_crd_defers_the_custom_resource_and_requeues() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[
            (
                "crd.yaml",
                "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: widgets.example.com\nspec:\n  group: example.com\n  names:\n    kind: Widget\n    plural: widgets\n  scope: Namespaced\n  versions:\n    - name: v1\n      served: true\n      storage: true\n      schema:\n        openAPIV3Schema:\n          type: object\n",
            ),
            (
                "widget.yaml",
                "apiVersion: example.com/v1\nkind: Widget\nmetadata:\n  name: one\n",
            ),
        ]);
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

    #[tokio::test]
    async fn a_bundle_with_a_crd_forces_a_discovery_refresh_so_the_deferred_cr_lands() {
        // Pass 1: the CRD applies, the CR is deferred on a kind the cluster does not serve yet.
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[
            (
                "crd.yaml",
                "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: widgets.example.com\nspec:\n  group: example.com\n  names:\n    kind: Widget\n    plural: widgets\n  scope: Namespaced\n  versions:\n    - name: v1\n      served: true\n      storage: true\n      schema:\n        openAPIV3Schema:\n          type: object\n",
            ),
            (
                "widget.yaml",
                "apiVersion: example.com/v1\nkind: Widget\nmetadata:\n  name: one\n",
            ),
        ]);
        let app = fixture.app(".");
        let first = fixture.pipeline.apply(&app).await.expect("first pass");
        assert_eq!(first.reason, REASON_PENDING);
        let fetches_after_first = fixture.discovery.fetches();

        // The API server now serves the new kind (the CRD got established).
        fixture
            .discovery
            .install("example.com", "Widget", Scope::Namespaced);

        // A fresh 1h snapshot would hide the new kind for minutes; the bundle contains a CRD, so
        // the pass must force a refresh instead of trusting the TTL (trap T6).
        let second = fixture.pipeline.apply(&app).await.expect("second pass");
        assert!(
            fixture.discovery.fetches() > fetches_after_first,
            "a bundle that defines CRDs must force a discovery refresh"
        );
        assert_eq!(
            second.reason, REASON_SYNC_SUCCEEDED,
            "the deferred custom resource must land on the follow-up pass: {}",
            second.message
        );
        assert!(
            fixture
                .cluster
                .applies()
                .iter()
                .any(|applied| applied == "example.com/Widget/payments/one"),
            "the custom resource must be applied: {:?}",
            fixture.cluster.applies()
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

    #[tokio::test]
    async fn create_namespace_is_rejected_instead_of_livelocking() {
        // H1: v0.2 never creates a namespace, so honoring the flag would defer every key
        // forever. It must fail terminally on the *first* pass instead.
        let fixture = fixture(FakeCluster::default());
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);
        let mut app = fixture.app(".");
        app.spec.sync_policy = Some(SyncPolicy {
            automated: None,
            sync_options: Some(ferriscd_crd::SyncOptions {
                create_namespace: true,
                ..ferriscd_crd::SyncOptions::default()
            }),
            retry: None,
        });

        let err = fixture
            .pipeline
            .apply(&app)
            .await
            .expect_err("createNamespace must be rejected, not deferred");

        assert!(
            matches!(err, ReconcileError::Invalid { .. }),
            "the rejection must be terminal: {err}"
        );
        assert_eq!(err.failure_class(), crate::FailureClass::Terminal);
        let message = err.to_string();
        assert!(message.contains("createNamespace"), "{message}");
        assert!(
            message.contains("declare the Namespace in Git"),
            "the message must be actionable: {message}"
        );
        assert!(
            fixture.cluster.applies().is_empty() && fixture.cluster.deletes().is_empty(),
            "nothing may be applied or deleted when the option is rejected"
        );
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
            }),
            Arc::new(FakeDryRun::default()),
        );
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

    #[tokio::test]
    async fn a_remote_destination_cluster_is_rejected() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[("configmap.yaml", CONFIGMAP)]);
        let mut app = fixture.app(".");
        app.spec.destination.cluster = "prod-cluster".to_owned();

        let err = fixture.pipeline.apply(&app).await.expect_err("rejected");
        assert!(err.to_string().contains("prod-cluster"), "{err}");
        assert!(fixture.cluster.applies().is_empty());
    }

    #[tokio::test]
    async fn lifecycle_hooks_and_generate_name_are_rejected() {
        let fixture = fixture(FakeCluster::default().with_namespace("payments"));
        fixture.commit(&[(
            "hook.yaml",
            "apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: migrate\n  annotations:\n    ferriscd.io/hook: PreSync\n",
        )]);
        let app = fixture.app(".");
        let err = fixture
            .pipeline
            .apply(&app)
            .await
            .expect_err("hooks are unsupported");
        assert!(err.to_string().contains("lifecycle hooks"), "{err}");

        fixture.commit(&[(
            "hook.yaml",
            "apiVersion: batch/v1\nkind: Job\nmetadata:\n  generateName: migrate-\n",
        )]);
        let err = fixture
            .pipeline
            .apply(&app)
            .await
            .expect_err("generateName is unsupported");
        assert!(err.to_string().contains("generateName"), "{err}");
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

    /// A desired `ConfigMap` for the pure selection tests.
    fn desired_configmap(name: &str) -> DesiredResource {
        DesiredResource {
            key: ResourceKey::new("", "ConfigMap", Some("payments".to_owned()), name),
            gvk: GroupVersionKind::parse("v1", "ConfigMap").unwrap(),
            object: config_map(name, None),
            source_file: "configmap.yaml".to_owned(),
        }
    }

    fn operation_annotation() -> BTreeMap<String, String> {
        BTreeMap::from([(
            annotations::OPERATION.to_owned(),
            r#"{"sync":{"revision":"main"}}"#.to_owned(),
        )])
    }

    /// **Trap guard** (`applyOutOfSyncOnly`): a resource the diff classified `Synced` is never
    /// selected for an apply, and a skipped pass selects nothing at all.
    #[test]
    fn apply_out_of_sync_only_skips_synced_resources() {
        let settings = desired_configmap("settings");
        let extra = desired_configmap("extra");
        let resources = vec![settings.clone(), extra.clone()];

        let statuses = BTreeMap::from([
            (settings.key.clone(), DiffStatus::Synced),
            (extra.key.clone(), DiffStatus::OutOfSync),
        ]);
        let execute = SyncDecision::Execute(SyncTrigger::DriftDetected);

        assert_eq!(
            apply_selection(execute, &statuses, &resources, true),
            BTreeSet::from([extra.key.clone()]),
            "only the out-of-sync resource may be patched"
        );
        assert_eq!(
            apply_selection(execute, &statuses, &resources, false),
            BTreeSet::from([settings.key.clone(), extra.key.clone()]),
            "applyOutOfSyncOnly: false applies the whole desired set"
        );
        for skip in [
            SkipReason::AutomatedDisabled,
            SkipReason::SelfHealDisabled,
            SkipReason::AlreadySynced,
        ] {
            assert!(
                apply_selection(SyncDecision::Skip(skip), &statuses, &resources, false).is_empty(),
                "a skip decision must never select an apply ({skip})"
            );
        }

        // A `Missing` resource needs a create, an orphan needs nothing.
        let mixed = BTreeMap::from([
            (settings.key.clone(), DiffStatus::Missing),
            (extra.key.clone(), DiffStatus::Orphaned),
        ]);
        assert_eq!(
            apply_selection(execute, &mixed, &resources, true),
            BTreeSet::from([settings.key.clone()])
        );

        // A resource the diff never classified must not be patched blind.
        assert!(
            apply_selection(execute, &BTreeMap::new(), &resources, true).is_empty(),
            "an unclassified resource must never be applied"
        );
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
                desired: 3,
                applied: 1,
                pruned: 0,
                retained_orphans: 0,
                pending: 2,
                invalid_ignore_pointers: 0,
                prune_enabled: false,
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
                desired: 3,
                applied: 3,
                pruned: 1,
                retained_orphans: 0,
                pending: 0,
                invalid_ignore_pointers: 0,
                prune_enabled: false,
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
                desired: 1,
                applied: 1,
                pruned: 0,
                retained_orphans: 1,
                pending: 0,
                invalid_ignore_pointers: 0,
                prune_enabled: false,
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
                desired: 2,
                applied: 0,
                pruned: 0,
                retained_orphans: 0,
                pending: 0,
                invalid_ignore_pointers: 0,
                prune_enabled: false,
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
                desired: 2,
                applied: 0,
                pruned: 0,
                retained_orphans: 0,
                pending: 0,
                invalid_ignore_pointers: 0,
                prune_enabled: false,
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
            desired: 0,
            applied: 0,
            pruned: 0,
            retained_orphans: 1,
            pending: 0,
            invalid_ignore_pointers: 1,
            prune_enabled: false,
        };

        let skipped = build_outcome(
            &app,
            SyncDecision::Skip(ferriscd_engine::diff::SkipReason::SelfHealDisabled),
            &orphan_summary,
            HASH,
            counts,
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

    #[test]
    fn prune_safety_rails_protect_opted_out_resources_crds_and_namespaces() {
        let options = SyncOptions::default();
        let crd = ResourceKey::new(
            scope::APIEXTENSIONS_GROUP,
            scope::CRD_KIND,
            None,
            "widgets.example.com",
        );
        let namespace = ResourceKey::new("", "Namespace", None, "team-a");
        let configmap = ResourceKey::new("", "ConfigMap", Some("payments".to_owned()), "settings");
        let object = config_map("settings", None);

        assert!(!prune_allowed(&crd, &options, &object));
        assert!(!prune_allowed(&namespace, &options, &object));
        assert!(prune_allowed(&configmap, &options, &object));

        let opted_in = SyncOptions {
            prune_crds: true,
            prune_namespaces: true,
            ..SyncOptions::default()
        };
        assert!(prune_allowed(&crd, &opted_in, &object));
        assert!(prune_allowed(&namespace, &opted_in, &object));

        let mut opted_out = object.clone();
        opted_out
            .metadata
            .annotations
            .get_or_insert_with(BTreeMap::new)
            .insert(annotations::PRUNE.to_owned(), "FALSE".to_owned());
        assert!(!prune_allowed(&configmap, &opted_in, &opted_out));
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
}
