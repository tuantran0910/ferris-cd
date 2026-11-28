//! Opt-in `ApplicationSet` controller (`T19.3`).
//!
//! This is an **independent** loop next to the `Application` controller: it watches
//! `ApplicationSet` objects in the control-plane namespace, evaluates their generator through
//! [`ferriscd_engine::applicationset`], and creates/updates the generated `Application`s **in the
//! `ApplicationSet`'s own namespace**. It is off unless `--enable-applicationsets` is passed
//! (`RunOptions::enable_applicationsets`), so upgrading FerrisCD never starts writing objects an
//! operator did not ask for.
//!
//! # What this module owns, and what it deliberately does not
//!
//! The engine decides *what* the fleet is (generators, templating, the fan-out cap, ownership and
//! prune/deletion planning) and is fully unit-tested without a cluster. This module owns the I/O:
//!
//! * every API read/write goes through [`ApplicationSetStore`], so the whole reconcile is testable
//!   with an in-memory fake that records writes (which is how "zero partial writes" is proven);
//! * the cluster generator reads the registry through
//!   [`ClusterManagerParamSource`], which is `ClusterManager::registrations()` — the same
//!   lifecycle-tracked snapshot `Application` destination resolution uses, never a `Secret` read;
//! * the Git generator reads repositories through [`RepoCacheParamSource`], i.e. the same
//!   `RepoCache` + `GIT` client + `ferriscd.io/secret-type=repository` credentials the sync pipeline
//!   uses, so a worktree is materialized and `sanitize_worktree`-checked before a single parameter
//!   file is parsed;
//! * every generated `Application` is authorized by [`ProjectPolicyAuthorizer`] **before** the first
//!   write, using the same [`AppProjectPolicy`] and [`ApplicationScope`] the reconcile pipeline
//!   uses. A generated `Application` therefore cannot bypass tenancy.
//!
//! # Deletion safety
//!
//! Generated `Application`s carry a same-namespace `ownerReference`, which is exactly what
//! Kubernetes garbage collection follows. The controller therefore adds the
//! [`ferriscd_crd::APPLICATIONSET_FINALIZER`] finalizer and, on deletion with
//! `spec.syncPolicy.preserveResourcesOnDeletion: true` (the default), **orphans** the generated
//! `Application`s — drops its owner reference, keeps the object and its workloads — before releasing
//! the finalizer. With `preserveResourcesOnDeletion: false` it deletes them instead. Nothing else in
//! the loop can delete an `Application`: pruning is opt-in (`spec.syncPolicy.prune`) and only ever
//! touches objects this `ApplicationSet` provably owns.
//!
//! # Failure behaviour
//!
//! Every pass patches `/status` (both on success and on failure) with `Ready`, `observedGeneration`,
//! and `generatedCount`, and a failure makes **no** write at all — the plan is computed in full
//! before the first API call, so a fan-out refusal, a template error, a policy violation, or a
//! transient Git error can never leave a half-applied fleet or delete the existing one.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use ferriscd_crd::applicationset::{
    APPLICATIONSET_FINALIZER, APPLICATIONSET_LABEL, ApplicationSet, ApplicationSetStatus,
};
use ferriscd_crd::{API_GROUP, Application};
use ferriscd_engine::applicationset::{
    ApplicationSetError, ClusterParamSource, ClusterRegistration, DeletionAction, Generation,
    GitParameterSource, Ownership, PruneAction, ReconcileAction, ReconcilePlan, plan_deletion,
    plan_reconcile,
};
use ferriscd_engine::policy::{AppProjectPolicy, ApplicationScope};
use ferriscd_engine::repo::{GitSource, RepoCache, RepoCheckout, RepoFuture, RepoUrlPolicy};
use futures::FutureExt as _;
use futures::future::BoxFuture;
use futures::stream::{BoxStream, StreamExt as _};
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams, Preconditions};
use kube::runtime::{WatchStreamExt as _, watcher};
use kube::{Client, ResourceExt};
use tokio::sync::broadcast;

use crate::cluster_manager::{ClusterLifecycleEvent, ClusterManager};
use crate::credentials::CredentialSource;
use crate::project::ProjectSource;
use crate::reconcile::now;

/// Default periodic re-evaluation interval when an `ApplicationSet` omits `requeueAfterSeconds`.
pub const DEFAULT_APPLICATIONSET_INTERVAL: Duration = Duration::from_secs(180);

/// How often the loop looks for due `ApplicationSet`s (never the reconcile interval itself).
const SCHEDULE_TICK: Duration = Duration::from_secs(5);

/// How often the loop re-reads the whole `ApplicationSet` set (`InitDone` also triggers one).
const CACHE_RESYNC_PERIOD: Duration = Duration::from_secs(600);

/// A failure of one `ApplicationSet` pass.
///
/// `Api` failures are retryable (the API server may be rolling), while [`ApplicationSetError`] and
/// policy refusals are terminal until the object changes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApplicationSetControllerError {
    /// The pure engine refused the `ApplicationSet`.
    #[error(transparent)]
    Engine(#[from] ApplicationSetError),

    /// A Kubernetes API read/write failed.
    #[error("the Kubernetes API operation failed: {message}")]
    Api {
        /// Bounded error text (never a credential).
        message: String,
        /// Whether a retry can succeed.
        retryable: bool,
    },

    /// A generated `Application` is not permitted by its `AppProject`.
    #[error("generated Application {name:?} is not permitted by its AppProject: {message}")]
    Policy {
        /// The generated `Application` name.
        name: String,
        /// The policy violation (a `PolicyError` message; never a credential value).
        message: String,
    },
}

impl ApplicationSetControllerError {
    /// Whether retrying the same inputs can succeed.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Engine(err) => err.is_retryable(),
            Self::Api { retryable, .. } => *retryable,
            Self::Policy { .. } => false,
        }
    }

    /// A bounded, machine-readable condition reason.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Engine(err) => err.reason(),
            Self::Api {
                retryable: true, ..
            } => "ApiError",
            Self::Api {
                retryable: false, ..
            } => "ApiRejected",
            Self::Policy { .. } => "PolicyViolation",
        }
    }
}

/// Reads and writes the objects one `ApplicationSet` pass touches.
///
/// All methods are object-safe and cloneable-by-`Arc`, so the reconciler is a plain struct with no
/// Kubernetes types beyond the manifests themselves.
pub trait ApplicationSetStore: Send + Sync + 'static {
    /// Lists every `Application` of `namespace` (the only namespace a generated `Application` may
    /// live in). Used for conflict detection, so it must not be filtered by the generated label.
    fn list_applications<'a>(
        &'a self,
        namespace: &'a str,
    ) -> BoxFuture<'a, Result<Vec<Application>, ApplicationSetControllerError>>;

    /// Server-Side-Apply one generated `Application` (creates or converges it).
    fn upsert<'a>(
        &'a self,
        application: &'a Application,
    ) -> BoxFuture<'a, Result<(), ApplicationSetControllerError>>;

    /// Deletes one generated `Application` (`prune` or `preserveResourcesOnDeletion: false`).
    ///
    /// `uid` is the identity the plan read (see `PruneDecision::uid`) and must become the delete's
    /// `Preconditions.uid`: between the list that produced the plan and this delete, the object may
    /// have been removed and re-created under the same name by someone else, and a name-only delete
    /// would then destroy an `Application` this `ApplicationSet` never owned.
    fn delete<'a>(
        &'a self,
        namespace: &'a str,
        name: &'a str,
        uid: Option<&'a str>,
    ) -> BoxFuture<'a, Result<(), ApplicationSetControllerError>>;

    /// Drops this controller's `ownerReference` from `application`, keeping the object.
    ///
    /// The patch carries the listed object's identity (`uid`, `resourceVersion`) so it can only ever
    /// hit the object the plan read. The two rejections that guard produces mean **opposite**
    /// things, so neither may be read as "gone" on its own (findings C-1, H-1):
    ///
    /// | answer | cause | outcome |
    /// |---|---|---|
    /// | `409 Conflict` | the `resourceVersion` is stale — what a routine `/status` write on the child does | the same object is still there: recompute from a live read and retry once |
    /// | `422 Invalid` | `metadata.uid` is immutable, so the name belongs to a **different** object | the listed object is gone |
    ///
    /// `Ok(())` therefore means "the listed `Application` no longer references this
    /// `ApplicationSet`" — orphaned, or already gone (`404`, or the live `uid` differs). A conflict
    /// that survives the retry is an **error and retryable**, because releasing the finalizer on a
    /// child that still carries its owner reference hands the whole fleet to garbage collection.
    fn orphan<'a>(
        &'a self,
        application: &'a Application,
    ) -> BoxFuture<'a, Result<(), ApplicationSetControllerError>>;

    /// Adds the `ApplicationSet` finalizer if it is missing.
    ///
    /// Only *this* finalizer may be added: another manager's finalizers are never replaced.
    fn ensure_finalizer<'a>(
        &'a self,
        appset: &'a ApplicationSet,
    ) -> BoxFuture<'a, Result<(), ApplicationSetControllerError>>;

    /// Removes the `ApplicationSet` finalizer, keeping every other finalizer.
    fn remove_finalizer<'a>(
        &'a self,
        appset: &'a ApplicationSet,
    ) -> BoxFuture<'a, Result<(), ApplicationSetControllerError>>;

    /// Patches the `/status` subresource.
    fn patch_status<'a>(
        &'a self,
        appset: &'a ApplicationSet,
        status: &'a ApplicationSetStatus,
    ) -> BoxFuture<'a, Result<(), ApplicationSetControllerError>>;
}

/// Authorizes one generated `Application` before it is written.
pub trait ApplicationAuthorizer: Send + Sync + 'static {
    /// Returns `Ok(())` when the `Application` may be created, or a refusal.
    fn authorize<'a>(
        &'a self,
        application: &'a Application,
    ) -> BoxFuture<'a, Result<(), ApplicationSetControllerError>>;

    /// Returns `Ok(())` when **every** `Application` of one plan may be created, or the first
    /// refusal.
    ///
    /// The default is the per-`Application` loop above. [`ProjectPolicyAuthorizer`] overrides it
    /// with a per-pass memo so a 200-`Application` fleet reads each distinct `AppProject` once
    /// (finding M-a) instead of once per generated `Application`.
    fn authorize_all<'a>(
        &'a self,
        applications: &'a [&'a Application],
    ) -> BoxFuture<'a, Result<(), ApplicationSetControllerError>> {
        Box::pin(async move {
            for application in applications {
                self.authorize(application).await?;
            }
            Ok(())
        })
    }
}

/// What one `ApplicationSet` pass did (for tests, logs, and metrics).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// The `ApplicationSet` name.
    pub name: String,
    /// How many `Application`s the generation produced.
    pub generated: usize,
    /// `Create` writes that succeeded.
    pub created: usize,
    /// `Update` writes that succeeded.
    pub updated: usize,
    /// `Application`s that already matched (no write).
    pub skipped: usize,
    /// Generated `Application`s deleted by an opted-in prune.
    pub pruned: usize,
    /// Generated `Application`s kept by the default prune protection.
    pub kept: usize,
    /// Generated `Application`s orphaned because the `ApplicationSet` is being deleted.
    pub orphaned: usize,
    /// Generated `Application`s deleted because the `ApplicationSet` is being deleted and
    /// `preserveResourcesOnDeletion` is `false`.
    pub deleted: usize,
    /// The failure, when the pass did not complete.
    pub failure: Option<ApplicationSetControllerError>,
}

impl ReconcileReport {
    fn new(appset: &ApplicationSet) -> Self {
        Self {
            name: appset.name_any(),
            ..Self::default()
        }
    }

    /// Whether the pass succeeded.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.failure.is_none()
    }
}

/// The `ApplicationSet` reconciler: engine + stores + policy, no watches.
pub struct ApplicationSetReconciler {
    namespace: String,
    clusters: Arc<dyn ClusterParamSource>,
    git: Arc<dyn GitParameterSource>,
    store: Arc<dyn ApplicationSetStore>,
    authorizer: Arc<dyn ApplicationAuthorizer>,
}

impl std::fmt::Debug for ApplicationSetReconciler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApplicationSetReconciler")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl ApplicationSetReconciler {
    /// Builds a reconciler. `namespace` is the control-plane namespace, which is the only namespace
    /// an `ApplicationSet` is read from or may generate into.
    #[must_use]
    pub fn new(
        namespace: impl Into<String>,
        clusters: Arc<dyn ClusterParamSource>,
        git: Arc<dyn GitParameterSource>,
        store: Arc<dyn ApplicationSetStore>,
        authorizer: Arc<dyn ApplicationAuthorizer>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            clusters,
            git,
            store,
            authorizer,
        }
    }

    /// Runs one pass over `appset` and patches `/status`.
    ///
    /// The pass is planned **completely** before the first write: a failure returns with
    /// [`ReconcileReport::failure`] set and no object was created, updated, pruned, or deleted.
    pub async fn reconcile(&self, appset: &ApplicationSet) -> ReconcileReport {
        let mut report = ReconcileReport::new(appset);
        let outcome = self.reconcile_inner(appset, &mut report).await;
        if let Err(error) = outcome {
            tracing::warn!(
                appset = %appset.name_any(),
                namespace = %self.namespace,
                reason = error.reason(),
                retryable = error.is_retryable(),
                error = %error,
                "ApplicationSet pass failed; no generated Application was written or deleted"
            );
            report.failure = Some(error);
        }
        // Always-update-status: patch on both outcomes. A status write failure is logged, never
        // allowed to mask the pass result (and never retried from here: the next pass does it).
        let status = self.status_for(appset, &report);
        if let Err(error) = self.store.patch_status(appset, &status).await {
            tracing::warn!(
                appset = %appset.name_any(),
                error = %error,
                "failed to patch ApplicationSet /status"
            );
        }
        report
    }

    async fn reconcile_inner(
        &self,
        appset: &ApplicationSet,
        report: &mut ReconcileReport,
    ) -> Result<(), ApplicationSetControllerError> {
        if appset.namespace().as_deref() != Some(self.namespace.as_str()) {
            // ApplicationSets are control-plane objects; a copy in a tenant namespace is not
            // reconciled at all (the watch is namespaced, so this is defense in depth).
            return Err(ApplicationSetControllerError::Api {
                message: format!(
                    "the ApplicationSet lives in namespace {:?}, outside the control-plane \
                     namespace {:?}",
                    appset.namespace().unwrap_or_default(),
                    self.namespace
                ),
                retryable: false,
            });
        }

        let existing = self.store.list_applications(&self.namespace).await?;

        if appset.metadata.deletion_timestamp.is_some() {
            return self.reconcile_deletion(appset, &existing, report).await;
        }

        // The engine validates the spec, expands the generator (bounded), renders and de-duplicates
        // every template. Any failure here is returned before a single write.
        let generation: Generation = ferriscd_engine::applicationset::generate(
            appset,
            self.clusters.as_ref(),
            self.git.as_ref(),
        )
        .await?;
        report.generated = generation.len();

        let plan: ReconcilePlan = plan_reconcile(appset, &generation, &existing)?;

        // Every generated Application is authorized before the first write (`T12.1`/`T12.2`). The
        // whole plan goes through one call so the authorizer can read each distinct `AppProject`
        // once per pass rather than once per `Application` (finding M-a).
        let planned: Vec<&Application> = plan
            .applications
            .iter()
            .map(|planned| &planned.rendered.application)
            .collect();
        self.authorizer.authorize_all(&planned).await?;

        self.store.ensure_finalizer(appset).await?;

        for planned in &plan.applications {
            match planned.action {
                ReconcileAction::Skip => report.skipped = report.skipped.saturating_add(1),
                ReconcileAction::Create => {
                    self.store.upsert(&planned.rendered.application).await?;
                    report.created = report.created.saturating_add(1);
                }
                ReconcileAction::Update => {
                    self.store.upsert(&planned.rendered.application).await?;
                    report.updated = report.updated.saturating_add(1);
                }
            }
        }

        // Prune last, and only after every create/update succeeded.
        for decision in &plan.prune {
            match decision.action {
                PruneAction::Keep => {
                    report.kept = report.kept.saturating_add(1);
                }
                PruneAction::Delete => {
                    self.store
                        .delete(&self.namespace, &decision.name, decision.uid.as_deref())
                        .await?;
                    report.pruned = report.pruned.saturating_add(1);
                }
            }
        }
        Ok(())
    }

    async fn reconcile_deletion(
        &self,
        appset: &ApplicationSet,
        existing: &[Application],
        report: &mut ReconcileReport,
    ) -> Result<(), ApplicationSetControllerError> {
        let plan = plan_deletion(appset, existing);
        for target in &plan.actions {
            match target.action {
                DeletionAction::Orphan => {
                    let Some(application) = existing
                        .iter()
                        .find(|application| application.name_any() == target.name)
                    else {
                        continue;
                    };
                    self.store.orphan(application).await?;
                    report.orphaned = report.orphaned.saturating_add(1);
                }
                DeletionAction::Delete => {
                    self.store
                        .delete(&self.namespace, &target.name, target.uid.as_deref())
                        .await?;
                    report.deleted = report.deleted.saturating_add(1);
                }
            }
        }
        // Only now may the object disappear: with `preserveResourcesOnDeletion: true` the children
        // no longer reference it, so garbage collection has nothing to cascade to.
        self.store.remove_finalizer(appset).await?;
        report.generated = existing
            .iter()
            .filter(|application| {
                ferriscd_engine::applicationset::ownership(application, appset)
                    == Ownership::Managed
            })
            .count();
        Ok(())
    }

    fn status_for(
        &self,
        appset: &ApplicationSet,
        report: &ReconcileReport,
    ) -> ApplicationSetStatus {
        let mut status = appset.status.clone().unwrap_or_default();
        status.observed_generation = appset.metadata.generation;
        match &report.failure {
            None => {
                status.generated_count = u32::try_from(report.generated).unwrap_or(u32::MAX);
                status.mark_ready(
                    "ApplicationsGenerated",
                    crate::reconcile::bounded(&format!(
                        "{} Application(s) generated ({} created, {} updated, {} unchanged, {} \
                         pruned, {} kept)",
                        report.generated,
                        report.created,
                        report.updated,
                        report.skipped,
                        report.pruned,
                        report.kept
                    )),
                    now(),
                );
            }
            Some(error) => {
                // `generatedCount` keeps the last successful count: a failed pass did not generate
                // anything, and zeroing it would hide how large the fleet currently is.
                status.mark_not_ready(
                    error.reason(),
                    crate::reconcile::bounded(&error.to_string()),
                    now(),
                );
            }
        }
        status
    }
}

// ---------------------------------------------------------------------------
// Production adapters
// ---------------------------------------------------------------------------

/// [`ApplicationSetStore`] backed by the `ferriscd.io/v1alpha1` APIs.
#[derive(Clone)]
pub struct KubeApplicationSetStore {
    client: Client,
    namespace: String,
}

impl std::fmt::Debug for KubeApplicationSetStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubeApplicationSetStore")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl KubeApplicationSetStore {
    /// Builds a store operating in the control-plane namespace.
    #[must_use]
    pub fn new(client: Client, namespace: impl Into<String>) -> Self {
        Self {
            client,
            namespace: namespace.into(),
        }
    }

    fn applications(&self, namespace: &str) -> Api<Application> {
        Api::namespaced(self.client.clone(), namespace)
    }

    fn appsets(&self) -> Api<ApplicationSet> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    /// Adds or drops this controller's finalizer through one resourceVersion-preconditioned merge
    /// patch (finding N-2).
    ///
    /// `cached` is the watch snapshot the pass was planned from. When it already agrees with the
    /// requested transition nothing is written (and nothing is read). Otherwise the transition is
    /// recomputed against a **live** read, so another manager's finalizer — added after the snapshot,
    /// or already there — is preserved: a merge patch must state the whole array, and the fresh read
    /// plus its `resourceVersion` make the write conditional on the object not having changed again
    /// since.
    async fn write_finalizer(
        &self,
        cached: &ApplicationSet,
        op: FinalizerOp,
    ) -> Result<(), ApplicationSetControllerError> {
        if finalizer_patch_body(cached, op).is_none() {
            return Ok(());
        }
        let name = cached.name_any();
        let live = match self.appsets().get(&name).await {
            Ok(live) => live,
            // Gone: there is no finalizer left to set or clear.
            Err(error) => return finalizer_outcome(&error),
        };
        let Some(body) = finalizer_patch_body(&live, op) else {
            return Ok(());
        };
        match self
            .appsets()
            .patch(&name, &PatchParams::default(), &Patch::Merge(&body))
            .await
        {
            Ok(_) => Ok(()),
            Err(error) => finalizer_outcome(&error),
        }
    }

    /// Sends the orphan patch for `application` once and classifies the answer.
    ///
    /// The body carries the identity of the object the caller read (`orphan_patch_body`), so the API
    /// server can only apply it to that object.
    async fn patch_orphan(
        &self,
        namespace: &str,
        application: &Application,
    ) -> Result<OrphanPatch, ApplicationSetControllerError> {
        let name = application.name_any();
        let body = orphan_patch_body(application)?;
        match self
            .applications(namespace)
            .patch(&name, &PatchParams::default(), &Patch::Merge(&body))
            .await
        {
            Ok(_) => Ok(OrphanPatch::Done),
            Err(error) => orphan_patch_outcome(&error),
        }
    }

    /// Decides what an orphan-patch conflict means by reading the live object **once** (findings
    /// C-1, H-1).
    ///
    /// The two codes the identity guard produces are opposites, and only the live object tells them
    /// apart:
    ///
    /// * **no live object** (`404`) — it is gone; same end state as the `404` the patch itself can
    ///   answer;
    /// * **a different `uid`** — the name was deleted and re-created, so the listed object is gone
    ///   and the new one keeps its own owner references;
    /// * **the same `uid`** — the object is still there and the patch was merely *stale* (a routine
    ///   `/status` write is enough), so the patch is recomputed from the live read — identity fields
    ///   from *that* read — and retried **once**.
    ///
    /// A conflict that survives the retry is **retryable, never "gone"**: releasing the
    /// `ApplicationSet` finalizer while a child still references it lets Kubernetes garbage
    /// collection delete the entire fleet, so the `ApplicationSet` stays `Terminating` for one more
    /// pass instead.
    async fn resolve_orphan_conflict(
        &self,
        namespace: &str,
        application: &Application,
    ) -> Result<(), ApplicationSetControllerError> {
        let name = application.name_any();
        let listed_uid = application.metadata.uid.as_deref();
        let live = match self.applications(namespace).get_opt(&name).await {
            Ok(live) => live,
            Err(error) => return Err(api_error(&error)),
        };
        let Some(live) = live else {
            return Ok(());
        };
        // A listed object without a `uid` is an unpersisted fixture, so there is no evidence of a
        // re-creation: taking the safe branch means retrying, never releasing the finalizer on an
        // object that might still reference this `ApplicationSet`.
        if let (Some(listed), Some(current)) = (listed_uid, live.metadata.uid.as_deref())
            && listed != current
        {
            return Ok(());
        }
        match self.patch_orphan(namespace, &live).await? {
            OrphanPatch::Done => Ok(()),
            OrphanPatch::Conflict => Err(ApplicationSetControllerError::Api {
                message: crate::reconcile::bounded(&format!(
                    "the owner-reference patch for Application {name:?} was rejected twice with a \
                     conflicting identity; the object is still present, so it is retained and \
                     retried rather than treated as gone"
                )),
                retryable: true,
            }),
        }
    }
}

fn api_error(error: &kube::Error) -> ApplicationSetControllerError {
    ApplicationSetControllerError::Api {
        message: crate::reconcile::bounded(&error.to_string()),
        retryable: api_retryable(error),
    }
}

/// Whether retrying the identical request can succeed.
///
/// Terminal: the request itself is rejected (authz, schema, or a field conflict another manager
/// owns). Retrying the identical body can never succeed, and a retry loop would only hide it.
fn api_retryable(error: &kube::Error) -> bool {
    !matches!(
        error,
        kube::Error::Api(status)
            if status.code == 400 || status.code == 403 || status.code == 409 || status.code == 422
    )
}

/// Classifies a failed `AppProject` read (finding N-b).
///
/// Before this, **every** failure of the authorizer's project read was retryable, so a permanently
/// rejected read — a `403` from an RBAC rule that does not grant `get appprojects`, a `422` the
/// generated `Application` provokes — was retried forever and never surfaced as the misconfiguration
/// it is. The API half now uses [`api_error`]'s classification (identical to every other API call in
/// this module); the rest of the seam's errors (`Invalid`: the `AppProject` CRD is not installed) are
/// terminal exactly as the reconcile pipeline classifies them.
fn project_error(error: &crate::reconcile::ReconcileError) -> ApplicationSetControllerError {
    match error {
        crate::reconcile::ReconcileError::Api(error) => api_error(error),
        other => ApplicationSetControllerError::Api {
            message: crate::reconcile::bounded(&other.to_string()),
            retryable: !matches!(
                other.failure_class(),
                crate::controller::FailureClass::Terminal
            ),
        },
    }
}

/// Classifies a failed `delete`, whose postcondition is "the object the plan read is gone".
///
/// `404` means someone else already removed it (success, exactly like [`delete`] has always treated
/// it) and `409` is the `Preconditions.uid` check firing: the name now belongs to a **different**
/// object, so the object this pass was allowed to delete is gone and the next pass re-plans against
/// the current state. Everything else keeps [`api_error`]'s classification.
fn delete_outcome(error: &kube::Error) -> Result<(), ApplicationSetControllerError> {
    match error {
        kube::Error::Api(status) if status.code == 404 || status.code == 409 => Ok(()),
        other => Err(api_error(other)),
    }
}

/// The merge patch that drops every `ApplicationSet` owner reference from `application`.
///
/// The generated label is not a substitute for the reference: if it were removed by hand, filtering
/// on it would leave the reference in place and Kubernetes garbage collection would delete the
/// `Application` even though `preserveResourcesOnDeletion` said to keep it. Only `ApplicationSet`
/// references are dropped — and "an `ApplicationSet` reference" means exactly what
/// [`ferriscd_engine::applicationset::ownership`] means by it: `kind == "ApplicationSet"` **in this
/// API group** (finding N1). Dropping on `kind` alone would un-own, and hand to garbage collection,
/// an object whose owner merely shares the Kind name in another group (`other.example/v1`), which
/// this controller has no business touching.
///
/// **Finding N-1:** the owner list is computed from a list snapshot, so the patch carries that
/// snapshot's identity. `PatchParams` has no precondition field (kube 5.1), but a patch *body*
/// whose identity disagrees with the stored object is rejected by the API server before the patch
/// is applied, which is what stops a name that was deleted and re-created in between from losing
/// its *own* owner references. The two rejections are different (findings C-1, H-1):
///
/// * a stale `resourceVersion` — a routine `/status` write on the child is enough — answers
///   `409 Conflict`, and the *same* object is still there;
/// * a `uid` that is no longer the stored one answers `422 Invalid` (`metadata.uid` is immutable),
///   and the listed object is gone.
///
/// [`ApplicationSetStore::orphan`] reads the live object to tell them apart; neither code is a
/// synonym for `404`.
fn orphan_patch_body(
    application: &Application,
) -> Result<serde_json::Value, ApplicationSetControllerError> {
    let remaining: Vec<_> = application
        .metadata
        .owner_references
        .clone()
        .unwrap_or_default()
        .into_iter()
        .filter(|reference| {
            // Finding N1: the same predicate `ownership()` uses, so the controller can never drop a
            // reference it would not have recognised as its own.
            !(reference.api_version.starts_with(API_GROUP) && reference.kind == "ApplicationSet")
        })
        .collect();
    let owner_references = if remaining.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::to_value(&remaining).map_err(|error| ApplicationSetControllerError::Api {
            message: crate::reconcile::bounded(&error.to_string()),
            retryable: false,
        })?
    };
    let mut metadata = serde_json::json!({ "ownerReferences": owner_references });
    if let Some(metadata) = metadata.as_object_mut() {
        for (field, value) in [
            ("uid", application.metadata.uid.as_deref()),
            (
                "resourceVersion",
                application.metadata.resource_version.as_deref(),
            ),
        ] {
            if let Some(value) = value {
                metadata.insert(
                    field.to_owned(),
                    serde_json::Value::String(value.to_owned()),
                );
            }
        }
    }
    Ok(serde_json::json!({ "metadata": metadata }))
}

/// What one orphan patch attempt established, **before** the live read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OrphanPatch {
    /// The patch was applied, or the generated `Application` was already gone (`404`, finding M7):
    /// the listed object no longer references this `ApplicationSet`, which is the end state wanted.
    Done,
    /// The API server rejected the patch because the body's identity is not the stored object's — a
    /// stale `resourceVersion` (`409`) or a `uid` that is no longer the stored one (`422`). The two
    /// mean opposite things, so the live object decides
    /// (`KubeApplicationSetStore::resolve_orphan_conflict`), never this classifier.
    Conflict,
}

/// Classifies a failed orphan patch.
///
/// Only `404` is decidable here: the generated `Application` is gone, so nothing is left to un-own.
///
/// A `409`/`422` is **not** "gone" (findings C-1, H-1): `409` is the ordinary stale-`resourceVersion`
/// answer to a *routine* `/status` write on the child, and treating it as gone released the
/// `ApplicationSet` finalizer while the children still carried their `ownerReference` — after which
/// Kubernetes garbage collection deleted the whole fleet. The live object decides, so a conflict is
/// handed back to the caller instead of being swallowed.
fn orphan_patch_outcome(error: &kube::Error) -> Result<OrphanPatch, ApplicationSetControllerError> {
    match error {
        kube::Error::Api(status) if status.code == 404 => Ok(OrphanPatch::Done),
        kube::Error::Api(status) if is_orphan_conflict(status.code) => Ok(OrphanPatch::Conflict),
        other => Err(api_error(other)),
    }
}

/// Whether a status code is the identity guard firing rather than a real rejection.
///
/// `409`: the patch body's `resourceVersion` is stale. `422`: the body's `uid` is not the stored one
/// (`metadata.uid` is immutable, so this is the code a re-created name produces).
///
/// A `422` the identity guard did *not* produce — a genuinely invalid patch — is therefore retried
/// (never released) by design: the two are indistinguishable from the code alone, so such an
/// `ApplicationSet` wedges in `Terminating`, reporting `ApiError` every requeue interval, instead of
/// surfacing terminally.
fn is_orphan_conflict(code: u16) -> bool {
    code == 409 || code == 422
}

/// Classifies a failed `/status` patch.
///
/// **Finding N-d:** the deletion pass releases the finalizer and then patches `/status` one last
/// time, so the `ApplicationSet` is usually gone by then and the write answers `404`. That is the
/// expected end state — the status it would have recorded is about an object that no longer exists —
/// so it is success, not the failure the warn-level "failed to patch ApplicationSet /status" log
/// used to report on every successful deletion. Everything else keeps [`api_error`]'s
/// classification, because a status write that fails for another reason still has to be visible.
fn status_outcome(error: &kube::Error) -> Result<(), ApplicationSetControllerError> {
    match error {
        kube::Error::Api(status) if status.code == 404 || status.code == 410 => Ok(()),
        other => Err(api_error(other)),
    }
}

/// What a finalizer read-modify-write does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FinalizerOp {
    /// Add [`APPLICATIONSET_FINALIZER`] and keep every other finalizer.
    Add,
    /// Drop [`APPLICATIONSET_FINALIZER`] and keep every other finalizer.
    Remove,
}

/// The `metadata`-only merge patch for one finalizer transition, or `None` when there is nothing to
/// do.
///
/// **Finding N-2:** the patch is computed from a *live* read and carries that read's
/// `resourceVersion`, so the API server applies it only if the object is still the one the list was
/// computed against (`409` otherwise — see `Store.Update`'s optimistic-lock check). A merge patch
/// has to state the whole `finalizers` array, so without the precondition a snapshot taken before
/// another manager added its finalizer would silently drop it; with it, the write is rejected and
/// the next pass recomputes from a fresh read.
fn finalizer_patch_body(appset: &ApplicationSet, op: FinalizerOp) -> Option<serde_json::Value> {
    let current = appset.metadata.finalizers.clone().unwrap_or_default();
    let present = current
        .iter()
        .any(|finalizer| finalizer == APPLICATIONSET_FINALIZER);
    let next: Vec<String> = match op {
        FinalizerOp::Add if present => return None,
        FinalizerOp::Add => {
            let mut next = current;
            next.push(APPLICATIONSET_FINALIZER.to_owned());
            next
        }
        FinalizerOp::Remove if !present => return None,
        FinalizerOp::Remove => current
            .into_iter()
            .filter(|finalizer| finalizer != APPLICATIONSET_FINALIZER)
            .collect(),
    };
    let mut metadata = serde_json::json!({ "finalizers": next });
    if let (Some(metadata), Some(resource_version)) = (
        metadata.as_object_mut(),
        appset.metadata.resource_version.as_deref(),
    ) {
        metadata.insert(
            "resourceVersion".to_owned(),
            serde_json::Value::String(resource_version.to_owned()),
        );
    }
    Some(serde_json::json!({ "metadata": metadata }))
}

/// Classifies a failed finalizer patch.
///
/// `404` means the `ApplicationSet` is gone, so there is no finalizer left to set or clear, and
/// `409` means the `resourceVersion` precondition fired: nothing was clobbered, and the next pass
/// recomputes the patch from a fresh read, so it is worth retrying rather than reporting terminal.
fn finalizer_outcome(error: &kube::Error) -> Result<(), ApplicationSetControllerError> {
    match error {
        kube::Error::Api(status) if status.code == 404 => Ok(()),
        kube::Error::Api(status) if status.code == 409 => Err(ApplicationSetControllerError::Api {
            message: crate::reconcile::bounded(&error.to_string()),
            retryable: true,
        }),
        other => Err(api_error(other)),
    }
}

impl ApplicationSetStore for KubeApplicationSetStore {
    fn list_applications<'a>(
        &'a self,
        namespace: &'a str,
    ) -> BoxFuture<'a, Result<Vec<Application>, ApplicationSetControllerError>> {
        Box::pin(async move {
            let mut items = self
                .applications(namespace)
                .list(&ListParams::default())
                .await
                .map_err(|error| api_error(&error))?
                .items;
            items.sort_by_key(|application| application.name_any());
            Ok(items)
        })
    }

    fn upsert<'a>(
        &'a self,
        application: &'a Application,
    ) -> BoxFuture<'a, Result<(), ApplicationSetControllerError>> {
        Box::pin(async move {
            let namespace = application
                .namespace()
                .unwrap_or_else(|| self.namespace.clone());
            let name = application.name_any();
            let mut body = application.clone();
            // `/status` is a subresource: never send it through the main resource.
            body.status = None;
            let params = PatchParams::apply(ferriscd_engine::default_field_manager());
            self.applications(&namespace)
                .patch(&name, &params, &Patch::Apply(&body))
                .await
                .map_err(|error| api_error(&error))?;
            Ok(())
        })
    }

    fn delete<'a>(
        &'a self,
        namespace: &'a str,
        name: &'a str,
        uid: Option<&'a str>,
    ) -> BoxFuture<'a, Result<(), ApplicationSetControllerError>> {
        Box::pin(async move {
            let mut params = DeleteParams::background();
            // The uid precondition is the TOCTOU guard: the delete only touches the object the plan
            // listed. It is omitted only when the plan had no uid to compare (an unpersisted fixture).
            if let Some(uid) = uid {
                params.preconditions = Some(Preconditions {
                    uid: Some(uid.to_owned()),
                    resource_version: None,
                });
            }
            match self.applications(namespace).delete(name, &params).await {
                Ok(_) => Ok(()),
                Err(error) => delete_outcome(&error),
            }
        })
    }

    fn orphan<'a>(
        &'a self,
        application: &'a Application,
    ) -> BoxFuture<'a, Result<(), ApplicationSetControllerError>> {
        Box::pin(async move {
            let namespace = application
                .namespace()
                .unwrap_or_else(|| self.namespace.clone());
            match self.patch_orphan(&namespace, application).await? {
                OrphanPatch::Done => Ok(()),
                OrphanPatch::Conflict => {
                    self.resolve_orphan_conflict(&namespace, application).await
                }
            }
        })
    }

    fn ensure_finalizer<'a>(
        &'a self,
        appset: &'a ApplicationSet,
    ) -> BoxFuture<'a, Result<(), ApplicationSetControllerError>> {
        Box::pin(async move { self.write_finalizer(appset, FinalizerOp::Add).await })
    }

    fn remove_finalizer<'a>(
        &'a self,
        appset: &'a ApplicationSet,
    ) -> BoxFuture<'a, Result<(), ApplicationSetControllerError>> {
        Box::pin(async move { self.write_finalizer(appset, FinalizerOp::Remove).await })
    }

    fn patch_status<'a>(
        &'a self,
        appset: &'a ApplicationSet,
        status: &'a ApplicationSetStatus,
    ) -> BoxFuture<'a, Result<(), ApplicationSetControllerError>> {
        Box::pin(async move {
            let body = serde_json::json!({ "status": status });
            match self
                .appsets()
                .patch_status(
                    &appset.name_any(),
                    &PatchParams::default(),
                    &Patch::Merge(&body),
                )
                .await
            {
                Ok(_) => Ok(()),
                Err(error) => status_outcome(&error),
            }
        })
    }
}

/// [`ClusterParamSource`] over the `T18.1` cluster registry.
///
/// `ClusterManager::registrations()` is the lifecycle-tracked, sorted snapshot the registry already
/// maintains (labels are recorded from the registration `Secret` when it is seeded); this adapter
/// never reads a cluster `Secret` itself, so there is no per-generator API traffic.
#[derive(Debug, Clone)]
pub struct ClusterManagerParamSource {
    clusters: Arc<ClusterManager>,
}

impl ClusterManagerParamSource {
    /// Builds the adapter over `clusters`.
    #[must_use]
    pub fn new(clusters: Arc<ClusterManager>) -> Self {
        Self { clusters }
    }
}

impl ClusterParamSource for ClusterManagerParamSource {
    fn clusters(&self) -> Vec<ClusterRegistration> {
        self.clusters
            .registrations()
            .into_iter()
            .map(|registration| ClusterRegistration {
                name: registration.name,
                labels: registration.labels,
                default_namespace: registration.default_namespace,
            })
            .collect()
    }
}

/// [`GitParameterSource`] over the sync pipeline's own `RepoCache`.
///
/// The checkout is materialized through the same `GitClient` + `RepoCache` the `Application` pipeline
/// uses, which means `sanitize_worktree` has already rejected escaping symlinks before a generator
/// parameter file is read, and repository credentials come from the control-plane namespace's
/// `ferriscd.io/secret-type=repository` `Secret`s only.
pub struct RepoCacheParamSource {
    repos: Arc<RepoCache>,
    credentials: Arc<dyn CredentialSource>,
    url_policy: RepoUrlPolicy,
}

impl std::fmt::Debug for RepoCacheParamSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepoCacheParamSource")
            .field("url_policy", &self.url_policy)
            .finish_non_exhaustive()
    }
}

impl RepoCacheParamSource {
    /// Builds the adapter.
    #[must_use]
    pub fn new(
        repos: Arc<RepoCache>,
        credentials: Arc<dyn CredentialSource>,
        url_policy: RepoUrlPolicy,
    ) -> Self {
        Self {
            repos,
            credentials,
            url_policy,
        }
    }
}

impl GitParameterSource for RepoCacheParamSource {
    fn checkout<'a>(
        &'a self,
        repo_url: &'a str,
        revision: &'a str,
    ) -> RepoFuture<'a, RepoCheckout> {
        Box::pin(async move {
            // The generator's repository is authored in the `ApplicationSet`, but it is still
            // untrusted input: the same URL policy as `spec.source.git` applies.
            let source = GitSource::new(repo_url, revision, "");
            source.validate(self.url_policy)?;
            let credentials =
                self.credentials
                    .credentials_for(repo_url)
                    .await
                    .map_err(|error| ferriscd_engine::repo::RepoError::AuthFailed {
                        reason: crate::reconcile::bounded(&error.to_string()),
                    })?;
            let resolved = self.repos.resolve_revision(&source, &credentials).await?;
            self.repos
                .checkout(&source, &resolved.commit_sha, &credentials)
                .await
        })
    }
}

/// [`ApplicationAuthorizer`] enforcing the `AppProject` boundary on generated `Application`s.
pub struct ProjectPolicyAuthorizer {
    projects: Arc<dyn ProjectSource>,
    scope: ApplicationScope,
    project_namespace: String,
}

impl std::fmt::Debug for ProjectPolicyAuthorizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectPolicyAuthorizer")
            .field("project_namespace", &self.project_namespace)
            .finish_non_exhaustive()
    }
}

/// One memoized `AppProject` lookup, valid for a single pass.
enum AuthorizedProject {
    /// The project was found; its policy is compiled once.
    Permitted(Box<AppProjectPolicy>),
    /// The project does not exist (a missing project permits nothing).
    Missing,
}

impl ProjectPolicyAuthorizer {
    /// Builds the authorizer over the same project source and scope the pipeline uses.
    #[must_use]
    pub fn new(
        projects: Arc<dyn ProjectSource>,
        scope: ApplicationScope,
        project_namespace: impl Into<String>,
    ) -> Self {
        Self {
            projects,
            scope,
            project_namespace: project_namespace.into(),
        }
    }

    /// Authorizes one `Application`, reading its `AppProject` from `cache` and only from the API
    /// server on a miss.
    ///
    /// **Finding M-a:** the cache is keyed by `project` and lives exactly one pass, so a fleet of
    /// 200 `Application`s that share a project performs **one** `AppProject` GET — the read count no
    /// longer scales with the fan-out.
    async fn check(
        &self,
        application: &Application,
        cache: &mut BTreeMap<String, AuthorizedProject>,
    ) -> Result<(), ApplicationSetControllerError> {
        let name = application.name_any();
        let project_name = application.spec.project.clone();
        if !cache.contains_key(&project_name) {
            let project = self
                .projects
                .get(&project_name)
                .await
                .map_err(|error| project_error(&error))?;
            let entry = project.map_or(AuthorizedProject::Missing, |project| {
                AuthorizedProject::Permitted(Box::new(AppProjectPolicy::from_project(&project)))
            });
            cache.insert(project_name.clone(), entry);
        }
        match cache.get(&project_name) {
            Some(AuthorizedProject::Permitted(policy)) => policy
                .check_application(application, &self.scope)
                .map_err(|error| ApplicationSetControllerError::Policy {
                    name,
                    message: error.to_string(),
                }),
            Some(AuthorizedProject::Missing) | None => Err(ApplicationSetControllerError::Policy {
                name,
                message: format!(
                    "AppProject {project_name:?} was not found in namespace {:?} (a missing \
                         project permits nothing)",
                    self.project_namespace
                ),
            }),
        }
    }
}

impl ApplicationAuthorizer for ProjectPolicyAuthorizer {
    fn authorize<'a>(
        &'a self,
        application: &'a Application,
    ) -> BoxFuture<'a, Result<(), ApplicationSetControllerError>> {
        Box::pin(async move {
            let mut cache = BTreeMap::new();
            self.check(application, &mut cache).await
        })
    }

    fn authorize_all<'a>(
        &'a self,
        applications: &'a [&'a Application],
    ) -> BoxFuture<'a, Result<(), ApplicationSetControllerError>> {
        Box::pin(async move {
            let mut cache: BTreeMap<String, AuthorizedProject> = BTreeMap::new();
            for application in applications {
                self.check(application, &mut cache).await?;
            }
            Ok(())
        })
    }
}

/// One change to the set of `ApplicationSet` objects.
#[derive(Debug, Clone)]
pub enum ApplicationSetEvent {
    /// An object was created or changed (also the per-object event of a re-list).
    ///
    /// Boxed: an `ApplicationSet` is a large manifest, and the variant must not make every event
    /// (including the `Resync`/`Deleted` ones) that large.
    Applied(Box<ApplicationSet>),
    /// An object was deleted.
    Deleted(String),
    /// A re-list bracket completed: the consumer should replace its whole cache.
    Resync,
}

/// A watch failure (surfaced, never fatal: the watch reconnects).
#[derive(Debug, Clone, thiserror::Error)]
#[error("the ApplicationSet watch failed: {message}")]
pub struct ApplicationSetWatchError {
    /// Bounded error text.
    pub message: String,
}

/// The source of `ApplicationSet` events.
pub trait ApplicationSetSource: Send + Sync + 'static {
    /// The event stream.
    fn events(&self) -> BoxStream<'static, Result<ApplicationSetEvent, ApplicationSetWatchError>>;

    /// The authoritative list of `ApplicationSet`s in the control-plane namespace.
    fn list(&self) -> BoxFuture<'_, Result<Vec<ApplicationSet>, ApplicationSetWatchError>>;
}

/// The production [`ApplicationSetSource`]: a namespaced watch of `ApplicationSet`s.
pub struct KubeApplicationSetSource {
    api: Api<ApplicationSet>,
    namespace: String,
}

impl std::fmt::Debug for KubeApplicationSetSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubeApplicationSetSource")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl KubeApplicationSetSource {
    /// Watches the `ApplicationSet`s of `namespace` (the control-plane namespace).
    #[must_use]
    pub fn new(client: Client, namespace: impl Into<String>) -> Self {
        let namespace = namespace.into();
        Self {
            api: Api::namespaced(client, &namespace),
            namespace,
        }
    }

    /// The namespace being watched.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
}

impl ApplicationSetSource for KubeApplicationSetSource {
    fn events(&self) -> BoxStream<'static, Result<ApplicationSetEvent, ApplicationSetWatchError>> {
        use futures::StreamExt as _;
        use futures::stream::BoxStream;

        // Every pass patches `/status`, and the API server reports that patch as another `Apply`
        // event. Without this guard the loop re-triggers itself forever (a live `kind` run measured
        // ~10 passes/second); the shared composite hash drops status/label/`resourceVersion`-only
        // updates while still reacting to a spec, finalizer, deletion, or control-annotation change.
        let mut tracker = crate::predicate::ApplicationSetChangeTracker::new();
        let stream: BoxStream<'static, Result<ApplicationSetEvent, ApplicationSetWatchError>> =
            watcher::watcher(self.api.clone(), watcher::Config::default())
                .default_backoff()
                .filter_map(move |event| {
                    // Decided synchronously (the tracker is not `Send`-shared across an await), then
                    // wrapped in an already-ready future because `filter_map` expects one.
                    let mapped = match event {
                        Ok(watcher::Event::Apply(appset))
                        | Ok(watcher::Event::InitApply(appset)) => {
                            if tracker.observe(&appset) {
                                Some(Ok(ApplicationSetEvent::Applied(Box::new(appset))))
                            } else {
                                None
                            }
                        }
                        Ok(watcher::Event::Delete(appset)) => {
                            // Forget it, so a re-created object of the same name always reconciles.
                            tracker.forget(&appset.name_any());
                            Some(Ok(ApplicationSetEvent::Deleted(appset.name_any())))
                        }
                        Ok(watcher::Event::InitDone) => Some(Ok(ApplicationSetEvent::Resync)),
                        Ok(watcher::Event::Init) => None,
                        Err(error) => Some(Err(ApplicationSetWatchError {
                            message: crate::reconcile::bounded(&error.to_string()),
                        })),
                    };
                    std::future::ready(mapped)
                })
                .boxed();
        stream
    }

    fn list(&self) -> BoxFuture<'_, Result<Vec<ApplicationSet>, ApplicationSetWatchError>> {
        Box::pin(async move {
            let mut items = self
                .api
                .list(&ListParams::default())
                .await
                .map_err(|error| ApplicationSetWatchError {
                    message: crate::reconcile::bounded(&error.to_string()),
                })?
                .items;
            items.sort_by_key(|appset| appset.name_any());
            Ok(items)
        })
    }
}

/// One tracked `ApplicationSet` and when it is next due.
struct Tracked {
    appset: ApplicationSet,
    next_due: tokio::time::Instant,
}

// ---------------------------------------------------------------------------
// External triggers (finding M3)
// ---------------------------------------------------------------------------

/// An external change that makes the affected tracked pass due immediately.
///
/// The periodic requeue (`spec.requeueAfterSeconds`, the 5 s scheduler tick, and the 10-minute
/// re-list) is a **backstop**, not the reaction time. Without a trigger, a newly registered cluster
/// waits up to three minutes before its `Application`s exist, and a hand-edited generated
/// `Application` waits as long to converge — the fleet is then only as fresh as the slowest timer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriggerEvent {
    /// A cluster registration was added, rebuilt, or removed (`T18.1` lifecycle broadcast).
    Cluster(ClusterLifecycleEvent),
    /// A `ferriscd.io/applicationset`-labelled `Application` was created, changed, or deleted, so the
    /// generated fleet may no longer match what this controller wrote.
    GeneratedApplication {
        /// The `ferriscd.io/applicationset` value: only that `ApplicationSet` is forced due, so one
        /// drifting child does not re-evaluate a 200-`ApplicationSet` fleet (finding M-b).
        ///
        /// `None` means the event names no single owner (a completed re-list, or an object whose
        /// label was removed by hand): every tracked `ApplicationSet` is due.
        applicationset: Option<String>,
    },
    /// The trigger stream fell behind and dropped events: re-read everything now.
    Lagged,
}

impl TriggerEvent {
    /// A stable, low-cardinality kind for logs.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Cluster(event) => match event {
                ClusterLifecycleEvent::Added(_) => "cluster-added",
                ClusterLifecycleEvent::Rebuilt(_) => "cluster-rebuilt",
                ClusterLifecycleEvent::Removed(_) => "cluster-removed",
            },
            Self::GeneratedApplication { .. } => "generated-application",
            Self::Lagged => "trigger-lagged",
        }
    }

    /// The single `ApplicationSet` this trigger is about, when it names one.
    ///
    /// A cluster registration or a dropped-event resync can affect every generator, so those return
    /// `None` ("everything is due").
    #[must_use]
    pub fn owner(&self) -> Option<&str> {
        match self {
            Self::GeneratedApplication { applicationset } => applicationset.as_deref(),
            Self::Cluster(_) | Self::Lagged => None,
        }
    }
}

/// The source of [`TriggerEvent`]s.
///
/// A trait rather than a concrete stream, so the loop can be driven by a scripted source in a test
/// (no cluster, no watch) exactly like the store and the generators are.
pub trait ApplicationSetTrigger: Send + Sync + 'static {
    /// The trigger stream. Ending it is allowed (the loop falls back to its timers).
    fn triggers(&self) -> BoxStream<'static, TriggerEvent>;
}

/// A trigger source that never fires; the default, so a hand-built controller keeps working.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoTrigger;

impl ApplicationSetTrigger for NoTrigger {
    fn triggers(&self) -> BoxStream<'static, TriggerEvent> {
        // `pending` never yields, so the loop's trigger arm simply parks.
        futures::stream::pending().boxed()
    }
}

/// The production [`ApplicationSetTrigger`]: cluster lifecycle events plus a generated-`Application`
/// watch.
pub struct ClusterApplicationSetTrigger {
    clusters: Arc<ClusterManager>,
    client: Client,
    namespace: String,
}

impl std::fmt::Debug for ClusterApplicationSetTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterApplicationSetTrigger")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl ClusterApplicationSetTrigger {
    /// Subscribes to `clusters` and watches the labelled `Application`s of `namespace`.
    #[must_use]
    pub fn new(
        clusters: Arc<ClusterManager>,
        client: Client,
        namespace: impl Into<String>,
    ) -> Self {
        Self {
            clusters,
            client,
            namespace: namespace.into(),
        }
    }
}

impl ApplicationSetTrigger for ClusterApplicationSetTrigger {
    fn triggers(&self) -> BoxStream<'static, TriggerEvent> {
        let labelled = Api::<Application>::namespaced(self.client.clone(), &self.namespace);
        futures::stream::select(
            cluster_trigger_stream(self.clusters.subscribe()),
            application_trigger_stream(watcher::watcher(
                labelled,
                watcher::Config::default().labels(APPLICATIONSET_LABEL),
            )),
        )
        .boxed()
    }
}

/// Turns the `T18.1` lifecycle broadcast into triggers.
///
/// A lagged subscriber is a supported outcome of the bounded channel, not an error: the registry is
/// authoritative, so dropped events collapse into one [`TriggerEvent::Lagged`] ("re-read
/// everything"). A closed channel ends the stream and the loop falls back to its timers.
fn cluster_trigger_stream(
    receiver: broadcast::Receiver<ClusterLifecycleEvent>,
) -> BoxStream<'static, TriggerEvent> {
    futures::stream::unfold(receiver, |mut receiver| async move {
        match receiver.recv().await {
            Ok(event) => Some((TriggerEvent::Cluster(event), receiver)),
            Err(broadcast::error::RecvError::Lagged(_)) => Some((TriggerEvent::Lagged, receiver)),
            Err(broadcast::error::RecvError::Closed) => None,
        }
    })
    .boxed()
}

/// Turns a `ferriscd.io/applicationset`-labelled `Application` watch into triggers.
///
/// Status-only updates are suppressed by the shared [`crate::predicate::PredicateTracker`] (its
/// composite hash ignores `/status`), which is what keeps the loop from re-running a pass for every
/// status write the `Application` controller performs on a generated `Application`. Its own writes do
/// re-trigger one extra pass, which converges to zero writes and therefore stops: an idempotence
/// requirement, not an accident.
fn application_trigger_stream<S>(events: S) -> BoxStream<'static, TriggerEvent>
where
    S: futures::Stream<Item = Result<watcher::Event<Application>, watcher::Error>> + Send + 'static,
{
    let events = Box::pin(events);
    futures::stream::unfold(
        (events, crate::predicate::PredicateTracker::new()),
        |(mut events, mut tracker)| async move {
            loop {
                let event = events.next().await?;
                if let Some(trigger) = classify_application_event(event, &mut tracker) {
                    return Some((trigger, (events, tracker)));
                }
            }
        },
    )
    .boxed()
}

/// Turns one `Application` watch event into a trigger, or drops it (noise, or a watch error).
fn classify_application_event(
    event: Result<watcher::Event<Application>, watcher::Error>,
    tracker: &mut crate::predicate::PredicateTracker,
) -> Option<TriggerEvent> {
    match event {
        Ok(watcher::Event::Apply(application)) | Ok(watcher::Event::InitApply(application)) => {
            tracker
                .observe(&application)
                .then(|| triggered_by(&application))
        }
        Ok(watcher::Event::Delete(application)) => {
            tracker.forget(application.namespace().as_deref(), &application.name_any());
            Some(triggered_by(&application))
        }
        // A completed (re-)list is the authoritative snapshot: compare everything again, and no
        // single `ApplicationSet` owns it.
        Ok(watcher::Event::InitDone) => Some(TriggerEvent::GeneratedApplication {
            applicationset: None,
        }),
        Ok(watcher::Event::Init) => None,
        // The watch itself retries; a broken connection is not a reason to fail a pass.
        Err(error) => {
            tracing::debug!(
                error = %crate::reconcile::bounded(&error.to_string()),
                "generated Application watch error; the fleet is re-read on the next pass"
            );
            None
        }
    }
}

/// The trigger one labelled `Application` produces: it names its `ApplicationSet` through
/// [`APPLICATIONSET_LABEL`] (finding M-b), or names none when the label is absent.
fn triggered_by(application: &Application) -> TriggerEvent {
    TriggerEvent::GeneratedApplication {
        applicationset: application.labels().get(APPLICATIONSET_LABEL).cloned(),
    }
}

/// Names whose periodic requeue is due, in deterministic (map) order.
fn due_names(tracked: &BTreeMap<String, Tracked>, now: tokio::time::Instant) -> Vec<String> {
    tracked
        .iter()
        .filter(|(_, entry)| entry.next_due <= now)
        .map(|(name, _)| name.clone())
        .collect()
}

/// Marks every tracked pass due right now and returns their names, in deterministic order.
fn force_due(tracked: &mut BTreeMap<String, Tracked>, now: tokio::time::Instant) -> Vec<String> {
    let mut names = Vec::with_capacity(tracked.len());
    for (name, entry) in tracked.iter_mut() {
        entry.next_due = now;
        names.push(name.clone());
    }
    names
}

/// Marks **one** tracked pass due right now — the selective form of [`force_due`] (finding M-b).
fn force_due_named(
    tracked: &mut BTreeMap<String, Tracked>,
    now: tokio::time::Instant,
    name: &str,
) -> Vec<String> {
    match tracked.get_mut(name) {
        Some(entry) => {
            entry.next_due = now;
            vec![name.to_owned()]
        }
        // A generated `Application` whose `ApplicationSet` is no longer tracked (deleted, or never
        // seen yet) has nothing to force: the watch/re-list delivers the owning object itself.
        None => Vec::new(),
    }
}

/// Folds `first` and every trigger that is **already ready** into one due-set (finding M-2).
///
/// `select!` hands the loop one trigger at a time, but a fan-out change arrives as a burst: a
/// cluster registration makes up to 200 `ApplicationSet`s due, a re-list delivers one event per
/// generated `Application`, and a lagging subscriber collapses into `Lagged`. Reconciling after each
/// of those events re-runs the same unchanged generators N times over, so the burst is drained
/// first and the *set* of affected objects is reconciled once each.
///
/// The drain only takes events that are buffered right now — it never awaits, so a pass is never
/// delayed by a quiet stream — and a name is returned at most once, which is what makes the burst
/// cost one pass per affected `ApplicationSet`.
fn drain_due(
    triggers: &mut BoxStream<'static, TriggerEvent>,
    tracked: &mut BTreeMap<String, Tracked>,
    first: TriggerEvent,
) -> Vec<String> {
    let mut due: BTreeSet<String> = BTreeSet::new();
    let mut next = Some(first);
    while let Some(trigger) = next {
        let now = tokio::time::Instant::now();
        // Finding M-b: a generated `Application` names its own `ApplicationSet`, so only that pass
        // is forced. A cluster registration, a dropped-event resync, or a re-list names nobody and
        // therefore forces everything.
        let names = match trigger.owner() {
            Some(name) => force_due_named(tracked, now, name),
            None => force_due(tracked, now),
        };
        due.extend(names);
        next = triggers.next().now_or_never().flatten();
    }
    due.into_iter().collect()
}

/// The periodic interval of one pass: `spec.requeueAfterSeconds`, or
/// [`DEFAULT_APPLICATIONSET_INTERVAL`] when the field is zero (an unvalidated object).
///
/// The CRD's own default comes from `DEFAULT_APPLICATIONSET_REQUEUE_AFTER_SECONDS`; the loop's
/// constant is the same value and is asserted equal to it in the tests, so the fallback and the
/// schema default cannot drift apart (finding N-3).
fn requeue_interval(appset: &ApplicationSet) -> Duration {
    match appset.spec.requeue_after_seconds {
        0 => DEFAULT_APPLICATIONSET_INTERVAL,
        seconds => Duration::from_secs(u64::from(seconds)),
    }
}

/// The opt-in `ApplicationSet` controller loop.
pub struct ApplicationSetController {
    reconciler: Arc<ApplicationSetReconciler>,
    source: Arc<dyn ApplicationSetSource>,
    triggers: Arc<dyn ApplicationSetTrigger>,
    namespace: String,
}

impl std::fmt::Debug for ApplicationSetController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApplicationSetController")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl ApplicationSetController {
    /// Builds the loop.
    #[must_use]
    pub fn new(
        reconciler: Arc<ApplicationSetReconciler>,
        source: Arc<dyn ApplicationSetSource>,
        namespace: impl Into<String>,
    ) -> Self {
        Self {
            reconciler,
            source,
            triggers: Arc::new(NoTrigger),
            namespace: namespace.into(),
        }
    }

    /// Reacts to external changes (`T18.1` cluster lifecycle, generated `Application` drift) instead
    /// of only to the periodic requeue.
    #[must_use]
    pub fn with_triggers(mut self, triggers: Arc<dyn ApplicationSetTrigger>) -> Self {
        self.triggers = triggers;
        self
    }

    /// Runs until `stop` is cancelled.
    ///
    /// The loop is a single task: it is deliberately not concurrent, so two passes can never write
    /// the same `ApplicationSet` at once. Generator Git fetches are asynchronous and parameter
    /// evaluation runs in `spawn_blocking`, so a slow repository delays other `ApplicationSet`s but
    /// never blocks a Tokio worker.
    ///
    /// Three inputs make a pass due, and the **fastest** one wins: the `ApplicationSet` watch, an
    /// external [`TriggerEvent`] (a cluster registration or a generated `Application` changing), and
    /// the periodic `spec.requeueAfterSeconds` timer. The timers are a backstop: nothing depends on
    /// a 180 s / 600 s tick for a fleet to be correct.
    pub async fn run(self: Arc<Self>, stop: tokio_util::sync::CancellationToken) {
        tracing::info!(
            namespace = %self.namespace,
            "ApplicationSet controller started (opt-in): generating Applications from ApplicationSet generators"
        );
        let mut tracked: BTreeMap<String, Tracked> = BTreeMap::new();
        let mut events = self.source.events();
        let mut triggers = self.triggers.triggers();
        let mut schedule = tokio::time::interval(SCHEDULE_TICK);
        let mut resync = tokio::time::interval(CACHE_RESYNC_PERIOD);
        // `Delay` (not the default `Burst`): a pass that overruns a tick must not fire a burst of
        // catch-up ticks afterwards, which would reconcile the same objects several times in a row.
        schedule.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        resync.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick of `interval` is immediate; consume it so the loop starts with the watch.
        schedule.tick().await;
        resync.tick().await;

        loop {
            tokio::select! {
                () = stop.cancelled() => break,
                event = events.next() => {
                    match event {
                        None => break,
                        Some(Ok(ApplicationSetEvent::Applied(appset))) => {
                            let appset = *appset;
                            let name = appset.name_any();
                            let report = self.reconciler.reconcile(&appset).await;
                            self.log_report(&report);
                            let next_due = tokio::time::Instant::now() + requeue_interval(&appset);
                            tracked.insert(name, Tracked { appset, next_due });
                        }
                        Some(Ok(ApplicationSetEvent::Deleted(name))) => {
                            tracked.remove(&name);
                        }
                        Some(Ok(ApplicationSetEvent::Resync)) => {
                            tracked = self.resync(&tracked).await;
                        }
                        Some(Err(error)) => tracing::warn!(error = %error, "ApplicationSet watch error"),
                    }
                }
                trigger = triggers.next() => {
                    match trigger {
                        Some(trigger) => {
                            // Finding M-2: one fan-out change arrives as a burst of ready triggers,
                            // so everything that is already buffered is folded into one due-set
                            // before the first pass. N back-to-back passes over the same unchanged
                            // inputs cost N generator evaluations per ApplicationSet for nothing.
                            let (kind, owner) =
                                (trigger.kind(), trigger.owner().map(str::to_owned));
                            let names = drain_due(&mut triggers, &mut tracked, trigger);
                            tracing::debug!(
                                trigger = kind,
                                applicationset = ?owner,
                                applicationsets = names.len(),
                                "external change: the affected ApplicationSet(s) are due now"
                            );
                            for name in &names {
                                self.reconcile_tracked(&mut tracked, name).await;
                            }
                        }
                        // A finished trigger stream must stop being polled, or `select!` would spin on
                        // it forever; `pending` parks the arm and the timers keep the loop alive.
                        None => triggers = futures::stream::pending().boxed(),
                    }
                }
                _ = schedule.tick() => {
                    let now = tokio::time::Instant::now();
                    for name in due_names(&tracked, now) {
                        self.reconcile_tracked(&mut tracked, &name).await;
                    }
                }
                _ = resync.tick() => {
                    tracked = self.resync(&tracked).await;
                }
            }
        }
        tracing::info!(
            namespace = %self.namespace,
            "ApplicationSet controller stopped"
        );
    }

    /// Reconciles one tracked `ApplicationSet` and schedules its next periodic pass.
    async fn reconcile_tracked(&self, tracked: &mut BTreeMap<String, Tracked>, name: &str) {
        let Some(entry) = tracked.get_mut(name) else {
            return;
        };
        let appset = entry.appset.clone();
        let report = self.reconciler.reconcile(&appset).await;
        self.log_report(&report);
        entry.next_due = tokio::time::Instant::now() + requeue_interval(&appset);
    }

    /// Replaces the cache with the authoritative list, reconciling every object once.
    async fn resync(&self, previous: &BTreeMap<String, Tracked>) -> BTreeMap<String, Tracked> {
        let listed = match self.source.list().await {
            Ok(listed) => listed,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "could not re-list ApplicationSets; keeping the current cache"
                );
                return previous
                    .iter()
                    .map(|(name, tracked)| {
                        (
                            name.clone(),
                            Tracked {
                                appset: tracked.appset.clone(),
                                next_due: tracked.next_due,
                            },
                        )
                    })
                    .collect();
            }
        };
        let mut next = BTreeMap::new();
        for appset in listed {
            let report = self.reconciler.reconcile(&appset).await;
            self.log_report(&report);
            next.insert(
                appset.name_any(),
                Tracked {
                    next_due: tokio::time::Instant::now() + requeue_interval(&appset),
                    appset,
                },
            );
        }
        next
    }

    fn log_report(&self, report: &ReconcileReport) {
        match &report.failure {
            None => tracing::info!(
                appset = %report.name,
                generated = report.generated,
                created = report.created,
                updated = report.updated,
                unchanged = report.skipped,
                pruned = report.pruned,
                kept = report.kept,
                // Finding N-a: the deletion pass reports `orphaned`/`deleted` and nothing else, so
                // omitting them made a successful `ApplicationSet` deletion look like a pass that
                // generated nothing at all — the one outcome an operator most needs to see.
                orphaned = report.orphaned,
                deleted = report.deleted,
                "ApplicationSet reconciled"
            ),
            Some(error) => tracing::warn!(
                appset = %report.name,
                reason = error.reason(),
                error = %error,
                "ApplicationSet reconciliation failed"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::Mutex;

    use ferriscd_crd::APPLICATIONSET_LABEL;
    use ferriscd_crd::applicationset::{ApplicationSetSpec, ApplicationSetSyncPolicy};
    use ferriscd_engine::applicationset::TemplateError;

    use super::*;

    // -----------------------------------------------------------------
    // Fakes: no cluster, no Git, no sleeps.
    // -----------------------------------------------------------------

    /// Every write the reconciler performed, in order.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Write {
        Upsert(String),
        /// A delete, carrying the `uid` precondition the plan supplied.
        Delete {
            name: String,
            uid: Option<String>,
        },
        Orphan(String),
        EnsureFinalizer(String),
        RemoveFinalizer(String),
        Status {
            name: String,
            ready: bool,
            reason: Option<String>,
            generated_count: u32,
            observed_generation: Option<i64>,
        },
    }

    #[derive(Default)]
    struct FakeStore {
        applications: Mutex<Vec<Application>>,
        writes: Mutex<Vec<Write>>,
        fail_upsert: Mutex<Option<String>>,
        /// Signalled after every recorded write, so a test can wait for a pass to land without a
        /// sleep and without polling a clock.
        written: tokio::sync::Notify,
    }

    impl FakeStore {
        fn with(applications: Vec<Application>) -> Arc<Self> {
            Arc::new(Self {
                applications: Mutex::new(applications),
                writes: Mutex::new(Vec::new()),
                fail_upsert: Mutex::new(None),
                written: tokio::sync::Notify::new(),
            })
        }

        fn writes(&self) -> Vec<Write> {
            self.writes.lock().expect("test lock").clone()
        }

        fn object_writes(&self) -> Vec<Write> {
            self.writes()
                .into_iter()
                .filter(|write| !matches!(write, Write::Status { .. }))
                .collect()
        }

        fn statuses(&self) -> Vec<Write> {
            self.writes()
                .into_iter()
                .filter(|write| matches!(write, Write::Status { .. }))
                .collect()
        }

        fn record(&self, write: Write) {
            self.writes.lock().expect("test lock").push(write);
            // `notify_one` keeps a permit for one waiter, so a write that lands between a test's
            // check and its await is never lost.
            self.written.notify_one();
        }

        /// Waits until the next write is recorded (no sleep, no clock).
        async fn next_write(&self) {
            self.written.notified().await;
        }
    }

    impl ApplicationSetStore for FakeStore {
        fn list_applications<'a>(
            &'a self,
            namespace: &'a str,
        ) -> BoxFuture<'a, Result<Vec<Application>, ApplicationSetControllerError>> {
            Box::pin(async move {
                Ok(self
                    .applications
                    .lock()
                    .expect("test lock")
                    .iter()
                    .filter(|application| application.namespace().as_deref() == Some(namespace))
                    .cloned()
                    .collect())
            })
        }

        fn upsert<'a>(
            &'a self,
            application: &'a Application,
        ) -> BoxFuture<'a, Result<(), ApplicationSetControllerError>> {
            Box::pin(async move {
                if let Some(message) = self.fail_upsert.lock().expect("test lock").clone() {
                    return Err(ApplicationSetControllerError::Api {
                        message,
                        retryable: true,
                    });
                }
                let name = application.name_any();
                self.record(Write::Upsert(name.clone()));
                let mut applications = self.applications.lock().expect("test lock");
                applications.retain(|existing| existing.name_any() != name);
                applications.push(application.clone());
                Ok(())
            })
        }

        fn delete<'a>(
            &'a self,
            _namespace: &'a str,
            name: &'a str,
            uid: Option<&'a str>,
        ) -> BoxFuture<'a, Result<(), ApplicationSetControllerError>> {
            Box::pin(async move {
                self.record(Write::Delete {
                    name: name.to_owned(),
                    uid: uid.map(str::to_owned),
                });
                self.applications
                    .lock()
                    .expect("test lock")
                    .retain(|application| application.name_any() != name);
                Ok(())
            })
        }

        fn orphan<'a>(
            &'a self,
            application: &'a Application,
        ) -> BoxFuture<'a, Result<(), ApplicationSetControllerError>> {
            Box::pin(async move {
                self.record(Write::Orphan(application.name_any()));
                Ok(())
            })
        }

        fn ensure_finalizer<'a>(
            &'a self,
            appset: &'a ApplicationSet,
        ) -> BoxFuture<'a, Result<(), ApplicationSetControllerError>> {
            Box::pin(async move {
                self.record(Write::EnsureFinalizer(appset.name_any()));
                Ok(())
            })
        }

        fn remove_finalizer<'a>(
            &'a self,
            appset: &'a ApplicationSet,
        ) -> BoxFuture<'a, Result<(), ApplicationSetControllerError>> {
            Box::pin(async move {
                self.record(Write::RemoveFinalizer(appset.name_any()));
                Ok(())
            })
        }

        fn patch_status<'a>(
            &'a self,
            appset: &'a ApplicationSet,
            status: &'a ApplicationSetStatus,
        ) -> BoxFuture<'a, Result<(), ApplicationSetControllerError>> {
            Box::pin(async move {
                self.record(Write::Status {
                    name: appset.name_any(),
                    ready: status.is_ready(),
                    reason: status
                        .conditions
                        .iter()
                        .find(|condition| condition.type_ == ferriscd_crd::status::CONDITION_READY)
                        .map(|condition| condition.reason.clone()),
                    generated_count: status.generated_count,
                    observed_generation: status.observed_generation,
                });
                Ok(())
            })
        }
    }

    #[derive(Default)]
    struct FakeClusters {
        registrations: Vec<ClusterRegistration>,
    }

    impl ClusterParamSource for FakeClusters {
        fn clusters(&self) -> Vec<ClusterRegistration> {
            self.registrations.clone()
        }
    }

    #[derive(Default)]
    struct FakeGit {
        root: Option<std::path::PathBuf>,
        fail: bool,
    }

    impl GitParameterSource for FakeGit {
        fn checkout<'a>(
            &'a self,
            _repo_url: &'a str,
            _revision: &'a str,
        ) -> RepoFuture<'a, RepoCheckout> {
            Box::pin(async move {
                if self.fail {
                    return Err(ferriscd_engine::repo::RepoError::Network {
                        message: "scripted transient failure".to_owned(),
                    });
                }
                Ok(RepoCheckout::new(
                    self.root
                        .clone()
                        .unwrap_or_else(|| std::path::PathBuf::from("/nonexistent")),
                    "0123456789abcdef0123456789abcdef01234567",
                ))
            })
        }
    }

    /// Authorizer with a scripted verdict per `Application` name.
    #[derive(Default)]
    struct FakeAuthorizer {
        denied: Vec<String>,
        seen: Mutex<Vec<String>>,
    }

    impl ApplicationAuthorizer for FakeAuthorizer {
        fn authorize<'a>(
            &'a self,
            application: &'a Application,
        ) -> BoxFuture<'a, Result<(), ApplicationSetControllerError>> {
            Box::pin(async move {
                let name = application.name_any();
                self.seen.lock().expect("test lock").push(name.clone());
                if self.denied.contains(&name) {
                    return Err(ApplicationSetControllerError::Policy {
                        name,
                        message: "scripted policy denial".to_owned(),
                    });
                }
                Ok(())
            })
        }
    }

    fn appset(yaml: &str) -> ApplicationSet {
        let spec: ApplicationSetSpec = serde_saphyr::from_str(yaml).expect("fixture spec");
        let mut appset = ApplicationSet::new("payments-fleet", spec);
        appset.metadata.namespace = Some("ferriscd-system".to_owned());
        appset.metadata.uid = Some("uid-payments-fleet".to_owned());
        // A stored object always has a resourceVersion, and the finalizer patch uses it as the
        // optimistic-concurrency precondition (finding N-2), so the fixture has one too.
        appset.metadata.resource_version = Some("1000".to_owned());
        appset.metadata.generation = Some(3);
        appset
    }

    fn list_fleet() -> ApplicationSet {
        appset(
            r#"
generators:
  - list:
      elements:
        - env: prod
          path: apps/api
        - env: dev
          path: apps/api
template:
  metadata:
    name: api-{{env}}
  spec:
    project: default
    source:
      git:
        repoURL: https://github.com/example/payments.git
        path: "{{path}}"
    destination:
      cluster: in-cluster
      namespace: "{{env}}"
"#,
        )
    }

    fn owned_application(name: &str, appset: &ApplicationSet) -> Application {
        let mut application = Application::new(name, appset.spec.template.spec.clone());
        application.metadata.namespace = Some("ferriscd-system".to_owned());
        // A real `Application` always has a server-assigned uid, and the delete plan carries it as a
        // precondition, so the fixture must have one too (a missing uid would silently disable it).
        application.metadata.uid = Some(format!("uid-{name}"));
        // A real generated `Application` carries the server-assigned `resourceVersion` the orphan
        // patch uses as its concurrency guard (finding N-1) and the label the trigger reads to pick
        // the owning `ApplicationSet` (finding M-b).
        application.metadata.resource_version = Some(format!("rv-{name}"));
        application.metadata.labels = Some(BTreeMap::from([(
            APPLICATIONSET_LABEL.to_owned(),
            "payments-fleet".to_owned(),
        )]));
        application.metadata.owner_references = Some(vec![
            ferriscd_engine::applicationset::template::owner_reference(
                "payments-fleet",
                "uid-payments-fleet",
            ),
        ]);
        application
    }

    fn reconciler(
        store: Arc<FakeStore>,
        clusters: FakeClusters,
        git: FakeGit,
        authorizer: Arc<FakeAuthorizer>,
    ) -> ApplicationSetReconciler {
        ApplicationSetReconciler::new(
            "ferriscd-system",
            Arc::new(clusters),
            Arc::new(git),
            store,
            authorizer,
        )
    }

    // -----------------------------------------------------------------
    // Happy path and status
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn a_successful_pass_writes_every_generated_application_and_its_status() {
        let store = FakeStore::with(Vec::new());
        let authorizer = Arc::new(FakeAuthorizer::default());
        let appset = list_fleet();
        let report = reconciler(
            store.clone(),
            FakeClusters::default(),
            FakeGit::default(),
            authorizer.clone(),
        )
        .reconcile(&appset)
        .await;

        assert!(report.is_ready(), "{report:?}");
        assert_eq!(report.generated, 2);
        assert_eq!(report.created, 2);
        assert_eq!(report.updated, 0);
        assert_eq!(report.failure, None);
        assert_eq!(
            store.object_writes(),
            vec![
                Write::EnsureFinalizer("payments-fleet".to_owned()),
                Write::Upsert("api-dev".to_owned()),
                Write::Upsert("api-prod".to_owned()),
            ],
            "the finalizer is added before the first generated Application"
        );
        let statuses = store.statuses();
        assert_eq!(statuses.len(), 1, "always-update-status: exactly one patch");
        assert_eq!(
            statuses[0],
            Write::Status {
                name: "payments-fleet".to_owned(),
                ready: true,
                reason: Some("ApplicationsGenerated".to_owned()),
                generated_count: 2,
                observed_generation: Some(3),
            }
        );
        assert_eq!(
            authorizer.seen.lock().expect("test lock").clone(),
            vec!["api-dev".to_owned(), "api-prod".to_owned()],
            "every Application is authorized before it is written"
        );
        // Every written Application lives in the ApplicationSet's own namespace and carries the
        // generated label.
        for application in store.applications.lock().expect("test lock").iter() {
            assert_eq!(application.namespace().as_deref(), Some("ferriscd-system"));
            assert_eq!(
                application
                    .labels()
                    .get(APPLICATIONSET_LABEL)
                    .map(String::as_str),
                Some("payments-fleet")
            );
        }
    }

    #[tokio::test]
    async fn a_steady_state_pass_performs_no_object_write() {
        let appset = list_fleet();
        let store = FakeStore::with(vec![
            owned_application("api-dev", &appset),
            owned_application("api-prod", &appset),
        ]);
        // Seed the exact specs/labels/owner the renderer produces.
        {
            let mut applications = store.applications.lock().expect("test lock");
            let rendered = ferriscd_engine::applicationset::render_template(
                &appset,
                &BTreeMap::from([
                    ("env".to_owned(), "dev".to_owned()),
                    ("path".to_owned(), "apps/api".to_owned()),
                ]),
            )
            .expect("template")
            .application;
            applications.retain(|application| application.name_any() != "api-dev");
            applications.push(rendered);
        }
        let report = reconciler(
            store.clone(),
            FakeClusters::default(),
            FakeGit::default(),
            Arc::new(FakeAuthorizer::default()),
        )
        .reconcile(&appset)
        .await;
        assert!(report.is_ready());
        assert_eq!(report.generated, 2);
        assert_eq!(
            report.skipped, 1,
            "the matching Application is not rewritten"
        );
        assert_eq!(report.updated, 1, "the drifted one converges");
        assert_eq!(
            store
                .object_writes()
                .into_iter()
                .filter(|write| matches!(write, Write::Upsert(_)))
                .count(),
            1
        );
    }

    // -----------------------------------------------------------------
    // Failure paths: zero partial writes and zero deletes
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn a_fan_out_refusal_patches_not_ready_and_writes_nothing() {
        let mut appset = list_fleet();
        appset.spec.max_generated_applications = Some(1);
        // A stale generated Application exists; if the failure path pruned anything, this is what
        // would disappear.
        let stale = owned_application("api-legacy", &appset);
        let store = FakeStore::with(vec![stale]);

        let report = reconciler(
            store.clone(),
            FakeClusters::default(),
            FakeGit::default(),
            Arc::new(FakeAuthorizer::default()),
        )
        .reconcile(&appset)
        .await;

        assert!(!report.is_ready());
        assert!(matches!(
            report.failure,
            Some(ApplicationSetControllerError::Engine(
                ApplicationSetError::FanOutLimitExceeded { .. }
            ))
        ));
        assert!(
            store.object_writes().is_empty(),
            "a refused fan-out must not write or delete anything: {:?}",
            store.object_writes()
        );
        assert_eq!(store.applications.lock().expect("test lock").len(), 1);
        assert_eq!(
            store.statuses(),
            vec![Write::Status {
                name: "payments-fleet".to_owned(),
                ready: false,
                reason: Some("FanOutLimitExceeded".to_owned()),
                generated_count: 0,
                observed_generation: Some(3),
            }],
            "the failure is surfaced on /status, and generatedCount stays at its previous value"
        );
    }

    #[tokio::test]
    async fn a_transient_git_error_preserves_existing_generated_applications() {
        let appset = appset(
            r#"
generators:
  - git:
      repoURL: https://github.com/example/config.git
      revision: HEAD
      directories:
        - path: apps/*
template:
  metadata:
    name: "{{path.basename}}"
  spec:
    project: default
    source:
      git:
        repoURL: https://github.com/example/payments.git
    destination:
      cluster: in-cluster
      namespace: payments
"#,
        );
        let generated = owned_application("api", &appset);
        let store = FakeStore::with(vec![generated.clone()]);
        let report = reconciler(
            store.clone(),
            FakeClusters::default(),
            FakeGit {
                root: None,
                fail: true,
            },
            Arc::new(FakeAuthorizer::default()),
        )
        .reconcile(&appset)
        .await;

        assert!(!report.is_ready());
        let failure = report.failure.expect("a failure is reported");
        assert!(failure.is_retryable(), "a Git error is retryable");
        assert_eq!(failure.reason(), "GeneratorError");
        assert!(
            store.object_writes().is_empty(),
            "a transient Git error must not delete or rewrite the fleet: {:?}",
            store.object_writes()
        );
        assert_eq!(
            store.applications.lock().expect("test lock").len(),
            1,
            "the existing generated Application is preserved"
        );
    }

    #[tokio::test]
    async fn an_unmanaged_conflict_is_refused_before_any_write() {
        let appset = list_fleet();
        // A hand-written `api-dev` (no owner reference) with a different spec.
        let mut hand_written = Application::new("api-dev", appset.spec.template.spec.clone());
        hand_written.metadata.namespace = Some("ferriscd-system".to_owned());
        hand_written.spec.destination.namespace = "operator-owned".to_owned();
        let store = FakeStore::with(vec![hand_written]);

        let report = reconciler(
            store.clone(),
            FakeClusters::default(),
            FakeGit::default(),
            Arc::new(FakeAuthorizer::default()),
        )
        .reconcile(&appset)
        .await;

        assert!(!report.is_ready());
        assert!(matches!(
            report.failure,
            Some(ApplicationSetControllerError::Engine(
                ApplicationSetError::Conflict { .. }
            ))
        ));
        assert_eq!(
            report.failure.expect("failure").reason(),
            "ApplicationConflict"
        );
        assert!(store.object_writes().is_empty());
        assert_eq!(
            store.applications.lock().expect("test lock")[0]
                .spec
                .destination
                .namespace,
            "operator-owned",
            "the operator's Application is untouched"
        );
    }

    #[tokio::test]
    async fn an_unauthorized_project_target_is_rejected_before_create() {
        let store = FakeStore::with(Vec::new());
        let authorizer = Arc::new(FakeAuthorizer {
            denied: vec!["api-dev".to_owned()],
            seen: Mutex::new(Vec::new()),
        });
        let report = reconciler(
            store.clone(),
            FakeClusters::default(),
            FakeGit::default(),
            authorizer,
        )
        .reconcile(&list_fleet())
        .await;

        assert!(!report.is_ready());
        let failure = report.failure.expect("failure");
        assert!(matches!(
            failure,
            ApplicationSetControllerError::Policy { .. }
        ));
        assert_eq!(failure.reason(), "PolicyViolation");
        assert!(
            store.object_writes().is_empty(),
            "a policy refusal must happen before the first write: {:?}",
            store.object_writes()
        );
        assert_eq!(
            store.statuses()[0],
            Write::Status {
                name: "payments-fleet".to_owned(),
                ready: false,
                reason: Some("PolicyViolation".to_owned()),
                generated_count: 0,
                observed_generation: Some(3),
            }
        );
    }

    #[tokio::test]
    async fn an_api_write_failure_stops_the_pass_and_is_reported() {
        let store = FakeStore::with(Vec::new());
        *store.fail_upsert.lock().expect("test lock") = Some("connection reset".to_owned());
        let report = reconciler(
            store.clone(),
            FakeClusters::default(),
            FakeGit::default(),
            Arc::new(FakeAuthorizer::default()),
        )
        .reconcile(&list_fleet())
        .await;
        assert!(!report.is_ready());
        let failure = report.failure.expect("failure");
        assert!(failure.is_retryable());
        assert_eq!(failure.reason(), "ApiError");
    }

    // -----------------------------------------------------------------
    // Prune and deletion safety
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn prune_is_off_by_default_and_opt_in_deletes_only_owned_applications() {
        let appset = list_fleet();
        let stale = owned_application("api-legacy", &appset);
        let foreign = {
            let mut application =
                Application::new("hand-written", appset.spec.template.spec.clone());
            application.metadata.namespace = Some("ferriscd-system".to_owned());
            application
        };
        let store = FakeStore::with(vec![stale, foreign]);
        let report = reconciler(
            store.clone(),
            FakeClusters::default(),
            FakeGit::default(),
            Arc::new(FakeAuthorizer::default()),
        )
        .reconcile(&appset)
        .await;
        assert!(report.is_ready(), "{report:?}");
        assert_eq!(report.kept, 1);
        assert!(
            !store
                .object_writes()
                .iter()
                .any(|write| matches!(write, Write::Delete { .. }))
        );

        let mut pruning = list_fleet();
        pruning.spec.sync_policy = ApplicationSetSyncPolicy {
            preserve_resources_on_deletion: true,
            prune: true,
        };
        let store = FakeStore::with(vec![owned_application("api-legacy", &pruning), {
            let mut application =
                Application::new("hand-written", pruning.spec.template.spec.clone());
            application.metadata.namespace = Some("ferriscd-system".to_owned());
            application
        }]);
        let report = reconciler(
            store.clone(),
            FakeClusters::default(),
            FakeGit::default(),
            Arc::new(FakeAuthorizer::default()),
        )
        .reconcile(&pruning)
        .await;
        assert!(report.is_ready(), "{report:?}");
        assert_eq!(report.pruned, 1);
        let deletes: Vec<Write> = store
            .object_writes()
            .into_iter()
            .filter(|write| matches!(write, Write::Delete { .. }))
            .collect();
        assert_eq!(
            deletes,
            vec![Write::Delete {
                name: "api-legacy".to_owned(),
                uid: Some("uid-api-legacy".to_owned()),
            }],
            "a prune deletes with the uid the plan read, so it can never remove a re-created object"
        );
        assert!(
            store
                .applications
                .lock()
                .expect("test lock")
                .iter()
                .any(|application| application.name_any() == "hand-written"),
            "a hand-written Application is never pruned"
        );
    }

    #[tokio::test]
    async fn deleting_an_applicationset_orphans_by_default() {
        let mut appset = list_fleet();
        appset.metadata.deletion_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::now(),
            ));
        appset
            .metadata
            .finalizers
            .get_or_insert_with(Vec::new)
            .push(APPLICATIONSET_FINALIZER.to_owned());
        let store = FakeStore::with(vec![
            owned_application("api-dev", &appset),
            owned_application("api-prod", &appset),
            {
                let mut hand_written =
                    Application::new("hand-written", appset.spec.template.spec.clone());
                hand_written.metadata.namespace = Some("ferriscd-system".to_owned());
                hand_written
            },
        ]);

        let report = reconciler(
            store.clone(),
            FakeClusters::default(),
            FakeGit::default(),
            Arc::new(FakeAuthorizer::default()),
        )
        .reconcile(&appset)
        .await;

        assert!(report.is_ready(), "{report:?}");
        assert_eq!(report.orphaned, 2);
        assert_eq!(report.deleted, 0);
        assert_eq!(
            store.object_writes(),
            vec![
                Write::Orphan("api-dev".to_owned()),
                Write::Orphan("api-prod".to_owned()),
                Write::RemoveFinalizer("payments-fleet".to_owned()),
            ],
            "deleting an ApplicationSet orphans the generated Applications by default"
        );
        assert!(
            !store
                .object_writes()
                .iter()
                .any(|write| matches!(write, Write::Delete { .. }))
        );
    }

    #[tokio::test]
    async fn deleting_an_applicationset_deletes_only_when_opted_in() {
        let mut appset = list_fleet();
        appset.spec.sync_policy.preserve_resources_on_deletion = false;
        appset.metadata.deletion_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::now(),
            ));
        let store = FakeStore::with(vec![owned_application("api-dev", &appset), {
            let mut hand_written =
                Application::new("hand-written", appset.spec.template.spec.clone());
            hand_written.metadata.namespace = Some("ferriscd-system".to_owned());
            hand_written
        }]);
        let report = reconciler(
            store.clone(),
            FakeClusters::default(),
            FakeGit::default(),
            Arc::new(FakeAuthorizer::default()),
        )
        .reconcile(&appset)
        .await;
        assert!(report.is_ready(), "{report:?}");
        assert_eq!(report.deleted, 1);
        assert_eq!(report.orphaned, 0);
        assert_eq!(
            store.object_writes(),
            vec![
                Write::Delete {
                    name: "api-dev".to_owned(),
                    uid: Some("uid-api-dev".to_owned()),
                },
                Write::RemoveFinalizer("payments-fleet".to_owned()),
            ]
        );
    }

    // -----------------------------------------------------------------
    // The real AppProject policy path
    // -----------------------------------------------------------------

    /// A scripted `AppProject` source: the real [`AppProjectPolicy`] runs against it, so the
    /// rejection is the same one a hand-authored `Application` would get.
    struct FakeProjects(Option<ferriscd_crd::AppProject>);

    impl ProjectSource for FakeProjects {
        fn get<'a>(
            &'a self,
            _name: &'a str,
        ) -> BoxFuture<'a, Result<Option<ferriscd_crd::AppProject>, crate::reconcile::ReconcileError>>
        {
            Box::pin(async move { Ok(self.0.clone()) })
        }
    }

    fn project(yaml: &str) -> ferriscd_crd::AppProject {
        serde_saphyr::from_str(yaml).expect("the project fixture must parse")
    }

    #[tokio::test]
    async fn the_real_project_policy_refuses_an_unauthorized_target_before_create() {
        // The default single-tenant scope: the control-plane namespace only.
        let scope = ApplicationScope::new(
            "ferriscd-system",
            ferriscd_engine::policy::ApplicationNamespaces::default(),
        );
        // `sourceRepos` permits a different repository: the generated Application's repoURL is not
        // listed, so the real `AppProjectPolicy` must refuse it.
        let denied = project(
            r#"
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: default
  namespace: ferriscd-system
spec:
  sourceRepos:
    - https://github.com/example/other.git
  sourceNamespaces:
    - ferriscd-system
  destinations:
    - cluster: in-cluster
      namespace: "*"
"#,
        );
        let store = FakeStore::with(Vec::new());
        let authorizer: Arc<dyn ApplicationAuthorizer> = Arc::new(ProjectPolicyAuthorizer::new(
            Arc::new(FakeProjects(Some(denied))),
            scope.clone(),
            "ferriscd-system",
        ));
        let reconciler = ApplicationSetReconciler::new(
            "ferriscd-system",
            Arc::new(FakeClusters::default()),
            Arc::new(FakeGit::default()),
            store.clone(),
            authorizer,
        );
        let report = reconciler.reconcile(&list_fleet()).await;
        assert!(!report.is_ready());
        let failure = report.failure.expect("a denial is reported");
        assert!(matches!(
            failure,
            ApplicationSetControllerError::Policy { .. }
        ));
        assert!(
            failure.to_string().contains("sourceRepos"),
            "the message must name the violated allow-list: {failure}"
        );
        assert!(
            store.object_writes().is_empty(),
            "the project refusal happens before the first write: {:?}",
            store.object_writes()
        );

        // The same project with the repository listed authorizes the fleet and writes it.
        let allowed = project(
            r#"
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: default
  namespace: ferriscd-system
spec:
  sourceRepos:
    - https://github.com/example/payments.git
  sourceNamespaces:
    - ferriscd-system
  destinations:
    - cluster: in-cluster
      namespace: "*"
"#,
        );
        let store = FakeStore::with(Vec::new());
        let authorizer: Arc<dyn ApplicationAuthorizer> = Arc::new(ProjectPolicyAuthorizer::new(
            Arc::new(FakeProjects(Some(allowed))),
            scope,
            "ferriscd-system",
        ));
        let report = ApplicationSetReconciler::new(
            "ferriscd-system",
            Arc::new(FakeClusters::default()),
            Arc::new(FakeGit::default()),
            store.clone(),
            authorizer,
        )
        .reconcile(&list_fleet())
        .await;
        assert!(report.is_ready(), "{report:?}");
        assert_eq!(report.created, 2);
    }

    #[tokio::test]
    async fn a_missing_project_is_a_policy_refusal() {
        let scope = ApplicationScope::new(
            "ferriscd-system",
            ferriscd_engine::policy::ApplicationNamespaces::default(),
        );
        let store = FakeStore::with(Vec::new());
        let authorizer: Arc<dyn ApplicationAuthorizer> = Arc::new(ProjectPolicyAuthorizer::new(
            Arc::new(FakeProjects(None)),
            scope,
            "ferriscd-system",
        ));
        let report = ApplicationSetReconciler::new(
            "ferriscd-system",
            Arc::new(FakeClusters::default()),
            Arc::new(FakeGit::default()),
            store.clone(),
            authorizer,
        )
        .reconcile(&list_fleet())
        .await;
        let failure = report.failure.expect("a missing project fails closed");
        assert_eq!(failure.reason(), "PolicyViolation");
        assert!(failure.to_string().contains("was not found"), "{failure}");
        assert!(store.object_writes().is_empty());
    }

    /// A `ProjectSource` whose read fails with one API status code, so the authorizer's
    /// classification of that failure is observable.
    struct RejectedProjects(u16);

    impl ProjectSource for RejectedProjects {
        fn get<'a>(
            &'a self,
            _name: &'a str,
        ) -> BoxFuture<'a, Result<Option<ferriscd_crd::AppProject>, crate::reconcile::ReconcileError>>
        {
            Box::pin(async move { Err(crate::reconcile::ReconcileError::Api(api_status(self.0))) })
        }
    }

    /// **Finding N-b:** the authorizer used to map **every** `AppProject` read failure to retryable,
    /// so an `ApplicationSet` whose controller `ServiceAccount` lacks `get appprojects` retried a
    /// permanently forbidden read forever (`ApiError`, retryable, no end) instead of reporting the
    /// RBAC misconfiguration once. Permanent rejections are terminal; a rolling API server is not.
    #[tokio::test]
    async fn a_permanently_rejected_project_read_is_terminal_and_a_transient_one_is_retryable() {
        let scope = ApplicationScope::new(
            "ferriscd-system",
            ferriscd_engine::policy::ApplicationNamespaces::default(),
        );
        for code in [400_u16, 403, 409, 422] {
            let store = FakeStore::with(Vec::new());
            let authorizer: Arc<dyn ApplicationAuthorizer> =
                Arc::new(ProjectPolicyAuthorizer::new(
                    Arc::new(RejectedProjects(code)),
                    scope.clone(),
                    "ferriscd-system",
                ));
            let report = ApplicationSetReconciler::new(
                "ferriscd-system",
                Arc::new(FakeClusters::default()),
                Arc::new(FakeGit::default()),
                store.clone(),
                authorizer,
            )
            .reconcile(&list_fleet())
            .await;
            let failure = report
                .failure
                .expect("a failed project read fails the pass");
            assert_eq!(failure.reason(), "ApiRejected", "code {code}: {failure:?}");
            assert!(
                !failure.is_retryable(),
                "code {code} is a permanent rejection: retrying the identical read cannot succeed"
            );
            assert!(store.object_writes().is_empty(), "code {code}");
        }

        for code in [0_u16, 429, 500, 503] {
            let authorizer: Arc<dyn ApplicationAuthorizer> =
                Arc::new(ProjectPolicyAuthorizer::new(
                    Arc::new(RejectedProjects(code)),
                    scope.clone(),
                    "ferriscd-system",
                ));
            let report = ApplicationSetReconciler::new(
                "ferriscd-system",
                Arc::new(FakeClusters::default()),
                Arc::new(FakeGit::default()),
                FakeStore::with(Vec::new()),
                authorizer,
            )
            .reconcile(&list_fleet())
            .await;
            let failure = report
                .failure
                .expect("a failed project read fails the pass");
            assert_eq!(failure.reason(), "ApiError", "code {code}: {failure:?}");
            assert!(
                failure.is_retryable(),
                "code {code} is transient (an unpopulated status, throttling, a rolling API \
                 server): it must be retried"
            );
        }
    }

    // -----------------------------------------------------------------
    // Engine integration through the real planner
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn a_template_error_is_terminal_and_writes_nothing() {
        let mut appset = list_fleet();
        // `{{missing}}` is produced by no generator.
        appset.spec.template.metadata.name = "api-{{missing}}".to_owned();
        let store = FakeStore::with(Vec::new());
        let report = reconciler(
            store.clone(),
            FakeClusters::default(),
            FakeGit::default(),
            Arc::new(FakeAuthorizer::default()),
        )
        .reconcile(&appset)
        .await;
        assert!(!report.is_ready());
        let failure = report.failure.expect("failure");
        assert!(matches!(
            failure,
            ApplicationSetControllerError::Engine(ApplicationSetError::Template(
                TemplateError::UnknownPlaceholder { .. }
            ))
        ));
        assert!(!failure.is_retryable());
        assert_eq!(failure.reason(), "TemplateError");
        assert!(store.object_writes().is_empty());
    }

    #[tokio::test]
    async fn an_applicationset_outside_the_control_plane_namespace_is_refused() {
        let mut appset = list_fleet();
        appset.metadata.namespace = Some("payments".to_owned());
        let store = FakeStore::with(Vec::new());
        let report = reconciler(
            store.clone(),
            FakeClusters::default(),
            FakeGit::default(),
            Arc::new(FakeAuthorizer::default()),
        )
        .reconcile(&appset)
        .await;
        assert!(!report.is_ready());
        assert_eq!(report.failure.expect("failure").reason(), "ApiRejected");
        assert!(store.object_writes().is_empty());
    }

    #[tokio::test]
    async fn the_matrix_example_from_the_roadmap_generates_six_applications() {
        // `Matrix(clusters × git.directories)` with 2 clusters and 3 directories = 6 Applications:
        // the roadmap's hands-on experiment, evaluated hermetically here.
        let directory = tempfile::TempDir::new().expect("temp dir");
        for app in ["api", "web", "worker"] {
            std::fs::create_dir_all(directory.path().join("apps").join(app))
                .expect("create fixture dir");
        }
        let appset = appset(
            r#"
generators:
  - matrix:
      generators:
        - clusters:
            selector:
              matchLabels:
                env: prod
        - git:
            repoURL: https://github.com/example/config.git
            revision: HEAD
            directories:
              - path: apps/*
template:
  metadata:
    name: "{{path.basename}}-{{cluster.name}}"
  spec:
    project: default
    source:
      git:
        repoURL: https://github.com/example/payments.git
        path: "{{path}}"
    destination:
      cluster: "{{cluster.name}}"
      namespace: "{{path.basename}}"
"#,
        );
        let clusters = FakeClusters {
            registrations: vec![
                ClusterRegistration::new(
                    "eu-prod",
                    BTreeMap::from([("env".to_owned(), "prod".to_owned())]),
                ),
                ClusterRegistration::new(
                    "us-prod",
                    BTreeMap::from([("env".to_owned(), "prod".to_owned())]),
                ),
                ClusterRegistration::new(
                    "us-dev",
                    BTreeMap::from([("env".to_owned(), "dev".to_owned())]),
                ),
            ],
        };
        let store = FakeStore::with(Vec::new());
        let report = reconciler(
            store.clone(),
            clusters,
            FakeGit {
                root: Some(directory.path().to_path_buf()),
                fail: false,
            },
            Arc::new(FakeAuthorizer::default()),
        )
        .reconcile(&appset)
        .await;
        assert!(report.is_ready(), "{report:?}");
        assert_eq!(report.generated, 6);
        assert_eq!(report.created, 6);
        let names: Vec<String> = store
            .applications
            .lock()
            .expect("test lock")
            .iter()
            .map(|application| application.name_any())
            .collect();
        assert_eq!(
            names,
            vec![
                "api-eu-prod",
                "api-us-prod",
                "web-eu-prod",
                "web-us-prod",
                "worker-eu-prod",
                "worker-us-prod"
            ]
        );
    }

    // -----------------------------------------------------------------
    // External triggers (finding M3)
    // -----------------------------------------------------------------

    fn tracked(appsets: &[ApplicationSet], next_due_in: Duration) -> BTreeMap<String, Tracked> {
        let due = tokio::time::Instant::now() + next_due_in;
        appsets
            .iter()
            .map(|appset| {
                (
                    appset.name_any(),
                    Tracked {
                        appset: appset.clone(),
                        next_due: due,
                    },
                )
            })
            .collect()
    }

    /// **Finding M3:** a cluster registration change must not wait for the 180 s requeue (or the
    /// 600 s re-list). The pass is due *immediately* after an injected event, with no sleep in the
    /// test: `force_due`/`due_names` are the loop's scheduling decision, computed against a
    /// `tokio::time::Instant` the test owns.
    #[tokio::test]
    async fn an_injected_trigger_makes_every_tracked_pass_due_without_waiting_for_the_requeue() {
        let first = list_fleet();
        let mut second = list_fleet();
        second.metadata.name = Some("payments-fleet-two".to_owned());
        let mut tracked = tracked(&[first, second], DEFAULT_APPLICATIONSET_INTERVAL);
        let now = tokio::time::Instant::now();
        assert!(
            due_names(&tracked, now).is_empty(),
            "before the trigger, a fresh pass is not due again for `requeueAfterSeconds`"
        );

        // Inject the event exactly as the loop receives it.
        let trigger = TriggerEvent::Cluster(ClusterLifecycleEvent::Added("eu-prod".to_owned()));
        let names = force_due(&mut tracked, now);
        assert_eq!(trigger.kind(), "cluster-added");
        assert_eq!(
            names,
            vec!["payments-fleet".to_owned(), "payments-fleet-two".to_owned()],
            "every tracked ApplicationSet is re-evaluated, in deterministic order"
        );
        assert_eq!(
            due_names(&tracked, now),
            names,
            "after the trigger, the same clock reads them as due"
        );
    }

    /// The injected event reaches the loop through the *real* stream adapter: a `T18.1` lifecycle
    /// event sent on the broadcast channel comes out as one trigger, and a lagged subscriber
    /// collapses the dropped events into a single "re-read everything" trigger. No sleeps: the
    /// values are already buffered when the stream is polled.
    #[tokio::test]
    async fn cluster_lifecycle_events_reach_the_trigger_stream() {
        let (sender, receiver) = broadcast::channel(4);
        let mut triggers = cluster_trigger_stream(receiver);
        sender
            .send(ClusterLifecycleEvent::Added("eu-prod".to_owned()))
            .expect("a receiver exists");
        sender
            .send(ClusterLifecycleEvent::Removed("us-dev".to_owned()))
            .expect("a receiver exists");
        assert_eq!(
            triggers.next().await,
            Some(TriggerEvent::Cluster(ClusterLifecycleEvent::Added(
                "eu-prod".to_owned()
            )))
        );
        assert_eq!(
            triggers.next().await,
            Some(TriggerEvent::Cluster(ClusterLifecycleEvent::Removed(
                "us-dev".to_owned()
            )))
        );

        // A subscriber that falls behind gets `Lagged`; that must not end (or wedge) the stream.
        let (sender, receiver) = broadcast::channel(1);
        let mut triggers = cluster_trigger_stream(receiver);
        sender
            .send(ClusterLifecycleEvent::Added("one".to_owned()))
            .expect("a receiver exists");
        sender
            .send(ClusterLifecycleEvent::Rebuilt("two".to_owned()))
            .expect("a receiver exists");
        assert_eq!(
            triggers.next().await,
            Some(TriggerEvent::Lagged),
            "a lagged receiver re-reads everything rather than losing the change"
        );
        assert_eq!(TriggerEvent::Lagged.kind(), "trigger-lagged");
        // `Lagged` is followed by the newest buffered event, so the collapsed notification still
        // carries the latest state …
        assert_eq!(
            triggers.next().await,
            Some(TriggerEvent::Cluster(ClusterLifecycleEvent::Rebuilt(
                "two".to_owned()
            )))
        );

        // … and a closed channel ends the stream, which the loop handles by parking the arm.
        drop(sender);
        assert_eq!(triggers.next().await, None);
    }

    /// A generated `Application` drifting (or disappearing) must re-run the pass, while the status
    /// writes the `Application` controller performs must not: otherwise every `/status` patch would
    /// re-evaluate every generator.
    #[tokio::test]
    async fn generated_application_watch_events_trigger_a_pass_but_status_writes_do_not() {
        let appset = list_fleet();
        let mut application = owned_application("api-dev", &appset);
        application.metadata.generation = Some(1);
        let mut tracker = crate::predicate::PredicateTracker::new();
        // Finding M-b: the trigger names the owning `ApplicationSet`, so only that pass is forced.
        let owned = || TriggerEvent::GeneratedApplication {
            applicationset: Some("payments-fleet".to_owned()),
        };

        assert_eq!(
            classify_application_event(
                Ok(watcher::Event::InitApply(application.clone())),
                &mut tracker
            ),
            Some(owned()),
            "the first observation of a generated Application triggers a pass"
        );
        assert_eq!(
            classify_application_event(
                Ok(watcher::Event::Apply(application.clone())),
                &mut tracker
            ),
            None,
            "an unchanged re-delivery does not"
        );

        let mut status_only = application.clone();
        status_only.status = Some(ferriscd_crd::status::ApplicationStatus::default());
        status_only.metadata.resource_version = Some("42".to_owned());
        assert_eq!(
            classify_application_event(Ok(watcher::Event::Apply(status_only)), &mut tracker),
            None,
            "a /status patch or a resourceVersion bump must not re-run the generators"
        );

        let mut edited = application.clone();
        edited.metadata.generation = Some(2);
        assert_eq!(
            classify_application_event(Ok(watcher::Event::Apply(edited)), &mut tracker),
            Some(owned()),
            "a hand-edited generated Application (spec bump) triggers a pass"
        );

        assert_eq!(
            classify_application_event(
                Ok(watcher::Event::Delete(application.clone())),
                &mut tracker
            ),
            Some(owned()),
            "a deleted generated Application triggers a pass, for its own ApplicationSet"
        );
        assert_eq!(
            classify_application_event(Ok(watcher::Event::InitDone), &mut tracker),
            Some(TriggerEvent::GeneratedApplication {
                applicationset: None
            }),
            "a completed re-list re-compares the whole fleet, naming no single ApplicationSet"
        );
        assert_eq!(
            classify_application_event(Ok(watcher::Event::Init), &mut tracker),
            None
        );

        // A forgot object reconciles again even with an identical hash.
        assert!(
            tracker.observe(&application),
            "after a deletion the same Application is observed as new"
        );

        // An `Application` whose label was removed by hand names no owner, so the pass that sees it
        // must re-read everything rather than silently skipping it.
        let mut unlabelled = application.clone();
        unlabelled.metadata.labels = Some(BTreeMap::new());
        assert_eq!(
            triggered_by(&unlabelled),
            TriggerEvent::GeneratedApplication {
                applicationset: None
            }
        );
    }

    /// **Finding M-b:** one generated `Application` drifting forces **only** its own `ApplicationSet`
    /// due; a cluster event or a dropped-event resync still forces everything.
    #[tokio::test]
    async fn a_generated_application_trigger_forces_only_its_own_applicationset() {
        let first = list_fleet();
        let mut second = list_fleet();
        second.metadata.name = Some("payments-fleet-two".to_owned());
        let mut tracked = tracked(&[first, second], DEFAULT_APPLICATIONSET_INTERVAL);
        let now = tokio::time::Instant::now();

        let trigger = TriggerEvent::GeneratedApplication {
            applicationset: Some("payments-fleet-two".to_owned()),
        };
        assert_eq!(trigger.kind(), "generated-application");
        assert_eq!(trigger.owner(), Some("payments-fleet-two"));
        let names = force_due_named(&mut tracked, now, trigger.owner().expect("a named owner"));
        assert_eq!(names, vec!["payments-fleet-two".to_owned()]);
        assert_eq!(
            due_names(&tracked, now),
            names,
            "only the owning ApplicationSet is due"
        );
        assert!(
            !due_names(&tracked, now).contains(&"payments-fleet".to_owned()),
            "the untouched fleet is not re-evaluated: a 200-ApplicationSet loop must not fan out \
             on every child event"
        );

        // A trigger that names an ApplicationSet nobody tracks forces nothing (nothing to do).
        assert!(
            force_due_named(&mut tracked, now, "not-tracked").is_empty(),
            "an unknown owner must not make the loop reconcile unrelated objects"
        );

        // No owner (a re-list) and no name-able event force everything.
        for trigger in [
            TriggerEvent::Lagged,
            TriggerEvent::GeneratedApplication {
                applicationset: None,
            },
            TriggerEvent::Cluster(ClusterLifecycleEvent::Removed("us-dev".to_owned())),
        ] {
            assert_eq!(trigger.owner(), None, "{trigger:?}");
            assert_eq!(
                force_due(&mut tracked, now),
                vec!["payments-fleet".to_owned(), "payments-fleet-two".to_owned()],
                "{trigger:?} falls back to every tracked ApplicationSet"
            );
        }
    }

    /// **Finding M-2:** one fan-out change arrives as a *burst* of ready triggers (a cluster
    /// registration re-triggering every `ApplicationSet`, a re-list delivering one event per child, a
    /// `Lagged` collapse). The burst is folded into one due-set, so it costs one pass per affected
    /// `ApplicationSet` instead of one pass per event — each of which would re-run the same unchanged
    /// generators.
    #[tokio::test]
    async fn a_burst_of_ready_triggers_is_coalesced_into_one_pass_per_applicationset() {
        let first = list_fleet();
        let mut second = list_fleet();
        second.metadata.name = Some("payments-fleet-two".to_owned());
        let mut tracked = tracked(&[first, second], DEFAULT_APPLICATIONSET_INTERVAL);

        // Nine ready events that name at most two ApplicationSets: three cluster registrations, a
        // dropped-event resync, a re-list (both "everything"), two children of the first fleet, and
        // a child whose owner is not tracked at all.
        let events = vec![
            TriggerEvent::Cluster(ClusterLifecycleEvent::Added("eu-prod".to_owned())),
            TriggerEvent::Cluster(ClusterLifecycleEvent::Rebuilt("us-prod".to_owned())),
            TriggerEvent::Cluster(ClusterLifecycleEvent::Removed("us-dev".to_owned())),
            TriggerEvent::Lagged,
            TriggerEvent::GeneratedApplication {
                applicationset: None,
            },
            TriggerEvent::GeneratedApplication {
                applicationset: Some("payments-fleet".to_owned()),
            },
            TriggerEvent::GeneratedApplication {
                applicationset: Some("payments-fleet".to_owned()),
            },
            TriggerEvent::GeneratedApplication {
                applicationset: Some("payments-fleet-two".to_owned()),
            },
            TriggerEvent::GeneratedApplication {
                applicationset: Some("a-fleet-this-controller-does-not-track".to_owned()),
            },
        ];
        let mut triggers: BoxStream<'static, TriggerEvent> = futures::stream::iter(events)
            .chain(futures::stream::pending())
            .boxed();

        let first_trigger = triggers.next().await.expect("the burst holds a trigger");
        let names = drain_due(&mut triggers, &mut tracked, first_trigger);

        assert_eq!(
            names,
            vec!["payments-fleet".to_owned(), "payments-fleet-two".to_owned()],
            "one due-set for the whole burst: every affected ApplicationSet exactly once"
        );
        assert_eq!(
            due_names(&tracked, tokio::time::Instant::now()),
            names,
            "the due-set is what the loop reconciles, in deterministic order"
        );
        assert!(
            triggers.next().now_or_never().is_none(),
            "the drain consumed the burst, so the loop cannot turn it into a second round of passes"
        );
        assert!(
            !names.contains(&"a-fleet-this-controller-does-not-track".to_owned()),
            "an untracked owner contributes nothing"
        );
    }

    /// **Finding M2:** the burst above starts with a cluster event, which forces *everything*, so its
    /// due-set is the same one a "force everything regardless of the event" mutant would produce and
    /// the per-event ownership decision is never actually discriminated. This burst contains no
    /// name-less event at all: every trigger names one owner, one of them is not tracked, and a third
    /// tracked `ApplicationSet` exists that nobody names. Only a per-event decision yields exactly the
    /// two named objects — a force-everything mutant returns all three, a first-only mutant returns
    /// one.
    #[tokio::test]
    async fn a_burst_of_named_triggers_queues_only_the_applicationsets_they_name() {
        let first = list_fleet();
        let mut second = list_fleet();
        second.metadata.name = Some("payments-fleet-two".to_owned());
        let mut third = list_fleet();
        third.metadata.name = Some("fleet-nobody-triggered".to_owned());
        let mut tracked = tracked(&[first, second, third], DEFAULT_APPLICATIONSET_INTERVAL);
        let now = tokio::time::Instant::now();
        assert!(
            due_names(&tracked, now).is_empty(),
            "nothing is due before the burst"
        );

        let events = vec![
            TriggerEvent::GeneratedApplication {
                applicationset: Some("payments-fleet".to_owned()),
            },
            TriggerEvent::GeneratedApplication {
                applicationset: Some("payments-fleet-two".to_owned()),
            },
            // A generated Application whose owning ApplicationSet this controller does not track.
            TriggerEvent::GeneratedApplication {
                applicationset: Some("untracked".to_owned()),
            },
        ];
        let mut triggers: BoxStream<'static, TriggerEvent> = futures::stream::iter(events)
            .chain(futures::stream::pending())
            .boxed();

        let first_trigger = triggers.next().await.expect("the burst holds a trigger");
        let names = drain_due(&mut triggers, &mut tracked, first_trigger);

        assert_eq!(
            names,
            vec!["payments-fleet".to_owned(), "payments-fleet-two".to_owned()],
            "each event forces only the ApplicationSet it names: the untracked owner contributes \
             nothing and the third tracked ApplicationSet is not swept in"
        );
        assert!(
            !names.contains(&"fleet-nobody-triggered".to_owned()),
            "no event in this burst names it, so coalescing must not widen the due-set to everything"
        );
        assert_eq!(
            due_names(&tracked, tokio::time::Instant::now()),
            names,
            "the due-set is exactly what the loop reconciles"
        );
        assert!(
            triggers.next().now_or_never().is_none(),
            "the drain consumed the whole burst"
        );
    }

    /// The default controller has no trigger source, and an empty stream must not spin the loop's
    /// `select!`. Polled once with a no-op waker, so the assertion costs no wall-clock time.
    #[tokio::test]
    async fn the_default_trigger_source_never_fires() {
        use futures::stream::StreamExt as _;
        use std::task::Poll;

        let controller = ApplicationSetController::new(
            Arc::new(reconciler(
                FakeStore::with(Vec::new()),
                FakeClusters::default(),
                FakeGit::default(),
                Arc::new(FakeAuthorizer::default()),
            )),
            Arc::new(StaticSource(Vec::new())),
            "ferriscd-system",
        );
        // Sanity: the default constructor is the no-op source.
        assert_eq!(controller.triggers.triggers().size_hint(), (0, Some(0)));
        let mut triggers = NoTrigger.triggers();
        let waker = futures::task::noop_waker();
        let mut context = std::task::Context::from_waker(&waker);
        assert!(
            matches!(triggers.poll_next_unpin(&mut context), Poll::Pending),
            "the no-op trigger source must stay pending: a stream that completes would make the \
             loop's `select!` arm spin"
        );
    }

    /// A source for the loop-level tests: it signals one re-list bracket and then never yields.
    struct StaticSource(Vec<ApplicationSet>);

    impl ApplicationSetSource for StaticSource {
        fn events(
            &self,
        ) -> BoxStream<'static, Result<ApplicationSetEvent, ApplicationSetWatchError>> {
            // One `Resync` (the loop's re-list bracket), then nothing: the loop must not need a
            // second event, and a real watch never ends.
            futures::stream::iter([Ok(ApplicationSetEvent::Resync)])
                .chain(futures::stream::pending())
                .boxed()
        }

        fn list(&self) -> BoxFuture<'_, Result<Vec<ApplicationSet>, ApplicationSetWatchError>> {
            let items = self.0.clone();
            Box::pin(async move { Ok(items) })
        }
    }

    /// A broadcast channel as the loop's trigger source (the production adapter's cluster half).
    struct ChannelTrigger(broadcast::Receiver<ClusterLifecycleEvent>);

    impl ApplicationSetTrigger for ChannelTrigger {
        fn triggers(&self) -> BoxStream<'static, TriggerEvent> {
            cluster_trigger_stream(self.0.resubscribe())
        }
    }

    /// One trigger through the **running loop**: the second pass happens because of the injected
    /// event, not because of a timer. The watchdog timeouts fail the test if a pass never lands; they
    /// never make it pass by waiting.
    #[tokio::test]
    async fn the_running_loop_reconciles_when_a_trigger_arrives() {
        let store = FakeStore::with(Vec::new());
        let reconciler = Arc::new(reconciler(
            store.clone(),
            FakeClusters::default(),
            FakeGit::default(),
            Arc::new(FakeAuthorizer::default()),
        ));
        // The initial re-list is the only pass that can run without a trigger.
        let source = Arc::new(StaticSource(vec![list_fleet()]));
        let (sender, receiver) = broadcast::channel(4);
        let controller = Arc::new(
            ApplicationSetController::new(reconciler, source, "ferriscd-system")
                .with_triggers(Arc::new(ChannelTrigger(receiver))),
        );
        let stop = tokio_util::sync::CancellationToken::new();
        let loop_task = tokio::spawn(controller.run(stop.clone()));

        // Wait (bounded) for the first pass's `/status` write.
        tokio::time::timeout(Duration::from_secs(5), async {
            while store.statuses().is_empty() {
                store.next_write().await;
            }
        })
        .await
        .expect("the initial ApplicationSet event must produce one pass");
        let after_first = store.statuses().len();
        let objects_after_first = store.object_writes();
        assert_eq!(
            objects_after_first,
            vec![
                Write::EnsureFinalizer("payments-fleet".to_owned()),
                Write::Upsert("api-dev".to_owned()),
                Write::Upsert("api-prod".to_owned()),
            ],
            "the first pass creates the fleet"
        );

        sender
            .send(ClusterLifecycleEvent::Added("eu-prod".to_owned()))
            .expect("the loop holds a receiver");
        tokio::time::timeout(Duration::from_secs(5), async {
            while store.statuses().len() <= after_first {
                store.next_write().await;
            }
        })
        .await
        .expect("an injected cluster event must cause another pass, with no timer to help it");

        stop.cancel();
        loop_task.await.expect("the loop task must not panic");
        let fleet_writes = |writes: Vec<Write>| {
            writes
                .into_iter()
                .filter(|write| {
                    matches!(
                        write,
                        Write::Upsert(_) | Write::Delete { .. } | Write::Orphan(_)
                    )
                })
                .count()
        };
        assert_eq!(
            fleet_writes(store.object_writes()),
            fleet_writes(objects_after_first),
            "the triggered pass converges: it re-asserts the finalizer and writes /status, but \
             touches no generated Application"
        );
    }

    // -----------------------------------------------------------------
    // Delete / orphan API classification (findings M5, M7)
    // -----------------------------------------------------------------

    /// A scripted API-server status error. Only `code` is classified, so the rest is minimal.
    fn api_status(code: u16) -> kube::Error {
        kube::Error::Api(
            kube::core::Status {
                status: None,
                message: format!("scripted {code}"),
                reason: "Conflict".to_owned(),
                code,
                details: None,
                metadata: None,
            }
            .boxed(),
        )
    }

    /// **Finding M5:** a `409` from a delete is the `Preconditions.uid` check firing (the name now
    /// belongs to a different object), and a `404` means it is already gone: both satisfy "the object
    /// the plan read is gone". **Finding M7:** the same `404` on the orphan patch is not a failure.
    /// **Findings C-1/H-1:** the orphan patch's identity guard answers `409` (stale
    /// `resourceVersion`) or `422` (immutable `uid`), and *neither* is decidable here — both are
    /// handed to the live read, because reading either as "gone" released the finalizer on a child
    /// that still referenced the `ApplicationSet` (the fleet-wipe outcome).
    #[test]
    fn delete_and_orphan_treat_already_gone_objects_as_success() {
        assert!(delete_outcome(&api_status(404)).is_ok());
        assert!(
            delete_outcome(&api_status(409)).is_ok(),
            "a uid-precondition conflict means the listed object is gone: never delete the new one"
        );
        for code in [400_u16, 403, 422] {
            let error =
                delete_outcome(&api_status(code)).expect_err("a rejected delete is an error");
            assert!(!error.is_retryable(), "code {code}: {:?}", error);
        }
        assert!(
            delete_outcome(&api_status(500))
                .expect_err("a server error is an error")
                .is_retryable(),
            "a 5xx delete is worth retrying"
        );

        assert_eq!(
            orphan_patch_outcome(&api_status(404)).expect("a 404 is a decided outcome"),
            OrphanPatch::Done,
            "orphaning an Application that is already gone must not wedge the finalizer"
        );
        for code in [409_u16, 422] {
            assert_eq!(
                orphan_patch_outcome(&api_status(code)).expect("a conflict is a decided outcome"),
                OrphanPatch::Conflict,
                "code {code} is the identity guard firing, which only the live object can \
                 interpret: reading it as gone here is the fleet-wipe bug (C-1/H-1)"
            );
            assert!(is_orphan_conflict(code), "code {code}");
        }
        assert!(
            !is_orphan_conflict(404),
            "a 404 is not a conflict: it is already gone"
        );
        assert!(
            orphan_patch_outcome(&api_status(500))
                .expect_err("a server error is a failure")
                .is_retryable()
        );
        assert!(
            !orphan_patch_outcome(&api_status(403))
                .expect_err("a forbidden patch is a failure")
                .is_retryable(),
            "a rejected orphan patch must not be retried forever"
        );
        // The base classification is unchanged: a `409` from a Server-Side Apply (a field another
        // manager owns) still fails the pass, because retrying the identical body cannot succeed.
        assert!(
            !api_error(&api_status(409)).is_retryable(),
            "an upsert conflict stays terminal"
        );
        assert!(api_error(&api_status(500)).is_retryable());
        // Finding N-d: the status write the deletion pass issues after releasing the finalizer
        // answers `404` on the object it just removed; that is the end state, not a failure.
        assert!(
            status_outcome(&api_status(404)).is_ok(),
            "a /status patch on a just-deleted ApplicationSet is gone, not a failure"
        );
        assert!(status_outcome(&api_status(410)).is_ok());
        assert!(
            !status_outcome(&api_status(403))
                .expect_err("a rejected status write is an error")
                .is_retryable()
        );
        assert!(
            status_outcome(&api_status(500))
                .expect_err("a server error is an error")
                .is_retryable()
        );
    }

    /// **Finding N-1:** the orphan patch is computed from a list snapshot, so it must carry that
    /// snapshot's identity — otherwise a name that was deleted and re-created in between would lose
    /// the *new* object's owner references.
    #[test]
    fn the_orphan_patch_carries_the_listed_objects_identity() {
        let appset = list_fleet();
        let mut application = owned_application("api-dev", &appset);
        application.metadata.uid = Some("uid-api-dev".to_owned());
        application.metadata.resource_version = Some("4242".to_owned());

        let body = orphan_patch_body(&application).expect("the body serializes");
        assert_eq!(body["metadata"]["uid"], serde_json::json!("uid-api-dev"));
        assert_eq!(
            body["metadata"]["resourceVersion"],
            serde_json::json!("4242"),
            "the identity is what makes the API server reject a patch aimed at another object: a \
             stale resourceVersion is a 409, a foreign uid is a 422 (metadata.uid is immutable)"
        );
        assert_eq!(
            body["metadata"]["ownerReferences"],
            serde_json::Value::Null,
            "the ApplicationSet reference is dropped entirely when it is the only owner"
        );

        // Somebody else's owner reference is kept, and an Application with no identity at all (an
        // unpersisted fixture) simply produces a body without the guard.
        let mut shared = application.clone();
        shared.metadata.owner_references = Some(vec![
            ferriscd_engine::applicationset::template::owner_reference(
                "payments-fleet",
                "uid-payments-fleet",
            ),
            k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                api_version: "example.com/v1".to_owned(),
                kind: "SomethingElse".to_owned(),
                name: "other".to_owned(),
                uid: "uid-other".to_owned(),
                controller: None,
                block_owner_deletion: None,
            },
            // Finding N1: the *same Kind name* in another API group is a different owner entirely.
            // Dropping on `kind` alone would strip it and hand that operator's Application to
            // garbage collection, so this reference must survive the patch untouched.
            k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                api_version: "other.example/v1".to_owned(),
                kind: "ApplicationSet".to_owned(),
                name: "somebody-elses-applicationset".to_owned(),
                uid: "uid-theirs".to_owned(),
                controller: None,
                block_owner_deletion: None,
            },
        ]);
        let body = orphan_patch_body(&shared).expect("the body serializes");
        let remaining = body["metadata"]["ownerReferences"]
            .as_array()
            .expect("a list");
        assert_eq!(
            remaining.len(),
            2,
            "only this API group's ApplicationSet reference is ours to drop: {remaining:?}"
        );
        assert_eq!(remaining[0]["kind"], "SomethingElse");
        assert_eq!(
            remaining[1]["uid"],
            serde_json::json!("uid-theirs"),
            "a foreign-group ApplicationSet owner reference is never stripped by this controller"
        );

        let mut anonymous = application.clone();
        anonymous.metadata.uid = None;
        anonymous.metadata.resource_version = None;
        let body = orphan_patch_body(&anonymous).expect("the body serializes");
        assert!(body["metadata"].get("uid").is_none());
        assert!(body["metadata"].get("resourceVersion").is_none());
    }

    /// **Finding N-2:** a finalizer patch must never drop a finalizer another manager owns. The patch
    /// is computed from a live read and carries that read's `resourceVersion`, so the array it states
    /// is the array the API server has (or the write is rejected with `409` and retried).
    #[test]
    fn finalizer_patches_preserve_another_managers_finalizer() {
        let mut live = list_fleet();
        live.metadata.finalizers = Some(vec!["other.example/cleanup".to_owned()]);
        live.metadata.resource_version = Some("777".to_owned());

        let add = finalizer_patch_body(&live, FinalizerOp::Add).expect("our finalizer is missing");
        assert_eq!(
            add["metadata"]["finalizers"],
            serde_json::json!(["other.example/cleanup", APPLICATIONSET_FINALIZER]),
            "the other manager's finalizer is kept and ours is appended"
        );
        assert_eq!(
            add["metadata"]["resourceVersion"],
            serde_json::json!("777"),
            "the write is conditional on the object not having changed since the read"
        );

        // Nothing to do when it is already there.
        let mut already = live.clone();
        already.metadata.finalizers = Some(vec![
            "other.example/cleanup".to_owned(),
            APPLICATIONSET_FINALIZER.to_owned(),
        ]);
        assert_eq!(finalizer_patch_body(&already, FinalizerOp::Add), None);

        // Removal drops exactly our own value, in place, keeping the other manager's.
        let remove =
            finalizer_patch_body(&already, FinalizerOp::Remove).expect("our finalizer is present");
        assert_eq!(
            remove["metadata"]["finalizers"],
            serde_json::json!(["other.example/cleanup"]),
            "releasing our finalizer must not release somebody else's"
        );
        assert_eq!(
            remove["metadata"]["resourceVersion"],
            serde_json::json!("777")
        );

        // Removing a finalizer that is not there is a no-op, never a write.
        assert_eq!(finalizer_patch_body(&live, FinalizerOp::Remove), None);

        // Releasing the last finalizer sends an empty list (not a missing key): a merge patch that
        // omitted the field would leave the object stuck in `Terminating`.
        let mut only_ours = list_fleet();
        only_ours.metadata.finalizers = Some(vec![APPLICATIONSET_FINALIZER.to_owned()]);
        let remove = finalizer_patch_body(&only_ours, FinalizerOp::Remove)
            .expect("our finalizer is present");
        assert_eq!(remove["metadata"]["finalizers"], serde_json::json!([]));
    }

    /// A `404` from a finalizer patch means there is nothing left to finalize, and a `409` is the
    /// precondition firing — retryable, because the next pass recomputes from a fresh read.
    #[test]
    fn finalizer_patch_failures_are_classified() {
        assert!(finalizer_outcome(&api_status(404)).is_ok());
        assert!(
            finalizer_outcome(&api_status(409))
                .expect_err("a stale read is an error")
                .is_retryable(),
            "a precondition conflict must be retried, not reported terminal"
        );
        assert!(!finalizer_outcome(&api_status(403)).is_err_and(|error| error.is_retryable()));
        assert!(finalizer_outcome(&api_status(500)).is_err());
    }

    // -----------------------------------------------------------------
    // The orphan patch against a scripted API server (findings C-1, H-1, N-d)
    // -----------------------------------------------------------------
    //
    // `orphan_outcome` used to be the whole story, so the *consequences* of reading a `409` as
    // "gone" (an orphaned child counted, the finalizer released, the fleet handed to garbage
    // collection) were invisible to a unit test. These tests drive the real `KubeApplicationSetStore`
    // over a scripted API server, so both the request bodies and the writes the pass performs are
    // observable.

    /// One request the scripted API server received.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Received {
        method: String,
        path: String,
        body: serde_json::Value,
    }

    /// The answer the scripted API server gives to one request.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Reply {
        /// `200` with this body.
        Ok(serde_json::Value),
        /// A `Status` failure with this HTTP code.
        Failed(u16),
    }

    /// One scripted answer for the orphan patch.
    #[derive(Debug, Clone)]
    enum Answer {
        /// `200` with the `Application` the server now stores (what a successful merge patch
        /// answers).
        Stored,
        /// A `Status` failure with this HTTP code.
        Failed(u16),
    }

    /// A scripted API server for one deletion pass.
    ///
    /// It answers the four calls the pass makes — `GET applications` (the snapshot), `PATCH
    /// applications/{name}` (the orphan patch, answered from a queue so a `409`-then-retry and a
    /// `409`-then-`409` are both expressible), `GET applications/{name}` (the live read) and the
    /// `ApplicationSet` finalizer/`/status` round-trips — and records every request.
    #[derive(Default)]
    struct ScriptedApi {
        received: Mutex<Vec<Received>>,
        /// The snapshot the list returns.
        listed: Mutex<Vec<serde_json::Value>>,
        /// What the live read sees; `None` is a `404`.
        live: Mutex<Option<serde_json::Value>>,
        /// Successive orphan-patch answers; an exhausted queue answers `500` so an unscripted call
        /// fails the test instead of silently succeeding.
        orphan_answers: Mutex<VecDeque<Answer>>,
        /// The `ApplicationSet` the finalizer round-trip reads and writes.
        appset: Mutex<serde_json::Value>,
        /// The `/status` answer, when the test needs one other than a `200`.
        status_answer: Mutex<Option<Reply>>,
    }

    impl ScriptedApi {
        fn received(&self) -> Vec<Received> {
            crate::lock_recover(&self.received).clone()
        }

        /// The orphan-patch bodies sent for `name`, in order.
        fn orphan_patches(&self, name: &str) -> Vec<serde_json::Value> {
            let suffix = format!("/applications/{name}");
            self.received()
                .into_iter()
                .filter(|request| request.method == "PATCH" && request.path.ends_with(&suffix))
                .map(|request| request.body)
                .collect()
        }

        /// The finalizer-patch bodies sent for `name`: the write that releases it.
        fn finalizer_patches(&self, name: &str) -> Vec<serde_json::Value> {
            let suffix = format!("/applicationsets/{name}");
            self.received()
                .into_iter()
                .filter(|request| request.method == "PATCH" && request.path.ends_with(&suffix))
                .map(|request| request.body)
                .collect()
        }

        /// The `/status` patch bodies sent for `name`.
        fn status_patches(&self, name: &str) -> Vec<serde_json::Value> {
            let suffix = format!("/applicationsets/{name}/status");
            self.received()
                .into_iter()
                .filter(|request| request.method == "PATCH" && request.path.ends_with(&suffix))
                .map(|request| request.body)
                .collect()
        }

        /// The `Application` the scripted server stores: the live one when there is one, otherwise
        /// the listed one.
        fn stored(&self) -> serde_json::Value {
            crate::lock_recover(&self.live)
                .clone()
                .or_else(|| crate::lock_recover(&self.listed).first().cloned())
                .unwrap_or(serde_json::Value::Null)
        }

        fn appset(&self) -> serde_json::Value {
            crate::lock_recover(&self.appset).clone()
        }

        fn answer(&self, method: &str, path: &str) -> Reply {
            // `/status` first: it is a patch of the `ApplicationSet`, not of an `Application`.
            if method == "PATCH" && path.ends_with("/status") {
                return crate::lock_recover(&self.status_answer)
                    .clone()
                    .unwrap_or_else(|| Reply::Ok(self.appset()));
            }
            // The finalizer read-modify-write (`get`, then a merge patch of the whole array).
            if path.contains("/applicationsets/") {
                return Reply::Ok(self.appset());
            }
            if method == "GET" && path.ends_with("/applications") {
                return Reply::Ok(serde_json::json!({
                    "apiVersion": "ferriscd.io/v1alpha1",
                    "kind": "ApplicationList",
                    "metadata": { "resourceVersion": "1" },
                    "items": crate::lock_recover(&self.listed).clone(),
                }));
            }
            if method == "GET" && path.contains("/applications/") {
                return crate::lock_recover(&self.live)
                    .clone()
                    .map_or(Reply::Failed(404), Reply::Ok);
            }
            if method == "PATCH" && path.contains("/applications/") {
                return match crate::lock_recover(&self.orphan_answers).pop_front() {
                    Some(Answer::Stored) => Reply::Ok(self.stored()),
                    Some(Answer::Failed(code)) => Reply::Failed(code),
                    None => Reply::Failed(500),
                };
            }
            Reply::Failed(500)
        }
    }

    /// A `Status` failure body, which is what makes kube surface a typed `kube::Error::Api`.
    fn respond(reply: Reply) -> http::Response<kube::client::Body> {
        let (status, body) = match reply {
            Reply::Ok(body) => (200, body),
            Reply::Failed(code) => (
                code,
                serde_json::json!({
                    "kind": "Status",
                    "apiVersion": "v1",
                    "metadata": {},
                    "status": "Failure",
                    "message": format!("scripted {code}"),
                    "reason": if code == 404 { "NotFound" } else { "Conflict" },
                    "code": code,
                }),
            ),
        };
        http::Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(kube::client::Body::from(
                serde_json::to_vec(&body).expect("a serializable body"),
            ))
            .expect("a valid response")
    }

    /// The scripted store the deletion pass writes through (a real `KubeApplicationSetStore`).
    fn scripted_store(api: &Arc<ScriptedApi>) -> KubeApplicationSetStore {
        let api = api.clone();
        let client = kube::Client::new(
            tower::service_fn(move |request: http::Request<kube::client::Body>| {
                let api = api.clone();
                async move {
                    let method = request.method().as_str().to_owned();
                    let path = request.uri().path().to_owned();
                    let body = request
                        .into_body()
                        .collect_bytes()
                        .await
                        .ok()
                        .filter(|bytes| !bytes.is_empty())
                        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                        .unwrap_or(serde_json::Value::Null);
                    let answer = api.answer(&method, &path);
                    crate::lock_recover(&api.received).push(Received { method, path, body });
                    Ok::<_, std::convert::Infallible>(respond(answer))
                }
            }),
            "ferriscd-system",
        );
        KubeApplicationSetStore::new(client, "ferriscd-system")
    }

    /// The `list_fleet` fixture in the state a deletion pass sees: a deletion timestamp and our
    /// finalizer.
    fn deleting_fleet() -> ApplicationSet {
        let mut appset = list_fleet();
        appset.metadata.deletion_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::now(),
            ));
        appset.metadata.finalizers = Some(vec![APPLICATIONSET_FINALIZER.to_owned()]);
        appset
    }

    /// A scripted API server holding `listed` and answering the orphan patch from `orphans`.
    fn deletion_api(
        appset: &ApplicationSet,
        listed: &[Application],
        live: Option<&Application>,
        orphans: Vec<Answer>,
    ) -> Arc<ScriptedApi> {
        let api = ScriptedApi {
            listed: Mutex::new(
                listed
                    .iter()
                    .map(|application| serde_json::to_value(application).expect("serializable"))
                    .collect(),
            ),
            live: Mutex::new(
                live.map(|application| serde_json::to_value(application).expect("serializable")),
            ),
            orphan_answers: Mutex::new(orphans.into()),
            appset: Mutex::new(serde_json::to_value(appset).expect("serializable")),
            ..ScriptedApi::default()
        };
        Arc::new(api)
    }

    fn deletion_reconciler(api: &Arc<ScriptedApi>) -> ApplicationSetReconciler {
        ApplicationSetReconciler::new(
            "ferriscd-system",
            Arc::new(FakeClusters::default()),
            Arc::new(FakeGit::default()),
            Arc::new(scripted_store(api)),
            Arc::new(FakeAuthorizer::default()),
        )
    }

    /// **Findings C-1/H-1:** a `409` from the orphan patch is what a *routine* `/status` write on the
    /// child produces — the listed `resourceVersion` is one write stale — so it does **not** mean the
    /// `Application` is gone. The object is still there: the patch is recomputed from a live read
    /// (identity from that read) and retried, and only then is the finalizer released.
    #[tokio::test]
    async fn a_stale_resource_version_orphan_conflict_is_retried_from_a_live_read() {
        let appset = deleting_fleet();
        let listed = owned_application("api-dev", &appset);
        let mut live = listed.clone();
        live.metadata.resource_version = Some("rv-after-status-write".to_owned());
        let api = deletion_api(
            &appset,
            std::slice::from_ref(&listed),
            Some(&live),
            vec![Answer::Failed(409), Answer::Stored],
        );

        let report = deletion_reconciler(&api).reconcile(&appset).await;

        assert!(report.is_ready(), "{report:?}");
        assert_eq!(report.orphaned, 1, "the child was in fact orphaned");
        assert_eq!(report.deleted, 0);
        let patches = api.orphan_patches("api-dev");
        assert_eq!(
            patches.len(),
            2,
            "the stale patch is retried: reading the 409 as 'gone' would have stopped after one \
             and un-owned nothing: {patches:?}"
        );
        assert_eq!(
            patches[0]["metadata"]["resourceVersion"],
            serde_json::json!("rv-api-dev"),
            "the first patch carries the identity of the list snapshot"
        );
        assert_eq!(
            patches[1]["metadata"]["resourceVersion"],
            serde_json::json!("rv-after-status-write"),
            "the retry carries the identity of the live read, which is what makes it succeed"
        );
        assert_eq!(
            patches[1]["metadata"]["ownerReferences"],
            serde_json::Value::Null,
            "the retry is a real orphan patch"
        );
        assert_eq!(
            api.finalizer_patches("payments-fleet").len(),
            1,
            "the finalizer is released only after every child really lost its owner reference"
        );
    }

    /// **Finding M1:** the identity guard's two sides can both be present-but-unequal, and the listed
    /// side can also be *absent* — a list snapshot whose `metadata.uid` is `None` while the live
    /// object has one. `None != Some(..)` is **not** evidence of a re-creation: nothing was compared
    /// that could prove one, so the safe branch is the retry. Reading it as "gone" would release the
    /// `ApplicationSet` finalizer with the child's owner reference still in place — the fleet-wipe
    /// outcome — which is why the retry, not the release, is what this asserts.
    #[tokio::test]
    async fn an_orphan_conflict_on_a_listed_application_without_a_uid_is_retried_not_released() {
        let appset = deleting_fleet();
        let mut listed = owned_application("api-dev", &appset);
        listed.metadata.uid = None;
        let live = owned_application("api-dev", &appset);
        assert_eq!(
            live.metadata.uid.as_deref(),
            Some("uid-api-dev"),
            "the live object does carry a server-assigned uid, unlike the snapshot"
        );
        let api = deletion_api(
            &appset,
            std::slice::from_ref(&listed),
            Some(&live),
            vec![Answer::Failed(409), Answer::Stored],
        );

        let report = deletion_reconciler(&api).reconcile(&appset).await;

        assert!(report.is_ready(), "{report:?}");
        assert_eq!(
            report.orphaned, 1,
            "the child really was orphaned, so exactly one orphan write is counted"
        );
        let patches = api.orphan_patches("api-dev");
        assert_eq!(
            patches.len(),
            2,
            "a listed uid of None proves nothing about a re-creation: it must be retried from the \
             live read, not taken as `None != Some(..)` == gone: {patches:?}"
        );
        assert!(
            patches[0]["metadata"].get("uid").is_none(),
            "the first patch carries no uid, because the snapshot had none: {patches:?}"
        );
        assert_eq!(
            patches[1]["metadata"]["uid"],
            serde_json::json!("uid-api-dev"),
            "the retry carries the uid of the live read, which is what makes it land"
        );
        assert_eq!(
            api.finalizer_patches("payments-fleet").len(),
            1,
            "the finalizer is released only after the retry really un-owned the child"
        );
    }

    /// **Findings C-1/H-1:** a conflict that survives the retry is a **retryable failure**, never
    /// "gone". The pass must not count the child as orphaned and must not release the
    /// `ApplicationSet` finalizer while the child still references it — releasing it hands the whole
    /// fleet to Kubernetes garbage collection.
    #[tokio::test]
    async fn a_second_orphan_conflict_is_retryable_and_never_releases_the_finalizer() {
        let appset = deleting_fleet();
        let listed = owned_application("api-dev", &appset);
        let mut live = listed.clone();
        live.metadata.resource_version = Some("rv-2".to_owned());
        let api = deletion_api(
            &appset,
            std::slice::from_ref(&listed),
            Some(&live),
            vec![Answer::Failed(409), Answer::Failed(422)],
        );

        let report = deletion_reconciler(&api).reconcile(&appset).await;

        assert!(!report.is_ready(), "{report:?}");
        let failure = report.failure.clone().expect("the conflict is reported");
        assert!(
            failure.is_retryable(),
            "a conflict on an object that is still present must be retried: {failure:?}"
        );
        assert_eq!(failure.reason(), "ApiError");
        assert_eq!(
            report.orphaned, 0,
            "a rejected patch orphaned nothing, so it must not be counted"
        );
        assert_eq!(api.orphan_patches("api-dev").len(), 2);
        assert!(
            api.finalizer_patches("payments-fleet").is_empty(),
            "the finalizer must never be released while the child still references the \
             ApplicationSet: {:?}",
            api.finalizer_patches("payments-fleet")
        );
        assert_eq!(
            api.status_patches("payments-fleet").len(),
            1,
            "the wedge is still reported on /status, so an operator can see it"
        );
    }

    /// **Findings C-1/H-1:** `422` is the other half of the identity guard — `metadata.uid` is
    /// immutable, so it means the name was deleted and re-created. The listed object **is** gone, the
    /// new one keeps its own owner references, and the `ApplicationSet` may finish deleting.
    #[tokio::test]
    async fn a_uid_mismatch_orphan_conflict_means_the_listed_application_is_gone() {
        let appset = deleting_fleet();
        let listed = owned_application("api-dev", &appset);
        let mut recreated = listed.clone();
        recreated.metadata.uid = Some("uid-somebody-elses-api-dev".to_owned());
        let api = deletion_api(
            &appset,
            std::slice::from_ref(&listed),
            Some(&recreated),
            vec![Answer::Failed(422)],
        );

        let report = deletion_reconciler(&api).reconcile(&appset).await;

        assert!(report.is_ready(), "{report:?}");
        assert_eq!(report.orphaned, 1);
        assert_eq!(
            api.orphan_patches("api-dev").len(),
            1,
            "there is nothing to retry: the listed object is gone"
        );
        assert_eq!(
            api.finalizer_patches("payments-fleet").len(),
            1,
            "with the children provably gone the ApplicationSet must not stay Terminating"
        );
    }

    /// A conflict whose live read answers `404` is the same end state as the `404` the patch itself
    /// can answer: the object is gone.
    #[tokio::test]
    async fn an_orphan_conflict_on_a_vanished_application_is_not_a_failure() {
        let appset = deleting_fleet();
        let listed = owned_application("api-dev", &appset);
        let api = deletion_api(
            &appset,
            std::slice::from_ref(&listed),
            None,
            vec![Answer::Failed(409)],
        );

        let report = deletion_reconciler(&api).reconcile(&appset).await;

        assert!(report.is_ready(), "{report:?}");
        assert_eq!(report.orphaned, 1);
        assert_eq!(api.orphan_patches("api-dev").len(), 1);
        assert_eq!(api.finalizer_patches("payments-fleet").len(), 1);
    }

    /// **Finding N-d:** the deletion pass releases the finalizer and then patches `/status` one last
    /// time, so the object is usually gone and the write answers `404`. That is the end state, not a
    /// failure — the store reports success, so the pass never logs the "failed to patch
    /// ApplicationSet /status" warning it used to log on every successful deletion.
    #[tokio::test]
    async fn a_status_patch_on_a_vanished_applicationset_is_gone_not_a_failure() {
        let appset = deleting_fleet();
        let listed = owned_application("api-dev", &appset);
        let api = deletion_api(
            &appset,
            std::slice::from_ref(&listed),
            Some(&listed),
            vec![Answer::Stored],
        );
        *crate::lock_recover(&api.status_answer) = Some(Reply::Failed(404));

        let report = deletion_reconciler(&api).reconcile(&appset).await;

        assert!(report.is_ready(), "{report:?}");
        assert_eq!(report.orphaned, 1);
        assert_eq!(
            api.status_patches("payments-fleet").len(),
            1,
            "the status write was attempted and refused with 404"
        );
        // The store is the seam the log hangs off: `Ok` means the pass takes no failure branch.
        let store = scripted_store(&api);
        assert!(
            store
                .patch_status(&appset, &ApplicationSetStatus::default())
                .await
                .is_ok(),
            "a 404 on the final status write is the object being gone, not a failure"
        );

        // A real failure is still surfaced: N-d must not swallow the whole status path.
        *crate::lock_recover(&api.status_answer) = Some(Reply::Failed(500));
        assert!(
            store
                .patch_status(&appset, &ApplicationSetStatus::default())
                .await
                .is_err()
        );
    }

    // -----------------------------------------------------------------
    // Read count and interval (findings M-a, N-3)
    // -----------------------------------------------------------------

    /// A `ProjectSource` that counts its reads, so the pass's API traffic is observable.
    #[derive(Default)]
    struct CountingProjects {
        project: Option<ferriscd_crd::AppProject>,
        gets: Mutex<Vec<String>>,
    }

    impl ProjectSource for CountingProjects {
        fn get<'a>(
            &'a self,
            name: &'a str,
        ) -> BoxFuture<'a, Result<Option<ferriscd_crd::AppProject>, crate::reconcile::ReconcileError>>
        {
            Box::pin(async move {
                self.gets.lock().expect("test lock").push(name.to_owned());
                Ok(self.project.clone())
            })
        }
    }

    /// **Finding M-a:** a 200-`Application` plan authorizes every one of them from a single
    /// `AppProject` read. Before the memo, the pass performed 200 identical GETs.
    #[tokio::test]
    async fn a_two_hundred_application_plan_performs_one_project_get() {
        // `matrix` of 2 clusters × 100 list elements reaches the engine's 200-Application ceiling.
        let elements: Vec<String> = (0..100)
            .map(|index| format!("{{id: \"{index}\"}}"))
            .collect();
        let generators: Vec<ferriscd_crd::applicationset::ApplicationSetGenerator> =
            serde_saphyr::from_str(&format!(
                "- matrix:\n    generators:\n      - clusters: {{}}\n      - list:\n          \
                 elements: [{}]\n",
                elements.join(", ")
            ))
            .expect("matrix fixture must parse");
        let mut appset = appset(
            r#"
generators:
  - list:
      elements: []
template:
  metadata:
    name: "api-{{cluster.name}}-{{id}}"
  spec:
    project: default
    source:
      git:
        repoURL: https://github.com/example/payments.git
        path: apps/api
    destination:
      cluster: in-cluster
      namespace: payments
"#,
        );
        appset.spec.generators = generators;
        let clusters = FakeClusters {
            registrations: (0..2)
                .map(|index| ClusterRegistration::new(format!("cluster-{index}"), BTreeMap::new()))
                .collect(),
        };
        let projects = Arc::new(CountingProjects {
            project: Some(project(
                r#"
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: default
  namespace: ferriscd-system
spec:
  sourceRepos:
    - https://github.com/example/payments.git
  sourceNamespaces:
    - ferriscd-system
  destinations:
    - cluster: in-cluster
      namespace: "*"
"#,
            )),
            gets: Mutex::new(Vec::new()),
        });
        let authorizer: Arc<dyn ApplicationAuthorizer> = Arc::new(ProjectPolicyAuthorizer::new(
            projects.clone(),
            ApplicationScope::new(
                "ferriscd-system",
                ferriscd_engine::policy::ApplicationNamespaces::default(),
            ),
            "ferriscd-system",
        ));
        let store = FakeStore::with(Vec::new());
        let report = ApplicationSetReconciler::new(
            "ferriscd-system",
            Arc::new(clusters),
            Arc::new(FakeGit::default()),
            store.clone(),
            authorizer,
        )
        .reconcile(&appset)
        .await;

        assert!(report.is_ready(), "{report:?}");
        assert_eq!(report.generated, 200, "the plan is the full fan-out cap");
        assert_eq!(report.created, 200);
        assert_eq!(
            projects.gets.lock().expect("test lock").as_slice(),
            ["default".to_owned()],
            "one AppProject GET for the whole pass, no matter how many Applications share it"
        );
    }

    /// **Finding N-3:** the loop's fallback interval and the CRD's schema default are the same value,
    /// and the fallback is actually used in production.
    #[test]
    fn the_default_interval_matches_the_crd_default_and_is_the_fallback() {
        assert_eq!(
            DEFAULT_APPLICATIONSET_INTERVAL.as_secs(),
            u64::from(ferriscd_crd::applicationset::DEFAULT_APPLICATIONSET_REQUEUE_AFTER_SECONDS),
            "the loop's fallback and the CRD default must not drift apart"
        );
        let mut appset = list_fleet();
        appset.spec.requeue_after_seconds = 0;
        assert_eq!(
            requeue_interval(&appset),
            DEFAULT_APPLICATIONSET_INTERVAL,
            "a zero interval falls back to the constant instead of spinning"
        );
        appset.spec.requeue_after_seconds = 45;
        assert_eq!(requeue_interval(&appset), Duration::from_secs(45));
        assert_eq!(
            requeue_interval(&list_fleet()),
            Duration::from_secs(180),
            "the schema default is what a stored ApplicationSet carries"
        );
    }
}
