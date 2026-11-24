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
    ApplicationStatus, Condition, ConditionStatus, MAX_STATUS_MESSAGE_CHARS, REASON_SYNC_ERROR,
};
use ferriscd_crd::{Application, annotations};
use futures::FutureExt;
use futures::future::BoxFuture;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use kube::ResourceExt;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{self, Event};
use tracing::Instrument;

use crate::controller::{BackoffTracker, FailureClass, object_key};
use crate::discovery::DiscoveryError;
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOutcome {
    /// `Ready=True` reason (e.g. `SyncSucceeded`).
    pub reason: String,
    /// Human-readable message for the `Ready` condition.
    pub message: String,
    /// Optional requeue override (persisted operation state may need a follow-up pass).
    pub requeue: Option<Duration>,
}

impl ApplyOutcome {
    /// Builds a successful outcome.
    #[must_use]
    pub fn ready(reason: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            message: message.into(),
            requeue: None,
        }
    }

    /// Requests a follow-up reconcile after `delay`.
    #[must_use]
    pub fn with_requeue(mut self, delay: Duration) -> Self {
        self.requeue = Some(delay);
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

    /// The desired state is invalid and retrying cannot help (terminal).
    #[error("{message}")]
    Invalid {
        /// Actionable, secret-free description.
        message: String,
    },
}

impl ReconcileError {
    /// Returns `true` when the error means "the target is already gone".
    ///
    /// `404`/`410` API responses and `NoMatchesForKind` discovery failures all mean there is
    /// nothing left to delete, so cleanup must release the finalizer instead of retrying.
    #[must_use]
    pub fn is_already_deleted(&self) -> bool {
        match self {
            Self::Api(err) => match err {
                kube::Error::Api(status) => status.code == 404 || status.code == 410,
                _ => false,
            },
            Self::Discovery(err) => err.is_no_matches_for_kind(),
            Self::Scope(_) | Self::Invalid { .. } => false,
        }
    }

    /// Classifies the error for the controller's backoff policy.
    #[must_use]
    pub fn failure_class(&self) -> FailureClass {
        match self {
            // `code == 0` is an unpopulated status: assume transient and retry.
            // 408/409/425/429 are transient API conditions (SSA field-ownership and
            // resourceVersion conflicts in particular must back off, not wait 10 minutes).
            Self::Api(kube::Error::Api(status)) => {
                if matches!(status.code, 0 | 408 | 409 | 425 | 429) || status.code >= 500 {
                    FailureClass::Retryable
                } else {
                    FailureClass::Terminal
                }
            }
            // Transport/timeout/decode failures: retry.
            Self::Api(_) => FailureClass::Retryable,
            Self::Discovery(DiscoveryError::NoMatchesForKind { .. }) => FailureClass::Terminal,
            Self::Discovery(DiscoveryError::Refresh { .. }) => FailureClass::Retryable,
            Self::Scope(_) | Self::Invalid { .. } => FailureClass::Terminal,
        }
    }
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
}

/// `/status` patching seam so the always-update-status contract is testable.
pub trait StatusWriter: Send + Sync + 'static {
    /// Patches the `status` subresource of `app`.
    fn patch<'a>(
        &'a self,
        app: &'a Application,
        status: ApplicationStatus,
    ) -> BoxFuture<'a, Result<(), ReconcileError>>;
}

/// [`StatusWriter`] backed by `Api::patch_status`.
pub struct ApiStatusWriter {
    api: Api<Application>,
    params: PatchParams,
}

impl ApiStatusWriter {
    /// Builds a writer over the `Application` API.
    #[must_use]
    pub fn new(api: Api<Application>) -> Self {
        Self {
            api,
            params: PatchParams::default(),
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
            // Merge patch on the `/status` subresource: only the fields we send are
            // updated, so Phase 06+ fields written by another pass are preserved.
            let body = serde_json::json!({ "status": status });
            self.api
                .patch_status(&name, &self.params, &Patch::Merge(&body))
                .await?;
            Ok(())
        })
    }
}

/// Shared controller state handed to every reconcile.
pub struct ReconcileContext {
    apps_api: Api<Application>,
    pipeline: Arc<dyn SyncPipeline>,
    status: Arc<dyn StatusWriter>,
    backoff: BackoffTracker,
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
            pipeline,
            status,
            backoff: BackoffTracker::new(),
        }
    }

    /// The namespaced `Application` API used by the finalizer helper.
    #[must_use]
    pub fn apps_api(&self) -> &Api<Application> {
        &self.apps_api
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
    match err {
        err if err.is_already_deleted() => match err {
            ReconcileError::Discovery(DiscoveryError::NoMatchesForKind { .. }) => {
                REASON_NO_MATCHES_FOR_KIND
            }
            _ => REASON_NOT_FOUND,
        },
        ReconcileError::Api(_) | ReconcileError::Discovery(_) => REASON_SYNC_ERROR,
        ReconcileError::Scope(_) | ReconcileError::Invalid { .. } => REASON_INVALID_SPEC,
    }
}

/// Current wall clock as a Kubernetes timestamp.
#[must_use]
pub fn now() -> Time {
    Time(k8s_openapi::jiff::Timestamp::now())
}

/// Truncates `message` to [`MAX_STATUS_MESSAGE_CHARS`] on a UTF-8 boundary.
///
/// `/status` is capped by `etcd`'s 1.5 MiB object limit, so an unbounded error message
/// (a stack-trace-shaped string) can never be allowed to grow the status.
fn bounded(message: &str) -> String {
    if message.chars().count() <= MAX_STATUS_MESSAGE_CHARS {
        return message.to_owned();
    }
    let mut truncated: String = message.chars().take(MAX_STATUS_MESSAGE_CHARS).collect();
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
    status.set_condition(failure_condition(generation, err, timestamp));
}

/// Runs the apply pipeline under the always-update-status wrapper.
///
/// This is the unit-testable core of the finalizer's `Event::Apply` branch: it performs no
/// API calls of its own beyond the injected [`StatusWriter`].
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
    let generation = app.metadata.generation;
    let mut status = app.status.clone().unwrap_or_default();
    match pipeline.apply(app).await {
        Ok(outcome) => {
            record_success(&mut status, generation, &outcome, now());
            status_writer.patch(app, status).await?;
            Ok(Action::requeue(outcome.requeue.unwrap_or(DEFAULT_REQUEUE)))
        }
        Err(err) => {
            record_failure(&mut status, generation, &err, now());
            // Best effort: the reconcile error is the one the caller must see.
            if let Err(patch_err) = status_writer.patch(app, status).await {
                tracing::warn!(
                    app.namespace = %app.namespace().unwrap_or_default(),
                    app.name = %app.name_any(),
                    error = %patch_err,
                    "failed to patch status after a reconcile error"
                );
            }
            Err(err)
        }
    }
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
    let key = object_key(&app);
    let api = ctx.apps_api.clone();
    let inner_ctx = ctx.clone();

    let result = finalizer::finalizer(&api, FINALIZER, app.clone(), move |event| {
        let ctx = inner_ctx.clone();
        async move {
            match event {
                Event::Apply(object) => apply_once(&object, ctx.pipeline(), ctx.status()).await,
                Event::Cleanup(object) => cleanup_once(&object, ctx.pipeline(), ctx.status()).await,
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
    use ferriscd_crd::status::CONDITION_READY;
    use ferriscd_crd::{
        ApplicationSpec, DEFAULT_PROJECT_NAME, DestinationSpec, GitSourceSpec, RendererSpec,
        SourceSpec,
    };
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
                git: GitSourceSpec {
                    repo_url: "https://example.com/repo.git".to_owned(),
                    target_revision: "HEAD".to_owned(),
                    path: String::new(),
                },
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
        ];
        for (err, expected) in cases {
            assert_eq!(err.failure_class(), expected, "unexpected class for {err}");
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
}
