//! `kube_runtime::Controller` wiring: namespace scope, bounded concurrency, the composite
//! watch predicate, and the retry/backoff error policy.
//!
//! Notes on the shape of this module:
//!
//! * The controller watches **only** the control-plane namespace (`ferriscd-system` by default).
//!   Cluster-wide `Application` watches would turn every agent into a
//!   cluster-scoped informer and would break multi-tenant isolation.
//! * That default is widened only explicitly (`T12.2`, ADR-007): `--application-namespaces`
//!   accepts a comma-separated list or `*`, and every tenant `Application` it exposes must carry
//!   its own `serviceAccountName` and be authorized by `AppProject.spec.sourceNamespaces`
//!   ([`ferriscd_engine::policy::AppProjectPolicy`]). The control-plane namespace is never dropped.
//! * The watch stream is filtered *before* the controller sees it
//!   ([`crate::predicate`]), which is what makes a `/status`-only write cost zero
//!   reconciles. `Controller::for_stream` is the only kube 5.1 API that accepts a
//!   pre-filtered stream, hence the `unstable-runtime` feature on `kube`.
//! * **One `Controller` per watched namespace** (finding C1). Kube has no "watch these N
//!   namespaces" API, but a `reflector::Store` has exactly one writer and a watcher emits
//!   `Init`/`InitApply`/`InitDone` on every (re)connect — `InitDone` *replaces* the store's
//!   whole content. Merging N namespaced watchers into one store therefore lets the last
//!   `InitDone` truncate every other namespace, and the controller then discards the resulting
//!   reconciles as `ObjectNotFound`. Each scope now owns a private store, reader and watch
//!   backoff, so that failure mode cannot be constructed ([`ApplicationControllers`]).
//! * Retries are classified by [`FailureClass`]: transient failures back off
//!   exponentially (5 s → 180 s), terminal failures wait a long fixed interval so a broken
//!   `Application` cannot spin the work queue.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferriscd_crd::Application;
use ferriscd_engine::policy::{
    ALL_NAMESPACES, ApplicationNamespaces, ApplicationScope, ApplicationScopeError,
};
use futures::stream::BoxStream;
use futures::{Stream, StreamExt};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::reflector::{self, Store};
use kube::runtime::{PredicateConfig, WatchStreamExt, watcher};
use kube::{Api, Client, ResourceExt};

use crate::reconcile::{ControllerError, ReconcileContext, reconcile_instance};
use crate::{ShutdownReason, lock_recover, predicate};

/// Default number of concurrent reconciles **per watched namespace scope**.
///
/// With N watched scopes the process can run up to `N × DEFAULT_CONCURRENCY` reconciles.
pub const DEFAULT_CONCURRENCY: u16 = 8;

/// Base delay for the retryable exponential backoff.
pub const RETRY_BASE_DELAY: Duration = Duration::from_secs(5);

/// Cap for the retryable exponential backoff (matches `spec.syncPolicy.retry.maxDuration`).
pub const RETRY_MAX_DELAY: Duration = Duration::from_secs(180);

/// Fixed delay used for terminal failures (invalid spec, unknown kind, ...).
pub const TERMINAL_DELAY: Duration = Duration::from_secs(600);

/// Default window allowed for in-flight reconciles to finish after a shutdown signal.
pub const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Environment variable overriding the watched namespace.
pub const NAMESPACE_ENV: &str = "FERRISCD_NAMESPACE";

/// Environment variable overriding `--application-namespaces` (`T12.2`).
///
/// Accepts a comma-separated namespace list or `*`; unset means "the control-plane namespace
/// only", which is the safe default.
pub const APPLICATION_NAMESPACES_ENV: &str = "FERRISCD_APPLICATION_NAMESPACES";

/// How a reconcile failure should be retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// Transient: retry with exponential backoff.
    Retryable,
    /// Deterministic: retry rarely, the operator must fix the spec.
    Terminal,
}

impl FailureClass {
    /// Stable label for logs.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Retryable => "retryable",
            Self::Terminal => "terminal",
        }
    }
}

/// Controller configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerConfig {
    /// Namespace whose `Application` objects this controller owns.
    ///
    /// This is also the control-plane namespace: `AppProject` objects are read from here and a
    /// tenant `Application` must carry its own `serviceAccountName` (ADR-007).
    pub namespace: String,
    /// Which namespaces may host `Application` objects (`T12.2`); the safe default is the
    /// control-plane namespace only.
    pub application_namespaces: ApplicationNamespaces,
    /// Maximum number of concurrent reconciles.
    pub concurrency: u16,
    /// How long in-flight reconciles may run after a shutdown signal.
    pub drain_timeout: Duration,
}

impl Default for ControllerConfig {
    fn default() -> Self {
        Self {
            namespace: ferriscd_crd::CONTROL_PLANE_NAMESPACE.to_owned(),
            application_namespaces: ApplicationNamespaces::ControlPlane,
            concurrency: DEFAULT_CONCURRENCY,
            drain_timeout: DEFAULT_DRAIN_TIMEOUT,
        }
    }
}

impl ControllerConfig {
    /// Overrides the watched namespace (builder style).
    #[must_use]
    pub fn namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = namespace.into();
        self
    }

    /// Widens the watched namespaces (`T12.2`, builder style).
    ///
    /// The control-plane namespace stays watched regardless; a tenant namespace only becomes
    /// reconcilable together with a project-authorized `serviceAccountName`.
    #[must_use]
    pub fn application_namespaces(mut self, namespaces: ApplicationNamespaces) -> Self {
        self.application_namespaces = namespaces;
        self
    }

    /// Overrides the reconcile concurrency (builder style).
    #[must_use]
    pub fn concurrency(mut self, concurrency: u16) -> Self {
        self.concurrency = concurrency;
        self
    }

    /// Overrides the drain window (builder style).
    #[must_use]
    pub fn drain_timeout(mut self, drain_timeout: Duration) -> Self {
        self.drain_timeout = drain_timeout;
        self
    }

    /// The resolved [`ApplicationScope`] the watcher and the policy enforcer share.
    #[must_use]
    pub fn application_scope(&self) -> ApplicationScope {
        ApplicationScope::new(self.namespace.clone(), self.application_namespaces.clone())
    }

    /// The namespaces to watch, or `None` for every namespace (`--application-namespaces '*'`).
    ///
    /// The control-plane namespace is always included.
    #[must_use]
    pub fn watched_namespaces(&self) -> Option<Vec<String>> {
        self.application_scope().watch_namespaces()
    }

    /// Resolves the watched namespace from [`NAMESPACE_ENV`], defaulting to
    /// `ferriscd-system`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::EmptyNamespace`] when the variable is set to a blank value: an
    /// empty namespace silently watches nothing, so it must fail loudly instead.
    pub fn namespace_from_env() -> Result<String, ConfigError> {
        namespace_from_env_value(std::env::var(NAMESPACE_ENV).ok().as_deref())
    }

    /// Resolves the application-namespace scope from [`APPLICATION_NAMESPACES_ENV`].
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidApplicationNamespaces`] for a malformed value: a typo must
    /// never silently watch the wrong namespaces.
    pub fn application_namespaces_from_env() -> Result<ApplicationNamespaces, ConfigError> {
        let value = std::env::var(APPLICATION_NAMESPACES_ENV).ok();
        Ok(ApplicationNamespaces::parse(value.as_deref())?)
    }
}

/// Configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The configured namespace is blank.
    #[error("{NAMESPACE_ENV} must not be empty")]
    EmptyNamespace,

    /// The configured application-namespace scope is malformed.
    #[error(transparent)]
    InvalidApplicationNamespaces(#[from] ApplicationScopeError),
}

/// Parses a [`NAMESPACE_ENV`] value.
///
/// # Errors
///
/// Returns [`ConfigError::EmptyNamespace`] for a blank value.
pub fn namespace_from_env_value(value: Option<&str>) -> Result<String, ConfigError> {
    match value {
        None => Ok(ferriscd_crd::CONTROL_PLANE_NAMESPACE.to_owned()),
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Err(ConfigError::EmptyNamespace)
            } else {
                Ok(trimmed.to_owned())
            }
        }
    }
}

/// Delay before retrying a failure of `class` that already failed `attempt` times.
///
/// Retryable failures double from [`RETRY_BASE_DELAY`] and saturate at
/// [`RETRY_MAX_DELAY`]; terminal failures always wait [`TERMINAL_DELAY`], which is longer
/// than the retryable cap so an unfixable `Application` stops churning the queue.
#[must_use]
pub fn backoff_delay(class: FailureClass, attempt: u32) -> Duration {
    match class {
        FailureClass::Terminal => TERMINAL_DELAY,
        FailureClass::Retryable => {
            // `1 << attempt` saturates at 2^16 attempts; durations are capped anyway.
            let factor = 1_u32.checked_shl(attempt.min(16)).unwrap_or(u32::MAX);
            RETRY_BASE_DELAY.saturating_mul(factor).min(RETRY_MAX_DELAY)
        }
    }
}

/// Per-object failure counter backing the exponential backoff.
///
/// `kube`'s `error_policy` receives no attempt count, so the controller keeps its own
/// counter and resets it on the next successful reconcile.
#[derive(Debug, Default)]
pub struct BackoffTracker {
    attempts: Mutex<HashMap<String, u32>>,
}

impl BackoffTracker {
    /// Builds an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a failure for `key` and returns the delay before the next attempt.
    pub fn record_failure(&self, key: &str, class: FailureClass) -> Duration {
        let mut attempts = lock_recover(&self.attempts);
        let attempt = attempts.entry(key.to_owned()).or_insert(0);
        let delay = backoff_delay(class, *attempt);
        *attempt = attempt.saturating_add(1);
        delay
    }

    /// Clears the failure counter for `key` after a successful reconcile.
    pub fn reset(&self, key: &str) {
        lock_recover(&self.attempts).remove(key);
    }

    /// Number of consecutive failures recorded for `key`.
    #[must_use]
    pub fn attempts(&self, key: &str) -> u32 {
        lock_recover(&self.attempts)
            .get(key)
            .copied()
            .unwrap_or_default()
    }
}

/// Stable per-object key (`<namespace>/<name>`) used for backoff bookkeeping.
#[must_use]
pub fn object_key(app: &Application) -> String {
    format!("{}/{}", app.namespace().unwrap_or_default(), app.name_any())
}

/// `error_policy` passed to [`Controller::run`].
pub fn error_policy(
    app: Arc<Application>,
    err: &ControllerError,
    ctx: Arc<ReconcileContext>,
) -> Action {
    let failure = err.failure();
    let delay = ctx.backoff().record_failure(&object_key(&app), failure);
    tracing::warn!(
        app.namespace = %app.namespace().unwrap_or_default(),
        app.name = %app.name_any(),
        failure = failure.as_str(),
        retry_after_seconds = delay.as_secs(),
        error = %err,
        "reconcile failed; requeueing"
    );
    Action::requeue(delay)
}

/// One `Controller` for one watched scope, with its **own** store, reader and watch backoff.
///
/// Finding C1: a `reflector::Store` accepts exactly one writer, and `InitDone` *swaps* that
/// writer's buffer into the store — i.e. it replaces the object set. Merging N namespaced
/// watchers into one store makes the last `InitDone` truncate the other namespaces, after which
/// the controller drops every reconcile for the vanished objects with `ObjectNotFound`. One
/// controller per scope makes that shape unrepresentable: each scope owns a private store.
pub struct NamespacedController {
    /// The namespace this controller watches, or `None` for the cluster-wide `*` scope.
    namespace: Option<String>,
    controller: Controller<Application>,
}

impl NamespacedController {
    /// The namespace this controller watches, or `None` for the cluster-wide `*` scope.
    #[must_use]
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// Stable label for logs and tests: the namespace, or `*` for the cluster-wide scope.
    #[must_use]
    pub fn label(&self) -> &str {
        self.namespace.as_deref().unwrap_or(ALL_NAMESPACES)
    }

    /// The store this controller reads. It is private to this scope: no other `Controller` in the
    /// set shares (or writes) it.
    #[must_use]
    pub fn store(&self) -> Store<Application> {
        self.controller.store()
    }
}

impl std::fmt::Debug for NamespacedController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NamespacedController")
            .field("namespace", &self.label())
            .field("objects", &self.store().len())
            .finish_non_exhaustive()
    }
}

/// Why a scope's store never became ready.
#[derive(Debug, thiserror::Error)]
pub enum ReadinessError {
    /// The watch stream ended (shutdown, or a fatal watch error) before the first successful
    /// list completed, so the scope never reflected any object.
    #[error("the {scope:?} Application watch ended before its first successful list")]
    StoreNotReady {
        /// The namespace whose store never became ready (or `*`).
        scope: String,
        /// The underlying `kube` error.
        #[source]
        source: reflector::store::WriterDropped,
    },
}

/// The reconciled scopes of one controller process: **one `Controller` and one store per
/// watched namespace** (finding C1).
///
/// Every scope shares the [`ReconcileContext`] (pipeline, status writer, per-object backoff) but
/// nothing else: reconciling a tenant `Application` must behave identically wherever it lives,
/// while the watchers must not be able to corrupt each other's view of the cluster.
pub struct ApplicationControllers {
    controllers: Vec<NamespacedController>,
}

impl std::fmt::Debug for ApplicationControllers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApplicationControllers")
            .field("scopes", &self.labels())
            .field("objects", &self.store_lengths())
            .finish()
    }
}

impl ApplicationControllers {
    /// How many scopes (i.e. controllers, stores and watchers) this set holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.controllers.len()
    }

    /// Whether nothing is watched. Never true for a valid [`ControllerConfig`]: the resolve path
    /// always yields at least one scope.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.controllers.is_empty()
    }

    /// The watched scopes in configuration order (`*` for the cluster-wide scope).
    #[must_use]
    pub fn labels(&self) -> Vec<&str> {
        self.controllers
            .iter()
            .map(NamespacedController::label)
            .collect()
    }

    /// The namespaces this set watches, `None` entries standing for `*`.
    #[must_use]
    pub fn namespaces(&self) -> Vec<Option<&str>> {
        self.controllers
            .iter()
            .map(NamespacedController::namespace)
            .collect()
    }

    /// How many objects each scope's own store currently reflects, in [`Self::labels`] order.
    #[must_use]
    pub fn store_lengths(&self) -> Vec<usize> {
        self.controllers
            .iter()
            .map(|controller| controller.store().len())
            .collect()
    }

    /// Waits until **every** scope's store has completed its first list.
    ///
    /// Returns the number of objects each scope reflected, in [`Self::labels`] order. Readiness is
    /// all-or-nothing on purpose (finding C1): declaring the controller ready after *one* namespace
    /// listed would hide a namespace whose watch is broken. The future is `'static` and borrows
    /// nothing, so it can be awaited concurrently with the very controller streams that populate
    /// the stores — a store only becomes ready *because* its stream is being polled.
    pub fn wait_until_ready(
        &self,
    ) -> impl Future<Output = Result<Vec<usize>, ReadinessError>> + 'static {
        let stores: Vec<(String, Store<Application>)> = self
            .controllers
            .iter()
            .map(|controller| (controller.label().to_owned(), controller.store()))
            .collect();
        async move {
            let mut objects = Vec::with_capacity(stores.len());
            for (scope, store) in stores {
                store
                    .wait_until_ready()
                    .await
                    .map_err(|source| ReadinessError::StoreNotReady { scope, source })?;
                objects.push(store.len());
            }
            Ok(objects)
        }
    }

    /// Turns every controller into its `run` stream, all of which are driven by [`run`].
    fn into_run_streams(
        self,
        ctx: Arc<ReconcileContext>,
        announced: Arc<AtomicBool>,
    ) -> Vec<BoxStream<'static, ControllerRunItem>> {
        self.controllers
            .into_iter()
            .map(|scope| {
                let announced = announced.clone();
                // One signal future per controller rather than a shared `Notify`: every scope must
                // observe the same shutdown, and `notify_one` would wake exactly one of them.
                let trigger = async move {
                    shutdown_reason_once(&announced).await;
                };
                scope
                    .controller
                    .graceful_shutdown_on(trigger)
                    .run(reconcile_instance, error_policy, ctx.clone())
                    .boxed()
            })
            .collect()
    }
}

/// One item of a `Controller::run` stream.
type ControllerRunItem = Result<
    (reflector::ObjectRef<Application>, Action),
    kube::runtime::controller::Error<ControllerError, watcher::Error>,
>;

/// The `Application` API for one scope: namespaced, or cluster-wide for `*`.
fn scope_api(client: &Client, namespace: Option<&str>) -> Api<Application> {
    match namespace {
        Some(namespace) => Api::namespaced(client.clone(), namespace),
        None => Api::all(client.clone()),
    }
}

/// Wires one watcher into a **private** store and returns the pre-filtered applied-object stream
/// together with that store's reader.
///
/// This is the single construction site for a scope's store (finding C1): the reflector, its
/// `default_backoff` and the composite predicate are created here and nowhere else, so "one
/// writer per store" holds by construction. Tests substitute a scripted event stream to prove
/// that an `Init`/`InitDone` in one scope cannot remove another scope's objects.
fn scoped_store<E>(
    events: E,
) -> (
    impl Stream<Item = Result<Application, watcher::Error>>,
    Store<Application>,
)
where
    E: Stream<Item = Result<watcher::Event<Application>, watcher::Error>> + Send + 'static,
{
    let (reader, writer) = reflector::store();
    let stream = events
        // Per-scope reconnect backoff: a namespace whose watch keeps failing backs off on its own
        // schedule instead of starving every other namespace (finding C1).
        .default_backoff()
        .reflect(writer)
        .applied_objects()
        // Filter *before* the controller schedules work: a status-only patch then costs
        // zero reconciles instead of one wasted pass per status write.
        .predicate_filter(predicate::predicate(), PredicateConfig::default());
    (stream, reader)
}

/// Builds **one `Controller` per watched namespace** for the configured scope (finding C1).
///
/// The returned controllers are not yet running: [`run`] drives their `run` streams and waits for
/// every store to be ready before declaring readiness.
#[must_use]
pub fn build_controllers(client: Client, config: &ControllerConfig) -> ApplicationControllers {
    let scopes: Vec<Option<String>> = match config.watched_namespaces() {
        Some(namespaces) => namespaces.into_iter().map(Some).collect(),
        // `*`: one cluster-wide controller. The per-`Application` `AppProject` guard (`T12.2`) is
        // what makes this safe: scope alone never authorizes a tenant `Application`.
        None => vec![None],
    };
    let controllers = scopes
        .into_iter()
        .map(|namespace| {
            let api = scope_api(&client, namespace.as_deref());
            let (stream, store) = scoped_store(watcher(api, watcher::Config::default()));
            let controller = Controller::for_stream(stream, store).with_config(
                kube::runtime::controller::Config::default().concurrency(config.concurrency),
            );
            NamespacedController {
                namespace,
                controller,
            }
        })
        .collect();
    ApplicationControllers { controllers }
}

/// Awaits the process shutdown signal, logging it exactly once across every scope.
async fn shutdown_reason_once(announced: &AtomicBool) -> ShutdownReason {
    let reason = crate::shutdown_signal().await;
    if !announced.swap(true, Ordering::SeqCst) {
        tracing::info!(
            signal = reason.as_str(),
            "graceful shutdown requested; draining in-flight reconciles"
        );
    }
    reason
}

/// Runs every per-namespace controller until `SIGINT`/`SIGTERM`, draining in-flight reconciles.
///
/// # Errors
///
/// Returns [`crate::ShutdownError::DrainTimeout`] when a reconcile is still running after
/// `config.drain_timeout`: the process must not report a clean exit when a status patch or
/// an apply was abandoned mid-flight.
pub async fn run(
    client: Client,
    config: ControllerConfig,
    ctx: Arc<ReconcileContext>,
) -> Result<(), crate::ShutdownError> {
    let drain_timeout = config.drain_timeout;
    let controllers = build_controllers(client, &config);
    let scopes: Vec<String> = controllers
        .labels()
        .iter()
        .map(|l| (*l).to_owned())
        .collect();
    let readiness = controllers.wait_until_ready();
    let announced = Arc::new(AtomicBool::new(false));
    let shutdown_announced = announced.clone();

    tracing::info!(
        namespace = %config.namespace,
        controllers = controllers.len(),
        scopes = ?scopes,
        concurrency = config.concurrency,
        finalizer = crate::reconcile::FINALIZER,
        "application controller started (one controller and private store per watched namespace)"
    );

    // One merged result stream over N independent controllers. Each controller keeps its own
    // store, watch backoff and schedule; only the reporting is merged.
    let mut results =
        futures::stream::select_all(controllers.into_run_streams(ctx, announced.clone()));

    let drive = async move {
        while let Some(result) = results.next().await {
            match result {
                Ok((object, _action)) => {
                    tracing::debug!(
                        namespace = object.namespace.as_deref().unwrap_or_default(),
                        object = %object.name,
                        "reconcile scheduled"
                    );
                }
                Err(err) => {
                    // Stream errors do not terminate the controller; surface and continue.
                    tracing::warn!(error = %err, "controller stream error");
                }
            }
        }
    };

    // Readiness covers *all* controllers: the log line appears only once every namespace has
    // completed its first list, and a watch that dies before that is reported instead of hidden.
    let readiness = async move {
        match readiness.await {
            Ok(objects) => tracing::info!(
                scopes = ?scopes,
                objects = ?objects,
                "every Application watch is ready"
            ),
            Err(err) => tracing::warn!(
                error = %err,
                "an Application watch ended before it became ready"
            ),
        }
    };

    // Readiness and the reconcile pump run together: the stores only become ready because the
    // streams are polled. The pump is what ends the work, exactly as before (a graceful shutdown
    // stops every controller, so every stream ends).
    let work = async move {
        let ((), ()) = tokio::join!(drive, readiness);
    };
    let shutdown = async move {
        // One log line for the whole process, whichever of the N+1 signal listeners sees it first.
        let _reason = shutdown_reason_once(&shutdown_announced).await;
    };
    crate::await_drained(work, shutdown, drain_timeout).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_watch_the_control_plane_namespace_with_bounded_concurrency() {
        let config = ControllerConfig::default();
        assert_eq!(config.namespace, "ferriscd-system");
        assert_eq!(config.concurrency, DEFAULT_CONCURRENCY);
        assert!(
            config.concurrency > 0,
            "unbounded concurrency is not allowed"
        );
        assert_eq!(config.drain_timeout, DEFAULT_DRAIN_TIMEOUT);

        let custom = config
            .clone()
            .namespace("apps-prod")
            .concurrency(2)
            .drain_timeout(Duration::from_secs(5));
        assert_eq!(custom.namespace, "apps-prod");
        assert_eq!(custom.concurrency, 2);
        assert_eq!(custom.drain_timeout, Duration::from_secs(5));
        // The original is untouched by the builder.
        assert_eq!(config.namespace, "ferriscd-system");
    }

    #[test]
    fn namespace_env_parsing_trims_and_rejects_blank_values() {
        assert_eq!(
            namespace_from_env_value(None).expect("default"),
            "ferriscd-system"
        );
        assert_eq!(
            namespace_from_env_value(Some(" apps ")).expect("custom"),
            "apps"
        );
        assert!(matches!(
            namespace_from_env_value(Some("   ")),
            Err(ConfigError::EmptyNamespace)
        ));
        assert!(matches!(
            namespace_from_env_value(Some("")),
            Err(ConfigError::EmptyNamespace)
        ));
    }

    #[test]
    fn retryable_backoff_grows_exponentially_and_saturates() {
        assert_eq!(backoff_delay(FailureClass::Retryable, 0), RETRY_BASE_DELAY);
        assert_eq!(
            backoff_delay(FailureClass::Retryable, 1),
            Duration::from_secs(10)
        );
        assert_eq!(
            backoff_delay(FailureClass::Retryable, 2),
            Duration::from_secs(20)
        );
        assert_eq!(
            backoff_delay(FailureClass::Retryable, 5),
            Duration::from_secs(160)
        );
        assert_eq!(
            backoff_delay(FailureClass::Retryable, 6),
            RETRY_MAX_DELAY,
            "the exponential backoff must saturate"
        );
        assert_eq!(
            backoff_delay(FailureClass::Retryable, 10_000),
            RETRY_MAX_DELAY
        );
    }

    #[test]
    fn terminal_backoff_is_fixed_and_longer_than_any_retryable_delay() {
        for attempt in [0, 1, 5, 100] {
            assert_eq!(
                backoff_delay(FailureClass::Terminal, attempt),
                TERMINAL_DELAY
            );
        }
        assert!(
            TERMINAL_DELAY > RETRY_MAX_DELAY,
            "a terminal failure must back off longer than any transient one"
        );
    }

    #[test]
    fn tracker_counts_failures_per_object_and_resets_on_success() {
        let tracker = BackoffTracker::new();
        assert_eq!(tracker.attempts("ferriscd-system/demo"), 0);

        assert_eq!(
            tracker.record_failure("ferriscd-system/demo", FailureClass::Retryable),
            RETRY_BASE_DELAY
        );
        assert_eq!(
            tracker.record_failure("ferriscd-system/demo", FailureClass::Retryable),
            Duration::from_secs(10)
        );
        assert_eq!(
            tracker.record_failure("ferriscd-system/other", FailureClass::Retryable),
            RETRY_BASE_DELAY,
            "objects must be tracked independently"
        );
        assert_eq!(tracker.attempts("ferriscd-system/demo"), 2);

        tracker.reset("ferriscd-system/demo");
        assert_eq!(tracker.attempts("ferriscd-system/demo"), 0);
        assert_eq!(
            tracker.record_failure("ferriscd-system/demo", FailureClass::Retryable),
            RETRY_BASE_DELAY,
            "a successful reconcile must reset the backoff"
        );
        assert_eq!(tracker.attempts("ferriscd-system/other"), 1);
    }

    #[test]
    fn failure_class_labels_are_stable() {
        assert_eq!(FailureClass::Retryable.as_str(), "retryable");
        assert_eq!(FailureClass::Terminal.as_str(), "terminal");
    }

    #[test]
    fn the_default_scope_watches_the_control_plane_namespace_only() {
        let config = ControllerConfig::default();
        assert_eq!(
            config.application_namespaces,
            ApplicationNamespaces::ControlPlane,
            "Apps-in-any-namespace must stay opt-in"
        );
        assert_eq!(
            config.watched_namespaces(),
            Some(vec!["ferriscd-system".to_owned()])
        );
        assert_eq!(
            config.application_scope().control_plane(),
            "ferriscd-system"
        );
    }

    #[test]
    fn the_watched_namespaces_follow_the_control_plane_namespace() {
        // `--namespace apps` moves the control plane, and the default scope follows it: a
        // controller restarted with a different `--namespace` must not silently keep watching
        // `ferriscd-system`.
        let config = ControllerConfig::default().namespace("apps");
        assert_eq!(config.watched_namespaces(), Some(vec!["apps".to_owned()]));
        assert!(!config.application_scope().allows("ferriscd-system"));
        assert!(config.application_scope().allows("apps"));
    }

    #[test]
    fn explicit_tenant_namespaces_are_watched_alongside_the_control_plane() {
        let config = ControllerConfig::default().application_namespaces(
            ApplicationNamespaces::parse(Some("team-a,team-b")).expect("valid list"),
        );
        assert_eq!(
            config.watched_namespaces(),
            Some(vec![
                "ferriscd-system".to_owned(),
                "team-a".to_owned(),
                "team-b".to_owned()
            ])
        );
        // The scope the pipeline enforces is exactly the scope the watcher covers.
        let scope = config.application_scope();
        assert!(scope.allows("ferriscd-system"));
        assert!(scope.allows("team-a"));
        assert!(!scope.allows("team-c"));
        assert!(scope.is_tenant("team-a"));
        assert!(!scope.is_tenant("ferriscd-system"));
    }

    #[test]
    fn the_wildcard_scope_watches_every_namespace() {
        let config = ControllerConfig::default().application_namespaces(ApplicationNamespaces::All);
        assert_eq!(
            config.watched_namespaces(),
            None,
            "`*` is a cluster-wide watch"
        );
        assert!(config.application_scope().allows("any-namespace"));
    }

    #[test]
    fn a_malformed_application_namespaces_value_is_a_config_error() {
        let err = ApplicationNamespaces::parse(Some("team-a,,team-b"))
            .expect_err("an empty entry must be rejected");
        let wrapped = ConfigError::from(err);
        assert!(
            matches!(wrapped, ConfigError::InvalidApplicationNamespaces(_)),
            "{wrapped:?}"
        );
        assert!(
            wrapped.to_string().contains("applicationNamespaces"),
            "{wrapped}"
        );
    }

    // ---------------------------------------------------------------------
    // Finding C1: one controller (and one private store) per namespace
    // ---------------------------------------------------------------------

    /// A `kube::Client` over a service that never dials out: enough to build the watchers, whose
    /// requests are only issued when a stream is polled.
    fn offline_client() -> Client {
        Client::new(
            tower::service_fn(|_request| async {
                Ok::<_, std::convert::Infallible>(http::Response::new(kube::client::Body::empty()))
            }),
            "ferriscd-system",
        )
    }

    fn scripted_application(namespace: &str, name: &str, generation: i64) -> Application {
        let spec = ferriscd_crd::ApplicationSpec {
            project: ferriscd_crd::DEFAULT_PROJECT_NAME.to_owned(),
            service_account_name: None,
            source: ferriscd_crd::SourceSpec {
                git: ferriscd_crd::GitSourceSpec {
                    repo_url: "https://example.com/repo.git".to_owned(),
                    target_revision: "main".to_owned(),
                    path: String::new(),
                },
                renderer: ferriscd_crd::RendererSpec::default(),
            },
            destination: ferriscd_crd::DestinationSpec {
                cluster: "in-cluster".to_owned(),
                namespace: namespace.to_owned(),
            },
            sync_policy: None,
            ignore_differences: Vec::new(),
            requeue_after_seconds: ferriscd_crd::application::DEFAULT_REQUEUE_AFTER_SECONDS,
            revision_history_limit: ferriscd_crd::application::DEFAULT_REVISION_HISTORY_LIMIT,
        };
        let mut app = Application::new(name, spec);
        app.metadata.namespace = Some(namespace.to_owned());
        app.metadata.generation = Some(generation);
        app
    }

    /// **Finding C1 (structural):** the construction produces one controller — and therefore one
    /// store, reader and watch backoff — per watched namespace, never a shared writer.
    #[tokio::test]
    async fn one_controller_and_one_store_per_watched_namespace() {
        let config = ControllerConfig::default().application_namespaces(
            ApplicationNamespaces::parse(Some("team-a,team-b")).expect("valid namespace list"),
        );
        let controllers = build_controllers(offline_client(), &config);

        assert_eq!(
            controllers.len(),
            3,
            "one controller per scope (control plane + two tenants)"
        );
        assert_eq!(
            controllers.labels(),
            vec!["ferriscd-system", "team-a", "team-b"],
            "the control-plane namespace is never dropped"
        );
        assert_eq!(
            controllers.namespaces(),
            vec![Some("ferriscd-system"), Some("team-a"), Some("team-b")]
        );
        assert_eq!(
            controllers.store_lengths(),
            vec![0, 0, 0],
            "every scope reports its own store, and nothing is listed yet"
        );
        assert!(!controllers.is_empty());

        // `*` stays a single cluster-wide controller: there is no list of namespaces to split.
        let all = build_controllers(
            offline_client(),
            &ControllerConfig::default().application_namespaces(ApplicationNamespaces::All),
        );
        assert_eq!(all.len(), 1);
        assert_eq!(all.namespaces(), vec![None]);
        assert_eq!(all.labels(), vec![ALL_NAMESPACES]);
    }

    /// The `run`-stream item of a test controller (whose reconciler fails with `io::Error`).
    type TestRunItem = Result<
        (reflector::ObjectRef<Application>, Action),
        kube::runtime::controller::Error<std::io::Error, watcher::Error>,
    >;

    type ScriptedSender = futures::channel::mpsc::UnboundedSender<
        Result<watcher::Event<Application>, watcher::Error>,
    >;

    fn send(sender: &mut ScriptedSender, event: watcher::Event<Application>) {
        assert!(
            sender.unbounded_send(Ok(event)).is_ok(),
            "a scripted scope must accept every event"
        );
    }

    /// Drives one scope through a complete list — `Init`, `InitApply`, `InitDone` — followed by a
    /// sentinel `Apply`, and polls until both were yielded.
    ///
    /// Polling the sentinel is what proves the `InitDone` **swap** was processed: `reflector`
    /// buffers `InitApply` objects and only replaces the store's content on `InitDone`.
    async fn list_scope(
        sender: &mut ScriptedSender,
        stream: &mut (impl Stream<Item = Result<Application, watcher::Error>> + Unpin),
        namespace: &str,
        generation: i64,
    ) {
        send(sender, watcher::Event::Init);
        send(
            sender,
            watcher::Event::InitApply(scripted_application(namespace, "demo", generation)),
        );
        send(sender, watcher::Event::InitDone);
        let listed = stream
            .next()
            .await
            .expect("the listed object must be yielded")
            .expect("a scripted event must not fail");
        assert_eq!(object_key(&listed), format!("{namespace}/demo"));
        send(
            sender,
            watcher::Event::Apply(scripted_application(namespace, "demo", generation + 1)),
        );
        assert!(
            stream.next().await.is_some(),
            "the sentinel change after InitDone must be yielded"
        );
    }

    /// **Finding C1 (behavioural):** an `Init`/`InitDone` in one scope cannot remove another
    /// scope's objects, because the two scopes do not share a store.
    ///
    /// The bug this pins: with a single merged store, scope A's `InitDone` *swaps* its buffer into
    /// the store, so `store_b` (the same store) loses `team-b/demo` and the controller then drops
    /// that object's reconciles as `ObjectNotFound`.
    #[tokio::test]
    async fn an_init_of_one_scope_cannot_remove_another_scopes_objects() {
        // Exactly the production seam: `scoped_store` is the one place a scope's store is created.
        let (mut tx_a, rx_a) = futures::channel::mpsc::unbounded();
        let (mut tx_b, rx_b) = futures::channel::mpsc::unbounded();
        let (stream_a, store_a) = scoped_store(rx_a);
        let (stream_b, store_b) = scoped_store(rx_b);
        let mut stream_a = Box::pin(stream_a);
        let mut stream_b = Box::pin(stream_b);

        list_scope(&mut tx_a, &mut stream_a, "team-a", 1).await;
        assert_eq!(store_a.len(), 1, "scope A reflects its own Application");

        list_scope(&mut tx_b, &mut stream_b, "team-b", 1).await;
        assert_eq!(store_b.len(), 1, "scope B reflects its own Application");
        assert_eq!(
            store_a.len(),
            1,
            "scope B's InitDone must not touch scope A's store"
        );

        // Scope A's watch restarts (a reconnect re-sends the whole list for A only).
        list_scope(&mut tx_a, &mut stream_a, "team-a", 5).await;

        assert_eq!(
            store_a.len(),
            1,
            "scope A still reflects its own Application"
        );
        assert_eq!(
            store_b.len(),
            1,
            "scope B's object must survive a restart of scope A's watcher (finding C1)"
        );
        assert!(
            store_b
                .get(&reflector::ObjectRef::new("demo").within("team-b"))
                .is_some(),
            "team-b/demo must still be in scope B's own store"
        );
        assert!(
            store_a
                .get(&reflector::ObjectRef::new("demo").within("team-a"))
                .is_some(),
            "team-a/demo must be in scope A's own store"
        );
    }

    /// **Finding C1 (end to end):** two namespaces, one `Application` each — both are reconciled,
    /// from their own controller, over their own store.
    #[tokio::test]
    async fn every_scope_reconciles_the_applications_it_watches() {
        let (mut tx_a, rx_a) = futures::channel::mpsc::unbounded();
        let (mut tx_b, rx_b) = futures::channel::mpsc::unbounded();
        for (sender, namespace) in [(&mut tx_a, "team-a"), (&mut tx_b, "team-b")] {
            send(sender, watcher::Event::Init);
            send(
                sender,
                watcher::Event::InitApply(scripted_application(namespace, "demo", 1)),
            );
            send(sender, watcher::Event::InitDone);
        }

        let (stream_a, store_a) = scoped_store(rx_a);
        let (stream_b, store_b) = scoped_store(rx_b);
        let reconciled = Arc::new(Mutex::new(Vec::new()));

        let record = {
            let reconciled = reconciled.clone();
            move |app: Arc<Application>, _ctx: Arc<()>| {
                let reconciled = reconciled.clone();
                async move {
                    lock_recover(&reconciled).push(object_key(&app));
                    Ok::<Action, std::io::Error>(Action::await_change())
                }
            }
        };
        let on_error =
            |_app: Arc<Application>, _err: &std::io::Error, _ctx: Arc<()>| Action::await_change();

        let runs: Vec<BoxStream<'static, TestRunItem>> = vec![
            Controller::for_stream(stream_a, store_a)
                .run(record.clone(), on_error, Arc::new(()))
                .boxed(),
            Controller::for_stream(stream_b, store_b)
                .run(record, on_error, Arc::new(()))
                .boxed(),
        ];
        let mut runs = futures::stream::select_all(runs);

        for _ in 0..2 {
            let item = tokio::time::timeout(Duration::from_secs(10), runs.next())
                .await
                .expect("both namespaces must be reconciled")
                .expect("the controller streams must not end");
            item.expect("a scripted reconcile must succeed");
        }

        let mut keys = lock_recover(&reconciled).clone();
        keys.sort();
        assert_eq!(
            keys,
            vec!["team-a/demo".to_owned(), "team-b/demo".to_owned()],
            "each controller reconciles the Application of its own namespace"
        );
    }
}
