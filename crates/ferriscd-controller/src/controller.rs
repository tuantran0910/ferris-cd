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
use tokio_util::sync::CancellationToken;

use crate::drift_watcher::{DriftTriggerChannels, DriftWatcherConfig};
use crate::reconcile::{ControllerError, ReconcileContext, reconcile_instance};
use crate::sharding::{Sharding, shard_predicate};
use crate::{lock_recover, predicate};

#[cfg(test)]
use crate::sharding::shard_of;

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
    /// Deterministic sharding (`T13.3`): when set, this replica queues only its own shard.
    ///
    /// `None` (the default) reconciles every `Application` in the watched namespaces: the
    /// pre-Phase-13 behaviour, unchanged. The filter runs on the watch stream, before the
    /// controller schedules work — see [`build_controllers`].
    pub shard: Option<Sharding>,
    /// Opt-in drift watcher (`T18.2`).
    ///
    /// Disabled by default. When enabled, every scope's `Controller` additionally reconciles on a
    /// bounded drift-trigger channel ([`crate::drift_watcher`]); the triggers themselves come from
    /// label-scoped `PartialObjectMetadata` watches started by the supervisor in
    /// [`run_until_with_readiness`].
    pub drift_watcher: DriftWatcherConfig,
}

impl Default for ControllerConfig {
    fn default() -> Self {
        Self {
            namespace: ferriscd_crd::CONTROL_PLANE_NAMESPACE.to_owned(),
            application_namespaces: ApplicationNamespaces::ControlPlane,
            concurrency: DEFAULT_CONCURRENCY,
            drain_timeout: DEFAULT_DRAIN_TIMEOUT,
            shard: None,
            drift_watcher: DriftWatcherConfig::disabled(),
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

    /// Restricts this replica to `shard` (`T13.3`, builder style).
    ///
    /// The shard is validated at construction ([`Sharding::new`]), so an out-of-range index can
    /// never reach the watch filter and silently reconcile nothing.
    #[must_use]
    pub fn with_shard(mut self, shard: Sharding) -> Self {
        self.shard = Some(shard);
        self
    }

    /// Opts into the drift watcher (`T18.2`, builder style).
    #[must_use]
    pub fn with_drift_watcher(mut self, drift_watcher: DriftWatcherConfig) -> Self {
        self.drift_watcher = drift_watcher;
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
    /// `T18.2`: the bounded drift-trigger channel of every scope. `None` unless the opt-in drift
    /// watcher is enabled, so a `v1.0` deployment allocates nothing.
    drift: Option<DriftTriggerChannels>,
}

impl std::fmt::Debug for ApplicationControllers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApplicationControllers")
            .field("scopes", &self.labels())
            .field("objects", &self.store_lengths())
            .field(
                "drift_scopes",
                &self.drift.as_ref().map(DriftTriggerChannels::len),
            )
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

    /// Every scope's private store, in [`Self::labels`] order (`T18.2`).
    ///
    /// The drift watcher derives its watch set and its `app-hash` index from exactly these stores,
    /// so it never issues an `Application` list of its own (no cluster-wide informer).
    #[must_use]
    pub fn stores(&self) -> Vec<Store<Application>> {
        self.controllers
            .iter()
            .map(NamespacedController::store)
            .collect()
    }

    /// The per-scope drift-trigger channels, or `None` when the drift watcher is disabled.
    #[must_use]
    pub fn drift_triggers(&self) -> Option<&DriftTriggerChannels> {
        self.drift.as_ref()
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
    ///
    /// `stop` is the **only** shutdown input: a `SIGTERM` cancels it in the single-replica path,
    /// and a lost leader lease cancels it in the `T13.2` path, so both stop the set identically.
    fn into_run_streams(
        self,
        ctx: Arc<ReconcileContext>,
        stop: CancellationToken,
    ) -> Vec<BoxStream<'static, ControllerRunItem>> {
        self.controllers
            .into_iter()
            .map(|scope| {
                // One trigger future per controller rather than a shared `Notify`: every scope must
                // observe the same shutdown, and `notify_one` would wake exactly one of them.
                let trigger = stop.clone();
                let trigger = async move {
                    trigger.cancelled().await;
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

/// Whether a run-stream item is "this object is no longer in the local store" (finding N-1).
///
/// A drift trigger (`T18.2`) names an `Application` by `ObjectRef`, so it can outlive the object:
/// the `Application` was deleted (or moved out of this scope) between the metadata event and the
/// dequeue. kube's `ObjectNotFound` is a **no-op** — nothing was scheduled, nothing failed, and the
/// drift that mattered is the one a still-present `Application` gets — so it is logged at `debug`
/// and never at `warn`. Warning on it turns an ordinary delete into a scary log line per trigger.
fn is_object_not_found(
    error: &kube::runtime::controller::Error<ControllerError, watcher::Error>,
) -> bool {
    matches!(error, kube::runtime::controller::Error::ObjectNotFound(_))
}

/// Reports one run-stream item, at the level it deserves (finding N-1).
///
/// Extracted from the drive loop so the `debug`-vs-`warn` split is assertable: an
/// `ObjectNotFound` is a no-op (debug), every other stream error is a real problem (warn).
fn log_run_stream_error(error: &kube::runtime::controller::Error<ControllerError, watcher::Error>) {
    if is_object_not_found(error) {
        tracing::debug!(
            error = %error,
            "controller stream: the object is no longer in the store; nothing to reconcile"
        );
    } else {
        tracing::warn!(error = %error, "controller stream error");
    }
}

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
///
/// `shard` adds the `T13.3` filter **on the stream**, i.e. before the controller enqueues anything:
/// an `Application` owned by another shard is dropped here and costs no reconcile, no queue slot and
/// no `/status` patch. It sits inside the same chain as the composite predicate
/// ([`crate::predicate`]) rather than in the reconciler, because a post-queue filter would still
/// schedule (and back off, and requeue) work this replica must never perform. `Err` items — watch
/// errors — always pass ([`crate::sharding::ShardPredicate::keeps`]).
fn scoped_store<E>(
    events: E,
    shard: Option<Sharding>,
) -> (
    impl Stream<Item = Result<Application, watcher::Error>>,
    Store<Application>,
)
where
    E: Stream<Item = Result<watcher::Event<Application>, watcher::Error>> + Send + 'static,
{
    let (reader, writer) = reflector::store();
    // `ShardPredicate` is `Copy`, so the closure owns a plain value: no lock, no allocation per
    // event, and the same decision every replica makes for the same object.
    let shard_predicate = shard.map(shard_predicate);
    let stream = events
        // Per-scope reconnect backoff: a namespace whose watch keeps failing backs off on its own
        // schedule instead of starving every other namespace (finding C1).
        .default_backoff()
        .reflect(writer)
        .applied_objects()
        // `T13.3`: drop other shards' work before it can be queued.
        .filter(move |item| {
            std::future::ready(
                shard_predicate
                    .map(|predicate| predicate.keeps(item))
                    .unwrap_or(true),
            )
        })
        // Filter *before* the controller schedules work: a status-only patch then costs
        // zero reconciles instead of one wasted pass per status write.
        .predicate_filter(predicate::predicate(), PredicateConfig::default());
    (stream, reader)
}

/// Wraps a drift-trigger receiver as the stream [`Controller::reconcile_on`] accepts.
///
/// Spelled with `futures::stream::unfold` rather than `tokio_stream::wrappers::ReceiverStream` so
/// the workspace does not take a new dependency for six lines of adapter: the item type,
/// back-pressure and cancellation semantics are identical.
fn drift_trigger_stream(
    receiver: tokio::sync::mpsc::Receiver<reflector::ObjectRef<Application>>,
) -> impl Stream<Item = reflector::ObjectRef<Application>> + Send + 'static {
    futures::stream::unfold(receiver, |mut receiver| async move {
        let next = receiver.recv().await?;
        Some((next, receiver))
    })
}

/// Builds **one `Controller` per watched namespace** for the configured scope (finding C1).
///
/// The returned controllers are not yet running: [`run`] drives their `run` streams and waits for
/// every store to be ready before declaring readiness.
///
/// `config.shard` (`T13.3`) reaches every scope: an `Application` is filtered by its own
/// `(namespace, name)`, so the shard boundary is independent of which namespace scope the watch
/// covers — including the cluster-wide `*` scope.
///
/// `config.drift_watcher` (`T18.2`) additionally wires one bounded
/// `mpsc::channel::<ObjectRef<Application>>` per scope into `Controller::reconcile_on`, so a
/// metadata-watch hit schedules exactly the `Application` it concerns — through the same store,
/// queue, concurrency limit and backoff as every other trigger. Disabled (the default), no channel
/// is created and the controller set is byte-for-byte the pre-`v1.2` wiring.
#[must_use]
pub fn build_controllers(client: Client, config: &ControllerConfig) -> ApplicationControllers {
    let scopes: Vec<Option<String>> = match config.watched_namespaces() {
        Some(namespaces) => namespaces.into_iter().map(Some).collect(),
        // `*`: one cluster-wide controller. The per-`Application` `AppProject` guard (`T12.2`) is
        // what makes this safe: scope alone never authorizes a tenant `Application`.
        None => vec![None],
    };
    let mut drift_scopes = Vec::new();
    let controllers = scopes
        .into_iter()
        .map(|namespace| {
            let api = scope_api(&client, namespace.as_deref());
            let (stream, store) =
                scoped_store(watcher(api, watcher::Config::default()), config.shard);
            let mut controller = Controller::for_stream(stream, store).with_config(
                kube::runtime::controller::Config::default().concurrency(config.concurrency),
            );
            if config.drift_watcher.enabled {
                // Clamped to at least 1: `mpsc::channel(0)` panics, and a misconfigured capacity
                // must never take the controller down at startup.
                let (sender, receiver) =
                    tokio::sync::mpsc::channel(config.drift_watcher.trigger_capacity.max(1));
                drift_scopes.push((namespace.clone(), sender));
                controller = controller.reconcile_on(drift_trigger_stream(receiver));
            }
            NamespacedController {
                namespace,
                controller,
            }
        })
        .collect();
    let drift = match drift_scopes.is_empty() {
        true => None,
        // Metrics are attached by the caller that owns the recorder (`run_until_with_readiness`):
        // `ControllerConfig` is a plain `Eq` value and must not carry a registry.
        false => Some(DriftTriggerChannels::new(drift_scopes, None)),
    };
    ApplicationControllers { controllers, drift }
}

/// Listens for `SIGINT`/`SIGTERM` and cancels `stop`, logging the signal exactly once.
fn spawn_shutdown_listener(stop: CancellationToken) {
    tokio::spawn(async move {
        let reason = crate::shutdown_signal().await;
        tracing::info!(
            signal = reason.as_str(),
            "graceful shutdown requested; draining in-flight reconciles"
        );
        stop.cancel();
    });
}

/// Runs every per-namespace controller until `SIGINT`/`SIGTERM`, draining in-flight reconciles.
///
/// This is the single-replica behaviour (and the `T13.2` standby's *non*-leader behaviour): no
/// `Lease` is involved, so exactly one replica must run.
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
    let stop = CancellationToken::new();
    spawn_shutdown_listener(stop.clone());
    run_until_with_readiness(client, config, ctx, stop, None, None).await
}

/// Runs the controller set for **one leader term** (`T13.2`).
///
/// `token` is cancelled when the leader lease is lost (or when the process is asked to stop while
/// leading), and the set then drains exactly like a `SIGTERM`. The caller owns the standby loop:
/// once this returns, the replica is a standby again and must re-acquire the lease.
///
/// # Errors
///
/// See [`run`].
pub async fn run_as_leader(
    client: Client,
    config: ControllerConfig,
    ctx: Arc<ReconcileContext>,
    token: CancellationToken,
) -> Result<(), crate::ShutdownError> {
    run_until_with_readiness(client, config, ctx, token, None, None).await
}

/// Same as [`run_as_leader`], additionally signalling [`ControlPlaneReadiness::mark_controllers_ready`](crate::ControlPlaneReadiness::mark_controllers_ready)
/// once every watched `Application` reflector store completes `InitDone` (`T17.1`).
///
/// # Errors
///
/// Returns [`crate::ShutdownError::DrainTimeout`] when a reconcile is still running after
/// `config.drain_timeout`.
pub async fn run_as_leader_with_readiness(
    client: Client,
    config: ControllerConfig,
    ctx: Arc<ReconcileContext>,
    token: CancellationToken,
    readiness: crate::ControlPlaneReadiness,
) -> Result<(), crate::ShutdownError> {
    run_until_with_readiness(client, config, ctx, token, Some(readiness), None).await
}

/// Same as [`run_as_leader_with_readiness`], additionally starting the opt-in drift watcher
/// (`T18.2`) for the duration of the term.
///
/// `drift` carries the collaborators the watcher needs but the controller set does not own (the
/// cluster registry, the self-echo cache and the metric registry). It is `None` for a caller that
/// did not opt in: the watcher is never started, and the controller set is unchanged.
///
/// # Errors
///
/// See [`run_as_leader_with_readiness`].
pub async fn run_as_leader_with_readiness_and_drift(
    client: Client,
    config: ControllerConfig,
    ctx: Arc<ReconcileContext>,
    token: CancellationToken,
    readiness: crate::ControlPlaneReadiness,
    drift: Option<crate::drift_watcher::DriftRuntime>,
) -> Result<(), crate::ShutdownError> {
    run_until_with_readiness(client, config, ctx, token, Some(readiness), drift).await
}

/// Drives the controller set until `stop` is cancelled, then drains in-flight reconciles.
///
/// # Errors
///
/// Returns [`crate::ShutdownError::DrainTimeout`] when a reconcile is still running after
/// `config.drain_timeout`.
async fn run_until_with_readiness(
    client: Client,
    config: ControllerConfig,
    ctx: Arc<ReconcileContext>,
    stop: CancellationToken,
    readiness_gate: Option<crate::ControlPlaneReadiness>,
    drift: Option<crate::drift_watcher::DriftRuntime>,
) -> Result<(), crate::ShutdownError> {
    let drain_timeout = config.drain_timeout;
    let controllers = build_controllers(client, &config);
    let scopes: Vec<String> = controllers
        .labels()
        .iter()
        .map(|l| (*l).to_owned())
        .collect();
    let readiness = controllers.wait_until_ready();
    // `T18.2`: start the opt-in supervisor before the reconcile pumps run, so the first metadata
    // event can be delivered as soon as an `Application` has completed its list. It is spawned with
    // the same `stop` token, so a lost lease or a `SIGTERM` stops the watches with everything else.
    let drift_task = match (config.drift_watcher.enabled, drift) {
        (true, Some(runtime)) => match controllers.drift_triggers() {
            Some(triggers) => {
                let channels = Arc::new(triggers.clone().with_metrics(runtime.metrics.clone()));
                let watcher = crate::drift_watcher::DriftWatcher::new(
                    config.drift_watcher.clone(),
                    runtime.clusters,
                    controllers.stores(),
                    channels,
                    runtime.echo,
                    config.shard,
                    runtime.metrics,
                );
                Some(tokio::spawn(watcher.run(stop.clone())))
            }
            // Enabled but unwired: a construction bug, never a silent downgrade.
            None => {
                tracing::warn!(
                    "the drift watcher is enabled but no scope was wired for drift triggers; \
                     continuing with periodic polling only"
                );
                None
            }
        },
        // Enabled but no runtime: `prepare` builds the two together, so this can only be a wiring
        // bug. Say so instead of quietly running Model 1 only.
        (true, None) => {
            tracing::warn!(
                "the drift watcher is enabled but no runtime was supplied for this term; \
                 continuing with periodic polling only"
            );
            None
        }
        // Finding M5: the *symmetric* case. A runtime was built (the flag was on when `prepare`
        // ran) but the term's config says disabled, which can only be a wiring bug. Saying so is
        // what makes the pair of warnings complete: neither half of the switch can silently
        // disagree with the other.
        (false, Some(runtime)) => {
            tracing::warn!(
                clusters = ?runtime.clusters.names(),
                "a drift watcher runtime was built but `--enable-drift-watcher` is off for this \
                 term; no metadata watch is started and only Model 1 periodic polling runs"
            );
            None
        }
        (false, None) => None,
    };

    tracing::info!(
        namespace = %config.namespace,
        controllers = controllers.len(),
        scopes = ?scopes,
        concurrency = config.concurrency,
        shard = ?config.shard,
        finalizer = crate::reconcile::FINALIZER,
        "application controller started (one controller and private store per watched namespace)"
    );

    // One merged result stream over N independent controllers. Each controller keeps its own
    // store, watch backoff and schedule; only the reporting is merged.
    let mut results = futures::stream::select_all(controllers.into_run_streams(ctx, stop.clone()));

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
                    //
                    // Finding N-1: an `ObjectNotFound` is not an error at all — the run stream (or a
                    // `T18.2` drift trigger) named an `Application` that has since left the store.
                    // It is the normal shape of "the object was deleted while the reconcile was
                    // queued", so it is logged at `debug` (see [`log_run_stream_error`]).
                    log_run_stream_error(&err);
                }
            }
        }
    };

    // Readiness covers *all* controllers: the log line appears only once every namespace has
    // completed its first list, and a watch that dies before that is reported instead of hidden.
    let readiness = async move {
        match readiness.await {
            Ok(objects) => {
                if let Some(gate) = readiness_gate {
                    gate.mark_controllers_ready();
                }
                tracing::info!(
                    scopes = ?scopes,
                    objects = ?objects,
                    "every Application watch is ready"
                );
            }
            Err(err) => tracing::warn!(
                error = %err,
                "an Application watch ended before it became ready"
            ),
        }
    };

    // Readiness and the reconcile pump run together: the stores only become ready because the
    // streams are polled. The pump is what ends the work, exactly as before (a graceful shutdown
    // stops every controller, so every stream ends).
    //
    // `T18.2`: the drift supervisor joins them. It ends when `stop` is cancelled (it is the same
    // token), so it can never hold shutdown open, and a panicking supervisor is reported instead of
    // aborting the drain.
    let work = async move {
        let drift = async move {
            if let Some(task) = drift_task
                && let Err(err) = task.await
            {
                tracing::warn!(error = %err, "the drift watcher task ended abnormally");
            }
        };
        let ((), (), ()) = tokio::join!(drive, readiness, drift);
    };
    let shutdown = async move {
        stop.cancelled().await;
    };
    crate::await_drained(work, shutdown, drain_timeout).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drift_watcher::DriftWatcherConfig;

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
            source: Some(ferriscd_crd::SourceSpec {
                git: Some(ferriscd_crd::GitSourceSpec {
                    repo_url: "https://example.com/repo.git".to_owned(),
                    target_revision: "main".to_owned(),
                    path: String::new(),
                }),
                oci: None,
                renderer: ferriscd_crd::RendererSpec::default(),
            }),
            sources: Vec::new(),
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
        let (stream_a, store_a) = scoped_store(rx_a, None);
        let (stream_b, store_b) = scoped_store(rx_b, None);
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

    /// The first `<namespace>/<name>` (scanning `app-0`, `app-1`, …) that `shard` assigns to
    /// `shard_id`.
    fn a_name_in_shard(namespace: &str, shard: Sharding, shard_id: u32) -> String {
        (0..1_000)
            .map(|index| format!("app-{index}"))
            .find(|name| shard_of(namespace, name, shard.total_shards()) == shard_id)
            .expect("every shard must hold at least one of the first 1000 names")
    }

    /// **`T13.3` wiring:** the shard filter runs on the watch stream, so another shard's
    /// `Application` is never handed to the controller — no reconcile, no queue slot, no backoff —
    /// while the store still reflects it (readiness must not depend on how many shards exist).
    ///
    /// The assertion is ordering-based rather than timeout-based: the two changes are sent
    /// back-to-back, and the stream must yield the owned one next. A filter applied one stage later
    /// (after the queue) would surface the foreign object first.
    #[tokio::test]
    async fn another_shards_application_is_never_queued() {
        let shard = Sharding::new(0, 2).expect("valid shard");
        let namespace = "ferriscd-system";
        let owned = a_name_in_shard(namespace, shard, 0);
        let foreign = a_name_in_shard(namespace, shard, 1);
        assert_ne!(owned, foreign);

        let (mut tx, rx) = futures::channel::mpsc::unbounded();
        let (stream, store) = scoped_store(rx, Some(shard));
        let mut stream = Box::pin(stream);

        send(&mut tx, watcher::Event::Init);
        send(
            &mut tx,
            watcher::Event::InitApply(scripted_application(namespace, &foreign, 1)),
        );
        send(
            &mut tx,
            watcher::Event::InitApply(scripted_application(namespace, &owned, 1)),
        );
        send(&mut tx, watcher::Event::InitDone);

        let first = stream
            .next()
            .await
            .expect("this shard's own Application must be queued")
            .expect("a scripted event must not fail");
        assert_eq!(
            object_key(&first),
            format!("{namespace}/{owned}"),
            "another shard's Application must never reach the controller"
        );

        send(
            &mut tx,
            watcher::Event::Apply(scripted_application(namespace, &foreign, 2)),
        );
        send(
            &mut tx,
            watcher::Event::Apply(scripted_application(namespace, &owned, 2)),
        );
        let second = stream
            .next()
            .await
            .expect("the next queued object must be this shard's")
            .expect("a scripted event must not fail");
        assert_eq!(object_key(&second), format!("{namespace}/{owned}"));
        assert_eq!(
            second.metadata.generation,
            Some(2),
            "the yielded object is the owned change, not the foreign one that was sent first"
        );
        // The store is *not* sharded: it holds everything the watch delivered (the `InitDone`
        // swap happens upstream of the filter), so readiness and inventory reads do not depend on
        // the shard count. Asserted here because a `Store` only reflects a list after `InitDone`
        // has been consumed, which the two changes above prove.
        assert_eq!(
            store.len(),
            2,
            "only the queue is sharded; the private store still reflects every listed object"
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

        let (stream_a, store_a) = scoped_store(rx_a, None);
        let (stream_b, store_b) = scoped_store(rx_b, None);
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

    // ---------------------------------------------------------------------
    // T18.2: the drift-trigger wiring
    // ---------------------------------------------------------------------

    /// Disabled (the default) wires nothing: no channel, no `reconcile_on`, no allocation.
    ///
    /// `#[tokio::test]` because building a `kube::Client` over a tower service needs a reactor (the
    /// same reason the finding-C1 tests are async).
    #[tokio::test]
    async fn the_drift_watcher_is_unwired_unless_it_is_enabled() {
        let client = offline_client();
        let disabled = build_controllers(client.clone(), &ControllerConfig::default());
        assert!(
            disabled.drift_triggers().is_none(),
            "`--enable-drift-watcher=false` must leave the controller set untouched"
        );

        let enabled = build_controllers(
            client,
            &ControllerConfig::default().with_drift_watcher(DriftWatcherConfig::from_flag(true)),
        );
        let triggers = enabled
            .drift_triggers()
            .expect("an enabled watcher wires one channel per scope");
        assert_eq!(
            triggers.len(),
            enabled.len(),
            "one bounded trigger channel per watched scope, never one shared queue"
        );
    }

    /// **T18.2 wiring (behavioural):** a reference pushed into a scope's drift channel reconciles
    /// exactly that `Application`, through the controller's own store and queue.
    ///
    /// The reconciler never returns `await_change` for the first pass here: it counts. The first
    /// reconcile comes from the initial list; the second can only come from the drift trigger, so the
    /// assertion proves the trigger reached the work queue (not just that a channel exists).
    #[tokio::test]
    async fn a_drift_trigger_reconciles_the_application_it_names() {
        let namespace = "ferriscd-system";
        let (mut sender, receiver) = futures::channel::mpsc::unbounded();
        send(&mut sender, watcher::Event::Init);
        send(
            &mut sender,
            watcher::Event::InitApply(scripted_application(namespace, "payments", 1)),
        );
        send(&mut sender, watcher::Event::InitDone);
        let (stream, store) = scoped_store(receiver, None);

        // The production wiring, verbatim: one bounded channel per scope, `reconcile_on` with the
        // receiver stream.
        let (drift_tx, drift_rx) =
            tokio::sync::mpsc::channel::<reflector::ObjectRef<Application>>(8);
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
        let mut run = Box::pin(
            Controller::for_stream(stream, store)
                .reconcile_on(drift_trigger_stream(drift_rx))
                .run(record, on_error, Arc::new(()))
                .boxed(),
        );

        // First: the list itself is reconciled.
        let first = tokio::time::timeout(Duration::from_secs(10), run.next())
            .await
            .expect("the listed Application must be reconciled")
            .expect("the controller stream must not end");
        first.expect("a scripted reconcile must succeed");
        assert_eq!(
            lock_recover(&reconciled).clone(),
            vec![format!("{namespace}/payments")]
        );

        // Then: a drift trigger for the same object schedules another pass, and the trigger carries
        // the `ObjectRef` identity (namespace + name), which is what `Sharding::owns` filtered on.
        drift_tx
            .try_send(reflector::ObjectRef::new("payments").within(namespace))
            .expect("the drift channel accepts the trigger");
        let second = tokio::time::timeout(Duration::from_secs(10), run.next())
            .await
            .expect("the drift trigger must schedule a reconcile")
            .expect("the controller stream must not end");
        second.expect("a scripted reconcile must succeed");
        assert_eq!(
            lock_recover(&reconciled).len(),
            2,
            "the trigger scheduled exactly one additional pass"
        );
    }

    /// A `/status` writer that records nothing: the shutdown contract is what this test pins.
    struct DiscardingStatus;

    impl crate::reconcile::StatusWriter for DiscardingStatus {
        fn patch<'a>(
            &'a self,
            _app: &'a Application,
            _status: ferriscd_crd::status::ApplicationStatus,
        ) -> futures::future::BoxFuture<'a, Result<(), crate::reconcile::ReconcileError>> {
            Box::pin(async { Ok(()) })
        }
    }

    /// **Finding M5:** cancelling the leader token must end **every** namespace scope's run
    /// stream, not one of them.
    ///
    /// The bug this pins: a shared `tokio::sync::Notify` plus `notify_one` wakes exactly one
    /// waiter. The scope that is not woken keeps reconciling — with the controller's own
    /// credentials — after the replica lost the `Lease`, which is precisely the split brain leader
    /// election exists to prevent. A `CancellationToken` is a broadcast, so every scope observes it.
    ///
    /// The scopes are built over scripted watch streams (not an API server): an empty, completed
    /// list makes each store ready, so the streams are live and quiet, and the only thing that can
    /// end them is the shutdown input.
    #[tokio::test]
    async fn cancelling_the_leader_token_ends_every_namespace_scope() {
        /// One scope over a scripted, completed and then quiet watch.
        fn quiet_scope(namespace: &str) -> (NamespacedController, ScriptedSender) {
            let (mut sender, receiver) = futures::channel::mpsc::unbounded();
            send(&mut sender, watcher::Event::Init);
            send(&mut sender, watcher::Event::InitDone);
            let (stream, store) = scoped_store(receiver, None);
            let controller = Controller::for_stream(stream, store);
            let scope = NamespacedController {
                namespace: Some(namespace.to_owned()),
                controller,
            };
            (scope, sender)
        }

        let mut scopes = Vec::new();
        let mut stores = Vec::new();
        // The senders are held for the duration of the test, so no scope's watch ever ends on its
        // own: the streams below can only stop because of the cancellation.
        let mut senders = Vec::new();
        for namespace in ["ferriscd-system", "team-a", "team-b"] {
            let (scope, sender) = quiet_scope(namespace);
            stores.push(scope.store());
            scopes.push(scope);
            senders.push(sender);
        }
        assert_eq!(
            scopes.len(),
            3,
            "the test must cover more than one scope for the regression to mean anything"
        );

        let ctx = Arc::new(ReconcileContext::new(
            Api::namespaced(offline_client(), "ferriscd-system"),
            Arc::new(crate::reconcile::UnwiredSyncPipeline),
            Arc::new(DiscardingStatus),
        ));
        let controllers = ApplicationControllers {
            controllers: scopes,
            drift: None,
        };
        let stop = CancellationToken::new();
        let mut runs = futures::stream::select_all(controllers.into_run_streams(ctx, stop.clone()));
        let mut ready = Box::pin(futures::future::join_all(
            stores.iter().map(reflector::Store::wait_until_ready),
        ));

        // Drive every scope through its (empty) list first: a `Controller` holds its work until the
        // store is ready, and a stream that is not polled never is.
        loop {
            tokio::select! {
                _ = &mut ready => break,
                item = runs.next() => assert!(item.is_none(), "an empty list yields no reconcile"),
            }
        }
        assert_eq!(senders.len(), 3);

        // The leader term ends (a lost renewal, or a graceful stop while leading).
        stop.cancel();

        let ended = tokio::time::timeout(Duration::from_secs(10), async {
            while runs.next().await.is_some() {}
        })
        .await;
        assert!(
            ended.is_ok(),
            "every scope's run stream must end when the leader token is cancelled: a \
             `notify_one` would leave the other namespaces reconciling without authority"
        );
    }

    // ---------------------------------------------------------------------
    // T18.2 (finding N-1): a trigger that outlives its Application
    // ---------------------------------------------------------------------

    /// A `Box<ObjectRef<DynamicObject>>`, the payload kube puts in `Error::ObjectNotFound`.
    ///
    /// `ObjectRef::<DynamicObject>::new` requires `DynamicType: Default`, which `ApiResource` does
    /// not implement, so the dynamic type is supplied explicitly.
    fn not_found_ref() -> Box<reflector::ObjectRef<kube::api::DynamicObject>> {
        let api_resource = kube::api::ApiResource::from_gvk(&kube::core::GroupVersionKind::gvk(
            "",
            "v1",
            "ConfigMap",
        ));
        Box::new(reflector::ObjectRef::new_with("payments", api_resource).within("team-a"))
    }

    /// Every constructible variant of the controller's run-stream error.
    fn run_stream_errors() -> Vec<kube::runtime::controller::Error<ControllerError, watcher::Error>>
    {
        vec![
            kube::runtime::controller::Error::ObjectNotFound(not_found_ref()),
            kube::runtime::controller::Error::ReconcilerFailed(
                ControllerError::from_reconcile(crate::reconcile::ReconcileError::Invalid {
                    message: "the reconciler gave up".to_owned(),
                }),
                not_found_ref(),
            ),
            kube::runtime::controller::Error::QueueError(watcher::Error::NoResourceVersion),
        ]
    }

    /// **Finding N-1:** only `ObjectNotFound` is "nothing to reconcile". It is the normal result of
    /// a `T18.2` drift trigger naming an `Application` that has since been deleted, so it must not be
    /// classified as a failure — every other run-stream variant is one.
    #[test]
    fn only_object_not_found_is_a_no_op_run_stream_error() {
        use kube::runtime::controller::Error as ControllerRunError;

        let errors = run_stream_errors();
        assert!(
            errors.len() >= 3,
            "the classifier must be exercised against more than one variant"
        );
        for error in &errors {
            let expected = matches!(error, ControllerRunError::ObjectNotFound(_));
            assert_eq!(
                is_object_not_found(error),
                expected,
                "misclassified {error:?}"
            );
        }
        assert!(
            is_object_not_found(&errors[0]),
            "the trigger's object leaving the store is the no-op case"
        );
        assert!(
            !is_object_not_found(&errors[1]) && !is_object_not_found(&errors[2]),
            "a failed reconcile and a broken queue are real problems"
        );
    }

    /// **Finding N-1 (the level, not just the predicate):** an `ObjectNotFound` is logged at
    /// `debug`, while every other run-stream error is logged at `warn`.
    ///
    /// Pins the split that [`log_run_stream_error`] performs: reverting the branch to `warn!` (the
    /// original bug) makes this test fail, whereas asserting only the predicate would not.
    #[test]
    fn an_object_not_found_is_logged_at_debug_and_every_other_error_at_warn() {
        let logs = captured_logs(|| {
            for error in run_stream_errors() {
                log_run_stream_error(&error);
            }
        });
        assert!(
            logs.contains("DEBUG"),
            "an ObjectNotFound must be logged (at debug), got: {logs}"
        );
        assert!(
            logs.contains("no longer in the store"),
            "the debug line must say the object is gone, got: {logs}"
        );
        assert!(
            logs.contains("WARN") && logs.contains("controller stream error"),
            "a real stream error must be logged at warn, got: {logs}"
        );
        let not_found = captured_logs(|| {
            log_run_stream_error(&kube::runtime::controller::Error::ObjectNotFound(
                not_found_ref(),
            ))
        });
        assert!(
            !not_found.contains("WARN"),
            "an ObjectNotFound must never be a warning, got: {not_found}"
        );
        let failed = captured_logs(|| {
            log_run_stream_error(&kube::runtime::controller::Error::QueueError(
                watcher::Error::NoResourceVersion,
            ));
        });
        assert!(
            failed.contains("WARN") && !failed.contains("DEBUG"),
            "a queue error must be a warning and nothing else, got: {failed}"
        );
    }

    /// A `tracing` writer that collects the formatted log lines of one test.
    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<std::sync::Mutex<Vec<u8>>>);

    impl CapturedLogs {
        fn contents(&self) -> String {
            let bytes = lock_recover(&self.0);
            String::from_utf8_lossy(&bytes).into_owned()
        }
    }

    impl std::io::Write for CapturedLogs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            lock_recover(&self.0).extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Runs `body` under a thread-local subscriber and returns the formatted log lines it produced.
    ///
    /// Thread-local (not global) on purpose: the test suite runs in parallel, and installing a
    /// global subscriber would both race other tests and capture their lines.
    fn captured_logs(body: impl FnOnce()) -> String {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt::Subscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(logs.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, body);
        logs.contents()
    }
}
