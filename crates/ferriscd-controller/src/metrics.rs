//! Low-cardinality Prometheus metrics (`T15.1`) and the dedicated `/metrics` listener.
//!
//! # Why every label is a *type*
//!
//! A Prometheus time series is `(name, label set)`. Every value that is not drawn from a small,
//! fixed set multiplies the series count, and the classic GitOps cardinality bomb is exactly the
//! information an operator would *like* to see: the commit SHA, the error message, the resource
//! name, the repository URL. On a fleet of a few hundred `Application`s these grow without bound —
//! one series per commit per app, one per distinct error string — and they take the Prometheus
//! server down with them, which is the opposite of observability (roadmap `T15.1` trap guard).
//!
//! So the label sets here are *not* `HashMap<String, String>`. They are three private structs whose
//! fields are `&'static str` (or, for the two labels the roadmap requires, the `Application`'s
//! identity), built only from [`ReconcileResult`], [`crate::controller::FailureClass`],
//! [`SyncStatus`], [`HealthStatus`] and [`CacheOutcome`]. There is no constructor that accepts a
//! runtime string, so `commit_sha=…`, `error_message=…` or `resource=…` cannot be expressed at all —
//! and the `T15.1` tests assert the exposed label *names* against an allow-list per family, so a
//! future field cannot sneak in unnoticed either.
//!
//! | Family | Type | Labels | Cardinality |
//! |---|---|---|---|
//! | `ferriscd_reconcile_duration_seconds` | histogram | `result` | 3 |
//! | `ferriscd_reconcile_total` | counter | `result` | 3 |
//! | `ferriscd_app_sync_status` | gauge | `app_namespace`, `app_name`, `status` | apps × 3 |
//! | `ferriscd_app_health_status` | gauge | `app_namespace`, `app_name`, `status` | apps × 6 |
//! | `ferriscd_git_fetch_duration_seconds` | histogram | — | 1 |
//! | `ferriscd_render_cache_total` | counter | `outcome` | 2 |
//! | `ferriscd_active_reconciles` | gauge | — | 1 |
//!
//! # The listener is separate from the API
//!
//! The exposition is the classic Prometheus **text 0.0.4** format
//! (`text/plain; version=0.0.4`), produced by the crate's own encoder, and it is served by its own
//! `axum` listener on its own port (`--metrics-addr`,
//! `FERRISCD_METRICS_ADDR`, default [`DEFAULT_METRICS_ADDR`]) and is **never** routed by
//! `ferriscd-server`'s API router: the API port carries the bearer-protected `/api/v1/*` surface and
//! the unauthenticated `/healthz`, `/readyz` probes (`T14.3`), and mixing scrapes into it would
//! either expose the API to a scraper's network or force a credential onto Prometheus.
//!
//! # Where the observations come from
//!
//! * reconcile start/end/result → [`Metrics::start_reconcile`] in
//!   [`reconcile_instance`](crate::reconcile::reconcile_instance);
//! * `app_sync_status`/`app_health_status` → [`MetricsStatusWriter`], which sees exactly the
//!   `/status` a pass persisted (success **and** failure);
//! * Git fetch duration and the render-cache hit/miss bridge → the `InventorySyncPipeline`'s
//!   [`fetch_desired`](crate::sync::InventorySyncPipeline) (the one place that resolves, checks out
//!   and renders), reading the *existing* [`RenderCache`](ferriscd_engine::manifest::RenderCache)
//!   counters rather than duplicating them.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use ferriscd_crd::Application;
use ferriscd_crd::status::{ApplicationStatus, HealthStatus, SyncStatus};
use ferriscd_engine::manifest::RenderCacheStats;
use futures::FutureExt as _;
use futures::future::BoxFuture;
use kube::ResourceExt as _;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::Registry;

use crate::controller::FailureClass;
use crate::reconcile::{ControllerError, ReconcileError, StatusWriter};

/// Default bind address of the internal metrics listener (`--metrics-addr`).
///
/// **All interfaces, port `9090`.** Unlike the API (`ferriscd_server::DEFAULT_API_ADDR`, loopback),
/// this endpoint exists to be *scraped*: Prometheus talks to the pod IP, so a loopback default would
/// make the shipped configuration un-scrapeable. The exposition carries `Application` names and
/// statuses, never a `Secret` value, a diff or a token, and `--metrics-addr 127.0.0.1:9090` (or a
/// `NetworkPolicy`) restricts it when a deployment needs that.
pub const DEFAULT_METRICS_ADDR: &str = "0.0.0.0:9090";

/// Environment variable that overrides `--metrics-addr`.
pub const METRICS_ADDR_ENV: &str = "FERRISCD_METRICS_ADDR";

/// Path the exposition is served on.
pub const METRICS_PATH: &str = "/metrics";

/// Registered name of the reconcile counter.
///
/// The exposition appends `_total` for counters (`prometheus-client` rejects a registered name that
/// already ends with it), so a scraper sees [`RECONCILE_TOTAL`].
pub const RECONCILE_COUNTER: &str = "ferriscd_reconcile";

/// Scraped name of the reconcile counter.
pub const RECONCILE_TOTAL: &str = "ferriscd_reconcile_total";

/// Scraped name of the reconcile latency histogram.
pub const RECONCILE_DURATION_SECONDS: &str = "ferriscd_reconcile_duration_seconds";

/// Scraped name of the per-`Application` sync-status gauge.
pub const APP_SYNC_STATUS: &str = "ferriscd_app_sync_status";

/// Scraped name of the per-`Application` health-status gauge.
pub const APP_HEALTH_STATUS: &str = "ferriscd_app_health_status";

/// Scraped name of the Git fetch latency histogram.
pub const GIT_FETCH_DURATION_SECONDS: &str = "ferriscd_git_fetch_duration_seconds";

/// Registered name of the render-cache counter (see [`RECONCILE_COUNTER`] for the `_total` suffix).
pub const RENDER_CACHE_COUNTER: &str = "ferriscd_render_cache";

/// Scraped name of the render-cache counter.
pub const RENDER_CACHE_TOTAL: &str = "ferriscd_render_cache_total";

/// Scraped name of the in-flight reconcile gauge.
pub const ACTIVE_RECONCILES: &str = "ferriscd_active_reconciles";

/// Registered name of the live RBAC reload counter (`T17.1`).
pub const RBAC_RELOAD_COUNTER: &str = "ferriscd_rbac_reload";

/// Scraped name of the live RBAC reload counter (`T17.1`).
pub const RBAC_RELOAD_TOTAL: &str = "ferriscd_rbac_reload_total";

/// The **complete** `result` label set, in the order it is documented.
pub const RECONCILE_RESULTS: [&str; 3] = ["success", "retryable", "terminal"];

/// The **complete** `status` label set of [`APP_SYNC_STATUS`].
pub const SYNC_STATUS_VALUES: [&str; 3] = ["Synced", "OutOfSync", "Unknown"];

/// The **complete** `status` label set of [`APP_HEALTH_STATUS`].
pub const HEALTH_STATUS_VALUES: [&str; 6] = [
    "Healthy",
    "Progressing",
    "Degraded",
    "Suspended",
    "Missing",
    "Unknown",
];

/// The **complete** `outcome` label set of [`RENDER_CACHE_TOTAL`].
pub const CACHE_OUTCOMES: [&str; 2] = ["hit", "miss"];

/// The **complete** `outcome` label set of [`RBAC_RELOAD_TOTAL`] (`T17.1`).
pub const RBAC_RELOAD_OUTCOMES: [&str; 3] = ["ok", "error", "deleted"];

/// First bucket of the latency histograms (5 ms).
const BUCKET_START_SECONDS: f64 = 0.005;

/// Bucket factor of the latency histograms (each bucket is twice the previous one).
const BUCKET_FACTOR: f64 = 2.0;

/// Number of buckets: `0.005 * 2^13 ≈ 41 s`, so a slow Git fetch or a slow Helm render still lands
/// in a bucket instead of only in `+Inf`.
const BUCKET_COUNT: u16 = 14;

/// Content type of the classic Prometheus text exposition (0.0.4).
const CONTENT_TYPE: &str = prometheus_client::encoding::prometheus_text::CONTENT_TYPE;

/// How one reconcile ended.
///
/// The variants are exactly the `result` label set ([`RECONCILE_RESULTS`]): a failure is reported by
/// its retry **class**, which is a fixed two-value set (`T05`), never by its message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileResult {
    /// The pass completed (a sync, a deliberate skip, or a preview).
    Success,
    /// The pass failed and will be retried with backoff.
    Retryable,
    /// The pass failed and only a spec/configuration change can fix it.
    Terminal,
}

impl ReconcileResult {
    /// The label value. Always one of [`RECONCILE_RESULTS`].
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => RECONCILE_RESULTS[0],
            Self::Retryable => RECONCILE_RESULTS[1],
            Self::Terminal => RECONCILE_RESULTS[2],
        }
    }

    /// Classifies a completed reconcile.
    ///
    /// This is the **only** function that decides a `result` value, so the label can only ever be a
    /// member of the fixed set — the error's message never reaches a label.
    #[must_use]
    pub fn of<T>(result: &Result<T, ControllerError>) -> Self {
        match result {
            Ok(_) => Self::Success,
            Err(err) => match err.failure() {
                FailureClass::Retryable => Self::Retryable,
                FailureClass::Terminal => Self::Terminal,
            },
        }
    }
}

/// How the render cache answered a lookup.
///
/// The variants are the `outcome` label set ([`CACHE_OUTCOMES`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CacheOutcome {
    /// Served from the cache: no renderer subprocess ran.
    Hit,
    /// Rendered again.
    Miss,
}

impl CacheOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Hit => CACHE_OUTCOMES[0],
            Self::Miss => CACHE_OUTCOMES[1],
        }
    }
}

/// `result` label set (private, `&'static str` only).
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ResultLabels {
    result: &'static str,
}

impl ResultLabels {
    fn of(result: ReconcileResult) -> Self {
        Self {
            result: result.as_str(),
        }
    }
}

/// Outcome of one live `ferriscd-rbac-cm` policy reload (`T17.1`).
///
/// The variants are the fixed `outcome` label set ([`RBAC_RELOAD_OUTCOMES`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RbacReloadOutcome {
    /// A valid policy replaced the active snapshot.
    Ok,
    /// The ConfigMap update failed validation; the last known-good snapshot was retained.
    Error,
    /// The ConfigMap was deleted; the active snapshot transitioned to default-deny.
    Deleted,
}

impl RbacReloadOutcome {
    /// The label value. Always one of [`RBAC_RELOAD_OUTCOMES`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => RBAC_RELOAD_OUTCOMES[0],
            Self::Error => RBAC_RELOAD_OUTCOMES[1],
            Self::Deleted => RBAC_RELOAD_OUTCOMES[2],
        }
    }
}

/// `outcome` label set (private, `&'static str` only).
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct OutcomeLabels {
    outcome: &'static str,
}

impl OutcomeLabels {
    fn of(outcome: CacheOutcome) -> Self {
        Self {
            outcome: outcome.as_str(),
        }
    }

    fn of_rbac_reload(outcome: RbacReloadOutcome) -> Self {
        Self {
            outcome: outcome.as_str(),
        }
    }
}

/// `app_namespace`/`app_name`/`status` label set.
///
/// The two identity labels are the object's own `metadata.namespace`/`metadata.name` — the
/// roadmap's requirement, bounded by the number of `Application`s — while `status` is a
/// `&'static str` produced only by [`sync_status_label`]/[`health_status_label`].
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct AppStatusLabels {
    app_namespace: String,
    app_name: String,
    status: &'static str,
}

/// The fixed label value of one [`SyncStatus`].
fn sync_status_label(status: SyncStatus) -> &'static str {
    match status {
        SyncStatus::Synced => SYNC_STATUS_VALUES[0],
        SyncStatus::OutOfSync => SYNC_STATUS_VALUES[1],
        SyncStatus::Unknown => SYNC_STATUS_VALUES[2],
    }
}

/// The fixed label value of one [`HealthStatus`].
fn health_status_label(status: HealthStatus) -> &'static str {
    match status {
        HealthStatus::Healthy => HEALTH_STATUS_VALUES[0],
        HealthStatus::Progressing => HEALTH_STATUS_VALUES[1],
        HealthStatus::Degraded => HEALTH_STATUS_VALUES[2],
        HealthStatus::Suspended => HEALTH_STATUS_VALUES[3],
        HealthStatus::Missing => HEALTH_STATUS_VALUES[4],
        HealthStatus::Unknown => HEALTH_STATUS_VALUES[5],
    }
}

/// Highest render-cache counter values already turned into Prometheus increments.
#[derive(Debug, Default)]
struct RenderCacheSeen {
    hits: u64,
    misses: u64,
}

/// The process's Prometheus registry and its seven families.
///
/// Cheap to clone (`Arc` inside), so the reconcile loop, the status writer, the pipeline and the
/// listener all share one registry. Recording touches only atomics; the registry lock is taken by
/// [`Metrics::encode`] alone.
#[derive(Clone)]
pub struct Metrics {
    registry: Arc<Mutex<Registry>>,
    reconcile_duration: Family<ResultLabels, Histogram>,
    reconcile_total: Family<ResultLabels, Counter>,
    app_sync_status: Family<AppStatusLabels, Gauge>,
    app_health_status: Family<AppStatusLabels, Gauge>,
    git_fetch_duration: Histogram,
    render_cache_total: Family<OutcomeLabels, Counter>,
    active_reconciles: Gauge,
    rbac_reload_total: Family<OutcomeLabels, Counter>,
    render_cache_seen: Arc<Mutex<RenderCacheSeen>>,
}

impl std::fmt::Debug for Metrics {
    /// Registration names and the live gauge only: the registry's contents are never printed (they
    /// carry every `Application` identity, which a log line does not need).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Metrics")
            .field("families", &FAMILY_DESCRIPTIONS)
            .field("active_reconciles", &self.active_reconciles.get())
            .finish_non_exhaustive()
    }
}

/// `(family, type)` of everything [`Metrics::new`] registers, for `Debug` and the docs.
///
/// **Advisory only:** it is hand-maintained documentation of the registry, not the source of truth
/// — the registration in [`Metrics::new`] and the `T15.1` tests are. A family added there without a
/// row here does not break anything (and is caught by the tests), it just reads as an omission.
const FAMILY_DESCRIPTIONS: [(&str, &str); 8] = [
    (RECONCILE_DURATION_SECONDS, "histogram"),
    (RECONCILE_TOTAL, "counter"),
    (APP_SYNC_STATUS, "gauge"),
    (APP_HEALTH_STATUS, "gauge"),
    (GIT_FETCH_DURATION_SECONDS, "histogram"),
    (RENDER_CACHE_TOTAL, "counter"),
    (ACTIVE_RECONCILES, "gauge"),
    (RBAC_RELOAD_TOTAL, "counter"),
];

/// Builds a latency histogram (same buckets for reconcile and Git fetch).
fn latency_histogram() -> Histogram {
    Histogram::new(exponential_buckets(
        BUCKET_START_SECONDS,
        BUCKET_FACTOR,
        BUCKET_COUNT,
    ))
}

impl Metrics {
    /// Creates a registry with every `T15.1` / `T17.1` family registered.
    #[must_use]
    pub fn new() -> Self {
        let reconcile_duration =
            Family::<ResultLabels, Histogram>::new_with_constructor(latency_histogram);
        let reconcile_total = Family::<ResultLabels, Counter>::default();
        let app_sync_status = Family::<AppStatusLabels, Gauge>::default();
        let app_health_status = Family::<AppStatusLabels, Gauge>::default();
        let git_fetch_duration = latency_histogram();
        let render_cache_total = Family::<OutcomeLabels, Counter>::default();
        let active_reconciles = Gauge::default();
        let rbac_reload_total = Family::<OutcomeLabels, Counter>::default();

        let mut registry = Registry::default();
        registry.register(
            RECONCILE_DURATION_SECONDS,
            "Wall-clock duration of one Application reconcile, by result",
            reconcile_duration.clone(),
        );
        registry.register(
            RECONCILE_COUNTER,
            "Application reconciles completed, by result",
            reconcile_total.clone(),
        );
        registry.register(
            APP_SYNC_STATUS,
            "Application sync status (1 for the current status, 0 for the others)",
            app_sync_status.clone(),
        );
        registry.register(
            APP_HEALTH_STATUS,
            "Application health status (1 for the current status, 0 for the others)",
            app_health_status.clone(),
        );
        registry.register(
            GIT_FETCH_DURATION_SECONDS,
            "Wall-clock duration of the Git resolve/checkout of one Application",
            git_fetch_duration.clone(),
        );
        registry.register(
            RENDER_CACHE_COUNTER,
            "Render cache lookups, by outcome",
            render_cache_total.clone(),
        );
        registry.register(
            ACTIVE_RECONCILES,
            "Application reconciles in flight",
            active_reconciles.clone(),
        );
        registry.register(
            RBAC_RELOAD_COUNTER,
            "Live ferriscd-rbac-cm policy reload attempts, by outcome",
            rbac_reload_total.clone(),
        );

        Self {
            registry: Arc::new(Mutex::new(registry)),
            reconcile_duration,
            reconcile_total,
            app_sync_status,
            app_health_status,
            git_fetch_duration,
            render_cache_total,
            active_reconciles,
            rbac_reload_total,
            render_cache_seen: Arc::new(Mutex::new(RenderCacheSeen::default())),
        }
    }

    /// Creates a registry whose fixed label sets are already **instantiated**.
    ///
    /// Every family built from a fixed set is created with a zero series up front
    /// (`result=success|retryable|terminal`, `outcome=hit|miss`), because `prometheus-client` only
    /// emits a family's `# HELP`/`# TYPE` header once it has at least one series. Without this a
    /// freshly started replica would expose no `ferriscd_reconcile_total` at all until its first
    /// reconcile — a missing series, not a zero — which breaks recording rules and "is it down?"
    /// alerts for exactly as long as the controller has not reconciled yet.
    ///
    /// The per-`Application` gauges are **not** pre-created: an `Application` that has never been
    /// reconciled has no series, and inventing one would report a status nobody observed.
    #[must_use]
    pub fn with_fixed_series() -> Self {
        let metrics = Self::new();
        for result in [
            ReconcileResult::Success,
            ReconcileResult::Retryable,
            ReconcileResult::Terminal,
        ] {
            let labels = ResultLabels::of(result);
            // Creating the child is what makes the family encode its `# HELP`/`# TYPE` block; no
            // observation is recorded, so `_count` still means "reconciles that ran".
            metrics.reconcile_duration.get_or_create_owned(&labels);
            metrics.reconcile_total.get_or_create_owned(&labels);
        }
        for outcome in [CacheOutcome::Hit, CacheOutcome::Miss] {
            metrics
                .render_cache_total
                .get_or_create_owned(&OutcomeLabels::of(outcome));
        }
        for outcome in [
            RbacReloadOutcome::Ok,
            RbacReloadOutcome::Error,
            RbacReloadOutcome::Deleted,
        ] {
            metrics
                .rbac_reload_total
                .get_or_create_owned(&OutcomeLabels::of_rbac_reload(outcome));
        }
        metrics
    }

    /// Records one live `ferriscd-rbac-cm` policy reload outcome (`T17.1`).
    pub fn record_rbac_reload(&self, outcome: RbacReloadOutcome) {
        self.rbac_reload_total
            .get_or_create_owned(&OutcomeLabels::of_rbac_reload(outcome))
            .inc();
    }

    /// Marks a reconcile as started and returns the guard that ends it.
    ///
    /// The guard increments [`ACTIVE_RECONCILES`] now and decrements it on drop, so a pass that is
    /// cancelled or that unwinds cannot leak the gauge; [`ReconcileGuard::finish`] records the
    /// duration and the `result` label.
    #[must_use]
    pub fn start_reconcile(&self) -> ReconcileGuard {
        self.active_reconciles.inc();
        ReconcileGuard {
            metrics: self.clone(),
            started: Instant::now(),
        }
    }

    /// Records the sync/health status a pass persisted (`None` fields are left untouched).
    ///
    /// Every value of the fixed set is written (`1` for the current one, `0` for the rest), so an
    /// `Application` that moves `OutOfSync -> Synced` does not leave a stale `1` behind and the
    /// series count stays `apps × statuses`.
    pub fn record_app_status(
        &self,
        app_namespace: &str,
        app_name: &str,
        status: &ApplicationStatus,
    ) {
        if let Some(sync) = status.sync.as_ref() {
            let current = sync_status_label(sync.status);
            for candidate in SYNC_STATUS_VALUES {
                let labels = AppStatusLabels {
                    app_namespace: app_namespace.to_owned(),
                    app_name: app_name.to_owned(),
                    status: candidate,
                };
                let gauge = self.app_sync_status.get_or_create_owned(&labels);
                gauge.set(if candidate == current { 1 } else { 0 });
            }
        }
        if let Some(health) = status.health.as_ref() {
            let current = health_status_label(health.status);
            for candidate in HEALTH_STATUS_VALUES {
                let labels = AppStatusLabels {
                    app_namespace: app_namespace.to_owned(),
                    app_name: app_name.to_owned(),
                    status: candidate,
                };
                let gauge = self.app_health_status.get_or_create_owned(&labels);
                gauge.set(if candidate == current { 1 } else { 0 });
            }
        }
    }

    /// Drops every gauge series of one `Application`.
    ///
    /// Called when an `Application` is deleted (`CleanupDisposition::Release`): the object is gone,
    /// so its `ferriscd_app_sync_status`/`ferriscd_app_health_status` series would otherwise stay in
    /// the exposition forever, reporting a status nobody can act on and slowly growing the registry
    /// (the cardinality trap `T15.1` exists to avoid). Families with no series left simply stop
    /// being exposed, exactly as before the first `Application` was observed.
    pub fn remove_app(&self, app_namespace: &str, app_name: &str) {
        for (family, statuses) in [
            (&self.app_sync_status, SYNC_STATUS_VALUES.as_slice()),
            (&self.app_health_status, HEALTH_STATUS_VALUES.as_slice()),
        ] {
            for status in statuses {
                family.remove(&AppStatusLabels {
                    app_namespace: app_namespace.to_owned(),
                    app_name: app_name.to_owned(),
                    status,
                });
            }
        }
    }

    /// Records one Git resolve/checkout duration in seconds.
    pub fn record_git_fetch(&self, duration: Duration) {
        self.git_fetch_duration.observe(duration.as_secs_f64());
    }

    /// Bridges the engine's cumulative [`RenderCache`](ferriscd_engine::manifest::RenderCache)
    /// counters into the Prometheus counter.
    ///
    /// The cache owns the counters (`hits`/`misses` since process start) and is sampled after each
    /// render; only the increase since the last sample is added, so the bridge is a delta and
    /// sampling the same snapshot twice adds nothing. Concurrent passes cannot double count: the
    /// snapshot keeps the **maximum** value seen, and a stale sample simply yields a zero delta.
    pub fn record_render_cache(&self, stats: RenderCacheStats) {
        let (hits, misses) = {
            let mut seen = self
                .render_cache_seen
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let hits = stats.hits.saturating_sub(seen.hits);
            let misses = stats.misses.saturating_sub(seen.misses);
            seen.hits = seen.hits.max(stats.hits);
            seen.misses = seen.misses.max(stats.misses);
            (hits, misses)
        };
        if hits > 0 {
            self.render_cache_total
                .get_or_create_owned(&OutcomeLabels::of(CacheOutcome::Hit))
                .inc_by(hits);
        }
        if misses > 0 {
            self.render_cache_total
                .get_or_create_owned(&OutcomeLabels::of(CacheOutcome::Miss))
                .inc_by(misses);
        }
    }

    /// Encodes the registry in the Prometheus text (0.0.4) exposition format.
    ///
    /// # Errors
    ///
    /// [`MetricsEncodeError`] when the encoder fails (a formatting error inside the registry).
    pub fn encode(&self) -> Result<String, MetricsEncodeError> {
        let registry = self.registry.lock().unwrap_or_else(PoisonError::into_inner);
        let mut body = String::new();
        // The **classic** 0.0.4 encoder (not the OpenMetrics one): it is the format every Prometheus
        // scrapes without a feature flag, and it spells a counter's `# HELP`/`# TYPE` with the full
        // `_total` name — so the exposition reads `# TYPE ferriscd_reconcile_total counter` and
        // `ferriscd_reconcile_total 1` for the family the roadmap names.
        prometheus_client::encoding::prometheus_text::encode(&mut body, &registry).map_err(
            |err| MetricsEncodeError::Encode {
                message: err.to_string(),
            },
        )?;
        Ok(body)
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// One in-flight reconcile, reported on drop.
#[derive(Debug)]
pub struct ReconcileGuard {
    metrics: Metrics,
    started: Instant,
}

impl ReconcileGuard {
    /// Records the duration and the `result` label, then releases [`ACTIVE_RECONCILES`].
    pub fn finish(self, result: ReconcileResult) {
        let elapsed = self.started.elapsed();
        self.metrics
            .reconcile_duration
            .get_or_create_owned(&ResultLabels::of(result))
            .observe(elapsed.as_secs_f64());
        self.metrics
            .reconcile_total
            .get_or_create_owned(&ResultLabels::of(result))
            .inc();
        // The active gauge is released by `Drop`, which still runs here.
    }
}

impl Drop for ReconcileGuard {
    fn drop(&mut self) {
        self.metrics.active_reconciles.dec();
    }
}

/// Errors raised while encoding the registry.
#[derive(Debug, thiserror::Error)]
pub enum MetricsEncodeError {
    /// The text encoder failed.
    #[error("the metrics registry could not be encoded: {message}")]
    Encode {
        /// The encoder's message (a formatting error; it never contains a metric value).
        message: String,
    },
}

/// [`StatusWriter`] decorator that records the status a pass persisted.
///
/// It wraps the real writer instead of re-deriving the outcome, because the *persisted* status is
/// the one an operator sees: a pass that failed still patches `/status` (the always-update-status
/// contract, trap T3), and the gauges must follow the same path.
pub struct MetricsStatusWriter {
    inner: Arc<dyn StatusWriter>,
    metrics: Metrics,
}

impl MetricsStatusWriter {
    /// Wraps `inner` so every successful `/status` patch updates the gauges.
    #[must_use]
    pub fn new(inner: Arc<dyn StatusWriter>, metrics: Metrics) -> Self {
        Self { inner, metrics }
    }
}

impl std::fmt::Debug for MetricsStatusWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The wrapped writer is a `dyn` seam that need not be `Debug`; nothing here is secret.
        f.debug_struct("MetricsStatusWriter")
            .finish_non_exhaustive()
    }
}

impl StatusWriter for MetricsStatusWriter {
    fn patch<'a>(
        &'a self,
        app: &'a Application,
        status: ApplicationStatus,
    ) -> BoxFuture<'a, Result<(), ReconcileError>> {
        async move {
            let namespace = app.namespace().unwrap_or_default();
            let name = app.name_any();
            // Recorded only after the patch landed: the gauges describe persisted state, not an
            // attempt the API server rejected.
            self.inner.patch(app, status.clone()).await?;
            self.metrics.record_app_status(&namespace, &name, &status);
            Ok(())
        }
        .boxed()
    }

    /// Drops the gauges of an `Application` that is being deleted.
    ///
    /// The removal rides on the same decorator as the recording, so a controller without metrics
    /// (the default [`StatusWriter`] impl) keeps the deletion path unchanged.
    fn forget_app(&self, app: &Application) {
        self.metrics
            .remove_app(&app.namespace().unwrap_or_default(), &app.name_any());
    }
}

// ---------------------------------------------------------------------------
// The listener
// ---------------------------------------------------------------------------

/// Why the metrics listener stopped.
#[derive(Debug, thiserror::Error)]
pub enum MetricsServeError {
    /// The listener could not bind (port in use, no permission, bad address).
    #[error("failed to bind the metrics listener to {addr}: {source}")]
    Bind {
        /// The address that was requested.
        addr: String,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },

    /// The server stopped with an I/O error.
    #[error("the metrics listener failed: {source}")]
    Serve {
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
}

/// Binds the metrics listener without serving it.
///
/// Binding during startup (rather than on the first scrape) turns "`--metrics-addr` is in use" into
/// a startup failure instead of a controller that reconciles while nothing can be scraped.
///
/// # Errors
///
/// [`MetricsServeError::Bind`] when the address is unusable.
pub async fn bind(addr: SocketAddr) -> Result<tokio::net::TcpListener, MetricsServeError> {
    tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|source| MetricsServeError::Bind {
            addr: addr.to_string(),
            source,
        })
}

/// Serves the metrics router on an already-bound listener until `shutdown` resolves.
///
/// Split out so the caller can bind first (fail fast, and read the real address back — `:0` is how
/// the tests scrape a real ephemeral port).
///
/// # Errors
///
/// [`MetricsServeError::Serve`] when the accept loop fails.
pub async fn serve_listener<F>(
    listener: tokio::net::TcpListener,
    metrics: Metrics,
    shutdown: F,
) -> Result<(), MetricsServeError>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let local = listener
        .local_addr()
        .map_or_else(|_| "<unknown>".to_owned(), |addr| addr.to_string());
    tracing::info!(
        addr = %local,
        path = METRICS_PATH,
        "metrics listener ready (low-cardinality Prometheus exposition on its own port)"
    );
    axum::serve(listener, router(metrics))
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|source| MetricsServeError::Serve { source })
}

/// Builds the `/metrics` router (a `GET`-only endpoint; every other path is a `404`).
pub fn router(metrics: Metrics) -> Router {
    Router::new()
        .route(METRICS_PATH, get(scrape))
        .with_state(metrics)
}

/// The scrape handler: encodes the registry off the async workers and answers `text/plain`.
async fn scrape(State(metrics): State<Metrics>) -> Response {
    // Encoding walks every series (a few hundred) under the registry lock: short, but it is CPU
    // work with a `std` lock, so it belongs on the blocking pool rather than a Tokio worker.
    match tokio::task::spawn_blocking(move || metrics.encode()).await {
        Ok(Ok(body)) => ([(header::CONTENT_TYPE, CONTENT_TYPE)], body).into_response(),
        Ok(Err(err)) => {
            tracing::error!(error = %err, "the metrics registry could not be encoded");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "the metrics registry could not be encoded\n",
            )
                .into_response()
        }
        Err(err) => {
            tracing::error!(error = %err, "the metrics encoder task failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "the metrics registry could not be encoded\n",
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Test support
// ---------------------------------------------------------------------------

/// Parser for the exposition format, shared by the `T15.1` tests in every module so a label
/// assertion is made against *parsed* series instead of a hand-spelled line (which would silently
/// pass if the encoder reordered labels).
#[cfg(test)]
pub(crate) mod exposition {
    use std::collections::{BTreeMap, BTreeSet};

    /// One exposed series.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct Sample {
        /// Full sample name (`ferriscd_reconcile_total`, `…_bucket`, …).
        pub(crate) name: String,
        /// Labels, unescaped.
        pub(crate) labels: BTreeMap<String, String>,
        /// The encoded value, verbatim (a float, so it is compared as text).
        pub(crate) value: String,
    }

    impl Sample {
        /// The family this sample belongs to: historically a counter appends `_total` and a
        /// histogram appends `_bucket`/`_sum`/`_count`, so both are stripped.
        pub(crate) fn family(&self) -> &str {
            let name = self.name.as_str();
            for suffix in ["_bucket", "_sum", "_count"] {
                if let Some(stripped) = name.strip_suffix(suffix) {
                    return stripped;
                }
            }
            name
        }

        /// Returns the value of `label`, if the series has it.
        pub(crate) fn label(&self, label: &str) -> Option<&str> {
            self.labels.get(label).map(String::as_str)
        }
    }

    /// Splits a body into its sample lines, ignoring `# HELP`/`# TYPE` comments.
    pub(crate) fn parse(body: &str) -> Vec<Sample> {
        body.lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(parse_line)
            .collect()
    }

    /// Parses `name{k="v",k2="v2"} value` (and the label-less `name value`).
    fn parse_line(line: &str) -> Sample {
        let (head, value) = match line.rsplit_once(' ') {
            Some((head, value)) => (head, value),
            None => (line, ""),
        };
        let (name, rest) = match head.split_once('{') {
            Some((name, rest)) => (name, Some(rest)),
            None => (head, None),
        };
        let mut labels = BTreeMap::new();
        if let Some(rest) = rest {
            let inner = rest.strip_suffix('}').unwrap_or(rest);
            for pair in split_pairs(inner) {
                let (key, raw) = pair
                    .split_once('=')
                    .unwrap_or_else(|| panic!("not a label pair: {pair:?} in {line:?}"));
                labels.insert(key.to_owned(), unescape(raw.trim_matches('"')));
            }
        }
        Sample {
            name: name.to_owned(),
            labels,
            value: value.to_owned(),
        }
    }

    /// Splits `a="1",b="2"` on commas that are not inside a quoted value.
    fn split_pairs(inner: &str) -> Vec<&str> {
        let mut pairs = Vec::new();
        let mut start = 0;
        let mut quoted = false;
        let mut escaped = false;
        for (index, byte) in inner.bytes().enumerate() {
            if escaped {
                escaped = false;
                continue;
            }
            match byte {
                b'\\' if quoted => escaped = true,
                b'"' => quoted = !quoted,
                b',' if !quoted => {
                    pairs.push(&inner[start..index]);
                    start = index + 1;
                }
                _ => {}
            }
        }
        if start < inner.len() {
            pairs.push(&inner[start..]);
        }
        pairs.retain(|pair| !pair.trim().is_empty());
        pairs
    }

    /// Reverses the encoder's `\\`, `\"` and `\n` escapes.
    fn unescape(raw: &str) -> String {
        let mut out = String::with_capacity(raw.len());
        let mut chars = raw.chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match chars.next() {
                Some('n') => out.push('\n'),
                Some(other) => out.push(other),
                None => out.push('\\'),
            }
        }
        out
    }

    /// Every sample of `family` (a counter's family is its `_total` name; a histogram's is its
    /// name without `_bucket`/`_sum`/`_count`).
    pub(crate) fn samples_of<'a>(samples: &'a [Sample], family: &str) -> Vec<&'a Sample> {
        samples
            .iter()
            .filter(|sample| sample.family() == family)
            .collect()
    }

    /// The sample with the **exact** name `name` whose labels contain every `(name, value)` pair.
    ///
    /// Exact names (not families) so a histogram's `_bucket`/`_sum`/`_count` series can be
    /// asserted individually instead of whichever one happens to come first.
    pub(crate) fn find<'a>(
        samples: &'a [Sample],
        name: &str,
        labels: &[(&str, &str)],
    ) -> Option<&'a Sample> {
        samples
            .iter()
            .filter(|sample| sample.name == name)
            .find(|sample| {
                labels
                    .iter()
                    .all(|(key, value)| sample.label(key) == Some(*value))
            })
    }

    /// The value of [`find`], panicking with the whole exposition when the series is missing.
    pub(crate) fn value_of(
        samples: &[Sample],
        name: &str,
        labels: &[(&str, &str)],
        body: &str,
    ) -> String {
        match find(samples, name, labels) {
            Some(sample) => sample.value.clone(),
            None => panic!("no series {name} with labels {labels:?} in:\n{body}"),
        }
    }

    /// `family -> the set of label names it exposes`.
    pub(crate) fn label_names(samples: &[Sample]) -> BTreeMap<String, BTreeSet<String>> {
        let mut families: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for sample in samples {
            let names = families.entry(sample.family().to_owned()).or_default();
            for name in sample.labels.keys() {
                names.insert(name.clone());
            }
        }
        families
    }

    /// `family -> the set of values exposed under `label`.
    pub(crate) fn label_values(samples: &[Sample], family: &str, label: &str) -> BTreeSet<String> {
        samples_of(samples, family)
            .into_iter()
            .filter_map(|sample| sample.label(label).map(str::to_owned))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use ferriscd_crd::Application;
    use ferriscd_crd::status::{HealthState, SyncState};

    use super::exposition::{self, Sample};
    use super::*;

    /// The `_count` series of a histogram (one per observation).
    fn count_series(histogram: &str) -> String {
        format!("{histogram}_count")
    }

    /// A body of the form `# HELP`/`# TYPE`/samples for `family`.
    fn scrape(metrics: &Metrics) -> (String, Vec<Sample>) {
        let body = metrics.encode().expect("the registry encodes");
        let samples = exposition::parse(&body);
        (body, samples)
    }

    fn status(sync: SyncStatus, health: HealthStatus) -> ApplicationStatus {
        ApplicationStatus {
            sync: Some(SyncState::new(sync, Some("deadbeef".to_owned()))),
            health: Some(HealthState::new(health)),
            ..ApplicationStatus::default()
        }
    }

    /// **Verification bullet:** the endpoint answers over a real socket, the exposition carries
    /// every required family with its help and type, and the content type is the classic 0.0.4
    /// format.
    #[tokio::test]
    async fn the_http_endpoint_serves_every_family_with_help_and_type() {
        // The fixed families exist from startup; the per-`Application` ones appear once a pass has
        // observed an `Application` (a status nobody observed must not be invented).
        let metrics = Metrics::with_fixed_series();
        metrics.record_app_status(
            "ferriscd-system",
            "demo",
            &status(SyncStatus::Synced, HealthStatus::Healthy),
        );
        let listener = bind("127.0.0.1:0".parse().expect("a loopback address"))
            .await
            .expect("an ephemeral port");
        let addr = listener.local_addr().expect("the bound address");
        let stop = tokio_util::sync::CancellationToken::new();
        let server = tokio::spawn(serve_listener(
            listener,
            metrics.clone(),
            stop.clone().cancelled_owned(),
        ));

        let response = http_get(addr, METRICS_PATH).await;
        assert_eq!(response.status, 200, "{}", response.body);
        assert!(
            response
                .content_type
                .as_deref()
                .is_some_and(|value| value.starts_with("text/plain; version=0.0.4")),
            "the exposition must be served as the classic text format: {:?}",
            response.content_type
        );

        for (family, kind) in [
            (RECONCILE_DURATION_SECONDS, "histogram"),
            (RECONCILE_TOTAL, "counter"),
            (APP_SYNC_STATUS, "gauge"),
            (APP_HEALTH_STATUS, "gauge"),
            (GIT_FETCH_DURATION_SECONDS, "histogram"),
            (RENDER_CACHE_TOTAL, "counter"),
            (ACTIVE_RECONCILES, "gauge"),
            (RBAC_RELOAD_TOTAL, "counter"),
        ] {
            assert!(
                response.body.contains(&format!("# HELP {family} ")),
                "{family} has no HELP line:\n{}",
                response.body
            );
            assert!(
                response.body.contains(&format!("# TYPE {family} {kind}\n")),
                "{family} is not declared a {kind}:\n{}",
                response.body
            );
        }
        assert!(
            !response.body.contains("# EOF"),
            "the classic 0.0.4 format has no EOF marker:\n{}",
            response.body
        );

        // Only `GET /metrics` is served: no other path, no other method.
        let missing = http_get(addr, "/api/v1/applications").await;
        assert_eq!(missing.status, 404, "{}", missing.body);
        let post = http_request(addr, "POST", METRICS_PATH).await;
        assert_eq!(post.status, 405, "{}", post.body);

        stop.cancel();
        server
            .await
            .expect("the server joins")
            .expect("no serve error");
    }

    /// The two per-`Application` families are created by the first observed status, never before:
    /// a gauge that "reports" an `Application` no pass has seen would be an invented observation.
    #[test]
    fn the_per_application_gauges_appear_once_an_application_is_observed() {
        let metrics = Metrics::with_fixed_series();
        let (before, samples) = scrape(&metrics);
        assert!(
            exposition::samples_of(&samples, APP_SYNC_STATUS).is_empty(),
            "no Application has been reconciled yet:\n{before}"
        );
        assert!(!before.contains(APP_HEALTH_STATUS), "{before}");

        metrics.record_app_status(
            "ferriscd-system",
            "demo",
            &status(SyncStatus::Unknown, HealthStatus::Unknown),
        );
        let (after, samples) = scrape(&metrics);
        assert!(
            after.contains(&format!("# TYPE {APP_SYNC_STATUS} gauge")),
            "{after}"
        );
        assert!(
            after.contains(&format!("# TYPE {APP_HEALTH_STATUS} gauge")),
            "{after}"
        );
        assert_eq!(exposition::samples_of(&samples, APP_SYNC_STATUS).len(), 3);
        assert_eq!(exposition::samples_of(&samples, APP_HEALTH_STATUS).len(), 6);
    }

    /// **Verification bullet:** after a (fake) reconcile the scraped values are the ones the pass
    /// produced — the in-flight gauge, the result counter/histogram, the two status gauges, the Git
    /// fetch histogram and the render-cache counter.
    #[tokio::test]
    async fn a_reconcile_is_visible_in_the_scraped_exposition() {
        let metrics = Metrics::new();
        let listener = bind("127.0.0.1:0".parse().expect("a loopback address"))
            .await
            .expect("an ephemeral port");
        let addr = listener.local_addr().expect("the bound address");
        let stop = tokio_util::sync::CancellationToken::new();
        let server = tokio::spawn(serve_listener(
            listener,
            metrics.clone(),
            stop.clone().cancelled_owned(),
        ));

        // In flight: the active gauge is 1 and nothing has been counted yet.
        let guard = metrics.start_reconcile();
        let in_flight = http_get(addr, METRICS_PATH).await.body;
        let parsed = exposition::parse(&in_flight);
        assert_eq!(
            exposition::value_of(&parsed, ACTIVE_RECONCILES, &[], &in_flight),
            "1"
        );
        assert!(
            exposition::find(&parsed, RECONCILE_TOTAL, &[("result", "success")]).is_none(),
            "a pass that has not finished must not be counted:\n{in_flight}"
        );

        // The pass finishes: exactly one `success` observation and an empty in-flight gauge.
        guard.finish(ReconcileResult::Success);
        metrics.record_app_status(
            "ferriscd-system",
            "demo",
            &status(SyncStatus::Synced, HealthStatus::Healthy),
        );
        metrics.record_git_fetch(Duration::from_millis(20));
        metrics.record_render_cache(RenderCacheStats {
            hits: 1,
            misses: 1,
            entries: 1,
            capacity: 128,
        });

        let body = http_get(addr, METRICS_PATH).await.body;
        let parsed = exposition::parse(&body);
        assert_eq!(
            exposition::value_of(&parsed, ACTIVE_RECONCILES, &[], &body),
            "0",
            "the in-flight gauge must return to zero:\n{body}"
        );
        assert_eq!(
            exposition::value_of(&parsed, RECONCILE_TOTAL, &[("result", "success")], &body),
            "1"
        );
        assert_eq!(
            exposition::value_of(
                &parsed,
                &count_series(RECONCILE_DURATION_SECONDS),
                &[("result", "success")],
                &body
            ),
            "1",
            "one observation in the histogram's `_count` series:\n{body}"
        );
        assert_eq!(
            exposition::value_of(
                &parsed,
                APP_SYNC_STATUS,
                &[
                    ("app_namespace", "ferriscd-system"),
                    ("app_name", "demo"),
                    ("status", "Synced"),
                ],
                &body
            ),
            "1"
        );
        assert_eq!(
            exposition::value_of(
                &parsed,
                APP_HEALTH_STATUS,
                &[
                    ("app_namespace", "ferriscd-system"),
                    ("app_name", "demo"),
                    ("status", "Healthy"),
                ],
                &body
            ),
            "1"
        );
        assert_eq!(
            exposition::value_of(
                &parsed,
                &count_series(GIT_FETCH_DURATION_SECONDS),
                &[],
                &body
            ),
            "1",
            "the Git fetch histogram counted one observation:\n{body}"
        );
        assert_eq!(
            exposition::value_of(&parsed, RENDER_CACHE_TOTAL, &[("outcome", "hit")], &body),
            "1"
        );
        assert_eq!(
            exposition::value_of(&parsed, RENDER_CACHE_TOTAL, &[("outcome", "miss")], &body),
            "1"
        );

        stop.cancel();
        server
            .await
            .expect("the server joins")
            .expect("no serve error");
    }

    /// **Trap guard:** the `result`/`status`/`outcome` values are the fixed sets and nothing else —
    /// every variant is exercised, and the union of the exposed values must equal the documented
    /// constant.
    #[test]
    fn the_label_values_come_from_fixed_sets() {
        let metrics = Metrics::new();
        for result in [
            ReconcileResult::Success,
            ReconcileResult::Retryable,
            ReconcileResult::Terminal,
        ] {
            metrics.start_reconcile().finish(result);
        }
        for sync in [
            SyncStatus::Synced,
            SyncStatus::OutOfSync,
            SyncStatus::Unknown,
        ] {
            for health in [
                HealthStatus::Healthy,
                HealthStatus::Progressing,
                HealthStatus::Degraded,
                HealthStatus::Suspended,
                HealthStatus::Missing,
                HealthStatus::Unknown,
            ] {
                metrics.record_app_status("ferriscd-system", "demo", &status(sync, health));
            }
        }
        metrics.record_render_cache(RenderCacheStats {
            hits: 1,
            misses: 0,
            entries: 1,
            capacity: 1,
        });
        metrics.record_render_cache(RenderCacheStats {
            hits: 1,
            misses: 1,
            entries: 1,
            capacity: 1,
        });

        let (body, samples) = scrape(&metrics);
        assert_eq!(
            exposition::label_values(&samples, RECONCILE_TOTAL, "result"),
            RECONCILE_RESULTS
                .iter()
                .map(|value| (*value).to_owned())
                .collect()
        );
        assert_eq!(
            exposition::label_values(&samples, APP_SYNC_STATUS, "status"),
            super::SYNC_STATUS_VALUES
                .iter()
                .map(|value| (*value).to_owned())
                .collect()
        );
        assert_eq!(
            exposition::label_values(&samples, APP_HEALTH_STATUS, "status"),
            super::HEALTH_STATUS_VALUES
                .iter()
                .map(|value| (*value).to_owned())
                .collect()
        );
        assert_eq!(
            exposition::label_values(&samples, RENDER_CACHE_TOTAL, "outcome"),
            CACHE_OUTCOMES
                .iter()
                .map(|value| (*value).to_owned())
                .collect()
        );

        // Every `result` series carries exactly one observation, and the sets are the documented
        // sizes: a new `result` value can only appear by changing the constant (and this test).
        for result in RECONCILE_RESULTS {
            assert_eq!(
                exposition::value_of(
                    &samples,
                    &count_series(RECONCILE_DURATION_SECONDS),
                    &[("result", result)],
                    &body
                ),
                "1",
                "{result}"
            );
        }
        assert_eq!(RECONCILE_RESULTS.len(), 3);
        assert_eq!(super::SYNC_STATUS_VALUES.len(), 3);
        assert_eq!(super::HEALTH_STATUS_VALUES.len(), 6);
        assert_eq!(CACHE_OUTCOMES.len(), 2);
    }

    /// **Trap guard (the cardinality half):** no family labels anything unbounded. The label
    /// *names* are asserted against an allow-list per family, so a `commit_sha`, `error_message`,
    /// `repo_url` or `resource` label cannot be added without failing here.
    #[test]
    fn no_family_labels_an_unbounded_value() {
        let metrics = Metrics::new();
        metrics.start_reconcile().finish(ReconcileResult::Retryable);
        metrics.record_app_status(
            "team-a",
            "payments",
            &status(SyncStatus::OutOfSync, HealthStatus::Degraded),
        );
        metrics.record_git_fetch(Duration::from_millis(5));
        metrics.record_render_cache(RenderCacheStats {
            hits: 2,
            misses: 3,
            entries: 1,
            capacity: 8,
        });

        metrics.record_rbac_reload(RbacReloadOutcome::Ok);
        metrics.record_rbac_reload(RbacReloadOutcome::Error);
        metrics.record_rbac_reload(RbacReloadOutcome::Deleted);

        let (body, samples) = scrape(&metrics);
        let families = exposition::label_names(&samples);
        let expected: [(&str, &[&str]); 8] = [
            (RECONCILE_DURATION_SECONDS, &["result", "le"]),
            (RECONCILE_TOTAL, &["result"]),
            (APP_SYNC_STATUS, &["app_namespace", "app_name", "status"]),
            (APP_HEALTH_STATUS, &["app_namespace", "app_name", "status"]),
            (GIT_FETCH_DURATION_SECONDS, &["le"]),
            (RENDER_CACHE_TOTAL, &["outcome"]),
            (ACTIVE_RECONCILES, &[]),
            (RBAC_RELOAD_TOTAL, &["outcome"]),
        ];
        assert_eq!(
            families.len(),
            expected.len(),
            "every family must be exercised: {families:?}\n{body}"
        );
        for (family, allowed) in expected {
            let actual = families
                .get(family)
                .unwrap_or_else(|| panic!("no series for {family}:\n{body}"));
            let actual: BTreeSet<&str> = actual.iter().map(String::as_str).collect();
            let expected: BTreeSet<&str> = allowed.iter().copied().collect();
            assert_eq!(
                actual, expected,
                "{family} exposes only bounded labels:\n{body}"
            );
        }

        // The forbidden ones are absent by construction; assert the *reason* explicitly, because
        // these are the four the roadmap names.
        for forbidden in [
            "commit_sha",
            "revision",
            "error",
            "error_message",
            "message",
            "url",
            "repo_url",
            "resource",
            "resource_name",
        ] {
            assert!(
                !families.values().any(|names| names.contains(forbidden)),
                "{forbidden} must never be a label:\n{body}"
            );
        }
    }

    /// **Trap guard (the injection half):** a hostile, absurdly long value cannot break out of its
    /// label — it is escaped by the encoder, so it can neither forge a metric line nor change the
    /// number of series. The only free-form labels are the `Application`'s own identity, which the
    /// API server bounds (`metadata.namespace`/`metadata.name`).
    #[test]
    fn a_hostile_label_value_is_escaped_and_cannot_forge_a_metric() {
        let metrics = Metrics::new();
        let hostile = format!(
            "evil\n{ACTIVE_RECONCILES} 999\n# TYPE forged counter\n{}",
            "x".repeat(4096)
        );
        metrics.record_app_status(
            "ferriscd-system",
            &hostile,
            &status(SyncStatus::Synced, HealthStatus::Healthy),
        );

        let (body, samples) = scrape(&metrics);
        // The forged line is not a line of its own: `parse` would have produced a series named
        // `ferriscd_active_reconciles` with the value 999.
        let forged = samples
            .iter()
            .filter(|sample| sample.name == ACTIVE_RECONCILES)
            .map(|sample| sample.value.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            forged,
            vec!["0".to_owned()],
            "a newline in a label value must not start a new sample:\n{body}"
        );
        assert_eq!(
            samples
                .iter()
                .filter(|sample| sample.name == "forged")
                .count(),
            0,
            "a label value must not be able to declare a family:\n{body}"
        );
        // The value survives, escaped, on its own line only.
        assert!(body.contains("\\n"), "the newline must be escaped:\n{body}");
        let hostile_series =
            exposition::find(&samples, APP_SYNC_STATUS, &[("app_name", hostile.as_str())]);
        assert!(
            hostile_series.is_some(),
            "the value round-trips as a single label:\n{body}"
        );
        // The series count is unchanged: three sync series for one application.
        assert_eq!(exposition::samples_of(&samples, APP_SYNC_STATUS).len(), 3);
    }

    /// **Trap guard (the growth half):** series are created per `Application`, never per reconcile.
    /// Fifty passes over two applications leave the same number of series as one pass.
    #[test]
    fn the_series_count_follows_applications_not_reconciles() {
        let metrics = Metrics::with_fixed_series();
        let record = |pass: usize| {
            metrics.start_reconcile().finish(if pass.is_multiple_of(2) {
                ReconcileResult::Success
            } else {
                ReconcileResult::Retryable
            });
            for app in ["payments", "billing"] {
                metrics.record_app_status(
                    "team-a",
                    app,
                    &status(
                        if pass.is_multiple_of(2) {
                            SyncStatus::Synced
                        } else {
                            SyncStatus::OutOfSync
                        },
                        HealthStatus::Progressing,
                    ),
                );
            }
        };

        record(0);
        let (_, first) = scrape(&metrics);
        let first_count = first.len();
        for pass in 1..50 {
            record(pass);
        }
        let (body, samples) = scrape(&metrics);

        assert_eq!(
            samples.len(),
            first_count,
            "50 reconciles of 2 applications must not create new series:\n{body}"
        );
        assert_eq!(
            exposition::samples_of(&samples, APP_SYNC_STATUS).len(),
            2 * 3
        );
        assert_eq!(
            exposition::samples_of(&samples, APP_HEALTH_STATUS).len(),
            2 * 6
        );
        assert_eq!(
            exposition::value_of(&samples, RECONCILE_TOTAL, &[("result", "success")], &body),
            "25"
        );
        assert_eq!(
            exposition::value_of(&samples, RECONCILE_TOTAL, &[("result", "retryable")], &body),
            "25"
        );
    }

    /// The gauges describe the *current* status: a transition zeroes the previous series instead of
    /// leaving a stale `1` behind, and the series count never grows for one application.
    #[test]
    fn a_status_transition_zeroes_the_previous_series() {
        let metrics = Metrics::new();
        metrics.record_app_status(
            "ferriscd-system",
            "demo",
            &status(SyncStatus::OutOfSync, HealthStatus::Degraded),
        );
        metrics.record_app_status(
            "ferriscd-system",
            "demo",
            &status(SyncStatus::Synced, HealthStatus::Healthy),
        );

        let (body, samples) = scrape(&metrics);
        let gauge = |family: &str, status: &str| {
            exposition::value_of(
                &samples,
                family,
                &[
                    ("app_namespace", "ferriscd-system"),
                    ("app_name", "demo"),
                    ("status", status),
                ],
                &body,
            )
        };
        assert_eq!(gauge(APP_SYNC_STATUS, "Synced"), "1");
        assert_eq!(gauge(APP_SYNC_STATUS, "OutOfSync"), "0", "{body}");
        assert_eq!(gauge(APP_HEALTH_STATUS, "Healthy"), "1");
        assert_eq!(gauge(APP_HEALTH_STATUS, "Degraded"), "0", "{body}");
        assert_eq!(exposition::samples_of(&samples, APP_SYNC_STATUS).len(), 3);
        assert_eq!(exposition::samples_of(&samples, APP_HEALTH_STATUS).len(), 6);
    }

    /// **Verification bullet (render cache):** the bridge adds only the *increase* of the engine's
    /// own counters, so sampling the same snapshot twice adds nothing and a stale sample cannot
    /// double count or go backwards.
    #[test]
    fn the_render_cache_bridge_counts_each_lookup_once() {
        let metrics = Metrics::new();
        let stats = |hits, misses| RenderCacheStats {
            hits,
            misses,
            entries: 1,
            capacity: 8,
        };

        metrics.record_render_cache(stats(3, 2));
        let (body, samples) = scrape(&metrics);
        assert_eq!(
            exposition::value_of(&samples, RENDER_CACHE_TOTAL, &[("outcome", "hit")], &body),
            "3"
        );
        assert_eq!(
            exposition::value_of(&samples, RENDER_CACHE_TOTAL, &[("outcome", "miss")], &body),
            "2"
        );

        // The same snapshot again: already counted.
        metrics.record_render_cache(stats(3, 2));
        // A stale (out-of-order) snapshot: no negative delta, no loss.
        metrics.record_render_cache(stats(1, 0));
        // Growth: only the delta is added.
        metrics.record_render_cache(stats(5, 4));

        let (body, samples) = scrape(&metrics);
        assert_eq!(
            exposition::value_of(&samples, RENDER_CACHE_TOTAL, &[("outcome", "hit")], &body),
            "5",
            "3 + 0 + 0 + 2:\n{body}"
        );
        assert_eq!(
            exposition::value_of(&samples, RENDER_CACHE_TOTAL, &[("outcome", "miss")], &body),
            "4",
            "2 + 0 + 0 + 2:\n{body}"
        );
    }

    /// The `result` label is the retry classification of the error, never its message.
    #[test]
    fn the_result_label_is_the_failure_class() {
        let retryable = ControllerError::from_reconcile(ReconcileError::Discovery(
            crate::discovery::DiscoveryError::Refresh {
                message: "error_message=connection reset by peer".to_owned(),
            },
        ));
        let terminal = ControllerError::from_reconcile(ReconcileError::Invalid {
            message: "commit_sha=deadbeef is not a valid repo".to_owned(),
        });
        assert_eq!(
            ReconcileResult::of(&Err::<(), _>(retryable)).as_str(),
            "retryable"
        );
        assert_eq!(
            ReconcileResult::of(&Err::<(), _>(terminal)).as_str(),
            "terminal"
        );
        assert_eq!(
            ReconcileResult::of(&Ok::<(), ControllerError>(())).as_str(),
            "success"
        );

        // The error's text never reaches a label.
        let metrics = Metrics::new();
        metrics
            .start_reconcile()
            .finish(ReconcileResult::of(&Err::<(), _>(
                ControllerError::from_reconcile(ReconcileError::Invalid {
                    message: "error_message=secret-token leaked".to_owned(),
                }),
            )));
        let body = metrics.encode().expect("encodes");
        assert!(!body.contains("secret-token"), "{body}");
        assert!(!body.contains("error_message"), "{body}");
        assert!(
            body.contains("ferriscd_reconcile_total{result=\"terminal\"} 1"),
            "{body}"
        );
    }

    /// The guard releases the in-flight gauge on drop, so a cancelled reconcile cannot leak it.
    #[test]
    fn a_dropped_reconcile_releases_the_active_gauge_without_counting() {
        let metrics = Metrics::new();
        {
            let _guard = metrics.start_reconcile();
        }
        let (body, samples) = scrape(&metrics);
        assert_eq!(
            exposition::value_of(&samples, ACTIVE_RECONCILES, &[], &body),
            "0"
        );
        assert!(
            exposition::samples_of(&samples, RECONCILE_TOTAL).is_empty(),
            "an abandoned pass is not a completed reconcile:\n{body}"
        );
    }

    /// **Deletion:** a released `Application` takes its gauges with it, and removing the last one
    /// drops the family entirely (nothing left to report).
    #[test]
    fn a_deleted_application_takes_its_gauges_with_it() {
        let metrics = Metrics::with_fixed_series();
        metrics.record_app_status(
            "ferriscd-system",
            "gone",
            &status(SyncStatus::Synced, HealthStatus::Healthy),
        );
        metrics.record_app_status(
            "ferriscd-system",
            "kept",
            &status(SyncStatus::OutOfSync, HealthStatus::Degraded),
        );

        metrics.remove_app("ferriscd-system", "gone");
        let (body, samples) = scrape(&metrics);
        for family in [APP_SYNC_STATUS, APP_HEALTH_STATUS] {
            assert!(
                exposition::find(&samples, family, &[("app_name", "gone")]).is_none(),
                "a deleted Application must not keep a {family} series:\n{body}"
            );
            assert!(
                exposition::find(&samples, family, &[("app_name", "kept")]).is_some(),
                "another Application's series must survive:\n{body}"
            );
        }
        assert_eq!(exposition::samples_of(&samples, APP_SYNC_STATUS).len(), 3);
        assert_eq!(exposition::samples_of(&samples, APP_HEALTH_STATUS).len(), 6);

        // Idempotent: forgetting an Application nobody observed is not an error.
        metrics.remove_app("ferriscd-system", "never-seen");

        metrics.remove_app("ferriscd-system", "kept");
        let (body, samples) = scrape(&metrics);
        assert!(
            exposition::samples_of(&samples, APP_SYNC_STATUS).is_empty(),
            "the last deletion must drop the family:\n{body}"
        );
        assert!(exposition::samples_of(&samples, APP_HEALTH_STATUS).is_empty());
    }

    /// `with_fixed_series` instantiates exactly the fixed families' series, so a freshly started
    /// replica exposes them (and only them) before its first reconcile.
    #[test]
    fn with_fixed_series_instantiates_every_fixed_label_set() {
        let (body, samples) = scrape(&Metrics::with_fixed_series());
        let families: BTreeSet<&str> = samples.iter().map(Sample::family).collect();
        let expected: BTreeSet<&str> = [
            RECONCILE_DURATION_SECONDS,
            RECONCILE_TOTAL,
            GIT_FETCH_DURATION_SECONDS,
            RENDER_CACHE_TOTAL,
            ACTIVE_RECONCILES,
            RBAC_RELOAD_TOTAL,
        ]
        .into_iter()
        .collect();
        assert_eq!(
            families, expected,
            "the fixed series, and no per-Application one:\n{body}"
        );
        assert_eq!(
            exposition::label_values(&samples, RBAC_RELOAD_TOTAL, "outcome"),
            RBAC_RELOAD_OUTCOMES
                .iter()
                .map(|value| (*value).to_owned())
                .collect()
        );
        assert_eq!(
            exposition::label_values(&samples, RECONCILE_TOTAL, "result"),
            RECONCILE_RESULTS
                .iter()
                .map(|value| (*value).to_owned())
                .collect()
        );
        assert_eq!(
            exposition::label_values(&samples, RENDER_CACHE_TOTAL, "outcome"),
            CACHE_OUTCOMES
                .iter()
                .map(|value| (*value).to_owned())
                .collect()
        );
        for sample in exposition::samples_of(&samples, RECONCILE_TOTAL) {
            assert_eq!(sample.value, "0", "{body}");
        }
    }

    /// **Startup failure:** a port that is already taken fails `bind` instead of leaving a working
    /// controller that can never be scraped.
    #[tokio::test]
    async fn an_occupied_port_fails_the_bind() {
        let held = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("an ephemeral port");
        let addr = held.local_addr().expect("the bound address");
        let error = bind(addr).await.expect_err("the port is already taken");
        assert!(
            matches!(error, MetricsServeError::Bind { .. }),
            "an occupied port must be a Bind error: {error:?}"
        );
        assert!(
            error.to_string().contains(&addr.to_string()),
            "the error must name the address it could not bind: {error}"
        );
    }

    /// The default listener address is the dedicated metrics port and is **not** the API port.
    #[test]
    fn the_default_address_is_the_dedicated_metrics_port() {
        let addr: SocketAddr = DEFAULT_METRICS_ADDR.parse().expect("a socket address");
        assert_eq!(addr.port(), 9090);
        assert_ne!(
            addr.port(),
            8080,
            "8080 is the API server's default port (`ferriscd_server::DEFAULT_API_ADDR`); the \
             scrape endpoint is never the API/webhook port"
        );
        assert_eq!(METRICS_ADDR_ENV, "FERRISCD_METRICS_ADDR");
        assert_eq!(METRICS_PATH, "/metrics");
    }

    /// Connecting to the metrics listener after shutdown fails: the socket really closed.
    #[tokio::test]
    async fn the_listener_stops_serving_after_shutdown() {
        let metrics = Metrics::new();
        let listener = bind("127.0.0.1:0".parse().expect("a loopback address"))
            .await
            .expect("an ephemeral port");
        let addr = listener.local_addr().expect("the bound address");
        let stop = tokio_util::sync::CancellationToken::new();
        let server = tokio::spawn(serve_listener(
            listener,
            metrics,
            stop.clone().cancelled_owned(),
        ));
        assert_eq!(http_get(addr, METRICS_PATH).await.status, 200);

        stop.cancel();
        server
            .await
            .expect("the server joins")
            .expect("no serve error");
        assert!(
            tokio::net::TcpStream::connect(addr).await.is_err(),
            "the listener socket must be closed after a graceful shutdown"
        );
    }

    /// Regression guard: the `MetricsStatusWriter` records only a `/status` that was **persisted**.
    #[tokio::test]
    async fn a_rejected_status_patch_is_not_recorded() {
        struct Failing;
        impl StatusWriter for Failing {
            fn patch<'a>(
                &'a self,
                _app: &'a Application,
                _status: ApplicationStatus,
            ) -> BoxFuture<'a, Result<(), ReconcileError>> {
                Box::pin(async {
                    Err(ReconcileError::Invalid {
                        message: "status subresource is not served".to_owned(),
                    })
                })
            }
        }

        let metrics = Metrics::new();
        let writer = MetricsStatusWriter::new(Arc::new(Failing), metrics.clone());
        let app: Application = serde_json::from_value(serde_json::json!({
            "apiVersion": "ferriscd.io/v1alpha1",
            "kind": "Application",
            "metadata": { "name": "demo", "namespace": "ferriscd-system" },
            "spec": {
                "project": "default",
                "source": { "git": { "repoURL": "https://example.com/demo.git", "path": "." } },
                "destination": { "namespace": "payments" }
            }
        }))
        .expect("a valid Application");
        assert!(
            writer
                .patch(&app, status(SyncStatus::Synced, HealthStatus::Healthy))
                .await
                .is_err()
        );

        let (body, samples) = scrape(&metrics);
        assert!(
            exposition::samples_of(&samples, APP_SYNC_STATUS).is_empty(),
            "a status the API server never stored must not become a gauge:\n{body}"
        );
    }

    /// A minimal HTTP/1.1 response, so the tests drive a real socket without an HTTP client
    /// dependency.
    #[derive(Debug)]
    struct HttpResponse {
        status: u16,
        content_type: Option<String>,
        body: String,
    }

    async fn http_get(addr: SocketAddr, path: &str) -> HttpResponse {
        http_request(addr, "GET", path).await
    }

    async fn http_request(addr: SocketAddr, method: &str, path: &str) -> HttpResponse {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect to the test listener");
        stream
            .write_all(
                format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .expect("write the request");
        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .await
            .expect("read the response");
        let text = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse::<u16>().ok())
            .expect("a status line");
        let content_type = head.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-type")
                .then(|| value.trim().to_owned())
        });
        HttpResponse {
            status,
            content_type,
            body: body.to_owned(),
        }
    }
}
