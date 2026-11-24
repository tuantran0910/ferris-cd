//! `kube_runtime::Controller` wiring: namespace scope, bounded concurrency, the composite
//! watch predicate, and the retry/backoff error policy.
//!
//! Notes on the shape of this module:
//!
//! * The controller watches **only** the control-plane namespace (`ferriscd-system` by
//!   default). Cluster-wide `Application` watches would turn every agent into a
//!   cluster-scoped informer and would break multi-tenant isolation.
//! * The watch stream is filtered *before* the controller sees it
//!   ([`crate::predicate`]), which is what makes a `/status`-only write cost zero
//!   reconciles. `Controller::for_stream` is the only kube 5.1 API that accepts a
//!   pre-filtered stream, hence the `unstable-runtime` feature on `kube`.
//! * Retries are classified by [`FailureClass`]: transient failures back off
//!   exponentially (5 s → 180 s), terminal failures wait a long fixed interval so a broken
//!   `Application` cannot spin the work queue.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferriscd_crd::Application;
use futures::StreamExt;
use kube::runtime::controller::{Action, Controller};
use kube::runtime::reflector;
use kube::runtime::{PredicateConfig, WatchStreamExt, watcher};
use kube::{Api, Client, ResourceExt};
use tokio::sync::Notify;

use crate::lock_recover;
use crate::predicate;
use crate::reconcile::{ControllerError, ReconcileContext, reconcile_instance};

/// Default number of concurrent reconciles.
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
    pub namespace: String,
    /// Maximum number of concurrent reconciles.
    pub concurrency: u16,
    /// How long in-flight reconciles may run after a shutdown signal.
    pub drain_timeout: Duration,
}

impl Default for ControllerConfig {
    fn default() -> Self {
        Self {
            namespace: ferriscd_crd::CONTROL_PLANE_NAMESPACE.to_owned(),
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
}

/// Configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The configured namespace is blank.
    #[error("{NAMESPACE_ENV} must not be empty")]
    EmptyNamespace,
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

/// Builds the `Application` controller for `config.namespace`.
///
/// The returned controller is not yet running: callers add shutdown triggers and then
/// [`Controller::run`].
#[must_use]
pub fn build_controller(client: Client, config: &ControllerConfig) -> Controller<Application> {
    let api: Api<Application> = Api::namespaced(client, &config.namespace);
    let (reader, writer) = reflector::store();
    let stream = watcher(api, watcher::Config::default())
        .default_backoff()
        .reflect(writer)
        .applied_objects()
        // Filter *before* the controller schedules work: a status-only patch then costs
        // zero reconciles instead of one wasted pass per status write.
        .predicate_filter(predicate::predicate(), PredicateConfig::default());

    Controller::for_stream(stream, reader)
        .with_config(kube::runtime::controller::Config::default().concurrency(config.concurrency))
}

/// Runs the controller until `SIGINT`/`SIGTERM`, draining in-flight reconciles.
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
    let shutdown_observed = Arc::new(Notify::new());

    let notify_on_signal = shutdown_observed.clone();
    let controller = build_controller(client, &config).graceful_shutdown_on(async move {
        let reason = crate::shutdown_signal().await;
        tracing::info!(
            signal = reason.as_str(),
            "graceful shutdown requested; draining in-flight reconciles"
        );
        notify_on_signal.notify_one();
    });

    tracing::info!(
        namespace = %config.namespace,
        concurrency = config.concurrency,
        finalizer = crate::reconcile::FINALIZER,
        "application controller started"
    );

    let mut stream = std::pin::pin!(controller.run(reconcile_instance, error_policy, ctx));
    let drain = async {
        while let Some(result) = stream.next().await {
            match result {
                Ok((object, _action)) => {
                    tracing::debug!(
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

    let shutdown = async move {
        shutdown_observed.notified().await;
    };
    crate::await_drained(drain, shutdown, drain_timeout).await
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
}
