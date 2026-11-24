//! FerrisCD Kubernetes controller runtime: reconciliation loop, watch predicates,
//! dynamic discovery cache, finalizer lifecycle, and graceful shutdown.

use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

use ferriscd_crd::Application;
use kube::{Api, Client, ResourceExt};

pub mod controller;
pub mod discovery;
pub mod live_state;
pub mod predicate;
pub mod reconcile;
pub mod scope;
pub mod sync;

pub use controller::{
    BackoffTracker, ConfigError, ControllerConfig, DEFAULT_CONCURRENCY, DEFAULT_DRAIN_TIMEOUT,
    FailureClass, RETRY_BASE_DELAY, RETRY_MAX_DELAY, TERMINAL_DELAY,
};
pub use discovery::{CachedDiscovery, DiscoveryCache, DiscoveryError, ScopeLookup};
pub use live_state::{
    ClusterStateReader, DynamicApiSource, FetchRequest, LiveObjectSource, LiveState,
    LiveStateError, TrackingOwner,
};
pub use predicate::{ApplicationPredicate, PredicateTracker, composite_hash};
pub use reconcile::{
    ApiStatusWriter, ApplyOutcome, CleanupDisposition, CleanupMode, CleanupOutcome,
    ControllerError, FINALIZER, ReconcileContext, ReconcileError, StatusWriter, SyncPipeline,
};
pub use scope::{ClusterNamespacePolicy, InBundleCrd, ScopeError, normalize_scopes};
pub use sync::{
    Applier, ApplyRequest, DeleteOutcome, DeleteRequest, DynamicApiApplier, InventorySyncPipeline,
    PENDING_REQUEUE,
};

/// Environment variable selecting the log format (`json` or `pretty`).
pub const LOG_FORMAT_ENV: &str = "FERRISCD_LOG_FORMAT";

/// Returns the controller identifier string.
#[must_use]
pub fn controller_name() -> &'static str {
    ferriscd_engine::default_field_manager()
}

/// Runtime options for [`run_with`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunOptions {
    /// Namespace whose `Application` objects this controller owns.
    ///
    /// `None` falls back to `FERRISCD_NAMESPACE`, then `ferriscd-system`.
    pub namespace: Option<String>,

    /// Accept `file://` URLs and local filesystem paths as Git sources.
    ///
    /// Off by default: production only allows `https://`/`ssh://`/SCP-style remotes, so an
    /// `Application` can never read the controller pod's filesystem. Tests and local `kind`
    /// demos must opt in explicitly (see `docs/lessons/06-inventory-tracking-and-live-state.md`).
    pub allow_local_repos: bool,

    /// Directory holding the Git mirror cache and materialized worktrees.
    ///
    /// `None` uses `<system temp dir>/ferriscd-repos`. In a cluster this should be an
    /// `emptyDir` mounted by the Deployment.
    pub work_root: Option<std::path::PathBuf>,
}

/// Runs the controller loop entrypoint with default [`RunOptions`].
///
/// # Errors
///
/// See [`run_with`].
pub async fn run() -> anyhow::Result<()> {
    run_with(RunOptions::default()).await
}

/// Runs the `v0.2` controller: watch `Application` objects, resolve Git, render manifests,
/// normalize scopes, read live state, apply with SSA and persist a crash-safe inventory.
///
/// # Errors
///
/// Fails when the log format is invalid, the namespace configuration is invalid, the
/// Kubernetes client cannot be configured, or in-flight reconciles outlive the drain timeout.
pub async fn run_with(options: RunOptions) -> anyhow::Result<()> {
    use anyhow::Context as _;

    let log_format = init_logging()?;
    tracing::info!(
        controller = controller_name(),
        api_group = ferriscd_crd::api_group(),
        log_format = log_format.as_str(),
        allow_local_repos = options.allow_local_repos,
        "ferriscd-controller starting"
    );

    let namespace_value = match options.namespace.as_deref() {
        Some(namespace) => Some(namespace.to_owned()),
        None => std::env::var(controller::NAMESPACE_ENV).ok(),
    };
    let config = ControllerConfig {
        namespace: controller::namespace_from_env_value(namespace_value.as_deref())?,
        ..ControllerConfig::default()
    };
    let client = Client::try_default()
        .await
        .context("failed to initialize the Kubernetes client from kubeconfig/in-cluster config")?;

    let apps_api = Api::<Application>::namespaced(client.clone(), &config.namespace);
    let status = Arc::new(ApiStatusWriter::new(apps_api.clone()));

    // Git: one scratch root backs both the gix worktrees and the repo cache, so publishing a
    // checkout is a same-filesystem atomic rename.
    let work_root = options
        .work_root
        .clone()
        .unwrap_or_else(std::env::temp_dir)
        .join("ferriscd-repos");
    let url_policy = if options.allow_local_repos {
        tracing::warn!(
            "allowing local and file:// Git repositories (--allow-local-repos); never use this \
             in production"
        );
        ferriscd_engine::repo::RepoUrlPolicy::AllowLocal
    } else {
        ferriscd_engine::repo::RepoUrlPolicy::Production
    };
    let git = ferriscd_engine::repo::GixGitClient::new(
        ferriscd_engine::repo::GixGitClientConfig::new()
            .with_url_policy(url_policy)
            .with_work_root(&work_root),
    );
    let repos = Arc::new(ferriscd_engine::repo::RepoCache::new(
        Arc::new(git),
        ferriscd_engine::repo::RepoCacheConfig::new(&work_root),
    ));

    let pipeline = Arc::new(
        sync::InventorySyncPipeline::new(
            repos,
            DiscoveryCache::new(client.clone()),
            Arc::new(DynamicApiSource::new(client.clone())),
            Arc::new(DynamicApiApplier::new(client.clone())),
        )
        .with_url_policy(url_policy),
    );
    let ctx = Arc::new(ReconcileContext::new(apps_api, pipeline, status));

    controller::run(client, config, ctx).await?;
    Ok(())
}

/// Creates the `reconcile` span carrying the application identity.
#[must_use]
pub fn reconcile_span(app: &Application) -> tracing::Span {
    tracing::info_span!(
        "reconcile",
        "app.namespace" = %app.namespace().unwrap_or_default(),
        "app.name" = %app.name_any(),
        "app.generation" = app.metadata.generation.unwrap_or_default(),
    )
}

/// Locks `mutex`, recovering from poisoning instead of panicking.
///
/// A panicking test or a poisoned status buffer must never take the controller down: the
/// guarded data here is bookkeeping (counters, indices) that stays usable.
pub(crate) fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Reads `lock`, recovering from poisoning instead of panicking.
pub(crate) fn read_recover<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(PoisonError::into_inner)
}

/// Writes `lock`, recovering from poisoning instead of panicking.
pub(crate) fn write_recover<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

/// How the controller was asked to stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    /// `SIGINT` / Ctrl+C.
    Interrupt,
    /// `SIGTERM` (Kubernetes pod termination).
    Terminate,
}

impl ShutdownReason {
    /// Stable label for logs.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Interrupt => "SIGINT",
            Self::Terminate => "SIGTERM",
        }
    }
}

/// Errors raised while shutting the controller down.
#[derive(Debug, thiserror::Error)]
pub enum ShutdownError {
    /// In-flight reconciles did not finish inside the drain window.
    ///
    /// Reported as a failure on purpose: a status patch or an apply that was abandoned
    /// mid-flight must not look like a clean shutdown.
    #[error("controller drain timed out after {timeout:?}; in-flight reconciles were abandoned")]
    DrainTimeout {
        /// The configured drain window.
        timeout: Duration,
    },
}

/// Resolves when the process receives `SIGINT` (Ctrl+C) or `SIGTERM`.
///
/// Feed this into `Controller::graceful_shutdown_on`.
pub async fn shutdown_signal() -> ShutdownReason {
    first_of(interrupt_signal(), terminate_signal()).await
}

async fn interrupt_signal() -> ShutdownReason {
    if tokio::signal::ctrl_c().await.is_err() {
        tracing::warn!("failed to listen for SIGINT; only SIGTERM will trigger shutdown");
        std::future::pending::<()>().await;
    }
    ShutdownReason::Interrupt
}

#[cfg(unix)]
async fn terminate_signal() -> ShutdownReason {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut signal) => {
            signal.recv().await;
            ShutdownReason::Terminate
        }
        Err(err) => {
            tracing::warn!(error = %err, "failed to listen for SIGTERM");
            std::future::pending::<()>().await;
            ShutdownReason::Terminate
        }
    }
}

#[cfg(not(unix))]
async fn terminate_signal() -> ShutdownReason {
    std::future::pending::<()>().await;
    ShutdownReason::Terminate
}

/// Awaits whichever signal future completes first.
async fn first_of<A, B>(interrupt: A, terminate: B) -> ShutdownReason
where
    A: Future<Output = ShutdownReason>,
    B: Future<Output = ShutdownReason>,
{
    tokio::select! {
        reason = interrupt => reason,
        reason = terminate => reason,
    }
}

/// Runs `run` to completion, allowing at most `drain_timeout` once `shutdown` resolves.
///
/// # Errors
///
/// [`ShutdownError::DrainTimeout`] when `run` is still pending after the drain window —
/// the caller must exit non-zero so the abandoned work is visible.
pub async fn await_drained<F, S, R>(
    run: F,
    shutdown: S,
    drain_timeout: Duration,
) -> Result<R, ShutdownError>
where
    F: Future<Output = R>,
    S: Future<Output = ()>,
{
    let mut run = std::pin::pin!(run);
    let mut shutdown = std::pin::pin!(shutdown);
    tokio::select! {
        result = &mut run => Ok(result),
        () = &mut shutdown => {
            tracing::info!(
                drain_timeout_seconds = drain_timeout.as_secs(),
                "shutdown signal observed; draining in-flight reconciles"
            );
            match tokio::time::timeout(drain_timeout, run).await {
                Ok(result) => Ok(result),
                Err(_) => Err(ShutdownError::DrainTimeout {
                    timeout: drain_timeout,
                }),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Log format
// ---------------------------------------------------------------------------

/// Structured log format selected by [`LOG_FORMAT_ENV`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable, multi-line output (default).
    #[default]
    Pretty,
    /// One JSON object per line, for log aggregation.
    Json,
}

impl LogFormat {
    /// Parses an explicit `FERRISCD_LOG_FORMAT` value.
    ///
    /// `json` selects [`LogFormat::Json`]; `pretty`, `text`, and `plain` select
    /// [`LogFormat::Pretty`]. Matching is case-insensitive and surrounding whitespace is
    /// ignored.
    ///
    /// # Errors
    ///
    /// [`LogFormatError::Unknown`] for any other value: a typo must not silently fall back
    /// to the wrong format.
    pub fn parse(value: &str) -> Result<Self, LogFormatError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "pretty" | "text" | "plain" => Ok(Self::Pretty),
            other => Err(LogFormatError::Unknown {
                value: other.to_owned(),
            }),
        }
    }

    /// Stable label used in logs and configuration errors.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pretty => "pretty",
            Self::Json => "json",
        }
    }

    /// Returns whether JSON output was requested.
    #[must_use]
    pub fn is_json(self) -> bool {
        matches!(self, Self::Json)
    }
}

/// Log-format parsing errors.
#[derive(Debug, thiserror::Error)]
pub enum LogFormatError {
    /// The value is not a known format.
    #[error("unknown {LOG_FORMAT_ENV} value {value:?}: expected one of json, pretty, text")]
    Unknown {
        /// The rejected value.
        value: String,
    },
}

/// Resolves [`LOG_FORMAT_ENV`] without touching the environment (testable).
///
/// An unset or blank variable means [`LogFormat::Pretty`].
///
/// # Errors
///
/// [`LogFormatError::Unknown`] for an unrecognized value.
pub fn log_format_from_env_value(value: Option<&str>) -> Result<LogFormat, LogFormatError> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        None => Ok(LogFormat::Pretty),
        Some(value) => LogFormat::parse(value),
    }
}

/// Reads [`LOG_FORMAT_ENV`] from the process environment.
///
/// # Errors
///
/// [`LogFormatError::Unknown`] for an unrecognized value.
pub fn log_format_from_env() -> Result<LogFormat, LogFormatError> {
    let value = std::env::var(LOG_FORMAT_ENV).ok();
    log_format_from_env_value(value.as_deref())
}

/// Installs the global tracing subscriber using [`LOG_FORMAT_ENV`] and `RUST_LOG`.
///
/// Called once from the binary; returning the selected format lets the caller log it.
///
/// # Errors
///
/// Fails for an unknown format or when a global subscriber is already installed.
pub fn init_logging() -> anyhow::Result<LogFormat> {
    let format = log_format_from_env()?;
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    let installed = match format {
        LogFormat::Json => builder.json().try_init(),
        LogFormat::Pretty => builder.try_init(),
    };
    installed.map_err(|err| anyhow::anyhow!("failed to install tracing subscriber: {err}"))?;
    Ok(format)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn controller_name_matches_field_manager() {
        assert_eq!(controller_name(), "ferriscd");
    }

    #[test]
    fn log_format_parsing_accepts_known_values_and_rejects_typos() {
        assert_eq!(LogFormat::parse(" JSON ").expect("json"), LogFormat::Json);
        assert_eq!(LogFormat::parse("text").expect("text"), LogFormat::Pretty);
        assert_eq!(LogFormat::parse("plain").expect("plain"), LogFormat::Pretty);
        assert!(LogFormat::parse("jsonl").is_err());
        assert_eq!(
            log_format_from_env_value(Some("   ")).expect("blank defaults"),
            LogFormat::Pretty
        );
        assert_eq!(
            log_format_from_env_value(None).expect("unset defaults"),
            LogFormat::Pretty
        );
    }

    #[tokio::test]
    async fn await_drained_returns_work_completed_before_shutdown() {
        let result = await_drained(
            async { 7_u8 },
            std::future::pending::<()>(),
            Duration::from_millis(10),
        )
        .await;
        assert!(matches!(result, Ok(7)));
    }

    #[tokio::test]
    async fn await_drained_times_out_on_stuck_work() {
        let result = await_drained(
            std::future::pending::<()>(),
            async {},
            Duration::from_millis(10),
        )
        .await;
        assert!(matches!(result, Err(ShutdownError::DrainTimeout { .. })));
    }

    #[tokio::test]
    async fn await_drained_finishes_work_that_completes_during_the_window() {
        let result = await_drained(
            async {
                tokio::time::sleep(Duration::from_millis(5)).await;
                9_u8
            },
            async {},
            Duration::from_millis(100),
        )
        .await;
        assert!(matches!(result, Ok(9)));
    }
}
