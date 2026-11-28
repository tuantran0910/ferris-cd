//! Rate-limited Kubernetes Events on `Application` resources (`T15.2`).
//!
//! # Why deduplication sits **in front of** `kube::runtime::events::Recorder`
//!
//! `kube::runtime::events::Recorder` keeps a 6-minute in-memory cache of `EventKey`s, but on a
//! cache hit it **still issues a `Patch::Merge` against `events.k8s.io/v1`** to bump
//! `series.count`. A persistently failing `Application` reconciling every 30 s would therefore
//! still hammer the API server and `etcd` on every retry.
//!
//! [`EventRecorder`] sits **in front of** [`EventPublisher`] (which wraps `Recorder` in
//! production) and enforces the `T15.2` trap guard before any API call is attempted:
//!
//! * Identical consecutive `Warning` reasons for the same `(app_namespace, app_name)` are
//!   suppressed within a configurable window (default [`DEFAULT_WARNING_DEDUP_WINDOW`] = 5 min).
//! * A `Normal SyncSucceeded` event clears the consecutive warning state for that `Application`, so
//!   a brand-new failure after recovery emits immediately.
//! * A different `Warning` reason for the same `Application` emits immediately and replaces the
//!   active consecutive warning record.
//! * The tracking table is strictly bounded ([`DEFAULT_MAX_TRACKED_APPS`]), evicting expired then
//!   oldest entries when full, and [`EventRecorder::forget_app`] drops deleted `Application`s
//!   immediately so memory cannot grow unboundedly.
//! * Every event `note` is redacted (base64/secret runs and embedded URL credentials) and truncated
//!   to Kubernetes's 1 KiB (`1024`-byte) `events.k8s.io/v1` limit on a UTF-8 character boundary.
//! * Publishing is strictly **best-effort**: API or RBAC failures are logged at `warn!` and never
//!   abort or fail reconciliation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferriscd_crd::Application;
use ferriscd_engine::manifest::ResourceKey;
use futures::future::BoxFuture;
use kube::runtime::events::{Event as KubeEvent, EventType as KubeEventType, Recorder, Reporter};
use kube::{Client, Resource as _, ResourceExt as _};

use crate::lock_recover;
use crate::reconcile::redact_payloads;
use crate::telemetry::redact_urls_in_text;

/// `Normal` event reason emitted when a sync execution settles cleanly.
pub const EVENT_REASON_SYNC_SUCCEEDED: &str = "SyncSucceeded";

/// `Normal` event reason emitted when orphaned resources are pruned.
pub const EVENT_REASON_RESOURCE_PRUNED: &str = "ResourcePruned";

/// `Warning` event reason emitted when a reconcile or sync pass fails.
pub const EVENT_REASON_SYNC_FAILED: &str = "SyncFailed";

/// Kubernetes Event `action` for sync lifecycle events.
pub const EVENT_ACTION_SYNC: &str = "Sync";

/// Kubernetes Event `action` for prune events.
pub const EVENT_ACTION_PRUNE: &str = "Prune";

/// Default suppression window for identical consecutive `Warning` reasons per `Application` (5 min).
pub const DEFAULT_WARNING_DEDUP_WINDOW: Duration = Duration::from_secs(300);

/// Default upper bound on tracked `Application`s in the warning deduplication table.
pub const DEFAULT_MAX_TRACKED_APPS: usize = 4_096;

/// Kubernetes `events.k8s.io/v1` maximum `note` length (1 KiB).
pub const MAX_EVENT_NOTE_BYTES: usize = 1024;

/// Kubernetes `events.k8s.io/v1` maximum `reason` length (128 characters).
pub const MAX_EVENT_REASON_CHARS: usize = 128;

/// Kubernetes `events.k8s.io/v1` maximum `action` length (128 characters).
pub const MAX_EVENT_ACTION_CHARS: usize = 128;

/// Maximum individual GKNN keys listed verbatim in a `ResourcePruned` event note before
/// summarizing the remainder as `(+N more)`.
const MAX_PRUNED_KEYS_IN_NOTE: usize = 8;

/// Monotonic clock seam for [`EventRecorder`] so deduplication tests never call `sleep`.
pub trait EventClock: Send + Sync + 'static {
    /// Returns the current monotonic instant.
    fn now(&self) -> Instant;
}

/// Production [`EventClock`] backed by [`Instant::now`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl EventClock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Event severity mirroring `kube::runtime::events::EventType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppEventType {
    /// Informational lifecycle transition (`SyncSucceeded`, `ResourcePruned`).
    Normal,
    /// Failure or degraded condition (`SyncFailed`).
    Warning,
}

impl From<AppEventType> for KubeEventType {
    fn from(value: AppEventType) -> Self {
        match value {
            AppEventType::Normal => Self::Normal,
            AppEventType::Warning => Self::Warning,
        }
    }
}

/// Structured, sanitized Kubernetes Event targeting an `Application`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppEvent {
    /// Event severity (`Normal` or `Warning`).
    pub type_: AppEventType,
    /// Short `PascalCase` reason (`<= 128` chars).
    pub reason: String,
    /// Short `PascalCase` action (`<= 128` chars).
    pub action: String,
    /// Redacted, UTF-8-bounded message (`<= 1024` bytes).
    pub note: String,
    /// Target `Application` namespace.
    pub app_namespace: String,
    /// Target `Application` name.
    pub app_name: String,
}

impl AppEvent {
    /// Builds a sanitized [`AppEvent`] for `app`.
    #[must_use]
    pub fn new(
        app: &Application,
        type_: AppEventType,
        reason: impl AsRef<str>,
        action: impl AsRef<str>,
        note: impl AsRef<str>,
    ) -> Self {
        Self {
            type_,
            reason: truncate_chars(reason.as_ref(), MAX_EVENT_REASON_CHARS),
            action: truncate_chars(action.as_ref(), MAX_EVENT_ACTION_CHARS),
            note: sanitize_note(note.as_ref()),
            app_namespace: app.namespace().unwrap_or_default(),
            app_name: app.name_any(),
        }
    }

    /// Builds a `Normal SyncSucceeded` event.
    #[must_use]
    pub fn sync_succeeded(app: &Application, message: &str) -> Self {
        Self::new(
            app,
            AppEventType::Normal,
            EVENT_REASON_SYNC_SUCCEEDED,
            EVENT_ACTION_SYNC,
            message,
        )
    }

    /// Builds a `Normal ResourcePruned` event summarizing pruned GKNN keys (never secret data).
    #[must_use]
    pub fn resource_pruned(app: &Application, pruned: &[ResourceKey]) -> Self {
        let count = pruned.len();
        let shown: Vec<String> = pruned
            .iter()
            .take(MAX_PRUNED_KEYS_IN_NOTE)
            .map(ResourceKey::canonical)
            .collect();
        let note = if count > MAX_PRUNED_KEYS_IN_NOTE {
            format!(
                "pruned {count} resource(s): {} (+{} more)",
                shown.join(", "),
                count - MAX_PRUNED_KEYS_IN_NOTE
            )
        } else {
            format!("pruned {count} resource(s): {}", shown.join(", "))
        };
        Self::new(
            app,
            AppEventType::Normal,
            EVENT_REASON_RESOURCE_PRUNED,
            EVENT_ACTION_PRUNE,
            note,
        )
    }

    /// Builds a `Warning SyncFailed` event with a redacted, bounded note.
    #[must_use]
    pub fn sync_failed(app: &Application, failure_reason: &str, detail: &str) -> Self {
        let note = if detail.trim().is_empty() {
            failure_reason.to_owned()
        } else {
            format!("{failure_reason}: {detail}")
        };
        Self::new(
            app,
            AppEventType::Warning,
            EVENT_REASON_SYNC_FAILED,
            EVENT_ACTION_SYNC,
            note,
        )
    }
}

/// Errors raised while publishing a Kubernetes Event.
///
/// These are always caught and logged at `warn!` by [`EventRecorder`]; an event publishing error
/// never fails reconciliation.
#[derive(Debug, thiserror::Error)]
pub enum EventError {
    /// Kubernetes `events.k8s.io/v1` API error (e.g., RBAC `403`, rate limit `429`, transport).
    #[error("kubernetes events API error: {0}")]
    Api(#[from] kube::Error),

    /// Custom or test publisher failure.
    #[error("event publish failed: {message}")]
    Publish {
        /// Secret-free diagnostic message.
        message: String,
    },
}

/// Low-level Kubernetes Event publishing seam.
///
/// Abstracted behind a trait so the rate-limiter and the full reconcile/sync pipeline are 100%
/// unit-testable without a cluster.
pub trait EventPublisher: Send + Sync + 'static {
    /// Publishes `event` attached to `app`.
    fn publish<'a>(
        &'a self,
        app: &'a Application,
        event: &'a AppEvent,
    ) -> BoxFuture<'a, Result<(), EventError>>;
}

/// Production [`EventPublisher`] backed by [`kube::runtime::events::Recorder`].
#[derive(Clone)]
pub struct KubeEventPublisher {
    recorder: Recorder,
    controller: String,
}

impl std::fmt::Debug for KubeEventPublisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubeEventPublisher")
            .field("controller", &self.controller)
            .finish_non_exhaustive()
    }
}

impl KubeEventPublisher {
    /// Builds a publisher reporting as the FerrisCD controller (with `HOSTNAME` as instance when
    /// present).
    #[must_use]
    pub fn new(client: Client) -> Self {
        let controller = crate::controller_name().to_owned();
        let instance = std::env::var("HOSTNAME")
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        let reporter = Reporter {
            controller: controller.clone(),
            instance,
        };
        Self::with_reporter(client, reporter)
    }

    /// Builds a publisher with an explicit `kube::runtime::events::Reporter`.
    #[must_use]
    pub fn with_reporter(client: Client, reporter: Reporter) -> Self {
        let controller = reporter.controller.clone();
        Self {
            recorder: Recorder::new(client, reporter),
            controller,
        }
    }
}

impl EventPublisher for KubeEventPublisher {
    fn publish<'a>(
        &'a self,
        app: &'a Application,
        event: &'a AppEvent,
    ) -> BoxFuture<'a, Result<(), EventError>> {
        Box::pin(async move {
            let reference = app.object_ref(&());
            let kube_event = KubeEvent {
                type_: event.type_.into(),
                reason: event.reason.clone(),
                note: Some(event.note.clone()),
                action: event.action.clone(),
                secondary: None,
            };
            self.recorder.publish(&kube_event, &reference).await?;
            Ok(())
        })
    }
}

/// No-op [`EventPublisher`] used by default in library/test contexts without a cluster.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopEventPublisher;

impl EventPublisher for NoopEventPublisher {
    fn publish<'a>(
        &'a self,
        _app: &'a Application,
        _event: &'a AppEvent,
    ) -> BoxFuture<'a, Result<(), EventError>> {
        Box::pin(async { Ok(()) })
    }
}

/// In-memory [`EventPublisher`] for hermetic unit and pipeline tests.
#[derive(Debug, Default)]
pub struct RecordingEventPublisher {
    events: Mutex<Vec<AppEvent>>,
    fail_with: Mutex<Option<String>>,
}

impl RecordingEventPublisher {
    /// Creates an empty recorder that succeeds on every publish.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a publisher that fails every publish with `message` (to prove best-effort
    /// observability never aborts reconciliation).
    #[must_use]
    pub fn failing(message: impl Into<String>) -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            fail_with: Mutex::new(Some(message.into())),
        }
    }

    /// Returns a snapshot of every published event, in emission order.
    #[must_use]
    pub fn events(&self) -> Vec<AppEvent> {
        lock_recover(&self.events).clone()
    }

    /// Clears recorded events.
    pub fn clear(&self) {
        lock_recover(&self.events).clear();
    }
}

impl EventPublisher for RecordingEventPublisher {
    fn publish<'a>(
        &'a self,
        _app: &'a Application,
        event: &'a AppEvent,
    ) -> BoxFuture<'a, Result<(), EventError>> {
        Box::pin(async move {
            if let Some(message) = lock_recover(&self.fail_with).clone() {
                return Err(EventError::Publish { message });
            }
            lock_recover(&self.events).push(event.clone());
            Ok(())
        })
    }
}

/// Result of attempting to emit a single event through [`EventRecorder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitOutcome {
    /// Passed the deduplication gate and was published successfully.
    Emitted,
    /// Suppressed as an identical consecutive `Warning` within the deduplication window.
    Deduplicated,
    /// Passed the gate, but publishing failed (logged at `warn!`; reconciliation continues).
    Failed,
}

/// Deduplication record for the most recent consecutive `Warning` emitted for one `Application`.
#[derive(Debug, Clone)]
struct WarningRecord {
    reason: String,
    last_emitted: Instant,
    suppressed: u64,
    seq: u64,
}

/// Internal gate decision returned by [`EventRecorder::decide_emit`].
enum EmitDecision {
    Emit,
    Suppress { suppressed: u64 },
}

#[derive(Debug, Default)]
struct DedupState {
    entries: HashMap<(String, String), WarningRecord>,
    next_seq: u64,
}

/// Rate-limited, deduplicating Kubernetes Event recorder (`T15.2`).
///
/// Cheap to clone (`Arc` inside) so the controller loop shares one deduplication table across all
/// concurrent reconciles.
#[derive(Clone)]
pub struct EventRecorder {
    publisher: Arc<dyn EventPublisher>,
    dedup_window: Duration,
    max_tracked_apps: usize,
    clock: Arc<dyn EventClock>,
    state: Arc<Mutex<DedupState>>,
}

impl std::fmt::Debug for EventRecorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tracked = lock_recover(&self.state).entries.len();
        f.debug_struct("EventRecorder")
            .field("dedup_window", &self.dedup_window)
            .field("max_tracked_apps", &self.max_tracked_apps)
            .field("tracked_apps", &tracked)
            .finish_non_exhaustive()
    }
}

impl EventRecorder {
    /// Builds a recorder around `publisher` with the default 5-minute warning deduplication window
    /// and bounded tracking table ([`DEFAULT_MAX_TRACKED_APPS`]).
    #[must_use]
    pub fn new(publisher: Arc<dyn EventPublisher>) -> Self {
        Self {
            publisher,
            dedup_window: DEFAULT_WARNING_DEDUP_WINDOW,
            max_tracked_apps: DEFAULT_MAX_TRACKED_APPS,
            clock: Arc::new(SystemClock),
            state: Arc::new(Mutex::new(DedupState::default())),
        }
    }

    /// Builds a production recorder backed by [`KubeEventPublisher`].
    #[must_use]
    pub fn for_client(client: Client) -> Self {
        Self::new(Arc::new(KubeEventPublisher::new(client)))
    }

    /// Builds a no-op recorder (default for library/test contexts without a cluster).
    #[must_use]
    pub fn noop() -> Self {
        Self::new(Arc::new(NoopEventPublisher))
    }

    /// Overrides the consecutive `Warning` deduplication window.
    #[must_use]
    pub fn with_dedup_window(mut self, window: Duration) -> Self {
        self.dedup_window = window;
        self
    }

    /// Overrides the maximum number of `Application`s tracked in the deduplication table.
    #[must_use]
    pub fn with_max_tracked_apps(mut self, max: usize) -> Self {
        self.max_tracked_apps = max;
        self
    }

    /// Injects a custom monotonic [`EventClock`] (used by tests to advance time without sleeping).
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn EventClock>) -> Self {
        self.clock = clock;
        self
    }

    /// Current number of `Application`s tracked in the warning deduplication table.
    #[must_use]
    pub fn tracked_apps(&self) -> usize {
        lock_recover(&self.state).entries.len()
    }

    /// Drops deduplication state for a deleted `Application`.
    pub fn forget_app(&self, app: &Application) {
        let key = app_key(app);
        lock_recover(&self.state).entries.remove(&key);
    }

    /// Emits `event` on `app` after applying the warning deduplication gate.
    ///
    /// Publishing errors are logged at `warn!` and **never** returned as `Err`: observability must
    /// never break reconciliation.
    pub async fn emit(&self, app: &Application, event: AppEvent) -> EmitOutcome {
        if let EmitDecision::Suppress { suppressed } = self.decide_emit(&event) {
            tracing::debug!(
                app.namespace = %event.app_namespace,
                app.name = %event.app_name,
                event.reason = %event.reason,
                suppressed_count = suppressed,
                dedup_window_seconds = self.dedup_window.as_secs(),
                "suppressing duplicate consecutive Warning event within deduplication window"
            );
            return EmitOutcome::Deduplicated;
        }

        match self.publisher.publish(app, &event).await {
            Ok(()) => EmitOutcome::Emitted,
            Err(err) => {
                tracing::warn!(
                    app.namespace = %event.app_namespace,
                    app.name = %event.app_name,
                    event.type = ?event.type_,
                    event.reason = %event.reason,
                    error = %err,
                    "failed to publish Kubernetes Event; continuing reconciliation"
                );
                EmitOutcome::Failed
            }
        }
    }

    /// Emits a `Normal SyncSucceeded` event on `app` (and clears any consecutive warning state).
    pub async fn emit_sync_succeeded(&self, app: &Application, message: &str) -> EmitOutcome {
        self.emit(app, AppEvent::sync_succeeded(app, message)).await
    }

    /// Emits a `Normal ResourcePruned` event summarizing `pruned` (no-op when `pruned` is empty).
    pub async fn emit_resource_pruned(
        &self,
        app: &Application,
        pruned: &[ResourceKey],
    ) -> Option<EmitOutcome> {
        if pruned.is_empty() {
            return None;
        }
        Some(self.emit(app, AppEvent::resource_pruned(app, pruned)).await)
    }

    /// Emits a rate-limited `Warning SyncFailed` event on `app`.
    pub async fn emit_sync_failed(
        &self,
        app: &Application,
        failure_reason: &str,
        detail: &str,
    ) -> EmitOutcome {
        self.emit(app, AppEvent::sync_failed(app, failure_reason, detail))
            .await
    }

    /// Applies the consecutive-warning deduplication gate and updates bounded tracking state.
    fn decide_emit(&self, event: &AppEvent) -> EmitDecision {
        let key = (event.app_namespace.clone(), event.app_name.clone());
        let mut state = lock_recover(&self.state);

        match event.type_ {
            AppEventType::Normal => {
                // Recovery resets consecutive warning tracking so a subsequent failure emits
                // immediately instead of being silenced by a stale window from before recovery.
                if event.reason == EVENT_REASON_SYNC_SUCCEEDED {
                    state.entries.remove(&key);
                }
                EmitDecision::Emit
            }
            AppEventType::Warning => {
                let now = self.clock.now();
                if let Some(existing) = state.entries.get_mut(&key)
                    && existing.reason == event.reason
                    && now.saturating_duration_since(existing.last_emitted) < self.dedup_window
                {
                    existing.suppressed = existing.suppressed.saturating_add(1);
                    return EmitDecision::Suppress {
                        suppressed: existing.suppressed,
                    };
                }

                if self.max_tracked_apps == 0 {
                    return EmitDecision::Emit;
                }

                // Enforce bounded memory before inserting a new key: first sweep expired entries,
                // then evict the oldest remaining record if still at capacity.
                if !state.entries.contains_key(&key) && state.entries.len() >= self.max_tracked_apps
                {
                    let window = self.dedup_window;
                    state.entries.retain(|_, record| {
                        now.saturating_duration_since(record.last_emitted) < window
                    });

                    while state.entries.len() >= self.max_tracked_apps {
                        let oldest = state
                            .entries
                            .iter()
                            .min_by_key(|(_, record)| (record.last_emitted, record.seq))
                            .map(|(entry_key, _)| entry_key.clone());
                        let Some(oldest_key) = oldest else {
                            break;
                        };
                        state.entries.remove(&oldest_key);
                    }
                }

                state.next_seq = state.next_seq.saturating_add(1);
                let seq = state.next_seq;
                state.entries.insert(
                    key,
                    WarningRecord {
                        reason: event.reason.clone(),
                        last_emitted: now,
                        suppressed: 0,
                        seq,
                    },
                );
                EmitDecision::Emit
            }
        }
    }
}

fn app_key(app: &Application) -> (String, String) {
    (app.namespace().unwrap_or_default(), app.name_any())
}

/// Redacts embedded secret payloads and URL credentials, then truncates to [`MAX_EVENT_NOTE_BYTES`]
/// (1 KiB) on a UTF-8 character boundary.
#[must_use]
pub fn sanitize_note(raw: &str) -> String {
    let urls_redacted = redact_urls_in_text(raw);
    let redacted = redact_payloads(&urls_redacted);
    truncate_utf8_bytes(&redacted, MAX_EVENT_NOTE_BYTES)
}

/// Truncates `text` so its UTF-8 byte length is at most `max_bytes`, appending `'…'` when
/// truncated.
#[must_use]
pub fn truncate_utf8_bytes(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    const ELLIPSIS: &str = "…";
    if max_bytes < ELLIPSIS.len() {
        // Too small even for an ellipsis; take whatever whole UTF-8 chars fit.
        let mut end = 0;
        for (idx, ch) in text.char_indices() {
            if idx + ch.len_utf8() > max_bytes {
                break;
            }
            end = idx + ch.len_utf8();
        }
        return text[..end].to_owned();
    }
    let budget = max_bytes - ELLIPSIS.len();
    let mut end = 0;
    for (idx, ch) in text.char_indices() {
        if idx + ch.len_utf8() > budget {
            break;
        }
        end = idx + ch.len_utf8();
    }
    let mut out = String::with_capacity(end + ELLIPSIS.len());
    out.push_str(&text[..end]);
    out.push_str(ELLIPSIS);
    out
}

/// Truncates `text` to at most `max_chars` Unicode scalar values.
fn truncate_chars(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_owned();
    }
    text.chars().take(max_chars).collect()
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use super::EventClock;
    use crate::lock_recover;

    /// Deterministic monotonic clock for zero-sleep deduplication tests.
    #[derive(Debug, Clone)]
    pub(crate) struct ManualClock {
        now: Arc<Mutex<Instant>>,
    }

    impl ManualClock {
        pub(crate) fn new() -> Self {
            Self {
                now: Arc::new(Mutex::new(Instant::now())),
            }
        }

        pub(crate) fn advance(&self, delta: Duration) {
            let mut guard = lock_recover(&self.now);
            *guard += delta;
        }
    }

    impl EventClock for ManualClock {
        fn now(&self) -> Instant {
            *lock_recover(&self.now)
        }
    }
}

#[cfg(test)]
mod tests {
    use ferriscd_crd::application::{
        DEFAULT_REQUEUE_AFTER_SECONDS, DEFAULT_REVISION_HISTORY_LIMIT,
    };
    use ferriscd_crd::{
        ApplicationSpec, DEFAULT_PROJECT_NAME, DestinationSpec, GitSourceSpec, RendererSpec,
        SourceSpec,
    };

    use super::test_support::ManualClock;
    use super::*;

    fn app(namespace: &str, name: &str) -> Application {
        let spec = ApplicationSpec {
            project: DEFAULT_PROJECT_NAME.to_owned(),
            service_account_name: None,
            source: Some(SourceSpec {
                git: Some(GitSourceSpec {
                    repo_url: "https://example.com/repo.git".to_owned(),
                    target_revision: "HEAD".to_owned(),
                    path: String::new(),
                }),
                oci: None,
                renderer: RendererSpec::default(),
            }),
            sources: Vec::new(),
            destination: DestinationSpec {
                cluster: "in-cluster".to_owned(),
                namespace: "payments".to_owned(),
            },
            sync_policy: None,
            ignore_differences: Vec::new(),
            requeue_after_seconds: DEFAULT_REQUEUE_AFTER_SECONDS,
            revision_history_limit: DEFAULT_REVISION_HISTORY_LIMIT,
        };
        let mut application = Application::new(name, spec);
        application.metadata.namespace = Some(namespace.to_owned());
        application
    }

    /// **`T15.2` Trap Guard:** repeated identical `Warning SyncFailed` for the same app within 5
    /// minutes emits only **1** event (zero spam); advancing the fake clock past 5 minutes emits
    /// again — with zero `tokio::time::sleep`.
    #[tokio::test]
    async fn identical_consecutive_warnings_are_deduplicated_within_five_minutes() {
        let clock = Arc::new(ManualClock::new());
        let publisher = Arc::new(RecordingEventPublisher::new());
        let recorder = EventRecorder::new(publisher.clone()).with_clock(clock.clone());
        let demo = app("ferriscd-system", "demo-app");

        assert_eq!(
            recorder
                .emit_sync_failed(&demo, "SyncError", "git fetch timed out")
                .await,
            EmitOutcome::Emitted
        );

        // Simulate 9 retries over 4m30s (every 30s): every one must be suppressed.
        for _ in 0..9 {
            clock.advance(Duration::from_secs(30));
            assert_eq!(
                recorder
                    .emit_sync_failed(&demo, "SyncError", "git fetch timed out again")
                    .await,
                EmitOutcome::Deduplicated
            );
        }
        assert_eq!(
            publisher.events().len(),
            1,
            "repeated Warning SyncFailed within 5 minutes must emit exactly once"
        );

        // 299s total elapsed -> still inside the 300s window.
        clock.advance(Duration::from_secs(29));
        assert_eq!(
            recorder
                .emit_sync_failed(&demo, "SyncError", "still failing at 299s")
                .await,
            EmitOutcome::Deduplicated
        );
        assert_eq!(publisher.events().len(), 1);

        // 300s elapsed -> window expired, emit again!
        clock.advance(Duration::from_secs(1));
        assert_eq!(
            recorder
                .emit_sync_failed(&demo, "SyncError", "still failing at 300s")
                .await,
            EmitOutcome::Emitted
        );
        assert_eq!(publisher.events().len(), 2);
    }

    #[tokio::test]
    async fn normal_sync_succeeded_resets_consecutive_warning_state() {
        let clock = Arc::new(ManualClock::new());
        let publisher = Arc::new(RecordingEventPublisher::new());
        let recorder = EventRecorder::new(publisher.clone()).with_clock(clock.clone());
        let demo = app("ferriscd-system", "demo-app");

        assert_eq!(
            recorder
                .emit_sync_failed(&demo, "SyncError", "transient failure")
                .await,
            EmitOutcome::Emitted
        );
        // Immediate retry is suppressed.
        assert_eq!(
            recorder
                .emit_sync_failed(&demo, "SyncError", "still failing")
                .await,
            EmitOutcome::Deduplicated
        );

        // App recovers: Normal SyncSucceeded emits and resets warning dedup state.
        clock.advance(Duration::from_secs(10));
        assert_eq!(
            recorder
                .emit_sync_succeeded(&demo, "applied 2 of 2 resource(s)")
                .await,
            EmitOutcome::Emitted
        );
        assert_eq!(recorder.tracked_apps(), 0);

        // A new failure 5 seconds later must emit immediately (not suppressed by pre-recovery state).
        clock.advance(Duration::from_secs(5));
        assert_eq!(
            recorder
                .emit_sync_failed(&demo, "SyncError", "new failure after recovery")
                .await,
            EmitOutcome::Emitted
        );

        let recorded = publisher.events();
        assert_eq!(recorded.len(), 3);
        assert_eq!(recorded[0].reason, EVENT_REASON_SYNC_FAILED);
        assert_eq!(recorded[1].reason, EVENT_REASON_SYNC_SUCCEEDED);
        assert_eq!(recorded[2].reason, EVENT_REASON_SYNC_FAILED);
    }

    #[tokio::test]
    async fn different_warning_reason_emits_immediately_and_replaces_active_reason() {
        let clock = Arc::new(ManualClock::new());
        let publisher = Arc::new(RecordingEventPublisher::new());
        let recorder = EventRecorder::new(publisher.clone()).with_clock(clock.clone());
        let demo = app("ferriscd-system", "demo-app");

        assert_eq!(
            recorder
                .emit(
                    &demo,
                    AppEvent::new(&demo, AppEventType::Warning, "SyncFailed", "Sync", "first")
                )
                .await,
            EmitOutcome::Emitted
        );
        // Different warning reason for the same app emits immediately.
        assert_eq!(
            recorder
                .emit(
                    &demo,
                    AppEvent::new(
                        &demo,
                        AppEventType::Warning,
                        "CleanupFailed",
                        "Cleanup",
                        "second"
                    )
                )
                .await,
            EmitOutcome::Emitted
        );
        // Repeating the new reason is suppressed.
        assert_eq!(
            recorder
                .emit(
                    &demo,
                    AppEvent::new(
                        &demo,
                        AppEventType::Warning,
                        "CleanupFailed",
                        "Cleanup",
                        "second again"
                    )
                )
                .await,
            EmitOutcome::Deduplicated
        );
        assert_eq!(publisher.events().len(), 2);
    }

    #[tokio::test]
    async fn different_applications_do_not_suppress_each_other() {
        let clock = Arc::new(ManualClock::new());
        let publisher = Arc::new(RecordingEventPublisher::new());
        let recorder = EventRecorder::new(publisher.clone()).with_clock(clock.clone());
        let app_a = app("team-a", "web");
        let app_b = app("team-b", "web");
        let app_c = app("team-a", "api");

        assert_eq!(
            recorder
                .emit_sync_failed(&app_a, "SyncError", "err a")
                .await,
            EmitOutcome::Emitted
        );
        assert_eq!(
            recorder
                .emit_sync_failed(&app_b, "SyncError", "err b")
                .await,
            EmitOutcome::Emitted
        );
        assert_eq!(
            recorder
                .emit_sync_failed(&app_c, "SyncError", "err c")
                .await,
            EmitOutcome::Emitted
        );
        assert_eq!(publisher.events().len(), 3);
    }

    #[tokio::test]
    async fn bounded_dedup_map_evicts_and_never_grows_unboundedly() {
        let clock = Arc::new(ManualClock::new());
        let publisher = Arc::new(RecordingEventPublisher::new());
        let recorder = EventRecorder::new(publisher.clone())
            .with_clock(clock.clone())
            .with_max_tracked_apps(3);

        for i in 0..20 {
            let application = app("ferriscd-system", &format!("app-{i}"));
            clock.advance(Duration::from_secs(1));
            assert_eq!(
                recorder
                    .emit_sync_failed(&application, "SyncError", "boom")
                    .await,
                EmitOutcome::Emitted
            );
            assert!(
                recorder.tracked_apps() <= 3,
                "dedup map must stay strictly bounded at 3, got {}",
                recorder.tracked_apps()
            );
        }

        // Most recent 3 apps (17, 18, 19) are still deduplicated.
        for i in 17..20 {
            let application = app("ferriscd-system", &format!("app-{i}"));
            assert_eq!(
                recorder
                    .emit_sync_failed(&application, "SyncError", "boom")
                    .await,
                EmitOutcome::Deduplicated
            );
        }

        // Deleting an app frees its slot immediately.
        recorder.forget_app(&app("ferriscd-system", "app-19"));
        assert_eq!(recorder.tracked_apps(), 2);
    }

    #[tokio::test]
    async fn event_publish_errors_are_swallowed_and_do_not_panic_or_fail() {
        let publisher = Arc::new(RecordingEventPublisher::failing("403 Forbidden"));
        let recorder = EventRecorder::new(publisher);
        let demo = app("ferriscd-system", "demo-app");

        assert_eq!(
            recorder.emit_sync_succeeded(&demo, "synced").await,
            EmitOutcome::Failed
        );
        assert_eq!(
            recorder.emit_sync_failed(&demo, "SyncError", "err").await,
            EmitOutcome::Failed
        );
    }

    #[test]
    fn sanitize_note_redacts_secrets_and_urls_and_truncates_utf8_to_1024_bytes() {
        // Base64 payload + embedded URL credentials must both be redacted.
        let base64_secret = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ==";
        let raw = format!(
            "failed to sync https://bot:ghp_SuperSecretToken123@git.example.com/org/repo.git?token=abc: \
             rejected value {base64_secret}"
        );
        let sanitized = sanitize_note(&raw);
        assert!(
            !sanitized.contains("ghp_SuperSecretToken123"),
            "{sanitized}"
        );
        assert!(!sanitized.contains("token=abc"), "{sanitized}");
        assert!(!sanitized.contains(base64_secret), "{sanitized}");
        assert!(sanitized.contains("***@git.example.com"), "{sanitized}");
        assert!(sanitized.contains("<redacted"), "{sanitized}");

        // Multi-byte UTF-8 truncation: 400 x 3-byte chars = 1200 bytes -> must truncate to <= 1024
        // bytes cleanly on a UTF-8 char boundary and end with ellipsis.
        let multibyte = "é".repeat(600); // 1200 bytes (2 bytes per char)
        let truncated = sanitize_note(&multibyte);
        assert!(
            truncated.len() <= MAX_EVENT_NOTE_BYTES,
            "byte len {} exceeds 1024",
            truncated.len()
        );
        assert!(truncated.ends_with('…'), "{truncated}");

        let cjk = "漢".repeat(400); // 1200 bytes (3 bytes per char)
        let truncated_cjk = sanitize_note(&cjk);
        assert!(
            truncated_cjk.len() <= MAX_EVENT_NOTE_BYTES,
            "byte len {} exceeds 1024",
            truncated_cjk.len()
        );
        assert!(truncated_cjk.ends_with('…'));

        // Exact 1024-byte ASCII input is untouched (no ellipsis added).
        let exact = "a ".repeat(512); // 1024 bytes, spaces prevent base64-run redaction
        assert_eq!(exact.len(), MAX_EVENT_NOTE_BYTES);
        assert_eq!(sanitize_note(&exact), exact);
    }

    #[test]
    fn resource_pruned_event_summarizes_gknn_keys_and_bounds_long_lists() {
        let demo = app("ferriscd-system", "demo-app");
        let keys: Vec<ResourceKey> = (0..12)
            .map(|i| {
                ResourceKey::new(
                    "",
                    "ConfigMap",
                    Some("payments".to_owned()),
                    format!("cm-{i}"),
                )
            })
            .collect();
        let event = AppEvent::resource_pruned(&demo, &keys);
        assert_eq!(event.type_, AppEventType::Normal);
        assert_eq!(event.reason, EVENT_REASON_RESOURCE_PRUNED);
        assert_eq!(event.action, EVENT_ACTION_PRUNE);
        assert!(
            event.note.contains("pruned 12 resource(s):"),
            "{}",
            event.note
        );
        assert!(event.note.contains("(+4 more)"), "{}", event.note);
        assert!(event.note.len() <= MAX_EVENT_NOTE_BYTES);
    }

    #[test]
    fn short_fields_are_bounded_to_128_chars() {
        let demo = app("ferriscd-system", "demo-app");
        let long = "R".repeat(200);
        let event = AppEvent::new(&demo, AppEventType::Warning, &long, &long, "note");
        assert_eq!(event.reason.chars().count(), MAX_EVENT_REASON_CHARS);
        assert_eq!(event.action.chars().count(), MAX_EVENT_ACTION_CHARS);
    }

    /// Live `kind` verification for `T15.2` (requires a `kind-*` cluster with CRDs installed).
    #[tokio::test]
    #[ignore = "requires a live kind cluster (asserts kind-* context)"]
    async fn live_kind_publishes_rate_limited_events_on_application() {
        // Safety invariant: never touch a non-kind cluster.
        let output = std::process::Command::new("kubectl")
            .args(["config", "current-context"])
            .output()
            .expect("kubectl must be installed");
        let ctx = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        assert!(
            ctx.starts_with("kind-"),
            "ABORT: refusing to run live test against non-kind context {ctx:?}"
        );

        crate::impersonation::ensure_crypto_provider();
        let client = Client::try_default()
            .await
            .expect("kind kubeconfig must connect");
        let recorder = EventRecorder::for_client(client);
        let target = app(ferriscd_crd::CONTROL_PLANE_NAMESPACE, "t15-2-smoke");

        // Verify the deduplicator suppresses consecutive warnings before hitting the API server.
        let first = recorder
            .emit_sync_failed(&target, "SyncError", "simulated failure")
            .await;
        assert_eq!(first, EmitOutcome::Emitted);
        let second = recorder
            .emit_sync_failed(&target, "SyncError", "simulated failure retry")
            .await;
        assert_eq!(second, EmitOutcome::Deduplicated);
    }
}
