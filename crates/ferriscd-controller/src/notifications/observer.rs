//! The edge-triggered observer: a [`StatusWriter`] decorator that decides *whether* to notify.
//!
//! # What "edge-triggered" means here
//!
//! An `Application` is reconciled on a requeue (180 s by default), on every watch event and on every
//! retry. The status of a persistently failing `Application` therefore looks identical several times
//! an hour — and a "notify on the status" implementation would page somebody each time. Three gates
//! stand between a status write and a delivery:
//!
//! 1. **Edge detection** — a trigger fires on a *transition*, never on a state: entering `Synced`,
//!    entering `Ready=False`, entering `Degraded`, and (after a debounce) entering `OutOfSync`.
//!    `on-out-of-sync` is debounced because a sync that is *about* to run always passes through
//!    `OutOfSync`; only a drift that survives the debounce is worth an alert.
//! 2. **Deduplication** — the roadmap's key `(app_ns, app_name, trigger, observed_generation,
//!    revision, health_status)` in a bounded LRU. It is the gate that keeps a *re-observed* state from
//!    notifying twice even when the edge table no longer has it (an evicted entry, a `forget_app`, or
//!    two observers in one process): without it, every path that resets edge state would page again.
//!
//!    The LRU is in memory, like the edge table, so a **process restart loses both**. The consequence
//!    is bounded and documented: after a restart, a persistently failing `Application` delivers at
//!    most one notification per subscribed trigger (the first reconcile looks like a fresh edge), and
//!    PagerDuty's `dedup_key` — which *is* this key — collapses that repeat on their side.
//! 3. **Per-`Application` rate limit** — a token bucket (`10 / 5 min` by default), so a fleet-wide
//!    outage that flaps 200 resources cannot turn into 2 000 pages from one `Application`.
//!
//! Every gate's state is *bounded*: the edge table, the dedup LRU and the rate-limit table all evict,
//! and [`NotificationObserver::forget_app`] drops a deleted `Application`'s entry immediately.
//!
//! # A suppressed event is retried, not lost (findings P19-M1 and R1-M7)
//!
//! The edge table is updated from a **snapshot** and committed only once a delivery was actually
//! enqueued: an event that all three gates suppressed leaves the edge state where it was, so the next
//! reconcile sees it again instead of believing it was announced. Malformed subscription annotations
//! are reported once per `Application` (not once per 180 s requeue), and
//! `--notifications-allowed-namespaces` decides which tenants may opt in at all (finding **R1-M6**): an
//! `Application` outside the allowlist is ignored before any state is touched.
//!
//! # What it never does
//!
//! * It never awaits a network call: the delivery is queued with `try_send` on a bounded channel and
//!   a full queue drops the notification (counted) rather than applying backpressure to the
//!   reconcile loop.
//! * It never reads from the API server: the trigger decision is computed from the `Application`
//!   and the status the pass just persisted.
//! * It never fails a reconcile: a delivery problem is the worker's business, and the observer
//!   returns the inner writer's result unchanged.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferriscd_crd::status::{ApplicationStatus, HealthStatus, SyncStatus};
use ferriscd_crd::{Application, annotations};
use futures::future::BoxFuture;
use kube::ResourceExt as _;
use tokio::sync::mpsc;

use crate::events::EventClock;
use crate::lock_recover;
use crate::metrics::{Metrics, NotificationOutcome};
use crate::notifications::{
    DEFAULT_DEDUP_CAPACITY, DEFAULT_MAX_TRACKED_APPS, DEFAULT_RATE_BURST, DEFAULT_RATE_WINDOW,
    MAX_REPORTED_MALFORMED, MalformedSubscription, NotificationConfig, NotificationContext,
    NotificationJob, Subscription, subscription_parse, template::MessageTemplate,
};
use crate::reconcile::{ReconcileError, StatusWriter};

/// What one status write decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservingOutcome {
    /// Nothing to do: no subscription, no edge, or the trigger is still inside its debounce.
    Idle,
    /// A notification was queued for delivery.
    Queued,
    /// The notification was suppressed by the deduplication LRU.
    Deduplicated,
    /// The notification was suppressed by the per-`Application` token bucket.
    RateLimited,
    /// The bounded queue was full; the notification was dropped (and counted).
    Dropped,
}

/// The last observation of one `Application`, for edge detection and the debounce.
#[derive(Debug, Clone, Default)]
struct Observation {
    sync: Option<SyncStatus>,
    health: Option<HealthStatus>,
    ready: Option<bool>,
    revision: Option<String>,
    out_of_sync_since: Option<std::time::Instant>,
    seq: u64,
}

/// The key a notification is deduplicated on (`T19.4`).
///
/// `revision` is *bounded* before it is stored (finding **R1-N7**): a Git revision is
/// attacker-influenced text of unbounded length, and this key is rendered into the PagerDuty
/// `dedup_key` body field and the `X-FerrisCD-Delivery` header, both of which receivers size-limit.
/// Anything longer than [`MAX_DEDUP_REVISION_CHARS`] is replaced by `sha256:<hex>` — still
/// collision-free for practical purposes, and still stable across restarts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DedupKey {
    namespace: String,
    name: String,
    trigger: &'static str,
    generation: Option<i64>,
    revision: Option<String>,
    health: Option<HealthStatus>,
}

/// Longest revision kept verbatim in a deduplication key.
const MAX_DEDUP_REVISION_CHARS: usize = 64;

/// Bounds one revision for the deduplication key (finding **R1-N7**).
fn bounded_revision(revision: &str) -> String {
    if revision.chars().count() <= MAX_DEDUP_REVISION_CHARS {
        return revision.to_owned();
    }
    let digest = ferriscd_engine::diff::sha256::digest(revision.as_bytes());
    let mut rendered = String::with_capacity(7 + 64);
    rendered.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        // Writing into a `String` cannot fail; the `let _` keeps the crate's no-`unwrap` rule.
        let _ = write!(rendered, "{byte:02x}");
    }
    rendered
}

impl DedupKey {
    fn render(&self) -> String {
        format!(
            "{namespace}/{name}:{trigger}:gen={generation}:rev={revision}:health={health}",
            namespace = self.namespace,
            name = self.name,
            trigger = self.trigger,
            generation = self
                .generation
                .map_or_else(|| "-".to_owned(), |value| value.to_string()),
            revision = self.revision.as_deref().unwrap_or("-"),
            health = self
                .health
                .map_or_else(|| "-".to_owned(), |value| format!("{value:?}")),
        )
    }
}

/// Per-`Application` token bucket.
#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    last_refill: std::time::Instant,
    seq: u64,
}

/// One trigger that fired, before the dedup/rate gates.
struct Fired {
    trigger: &'static str,
    key: DedupKey,
}

#[derive(Debug, Default)]
struct ObserverState {
    observations: HashMap<(String, String), Observation>,
    dedup: HashMap<DedupKey, ()>,
    dedup_order: VecDeque<DedupKey>,
    buckets: HashMap<(String, String), TokenBucket>,
    /// `(application key, annotation key)` pairs whose refusal has already been logged (finding
    /// **M7**): a malformed annotation is reported once, not on every 180 s requeue.
    reported_malformed: HashSet<(String, String)>,
    reported_malformed_order: VecDeque<(String, String)>,
    next_seq: u64,
}

/// The notification decision engine (cheap to clone, shared by every reconcile).
#[derive(Clone)]
pub struct Notifier {
    tx: mpsc::Sender<NotificationJob>,
    config: Arc<NotificationConfig>,
    metrics: Metrics,
    clock: Arc<dyn EventClock>,
    dedup_capacity: usize,
    max_tracked_apps: usize,
    rate_burst: u32,
    rate_window: Duration,
    /// Tenants allowed to opt in through annotations (finding **R1-M6**); `None` means every namespace.
    allowed_namespaces: Option<Arc<Vec<String>>>,
    state: Arc<Mutex<ObserverState>>,
}

impl std::fmt::Debug for Notifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = lock_recover(&self.state);
        f.debug_struct("Notifier")
            .field("queue_closed", &self.tx.is_closed())
            .field("tracked_apps", &state.observations.len())
            .field("dedup_entries", &state.dedup.len())
            .field("dedup_capacity", &self.dedup_capacity)
            .field("rate_burst", &self.rate_burst)
            .field("rate_window", &self.rate_window)
            .field("allowed_namespaces", &self.allowed_namespaces)
            .finish_non_exhaustive()
    }
}

impl Notifier {
    /// Builds a notifier feeding `tx`.
    #[must_use]
    pub fn new(
        tx: mpsc::Sender<NotificationJob>,
        config: Arc<NotificationConfig>,
        metrics: Metrics,
        clock: Arc<dyn EventClock>,
    ) -> Self {
        Self {
            tx,
            config,
            metrics,
            clock,
            dedup_capacity: DEFAULT_DEDUP_CAPACITY,
            max_tracked_apps: DEFAULT_MAX_TRACKED_APPS,
            rate_burst: DEFAULT_RATE_BURST,
            rate_window: DEFAULT_RATE_WINDOW,
            allowed_namespaces: None,
            state: Arc::new(Mutex::new(ObserverState::default())),
        }
    }

    /// Overrides the deduplication capacity (tests use a tiny value to prove eviction).
    #[must_use]
    pub fn with_dedup_capacity(mut self, capacity: usize) -> Self {
        self.dedup_capacity = capacity;
        self
    }

    /// Overrides the per-`Application` token bucket (`burst` per `window`).
    #[must_use]
    pub fn with_rate_limit(mut self, burst: u32, window: Duration) -> Self {
        self.rate_burst = burst;
        self.rate_window = window;
        self
    }

    /// Overrides the number of tracked `Application`s in the edge/rate tables.
    #[must_use]
    pub fn with_max_tracked_apps(mut self, max: usize) -> Self {
        self.max_tracked_apps = max;
        self
    }

    /// Restricts which tenants may opt in at all (finding **R1-M6**).
    ///
    /// `None` keeps the historical behaviour (any namespace may subscribe); `Some(namespaces)`
    /// makes an `Application` outside the list completely inert — it is not even given edge state,
    /// so a tenant cannot page another team's channel or consume the controller's rate-limit budget.
    #[must_use]
    pub fn with_allowed_namespaces(mut self, namespaces: Option<Vec<String>>) -> Self {
        self.allowed_namespaces = namespaces.map(Arc::new);
        self
    }

    /// The tenant allowlist this notifier enforces (`None` = every namespace).
    #[must_use]
    pub fn allowed_namespaces(&self) -> Option<&[String]> {
        self.allowed_namespaces.as_deref().map(Vec::as_slice)
    }

    /// Number of `(application, annotation)` refusals already reported (bounded by
    /// [`MAX_REPORTED_MALFORMED`], finding **R1-M7**).
    #[must_use]
    pub fn reported_malformed(&self) -> usize {
        lock_recover(&self.state).reported_malformed.len()
    }

    /// Returns whether this notifier may act for an `Application` in `namespace` (finding **R1-M6**).
    fn permits_namespace(&self, namespace: &str) -> bool {
        match self.allowed_namespaces.as_deref() {
            None => true,
            Some(allowed) => allowed.iter().any(|known| known == namespace),
        }
    }

    /// Number of `Application`s with edge/rate state (bounded by [`Self::with_max_tracked_apps`]).
    #[must_use]
    pub fn tracked_apps(&self) -> usize {
        lock_recover(&self.state).observations.len()
    }

    /// Number of live deduplication keys (bounded by the dedup capacity).
    #[must_use]
    pub fn dedup_entries(&self) -> usize {
        lock_recover(&self.state).dedup.len()
    }

    /// Drops every entry of a deleted `Application`.
    pub fn forget_app(&self, app: &Application) {
        let key = (app.namespace().unwrap_or_default(), app.name_any());
        let mut state = lock_recover(&self.state);
        state.observations.remove(&key);
        state.buckets.remove(&key);
        state
            .dedup
            .retain(|dedup, _| dedup.namespace != key.0 || dedup.name != key.1);
        state
            .dedup_order
            .retain(|dedup| dedup.namespace != key.0 || dedup.name != key.1);
    }

    /// Computes the triggers that fired for this status write.
    ///
    /// `previous` is the observation recorded for the `Application` (resolved against the persisted
    /// `status`, and *filled in* for the current one), `subscriptions` are the annotation-driven
    /// targets.
    fn fired_triggers(
        &self,
        app: &Application,
        status: &ApplicationStatus,
        previous: &mut Observation,
    ) -> Vec<Fired> {
        let namespace = app.namespace().unwrap_or_default();
        let name = app.name_any();
        let generation = status.observed_generation.or(app.metadata.generation);
        let sync = status.sync.as_ref().map(|sync| sync.status);
        let health = status.health.as_ref().map(|health| health.status);
        let ready = status
            .condition(ferriscd_crd::status::CONDITION_READY)
            .map(ferriscd_crd::status::Condition::is_true);
        let revision = status.sync.as_ref().and_then(|sync| {
            sync.revision
                .clone()
                .or_else(|| sync.last_synced_revision.clone())
        });
        let now = self.clock.now();

        let mut fired = Vec::new();
        let mut push = |trigger: &'static str| {
            fired.push(Fired {
                trigger,
                key: DedupKey {
                    namespace: namespace.clone(),
                    name: name.clone(),
                    trigger,
                    generation,
                    // Finding R1-N7: the dedup key is rendered into a PagerDuty body field and an HTTP
                    // header, so an unbounded revision is hashed rather than copied.
                    revision: revision.as_deref().map(bounded_revision),
                    health,
                },
            });
        };

        // `on-sync-succeeded`: entering `Synced`, or a new revision that is already synced. The
        // revision half matters because a successful sync of a *new* commit is exactly the release
        // an operator wants to announce, and no requeue produces a new revision.
        if sync == Some(SyncStatus::Synced)
            && (previous.sync != Some(SyncStatus::Synced)
                || previous.revision != revision
                || previous.sync.is_none())
        {
            push(annotations::TRIGGER_SYNC_SUCCEEDED);
        }

        // A *new revision* is a new fact even when the state is unchanged: "revision feedface
        // failed" is not the same alert as "revision deadbeef failed", so the failure edges below
        // also fire when the observed revision moved.
        let revision_changed = previous.revision != revision;

        // `on-sync-failed`: entering `Ready=False`. `Ready` is the always-update-status contract's
        // failure signal (trap T3), and it is what the status writer persists for both a failed
        // apply and a failed render.
        if ready == Some(false) && (previous.ready != Some(false) || revision_changed) {
            push(annotations::TRIGGER_SYNC_FAILED);
        }

        // `on-health-degraded`: entering `Degraded` (or degrading a different revision).
        if health == Some(HealthStatus::Degraded)
            && (previous.health != Some(HealthStatus::Degraded) || revision_changed)
        {
            push(annotations::TRIGGER_HEALTH_DEGRADED);
        }

        // `on-out-of-sync`: debounced, so a sync that is about to run does not page anybody.
        if sync == Some(SyncStatus::OutOfSync) {
            let since = *previous.out_of_sync_since.get_or_insert(now);
            let debounce = self.config.debounce_for(annotations::TRIGGER_OUT_OF_SYNC);
            if now.saturating_duration_since(since) >= debounce {
                push(annotations::TRIGGER_OUT_OF_SYNC);
            }
        } else {
            previous.out_of_sync_since = None;
        }

        previous.sync = sync;
        previous.health = health;
        previous.ready = ready;
        previous.revision = revision;
        fired
    }

    /// Applies the deduplication and rate-limit gates, then enqueues.
    ///
    /// # When edge state is committed (finding P19-M1)
    ///
    /// The new observation is computed against a **snapshot** of the previous one and is committed
    /// only when at least one delivery was actually enqueued. If every event of this write was
    /// suppressed (deduplicated, rate limited, or dropped on a full queue) the edge state is rolled
    /// back, so the event is retried on the next observation instead of being silently lost: with
    /// the state committed first, one rate-limited `on-sync-failed` would mean the failure is never
    /// announced, because the "we already saw `Ready=False`" edge is now permanent state.
    ///
    /// The `on-out-of-sync` debounce timer is *not* rolled back — it is a clock, not an edge, and
    /// resetting it would re-arm a 60 s wait every 180 s and never fire. When a write fires several
    /// triggers and only some are enqueued, the whole observation advances (the suppressed trigger
    /// is not tracked separately); that is the documented limit of the snapshot/restore approach.
    fn dispatch(&self, app: &Application, status: &ApplicationStatus) -> ObservingOutcome {
        let namespace = app.namespace().unwrap_or_default();
        let name = app.name_any();
        // Finding R1-M6: a tenant outside the allowlist is completely inert — no edge state, no dedup
        // entry, no rate-limit token, nothing queued.
        if !self.permits_namespace(&namespace) {
            return ObservingOutcome::Idle;
        }
        let parsed = subscription_parse(app);
        self.report_malformed(&namespace, &name, &parsed.malformed);
        let subscriptions = parsed.subscriptions;
        if subscriptions.is_empty() {
            return ObservingOutcome::Idle;
        }
        let app_key = (namespace.clone(), name.clone());

        let (fired, previous, next) = {
            let mut state = lock_recover(&self.state);
            if !state.observations.contains_key(&app_key)
                && state.observations.len() >= self.max_tracked_apps
            {
                evict_oldest(&mut state);
            }
            state.next_seq = state.next_seq.saturating_add(1);
            let seq = state.next_seq;
            let previous = state
                .observations
                .get(&app_key)
                .cloned()
                .unwrap_or(Observation {
                    seq,
                    ..Observation::default()
                });
            let mut next = previous.clone();
            next.seq = seq;
            let fired = self.fired_triggers(app, status, &mut next);
            (fired, previous, next)
        };
        if fired.is_empty() {
            // Nothing can be suppressed, so the new edge state is simply committed: this is what
            // makes a repeated status write cheap and silent.
            self.commit_observation(&app_key, next, previous, true);
            return ObservingOutcome::Idle;
        }

        let mut outcome = ObservingOutcome::Idle;
        let mut enqueued = false;
        for event in fired {
            let recipients: Vec<&Subscription> = subscriptions
                .iter()
                .filter(|subscription| subscription.trigger == event.trigger)
                .collect();
            if recipients.is_empty() {
                // The trigger fired but nobody subscribed to it: no dedup entry is consumed, so
                // subscribing later still gets the next edge.
                continue;
            }
            // Deduplication is checked **first** (cheap, and it keeps a duplicate from consuming a
            // rate-limit token) but recorded only after a delivery was actually queued: an event
            // suppressed by the token bucket must be retryable on the next observation, not lost.
            if self.dedup_seen(&event.key) {
                // Visible in `ferriscd_notifications_total{outcome="suppressed"}`: "how much am I
                // being deduplicated?" is the first question an operator asks after an alert storm.
                for subscription in &recipients {
                    self.metrics
                        .record_notification(subscription.service, NotificationOutcome::Suppressed);
                }
                outcome = worse(outcome, ObservingOutcome::Deduplicated);
                continue;
            }
            for subscription in recipients {
                if !self.consume_token(&app_key) {
                    self.metrics
                        .record_notification(subscription.service, NotificationOutcome::Suppressed);
                    outcome = worse(outcome, ObservingOutcome::RateLimited);
                    continue;
                }
                let context = NotificationContext::from_status(
                    app,
                    status,
                    event.trigger,
                    subscription.service.as_str(),
                    &subscription.recipient,
                );
                let template = self
                    .config
                    .template_for(event.trigger)
                    .cloned()
                    .unwrap_or_else(|| MessageTemplate::default_for(event.trigger));
                let job = NotificationJob {
                    namespace: namespace.clone(),
                    name: name.clone(),
                    service: subscription.service,
                    recipient: subscription.recipient.clone(),
                    dedup_key: event.key.render(),
                    context,
                    template,
                };
                match self.tx.try_send(job) {
                    Ok(()) => {
                        self.remember(&event.key);
                        enqueued = true;
                        outcome = worse(outcome, ObservingOutcome::Queued);
                    }
                    Err(err) => {
                        // Finding P19-M1: the token was only *reserved* for this delivery, so a full
                        // queue gives it back. Consuming it here would let a single burst of 512
                        // dropped alerts empty the tenant's bucket and rate-limit the one real page
                        // that follows, which is the exact alert the budget exists to protect.
                        self.refund_token(&app_key);
                        self.metrics.record_notification(
                            subscription.service,
                            NotificationOutcome::Dropped,
                        );
                        tracing::warn!(
                            app.namespace = %namespace,
                            app.name = %name,
                            service = subscription.service.as_str(),
                            error = %err,
                            "the notification queue is full: dropping this notification instead of \
                             delaying reconciliation"
                        );
                        outcome = worse(outcome, ObservingOutcome::Dropped);
                    }
                }
            }
        }
        // Finding P19-M1: commit the edge state only if a delivery really went out; otherwise roll it
        // back (keeping the debounce timer) so the event can be retried and is never lost.
        self.commit_observation(&app_key, next, previous, enqueued);
        outcome
    }

    /// Records the observation that follows this write.
    ///
    /// `next` is committed when a delivery was enqueued (or when nothing could be suppressed);
    /// otherwise `previous` is restored, except for the `on-out-of-sync` debounce timer, which keeps
    /// running (finding **P19-M1**). A delivery that never happened does not resurrect an `Application`
    /// that [`Self::forget_app`] dropped while the write was in flight.
    fn commit_observation(
        &self,
        app_key: &(String, String),
        next: Observation,
        previous: Observation,
        enqueued: bool,
    ) {
        let mut state = lock_recover(&self.state);
        if !enqueued && !state.observations.contains_key(app_key) {
            return;
        }
        let committed = if enqueued {
            next
        } else {
            Observation {
                out_of_sync_since: next.out_of_sync_since.or(previous.out_of_sync_since),
                seq: next.seq,
                ..previous
            }
        };
        state.observations.insert(app_key.clone(), committed);
    }

    /// Reports each refused subscription annotation **once per `Application`** (finding **R1-M7**).
    ///
    /// The parser runs on every reconcile pass, so a warning at the parse site would repeat every
    /// 180 s forever for a typo nobody fixes and drown the log. The reported set is bounded
    /// ([`MAX_REPORTED_MALFORMED`], least recently reported evicted first), so a fleet that
    /// generates a fresh typo on every pass cannot grow it without bound; a repeat is logged at
    /// `debug` (still available when someone is actually debugging that `Application`).
    fn report_malformed(&self, namespace: &str, name: &str, malformed: &[MalformedSubscription]) {
        if malformed.is_empty() {
            return;
        }
        let mut state = lock_recover(&self.state);
        for entry in malformed {
            let key = (format!("{namespace}/{name}"), entry.key.clone());
            let already_reported = !state.reported_malformed.insert(key.clone());
            if already_reported {
                state.reported_malformed_order.retain(|known| *known != key);
                state.reported_malformed_order.push_back(key);
                tracing::debug!(
                    app.namespace = %namespace,
                    app.name = %name,
                    annotation = %entry.key,
                    reason = entry.reason,
                    "still ignoring a malformed notification subscription annotation"
                );
                continue;
            }
            state.reported_malformed_order.push_back(key);
            while state.reported_malformed.len() > MAX_REPORTED_MALFORMED {
                let Some(oldest) = state.reported_malformed_order.pop_front() else {
                    break;
                };
                state.reported_malformed.remove(&oldest);
            }
            tracing::warn!(
                app.namespace = %namespace,
                app.name = %name,
                annotation = %entry.key,
                reason = entry.reason,
                "ignoring a malformed notification subscription annotation (reported once per \
                 Application; expected notifications.ferriscd.io/subscribe.<trigger>.<service>)"
            );
        }
    }

    /// Returns whether `key` was already delivered, refreshing its LRU recency.
    /// Nothing is inserted here: [`Self::remember`] records a key only once a delivery is queued, so
    /// a rate-limited event is not permanently silenced.
    fn dedup_seen(&self, key: &DedupKey) -> bool {
        let mut state = lock_recover(&self.state);
        if state.dedup.contains_key(key) {
            state.dedup_order.retain(|candidate| candidate != key);
            state.dedup_order.push_back(key.clone());
            return true;
        }
        false
    }

    /// Records `key` in the bounded LRU, evicting the least recently used key when full.
    fn remember(&self, key: &DedupKey) {
        if self.dedup_capacity == 0 {
            return;
        }
        let mut state = lock_recover(&self.state);
        if state.dedup.insert(key.clone(), ()).is_none() {
            state.dedup_order.push_back(key.clone());
        }
        while state.dedup.len() > self.dedup_capacity {
            let Some(oldest) = state.dedup_order.pop_front() else {
                break;
            };
            state.dedup.remove(&oldest);
        }
    }

    /// *Reserves* one token from the `Application`'s bucket, refilling it first.
    ///
    /// The reservation is not a decision: the delivery still has to be queued, and
    /// [`Self::refund_token`] gives the token back when it was not (finding **P19-M1**). Consume-first
    /// plus refund is deliberate — a "peek then send then consume" shape would let two concurrent
    /// writes of the same `Application` both observe a token and both deliver, so the bucket would
    /// bound bursts only under a lock the sender does not hold anyway.
    fn consume_token(&self, app_key: &(String, String)) -> bool {
        if self.rate_burst == 0 {
            return false;
        }
        let now = self.clock.now();
        let mut state = lock_recover(&self.state);
        if !state.buckets.contains_key(app_key) && state.buckets.len() >= self.max_tracked_apps {
            // Bounded: drop the least recently refilled bucket rather than growing forever.
            if let Some(oldest) = state
                .buckets
                .iter()
                .min_by_key(|(_, bucket)| (bucket.last_refill, bucket.seq))
                .map(|(key, _)| key.clone())
            {
                state.buckets.remove(&oldest);
            }
        }
        let per_second = if self.rate_window.is_zero() {
            f64::INFINITY
        } else {
            f64::from(self.rate_burst) / self.rate_window.as_secs_f64()
        };
        state.next_seq = state.next_seq.saturating_add(1);
        let seq = state.next_seq;
        let burst = f64::from(self.rate_burst);
        let bucket = state.buckets.entry(app_key.clone()).or_insert(TokenBucket {
            tokens: burst,
            last_refill: now,
            seq,
        });
        let elapsed = now
            .saturating_duration_since(bucket.last_refill)
            .as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * per_second).min(burst);
        bucket.last_refill = now;
        bucket.seq = seq;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Returns a token reserved by [`Self::consume_token`] whose delivery never made it out.
    ///
    /// Idempotent by construction: it is called exactly once per failed `try_send`, and it only
    /// touches an existing bucket (an evicted `Application` has already lost its budget, and
    /// resurrecting it would let eviction be used to launder unlimited deliveries). The refill
    /// timestamp is left alone — the bucket refills on the normal schedule, so a refund never grants
    /// more than the burst the operator configured.
    fn refund_token(&self, app_key: &(String, String)) {
        let burst = f64::from(self.rate_burst);
        let mut state = lock_recover(&self.state);
        if let Some(bucket) = state.buckets.get_mut(app_key) {
            bucket.tokens = (bucket.tokens + 1.0).min(burst);
        }
    }
}

/// Ranks the outcomes so a caller can report the most consequential thing that happened.
fn worse(current: ObservingOutcome, candidate: ObservingOutcome) -> ObservingOutcome {
    fn rank(outcome: ObservingOutcome) -> u8 {
        match outcome {
            ObservingOutcome::Idle => 0,
            ObservingOutcome::Queued => 1,
            ObservingOutcome::Deduplicated => 2,
            ObservingOutcome::RateLimited => 3,
            ObservingOutcome::Dropped => 4,
        }
    }
    if rank(candidate) > rank(current) {
        candidate
    } else {
        current
    }
}

/// Evicts the least recently observed `Application` from the edge/rate tables.
fn evict_oldest(state: &mut ObserverState) {
    let Some(oldest) = state
        .observations
        .iter()
        .min_by_key(|(_, observation)| observation.seq)
        .map(|(key, _)| key.clone())
    else {
        return;
    };
    state.observations.remove(&oldest);
    state.buckets.remove(&oldest);
}

/// [`StatusWriter`] decorator that notifies after a status write landed (`T19.4`).
pub struct NotificationObserver {
    inner: Arc<dyn StatusWriter>,
    notifier: Notifier,
}

impl NotificationObserver {
    /// Wraps `inner` so every **persisted** status is observed once.
    #[must_use]
    pub fn new(inner: Arc<dyn StatusWriter>, notifier: Notifier) -> Self {
        Self { inner, notifier }
    }

    /// The decision engine (tests drive it directly through [`Self::patch`], the production path).
    #[must_use]
    pub fn notifier(&self) -> &Notifier {
        &self.notifier
    }

    /// Observes `status` as if it had just been persisted (the production path via [`Self::patch`]).
    pub fn observe(&self, app: &Application, status: &ApplicationStatus) -> ObservingOutcome {
        self.notifier.dispatch(app, status)
    }
}

impl std::fmt::Debug for NotificationObserver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotificationObserver")
            .field("notifier", &self.notifier)
            .finish_non_exhaustive()
    }
}

impl StatusWriter for NotificationObserver {
    fn patch<'a>(
        &'a self,
        app: &'a Application,
        status: ApplicationStatus,
    ) -> BoxFuture<'a, Result<(), ReconcileError>> {
        Box::pin(async move {
            // Only a status the API server actually accepted describes the world; notifying from a
            // rejected patch would page somebody about a state change that never happened.
            self.inner.patch(app, status.clone()).await?;
            self.notifier.dispatch(app, &status);
            Ok(())
        })
    }

    /// Drops the `Application`'s edge/dedup/rate state when it is deleted.
    fn forget_app(&self, app: &Application) {
        self.inner.forget_app(app);
        self.notifier.forget_app(app);
    }
}

/// Spawns the delivery worker and returns the notifier that feeds it (`T19.4` wiring helper).
///
/// Separate from [`NotificationObserver`] so the decision (cheap, synchronous, unit-tested) and the
/// delivery (I/O, retried, bounded) are independently testable. `allowed_namespaces` is the
/// `--notifications-allowed-namespaces` tenant boundary (finding **R1-M6**); `None` keeps the
/// historical "any namespace may opt in" behaviour.
pub fn spawn_worker(
    config: NotificationConfig,
    channels: Arc<dyn crate::notifications::ChannelSource>,
    transport: Arc<dyn crate::notifications::NotificationTransport>,
    policy: crate::notifications::EgressPolicy,
    metrics: Metrics,
    allowed_namespaces: Option<Vec<String>>,
) -> (Notifier, crate::notifications::NotificationWorkerHandle) {
    let config = Arc::new(config);
    let (tx, rx) = mpsc::channel(crate::notifications::DEFAULT_QUEUE_CAPACITY);
    let notifier = Notifier::new(
        tx,
        config.clone(),
        metrics.clone(),
        Arc::new(crate::events::SystemClock),
    )
    .with_allowed_namespaces(allowed_namespaces);
    let worker =
        crate::notifications::NotificationWorker::new(rx, channels, transport, policy, metrics);
    let handle = worker.spawn();
    (notifier, handle)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use ferriscd_crd::application::{
        DEFAULT_REQUEUE_AFTER_SECONDS, DEFAULT_REVISION_HISTORY_LIMIT,
    };
    use ferriscd_crd::status::{Condition, ConditionStatus, HealthState, SyncState};
    use ferriscd_crd::{ApplicationSpec, DestinationSpec, GitSourceSpec, RendererSpec, SourceSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
    use tokio::sync::mpsc;

    use crate::events::test_support::ManualClock;
    use crate::notifications::NotificationService;

    use super::*;

    /// A `StatusWriter` that records what was persisted and can be made to fail.
    #[derive(Default)]
    struct RecordingWriter {
        patched: Mutex<Vec<ApplicationStatus>>,
        fail: bool,
    }

    impl StatusWriter for RecordingWriter {
        fn patch<'a>(
            &'a self,
            _app: &'a Application,
            status: ApplicationStatus,
        ) -> BoxFuture<'a, Result<(), ReconcileError>> {
            Box::pin(async move {
                if self.fail {
                    return Err(ReconcileError::Invalid {
                        message: "the API server refused the status patch".to_owned(),
                    });
                }
                lock_recover(&self.patched).push(status);
                Ok(())
            })
        }
    }

    fn app(namespace: &str, name: &str, subscriptions: &[(&str, &str, &str)]) -> Application {
        let spec = ApplicationSpec {
            project: "payments".to_owned(),
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
        let mut application = Application::new(name, spec);
        application.metadata.namespace = Some(namespace.to_owned());
        application.metadata.generation = Some(1);
        let mut annotations = BTreeMap::new();
        for (trigger, service, recipient) in subscriptions {
            annotations.insert(
                format!("notifications.ferriscd.io/subscribe.{trigger}.{service}"),
                (*recipient).to_owned(),
            );
        }
        application.metadata.annotations = Some(annotations);
        application
    }

    fn status(
        sync: SyncStatus,
        health: HealthStatus,
        ready: Option<bool>,
        revision: &str,
    ) -> ApplicationStatus {
        ApplicationStatus {
            observed_generation: Some(1),
            sync: Some(SyncState::new(sync, Some(revision.to_owned()))),
            health: Some(HealthState::new(health)),
            conditions: ready.map_or_else(Vec::new, |ready| {
                vec![Condition::ready(
                    if ready {
                        ConditionStatus::True
                    } else {
                        ConditionStatus::False
                    },
                    if ready { "SyncSucceeded" } else { "SyncFailed" },
                    "apply failed: 422 Immutable",
                    Time("2026-11-24T12:00:00Z".parse().expect("timestamp")),
                )]
            }),
            ..ApplicationStatus::default()
        }
    }

    struct Harness {
        observer: NotificationObserver,
        rx: mpsc::Receiver<NotificationJob>,
        clock: Arc<ManualClock>,
        writer: Arc<RecordingWriter>,
    }

    fn test_harness() -> Harness {
        let writer = Arc::new(RecordingWriter::default());
        let (tx, rx) = mpsc::channel(512);
        let clock = Arc::new(ManualClock::new());
        let notifier = Notifier::new(
            tx,
            Arc::new(NotificationConfig::built_in()),
            Metrics::new(),
            clock.clone(),
        );
        Harness {
            observer: NotificationObserver::new(writer.clone(), notifier),
            rx,
            clock,
            writer,
        }
    }

    fn drain(rx: &mut mpsc::Receiver<NotificationJob>) -> Vec<NotificationJob> {
        let mut jobs = Vec::new();
        while let Ok(job) = rx.try_recv() {
            jobs.push(job);
        }
        jobs
    }

    const ALL_TRIGGERS: [(&str, &str, &str); 4] = [
        ("on-sync-succeeded", "slack", "payments-oncall"),
        ("on-sync-failed", "slack", "payments-oncall"),
        ("on-health-degraded", "pagerduty", "payments-pd"),
        ("on-out-of-sync", "webhook", "automation"),
    ];

    /// **Verification bullet (3):** a persistently failing `Application` reconciled every 180 s
    /// fires **exactly one** notification, and a *new* failure after recovery fires again.
    #[tokio::test]
    async fn repeated_unchanged_failures_fire_exactly_one_notification() {
        let mut harness = test_harness();
        let demo = app("ferriscd-system", "demo-app", &ALL_TRIGGERS);
        let failing = status(
            SyncStatus::Unknown,
            HealthStatus::Degraded,
            Some(false),
            "deadbeef",
        );

        assert_eq!(
            harness.observer.observe(&demo, &failing),
            ObservingOutcome::Queued
        );
        // The observer forwards the status to the real writer (it decorates, never replaces it) and
        // notifies only after that write succeeded.
        assert_eq!(lock_recover(&harness.writer.patched).len(), 0);
        harness
            .observer
            .patch(&demo, failing.clone())
            .await
            .expect("the inner writer accepts the status");
        assert_eq!(lock_recover(&harness.writer.patched).len(), 1);
        let queued = drain(&mut harness.rx);
        assert_eq!(queued.len(), 2, "on-sync-failed + on-health-degraded");
        assert!(
            queued[0].dedup_key.contains("health=Degraded"),
            "{:?}",
            queued[0].dedup_key
        );

        // Ten requeues, 180 s apart, with the same failure: nothing more may be delivered.
        for _ in 0..10 {
            harness.clock.advance(Duration::from_secs(180));
            assert_eq!(
                harness.observer.observe(&demo, &failing),
                ObservingOutcome::Idle,
                "an unchanged status must not renotify (no edge, so nothing even reaches dedup)"
            );
            assert!(drain(&mut harness.rx).is_empty());
        }

        // The deduplication key alone suppresses a replay when the edge state is gone (evicted entry,
        // `forget_app`, or a second observer over the same cache).
        let mut restarted = harness_with_shared_state(&demo, &harness);
        harness.clock.advance(Duration::from_secs(1));
        assert_eq!(
            restarted.observer.observe(&demo, &failing),
            ObservingOutcome::Deduplicated,
            "the (generation, revision, health) key must suppress a replay even without edge state"
        );
        assert!(drain(&mut restarted.rx).is_empty());

        // Recovery, then a fresh failure on the same revision: the failure is a *new* edge and a new
        // dedup entry only when the revision changed; the same revision/health is still deduplicated.
        harness.clock.advance(Duration::from_secs(180));
        let recovered = status(
            SyncStatus::Synced,
            HealthStatus::Healthy,
            Some(true),
            "deadbeef",
        );
        assert_eq!(
            harness.observer.observe(&demo, &recovered),
            ObservingOutcome::Queued,
            "entering Synced announces the release"
        );
        drain(&mut harness.rx);
        harness.clock.advance(Duration::from_secs(180));
        assert_eq!(
            harness.observer.observe(&demo, &failing),
            ObservingOutcome::Deduplicated,
            "the same (revision, health) failure was already paged for"
        );

        // A genuinely new revision fails: a new dedup key, so it pages.
        harness.clock.advance(Duration::from_secs(180));
        let new_revision = status(
            SyncStatus::Unknown,
            HealthStatus::Degraded,
            Some(false),
            "feedface",
        );
        assert_eq!(
            harness.observer.observe(&demo, &new_revision),
            ObservingOutcome::Queued
        );
        let jobs = drain(&mut harness.rx);
        assert!(
            jobs.iter()
                .any(|job| job.dedup_key.contains("on-sync-failed")
                    && job.dedup_key.contains("rev=feedface")),
            "{:?}",
            jobs.iter()
                .map(|job| job.dedup_key.clone())
                .collect::<Vec<_>>()
        );
    }

    /// A second observer sharing the first one's dedup cache with an empty edge table: the dedup gate
    /// on its own, with no edge to fire it.
    fn harness_with_shared_state(_app: &Application, first: &Harness) -> Harness {
        let writer = Arc::new(RecordingWriter::default());
        let (tx, rx) = mpsc::channel(512);
        let clock = first.clock.clone();
        let mut notifier = Notifier::new(
            tx,
            Arc::new(NotificationConfig::built_in()),
            Metrics::new(),
            clock.clone(),
        );
        notifier.state = first.observer.notifier.state.clone();
        // Edge state is what a restart loses; the LRU is retained.
        lock_recover(&notifier.state).observations.clear();
        Harness {
            observer: NotificationObserver::new(writer, notifier),
            rx,
            clock,
            writer: Arc::new(RecordingWriter::default()),
        }
    }

    /// **Verification bullet (4):** the per-`Application` token bucket bounds a burst, and it refills
    /// once the window elapses (proved with the injected clock, not a sleep).
    #[tokio::test]
    async fn the_per_app_rate_limiter_bounds_bursts_and_refills() {
        let writer = Arc::new(RecordingWriter::default());
        let (tx, mut rx) = mpsc::channel(512);
        let clock = Arc::new(ManualClock::new());
        let metrics = Metrics::with_fixed_series();
        let notifier = Notifier::new(
            tx,
            Arc::new(NotificationConfig::built_in()),
            metrics.clone(),
            clock.clone(),
        )
        .with_rate_limit(10, Duration::from_secs(300));
        let observer = NotificationObserver::new(writer, notifier);
        let demo = app(
            "ferriscd-system",
            "demo-app",
            &[("on-sync-succeeded", "slack", "payments-oncall")],
        );

        // 20 distinct revisions, all synced: 20 distinct dedup keys, so only the bucket can stop them.
        let mut queued = 0;
        let mut limited = 0;
        for index in 0..20 {
            let revision = format!("rev-{index}");
            match observer.observe(
                &demo,
                &status(
                    SyncStatus::Synced,
                    HealthStatus::Healthy,
                    Some(true),
                    &revision,
                ),
            ) {
                ObservingOutcome::Queued => queued += 1,
                ObservingOutcome::RateLimited => limited += 1,
                other => panic!("unexpected outcome {other:?}"),
            }
            clock.advance(Duration::from_millis(100));
        }
        assert_eq!(queued, 10, "the bucket holds exactly one burst");
        assert_eq!(limited, 10, "the rest of the burst is rate limited");
        assert_eq!(drain(&mut rx).len(), 10);
        // The suppressed deliveries are visible, not silently dropped.
        let body = metrics.encode().expect("metrics encode");
        assert!(
            body.contains(
                "ferriscd_notifications_total{service=\"slack\",outcome=\"suppressed\"} 10"
            ),
            "{body}"
        );

        // After the window, one token is available again (10 per 300 s = one every 30 s).
        clock.advance(Duration::from_secs(300));
        assert_eq!(
            observer.observe(
                &demo,
                &status(
                    SyncStatus::Synced,
                    HealthStatus::Healthy,
                    Some(true),
                    "rev-refilled"
                ),
            ),
            ObservingOutcome::Queued
        );
        assert_eq!(drain(&mut rx).len(), 1);
    }

    /// Each trigger fires on its own edge: entering the state, not being in it — and
    /// `on-out-of-sync` only after its debounce.
    #[tokio::test]
    async fn every_trigger_fires_on_its_edge_and_out_of_sync_is_debounced() {
        let mut harness = test_harness();
        let demo = app("ferriscd-system", "demo-app", &ALL_TRIGGERS);

        // 1. Out of sync, healthy: nothing yet (inside the 60 s debounce).
        let out_of_sync = status(
            SyncStatus::OutOfSync,
            HealthStatus::Healthy,
            Some(true),
            "rev-1",
        );
        assert_eq!(
            harness.observer.observe(&demo, &out_of_sync),
            ObservingOutcome::Idle
        );
        assert!(drain(&mut harness.rx).is_empty());

        // 2. Still out of sync after 59 s: still inside the debounce.
        harness.clock.advance(Duration::from_secs(59));
        assert_eq!(
            harness.observer.observe(&demo, &out_of_sync),
            ObservingOutcome::Idle
        );

        // 3. 60 s after the first observation: the debounced trigger fires exactly once.
        harness.clock.advance(Duration::from_secs(1));
        assert_eq!(
            harness.observer.observe(&demo, &out_of_sync),
            ObservingOutcome::Queued
        );
        let jobs = drain(&mut harness.rx);
        assert_eq!(jobs.len(), 1);
        assert!(
            jobs[0].dedup_key.contains("on-out-of-sync"),
            "{:?}",
            jobs[0].dedup_key
        );
        assert_eq!(jobs[0].service, NotificationService::Webhook);

        // 4. Repeated requeues while still out of sync: deduplicated, not repeated pages.
        harness.clock.advance(Duration::from_secs(180));
        assert_eq!(
            harness.observer.observe(&demo, &out_of_sync),
            ObservingOutcome::Deduplicated
        );
        assert!(drain(&mut harness.rx).is_empty());

        // 5. The sync succeeds: entering `Synced` fires on-sync-succeeded.
        let synced = status(
            SyncStatus::Synced,
            HealthStatus::Healthy,
            Some(true),
            "rev-1",
        );
        assert_eq!(
            harness.observer.observe(&demo, &synced),
            ObservingOutcome::Queued
        );
        assert_eq!(drain(&mut harness.rx).len(), 1);

        // 6. Health degrades: on-health-degraded fires; repeating it does not.
        let degraded = status(
            SyncStatus::Synced,
            HealthStatus::Degraded,
            Some(true),
            "rev-1",
        );
        assert_eq!(
            harness.observer.observe(&demo, &degraded),
            ObservingOutcome::Queued
        );
        harness.clock.advance(Duration::from_secs(180));
        assert_eq!(
            harness.observer.observe(&demo, &degraded),
            ObservingOutcome::Idle
        );
        let jobs = drain(&mut harness.rx);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].service, NotificationService::PagerDuty);

        // 7. A failed pass (Ready=False) fires on-sync-failed once.
        let failed = status(
            SyncStatus::Unknown,
            HealthStatus::Degraded,
            Some(false),
            "rev-1",
        );
        assert_eq!(
            harness.observer.observe(&demo, &failed),
            ObservingOutcome::Queued
        );
        harness.clock.advance(Duration::from_secs(180));
        assert_eq!(
            harness.observer.observe(&demo, &failed),
            ObservingOutcome::Idle
        );
        let jobs = drain(&mut harness.rx);
        assert_eq!(jobs.len(), 1);
        assert!(jobs[0].dedup_key.contains("on-sync-failed"));
    }

    /// An `Application` that subscribes to nothing costs nothing, and an unknown trigger in the
    /// annotation cannot deliver.
    #[tokio::test]
    async fn unsubscribed_applications_never_enqueue() {
        let mut harness = test_harness();
        let demo = app("ferriscd-system", "demo-app", &[]);
        assert_eq!(
            harness.observer.observe(
                &demo,
                &status(SyncStatus::Synced, HealthStatus::Healthy, Some(true), "r")
            ),
            ObservingOutcome::Idle
        );
        assert!(drain(&mut harness.rx).is_empty());
        assert_eq!(harness.observer.notifier().tracked_apps(), 0);

        // Subscribed to a trigger that never fires: nothing is queued, nothing leaks.
        let mut only_out_of_sync = test_harness();
        let other = app(
            "ferriscd-system",
            "demo-app",
            &[("on-out-of-sync", "slack", "oncall")],
        );
        assert_eq!(
            only_out_of_sync.observer.observe(
                &other,
                &status(SyncStatus::Synced, HealthStatus::Healthy, Some(true), "r")
            ),
            ObservingOutcome::Idle
        );
        assert_eq!(drain(&mut only_out_of_sync.rx).len(), 0);
    }

    /// A rejected `/status` patch must not notify: the world did not change.
    #[tokio::test]
    async fn a_failed_status_patch_never_notifies() {
        let writer = Arc::new(RecordingWriter {
            patched: Mutex::new(Vec::new()),
            fail: true,
        });
        let (tx, mut rx) = mpsc::channel(8);
        let clock = Arc::new(ManualClock::new());
        let notifier = Notifier::new(
            tx,
            Arc::new(NotificationConfig::built_in()),
            Metrics::new(),
            clock,
        );
        let observer = NotificationObserver::new(writer, notifier);
        let demo = app(
            "ferriscd-system",
            "demo-app",
            &[("on-sync-failed", "slack", "oncall")],
        );
        let err = observer
            .patch(
                &demo,
                status(
                    SyncStatus::Unknown,
                    HealthStatus::Degraded,
                    Some(false),
                    "r",
                ),
            )
            .await
            .expect_err("the inner writer failed");
        assert!(err.to_string().contains("refused"), "{err}");
        assert!(
            drain(&mut rx).is_empty(),
            "no notification for a rejected write"
        );
    }

    /// The deduplication cache is bounded: the oldest key is evicted, so memory cannot grow with the
    /// number of distinct revisions a fleet has ever synced.
    #[tokio::test]
    async fn the_dedup_cache_is_bounded_and_evicts_the_oldest_key() {
        let writer = Arc::new(RecordingWriter::default());
        let (tx, mut rx) = mpsc::channel(512);
        let clock = Arc::new(ManualClock::new());
        let notifier = Notifier::new(
            tx,
            Arc::new(NotificationConfig::built_in()),
            Metrics::new(),
            clock.clone(),
        )
        .with_dedup_capacity(2)
        .with_rate_limit(1_000, Duration::from_secs(300));
        let observer = NotificationObserver::new(writer, notifier);
        let demo = app(
            "ferriscd-system",
            "demo-app",
            &[("on-sync-succeeded", "slack", "oncall")],
        );

        for revision in ["rev-a", "rev-b", "rev-c"] {
            assert_eq!(
                observer.observe(
                    &demo,
                    &status(
                        SyncStatus::Synced,
                        HealthStatus::Healthy,
                        Some(true),
                        revision
                    )
                ),
                ObservingOutcome::Queued
            );
            clock.advance(Duration::from_secs(1));
            assert!(
                observer.notifier().dedup_entries() <= 2,
                "the dedup cache must stay bounded, got {}",
                observer.notifier().dedup_entries()
            );
        }
        assert_eq!(drain(&mut rx).len(), 3);

        // `rev-a` was evicted, so it is no longer deduplicated (the LRU, not a permanent ledger).
        assert_eq!(
            observer.observe(
                &demo,
                &status(
                    SyncStatus::Synced,
                    HealthStatus::Healthy,
                    Some(true),
                    "rev-a"
                )
            ),
            ObservingOutcome::Queued
        );
        // `rev-c` is still cached, so re-observing it is deduplicated rather than re-delivered.
        assert_eq!(
            observer.observe(
                &demo,
                &status(
                    SyncStatus::Synced,
                    HealthStatus::Healthy,
                    Some(true),
                    "rev-c"
                )
            ),
            ObservingOutcome::Deduplicated
        );
    }

    /// **Trap-adjacent:** a full queue drops the notification (counted) and never blocks the
    /// reconcile, so a hung receiver cannot stall a sync loop.
    #[tokio::test]
    async fn a_full_queue_drops_without_blocking() {
        let writer = Arc::new(RecordingWriter::default());
        let (tx, mut rx) = mpsc::channel(1);
        let clock = Arc::new(ManualClock::new());
        let metrics = Metrics::with_fixed_series();
        let notifier = Notifier::new(
            tx,
            Arc::new(NotificationConfig::built_in()),
            metrics.clone(),
            clock.clone(),
        )
        .with_rate_limit(1_000, Duration::from_secs(300));
        let observer = NotificationObserver::new(writer, notifier);
        let demo = app(
            "ferriscd-system",
            "demo-app",
            &[("on-sync-succeeded", "slack", "oncall")],
        );

        assert_eq!(
            observer.observe(
                &demo,
                &status(
                    SyncStatus::Synced,
                    HealthStatus::Healthy,
                    Some(true),
                    "rev-1"
                )
            ),
            ObservingOutcome::Queued
        );
        clock.advance(Duration::from_secs(1));
        // The queue holds one job and nobody drained it: the next distinct event is dropped.
        assert_eq!(
            observer.observe(
                &demo,
                &status(
                    SyncStatus::Synced,
                    HealthStatus::Healthy,
                    Some(true),
                    "rev-2"
                )
            ),
            ObservingOutcome::Dropped
        );
        let body = metrics.encode().expect("metrics encode");
        assert!(
            body.contains("ferriscd_notifications_total{service=\"slack\",outcome=\"dropped\"}"),
            "{body}"
        );
        assert_eq!(drain(&mut rx).len(), 1);
    }

    /// The edge/rate tables are bounded and a deleted `Application`'s entry is dropped.
    #[tokio::test]
    async fn observer_state_is_bounded_and_released_on_delete() {
        let writer = Arc::new(RecordingWriter::default());
        let (tx, _rx) = mpsc::channel(512);
        let clock = Arc::new(ManualClock::new());
        let notifier = Notifier::new(
            tx,
            Arc::new(NotificationConfig::built_in()),
            Metrics::new(),
            clock.clone(),
        )
        .with_max_tracked_apps(2)
        .with_rate_limit(1_000, Duration::from_secs(300));
        let observer = NotificationObserver::new(writer, notifier);

        for index in 0..10 {
            let demo = app(
                "ferriscd-system",
                &format!("app-{index}"),
                &[("on-sync-succeeded", "slack", "oncall")],
            );
            clock.advance(Duration::from_secs(1));
            observer.observe(
                &demo,
                &status(SyncStatus::Synced, HealthStatus::Healthy, Some(true), "rev"),
            );
            assert!(
                observer.notifier().tracked_apps() <= 2,
                "edge state must stay bounded, got {}",
                observer.notifier().tracked_apps()
            );
        }

        let demo = app(
            "ferriscd-system",
            "app-9",
            &[("on-sync-succeeded", "slack", "oncall")],
        );
        let tracked_before = observer.notifier().tracked_apps();
        let dedup_before = observer.notifier().dedup_entries();
        assert!(dedup_before >= 1);
        observer.forget_app(&demo);
        assert!(
            observer.notifier().tracked_apps() < tracked_before.max(1),
            "the deleted application's edge state is released"
        );
        assert_eq!(
            observer.notifier().dedup_entries(),
            dedup_before - 1,
            "the deleted application's dedup key is released too"
        );
    }

    /// **Finding P19-M1:** an event the token bucket suppressed leaves the edge state exactly where it
    /// was, so the next observation *retries* it instead of the failure being silently swallowed for
    /// the lifetime of the `Application` (with the edge committed first, "we already saw
    /// `Ready=False`" would be permanent state and the failure would never be announced).
    #[tokio::test]
    async fn a_rate_limited_event_is_retried_on_the_next_observation() {
        let writer = Arc::new(RecordingWriter::default());
        let (tx, mut rx) = mpsc::channel(512);
        let clock = Arc::new(ManualClock::new());
        let metrics = Metrics::with_fixed_series();
        let notifier = Notifier::new(
            tx,
            Arc::new(NotificationConfig::built_in()),
            metrics.clone(),
            clock.clone(),
        )
        // One notification per window: the second event of a burst can only be rate limited.
        .with_rate_limit(1, Duration::from_secs(300));
        let observer = NotificationObserver::new(writer, notifier);
        let demo = app(
            "ferriscd-system",
            "demo-app",
            &[("on-sync-failed", "slack", "payments-oncall")],
        );

        let first = status(
            SyncStatus::Unknown,
            HealthStatus::Degraded,
            Some(false),
            "rev-1",
        );
        assert_eq!(
            observer.observe(&demo, &first),
            ObservingOutcome::Queued,
            "the first failure of the window is announced"
        );
        assert_eq!(drain(&mut rx).len(), 1);

        // A new revision fails inside the same window: the bucket is empty.
        clock.advance(Duration::from_secs(1));
        let second = status(
            SyncStatus::Unknown,
            HealthStatus::Degraded,
            Some(false),
            "rev-2",
        );
        assert_eq!(
            observer.observe(&demo, &second),
            ObservingOutcome::RateLimited
        );
        assert!(drain(&mut rx).is_empty());
        assert_eq!(
            observer.notifier().dedup_entries(),
            1,
            "a suppressed event must not consume a deduplication entry (only the delivered one is \
             recorded)"
        );
        let body = metrics.encode().expect("metrics encode");
        assert!(
            body.contains(
                "ferriscd_notifications_total{service=\"slack\",outcome=\"suppressed\"} 1"
            ),
            "a suppressed delivery is visible in the metric: {body}"
        );

        // The very same status arrives again once the window has refilled: because the edge state
        // was rolled back, this is still a *new* failure and it is announced now.
        clock.advance(Duration::from_secs(300));
        assert_eq!(
            observer.observe(&demo, &second),
            ObservingOutcome::Queued,
            "a rate-limited event is retried, not lost"
        );
        let jobs = drain(&mut rx);
        assert_eq!(jobs.len(), 1);
        assert!(
            jobs[0].dedup_key.contains("rev=rev-2"),
            "the retried page describes the revision that was suppressed: {}",
            jobs[0].dedup_key
        );

        // That retried delivery *is* remembered: a second observer that lost the edge state (a
        // restart) does not page a third time — the rollback is conditional, not a blanket "never
        // record".
        let (tx, mut restarted_rx) = mpsc::channel(512);
        let mut restarted = Notifier::new(
            tx,
            Arc::new(NotificationConfig::built_in()),
            Metrics::new(),
            clock.clone(),
        )
        .with_rate_limit(1, Duration::from_secs(300));
        restarted.state = observer.notifier().state.clone();
        lock_recover(&restarted.state).observations.clear();
        let restarted = NotificationObserver::new(Arc::new(RecordingWriter::default()), restarted);
        clock.advance(Duration::from_secs(1));
        assert_eq!(
            restarted.observe(&demo, &second),
            ObservingOutcome::Deduplicated
        );
        assert!(drain(&mut restarted_rx).is_empty());
    }

    /// **Finding P19-M1 (queue-full half):** a notification dropped on a full queue is counted and
    /// logged, **not** recorded as delivered, so the same event is retried once the queue drains. A
    /// `try_send` failure must never cost the alert — and it must not cost a rate-limit token
    /// either: the bucket holds exactly two tokens here, so a drop that kept its token would make
    /// the retry `RateLimited` and the event would be lost for a whole window.
    #[tokio::test]
    async fn a_notification_dropped_on_a_full_queue_is_retried_after_the_queue_drains() {
        let writer = Arc::new(RecordingWriter::default());
        let (tx, mut rx) = mpsc::channel(1);
        let clock = Arc::new(ManualClock::new());
        let metrics = Metrics::with_fixed_series();
        let notifier = Notifier::new(
            tx,
            Arc::new(NotificationConfig::built_in()),
            metrics.clone(),
            clock.clone(),
        )
        .with_rate_limit(2, Duration::from_secs(300));
        let observer = NotificationObserver::new(writer, notifier);
        let demo = app(
            "ferriscd-system",
            "demo-app",
            &[("on-sync-succeeded", "slack", "oncall")],
        );

        let synced = |revision: &str| {
            status(
                SyncStatus::Synced,
                HealthStatus::Healthy,
                Some(true),
                revision,
            )
        };
        assert_eq!(
            observer.observe(&demo, &synced("rev-1")),
            ObservingOutcome::Queued
        );
        // The queue holds one job and nobody drains it: this event cannot be enqueued.
        clock.advance(Duration::from_secs(1));
        assert_eq!(
            observer.observe(&demo, &synced("rev-2")),
            ObservingOutcome::Dropped,
            "a full queue drops the notification instead of delaying the reconcile"
        );
        assert_eq!(
            observer.notifier().dedup_entries(),
            1,
            "the dropped event is not recorded as delivered"
        );
        let body = metrics.encode().expect("metrics encode");
        assert!(
            body.contains("ferriscd_notifications_total{service=\"slack\",outcome=\"dropped\"} 1"),
            "{body}"
        );
        // The refund: the drop is *not* a rate-limited suppression, so the token it reserved is
        // available again and the metric shows no suppression at all.
        assert!(
            body.contains(
                "ferriscd_notifications_total{service=\"slack\",outcome=\"suppressed\"} 0"
            ),
            "a queue-full drop must not be counted (or charged) as a rate-limit suppression: {body}"
        );

        // The worker catches up; the next observation of the *unchanged* state still announces it,
        // because the drop rolled the edge state back and refunded the token.
        assert_eq!(drain(&mut rx).len(), 1);
        clock.advance(Duration::from_secs(1));
        assert_eq!(
            observer.observe(&demo, &synced("rev-2")),
            ObservingOutcome::Queued,
            "a queue-full drop is retried once there is room: it must not have burned a token"
        );
        let jobs = drain(&mut rx);
        assert_eq!(jobs.len(), 1);
        assert!(
            jobs[0].dedup_key.contains("rev=rev-2"),
            "{}",
            jobs[0].dedup_key
        );
    }

    /// **Finding R1-M6:** an `Application` outside `--notifications-allowed-namespaces` is completely
    /// inert — it is refused *before* any gate, so it creates no edge state, consumes no
    /// deduplication entry, spends no rate-limit token and its malformed annotations are not even
    /// reported. The allowlisted tenant is unaffected.
    #[tokio::test]
    async fn a_tenant_outside_the_allowed_namespaces_touches_no_state() {
        let writer = Arc::new(RecordingWriter::default());
        let (tx, mut rx) = mpsc::channel(512);
        let clock = Arc::new(ManualClock::new());
        let metrics = Metrics::with_fixed_series();
        let notifier = Notifier::new(
            tx,
            Arc::new(NotificationConfig::built_in()),
            metrics.clone(),
            clock.clone(),
        )
        .with_allowed_namespaces(Some(vec!["team-a".to_owned()]));
        assert_eq!(
            notifier.allowed_namespaces(),
            Some(["team-a".to_owned()].as_slice()),
            "the allowlist is what the operator passed"
        );
        let observer = NotificationObserver::new(writer, notifier);

        // A denied tenant, with both a valid subscription and a typo nobody will fix.
        let mut denied = app(
            "team-b",
            "demo-app",
            &[("on-sync-failed", "slack", "payments-oncall")],
        );
        denied
            .metadata
            .annotations
            .as_mut()
            .expect("the helper sets annotations")
            .insert(
                "notifications.ferriscd.io/subscribe.on-everything.slack".to_owned(),
                "x".to_owned(),
            );
        let failing = status(
            SyncStatus::Unknown,
            HealthStatus::Degraded,
            Some(false),
            "rev-1",
        );
        for _ in 0..3 {
            clock.advance(Duration::from_secs(180));
            assert_eq!(
                observer.observe(&denied, &failing),
                ObservingOutcome::Idle,
                "a tenant outside the allowlist never notifies"
            );
        }
        assert!(drain(&mut rx).is_empty());
        assert_eq!(
            observer.notifier().tracked_apps(),
            0,
            "no edge state is created for a denied tenant"
        );
        assert_eq!(
            observer.notifier().dedup_entries(),
            0,
            "no deduplication entry is consumed by a denied tenant"
        );
        assert_eq!(
            observer.notifier().reported_malformed(),
            0,
            "a denied tenant's malformed annotation is not even reported"
        );
        let body = metrics.encode().expect("metrics encode");
        let recorded: Vec<&str> = body
            .lines()
            .filter(|line| line.starts_with("ferriscd_notifications_total"))
            .filter(|line| !line.trim_end().ends_with(" 0"))
            .collect();
        assert!(
            recorded.is_empty(),
            "a denied tenant leaves every notification counter at zero: {recorded:?}"
        );

        // The allowlisted tenant is unaffected.
        let allowed = app(
            "team-a",
            "demo-app",
            &[("on-sync-failed", "slack", "payments-oncall")],
        );
        assert_eq!(
            observer.observe(&allowed, &failing),
            ObservingOutcome::Queued
        );
        assert_eq!(drain(&mut rx).len(), 1);

        // An empty allowlist denies everyone (fail closed), and `None` keeps the historical
        // "any namespace may opt in" behaviour.
        let (tx, mut empty_rx) = mpsc::channel(512);
        let empty = NotificationObserver::new(
            Arc::new(RecordingWriter::default()),
            Notifier::new(
                tx,
                Arc::new(NotificationConfig::built_in()),
                Metrics::new(),
                clock.clone(),
            )
            .with_allowed_namespaces(Some(Vec::new())),
        );
        assert_eq!(
            empty.observe(&allowed, &failing),
            ObservingOutcome::Idle,
            "an empty allowlist is not 'allow everything'"
        );
        assert!(drain(&mut empty_rx).is_empty());

        let (tx, mut open_rx) = mpsc::channel(512);
        let open = NotificationObserver::new(
            Arc::new(RecordingWriter::default()),
            Notifier::new(
                tx,
                Arc::new(NotificationConfig::built_in()),
                Metrics::new(),
                clock,
            ),
        );
        assert_eq!(
            open.observe(&denied, &failing),
            ObservingOutcome::Queued,
            "unset means the pre-existing behaviour: every namespace may opt in"
        );
        assert_eq!(drain(&mut open_rx).len(), 1);
    }

    /// **Finding R1-M7:** a malformed subscription annotation is reported **once per `Application`**,
    /// not on every 180 s requeue (the parser runs on every pass, so a warning at the parse site
    /// would flood the log forever). The reported set is bounded, so a fleet that invents a fresh
    /// typo every pass cannot grow it without limit.
    #[tokio::test]
    async fn a_malformed_subscription_is_reported_once_per_application_and_bounded() {
        let mut harness = test_harness();
        let mut broken = app(
            "ferriscd-system",
            "demo-app",
            &[("on-sync-failed", "slack", "payments-oncall")],
        );
        broken
            .metadata
            .annotations
            .as_mut()
            .expect("the helper sets annotations")
            .insert(
                "notifications.ferriscd.io/subscribe.on-everything.slack".to_owned(),
                "x".to_owned(),
            );
        let failing = status(
            SyncStatus::Unknown,
            HealthStatus::Degraded,
            Some(false),
            "rev-1",
        );

        for pass in 0..4 {
            harness.clock.advance(Duration::from_secs(180));
            harness.observer.observe(&broken, &failing);
            assert_eq!(
                harness.observer.notifier().reported_malformed(),
                1,
                "pass {pass}: the same refusal is remembered, so the warning is emitted once"
            );
        }

        // A second refused key on the same Application is its own report.
        broken
            .metadata
            .annotations
            .as_mut()
            .expect("annotations")
            .insert(
                "notifications.ferriscd.io/subscribe.on-sync-failed.sms".to_owned(),
                "x".to_owned(),
            );
        harness.observer.observe(&broken, &failing);
        assert_eq!(harness.observer.notifier().reported_malformed(), 2);

        // A different Application gets its own report for the same key (the set is keyed by
        // `application/annotation`, not by annotation alone).
        let mut other = broken.clone();
        other.metadata.name = Some("other-app".to_owned());
        harness.observer.observe(&other, &failing);
        assert_eq!(harness.observer.notifier().reported_malformed(), 4);

        // Bounded: a fleet that generates a fresh typo on every pass evicts, it does not grow.
        drain(&mut harness.rx);
        let mut flooded = app("ferriscd-system", "flood", &[]);
        let annotations = flooded
            .metadata
            .annotations
            .get_or_insert_with(BTreeMap::new);
        for index in 0..MAX_REPORTED_MALFORMED + 8 {
            annotations.insert(
                format!("notifications.ferriscd.io/subscribe.on-typo-{index}.slack"),
                "x".to_owned(),
            );
        }
        harness.observer.observe(&flooded, &failing);
        assert_eq!(
            harness.observer.notifier().reported_malformed(),
            MAX_REPORTED_MALFORMED,
            "the remembered refusals are capped at MAX_REPORTED_MALFORMED"
        );
        // Nothing was queued for the malformed-only Application: a typo never becomes a delivery.
        assert!(
            drain(&mut harness.rx).is_empty(),
            "a refused annotation is never delivered to"
        );
    }

    /// **Finding R1-N7:** the revision is *bounded* in the deduplication key. A Git revision is
    /// attacker-influenced text of unbounded length, and this key is rendered into the PagerDuty
    /// `dedup_key` body field and the `X-FerrisCD-Delivery` header, both of which receivers
    /// size-limit. Long revisions are replaced by a stable `sha256:<hex>`.
    #[tokio::test]
    async fn the_dedup_key_bounds_an_unbounded_revision() {
        let (tx, mut rx) = mpsc::channel(512);
        let clock = Arc::new(ManualClock::new());
        let observer = NotificationObserver::new(
            Arc::new(RecordingWriter::default()),
            Notifier::new(
                tx,
                Arc::new(NotificationConfig::built_in()),
                Metrics::new(),
                clock.clone(),
            )
            .with_rate_limit(1_000, Duration::from_secs(300)),
        );
        let demo = app(
            "ferriscd-system",
            "demo-app",
            &[("on-sync-succeeded", "slack", "oncall")],
        );
        let synced = |revision: &str| {
            status(
                SyncStatus::Synced,
                HealthStatus::Healthy,
                Some(true),
                revision,
            )
        };

        // A 4 KiB "revision" is refused verbatim: it is hashed.
        let hostile = "f".repeat(4_096);
        assert_eq!(
            observer.observe(&demo, &synced(&hostile)),
            ObservingOutcome::Queued
        );
        let jobs = drain(&mut rx);
        assert_eq!(jobs.len(), 1);
        let key = &jobs[0].dedup_key;
        assert!(
            key.contains("rev=sha256:") && !key.contains(&hostile),
            "the long revision is hashed, not copied: {key}"
        );
        assert!(
            key.len() < 256,
            "the key stays bounded (it is a header value and a PagerDuty field): {key}"
        );
        assert!(key.is_ascii(), "the key is header-safe ASCII: {key}");

        // Stable across observations: the same hostile revision is the *same* event. The edge state
        // is what makes an unchanged status silent; the LRU is what suppresses it once that state is
        // gone (a restart), which is the half this pins.
        clock.advance(Duration::from_secs(1));
        assert_eq!(
            observer.observe(&demo, &synced(&hostile)),
            ObservingOutcome::Idle,
            "an unchanged status produces no edge"
        );
        let (tx, mut restarted_rx) = mpsc::channel(512);
        let mut restarted = Notifier::new(
            tx,
            Arc::new(NotificationConfig::built_in()),
            Metrics::new(),
            clock.clone(),
        )
        .with_rate_limit(1_000, Duration::from_secs(300));
        restarted.state = observer.notifier().state.clone();
        lock_recover(&restarted.state).observations.clear();
        let restarted = NotificationObserver::new(Arc::new(RecordingWriter::default()), restarted);
        assert_eq!(
            restarted.observe(&demo, &synced(&hostile)),
            ObservingOutcome::Deduplicated,
            "the hash is deterministic, so the deduplication still works"
        );
        assert!(drain(&mut restarted_rx).is_empty());

        // A different long revision is a different event.
        clock.advance(Duration::from_secs(1));
        assert_eq!(
            observer.observe(&demo, &synced(&"e".repeat(4_096))),
            ObservingOutcome::Queued
        );
        drain(&mut rx);

        // A normal revision is kept verbatim, because an operator reads this key.
        clock.advance(Duration::from_secs(1));
        assert_eq!(
            observer.observe(&demo, &synced("c0ffee1")),
            ObservingOutcome::Queued
        );
        let jobs = drain(&mut rx);
        assert!(
            jobs[0].dedup_key.contains("rev=c0ffee1"),
            "{}",
            jobs[0].dedup_key
        );

        // The boundary itself: 64 characters verbatim, 65 hashed.
        clock.advance(Duration::from_secs(1));
        assert_eq!(
            observer.observe(&demo, &synced(&"a".repeat(64))),
            ObservingOutcome::Queued
        );
        let jobs = drain(&mut rx);
        assert!(
            jobs[0]
                .dedup_key
                .contains(&format!("rev={}", "a".repeat(64))),
            "{}",
            jobs[0].dedup_key
        );
        clock.advance(Duration::from_secs(1));
        assert_eq!(
            observer.observe(&demo, &synced(&"a".repeat(65))),
            ObservingOutcome::Queued
        );
        let jobs = drain(&mut rx);
        assert!(
            jobs[0].dedup_key.contains("rev=sha256:"),
            "65 characters is already too long for a header: {}",
            jobs[0].dedup_key
        );
    }
}
