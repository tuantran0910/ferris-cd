//! Hardened GitHub and GitLab webhooks (`T14.2`).
//!
//! A webhook is an **unauthenticated, internet-facing** endpoint that makes the control plane talk
//! to a Git remote, so every layer below is a defence against a different attack:
//!
//! | Layer | Attack it stops |
//! |---|---|
//! | [`DefaultBodyLimit`](axum::extract::DefaultBodyLimit) of 1 MiB, installed on the whole router before any parsing | memory exhaustion from a huge body |
//! | `X-Hub-Signature-256` HMAC-SHA256, constant-time | forged deliveries (anyone can POST a JSON body) |
//! | `X-GitHub-Delivery` dedupe in a bounded TTL cache (10 000 ids / 15 min) | replay storms and GitHub's own retries double-syncing |
//! | `X-Gitlab-Token` shared secret, constant-time | forged deliveries (GitLab has no HMAC, so the token is the whole authentication) |
//! | secondary rate limit per client | a valid-but-hostile caller hammering one repository |
//! | per-repository 2 s debounce + jittered fan-out | a monorepo push matching 50 `Application`s becoming 50 simultaneous reconciles (thundering herd) |
//!
//! ## GitHub vs GitLab: two different, non-interchangeable schemes
//!
//! GitHub signs the raw body with a shared secret (`sha256=<hex>`), which authenticates **the
//! content**; GitLab sends a static token in a header, which authenticates **the caller** but says
//! nothing about the body. Implementing "GitHub HMAC *or* a token" for both — or reusing the delivery
//! id as a token — would silently weaken whichever scheme is checked second (finding H8).
//!
//! ## Ordering
//!
//! Authenticate **before** touching the dedupe cache: an unauthenticated caller must not be able to
//! burn a legitimate delivery id. Deduplicate **before** parsing the payload: a replay must cost one
//! map lookup, not a JSON parse and a cluster read.
//!
//! ## What a webhook does *not* do
//!
//! It never applies anything. It patches `ferriscd.io/refresh` on the matched `Application`s, which
//! the composite watch predicate turns into a reconcile; the diff gate, the policy checks and the
//! machine-generated plan all still run in the controller. The response says exactly what happened
//! (`accepted`/`duplicate`/`ignored`) and never what "should" happen.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use axum::Extension;
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use ferriscd_crd::Application;
use ferriscd_crd::annotations;
use ferriscd_engine::diff::sha256;
use kube::ResourceExt as _;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use utoipa::ToSchema;

use crate::audit::{AuditOutcome, RequestId, record_webhook_delivery};
use crate::error::{ApiError, ApiErrorBody};
use crate::state::{AppState, SeamFuture};

/// GitHub's HMAC-SHA256 signature header.
pub const GITHUB_SIGNATURE_HEADER: &str = "x-hub-signature-256";

/// GitHub's event header (`push`, `ping`, ...).
pub const GITHUB_EVENT_HEADER: &str = "x-github-event";

/// GitHub's per-delivery UUID, used for replay protection.
pub const GITHUB_DELIVERY_HEADER: &str = "x-github-delivery";

/// GitLab's shared-secret header.
pub const GITLAB_TOKEN_HEADER: &str = "x-gitlab-token";

/// GitLab's event header (`Push Hook`, `Tag Push Hook`, ...).
pub const GITLAB_EVENT_HEADER: &str = "x-gitlab-event";

/// Body cap enforced by [`DefaultBodyLimit`](axum::extract::DefaultBodyLimit) before any parsing.
pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;

/// Per-repository debounce window (`T14.2`).
pub const DEFAULT_DEBOUNCE: Duration = Duration::from_secs(2);

/// Maximum per-`Application` delay inside one fan-out, so 50 matches never fire at once.
pub const DEFAULT_MAX_JITTER: Duration = Duration::from_millis(500);

/// How many `X-GitHub-Delivery` ids the replay cache holds.
pub const DEFAULT_DEDUPE_CAPACITY: usize = 10_000;

/// How long a delivery id is remembered.
pub const DEFAULT_DEDUPE_TTL: Duration = Duration::from_secs(15 * 60);

/// Longest delivery id accepted (a header is attacker-controlled; the cache must stay bounded).
pub const MAX_DELIVERY_ID_CHARS: usize = 128;

/// A webhook shared secret.
///
/// Holds credential material, so `Debug`/`Display` never render it: a log line, a `tracing::warn!`
/// or an error that captured the configuration must not publish the secret that authenticates every
/// delivery.
#[derive(Clone, PartialEq, Eq)]
pub struct WebhookSecret(String);

impl WebhookSecret {
    /// Wraps a secret, rejecting an empty or whitespace-only value.
    ///
    /// An empty secret would authenticate *everything* (an HMAC with an empty key is computable by
    /// anyone, and an empty GitLab token matches an empty header), so it is refused at construction
    /// instead of accepted as "configured".
    #[must_use]
    pub fn new(secret: impl Into<String>) -> Option<Self> {
        let secret = secret.into();
        (!secret.trim().is_empty()).then_some(Self(secret))
    }

    /// The secret bytes (only for computing/verifying the MAC).
    fn expose(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Whether `header` carries a valid `sha256=<hex>` HMAC of `body`.
    #[must_use]
    pub fn verify_github(&self, body: &[u8], header: Option<&str>) -> bool {
        let Some(header) = header else {
            return false;
        };
        let Some(hex) = header.trim().strip_prefix("sha256=") else {
            return false;
        };
        let Some(expected) = decode_hex(hex) else {
            return false;
        };
        if expected.len() != 32 {
            return false;
        }
        let actual = hmac_sha256(self.expose(), body);
        bool::from(actual.ct_eq(expected.as_slice()))
    }

    /// Whether `header` matches this token in constant time.
    #[must_use]
    pub fn verify_gitlab(&self, header: Option<&str>) -> bool {
        let Some(header) = header else {
            return false;
        };
        // Compare the SHA-256 digests of both sides: the comparison is then independent of both
        // lengths and of where the first difference is (a plain `==` on the raw token leaks a
        // prefix guess byte by byte, and a length comparison leaks the token's length).
        let expected = sha256::digest(self.expose());
        let actual = sha256::digest(header.as_bytes());
        bool::from(expected.ct_eq(&actual))
    }
}

impl fmt::Debug for WebhookSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WebhookSecret(<redacted>)")
    }
}

/// Webhook configuration.
///
/// `Debug` is derived: [`WebhookSecret`] redacts itself, so this can be logged (it is, once, at
/// startup).
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    /// GitHub HMAC secret (`None` = GitHub webhooks are refused, never accepted unverified).
    pub github_secret: Option<WebhookSecret>,
    /// GitLab shared token (`None` = GitLab webhooks are refused).
    pub gitlab_secret: Option<WebhookSecret>,
    /// Per-repository debounce window.
    pub debounce: Duration,
    /// Maximum per-`Application` fan-out delay (jitter).
    pub max_jitter: Duration,
    /// Replay-cache capacity.
    pub dedupe_capacity: usize,
    /// Replay-cache TTL.
    pub dedupe_ttl: Duration,
    /// Body cap (enforced by `DefaultBodyLimit` on the router).
    pub max_body_bytes: usize,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            github_secret: None,
            gitlab_secret: None,
            debounce: DEFAULT_DEBOUNCE,
            max_jitter: DEFAULT_MAX_JITTER,
            dedupe_capacity: DEFAULT_DEDUPE_CAPACITY,
            dedupe_ttl: DEFAULT_DEDUPE_TTL,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }
}

impl WebhookConfig {
    /// The body cap the router enforces.
    #[must_use]
    pub fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    /// Whether any webhook source is configured at all.
    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.github_secret.is_some() || self.gitlab_secret.is_some()
    }
}

/// Bounded, TTL'd replay cache for `X-GitHub-Delivery` ids.
///
/// Insertion order and a monotonic clock are enough: an entry can only expire, and the oldest
/// entries expire first, so the deque in front of the map is the eviction queue. Capacity and TTL
/// are both hard bounds — the cache can never grow with traffic.
#[derive(Debug)]
pub struct DeliveryDedupe {
    capacity: usize,
    ttl: Duration,
    state: Mutex<DedupeState>,
}

#[derive(Debug, Default)]
struct DedupeState {
    seen: HashMap<String, Instant>,
    order: VecDeque<String>,
}

impl DeliveryDedupe {
    /// Builds a cache; `capacity` is clamped to at least 1 (a zero-capacity replay cache would
    /// silently disable replay protection).
    #[must_use]
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            capacity: capacity.max(1),
            ttl,
            state: Mutex::new(DedupeState::default()),
        }
    }

    /// Admits `id` at the current time. `true` = new delivery, `false` = replay.
    pub fn admit(&self, id: &str) -> bool {
        self.admit_at(id, Instant::now())
    }

    /// Admits `id` as seen at `now` (testable without sleeping).
    pub fn admit_at(&self, id: &str, now: Instant) -> bool {
        let mut state = self.lock();
        // Expire the front: entries are ordered by admission, and time only moves forward.
        while let Some(oldest) = state.order.front() {
            let expired = state
                .seen
                .get(oldest)
                .is_some_and(|seen_at| now.saturating_duration_since(*seen_at) >= self.ttl);
            if !expired {
                break;
            }
            if let Some(id) = state.order.pop_front() {
                state.seen.remove(&id);
            }
        }
        if state.seen.contains_key(id) {
            return false;
        }
        while state.order.len() >= self.capacity {
            if let Some(oldest) = state.order.pop_front() {
                state.seen.remove(&oldest);
            }
        }
        state.seen.insert(id.to_owned(), now);
        state.order.push_back(id.to_owned());
        true
    }

    /// How many ids are currently remembered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().seen.len()
    }

    /// Whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> MutexGuard<'_, DedupeState> {
        // A poisoned replay cache is still usable: the worst case is one extra reconcile.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One matched `Application` a webhook fan-out refreshes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RefreshTarget {
    /// Namespace of the `Application`.
    pub namespace: String,
    /// Name of the `Application`.
    pub name: String,
}

impl RefreshTarget {
    /// Builds a target from an `Application`.
    #[must_use]
    pub fn for_application(app: &Application) -> Option<Self> {
        Some(Self {
            namespace: app.namespace()?,
            name: app.name_any(),
        })
    }
}

impl fmt::Display for RefreshTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.namespace, self.name)
    }
}

/// Writes `ferriscd.io/refresh` on an `Application`.
pub trait RefreshSink: Send + Sync + 'static {
    /// Requests an immediate reconcile of `target`.
    fn refresh(&self, target: RefreshTarget) -> SeamFuture<'_, ()>;
}

/// The default sink: no refresh writer is wired, so a webhook can never claim it triggered a sync.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnconfiguredRefreshSink;

impl RefreshSink for UnconfiguredRefreshSink {
    fn refresh(&self, target: RefreshTarget) -> SeamFuture<'_, ()> {
        Box::pin(async move {
            Err(ApiError::backend(&format!(
                "no ferriscd.io/refresh writer is wired, so {target} was not refreshed"
            )))
        })
    }
}

/// What [`FanOut::submit`] did with a delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanOutOutcome {
    /// The window is open and this delivery merged into it.
    Coalesced {
        /// Targets pending in this window (after the merge).
        pending: usize,
    },
    /// This delivery (re)armed the window.
    Scheduled {
        /// Targets pending in this window (after the merge).
        pending: usize,
    },
    /// Nothing matched, so nothing was scheduled.
    Empty,
}

/// Per-repository debounce plus jittered fan-out (`T14.2`).
///
/// A delivery does not refresh anything immediately. It merges its targets into a per-repository
/// window and (re)arms that window; when the window closes, every target of that window is refreshed
/// **once**, each after its own deterministic jitter. Ten pushes to one monorepo in two seconds
/// therefore cost one fan-out, not ten, and the fan-out itself is spread over
/// [`WebhookConfig::max_jitter`] instead of hitting the API server as one burst.
pub struct FanOut {
    sink: Arc<dyn RefreshSink>,
    debounce: Duration,
    max_jitter: Duration,
    state: Mutex<FanOutState>,
}

#[derive(Debug, Default)]
struct FanOutState {
    repositories: HashMap<String, PendingFanOut>,
}

#[derive(Debug)]
struct PendingFanOut {
    targets: BTreeSet<RefreshTarget>,
    deadline: tokio::time::Instant,
    generation: u64,
    armed: bool,
}

impl fmt::Debug for FanOut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FanOut")
            .field("debounce", &self.debounce)
            .field("max_jitter", &self.max_jitter)
            .finish_non_exhaustive()
    }
}

impl FanOut {
    /// Builds a fan-out from the webhook configuration and a refresh writer.
    #[must_use]
    pub fn new(config: &WebhookConfig, sink: Arc<dyn RefreshSink>) -> Self {
        Self {
            sink,
            debounce: config.debounce,
            max_jitter: config.max_jitter,
            state: Mutex::new(FanOutState::default()),
        }
    }

    /// Merges `targets` into the window for `repository`.
    ///
    /// The window is a trailing debounce: each delivery inside it extends the deadline, and the
    /// dispatcher task is spawned exactly once per window.
    pub fn submit(
        self: &Arc<Self>,
        repository: &str,
        targets: impl IntoIterator<Item = RefreshTarget>,
    ) -> FanOutOutcome {
        let merged = {
            let mut state = self.lock();
            let now = tokio::time::Instant::now();
            let incoming: BTreeSet<RefreshTarget> = targets.into_iter().collect();
            // Nothing matched and no window is open: do not create one (an empty window would keep
            // `pending_repositories` non-zero and spawn a dispatcher that has nothing to do).
            if incoming.is_empty() && !state.repositories.contains_key(repository) {
                return FanOutOutcome::Empty;
            }
            let entry = state
                .repositories
                .entry(repository.to_owned())
                .or_insert_with(|| PendingFanOut {
                    targets: BTreeSet::new(),
                    deadline: now,
                    generation: 0,
                    armed: false,
                });
            entry.targets.extend(incoming);
            if entry.targets.is_empty() {
                return FanOutOutcome::Empty;
            }
            // A trailing debounce: every delivery inside the window pushes the deadline out, and
            // the dispatcher task is spawned exactly once per window.
            entry.deadline = now + self.debounce;
            entry.generation = entry.generation.wrapping_add(1);
            let merged = (entry.targets.len(), entry.armed);
            entry.armed = true;
            merged
        };
        let (pending, was_armed) = merged;
        if !was_armed {
            let fan_out = Arc::clone(self);
            let repository = repository.to_owned();
            tokio::spawn(async move { fan_out.run_window(repository).await });
            return FanOutOutcome::Scheduled { pending };
        }
        FanOutOutcome::Coalesced { pending }
    }

    /// Waits for the window to close, then refreshes every target once.
    async fn run_window(self: Arc<Self>, repository: String) {
        loop {
            let Some((deadline, generation)) = self.window_state(&repository) else {
                return;
            };
            tokio::time::sleep_until(deadline).await;
            let Some(targets) = self.take_window(&repository, generation) else {
                // The deadline moved while we slept: another delivery extended the window.
                continue;
            };
            self.dispatch(&repository, targets).await;
            return;
        }
    }

    fn window_state(&self, repository: &str) -> Option<(tokio::time::Instant, u64)> {
        let state = self.lock();
        state
            .repositories
            .get(repository)
            .map(|entry| (entry.deadline, entry.generation))
    }

    /// Takes the targets when `generation` is still current; `None` when the window was extended.
    fn take_window(&self, repository: &str, generation: u64) -> Option<BTreeSet<RefreshTarget>> {
        let mut state = self.lock();
        let entry = state.repositories.get(repository)?;
        if entry.generation != generation {
            return None;
        }
        state
            .repositories
            .remove(repository)
            .map(|entry| entry.targets)
    }

    /// Refreshes every target concurrently, each after its own deterministic jitter.
    async fn dispatch(&self, repository: &str, targets: BTreeSet<RefreshTarget>) {
        let mut tasks = Vec::with_capacity(targets.len());
        for (index, target) in targets.into_iter().enumerate() {
            let delay = self.jitter_delay(repository, index);
            let sink = Arc::clone(&self.sink);
            tasks.push(tokio::spawn(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                if let Err(err) = sink.refresh(target.clone()).await {
                    tracing::warn!(
                        app = %target,
                        error = %err,
                        "webhook fan-out could not request a refresh; the periodic requeue still \
                         converges this Application"
                    );
                }
            }));
        }
        for task in tasks {
            // A panicking refresh writer must not take the dispatcher down with it.
            if let Err(err) = task.await {
                tracing::warn!(error = %err, "webhook fan-out task failed");
            }
        }
        tracing::debug!(
            repository = %repository,
            "webhook fan-out dispatched"
        );
    }

    /// Deterministic jitter in `0..max_jitter`, derived from the repository and the target index.
    ///
    /// Deterministic on purpose: a fan-out is reproducible (and testable), while still spreading 50
    /// refreshes across the jitter window instead of firing them at the same instant.
    fn jitter_delay(&self, repository: &str, index: usize) -> Duration {
        if self.max_jitter.is_zero() {
            return Duration::ZERO;
        }
        let seed = sha256::digest(format!("{repository}#{index}").as_bytes());
        let fraction = u32::from_be_bytes([seed[0], seed[1], seed[2], seed[3]]);
        let window_nanos = u64::try_from(self.max_jitter.as_nanos()).unwrap_or(u64::MAX);
        if window_nanos == 0 {
            return Duration::ZERO;
        }
        Duration::from_nanos(u64::from(fraction) % window_nanos)
    }

    fn lock(&self) -> MutexGuard<'_, FanOutState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Repositories with an open window (test/observability seam).
    #[must_use]
    pub fn pending_repositories(&self) -> usize {
        self.lock().repositories.len()
    }
}

/// Whether a pushed ref is a branch or a tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefKind {
    /// `refs/heads/<name>`.
    Branch,
    /// `refs/tags/<name>`.
    Tag,
}

/// The ref a push event reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushRef {
    /// Branch or tag.
    pub kind: RefKind,
    /// Short name (`main`, `v1.2.3`).
    pub name: String,
    /// The pushed repository's default branch, when the payload reports one.
    pub default_branch: Option<String>,
}

impl PushRef {
    /// The full `refs/...` name.
    #[must_use]
    pub fn full(&self) -> String {
        match self.kind {
            RefKind::Branch => format!("refs/heads/{}", self.name),
            RefKind::Tag => format!("refs/tags/{}", self.name),
        }
    }

    /// Parses a payload `ref`.
    ///
    /// A ref that is neither a branch nor a tag (`refs/notes/commits`, a pull-request ref) is not a
    /// push target FerrisCD tracks, so it is refused rather than guessed at.
    #[must_use]
    pub fn parse(reference: &str, default_branch: Option<&str>) -> Option<Self> {
        let reference = reference.trim();
        let (kind, name) = reference
            .strip_prefix("refs/heads/")
            .map(|name| (RefKind::Branch, name))
            .or_else(|| {
                reference
                    .strip_prefix("refs/tags/")
                    .map(|name| (RefKind::Tag, name))
            })?;
        if name.trim().is_empty() {
            return None;
        }
        Some(Self {
            kind,
            name: name.to_owned(),
            default_branch: default_branch.map(ToOwned::to_owned),
        })
    }
}

/// A normalized push event: the repository identities it names and the ref that moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushEvent {
    /// Every transport-specific spelling of the repository, reduced to one identity
    /// (`host/org/repo`).
    pub identities: Vec<String>,
    /// The ref that moved.
    pub reference: PushRef,
}

/// Reduces a repository URL to its transport-independent identity.
///
/// `git@github.com:org/repo.git`, `ssh://git@github.com/org/repo` and
/// `https://github.com/org/repo.git` are the **same repository**, so the scheme (and any userinfo,
/// default port, or `.git` suffix) is dropped: an `Application` that clones over SSH must react to a
/// webhook that reports an HTTPS URL. `ferriscd_controller::normalize_repo_url` does the parsing
/// (lowercasing, userinfo/default-port/`.git` removal, SCP-style expansion); this only drops the
/// scheme from the result.
#[must_use]
pub fn repository_identity(url: &str) -> Option<String> {
    let normalized = ferriscd_controller::normalize_repo_url(url)?;
    Some(match normalized.split_once("://") {
        Some((_, authority_and_path)) => authority_and_path.to_owned(),
        None => normalized,
    })
}

/// Whether `app` should be refreshed by `event`.
///
/// Two conditions, both required:
///
/// 1. the `Application`'s repository identity is one of the pushed identities;
/// 2. its `spec.source.git.targetRevision` is the branch/tag that moved — `HEAD` only matches the
///    pushed repository's **default branch**, because "HEAD" means "whatever the remote's default
///    is" and matching every branch would wake every manifest-only app on every feature branch.
#[must_use]
pub fn application_matches(app: &Application, event: &PushEvent) -> bool {
    // `T18.3`: only a Git source can be woken by a push. An OCI-backed `Application` has no Git
    // identity to match, so a push event never refreshes it.
    let Some(git) = app.spec.source.git_source() else {
        return false;
    };
    let Some(identity) = repository_identity(&git.repo_url) else {
        return false;
    };
    if !event.identities.iter().any(|pushed| pushed == &identity) {
        return false;
    }
    revision_matches(&git.target_revision, &event.reference)
}

/// Whether a `targetRevision` tracks the pushed ref.
fn revision_matches(target_revision: &str, reference: &PushRef) -> bool {
    let target = target_revision.trim();
    if target.is_empty() {
        return false;
    }
    if target.eq_ignore_ascii_case("HEAD") {
        return reference.kind == RefKind::Branch
            && reference
                .default_branch
                .as_deref()
                .is_some_and(|branch| branch == reference.name);
    }
    target == reference.name || target == reference.full()
}

/// The `ferriscd.io/refresh` request a webhook reports back.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WebhookResponse {
    /// `accepted`, `duplicate`, or `ignored`.
    pub status: String,
    /// The pushed repository, redacted (a remote URL may carry a token).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    /// The pushed ref (`refs/heads/main`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// How many `Application`s matched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched: Option<usize>,
    /// Why nothing was done (`ignored`), or which delivery id was a replay.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl WebhookResponse {
    fn accepted(repository: &str, reference: &str, matched: usize) -> Self {
        Self {
            status: "accepted".to_owned(),
            repository: Some(ferriscd_engine::manifest::redact_repo_url(repository)),
            reference: Some(reference.to_owned()),
            matched: Some(matched),
            message: None,
        }
    }

    fn duplicate(delivery: &str) -> Self {
        Self {
            status: "duplicate".to_owned(),
            repository: None,
            reference: None,
            matched: None,
            message: Some(format!(
                "delivery {delivery} was already processed; ignoring the replay"
            )),
        }
    }

    fn ignored(reason: impl Into<String>) -> Self {
        Self {
            status: "ignored".to_owned(),
            repository: None,
            reference: None,
            matched: None,
            message: Some(reason.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Payloads
// ---------------------------------------------------------------------------

/// The GitHub `push` payload, reduced to what matching needs.
#[derive(Debug, Deserialize)]
struct GitHubPushPayload {
    #[serde(default)]
    r#ref: String,
    #[serde(default)]
    repository: Option<GitHubRepository>,
}

#[derive(Debug, Deserialize)]
struct GitHubRepository {
    #[serde(default)]
    html_url: Option<String>,
    #[serde(default)]
    clone_url: Option<String>,
    #[serde(default)]
    ssh_url: Option<String>,
    #[serde(default)]
    git_url: Option<String>,
    #[serde(default)]
    default_branch: Option<String>,
}

impl GitHubRepository {
    fn urls(&self) -> impl Iterator<Item = &String> {
        [
            self.html_url.as_ref(),
            self.clone_url.as_ref(),
            self.ssh_url.as_ref(),
            self.git_url.as_ref(),
        ]
        .into_iter()
        .flatten()
    }
}

/// The GitLab `push`/`tag_push` payload, reduced to what matching needs.
#[derive(Debug, Deserialize)]
struct GitLabPushPayload {
    #[serde(default)]
    object_kind: Option<String>,
    #[serde(default)]
    r#ref: String,
    #[serde(default)]
    project: Option<GitLabProject>,
}

#[derive(Debug, Deserialize)]
struct GitLabProject {
    #[serde(default)]
    web_url: Option<String>,
    #[serde(default)]
    git_http_url: Option<String>,
    #[serde(default)]
    git_ssh_url: Option<String>,
    #[serde(default)]
    default_branch: Option<String>,
}

impl GitLabProject {
    fn urls(&self) -> impl Iterator<Item = &String> {
        [
            self.web_url.as_ref(),
            self.git_http_url.as_ref(),
            self.git_ssh_url.as_ref(),
        ]
        .into_iter()
        .flatten()
    }
}

/// Collects the distinct repository identities of a set of URLs, preserving payload order.
fn identities<'a>(urls: impl Iterator<Item = &'a String>) -> Vec<String> {
    let mut identities: Vec<String> = Vec::new();
    for url in urls {
        if let Some(identity) = repository_identity(url)
            && !identities.contains(&identity)
        {
            identities.push(identity);
        }
    }
    identities
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /api/v1/webhooks/github`.
///
/// # Errors
///
/// [`ApiError::Unprocessable`] when no GitHub secret is configured (fail closed), `400` for a
/// missing/malformed signature envelope or payload, `401` for a bad signature, and `413` (from the
/// body limit) for an oversized body. A replayed delivery and a non-`push` event are `200`/`202`:
/// they are not errors, and returning an error would make GitHub retry them.
#[utoipa::path(
    post,
    path = "/api/v1/webhooks/github",
    tag = "webhooks",
    description = "GitHub push webhook. Authenticated by `X-Hub-Signature-256` (HMAC-SHA256 over \
                   the raw body, constant-time) and replay-protected by `X-GitHub-Delivery`. \
                   Responds 202 with how many Applications matched; nothing is applied here.",
    request_body = Object,
    responses(
        (status = 200, description = "The push was accepted and a refresh scheduled, or a replayed delivery / non-push event was ignored (`status` says which)", body = WebhookResponse),
        (status = 400, description = "Malformed delivery id or payload", body = ApiErrorBody),
        (status = 401, description = "The signature is missing or wrong", body = ApiErrorBody),
        (status = 413, description = "Payload too large", body = ApiErrorBody),
        (status = 422, description = "GitHub webhooks are not configured", body = ApiErrorBody),
    ),
)]
pub async fn github(
    State(state): State<AppState>,
    request_id: Option<Extension<RequestId>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<WebhookResponse>, ApiError> {
    let req_id = request_id.as_ref().map(|Extension(id)| id.as_str());
    let Some(secret) = state.webhooks.github_secret.as_ref() else {
        record_webhook_delivery(
            &state.audit,
            req_id,
            "github",
            "github.webhook",
            None,
            AuditOutcome::Failed,
            "GitHub webhooks are not configured",
        );
        return Err(ApiError::unprocessable(
            "GitHub webhooks are not configured on this server: no HMAC secret is set, and an \
             unverified webhook is never accepted",
        ));
    };
    let signature = header(&headers, GITHUB_SIGNATURE_HEADER);
    if !secret.verify_github(&body, signature) {
        // One message for "missing", "malformed", and "wrong": the caller learns nothing about
        // which part of the check failed.
        record_webhook_delivery(
            &state.audit,
            req_id,
            "github",
            "github.webhook",
            None,
            AuditOutcome::Denied,
            "invalid or missing X-Hub-Signature-256 signature",
        );
        return Err(ApiError::unauthorized(
            "the X-Hub-Signature-256 header is missing or does not match the body",
        ));
    }

    let Some(delivery) = header(&headers, GITHUB_DELIVERY_HEADER) else {
        record_webhook_delivery(
            &state.audit,
            req_id,
            "github",
            "github.webhook",
            None,
            AuditOutcome::Failed,
            "missing X-GitHub-Delivery header",
        );
        return Err(ApiError::bad_request(
            "a GitHub delivery must carry X-GitHub-Delivery (it is the only replay protection)",
        ));
    };
    let delivery = delivery.trim();
    if delivery.is_empty() || delivery.chars().count() > MAX_DELIVERY_ID_CHARS {
        record_webhook_delivery(
            &state.audit,
            req_id,
            "github",
            "github.webhook",
            None,
            AuditOutcome::Failed,
            "malformed X-GitHub-Delivery header",
        );
        return Err(ApiError::bad_request(format!(
            "X-GitHub-Delivery must be a non-empty id of at most {MAX_DELIVERY_ID_CHARS} characters"
        )));
    }
    if !state.dedupe.admit(delivery) {
        tracing::info!(delivery = %delivery, "duplicate GitHub delivery ignored");
        record_webhook_delivery(
            &state.audit,
            req_id,
            "github",
            "github.push",
            None,
            AuditOutcome::Accepted,
            "duplicate delivery ignored",
        );
        return Ok(Json(WebhookResponse::duplicate(delivery)));
    }

    let event = header(&headers, GITHUB_EVENT_HEADER).unwrap_or_default();
    if !event.eq_ignore_ascii_case("push") {
        tracing::debug!(event = %event, delivery = %delivery, "ignoring a non-push GitHub event");
        record_webhook_delivery(
            &state.audit,
            req_id,
            "github",
            "github.non_push",
            None,
            AuditOutcome::Accepted,
            "ignored non-push GitHub event",
        );
        return Ok(Json(WebhookResponse::ignored(format!(
            "GitHub event {event:?} is not a push; FerrisCD only reacts to pushed refs"
        ))));
    }

    let payload: GitHubPushPayload = match parse_payload(&body) {
        Ok(payload) => payload,
        Err(error) => {
            record_webhook_delivery(
                &state.audit,
                req_id,
                "github",
                "github.push",
                None,
                AuditOutcome::Failed,
                "malformed GitHub push JSON payload",
            );
            return Err(error);
        }
    };
    let repository = payload
        .repository
        .as_ref()
        .and_then(|repository| repository.urls().next())
        .map_or("", String::as_str);
    let identities = payload
        .repository
        .as_ref()
        .map(|repository| identities(repository.urls()))
        .unwrap_or_default();
    let reference = PushRef::parse(
        &payload.r#ref,
        payload
            .repository
            .as_ref()
            .and_then(|repository| repository.default_branch.as_deref()),
    );

    let (response, jobs) = match fan_out_push(&state, repository, identities, reference).await {
        Ok(res) => res,
        Err(error) => {
            record_webhook_delivery(
                &state.audit,
                req_id,
                "github",
                "github.push",
                Some(repository),
                AuditOutcome::Failed,
                "GitHub push could not be matched",
            );
            return Err(error);
        }
    };
    let matched = response.matched.unwrap_or_default();
    record_webhook_delivery(
        &state.audit,
        req_id,
        "github",
        "github.push",
        Some(repository),
        AuditOutcome::Accepted,
        &format!("status={} matched={matched}", response.status),
    );
    tracing::info!(
        delivery = %delivery,
        repository = %response.repository.as_deref().unwrap_or_default(),
        reference = %response.reference.as_deref().unwrap_or_default(),
        matched,
        "GitHub push accepted"
    );
    jobs.dispatch(&state);
    Ok(Json(response))
}

/// `POST /api/v1/webhooks/gitlab`.
///
/// # Errors
///
/// See [`github`]; GitLab has no HMAC and no delivery id, so the shared token is the *whole*
/// authentication and replay protection is limited to the debounce window.
#[utoipa::path(
    post,
    path = "/api/v1/webhooks/gitlab",
    tag = "webhooks",
    description = "GitLab push webhook. Authenticated by the `X-Gitlab-Token` shared secret \
                   (constant-time); GitLab signs nothing, so the token is the whole authentication. \
                   Responds 202 with how many Applications matched; nothing is applied here.",
    request_body = Object,
    responses(
        (status = 200, description = "The push was accepted and a refresh scheduled, or a non-push event was ignored (`status` says which)", body = WebhookResponse),
        (status = 400, description = "Malformed payload", body = ApiErrorBody),
        (status = 401, description = "The token is missing or wrong", body = ApiErrorBody),
        (status = 413, description = "Payload too large", body = ApiErrorBody),
        (status = 422, description = "GitLab webhooks are not configured", body = ApiErrorBody),
    ),
)]
pub async fn gitlab(
    State(state): State<AppState>,
    request_id: Option<Extension<RequestId>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<WebhookResponse>, ApiError> {
    let req_id = request_id.as_ref().map(|Extension(id)| id.as_str());
    let Some(secret) = state.webhooks.gitlab_secret.as_ref() else {
        record_webhook_delivery(
            &state.audit,
            req_id,
            "gitlab",
            "gitlab.webhook",
            None,
            AuditOutcome::Failed,
            "GitLab webhooks are not configured",
        );
        return Err(ApiError::unprocessable(
            "GitLab webhooks are not configured on this server: no X-Gitlab-Token secret is set, \
             and an unverified webhook is never accepted",
        ));
    };
    if !secret.verify_gitlab(header(&headers, GITLAB_TOKEN_HEADER)) {
        record_webhook_delivery(
            &state.audit,
            req_id,
            "gitlab",
            "gitlab.webhook",
            None,
            AuditOutcome::Denied,
            "invalid or missing X-Gitlab-Token header",
        );
        return Err(ApiError::unauthorized(
            "the X-Gitlab-Token header is missing or does not match",
        ));
    }

    let event = header(&headers, GITLAB_EVENT_HEADER).unwrap_or_default();
    let payload: GitLabPushPayload = match parse_payload(&body) {
        Ok(payload) => payload,
        Err(error) => {
            record_webhook_delivery(
                &state.audit,
                req_id,
                "gitlab",
                "gitlab.push",
                None,
                AuditOutcome::Failed,
                "malformed GitLab push JSON payload",
            );
            return Err(error);
        }
    };
    let kind = payload
        .object_kind
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if !matches!(kind.as_str(), "push" | "tag_push") {
        tracing::debug!(event = %event, object_kind = %kind, "ignoring a non-push GitLab event");
        record_webhook_delivery(
            &state.audit,
            req_id,
            "gitlab",
            "gitlab.non_push",
            None,
            AuditOutcome::Accepted,
            "ignored non-push GitLab event",
        );
        return Ok(Json(WebhookResponse::ignored(format!(
            "GitLab event {kind:?} is not a push; FerrisCD only reacts to pushed refs"
        ))));
    }

    let repository = payload
        .project
        .as_ref()
        .and_then(|project| project.urls().next())
        .map_or("", String::as_str);
    let identities = payload
        .project
        .as_ref()
        .map(|project| identities(project.urls()))
        .unwrap_or_default();
    let reference = PushRef::parse(
        &payload.r#ref,
        payload
            .project
            .as_ref()
            .and_then(|project| project.default_branch.as_deref()),
    );

    let (response, jobs) = match fan_out_push(&state, repository, identities, reference).await {
        Ok(res) => res,
        Err(error) => {
            record_webhook_delivery(
                &state.audit,
                req_id,
                "gitlab",
                "gitlab.push",
                Some(repository),
                AuditOutcome::Failed,
                "GitLab push could not be matched",
            );
            return Err(error);
        }
    };
    let matched = response.matched.unwrap_or_default();
    record_webhook_delivery(
        &state.audit,
        req_id,
        "gitlab",
        "gitlab.push",
        Some(repository),
        AuditOutcome::Accepted,
        &format!("status={} matched={matched}", response.status),
    );
    tracing::info!(
        event = %event,
        repository = %response.repository.as_deref().unwrap_or_default(),
        reference = %response.reference.as_deref().unwrap_or_default(),
        matched,
        "GitLab push accepted"
    );
    jobs.dispatch(&state);
    Ok(Json(response))
}

/// The matched targets of one delivery, ready to be merged into the debounce window.
struct FanOutJobs {
    repository: String,
    targets: Vec<RefreshTarget>,
}

impl FanOutJobs {
    /// Schedules the fan-out (a no-op when nothing matched).
    fn dispatch(&self, state: &AppState) {
        if self.targets.is_empty() {
            return;
        }
        match state
            .fan_out
            .submit(&self.repository, self.targets.iter().cloned())
        {
            FanOutOutcome::Empty => {}
            FanOutOutcome::Scheduled { pending } => tracing::info!(
                repository = %self.repository,
                pending,
                debounce = ?state.webhooks.debounce,
                "webhook fan-out window opened"
            ),
            FanOutOutcome::Coalesced { pending } => tracing::debug!(
                repository = %self.repository,
                pending,
                "webhook delivery coalesced into the open fan-out window"
            ),
        }
    }
}

/// Matches the pushed repository/ref against every `Application` and builds the response.
async fn fan_out_push(
    state: &AppState,
    repository: &str,
    identities: Vec<String>,
    reference: Option<PushRef>,
) -> Result<(WebhookResponse, FanOutJobs), ApiError> {
    let Some(reference) = reference else {
        // A ref FerrisCD does not track (a note, a pull-request ref). Correct answer: nothing.
        return Ok((
            WebhookResponse::ignored("the pushed ref is neither a branch nor a tag"),
            FanOutJobs {
                repository: String::new(),
                targets: Vec::new(),
            },
        ));
    };
    if identities.is_empty() {
        return Err(ApiError::bad_request(
            "the payload names no usable repository URL, so no Application can be matched",
        ));
    }
    let event = PushEvent {
        identities: identities.clone(),
        reference: reference.clone(),
    };
    let applications = state.applications.list().await?;
    let mut targets: Vec<RefreshTarget> = Vec::new();
    for app in &applications {
        if application_matches(app, &event)
            && let Some(target) = RefreshTarget::for_application(app)
            && !targets.contains(&target)
        {
            targets.push(target);
        }
    }
    let matched = targets.len();
    let response = WebhookResponse::accepted(repository, &reference.full(), matched);
    Ok((
        response,
        FanOutJobs {
            repository: identities.first().cloned().unwrap_or_default(),
            targets,
        },
    ))
}

/// Reads one header as `&str` (a header that is not ASCII is treated as absent).
fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// Parses a webhook body, mapping a malformed payload to `400` without echoing it.
fn parse_payload<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|err| {
        // `serde_json`'s message can quote the offending value (which may be a secret a caller
        // pasted in), so only the position is forwarded.
        ApiError::bad_request(format!(
            "the webhook body is not the expected JSON payload (invalid JSON at line {}, column {})",
            err.line(),
            err.column()
        ))
    })
}

/// HMAC-SHA256 (RFC 2104) over the workspace's SHA-256.
///
/// The workspace deliberately has one SHA-256 (`ferriscd_engine::diff::sha256`, pinned to the FIPS
/// 180-4 known-answer vectors) instead of two; HMAC is the standard construction on top of it, and
/// the comparison is constant-time ([`subtle`]). A vetted implementation (`ring::hmac`) should
/// replace this the moment one is a direct dependency.
#[must_use]
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key_block = [0_u8; BLOCK];
    if key.len() > BLOCK {
        key_block[..32].copy_from_slice(&sha256::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(BLOCK + message.len());
    inner.extend(key_block.iter().map(|byte| byte ^ 0x36));
    inner.extend_from_slice(message);
    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend(key_block.iter().map(|byte| byte ^ 0x5c));
    outer.extend_from_slice(&sha256::digest(&inner));
    sha256::digest(&outer)
}

/// Decodes a lowercase/uppercase hex string.
fn decode_hex(value: &str) -> Option<Vec<u8>> {
    let value = value.trim();
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let (pairs, _remainder) = value.as_bytes().as_chunks::<2>();
    for pair in pairs {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Some(bytes)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The annotation key a refresh writes (`ferriscd.io/refresh`).
#[must_use]
pub fn refresh_annotation() -> &'static str {
    annotations::REFRESH
}

/// A refresh value that always changes, so the composite predicate sees a new hash.
#[must_use]
pub fn refresh_token() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    format!("{nanos:x}-{:x}", COUNTER.fetch_add(1, Ordering::Relaxed))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ferriscd_crd::ApplicationSpec;
    use tokio::sync::mpsc;

    use super::*;

    fn secret() -> WebhookSecret {
        WebhookSecret::new("s3cr3t-webhook-key").expect("a non-empty secret")
    }

    fn github_signature(secret: &WebhookSecret, body: &[u8]) -> String {
        let digest = hmac_sha256(secret.expose(), body);
        let mut hex = String::with_capacity(7 + 64);
        hex.push_str("sha256=");
        for byte in digest {
            hex.push_str(&format!("{byte:02x}"));
        }
        hex
    }

    #[test]
    fn an_empty_secret_is_refused() {
        assert!(WebhookSecret::new("").is_none());
        assert!(WebhookSecret::new("   ").is_none());
        assert!(WebhookSecret::new("k").is_some());
    }

    /// **Trap guard:** the secret never appears in a log line (`Debug`), and the configuration's
    /// own `Debug` inherits that.
    #[test]
    fn the_secret_never_reaches_debug_output() {
        let rendered = format!("{:?}", secret());
        assert!(!rendered.contains("s3cr3t"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");

        let config = WebhookConfig {
            github_secret: Some(secret()),
            gitlab_secret: Some(WebhookSecret::new("glpat-token").expect("secret")),
            ..WebhookConfig::default()
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("s3cr3t"), "{rendered}");
        assert!(!rendered.contains("glpat-token"), "{rendered}");
    }

    /// FIPS 180-4/RFC 4231 known-answer vectors (HMAC-SHA256, RFC 4231 test cases 1 and 2).
    #[test]
    fn hmac_matches_the_published_vectors() {
        let key = [0x0b_u8; 20];
        let digest = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            digest.to_vec(),
            decode_hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
                .expect("vector")
        );

        let digest = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            digest.to_vec(),
            decode_hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
                .expect("vector")
        );

        // A key longer than the block is hashed first (RFC 2104).
        let long_key = [0xaa_u8; 131];
        let digest = hmac_sha256(
            &long_key,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            digest.to_vec(),
            decode_hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
                .expect("vector")
        );
    }

    #[test]
    fn a_valid_github_signature_is_accepted_and_every_tampered_variant_is_not() {
        let body = br#"{"ref":"refs/heads/main"}"#;
        let signature = github_signature(&secret(), body);
        assert!(secret().verify_github(body, Some(&signature)));
        // Uppercase hex is still the same MAC.
        assert!(secret().verify_github(
            body,
            Some(&signature.to_uppercase().replace("SHA256=", "sha256="))
        ));

        // A tampered body.
        assert!(!secret().verify_github(br#"{"ref":"refs/heads/main "}"#, Some(&signature)));
        // A signature made with the attacker's own key must not verify against the real secret.
        let attacker = WebhookSecret::new("attacker-key").expect("secret");
        assert!(!secret().verify_github(body, Some(&github_signature(&attacker, body))));
        assert!(
            attacker.verify_github(body, Some(&github_signature(&attacker, body))),
            "the attacker's key verifies its own MAC — which is why the key must be secret"
        );
        // Malformed envelopes.
        for header in [
            None,
            Some(""),
            Some("sha256="),
            Some("sha1=deadbeef"),
            Some("sha256=zz"),
            Some("sha256=0011223344"),
        ] {
            assert!(
                !secret().verify_github(body, header),
                "header {header:?} must be rejected"
            );
        }
    }

    #[test]
    fn the_gitlab_token_is_compared_constant_time_and_exactly() {
        let token = secret();
        assert!(token.verify_gitlab(Some("s3cr3t-webhook-key")));
        assert!(!token.verify_gitlab(Some("s3cr3t-webhook-ke")));
        assert!(!token.verify_gitlab(Some("s3cr3t-webhook-key ")));
        assert!(!token.verify_gitlab(Some("")));
        assert!(!token.verify_gitlab(None));
        // A token of a different length must not be reported as a prefix match.
        assert!(!token.verify_gitlab(Some("s3cr3t-webhook-key-and-more")));
    }

    // -----------------------------------------------------------------------
    // Replay cache
    // -----------------------------------------------------------------------

    #[test]
    fn a_delivery_id_is_admitted_once_and_evicted_by_capacity() {
        let dedupe = DeliveryDedupe::new(2, Duration::from_secs(900));
        let now = Instant::now();
        assert!(dedupe.admit_at("a", now));
        assert!(!dedupe.admit_at("a", now), "a replay must be refused");
        assert!(dedupe.admit_at("b", now));
        assert_eq!(dedupe.len(), 2);
        // Capacity 2: admitting a third evicts the oldest, so the cache never grows with traffic.
        assert!(dedupe.admit_at("c", now));
        assert_eq!(dedupe.len(), 2);
        assert!(dedupe.admit_at("a", now), "the evicted id is forgotten");
    }

    #[test]
    fn a_delivery_id_expires_after_the_ttl() {
        let ttl = Duration::from_secs(900);
        let dedupe = DeliveryDedupe::new(10, ttl);
        let now = Instant::now();
        assert!(dedupe.admit_at("delivery-1", now));
        assert!(!dedupe.admit_at("delivery-1", now + ttl - Duration::from_secs(1)));
        assert!(
            dedupe.admit_at("delivery-1", now + ttl),
            "an id older than the TTL is forgotten, so a very delayed retry still syncs"
        );
    }

    #[test]
    fn a_zero_capacity_cache_still_remembers_one_delivery() {
        let dedupe = DeliveryDedupe::new(0, Duration::from_secs(60));
        let now = Instant::now();
        assert!(dedupe.admit_at("only", now));
        assert!(!dedupe.admit_at("only", now));
        assert!(dedupe.is_empty() || dedupe.len() == 1);
    }

    // -----------------------------------------------------------------------
    // Matching
    // -----------------------------------------------------------------------

    fn application(repo_url: &str, target_revision: &str) -> Application {
        let spec: ApplicationSpec = serde_json::from_value(serde_json::json!({
            "project": "default",
            "source": {
                "git": {
                    "repoURL": repo_url,
                    "targetRevision": target_revision,
                    "path": "deploy",
                },
                "renderer": {"plainYaml": {}},
            },
            "destination": {"cluster": "in-cluster", "namespace": "payments"},
        }))
        .expect("a valid ApplicationSpec");
        let mut app = Application::new("payment-api", spec);
        app.metadata.namespace = Some("ferriscd-system".to_owned());
        app
    }

    fn push(reference: &str) -> PushEvent {
        push_with_default(reference, Some("main"))
    }

    fn push_with_default(reference: &str, default_branch: Option<&str>) -> PushEvent {
        PushEvent {
            identities: vec!["github.com/example/payment-service".to_owned()],
            reference: PushRef::parse(reference, default_branch).expect("a branch or tag"),
        }
    }

    /// **Trap guard:** HTTPS, SSH and SCP spellings of one repository are the same repository, so an
    /// SSH-cloned `Application` reacts to GitHub's HTTPS webhook URL (and vice versa).
    #[test]
    fn every_transport_spelling_is_one_repository_identity() {
        for url in [
            "https://github.com/example/payment-service.git",
            "https://github.com/example/payment-service",
            "git@github.com:example/payment-service.git",
            "ssh://git@github.com/example/payment-service",
            "https://user:token@github.com/example/payment-service.git",
        ] {
            assert_eq!(
                repository_identity(url).as_deref(),
                Some("github.com/example/payment-service"),
                "{url}"
            );
        }
        assert!(repository_identity("").is_none());
    }

    #[test]
    fn a_branch_push_matches_only_the_application_that_tracks_that_branch() {
        let app = application("git@github.com:example/payment-service.git", "main");
        assert!(application_matches(&app, &push("refs/heads/main")));
        assert!(!application_matches(&app, &push("refs/heads/feature/x")));
        assert!(!application_matches(&app, &push("refs/tags/v1.0.0")));

        let tagged = application("https://github.com/example/payment-service", "v1.0.0");
        assert!(application_matches(&tagged, &push("refs/tags/v1.0.0")));
        assert!(!application_matches(&tagged, &push("refs/heads/main")));

        // A fully qualified targetRevision is accepted too.
        let qualified = application(
            "https://github.com/example/payment-service",
            "refs/heads/release/1.2",
        );
        assert!(application_matches(
            &qualified,
            &push("refs/heads/release/1.2")
        ));
    }

    /// `HEAD` means "the remote's default branch": it must not match every branch, and when the
    /// payload does not say which branch is the default, nothing is guessed.
    #[test]
    fn head_tracks_only_the_default_branch() {
        let app = application("https://github.com/example/payment-service", "HEAD");
        assert!(application_matches(&app, &push("refs/heads/main")));
        assert!(!application_matches(&app, &push("refs/heads/feature/x")));
        assert!(!application_matches(
            &app,
            &push_with_default("refs/heads/main", None)
        ));
        assert!(!application_matches(&app, &push("refs/tags/v1")));
        // The payload's own default branch is what counts, not a hardcoded "main".
        let trunk = application("https://github.com/example/payment-service", "head");
        assert!(application_matches(
            &trunk,
            &push_with_default("refs/heads/trunk", Some("trunk"))
        ));
    }

    #[test]
    fn a_different_repository_never_matches() {
        let app = application("https://github.com/example/other-service", "main");
        assert!(!application_matches(&app, &push("refs/heads/main")));
    }

    #[test]
    fn a_ref_that_is_neither_branch_nor_tag_is_not_a_push_target() {
        assert!(PushRef::parse("refs/notes/commits", None).is_none());
        assert!(PushRef::parse("refs/pull/1/head", None).is_none());
        assert!(PushRef::parse("", None).is_none());
        assert!(PushRef::parse("refs/heads/", None).is_none());
        let branch = PushRef::parse("refs/heads/main", None).expect("branch");
        assert_eq!(branch.kind, RefKind::Branch);
        assert_eq!(branch.full(), "refs/heads/main");
        let tag = PushRef::parse("refs/tags/v1", None).expect("tag");
        assert_eq!(tag.kind, RefKind::Tag);
        assert_eq!(tag.full(), "refs/tags/v1");
    }

    // -----------------------------------------------------------------------
    // Debounce / fan-out
    // -----------------------------------------------------------------------

    #[derive(Default)]
    struct RecordingSink {
        refreshed: Mutex<Vec<RefreshTarget>>,
        calls: AtomicUsize,
    }

    impl RefreshSink for RecordingSink {
        fn refresh(&self, target: RefreshTarget) -> SeamFuture<'_, ()> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.refreshed
                    .lock()
                    .map_err(|_| ApiError::backend(&"poisoned"))?
                    .push(target);
                Ok(())
            })
        }
    }

    fn config(debounce: Duration, jitter: Duration) -> WebhookConfig {
        WebhookConfig {
            debounce,
            max_jitter: jitter,
            ..WebhookConfig::default()
        }
    }

    /// Lets every ready task run (paused time: nothing sleeps for real, so this is not a wait).
    async fn settle() {
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
    }

    fn targets(count: usize) -> Vec<RefreshTarget> {
        (0..count)
            .map(|index| RefreshTarget {
                namespace: "ferriscd-system".to_owned(),
                name: format!("app-{index}"),
            })
            .collect()
    }

    /// **Trap guard:** a monorepo push matching several `Application`s refreshes each one **once**
    /// after the window closes, and repeated deliveries inside the window are coalesced.
    #[tokio::test(start_paused = true)]
    async fn a_burst_of_deliveries_fans_out_once() {
        let sink = Arc::new(RecordingSink::default());
        let fan_out = Arc::new(FanOut::new(
            &config(Duration::from_secs(2), Duration::ZERO),
            sink.clone(),
        ));

        let first = fan_out.submit("github.com/example/mono", targets(3));
        assert!(matches!(first, FanOutOutcome::Scheduled { pending: 3 }));
        // A second delivery inside the window: coalesced, same window.
        let second = fan_out.submit(
            "github.com/example/mono",
            vec![RefreshTarget {
                namespace: "ferriscd-system".to_owned(),
                name: "app-0".to_owned(),
            }],
        );
        assert!(matches!(second, FanOutOutcome::Coalesced { pending: 3 }));
        assert_eq!(fan_out.pending_repositories(), 1);
        assert_eq!(
            sink.calls.load(Ordering::SeqCst),
            0,
            "nothing fires before the window closes"
        );

        // Close the window deterministically: paused time only advances when we say so.
        tokio::time::advance(Duration::from_secs(2)).await;
        settle().await;

        assert_eq!(sink.calls.load(Ordering::SeqCst), 3);
        let refreshed = sink.refreshed.lock().expect("lock").clone();
        assert_eq!(refreshed.len(), 3);
        assert_eq!(fan_out.pending_repositories(), 0);
    }

    /// Every target is refreshed at most once per window, even if the same target was submitted
    /// twice, and a second window after the first still works (the debounce is not one-shot).
    #[tokio::test(start_paused = true)]
    async fn the_window_is_trailing_and_reusable() {
        let sink = Arc::new(RecordingSink::default());
        let fan_out = Arc::new(FanOut::new(
            &config(Duration::from_secs(2), Duration::ZERO),
            sink.clone(),
        ));

        fan_out.submit("repo", targets(1));
        tokio::time::advance(Duration::from_millis(1500)).await;
        // A late delivery extends the deadline: the window is trailing, not a fixed 2s bucket.
        fan_out.submit("repo", targets(2));
        tokio::time::advance(Duration::from_millis(1500)).await;
        settle().await;
        assert_eq!(
            sink.calls.load(Ordering::SeqCst),
            0,
            "the delivery at t+1.5s must have pushed the deadline to t+3.5s"
        );

        tokio::time::advance(Duration::from_millis(600)).await;
        settle().await;
        assert_eq!(sink.calls.load(Ordering::SeqCst), 2);

        fan_out.submit("repo", targets(1));
        tokio::time::advance(Duration::from_millis(2100)).await;
        settle().await;
        assert_eq!(sink.calls.load(Ordering::SeqCst), 3);
    }

    /// Distinct repositories keep distinct windows, so one busy monorepo cannot delay another.
    #[tokio::test(start_paused = true)]
    async fn windows_are_per_repository() {
        let sink = Arc::new(RecordingSink::default());
        let fan_out = Arc::new(FanOut::new(
            &config(Duration::from_secs(2), Duration::ZERO),
            sink.clone(),
        ));
        fan_out.submit("repo-a", targets(1));
        fan_out.submit("repo-b", targets(1));
        assert_eq!(fan_out.pending_repositories(), 2);
        tokio::time::advance(Duration::from_secs(2)).await;
        settle().await;
        assert_eq!(sink.calls.load(Ordering::SeqCst), 2);
    }

    /// The jitter is deterministic, inside the window, and not all-zero (so a real fan-out spreads).
    #[test]
    fn the_fan_out_jitter_is_deterministic_and_bounded() {
        let fan_out = FanOut::new(
            &config(Duration::from_secs(2), Duration::from_millis(500)),
            Arc::new(RecordingSink::default()),
        );
        let mut seen: Vec<Duration> = (0..16)
            .map(|index| fan_out.jitter_delay("github.com/example/mono", index))
            .collect();
        for delay in &seen {
            assert!(*delay < Duration::from_millis(500), "{delay:?}");
        }
        assert!(
            seen.iter().any(|delay| !delay.is_zero()),
            "a fan-out must spread: {seen:?}"
        );
        // Deterministic: the same inputs give the same schedule, so a fan-out is reproducible.
        seen.sort_unstable();
        let mut again: Vec<Duration> = (0..16)
            .map(|index| fan_out.jitter_delay("github.com/example/mono", index))
            .collect();
        again.sort_unstable();
        assert_eq!(seen, again);

        let no_jitter = FanOut::new(
            &config(Duration::from_secs(2), Duration::ZERO),
            Arc::new(RecordingSink::default()),
        );
        assert!(no_jitter.jitter_delay("repo", 0).is_zero());
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_matched_schedules_nothing() {
        let sink = Arc::new(RecordingSink::default());
        let fan_out = Arc::new(FanOut::new(
            &config(Duration::from_secs(2), Duration::ZERO),
            sink.clone(),
        ));
        assert_eq!(fan_out.submit("repo", Vec::new()), FanOutOutcome::Empty);
        assert_eq!(fan_out.pending_repositories(), 0);
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(sink.calls.load(Ordering::SeqCst), 0);
    }

    /// `refresh_token` changes on every call: an unchanged value would produce an identical
    /// composite predicate hash and the watch would swallow the refresh entirely.
    #[test]
    fn refresh_tokens_are_unique() {
        let tokens: BTreeSet<String> = (0..64).map(|_| refresh_token()).collect();
        assert_eq!(tokens.len(), 64);
        assert_eq!(refresh_annotation(), "ferriscd.io/refresh");
    }

    /// A `mpsc`-based sink proves the fan-out really calls the writer once per matched target.
    #[tokio::test(start_paused = true)]
    async fn the_fan_out_calls_the_refresh_writer_exactly_once_per_target() {
        struct ChannelSink(mpsc::UnboundedSender<RefreshTarget>);
        impl RefreshSink for ChannelSink {
            fn refresh(&self, target: RefreshTarget) -> SeamFuture<'_, ()> {
                Box::pin(async move {
                    self.0
                        .send(target)
                        .map_err(|_| ApiError::backend(&"the receiver is gone"))
                })
            }
        }

        let (tx, mut rx) = mpsc::unbounded_channel();
        let fan_out = Arc::new(FanOut::new(
            &config(Duration::from_secs(2), Duration::from_millis(100)),
            Arc::new(ChannelSink(tx)),
        ));
        fan_out.submit("repo", targets(2));
        tokio::time::advance(Duration::from_secs(2)).await;
        // Jitter is bounded by max_jitter; advancing past it makes every refresh ready.
        tokio::time::advance(Duration::from_millis(200)).await;

        let first = rx.recv().await.expect("a refresh");
        let second = rx.recv().await.expect("a refresh");
        assert_ne!(first, second);
        assert!(rx.try_recv().is_err(), "exactly two refreshes");
    }
}
