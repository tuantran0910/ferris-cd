//! The delivery worker: channel resolution, SSRF validation, bounded retries (`T19.4`).
//!
//! # Why delivery is a separate task
//!
//! Everything in this module can block on the network. It runs on its own Tokio task fed by a
//! bounded channel (`try_send`, capacity [`DEFAULT_QUEUE_CAPACITY`]), so:
//!
//! * a hung Slack endpoint delays the *notifications*, never a reconcile pass (the `T19.4`
//!   non-functional requirement), and
//! * the memory cost of a slow receiver is capped by the channel, and each delivery is capped by
//!   [`DEFAULT_REQUEST_TIMEOUT`] and [`DEFAULT_MAX_ATTEMPTS`].
//!
//! # Retry policy
//!
//! A 2xx is success. A **3xx is a hard failure**: the redirect is never followed (that is the classic
//! SSRF bypass — `302 -> http://169.254.169.254/...`), and the production client is additionally
//! built with `reqwest::redirect::Policy::none()`. A 4xx is retried too, but only the configured
//! number of times: a receiver that answers `400` for a malformed body will not start accepting it,
//! and the metric (`outcome="failed"`) is what makes that visible, not an infinite retry loop.
//! Between attempts the worker sleeps an exponential backoff ([`DEFAULT_RETRY_BASE_DELAY`], doubled),
//! through the [`BackoffSleeper`] seam so tests never sleep.
//!
//! # Never logged, never forwarded
//!
//! * The destination URL is only ever logged in its [`redact_audit_url`] form, and a transport error
//!   is logged with `reqwest`'s `without_url()` applied where the transport exposes it.
//! * The request body is not logged at all: it carries the `Application`'s identity and condition
//!   message, which belong to the receiver, not to the controller's log stream.
//!
//! [`redact_audit_url`]: crate::audit::redact_audit_url

use std::collections::BTreeMap;
use std::fmt;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::FutureExt as _;
use futures::future::BoxFuture;
use k8s_openapi::api::core::v1::Secret;
use kube::ResourceExt as _;
use kube::api::{Api, ListParams};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::lock_recover;
use crate::metrics::{Metrics, NotificationOutcome};
use crate::notifications::adapters::{self, Delivery};
use crate::notifications::ssrf::{
    DestinationResolver, EgressPolicy, SystemResolution, ValidatedWebhookUrl,
};
use crate::notifications::template::MessageTemplate;
use crate::notifications::{
    DEFAULT_MAX_ATTEMPTS, DEFAULT_REQUEST_TIMEOUT, DEFAULT_RETRY_BASE_DELAY, NotificationChannel,
    NotificationContext, NotificationService, SECRET_TYPE_LABEL, SECRET_TYPE_NOTIFICATIONS,
    channel_from_secret, channel_label_selector,
};

/// One queued notification: everything the worker needs, resolved at trigger time.
#[derive(Clone)]
pub struct NotificationJob {
    /// `Application` namespace.
    pub namespace: String,
    /// `Application` name.
    pub name: String,
    /// Destination service (from the annotation).
    pub service: NotificationService,
    /// Recipient key: the name of the channel `Secret`.
    pub recipient: String,
    /// The `(app, trigger, generation, revision, health)` key, used for PagerDuty `dedup_key` and
    /// the `X-FerrisCD-Delivery` header.
    pub dedup_key: String,
    /// The redacted context the template renders against.
    pub context: NotificationContext,
    /// The template to render (already resolved from the config at trigger time).
    pub template: MessageTemplate,
}

impl fmt::Debug for NotificationJob {
    /// The job's *body* is not printed: the context is redacted already, but a log line does not need
    /// an `Application`'s status message repeated for every queued notification.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotificationJob")
            .field("namespace", &self.namespace)
            .field("name", &self.name)
            .field("service", &self.service.as_str())
            .field("recipient", &self.recipient)
            .field("dedup_key", &self.dedup_key)
            .field("trigger", &self.context.trigger())
            .finish()
    }
}

/// Errors raised while resolving a recipient to a channel.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ChannelError {
    /// The recipient names no channel (or the `Secret` is unusable).
    #[error("notification channel is unusable: {message}")]
    Invalid {
        /// Secret-free diagnostic message.
        message: String,
    },

    /// The channel `Secret` could not be read.
    #[error("notification channel could not be read: {message}")]
    Api {
        /// Secret-free diagnostic message.
        message: String,
    },

    /// The annotation and the channel `Secret` disagree about the service.
    #[error(
        "notification channel {channel} declares service {declared}, but the annotation asks for \
         {requested}"
    )]
    ServiceMismatch {
        /// The channel (Secret) name.
        channel: String,
        /// The service the `Secret` declares.
        declared: &'static str,
        /// The service the annotation named.
        requested: &'static str,
    },
}

/// Resolves a recipient key (an `Application` annotation value) to its channel.
pub trait ChannelSource: Send + Sync + 'static {
    /// Resolves `recipient` to the channel it names.
    fn resolve<'a>(
        &'a self,
        recipient: &'a str,
    ) -> BoxFuture<'a, Result<Arc<NotificationChannel>, ChannelError>>;
}

/// A fixed, in-memory set of channels (tests and embedders that configure channels out of band).
#[derive(Debug, Clone, Default)]
pub struct StaticChannelSource {
    channels: BTreeMap<String, Arc<NotificationChannel>>,
}

impl StaticChannelSource {
    /// Builds a source from already-parsed channels.
    #[must_use]
    pub fn new(channels: impl IntoIterator<Item = NotificationChannel>) -> Self {
        Self {
            channels: channels
                .into_iter()
                .map(|channel| (channel.name.clone(), Arc::new(channel)))
                .collect(),
        }
    }
}

impl ChannelSource for StaticChannelSource {
    fn resolve<'a>(
        &'a self,
        recipient: &'a str,
    ) -> BoxFuture<'a, Result<Arc<NotificationChannel>, ChannelError>> {
        let resolved = self.channels.get(recipient.trim()).cloned();
        Box::pin(async move {
            resolved.ok_or_else(|| ChannelError::Invalid {
                message: format!(
                    "no notification channel named {recipient:?} (a channel is a Secret labelled \
                     {selector})",
                    selector = channel_label_selector(),
                ),
            })
        })
    }
}

/// [`ChannelSource`] backed by labelled `Secret`s in the control-plane namespace.
///
/// The `Api<Secret>` is namespaced, so no code path here can request a cluster-wide `Secret` list; the
/// label selector narrows it to `ferriscd.io/secret-type=notifications`. The list is cached for
/// [`Self::cache_ttl`] so a burst of notifications resolves against one API read instead of one per
/// delivery, and a rotated channel `Secret` is picked up at the next refresh.
pub struct SecretChannelSource {
    api: Api<Secret>,
    namespace: String,
    cache_ttl: Duration,
    cache: Mutex<Option<CachedChannels>>,
}

#[derive(Clone)]
struct CachedChannels {
    fetched_at: std::time::Instant,
    channels: BTreeMap<String, Arc<NotificationChannel>>,
}

impl fmt::Debug for SecretChannelSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretChannelSource")
            .field("namespace", &self.namespace)
            .field("selector", &channel_label_selector())
            .field("cache_ttl", &self.cache_ttl)
            .finish_non_exhaustive()
    }
}

impl SecretChannelSource {
    /// Default lifetime of the resolved-channel cache (`60 s`).
    pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(60);

    /// Builds a source reading labelled `Secret`s from `namespace` (the control-plane namespace).
    #[must_use]
    pub fn new(client: kube::Client, namespace: &str) -> Self {
        Self {
            api: Api::namespaced(client, namespace),
            namespace: namespace.to_owned(),
            cache_ttl: Self::DEFAULT_CACHE_TTL,
            cache: Mutex::new(None),
        }
    }

    /// Overrides the cache lifetime (`0` reads the API server on every resolution).
    #[must_use]
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// The control-plane namespace these channels live in.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Lists and parses the channel `Secret`s (one namespaced, label-filtered read).
    ///
    /// # Errors
    ///
    /// [`ChannelError::Api`] when the list fails. A single unusable `Secret` is logged and skipped so
    /// one bad channel cannot take every other channel down.
    async fn load(&self) -> Result<BTreeMap<String, Arc<NotificationChannel>>, ChannelError> {
        let params = ListParams::default().labels(&channel_label_selector());
        let secrets = self
            .api
            .list(&params)
            .await
            .map_err(|err| ChannelError::Api {
                message: err.to_string(),
            })?
            .items;
        let mut channels = BTreeMap::new();
        for secret in &secrets {
            match channel_from_secret(secret) {
                Ok(channel) => {
                    channels.insert(channel.name.clone(), Arc::new(channel));
                }
                Err(err) => tracing::warn!(
                    namespace = %self.namespace,
                    secret = %secret.name_any(),
                    label = SECRET_TYPE_LABEL,
                    label_value = SECRET_TYPE_NOTIFICATIONS,
                    error = %err,
                    "ignoring an unusable notification channel Secret"
                ),
            }
        }
        Ok(channels)
    }
}

impl ChannelSource for SecretChannelSource {
    fn resolve<'a>(
        &'a self,
        recipient: &'a str,
    ) -> BoxFuture<'a, Result<Arc<NotificationChannel>, ChannelError>> {
        Box::pin(async move {
            let recipient = recipient.trim();
            if let Some(cached) = {
                let cache = lock_recover(&self.cache);
                cache.as_ref().and_then(|cached| {
                    if cached.fetched_at.elapsed() < self.cache_ttl {
                        Some(cached.channels.clone())
                    } else {
                        None
                    }
                })
            } && let Some(channel) = cached.get(recipient)
            {
                return Ok(channel.clone());
            }
            let channels = self.load().await?;
            let resolved = channels.get(recipient).cloned();
            *lock_recover(&self.cache) = Some(CachedChannels {
                fetched_at: std::time::Instant::now(),
                channels,
            });
            resolved.ok_or_else(|| ChannelError::Invalid {
                message: format!(
                    "no notification channel named {recipient:?} in namespace {namespace:?} \
                     (expected a Secret labelled {selector})",
                    namespace = self.namespace,
                    selector = channel_label_selector(),
                ),
            })
        })
    }
}

/// One HTTP POST the transport must perform.
///
/// `Debug` is hand-written (finding **R1-M4**): the URL may carry a replayable webhook token in its
/// path or query string, and a header *value* may carry the bearer credential or the HMAC, so only
/// the redacted destination, the header **names** and the body's size are printable.
#[derive(Clone, PartialEq, Eq)]
pub struct DeliveryRequest {
    /// Destination URL (may carry a query token; never logged).
    pub url: String,
    /// Request headers.
    pub headers: Vec<(String, String)>,
    /// JSON body.
    pub body: String,
}

impl fmt::Debug for DeliveryRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeliveryRequest")
            .field(
                "url",
                &crate::notifications::redact_notification_url(&self.url),
            )
            .field("headers", &header_names(&self.headers))
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

/// The header **names** of `headers`, in order (never a value: it may be a credential).
fn header_names(headers: &[(String, String)]) -> Vec<&str> {
    headers
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
}

impl From<&Delivery> for DeliveryRequest {
    fn from(delivery: &Delivery) -> Self {
        Self {
            url: delivery.url.clone(),
            headers: delivery.headers.clone(),
            body: delivery.body.clone(),
        }
    }
}

/// The transport's answer: only the status code matters to the retry policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryResponse {
    /// HTTP status code.
    pub status: u16,
}

impl DeliveryResponse {
    /// Whether the receiver accepted the payload.
    #[must_use]
    pub fn is_success(self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Whether the receiver answered with a redirect (which is never followed).
    #[must_use]
    pub fn is_redirection(self) -> bool {
        (300..400).contains(&self.status)
    }
}

/// Errors raised by a [`NotificationTransport`].
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The request could not be sent (DNS, TLS, timeout, connection reset).
    #[error("notification delivery failed: {message}")]
    Request {
        /// Secret-free diagnostic (the URL is never included).
        message: String,
    },

    /// The operator's `--notifications-ca-file` could not be turned into trust anchors.
    ///
    /// The path is *not* a credential (it is an operator flag) and is named so a typo is debuggable;
    /// the PEM content is never echoed.
    #[error("the notification CA file {path:?} is unusable: {message}")]
    CaFile {
        /// The operator-supplied path.
        path: std::path::PathBuf,
        /// Why the file could not be used (never the file's content).
        message: String,
    },
}

/// Sends one request. Abstracted so the whole delivery path is testable without a network.
pub trait NotificationTransport: Send + Sync + 'static {
    /// Sends `request`, returning the receiver's status.
    fn post<'a>(
        &'a self,
        request: &'a DeliveryRequest,
    ) -> BoxFuture<'a, Result<DeliveryResponse, TransportError>>;
}

/// The redirect policy a [`TransportConfig`] maps to (`T19.4` trap guard).
///
/// `reqwest::redirect::Policy` is opaque and implements neither `Debug` nor `PartialEq`, so the
/// mapping "`max_redirects == 0` means `Policy::none()`" cannot be asserted through it. This small
/// enum is the testable half: [`TransportConfig::redirect_policy`] returns it, [`Self::to_reqwest`]
/// is the only place it becomes a `reqwest` policy, and a test pins
/// [`Self::None`] as the production value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectPolicy {
    /// Never follow a redirect (`reqwest::redirect::Policy::none()`).
    None,
    /// Follow at most this many redirects (never used in production: the SSRF trap guard).
    Limited(usize),
}

impl RedirectPolicy {
    /// The `max_redirects` value this policy is configured from (`0` is [`Self::None`]).
    #[must_use]
    pub fn from_max_redirects(max_redirects: usize) -> Self {
        match max_redirects {
            0 => Self::None,
            limit => Self::Limited(limit),
        }
    }

    /// The `reqwest` policy this maps to.
    #[must_use]
    pub fn to_reqwest(self) -> reqwest::redirect::Policy {
        match self {
            Self::None => reqwest::redirect::Policy::none(),
            Self::Limited(limit) => reqwest::redirect::Policy::limited(limit),
        }
    }

    /// Whether this policy follows redirects at all.
    #[must_use]
    pub fn follows_redirects(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// What [`ReqwestTransport::build`] configured the production client with (finding **R1-H2**).
///
/// `reqwest::Client` exposes no accessor for its own builder state, so the settings are recorded
/// here: that is what makes "the client really is HTTPS-only, proxy-free, redirect-free and pinned
/// to the SSRF guard's resolver" an assertion instead of a code review. It is not a second source of
/// truth — [`ReqwestTransport::build`] reads every field back from this struct when it constructs
/// the builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportConfig {
    /// `reqwest` `https_only`: a plaintext `http://` destination is refused by the client itself.
    pub https_only: bool,
    /// `no_proxy`: `HTTP(S)_PROXY` cannot reroute a notification through an operator's proxy.
    pub proxy_disabled: bool,
    /// Redirects the client follows. **`0` means `reqwest::redirect::Policy::none()`.**
    pub max_redirects: usize,
    /// The egress policy the pinning DNS resolver enforces.
    pub egress_policy: EgressPolicy,
    /// Whether the [`GuardedResolver`](crate::notifications::ssrf::GuardedResolver) is installed
    /// (the address-pinning half of the SSRF guard).
    pub pinned_resolver: bool,
    /// The per-request timeout.
    pub timeout: Duration,
    /// How many **operator-supplied** root certificates (`--notifications-ca-file`) were added.
    ///
    /// `0` is the default: the platform trust store alone. A non-zero value does not disable system
    /// trust and does not weaken verification — it *adds* private/self-signed receiver CAs to the
    /// roots the client will build a chain to, which is the only supported way to reach an internal
    /// HTTPS receiver without turning the SSRF guard off.
    pub custom_root_certificates: usize,
}

impl TransportConfig {
    /// The configuration for `policy`: HTTPS-only, no proxy, no redirects, pinned resolver, and the
    /// documented [`DEFAULT_REQUEST_TIMEOUT`].
    #[must_use]
    pub fn strict(policy: EgressPolicy) -> Self {
        Self {
            https_only: true,
            proxy_disabled: true,
            max_redirects: 0,
            egress_policy: policy,
            pinned_resolver: true,
            timeout: DEFAULT_REQUEST_TIMEOUT,
            custom_root_certificates: 0,
        }
    }

    /// The `reqwest` redirect policy this configuration maps to.
    #[must_use]
    pub fn redirect_policy(&self) -> RedirectPolicy {
        RedirectPolicy::from_max_redirects(self.max_redirects)
    }
}

/// Production transport: one pooled, SSRF-guarded `reqwest` client.
pub struct ReqwestTransport {
    client: reqwest::Client,
    config: TransportConfig,
}

impl fmt::Debug for ReqwestTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReqwestTransport")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl ReqwestTransport {
    /// Builds the client: HTTPS-only, no proxy, **no redirects**, bounded timeout, and the
    /// [`GuardedResolver`](crate::notifications::ssrf::GuardedResolver) pinning validated addresses.
    ///
    /// # Errors
    ///
    /// [`TransportError::Request`] when the TLS client cannot be built (a startup failure: without a
    /// client every notification would be dropped).
    pub fn build(policy: EgressPolicy) -> Result<Self, TransportError> {
        Self::build_with_root_certificates(policy, Vec::new())
    }

    /// Builds the client with extra **root** certificates (the `--notifications-ca-file` case).
    ///
    /// The extra roots are *added* to the platform trust store (`reqwest`'s
    /// `add_root_certificate`), never substituted for it, and every other guard is unchanged: this is
    /// a convenience for internal/self-signed receiver CAs, **not** a way to bypass verification.
    ///
    /// # Errors
    ///
    /// [`TransportError::Request`] when the TLS client cannot be built.
    pub fn build_with_root_certificates(
        policy: EgressPolicy,
        root_certificates: Vec<reqwest::Certificate>,
    ) -> Result<Self, TransportError> {
        let mut config = TransportConfig::strict(policy);
        config.custom_root_certificates = root_certificates.len();
        // Pin the process-level rustls provider before constructing a TLS client (the workspace
        // links two providers; `rustls` refuses to guess).
        crate::impersonation::ensure_crypto_provider();
        let mut builder = reqwest::Client::builder()
            .https_only(config.https_only)
            .timeout(config.timeout)
            // `T19.4` trap guard: a redirect is the classic SSRF bypass, so none is followed. The
            // worker independently refuses every 3xx, so the guard does not depend on this one line.
            .redirect(config.redirect_policy().to_reqwest());
        if config.proxy_disabled {
            builder = builder.no_proxy();
        }
        if config.pinned_resolver {
            builder = builder.dns_resolver(Arc::new(
                crate::notifications::ssrf::GuardedResolver::new(config.egress_policy.clone()),
            ));
        }
        for certificate in root_certificates {
            builder = builder.add_root_certificate(certificate);
        }
        let client = builder.build().map_err(|err| TransportError::Request {
            message: err.without_url().to_string(),
        })?;
        Ok(Self { client, config })
    }

    /// The configuration this transport's client was built with (finding **R1-H2**).
    #[must_use]
    pub fn config(&self) -> &TransportConfig {
        &self.config
    }

    /// A cloned handle on the built client, so a test can drive it without a network.
    #[must_use]
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// The per-request timeout this transport enforces.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.config.timeout
    }
}

impl NotificationTransport for ReqwestTransport {
    fn post<'a>(
        &'a self,
        request: &'a DeliveryRequest,
    ) -> BoxFuture<'a, Result<DeliveryResponse, TransportError>> {
        Box::pin(async move {
            let mut builder = self.client.post(&request.url);
            for (name, value) in &request.headers {
                builder = builder.header(name.as_str(), value.as_str());
            }
            let response = builder
                .body(request.body.clone())
                .send()
                .await
                .map_err(|err| {
                    // `without_url()` keeps a webhook token out of the log line.
                    TransportError::Request {
                        message: err.without_url().to_string(),
                    }
                })?;
            Ok(DeliveryResponse {
                status: response.status().as_u16(),
            })
        })
    }
}

/// Loads the operator's PEM CA bundle for the notification client (`--notifications-ca-file`).
///
/// This is the *only* supported way to reach an HTTPS receiver whose certificate is signed by a
/// private CA: the alternative — disabling verification or allowing plaintext — would remove the
/// very protection the SSRF guard exists for. The certificates are handed to
/// [`ReqwestTransport::build_with_root_certificates`], which **adds** them to the platform roots.
///
/// The read is async (`tokio::fs`) even though it happens at startup: a blocking file read on a
/// runtime worker is exactly what `AGENTS.md`'s async-hygiene rule forbids, and this function is the
/// seam a caller is tempted to call from the reconcile path later.
///
/// # Errors
///
/// [`TransportError::CaFile`] when the file cannot be read, is empty, or contains no PEM
/// certificate (`reqwest::Certificate::from_pem_bundle` refuses it). Failing closed matters: an
/// unreadable CA file silently treated as "no extra trust" would surface as a TLS error on the first
/// production alert instead of at startup.
pub async fn load_root_certificates(
    path: &std::path::Path,
) -> Result<Vec<reqwest::Certificate>, TransportError> {
    let pem = tokio::fs::read(path)
        .await
        .map_err(|err| TransportError::CaFile {
            path: path.to_path_buf(),
            message: format!("it could not be read ({err})"),
        })?;
    if pem.iter().all(u8::is_ascii_whitespace) {
        return Err(TransportError::CaFile {
            path: path.to_path_buf(),
            message: "the file is empty (expected a PEM certificate bundle)".to_owned(),
        });
    }
    // `from_pem_bundle` parses the PEM off the bytes; its own error names no content, so it is safe
    // to pass through.
    let certificates =
        reqwest::Certificate::from_pem_bundle(&pem).map_err(|err| TransportError::CaFile {
            path: path.to_path_buf(),
            message: format!("it is not a PEM certificate bundle ({err})"),
        })?;
    if certificates.is_empty() {
        return Err(TransportError::CaFile {
            path: path.to_path_buf(),
            message: "it contains no CERTIFICATE block".to_owned(),
        });
    }
    Ok(certificates)
}

/// Sleeps between delivery attempts (the seam that keeps retry tests sleep-free).
pub trait BackoffSleeper: Send + Sync + 'static {
    /// Sleeps for `duration`.
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()>;
}

/// Production sleeper.
#[derive(Debug, Default, Clone, Copy)]
pub struct TokioSleeper;

impl BackoffSleeper for TokioSleeper {
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep(duration))
    }
}

/// How one delivery ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// A 2xx response.
    Delivered,
    /// Every attempt failed (or the destination was refused); `reason` is a stable label.
    Failed {
        /// Why (`ssrf_<reason>`, `redirect`, `http_<status>`, `transport`, `channel`, `payload`).
        reason: &'static str,
    },
    /// The notification was not attempted at all (unresolvable channel, service mismatch).
    Dropped {
        /// Why (`unknown_channel`, `service_mismatch`).
        reason: &'static str,
    },
}

impl DeliveryOutcome {
    /// The `outcome` metric label.
    #[must_use]
    pub fn metric_outcome(self) -> NotificationOutcome {
        match self {
            Self::Delivered => NotificationOutcome::Delivered,
            Self::Failed { .. } => NotificationOutcome::Failed,
            Self::Dropped { .. } => NotificationOutcome::Dropped,
        }
    }
}

/// The bounded delivery worker.
///
/// # Concurrency (finding R1-M3)
///
/// The worker keeps at most [`DEFAULT_DELIVERY_CONCURRENCY`] deliveries in flight, each on its own
/// task: a destination that takes the full 5 s timeout cannot make every *other* `Application`'s
/// alert wait behind it (the serial worker turned one slow receiver into fleet-wide alert latency).
/// The bound is what keeps the memory and socket cost of a burst predictable, and the bounded queue
/// in front of it is what keeps a pathological receiver from delaying a reconcile.
///
/// # Failure isolation (finding R1-M2)
///
/// Each delivery is run under `catch_unwind` and each task's join result is inspected: a panic in a
/// template, an adapter or a transport (including a third-party one) is logged as an error and
/// counted as a failure, and the worker keeps delivering. A panic can therefore no longer take the
/// whole notification subsystem down with it.
pub struct NotificationWorker {
    rx: mpsc::Receiver<NotificationJob>,
    channels: Arc<dyn ChannelSource>,
    transport: Arc<dyn NotificationTransport>,
    policy: EgressPolicy,
    metrics: Metrics,
    sleeper: Arc<dyn BackoffSleeper>,
    resolver: Arc<dyn DestinationResolver>,
    max_attempts: u32,
    retry_base_delay: Duration,
    concurrency: usize,
}

/// The delivery policy, shared by every in-flight delivery (`T19.4`).
pub struct DeliveryEngine {
    channels: Arc<dyn ChannelSource>,
    transport: Arc<dyn NotificationTransport>,
    policy: EgressPolicy,
    metrics: Metrics,
    sleeper: Arc<dyn BackoffSleeper>,
    resolver: Arc<dyn DestinationResolver>,
    max_attempts: u32,
    retry_base_delay: Duration,
}

/// How many deliveries one worker performs concurrently (`T19.4` finding R1-M3).
pub const DEFAULT_DELIVERY_CONCURRENCY: usize = 4;

impl fmt::Debug for NotificationWorker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotificationWorker")
            .field("max_attempts", &self.max_attempts)
            .field("retry_base_delay", &self.retry_base_delay)
            .field("concurrency", &self.concurrency)
            .finish_non_exhaustive()
    }
}

impl NotificationWorker {
    /// Builds a worker over `rx`.
    #[must_use]
    pub fn new(
        rx: mpsc::Receiver<NotificationJob>,
        channels: Arc<dyn ChannelSource>,
        transport: Arc<dyn NotificationTransport>,
        policy: EgressPolicy,
        metrics: Metrics,
    ) -> Self {
        Self {
            rx,
            channels,
            transport,
            policy,
            metrics,
            sleeper: Arc::new(TokioSleeper),
            resolver: Arc::new(SystemResolution),
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            retry_base_delay: DEFAULT_RETRY_BASE_DELAY,
            concurrency: DEFAULT_DELIVERY_CONCURRENCY,
        }
    }

    /// The shared delivery policy these settings describe (one `Arc` in [`Self::run`]).
    fn engine(&self) -> DeliveryEngine {
        DeliveryEngine {
            channels: self.channels.clone(),
            transport: self.transport.clone(),
            policy: self.policy.clone(),
            metrics: self.metrics.clone(),
            sleeper: self.sleeper.clone(),
            resolver: self.resolver.clone(),
            max_attempts: self.max_attempts,
            retry_base_delay: self.retry_base_delay,
        }
    }

    /// Overrides the attempt ceiling (`0` is treated as `1`: a delivery always gets one attempt).
    #[must_use]
    pub fn with_max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = attempts.max(1);
        self
    }

    /// Overrides the backoff base delay.
    #[must_use]
    pub fn with_retry_base_delay(mut self, delay: Duration) -> Self {
        self.retry_base_delay = delay;
        self
    }

    /// Injects the sleeper seam (tests use an instantaneous one).
    #[must_use]
    pub fn with_sleeper(mut self, sleeper: Arc<dyn BackoffSleeper>) -> Self {
        self.sleeper = sleeper;
        self
    }

    /// Injects the DNS-resolution seam (tests resolve without network).
    #[must_use]
    pub fn with_resolver(mut self, resolver: Arc<dyn DestinationResolver>) -> Self {
        self.resolver = resolver;
        self
    }

    /// Overrides the concurrency bound (`0` is clamped to `1`).
    #[must_use]
    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency.max(1);
        self
    }

    /// Delivers one job, with the SSRF guard, the retry policy and the metric.
    ///
    /// Public so the whole delivery policy is unit-testable without spawning a task.
    pub async fn deliver(&self, job: &NotificationJob) -> DeliveryOutcome {
        self.engine().deliver(job).await
    }
}

impl DeliveryEngine {
    /// Delivers one job, with the SSRF guard, the retry policy and the metric.
    pub async fn deliver(&self, job: &NotificationJob) -> DeliveryOutcome {
        let channel = match self.channels.resolve(&job.recipient).await {
            Ok(channel) => channel,
            Err(err) => {
                tracing::warn!(
                    app.namespace = %job.namespace,
                    app.name = %job.name,
                    recipient = %job.recipient,
                    error = %err,
                    "cannot resolve the notification channel: dropping the notification"
                );
                return self.record(
                    job.service,
                    DeliveryOutcome::Dropped {
                        reason: "unknown_channel",
                    },
                );
            }
        };

        if channel.service != job.service {
            tracing::warn!(
                channel = %channel.name,
                declared = channel.service.as_str(),
                requested = job.service.as_str(),
                "the notification annotation and the channel Secret disagree about the service"
            );
            return self.record(
                job.service,
                DeliveryOutcome::Dropped {
                    reason: "service_mismatch",
                },
            );
        }

        // Static validation first (scheme, credentials, literal address, host names), then
        // resolution: a destination the operator allowlisted is re-checked against what it resolves
        // to right now.
        let target = match ValidatedWebhookUrl::parse(channel.url(), &self.policy) {
            Ok(target) => target,
            Err(err) => {
                tracing::warn!(
                    channel = %channel.name,
                    reason = err.reason().map(crate::notifications::ssrf::BlockReason::as_str),
                    error = %err,
                    "the notification destination is refused by the SSRF egress guard"
                );
                return self.record(
                    job.service,
                    DeliveryOutcome::Failed {
                        reason: "ssrf_blocked",
                    },
                );
            }
        };
        if let Err(err) = self.resolver.resolve(&target, &self.policy).await {
            tracing::warn!(
                channel = %channel.name,
                reason = err.reason().map(crate::notifications::ssrf::BlockReason::as_str),
                error = %err,
                "the notification destination resolves to a refused address"
            );
            return self.record(
                job.service,
                DeliveryOutcome::Failed {
                    reason: "ssrf_blocked",
                },
            );
        }

        // The template was resolved from the live config at trigger time, so the payload matches the
        // event that fired (even if the `ConfigMap` changed in between).
        let delivery =
            match adapters::build_delivery(&channel, &job.template, &job.context, &job.dedup_key) {
                Ok(delivery) => delivery,
                Err(err) => {
                    tracing::warn!(
                        channel = %channel.name,
                        error = %err,
                        "cannot build the notification payload"
                    );
                    return self.record(job.service, DeliveryOutcome::Failed { reason: "payload" });
                }
            };
        let request = {
            let mut request = DeliveryRequest::from(&delivery);
            // Finding R1-N6: post to the URL the guard *validated* (normalised scheme/host/port), not to
            // the raw `Secret` value, so the bytes on the wire and the bytes that were checked cannot
            // diverge (a `https://Example.COM:443/x` in a `Secret` must not become a different
            // request than the one the guard admitted).
            request.url = target.raw().to_owned();
            request
        };

        let attempts = self.max_attempts.max(1);
        let mut last_failure = "transport";
        for attempt in 0..attempts {
            match self.transport.post(&request).await {
                Ok(response) if response.is_success() => {
                    return self.record(job.service, DeliveryOutcome::Delivered);
                }
                Ok(response) if response.is_redirection() => {
                    // A redirect is refused, never followed: the target could be a metadata address
                    // and this client's own DNS guard would not see it. Retrying cannot help either.
                    tracing::warn!(
                        channel = %channel.name,
                        status = response.status,
                        "the notification receiver answered with a redirect; refusing to follow it"
                    );
                    return self
                        .record(job.service, DeliveryOutcome::Failed { reason: "redirect" });
                }
                Ok(response) => {
                    last_failure = "http_error";
                    tracing::warn!(
                        channel = %channel.name,
                        status = response.status,
                        attempt = attempt + 1,
                        attempts,
                        "the notification receiver rejected the payload"
                    );
                }
                Err(err) => {
                    last_failure = "transport";
                    tracing::warn!(
                        channel = %channel.name,
                        error = %err,
                        attempt = attempt + 1,
                        attempts,
                        "the notification delivery failed"
                    );
                }
            }
            if attempt + 1 < attempts {
                self.sleeper
                    .sleep(self.backoff(attempt, &job.dedup_key))
                    .await;
            }
        }
        self.record(
            job.service,
            DeliveryOutcome::Failed {
                reason: last_failure,
            },
        )
    }

    /// Backoff for the attempt that just failed: `base * 2^attempt`, jittered, saturating.
    ///
    /// The nominal delay is scaled into `[50 %, 100 %]` by a value derived from the job's
    /// deduplication key (finding **R1-N2**). Without jitter, a fleet-wide outage that fails 200
    /// Applications in the same reconcile wave retries them in lockstep and turns one thundering herd
    /// into three; deriving the jitter from the key keeps it **deterministic per delivery** (a retry
    /// test is still exact, and a retried job keeps its own schedule) while decorrelating different
    /// `Application`s.
    fn backoff(&self, attempt: u32, dedup_key: &str) -> Duration {
        let factor = 1_u32 << attempt.min(16);
        let nominal = self.retry_base_delay.saturating_mul(factor);
        let digest = ferriscd_engine::diff::sha256::digest(dedup_key.as_bytes());
        // 500..=1000 per mille, so the jitter is `[nominal/2, nominal]`.
        let per_mille = 500 + u32::from(digest[0]) % 501;
        nominal.mul_f64(f64::from(per_mille) / 1_000.0)
    }

    fn record(&self, service: NotificationService, outcome: DeliveryOutcome) -> DeliveryOutcome {
        self.metrics
            .record_notification(service, outcome.metric_outcome());
        outcome
    }
}

impl NotificationWorker {
    /// Runs until `cancel` is cancelled or the queue is closed.
    ///
    /// The `select!` is **biased** towards the cancel token (finding **R1-M5**): once shutdown starts,
    /// a job that is already queued can no longer win the race against the cancellation, so "cancel
    /// stops the worker" is a deterministic statement and not a coin flip against `recv()`.
    ///
    /// Each accepted job runs on its own task under a concurrency permit, so one slow receiver
    /// cannot delay another `Application`'s alert (finding **R1-M3**), and a panic inside one delivery
    /// is caught and logged instead of killing the loop (finding **R1-M2**).
    ///
    /// When the token is cancelled, jobs still in the queue are **not** delivered (they are logged as
    /// dropped and are not counted in `ferriscd_notifications_total`: nothing was attempted, so there
    /// is no outcome to report — see [`NotificationWorkerHandle::shutdown`]); deliveries already in
    /// flight are awaited, bounded by the caller's shutdown deadline.
    pub async fn run(mut self, cancel: tokio_util::sync::CancellationToken) {
        let engine = Arc::new(self.engine());
        let permits = Arc::new(tokio::sync::Semaphore::new(self.concurrency.max(1)));
        let mut in_flight: JoinSet<DeliveryOutcome> = JoinSet::new();
        loop {
            let job = tokio::select! {
                biased;
                () = cancel.cancelled() => break,
                Some(joined) = in_flight.join_next(), if !in_flight.is_empty() => {
                    log_join(joined);
                    continue;
                }
                job = self.rx.recv() => job,
            };
            let Some(job) = job else {
                break;
            };
            let permit = tokio::select! {
                biased;
                () = cancel.cancelled() => break,
                permit = permits.clone().acquire_owned() => match permit {
                    Ok(permit) => permit,
                    // The semaphore is only closed when this future is dropped; treated as shutdown.
                    Err(_) => break,
                },
            };
            let engine = engine.clone();
            in_flight.spawn(async move {
                let _permit = permit;
                let namespace = job.namespace.clone();
                let name = job.name.clone();
                let service = job.service;
                // Finding R1-M2: one panicking delivery must not take the subsystem down. The panic is
                // logged (never re-raised) and counted as a failure so it is visible in the metric.
                let outcome = match AssertUnwindSafe(engine.deliver(&job)).catch_unwind().await {
                    Ok(outcome) => outcome,
                    Err(panic) => {
                        tracing::error!(
                            app.namespace = %namespace,
                            app.name = %name,
                            service = service.as_str(),
                            panic = %panic_message(panic.as_ref()),
                            "a notification delivery panicked; the delivery is counted as failed and \
                             the worker keeps running"
                        );
                        engine.record(service, DeliveryOutcome::Failed { reason: "panic" })
                    }
                };
                tracing::debug!(
                    app.namespace = %namespace,
                    app.name = %name,
                    service = service.as_str(),
                    outcome = ?outcome,
                    "notification delivery attempted"
                );
                outcome
            });
        }
        let queued = self.rx.len();
        if queued > 0 {
            tracing::info!(
                dropped = queued,
                "stopping the notification worker with queued notifications; they are not delivered"
            );
        }
        // Stop accepting, and let the deliveries already in flight finish (the caller's shutdown
        // deadline bounds this).
        drop(self.rx);
        while let Some(joined) = in_flight.join_next().await {
            log_join(joined);
        }
    }

    /// Spawns [`Self::run`] on its own task and returns the handle the control plane drains.
    #[must_use]
    pub fn spawn(self) -> NotificationWorkerHandle {
        let cancel = tokio_util::sync::CancellationToken::new();
        let task = tokio::spawn(self.run(cancel.clone()));
        NotificationWorkerHandle {
            cancel,
            task: Mutex::new(Some(task)),
        }
    }
}

/// Logs the join result of one delivery task (`T19.4` finding **R1-M2**).
///
/// A task that panicked *outside* the `catch_unwind` (or that was aborted at shutdown) reaches this
/// function as a `JoinError`; swallowing it is how a silently dead delivery disappears from the
/// logs, so it is always reported.
fn log_join(joined: Result<DeliveryOutcome, tokio::task::JoinError>) {
    match joined {
        Ok(outcome) => tracing::debug!(
            outcome = ?outcome,
            "notification delivery task finished"
        ),
        Err(err) if err.is_cancelled() => tracing::debug!(
            error = %err,
            "a notification delivery task was cancelled at shutdown"
        ),
        Err(err) => tracing::error!(
            error = %err,
            "a notification delivery task failed; the worker keeps running"
        ),
    }
}

/// A panic payload rendered for a log line (never a credential: the payload is a Rust message).
fn panic_message(panic: &(dyn std::any::Any + Send)) -> &str {
    panic
        .downcast_ref::<&'static str>()
        .copied()
        .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic payload")
}

/// Handle to the spawned worker, so shutdown can stop it deterministically.
pub struct NotificationWorkerHandle {
    cancel: tokio_util::sync::CancellationToken,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl fmt::Debug for NotificationWorkerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotificationWorkerHandle")
            .field("cancelled", &self.cancel.is_cancelled())
            .finish_non_exhaustive()
    }
}

impl NotificationWorkerHandle {
    /// How long [`Self::shutdown`] waits for the worker task (`1 s`).
    pub const DRAIN_DEADLINE: Duration = Duration::from_secs(1);

    /// Cancels the worker and awaits it with a bounded deadline.
    ///
    /// What actually happens to a queued notification at shutdown (finding **R1-N5** — this used to
    /// claim the drops were counted, which they are not): the cancellation wins against `recv()`
    /// (the loop is biased), so jobs still in the queue are **not** attempted. They are logged as
    /// dropped and leave no `ferriscd_notifications_total` sample at all, because nothing was
    /// attempted and an `outcome` label would be a lie. Deliveries already in flight are awaited
    /// within [`Self::DRAIN_DEADLINE`]; a delivery that outlives the deadline is lost (and logged),
    /// because a stopping process must not hang on a receiver that stopped answering.
    pub async fn shutdown(self) {
        self.cancel.cancel();
        let task = lock_recover(&self.task).take();
        let Some(task) = task else {
            return;
        };
        match tokio::time::timeout(Self::DRAIN_DEADLINE, task).await {
            Ok(Ok(())) => {}
            // `T19.4` finding R1-M2: a join error (a panic that escaped the per-delivery guard, or a
            // cancelled task) was previously discarded, so a dead worker looked healthy.
            Ok(Err(err)) => tracing::error!(
                error = %err,
                "the notification worker task ended abnormally"
            ),
            Err(_) => tracing::warn!(
                deadline = ?Self::DRAIN_DEADLINE,
                "the notification worker did not stop before the shutdown deadline; its queued \
                 notifications are lost and an in-flight delivery may be cut short"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use ferriscd_crd::annotations::{
        TRIGGER_HEALTH_DEGRADED, TRIGGER_OUT_OF_SYNC, TRIGGER_SYNC_FAILED, TRIGGER_SYNC_SUCCEEDED,
    };
    use ferriscd_crd::application::{
        DEFAULT_REQUEUE_AFTER_SECONDS, DEFAULT_REVISION_HISTORY_LIMIT,
    };
    use ferriscd_crd::status::{
        ApplicationStatus, Condition, ConditionStatus, HealthState, HealthStatus, SyncState,
        SyncStatus,
    };
    use ferriscd_crd::{
        Application, ApplicationSpec, DestinationSpec, GitSourceSpec, RendererSpec, SourceSpec,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;

    use crate::notifications::{
        DEFAULT_QUEUE_CAPACITY, SecretValue, template::NotificationContext,
    };

    use super::*;

    const SIGNING_KEY: &str = "the-hmac-signing-key";

    /// Records every request and answers with a scripted status.
    struct MockTransport {
        responses: StdMutex<Vec<Result<u16, ()>>>,
        requests: StdMutex<Vec<DeliveryRequest>>,
    }

    impl MockTransport {
        fn new(responses: Vec<Result<u16, ()>>) -> Arc<Self> {
            Arc::new(Self {
                responses: StdMutex::new(responses),
                requests: StdMutex::new(Vec::new()),
            })
        }

        fn requests(&self) -> Vec<DeliveryRequest> {
            self.requests.lock().expect("transport lock").clone()
        }
    }

    impl NotificationTransport for MockTransport {
        fn post<'a>(
            &'a self,
            request: &'a DeliveryRequest,
        ) -> BoxFuture<'a, Result<DeliveryResponse, TransportError>> {
            Box::pin(async move {
                self.requests
                    .lock()
                    .expect("transport lock")
                    .push(request.clone());
                let next = {
                    let mut responses = self.responses.lock().expect("responses lock");
                    if responses.is_empty() {
                        Ok(200)
                    } else {
                        responses.remove(0)
                    }
                };
                match next {
                    Ok(status) => Ok(DeliveryResponse { status }),
                    Err(()) => Err(TransportError::Request {
                        message: "connection reset by peer".to_owned(),
                    }),
                }
            })
        }
    }

    /// A resolver with no network: answers every name with one address (by default a public one), or
    /// hands back a blocked address to model DNS rebinding.
    struct StubResolver {
        answer: Vec<std::net::SocketAddr>,
    }

    impl StubResolver {
        fn public() -> Arc<Self> {
            Arc::new(Self {
                answer: vec!["93.184.216.34:443".parse().expect("a public address")],
            })
        }

        fn rebinding_to_metadata() -> Arc<Self> {
            Arc::new(Self {
                answer: vec!["169.254.169.254:443".parse().expect("a metadata address")],
            })
        }
    }

    impl DestinationResolver for StubResolver {
        fn resolve<'a>(
            &'a self,
            target: &'a ValidatedWebhookUrl,
            policy: &'a EgressPolicy,
        ) -> BoxFuture<'a, Result<Vec<std::net::SocketAddr>, crate::notifications::SsrfError>>
        {
            let answer = self.answer.clone();
            let redacted = target.redacted().to_owned();
            let policy = policy.clone();
            Box::pin(async move {
                for addr in &answer {
                    policy.permits(addr.ip()).map_err(|reason| {
                        crate::notifications::SsrfError::Blocked {
                            url: redacted.clone(),
                            reason,
                            address: Some(addr.ip()),
                        }
                    })?;
                }
                Ok(answer)
            })
        }
    }

    /// Records the backoff durations instead of sleeping.
    #[derive(Default)]
    struct RecordingSleeper {
        slept: StdMutex<Vec<Duration>>,
    }

    impl BackoffSleeper for RecordingSleeper {
        fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
            self.slept.lock().expect("sleeper lock").push(duration);
            Box::pin(async {})
        }
    }

    fn channel(service: NotificationService, url: &str) -> NotificationChannel {
        NotificationChannel::new(
            "payments-oncall",
            service,
            url,
            Some(SecretValue::new(SIGNING_KEY.as_bytes())),
            (service == NotificationService::PagerDuty)
                .then(|| SecretValue::new(b"pd-routing-key".to_vec())),
        )
        .expect("a valid channel")
    }

    /// A channel under an explicit name, so two recipients can be told apart (finding R1-M3's
    /// concurrency test delivers to a `slow` and a `fast` channel).
    fn named_channel(name: &str, service: NotificationService, url: &str) -> NotificationChannel {
        NotificationChannel::new(
            name,
            service,
            url,
            (service != NotificationService::PagerDuty)
                .then(|| SecretValue::new(SIGNING_KEY.as_bytes())),
            (service == NotificationService::PagerDuty)
                .then(|| SecretValue::new(b"pd-routing-key".to_vec())),
        )
        .expect("a valid channel")
    }

    fn context(trigger: &'static str) -> NotificationContext {
        let spec = ApplicationSpec {
            project: "payments".to_owned(),
            service_account_name: None,
            source: SourceSpec {
                git: Some(GitSourceSpec {
                    repo_url: "https://example.com/repo.git".to_owned(),
                    target_revision: "HEAD".to_owned(),
                    path: String::new(),
                }),
                oci: None,
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
        let status = ApplicationStatus {
            observed_generation: Some(2),
            sync: Some(SyncState::new(
                SyncStatus::Synced,
                Some("abc1234".to_owned()),
            )),
            health: Some(HealthState::new(HealthStatus::Healthy)),
            conditions: vec![Condition::ready(
                ConditionStatus::True,
                "SyncSucceeded",
                "applied 3 of 3 resources",
                Time("2026-11-24T12:00:00Z".parse().expect("timestamp")),
            )],
            ..ApplicationStatus::default()
        };
        NotificationContext::from_status(&app, &status, trigger, "webhook", "payments-oncall")
    }

    fn job(service: NotificationService, trigger: &'static str) -> NotificationJob {
        NotificationJob {
            namespace: "ferriscd-system".to_owned(),
            name: "demo-app".to_owned(),
            service,
            recipient: "payments-oncall".to_owned(),
            dedup_key: "ferriscd:ferriscd-system/demo-app:trigger:gen=2".to_owned(),
            context: context(trigger),
            template: MessageTemplate::default_for(trigger),
        }
    }

    fn test_worker(
        transport: Arc<MockTransport>,
        channels: Vec<NotificationChannel>,
        sleeper: Arc<RecordingSleeper>,
        metrics: Metrics,
    ) -> NotificationWorker {
        let (_tx, rx) = mpsc::channel(DEFAULT_QUEUE_CAPACITY);
        NotificationWorker::new(
            rx,
            Arc::new(StaticChannelSource::new(channels)),
            transport,
            EgressPolicy::strict(),
            metrics,
        )
        .with_sleeper(sleeper)
        .with_resolver(StubResolver::public())
        .with_retry_base_delay(Duration::from_millis(500))
    }

    /// **Verification bullet (2) + retry bullet:** two failures then a success produces exactly three
    /// attempts with a doubling (jittered) backoff, and the metric reports the final outcome — with
    /// no sleep.
    #[tokio::test]
    async fn deliveries_are_retried_with_exponential_backoff_and_counted() {
        let transport = MockTransport::new(vec![Ok(500), Err(()), Ok(204)]);
        let sleeper = Arc::new(RecordingSleeper::default());
        let metrics = Metrics::with_fixed_series();
        let worker = test_worker(
            transport.clone(),
            vec![channel(
                NotificationService::Webhook,
                "https://automation.example.com/hook",
            )],
            sleeper.clone(),
            metrics.clone(),
        );

        let delivered = job(NotificationService::Webhook, TRIGGER_SYNC_SUCCEEDED);
        let outcome = worker.deliver(&delivered).await;
        assert_eq!(outcome, DeliveryOutcome::Delivered);
        assert_eq!(
            transport.requests().len(),
            3,
            "one attempt plus two retries"
        );
        let slept = sleeper.slept.lock().expect("sleeper lock").clone();
        assert_eq!(slept.len(), 2, "one sleep between each pair of attempts");
        // Finding R1-N2: the delay is the nominal exponential backoff scaled into `[50 %, 100 %]` by a
        // value derived from the job's deduplication key, so a fleet-wide outage does not retry in
        // lockstep. The nominal doubling is what the bounds pin.
        assert!(
            slept[0] >= Duration::from_millis(250) && slept[0] <= Duration::from_millis(500),
            "the first backoff is half of 500 ms at worst, 500 ms at best: {slept:?}"
        );
        assert!(
            slept[1] >= Duration::from_millis(500) && slept[1] <= Duration::from_millis(1_000),
            "the second backoff is half of 1 s at worst, 1 s at best: {slept:?}"
        );
        assert!(
            slept[1] >= slept[0],
            "the second backoff can never be shorter than the first (the nominal delay doubles; \
             the jitter only shortens each one by up to half): {slept:?}"
        );
        // The recorded sleeps are the deterministic jitter of attempt 0 and attempt 1 for *this*
        // delivery's key: the loop really walks the attempt indices (a shared `jitter(0)` for every
        // attempt would still satisfy the bounds above).
        let engine = worker.engine();
        assert_eq!(slept[0], engine.backoff(0, &delivered.dedup_key));
        assert_eq!(slept[1], engine.backoff(1, &delivered.dedup_key));

        let body = metrics.encode().expect("metrics encode");
        assert!(
            body.contains(
                "ferriscd_notifications_total{service=\"webhook\",outcome=\"delivered\"}"
            ),
            "{body}"
        );

        // The signed generic payload went out intact, with the signature header.
        let request = &transport.requests()[0];
        assert!(
            request
                .headers
                .iter()
                .any(|(name, _)| name == adapters::SIGNATURE_HEADER)
        );
        assert!(request.body.contains("\"trigger\":\"on-sync-succeeded\""));
        assert!(!request.body.contains(SIGNING_KEY));
    }

    /// **Finding R1-N1:** the roadmap's "max 3 exponential-backoff retries" is implemented as three
    /// *attempts* (one try plus two retries); the interpretation is pinned here so it cannot drift.
    #[test]
    fn the_attempt_ceiling_is_documented_as_attempts_not_retries() {
        assert_eq!(DEFAULT_MAX_ATTEMPTS, 3);
        assert_eq!(
            crate::notifications::DEFAULT_MAX_RETRIES,
            DEFAULT_MAX_ATTEMPTS - 1,
            "three attempts are two retries, and therefore two backoff sleeps"
        );
        // The worst case for a hung receiver stays inside the documented budget: three 5 s timeouts
        // plus the two backoffs.
        assert!(
            DEFAULT_REQUEST_TIMEOUT * DEFAULT_MAX_ATTEMPTS
                + DEFAULT_RETRY_BASE_DELAY
                + DEFAULT_RETRY_BASE_DELAY * 2
                <= Duration::from_secs(20),
            "3 attempts + backoff must stay under 20 s"
        );
    }

    /// **Finding R1-N2:** the jitter is a pure function of the job's deduplication key, so a retry is
    /// reproducible while two different `Application`s do not share a schedule.
    #[test]
    fn the_backoff_jitter_is_deterministic_per_delivery_and_bounded() {
        let worker = test_worker(
            MockTransport::new(Vec::new()),
            Vec::new(),
            Arc::new(RecordingSleeper::default()),
            Metrics::new(),
        );
        for attempt in 0..3 {
            let nominal = DEFAULT_RETRY_BASE_DELAY * (1_u32 << attempt);
            let first = worker
                .engine()
                .backoff(attempt, "ferriscd:ns/app-a:on-sync-failed");
            let again = worker
                .engine()
                .backoff(attempt, "ferriscd:ns/app-a:on-sync-failed");
            assert_eq!(
                first, again,
                "the same delivery always jitters the same way"
            );
            assert!(
                first >= nominal / 2 && first <= nominal,
                "attempt {attempt} must stay inside [nominal/2, nominal]: {first:?} for {nominal:?}"
            );
        }

        // Different deliveries get different delays (not guaranteed for every pair, but guaranteed
        // for a large sample: 501 possible buckets).
        let distinct = (0..64)
            .map(|index| {
                worker
                    .engine()
                    .backoff(0, &format!("ferriscd:ns/app-{index}:on-sync-failed"))
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert!(
            distinct.len() > 4,
            "jitter must decorrelate deliveries, got {distinct:?}"
        );
    }

    /// **Verification bullet (2), failure half:** an always-failing receiver is attempted exactly
    /// `max_attempts` times and then reported as `failed` — never retried forever.
    #[tokio::test]
    async fn exhausted_retries_are_bounded_and_reported() {
        let transport = MockTransport::new(vec![Ok(502), Ok(502), Ok(502), Ok(502)]);
        let sleeper = Arc::new(RecordingSleeper::default());
        let metrics = Metrics::with_fixed_series();
        let worker = test_worker(
            transport.clone(),
            vec![channel(
                NotificationService::Slack,
                "https://hooks.slack.com/services/T/B/x",
            )],
            sleeper.clone(),
            metrics.clone(),
        );

        let outcome = worker
            .deliver(&job(NotificationService::Slack, TRIGGER_SYNC_FAILED))
            .await;
        assert_eq!(
            outcome,
            DeliveryOutcome::Failed {
                reason: "http_error"
            }
        );
        assert_eq!(transport.requests().len(), 3, "the attempt ceiling is 3");
        assert_eq!(sleeper.slept.lock().expect("sleeper lock").len(), 2);
        let body = metrics.encode().expect("metrics encode");
        assert!(
            body.contains("ferriscd_notifications_total{service=\"slack\",outcome=\"failed\"}"),
            "{body}"
        );
    }

    /// **Trap guard:** a redirect is refused, not followed, and not retried — even when it points at
    /// an address the egress guard would block anyway.
    #[tokio::test]
    async fn a_redirect_is_never_followed() {
        let transport = MockTransport::new(vec![Ok(302), Ok(200)]);
        let sleeper = Arc::new(RecordingSleeper::default());
        let metrics = Metrics::with_fixed_series();
        let worker = test_worker(
            transport.clone(),
            vec![channel(
                NotificationService::Webhook,
                "https://automation.example.com/hook",
            )],
            sleeper.clone(),
            metrics.clone(),
        );

        let outcome = worker
            .deliver(&job(NotificationService::Webhook, TRIGGER_SYNC_SUCCEEDED))
            .await;
        assert_eq!(outcome, DeliveryOutcome::Failed { reason: "redirect" });
        assert_eq!(
            transport.requests().len(),
            1,
            "the redirect target is never requested, and the attempt is not retried"
        );
        assert!(sleeper.slept.lock().expect("sleeper lock").is_empty());
        let body = metrics.encode().expect("metrics encode");
        assert!(
            body.contains("ferriscd_notifications_total{service=\"webhook\",outcome=\"failed\"}"),
            "{body}"
        );

        // The redirect target this receiver pointed at is one the guard refuses, so even a
        // hypothetical follow would be blocked.
        for location in [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "https://127.0.0.1:10255/pods",
            "https://[::ffff:169.254.169.254]/latest/meta-data/",
        ] {
            assert!(
                ValidatedWebhookUrl::parse(location, &EgressPolicy::strict()).is_err(),
                "{location} must be blocked"
            );
        }
    }

    /// **Verification bullet (2):** a destination that is refused by the egress guard is never
    /// contacted — the transport sees zero requests.
    #[tokio::test]
    async fn blocked_destinations_are_never_contacted() {
        for url in [
            "http://169.254.169.254/latest/meta-data/",
            "https://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1/hook",
            "https://[::1]/hook",
            "https://[::ffff:169.254.169.254]/hook",
            "https://[::ffff:127.0.0.1]/hook",
            "https://10.0.0.9/hook",
            "https://localhost/hook",
        ] {
            let transport = MockTransport::new(vec![Ok(200)]);
            let sleeper = Arc::new(RecordingSleeper::default());
            let metrics = Metrics::with_fixed_series();
            let worker = test_worker(
                transport.clone(),
                // The channel is built directly: the guard, not the channel parser, must refuse it,
                // because a `Secret` is operator input and the guard is the last line.
                vec![channel(NotificationService::Webhook, url)],
                sleeper,
                metrics.clone(),
            );
            let outcome = worker
                .deliver(&job(NotificationService::Webhook, TRIGGER_SYNC_SUCCEEDED))
                .await;
            assert_eq!(
                outcome,
                DeliveryOutcome::Failed {
                    reason: "ssrf_blocked"
                },
                "{url}"
            );
            assert!(
                transport.requests().is_empty(),
                "{url} must never be contacted"
            );
            let body = metrics.encode().expect("metrics encode");
            assert!(
                body.contains("outcome=\"failed\""),
                "{url} must be counted as a failure: {body}"
            );
        }
    }

    /// **DNS rebinding:** a public host name whose answer is a metadata address is refused at
    /// resolution time, before any socket is opened.
    #[tokio::test]
    async fn a_host_resolving_to_a_blocked_address_is_never_contacted() {
        let transport = MockTransport::new(vec![Ok(200)]);
        let sleeper = Arc::new(RecordingSleeper::default());
        let metrics = Metrics::with_fixed_series();
        let (_tx, rx) = mpsc::channel(DEFAULT_QUEUE_CAPACITY);
        let worker = NotificationWorker::new(
            rx,
            Arc::new(StaticChannelSource::new(vec![channel(
                NotificationService::Webhook,
                "https://innocent.example.com/hook",
            )])),
            transport.clone(),
            EgressPolicy::strict(),
            metrics.clone(),
        )
        .with_sleeper(sleeper)
        .with_resolver(StubResolver::rebinding_to_metadata());

        assert_eq!(
            worker
                .deliver(&job(NotificationService::Webhook, TRIGGER_SYNC_SUCCEEDED))
                .await,
            DeliveryOutcome::Failed {
                reason: "ssrf_blocked"
            }
        );
        assert!(
            transport.requests().is_empty(),
            "the metadata address must never be contacted"
        );
        let body = metrics.encode().expect("metrics encode");
        assert!(body.contains("outcome=\"failed\""), "{body}");
    }

    /// An allowlisted private receiver is contacted (the operator opted in), while a private one
    /// outside the allowlist is not.
    #[tokio::test]
    async fn the_allowlist_is_honoured_at_delivery_time() {
        let transport = MockTransport::new(vec![Ok(200)]);
        let sleeper = Arc::new(RecordingSleeper::default());
        let (_tx, rx) = mpsc::channel(DEFAULT_QUEUE_CAPACITY);
        let policy = EgressPolicy::from_allowlist_spec(Some("10.20.0.0/16")).expect("policy");
        let worker = NotificationWorker::new(
            rx,
            Arc::new(StaticChannelSource::new(vec![channel(
                NotificationService::Webhook,
                "https://10.20.5.7/hook",
            )])),
            transport.clone(),
            policy,
            Metrics::new(),
        )
        .with_sleeper(sleeper)
        .with_resolver(StubResolver::public());

        assert_eq!(
            worker
                .deliver(&job(NotificationService::Webhook, TRIGGER_SYNC_SUCCEEDED))
                .await,
            DeliveryOutcome::Delivered
        );
        assert_eq!(transport.requests().len(), 1);
        assert_eq!(transport.requests()[0].url, "https://10.20.5.7/hook");
    }

    /// An unknown recipient and a service mismatch are dropped (not retried, not contacted).
    #[tokio::test]
    async fn unresolvable_or_mismatched_channels_are_dropped() {
        let transport = MockTransport::new(vec![Ok(200)]);
        let sleeper = Arc::new(RecordingSleeper::default());
        let metrics = Metrics::with_fixed_series();
        let mut worker = test_worker(
            transport.clone(),
            vec![channel(
                NotificationService::Slack,
                "https://hooks.slack.com/services/T/B/x",
            )],
            sleeper.clone(),
            metrics.clone(),
        );

        // Unknown recipient.
        let unknown = NotificationJob {
            recipient: "nobody".to_owned(),
            ..job(NotificationService::Slack, TRIGGER_SYNC_FAILED)
        };
        assert_eq!(
            worker.deliver(&unknown).await,
            DeliveryOutcome::Dropped {
                reason: "unknown_channel"
            }
        );

        // The annotation asks for a webhook, the Secret declares Slack.
        assert_eq!(
            worker
                .deliver(&job(NotificationService::Webhook, TRIGGER_SYNC_FAILED))
                .await,
            DeliveryOutcome::Dropped {
                reason: "service_mismatch"
            }
        );
        assert!(transport.requests().is_empty());
        let body = metrics.encode().expect("metrics encode");
        assert!(
            body.contains("ferriscd_notifications_total{service=\"slack\",outcome=\"dropped\"}"),
            "{body}"
        );

        // A receiver that cannot be reached at all is a failure, not a drop.
        worker = test_worker(
            MockTransport::new(vec![Err(()), Err(()), Err(())]),
            vec![channel(
                NotificationService::Slack,
                "https://hooks.slack.com/services/T/B/x",
            )],
            sleeper,
            metrics,
        );
        assert_eq!(
            worker
                .deliver(&job(NotificationService::Slack, TRIGGER_SYNC_FAILED))
                .await,
            DeliveryOutcome::Failed {
                reason: "transport"
            }
        );
    }

    /// One job per supported service goes out, and PagerDuty carries its routing key while no payload
    /// carries the HMAC key.
    #[tokio::test]
    async fn every_service_delivers_its_payload() {
        for (service, url, expected_fragment) in [
            (
                NotificationService::Slack,
                "https://hooks.slack.com/services/T/B/x",
                "\"text\"",
            ),
            (
                NotificationService::Teams,
                "https://prod-00.westeurope.logic.azure.com/workflows/x",
                "AdaptiveCard",
            ),
            (
                NotificationService::PagerDuty,
                "https://events.pagerduty.com/v2/enqueue",
                "\"event_action\":\"trigger\"",
            ),
            (
                NotificationService::Webhook,
                "https://automation.example.com/hook",
                "\"schemaVersion\"",
            ),
        ] {
            let transport = MockTransport::new(vec![Ok(202)]);
            let sleeper = Arc::new(RecordingSleeper::default());
            let metrics = Metrics::with_fixed_series();
            let worker = test_worker(
                transport.clone(),
                vec![channel(service, url)],
                sleeper,
                metrics.clone(),
            );
            for trigger in [
                TRIGGER_SYNC_SUCCEEDED,
                TRIGGER_SYNC_FAILED,
                TRIGGER_HEALTH_DEGRADED,
                TRIGGER_OUT_OF_SYNC,
            ] {
                assert_eq!(
                    worker.deliver(&job(service, trigger)).await,
                    DeliveryOutcome::Delivered,
                    "{service} / {trigger}"
                );
            }
            let requests = transport.requests();
            assert_eq!(requests.len(), 4);
            for request in &requests {
                assert!(
                    request.body.contains(expected_fragment),
                    "{service}: {}",
                    request.body
                );
                assert!(
                    !request.body.contains(SIGNING_KEY),
                    "{service} leaked the HMAC key"
                );
                assert!(
                    request
                        .headers
                        .iter()
                        .any(|(name, _)| name.eq_ignore_ascii_case("content-type")),
                    "{service} must send JSON"
                );
                assert_eq!(request.url, url);
            }
            if service == NotificationService::PagerDuty {
                assert!(requests[0].body.contains("pd-routing-key"));
            }
        }
    }

    /// The worker finishes the queue when the **sender closes** (which is what the old
    /// `the_spawned_worker_drains_queued_jobs_and_stops_on_cancel` actually asserted — finding R1-M5
    /// kept the name honest).
    #[tokio::test]
    async fn the_worker_finishes_queued_jobs_when_the_sender_closes() {
        let transport = MockTransport::new(vec![Ok(200), Ok(200)]);
        let sleeper = Arc::new(RecordingSleeper::default());
        let metrics = Metrics::with_fixed_series();
        let (tx, rx) = mpsc::channel(8);
        let worker = NotificationWorker::new(
            rx,
            Arc::new(StaticChannelSource::new(vec![channel(
                NotificationService::Slack,
                "https://hooks.slack.com/services/T/B/x",
            )])),
            transport.clone(),
            EgressPolicy::strict(),
            metrics.clone(),
        )
        .with_sleeper(sleeper)
        .with_resolver(StubResolver::public());
        let handle = worker.spawn();

        for _ in 0..2 {
            tx.try_send(job(NotificationService::Slack, TRIGGER_SYNC_SUCCEEDED))
                .expect("the queue has room");
        }
        drop(tx);
        // Waiting for the task to end is what proves it drained the queue.
        let delivered = wait_for_deliveries(&transport, 2).await;
        assert_eq!(delivered, 2, "a closed queue is drained, not abandoned");
        handle.shutdown().await;
    }

    /// **Finding R1-M5:** `shutdown` (a cancel) is *not* a drain. The loop is biased towards the cancel
    /// token, so a queued job is dropped deterministically instead of racing `recv()` — and the drop
    /// is reported as a log, never as an `outcome` sample (nothing was attempted).
    #[tokio::test]
    async fn shutdown_cancels_before_a_queued_job_is_delivered() {
        let transport = MockTransport::new(vec![Ok(200)]);
        let sleeper = Arc::new(RecordingSleeper::default());
        let metrics = Metrics::with_fixed_series();
        let (tx, rx) = mpsc::channel(8);
        let worker = NotificationWorker::new(
            rx,
            Arc::new(StaticChannelSource::new(vec![channel(
                NotificationService::Slack,
                "https://hooks.slack.com/services/T/B/x",
            )])),
            transport.clone(),
            EgressPolicy::strict(),
            metrics.clone(),
        )
        .with_sleeper(sleeper)
        .with_resolver(StubResolver::public())
        // One delivery at a time, so the test controls exactly how many are in flight.
        .with_concurrency(1);
        let handle = worker.spawn();

        for _ in 0..3 {
            tx.try_send(job(NotificationService::Slack, TRIGGER_SYNC_SUCCEEDED))
                .expect("the queue has room");
        }
        handle.shutdown().await;
        // Deterministic: the cancel is observed before any queued job is picked up, because the
        // biased `select!` polls the token first. (`recv()` may already have been polled once before
        // the cancel, so at most one job can be in flight — never all three.)
        let delivered = transport.requests().len();
        assert!(
            delivered <= 1,
            "shutdown must not drain the queue, but {delivered} notifications were delivered"
        );
        let body = metrics.encode().expect("metrics encode");
        assert!(
            !body.contains("ferriscd_notifications_total{service=\"slack\",outcome=\"dropped\"} 1"),
            "queued-at-shutdown jobs are logged, not counted as dropped: {body}"
        );
    }

    /// **Finding R1-M3:** a slow destination does not block another `Application`'s alert.
    ///
    /// The worker used to deliver strictly serially, so one receiver that used its whole 5 s timeout
    /// delayed *every* other notification by 5 s. The gate is released by the test, never by a sleep.
    #[tokio::test]
    async fn one_slow_destination_does_not_block_another() {
        struct GatedTransport {
            release_slow: Arc<tokio::sync::Notify>,
            fast_delivered: Arc<tokio::sync::Notify>,
        }

        impl NotificationTransport for GatedTransport {
            fn post<'a>(
                &'a self,
                request: &'a DeliveryRequest,
            ) -> BoxFuture<'a, Result<DeliveryResponse, TransportError>> {
                Box::pin(async move {
                    if request.url.contains("slow") {
                        self.release_slow.notified().await;
                    } else {
                        self.fast_delivered.notify_one();
                    }
                    Ok(DeliveryResponse { status: 200 })
                })
            }
        }

        let transport = Arc::new(GatedTransport {
            release_slow: Arc::new(tokio::sync::Notify::new()),
            fast_delivered: Arc::new(tokio::sync::Notify::new()),
        });
        let (tx, rx) = mpsc::channel(8);
        let worker = NotificationWorker::new(
            rx,
            Arc::new(StaticChannelSource::new(vec![
                named_channel(
                    "slow",
                    NotificationService::Webhook,
                    "https://slow.example.com/hook",
                ),
                named_channel(
                    "fast",
                    NotificationService::Webhook,
                    "https://fast.example.com/hook",
                ),
            ])),
            transport.clone(),
            EgressPolicy::strict(),
            Metrics::new(),
        )
        .with_sleeper(Arc::new(RecordingSleeper::default()))
        .with_resolver(StubResolver::public());
        let handle = worker.spawn();

        tx.try_send(NotificationJob {
            recipient: "slow".to_owned(),
            ..job(NotificationService::Webhook, TRIGGER_SYNC_FAILED)
        })
        .expect("the queue has room");
        tx.try_send(NotificationJob {
            recipient: "fast".to_owned(),
            ..job(NotificationService::Webhook, TRIGGER_SYNC_FAILED)
        })
        .expect("the queue has room");

        // The fast delivery completes while the slow one is still blocked: a bounded wait, not a
        // sleep, and it fails loudly instead of hanging.
        tokio::time::timeout(Duration::from_secs(5), transport.fast_delivered.notified())
            .await
            .expect("the fast destination must be delivered while the slow one is still blocked");

        transport.release_slow.notify_waiters();
        handle.shutdown().await;
    }

    /// **Finding R1-M2:** a panicking delivery is logged, counted and survived — the worker keeps
    /// delivering the next job (a `catch_unwind` per delivery).
    #[tokio::test]
    async fn a_panicking_delivery_does_not_stop_the_worker() {
        struct PanicsOnce {
            panicked: StdMutex<bool>,
            delivered: Arc<tokio::sync::Notify>,
        }

        impl NotificationTransport for PanicsOnce {
            fn post<'a>(
                &'a self,
                _request: &'a DeliveryRequest,
            ) -> BoxFuture<'a, Result<DeliveryResponse, TransportError>> {
                Box::pin(async move {
                    let first = {
                        let mut panicked = self.panicked.lock().expect("panic flag lock");
                        let first = !*panicked;
                        *panicked = true;
                        first
                    };
                    if first {
                        panic!("a transport bug");
                    }
                    self.delivered.notify_one();
                    Ok(DeliveryResponse { status: 200 })
                })
            }
        }

        let metrics = Metrics::with_fixed_series();
        let transport = Arc::new(PanicsOnce {
            panicked: StdMutex::new(false),
            delivered: Arc::new(tokio::sync::Notify::new()),
        });
        let (tx, rx) = mpsc::channel(8);
        let worker = NotificationWorker::new(
            rx,
            Arc::new(StaticChannelSource::new(vec![channel(
                NotificationService::Webhook,
                "https://automation.example.com/hook",
            )])),
            transport.clone(),
            EgressPolicy::strict(),
            metrics.clone(),
        )
        .with_sleeper(Arc::new(RecordingSleeper::default()))
        .with_resolver(StubResolver::public());
        let handle = worker.spawn();

        for _ in 0..2 {
            tx.try_send(job(NotificationService::Webhook, TRIGGER_SYNC_SUCCEEDED))
                .expect("the queue has room");
        }
        tokio::time::timeout(Duration::from_secs(5), transport.delivered.notified())
            .await
            .expect("the worker must survive the panicking delivery and deliver the next job");

        handle.shutdown().await;
        let body = metrics.encode().expect("metrics encode");
        assert!(
            body.contains("ferriscd_notifications_total{service=\"webhook\",outcome=\"failed\"} 1"),
            "the panic is counted as a failure: {body}"
        );
        assert!(
            body.contains(
                "ferriscd_notifications_total{service=\"webhook\",outcome=\"delivered\"} 1"
            ),
            "the second delivery still happens: {body}"
        );
    }

    /// **Finding R1-N6:** the request goes to the URL the egress guard *validated*, not to the raw
    /// `Secret` value, so the bytes on the wire are the bytes that were checked.
    #[tokio::test]
    async fn the_request_uses_the_validated_url() {
        let transport = MockTransport::new(vec![Ok(200)]);
        let sleeper = Arc::new(RecordingSleeper::default());
        let worker = test_worker(
            transport.clone(),
            vec![channel(
                NotificationService::Webhook,
                // An uppercase host (and an explicit default port) is normalised by the URL parser.
                "https://Automation.Example.COM:443/hook?token=abc123",
            )],
            sleeper,
            Metrics::new(),
        );
        assert_eq!(
            worker
                .deliver(&job(NotificationService::Webhook, TRIGGER_SYNC_SUCCEEDED))
                .await,
            DeliveryOutcome::Delivered
        );
        let request = &transport.requests()[0];
        assert_eq!(
            request.url, "https://automation.example.com/hook?token=abc123",
            "the posted URL is the validated (normalised) one"
        );
    }

    /// **Finding R1-H2:** the production client's configuration is *assertable*, and a plaintext
    /// destination is refused by the client itself (offline: no DNS, no socket).
    #[tokio::test]
    async fn the_production_transport_refuses_plaintext_and_follows_no_redirects() {
        let policy =
            EgressPolicy::from_allowlist_spec(Some("10.20.0.0/16")).expect("a valid allowlist");
        let transport = ReqwestTransport::build(policy.clone()).expect("the client must build");

        let config = transport.config();
        assert!(config.https_only, "the client must be HTTPS-only");
        assert!(
            config.proxy_disabled,
            "`HTTP(S)_PROXY` must not be able to reroute a notification"
        );
        assert_eq!(
            config.max_redirects, 0,
            "no redirect may ever be followed (Policy::none())"
        );
        assert_eq!(
            config.redirect_policy(),
            RedirectPolicy::None,
            "the mapping from the recorded config to the client must be `Policy::none()`"
        );
        assert!(
            !config.redirect_policy().follows_redirects(),
            "no redirect may ever be followed"
        );
        assert!(
            config.pinned_resolver,
            "the GuardedResolver must be installed (the address-pinning half of the guard)"
        );
        assert_eq!(
            config.egress_policy, policy,
            "the resolver must enforce the configured policy"
        );
        assert_eq!(config.timeout, DEFAULT_REQUEST_TIMEOUT);
        assert_eq!(transport.timeout(), DEFAULT_REQUEST_TIMEOUT);
        assert_eq!(
            TransportConfig::strict(policy.clone()),
            *config,
            "`build` stores exactly what `TransportConfig::strict` documents"
        );

        // And the behaviour, not just the record: an `http://` destination never reaches a socket.
        // `reqwest`'s `Display` for a builder-kind error is the fixed string "builder error" (the
        // scheme detail lives in the error's source, which is deliberately not rendered here so a
        // URL can never be spliced into the message); a *connect* failure would have been
        // "error sending request" instead, so the kind is what this assertion pins.
        let error = transport
            .post(&DeliveryRequest {
                url: "http://127.0.0.1:1/hook".to_owned(),
                headers: Vec::new(),
                body: "{}".to_owned(),
            })
            .await
            .expect_err("a plaintext destination must be refused by the transport itself");
        let message = match error {
            TransportError::Request { message } => message,
            other => panic!("the refusal is a request error, not a CA-file error: {other:?}"),
        };
        assert!(
            message.contains("builder")
                || message.to_lowercase().contains("scheme")
                || message.to_lowercase().contains("https"),
            "the client refuses the scheme (the guard is not the only layer): {message}"
        );
        assert!(
            !message.contains("error sending request"),
            "the plaintext URL must be refused before a connection is attempted: {message}"
        );
        assert!(
            !message.contains("127.0.0.1"),
            "the error stays credential/address-free: {message}"
        );
    }

    /// **Finding R1-M4:** neither request type prints its URL, a header value, or the body.
    #[test]
    fn delivery_debug_output_redacts_the_url_and_the_header_values() {
        let delivery = adapters::build_delivery(
            &channel(
                NotificationService::Webhook,
                "https://hooks.example.com/services/T000/B000/superSecretPathToken",
            ),
            &MessageTemplate::default_for(TRIGGER_SYNC_FAILED),
            &context(TRIGGER_SYNC_FAILED),
            "ferriscd:ns/app:on-sync-failed:gen=2",
        )
        .expect("a delivery");
        let printed = format!("{delivery:?}");
        assert!(
            !printed.contains("superSecretPathToken"),
            "the URL path token must be redacted: {printed}"
        );
        assert!(!printed.contains(SIGNING_KEY), "{printed}");
        assert!(
            printed.contains(adapters::SIGNATURE_HEADER),
            "header *names* are useful and safe: {printed}"
        );

        let request = DeliveryRequest::from(&delivery);
        let printed = format!("{request:?}");
        assert!(!printed.contains("superSecretPathToken"), "{printed}");
        assert!(!printed.contains(SIGNING_KEY), "{printed}");
        assert!(
            !printed.contains("applied 3 of 3 resources"),
            "the body is not printed, only its size: {printed}"
        );
        assert!(printed.contains("body_bytes"), "{printed}");
        assert!(printed.contains("hooks.example.com"), "{printed}");
    }

    /// A throwaway self-signed CA, generated once for this test (the private key is deliberately not
    /// stored: nothing here signs anything, the certificate only has to be a parsable PEM root).
    const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDAjCCAeqgAwIBAgIUCi7TmkckvzdJ3A77a3bCL31A5hcwDQYJKoZIhvcNAQEL\n\
BQAwIDEeMBwGA1UEAwwVZmVycmlzY2QtdDE5NC10ZXN0LWNhMCAXDTI2MTEyNzE5\n\
MDM0NFoYDzIxMjYxMTAzMTkwMzQ0WjAgMR4wHAYDVQQDDBVmZXJyaXNjZC10MTk0\n\
LXRlc3QtY2EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCunUwikP4S\n\
dQd51pn/+4VaARML989S3wfP3jUO7boaw8da4q6tpQCtIYQUcnt2ItPSLURxQQ6g\n\
r6toZN+557KiJBVF4X11++J7M5MV6+52vCg7dgMdNQGXFN7QjoiIiZY8AoTM6mCk\n\
LfMpIb+Kjz48BXib9ImWQGNsfwljlurtfpmSHEr+buDDmiFR3WaJhVR4aPsP0omq\n\
sOf5aJay0aXXFm0QZ35QhVoijptgik+3ZG/mtPAcrXzqbhYsEz0gKqCpfcTnCrSX\n\
crosCnELhCPWcNS7uT8NynrfsZcNHcAoYwaI44I9yaB2bVjsNRM6kY2HNcX+X7ff\n\
mCZ7GCWNiyDLAgMBAAGjMjAwMB0GA1UdDgQWBBTkHXZCQPPx43Yc3bl3r5lChtOe\n\
OjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAl4obG/a4smKKc\n\
B5EPWpnpQTnOxzair9lquhjlYPAk1/vwdjtWAGB1sUtYYpGeIUo2fsmagnVexYKQ\n\
LZcfgQxh0vcgAKkWpityiT5oS04RJRaRE94gVkNYZNq+ugy72q+2sExUowAIruzT\n\
OqLhko0xRdMaHirFSejT0XxwKcvedqQZLaDEbLq+HrtUIWpNT/8zepnNkK7gtKUV\n\
q7PFAe8SsEwj++RxElO/iire8uhCfK2ILhqj9CJd0UvFPSPD/N3Hws3g9TKQnaPo\n\
1BbnHT5iTxwiFq5+lIMGUhBEMlbQVFEAkTHQPN7lfkNVAeO4tWysbnE0SRVLjXEb\n\
SwDxNuBq\n\
-----END CERTIFICATE-----\n";

    /// **Finding P19-H1 (the `--notifications-ca-file` half):** the operator's PEM bundle is loaded and
    /// **added** to the client's roots — verification, hostname/IP checks, HTTPS-only and the SSRF
    /// resolver are all untouched — and every failure mode (missing, empty, not PEM) fails closed at
    /// startup instead of silently falling back to "no extra trust".
    #[tokio::test]
    async fn the_ca_file_adds_roots_and_fails_closed() {
        let dir = tempfile::TempDir::new().expect("a scratch directory");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, TEST_CA_PEM).expect("write the CA fixture");

        let certificates = load_root_certificates(&ca_path)
            .await
            .expect("the PEM fixture is a valid root");
        assert_eq!(certificates.len(), 1, "one CERTIFICATE block, one root");
        let transport =
            ReqwestTransport::build_with_root_certificates(EgressPolicy::strict(), certificates)
                .expect("the client must build with an extra root");
        assert_eq!(
            transport.config().custom_root_certificates,
            1,
            "the added root is part of the recorded configuration"
        );
        // Adding a root changes *nothing* else: still HTTPS-only, proxy-free, redirect-free, pinned.
        assert_eq!(
            transport.config(),
            &TransportConfig {
                custom_root_certificates: 1,
                ..TransportConfig::strict(EgressPolicy::strict())
            },
            "the CA file must not weaken any other guard"
        );
        assert_eq!(
            TransportConfig::strict(EgressPolicy::strict()).custom_root_certificates,
            0,
            "the default adds no root: the platform trust store alone"
        );
        assert!(
            !format!("{transport:?}").contains("BEGIN CERTIFICATE"),
            "the certificate material is never logged"
        );

        // A bundle with two certificates yields two roots (a rotation bundle works unchanged).
        let bundle_path = dir.path().join("bundle.pem");
        std::fs::write(&bundle_path, format!("{TEST_CA_PEM}{TEST_CA_PEM}"))
            .expect("write the bundle fixture");
        assert_eq!(
            load_root_certificates(&bundle_path)
                .await
                .expect("a two-certificate bundle")
                .len(),
            2
        );

        // Missing file: the error names the path (a typo must be debuggable) and nothing else.
        let missing = dir.path().join("nope.pem");
        let error = load_root_certificates(&missing)
            .await
            .expect_err("a missing CA file must fail closed");
        match error {
            TransportError::CaFile { path, message } => {
                assert_eq!(path, missing);
                assert!(message.contains("could not be read"), "{message}");
            }
            other => panic!("expected a CaFile error, got {other:?}"),
        }

        // Empty file and not-a-PEM file are refused too (an empty CA file would "work" and then fail
        // TLS on the first alert).
        for (name, content, expected) in [
            ("empty.pem", "", "empty"),
            (
                "junk.pem",
                "not a certificate",
                "it contains no CERTIFICATE block",
            ),
        ] {
            let path = dir.path().join(name);
            std::fs::write(&path, content).expect("write the bad fixture");
            let error = load_root_certificates(&path)
                .await
                .expect_err("an unusable CA file must fail closed");
            let printed = error.to_string();
            assert!(
                printed.contains(expected) && printed.contains(name),
                "expected {expected:?} for {name}: {printed}"
            );
            assert!(
                !printed.contains(content) || content.is_empty(),
                "the file's content is never echoed: {printed}"
            );
        }

        // A `CERTIFICATE` block whose payload is not a certificate: `reqwest` accepts the PEM
        // leniently, so the failure surfaces one step later — at client construction, still at
        // startup, never as a controller that comes up and then cannot deliver.
        let bogus = dir.path().join("bogus.pem");
        std::fs::write(
            &bogus,
            "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n",
        )
        .expect("write the bogus fixture");
        let certificates = load_root_certificates(&bogus)
            .await
            .expect("a PEM block is accepted leniently");
        let error =
            ReqwestTransport::build_with_root_certificates(EgressPolicy::strict(), certificates)
                .expect_err("an unusable root certificate must not build a client");
        assert!(
            matches!(error, TransportError::Request { .. }),
            "the refusal is a client-construction error: {error:?}"
        );
    }

    /// Polls the mock transport until it has recorded `expected` requests (bounded, never a sleep).
    async fn wait_for_deliveries(transport: &MockTransport, expected: usize) -> usize {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let seen = transport.requests().len();
            if seen >= expected || tokio::time::Instant::now() >= deadline {
                return seen;
            }
            tokio::task::yield_now().await;
        }
    }

    #[test]
    fn the_queue_capacity_and_attempt_ceiling_are_the_documented_values() {
        assert_eq!(DEFAULT_QUEUE_CAPACITY, 512);
        let (_tx, rx) = mpsc::channel(4);
        let worker = NotificationWorker::new(
            rx,
            Arc::new(StaticChannelSource::default()),
            MockTransport::new(Vec::new()),
            EgressPolicy::strict(),
            Metrics::new(),
        );
        assert_eq!(worker.max_attempts, DEFAULT_MAX_ATTEMPTS);
        assert_eq!(worker.retry_base_delay, DEFAULT_RETRY_BASE_DELAY);
        // `with_max_attempts(0)` is clamped to one attempt: a delivery always gets one try.
        let (_tx, rx) = mpsc::channel(4);
        let clamped = NotificationWorker::new(
            rx,
            Arc::new(StaticChannelSource::default()),
            MockTransport::new(Vec::new()),
            EgressPolicy::strict(),
            Metrics::new(),
        )
        .with_max_attempts(0);
        assert_eq!(clamped.max_attempts, 1);
        let printed = format!("{:?}", job(NotificationService::Slack, TRIGGER_SYNC_FAILED));
        assert!(printed.contains("trigger: \"on-sync-failed\""), "{printed}");
        assert!(printed.contains("service: \"slack\""), "{printed}");
        assert!(
            !printed.contains("applied 3 of 3 resources"),
            "the rendered body is not part of the job's Debug: {printed}"
        );
    }
}
