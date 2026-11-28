//! Event-driven notifications (`T19.4`): annotation-driven subscriptions, redacted payloads, and an
//! SSRF-guarded, bounded delivery worker.
//!
//! # The event flow
//!
//! ```text
//! reconcile pass ──► StatusWriter::patch(status)          (always-update-status, trap T3)
//!                       │
//!                       ├─► ApiStatusWriter            (the real /status patch)
//!                       └─► NotificationObserver       (this module, after the patch landed)
//!                              │  edge detection on (sync, health, revision, generation)
//!                              │  dedup LRU + per-app token bucket + out-of-sync debounce
//!                              ▼
//!                        try_send (capacity 512, never awaited)
//!                              ▼
//!                     NotificationWorker (its own task)
//!                              │  channel Secret ─► template ─► adapter payload (+ HMAC)
//!                              │  SSRF guard ─► HTTPS POST, 5 s timeout, ≤ 3 attempts
//!                              ▼
//!                     ferriscd_notifications_total{service, outcome}
//! ```
//!
//! # Why a status-writer decorator (and not a new controller)
//!
//! The status a pass persisted is exactly the input of every trigger: `Synced` for
//! `on-sync-succeeded`, `Ready=False` for `on-sync-failed`, `Degraded` for `on-health-degraded`,
//! `OutOfSync` for `on-out-of-sync`. Attaching to the writer means **zero extra API server reads**
//! (no second list/watch, no re-fetch per trigger) and it composes with the `T15.1` metrics
//! decorator, which reads the same value.
//!
//! Nothing in the observer awaits a network call: it enqueues with `try_send` on a bounded channel,
//! so a Slack outage can never delay a reconcile (`T19.4` non-functional requirement). Delivery,
//! retries and backoff all happen on the worker's own task.
//!
//! # Configuration surfaces
//!
//! | What | Where | Never |
//! |---|---|---|
//! | Which triggers, which service, which recipient | `Application` annotation `notifications.ferriscd.io/subscribe.<trigger>.<service>: <recipient>` | never in `ApplicationSpec` (no spec change for an alert) |
//! | Message text and the out-of-sync debounce | `ConfigMap/ferriscd-notifications-cm` in the control-plane namespace | never secret material |
//! | Destination URL, HMAC key, PagerDuty routing key, bearer token, Slack channel | `Secret`s labelled `ferriscd.io/secret-type: notifications` (`url`, `service`, `signingKey`, `routingKey`, `token`, `channel`) | never in an annotation or a `ConfigMap` (`T19.4` trap guard) |
//! | Which **tenants** may opt in at all | `--notifications-allowed-namespaces` (an explicit, bounded allowlist; unset means every namespace, as before) | never inferred from a cluster-wide `Application` list |
//!
//! The channel `Secrets` are read through a **namespaced** `Api<Secret>` for the control-plane
//! namespace only, so a tenant cannot point an annotation at a `Secret` outside it. Because a
//! tenant that can write an annotation can still name *another team's* channel in that namespace,
//! `--notifications-allowed-namespaces` is the explicit tenancy boundary (finding **R1-M6**): an
//! `Application` whose namespace is not on the list is ignored before any gate, token or delivery.
//!
//! # Trap guards implemented here
//!
//! * Subscription annotations are **not** in
//!   [`CONTROL_ANNOTATIONS`](ferriscd_crd::annotations::CONTROL_ANNOTATIONS), so subscribing emits
//!   no reconcile (asserted against [`crate::predicate::composite_hash`]).
//! * Channel `Secret` values live in [`NotificationChannel`], whose `Debug` prints neither the URL's
//!   query string nor the HMAC/routing key; payloads are built from the redacted
//!   [`NotificationContext`](template::NotificationContext) only.
//! * Destinations are validated by [`ssrf`] (HTTPS-only, private/link-local/metadata refusal, IPv4-
//!   mapped IPv6 canonicalisation), redirects are never followed, and the production client pins the
//!   validated address at DNS time.

pub mod adapters;
pub mod observer;
pub mod ssrf;
pub mod template;
pub mod worker;

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use ferriscd_crd::Application;
use ferriscd_crd::annotations;
use ferriscd_engine::manifest::YamlGuardError;
use ferriscd_engine::manifest::parse_document;
use kube::ResourceExt as _;
use serde::Deserialize;

pub use adapters::{Delivery, MAX_REQUEST_BODY_BYTES};
pub use observer::{NotificationObserver, Notifier};
pub use ssrf::{
    BlockReason, Cidr, DestinationResolver, EgressConfigError, EgressPolicy, GuardedResolver,
    SsrfError, SystemResolution, ValidatedWebhookUrl, redact_notification_url,
};
pub use template::{MessageTemplate, NotificationContext, Template};
pub use worker::{
    ChannelError, ChannelSource, DeliveryOutcome, DeliveryRequest, DeliveryResponse,
    NotificationJob, NotificationTransport, NotificationWorker, NotificationWorkerHandle,
    RedirectPolicy, ReqwestTransport, SecretChannelSource, StaticChannelSource, TransportConfig,
    TransportError, load_root_certificates,
};

/// Name of the `ConfigMap` holding templates and trigger tuning, in the control-plane namespace.
pub const CONFIG_MAP_NAME: &str = "ferriscd-notifications-cm";

/// Key of the `ConfigMap` document (`templates` + `triggers`).
pub const CONFIG_MAP_KEY: &str = "notifications.yaml";

/// Label that opts a `Secret` in as a notification channel.
pub const SECRET_TYPE_LABEL: &str = "ferriscd.io/secret-type";

/// Label value selecting notification channel `Secret`s.
pub const SECRET_TYPE_NOTIFICATIONS: &str = "notifications";

/// Secret key holding the destination URL (`https://` only).
pub const KEY_URL: &str = "url";

/// Secret key holding the optional HMAC-SHA256 signing key (generic webhooks).
pub const KEY_SIGNING_KEY: &str = "signingKey";

/// Secret key holding the optional PagerDuty Events API v2 routing/integration key.
pub const KEY_ROUTING_KEY: &str = "routingKey";

/// Secret key holding an optional bearer token (Slack **Bot API**: `https://slack.com/api/chat.postMessage`).
pub const KEY_TOKEN: &str = "token";

/// Secret key naming the Slack channel for the Bot API (`chat.postMessage` requires it).
pub const KEY_CHANNEL: &str = "channel";

/// Secret key asserting the channel's service kind (`slack|teams|pagerduty|webhook`).
pub const KEY_SERVICE: &str = "service";

/// Bounded queue capacity between the observer and the delivery worker (`512`).
pub const DEFAULT_QUEUE_CAPACITY: usize = 512;

/// Per-request HTTP timeout (`5 s`).
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum delivery attempts, **including the first one** — i.e. one try plus two retries.
///
/// Finding **R1-N1**: the roadmap says "max 3 exponential-backoff retries", which read literally would
/// be four attempts. It is implemented as three *attempts* (`1 + 2 retries`, two backoff sleeps),
/// because what that budget is protecting is the worst case for a hung receiver: `3 × 5 s` timeout +
/// `0.5 s + 1 s` backoff ≈ `16.5 s` before an alert is given up on, and a fourth attempt would push
/// the same alert past 20 s for no diagnostic gain (`outcome="failed"` already reports it). The
/// interpretation is pinned by a test so it cannot drift silently.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 3;

/// Retries a delivery gets after its first attempt (`DEFAULT_MAX_ATTEMPTS - 1`).
pub const DEFAULT_MAX_RETRIES: u32 = DEFAULT_MAX_ATTEMPTS - 1;

/// Base of the exponential backoff between attempts (`500 ms`, then `1 s`).
pub const DEFAULT_RETRY_BASE_DELAY: Duration = Duration::from_millis(500);

/// Upper bound on the deduplication cache (`(app, trigger, generation, revision, health)` keys).
pub const DEFAULT_DEDUP_CAPACITY: usize = 4_096;

/// Notification burst a single `Application` may fire inside [`DEFAULT_RATE_WINDOW`].
pub const DEFAULT_RATE_BURST: u32 = 10;

/// Token-bucket window (`5 min`): `10 notifications / 5 min` per `Application`.
pub const DEFAULT_RATE_WINDOW: Duration = Duration::from_secs(300);

/// Default `on-out-of-sync` debounce (`60 s`).
pub const DEFAULT_OUT_OF_SYNC_DEBOUNCE: Duration = Duration::from_secs(60);

/// Upper bound on the `on-out-of-sync` debounce a `ConfigMap` may set (`1 h`).
pub const MAX_DEBOUNCE: Duration = Duration::from_secs(3_600);

/// Upper bound on tracked `Application`s in the observer's edge/rate tables.
pub const DEFAULT_MAX_TRACKED_APPS: usize = 4_096;

/// Upper bound on the `--notifications-allowed-namespaces` allowlist (finding **R1-M6**).
///
/// The allowlist bounds which tenants may page through this controller, so it is a small, explicit
/// operator list — never a cluster-wide enumeration.
pub const MAX_ALLOWED_NAMESPACES: usize = 256;

/// Upper bound on the `(application, annotation)` pairs whose refusal is remembered so it is logged
/// once rather than on every reconcile (finding **R1-M7**).
pub const MAX_REPORTED_MALFORMED: usize = 1_024;

/// A notification service FerrisCD can deliver to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NotificationService {
    /// Slack Incoming Webhook / Bot API (`{"text": ...}`).
    Slack,
    /// Microsoft Teams Workflow webhook (adaptive card).
    Teams,
    /// PagerDuty Events API v2 (`event_action: trigger`).
    PagerDuty,
    /// Generic webhook with optional HMAC-SHA256 `X-FerrisCD-Signature-256`.
    Webhook,
}

impl NotificationService {
    /// Every service, in documentation order.
    pub const ALL: [Self; 4] = [Self::Slack, Self::Teams, Self::PagerDuty, Self::Webhook];

    /// Stable label / annotation-segment / metric-label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Slack => "slack",
            Self::Teams => "teams",
            Self::PagerDuty => "pagerduty",
            Self::Webhook => "webhook",
        }
    }

    /// Parses an annotation segment or `Secret` `service` value (`pagerduty` also accepts
    /// `pager-duty`, the spelling people type).
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "slack" => Some(Self::Slack),
            "teams" | "msteams" | "microsoft-teams" => Some(Self::Teams),
            "pagerduty" | "pager-duty" | "pager_duty" => Some(Self::PagerDuty),
            "webhook" | "generic" | "generic-webhook" => Some(Self::Webhook),
            _ => None,
        }
    }
}

impl fmt::Display for NotificationService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One `(trigger, service, recipient)` subscription parsed from an annotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    /// The trigger name (`on-sync-failed`, ...).
    pub trigger: &'static str,
    /// The service the annotation named.
    pub service: NotificationService,
    /// The recipient: the name of a channel `Secret` in the control-plane namespace.
    pub recipient: String,
}

impl Subscription {
    /// The full annotation key this subscription came from.
    #[must_use]
    pub fn annotation_key(&self) -> String {
        format!(
            "{}{}.{}",
            annotations::NOTIFICATIONS_SUBSCRIBE_PREFIX,
            self.trigger,
            self.service.as_str()
        )
    }
}

/// One `notifications.ferriscd.io/*` annotation the parser refused.
///
/// Carried out of [`subscription_parse`] instead of being logged there, because the parser runs on
/// every reconcile pass: logging at the parse site would emit the same warning every 180 s forever
/// for a typo nobody fixes (finding **R1-M7**). [`Notifier`](observer::Notifier) is what decides how
/// often to say it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MalformedSubscription {
    /// The annotation key that was refused.
    pub key: String,
    /// Why it was refused (a closed set of strings, never the annotation's value).
    pub reason: &'static str,
}

/// Why a subscription annotation was refused (see [`MalformedSubscription::reason`]).
const MALFORMED_SHAPE: &str = "expected notifications.ferriscd.io/subscribe.<trigger>.<service>";
/// Why a subscription annotation was refused: unknown trigger.
const MALFORMED_TRIGGER: &str = "unknown trigger";
/// Why a subscription annotation was refused: unknown service.
const MALFORMED_SERVICE: &str = "unknown service";
/// Why a subscription annotation was refused: empty recipient.
const MALFORMED_RECIPIENT: &str = "empty recipient";

/// The result of parsing one `Application`'s subscription annotations.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubscriptionParse {
    /// The well-formed subscriptions, sorted (deterministic delivery order).
    pub subscriptions: Vec<Subscription>,
    /// The annotations that were refused, sorted by key.
    pub malformed: Vec<MalformedSubscription>,
}

/// Parses every `notifications.ferriscd.io/subscribe.<trigger>.<service>` annotation of `app`.
///
/// Malformed keys (unknown trigger, unknown service, no recipient) are **skipped**, never guessed
/// at: a typo must not silently deliver a production alert to a channel nobody intended. They are
/// reported through [`SubscriptionParse::malformed`] rather than logged here (finding **R1-M7**). Both
/// lists are sorted, so the delivery order (and the tests) are deterministic.
#[must_use]
pub fn subscription_parse(app: &Application) -> SubscriptionParse {
    let Some(annotations_map) = app.metadata.annotations.as_ref() else {
        return SubscriptionParse::default();
    };
    let mut parsed = Vec::new();
    let mut malformed = Vec::new();
    for (key, value) in annotations_map {
        let Some(rest) = key.strip_prefix(annotations::NOTIFICATIONS_SUBSCRIBE_PREFIX) else {
            continue;
        };
        let refuse = |reason: &'static str, malformed: &mut Vec<MalformedSubscription>| {
            malformed.push(MalformedSubscription {
                key: key.clone(),
                reason,
            });
        };
        let mut segments = rest.split('.');
        let (Some(trigger), Some(service), None) =
            (segments.next(), segments.next(), segments.next())
        else {
            refuse(MALFORMED_SHAPE, &mut malformed);
            continue;
        };
        let Some(trigger) = annotations::TRIGGER_NAMES
            .iter()
            .find(|candidate| **candidate == trigger)
        else {
            refuse(MALFORMED_TRIGGER, &mut malformed);
            continue;
        };
        let Some(service) = NotificationService::parse(service) else {
            refuse(MALFORMED_SERVICE, &mut malformed);
            continue;
        };
        let recipient = value.trim();
        if recipient.is_empty() {
            refuse(MALFORMED_RECIPIENT, &mut malformed);
            continue;
        }
        parsed.push(Subscription {
            trigger,
            service,
            recipient: recipient.to_owned(),
        });
    }
    malformed.sort_by(|left, right| left.key.cmp(&right.key));
    parsed.sort_by(|left, right| {
        (left.trigger, left.service.as_str(), left.recipient.as_str()).cmp(&(
            right.trigger,
            right.service.as_str(),
            right.recipient.as_str(),
        ))
    });
    SubscriptionParse {
        subscriptions: parsed,
        malformed,
    }
}

/// Parses every subscription annotation of `app`, dropping the ones that were refused.
///
/// See [`subscription_parse`] for the reported form (which is what the observer uses).
#[must_use]
pub fn subscriptions(app: &Application) -> Vec<Subscription> {
    subscription_parse(app).subscriptions
}

/// The redacted, in-memory form of one `ferriscd.io/secret-type=notifications` `Secret`.
///
/// `Debug` prints the recipient name and the service only: the URL (which carries the webhook
/// token for Slack/Teams) and the HMAC/routing keys stay out of every log line.
#[derive(Clone, PartialEq, Eq)]
pub struct NotificationChannel {
    /// The recipient key the annotation names (also the `Secret`'s name).
    pub name: String,
    /// The service this channel delivers to.
    pub service: NotificationService,
    url: String,
    signing_key: Option<SecretValue>,
    routing_key: Option<SecretValue>,
    token: Option<SecretValue>,
    sink: Option<String>,
}

/// Opaque credential bytes that never print themselves.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(Vec<u8>);

impl SecretValue {
    /// Wraps the credential bytes.
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// The credential bytes (only adapters call this, to sign a payload).
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl NotificationChannel {
    /// Builds a channel.
    ///
    /// # Errors
    ///
    /// [`ChannelError`] when the recipient name or URL is blank, or when a PagerDuty channel has no
    /// routing key (the Events API cannot be called without it).
    pub fn new(
        name: &str,
        service: NotificationService,
        url: &str,
        signing_key: Option<SecretValue>,
        routing_key: Option<SecretValue>,
    ) -> Result<Self, ChannelError> {
        Self::with_bearer(name, service, url, signing_key, routing_key, None, None)
    }

    /// Builds a channel, optionally with a bearer token (Slack Bot API) and a Slack channel name.
    ///
    /// # Errors
    ///
    /// As [`Self::new`], plus [`ChannelError::Invalid`] for a blank `channel` value.
    pub fn with_bearer(
        name: &str,
        service: NotificationService,
        url: &str,
        signing_key: Option<SecretValue>,
        routing_key: Option<SecretValue>,
        token: Option<SecretValue>,
        channel: Option<String>,
    ) -> Result<Self, ChannelError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(ChannelError::Invalid {
                message: "the notification channel has no name (it must be the Secret's name)"
                    .to_owned(),
            });
        }
        if url.trim().is_empty() {
            return Err(ChannelError::Invalid {
                message: format!("notification channel {name:?} has no destination url"),
            });
        }
        if service == NotificationService::PagerDuty && routing_key.is_none() {
            return Err(ChannelError::Invalid {
                message: format!(
                    "notification channel {name:?} is a PagerDuty channel without a routingKey"
                ),
            });
        }
        let sink = channel
            .map(|channel| channel.trim().to_owned())
            .filter(|channel| !channel.is_empty());
        Ok(Self {
            name: name.to_owned(),
            service,
            url: url.trim().to_owned(),
            signing_key,
            routing_key,
            token,
            sink,
        })
    }

    /// The destination URL (never logged; see [`Self::redacted_url`]).
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Credential-free destination, for logs and errors.
    ///
    /// Only `scheme://host[:port]` survives: a Slack/Teams webhook token lives in the URL's **path**,
    /// so [`redact_audit_url`](crate::audit::redact_audit_url) alone (which strips the query) would
    /// still print a replayable credential.
    #[must_use]
    pub fn redacted_url(&self) -> String {
        ssrf::redact_notification_url(&self.url)
    }

    /// The optional HMAC-SHA256 key (generic webhooks).
    #[must_use]
    pub fn signing_key(&self) -> Option<&SecretValue> {
        self.signing_key.as_ref()
    }

    /// The optional PagerDuty routing key.
    #[must_use]
    pub fn routing_key(&self) -> Option<&SecretValue> {
        self.routing_key.as_ref()
    }

    /// The optional bearer token (Slack Bot API `chat.postMessage`).
    #[must_use]
    pub fn token(&self) -> Option<&SecretValue> {
        self.token.as_ref()
    }

    /// The optional Slack channel the Bot API should post into.
    #[must_use]
    pub fn sink_channel(&self) -> Option<&str> {
        self.sink.as_deref()
    }
}

impl fmt::Debug for NotificationChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotificationChannel")
            .field("name", &self.name)
            .field("service", &self.service.as_str())
            .field("url", &self.redacted_url())
            .field(
                "signing_key",
                &self.signing_key.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "routing_key",
                &self.routing_key.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Templates and trigger tuning loaded from `ConfigMap/ferriscd-notifications-cm`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationConfig {
    templates: BTreeMap<&'static str, MessageTemplate>,
    debounce: BTreeMap<&'static str, Duration>,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        let templates = annotations::TRIGGER_NAMES
            .iter()
            .map(|trigger| (*trigger, MessageTemplate::default_for(trigger)))
            .collect();
        let debounce = BTreeMap::from([(
            annotations::TRIGGER_OUT_OF_SYNC,
            DEFAULT_OUT_OF_SYNC_DEBOUNCE,
        )]);
        Self {
            templates,
            debounce,
        }
    }
}

impl NotificationConfig {
    /// The built-in configuration (used when the `ConfigMap` is absent).
    #[must_use]
    pub fn built_in() -> Self {
        Self::default()
    }

    /// The template of `trigger`.
    ///
    /// `None` only when a caller asks for a trigger this build does not know; the delivery path
    /// falls back to [`MessageTemplate::default_for`] rather than sending a blank alert.
    #[must_use]
    pub fn template_for(&self, trigger: &'static str) -> Option<&MessageTemplate> {
        self.templates.get(trigger)
    }

    /// The debounce of `trigger` (only `on-out-of-sync` is debounced; the others are immediate).
    #[must_use]
    pub fn debounce_for(&self, trigger: &'static str) -> Duration {
        self.debounce.get(trigger).copied().unwrap_or_default()
    }

    /// Parses the `ConfigMap` document (`notifications.yaml`) under FerrisCD's guarded YAML parser.
    ///
    /// ```yaml
    /// templates:
    ///   on-sync-failed:
    ///     title: "Sync failed"
    ///     body: "{{app.namespace}}/{{app.name}}: {{app.message}}"
    /// triggers:
    ///   on-out-of-sync:
    ///     debounceSeconds: 120
    /// ```
    ///
    /// # Errors
    ///
    /// [`ConfigError`] for an unparseable document (including a YAML budget breach), an unknown
    /// trigger/service key, a blank template, a template referencing a field outside
    /// [`template::ALLOWED_FIELDS`], or a debounce above [`MAX_DEBOUNCE`]. A caller must fall back to
    /// [`Self::built_in`] — never to an empty template that would deliver a blank alert.
    pub fn parse(document: &str) -> Result<Self, ConfigError> {
        let parsed: ConfigDocument = parse_document(document).map_err(|err| match err {
            YamlGuardError::Budget { limit } => ConfigError::Malformed {
                reason: format!("exceeds the YAML parser budget ({limit})"),
            },
            YamlGuardError::Parse => ConfigError::Malformed {
                reason: "the document is not valid YAML for the notifications config".to_owned(),
            },
        })?;
        let mut config = Self::default();
        for (name, document) in parsed.templates.unwrap_or_default() {
            let trigger = known_trigger(&name)?;
            config.templates.insert(
                trigger,
                MessageTemplate::parse(&document.title, &document.body).map_err(|err| {
                    ConfigError::Template {
                        trigger: trigger.to_owned(),
                        reason: err.to_string(),
                    }
                })?,
            );
        }
        for (name, document) in parsed.triggers.unwrap_or_default() {
            let trigger = known_trigger(&name)?;
            if let Some(seconds) = document.debounce_seconds {
                let debounce = Duration::from_secs(seconds);
                if debounce > MAX_DEBOUNCE {
                    return Err(ConfigError::Debounce {
                        trigger: trigger.to_owned(),
                        max_seconds: MAX_DEBOUNCE.as_secs(),
                    });
                }
                config.debounce.insert(trigger, debounce);
            }
        }
        Ok(config)
    }
}

/// Resolves a `ConfigMap` key to one of the four known triggers.
fn known_trigger(name: &str) -> Result<&'static str, ConfigError> {
    annotations::TRIGGER_NAMES
        .iter()
        .find(|trigger| **trigger == name.trim())
        .copied()
        .ok_or_else(|| ConfigError::UnknownTrigger {
            trigger: name.to_owned(),
            allowed: &annotations::TRIGGER_NAMES,
        })
}

/// The YAML shape of `notifications.yaml` (never exposed).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ConfigDocument {
    #[serde(default)]
    templates: Option<BTreeMap<String, TemplateDocument>>,
    #[serde(default)]
    triggers: Option<BTreeMap<String, TriggerDocument>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TemplateDocument {
    title: String,
    body: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TriggerDocument {
    #[serde(default)]
    debounce_seconds: Option<u64>,
}

/// Errors raised while parsing `ConfigMap/ferriscd-notifications-cm`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    /// The document itself is unusable.
    #[error("the notifications config is unusable: {reason}")]
    Malformed {
        /// Why (never echoes document content).
        reason: String,
    },
    /// A key is not one of the four triggers.
    #[error("unknown notification trigger {trigger:?} (expected one of {allowed:?})")]
    UnknownTrigger {
        /// The rejected key.
        trigger: String,
        /// The closed set.
        allowed: &'static [&'static str; 4],
    },
    /// A template is unusable.
    #[error("notification template for {trigger} is unusable: {reason}")]
    Template {
        /// The trigger it belongs to.
        trigger: String,
        /// The parser's message.
        reason: String,
    },
    /// A debounce is longer than [`MAX_DEBOUNCE`].
    #[error("notification debounce for {trigger} exceeds {max_seconds}s")]
    Debounce {
        /// The trigger it belongs to.
        trigger: String,
        /// The documented ceiling.
        max_seconds: u64,
    },
}

/// Loads the notification config from `ConfigMap/ferriscd-notifications-cm`.
///
/// Best-effort by design: a missing `ConfigMap` (the common case) is not an error, and an unusable
/// one is logged and replaced by [`NotificationConfig::built_in`], because the templates only decide
/// message *text* — no delivery decision depends on them.
pub async fn load_config(client: kube::Client, namespace: &str) -> NotificationConfig {
    use k8s_openapi::api::core::v1::ConfigMap;
    use kube::api::Api;

    let config_maps: Api<ConfigMap> = Api::namespaced(client, namespace);
    let config_map = match config_maps.get_opt(CONFIG_MAP_NAME).await {
        Ok(Some(config_map)) => config_map,
        Ok(None) => {
            tracing::debug!(
                namespace = %namespace,
                config_map = CONFIG_MAP_NAME,
                "no notifications ConfigMap: using the built-in templates"
            );
            return NotificationConfig::built_in();
        }
        Err(err) => {
            tracing::warn!(
                namespace = %namespace,
                config_map = CONFIG_MAP_NAME,
                error = %err,
                "could not read the notifications ConfigMap: using the built-in templates"
            );
            return NotificationConfig::built_in();
        }
    };
    let Some(document) = config_map
        .data
        .as_ref()
        .and_then(|data| data.get(CONFIG_MAP_KEY))
    else {
        return NotificationConfig::built_in();
    };
    match NotificationConfig::parse(document) {
        Ok(config) => config,
        Err(err) => {
            tracing::warn!(
                namespace = %namespace,
                config_map = CONFIG_MAP_NAME,
                key = CONFIG_MAP_KEY,
                error = %err,
                "the notifications ConfigMap is unusable: using the built-in templates"
            );
            NotificationConfig::built_in()
        }
    }
}

/// The label selector every notification channel list uses.
#[must_use]
pub fn channel_label_selector() -> String {
    format!("{SECRET_TYPE_LABEL}={SECRET_TYPE_NOTIFICATIONS}")
}

/// Errors raised while parsing `--notifications-allowed-namespaces` (finding **R1-M6**).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TenantScopeError {
    /// The list has no entries, or one of them is blank.
    #[error(
        "--notifications-allowed-namespaces has an empty entry (expected a comma-separated list of \
         namespaces)"
    )]
    EmptyEntry,

    /// The list is longer than [`MAX_ALLOWED_NAMESPACES`].
    #[error(
        "--notifications-allowed-namespaces lists more than {max} namespaces; an allowlist this \
         large is not a tenancy boundary"
    )]
    TooMany {
        /// The documented ceiling.
        max: usize,
    },
}

/// Parses `--notifications-allowed-namespaces` into the bounded tenant allowlist.
///
/// `None` (or a blank value) means **no restriction**: any namespace may opt in through its
/// annotations, which is the pre-existing behaviour. Any other value is an explicit allowlist —
/// an `Application` in a namespace outside it never reaches the observer's gates, so a tenant can
/// neither page another tenant's channel nor spend the controller's delivery budget (finding
/// **M6**). An empty entry fails closed instead of silently widening the list.
///
/// # Errors
///
/// [`TenantScopeError`] for a blank entry or a list above [`MAX_ALLOWED_NAMESPACES`].
pub fn parse_allowed_namespaces(
    spec: Option<&str>,
) -> Result<Option<Vec<String>>, TenantScopeError> {
    let Some(spec) = spec.map(str::trim).filter(|spec| !spec.is_empty()) else {
        return Ok(None);
    };
    let mut namespaces = Vec::new();
    for entry in spec.split(',') {
        let namespace = entry.trim();
        if namespace.is_empty() {
            return Err(TenantScopeError::EmptyEntry);
        }
        if !namespaces.iter().any(|known| known == namespace) {
            namespaces.push(namespace.to_owned());
        }
    }
    if namespaces.is_empty() {
        return Err(TenantScopeError::EmptyEntry);
    }
    if namespaces.len() > MAX_ALLOWED_NAMESPACES {
        return Err(TenantScopeError::TooMany {
            max: MAX_ALLOWED_NAMESPACES,
        });
    }
    Ok(Some(namespaces))
}

/// The startup warning for a **default-open** tenant allowlist (finding **P19-M2**).
///
/// `--notifications-allowed-namespaces` unset means "any namespace may opt in", which is only a
/// tenancy boundary on paper: a tenant whose `Application` sits outside the control-plane namespace
/// can page any channel `Secret` in it. That is a deliberate, documented default (nobody's existing
/// `Application` stops alerting when the flag is introduced), but an operator who runs
/// Apps-in-any-namespace with notifications on has almost certainly not decided it — so the
/// combination is announced once at startup.
///
/// Returns `None` (nothing to warn about) when an explicit allowlist is set, or when the effective
/// `Application` scope is exactly the control-plane namespace, where every subscriber is already
/// trusted with the control plane's own `Secrets`. A pure predicate, so the wiring is assertable
/// without capturing logs.
#[must_use]
pub fn open_tenant_allowlist_warning(
    scope: &ferriscd_engine::policy::ApplicationScope,
    allowed_namespaces: Option<&[String]>,
) -> Option<OpenTenantAllowlist> {
    if allowed_namespaces.is_some() {
        return None;
    }
    if !scope.watches_more_than_the_control_plane() {
        return None;
    }
    Some(OpenTenantAllowlist {
        control_plane: scope.control_plane().to_owned(),
        application_scope: scope.describe(),
    })
}

/// The facts [`open_tenant_allowlist_warning`] reports, so the log line stays structured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenTenantAllowlist {
    /// The control-plane namespace (home of every channel `Secret`).
    pub control_plane: String,
    /// The configured `Application` scope (`*` for every namespace).
    pub application_scope: String,
}

/// Parses one labelled `Secret` into a [`NotificationChannel`].
///
/// # Errors
///
/// [`ChannelError`] when the `Secret` carries no `url`, a non-UTF-8 value, an unknown `service`, or
/// (for PagerDuty) no `routingKey`.
pub fn channel_from_secret(
    secret: &k8s_openapi::api::core::v1::Secret,
) -> Result<NotificationChannel, ChannelError> {
    let name = secret.name_any();
    let mut decoded = BTreeMap::new();
    for (key, value) in secret.string_data.as_ref().into_iter().flatten() {
        decoded.insert(key.clone(), value.clone());
    }
    for (key, k8s_openapi::ByteString(bytes)) in secret.data.as_ref().into_iter().flatten() {
        let value = String::from_utf8(bytes.clone()).map_err(|_| ChannelError::Invalid {
            message: format!("notification channel {name:?}: {key:?} is not valid UTF-8"),
        })?;
        decoded.insert(key.clone(), value);
    }
    let value = |key: &str| {
        decoded
            .get(key)
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
    };
    let Some(url) = value(KEY_URL) else {
        return Err(ChannelError::Invalid {
            message: format!("notification channel {name:?} has no {KEY_URL:?} key"),
        });
    };
    let service = match value(KEY_SERVICE) {
        Some(declared) => {
            NotificationService::parse(declared).ok_or_else(|| ChannelError::Invalid {
                message: format!(
                    "notification channel {name:?} declares an unknown service {declared:?} \
                     (expected slack, teams, pagerduty or webhook)"
                ),
            })?
        }
        None => {
            return Err(ChannelError::Invalid {
                message: format!(
                    "notification channel {name:?} must declare its {KEY_SERVICE:?} \
                     (slack, teams, pagerduty or webhook)"
                ),
            });
        }
    };
    NotificationChannel::with_bearer(
        &name,
        service,
        url,
        value(KEY_SIGNING_KEY).map(|key| SecretValue::new(key.as_bytes())),
        value(KEY_ROUTING_KEY).map(|key| SecretValue::new(key.as_bytes())),
        value(KEY_TOKEN).map(|token| SecretValue::new(token.as_bytes())),
        value(KEY_CHANNEL).map(str::to_owned),
    )
}

#[cfg(test)]
mod tests {
    use ferriscd_crd::application::{
        DEFAULT_REQUEUE_AFTER_SECONDS, DEFAULT_REVISION_HISTORY_LIMIT,
    };
    use ferriscd_crd::status::{HealthState, SyncState, SyncStatus};
    use ferriscd_crd::{ApplicationSpec, DestinationSpec, GitSourceSpec, RendererSpec, SourceSpec};
    use k8s_openapi::ByteString;
    use k8s_openapi::api::core::v1::Secret;

    use crate::predicate::composite_hash;

    use super::*;

    fn app() -> Application {
        let spec = ApplicationSpec {
            project: "default".to_owned(),
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
        let mut application = Application::new("demo-app", spec);
        application.metadata.namespace = Some("ferriscd-system".to_owned());
        application.metadata.generation = Some(1);
        application
    }

    fn annotate(app: &mut Application, key: &str, value: &str) {
        app.metadata
            .annotations
            .get_or_insert_with(BTreeMap::new)
            .insert(key.to_owned(), value.to_owned());
    }

    /// **Verification bullet (1):** adding, editing, or removing a subscription annotation leaves
    /// `composite_hash` unchanged, so subscribing to (or muting) an alert never costs a reconcile.
    #[test]
    fn subscription_annotations_never_change_the_watch_predicate() {
        let before = app();
        let mut after = before.clone();
        annotate(
            &mut after,
            "notifications.ferriscd.io/subscribe.on-sync-failed.slack",
            "payments-oncall",
        );
        annotate(
            &mut after,
            "notifications.ferriscd.io/subscribe.on-health-degraded.pagerduty",
            "payments-pd",
        );
        assert_eq!(
            composite_hash(&before.metadata),
            composite_hash(&after.metadata),
            "a notification subscription must not trigger a reconcile"
        );

        // Editing the recipient and then removing it stay invisible too.
        annotate(
            &mut after,
            "notifications.ferriscd.io/subscribe.on-sync-failed.slack",
            "other-channel",
        );
        assert_eq!(
            composite_hash(&before.metadata),
            composite_hash(&after.metadata)
        );
        after.metadata.annotations = None;
        assert_eq!(
            composite_hash(&before.metadata),
            composite_hash(&after.metadata)
        );
        // And calling it out explicitly: the keys are not control annotations.
        for key in annotations::CONTROL_ANNOTATIONS {
            assert!(!key.starts_with(annotations::NOTIFICATIONS_PREFIX));
        }
    }

    /// Only well-formed subscription annotations are honoured; a typo is skipped, not guessed.
    #[test]
    fn subscriptions_parse_strictly_and_deterministically() {
        let mut application = app();
        annotate(
            &mut application,
            "notifications.ferriscd.io/subscribe.on-sync-failed.slack",
            "payments-oncall",
        );
        annotate(
            &mut application,
            "notifications.ferriscd.io/subscribe.on-sync-succeeded.slack",
            "payments-oncall",
        );
        annotate(
            &mut application,
            "notifications.ferriscd.io/subscribe.on-health-degraded.pager-duty",
            "payments-pd",
        );
        annotate(
            &mut application,
            "notifications.ferriscd.io/subscribe.on-sync-failed.webhook",
            "  internal-automation  ",
        );
        // Malformed: unknown trigger, unknown service, missing service, extra segment, empty value.
        annotate(
            &mut application,
            "notifications.ferriscd.io/subscribe.on-everything.slack",
            "x",
        );
        annotate(
            &mut application,
            "notifications.ferriscd.io/subscribe.on-sync-failed.carrier-pigeon",
            "x",
        );
        annotate(
            &mut application,
            "notifications.ferriscd.io/subscribe.on-sync-failed",
            "x",
        );
        annotate(
            &mut application,
            "notifications.ferriscd.io/subscribe.on-sync-failed.slack.extra",
            "x",
        );
        annotate(
            &mut application,
            "notifications.ferriscd.io/subscribe.on-sync-failed.teams",
            "   ",
        );

        let parsed = subscriptions(&application);
        assert_eq!(
            parsed
                .iter()
                .map(|subscription| (
                    subscription.trigger,
                    subscription.service.as_str(),
                    subscription.recipient.as_str()
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    annotations::TRIGGER_HEALTH_DEGRADED,
                    "pagerduty",
                    "payments-pd"
                ),
                (annotations::TRIGGER_SYNC_FAILED, "slack", "payments-oncall"),
                (
                    annotations::TRIGGER_SYNC_FAILED,
                    "webhook",
                    "internal-automation"
                ),
                (
                    annotations::TRIGGER_SYNC_SUCCEEDED,
                    "slack",
                    "payments-oncall"
                ),
            ]
        );
        assert_eq!(
            parsed[0].annotation_key(),
            "notifications.ferriscd.io/subscribe.on-health-degraded.pagerduty"
        );

        // An `Application` with no annotations has no subscriptions (opt-in only).
        assert!(subscriptions(&app()).is_empty());
    }

    /// **Finding R1-M6:** `--notifications-allowed-namespaces` is the tenancy boundary, so its parser
    /// normalises (trim, order-preserving dedup), fails closed on a blank entry, and refuses a list
    /// too long to be a boundary rather than quietly truncating it. Unset means "no restriction",
    /// which is the pre-existing behaviour and must stay distinguishable from an empty allowlist.
    #[test]
    fn the_tenant_allowlist_is_normalised_bounded_and_fails_closed() {
        // Unset / blank is *no* allowlist (every namespace may opt in), never an empty one.
        assert_eq!(parse_allowed_namespaces(None), Ok(None));
        assert_eq!(parse_allowed_namespaces(Some("")), Ok(None));
        assert_eq!(parse_allowed_namespaces(Some("   ")), Ok(None));

        // Trimmed, deduplicated, first-seen order preserved (the operator's list is the log's list).
        assert_eq!(
            parse_allowed_namespaces(Some(" team-a , team-b ,team-a"))
                .expect("a well-formed allowlist"),
            Some(vec!["team-a".to_owned(), "team-b".to_owned()])
        );

        // Every blank-entry shape fails closed: silently dropping one would *widen* the allowlist.
        for malformed in ["team-a,", ",team-a", "team-a,,team-b", ","] {
            assert_eq!(
                parse_allowed_namespaces(Some(malformed)),
                Err(TenantScopeError::EmptyEntry),
                "{malformed:?} must be refused"
            );
        }

        // The cap is enforced, and exactly at the documented bound (off-by-one guard).
        let at_cap = (0..MAX_ALLOWED_NAMESPACES)
            .map(|index| format!("ns-{index}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            parse_allowed_namespaces(Some(&at_cap))
                .expect("the documented maximum is accepted")
                .map(|namespaces| namespaces.len()),
            Some(MAX_ALLOWED_NAMESPACES)
        );
        let over_cap = (0..=MAX_ALLOWED_NAMESPACES)
            .map(|index| format!("ns-{index}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            parse_allowed_namespaces(Some(&over_cap)),
            Err(TenantScopeError::TooMany {
                max: MAX_ALLOWED_NAMESPACES
            })
        );
        // Repeats must not consume the budget: 300 entries naming 2 namespaces is a 2-entry list.
        let repeated = vec!["team-a,team-b"; MAX_ALLOWED_NAMESPACES].join(",");
        assert_eq!(
            parse_allowed_namespaces(Some(&repeated))
                .expect("deduplication happens before the cap")
                .map(|namespaces| namespaces.len()),
            Some(2)
        );

        // The error text is operator-facing and names the flag, so a startup failure is actionable.
        let printed = TenantScopeError::EmptyEntry.to_string();
        assert!(
            printed.contains("--notifications-allowed-namespaces"),
            "{printed}"
        );
        assert!(!printed.contains("team-a"), "{printed}");
    }

    /// **Finding P19-M2:** a default-open tenant allowlist is only announced when it actually widens who
    /// may page — notifications on, no allowlist, and an `Application` scope beyond the control plane.
    #[test]
    fn the_open_tenant_allowlist_is_warned_about_only_when_it_widens_the_scope() {
        use ferriscd_engine::policy::{ApplicationNamespaces, ApplicationScope};

        let control_plane = ApplicationScope::default();
        let listed_tenant = ApplicationScope::new(
            ferriscd_crd::CONTROL_PLANE_NAMESPACE,
            ApplicationNamespaces::Listed(vec!["team-a".to_owned()]),
        );
        let every_namespace = ApplicationScope::new(
            ferriscd_crd::CONTROL_PLANE_NAMESPACE,
            ApplicationNamespaces::All,
        );
        // A list that repeats only the control-plane namespace resolves to the safe default set.
        let listed_same = ApplicationScope::new(
            ferriscd_crd::CONTROL_PLANE_NAMESPACE,
            ApplicationNamespaces::Listed(vec![ferriscd_crd::CONTROL_PLANE_NAMESPACE.to_owned()]),
        );
        let allowlist = vec!["team-a".to_owned()];

        // The warned combination.
        for scope in [&listed_tenant, &every_namespace] {
            let warning = open_tenant_allowlist_warning(scope, None)
                .expect("a default-open allowlist over a wider scope must be warned about");
            assert_eq!(warning.control_plane, ferriscd_crd::CONTROL_PLANE_NAMESPACE);
            assert_eq!(warning.application_scope, scope.describe());
        }
        assert_eq!(
            open_tenant_allowlist_warning(&every_namespace, None)
                .expect("warned")
                .application_scope,
            "*"
        );

        // Nothing to warn about: an explicit allowlist (the boundary is chosen), or a scope that is
        // exactly the control plane (every subscriber already lives there).
        assert_eq!(
            open_tenant_allowlist_warning(&every_namespace, Some(&allowlist)),
            None
        );
        assert_eq!(
            open_tenant_allowlist_warning(&listed_tenant, Some(&allowlist)),
            None
        );
        assert_eq!(open_tenant_allowlist_warning(&control_plane, None), None);
        assert_eq!(open_tenant_allowlist_warning(&listed_same, None), None);
    }

    /// The `ConfigMap` document is parsed under the guarded YAML parser and the strict key set.
    #[test]
    fn the_config_map_document_parses_templates_and_debounce() {
        let document = r#"
templates:
  on-sync-failed:
    title: "Sync failed: {{app.name}}"
    body: "{{app.namespace}}/{{app.name}} failed at {{app.revision}}: {{app.message}}"
triggers:
  on-out-of-sync:
    debounceSeconds: 120
"#;
        let config = NotificationConfig::parse(document).expect("a valid config document");
        let context = NotificationContext::from_status(
            &app(),
            &ferriscd_crd::ApplicationStatus {
                sync: Some(SyncState::new(
                    SyncStatus::OutOfSync,
                    Some("deadbeef".to_owned()),
                )),
                health: Some(HealthState::new(ferriscd_crd::HealthStatus::Degraded)),
                ..ferriscd_crd::ApplicationStatus::default()
            },
            annotations::TRIGGER_SYNC_FAILED,
            "slack",
            "payments-oncall",
        );
        let (title, body) = config
            .template_for(annotations::TRIGGER_SYNC_FAILED)
            .expect("the parsed template replaces the built-in one")
            .render(&context);
        assert_eq!(title, "Sync failed: demo-app");
        assert!(
            body.starts_with("ferriscd-system/demo-app failed at deadbeef"),
            "{body}"
        );
        assert_eq!(
            config.debounce_for(annotations::TRIGGER_OUT_OF_SYNC),
            Duration::from_secs(120)
        );
        // Untouched triggers keep their built-in template.
        assert_eq!(
            config.template_for(annotations::TRIGGER_SYNC_SUCCEEDED),
            NotificationConfig::built_in().template_for(annotations::TRIGGER_SYNC_SUCCEEDED)
        );
    }

    /// Every way the document can be wrong fails closed (the caller falls back to the built-ins)
    /// rather than delivering a blank or unintended alert.
    #[test]
    fn an_unusable_config_is_refused() {
        for (document, expected) in [
            (
                "templates:\n  on-nope:\n    title: t\n    body: b\n",
                "on-nope",
            ),
            (
                "triggers:\n  on-everything:\n    debounceSeconds: 5\n",
                "on-everything",
            ),
            (
                "templates:\n  on-sync-failed:\n    title: t\n",
                "not valid YAML",
            ),
            // A template that references a field outside the allow-list is refused at load time.
            (
                "templates:\n  on-sync-failed:\n    title: t\n    body: \"{{app.status.sync.status}}\"\n",
                "unknown notification template field",
            ),
            (
                "triggers:\n  on-out-of-sync:\n    debounceSeconds: 999999\n",
                "exceeds",
            ),
            ("templates: []\n", "not valid YAML"),
        ] {
            let err =
                NotificationConfig::parse(document).expect_err("the document must be refused");
            assert!(
                err.to_string().contains(expected),
                "expected {expected:?} in: {err}"
            );
        }

        // The YAML guard budgets apply: a billion-laughs document is a malformed config, not a hang.
        let bomb = "templates:\n  a: &a [x,x,x,x,x,x,x,x,x,x]\n  b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]\n  c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b,*b]\n  d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c,*c]\n  e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d,*d]\n  f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e,*e]\n  g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f,*f]\n  h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g,*g]\n";
        let err = NotificationConfig::parse(bomb).expect_err("an alias bomb must be refused");
        assert!(matches!(err, ConfigError::Malformed { .. }), "{err:?}");
    }

    /// **Trap guard:** a credential cannot live in the `ConfigMap` — the document has no field for a
    /// destination URL, a signing key or a routing key, and an unknown key makes the whole document
    /// unusable (so it falls back to the built-in templates instead of quietly reading a secret).
    #[test]
    fn a_credential_in_the_config_map_is_refused() {
        for document in [
            "url: https://hooks.slack.com/services/T/B/token\n",
            "templates:\n  on-sync-failed:\n    title: t\n    body: b\n    url: https://x.example/h\n",
            "triggers:\n  on-out-of-sync:\n    debounceSeconds: 10\n    signingKey: abc\n",
            "signingKey: abc\n",
        ] {
            let err = NotificationConfig::parse(document)
                .expect_err("a credential-shaped ConfigMap must be refused");
            assert!(
                matches!(err, ConfigError::Malformed { .. }),
                "{document:?} -> {err:?}"
            );
        }
    }

    /// **Verification bullet (5), redaction half:** the channel's `Debug` and its redacted URL never
    /// print the webhook token or either key.
    #[test]
    fn channel_secrets_never_reach_debug_output() {
        let channel = NotificationChannel::new(
            "payments-oncall",
            NotificationService::Webhook,
            "https://hooks.example.com/services/T000/B000/superSecretPathToken?token=abc123",
            Some(SecretValue::new(b"hmac-signing-key-material")),
            None,
        )
        .expect("a valid channel");
        let printed = format!("{channel:?}");
        assert!(
            !printed.contains("superSecretPathToken"),
            "the webhook token in the URL path must be redacted: {printed}"
        );
        assert!(!printed.contains("abc123"), "{printed}");
        assert!(!printed.contains("hmac-signing-key-material"), "{printed}");
        assert!(printed.contains("<redacted>"), "{printed}");
        assert!(printed.contains("hooks.example.com"), "{printed}");
        assert!(channel.redacted_url().contains("hooks.example.com"));
        assert!(!channel.redacted_url().contains("abc123"));
        assert_eq!(
            format!("{:?}", SecretValue::new(b"top-secret".to_vec())),
            "<redacted>"
        );
    }

    #[test]
    fn channel_construction_enforces_its_contract() {
        assert!(
            NotificationChannel::new(
                "pd",
                NotificationService::PagerDuty,
                "https://events.pagerduty.com/v2/enqueue",
                None,
                None
            )
            .is_err(),
            "a PagerDuty channel needs its routing key"
        );
        assert!(
            NotificationChannel::new("slack", NotificationService::Slack, "  ", None, None)
                .is_err()
        );
        assert!(
            NotificationChannel::new(
                " ",
                NotificationService::Slack,
                "https://x.example/h",
                None,
                None
            )
            .is_err()
        );
        assert_eq!(
            NotificationService::parse("Pager-Duty"),
            Some(NotificationService::PagerDuty)
        );
        assert_eq!(
            NotificationService::parse("msteams"),
            Some(NotificationService::Teams)
        );
        assert_eq!(NotificationService::parse("sms"), None);
        assert_eq!(NotificationService::Webhook.to_string(), "webhook");
    }

    /// Live `kind` verification for `T19.4` (requires a `kind-*` cluster; nothing is delivered).
    ///
    /// It proves the two Kubernetes-facing halves a hermetic test cannot: the `ConfigMap` document is
    /// read through the real API and parsed under the YAML budgets, and the channel `Secret` (labelled
    /// `ferriscd.io/secret-type=notifications`) resolves to a channel whose destination the SSRF
    /// guard admits **only** when the in-cluster CIDR is allowlisted.
    #[tokio::test]
    #[ignore = "requires a live kind cluster (asserts kind-* context)"]
    async fn live_kind_loads_the_notifications_config_map_and_channel_secret() {
        use k8s_openapi::api::core::v1::ConfigMap;
        use kube::api::{Api, DeleteParams, PostParams};

        // Safety invariant: never touch a non-kind cluster.
        let output = std::process::Command::new("kubectl")
            .args(["config", "current-context"])
            .output()
            .expect("kubectl must be installed");
        let context = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        assert!(
            context.starts_with("kind-"),
            "ABORT: refusing to run a live test against non-kind context {context:?}"
        );

        crate::impersonation::ensure_crypto_provider();
        let client = kube::Client::try_default()
            .await
            .expect("the kind kubeconfig must connect");
        let namespace = ferriscd_crd::CONTROL_PLANE_NAMESPACE;
        let config_maps: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
        let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);

        // The fixtures are applied by the live harness; create them when they are absent so the test
        // is self-contained on a freshly created cluster.
        let config_map = ConfigMap {
            metadata: kube::core::ObjectMeta {
                name: Some(CONFIG_MAP_NAME.to_owned()),
                namespace: Some(namespace.to_owned()),
                ..Default::default()
            },
            data: Some(BTreeMap::from([(
                CONFIG_MAP_KEY.to_owned(),
                "triggers:\n  on-out-of-sync:\n    debounceSeconds: 90\n".to_owned(),
            )])),
            ..ConfigMap::default()
        };
        config_maps
            .create(&PostParams::default(), &config_map)
            .await
            .expect("the notifications ConfigMap fixture must be creatable");

        let mut secret = Secret {
            metadata: kube::core::ObjectMeta {
                name: Some("t19-4-live-channel".to_owned()),
                namespace: Some(namespace.to_owned()),
                labels: Some(BTreeMap::from([(
                    SECRET_TYPE_LABEL.to_owned(),
                    SECRET_TYPE_NOTIFICATIONS.to_owned(),
                )])),
                ..Default::default()
            },
            ..Secret::default()
        };
        secret.data = Some(BTreeMap::from([
            (
                KEY_URL.to_owned(),
                k8s_openapi::ByteString(b"https://10.96.0.20/hook".to_vec()),
            ),
            (
                KEY_SERVICE.to_owned(),
                k8s_openapi::ByteString(b"webhook".to_vec()),
            ),
            (
                KEY_SIGNING_KEY.to_owned(),
                k8s_openapi::ByteString(b"live-signing-key".to_vec()),
            ),
        ]));
        secrets
            .create(&PostParams::default(), &secret)
            .await
            .expect("the notification channel Secret fixture must be creatable");

        // 1. The `ConfigMap` is read and parsed.
        let config = load_config(client.clone(), namespace).await;
        assert_eq!(
            config.debounce_for(annotations::TRIGGER_OUT_OF_SYNC),
            Duration::from_secs(90)
        );

        // 2. The labelled `Secret` resolves to a channel.
        let source = SecretChannelSource::new(client.clone(), namespace);
        let channel = source
            .resolve("t19-4-live-channel")
            .await
            .expect("the labelled channel Secret must resolve");
        assert_eq!(channel.service, NotificationService::Webhook);
        assert!(channel.signing_key().is_some());
        assert!(!format!("{channel:?}").contains("live-signing-key"));

        // 3. The in-cluster service CIDR is refused by default and admitted when allowlisted.
        assert!(
            ValidatedWebhookUrl::parse(channel.url(), &EgressPolicy::strict()).is_err(),
            "an in-cluster destination must be refused without an allowlist"
        );
        let allowlisted = EgressPolicy::from_allowlist_spec(Some("10.96.0.0/12"))
            .expect("the kind service CIDR is a valid allowlist");
        assert!(
            ValidatedWebhookUrl::parse(channel.url(), &allowlisted).is_ok(),
            "an operator allowlist admits the in-cluster receiver"
        );

        // Clean up so the test is repeatable.
        let _ = config_maps
            .delete(CONFIG_MAP_NAME, &DeleteParams::default())
            .await;
        let _ = secrets
            .delete("t19-4-live-channel", &DeleteParams::default())
            .await;
    }

    /// A channel `Secret` is the only place a destination URL may live, and it must declare its
    /// service explicitly (a Slack URL posted with a PagerDuty body is a silent outage).
    #[test]
    fn channel_secrets_parse_and_reject_incomplete_material() {
        let mut secret = Secret {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("payments-oncall".to_owned()),
                namespace: Some("ferriscd-system".to_owned()),
                ..Default::default()
            },
            ..Secret::default()
        };
        secret.data = Some(BTreeMap::from([
            (
                KEY_URL.to_owned(),
                ByteString(b"https://hooks.slack.com/services/T/B/xyz".to_vec()),
            ),
            (KEY_SERVICE.to_owned(), ByteString(b"slack".to_vec())),
            (KEY_SIGNING_KEY.to_owned(), ByteString(b"hmac-key".to_vec())),
        ]));
        let channel = channel_from_secret(&secret).expect("a valid channel Secret");
        assert_eq!(channel.name, "payments-oncall");
        assert_eq!(channel.service, NotificationService::Slack);
        assert_eq!(channel.url(), "https://hooks.slack.com/services/T/B/xyz");
        // The Bot API keys are read too (`token` travels in the Authorization header, `channel` in
        // the body), and `Debug` still redacts them.
        let mut bot = secret.clone();
        bot.data = Some(BTreeMap::from([
            (
                KEY_URL.to_owned(),
                ByteString(b"https://slack.com/api/chat.postMessage".to_vec()),
            ),
            (KEY_SERVICE.to_owned(), ByteString(b"slack".to_vec())),
            (KEY_TOKEN.to_owned(), ByteString(b"xoxb-token".to_vec())),
            (KEY_CHANNEL.to_owned(), ByteString(b"#alerts".to_vec())),
        ]));
        let bot = channel_from_secret(&bot).expect("a Bot API channel Secret");
        assert_eq!(
            bot.token().map(SecretValue::expose),
            Some(b"xoxb-token".as_slice())
        );
        assert_eq!(bot.sink_channel(), Some("#alerts"));
        assert!(!format!("{bot:?}").contains("xoxb-token"));
        assert!(channel.signing_key().is_some());
        assert!(channel.routing_key().is_none());
        assert!(channel.token().is_none());
        assert!(channel.sink_channel().is_none());

        for (mutated, expected) in [
            (
                BTreeMap::from([(KEY_SERVICE.to_owned(), ByteString(b"slack".to_vec()))]),
                "has no \"url\" key",
            ),
            (
                BTreeMap::from([(
                    KEY_URL.to_owned(),
                    ByteString(b"https://hooks.slack.com/x".to_vec()),
                )]),
                "must declare its \"service\"",
            ),
            (
                BTreeMap::from([
                    (
                        KEY_URL.to_owned(),
                        ByteString(b"https://hooks.slack.com/x".to_vec()),
                    ),
                    (KEY_SERVICE.to_owned(), ByteString(b"sms".to_vec())),
                ]),
                "unknown service",
            ),
            (
                BTreeMap::from([
                    (
                        KEY_URL.to_owned(),
                        ByteString(b"https://events.pagerduty.com/v2/enqueue".to_vec()),
                    ),
                    (KEY_SERVICE.to_owned(), ByteString(b"pagerduty".to_vec())),
                ]),
                "without a routingKey",
            ),
            (
                BTreeMap::from([
                    (KEY_URL.to_owned(), ByteString(vec![0xff, 0xfe])),
                    (KEY_SERVICE.to_owned(), ByteString(b"slack".to_vec())),
                ]),
                "not valid UTF-8",
            ),
        ] {
            secret.data = Some(mutated);
            let err = channel_from_secret(&secret).expect_err("the Secret must be refused");
            assert!(
                err.to_string().contains(expected),
                "expected {expected:?} in: {err}"
            );
        }
        assert_eq!(
            channel_label_selector(),
            "ferriscd.io/secret-type=notifications"
        );
    }
}
