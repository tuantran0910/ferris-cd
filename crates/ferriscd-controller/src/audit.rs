//! Immutable compliance audit trail & security telemetry (`T17.2`).
//!
//! Every security-relevant event across the API server and controller — manual syncs/rollbacks,
//! authentication/authorization denials, Git webhook deliveries, `ServiceAccount` impersonation
//! resolutions, and remote cluster registry lifecycle transitions — is serialized into one
//! versioned [`AuditEvent`] schema (`schemaVersion: "ferriscd.io/audit/v1"`).
//!
//! ## Delivery & non-blocking guarantees
//!
//! * **Stdout structured JSON (`TracingAuditSink`, enabled by default):** synchronous and lossless
//!   on the `ferriscd::audit` tracing target so Kubernetes log shippers (FluentBit, Vector, Loki)
//!   capture every event without blocking on external SIEM availability.
//! * **Optional external sinks (`JsonlFileAuditSink`, `WebhookAuditSink`):** strictly non-blocking
//!   via a bounded `tokio::sync::mpsc::channel` (`capacity = 1_024`) driven by `try_send`. A slow
//!   or unreachable SIEM endpoint can **never** stall production syncs, rollbacks, or
//!   reconciliation; drops increment `ferriscd_audit_dropped_total` and emit a throttled warning.
//!
//! ## Secret hygiene (Trap Guard)
//!
//! No raw `Secret.data`, bearer token, `Authorization` header, kubeconfig, webhook secret,
//! `X-Gitlab-Token`, query-string token, or unredacted repository URL may ever serialize into an
//! [`AuditEvent`]. All free-form strings are sanitized, length-bounded, and stripped of URL
//! userinfo, query parameters, fragments, and control characters before emission.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ferriscd_engine::manifest::redact_repo_url;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt as _;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use crate::metrics::Metrics;

/// Versioned schema identifier carried by every [`AuditEvent`].
pub const AUDIT_SCHEMA_VERSION: &str = "ferriscd.io/audit/v1";

/// Tracing target for lossless structured JSON audit emission (`ferriscd::audit`).
pub const AUDIT_TRACING_TARGET: &str = "ferriscd::audit";

/// Bounded channel capacity for non-blocking external audit sinks (`T17.2`).
pub const DEFAULT_AUDIT_CHANNEL_CAPACITY: usize = 1_024;

/// Maximum characters retained in [`AuditEvent::reason`].
pub const MAX_AUDIT_REASON_CHARS: usize = 256;

/// Maximum characters retained in bounded identity/target fields (`target.name`, `actor.username`).
const MAX_AUDIT_FIELD_CHARS: usize = 256;

/// Minimum interval between drop/delivery-warning log lines so a SIEM outage cannot flood stderr.
const WARN_THROTTLE_INTERVAL_SECS: i64 = 10;

/// Maximum events sent in a single HTTPS webhook batch POST.
const WEBHOOK_MAX_BATCH_SIZE: usize = 64;

/// Maximum time a partial webhook batch waits before flushing.
const WEBHOOK_FLUSH_INTERVAL: Duration = Duration::from_millis(500);

/// Per-request timeout for the async audit webhook sink.
const WEBHOOK_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Alibaba Cloud link-local-equivalent metadata IP (`100.100.100.200`).
const ALIBABA_IMDS_V4: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 200);

/// AWS EC2 IPv6 Instance Metadata Service (`fd00:ec2::254`).
const AWS_IMDS_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);

/// All five low-cardinality audit categories (`T17.2`).
pub const AUDIT_CATEGORIES: [&str; 5] = [
    AuditCategory::ApiOperation.as_str(),
    AuditCategory::ApiAuthzDenied.as_str(),
    AuditCategory::WebhookDelivery.as_str(),
    AuditCategory::ControllerImpersonation.as_str(),
    AuditCategory::ClusterRegistry.as_str(),
];

/// All four low-cardinality audit outcomes (`T17.2`).
pub const AUDIT_OUTCOMES: [&str; 4] = [
    AuditOutcome::Allowed.as_str(),
    AuditOutcome::Denied.as_str(),
    AuditOutcome::Accepted.as_str(),
    AuditOutcome::Failed.as_str(),
];

/// Fixed, low-cardinality classification of an [`AuditEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuditCategory {
    /// Manual API mutation (`POST .../sync`, `POST .../rollback`).
    #[serde(rename = "api.operation")]
    ApiOperation,
    /// Rejected authentication (`401`) or RBAC authorization (`403` / hidden `404`).
    #[serde(rename = "api.authz_denied")]
    ApiAuthzDenied,
    /// GitHub or GitLab webhook delivery (matched, ignored, duplicate, or rejected).
    #[serde(rename = "webhook.delivery")]
    WebhookDelivery,
    /// Controller `ServiceAccount` impersonation resolution.
    #[serde(rename = "controller.impersonation")]
    ControllerImpersonation,
    /// Remote cluster registry lifecycle transition (`Added`, `Rebuilt`, `Removed`, or rejected).
    #[serde(rename = "cluster.registry")]
    ClusterRegistry,
}

impl AuditCategory {
    /// Stable wire and Prometheus label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApiOperation => "api.operation",
            Self::ApiAuthzDenied => "api.authz_denied",
            Self::WebhookDelivery => "webhook.delivery",
            Self::ControllerImpersonation => "controller.impersonation",
            Self::ClusterRegistry => "cluster.registry",
        }
    }
}

impl fmt::Display for AuditCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Fixed, low-cardinality outcome of an [`AuditEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditOutcome {
    /// Policy or impersonation check permitted the action.
    Allowed,
    /// Authentication, authorization, or signature verification denied the action.
    Denied,
    /// Operation, webhook delivery, or registry mutation was accepted.
    Accepted,
    /// Operation, delivery, or cluster registration failed.
    Failed,
}

impl AuditOutcome {
    /// Stable wire and Prometheus label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Accepted => "accepted",
            Self::Failed => "failed",
        }
    }
}

impl fmt::Display for AuditOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Who initiated or was resolved for an audited action.
///
/// Never carries raw bearer tokens, credentials, or secrets: `token_fingerprint` holds at most the
/// 12-hex-char one-way SHA-256 prefix.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditActor {
    /// Authenticated Kubernetes username (or impersonated ServiceAccount principal).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Authenticated or impersonated Kubernetes groups.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    /// First 12 lowercase hex characters of `SHA-256(bearer_token)`, never the raw token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_fingerprint: Option<String>,
}

impl AuditActor {
    /// System/controller-initiated actor (e.g. cluster registry watcher).
    #[must_use]
    pub fn system(component: impl Into<String>) -> Self {
        Self {
            username: Some(component.into()),
            groups: Vec::new(),
            token_fingerprint: None,
        }
    }

    /// Actor identified only by a one-way 12-hex token fingerprint (e.g. rejected `401`).
    #[must_use]
    pub fn token_fingerprint_only(fingerprint: impl Into<String>) -> Self {
        Self {
            username: None,
            groups: Vec::new(),
            token_fingerprint: sanitize_token_fingerprint(Some(fingerprint.into())),
        }
    }
}

/// Resource scope affected by an audited action.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditTarget {
    /// Kubernetes namespace of the targeted resource or `Application`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Kubernetes name of the targeted resource or `Application`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `AppProject` name governing the targeted `Application`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// Target cluster name (`in-cluster` or registered cluster name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
}

/// One versioned compliance audit record (`schemaVersion: "ferriscd.io/audit/v1"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    /// Schema identifier (`"ferriscd.io/audit/v1"`).
    pub schema_version: String,
    /// RFC 3339 UTC timestamp when the event was recorded.
    pub timestamp: String,
    /// RFC 4122 UUIDv4 unique event identifier.
    pub event_id: String,
    /// Correlated HTTP `X-Request-Id`, when the event originated from an HTTP request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Low-cardinality event category.
    pub category: AuditCategory,
    /// Subject performing or targeted by the security action.
    pub actor: AuditActor,
    /// Affected Kubernetes/GitOps resource scope.
    pub target: AuditTarget,
    /// Specific verb or event action (`sync`, `rollback`, `authenticate`, `impersonate`, etc.).
    pub action: String,
    /// Low-cardinality outcome (`allowed`, `denied`, `accepted`, `failed`).
    pub outcome: AuditOutcome,
    /// Bounded, secret-free human-readable explanation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl AuditEvent {
    /// Constructs a new [`AuditEvent`] stamped with the current UTC RFC 3339 timestamp and a fresh
    /// UUIDv4 `event_id`.
    #[must_use]
    pub fn new(
        category: AuditCategory,
        actor: AuditActor,
        target: AuditTarget,
        action: impl Into<String>,
        outcome: AuditOutcome,
    ) -> Self {
        let mut event = Self {
            schema_version: AUDIT_SCHEMA_VERSION.to_owned(),
            timestamp: current_rfc3339_utc(),
            event_id: generate_uuid_v4(),
            request_id: None,
            category,
            actor,
            target,
            action: action.into(),
            outcome,
            reason: None,
        };
        event.sanitize();
        event
    }

    /// Attaches a correlated HTTP `X-Request-Id`.
    #[must_use]
    pub fn with_request_id(mut self, request_id: Option<String>) -> Self {
        self.request_id = request_id.and_then(|id| sanitize_header_id(&id));
        self
    }

    /// Attaches a bounded, redacted reason string.
    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        let sanitized = sanitize_audit_reason(&reason.into());
        self.reason = (!sanitized.is_empty()).then_some(sanitized);
        self
    }

    /// Sanitizes every mutable field defensively before serialization.
    fn sanitize(&mut self) {
        self.schema_version = AUDIT_SCHEMA_VERSION.to_owned();
        self.action = sanitize_bounded_field(&self.action).unwrap_or_else(|| "unknown".to_owned());
        self.actor.username = self
            .actor
            .username
            .as_deref()
            .and_then(sanitize_bounded_field);
        self.actor.groups = self
            .actor
            .groups
            .iter()
            .filter_map(|group| sanitize_bounded_field(group))
            .collect();
        self.actor.token_fingerprint =
            sanitize_token_fingerprint(self.actor.token_fingerprint.take());
        self.target.namespace = self
            .target
            .namespace
            .as_deref()
            .and_then(sanitize_bounded_field);
        self.target.name = self.target.name.as_deref().and_then(sanitize_bounded_field);
        self.target.project = self
            .target
            .project
            .as_deref()
            .and_then(sanitize_bounded_field);
        self.target.cluster = self
            .target
            .cluster
            .as_deref()
            .and_then(sanitize_bounded_field);
        self.request_id = self.request_id.as_deref().and_then(sanitize_header_id);
        self.reason = self
            .reason
            .as_deref()
            .map(sanitize_audit_reason)
            .filter(|reason| !reason.is_empty());
    }
}

/// Result of attempting to enqueue/emit one [`AuditEvent`] to an [`AuditSink`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEmitResult {
    /// The event was written synchronously or accepted into the sink's bounded buffer.
    Delivered,
    /// The sink's bounded channel was full or closed; the event was dropped without blocking.
    Dropped,
}

/// Pluggable compliance audit destination (`T17.2`).
///
/// Implementations **must not block** the caller's Tokio task on disk or network I/O when used as
/// an external sink (use a bounded `try_send` queue).
pub trait AuditSink: Send + Sync + 'static {
    /// Human-readable sink identifier for drop diagnostics.
    fn name(&self) -> &'static str;

    /// Emits one sanitized [`AuditEvent`].
    fn emit(&self, event: &AuditEvent) -> AuditEmitResult;
}

/// Synchronous, lossless structured JSON sink writing to tracing target `ferriscd::audit`.
#[derive(Debug, Clone, Copy, Default)]
pub struct TracingAuditSink;

impl AuditSink for TracingAuditSink {
    fn name(&self) -> &'static str {
        "tracing"
    }

    fn emit(&self, event: &AuditEvent) -> AuditEmitResult {
        match serde_json::to_string(event) {
            Ok(payload) => {
                tracing::info!(
                    target: AUDIT_TRACING_TARGET,
                    schema_version = %event.schema_version,
                    event_id = %event.event_id,
                    request_id = event.request_id.as_deref().unwrap_or(""),
                    category = event.category.as_str(),
                    action = %event.action,
                    outcome = event.outcome.as_str(),
                    audit_json = %payload,
                    "audit event"
                );
                AuditEmitResult::Delivered
            }
            Err(_) => AuditEmitResult::Dropped,
        }
    }
}

/// Errors building optional external audit sinks.
#[derive(Debug, thiserror::Error)]
pub enum AuditSinkError {
    /// The JSONL audit file could not be opened or created for append.
    #[error("cannot open audit log file {path:?}: {source}")]
    OpenFile {
        /// File path that failed to open.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// The webhook URL failed HTTPS-only or SSRF validation.
    #[error("invalid audit webhook URL {url:?}: {reason}")]
    InvalidWebhookUrl {
        /// Redacted URL (userinfo, query string, and fragment stripped).
        url: String,
        /// Why it was refused.
        reason: String,
    },

    /// The underlying HTTPS client for the webhook sink could not be built.
    #[error("cannot initialize HTTPS client for audit webhook sink: {message}")]
    HttpClient {
        /// Bounded, secret-free error description.
        message: String,
    },
}

/// Non-blocking append-only JSONL file audit sink (`--audit-log-path`).
///
/// Enqueues serialized JSON lines onto a bounded `mpsc` channel (`capacity = 1_024`) via
/// `try_send`. A background Tokio task flushes lines sequentially to disk so API handlers and
/// reconciles never block on filesystem latency. Disk write failures increment
/// `ferriscd_audit_dropped_total`.
pub struct JsonlFileAuditSink {
    tx: Mutex<Option<mpsc::Sender<String>>>,
    capacity: usize,
    worker: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl fmt::Debug for JsonlFileAuditSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsonlFileAuditSink")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl JsonlFileAuditSink {
    /// Opens `path` in append mode (creating it if absent) and spawns its background writer task.
    ///
    /// # Errors
    ///
    /// [`AuditSinkError::OpenFile`] if `path` cannot be opened for append.
    pub async fn open(
        path: PathBuf,
        capacity: usize,
        metrics: Metrics,
    ) -> Result<Self, AuditSinkError> {
        let mut options = tokio::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            // Audit records carry usernames, groups and cluster names: never inherit the umask.
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .await
            .map_err(|source| AuditSinkError::OpenFile {
                path: path.clone(),
                source,
            })?;
        let bounded_capacity = capacity.max(1);
        let (tx, mut rx) = mpsc::channel::<String>(bounded_capacity);
        let worker = tokio::spawn(async move {
            while let Some(mut line) = rx.recv().await {
                line.push('\n');
                if let Err(error) = file.write_all(line.as_bytes()).await {
                    metrics.record_audit_dropped();
                    tracing::warn!(
                        path = %path.display(),
                        error = %error,
                        "failed to write audit JSONL record"
                    );
                    continue;
                }
                if let Err(error) = file.flush().await {
                    metrics.record_audit_dropped();
                    tracing::warn!(
                        path = %path.display(),
                        error = %error,
                        "failed to flush audit JSONL file"
                    );
                }
            }
        });
        Ok(Self {
            tx: Mutex::new(Some(tx)),
            capacity: bounded_capacity,
            worker: Mutex::new(Some(worker)),
        })
    }

    /// Closes the channel sender and waits for the background writer task to drain all queued
    /// records cleanly (no deadlock).
    pub async fn wait_drained(&self) {
        // Explicitly drop the sender BEFORE awaiting the worker so `rx.recv().await` sees EOF.
        drop(
            self.tx
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(),
        );
        let handle = self
            .worker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(handle) = handle {
            let _ = handle.await;
        }
    }
}

impl AuditSink for JsonlFileAuditSink {
    fn name(&self) -> &'static str {
        "jsonl-file"
    }

    fn emit(&self, event: &AuditEvent) -> AuditEmitResult {
        let Ok(line) = serde_json::to_string(event) else {
            return AuditEmitResult::Dropped;
        };
        let guard = self.tx.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(tx) = guard.as_ref() else {
            return AuditEmitResult::Dropped;
        };
        match tx.try_send(line) {
            Ok(()) => AuditEmitResult::Delivered,
            Err(TrySendError::Full(_) | TrySendError::Closed(_)) => AuditEmitResult::Dropped,
        }
    }
}

/// Redacts a URL for audit logs and `Debug`: strips embedded credentials (`user:pass@`), query
/// parameters (`?token=...`), and fragments (`#...`) while preserving `scheme://host[:port]/path`.
#[must_use]
pub fn redact_audit_url(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Ok(mut parsed) = reqwest::Url::parse(trimmed) {
        let _ = parsed.set_username("");
        let _ = parsed.set_password(None);
        parsed.set_query(None);
        parsed.set_fragment(None);
        return parsed.to_string();
    }
    // Fallback for non-standard or SCP-like URLs: strip query/fragment first, then userinfo.
    let without_query = trimmed.split(['?', '#']).next().unwrap_or(trimmed);
    redact_repo_url(without_query)
}

/// Validated, SSRF-checked HTTPS destination for [`WebhookAuditSink`].
///
/// Manual `Debug` prints only the query-stripped, credential-free [`Self::redacted`] URL.
#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedAuditWebhookUrl {
    raw: String,
    redacted: String,
    host: String,
    port: u16,
}

impl fmt::Debug for ValidatedAuditWebhookUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedAuditWebhookUrl")
            .field("url", &self.redacted)
            .field("host", &self.host)
            .field("port", &self.port)
            .finish()
    }
}

impl ValidatedAuditWebhookUrl {
    /// Parses and validates an audit webhook URL against HTTPS-only and SSRF rules.
    ///
    /// # Rules
    ///
    /// * Scheme **must** be `https://` (plaintext `http://` and all other schemes are refused).
    /// * Embedded credentials (`user:pass@host`) are refused so webhook secrets never travel in
    ///   CLI flags or URL strings.
    /// * Loopback (`localhost`, `127.0.0.0/8`, `::1`), unspecified (`0.0.0.0`, `::`), link-local /
    ///   cloud metadata IMDS (`169.254.0.0/16`, `100.100.100.200`, `fd00:ec2::254`, `fe80::/10`),
    ///   multicast, IPv4-mapped IPv6 (`::ffff:0:0/96`), IPv4-compatible IPv6 (`::a.b.c.d`), and
    ///   NAT64 (`64:ff9b::/96`) equivalents are unconditionally refused.
    ///
    /// # Errors
    ///
    /// [`AuditSinkError::InvalidWebhookUrl`] when any rule is violated.
    pub fn parse(raw: &str) -> Result<Self, AuditSinkError> {
        let trimmed = raw.trim();
        let redacted = redact_audit_url(trimmed);
        let parsed =
            reqwest::Url::parse(trimmed).map_err(|_| AuditSinkError::InvalidWebhookUrl {
                url: redacted.clone(),
                reason: "not a valid absolute URL".to_owned(),
            })?;
        if parsed.scheme() != "https" {
            return Err(AuditSinkError::InvalidWebhookUrl {
                url: redacted,
                reason: "audit webhook URL must use https://".to_owned(),
            });
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(AuditSinkError::InvalidWebhookUrl {
                url: redacted,
                reason: "audit webhook URL must not embed credentials in userinfo".to_owned(),
            });
        }
        let Some(host_str) = parsed.host_str() else {
            return Err(AuditSinkError::InvalidWebhookUrl {
                url: redacted,
                reason: "audit webhook URL has no host".to_owned(),
            });
        };
        let host_lower = host_str.trim_end_matches('.').to_ascii_lowercase();
        if host_lower.is_empty()
            || host_lower == "localhost"
            || host_lower.ends_with(".localhost")
            || host_lower == "metadata.google.internal"
            || host_lower == "metadata"
        {
            return Err(AuditSinkError::InvalidWebhookUrl {
                url: redacted,
                reason: "audit webhook host is blocked by SSRF policy (loopback/metadata)"
                    .to_owned(),
            });
        }
        let unbracketed = host_str
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(host_str);
        if let Ok(ip) = unbracketed.parse::<IpAddr>()
            && is_blocked_ssrf_ip(ip)
        {
            return Err(AuditSinkError::InvalidWebhookUrl {
                url: redacted,
                reason: "audit webhook IP is blocked by SSRF policy (loopback/link-local/metadata)"
                    .to_owned(),
            });
        }
        let port = parsed.port_or_known_default().unwrap_or(443);
        Ok(Self {
            raw: parsed.to_string(),
            redacted,
            host: unbracketed.to_owned(),
            port,
        })
    }

    /// Redacted URL (no userinfo, query string, or fragment) safe for logs and `Debug`.
    #[must_use]
    pub fn redacted(&self) -> &str {
        &self.redacted
    }

    /// Validated host (unbracketed for IPv6).
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Target TCP port (defaults to `443`).
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Returns `true` if `ip` must be blocked by the audit webhook SSRF guard.
#[must_use]
pub fn is_blocked_ssrf_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_ssrf_v4(v4),
        IpAddr::V6(v6) => is_blocked_ssrf_v6(v6),
    }
}

fn is_blocked_ssrf_v4(v4: Ipv4Addr) -> bool {
    let octets = v4.octets();
    v4.is_loopback()
        || v4.is_link_local() // 169.254.0.0/16 (AWS/GCP/Azure IMDS 169.254.169.254)
        || v4 == ALIBABA_IMDS_V4 // 100.100.100.200 (Alibaba Cloud IMDS)
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
        || octets[0] == 0 // 0.0.0.0/8 "this network"
}

fn is_blocked_ssrf_v6(v6: Ipv6Addr) -> bool {
    if let Some(mapped) = v6.to_ipv4_mapped() {
        return is_blocked_ssrf_v4(mapped);
    }
    // Deprecated IPv4-compatible IPv6 (`::a.b.c.d`, e.g. `::169.254.169.254`).
    if let Some(compat) = v6.to_ipv4()
        && !v6.is_loopback()
        && !v6.is_unspecified()
    {
        return is_blocked_ssrf_v4(compat);
    }
    let segments = v6.segments();
    // NAT64 well-known prefix `64:ff9b::/96` (RFC 6052) embedding an IPv4 address in the low 32 bits.
    if segments[0] == 0x0064
        && segments[1] == 0xff9b
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0
    {
        let embedded = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            (segments[6] & 0xff) as u8,
            (segments[7] >> 8) as u8,
            (segments[7] & 0xff) as u8,
        );
        return is_blocked_ssrf_v4(embedded);
    }
    let is_unicast_link_local = (segments[0] & 0xffc0) == 0xfe80;
    v6 == AWS_IMDS_V6
        || v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        || is_unicast_link_local
}

/// Custom `reqwest` DNS resolver enforcing [`is_blocked_ssrf_ip`] on every resolution so one
/// pooled HTTPS client stays immune to DNS rebinding without rebuilding TLS connectors per batch.
struct SsrfGuardedDnsResolver;

impl reqwest::dns::Resolve for SsrfGuardedDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addrs = resolve_safe_socket_addrs(&host, 0).await.map_err(
                |reason| -> Box<dyn std::error::Error + Send + Sync> {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        reason,
                    ))
                },
            )?;
            let iter: reqwest::dns::Addrs = Box::new(addrs.into_iter());
            Ok(iter)
        })
    }
}

/// Non-blocking, async batched HTTPS webhook audit sink (`--audit-webhook-url`).
///
/// * Enforces HTTPS-only (`.https_only(true)`), `.no_proxy()`, no redirects, and both static and
///   DNS-time SSRF guards on **one** pooled `reqwest::Client`.
/// * Enqueues events via bounded `try_send` (`capacity = 1_024`) so a slow or down SIEM can never
///   stall API or controller operations.
pub struct WebhookAuditSink {
    url: ValidatedAuditWebhookUrl,
    capacity: usize,
    tx: Mutex<Option<mpsc::Sender<AuditEvent>>>,
    worker: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl fmt::Debug for WebhookAuditSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookAuditSink")
            .field("url", &self.url.redacted())
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl WebhookAuditSink {
    /// Validates `url`, builds one pooled SSRF-guarded HTTPS client, and spawns the background
    /// async batching worker.
    ///
    /// # Errors
    ///
    /// [`AuditSinkError::InvalidWebhookUrl`] when `url` fails HTTPS/SSRF validation, or
    /// [`AuditSinkError::HttpClient`] when the TLS HTTP client cannot be initialized.
    pub fn spawn(url: &str, capacity: usize, metrics: Metrics) -> Result<Self, AuditSinkError> {
        let validated = ValidatedAuditWebhookUrl::parse(url)?;
        // Pin process-level rustls CryptoProvider before constructing reqwest TLS client.
        crate::impersonation::ensure_crypto_provider();
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .timeout(WEBHOOK_REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .dns_resolver(Arc::new(SsrfGuardedDnsResolver))
            .build()
            .map_err(|err| AuditSinkError::HttpClient {
                message: err.without_url().to_string(),
            })?;
        let bounded_capacity = capacity.max(1);
        let (tx, mut rx) = mpsc::channel::<AuditEvent>(bounded_capacity);
        let target = validated.clone();
        let worker = tokio::spawn(async move {
            let mut batch: Vec<AuditEvent> = Vec::with_capacity(WEBHOOK_MAX_BATCH_SIZE);
            let mut interval = tokio::time::interval(WEBHOOK_FLUSH_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let warn_throttle = WarnThrottle::new();
            loop {
                tokio::select! {
                    maybe_event = rx.recv() => {
                        match maybe_event {
                            Some(event) => {
                                batch.push(event);
                                if batch.len() >= WEBHOOK_MAX_BATCH_SIZE {
                                    flush_webhook_batch(&client, &target, &mut batch, &metrics, &warn_throttle).await;
                                }
                            }
                            None => {
                                if !batch.is_empty() {
                                    flush_webhook_batch(&client, &target, &mut batch, &metrics, &warn_throttle).await;
                                }
                                break;
                            }
                        }
                    }
                    _ = interval.tick() => {
                        if !batch.is_empty() {
                            flush_webhook_batch(&client, &target, &mut batch, &metrics, &warn_throttle).await;
                        }
                    }
                }
            }
        });
        Ok(Self {
            url: validated,
            capacity: bounded_capacity,
            tx: Mutex::new(Some(tx)),
            worker: Mutex::new(Some(worker)),
        })
    }

    /// Closes the queue and waits for the batching worker to flush its pending batch.
    pub async fn wait_drained(&self) {
        drop(
            self.tx
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(),
        );
        let handle = self
            .worker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(handle) = handle {
            let _ = handle.await;
        }
    }

    /// The redacted URL this sink delivers batches to.
    #[must_use]
    pub fn redacted_url(&self) -> &str {
        self.url.redacted()
    }
}

impl AuditSink for WebhookAuditSink {
    fn name(&self) -> &'static str {
        "webhook"
    }

    fn emit(&self, event: &AuditEvent) -> AuditEmitResult {
        let tx = self
            .tx
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .cloned();
        match tx {
            Some(tx) => match tx.try_send(event.clone()) {
                Ok(()) => AuditEmitResult::Delivered,
                Err(TrySendError::Full(_) | TrySendError::Closed(_)) => AuditEmitResult::Dropped,
            },
            None => AuditEmitResult::Dropped,
        }
    }
}

/// Posts a batch using the pooled SSRF-guarded HTTPS client, throttling failure logs and never
/// logging URL query parameters (`error.without_url()`).
async fn flush_webhook_batch(
    client: &reqwest::Client,
    target: &ValidatedAuditWebhookUrl,
    batch: &mut Vec<AuditEvent>,
    metrics: &Metrics,
    warn_throttle: &WarnThrottle,
) {
    let events = std::mem::take(batch);
    let count = events.len() as u64;
    let payload = serde_json::json!({
        "schemaVersion": AUDIT_SCHEMA_VERSION,
        "events": events,
    });
    match client.post(&target.raw).json(&payload).send().await {
        Ok(response) if response.status().is_success() => {}
        Ok(response) => {
            metrics.record_audit_dropped_by(count);
            if let Some(suppressed) = warn_throttle.should_warn() {
                tracing::warn!(
                    url = %target.redacted(),
                    status = response.status().as_u16(),
                    dropped = count,
                    suppressed_since_last_warning = suppressed,
                    "audit webhook endpoint rejected batch"
                );
            }
        }
        Err(error) => {
            metrics.record_audit_dropped_by(count);
            if let Some(suppressed) = warn_throttle.should_warn() {
                tracing::warn!(
                    url = %target.redacted(),
                    dropped = count,
                    suppressed_since_last_warning = suppressed,
                    error = %error.without_url(),
                    "audit webhook delivery failed"
                );
            }
        }
    }
}

/// Resolves `host:port` and refuses the lookup if **any** returned IP violates [`is_blocked_ssrf_ip`].
///
/// # Errors
///
/// Returns a secret-free reason string if DNS fails, yields no addresses, or resolves to any
/// blocked loopback, link-local, IMDS, or unspecified IP.
pub async fn resolve_safe_socket_addrs(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_blocked_ssrf_ip(ip) {
            return Err("literal IP is blocked by SSRF policy".to_owned());
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|err| format!("DNS resolution failed: {err}"))?
        .collect();
    if addrs.is_empty() {
        return Err("DNS resolution returned no addresses".to_owned());
    }
    if let Some(blocked) = addrs.iter().find(|addr| is_blocked_ssrf_ip(addr.ip())) {
        return Err(format!(
            "resolved address {} is blocked by SSRF policy",
            blocked.ip()
        ));
    }
    Ok(addrs)
}

/// Lock-free warning rate limiter (at most one warning every [`WARN_THROTTLE_INTERVAL_SECS`]).
struct WarnThrottle {
    last_warn_epoch: AtomicI64,
    suppressed: AtomicU64,
}

impl WarnThrottle {
    fn new() -> Self {
        Self {
            last_warn_epoch: AtomicI64::new(0),
            suppressed: AtomicU64::new(0),
        }
    }

    fn should_warn(&self) -> Option<u64> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
        let last = self.last_warn_epoch.load(Ordering::Relaxed);
        if now.saturating_sub(last) >= WARN_THROTTLE_INTERVAL_SECS
            && self
                .last_warn_epoch
                .compare_exchange(last, now, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
        {
            Some(self.suppressed.swap(0, Ordering::Relaxed))
        } else {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

/// Shared, cheaply cloneable compliance audit dispatcher (`T17.2`).
///
/// Fans each sanitized [`AuditEvent`] out to all registered [`AuditSink`]s, increments
/// `ferriscd_audit_events_total{category, outcome}`, and increments `ferriscd_audit_dropped_total`
/// with a throttled warning whenever any non-blocking external sink drops an event.
#[derive(Clone)]
pub struct AuditLogger {
    inner: Arc<AuditLoggerInner>,
}

struct AuditLoggerInner {
    sinks: Vec<Arc<dyn AuditSink>>,
    metrics: Metrics,
    drop_warn_throttle: WarnThrottle,
}

impl fmt::Debug for AuditLogger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sink_names: Vec<&'static str> =
            self.inner.sinks.iter().map(|sink| sink.name()).collect();
        f.debug_struct("AuditLogger")
            .field("sinks", &sink_names)
            .finish_non_exhaustive()
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new(Metrics::new())
    }
}

impl AuditLogger {
    /// Builds the default logger: lossless stdout structured JSON (`TracingAuditSink`) wired to
    /// `metrics`.
    #[must_use]
    pub fn new(metrics: Metrics) -> Self {
        Self::with_sinks(vec![Arc::new(TracingAuditSink)], metrics)
    }

    /// Builds a logger with an explicit list of sinks and a [`Metrics`] registry.
    #[must_use]
    pub fn with_sinks(sinks: Vec<Arc<dyn AuditSink>>, metrics: Metrics) -> Self {
        Self {
            inner: Arc::new(AuditLoggerInner {
                sinks,
                metrics,
                drop_warn_throttle: WarnThrottle::new(),
            }),
        }
    }

    /// Returns a new logger appending `sink` to the existing sink list.
    #[must_use]
    pub fn with_additional_sink(&self, sink: Arc<dyn AuditSink>) -> Self {
        let mut sinks = self.inner.sinks.clone();
        sinks.push(sink);
        Self::with_sinks(sinks, self.inner.metrics.clone())
    }

    /// The shared [`Metrics`] registry backing `ferriscd_audit_*` counters.
    #[must_use]
    pub fn metrics(&self) -> &Metrics {
        &self.inner.metrics
    }

    /// Sanitizes and emits one [`AuditEvent`] across all registered sinks without blocking.
    pub fn emit(&self, mut event: AuditEvent) {
        event.sanitize();
        self.inner
            .metrics
            .record_audit_event(event.category, event.outcome);
        for sink in &self.inner.sinks {
            if sink.emit(&event) == AuditEmitResult::Dropped {
                self.inner.metrics.record_audit_dropped();
                if let Some(suppressed) = self.inner.drop_warn_throttle.should_warn() {
                    tracing::warn!(
                        sink = sink.name(),
                        suppressed_since_last_warning = suppressed,
                        "audit sink channel full; dropped audit event without blocking \
                         request/reconcile (see ferriscd_audit_dropped_total)"
                    );
                }
            }
        }
    }
}

/// In-memory [`AuditSink`] for deterministic unit and HTTP integration tests.
#[derive(Debug, Default)]
pub struct RecordingAuditSink {
    events: Mutex<Vec<AuditEvent>>,
}

impl RecordingAuditSink {
    /// Creates an empty recorder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a snapshot of every recorded [`AuditEvent`] in emission order.
    #[must_use]
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Clears recorded events.
    pub fn clear(&self) {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

impl AuditSink for RecordingAuditSink {
    fn name(&self) -> &'static str {
        "recording"
    }

    fn emit(&self, event: &AuditEvent) -> AuditEmitResult {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(event.clone());
        AuditEmitResult::Delivered
    }
}

/// Generates a cryptographically random RFC 4122 UUIDv4 string (`xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`).
#[must_use]
pub fn generate_uuid_v4() -> String {
    let mut bytes = [0_u8; 16];
    if getrandom::fill(&mut bytes).is_err() {
        // Fallback only if OS entropy fails unexpectedly: hash monotonic counter + timestamp.
        static FALLBACK_COUNTER: AtomicU64 = AtomicU64::new(1);
        let seq = FALLBACK_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0_u128, |d| d.as_nanos());
        let mut seed = [0_u8; 24];
        seed[..8].copy_from_slice(&seq.to_le_bytes());
        seed[8..].copy_from_slice(&nanos.to_le_bytes());
        let digest = ferriscd_engine::diff::sha256::digest(&seed);
        bytes.copy_from_slice(&digest[..16]);
    }
    // RFC 4122 §4.4: version 4 (0100) and variant 1 (10xx).
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

/// Current UTC timestamp formatted as RFC 3339 (`YYYY-MM-DDTHH:MM:SS.sssssssssZ`).
#[must_use]
pub fn current_rfc3339_utc() -> String {
    k8s_openapi::jiff::Timestamp::now().to_string()
}

/// Validates and bounds a request/correlation header ID (`<= 128` printable ASCII chars).
#[must_use]
pub fn sanitize_header_id(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 128 {
        return None;
    }
    if !trimmed
        .bytes()
        .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
    {
        return None;
    }
    Some(trimmed.to_owned())
}

/// Strips control characters and caps length on untrusted identity/target metadata fields.
fn sanitize_bounded_field(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .trim()
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_AUDIT_FIELD_CHARS)
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

/// Validates that a token fingerprint is strictly 12 lowercase hex characters (never a raw token).
fn sanitize_token_fingerprint(fingerprint: Option<String>) -> Option<String> {
    let fp = fingerprint?;
    let trimmed = fp.trim();
    if trimmed.len() == 12
        && trimmed
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        Some(trimmed.to_owned())
    } else {
        None
    }
}

/// Redacts a token containing `"://"` anywhere (including Rust `Debug`-quoted `"https://..."`,
/// parenthesized `(https://...)`, or key-prefixed `url=https://...`), stripping control chars,
/// embedded credentials, query strings, and fragments.
fn redact_embedded_url_token(token: &str) -> Option<String> {
    let scheme_sep = token.find("://")?;
    let before = &token[..scheme_sep];
    let scheme_start = before
        .rfind(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.')))
        .map_or(0, |idx| {
            idx + before[idx..].chars().next().map_or(1, char::len_utf8)
        });
    let prefix = &token[..scheme_start];
    let rest = &token[scheme_start..];
    let trimmed_rest = rest.trim_end_matches(['"', '\'', ')', ']', '}', ',', ';']);
    let suffix = &rest[trimmed_rest.len()..];
    let clean_url: String = trimmed_rest.chars().filter(|ch| !ch.is_control()).collect();
    let redacted = redact_audit_url(&clean_url);
    let clean_prefix: String = prefix.chars().filter(|ch| !ch.is_control()).collect();
    let clean_suffix: String = suffix.chars().filter(|ch| !ch.is_control()).collect();
    Some(format!("{clean_prefix}{redacted}{clean_suffix}"))
}

/// Redacts embedded URL credentials/queries, `Bearer`/`Basic`/`Authorization`/`X-Gitlab-Token`
/// values (even when quoted or header-prefixed), strips control characters, and caps length to
/// [`MAX_AUDIT_REASON_CHARS`].
#[must_use]
pub fn sanitize_audit_reason(raw: &str) -> String {
    let mut cleaned_tokens = Vec::new();
    let mut redact_next = false;
    for raw_token in raw.split_whitespace() {
        let token: String = raw_token.chars().filter(|ch| !ch.is_control()).collect();
        if token.is_empty() {
            continue;
        }
        if redact_next {
            let trimmed_word = token
                .trim_matches(['"', '\'', ',', ';'])
                .to_ascii_lowercase();
            // Handle `Authorization: Bearer <token>` where `Bearer` follows `Authorization:`.
            if trimmed_word == "bearer" || trimmed_word == "basic" {
                cleaned_tokens.push(token);
                continue;
            }
            cleaned_tokens.push("<redacted>".to_owned());
            redact_next = false;
            continue;
        }

        // Check inline `header:value` / `key=value` secret forms like `X-Gitlab-Token:secret`.
        let lower = token.to_ascii_lowercase();
        let unquoted_lower = lower.trim_matches(['"', '\'', '(', '[', '{', ',', ';']);
        if let Some((key, val)) = unquoted_lower.split_once([':', '='])
            && matches!(
                key,
                "x-gitlab-token" | "authorization" | "x-hub-signature-256"
            )
        {
            if val.is_empty() || matches!(val, "bearer" | "basic") {
                cleaned_tokens.push(format!("{key}:"));
                redact_next = true;
            } else {
                cleaned_tokens.push(format!("{key}:<redacted>"));
            }
            continue;
        }

        let bare_word = unquoted_lower.trim_end_matches([':', '=']);
        if matches!(
            bare_word,
            "bearer" | "basic" | "x-gitlab-token" | "authorization" | "x-hub-signature-256"
        ) {
            cleaned_tokens.push(token);
            redact_next = true;
            continue;
        }

        if let Some(redacted_url) = redact_embedded_url_token(&token) {
            cleaned_tokens.push(redacted_url);
            continue;
        }

        cleaned_tokens.push(token);
    }
    let joined = cleaned_tokens.join(" ");
    let mut bounded: String = joined.chars().take(MAX_AUDIT_REASON_CHARS).collect();
    if joined.chars().count() > MAX_AUDIT_REASON_CHARS {
        bounded.truncate(
            bounded
                .char_indices()
                .nth(MAX_AUDIT_REASON_CHARS.saturating_sub(3))
                .map_or(bounded.len(), |(idx, _)| idx),
        );
        bounded.push_str("...");
    }
    bounded
}

// ---------------------------------------------------------------------------
// Controller audit hooks (`controller.impersonation` and `cluster.registry`)
// ---------------------------------------------------------------------------

/// Emits a `controller.impersonation` audit record for an `Application` reconcile resolution.
#[allow(clippy::too_many_arguments)]
pub fn record_impersonation(
    audit: &AuditLogger,
    impersonated_user: &str,
    groups: &[String],
    app_namespace: Option<&str>,
    app_name: &str,
    project: &str,
    cluster: &str,
    outcome: AuditOutcome,
    reason: Option<&str>,
) {
    let mut event = AuditEvent::new(
        AuditCategory::ControllerImpersonation,
        AuditActor {
            username: Some(impersonated_user.to_owned()),
            groups: groups.to_vec(),
            token_fingerprint: None,
        },
        AuditTarget {
            namespace: app_namespace.map(ToOwned::to_owned),
            name: Some(app_name.to_owned()),
            project: Some(project.to_owned()),
            cluster: Some(cluster.to_owned()),
        },
        "impersonate",
        outcome,
    );
    if let Some(reason) = reason {
        event = event.with_reason(reason);
    }
    audit.emit(event);
}

/// Emits a `cluster.registry` audit record for `ClusterManager` add/rebuild/remove/reject events.
pub fn record_cluster_registry(
    audit: &AuditLogger,
    control_plane_namespace: &str,
    cluster_name: Option<&str>,
    secret_name: Option<&str>,
    action: &str,
    outcome: AuditOutcome,
    reason: Option<&str>,
) {
    let mut event = AuditEvent::new(
        AuditCategory::ClusterRegistry,
        AuditActor::system("ferriscd-controller/cluster-manager"),
        AuditTarget {
            namespace: Some(control_plane_namespace.to_owned()),
            name: secret_name.map(ToOwned::to_owned),
            project: None,
            cluster: cluster_name.map(ToOwned::to_owned),
        },
        action,
        outcome,
    );
    if let Some(reason) = reason {
        event = event.with_reason(reason);
    }
    audit.emit(event);
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    struct AlwaysDropSink {
        attempts: AtomicUsize,
    }

    impl AlwaysDropSink {
        fn new() -> Self {
            Self {
                attempts: AtomicUsize::new(0),
            }
        }
    }

    impl AuditSink for AlwaysDropSink {
        fn name(&self) -> &'static str {
            "always-drop"
        }

        fn emit(&self, _event: &AuditEvent) -> AuditEmitResult {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            AuditEmitResult::Dropped
        }
    }

    #[test]
    fn audit_event_json_schema_matches_v1_contract() {
        let mut event = AuditEvent::new(
            AuditCategory::ApiOperation,
            AuditActor {
                username: Some("system:serviceaccount:payments:deployer".to_owned()),
                groups: vec!["payments-team".to_owned()],
                token_fingerprint: Some("0123456789ab".to_owned()),
            },
            AuditTarget {
                namespace: Some("ferriscd-system".to_owned()),
                name: Some("payments-api".to_owned()),
                project: Some("payments".to_owned()),
                cluster: Some("in-cluster".to_owned()),
            },
            "sync",
            AuditOutcome::Accepted,
        )
        .with_request_id(Some("req-123".to_owned()))
        .with_reason("manual sync queued");
        event.timestamp = "2026-11-27T12:00:00Z".to_owned();
        event.event_id = "11111111-2222-4333-8444-555555555555".to_owned();

        let value = serde_json::to_value(&event).expect("serialize audit event");
        assert_eq!(
            value,
            serde_json::json!({
                "schemaVersion": "ferriscd.io/audit/v1",
                "timestamp": "2026-11-27T12:00:00Z",
                "eventId": "11111111-2222-4333-8444-555555555555",
                "requestId": "req-123",
                "category": "api.operation",
                "actor": {
                    "username": "system:serviceaccount:payments:deployer",
                    "groups": ["payments-team"],
                    "tokenFingerprint": "0123456789ab"
                },
                "target": {
                    "namespace": "ferriscd-system",
                    "name": "payments-api",
                    "project": "payments",
                    "cluster": "in-cluster"
                },
                "action": "sync",
                "outcome": "accepted",
                "reason": "manual sync queued"
            })
        );
    }

    #[test]
    fn uuid_v4_has_valid_rfc4122_format_and_uniqueness() {
        let first = generate_uuid_v4();
        let second = generate_uuid_v4();
        assert_ne!(first, second);
        assert_eq!(first.len(), 36);
        assert_eq!(&first[14..15], "4");
        assert!(matches!(&first[19..20], "8" | "9" | "a" | "b"));
    }

    #[test]
    fn sanitize_audit_reason_never_splits_a_multibyte_char_at_the_scheme_boundary() {
        // Regression: `rfind` returns a byte index; adding 1 used to slice inside a multi-byte
        // character and panic from the cluster-registry watch task.
        let sanitized = sanitize_audit_reason("cluster \"«https://evil.example\" is unusable");
        assert!(sanitized.contains("evil.example"), "{sanitized}");
    }

    #[test]
    fn sanitize_header_id_rejects_control_characters_and_oversize_values() {
        assert_eq!(sanitize_header_id("a\nb"), None);
        assert_eq!(sanitize_header_id("a\u{7f}b"), None);
        assert_eq!(sanitize_header_id(&"x".repeat(129)), None);
        assert_eq!(sanitize_header_id("a\"b"), None);
        assert_eq!(sanitize_header_id("a\\b"), None);
        assert_eq!(sanitize_header_id("req-123"), Some("req-123".to_owned()));
    }

    #[test]
    fn sanitize_strips_control_characters_from_the_action_field() {
        let mut event = AuditEvent::new(
            AuditCategory::ApiOperation,
            AuditActor::default(),
            AuditTarget::default(),
            "sync\nforged\u{7f}",
            AuditOutcome::Accepted,
        );
        event.sanitize();
        assert_eq!(event.action, "syncforged");
    }

    #[test]
    fn sanitization_redacts_tokens_quoted_urls_headers_and_bounds_reason() {
        let raw_reason = concat!(
            r#"Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.supersecret "#,
            r#"X-Gitlab-Token: glpat-header-secret "#,
            r#"failed pushing "https://oauth2:ghp_quoted123@github.com/org/repo.git?token=qsecret" "#,
            r#"url=https://user:pass456@git.example.com/team/app.git#frag "#,
            "ctrl=https://u:p@example.com/a\x07b",
        );
        let sanitized = sanitize_audit_reason(raw_reason);
        for leaked in [
            "supersecret",
            "glpat-header-secret",
            "ghp_quoted123",
            "qsecret",
            "pass456",
            "\x07",
        ] {
            assert!(
                !sanitized.contains(leaked),
                "secret/control {leaked:?} leaked in {sanitized:?}"
            );
        }
        assert!(sanitized.contains("github.com/org/repo.git"), "{sanitized}");
        assert!(
            sanitized.contains("git.example.com/team/app.git"),
            "{sanitized}"
        );

        // Over-long reason is truncated cleanly.
        let huge = "a".repeat(MAX_AUDIT_REASON_CHARS + 100);
        let bounded = sanitize_audit_reason(&huge);
        assert!(bounded.chars().count() <= MAX_AUDIT_REASON_CHARS);
        assert!(bounded.ends_with("..."));

        // Non-12-hex token fingerprint (e.g. accidental raw JWT) is stripped completely, and
        // control characters in untrusted target.name / actor.username are stripped.
        let event = AuditEvent::new(
            AuditCategory::ApiAuthzDenied,
            AuditActor {
                username: Some("bad\x00user\nname".to_owned()),
                groups: Vec::new(),
                token_fingerprint: Some("eyJhbGciOiJSUzI1NiJ9.rawjwt".to_owned()),
            },
            AuditTarget {
                name: Some("/api/v1/\r\nevil".to_owned()),
                ..AuditTarget::default()
            },
            "authenticate",
            AuditOutcome::Denied,
        );
        assert_eq!(event.actor.token_fingerprint, None);
        assert_eq!(event.actor.username.as_deref(), Some("badusername"));
        assert_eq!(event.target.name.as_deref(), Some("/api/v1/evil"));
    }

    #[test]
    fn webhook_url_validator_enforces_https_ssrf_and_query_redaction() {
        let parsed =
            ValidatedAuditWebhookUrl::parse("https://siem.example.com/audit?api_key=s3cr3t#frag")
                .expect("valid https url");
        assert_eq!(parsed.redacted(), "https://siem.example.com/audit");
        let debug = format!("{parsed:?}");
        assert!(
            !debug.contains("s3cr3t"),
            "Debug must never print query secrets: {debug}"
        );
        assert!(!debug.contains("frag"), "{debug}");

        assert!(ValidatedAuditWebhookUrl::parse("https://10.96.0.10:8443/v1/events").is_ok());

        for rejected in [
            "http://siem.example.com/audit",
            "https://user:pass@siem.example.com/audit",
            "https://localhost/audit",
            "https://sub.localhost:8443/audit",
            "https://127.0.0.1:8443/audit",
            "https://[::1]:8443/audit",
            "https://169.254.169.254/latest/meta-data",
            "https://100.100.100.200/latest/meta-data",
            "https://[fd00:ec2::254]/latest/meta-data",
            "https://[::ffff:169.254.169.254]/audit",
            "https://[::169.254.169.254]/audit",
            "https://[64:ff9b::169.254.169.254]/audit",
            "https://[64:ff9b::127.0.0.1]/audit",
            "https://[fe80::1]/audit",
            "https://0.0.0.0/audit",
            "https://metadata.google.internal/computeMetadata/v1",
        ] {
            assert!(
                ValidatedAuditWebhookUrl::parse(rejected).is_err(),
                "{rejected} must be refused"
            );
        }
    }

    #[tokio::test]
    async fn resolve_safe_socket_addrs_blocks_loopback_dns() {
        let err = resolve_safe_socket_addrs("localhost", 443)
            .await
            .expect_err("localhost DNS resolution must be blocked by SSRF guard");
        assert!(
            err.contains("SSRF") || err.contains("DNS"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn stalled_sink_drops_without_blocking_and_increments_metrics() {
        let metrics = Metrics::with_fixed_series();
        let drop_sink = Arc::new(AlwaysDropSink::new());
        let recorder = Arc::new(RecordingAuditSink::new());
        let logger =
            AuditLogger::with_sinks(vec![drop_sink.clone(), recorder.clone()], metrics.clone());

        logger.emit(AuditEvent::new(
            AuditCategory::ClusterRegistry,
            AuditActor::system("ferriscd-controller/cluster-manager"),
            AuditTarget {
                cluster: Some("eu-prod".to_owned()),
                ..AuditTarget::default()
            },
            "cluster.added",
            AuditOutcome::Accepted,
        ));

        assert_eq!(drop_sink.attempts.load(Ordering::SeqCst), 1);
        assert_eq!(recorder.events().len(), 1);
        let encoded = metrics.encode().expect("metrics encode");
        assert!(
            encoded.contains(
                r#"ferriscd_audit_events_total{category="cluster.registry",outcome="accepted"} 1"#
            ),
            "{encoded}"
        );
        assert!(
            encoded.contains("ferriscd_audit_dropped_total 1"),
            "{encoded}"
        );
    }

    #[tokio::test]
    async fn jsonl_file_sink_drains_cleanly_via_wait_drained_without_deadlock() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let metrics = Metrics::with_fixed_series();
        let sink = Arc::new(
            JsonlFileAuditSink::open(path.clone(), 8, metrics)
                .await
                .expect("open jsonl sink"),
        );
        let event = AuditEvent::new(
            AuditCategory::ControllerImpersonation,
            AuditActor {
                username: Some("system:serviceaccount:payments:deployer".to_owned()),
                groups: vec!["system:serviceaccounts:payments".to_owned()],
                token_fingerprint: None,
            },
            AuditTarget {
                namespace: Some("payments".to_owned()),
                name: Some("checkout".to_owned()),
                project: Some("payments".to_owned()),
                cluster: Some("in-cluster".to_owned()),
            },
            "impersonate",
            AuditOutcome::Allowed,
        );
        assert_eq!(sink.emit(&event), AuditEmitResult::Delivered);

        // `wait_drained` closes the sender and joins the writer without deadlocking.
        tokio::time::timeout(Duration::from_secs(2), sink.wait_drained())
            .await
            .expect("wait_drained must not deadlock");
        assert_eq!(
            sink.emit(&event),
            AuditEmitResult::Dropped,
            "emitting after wait_drained must return Dropped without panicking"
        );

        let content = tokio::fs::read_to_string(&path)
            .await
            .expect("audit.jsonl readable");
        let parsed: AuditEvent =
            serde_json::from_str(content.trim()).expect("valid JSONL AuditEvent");
        assert_eq!(parsed.schema_version, AUDIT_SCHEMA_VERSION);
        assert_eq!(parsed.category, AuditCategory::ControllerImpersonation);
        assert_eq!(parsed.action, "impersonate");
    }

    #[tokio::test]
    async fn webhook_sink_bounded_channel_drops_without_blocking_when_saturated() {
        // Construct a real WebhookAuditSink with a 1-slot channel whose receiver is never drained
        // (simulating a completely stalled SIEM), proving `try_send` returns `Dropped` immediately.
        let validated = ValidatedAuditWebhookUrl::parse("https://siem.example.com/ingest")
            .expect("valid https url");
        let (tx, _stalled_rx) = mpsc::channel::<AuditEvent>(1);
        let sink = WebhookAuditSink {
            url: validated,
            capacity: 1,
            tx: Mutex::new(Some(tx)),
            worker: Mutex::new(None),
        };
        let event = AuditEvent::new(
            AuditCategory::ApiOperation,
            AuditActor::system("test"),
            AuditTarget::default(),
            "sync",
            AuditOutcome::Accepted,
        );
        assert_eq!(sink.emit(&event), AuditEmitResult::Delivered);
        assert_eq!(
            sink.emit(&event),
            AuditEmitResult::Dropped,
            "second emit into full 1-slot channel must drop without blocking"
        );
    }
}
