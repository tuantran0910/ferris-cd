//! HTTP audit middleware, request correlation (`X-Request-Id`), and API/webhook audit helpers
//! (`T17.2`).
//!
//! Re-exports the versioned [`AuditEvent`] schema and [`AuditSink`] primitives from
//! `ferriscd-controller` so the REST API and controller share one schema, one sink pipeline, and
//! one Prometheus counter registry (`ferriscd_audit_events_total`, `ferriscd_audit_dropped_total`).

use axum::extract::Request;
use axum::http::header::HeaderName;
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use ferriscd_crd::Application;
use kube::ResourceExt as _;

pub use ferriscd_controller::audit::{
    AUDIT_CATEGORIES, AUDIT_OUTCOMES, AUDIT_SCHEMA_VERSION, AUDIT_TRACING_TARGET, AuditActor,
    AuditCategory, AuditEmitResult, AuditEvent, AuditLogger, AuditOutcome, AuditSink,
    AuditSinkError, AuditTarget, DEFAULT_AUDIT_CHANNEL_CAPACITY, JsonlFileAuditSink,
    MAX_AUDIT_REASON_CHARS, RecordingAuditSink, TracingAuditSink, ValidatedAuditWebhookUrl,
    WebhookAuditSink, current_rfc3339_utc, generate_uuid_v4, is_blocked_ssrf_ip, redact_audit_url,
    sanitize_audit_reason, sanitize_header_id,
};

use crate::auth::AuthenticatedIdentity;
use crate::rbac::Action;

/// Correlation header propagated on every HTTP request and mirrored on the response (`T17.2`).
pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// Request extension holding the validated `X-Request-Id` for the current HTTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(pub String);

impl RequestId {
    /// Returns the correlation ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Request extension holding the 12-hex one-way SHA-256 fingerprint of the caller's bearer token.
///
/// Inserted by [`crate::auth::authenticate`] on authenticated requests so downstream handlers can
/// populate [`AuditActor::token_fingerprint`] without ever retaining the raw credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenFingerprint(pub String);

/// Axum middleware that ensures every request carries a sanitized `X-Request-Id`, stores it in
/// request extensions as [`RequestId`], and echoes it back on the HTTP response.
pub async fn request_id_middleware(mut request: Request, next: Next) -> Response {
    let incoming = request
        .headers()
        .get(&REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(sanitize_header_id);
    let id = incoming.unwrap_or_else(generate_uuid_v4);
    request.extensions_mut().insert(RequestId(id.clone()));
    let mut response = next.run(request).await;
    if let Ok(header_value) = HeaderValue::from_str(&id) {
        response
            .headers_mut()
            .insert(REQUEST_ID_HEADER, header_value);
    }
    response
}

/// Builds an [`AuditActor`] from an authenticated identity and optional 12-hex token fingerprint.
#[must_use]
pub fn actor_from_identity(
    identity: &AuthenticatedIdentity,
    fingerprint: Option<&TokenFingerprint>,
) -> AuditActor {
    AuditActor {
        username: identity
            .username
            .clone()
            .or_else(|| Some("anonymous".to_owned())),
        groups: identity.groups.clone(),
        token_fingerprint: fingerprint.map(|fp| fp.0.clone()),
    }
}

/// Emits an `api.authz_denied` audit event for a rejected `401 Unauthorized` authentication
/// attempt. Carries **only** the 12-hex token fingerprint (never the raw bearer token or
/// `Authorization` header).
pub fn record_auth_denied(
    audit: &AuditLogger,
    request_id: Option<&str>,
    path: &str,
    token_fingerprint: Option<&str>,
    reason: &str,
) {
    let actor = match token_fingerprint {
        Some(fp) => AuditActor::token_fingerprint_only(fp),
        None => AuditActor::default(),
    };
    let event = AuditEvent::new(
        AuditCategory::ApiAuthzDenied,
        actor,
        AuditTarget {
            name: Some(path.to_owned()),
            ..AuditTarget::default()
        },
        "authenticate",
        AuditOutcome::Denied,
    )
    .with_request_id(request_id.map(ToOwned::to_owned))
    .with_reason(reason);
    audit.emit(event);
}

/// Emits an `api.authz_denied` audit event for an RBAC denial (`403 Forbidden` or existence-hiding
/// `404 Not Found` when the caller has zero grants on the `Application`'s project).
///
/// **Trap guard:** the HTTP response remains `404` when the caller has no grant on the project;
/// only the internal audit trail records the underlying project/action denial.
#[allow(clippy::too_many_arguments)]
pub fn record_rbac_denied(
    audit: &AuditLogger,
    request_id: Option<&str>,
    identity: &AuthenticatedIdentity,
    fingerprint: Option<&TokenFingerprint>,
    app: &Application,
    action: Action,
    http_status: StatusCode,
) {
    let reason = if http_status == StatusCode::NOT_FOUND {
        format!(
            "no project grant on AppProject {} for action `{}` (HTTP 404 existence-hiding)",
            app.spec.project,
            action.as_str()
        )
    } else {
        format!(
            "missing `{}` grant on AppProject {} (HTTP 403)",
            action.as_str(),
            app.spec.project
        )
    };
    let event = AuditEvent::new(
        AuditCategory::ApiAuthzDenied,
        actor_from_identity(identity, fingerprint),
        AuditTarget {
            namespace: app.namespace(),
            name: Some(app.name_any()),
            project: Some(app.spec.project.clone()),
            cluster: Some(app.spec.destination.cluster.clone()),
        },
        action.as_str(),
        AuditOutcome::Denied,
    )
    .with_request_id(request_id.map(ToOwned::to_owned))
    .with_reason(reason);
    audit.emit(event);
}

/// Emits an `api.operation` audit event for `POST .../sync` or `POST .../rollback`.
#[allow(clippy::too_many_arguments)]
pub fn record_api_operation(
    audit: &AuditLogger,
    request_id: Option<&str>,
    identity: &AuthenticatedIdentity,
    fingerprint: Option<&TokenFingerprint>,
    app: &Application,
    action: &str,
    outcome: AuditOutcome,
    reason: Option<&str>,
) {
    let mut event = AuditEvent::new(
        AuditCategory::ApiOperation,
        actor_from_identity(identity, fingerprint),
        AuditTarget {
            namespace: app.namespace(),
            name: Some(app.name_any()),
            project: Some(app.spec.project.clone()),
            cluster: Some(app.spec.destination.cluster.clone()),
        },
        action,
        outcome,
    )
    .with_request_id(request_id.map(ToOwned::to_owned));
    if let Some(reason) = reason {
        event = event.with_reason(reason);
    }
    audit.emit(event);
}

/// Emits a `webhook.delivery` audit event for GitHub or GitLab webhook deliveries (accepted,
/// ignored/duplicate, or rejected). Never logs `X-Gitlab-Token` or HMAC secrets and always passes
/// repository URLs through [`redact_audit_url`] (stripping userinfo, query strings, and fragments).
#[allow(clippy::too_many_arguments)]
pub fn record_webhook_delivery(
    audit: &AuditLogger,
    request_id: Option<&str>,
    provider: &str,
    action: &str,
    repository: Option<&str>,
    outcome: AuditOutcome,
    reason: &str,
) {
    let redacted_repo = repository
        .filter(|repo| !repo.is_empty())
        .map(redact_audit_url);
    let event = AuditEvent::new(
        AuditCategory::WebhookDelivery,
        AuditActor::system(format!("webhook/{provider}")),
        AuditTarget {
            name: redacted_repo,
            ..AuditTarget::default()
        },
        action,
        outcome,
    )
    .with_request_id(request_id.map(ToOwned::to_owned))
    .with_reason(reason);
    audit.emit(event);
}
