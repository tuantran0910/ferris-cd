#![allow(clippy::expect_used, clippy::unwrap_used)]
//! HTTP integration tests for the `T17.2` compliance audit trail.
//!
//! Drives the full `ferriscd-server` axum router via `tower::ServiceExt::oneshot` and asserts:
//!
//! 1. `POST .../sync` and `POST .../rollback` emit correlated `api.operation` events carrying
//!    `X-Request-Id` and the 12-hex `tokenFingerprint` (never the raw bearer token).
//! 2. `403 Forbidden` and existence-hiding `404 Not Found` RBAC denials both emit accurate
//!    internal `api.authz_denied` records without changing the HTTP `404` response body.
//! 3. `401 Unauthorized` authentication failures record only the 12-hex token fingerprint.
//! 4. Valid and invalid GitHub/GitLab webhook deliveries each emit one correlated
//!    `webhook.delivery` event with redacted repository URLs and zero leaked webhook secrets.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use ferriscd_controller::{DiffPreview, Metrics};
use ferriscd_crd::{AppProject, Application};
use ferriscd_engine::diff::DiffSummary;
use ferriscd_server::audit::{
    AUDIT_SCHEMA_VERSION, AuditCategory, AuditLogger, AuditOutcome, REQUEST_ID_HEADER,
    RecordingAuditSink,
};
use ferriscd_server::auth::{
    AuthPolicy, AuthenticatedIdentity, TokenAuthenticator, fingerprint_label, token_fingerprint,
};
use ferriscd_server::rbac::RbacPolicy;
use ferriscd_server::state::{
    AppState, ApplicationSource, ChildNode, ClusterCatalog, ClusterEntry, DiffSource, GraphRequest,
    GraphTraversal, InventoryReader, LiveResourceState, OperationRequest, OperationWriter,
    ProjectCatalog, SeamFuture, ServingReadiness, WorkloadGraphSource,
};
use ferriscd_server::webhooks::{self, RefreshSink, RefreshTarget, WebhookConfig, WebhookSecret};
use serde_json::json;
use tower::ServiceExt as _;

const ADMIN_TOKEN: &str = "eyJhbGciOiJSUzI1NiJ9.admin-raw-secret-token";
const READONLY_TOKEN: &str = "eyJhbGciOiJSUzI1NiJ9.readonly-raw-secret-token";
const TENANT_A_TOKEN: &str = "eyJhbGciOiJSUzI1NiJ9.tenanta-raw-secret-token";
const BOGUS_TOKEN: &str = "eyJhbGciOiJSUzI1NiJ9.bogus-invalid-secret-token";
const GITHUB_SECRET: &str = "gh-webhook-top-secret-hmac-key";
const GITLAB_SECRET: &str = "glpat-webhook-top-secret-token";

const POLICY: &str = r#"
rules:
  - subject: { kind: group, name: platform-admins }
    project: "*"
    actions: [admin]
  - subject: { kind: group, name: payments-readonly }
    project: payments
    actions: [get, diff]
  - subject: { kind: group, name: tenant-a }
    project: tenant-a
    actions: [get, diff, sync]
"#;

struct FakeTokens(BTreeMap<String, AuthenticatedIdentity>);

impl FakeTokens {
    fn standard() -> Self {
        let mut map = BTreeMap::new();
        map.insert(
            ADMIN_TOKEN.to_owned(),
            AuthenticatedIdentity::new(
                "system:serviceaccount:ferriscd-system:platform-admin",
                vec!["platform-admins".to_owned()],
            ),
        );
        map.insert(
            READONLY_TOKEN.to_owned(),
            AuthenticatedIdentity::new(
                "system:serviceaccount:ferriscd-system:payments-ro",
                vec!["payments-readonly".to_owned()],
            ),
        );
        map.insert(
            TENANT_A_TOKEN.to_owned(),
            AuthenticatedIdentity::new(
                "system:serviceaccount:ferriscd-system:tenant-a",
                vec!["tenant-a".to_owned()],
            ),
        );
        Self(map)
    }
}

impl TokenAuthenticator for FakeTokens {
    fn authenticate<'a>(&'a self, token: &'a str) -> SeamFuture<'a, Option<AuthenticatedIdentity>> {
        let found = self.0.get(token).cloned();
        Box::pin(async move { Ok(found) })
    }
}

struct FakeApps(Vec<Application>);

impl ApplicationSource for FakeApps {
    fn list(&self) -> SeamFuture<'_, Vec<Application>> {
        let items = self.0.clone();
        Box::pin(async move { Ok(items) })
    }

    fn get(&self, namespace: &str, name: &str) -> SeamFuture<'_, Option<Application>> {
        let found = self
            .0
            .iter()
            .find(|app| {
                app.metadata.namespace.as_deref() == Some(namespace)
                    && app.metadata.name.as_deref() == Some(name)
            })
            .cloned();
        Box::pin(async move { Ok(found) })
    }
}

struct NoProjects;
impl ProjectCatalog for NoProjects {
    fn list(&self) -> SeamFuture<'_, Vec<AppProject>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

struct NoClusters;
impl ClusterCatalog for NoClusters {
    fn list(&self) -> Vec<ClusterEntry> {
        Vec::new()
    }
}

struct AcceptOperations;
impl OperationWriter for AcceptOperations {
    fn request<'a>(
        &'a self,
        _namespace: &'a str,
        _name: &'a str,
        _resource_version: Option<&'a str>,
        _operation: OperationRequest,
    ) -> SeamFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}

struct NoInventory;
impl InventoryReader for NoInventory {
    fn read<'a>(&'a self, _app: &'a Application) -> SeamFuture<'a, Vec<LiveResourceState>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

struct NoGraph;
impl WorkloadGraphSource for NoGraph {
    fn children<'a>(
        &'a self,
        _traversal: &'a GraphTraversal,
        _parent: &GraphRequest<'_>,
    ) -> SeamFuture<'a, Vec<ChildNode>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

struct EmptyDiff;
impl DiffSource for EmptyDiff {
    fn diff<'a>(&'a self, _app: &'a Application) -> SeamFuture<'a, DiffPreview> {
        Box::pin(async {
            Ok(DiffPreview {
                revision: "deadbeef".to_owned(),
                diffs: Vec::new(),
                summary: DiffSummary::default(),
                desired: 0,
                would_sync: false,
                policy_violations: Vec::new(),
            })
        })
    }
}

struct NoopRefresh;
impl RefreshSink for NoopRefresh {
    fn refresh(&self, _target: RefreshTarget) -> SeamFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

fn payment_app() -> Application {
    let spec: ferriscd_crd::ApplicationSpec = serde_json::from_value(json!({
        "project": "payments",
        "source": {
            "git": {
                "repoURL": "https://github.com/org/payments.git",
                "targetRevision": "main",
                "path": "deploy",
            },
            "renderer": { "plainYaml": {} },
        },
        "destination": { "cluster": "in-cluster", "namespace": "payments" },
    }))
    .expect("valid ApplicationSpec");
    let mut app = Application::new("payments-api", spec);
    app.metadata.namespace = Some("ferriscd-system".to_owned());
    app.metadata.resource_version = Some("42".to_owned());
    let ts: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time =
        serde_json::from_value(json!("2026-11-27T00:00:00Z")).expect("timestamp");
    app.status = Some(ferriscd_crd::status::ApplicationStatus {
        history: vec![ferriscd_crd::status::RevisionHistoryEntry::new(
            7,
            Some("8f3a1c2".to_owned()),
            ts,
        )],
        ..ferriscd_crd::status::ApplicationStatus::default()
    });
    app
}

fn build_app_and_recorder() -> (axum::Router, Arc<RecordingAuditSink>, Metrics) {
    let recorder = Arc::new(RecordingAuditSink::new());
    let metrics = Metrics::with_fixed_series();
    let audit = AuditLogger::with_sinks(vec![recorder.clone()], metrics.clone());
    let webhooks = WebhookConfig {
        github_secret: WebhookSecret::new(GITHUB_SECRET),
        gitlab_secret: WebhookSecret::new(GITLAB_SECRET),
        debounce: std::time::Duration::from_millis(10),
        max_jitter: std::time::Duration::ZERO,
        ..WebhookConfig::default()
    };
    let state = AppState::new(
        Arc::new(FakeApps(vec![payment_app()])),
        Arc::new(NoProjects),
        Arc::new(NoClusters),
        Arc::new(AcceptOperations),
        Arc::new(NoInventory),
        Arc::new(NoGraph),
        Arc::new(EmptyDiff),
        Arc::new(ServingReadiness),
    )
    .with_auth(AuthPolicy::TokenReview)
    .with_token_authenticator(Arc::new(FakeTokens::standard()))
    .with_rbac(Arc::new(RbacPolicy::parse(POLICY).expect("valid policy")))
    .with_refresh_sink(Arc::new(NoopRefresh))
    .with_webhooks(webhooks)
    .with_audit(audit);

    (ferriscd_server::router(state), recorder, metrics)
}

#[tokio::test]
async fn sync_and_rollback_emit_correlated_audit_events_without_leaking_tokens() {
    let (router, recorder, metrics) = build_app_and_recorder();

    // 1. POST .../sync with explicit X-Request-Id
    let sync_req = Request::builder()
        .method("POST")
        .uri("/api/v1/applications/ferriscd-system/payments-api/sync")
        .header(header::AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
        .header(REQUEST_ID_HEADER, "req-sync-001")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .expect("sync request");
    let sync_resp = router
        .clone()
        .oneshot(sync_req)
        .await
        .expect("sync response");
    assert_eq!(sync_resp.status(), StatusCode::ACCEPTED);
    assert_eq!(
        sync_resp.headers().get(REQUEST_ID_HEADER).unwrap(),
        "req-sync-001"
    );

    // 2. POST .../rollback without X-Request-Id -> generated UUIDv4 echoed & correlated
    let rb_req = Request::builder()
        .method("POST")
        .uri("/api/v1/applications/ferriscd-system/payments-api/rollback")
        .header(header::AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"id":7}"#))
        .expect("rollback request");
    let rb_resp = router.oneshot(rb_req).await.expect("rollback response");
    assert_eq!(rb_resp.status(), StatusCode::ACCEPTED);
    let generated_id = rb_resp
        .headers()
        .get(REQUEST_ID_HEADER)
        .expect("response must carry X-Request-Id")
        .to_str()
        .expect("ascii")
        .to_owned();

    let events = recorder.events();
    assert_eq!(events.len(), 2);

    let expected_fp = fingerprint_label(&token_fingerprint(ADMIN_TOKEN));
    assert_eq!(events[0].schema_version, AUDIT_SCHEMA_VERSION);
    assert_eq!(events[0].category, AuditCategory::ApiOperation);
    assert_eq!(events[0].action, "sync");
    assert_eq!(events[0].outcome, AuditOutcome::Accepted);
    assert_eq!(events[0].request_id.as_deref(), Some("req-sync-001"));
    assert_eq!(
        events[0].actor.token_fingerprint.as_deref(),
        Some(expected_fp.as_str())
    );
    assert_eq!(events[0].target.project.as_deref(), Some("payments"));

    assert_eq!(events[1].category, AuditCategory::ApiOperation);
    assert_eq!(events[1].action, "rollback");
    assert_eq!(events[1].outcome, AuditOutcome::Accepted);
    assert_eq!(events[1].request_id.as_deref(), Some(generated_id.as_str()));

    let serialized = serde_json::to_string(&events).expect("serialize");
    assert!(
        !serialized.contains(ADMIN_TOKEN),
        "raw bearer token must never appear in audit events"
    );

    let encoded = metrics.encode().expect("metrics");
    assert!(
        encoded.contains(
            r#"ferriscd_audit_events_total{category="api.operation",outcome="accepted"} 2"#
        ),
        "{encoded}"
    );
}

#[tokio::test]
async fn rbac_403_and_hidden_404_audit_internally_without_leaking_existence() {
    let (router, recorder, _metrics) = build_app_and_recorder();

    // Read-only caller attempts sync -> HTTP 403 + internal audit record.
    let sync_req = Request::builder()
        .method("POST")
        .uri("/api/v1/applications/ferriscd-system/payments-api/sync")
        .header(header::AUTHORIZATION, format!("Bearer {READONLY_TOKEN}"))
        .header(REQUEST_ID_HEADER, "req-403")
        .body(Body::from("{}"))
        .expect("req");
    let resp_403 = router.clone().oneshot(sync_req).await.expect("resp");
    assert_eq!(resp_403.status(), StatusCode::FORBIDDEN);

    // Cross-tenant caller attempts GET on payments-api -> HTTP 404 (existence-hiding!),
    // byte-identical in shape to a genuinely missing Application, while internal audit accurately
    // records the project denial.
    let get_req = Request::builder()
        .method("GET")
        .uri("/api/v1/applications/ferriscd-system/payments-api")
        .header(header::AUTHORIZATION, format!("Bearer {TENANT_A_TOKEN}"))
        .header(REQUEST_ID_HEADER, "req-404-hidden")
        .body(Body::empty())
        .expect("req");
    let resp_404 = router.clone().oneshot(get_req).await.expect("resp");
    assert_eq!(resp_404.status(), StatusCode::NOT_FOUND);
    let hidden_body = axum::body::to_bytes(resp_404.into_body(), 8192)
        .await
        .expect("body");

    let missing_req = Request::builder()
        .method("GET")
        .uri("/api/v1/applications/ferriscd-system/does-not-exist")
        .header(header::AUTHORIZATION, format!("Bearer {TENANT_A_TOKEN}"))
        .header(REQUEST_ID_HEADER, "req-404-missing")
        .body(Body::empty())
        .expect("req");
    let resp_missing = router.oneshot(missing_req).await.expect("resp");
    assert_eq!(resp_missing.status(), StatusCode::NOT_FOUND);
    let missing_body = axum::body::to_bytes(resp_missing.into_body(), 8192)
        .await
        .expect("body");

    let hidden_text = String::from_utf8_lossy(&hidden_body);
    let normalized_missing =
        String::from_utf8_lossy(&missing_body).replace("does-not-exist", "payments-api");
    assert_eq!(
        hidden_text, normalized_missing,
        "hidden 404 must be byte-identical to a missing Application response"
    );

    let events = recorder.events();
    assert_eq!(events.len(), 2);

    assert_eq!(events[0].category, AuditCategory::ApiAuthzDenied);
    assert_eq!(events[0].action, "sync");
    assert_eq!(events[0].outcome, AuditOutcome::Denied);
    assert_eq!(events[0].request_id.as_deref(), Some("req-403"));
    assert!(
        events[0]
            .reason
            .as_deref()
            .is_some_and(|r| r.contains("HTTP 403")),
        "{:?}",
        events[0].reason
    );

    assert_eq!(events[1].category, AuditCategory::ApiAuthzDenied);
    assert_eq!(events[1].action, "get");
    assert_eq!(events[1].outcome, AuditOutcome::Denied);
    assert_eq!(events[1].request_id.as_deref(), Some("req-404-hidden"));
    assert_eq!(events[1].target.project.as_deref(), Some("payments"));
    assert!(
        events[1]
            .reason
            .as_deref()
            .is_some_and(|r| r.contains("HTTP 404 existence-hiding")),
        "{:?}",
        events[1].reason
    );
}

#[tokio::test]
async fn auth_401_audits_token_fingerprint_only_never_raw_token() {
    let (router, recorder, _metrics) = build_app_and_recorder();

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/applications")
        .header(header::AUTHORIZATION, format!("Bearer {BOGUS_TOKEN}"))
        .header(REQUEST_ID_HEADER, "req-401")
        .body(Body::empty())
        .expect("req");
    let resp = router.oneshot(req).await.expect("resp");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let events = recorder.events();
    assert_eq!(events.len(), 1);
    let expected_fp = fingerprint_label(&token_fingerprint(BOGUS_TOKEN));
    assert_eq!(events[0].category, AuditCategory::ApiAuthzDenied);
    assert_eq!(events[0].action, "authenticate");
    assert_eq!(events[0].outcome, AuditOutcome::Denied);
    assert_eq!(events[0].request_id.as_deref(), Some("req-401"));
    assert_eq!(events[0].actor.username, None);
    assert_eq!(
        events[0].actor.token_fingerprint.as_deref(),
        Some(expected_fp.as_str())
    );
    let serialized = serde_json::to_string(&events[0]).expect("serialize");
    assert!(
        !serialized.contains(BOGUS_TOKEN),
        "raw invalid bearer token must never appear in audit record"
    );
}

#[tokio::test]
async fn valid_and_invalid_github_and_gitlab_webhooks_emit_redacted_audit_events() {
    let (router, recorder, _metrics) = build_app_and_recorder();

    // 1. Valid GitHub push carrying a credentialed clone_url -> accepted & repo URL redacted.
    let gh_payload = serde_json::to_vec(&json!({
        "ref": "refs/heads/main",
        "repository": {
            "clone_url": "https://oauth2:ghp_secret123@github.com/org/payments.git",
            "default_branch": "main"
        }
    }))
    .expect("gh payload");
    let digest = webhooks::hmac_sha256(GITHUB_SECRET.as_bytes(), &gh_payload);
    let gh_sig = format!(
        "sha256={}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let gh_ok = Request::builder()
        .method("POST")
        .uri("/api/v1/webhooks/github")
        .header(REQUEST_ID_HEADER, "req-gh-ok")
        .header(webhooks::GITHUB_SIGNATURE_HEADER, gh_sig)
        .header(webhooks::GITHUB_EVENT_HEADER, "push")
        .header(webhooks::GITHUB_DELIVERY_HEADER, "deliv-audit-1")
        .body(Body::from(gh_payload.clone()))
        .expect("gh ok req");
    let resp = router.clone().oneshot(gh_ok).await.expect("gh ok");
    assert_eq!(resp.status(), StatusCode::OK);

    // 2. Invalid GitHub signature -> 401 + Denied audit record.
    let gh_bad = Request::builder()
        .method("POST")
        .uri("/api/v1/webhooks/github")
        .header(REQUEST_ID_HEADER, "req-gh-bad")
        .header(webhooks::GITHUB_SIGNATURE_HEADER, "sha256=deadbeef")
        .header(webhooks::GITHUB_EVENT_HEADER, "push")
        .header(webhooks::GITHUB_DELIVERY_HEADER, "deliv-audit-2")
        .body(Body::from(gh_payload))
        .expect("gh bad req");
    let resp = router.clone().oneshot(gh_bad).await.expect("gh bad");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 3. Valid GitLab push -> 200 + Accepted audit record (never logs X-Gitlab-Token).
    let gl_payload = serde_json::to_vec(&json!({
        "object_kind": "push",
        "ref": "refs/heads/main",
        "project": {
            "git_http_url": "https://oauth2:glpat_repo_secret@github.com/org/payments.git",
            "default_branch": "main"
        }
    }))
    .expect("gl payload");
    let gl_ok = Request::builder()
        .method("POST")
        .uri("/api/v1/webhooks/gitlab")
        .header(REQUEST_ID_HEADER, "req-gl-ok")
        .header(webhooks::GITLAB_TOKEN_HEADER, GITLAB_SECRET)
        .header(webhooks::GITLAB_EVENT_HEADER, "Push Hook")
        .body(Body::from(gl_payload.clone()))
        .expect("gl ok req");
    let resp = router.clone().oneshot(gl_ok).await.expect("gl ok");
    assert_eq!(resp.status(), StatusCode::OK);

    // 4. Invalid GitLab token -> 401 + Denied audit record (never logs wrong token).
    let wrong_gl_token = "wrong-gitlab-secret-probe-value";
    let gl_bad = Request::builder()
        .method("POST")
        .uri("/api/v1/webhooks/gitlab")
        .header(REQUEST_ID_HEADER, "req-gl-bad")
        .header(webhooks::GITLAB_TOKEN_HEADER, wrong_gl_token)
        .header(webhooks::GITLAB_EVENT_HEADER, "Push Hook")
        .body(Body::from(gl_payload))
        .expect("gl bad req");
    let resp = router.oneshot(gl_bad).await.expect("gl bad");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let events = recorder.events();
    assert_eq!(events.len(), 4);

    assert_eq!(events[0].category, AuditCategory::WebhookDelivery);
    assert_eq!(events[0].outcome, AuditOutcome::Accepted);
    assert_eq!(events[0].request_id.as_deref(), Some("req-gh-ok"));

    assert_eq!(events[1].category, AuditCategory::WebhookDelivery);
    assert_eq!(events[1].outcome, AuditOutcome::Denied);
    assert_eq!(events[1].request_id.as_deref(), Some("req-gh-bad"));

    assert_eq!(events[2].category, AuditCategory::WebhookDelivery);
    assert_eq!(events[2].outcome, AuditOutcome::Accepted);
    assert_eq!(events[2].request_id.as_deref(), Some("req-gl-ok"));

    assert_eq!(events[3].category, AuditCategory::WebhookDelivery);
    assert_eq!(events[3].outcome, AuditOutcome::Denied);
    assert_eq!(events[3].request_id.as_deref(), Some("req-gl-bad"));

    let serialized = serde_json::to_string(&events).expect("serialize");
    for secret in [
        GITHUB_SECRET,
        GITLAB_SECRET,
        wrong_gl_token,
        "ghp_secret123",
        "glpat_repo_secret",
    ] {
        assert!(
            !serialized.contains(secret),
            "secret {secret:?} leaked into webhook audit trail: {serialized}"
        );
    }
}
