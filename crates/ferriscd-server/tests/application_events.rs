#![allow(clippy::expect_used, clippy::unwrap_used)]
//! HTTP-level tests for the `T17.3` observability surfaces:
//! `GET /api/v1/applications/{namespace}/{name}/events` and the SSE feed
//! `GET /api/v1/applications/stream`.
//!
//! Everything runs in-process with `tower::ServiceExt::oneshot`: the real router, the real auth
//! middleware, the real `T14.4` RBAC matcher and the real DTO mapping, with only the cluster replaced
//! by fakes. What is asserted is exactly what the roadmap's verification bullets say:
//!
//! * `/events` is `404` when the caller cannot see the `Application` (indistinguishable from "does
//!   not exist") and `403` when it can see it but lacks `get`;
//! * `/events` never leaks a credential or a `Secret` payload, and never returns more than the
//!   documented bound;
//! * `/stream` never emits an application from a project the caller cannot see;
//! * `/stream` tears the subscription down when the client goes away (no detached task, no leak);
//! * `/stream` authenticates from the `Authorization` header only — a `?access_token=` (what an
//!   `EventSource` would need) is **not** accepted.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode, header};
use ferriscd_controller::DiffPreview;
use ferriscd_crd::{AppProject, Application};
use ferriscd_engine::diff::DiffSummary;
use ferriscd_server::auth::{AuthPolicy, AuthenticatedIdentity, IdentityCache, TokenAuthenticator};
use ferriscd_server::error::ApiError;
use ferriscd_server::rbac::RbacPolicy;
use ferriscd_server::state::{
    AppState, ApplicationEvent, ApplicationSnapshotSource, ApplicationSource, ChildNode,
    ClusterCatalog, ClusterEntry, DiffSource, EventSource, GraphRequest, GraphTraversal,
    InventoryReader, LiveResourceState, MAX_APPLICATION_EVENTS, OperationRequest, OperationWriter,
    ProjectCatalog, Readiness, SeamFuture, WorkloadGraphSource,
};
use ferriscd_server::webhooks::{RefreshSink, RefreshTarget, WebhookConfig};
use futures::StreamExt as _;
use futures::stream::BoxStream;
use kube::ResourceExt as _;
use serde_json::{Value, json};
use tower::ServiceExt;

const TENANT_A_USER: &str = "system:serviceaccount:ferriscd-system:tenant-a";
const TENANT_A_GROUP: &str = "tenant-a";
const READ_ONLY_USER: &str = "system:serviceaccount:ferriscd-system:auditor";
const READ_ONLY_GROUP: &str = "auditors";

/// `tenant-a` may read and sync its own project; `auditors` may `diff` `payments` but **not** `get`
/// it (which is what makes the ``403``-vs-``404`` distinction testable); nothing else is granted.
const POLICY: &str = r#"
rules:
  - subject: {kind: group, name: tenant-a}
    project: tenant-a
    actions: [get, sync]
  - subject: {kind: group, name: auditors}
    project: payments
    actions: [diff]
"#;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn application(namespace: &str, name: &str, project: &str) -> Application {
    let spec: ferriscd_crd::ApplicationSpec = serde_json::from_value(json!({
        "project": project,
        "source": {
            "git": {
                "repoURL": "https://github.com/example/payment-service.git",
                "targetRevision": "main",
                "path": "deploy",
            },
            "renderer": {"plainYaml": {}},
        },
        "destination": {"cluster": "in-cluster", "namespace": "payments"},
    }))
    .expect("a valid ApplicationSpec");
    let mut app = Application::new(name, spec);
    app.metadata.namespace = Some(namespace.to_owned());
    app.metadata.uid = Some(format!("uid-{name}"));
    app.metadata.resource_version = Some("42".to_owned());
    app
}

struct Apps(Vec<Application>);

impl ApplicationSource for Apps {
    fn list(&self) -> SeamFuture<'_, Vec<Application>> {
        Box::pin(async { Ok(self.0.clone()) })
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

struct Projects;

impl ProjectCatalog for Projects {
    fn list(&self) -> SeamFuture<'_, Vec<AppProject>> {
        Box::pin(async {
            let project = |name: &str| -> AppProject {
                serde_json::from_value(json!({
                    "apiVersion": "ferriscd.io/v1alpha1",
                    "kind": "AppProject",
                    "metadata": {"name": name, "namespace": "ferriscd-system"},
                    "spec": {"destinations": [{"cluster": "in-cluster", "namespace": "*"}]},
                }))
                .expect("a valid AppProject")
            };
            Ok(vec![project("payments"), project("tenant-a")])
        })
    }
}

struct Clusters;

impl ClusterCatalog for Clusters {
    fn list(&self) -> Vec<ClusterEntry> {
        vec![ClusterEntry {
            name: "in-cluster".to_owned(),
            in_cluster: true,
        }]
    }
}

struct Operations;

impl OperationWriter for Operations {
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

struct NoDiff;

impl DiffSource for NoDiff {
    fn diff<'a>(&'a self, _app: &'a Application) -> SeamFuture<'a, DiffPreview> {
        Box::pin(async {
            Ok(DiffPreview {
                revision: "8f3a1c2".to_owned(),
                summary: DiffSummary::from_diffs(&[]),
                desired: 0,
                would_sync: false,
                policy_violations: Vec::new(),
                diffs: Vec::new(),
            })
        })
    }
}

struct Ready;

impl Readiness for Ready {
    fn is_ready(&self) -> bool {
        true
    }
}

struct Sink;

impl RefreshSink for Sink {
    fn refresh(&self, _target: RefreshTarget) -> SeamFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

/// A `TokenReview` replacement: a token table plus the identities it knows.
#[derive(Default)]
struct Tokens {
    identities: BTreeMap<String, AuthenticatedIdentity>,
}

impl Tokens {
    fn new() -> Self {
        Self {
            identities: BTreeMap::from([
                (
                    "tenant-a-token".to_owned(),
                    AuthenticatedIdentity::new(TENANT_A_USER, vec![TENANT_A_GROUP.to_owned()]),
                ),
                (
                    "auditor-token".to_owned(),
                    AuthenticatedIdentity::new(READ_ONLY_USER, vec![READ_ONLY_GROUP.to_owned()]),
                ),
            ]),
        }
    }
}

impl TokenAuthenticator for Tokens {
    fn authenticate<'a>(&'a self, token: &'a str) -> SeamFuture<'a, Option<AuthenticatedIdentity>> {
        let identity = self.identities.get(token).cloned();
        Box::pin(async move { Ok(identity) })
    }
}

/// The event seam: a fixed list, plus a counter so "read exactly once" can be asserted.
#[derive(Default)]
struct Events {
    events: Mutex<Vec<ApplicationEvent>>,
    asked: Mutex<Vec<String>>,
}

impl Events {
    fn with(events: Vec<ApplicationEvent>) -> Self {
        Self {
            events: Mutex::new(events),
            asked: Mutex::new(Vec::new()),
        }
    }

    fn asked(&self) -> Vec<String> {
        self.asked.lock().expect("test state").clone()
    }
}

impl EventSource for Events {
    fn list<'a>(&'a self, app: &'a Application) -> SeamFuture<'a, Vec<ApplicationEvent>> {
        let name = app.name_any();
        self.asked.lock().expect("test state").push(name);
        let events = self.events.lock().expect("test state").clone();
        Box::pin(async move { Ok(events) })
    }
}

/// Counts how many subscriptions are alive, so a client disconnect is observable.
#[derive(Default)]
struct Live(Arc<AtomicUsize>);

impl Drop for Live {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The SSE seam: a fixed sequence of frames, each `Ok`/`Err` exactly as supplied.
#[derive(Default)]
struct Snapshots {
    frames: Mutex<Vec<Result<Vec<Application>, ApiError>>>,
    subscriptions: Arc<AtomicUsize>,
    live: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
}

impl Snapshots {
    fn with(frames: Vec<Result<Vec<Application>, ApiError>>) -> Self {
        Self {
            frames: Mutex::new(frames),
            ..Self::default()
        }
    }

    fn live(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }

    fn dropped(&self) -> usize {
        self.dropped.load(Ordering::SeqCst)
    }
}

impl ApplicationSnapshotSource for Snapshots {
    fn subscribe(&self) -> BoxStream<'static, Result<Vec<Application>, ApiError>> {
        self.subscriptions.fetch_add(1, Ordering::SeqCst);
        self.live.fetch_add(1, Ordering::SeqCst);
        // The guard lives inside the stream's state, so it is dropped exactly when the response body
        // is: that is what "cleans up on client disconnect" has to mean.
        struct Guard {
            // Held for its `Drop`, never read.
            _live: Live,
            dropped: Arc<AtomicUsize>,
        }
        impl Drop for Guard {
            fn drop(&mut self) {
                self.dropped.fetch_add(1, Ordering::SeqCst);
            }
        }
        let guard = Guard {
            _live: Live(Arc::clone(&self.live)),
            dropped: Arc::clone(&self.dropped),
        };
        let frames: VecDeque<Result<Vec<Application>, ApiError>> = self
            .frames
            .lock()
            .expect("test state")
            .iter()
            .cloned()
            .collect();
        Box::pin(futures::stream::unfold(
            (frames, guard),
            |(mut frames, guard)| async move {
                let next = frames.pop_front()?;
                // Keep the guard owned by the stream for its whole life.
                let _ = &guard;
                Some((next, (frames, guard)))
            },
        ))
    }
}

// ---------------------------------------------------------------------------
// State + HTTP helpers
// ---------------------------------------------------------------------------

fn tenants() -> Vec<Application> {
    vec![
        application("ferriscd-system", "payments-api", "payments"),
        application("ferriscd-system", "tenant-a-api", "tenant-a"),
        application("ferriscd-system", "tenant-b-api", "tenant-b"),
    ]
}

fn state_with(
    events: Arc<dyn EventSource>,
    snapshots: Arc<dyn ApplicationSnapshotSource>,
) -> AppState {
    AppState::new(
        Arc::new(Apps(tenants())),
        Arc::new(Projects),
        Arc::new(Clusters),
        Arc::new(Operations),
        Arc::new(NoInventory),
        Arc::new(NoGraph),
        Arc::new(NoDiff),
        Arc::new(Ready),
    )
    .with_refresh_sink(Arc::new(Sink))
    .with_auth(AuthPolicy::TokenReview)
    .with_token_authenticator(Arc::new(Tokens::new()))
    .with_identity_cache(Arc::new(IdentityCache::default()))
    .with_rbac(Arc::new(
        RbacPolicy::parse(POLICY).expect("the documented policy parses"),
    ))
    .with_event_source(events)
    .with_snapshot_source(snapshots)
    .with_webhooks(WebhookConfig::default())
}

fn state(events: Arc<dyn EventSource>) -> AppState {
    state_with(events, Arc::new(Snapshots::default()))
}

fn with_token(mut request: Request<Body>, token: &str) -> Request<Body> {
    request.headers_mut().insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).expect("a header value"),
    );
    request
}

fn get_request(path: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .expect("a request")
}

async fn send(state: AppState, request: Request<Body>) -> (StatusCode, Value) {
    let response = ferriscd_server::router(state)
        .oneshot(request)
        .await
        .expect("the router answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, body)
}

async fn get_as(state: AppState, path: &str, token: &str) -> (StatusCode, Value) {
    send(state, with_token(get_request(path), token)).await
}

/// One SSE frame's `event:`/`data:` pair.
fn parse_frame(raw: &str) -> (String, String) {
    let mut event = String::new();
    let mut data = String::new();
    for line in raw.lines() {
        if let Some(name) = line.strip_prefix("event: ") {
            event = name.to_owned();
        } else if let Some(payload) = line.strip_prefix("data: ") {
            data.push_str(payload);
        }
    }
    (event, data)
}

fn event(name: &str, event_type: &str, reason: &str, note: &str) -> ApplicationEvent {
    ApplicationEvent {
        name: name.to_owned(),
        event_type: event_type.to_owned(),
        reason: reason.to_owned(),
        note: note.to_owned(),
        action: Some("Sync".to_owned()),
        count: 1,
        reporting_component: Some("ferriscd.io/controller".to_owned()),
        last_observed_at: Some("2027-01-15T10:30:00Z".to_owned()),
        first_observed_at: Some("2027-01-15T10:00:00Z".to_owned()),
    }
}

// ---------------------------------------------------------------------------
// GET /api/v1/applications/{namespace}/{name}/events
// ---------------------------------------------------------------------------

/// The timeline is the controller's own events, redacted, in the order the source reported them.
#[tokio::test]
async fn the_events_timeline_is_redacted_and_carries_the_event_fields() {
    let source = Arc::new(Events::with(vec![
        event(
            "tenant-a-api.1",
            "Warning",
            "SyncFailed",
            // A real note can quote a repository URL (which may carry a token) and an apply failure.
            "failed to apply https://oauth2:ghp_averysecrettoken@github.com/acme/repo.git",
        ),
        event(
            "tenant-a-api.2",
            "Normal",
            "SyncSucceeded",
            "applied 15 resources",
        ),
    ]));
    let (status, body) = get_as(
        state(source.clone()),
        "/api/v1/applications/ferriscd-system/tenant-a-api/events",
        "tenant-a-token",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(source.asked(), vec!["tenant-a-api".to_owned()]);
    assert_eq!(body["items"][0]["reason"], "SyncFailed");
    assert_eq!(body["items"][0]["type"], "Warning");
    assert_eq!(body["items"][0]["action"], "Sync");
    assert_eq!(body["items"][0]["count"], 1);
    assert_eq!(
        body["items"][0]["reportingComponent"],
        "ferriscd.io/controller"
    );
    assert_eq!(body["items"][0]["lastObservedAt"], "2027-01-15T10:30:00Z");
    assert_eq!(body["items"][0]["firstObservedAt"], "2027-01-15T10:00:00Z");
    assert_eq!(body["items"][1]["reason"], "SyncSucceeded");
    assert_eq!(body["truncated"], false);

    let rendered = body.to_string();
    assert!(
        !rendered.contains("ghp_averysecrettoken"),
        "an event note can quote a repository URL and the credential must be redacted: {rendered}"
    );
    assert!(
        rendered.contains("***@github.com/acme/repo.git"),
        "the URL stays recognizable while the credential is masked: {rendered}"
    );
}

/// The response is a bounded timeline: at most `MAX_APPLICATION_EVENTS`, and it says so.
#[tokio::test]
async fn a_long_event_history_is_truncated_and_flagged() {
    let mut events: Vec<ApplicationEvent> = (0..MAX_APPLICATION_EVENTS + 7)
        .map(|index| {
            event(
                &format!("tenant-a-api.{index}"),
                "Normal",
                "SyncSucceeded",
                "applied",
            )
        })
        .collect();
    events.reverse();
    let (status, body) = get_as(
        state(Arc::new(Events::with(events))),
        "/api/v1/applications/ferriscd-system/tenant-a-api/events",
        "tenant-a-token",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["items"].as_array().expect("items").len(),
        MAX_APPLICATION_EVENTS
    );
    assert_eq!(body["truncated"], true);
}

/// `404`-if-unseen and `403`-if-visible: the two answers a restricted caller can get. An invisible
/// `Application` answers exactly the `404` a missing one answers for the same path — the message only
/// ever names what the caller asked for, never whether the object exists.
#[tokio::test]
async fn the_events_endpoint_enforces_404_if_unseen_and_403_if_visible() {
    let source = Arc::new(Events::default());

    let (unseen_status, unseen_body) = get_as(
        state(source.clone()),
        "/api/v1/applications/ferriscd-system/payments-api/events",
        "tenant-a-token",
    )
    .await;
    let (missing_status, missing_body) = get_as(
        state(source.clone()),
        "/api/v1/applications/ferriscd-system/payments-api-typo/events",
        "tenant-a-token",
    )
    .await;
    assert_eq!(unseen_status, StatusCode::NOT_FOUND);
    assert_eq!(missing_status, StatusCode::NOT_FOUND);
    assert_eq!(unseen_body["error"]["code"], missing_body["error"]["code"]);
    assert_eq!(
        unseen_body["error"]["message"], "Application ferriscd-system/payments-api not found",
        "the body is the plain not-found message: nothing tells the caller the object exists"
    );
    assert!(
        source.asked().is_empty(),
        "no cluster read happens for an application the caller cannot see: {:?}",
        source.asked()
    );

    let (visible_status, visible_body) = get_as(
        state(source.clone()),
        "/api/v1/applications/ferriscd-system/payments-api/events",
        "auditor-token",
    )
    .await;
    assert_eq!(
        visible_status,
        StatusCode::FORBIDDEN,
        "a caller that can already see the application is told it lacks `get`"
    );
    assert_eq!(visible_body["error"]["code"], "Forbidden");
    assert!(
        source.asked().is_empty(),
        "authorization happens before the event read: {:?}",
        source.asked()
    );
}

/// Without a bearer token the endpoint is unreachable, exactly like every other protected route.
#[tokio::test]
async fn the_events_endpoint_requires_authentication() {
    let (status, body) = send(
        state(Arc::new(Events::default())),
        get_request("/api/v1/applications/ferriscd-system/payments-api/events"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "Unauthorized");
}

// ---------------------------------------------------------------------------
// GET /api/v1/applications/stream
// ---------------------------------------------------------------------------

/// A snapshot never carries an application from a project the caller cannot see.
#[tokio::test]
async fn the_stream_never_emits_an_unauthorized_project() {
    let snapshots = Arc::new(Snapshots::with(vec![Ok(tenants())]));
    let state = state_with(Arc::new(Events::default()), snapshots.clone());

    let response = ferriscd_server::router(state)
        .oneshot(with_token(
            get_request("/api/v1/applications/stream"),
            "tenant-a-token",
        ))
        .await
        .expect("the router answers");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap_or_default()),
        Some("text/event-stream")
    );

    let mut frames = response.into_body().into_data_stream();
    let chunk = frames
        .next()
        .await
        .expect("the first frame")
        .expect("a data chunk");
    let raw = String::from_utf8_lossy(&chunk).into_owned();
    let (name, data) = parse_frame(&raw);
    assert_eq!(name, "applications");
    assert!(
        data.contains("tenant-a-api"),
        "the caller's own application must be there: {data}"
    );
    assert!(
        !data.contains("tenant-b-api") && !data.contains("payments-api"),
        "a snapshot must never carry another project's application: {data}"
    );
    assert_eq!(snapshots.live(), 1);
    drop(frames);
}

/// Dropping the response body (what a client disconnect does) tears the subscription down.
#[tokio::test]
async fn the_stream_cleans_up_when_the_client_disconnects() {
    let snapshots = Arc::new(Snapshots::with(vec![
        Ok(vec![application(
            "ferriscd-system",
            "tenant-a-api",
            "tenant-a",
        )]),
        Ok(vec![application(
            "ferriscd-system",
            "tenant-a-api",
            "tenant-a",
        )]),
        Ok(vec![application(
            "ferriscd-system",
            "tenant-a-api",
            "tenant-a",
        )]),
    ]));
    let state = state_with(Arc::new(Events::default()), snapshots.clone());

    let response = ferriscd_server::router(state)
        .oneshot(with_token(
            get_request("/api/v1/applications/stream"),
            "tenant-a-token",
        ))
        .await
        .expect("the router answers");
    let mut frames = response.into_body().into_data_stream();

    let first = frames
        .next()
        .await
        .expect("the first frame")
        .expect("a data chunk");
    assert_eq!(
        parse_frame(&String::from_utf8_lossy(&first)).0,
        "applications"
    );
    assert_eq!(
        snapshots.live(),
        1,
        "the subscription is open while the client reads"
    );
    assert_eq!(snapshots.dropped(), 0);
    assert_eq!(snapshots.subscriptions.load(Ordering::SeqCst), 1);

    // The client goes away.
    drop(frames);

    assert_eq!(
        snapshots.dropped(),
        1,
        "the subscription must be dropped with the response body (no detached task)"
    );
    assert_eq!(snapshots.live(), 0);
}

/// A failing snapshot ends the stream with one `error` frame instead of looping forever.
#[tokio::test]
async fn a_failing_snapshot_ends_the_stream_with_one_error_frame() {
    let snapshots = Arc::new(Snapshots::with(vec![
        Ok(vec![application(
            "ferriscd-system",
            "tenant-a-api",
            "tenant-a",
        )]),
        Err(ApiError::backend(&"the cluster could not be listed")),
    ]));
    let state = state_with(Arc::new(Events::default()), snapshots.clone());

    let response = ferriscd_server::router(state)
        .oneshot(with_token(
            get_request("/api/v1/applications/stream"),
            "tenant-a-token",
        ))
        .await
        .expect("the router answers");
    let mut frames = response.into_body().into_data_stream();

    let first = frames.next().await.expect("a frame").expect("bytes");
    assert_eq!(
        parse_frame(&String::from_utf8_lossy(&first)).0,
        "applications"
    );

    let second = frames
        .next()
        .await
        .expect("the error frame")
        .expect("bytes");
    let (name, data) = parse_frame(&String::from_utf8_lossy(&second));
    assert_eq!(name, "error");
    let body: Value = serde_json::from_str(&data).expect("the error frame is the API error shape");
    assert_eq!(body["error"]["code"], "BackendUnavailable");
    assert_eq!(body["error"]["message"], "the cluster could not be listed");

    assert!(
        frames.next().await.is_none(),
        "the stream must end after a terminal error"
    );
    assert_eq!(snapshots.dropped(), 1);
}

/// **Trap guard:** the bearer token comes from the `Authorization` header. A token in the query
/// string (the only thing an `EventSource` could do) is not a credential here.
#[tokio::test]
async fn the_stream_authenticates_from_the_header_only_never_from_the_query() {
    let state = state_with(
        Arc::new(Events::default()),
        Arc::new(Snapshots::with(vec![Ok(tenants())])),
    );

    // A token in the URL is ignored, so the request is unauthenticated.
    let (status, body) = send(
        state.clone(),
        get_request("/api/v1/applications/stream?access_token=tenant-a-token"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "Unauthorized");

    // The same credential in the header is accepted.
    let response = ferriscd_server::router(state)
        .oneshot(with_token(
            get_request("/api/v1/applications/stream"),
            "tenant-a-token",
        ))
        .await
        .expect("the router answers");
    assert_eq!(response.status(), StatusCode::OK);
}
